use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType as FuseFileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use rusqlite::Connection;
use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::metadata::inode::Inode;
use teagarden_core::metadata::types::FileType;

use teagarden_cache::block_cache::BlockCache;
use teagarden_core::block::aad::block_aad;
use teagarden_core::block::pointer::{BlockPointer, FileManifest};
use teagarden_core::block::srb2::sha256 as sha256_bytes;
use teagarden_core::crypto::aead;
use teagarden_core::crypto::blake3::keyed_hash;
use teagarden_core::crypto::kdf::derive_epoch_key;
use teagarden_core::volume::journal_head::JournalHead;
use teagarden_core::volume::metadata_journal::{encrypt_delta, DeltaHeader};
use teagarden_store::block_store::{BlockRecord, BlockStore};
use teagarden_store::dag_store::DagStore;
use teagarden_store::inode_store::InodeStore;
use teagarden_store::local_db::{CheckpointRefused, SessionCheckpoints};
use teagarden_store::manifest_store::ManifestStore;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::sdo_clock_store::SdoClockStore;
use teagarden_store::sdo_cursor_store::SdoCursorStore;
use teagarden_store::sdo_identity_store::{SdoFileIdentity, SdoIdentityStore};
use teagarden_store::sdo_pending_store::{SdoPendingWrite, SdoPendingWriteStore};
use teagarden_store::sdo_version_store::{SdoVersionStore, StoredSdoVersion};
use teagarden_telegram::client::BlockTransport;

use crate::handle::HandleTable;
use zeroize::Zeroize;

const TTL: Duration = Duration::from_secs(1);
const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(120);

/// Largest file this filesystem accepts (64 GiB). A file being written is held
/// whole in an in-memory buffer until it is persisted, so a write ending past this
/// offset — or a truncate to a larger size — is refused with `EFBIG` instead of
/// attempting the allocation (a 1 TiB `pwrite` offset used to abort the daemon).
/// Below the cap, an allocation the host cannot satisfy is `ENOSPC`.
pub const MAX_FILE_SIZE: u64 = 64 << 30;

/// `renameat2(2)` `RENAME_NOREPLACE` (Linux ABI value). Zero elsewhere, so every
/// rename flag is refused on platforms whose flag values we do not map.
#[cfg(target_os = "linux")]
const RENAME_NOREPLACE: u32 = 1;
#[cfg(not(target_os = "linux"))]
const RENAME_NOREPLACE: u32 = 0;

/// Generous backstop for a single block download. The transport's own smart timeout
/// (idle-stall + rate-degradation detection) is the primary guard and fires far
/// sooner for a bad connection; this only bounds a true hang outside the chunk loop.
/// Large blocks at a slow-but-steady rate must NOT be truncated — a 45 MiB block
/// completes well within this even at ~80 KiB/s.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// How many blocks ahead of the current read to prefetch concurrently into the cache.
/// Overlaps the next blocks' downloads with the app's processing of the current one,
/// so a sequential reader of a large file isn't serialized one round-trip per block.
const PREFETCH_DEPTH: usize = 4;
const BLOCK_SIZE: u32 = 4096;

/// Maximum size of a single Telegram upload chunk.
/// Smaller chunks enable more parallelism with multi-session transport.
/// Must be a multiple of 512 for Telegram's upload API.
const UPLOAD_CHUNK_SIZE: usize = 512 * 1024; // 512 KB

/// Defensive upper bound on the FUSE plaintext block size, matching the cloud Bot
/// API document ceiling (conservative decimal 50 MB) with ~2 MB reserved for SRB/AEAD
/// per-block overhead (~86 bytes) plus slack, so a block's ciphertext always uploads
/// through one cloud bot. `BlockConfig::fuse_chunk_size` already clamps to this same
/// ceiling; this is the backstop in `with_fuse_block_size` for directly-built mounts.
const MAX_FUSE_BLOCK_SIZE: usize = 48_000_000;

/// A pending upload to be processed by the background upload worker.
///
/// The FUSE thread encrypts data synchronously (CPU-bound), then sends the
/// ciphertext to the worker via channel. The worker calls `transport.upload_block`
/// and returns the `message_id` via `result_tx`. This decouples the FUSE thread
/// from Telegram RTT — multiple chunks can be in-flight concurrently.
struct PendingUpload {
    ciphertext: Vec<u8>,
    _memory: tokio::sync::OwnedSemaphorePermit,
    filename: String,
    /// Bound on the upload itself, applied by the worker (carried per item so it
    /// does not depend on builder call order).
    timeout: Duration,
    result_tx: tokio::sync::oneshot::Sender<std::result::Result<i64, String>>,
}

/// How a chunk's `blocks` row should be mutated when the write is journaled.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockDisposition {
    /// Newly uploaded — insert a `blocks` row (ref_count 1).
    New,
    /// Already present in the DB — bump its ref_count once.
    DedupExisting,
    /// Identical to an earlier chunk in THIS same write — contributes a manifest
    /// pointer only, no table write (the earlier chunk's New/DedupExisting writes
    /// the single row, and all pointers share its message id so reads + integrity
    /// hashes line up). Avoids a PRIMARY KEY collision and a double ref bump.
    BatchDuplicate,
}

/// Result of preparing one chunk for a file write: the block record plus how its
/// `blocks` row should be mutated. The table mutation is deferred to the journaled
/// transaction in `persist_file_blocks` so it lands in the metadata delta — a
/// crashed session's block records must be recoverable, not orphaned.
pub struct BlockOutcome {
    record: BlockRecord,
    disposition: BlockDisposition,
}

/// TeaGarden FUSE filesystem.
///
/// Bridges between the FUSE kernel module and our encrypted storage layer.
/// Uses tokio for async dispatch to avoid blocking FUSE threads (fixes v1 100% CPU bug).
pub struct CryptFs {
    conn: Connection,
    schema: OpaqueSchema,
    meta_key: SymmetricKey,
    sdo_generation_meta_keys: std::collections::BTreeMap<u64, SymmetricKey>,
    sdo_key_generation: u64,
    sdo_generation_boundary: Option<i64>,
    sdo_device_public_key: Option<String>,
    sdo_signing_key: Option<teagarden_core::sdo::SigningKey>,
    sdo_outbox: Option<(Connection, OpaqueSchema, SymmetricKey)>,
    transient_spool_root: std::path::PathBuf,
    sdo_object_envelope: Option<(Vec<u8>, teagarden_core::crypto::keys::KeyHierarchy)>,
    data_key: SymmetricKey,
    /// Base key for keyed block identity (CABS spec §3). Epoch-scoped in flush_to_transport.
    block_id_key: Option<SymmetricKey>,
    /// Base key for grammar filename derivation (CABS spec §4). Epoch-scoped in flush_to_transport.
    filename_key: Option<SymmetricKey>,
    /// Base key for manifest identity (Phase 4 DAG). Used to compute stable manifest IDs.
    manifest_key: Option<SymmetricKey>,
    /// Portable object identity for mounts that publish SDO file versions.
    sdo_context: Option<SdoContext>,
    /// Latest locally emitted/observed HLC; mutation code persists it before upload.
    sdo_clock: Mutex<teagarden_core::sdo::HybridLogicalClock>,
    /// False means the durable HLC state could not be read; writes then fail closed.
    sdo_clock_loaded: bool,
    /// Uploaded versions awaiting their local journal COMMIT, keyed by path digest.
    pending_sdo: Mutex<std::collections::HashMap<[u8; 32], PendingSdoVersion>>,
    sdo_read_cache: Mutex<std::collections::VecDeque<CachedSdoSegment>>,
    sdo_authenticated_headers: Mutex<std::collections::VecDeque<AuthenticatedReadHeader>>,
    sdo_policy_cache: Mutex<Option<([u8; 32], teagarden_core::sdo::HeaderDocument)>>,
    /// Current key epoch for new block encryption.
    current_epoch: u32,
    /// Table of open file handles, keyed by file-handle ID.
    pub handles: HandleTable,
    uid: u32,
    gid: u32,
    /// Optional block transport for uploading/downloading blocks to Telegram.
    transport: Option<Arc<dyn BlockTransport>>,
    /// Optional block cache for caching downloaded blocks locally.
    cache: Option<Arc<BlockCache>>,
    /// Tokio runtime handle for async operations from sync FUSE callbacks.
    rt: Option<tokio::runtime::Handle>,
    /// Sender half of the upload queue channel.
    /// When set, `release()` sends encrypted chunks here instead of uploading inline.
    /// The background worker spawns a tokio task per chunk for concurrent Telegram I/O.
    upload_tx: Option<tokio::sync::mpsc::UnboundedSender<PendingUpload>>,
    upload_memory: Arc<tokio::sync::Semaphore>,
    /// T7 fail-closed: when set, a block whose store record is missing or whose
    /// SRB2 hashes are zero is refused at read time rather than served
    /// unverified. Driven by `VolumeConfig::require_block_integrity`.
    require_block_integrity: bool,
    /// T7 part 2: block-v2 AAD epoch threshold. A block whose epoch is `>=` this
    /// is sealed/verified with the block-v2 AAD (binds ciphertext to block_id).
    /// Driven by `VolumeConfig::block_v2_from_epoch`.
    block_v2_from_epoch: Option<u32>,
    /// v0.4.3 metadata durability journal. When set (and a transport + runtime are
    /// present), each journaled transaction captures a SQLite changeset, publishes
    /// it to the channel as an encrypted delta, and advances the HMAC'd HEAD floor
    /// — all BEFORE the local COMMIT — so a crash cannot orphan metadata committed
    /// through `journaled_txn` (directory ops, block records + manifest on release,
    /// setattr). The lone deliberate exception is `write`'s in-flight size/mtime
    /// preview, which is not durable until `release` (see `write`). `None` on
    /// offline volumes (plain transactions).
    journal: Option<JournalState>,
    /// Plaintext chunk size the write path splits files into before encrypting and
    /// uploading (one block = one Telegram message). Defaults to `UPLOAD_CHUNK_SIZE`;
    /// set from the volume's `BlockConfig::fuse_chunk_size()` at mount so larger
    /// blocks beat Telegram's per-message rate limit on big files.
    fuse_block_size: usize,
    /// Block IDs currently being fetched by a background read-ahead task, so a read
    /// (or another prefetch) does not redundantly download the same block. Entries are
    /// removed when the task finishes. See `trigger_prefetch`.
    prefetch_inflight: Arc<Mutex<std::collections::HashSet<[u8; 32]>>>,
    /// When set, every mutating FUSE op is refused with `EROFS`. Used to mount a
    /// read-only *share*: the recipient of a read-only-shared volume can read and
    /// list but cannot write, create, delete, rename, chmod, or truncate. Enforced
    /// at the FUSE surface (every mutating op guards on this) so the refusal is what
    /// a user's syscall actually hits, not merely a UI affordance.
    read_only: bool,
    /// FUSE inode generation per inode number, for numbers deleted during this
    /// mount. `next_ino` (= MAX(ino)+1) can hand a deleted file's number to the
    /// next create; replying with a bumped generation makes the kernel treat the
    /// new file as a different inode (it marks the old cached one bad, so I/O on a
    /// descriptor of the deleted file fails) instead of aliasing the two. Kept in
    /// memory only: the kernel's inode cache does not survive a remount, so the
    /// generation only needs to be distinct within one mount. Numbers never
    /// deleted this mount are generation 0, as before.
    generations: Mutex<std::collections::HashMap<u64, u64>>,
    /// Upper bound on a single block upload (inline and upload-queue paths). A
    /// transport that never answers turns into `EIO` after this long instead of
    /// wedging the FUSE thread. Defaults to `TRANSPORT_TIMEOUT`.
    upload_timeout: Duration,
    /// The session's ownership of the DB's main file (see
    /// `teagarden_store::local_db::SessionCheckpoints`): when set, `conn`
    /// never checkpoints on its own; this filesystem checkpoints it itself
    /// when the WAL grows past `SESSION_CHECKPOINT_PAGES` and before the
    /// connection closes, never over a main file another program wrote.
    checkpoints: Option<Arc<SessionCheckpoints>>,
    /// One bounded remote batch is applied by the serialized FUSE request loop.
    sdo_poll_rx: Option<tokio::sync::mpsc::Receiver<SdoPollBatch>>,
    /// Shared slot filled after FUSE Session construction.
    sdo_notifier: Option<Arc<Mutex<Option<fuser::Notifier>>>>,
    /// Unix second of the last local filesystem mutation.
    sdo_last_activity: Option<Arc<AtomicU64>>,
    /// Interrupts an idle topic-poll delay when local filesystem activity occurs.
    sdo_activity_notify: Option<Arc<tokio::sync::Notify>>,
}

/// One downloaded high-water batch waiting for serialized SQLite application.
pub struct SdoPollBatch {
    /// Telegram raw-message high-water ID represented by this batch.
    pub high_water_id: i64,
    /// Authenticated-format header bytes and their Telegram message IDs.
    pub objects: Vec<(i64, Vec<u8>)>,
    /// Authenticated key generation learned from this batch's per-device handoff.
    pub generation_update: Option<SdoGenerationUpdate>,
    /// Acknowledges commit or failure to the poll worker.
    pub ack: tokio::sync::oneshot::Sender<std::result::Result<(), i32>>,
}

/// Runtime generation keys installed by an authenticated device key handoff.
#[derive(Clone)]
pub struct SdoGenerationUpdate {
    /// Active generation for future writes.
    pub active_generation: u64,
    /// First message ID of this generation.
    pub boundary_message_id: Option<i64>,
    /// Active and retained bridge metadata keys.
    pub generation_meta_keys: std::collections::BTreeMap<u64, SymmetricKey>,
    /// Credential bootstrap for writes after this handoff.
    pub object_envelope: Option<(Vec<u8>, teagarden_core::crypto::keys::KeyHierarchy)>,
}

/// Per-volume metadata-journal state held by [`CryptFs`].
struct JournalState {
    /// Hierarchy integrity key — authenticates the on-disk HEAD floor.
    integrity_key: SymmetricKey,
    /// Path of the HMAC'd journal HEAD file (sibling of the metadata DB).
    head_path: PathBuf,
    /// Running HEAD (seq advances by one per published delta). Interior mutability
    /// because journaled transactions run through `&self` FUSE callbacks.
    head: Mutex<JournalHead>,
    /// Set if a local `COMMIT` ever failed after the delta was published + HEAD
    /// advanced: the on-disk floor is then ahead of an indeterminate local DB.
    /// That state is *recoverable* (a remount rebuilds from the channel), but
    /// continuing to write against the diverged DB would compound the divergence,
    /// so every subsequent journaled transaction refuses with `EIO` until remount.
    poisoned: std::sync::atomic::AtomicBool,
}

#[derive(Clone, Copy)]
struct SdoContext {
    volume_id: uuid::Uuid,
    author_device_id: uuid::Uuid,
    max_file_size: u64,
}

struct AuthenticatedReadHeader {
    version: uuid::Uuid,
    message: i64,
    stamp: [u8; 32],
    header: RangedSdoHeader,
}

type CachedSdoSegment = (uuid::Uuid, u32, Arc<Vec<u8>>);

#[derive(Clone)]
struct PendingSdoVersion {
    fingerprint: [u8; 32],
    manifest: teagarden_core::sdo::SdoObjectMetadataV3,
    stored: StoredSdoVersion,
}

#[derive(Clone)]
enum RangedSdoHeader {
    V2(teagarden_core::sdo::SdoObjectHeader),
    V3(Box<teagarden_core::sdo::SdoObjectHeaderV3>),
}

impl RangedSdoHeader {
    fn key_generation(&self) -> u64 {
        match self {
            Self::V2(_) => 0,
            Self::V3(header) => header.metadata.key_generation,
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::V2(h) => h.metadata.size,
            Self::V3(h) => h.metadata.size,
        }
    }
    fn segment_size(&self) -> u32 {
        match self {
            Self::V2(h) => h.metadata.segment_size,
            Self::V3(h) => h.metadata.segment_size,
        }
    }
    fn segment_count(&self) -> u32 {
        match self {
            Self::V2(h) => h.metadata.segment_count,
            Self::V3(h) => h.metadata.segment_count,
        }
    }
    fn content_sha256(&self) -> &str {
        match self {
            Self::V2(h) => &h.metadata.content_sha256,
            Self::V3(h) => &h.metadata.content_sha256,
        }
    }
    fn deleted(&self) -> bool {
        match self {
            Self::V2(h) => h.metadata.deleted,
            Self::V3(h) => h.metadata.deleted,
        }
    }
    fn version_id(&self) -> uuid::Uuid {
        match self {
            Self::V2(h) => h.metadata.version_id,
            Self::V3(h) => h.metadata.version_id,
        }
    }
    fn portable_record(&self) -> Result<PortableVersionRecord, libc::c_int> {
        match self {
            Self::V2(header) => {
                let metadata = &header.metadata;
                Ok(PortableVersionRecord {
                    record: teagarden_core::sdo::legacy_object_record(metadata),
                    file_id: metadata.file_id,
                    origin_message_id: metadata.origin_message_id,
                    local_version: metadata.local_version,
                    size: metadata.size,
                    mtime_ns: metadata.mtime_ns,
                    mode: metadata.mode,
                    content_sha256: metadata.content_sha256.clone(),
                    segment_size: metadata.segment_size,
                    segment_count: metadata.segment_count,
                })
            }
            Self::V3(header) => {
                let metadata = &header.metadata;
                let path = match metadata.kind {
                    teagarden_core::sdo::SdoKind::Device => {
                        metadata.installation_id.ok_or(libc::EIO)?.to_string()
                    }
                    _ => metadata.path.clone().ok_or(libc::EIO)?,
                };
                Ok(PortableVersionRecord {
                    record: teagarden_core::sdo::SdoRecord {
                        path,
                        kind: metadata.kind,
                        clock_ms: metadata.clock_ms,
                        clock_counter: metadata.clock_counter,
                        author_device_id: metadata.author_device_id,
                        version_id: metadata.version_id,
                        deleted: metadata.deleted,
                        legacy: false,
                        implicit: false,
                    },
                    file_id: metadata.file_id,
                    origin_message_id: metadata.origin_message_id,
                    local_version: metadata.local_version,
                    size: metadata.size,
                    mtime_ns: metadata.mtime_ns,
                    mode: metadata.mode,
                    content_sha256: metadata.content_sha256.clone(),
                    segment_size: metadata.segment_size,
                    segment_count: metadata.segment_count,
                })
            }
        }
    }
    fn segment_offset(&self, i: u32) -> teagarden_core::error::Result<u64> {
        match self {
            Self::V2(h) => h.segment_offset(i),
            Self::V3(h) => h.segment_offset(i),
        }
    }
    fn encrypted_segment_len(&self, i: u32) -> teagarden_core::error::Result<u32> {
        match self {
            Self::V2(h) => h.encrypted_segment_len(i),
            Self::V3(h) => h.encrypted_segment_len(i),
        }
    }
    fn decrypt_segment(
        &self,
        key: &SymmetricKey,
        i: u32,
        bytes: &[u8],
    ) -> teagarden_core::error::Result<Vec<u8>> {
        match self {
            Self::V2(h) => teagarden_core::sdo::SdoFileObject::decrypt_segment(h, key, i, bytes),
            Self::V3(h) => teagarden_core::sdo::SdoFileObjectV3::decrypt_segment(h, key, i, bytes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PortableVersionRecord {
    record: teagarden_core::sdo::SdoRecord,
    file_id: uuid::Uuid,
    origin_message_id: Option<i64>,
    local_version: u64,
    size: u64,
    mtime_ns: i64,
    mode: u32,
    content_sha256: String,
    segment_size: u32,
    segment_count: u32,
}

fn decode_stored_sdo_header(
    wire: &[u8],
    volume_id: uuid::Uuid,
    meta_key: &SymmetricKey,
    generation_meta_keys: &std::collections::BTreeMap<u64, SymmetricKey>,
) -> teagarden_core::error::Result<RangedSdoHeader> {
    match wire.get(4..6) {
        Some([2, 0]) => Ok(RangedSdoHeader::V2(
            teagarden_core::sdo::SdoFileObject::decode_header(
                wire,
                volume_id,
                generation_meta_keys.get(&0).unwrap_or(meta_key),
            )?,
        )),
        Some([3, 0]) if wire.len() >= 30 => {
            let generation = u64::from_le_bytes(wire[22..30].try_into().unwrap());
            Ok(RangedSdoHeader::V3(Box::new(
                teagarden_core::sdo::SdoFileObjectV3::decode_header(
                    wire,
                    volume_id,
                    generation,
                    generation_meta_keys.get(&generation).unwrap_or(meta_key),
                )?,
            )))
        }
        _ => Err(teagarden_core::error::CoreError::Manifest(
            "unsupported TGFV object format".into(),
        )),
    }
}

/// Upload refusals during recovery that no retry can change: revoked or
/// mismatched authority, a key generation this build cannot use, or a size
/// limit. Anything else (transport and I/O failures) stays pending.
fn recovery_upload_error_is_permanent(errno: libc::c_int) -> bool {
    matches!(
        errno,
        libc::EPERM | libc::EACCES | libc::ENOTSUP | libc::EFBIG
    )
}

fn sdo_upload_errno(error: teagarden_telegram::error::TelegramError) -> libc::c_int {
    match error {
        teagarden_telegram::error::TelegramError::BlockTooLarge { size, max } => {
            tracing::error!(
                object_size = size,
                telegram_limit = max,
                "TGFV file object exceeds the Telegram account upload limit"
            );
            libc::EFBIG
        }
        error => {
            tracing::error!(%error, "portable file object upload failed");
            libc::EIO
        }
    }
}

impl CryptFs {
    /// Construct an offline `CryptFs` over the given SQLite connection and keys.
    ///
    /// Transport, cache, runtime, upload queue, and metadata journal are left unset
    /// (offline mode); files are owned by `uid`/`gid`. Use the builder-style setters
    /// to attach a transport, cache, or journal before mounting.
    pub fn new(
        conn: Connection,
        schema: OpaqueSchema,
        meta_key: SymmetricKey,
        data_key: SymmetricKey,
        uid: u32,
        gid: u32,
    ) -> Self {
        let sdo_generation_meta_keys = std::collections::BTreeMap::from([(0, meta_key.clone())]);
        Self {
            conn,
            schema,
            meta_key,
            sdo_generation_meta_keys,
            sdo_key_generation: 0,
            sdo_generation_boundary: None,
            sdo_device_public_key: None,
            sdo_signing_key: None,
            sdo_outbox: None,
            transient_spool_root: std::env::temp_dir()
                .join(format!("teagarden-spool-{}", uuid::Uuid::new_v4())),
            sdo_object_envelope: None,
            data_key,
            block_id_key: None,
            filename_key: None,
            manifest_key: None,
            sdo_context: None,
            sdo_clock: Mutex::new(teagarden_core::sdo::HybridLogicalClock::new(0, 0)),
            sdo_clock_loaded: false,
            pending_sdo: Mutex::new(std::collections::HashMap::new()),
            sdo_read_cache: Mutex::new(std::collections::VecDeque::new()),
            sdo_authenticated_headers: Mutex::new(std::collections::VecDeque::new()),
            sdo_policy_cache: Mutex::new(None),
            current_epoch: 0,
            handles: HandleTable::new(),
            uid,
            gid,
            transport: None,
            cache: None,
            rt: None,
            upload_tx: None,
            upload_memory: Arc::new(tokio::sync::Semaphore::new(64 * 1024 * 1024)),
            require_block_integrity: false,
            block_v2_from_epoch: None,
            journal: None,
            fuse_block_size: UPLOAD_CHUNK_SIZE,
            prefetch_inflight: Arc::new(Mutex::new(std::collections::HashSet::new())),
            read_only: false,
            upload_timeout: TRANSPORT_TIMEOUT,
            generations: Mutex::new(std::collections::HashMap::new()),
            checkpoints: None,
            sdo_poll_rx: None,
            sdo_notifier: None,
            sdo_last_activity: None,
            sdo_activity_notify: None,
        }
    }

    /// Hand the DB's checkpoints to the session that opened it (`ck`, from
    /// `SessionCheckpoints::start` on the DB `conn` has open): `conn` stops
    /// checkpointing on its own, and this filesystem checkpoints through
    /// `ck` (past `SESSION_CHECKPOINT_PAGES` WAL frames, and when it is
    /// dropped). Fails when SQLite refuses the settings.
    pub fn with_session_checkpoints(
        mut self,
        ck: Arc<SessionCheckpoints>,
    ) -> rusqlite::Result<Self> {
        teagarden_store::local_db::own_checkpoints(&self.conn)?;
        self.checkpoints = Some(ck);
        Ok(self)
    }

    /// The session's checkpoint of `conn` once the WAL holds more than
    /// `pages` frames (always with `pages == 0` and any frame). A main file
    /// another program wrote is never checkpointed over: the journal is
    /// poisoned (further writes fail with `EIO`) and, for a journaled
    /// volume, the DB is marked to be rebuilt from Telegram, which holds
    /// every acknowledged change.
    fn session_checkpoint(&self, pages: u64) {
        let Some(ck) = &self.checkpoints else { return };
        match ck.checkpoint_past(&self.conn, pages) {
            Ok(_) => {}
            Err(CheckpointRefused::Failed(e)) => {
                // The WAL keeps the frames; the next checkpoint retries.
                tracing::warn!(error = %e, "session checkpoint did not complete");
            }
            Err(CheckpointRefused::Foreign(why)) => self.foreign_main_file(&why),
        }
    }

    /// Another program wrote the main DB file: see `session_checkpoint`.
    fn foreign_main_file(&self, why: &str) {
        tracing::error!(
            reason = why,
            "the metadata database was changed by another program; not checkpointing over it"
        );
        let Some(journal) = &self.journal else { return };
        journal
            .poisoned
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(dir) = journal.head_path.parent() {
            if journal.head_path.exists() {
                if let Err(e) = teagarden_core::volume::rebuild_marker::mark(
                    dir,
                    "the session found its metadata database written by another program \
                     while the volume was in use",
                ) {
                    tracing::error!(error = %e, "could not mark the metadata database to be rebuilt");
                }
            }
        }
    }

    /// Set the plaintext chunk size the write path splits files into (one block per
    /// Telegram message). Values are clamped/aligned by
    /// [`BlockConfig::fuse_chunk_size`](teagarden_core::volume::config::BlockConfig::fuse_chunk_size);
    /// callers should pass that. Defaults to `UPLOAD_CHUNK_SIZE` when unset.
    ///
    /// Clamped here too — to `[UPLOAD_CHUNK_SIZE, MAX_FUSE_BLOCK_SIZE]` — as a
    /// defensive backstop so a block's ciphertext can never exceed the Telegram
    /// per-document limit even if a caller bypasses `fuse_chunk_size`.
    pub fn with_fuse_block_size(mut self, size: usize) -> Self {
        self.fuse_block_size = size.clamp(UPLOAD_CHUNK_SIZE, MAX_FUSE_BLOCK_SIZE);
        self
    }

    /// Enable the v0.4.3 metadata durability journal.
    ///
    /// `integrity_key` authenticates the on-disk HEAD floor; `head_path` is where
    /// the HMAC'd HEAD file lives (sibling of the metadata DB); `initial_head` is
    /// the HEAD loaded at mount (or a fresh `{seq:0, parent_msg_id:0,
    /// base_snapshot_version: <current snapshot version>}` for a new chain).
    ///
    /// Journaling only activates when a transport and runtime are also set;
    /// otherwise transactions run plain (offline volumes).
    pub fn with_journal(
        mut self,
        integrity_key: SymmetricKey,
        head_path: PathBuf,
        initial_head: JournalHead,
    ) -> Self {
        self.journal = Some(JournalState {
            integrity_key,
            head_path,
            head: Mutex::new(initial_head),
            poisoned: std::sync::atomic::AtomicBool::new(false),
        });
        self
    }

    /// Set the current epoch for block encryption.
    pub fn with_epoch(mut self, epoch: u32) -> Self {
        self.current_epoch = epoch;
        self
    }

    /// Enable T7 fail-closed block integrity (from `VolumeConfig`).
    pub fn with_block_integrity(mut self, required: bool) -> Self {
        self.require_block_integrity = required;
        self
    }

    /// Set the block-v2 AAD epoch threshold (from `VolumeConfig`).
    pub fn with_block_v2_from_epoch(mut self, threshold: Option<u32>) -> Self {
        self.block_v2_from_epoch = threshold;
        self
    }

    /// Set the block identity and filename keys (CABS spec §3–4).
    /// Both keys are required for keyed block_id dedup and grammar filenames.
    pub fn with_block_keys(
        mut self,
        block_id_key: SymmetricKey,
        filename_key: SymmetricKey,
    ) -> Self {
        self.block_id_key = Some(block_id_key);
        self.filename_key = Some(filename_key);
        self
    }

    /// Set the manifest identity key (Phase 4 DAG history).
    pub fn with_manifest_key(mut self, key: SymmetricKey) -> Self {
        self.manifest_key = Some(key);
        self
    }

    /// Enable portable encrypted file-version publication for this volume.
    pub fn with_sdo(mut self, volume_id: uuid::Uuid, author_device_id: uuid::Uuid) -> Self {
        self.sdo_context = Some(SdoContext {
            volume_id,
            author_device_id,
            max_file_size: teagarden_core::sdo::MAX_SDO_FILE_BYTES,
        });
        match self.sdo_clock_store().get() {
            Ok(Some((physical_ms, counter))) => {
                self.sdo_clock = Mutex::new(teagarden_core::sdo::HybridLogicalClock::new(
                    physical_ms,
                    counter,
                ));
                self.sdo_clock_loaded = true;
            }
            Ok(None) => self.sdo_clock_loaded = true,
            Err(error) => {
                tracing::error!(%error, "portable hybrid clock state could not be loaded");
                self.sdo_clock_loaded = false;
            }
        }
        self
    }

    /// Add active and bridged metadata keys recovered from the authenticated
    /// TGHD2 rotation state. New portable writes use `active_generation`.
    pub fn with_sdo_generation_keys(
        mut self,
        active_generation: u64,
        generation_boundary: Option<i64>,
        generation_meta_keys: std::collections::BTreeMap<u64, SymmetricKey>,
    ) -> Self {
        self.sdo_key_generation = active_generation;
        self.sdo_generation_boundary = generation_boundary;
        self.sdo_generation_meta_keys = generation_meta_keys;
        self
    }

    /// Attach this installation's public key for future owner key handoffs.
    pub fn with_sdo_device_public_key(mut self, public_key_hex: String) -> Self {
        self.sdo_device_public_key = Some(public_key_hex);
        self
    }

    /// Attach the installation's stable encrypted outbox independently of its
    /// disposable namespace index and rotating remote data keys.
    pub fn with_sdo_outbox(
        mut self,
        conn: Connection,
        schema: OpaqueSchema,
        key: SymmetricKey,
    ) -> Self {
        self.sdo_outbox = Some((conn, schema, key));
        self
    }

    /// Use this installation's signing capability for every new portable version.
    pub fn with_sdo_signing_key(mut self, signing_key: teagarden_core::sdo::SigningKey) -> Self {
        self.sdo_signing_key = Some(signing_key);
        self
    }

    fn sdo_policy_stamp(&self) -> [u8; 32] {
        self.sdo_object_envelope
            .as_ref()
            .map_or([0; 32], |(wire, h)| keyed_hash(&h.integrity, wire))
    }

    fn sdo_policy(
        &self,
    ) -> std::result::Result<Option<teagarden_core::sdo::HeaderDocument>, libc::c_int> {
        let stamp = self.sdo_policy_stamp();
        if let Some((previous, header)) = self
            .sdo_policy_cache
            .lock()
            .map_err(|_| libc::EIO)?
            .as_ref()
        {
            if *previous == stamp {
                return Ok(Some(header.clone()));
            }
        }
        self.sdo_object_envelope
            .as_ref()
            .map(|(wire, hierarchy)| {
                let header = teagarden_core::sdo::HeaderDocument::decode(
                    wire,
                    &hierarchy.integrity,
                )
                .and_then(|header| {
                    header.require_complete_revocation_cutoffs()?;
                    #[cfg(not(feature = "key-rotation"))]
                    if header.key_generation.unwrap_or(0) != 0
                        || !header.retained_key_bridges.is_empty()
                        || header.rotation_state.is_some()
                    {
                        return Err(teagarden_core::error::CoreError::Manifest(
                            "TGFV key rotation is not available in the 1.0 build".into(),
                        ));
                    }
                    Ok(header)
                })
                .map_err(|error| {
                    tracing::error!(%error, "refusing incomplete or invalid portable policy");
                    libc::EIO
                })?;
                *self.sdo_policy_cache.lock().map_err(|_| libc::EIO)? =
                    Some((stamp, header.clone()));
                Ok(header)
            })
            .transpose()
    }

    fn sdo_header_allowed(
        policy: Option<&teagarden_core::sdo::HeaderDocument>,
        header: &RangedSdoHeader,
        message_id: i64,
    ) -> bool {
        policy.is_none_or(|policy| match header {
            RangedSdoHeader::V3(header) => teagarden_core::sdo::object_transition_is_acceptable(
                policy,
                &header.metadata,
                message_id,
            ),
            RangedSdoHeader::V2(header) => teagarden_core::sdo::object_transition_is_acceptable(
                policy,
                &teagarden_core::sdo::legacy_metadata_v3(&header.metadata),
                message_id,
            ),
        })
    }

    /// Supply the authenticated credential bootstrap for complete portable objects.
    pub fn with_sdo_object_envelope(
        mut self,
        header_wire: Vec<u8>,
        hierarchy: teagarden_core::crypto::keys::KeyHierarchy,
    ) -> Self {
        self.sdo_object_envelope = Some((header_wire, hierarchy));
        self
    }

    fn seal_sdo_object(&self, wire: Vec<u8>) -> teagarden_core::error::Result<Vec<u8>> {
        match &self.sdo_object_envelope {
            Some((header, hierarchy)) => {
                teagarden_core::sdo::ObjectEnvelope::seal(&wire, header, hierarchy)
            }
            None => Ok(wire), // Legacy builders and codec-only fixtures.
        }
    }

    fn sdo_meta_key_for_generation(&self, generation: u64) -> &SymmetricKey {
        self.sdo_generation_meta_keys
            .get(&generation)
            .unwrap_or(&self.meta_key)
    }

    /// Attach the bounded inbox used to serialize remote topic batches through
    /// this filesystem's SQLite connection.
    pub fn with_sdo_poll_inbox(
        mut self,
        receiver: tokio::sync::mpsc::Receiver<SdoPollBatch>,
        notifier_slot: Arc<Mutex<Option<fuser::Notifier>>>,
        last_activity: Arc<AtomicU64>,
        activity_notify: Arc<tokio::sync::Notify>,
    ) -> Self {
        self.sdo_poll_rx = Some(receiver);
        self.sdo_notifier = Some(notifier_slot);
        self.sdo_last_activity = Some(last_activity);
        self.sdo_activity_notify = Some(activity_notify);
        self
    }

    fn mark_sdo_activity(&self) {
        if let Some(last_activity) = &self.sdo_last_activity {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            last_activity.store(now, Ordering::Relaxed);
        }
        if let Some(activity_notify) = &self.sdo_activity_notify {
            activity_notify.notify_one();
        }
    }

    /// Set the per-object plaintext limit determined from the authenticated Telegram account.
    pub fn with_sdo_file_limit(mut self, max_file_size: u64) -> Self {
        if let Some(context) = &mut self.sdo_context {
            context.max_file_size =
                max_file_size.min(teagarden_core::sdo::MAX_SDO_FILE_BYTES_PREMIUM);
        }
        self
    }

    /// Observe a remote HLC before creating local versions and persist the
    /// resulting state in this installation's private index.
    pub fn observe_sdo_clock(
        &self,
        remote_ms: u64,
        remote_counter: u64,
    ) -> std::result::Result<(), libc::c_int> {
        if self.sdo_context.is_none() || !self.sdo_clock_loaded {
            return Err(libc::EIO);
        }
        let utc_ms = u64::try_from(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let (physical_ms, counter) = self
            .sdo_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .receive(remote_ms, remote_counter, utc_ms)
            .map_err(|error| {
                tracing::error!(%error, "received hybrid clock overflow");
                libc::EIO
            })?;
        self.sdo_clock_store()
            .set(physical_ms, counter)
            .map_err(|error| {
                tracing::error!(%error, "received hybrid clock persistence failed");
                libc::EIO
            })
    }

    /// Publish or refresh the encrypted registry announcement for this
    /// installation before the mount serves its first mutation.
    pub fn publish_sdo_device_announcement(
        &self,
        label: &str,
        telegram_user_id: i64,
        authorization_session_hash: Option<i64>,
    ) -> std::result::Result<(), libc::c_int> {
        let Some(context) = self.sdo_context else {
            return Err(libc::EINVAL);
        };
        if label.len() > 128 || telegram_user_id <= 0 || !self.sdo_clock_loaded {
            return Err(libc::EINVAL);
        }
        self.transport.as_ref().ok_or(libc::EIO)?;
        let manifest_key = self.manifest_key.as_ref().ok_or(libc::EIO)?;
        let path_id = keyed_hash(
            manifest_key,
            &[
                b"teagarden.sdo.device.v1".as_slice(),
                context.author_device_id.as_bytes(),
            ]
            .concat(),
        );
        let existing = self
            .sdo_version_store()
            .list_for_path(&path_id)
            .map_err(|error| {
                tracing::error!(%error, "device announcement history lookup failed");
                libc::EIO
            })?;
        let mut prior_device = None;
        for stored in existing {
            if let Ok(RangedSdoHeader::V3(header)) = decode_stored_sdo_header(
                &stored.wire,
                context.volume_id,
                &self.meta_key,
                &self.sdo_generation_meta_keys,
            ) {
                let metadata = &header.metadata;
                if metadata.kind == teagarden_core::sdo::SdoKind::Device
                    && metadata.installation_id == Some(context.author_device_id)
                    && prior_device.as_ref().is_none_or(
                        |prior: &teagarden_core::sdo::SdoObjectMetadataV3| {
                            (prior.clock_ms, prior.clock_counter)
                                < (metadata.clock_ms, metadata.clock_counter)
                        },
                    )
                {
                    prior_device = Some(metadata.clone());
                }
            }
        }
        let authorization_session_hash = authorization_session_hash
            .filter(|hash| *hash != 0)
            .map(|hash| hash.to_string())
            .or_else(|| {
                prior_device
                    .as_ref()
                    .filter(|metadata| metadata.telegram_user_id == Some(telegram_user_id))
                    .and_then(|metadata| metadata.authorization_session_hash.as_ref())
                    .filter(|hash| hash.as_str() != "0")
                    .cloned()
            });
        if prior_device.as_ref().is_some_and(|metadata| {
            metadata.device_public_key == self.sdo_device_public_key
                && metadata.telegram_user_id == Some(telegram_user_id)
                && metadata.authorization_session_hash == authorization_session_hash
        }) {
            return Ok(());
        }
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let created_at_ms = prior_device
            .as_ref()
            .and_then(|metadata| metadata.created_at_ms)
            .unwrap_or(u64::try_from(now.as_millis()).map_err(|_| libc::EIO)?);
        let (clock_ms, clock_counter) = self
            .sdo_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tick(created_at_ms)
            .map_err(|_| libc::EIO)?;
        self.sdo_clock_store()
            .set(clock_ms, clock_counter)
            .map_err(|error| {
                tracing::error!(%error, "device announcement clock persistence failed before upload");
                libc::EIO
            })?;

        let version_id = uuid::Uuid::new_v4();
        let metadata = teagarden_core::sdo::SdoObjectMetadataV3 {
            authority: None,
            migration_receipt: None,
            file_id: prior_device
                .as_ref()
                .map_or_else(uuid::Uuid::new_v4, |metadata| metadata.file_id),
            origin_message_id: prior_device
                .as_ref()
                .and_then(|metadata| metadata.origin_message_id),
            path: None,
            size: 0,
            mtime_ns: 0,
            mode: 0,
            version_id,
            author_device_id: context.author_device_id,
            previous_version_id: prior_device.as_ref().map(|metadata| metadata.version_id),
            kind: teagarden_core::sdo::SdoKind::Device,
            key_generation: self.sdo_key_generation,
            clock_ms,
            clock_counter,
            saved_at_ns: system_time_to_ns(SystemTime::now()) as i64,
            local_version: prior_device
                .as_ref()
                .map_or(1, |metadata| metadata.local_version.saturating_add(1)),
            deleted: false,
            installation_id: Some(context.author_device_id),
            label: Some(label.to_owned()),
            telegram_user_id: Some(telegram_user_id),
            authorization_session_hash,
            created_at_ms: Some(created_at_ms),
            device_public_key: self.sdo_device_public_key.clone(),
            device_key_update: prior_device
                .as_ref()
                .and_then(|metadata| metadata.device_key_update.clone()),
            segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
            segment_count: 0,
            content_sha256: hex::encode(sha256_bytes(&[])),
        };
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
            context.volume_id,
            self.sdo_key_generation,
            self.sdo_meta_key_for_generation(self.sdo_key_generation),
            metadata.clone(),
            &[],
            self.sdo_signing_key.as_ref(),
        )
        .and_then(|wire| self.seal_sdo_object(wire))
        .map_err(|error| {
            tracing::error!(%error, "device announcement encoding failed");
            libc::EIO
        })?;
        let mut fingerprint = Vec::new();
        fingerprint.extend_from_slice(context.author_device_id.as_bytes());
        fingerprint.extend_from_slice(label.as_bytes());
        fingerprint.extend_from_slice(&telegram_user_id.to_le_bytes());
        fingerprint.extend_from_slice(&clock_ms.to_le_bytes());
        fingerprint.extend_from_slice(&clock_counter.to_le_bytes());
        let pending = PendingSdoVersion {
            fingerprint: sha256_bytes(&fingerprint),
            manifest: metadata,
            stored: StoredSdoVersion {
                path_id,
                ino: 0,
                message_id: 0,
                wire,
            },
        };
        let pending = self.retry_sdo_upload(pending)?;
        self.journaled_txn(|| self.commit_sdo_version(&pending))?;
        self.pending_sdo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&pending.stored.path_id);
        Ok(())
    }

    /// Upload portable versions for current regular files that predate SDO. This
    /// runs through the normal journaled transaction path so a backfill is part of
    /// the snapshot being prepared.
    pub fn backfill_sdo_versions(&self) -> std::result::Result<usize, libc::c_int> {
        if self.sdo_context.is_none() {
            return Ok(0);
        }
        let inodes = self.store().list_all().map_err(|e| {
            tracing::error!(error = %e, "portable backfill inode scan failed");
            libc::EIO
        })?;
        let mut added = 0;
        for inode in inodes
            .into_iter()
            .filter(|inode| inode.ino != 1 && (inode.is_file() || inode.is_dir()))
        {
            let path = self.path_for_inode(inode.ino)?;
            let path_id = {
                let key = self.manifest_key.as_ref().ok_or(libc::EIO)?;
                keyed_hash(
                    key,
                    &[b"teagarden.sdo.path.v1".as_slice(), path.as_bytes()].concat(),
                )
            };
            if !self
                .sdo_version_store()
                .list_for_path(&path_id)
                .map_err(|_| libc::EIO)?
                .is_empty()
            {
                continue;
            }
            let pointers = inode
                .manifest
                .as_ref()
                .map_or(&[][..], |m| m.blocks.as_slice());
            let content = if inode.is_file() {
                self.current_inode_content(&inode)?
            } else {
                Vec::new()
            };
            let pending =
                self.upload_sdo_version(&inode, &path, &content, pointers, &[], false, None)?;
            self.journaled_txn(|| self.commit_sdo_version(&pending))?;
            self.pending_sdo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&pending.stored.path_id);
            added += 1;
        }
        Ok(added)
    }

    /// Retry pending portable writes loaded from the durable metadata index.
    /// Failed records remain encrypted in SQLite for the next mount attempt.
    pub fn retry_pending_sdo_writes(&mut self) -> std::result::Result<usize, libc::c_int> {
        let mut spool_completed = 0;
        let root = self.spool_root();
        if root.exists() {
            for entry in std::fs::read_dir(&root).map_err(|_| libc::EIO)? {
                let path = entry.map_err(|_| libc::EIO)?.path();
                if path.extension().is_none_or(|e| e != "intent") {
                    continue;
                }
                let quarantine = |reason: &str| match crate::spool::WriteSpool::quarantine(
                    &path, reason,
                ) {
                    Ok(destination) => {
                        tracing::warn!(%reason, path = %destination.display(), "quarantined pending write; mount continues");
                        eprintln!(
                            "Warning: quarantined pending write at {}: {reason}; mount continues",
                            destination.display()
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, %reason, path = %path.display(), "could not move unsafe pending write; ignored for mount readiness");
                        eprintln!("Warning: unsafe pending write {} ignored; quarantine failed: {error}; reason: {reason}", path.display());
                    }
                };
                let mut spool = match crate::spool::WriteSpool::load(
                    &path,
                    self.spool_key().clone(),
                    self.manifest_key.as_ref().ok_or(libc::EIO)?,
                ) {
                    Ok(spool) => spool,
                    Err(error) => {
                        quarantine(&error.to_string());
                        continue;
                    }
                };
                let validation = spool
                    .verify_recoverable(self.manifest_key.as_ref().ok_or(libc::EIO)?)
                    .and_then(|()| {
                        let Some(plan) = spool.intent.plan.as_ref() else {
                            return Ok(());
                        };
                        plan.clone()
                            .reader(
                                spool.file.try_clone()?,
                                self.sdo_meta_key_for_generation(plan.metadata.key_generation)
                                    .clone(),
                                self.sdo_object_envelope.as_ref().map(|(_, h)| h.clone()),
                            )
                            .map(|_| ())
                            .map_err(|e| std::io::Error::other(e.to_string()))
                    });
                if let Err(error) = validation {
                    quarantine(&error.to_string());
                    continue;
                }
                let pending = match self.upload_spool(&mut spool) {
                    Ok(pending) => pending,
                    // Refusals that a retry can never change (revoked or
                    // mismatched authority, unsupported key generation, size
                    // limit) are set aside, not retried on every mount.
                    Err(error) if recovery_upload_error_is_permanent(error) => {
                        quarantine(&format!("upload permanently refused (errno {error})"));
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(errno = error, version_id = %spool.intent.metadata.version_id,
                            "recovery upload remains pending for next mount; mount continues");
                        eprintln!("Warning: recovery upload {} failed (errno {error}); retained for next mount; mount continues",
                            spool.intent.metadata.version_id);
                        continue;
                    }
                };
                // The version is on Telegram now. Failing to record it locally
                // must not stop the mount: the intent stays (its confirmation
                // repairs the index on the next mount without re-uploading),
                // and the topic poller also applies the published version.
                let version_id = spool.intent.metadata.version_id;
                let applied = SdoCursorStore::new(&self.conn, &self.schema)
                    .get()
                    .map_err(|_| libc::EIO)
                    .map(|cursor| cursor.map_or(0, |(id, _)| id))
                    .and_then(|cursor| {
                        self.apply_remote_sdo_batch(
                            vec![(pending.stored.message_id, pending.stored.wire)],
                            cursor,
                        )
                    })
                    .and_then(|_| spool.cleanup().map_err(|_| libc::EIO));
                if let Err(error) = applied {
                    tracing::warn!(errno = error, %version_id,
                        "recovered upload is published but not yet recorded locally; retained for next mount; mount continues");
                    eprintln!("Warning: recovered upload {version_id} is published but could not be recorded locally (errno {error}); retained for next mount; mount continues");
                    continue;
                }
                spool_completed += 1;
            }
        }
        let pending = self.sdo_pending_write_store().list().map_err(|error| {
            tracing::error!(%error, "portable pending-write recovery scan failed");
            libc::EIO
        })?;
        let mut completed = spool_completed;
        for retry in pending {
            if retry.wire.is_some() || retry.metadata_snapshot.is_some() {
                match self.recover_portable_outbox_record(&retry) {
                    Ok(()) => completed += 1,
                    Err(error) => {
                        tracing::warn!(version_id = %retry.version_id, errno = error, "stable portable outbox record remains queued")
                    }
                }
                continue;
            }

            let Some(inode) = self.store().get(retry.inode).map_err(|error| {
                tracing::error!(%error, ino = retry.inode, "pending-write inode lookup failed");
                libc::EIO
            })?
            else {
                tracing::warn!(ino = retry.inode, version_id = %retry.version_id, "pending write has no local inode; preserving it for repair");
                continue;
            };
            let fh = match retry.predecessor {
                Some(version_id) => {
                    self.handles
                        .open_pinned_sdo(retry.inode, libc::O_RDWR, inode.uid, version_id)
                }
                None => self.handles.open(retry.inode, libc::O_RDWR, inode.uid),
            };
            if retry.handle_id != fh {
                let mut rebound = retry.clone();
                rebound.handle_id = fh;
                self.sdo_pending_write_store().put(&rebound).map_err(|error| {
                    tracing::error!(%error, version_id = %retry.version_id, "pending-write retry binding failed");
                    libc::EIO
                })?;
            }
            self.handles.insert_handle_buffer(fh, retry.bytes.clone());
            match self.persist_handle_buffer(retry.inode, fh) {
                Ok(()) => completed += 1,
                Err(error) => {
                    tracing::warn!(ino = retry.inode, version_id = %retry.version_id, errno = error, "pending portable write remains queued for retry")
                }
            }
            self.handles.close(fh);
        }
        Ok(completed)
    }

    fn recover_portable_outbox_record(
        &mut self,
        retry: &SdoPendingWrite,
    ) -> std::result::Result<(), libc::c_int> {
        let context = self.sdo_context.ok_or(libc::EIO)?;
        let wire = if let Some(wire) = &retry.wire {
            wire.clone()
        } else {
            let mut metadata = teagarden_core::sdo::SdoObjectMetadataV3::decode_snapshot(
                retry.metadata_snapshot.as_deref().ok_or(libc::EIO)?,
            )
            .map_err(|_| libc::EIO)?;
            metadata.key_generation = self.sdo_key_generation;
            let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
                context.volume_id,
                self.sdo_key_generation,
                self.sdo_meta_key_for_generation(self.sdo_key_generation),
                metadata,
                &retry.bytes,
                self.sdo_signing_key.as_ref(),
            )
            .map_err(|_| libc::EIO)?;
            self.seal_sdo_object(wire).map_err(|_| libc::EIO)?
        };
        #[cfg(feature = "key-rotation")]
        let mut wire = wire;
        let generation = wire
            .get(22..30)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .ok_or(libc::EIO)?;
        let object = teagarden_core::sdo::SdoFileObjectV3::decode(
            &wire,
            context.volume_id,
            generation,
            self.sdo_meta_key_for_generation(generation),
        )
        .map_err(|_| libc::EIO)?;
        #[cfg(feature = "key-rotation")]
        let mut object = object;
        if object.metadata.author_device_id != context.author_device_id {
            return Err(libc::EPERM);
        }
        if self.sdo_policy()?.is_some_and(|policy| {
            policy
                .revoked_device_ids
                .contains(&context.author_device_id)
        }) {
            return Err(libc::EPERM);
        }
        if generation != self.sdo_key_generation {
            #[cfg(not(feature = "key-rotation"))]
            return Err(libc::ENOTSUP);
            #[cfg(feature = "key-rotation")]
            {
                if object.metadata.authority.is_none() {
                    if let Some(signer) = &self.sdo_signing_key {
                        object
                            .metadata
                            .sign_authority(context.volume_id, signer, &object.content)
                            .map_err(|_| libc::EIO)?;
                    }
                }
                if self.sdo_policy()?.is_some_and(|policy| {
                    !teagarden_core::sdo::object_transition_is_acceptable(
                        &policy,
                        &object.metadata,
                        i64::MAX,
                    )
                }) {
                    return Err(libc::EPERM);
                }
                object.metadata.key_generation = self.sdo_key_generation;
                wire = self
                    .seal_sdo_object(
                        teagarden_core::sdo::SdoFileObjectV3::encode(
                            context.volume_id,
                            self.sdo_key_generation,
                            self.sdo_meta_key_for_generation(self.sdo_key_generation),
                            object.metadata.clone(),
                            &object.content,
                        )
                        .map_err(|_| libc::EIO)?,
                    )
                    .map_err(|_| libc::EIO)?;
            }
        }
        let mut exact_retry = retry.clone();
        exact_retry.wire = Some(wire.clone());
        self.sdo_pending_write_store()
            .put(&exact_retry)
            .map_err(|_| libc::EIO)?;
        let transport = self.transport.as_ref().ok_or(libc::EIO)?.clone();
        let rt = self.rt.as_ref().ok_or(libc::EIO)?;
        let mut source = teagarden_telegram::transfer::SliceSource::new(&wire);
        let uploaded = rt
            .block_on(transport.upload_file_source(
                &mut source,
                "teagarden-file-v3.tgf",
                self.upload_timeout,
            ))
            .map_err(|_| libc::EIO)?;
        if uploaded.size != wire.len() {
            return Err(libc::EIO);
        }
        if !Self::sdo_header_allowed(
            self.sdo_policy()?.as_ref(),
            &decode_stored_sdo_header(
                &wire,
                context.volume_id,
                &self.meta_key,
                &self.sdo_generation_meta_keys,
            )
            .map_err(|_| libc::EIO)?,
            i64::MAX,
        ) {
            return Err(libc::EPERM);
        }
        #[cfg(feature = "key-rotation")]
        if let Some(previous) = self
            .sdo_version_store()
            .get(retry.version_id.as_bytes())
            .map_err(|_| libc::EIO)?
        {
            let previous_header = decode_stored_sdo_header(
                &previous.wire,
                context.volume_id,
                &self.meta_key,
                &self.sdo_generation_meta_keys,
            )
            .map_err(|_| libc::EIO)?;
            #[cfg(feature = "key-rotation")]
            if previous_header.key_generation() < self.sdo_key_generation
                && previous.message_id != uploaded.message_id
            {
                rt.block_on(async {
                    tokio::time::timeout(
                        self.upload_timeout,
                        transport.delete_message(previous.message_id),
                    )
                    .await
                })
                .map_err(|_| libc::EIO)?
                .map_err(|_| libc::EIO)?;
            }
        }
        let header_length = u32::from_le_bytes(wire[30..34].try_into().unwrap()) as usize;
        let cursor = SdoCursorStore::new(&self.conn, &self.schema)
            .get()
            .map_err(|_| libc::EIO)?
            .map_or(0, |(cursor, _)| cursor);
        self.apply_remote_sdo_batch(
            vec![(uploaded.message_id, wire[..34 + header_length].to_vec())],
            cursor,
        )
        .map_err(|_| libc::EIO)?;
        self.sdo_pending_write_store()
            .delete(&retry.version_id)
            .map_err(|_| libc::EIO)?;
        Ok(())
    }

    /// Apply a complete, ascending remote topic batch through this FUSE-owned
    /// SQLite connection. New version rows, the reduced namespace, HLC
    /// observation and cursor advancement commit as one transaction.
    pub fn apply_remote_sdo_batch(
        &mut self,
        objects: Vec<(i64, Vec<u8>)>,
        high_water_id: i64,
    ) -> std::result::Result<usize, libc::c_int> {
        let context = self.sdo_context.ok_or(libc::EINVAL)?;
        let key = self.manifest_key.as_ref().ok_or(libc::EIO)?;
        let policy = self.sdo_policy()?;
        let tx = self.conn.transaction().map_err(|error| {
            tracing::error!(%error, "start remote SDO apply transaction failed");
            libc::EIO
        })?;
        let version_store = SdoVersionStore::new(&tx, &self.schema);
        let mut metadata = std::collections::HashMap::<uuid::Uuid, PortableVersionRecord>::new();
        let mut records = Vec::new();
        let existing = version_store.list_all().map_err(|error| {
            tracing::error!(%error, "list local SDO history before remote apply failed");
            libc::EIO
        })?;
        for stored in existing {
            let header = decode_stored_sdo_header(
                &stored.wire,
                context.volume_id,
                &self.meta_key,
                &self.sdo_generation_meta_keys,
            )
            .map_err(|error| {
                tracing::error!(%error, "authenticate stored SDO during remote apply failed");
                libc::EIO
            })?;
            if !Self::sdo_header_allowed(policy.as_ref(), &header, stored.message_id) {
                continue;
            }
            let version = header.portable_record()?;
            if metadata
                .insert(version.record.version_id, version.clone())
                .is_some_and(|previous| previous != version)
            {
                tracing::error!("local SDO history contains conflicting version UUID metadata");
                return Err(libc::EIO);
            }
            records.push(version.record);
        }

        let mut inserted = 0;
        let mut remote_clocks = Vec::new();
        for (message_id, wire) in objects {
            let header = decode_stored_sdo_header(
                &wire,
                context.volume_id,
                &self.meta_key,
                &self.sdo_generation_meta_keys,
            )
            .map_err(|error| {
                tracing::error!(message_id, %error, "authenticate remote SDO header failed");
                libc::EIO
            })?;
            if !Self::sdo_header_allowed(policy.as_ref(), &header, message_id) {
                continue;
            }
            let version = header.portable_record()?;
            let version_id = version.record.version_id;
            if let Some(previous) = metadata.get(&version_id) {
                if previous != &version {
                    tracing::error!(message_id, %version_id, "remote SDO version UUID has conflicting plaintext metadata");
                    return Err(libc::EIO);
                }
                let previous_location = version_store
                    .get(version_id.as_bytes())
                    .map_err(|_| libc::EIO)?
                    .ok_or(libc::EIO)?;
                let previous_header = decode_stored_sdo_header(
                    &previous_location.wire,
                    context.volume_id,
                    &self.meta_key,
                    &self.sdo_generation_meta_keys,
                )
                .map_err(|_| libc::EIO)?;
                if header.key_generation() > previous_header.key_generation() {
                    #[cfg(not(feature = "key-rotation"))]
                    return Err(libc::ENOTSUP);
                    #[cfg(feature = "key-rotation")]
                    {
                        version_store
                        .replace_location(version_id.as_bytes(), message_id, &wire)
                        .map_err(|error| {
                            tracing::error!(%error, "replace migrated SDO version routing failed");
                            libc::EIO
                        })?;
                    }
                }
                continue;
            }
            let path_id = keyed_hash(
                key,
                &[
                    b"teagarden.sdo.path.v1".as_slice(),
                    version.record.path.as_bytes(),
                ]
                .concat(),
            );
            version_store
                .insert(
                    version_id.as_bytes(),
                    &StoredSdoVersion {
                        path_id,
                        ino: 0,
                        message_id,
                        wire,
                    },
                )
                .map_err(|error| {
                    tracing::error!(%error, "store remote SDO header failed");
                    libc::EIO
                })?;
            records.push(version.record.clone());
            remote_clocks.push((version.record.clock_ms, version.record.clock_counter));
            metadata.insert(version_id, version);
            inserted += 1;
        }
        let view = teagarden_core::sdo::reduce_records(records).map_err(|error| {
            tracing::error!(%error, "reduce remote SDO history failed");
            libc::EIO
        })?;

        let mut all_paths = std::collections::BTreeSet::new();
        for version in metadata.values() {
            if matches!(
                version.record.kind,
                teagarden_core::sdo::SdoKind::File | teagarden_core::sdo::SdoKind::Directory
            ) {
                let components: Vec<_> = version.record.path.split('/').collect();
                let mut prefix = String::new();
                for component in components.iter().take(components.len().saturating_sub(1)) {
                    if !prefix.is_empty() {
                        prefix.push('/');
                    }
                    prefix.push_str(component);
                    all_paths.insert(prefix.clone());
                }
                all_paths.insert(version.record.path.clone());
            }
        }
        let winners: std::collections::BTreeMap<_, _> = all_paths
            .iter()
            .filter_map(|path| {
                view.winner(path)
                    .filter(|_| view.is_visible(path))
                    .map(|winner| (path.clone(), winner.clone()))
            })
            .collect();

        let inode_store = InodeStore::new(&tx, &self.schema, &self.meta_key);
        let all_inodes = inode_store.list_all().map_err(|error| {
            tracing::error!(%error, "list inodes before remote SDO apply failed");
            libc::EIO
        })?;
        let by_ino: std::collections::HashMap<_, _> = all_inodes
            .iter()
            .cloned()
            .map(|inode| (inode.ino, inode))
            .collect();
        let mut path_inos = std::collections::BTreeMap::<String, u64>::new();
        for inode in &all_inodes {
            if inode.ino == 1 {
                continue;
            }
            let mut current = inode;
            let mut parts = Vec::new();
            let mut seen = std::collections::HashSet::new();
            while current.ino != 1 && current.parent != 0 && seen.insert(current.ino) {
                parts.push(current.name.clone());
                let Some(parent) = by_ino.get(&current.parent) else {
                    break;
                };
                current = parent;
            }
            if current.ino == 1 {
                parts.reverse();
                path_inos.insert(parts.join("/"), inode.ino);
            }
        }

        let mut chosen = std::collections::BTreeMap::<String, (u64, bool)>::new();
        for (path, winner) in &winners {
            let (parent_path, name) = path
                .rsplit_once('/')
                .map_or(("", path.as_str()), |(parent, name)| (parent, name));
            let parent_ino = if parent_path.is_empty() {
                1
            } else {
                chosen.get(parent_path).ok_or(libc::EIO)?.0
            };
            let is_dir = winner.kind == teagarden_core::sdo::SdoKind::Directory;
            let source = metadata.get(&winner.version_id);
            let existing_ino = path_inos.get(path).copied();
            let existing_inode = existing_ino
                .and_then(|ino| by_ino.get(&ino).cloned())
                .filter(|inode| inode.is_dir() == is_dir);
            let is_new = existing_inode.is_none();
            let mut inode = if let Some(inode) = existing_inode {
                inode
            } else {
                let ino = inode_store.next_ino().map_err(|_| libc::EIO)?;
                if is_dir {
                    Inode::new_dir(ino, parent_ino, name.to_owned(), 0o755, self.uid, self.gid)
                } else {
                    Inode::new_file(ino, parent_ino, name.to_owned(), 0o644, self.uid, self.gid)
                }
            };
            inode.parent = parent_ino;
            inode.name = name.to_owned();
            inode.children.clear();
            inode.nlink = if is_dir { 2 } else { 1 };
            if let Some(source) = source {
                inode.mode = source.mode;
                inode.size = source.size;
                let ns = i128::from(source.mtime_ns);
                inode.timestamps.mtime_ns = ns;
                if !is_dir {
                    SdoIdentityStore::new(&tx, &self.schema, &self.meta_key)
                        .set(
                            inode.ino,
                            &SdoFileIdentity {
                                file_id: source.file_id,
                                origin_message_id: source.origin_message_id,
                                latest_version_id: Some(winner.version_id),
                                local_version: source.local_version,
                            },
                        )
                        .map_err(|error| {
                            tracing::error!(%error, "update remote SDO identity failed");
                            libc::EIO
                        })?;
                }
            } else if is_dir {
                SdoIdentityStore::new(&tx, &self.schema, &self.meta_key)
                    .delete(inode.ino)
                    .map_err(|_| libc::EIO)?;
            }
            if is_new {
                inode_store.insert(&inode).map_err(|_| libc::EIO)?;
            } else {
                inode_store.update(&inode).map_err(|_| libc::EIO)?;
            }
            chosen.insert(path.clone(), (inode.ino, is_dir));
        }

        let active_inos: std::collections::HashSet<_> =
            chosen.values().map(|(ino, _)| *ino).collect();
        for mut inode in all_inodes.into_iter().filter(|inode| inode.ino != 1) {
            if !active_inos.contains(&inode.ino) && inode.parent != 0 {
                inode.parent = 0;
                inode.children.clear();
                inode_store.update(&inode).map_err(|_| libc::EIO)?;
            }
        }
        let mut children = std::collections::HashMap::<u64, Vec<u64>>::new();
        let mut dir_links = std::collections::HashMap::<u64, u32>::new();
        for (path, (ino, is_dir)) in &chosen {
            let (parent_path, _) = path.rsplit_once('/').map_or(("", ""), |(p, n)| (p, n));
            let parent = if parent_path.is_empty() {
                1
            } else {
                chosen[parent_path].0
            };
            children.entry(parent).or_default().push(*ino);
            if *is_dir {
                *dir_links.entry(parent).or_default() += 1;
            }
        }
        for parent_ino in std::iter::once(1).chain(
            chosen
                .values()
                .filter_map(|(ino, is_dir)| is_dir.then_some(*ino)),
        ) {
            if let Some(mut parent) = inode_store.get(parent_ino).map_err(|_| libc::EIO)? {
                parent.children = children.remove(&parent_ino).unwrap_or_default();
                parent.nlink = 2 + dir_links.get(&parent_ino).copied().unwrap_or(0);
                inode_store.update(&parent).map_err(|_| libc::EIO)?;
            }
        }

        let mut next_clock = *self
            .sdo_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        for (remote_ms, remote_counter) in remote_clocks {
            next_clock
                .receive(remote_ms, remote_counter, now_ms)
                .map_err(|error| {
                    tracing::error!(%error, "observe remote SDO clock failed");
                    libc::EIO
                })?;
        }
        let (clock_ms, clock_counter) = next_clock.as_pair();
        SdoClockStore::new(&tx, &self.schema)
            .set(clock_ms, clock_counter)
            .map_err(|_| libc::EIO)?;
        let cursor_store = SdoCursorStore::new(&tx, &self.schema);
        if cursor_store.get().map_err(|_| libc::EIO)?.is_some_and(
            |(cursor, previous_high_water)| {
                high_water_id < cursor || high_water_id < previous_high_water
            },
        ) {
            return Err(libc::EAGAIN);
        }
        cursor_store
            .set(high_water_id, high_water_id)
            .map_err(|_| libc::EIO)?;
        tx.commit().map_err(|error| {
            tracing::error!(%error, "commit remote SDO batch failed");
            libc::EIO
        })?;
        *self
            .sdo_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next_clock;
        if let Some(slot) = &self.sdo_notifier {
            if let Some(notifier) = slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                for path in &all_paths {
                    if let Some((ino, _)) = chosen.get(path) {
                        if let Err(error) = notifier.inval_inode(*ino, 0, -1) {
                            tracing::debug!(ino, %error, "invalidate remote SDO inode cache failed");
                        }
                    }
                    let (parent_path, name) = path
                        .rsplit_once('/')
                        .map_or(("", path.as_str()), |(parent, name)| (parent, name));
                    let parent = if parent_path.is_empty() {
                        1
                    } else {
                        chosen.get(parent_path).map_or(1, |(parent, _)| *parent)
                    };
                    if let Err(error) = notifier.inval_entry(parent, OsStr::new(name)) {
                        tracing::debug!(parent, name, %error, "invalidate remote SDO directory entry cache failed");
                    }
                }
            }
        }
        Ok(inserted)
    }

    fn apply_pending_sdo_poll(&mut self) -> std::result::Result<(), libc::c_int> {
        let batch = match self.sdo_poll_rx.as_mut() {
            Some(receiver) => match receiver.try_recv() {
                Ok(batch) => batch,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return Ok(()),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return Ok(()),
            },
            None => return Ok(()),
        };
        let previous_generation = batch.generation_update.as_ref().map(|_| {
            (
                self.sdo_key_generation,
                self.sdo_generation_boundary,
                self.sdo_generation_meta_keys.clone(),
                self.sdo_object_envelope.clone(),
            )
        });
        if let Some(update) = batch.generation_update {
            self.sdo_key_generation = update.active_generation;
            self.sdo_generation_boundary = update.boundary_message_id;
            self.sdo_generation_meta_keys = update.generation_meta_keys;
            if let Some(envelope) = update.object_envelope {
                self.sdo_object_envelope = Some(envelope);
            }
        }
        let result = self
            .apply_remote_sdo_batch(batch.objects, batch.high_water_id)
            .map(|_| ());
        if result.is_err() {
            if let Some((generation, boundary, keys, envelope)) = previous_generation {
                self.sdo_key_generation = generation;
                self.sdo_generation_boundary = boundary;
                self.sdo_generation_meta_keys = keys;
                self.sdo_object_envelope = envelope;
            }
        }
        let _ = batch.ack.send(result);
        result
    }

    /// Refuse all mutating FUSE ops (EROFS). Used for read-only shares.
    pub fn with_read_only(mut self, ro: bool) -> Self {
        self.read_only = ro;
        self
    }

    /// The FUSE generation currently in use for inode number `ino` (see the
    /// `generations` field).
    pub fn generation(&self, ino: u64) -> u64 {
        self.generations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&ino)
            .copied()
            .unwrap_or(0)
    }

    /// Inode `ino` was deleted: refuse further data operations through handles
    /// opened on it, drop its unpersisted buffer, and bump the generation so a
    /// file that later reuses the number is a different inode to the kernel.
    fn forget_deleted_inode(&self, ino: u64) {
        self.handles.mark_stale(ino);
        self.handles.discard_buffer(ino);
        let mut gens = self
            .generations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let g = gens.entry(ino).or_insert(0);
        *g = g.wrapping_add(1);
    }

    /// `Err(ESTALE)` if `fh` is a handle on a deleted file (see
    /// [`crate::handle::FileHandle::stale`]); `Ok` for a live or absent handle.
    pub fn check_handle_live(&self, fh: Option<u64>) -> std::result::Result<(), libc::c_int> {
        match fh.and_then(|fh| self.handles.get(fh)) {
            Some(h) if h.stale => Err(libc::ESTALE),
            _ => Ok(()),
        }
    }

    /// Bound each portable part request (default 120 s), with no object deadline.
    /// Legacy block transports also use this as their individual block deadline.
    pub fn with_upload_timeout(mut self, timeout: Duration) -> Self {
        self.upload_timeout = timeout;
        self
    }

    /// Set the block transport (enables Telegram I/O).
    pub fn with_transport(mut self, transport: Arc<dyn BlockTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Set the block cache.
    pub fn with_cache(mut self, cache: Arc<BlockCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the tokio runtime handle for async dispatch.
    pub fn with_runtime(mut self, rt: tokio::runtime::Handle) -> Self {
        self.rt = Some(rt);
        self
    }

    /// Enable the background upload queue for parallel chunk uploads.
    ///
    /// Spawns a worker task on the tokio runtime that accepts `PendingUpload`
    /// messages and dispatches each one as a separate tokio task against the
    /// transport, allowing multiple Telegram uploads to be in-flight concurrently.
    ///
    /// Must be called after `with_transport` and `with_runtime`.
    /// When not called, `release()` falls back to inline `rt.block_on(...)` uploads.
    pub fn with_upload_queue(mut self) -> Self {
        let transport = match &self.transport {
            Some(t) => t.clone(),
            None => return self, // no transport — queue has nothing to dispatch to
        };
        let rt = match &self.rt {
            Some(r) => r.clone(),
            None => return self, // no runtime — can't spawn worker
        };

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PendingUpload>();

        // Payload bytes, reserved by the producer, provide backpressure. There
        // is no request-count or network-rate cap on this existing connection.
        rt.spawn(async move {
            while let Some(pending) = rx.recv().await {
                let transport = transport.clone();
                tokio::task::spawn(async move {
                    let _memory = pending._memory;
                    let result = match tokio::time::timeout(
                        pending.timeout,
                        transport.upload_block(&pending.ciphertext, &pending.filename),
                    )
                    .await
                    {
                        Ok(r) => r.map(|r| r.message_id).map_err(|e| e.to_string()),
                        Err(_) => Err(format!("upload timed out after {:?}", pending.timeout)),
                    };
                    // result_tx.send() fails only if the receiver was dropped (FUSE thread timed out)
                    let _ = pending.result_tx.send(result);
                });
            }
        });

        self.upload_tx = Some(tx);
        self
    }

    /// Open an `InodeStore` view over this volume's connection, schema, and metadata key.
    pub fn store(&self) -> InodeStore<'_> {
        InodeStore::new(&self.conn, &self.schema, &self.meta_key)
    }

    /// Begin a SQLite transaction for multi-step mutations.
    fn begin_txn(&self) -> std::result::Result<(), libc::c_int> {
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(|e| {
            tracing::error!(error = %e, "begin transaction failed");
            libc::EIO
        })
    }

    /// Commit a SQLite transaction.
    fn commit_txn(&self) -> std::result::Result<(), libc::c_int> {
        self.conn.execute_batch("COMMIT").map_err(|e| {
            tracing::error!(error = %e, "commit transaction failed");
            libc::EIO
        })
    }

    /// Rollback a SQLite transaction.
    fn rollback_txn(&self) {
        let _ = self.conn.execute_batch("ROLLBACK");
    }

    /// Run `f` inside an explicit transaction with metadata-journal capture.
    ///
    /// When journaling is active (journal + transport + runtime all set), a SQLite
    /// session records every change `f` makes; on success the changeset is
    /// published to the channel as an encrypted delta and the HMAC'd HEAD floor is
    /// advanced — both BEFORE the local `COMMIT`. This is fail-closed: a crash
    /// between the floor write and the commit leaves the floor *ahead* of the DB
    /// (recoverable on next mount), never behind (which would orphan committed
    /// metadata). If the delta publish or HEAD persist fails, the whole write is
    /// rolled back and `EIO` is returned — the application learns the write did
    /// not durably land, exactly as a failed block upload already behaves.
    ///
    /// Without journaling it is a plain `BEGIN`/`COMMIT` transaction.
    ///
    /// `f` must perform ONLY `&self` DB mutations (via the stores). Any `&mut self`
    /// work (the handle table, kernel replies) must stay OUTSIDE this call.
    fn journaled_txn<T>(
        &self,
        f: impl FnOnce() -> Result<T, libc::c_int>,
    ) -> Result<T, libc::c_int> {
        // Plain transaction when journaling is not fully wired (offline volume).
        let (journal, transport, rt) = match (&self.journal, &self.transport, &self.rt) {
            (Some(j), Some(t), Some(rt)) => (j, t, rt),
            _ => {
                self.begin_txn()?;
                return match f() {
                    Ok(v) => self.commit_txn().map(|()| v),
                    Err(e) => {
                        self.rollback_txn();
                        Err(e)
                    }
                };
            }
        };

        // A prior local COMMIT failure left the on-disk floor ahead of an
        // indeterminate DB. Refuse further writes so we never compound the
        // divergence; a remount rebuilds a consistent DB from the channel.
        if journal.poisoned.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::error!("journal poisoned by a prior commit failure — refusing write (EIO)");
            return Err(libc::EIO);
        };

        // Attach a session BEFORE the mutations so it records them.
        let mut session = rusqlite::session::Session::new(&self.conn).map_err(|e| {
            tracing::error!(error = %e, "journal: session create failed");
            libc::EIO
        })?;
        if let Err(e) = session.attach(None::<&str>) {
            tracing::error!(error = %e, "journal: session attach failed");
            return Err(libc::EIO);
        }

        self.begin_txn()?;
        let value = match f() {
            Ok(v) => v,
            Err(e) => {
                self.rollback_txn();
                return Err(e);
            }
        };

        // Capture the changeset of f's mutations (still inside the open txn).
        let mut changeset = Vec::new();
        if let Err(e) = session.changeset_strm(&mut changeset) {
            tracing::error!(error = %e, "journal: changeset capture failed");
            self.rollback_txn();
            return Err(libc::EIO);
        }

        // No metadata changed (read-only / no-op) — nothing to journal.
        if changeset.is_empty() {
            return self.commit_txn().map(|()| value);
        }

        // Build the delta on top of the running HEAD.
        let mut head = journal
            .head
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next_seq = match head.seq.checked_add(1) {
            Some(s) => s,
            None => {
                tracing::error!("journal: seq overflow");
                self.rollback_txn();
                return Err(libc::EIO);
            }
        };
        // Bind the delta to its predecessor's exact bytes. A HEAD written before
        // HEADs recorded that hash (format v1, with deltas) gets it once from the
        // channel; every HEAD written from here on carries it.
        let prev_hash = match head.chain_hash() {
            Some(h) => h,
            None => {
                let fetched = rt.block_on(async {
                    tokio::time::timeout(
                        TRANSPORT_TIMEOUT,
                        transport.fetch_metadata(head.parent_msg_id),
                    )
                    .await
                });
                match fetched {
                    Ok(Ok(blob)) => teagarden_core::volume::metadata_journal::blob_hash(&blob),
                    _ => {
                        tracing::error!("journal: could not fetch the previous delta to bind it");
                        self.rollback_txn();
                        return Err(libc::EIO);
                    }
                }
            }
        };
        let delta_header = DeltaHeader {
            seq: next_seq,
            base_snapshot_version: head.base_snapshot_version,
            parent_msg_id: head.parent_msg_id,
            prev_hash: Some(prev_hash),
        };
        let blob = match encrypt_delta(&self.data_key, delta_header, &changeset) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "journal: delta encryption failed");
                self.rollback_txn();
                return Err(libc::EIO);
            }
        };

        // The DB records the journal position this transaction produces, in
        // the same transaction (its session record is never journaled): a
        // publish proves by it that the file it reads holds every entry the
        // HEAD names (`local_db::SessionRecord`).
        if let Err(e) =
            teagarden_store::local_db::set_session_seq(&self.conn, &self.schema, next_seq)
        {
            tracing::error!(error = %e, "journal: recording the journal position failed");
            self.rollback_txn();
            return Err(libc::EIO);
        }

        // Publish the delta (durable in the channel) BEFORE committing locally.
        // If the publish fails or times out, Telegram may still have stored it; the
        // next write then reuses this seq and parent, but its blob (fresh nonce,
        // its own changeset) has a different hash, and only that hash reaches the
        // HEAD, so the orphan can never be accepted in its place.
        let publish = rt.block_on(async {
            tokio::time::timeout(TRANSPORT_TIMEOUT, transport.sync_metadata(&blob)).await
        });
        let msg_id = match publish {
            Ok(Ok(id)) => id,
            _ => {
                tracing::error!("journal: delta publish failed; rolling back write");
                self.rollback_txn();
                return Err(libc::EIO);
            }
        };

        // Advance + persist the HMAC'd HEAD floor BEFORE the local COMMIT.
        let new_head = JournalHead {
            seq: next_seq,
            parent_msg_id: msg_id,
            base_snapshot_version: head.base_snapshot_version,
            base_snapshot_msg_id: head.base_snapshot_msg_id,
            base_snapshot_hash: head.base_snapshot_hash,
            last_hash: Some(teagarden_core::volume::metadata_journal::blob_hash(&blob)),
            // The DB's lineage stamp is outside the journal: an entry never
            // changes which state the DB descends from.
            lineage: head.lineage,
        };
        if let Err(e) = new_head.store_atomic(&journal.head_path, &journal.integrity_key) {
            tracing::error!(error = %e, "journal: HEAD persist failed; rolling back write");
            self.rollback_txn();
            return Err(libc::EIO);
        }
        *head = new_head;
        drop(head);

        // The delta is published and the floor persisted. If the local COMMIT now
        // fails, the on-disk floor is ahead of an indeterminate DB. That is
        // recoverable on remount (the channel has deltas 1..=seq), but we must not
        // keep writing against the diverged DB — poison the journal so further
        // transactions refuse with EIO.
        match self.commit_txn() {
            Ok(()) => {
                self.session_checkpoint(teagarden_store::local_db::SESSION_CHECKPOINT_PAGES);
                Ok(value)
            }
            Err(e) => {
                tracing::error!("journal: local COMMIT failed after publish — poisoning journal");
                journal
                    .poisoned
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Open a `BlockStore` view over this volume's connection and schema.
    pub fn block_store(&self) -> BlockStore<'_> {
        BlockStore::new(&self.conn, &self.schema)
    }

    /// Open a `DagStore` view over this volume's connection and schema.
    pub fn dag_store(&self) -> DagStore<'_> {
        DagStore::new(&self.conn, &self.schema)
    }

    /// Open a `ManifestStore` view over this volume's connection, schema, and metadata key.
    pub fn manifest_store(&self) -> ManifestStore<'_> {
        ManifestStore::new(&self.conn, &self.schema, &self.meta_key)
    }

    fn sdo_version_store(&self) -> SdoVersionStore<'_> {
        SdoVersionStore::new(&self.conn, &self.schema)
    }

    fn sdo_identity_store(&self) -> SdoIdentityStore<'_> {
        SdoIdentityStore::new(&self.conn, &self.schema, &self.meta_key)
    }

    fn sdo_clock_store(&self) -> SdoClockStore<'_> {
        SdoClockStore::new(&self.conn, &self.schema)
    }

    fn sdo_pending_write_store(&self) -> SdoPendingWriteStore<'_> {
        match &self.sdo_outbox {
            Some((conn, schema, key)) => SdoPendingWriteStore::new(conn, schema, key),
            None => SdoPendingWriteStore::new(&self.conn, &self.schema, &self.meta_key),
        }
    }

    fn opened_sdo_identity(
        &self,
        ino: u64,
        handle: &crate::handle::FileHandle,
        captured: Option<&[u8]>,
    ) -> std::result::Result<Option<SdoFileIdentity>, libc::c_int> {
        if let Some(snapshot) = captured {
            let metadata = teagarden_core::sdo::SdoObjectMetadataV3::decode_snapshot(snapshot)
                .map_err(|_| libc::EIO)?;
            return Ok(Some(SdoFileIdentity {
                file_id: metadata.file_id,
                origin_message_id: metadata.origin_message_id,
                latest_version_id: metadata.previous_version_id,
                local_version: metadata.local_version.saturating_sub(1),
            }));
        }
        if let Some(pinned) = handle.pinned_sdo_version {
            let stored = self
                .sdo_version_store()
                .get(pinned.as_bytes())
                .map_err(|_| libc::EIO)?
                .ok_or(libc::EIO)?;
            let context = self.sdo_context.ok_or(libc::EIO)?;
            let header = decode_stored_sdo_header(
                &stored.wire,
                context.volume_id,
                &self.meta_key,
                &self.sdo_generation_meta_keys,
            )
            .map_err(|_| libc::EIO)?;
            let version = header.portable_record()?;
            return Ok(Some(SdoFileIdentity {
                file_id: version.file_id,
                origin_message_id: version.origin_message_id,
                latest_version_id: Some(pinned),
                local_version: version.local_version,
            }));
        }
        self.sdo_identity_store().get(ino).map_err(|_| libc::EIO)
    }

    fn stage_portable_write(
        &self,
        inode: u64,
        handle: &crate::handle::FileHandle,
        initialized: bool,
    ) -> std::result::Result<(), libc::c_int> {
        if self.handles.spool(true, handle.fh).is_some() {
            return Ok(());
        }
        if !self.sdo_clock_loaded {
            return Err(libc::EIO);
        }
        let utc_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let (clock_ms, clock_counter) = self
            .sdo_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tick(utc_ms)
            .map_err(|_| libc::EIO)?;
        self.sdo_clock_store()
            .set(clock_ms, clock_counter)
            .map_err(|e| {
                tracing::error!(%e,"portable spool HLC persistence failed");
                libc::EIO
            })?;
        let version_id = uuid::Uuid::new_v4();
        let current = self
            .store()
            .get(inode)
            .map_err(|_| libc::EIO)?
            .ok_or(libc::ENOENT)?;
        let identity = self.opened_sdo_identity(inode, handle, None)?;
        let context = self.sdo_context.ok_or(libc::EIO)?;
        let snapshot = teagarden_core::sdo::SdoObjectMetadataV3 {
            authority: None,
            migration_receipt: None,
            file_id: identity.map_or_else(uuid::Uuid::new_v4, |identity| identity.file_id),
            origin_message_id: identity.and_then(|identity| identity.origin_message_id),
            path: Some(self.path_for_inode(inode)?),
            size: 0,
            mtime_ns: current.timestamps.mtime_ns as i64,
            mode: current.mode,
            version_id,
            author_device_id: context.author_device_id,
            previous_version_id: identity.and_then(|identity| identity.latest_version_id),
            kind: teagarden_core::sdo::SdoKind::File,
            key_generation: self.sdo_key_generation,
            clock_ms,
            clock_counter,
            saved_at_ns: system_time_to_ns(SystemTime::now()) as i64,
            local_version: identity.map_or(1, |identity| identity.local_version.saturating_add(1)),
            deleted: false,
            installation_id: None,
            label: None,
            telegram_user_id: None,
            authorization_session_hash: None,
            created_at_ms: None,
            device_public_key: None,
            device_key_update: None,
            segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
            segment_count: 0,
            content_sha256: String::new(),
        };
        let mut spool = crate::spool::WriteSpool::create(
            &self.spool_root(),
            self.spool_key().clone(),
            self.manifest_key.as_ref().ok_or(libc::EIO)?,
            snapshot,
            inode,
            handle.fh,
        )
        .map_err(|e| {
            tracing::error!(%e,"create write spool");
            libc::EIO
        })?;
        if initialized {
            spool.finish_initialization().map_err(|_| libc::EIO)?;
        }
        self.handles.insert_spool(true, handle.fh, spool);
        Ok(())
    }

    fn spool_root(&self) -> std::path::PathBuf {
        let conn = self
            .sdo_outbox
            .as_ref()
            .map_or(&self.conn, |(conn, _, _)| conn);
        conn.path()
            .filter(|p| !p.is_empty())
            .and_then(|p| std::path::Path::new(p).parent())
            .map_or_else(
                || self.transient_spool_root.clone(),
                |p| p.join("write-spools"),
            )
    }
    fn spool_key(&self) -> &SymmetricKey {
        self.sdo_outbox
            .as_ref()
            .map_or(&self.meta_key, |(_, _, key)| key)
    }

    fn ensure_spool(
        &self,
        ino: u64,
        handle: &crate::handle::FileHandle,
    ) -> std::result::Result<(), libc::c_int> {
        let portable = self.sdo_context.is_some();
        let id = if portable { handle.fh } else { ino };
        if self.handles.spool(portable, id).is_some() {
            return Ok(());
        }
        if portable {
            self.stage_portable_write(ino, handle, false)?;
        } else {
            let metadata:teagarden_core::sdo::SdoObjectMetadataV3=serde_json::from_value(serde_json::json!({
                "file_id":uuid::Uuid::new_v4(),"path":self.path_for_inode(ino)?,"size":0,"mtime_ns":0,"mode":384,
                "version_id":uuid::Uuid::new_v4(),"author_device_id":uuid::Uuid::nil(),"kind":"file","key_generation":0,"clock_ms":0,"clock_counter":0,"saved_at_ns":0,"local_version":1,"deleted":false,"segment_size":1048576,"segment_count":0,"content_sha256":""})).map_err(|_|libc::EIO)?;
            let spool = crate::spool::WriteSpool::create(
                &self.spool_root(),
                self.spool_key().clone(),
                self.manifest_key.as_ref().ok_or(libc::EIO)?,
                metadata,
                ino,
                handle.fh,
            )
            .map_err(|_| libc::EIO)?;
            self.handles.insert_spool(false, ino, spool);
        }
        let spool = self.handles.spool(portable, id).ok_or(libc::EIO)?;
        let result = (|| {
            let mut spool = spool.lock().map_err(|_| libc::EIO)?;
            if portable {
                if let Some(version) = self
                    .opened_sdo_identity(ino, handle, None)?
                    .and_then(|identity| identity.latest_version_id)
                {
                    let context = self.sdo_context.ok_or(libc::EIO)?;
                    let stored = self
                        .sdo_version_store()
                        .get(version.as_bytes())
                        .map_err(|_| libc::EIO)?
                        .ok_or(libc::EIO)?;
                    let header = decode_stored_sdo_header(
                        &stored.wire,
                        context.volume_id,
                        &self.meta_key,
                        &self.sdo_generation_meta_keys,
                    )
                    .map_err(|_| libc::EIO)?;
                    let mut offset = 0;
                    while offset < header.size() {
                        let n = (header.size() - offset).min(1024 * 1024);
                        let bytes =
                            self.read_sdo_stored_range(ino, version, stored.clone(), offset, n)?;
                        spool.write(offset, &bytes).map_err(|_| libc::EIO)?;
                        offset += n;
                        #[cfg(test)]
                        if offset == 1024 * 1024
                            && std::env::var_os("TEAGARDEN_TEST_SEED_CRASH_ROOT").is_some_and(
                                |root| self.spool_root().as_path() == std::path::Path::new(&root),
                            )
                        {
                            std::fs::write(self.spool_root().join("seed-paused"), b"ready")
                                .unwrap();
                            unsafe {
                                libc::raise(libc::SIGSTOP);
                            }
                        }
                    }
                    return Ok(());
                }
            }
            let inode = self
                .store()
                .get(ino)
                .map_err(|_| libc::EIO)?
                .ok_or(libc::ENOENT)?;
            if inode.size > self.sdo_context.map_or(MAX_FILE_SIZE, |c| c.max_file_size) {
                return Err(libc::EFBIG);
            }
            if let Some(manifest) = inode.manifest {
                spool.resize(inode.size).map_err(|_| libc::EIO)?;
                for bp in manifest.blocks {
                    if bp.file_offset >= inode.size {
                        continue;
                    }
                    let block = self
                        .download_block(bp.message_id, &bp.block_id, bp.epoch)
                        .ok_or(libc::EIO)?;
                    let n = bp.length.min(inode.size - bp.file_offset) as usize;
                    let start = bp.block_data_offset as usize;
                    spool
                        .write(
                            bp.file_offset,
                            block.get(start..start + n).ok_or(libc::EIO)?,
                        )
                        .map_err(|_| libc::EIO)?;
                }
            }
            Ok(())
        })();
        let result = result.and_then(|()| {
            spool
                .lock()
                .map_err(|_| libc::EIO)?
                .finish_initialization()
                .map_err(|_| libc::EIO)
        });
        if result.is_err() {
            if let Ok(spool) = spool.lock() {
                let _ = spool.cleanup();
            }
            self.handles.remove_spool(portable, id);
        }
        result
    }

    fn persist_spool(&self, ino: u64, fh: u64) -> std::result::Result<(), libc::c_int> {
        let portable = self.sdo_context.is_some();
        let id = if portable { fh } else { ino };
        let Some(spool) = self.handles.spool(portable, id) else {
            return Ok(());
        };
        let mut spool = spool.lock().map_err(|_| libc::EIO)?;
        if portable {
            let pending = self.upload_spool(&mut spool)?;
            self.commit_stream_manifest(&pending, spool.intent.file_hash)?;
            self.handles
                .advance_sdo_version(fh, spool.intent.metadata.version_id);
        } else {
            self.publish_legacy_spool(&mut spool)?;
        }
        spool.cleanup().map_err(|_| libc::EIO)?;
        self.handles.remove_spool(portable, id);
        Ok(())
    }

    fn upload_spool(
        &self,
        spool: &mut crate::spool::WriteSpool,
    ) -> std::result::Result<PendingSdoVersion, libc::c_int> {
        use std::io::{Seek, SeekFrom};
        use teagarden_core::sdo::streaming::SdoStreamPlan;
        let context = self.sdo_context.ok_or(libc::EIO)?;
        let mk = self.manifest_key.as_ref().ok_or(libc::EIO)?;
        if spool.intent.confirmed.is_none()
            && spool.len().map_err(|_| libc::EIO)? > context.max_file_size
        {
            return Err(libc::EFBIG);
        }
        if self
            .sdo_policy()?
            .is_some_and(|p| p.revoked_device_ids.contains(&context.author_device_id))
        {
            return Err(libc::EPERM);
        }
        if spool.intent.metadata.author_device_id != context.author_device_id {
            return Err(libc::EPERM);
        }
        if spool
            .intent
            .plan
            .as_ref()
            .is_some_and(|p| p.metadata.key_generation != self.sdo_key_generation)
            && spool.intent.confirmed.is_none()
        {
            #[cfg(not(feature = "key-rotation"))]
            return Err(libc::ENOTSUP);
            #[cfg(feature = "key-rotation")]
            {
                use rand::Rng;
                let previous = spool.intent.plan.as_ref().ok_or(libc::EIO)?;
                if self.sdo_policy()?.is_some_and(|p| {
                    !teagarden_core::sdo::object_authority_is_acceptable(&p, &previous.metadata)
                }) {
                    return Err(libc::EPERM);
                }
                let digest: [u8; 32] = hex::decode(&previous.metadata.content_sha256)
                    .map_err(|_| libc::EIO)?
                    .try_into()
                    .map_err(|_| libc::EIO)?;
                let mut metadata = previous.metadata.clone();
                metadata.key_generation = self.sdo_key_generation;
                let mut next = SdoStreamPlan::prepare(
                    context.volume_id,
                    self.sdo_key_generation,
                    self.sdo_meta_key_for_generation(self.sdo_key_generation),
                    metadata,
                    digest,
                    self.sdo_signing_key.as_ref(),
                )
                .map_err(|_| libc::EIO)?;
                next.spool_segment_hashes = previous.spool_segment_hashes.clone();
                if let Some((bootstrap, hierarchy)) = &self.sdo_object_envelope {
                    next = next
                        .with_envelope(bootstrap, hierarchy)
                        .map_err(|_| libc::EIO)?;
                }
                let progress = spool.intent_path.with_extension("parts");
                if progress.exists() {
                    std::fs::remove_file(progress).map_err(|_| libc::EIO)?;
                }
                spool.intent.acknowledged.clear();
                spool.intent.upload_id = rand::thread_rng().gen();
                spool.intent.publication_id = rand::thread_rng().gen();
                spool.intent.metadata = next.metadata.clone();
                spool.intent.plan = Some(next);
                spool.save().map_err(|_| libc::EIO)?;
            }
        }
        if spool.intent.plan.is_none() {
            spool.file.sync_data().map_err(|_| libc::EIO)?;
            let (digest, file_hash) = spool.digests(mk).map_err(|_| libc::EIO)?;
            let inode = self
                .store()
                .get(spool.intent.inode)
                .map_err(|_| libc::EIO)?;
            let mut metadata = spool.intent.metadata.clone();
            metadata.size = spool.len().map_err(|_| libc::EIO)?;
            if let Some(inode) = inode {
                metadata.mode = inode.mode;
                metadata.mtime_ns = inode.timestamps.mtime_ns as i64;
            }
            metadata.key_generation = self.sdo_key_generation;
            let mut plan = SdoStreamPlan::prepare(
                context.volume_id,
                self.sdo_key_generation,
                self.sdo_meta_key_for_generation(self.sdo_key_generation),
                metadata,
                digest,
                self.sdo_signing_key.as_ref(),
            )
            .map_err(|e| {
                tracing::error!(%e,"prepare spool");
                libc::EIO
            })?;
            plan.spool_segment_hashes = spool.segment_checks();
            if let Some((bootstrap, hierarchy)) = &self.sdo_object_envelope {
                plan = plan.with_envelope(bootstrap, hierarchy).map_err(|e| {
                    tracing::error!(%e,"stream envelope");
                    libc::EIO
                })?;
            }
            spool.intent.metadata = plan.metadata.clone();
            spool.intent.plan = Some(plan);
            spool.intent.file_hash = file_hash;
            spool.save().map_err(|_| libc::EIO)?;
        }
        let plan = spool.intent.plan.as_ref().ok_or(libc::EIO)?.clone();
        let header = decode_stored_sdo_header(
            &plan.header_wire,
            context.volume_id,
            &self.meta_key,
            &self.sdo_generation_meta_keys,
        )
        .map_err(|_| libc::EIO)?;
        if !Self::sdo_header_allowed(
            self.sdo_policy()?.as_ref(),
            &header,
            spool.intent.confirmed.unwrap_or(i64::MAX),
        ) {
            return Err(libc::EPERM);
        }
        let message_id = if let Some(id) = spool.intent.confirmed {
            id
        } else {
            let mut completed = None;
            for attempt in 0..2 {
                let mut file = spool.file.try_clone().map_err(|_| libc::EIO)?;
                file.seek(SeekFrom::Start(0)).map_err(|_| libc::EIO)?;
                let stream = plan
                    .clone()
                    .reader(
                        file,
                        self.sdo_meta_key_for_generation(plan.metadata.key_generation)
                            .clone(),
                        self.sdo_object_envelope.as_ref().map(|(_, h)| h.clone()),
                    )
                    .map_err(|_| libc::EIO)?;
                let mut source = crate::spool::SpoolUpload { stream, spool };
                let result = self.rt.as_ref().ok_or(libc::EIO)?.block_on(
                    self.transport
                        .as_ref()
                        .ok_or(libc::EIO)?
                        .upload_file_source(
                            &mut source,
                            "teagarden-file-v3.tgf",
                            self.upload_timeout,
                        ),
                );
                match result {
                    Ok(result) => {
                        completed = Some(result);
                        break;
                    }
                    Err(error) if error.requires_new_upload() => {
                        spool.restart_upload().map_err(|_| libc::EIO)?;
                        if attempt == 1 {
                            return Err(libc::EIO);
                        }
                    }
                    Err(error) => return Err(sdo_upload_errno(error)),
                }
            }
            let result = completed.ok_or(libc::EIO)?;
            if result.size as u64 != plan.wire_len() {
                return Err(libc::EIO);
            }
            spool.confirm(result.message_id).map_err(|_| libc::EIO)?;
            result.message_id
        };
        let path = plan.metadata.path.as_ref().ok_or(libc::EIO)?;
        let pending = PendingSdoVersion {
            fingerprint: [0; 32],
            manifest: plan.metadata.clone(),
            stored: StoredSdoVersion {
                ino: spool.intent.inode,
                path_id: keyed_hash(
                    mk,
                    &[b"teagarden.sdo.path.v1".as_slice(), path.as_bytes()].concat(),
                ),
                message_id,
                wire: plan.header_wire,
            },
        };
        Ok(pending)
    }

    fn commit_stream_manifest(
        &self,
        pending: &PendingSdoVersion,
        file_hash: [u8; 32],
    ) -> std::result::Result<(), libc::c_int> {
        let ino = pending.stored.ino;
        let mk = self.manifest_key.as_ref().ok_or(libc::EIO)?;
        let mut inode = self
            .store()
            .get(ino)
            .map_err(|_| libc::EIO)?
            .ok_or(libc::ENOENT)?;
        let parent_ids = inode
            .manifest
            .as_ref()
            .map(|m| vec![m.compute_id(mk)])
            .unwrap_or_default();
        let version = self
            .manifest_store()
            .max_version(ino)
            .map_err(|_| libc::EIO)?
            .max(inode.manifest.as_ref().map_or(0, |m| m.version))
            + 1;
        let manifest = FileManifest {
            inode: ino,
            version,
            total_size: pending.manifest.size,
            file_hash,
            blocks: Vec::new(),
            parent_ids: parent_ids.clone(),
        };
        self.journaled_txn(|| {
            self.manifest_store()
                .insert(&manifest)
                .map_err(|_| libc::EIO)?;
            if !parent_ids.is_empty() {
                self.dag_store()
                    .insert_edges(&manifest.compute_id(mk), &parent_ids)
                    .map_err(|_| libc::EIO)?;
            }
            inode.size = manifest.total_size;
            inode.manifest = Some(manifest);
            self.store().update(&inode).map_err(|_| libc::EIO)?;
            self.commit_sdo_version(pending)
        })
    }

    fn publish_legacy_spool(
        &self,
        spool: &mut crate::spool::WriteSpool,
    ) -> std::result::Result<(), libc::c_int> {
        let (_, hash) = spool
            .digests(self.manifest_key.as_ref().ok_or(libc::EIO)?)
            .map_err(|_| libc::EIO)?;
        let len = spool.len().map_err(|_| libc::EIO)?;
        let mut offset = 0;
        let mut outcomes: Vec<BlockOutcome> = Vec::new();
        let mut known = std::collections::HashMap::<[u8; 32], BlockRecord>::new();
        while offset < len {
            let bytes = spool
                .read_range(offset, self.fuse_block_size)
                .map_err(|_| libc::EIO)?;
            let (block_id, _) = self.derive_block_identity(&bytes).ok_or(libc::EIO)?;
            if let Some(record) = known.get(&block_id) {
                outcomes.push(BlockOutcome {
                    record: record.clone(),
                    disposition: BlockDisposition::BatchDuplicate,
                });
            } else {
                let mut batch = self
                    .flush_chunks_to_transport(spool.intent.inode, &bytes)
                    .ok_or(libc::EIO)?;
                known.insert(block_id, batch[0].record.clone());
                outcomes.append(&mut batch);
            }
            offset += bytes.len() as u64;
        }
        self.persist_file_blocks_prepared(
            spool.intent.inode,
            &[],
            outcomes,
            None,
            None,
            None,
            Some((len, hash)),
            None,
        )
    }

    fn inode_to_attr(inode: &Inode) -> FileAttr {
        let kind = match inode.file_type {
            FileType::RegularFile => FuseFileType::RegularFile,
            FileType::Directory => FuseFileType::Directory,
            FileType::Symlink => FuseFileType::Symlink,
        };

        let ts = &inode.timestamps;
        let atime = ns_to_system_time(ts.atime_ns);
        let mtime = ns_to_system_time(ts.mtime_ns);
        let ctime = ns_to_system_time(ts.ctime_ns);
        let crtime = ns_to_system_time(ts.crtime_ns);

        FileAttr {
            ino: inode.ino,
            size: inode.size,
            blocks: inode.size.div_ceil(512),
            atime,
            mtime,
            ctime,
            crtime,
            kind,
            perm: inode.mode as u16,
            nlink: inode.nlink,
            uid: inode.uid,
            gid: inode.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Upload dirty write buffer as a block via transport.
    ///
    /// Computes `block_id = BLAKE3_keyed(Kblocks_epoch, plaintext)` and uses it
    /// as the dedup key and storage identity. Derives a grammar filename from
    /// `BLAKE3_keyed(Kfilename_epoch, block_id)` per CABS spec §3–4.
    ///
    /// Falls back to random block_id if block keys are not configured (no keyed dedup).
    ///
    /// NOTE: this single-block helper is **not on the production write path** —
    /// `release` uses `flush_chunks_to_transport` + `persist_file_blocks`, which
    /// journal the `blocks` rows. It inserts the row in autocommit and survives only
    /// as a test helper; do not call it from production code (it would be an
    /// un-journaled escape). Kept `pub` so the integration tests can reach it.
    pub fn flush_to_transport(&self, _ino: u64, data: &[u8]) -> Option<BlockRecord> {
        let transport = self.transport.as_ref()?;
        let rt = self.rt.as_ref()?;

        // Derive epoch-scoped block_id key: Kblocks_epoch = HKDF(Kblocks, "epoch:N")
        let (block_id, filename) =
            if let (Some(bid_key), Some(_fn_key)) = (&self.block_id_key, &self.filename_key) {
                let kblocks_epoch = match derive_epoch_key(bid_key, self.current_epoch) {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::error!(error = %e, "block_id key derivation failed");
                        return None;
                    }
                };
                let block_id = keyed_hash(&kblocks_epoch.key, data);

                // Filenames reveal nothing about the plaintext or block identity:
                // a fresh random UUID, no extension. See "What Telegram can see" in
                // docs/SECURITY_MODEL.md and the document naming in docs/FORMAT.md.
                let filename = uuid::Uuid::new_v4().to_string();

                (block_id, filename)
            } else {
                // No keys configured — use random block_id (no content-addressed dedup).
                // This should only occur in tests without a full key hierarchy.
                let mut block_id = [0u8; 32];
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut block_id);
                let filename = uuid::Uuid::new_v4().to_string();
                (block_id, filename)
            };

        // Dedup: if a block with this identity already exists, increment its ref_count.
        let block_store = self.block_store();
        if let Ok(Some(existing)) = block_store.find_by_block_id(&block_id) {
            let _ = block_store.increment_ref(&block_id);
            return Some(existing);
        }

        // Encrypt with epoch-scoped data key before uploading to Telegram.
        let epoch_data_key = match derive_epoch_key(&self.data_key, self.current_epoch) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, "data key derivation failed");
                return None;
            }
        };
        let aad = block_aad(self.current_epoch, &block_id, self.block_v2_from_epoch);
        let ciphertext = match aead::encrypt(&epoch_data_key.key, data, &aad) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "block encryption failed");
                return None;
            }
        };

        let upload_result = rt
            .block_on(async {
                tokio::time::timeout(
                    self.upload_timeout,
                    transport.upload_block(&ciphertext, &filename),
                )
                .await
            })
            .unwrap_or_else(|_| {
                tracing::error!("upload_block timed out after {:?}", self.upload_timeout);
                Err(teagarden_telegram::error::TelegramError::Timeout)
            });

        match upload_result {
            Ok(result) => {
                let block = BlockRecord {
                    block_id,
                    filename,
                    message_id: result.message_id,
                    plaintext_size: data.len() as i64,
                    encrypted_size: ciphertext.len() as i64,
                    epoch: self.current_epoch,
                    ref_count: 1,
                    compressed: false,
                    plaintext_sha256: sha256_bytes(data),
                    ciphertext_sha256: sha256_bytes(&ciphertext),
                };

                if let Err(e) = block_store.insert(&block) {
                    tracing::error!(error = %e, "failed to insert block record");
                    return None;
                }

                if let Some(cache) = &self.cache {
                    let _ = cache.put(&block_id, data);
                }

                Some(block)
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to upload block");
                None
            }
        }
    }

    /// Derive the keyed (block_id, filename) pair for a chunk of plaintext.
    ///
    /// Returns `(block_id, filename)`. Falls back to a random block_id if block
    /// keys are not configured (test mode without a full key hierarchy).
    fn derive_block_identity(&self, chunk: &[u8]) -> Option<([u8; 32], String)> {
        if let (Some(bid_key), Some(_fn_key)) = (&self.block_id_key, &self.filename_key) {
            let kblocks_epoch = match derive_epoch_key(bid_key, self.current_epoch) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(error = %e, "block_id key derivation failed");
                    return None;
                }
            };
            let block_id = keyed_hash(&kblocks_epoch.key, chunk);

            // Filenames reveal nothing about the plaintext or block identity:
            // a fresh random UUID, no extension. See "What Telegram can see" in
            // docs/SECURITY_MODEL.md and the document naming in docs/FORMAT.md.
            let filename = uuid::Uuid::new_v4().to_string();

            Some((block_id, filename))
        } else {
            let mut block_id = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut block_id);
            let filename = uuid::Uuid::new_v4().to_string();
            Some((block_id, filename))
        }
    }

    /// Split `data` into `UPLOAD_CHUNK_SIZE` chunks and upload all chunks in parallel.
    ///
    /// When an upload queue is active, each chunk's ciphertext is sent to the worker
    /// which spawns a separate tokio task, allowing all chunks to be in-flight over
    /// Telegram simultaneously. The FUSE thread then blocking-waits for all results.
    ///
    /// Without an upload queue, falls back to `rt.block_on(join_all(...))` which still
    /// achieves concurrency for multi-session transport but blocks the FUSE thread for
    /// the full RTT of the slowest chunk.
    ///
    /// Returns `Vec<BlockOutcome>` in chunk order (uploads only — the `blocks`-table
    /// inserts / ref bumps are deferred to `persist_file_blocks` so they are captured
    /// in the journal). Returns `None` if transport or runtime is not configured, or
    /// if any chunk upload fails.
    pub fn flush_chunks_to_transport(&self, _ino: u64, data: &[u8]) -> Option<Vec<BlockOutcome>> {
        let transport = self.transport.as_ref()?;
        let rt = self.rt.as_ref()?;

        // Derive the epoch-scoped data encryption key once, shared across all chunks.
        let epoch_data_key = match derive_epoch_key(&self.data_key, self.current_epoch) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, "data key derivation failed");
                return None;
            }
        };

        // Split into chunks; single-block files use one chunk without extra overhead.
        // The chunk size is the volume's configured FUSE block size (default
        // UPLOAD_CHUNK_SIZE) — larger blocks mean fewer rate-limited Telegram messages.
        let block_size = self.fuse_block_size;
        let chunks: Vec<&[u8]> = if data.len() <= block_size {
            vec![data]
        } else {
            data.chunks(block_size).collect()
        };

        let block_store = self.block_store();

        // Phase 1: for each chunk classify it (DB-dedup / new-upload / in-batch
        // duplicate) and encrypt new chunks. Intra-batch duplicates (identical
        // chunks in one write, e.g. a large zero-filled file) reference the first
        // occurrence so we upload + insert exactly one row per block_id.
        enum ChunkPrep<'a> {
            Dedup(BlockRecord),
            BatchDuplicate {
                first: usize,
            },
            NeedsUpload {
                block_id: [u8; 32],
                filename: String,
                ciphertext: Vec<u8>,
                plaintext: &'a [u8],
            },
        }

        let mut preps: Vec<ChunkPrep<'_>> = Vec::with_capacity(chunks.len());
        let mut first_seen: std::collections::HashMap<[u8; 32], usize> =
            std::collections::HashMap::new();
        for chunk in &chunks {
            let (block_id, filename) = self.derive_block_identity(chunk)?;

            // Already produced earlier in THIS batch → pointer only.
            if let Some(&first) = first_seen.get(&block_id) {
                preps.push(ChunkPrep::BatchDuplicate { first });
                continue;
            }

            if let Ok(Some(existing)) = block_store.find_by_block_id(&block_id) {
                // DB dedup hit. The ref_count bump is deferred to persist_file_blocks.
                first_seen.insert(block_id, preps.len());
                preps.push(ChunkPrep::Dedup(existing));
                continue;
            }

            let aad = block_aad(self.current_epoch, &block_id, self.block_v2_from_epoch);
            let ciphertext = match aead::encrypt(&epoch_data_key.key, chunk, &aad) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "chunk encryption failed");
                    return None;
                }
            };
            first_seen.insert(block_id, preps.len());
            preps.push(ChunkPrep::NeedsUpload {
                block_id,
                filename,
                ciphertext,
                plaintext: chunk,
            });
        }

        // Phase 2: Upload non-dedup chunks — either via queue (concurrent) or inline (parallel).
        if let Some(upload_tx) = &self.upload_tx {
            // Queue path: send all pending chunks to the worker upfront (non-blocking),
            // then collect results. The worker spawns one tokio task per chunk, so all
            // chunks are in-flight concurrently even while this FUSE thread iterates.

            // Collect one oneshot Receiver per pending upload (in submission order).
            let mut pending_rxs: Vec<
                tokio::sync::oneshot::Receiver<std::result::Result<i64, String>>,
            > = Vec::new();

            for (i, prep) in preps.iter().enumerate() {
                if let ChunkPrep::NeedsUpload {
                    filename,
                    ciphertext,
                    ..
                } = prep
                {
                    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                    let memory = rt
                        .block_on(
                            self.upload_memory
                                .clone()
                                .acquire_many_owned(ciphertext.len().max(1) as u32),
                        )
                        .ok()?;
                    let pending = PendingUpload {
                        _memory: memory,
                        ciphertext: ciphertext.clone(),
                        filename: filename.clone(),
                        timeout: self.upload_timeout,
                        result_tx,
                    };
                    if upload_tx.send(pending).is_err() {
                        tracing::error!(chunk = i, "upload queue closed; cannot upload chunk");
                        return None;
                    }
                    pending_rxs.push(result_rx);
                }
            }

            // Drain all receivers (submitted order = arrival order in worker). The
            // worker bounds each upload by `upload_timeout`; this wait is a backstop
            // (twice that, covering a wait for a concurrency slot) so a stalled or
            // dead worker can never wedge the FUSE thread forever.
            let backstop = self.upload_timeout.saturating_mul(2);
            let mut message_ids: Vec<i64> = Vec::with_capacity(pending_rxs.len());
            for (slot, result_rx) in pending_rxs.into_iter().enumerate() {
                match rt.block_on(async { tokio::time::timeout(backstop, result_rx).await }) {
                    Ok(Ok(Ok(message_id))) => message_ids.push(message_id),
                    Ok(Ok(Err(e))) => {
                        tracing::error!(slot, error = %e, "upload worker reported failure");
                        return None;
                    }
                    Ok(Err(_)) => {
                        tracing::error!(slot, "upload worker channel closed unexpectedly");
                        return None;
                    }
                    Err(_) => {
                        tracing::error!(slot, "no upload result within {backstop:?}");
                        return None;
                    }
                }
            }

            // Phase 3: build outcomes (no DB writes — deferred to the journal).
            let mut records: Vec<BlockOutcome> = Vec::with_capacity(preps.len());
            let mut msg_iter = message_ids.into_iter();
            for prep in preps {
                match prep {
                    ChunkPrep::Dedup(record) => records.push(BlockOutcome {
                        record,
                        disposition: BlockDisposition::DedupExisting,
                    }),
                    ChunkPrep::BatchDuplicate { first } => {
                        let record = records[first].record.clone();
                        records.push(BlockOutcome {
                            record,
                            disposition: BlockDisposition::BatchDuplicate,
                        });
                    }
                    ChunkPrep::NeedsUpload {
                        block_id,
                        filename,
                        ciphertext,
                        plaintext,
                    } => {
                        let message_id = match msg_iter.next() {
                            Some(id) => id,
                            None => {
                                tracing::error!(
                                    "BUG: message_id iterator exhausted before NeedsUpload entries"
                                );
                                return None;
                            }
                        };

                        let block = BlockRecord {
                            block_id,
                            filename,
                            message_id,
                            plaintext_size: plaintext.len() as i64,
                            encrypted_size: ciphertext.len() as i64,
                            epoch: self.current_epoch,
                            ref_count: 1,
                            compressed: false,
                            plaintext_sha256: sha256_bytes(plaintext),
                            ciphertext_sha256: sha256_bytes(&ciphertext),
                        };

                        if let Some(cache) = &self.cache {
                            let _ = cache.put(&block_id, plaintext);
                        }

                        records.push(BlockOutcome {
                            record: block,
                            disposition: BlockDisposition::New,
                        });
                    }
                }
            }

            Some(records)
        } else {
            // Preserve chunk ordering while bounding resident ciphertext by bytes.
            use futures::StreamExt as _;
            let mut upload_futures: Vec<_> = Vec::new();

            for prep in preps.iter() {
                if let ChunkPrep::NeedsUpload {
                    filename,
                    ciphertext,
                    ..
                } = prep
                {
                    let transport = transport.clone();
                    let ciphertext = ciphertext.clone();
                    let filename = filename.clone();
                    let upload_timeout = self.upload_timeout;
                    upload_futures.push(async move {
                        tokio::time::timeout(
                            upload_timeout,
                            transport.upload_block(&ciphertext, &filename),
                        )
                        .await
                        .unwrap_or_else(|_| {
                            tracing::error!("chunk upload timed out after {upload_timeout:?}");
                            Err(teagarden_telegram::error::TelegramError::Timeout)
                        })
                    });
                }
            }

            let upload_results: Vec<_> = rt.block_on(
                futures::stream::iter(upload_futures)
                    .buffered((64 * 1024 * 1024 / self.fuse_block_size).max(1))
                    .collect(),
            );

            // Phase 3: build outcomes (no DB writes — deferred to the journal).
            let mut records: Vec<BlockOutcome> = Vec::with_capacity(preps.len());
            let mut upload_iter = upload_results.into_iter();

            for prep in preps {
                match prep {
                    ChunkPrep::Dedup(record) => records.push(BlockOutcome {
                        record,
                        disposition: BlockDisposition::DedupExisting,
                    }),
                    ChunkPrep::BatchDuplicate { first } => {
                        let record = records[first].record.clone();
                        records.push(BlockOutcome {
                            record,
                            disposition: BlockDisposition::BatchDuplicate,
                        });
                    }
                    ChunkPrep::NeedsUpload {
                        block_id,
                        filename,
                        ciphertext,
                        plaintext,
                    } => {
                        let result = match upload_iter.next() {
                            Some(r) => r,
                            None => {
                                tracing::error!("BUG: upload_results iterator exhausted before NeedsUpload entries");
                                return None;
                            }
                        };
                        match result {
                            Ok(upload) => {
                                let block = BlockRecord {
                                    block_id,
                                    filename,
                                    message_id: upload.message_id,
                                    plaintext_size: plaintext.len() as i64,
                                    encrypted_size: ciphertext.len() as i64,
                                    epoch: self.current_epoch,
                                    ref_count: 1,
                                    compressed: false,
                                    plaintext_sha256: sha256_bytes(plaintext),
                                    ciphertext_sha256: sha256_bytes(&ciphertext),
                                };

                                if let Some(cache) = &self.cache {
                                    let _ = cache.put(&block_id, plaintext);
                                }

                                records.push(BlockOutcome {
                                    record: block,
                                    disposition: BlockDisposition::New,
                                });
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "chunk upload failed");
                                return None;
                            }
                        }
                    }
                }
            }

            Some(records)
        }
    }

    fn path_for_inode(&self, ino: u64) -> std::result::Result<String, libc::c_int> {
        let store = self.store();
        let mut current = ino;
        let mut seen = std::collections::HashSet::new();
        let mut components = Vec::new();
        for _ in 0..256 {
            if current == 1 {
                components.reverse();
                return Ok(components.join("/"));
            }
            if !seen.insert(current) {
                tracing::error!(ino, current, "portable path contains a parent cycle");
                return Err(libc::EIO);
            }
            let inode = store
                .get(current)
                .map_err(|e| {
                    tracing::error!(ino, current, error = %e, "portable path inode read failed");
                    libc::EIO
                })?
                .ok_or(libc::ENOENT)?;
            if inode.name.is_empty() || inode.name.contains('/') || inode.name.contains('\0') {
                tracing::error!(ino, current, "portable path has an invalid component");
                return Err(libc::EIO);
            }
            components.push(inode.name);
            current = inode.parent;
        }
        tracing::error!(ino, "portable path exceeded 256 components");
        Err(libc::EIO)
    }

    /// Build and upload a TGFV object. The pending cache keeps the exact UUID and
    /// bytes when Telegram stored a manifest but the journal transaction failed.
    #[allow(clippy::too_many_arguments)]
    fn upload_sdo_version(
        &self,
        inode: &Inode,
        path: &str,
        content: &[u8],
        _pointers: &[BlockPointer],
        _supplied: &[BlockRecord],
        deleted: bool,
        identity_override: Option<SdoFileIdentity>,
    ) -> std::result::Result<PendingSdoVersion, libc::c_int> {
        self.upload_sdo_version_with_retry(
            inode,
            path,
            content,
            _pointers,
            _supplied,
            deleted,
            identity_override,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn upload_sdo_version_with_retry(
        &self,
        inode: &Inode,
        path: &str,
        content: &[u8],
        _pointers: &[BlockPointer],
        _supplied: &[BlockRecord],
        deleted: bool,
        identity_override: Option<SdoFileIdentity>,
        durable_retry: Option<&SdoPendingWrite>,
    ) -> std::result::Result<PendingSdoVersion, libc::c_int> {
        let Some(context) = self.sdo_context else {
            return Err(libc::EINVAL);
        };
        if !self.sdo_clock_loaded {
            return Err(libc::EIO);
        }
        let manifest_key = self.manifest_key.as_ref().ok_or(libc::EIO)?;
        let path_id = keyed_hash(
            manifest_key,
            &[b"teagarden.sdo.path.v1".as_slice(), path.as_bytes()].concat(),
        );
        let pending = self
            .pending_sdo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&path_id)
            .cloned();
        let kind = if inode.is_dir() {
            teagarden_core::sdo::SdoKind::Directory
        } else {
            teagarden_core::sdo::SdoKind::File
        };
        if kind == teagarden_core::sdo::SdoKind::Directory && !content.is_empty() {
            return Err(libc::EINVAL);
        }
        let identity = match identity_override {
            Some(identity) => Some(identity),
            None => self.sdo_identity_store().get(inode.ino).map_err(|e| {
                tracing::error!(ino = inode.ino, error = %e, "portable identity read failed");
                libc::EIO
            })?,
        };
        let captured = durable_retry
            .and_then(|retry| retry.metadata_snapshot.as_ref())
            .map(|snapshot| teagarden_core::sdo::SdoObjectMetadataV3::decode_snapshot(snapshot))
            .transpose()
            .map_err(|_| libc::EIO)?;
        let mut fingerprint_manifest = teagarden_core::sdo::SdoObjectMetadataV3 {
            authority: None,
            migration_receipt: None,
            file_id: pending
                .as_ref()
                .map(|p| p.manifest.file_id)
                .or(identity.map(|id| id.file_id))
                .or_else(|| captured.as_ref().map(|record| record.file_id))
                .unwrap_or_else(uuid::Uuid::new_v4),
            origin_message_id: pending
                .as_ref()
                .map(|p| p.manifest.origin_message_id)
                .unwrap_or_else(|| identity.and_then(|id| id.origin_message_id)),
            path: Some(path.to_owned()),
            size: if deleted || kind == teagarden_core::sdo::SdoKind::Directory {
                0
            } else {
                content.len() as u64
            },
            mtime_ns: inode.timestamps.mtime_ns as i64,
            mode: inode.mode,
            version_id: uuid::Uuid::nil(),
            author_device_id: context.author_device_id,
            previous_version_id: None,
            kind,
            key_generation: self.sdo_key_generation,
            clock_ms: 0,
            clock_counter: 0,
            saved_at_ns: 0,
            local_version: 0,
            deleted,
            installation_id: None,
            label: None,
            telegram_user_id: None,
            authorization_session_hash: None,
            created_at_ms: None,
            device_public_key: None,
            device_key_update: None,
            segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
            segment_count: 0,
            content_sha256: hex::encode(sha256_bytes(if deleted { &[] } else { content })),
        };
        let mut fingerprint_bytes = Vec::new();
        fingerprint_bytes.extend_from_slice(path.as_bytes());
        fingerprint_bytes.extend_from_slice(fingerprint_manifest.file_id.as_bytes());
        fingerprint_bytes.extend_from_slice(
            &fingerprint_manifest
                .origin_message_id
                .unwrap_or_default()
                .to_le_bytes(),
        );
        fingerprint_bytes.extend_from_slice(&fingerprint_manifest.size.to_le_bytes());
        fingerprint_bytes.extend_from_slice(if deleted { &[] } else { content });
        fingerprint_bytes.extend_from_slice(&fingerprint_manifest.mtime_ns.to_le_bytes());
        fingerprint_bytes.extend_from_slice(&fingerprint_manifest.mode.to_le_bytes());
        fingerprint_bytes.extend_from_slice(fingerprint_manifest.author_device_id.as_bytes());
        fingerprint_bytes.push(u8::from(fingerprint_manifest.deleted));
        let fingerprint = sha256_bytes(&fingerprint_bytes);

        if let Some(wire) = durable_retry.and_then(|retry| retry.wire.as_ref()) {
            let generation = u64::from_le_bytes(wire[22..30].try_into().map_err(|_| libc::EIO)?);
            let header = teagarden_core::sdo::SdoFileObjectV3::decode_header(
                wire,
                context.volume_id,
                generation,
                self.sdo_meta_key_for_generation(generation),
            )
            .map_err(|error| {
                tracing::error!(%error, "durable portable retry object failed authentication");
                libc::EIO
            })?;
            let retry = PendingSdoVersion {
                fingerprint,
                manifest: header.metadata,
                stored: StoredSdoVersion {
                    path_id,
                    ino: inode.ino,
                    message_id: 0,
                    wire: wire.clone(),
                },
            };
            self.pending_sdo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(path_id, retry.clone());
            return self.retry_sdo_upload(retry);
        }

        let (file_id, origin_message_id, version_id, previous_version_id, local_version) =
            if let Some(p) = &pending {
                if p.fingerprint == fingerprint {
                    return self.retry_sdo_upload(p.clone());
                }
                let origin = p.manifest.origin_message_id.or(Some(p.stored.message_id));
                (
                    p.manifest.file_id,
                    origin,
                    durable_retry.map_or_else(uuid::Uuid::new_v4, |retry| retry.version_id),
                    Some(p.manifest.version_id),
                    p.manifest.local_version.saturating_add(1),
                )
            } else {
                match identity {
                    Some(identity) => (
                        identity.file_id,
                        identity.origin_message_id,
                        durable_retry.map_or_else(uuid::Uuid::new_v4, |retry| retry.version_id),
                        identity.latest_version_id,
                        identity.local_version.saturating_add(1).max(1),
                    ),
                    None => (
                        fingerprint_manifest.file_id,
                        None,
                        durable_retry.map_or_else(uuid::Uuid::new_v4, |retry| retry.version_id),
                        None,
                        1,
                    ),
                }
            };
        fingerprint_manifest.file_id = file_id;
        fingerprint_manifest.origin_message_id = origin_message_id;
        fingerprint_manifest.version_id = version_id;
        fingerprint_manifest.previous_version_id = previous_version_id;
        fingerprint_manifest.local_version = local_version;
        fingerprint_manifest.saved_at_ns = system_time_to_ns(SystemTime::now()) as i64;
        let utc_ms = u64::try_from(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let (clock_ms, clock_counter) = if let Some(retry) = durable_retry {
            (retry.clock_ms, retry.clock_counter)
        } else {
            let (clock_ms, clock_counter) = self
                .sdo_clock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .tick(utc_ms)
                .map_err(|error| {
                    tracing::error!(error = %error, "portable hybrid clock overflow");
                    libc::EIO
                })?;
            self.sdo_clock_store()
                .set(clock_ms, clock_counter)
                .map_err(|error| {
                    tracing::error!(%error, "portable hybrid clock persistence failed before upload");
                    libc::EIO
                })?;
            (clock_ms, clock_counter)
        };
        fingerprint_manifest.clock_ms = clock_ms;
        fingerprint_manifest.clock_counter = clock_counter;
        if self.sdo_policy()?.is_some_and(|policy| {
            policy
                .revoked_device_ids
                .contains(&context.author_device_id)
        }) {
            return Err(libc::EPERM);
        }
        let wire = if let Some(wire) = durable_retry.and_then(|retry| retry.wire.as_ref()) {
            let generation = wire
                .get(22..30)
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                .ok_or(libc::EIO)?;
            if generation == self.sdo_key_generation {
                wire.clone()
            } else {
                #[cfg(not(feature = "key-rotation"))]
                return Err(libc::ENOTSUP);
                #[cfg(feature = "key-rotation")]
                {
                    let mut object = teagarden_core::sdo::SdoFileObjectV3::decode(
                        wire,
                        context.volume_id,
                        generation,
                        self.sdo_meta_key_for_generation(generation),
                    )
                    .map_err(|_| libc::EIO)?;
                    if object.metadata.authority.is_none()
                        && object.metadata.author_device_id == context.author_device_id
                    {
                        if let Some(signer) = &self.sdo_signing_key {
                            object
                                .metadata
                                .sign_authority(context.volume_id, signer, &object.content)
                                .map_err(|_| libc::EIO)?;
                        }
                    }
                    if self.sdo_policy()?.is_some_and(|policy| {
                        !teagarden_core::sdo::object_transition_is_acceptable(
                            &policy,
                            &object.metadata,
                            i64::MAX,
                        )
                    }) {
                        return Err(libc::EPERM);
                    }
                    object.metadata.key_generation = self.sdo_key_generation;
                    self.seal_sdo_object(
                        teagarden_core::sdo::SdoFileObjectV3::encode(
                            context.volume_id,
                            self.sdo_key_generation,
                            self.sdo_meta_key_for_generation(self.sdo_key_generation),
                            object.metadata,
                            &object.content,
                        )
                        .map_err(|_| libc::EIO)?,
                    )
                    .map_err(|_| libc::EIO)?
                }
            }
        } else {
            teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
                context.volume_id,
                self.sdo_key_generation,
                self.sdo_meta_key_for_generation(self.sdo_key_generation),
                fingerprint_manifest.clone(),
                if deleted { &[] } else { content },
                self.sdo_signing_key.as_ref(),
            )
            .and_then(|wire| self.seal_sdo_object(wire))
            .map_err(|e| {
                tracing::error!(error = %e, "portable manifest encoding failed");
                libc::EIO
            })?
        };
        if let Some(retry) = durable_retry.filter(|retry| retry.wire.as_ref() != Some(&wire)) {
            let mut durable = retry.clone();
            durable.wire = Some(wire.clone());
            self.sdo_pending_write_store().put(&durable).map_err(|error| {
                tracing::error!(%error, "portable encoded retry persistence failed before Telegram upload");
                libc::EIO
            })?;
        }
        let pending = PendingSdoVersion {
            fingerprint,
            manifest: fingerprint_manifest,
            stored: StoredSdoVersion {
                path_id,
                ino: inode.ino,
                message_id: 0,
                wire,
            },
        };
        self.pending_sdo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path_id, pending.clone());
        self.retry_sdo_upload(pending)
    }

    fn retry_sdo_upload(
        &self,
        mut pending: PendingSdoVersion,
    ) -> std::result::Result<PendingSdoVersion, libc::c_int> {
        let transport = self.transport.as_ref().ok_or(libc::EIO)?;
        let rt = self.rt.as_ref().ok_or(libc::EIO)?;
        let mut source = teagarden_telegram::transfer::SliceSource::new(&pending.stored.wire);
        let result = rt
            .block_on(transport.upload_file_source(
                &mut source,
                "teagarden-file-v3.tgf",
                self.upload_timeout,
            ))
            .map_err(sdo_upload_errno)?;
        pending.stored.message_id = result.message_id;
        self.pending_sdo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(pending.stored.path_id, pending.clone());
        Ok(pending)
    }

    fn commit_sdo_version(
        &self,
        pending: &PendingSdoVersion,
    ) -> std::result::Result<(), libc::c_int> {
        let mut stored_header = pending.stored.clone();
        let encrypted_header_len =
            u32::from_le_bytes(stored_header.wire[30..34].try_into().unwrap()) as usize;
        stored_header.wire.truncate(34 + encrypted_header_len);
        self.sdo_version_store()
            .insert(pending.manifest.version_id.as_bytes(), &stored_header)
            .map_err(|e| {
                tracing::error!(error = %e, "portable version identity insert failed");
                libc::EIO
            })?;
        let store = self.store();
        let inode = store.get(pending.stored.ino).map_err(|e| {
            tracing::error!(error = %e, "portable version inode lookup failed");
            libc::EIO
        })?;
        if inode.is_some() {
            self.sdo_identity_store()
                .set(
                    pending.stored.ino,
                    &SdoFileIdentity {
                        file_id: pending.manifest.file_id,
                        origin_message_id: pending
                            .manifest
                            .origin_message_id
                            .or(Some(pending.stored.message_id)),
                        latest_version_id: Some(pending.manifest.version_id),
                        local_version: pending.manifest.local_version,
                    },
                )
                .map_err(|e| {
                    tracing::error!(error = %e, "portable file identity update failed");
                    libc::EIO
                })?;
        } else {
            self.sdo_identity_store()
                .delete(pending.stored.ino)
                .map_err(|e| {
                    tracing::error!(error = %e, "portable deleted file identity cleanup failed");
                    libc::EIO
                })?;
        }
        Ok(())
    }

    /// Persist a file write: insert/ref-bump the `blocks` rows AND update the inode
    /// manifest + DAG edges in ONE journaled transaction, so the block records and
    /// the manifest that references them land in the same metadata delta and are
    /// recovered together. The blocks must already be uploaded (each `outcome`
    /// carries its message id). Returns `EIO` on journal failure (the whole write
    /// rolls back) — a crashed session never leaves a manifest pointing at
    /// unrecorded blocks.
    fn persist_file_blocks(
        &self,
        ino: u64,
        data: &[u8],
        outcomes: Vec<BlockOutcome>,
    ) -> std::result::Result<(), libc::c_int> {
        self.persist_file_blocks_inner(ino, data, outcomes, None)
    }

    /// As [`Self::persist_file_blocks`], but `apply_attrs`, when `Some`, copies the
    /// caller's inode attributes (mode/uid/gid/timestamps) onto the inode inside the
    /// SAME journaled transaction as the block rows + manifest + size. This lets a
    /// truncate-materialize (`setattr` shrink) update size, content, and timestamps
    /// atomically — no two-write window between an attr update and the manifest
    /// rewrite (the v0.4.4 finding-#4 hazard).
    fn persist_file_blocks_inner(
        &self,
        ino: u64,
        data: &[u8],
        outcomes: Vec<BlockOutcome>,
        apply_attrs: Option<Inode>,
    ) -> std::result::Result<(), libc::c_int> {
        self.persist_file_blocks_inner_with_identity(ino, data, outcomes, apply_attrs, None, None)
    }

    fn persist_file_blocks_inner_with_identity(
        &self,
        ino: u64,
        data: &[u8],
        outcomes: Vec<BlockOutcome>,
        apply_attrs: Option<Inode>,
        identity_override: Option<SdoFileIdentity>,
        durable_retry: Option<SdoPendingWrite>,
    ) -> std::result::Result<(), libc::c_int> {
        self.persist_file_blocks_prepared(
            ino,
            data,
            outcomes,
            apply_attrs,
            identity_override,
            durable_retry,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_file_blocks_prepared(
        &self,
        ino: u64,
        data: &[u8],
        outcomes: Vec<BlockOutcome>,
        apply_attrs: Option<Inode>,
        identity_override: Option<SdoFileIdentity>,
        durable_retry: Option<SdoPendingWrite>,
        summary: Option<(u64, [u8; 32])>,
        streamed: Option<PendingSdoVersion>,
    ) -> std::result::Result<(), libc::c_int> {
        // Build block pointers + manifest from the outcomes (read-only work).
        let mut file_offset: u64 = 0;
        let mut block_pointers: Vec<BlockPointer> = Vec::with_capacity(outcomes.len());
        for o in &outcomes {
            let b = &o.record;
            let length = b.plaintext_size as u64;
            block_pointers.push(BlockPointer {
                block_id: b.block_id,
                message_id: b.message_id,
                file_offset,
                length,
                block_data_offset: 0,
                encrypted_size: b.encrypted_size as u64,
                compressed: b.compressed,
                epoch: b.epoch,
            });
            file_offset += length;
        }

        let (parent_ids, prev_version) = {
            let store = self.store();
            match store.get(ino) {
                Ok(Some(inode)) => {
                    if let (Some(prev), Some(mk)) = (&inode.manifest, &self.manifest_key) {
                        (vec![prev.compute_id(mk)], prev.version)
                    } else {
                        (Vec::new(), 0)
                    }
                }
                _ => (Vec::new(), 0),
            }
        };
        // Strictly monotonic per-inode version. `prev_version` resets to 0 when the
        // current manifest is None (after O_TRUNC / truncate-to-zero), so fold in the
        // max persisted history version to never reuse a `(ino, version)` PK. A DB
        // read fault here must surface as EIO (and be logged) — masking it to 0 would
        // pick the collision-prone version and report a misleading PK-collision error.
        let max_persisted = self.manifest_store().max_version(ino).map_err(|e| {
            tracing::error!(error = %e, "persist: max_version read failed");
            libc::EIO
        })?;
        let new_version = prev_version.max(max_persisted) + 1;

        // Keyed BLAKE3 (R6-L01): an unkeyed hash would leak whether a specific
        // plaintext was ever stored to any adversary with database access.
        let file_hash = if let Some((_, hash)) = summary {
            hash
        } else if let Some(mk) = &self.manifest_key {
            keyed_hash(mk, data)
        } else {
            debug_assert!(
                false,
                "manifest_key must be set; unkeyed file_hash is a security regression"
            );
            *blake3::hash(data).as_bytes()
        };

        let total_size = summary.map_or(data.len() as u64, |(len, _)| len);
        let manifest = FileManifest {
            inode: ino,
            version: new_version,
            total_size,
            file_hash,
            blocks: block_pointers,
            parent_ids: parent_ids.clone(),
        };
        let new_manifest_id = self.manifest_key.as_ref().map(|mk| manifest.compute_id(mk));

        // Blocks have already been acknowledged. Upload the TGFV object before
        // `journaled_txn` can publish its delta and commit the local inode.
        let pending_sdo = if streamed.is_some() {
            streamed
        } else if self.sdo_context.is_some() {
            let mut inode = self
                .store()
                .get(ino)
                .map_err(|e| {
                    tracing::error!(error = %e, "portable save inode read failed");
                    libc::EIO
                })?
                .ok_or(libc::ENOENT)?;
            if let Some(src) = &apply_attrs {
                inode.mode = src.mode;
                inode.uid = src.uid;
                inode.gid = src.gid;
                inode.timestamps = src.timestamps;
            }
            inode.manifest = Some(manifest.clone());
            inode.size = total_size;
            let path = self.path_for_inode(ino)?;
            Some(self.upload_sdo_version_with_retry(
                &inode,
                &path,
                data,
                &manifest.blocks,
                &[],
                false,
                identity_override,
                durable_retry.as_ref(),
            )?)
        } else {
            None
        };

        self.journaled_txn(|| {
            let block_store = self.block_store();
            for o in &outcomes {
                match o.disposition {
                    BlockDisposition::New => block_store.insert(&o.record).map_err(|e| {
                        tracing::error!(error = %e, "failed to journal block record");
                        libc::EIO
                    })?,
                    BlockDisposition::DedupExisting => {
                        block_store.increment_ref(&o.record.block_id).map_err(|e| {
                            tracing::error!(error = %e, "failed to journal block ref bump");
                            libc::EIO
                        })?
                    }
                    // In-batch duplicate: the first occurrence already wrote the row.
                    BlockDisposition::BatchDuplicate => {}
                }
            }
            // Fail-closed: the inode MUST exist — otherwise we would journal block
            // rows with no manifest referencing them (orphaned). Roll back instead.
            let store = self.store();
            let mut inode = store
                .get(ino)
                .map_err(|e| {
                    tracing::error!(error = %e, "persist: inode read failed");
                    libc::EIO
                })?
                .ok_or(libc::ENOENT)?;
            // Apply the caller's attribute changes (truncate-materialize) in THIS
            // txn so size + content + mode/uid/times all commit atomically.
            if let Some(ref src) = apply_attrs {
                inode.mode = src.mode;
                inode.uid = src.uid;
                inode.gid = src.gid;
                inode.timestamps = src.timestamps;
            }
            // Archive this manifest version so prior versions survive — the
            // substrate for `history` / `diff` / `revert`. Written in THIS
            // journaled_txn (not autocommit): an un-journaled mutation of the
            // `manifests` table would escape the changeset chain and vanish on crash
            // recovery (the round-2 poison class).
            self.manifest_store().insert(&manifest).map_err(|e| {
                tracing::error!(error = %e, "failed to journal manifest version");
                libc::EIO
            })?;
            inode.manifest = Some(manifest);
            inode.size = total_size;
            store.update(&inode).map_err(|e| {
                tracing::error!(error = %e, "failed to update inode manifest");
                libc::EIO
            })?;
            if let Some(pending) = &pending_sdo {
                self.commit_sdo_version(pending)?;
            }
            if let Some(retry) = &durable_retry {
                self.sdo_pending_write_store()
                    .delete(&retry.version_id)
                    .map_err(|error| {
                        tracing::error!(%error, "portable pending retry cleanup failed in commit transaction");
                        libc::EIO
                    })?;
            }
            if let Some(ref new_id) = new_manifest_id {
                if !parent_ids.is_empty() {
                    let dag = self.dag_store();
                    if let Err(e) = dag.insert_edges(new_id, &parent_ids) {
                        tracing::warn!(ino, error = %e, "failed to insert DAG edges");
                    }
                }
            }
            Ok(())
        })?;
        if let Some(pending) = pending_sdo {
            self.pending_sdo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&pending.stored.path_id);
        }
        Ok(())
    }

    /// Core of `write`: buffer the bytes into the inode's write buffer. Callable
    /// in-process for tests (the FUSE callback is a thin wrapper). Returns bytes
    /// written.
    ///
    /// The buffer is per INODE (shared by every handle open on it — see
    /// [`HandleTable`]), so concurrent writers through different descriptors see one
    /// coherent image and the persisted file holds all of their writes.
    ///
    /// Bytes go to the sole disk spool; the persisted inode changes only when
    /// `flush` / `fsync` / `release` uploads and journals its size and timestamp. A `stat` during an
    /// open write sees the growing size via the in-flight overlay in `getattr`.
    /// Updating the journaled inode row here (as a previous version did) would
    /// poison the next journaled delta's changeset before-image and abort crash
    /// recovery for the whole volume.
    fn write_impl(
        &self,
        ino: u64,
        fh: u64,
        req_uid: u32,
        offset: i64,
        data: &[u8],
    ) -> std::result::Result<u32, libc::c_int> {
        // Enforce file-handle ownership: the writing UID must match the opener's UID,
        // unless the opener was root (uid=0) or the writer is root.
        let handle = match self.handles.get(fh) {
            Some(h) => h,
            None => return Err(libc::EBADF),
        };
        if handle.uid != 0 && req_uid != 0 && req_uid != handle.uid {
            return Err(libc::EACCES);
        }
        // The file this handle was opened on was deleted; its inode number may now
        // belong to another file. Never write into that file.
        if handle.stale {
            return Err(libc::ESTALE);
        }

        // R4-H01: negative offset wraps to ~usize::MAX → ~9 EB Vec::resize (OOM).
        if offset < 0 {
            return Err(libc::EINVAL);
        }
        let offset = offset as usize;
        let end = offset.checked_add(data.len()).ok_or(libc::EINVAL)?;
        // M6: never size the buffer from an untrusted offset beyond the cap.
        let max_file_size = self
            .sdo_context
            .map_or(MAX_FILE_SIZE, |context| context.max_file_size);
        if end as u64 > max_file_size {
            if self.sdo_context.is_some() {
                tracing::error!(
                    limit_bytes = max_file_size,
                    "file exceeds the Telegram single-object limit; refusing write with EFBIG"
                );
            }
            return Err(libc::EFBIG);
        }

        self.ensure_spool(ino, &handle)?;
        let portable = self.sdo_context.is_some();
        let id = if portable { fh } else { ino };
        let spool = self.handles.spool(portable, id).ok_or(libc::EIO)?;
        spool
            .lock()
            .map_err(|_| libc::EIO)?
            .write(offset as u64, data)
            .map_err(|e| {
                tracing::error!(%e,"write spool");
                libc::EIO
            })?;
        if !data.is_empty() {
            self.handles.mark_written(fh);
        }
        Ok(data.len() as u32)
    }

    fn read_sdo_range(
        &self,
        ino: u64,
        offset: u64,
        length: u64,
    ) -> std::result::Result<Vec<u8>, libc::c_int> {
        let identity = self
            .sdo_identity_store()
            .get(ino)
            .map_err(|e| {
                tracing::error!(ino, error = %e, "portable file identity lookup failed");
                libc::EIO
            })?
            .ok_or(libc::ENOENT)?;
        let version_id = identity.latest_version_id.ok_or(libc::EIO)?;
        self.read_sdo_version_range(ino, version_id, offset, length)
    }

    fn read_sdo_version_range(
        &self,
        ino: u64,
        version_id: uuid::Uuid,
        offset: u64,
        length: u64,
    ) -> std::result::Result<Vec<u8>, libc::c_int> {
        let stored = self
            .sdo_version_store()
            .get(version_id.as_bytes())
            .map_err(|e| {
                tracing::error!(ino, error = %e, "portable version lookup failed");
                libc::EIO
            })?
            .ok_or(libc::EIO)?;
        self.read_sdo_stored_range(ino, version_id, stored, offset, length)
    }

    fn read_sdo_stored_range(
        &self,
        ino: u64,
        version_id: uuid::Uuid,
        stored: StoredSdoVersion,
        offset: u64,
        length: u64,
    ) -> std::result::Result<Vec<u8>, libc::c_int> {
        let context = self.sdo_context.ok_or(libc::EIO)?;
        // Bind authentication reuse to the exact immutable header, its key,
        // source position and the complete current owner policy. Any key/policy
        // change invalidates it before even the plaintext segment cache is used.
        let generation = match stored.wire.get(4..6) {
            Some([3, 0]) => stored
                .wire
                .get(22..30)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                .ok_or(libc::EIO)?,
            _ => 0,
        };
        let mut stamp =
            blake3::Hasher::new_keyed(self.sdo_meta_key_for_generation(generation).as_bytes());
        stamp.update(context.volume_id.as_bytes());
        stamp.update(&self.sdo_key_generation.to_le_bytes());
        stamp.update(&self.sdo_policy_stamp());
        stamp.update(&stored.wire);
        let stamp = *stamp.finalize().as_bytes();
        let cached = self
            .sdo_authenticated_headers
            .lock()
            .map_err(|_| libc::EIO)?
            .iter()
            .find(|entry| {
                entry.version == version_id
                    && entry.message == stored.message_id
                    && entry.stamp == stamp
            })
            .map(|entry| entry.header.clone());
        let header = if let Some(header) = cached {
            header
        } else {
            let header = decode_stored_sdo_header(
                &stored.wire,
                context.volume_id,
                &self.meta_key,
                &self.sdo_generation_meta_keys,
            )
            .map_err(|e| {
                tracing::error!(ino,%e,"portable file header authentication failed");
                libc::EIO
            })?;
            if !Self::sdo_header_allowed(self.sdo_policy()?.as_ref(), &header, stored.message_id) {
                return Err(libc::EACCES);
            }
            let mut headers = self
                .sdo_authenticated_headers
                .lock()
                .map_err(|_| libc::EIO)?;
            if headers.len() == 32 {
                headers.pop_front();
            }
            headers.push_back(AuthenticatedReadHeader {
                version: version_id,
                message: stored.message_id,
                stamp,
                header: header.clone(),
            });
            header
        };
        if header.deleted() {
            return Err(libc::ENOENT);
        }
        if offset >= header.size() || length == 0 {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(length).min(header.size());
        let mut out = vec![0u8; (end - offset) as usize];
        let first = (offset / u64::from(header.segment_size())) as u32;
        let last = ((end - 1) / u64::from(header.segment_size())) as u32;
        let transport = self.transport.as_ref().ok_or(libc::EIO)?;
        let rt = self.rt.as_ref().ok_or(libc::EIO)?;
        for index in first..=last {
            let cached = self
                .sdo_read_cache
                .lock()
                .map_err(|_| libc::EIO)?
                .iter()
                .find(|(v, i, _)| *v == version_id && *i == index)
                .map(|(_, _, p)| p.clone());
            let plaintext = if let Some(bytes) = cached {
                bytes
            } else {
                // A small random read fetches one authenticated segment. Once a
                // sequential reader advances, fill a 16 MiB resident window with
                // one pipelined range call. This works without a disk cache and
                // never races a second background download for the same segment.
                let count = if offset >= u64::from(header.segment_size()) && length >= 64 * 1024 {
                    16
                } else {
                    1
                };
                let stop = (index + count).min(header.segment_count());
                let encrypted_offset = header.segment_offset(index).map_err(|_| libc::EIO)?;
                let encrypted_end = header.segment_offset(stop - 1).map_err(|_| libc::EIO)?
                    + u64::from(
                        header
                            .encrypted_segment_len(stop - 1)
                            .map_err(|_| libc::EIO)?,
                    );
                let fetched = rt
                    .block_on(transport.download_range(
                        stored.message_id,
                        encrypted_offset,
                        (encrypted_end - encrypted_offset) as u32,
                    ))
                    .map_err(|e| {
                        tracing::error!(%e,"pipelined segment range");
                        libc::EIO
                    })?;
                if fetched.len() as u64 != encrypted_end - encrypted_offset {
                    return Err(libc::EIO);
                }
                let mut spans = Vec::new();
                let mut at = 0;
                for part in index..stop {
                    let len = header.encrypted_segment_len(part).map_err(|_| libc::EIO)? as usize;
                    spans.push((part, &fetched[at..at + len]));
                    at += len;
                }
                let key = self.sdo_meta_key_for_generation(header.key_generation());
                let decoded = if spans.len() == 1 {
                    vec![header
                        .decrypt_segment(key, index, spans[0].1)
                        .map_err(|_| libc::EIO)?]
                } else {
                    std::thread::scope(|scope| -> std::result::Result<Vec<Vec<u8>>, libc::c_int> {
                        let tasks: Vec<_> = spans
                            .iter()
                            .map(|(part, bytes)| {
                                let header = &header;
                                scope.spawn(move || {
                                    header
                                        .decrypt_segment(key, *part, bytes)
                                        .map_err(|_| libc::EIO)
                                })
                            })
                            .collect();
                        tasks
                            .into_iter()
                            .map(|task| task.join().map_err(|_| libc::EIO)?)
                            .collect()
                    })?
                };
                let mut cache = self.sdo_read_cache.lock().map_err(|_| libc::EIO)?;
                let mut first = None;
                for (part, bytes) in (index..stop).zip(decoded) {
                    let bytes = Arc::new(bytes);
                    if part == index {
                        first = Some(bytes.clone());
                    }
                    while cache.iter().map(|(_, _, p)| p.len()).sum::<usize>() + bytes.len()
                        > 32 * 1024 * 1024
                    {
                        cache.pop_front();
                    }
                    cache.push_back((version_id, part, bytes));
                }
                first.ok_or(libc::EIO)?
            };
            let seg_start = u64::from(index) * u64::from(header.segment_size());
            let copy_start = offset.max(seg_start);
            let copy_end = end.min(seg_start + plaintext.len() as u64);
            if copy_start < copy_end {
                let from = (copy_start - seg_start) as usize;
                let to = (copy_end - seg_start) as usize;
                let dest = (copy_start - offset) as usize;
                out[dest..dest + to - from].copy_from_slice(&plaintext[from..to]);
            }
        }

        if offset == 0
            && end == header.size()
            && hex::encode(sha256_bytes(&out)) != header.content_sha256()
        {
            return Err(libc::EIO);
        }
        Ok(out)
    }

    /// Read complete current bytes, preferring the portable file object and
    /// falling back to legacy local block manifests for pre-upgrade files.
    fn current_inode_content(&self, inode: &Inode) -> std::result::Result<Vec<u8>, libc::c_int> {
        if self
            .sdo_identity_store()
            .get(inode.ino)
            .map_err(|_| libc::EIO)?
            .is_some()
        {
            return self.read_sdo_range(inode.ino, 0, inode.size);
        }
        match inode.manifest.as_ref() {
            Some(manifest) => self.assemble_content(manifest, inode.size),
            None => zeroed_buffer(inode.size),
        }
    }

    /// Reassemble bytes `[0, size)` of a file from its manifest. Each pointer
    /// contributes EXACTLY the bytes it records — `length` bytes (clipped to `size`)
    /// placed at its `file_offset` — never the whole decrypted block: a trimmed
    /// pointer (after a shrink) is shorter than its block, and copying the rest
    /// would resurrect truncated bytes. Ranges no pointer covers (holes, a
    /// grow-truncated tail) are zeros. A block that cannot be produced, or that is
    /// shorter than the bytes its pointer claims, fails closed with `EIO`.
    fn assemble_content(
        &self,
        manifest: &FileManifest,
        size: u64,
    ) -> std::result::Result<Vec<u8>, libc::c_int> {
        let mut out = zeroed_buffer(size)?;
        for bp in &manifest.blocks {
            if bp.file_offset >= size {
                continue;
            }
            let need = bp.length.min(size - bp.file_offset) as usize;
            if need == 0 {
                continue;
            }
            let data = self
                .download_block(bp.message_id, &bp.block_id, bp.epoch)
                .ok_or(libc::EIO)?;
            if data.len() < need {
                tracing::error!(
                    ino = manifest.inode,
                    block_id = hex::encode(bp.block_id),
                    block_len = data.len(),
                    needed = need,
                    "block shorter than its manifest pointer — refusing (EIO)"
                );
                return Err(libc::EIO);
            }
            let off = bp.file_offset as usize;
            out[off..off + need].copy_from_slice(&data[..need]);
        }
        Ok(out)
    }

    /// In-flight file size for `ino`: the length of its dirty write buffer, if any.
    /// Lets `getattr` show a growing file during writing without persisting a
    /// non-durable size to the journaled `inodes` table.
    fn inflight_size(&self, ino: u64) -> Option<u64> {
        self.handles
            .handles_for_ino(ino)
            .into_iter()
            .filter_map(|fh| self.handles.spool(true, fh))
            .filter_map(|s| s.lock().ok()?.len().ok())
            .max()
            .or_else(|| self.handles.buffer_len(ino))
    }

    /// Core of `setattr`: apply + journal an attribute change. Callable in-process
    /// for tests. Returns the updated inode for the reply. The attribute change is
    /// journaled so chmod/chown/truncate/utimes survive crash recovery.
    ///
    /// A size change is applied to the inode's in-flight write buffer too (if it
    /// has one), but only AFTER the persisted change commits, so a failed setattr
    /// leaves the buffer untouched. Truncating to zero discards the buffer outright.
    #[allow(clippy::too_many_arguments)]
    fn setattr_impl(
        &self,
        ino: u64,
        req_uid: u32,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> std::result::Result<Inode, libc::c_int> {
        let explicit_setattr = mode.is_some()
            || uid.is_some()
            || gid.is_some()
            || size.is_some()
            || atime.is_some()
            || mtime.is_some();
        if let Some(s) = size {
            // M6: refuse sizes past the cap; a later write would have to allocate it.
            if s > MAX_FILE_SIZE {
                return Err(libc::EFBIG);
            }
            // Reserve any buffer growth BEFORE persisting, so an allocation failure
            // cannot leave the persisted size and the buffer length disagreeing.
            let reserved = self.handles.with_buffer(ino, |buf| {
                let s = s as usize;
                if s > buf.len() {
                    buf.try_reserve(s - buf.len())
                } else {
                    Ok(())
                }
            });
            if let Some(Err(_)) = reserved {
                return Err(libc::ENOSPC);
            }
        }
        let inode =
            self.setattr_persist(ino, req_uid, mode, uid, gid, size, atime, mtime, false)?;
        if let Some(s) = size {
            if let Some(spool) = self.handles.spool(false, ino) {
                spool
                    .lock()
                    .map_err(|_| libc::EIO)?
                    .resize(s)
                    .map_err(|_| libc::EIO)?;
            }
            if s == 0 {
                self.handles.discard_buffer(ino);
            } else {
                self.handles
                    .with_buffer(ino, |buf| buf.resize(s as usize, 0));
            }
        }
        if explicit_setattr {
            self.handles.mark_setattr(ino);
        }
        Ok(inode)
    }

    /// The persisted half of [`Self::setattr_impl`].
    #[allow(clippy::too_many_arguments)]
    fn setattr_persist(
        &self,
        ino: u64,
        req_uid: u32,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        defer_portable: bool,
    ) -> std::result::Result<Inode, libc::c_int> {
        let mut inode = self
            .store()
            .get(ino)
            .map_err(|e| {
                tracing::error!(error = %e, "setattr get failed");
                libc::EIO
            })?
            .ok_or(libc::ENOENT)?;

        if self.sdo_context.is_some()
            && (atime.is_some()
                || uid.is_some()
                || gid.is_some()
                || (inode.is_dir()
                    && (size.is_some() || (ino == 1 && (mode.is_some() || mtime.is_some())))))
        {
            tracing::warn!(ino, "TGFV does not persist access times, ownership, directory sizes or root-directory attributes");
            return Err(libc::ENOTSUP);
        }

        // H7: only root may chown/chgrp; only root or the owner may chmod.
        if (uid.is_some() || gid.is_some()) && req_uid != 0 {
            return Err(libc::EPERM);
        }
        if mode.is_some() && req_uid != 0 && req_uid != inode.uid {
            return Err(libc::EPERM);
        }

        if let Some(m) = mode {
            inode.mode = m;
        }
        if let Some(u) = uid {
            inode.uid = u;
        }
        if let Some(g) = gid {
            inode.gid = g;
        }
        if let Some(a) = atime {
            inode.timestamps.atime_ns = time_or_now_to_ns(a);
        }
        if let Some(m) = mtime {
            inode.timestamps.mtime_ns = time_or_now_to_ns(m);
        }
        inode.timestamps.ctime_ns = system_time_to_ns(SystemTime::now());

        if defer_portable {
            // The dirty descriptor will publish these attributes with its resized
            // spool at flush. Keep committed content and size intact until then.
            self.journaled_txn(|| self.store().update(&inode).map_err(|_| libc::EIO))?;
            return Ok(inode);
        }

        // Portable versions describe the complete logical bytes after every
        // truncate/grow, including zero-filled growth. Materialize that image and
        // route it through the same block → TGFV → journal transaction as writes.
        if self.sdo_context.is_some() && inode.is_file() {
            if let Some(new_size) = size.filter(|s| *s != inode.size) {
                if new_size
                    > self
                        .sdo_context
                        .map_or(MAX_FILE_SIZE, |context| context.max_file_size)
                {
                    return Err(libc::EFBIG);
                }
                let mut content =
                    if let Some(buffer) = self.handles.with_buffer(ino, |buf| buf.clone()) {
                        buffer
                    } else {
                        self.current_inode_content(&inode)?
                    };
                content.resize(new_size as usize, 0);
                let outcomes = Vec::new();
                inode.size = new_size;
                return self
                    .persist_file_blocks_inner(ino, &content, outcomes, Some(inode))
                    .and_then(|()| {
                        self.store()
                            .get(ino)
                            .map_err(|_| libc::EIO)?
                            .ok_or(libc::ENOENT)
                    });
            }
        }

        // Truncate is AUTHORITATIVE over the file LENGTH via `inode.size`, and the
        // committed manifest must NEVER describe more bytes than `inode.size` —
        // otherwise a later grow back into the stale region resurrects truncated
        // bytes (a confidentiality leak: truncated-away plaintext re-served). On
        // EVERY size change we reconcile the manifest down to `cut = min(new_size,
        // old_size)` whenever `manifest.total_size > cut` — keyed off the
        // AUTHORITATIVE `old_size`, never `manifest.total_size`, and UNCONDITIONALLY
        // (regardless of dirty handles, else a grow while a handle is dirty would
        // commit a torn manifest):
        //   - CLEAN, ONLINE shrink (`cut == s`, no dirty handle, transport present):
        //     MATERIALIZE — download [0,s), re-cut, re-persist (correct file_hash,
        //     the common case);
        //   - otherwise (dirty handle, a grow with a torn manifest, or an offline
        //     shrink): metadata-only pointer-trim to `cut` (no download), archived as
        //     a NEW manifest version so the inline manifest's identity stays in the
        //     archive and a later persist's `parent_ids` / DAG lineage don't dangle.
        // A torn state only resurrects on grow; plain reads serve the valid prefix,
        // so no eager pre-v0.4.7 migration is needed — the grow-cut heals lazily.
        if let Some(s) = size {
            let old_size = inode.size;
            inode.size = s;
            // A write buffer is the in-flight content the next persist uploads; the
            // caller (`setattr_impl`) resizes it to `s` once this commits.
            let has_dirty = self.handles.has_buffer(ino);
            if s == 0 {
                // No live bytes — drop the manifest so recovery and GC see an empty
                // file rather than a stale block list.
                inode.manifest = None;
            } else if let Some(m) = inode.manifest.clone() {
                let cut = s.min(old_size);
                if m.total_size > cut {
                    if cut == s && !has_dirty && self.transport.is_some() {
                        // MATERIALIZE: reconstruct [0, s) from the existing blocks
                        // (fail-closed EIO on any missing block — commit nothing),
                        // truncate, and re-persist the trimmed content + this setattr's
                        // attrs in ONE journaled txn (no two-write window). Fixed-size
                        // chunking means only the boundary chunk re-uploads.
                        let content = self.assemble_content(&m, s)?;
                        let outcomes = self
                            .flush_chunks_to_transport(ino, &content)
                            .ok_or(libc::EIO)?;
                        self.persist_file_blocks_inner(
                            ino,
                            &content,
                            outcomes,
                            Some(inode.clone()),
                        )?;
                        return self
                            .store()
                            .get(ino)
                            .map_err(|_| libc::EIO)?
                            .ok_or(libc::ENOENT);
                    } else {
                        // Metadata-only pointer-trim to `cut`, archived as a NEW
                        // version (parent = the original manifest's id) so lineage
                        // stays intact. No download. `inode.size` stays `s`; `read`
                        // zero-fills [cut, s). (For a dirty shrink the buffer is the
                        // live content and release rewrites the manifest; this trim
                        // only keeps the committed state non-torn meanwhile.)
                        let max_persisted = self.manifest_store().max_version(ino).map_err(|e| {
                            tracing::error!(error = %e, "setattr trim: max_version read failed");
                            libc::EIO
                        })?;
                        let new_version = m.version.max(max_persisted) + 1;
                        let parent_id = self.manifest_key.as_ref().map(|mk| m.compute_id(mk));
                        let mut trimmed = trim_manifest_blocks(&m, cut);
                        trimmed.version = new_version;
                        trimmed.parent_ids = parent_id.into_iter().collect();
                        let trimmed_id =
                            self.manifest_key.as_ref().map(|mk| trimmed.compute_id(mk));
                        inode.manifest = Some(trimmed.clone());
                        self.journaled_txn(|| {
                            self.manifest_store().insert(&trimmed).map_err(|e| {
                                tracing::error!(error = %e, "setattr: archive trimmed manifest failed");
                                libc::EIO
                            })?;
                            if let (Some(tid), Some(pid)) = (&trimmed_id, &parent_id) {
                                if let Err(e) =
                                    self.dag_store().insert_edges(tid, std::slice::from_ref(pid))
                                {
                                    tracing::warn!(ino, error = %e, "setattr: trimmed-manifest DAG edge failed");
                                }
                            }
                            self.store().update(&inode).map_err(|e| {
                                tracing::error!(error = %e, "setattr trim update failed");
                                libc::EIO
                            })
                        })?;
                        return Ok(inode);
                    }
                }
            }
        }

        let pending_sdo = if self.sdo_context.is_some()
            && (inode.is_file() || (inode.is_dir() && (mode.is_some() || mtime.is_some())))
        {
            let path = self.path_for_inode(ino)?;
            let content = if inode.is_file() {
                self.current_inode_content(&inode)?
            } else {
                Vec::new()
            };
            let pointers = inode
                .manifest
                .as_ref()
                .map(|manifest| manifest.blocks.as_slice())
                .unwrap_or(&[]);
            Some(self.upload_sdo_version(&inode, &path, &content, pointers, &[], false, None)?)
        } else {
            None
        };
        self.journaled_txn(|| {
            self.store().update(&inode).map_err(|e| {
                tracing::error!(error = %e, "setattr update failed");
                libc::EIO
            })?;
            if let Some(pending) = &pending_sdo {
                self.commit_sdo_version(pending)?;
            }
            Ok(())
        })?;
        if let Some(pending) = pending_sdo {
            self.pending_sdo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&pending.stored.path_id);
        }
        Ok(inode)
    }

    /// Persist `ino`'s dirty write buffer, if it has one: upload the blocks and
    /// journal the block rows + manifest. On success the buffer is zeroized and
    /// dropped (the persisted state is now authoritative; a later write re-seeds
    /// from it). On failure the buffer is put back UNCHANGED and the error returned,
    /// so the data is not lost while the file is still open and a later
    /// flush/fsync/release can retry.
    fn persist_buffer(&self, ino: u64) -> std::result::Result<(), libc::c_int> {
        if self.handles.spool(false, ino).is_some() {
            return self.persist_spool(ino, 0);
        }
        let Some(mut data) = self.handles.take_buffer(ino) else {
            return Ok(());
        };
        match self.persist_data(ino, &data) {
            Ok(()) => {
                data.zeroize();
                Ok(())
            }
            Err(e) => {
                self.handles.insert_buffer(ino, data);
                Err(e)
            }
        }
    }

    fn persist_handle_buffer(&self, ino: u64, fh: u64) -> std::result::Result<(), libc::c_int> {
        if self.handles.spool(true, fh).is_some() {
            return self.persist_spool(ino, fh);
        }
        let Some(mut data) = self.handles.take_handle_buffer(fh) else {
            return Ok(());
        };
        let result = (|| {
            let handle = self.handles.get(fh).ok_or(libc::EBADF)?;
            let durable_retry = self
                .sdo_pending_write_store()
                .list()
                .map_err(|_| libc::EIO)?
                .into_iter()
                .find(|pending| pending.handle_id == fh)
                .ok_or(libc::EIO)?;
            let pinned_identity =
                self.opened_sdo_identity(ino, &handle, durable_retry.metadata_snapshot.as_deref())?;
            self.persist_file_blocks_inner_with_identity(
                ino,
                &data,
                Vec::new(),
                None,
                pinned_identity,
                Some(durable_retry),
            )
        })();
        match result {
            Ok(()) => {
                data.zeroize();
                Ok(())
            }
            Err(error) => {
                self.handles.insert_handle_buffer(fh, data);
                Err(error)
            }
        }
    }

    fn persist_portable_rename_writes(&self, ino: u64) -> std::result::Result<(), libc::c_int> {
        let mut dirty = Vec::new();
        for fh in self.handles.handles_for_ino(ino) {
            if self.check_handle_live(Some(fh)).is_err() || !self.handles.has_handle_buffer(fh) {
                continue;
            }
            let (clock_ms, clock_counter) = if let Some(spool) = self.handles.spool(true, fh) {
                let spool = spool.lock().map_err(|_| libc::EIO)?;
                (
                    spool.intent.metadata.clock_ms,
                    spool.intent.metadata.clock_counter,
                )
            } else {
                (0, 0)
            };
            dirty.push((clock_ms, clock_counter, fh));
        }
        // The last published local version becomes the rename source. Apply
        // dirty writers in the same order as the portable history clock.
        dirty.sort_unstable();
        for (_, _, fh) in dirty {
            self.persist_handle_buffer(ino, fh)?;
        }
        Ok(())
    }

    fn persist_data(&self, ino: u64, data: &[u8]) -> std::result::Result<(), libc::c_int> {
        // An empty buffer mirrors an empty persisted file (a truncate to zero
        // discards the buffer, so an empty one only ever seeds from size 0).
        if data.is_empty() && self.sdo_context.is_none() {
            return Ok(());
        }
        // C3: without a transport there is nowhere to store blocks. Never report
        // success for bytes that were not persisted.
        if self.transport.is_none() {
            tracing::error!(
                ino,
                bytes = data.len(),
                "no block transport on this mount — cannot persist file data (EIO)"
            );
            return Err(libc::EIO);
        }
        match self.store().get(ino) {
            Ok(Some(_)) => {}
            // Unlinked while open: the data has no file to belong to (POSIX drops
            // it at last close). Nothing to persist, nothing to report.
            Ok(None) => {
                tracing::debug!(ino, "persist: inode was unlinked; dropping its buffer");
                return Ok(());
            }
            Err(e) => {
                tracing::error!(ino, error = %e, "persist: inode read failed");
                return Err(libc::EIO);
            }
        }
        let outcomes = if data.is_empty() || self.sdo_context.is_some() {
            Vec::new()
        } else {
            self.flush_chunks_to_transport(ino, data).ok_or_else(|| {
                tracing::error!(ino, "block upload failed — returning EIO");
                libc::EIO
            })?
        };
        self.persist_file_blocks(ino, data, outcomes)
    }

    /// Core of `release`: persist any dirty data still buffered for the inode
    /// (normally `flush` already did, so this is a retry for a failed flush).
    /// Callable in-process for tests. Does NOT touch the handle table (the caller
    /// closes the handle, which discards the buffer once no handle remains).
    fn release_impl(&self, ino: u64, fh: u64) -> std::result::Result<(), libc::c_int> {
        // A stale handle's own data was discarded with its deleted file; any buffer
        // under this number belongs to the file that reused it.
        if self.check_handle_live(Some(fh)).is_err() {
            return Ok(());
        }
        if self.sdo_context.is_some() && self.handles.has_handle_buffer(fh) {
            self.persist_handle_buffer(ino, fh)
        } else {
            self.persist_buffer(ino)
        }
    }

    /// Core of FUSE `flush`, which the kernel sends on EVERY `close(2)` of a
    /// descriptor (including dup'd ones and a child's inherited fds at exit) and
    /// whose error `close(2)` returns. A handle opened for writing persists the
    /// inode's dirty data here, so a failed upload surfaces to the application as
    /// `EIO` from `close(2)` instead of being lost silently in `release` (whose
    /// errors the kernel discards). A read-only handle does nothing.
    fn flush_impl(&self, ino: u64, fh: u64) -> std::result::Result<(), libc::c_int> {
        match self.handles.get(fh) {
            // Stale (deleted file): nothing of this handle's is left to persist, and
            // the writes through it already failed with ESTALE.
            Some(handle) if handle.writable() && !handle.stale => {
                // dup/dup2 users (including shell redirects) close the original
                // descriptor before writing. Only final RELEASE commits an
                // untouched create; real writes still report flush errors.
                if self.handles.is_deferred_empty_create(fh) {
                    return Ok(());
                }
                if self.sdo_context.is_some() && self.handles.has_handle_buffer(fh) {
                    self.persist_handle_buffer(ino, fh)
                } else {
                    self.persist_buffer(ino)
                }
            }
            _ => Ok(()),
        }
    }

    /// `fsync(2)` core: durably commit the inode's buffered writes NOW — upload the
    /// blocks (blocks until they land on the transport) and journal the manifest,
    /// WITHOUT closing the handle. This is what lets an HTTP gateway upload
    /// (`fsync`/`sync_all` before it reports success) guarantee the object is on
    /// Telegram and immediately readable.
    fn fsync_impl(&self, ino: u64, fh: u64) -> std::result::Result<(), libc::c_int> {
        self.check_handle_live(Some(fh))?;
        self.handles.mark_written(fh);
        if self.sdo_context.is_some() && self.handles.has_handle_buffer(fh) {
            self.persist_handle_buffer(ino, fh)
        } else {
            self.persist_buffer(ino)
        }
    }

    /// Core of `volume revert`: append a NEW manifest version for `ino` whose content
    /// is the prior `target_version`'s blocks — restoring that version without losing
    /// history (git-revert style: the new version descends from BOTH the current head
    /// and the target). The target's blocks are reused verbatim (no re-upload — they
    /// are still present; GC has not run), so this is `persist` minus the upload, in
    /// ONE `journaled_txn` (publish delta → persist HEAD → commit — the same crash-safe
    /// ordering). Callable in-process for tests; the CLI drives it via a transient
    /// journaled mount (offline + while-FUSE-mounted are refused — single-writer).
    pub fn revert_impl(
        &self,
        ino: u64,
        target_version: u64,
    ) -> std::result::Result<Inode, libc::c_int> {
        let inode = self
            .store()
            .get(ino)
            .map_err(|_| libc::EIO)?
            .ok_or(libc::ENOENT)?;
        if !inode.is_file() {
            // A directory is EISDIR; a symlink (or anything else) is EINVAL — never
            // misreport a symlink as a directory.
            return Err(if inode.is_dir() {
                libc::EISDIR
            } else {
                libc::EINVAL
            });
        }
        let target = self
            .manifest_store()
            .get(ino, target_version)
            .map_err(|_| libc::EIO)?
            .ok_or(libc::ENOENT)?; // no such version

        // The reverting version reuses the target's blocks BY REFERENCE (no
        // re-upload), so every referenced block must still be present in the block
        // store — otherwise we would commit a new head whose blocks are dangling and
        // the file would read EIO with "Reverted" reported as success. `increment_ref`
        // silently no-ops on a missing row, so verify existence explicitly first.
        // (Unreachable today — no path prunes block rows — but a required precondition
        // before block-GC lands; see audit v0.4.8 #6.)
        {
            let block_store = self.block_store();
            for bp in &target.blocks {
                let present = block_store
                    .get(&bp.block_id)
                    .map_err(|e| {
                        tracing::error!(error = %e, "revert: block existence check failed");
                        libc::EIO
                    })?
                    .is_some();
                if !present {
                    tracing::error!(
                        ino,
                        target_version,
                        "revert: target version references a block no longer present; refusing"
                    );
                    return Err(libc::EIO);
                }
            }
        }

        let mk = self.manifest_key.as_ref();
        let head_id = inode
            .manifest
            .as_ref()
            .zip(mk)
            .map(|(m, k)| m.compute_id(k));
        let target_id = mk.map(|k| target.compute_id(k));
        let prev_version = inode.manifest.as_ref().map_or(0, |m| m.version);
        let max_persisted = self.manifest_store().max_version(ino).map_err(|e| {
            tracing::error!(error = %e, "revert: max_version read failed");
            libc::EIO
        })?;
        let new_version = prev_version.max(max_persisted) + 1;

        // Lineage parents: the current head (if any) and the reverted-to target,
        // deduplicated (reverting onto the current head is a no-op-content version).
        let mut parent_ids: Vec<[u8; 32]> = Vec::new();
        if let Some(h) = head_id {
            parent_ids.push(h);
        }
        if let Some(t) = target_id {
            if !parent_ids.contains(&t) {
                parent_ids.push(t);
            }
        }

        let manifest = FileManifest {
            inode: ino,
            version: new_version,
            total_size: target.total_size,
            file_hash: target.file_hash,
            blocks: target.blocks.clone(),
            parent_ids: parent_ids.clone(),
        };
        let new_id = mk.map(|k| manifest.compute_id(k));
        let pending_sdo = if self.sdo_context.is_some() {
            let path = self.path_for_inode(ino)?;
            let mut published = inode.clone();
            published.manifest = Some(manifest.clone());
            published.size = manifest.total_size;
            let content = if self.sdo_context.is_some()
                && manifest.total_size > 0
                && manifest.blocks.is_empty()
            {
                let context = self.sdo_context.ok_or(libc::EIO)?;
                let mut match_content = None;
                let versions = self.sdo_version_store().list_for_inode(ino).map_err(|e| {
                    tracing::error!(ino, error = %e, "revert: portable history lookup failed");
                    libc::EIO
                })?;
                for stored in versions.into_iter().rev() {
                    let header = decode_stored_sdo_header(
                        &stored.wire,
                        context.volume_id,
                        &self.meta_key,
                        &self.sdo_generation_meta_keys,
                    )
                    .map_err(|_| libc::EIO)?;
                    if header.deleted() || header.size() != manifest.total_size {
                        continue;
                    }
                    let content = self.read_sdo_stored_range(
                        ino,
                        header.version_id(),
                        stored,
                        0,
                        manifest.total_size,
                    )?;
                    if keyed_hash(self.manifest_key.as_ref().ok_or(libc::EIO)?, &content)
                        == manifest.file_hash
                    {
                        match_content = Some(content);
                        break;
                    }
                }
                match_content.ok_or(libc::EIO)?
            } else {
                self.assemble_content(&manifest, manifest.total_size)?
            };
            Some(self.upload_sdo_version(
                &published,
                &path,
                &content,
                &manifest.blocks,
                &[],
                false,
                None,
            )?)
        } else {
            None
        };

        self.journaled_txn(|| {
            let block_store = self.block_store();
            // Re-reference the reused blocks (consistency with the persist path;
            // ref_count is currently advisory — GC will be a mark-sweep).
            for bp in &manifest.blocks {
                block_store.increment_ref(&bp.block_id).map_err(|e| {
                    tracing::error!(error = %e, "revert: block ref bump failed");
                    libc::EIO
                })?;
            }
            self.manifest_store().insert(&manifest).map_err(|e| {
                tracing::error!(error = %e, "revert: archive manifest failed");
                libc::EIO
            })?;
            let store = self.store();
            let mut inode = store.get(ino).map_err(|_| libc::EIO)?.ok_or(libc::ENOENT)?;
            inode.manifest = Some(manifest.clone());
            inode.size = manifest.total_size;
            store.update(&inode).map_err(|e| {
                tracing::error!(error = %e, "revert: inode update failed");
                libc::EIO
            })?;
            if let Some(pending) = &pending_sdo {
                self.commit_sdo_version(pending)?;
            }
            if let Some(nid) = &new_id {
                if !parent_ids.is_empty() {
                    if let Err(e) = self.dag_store().insert_edges(nid, &parent_ids) {
                        tracing::warn!(ino, error = %e, "revert: DAG edges failed");
                    }
                }
            }
            Ok(())
        })?;

        if let Some(pending) = pending_sdo {
            self.pending_sdo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&pending.stored.path_id);
        }

        self.store()
            .get(ino)
            .map_err(|_| libc::EIO)?
            .ok_or(libc::ENOENT)
    }

    /// Core of `open`: verify the inode exists, apply `O_TRUNC` (truncate the file
    /// to zero, journaled), and open a handle. Callable in-process for tests.
    fn open_impl(&self, ino: u64, flags: i32, uid: u32) -> std::result::Result<u64, libc::c_int> {
        let inode = match self.store().get(ino) {
            Ok(Some(i)) => i,
            Ok(None) => return Err(libc::ENOENT),
            Err(_) => return Err(libc::EIO),
        };

        if self.sdo_context.is_some() && flags & libc::O_TRUNC != 0 {
            // Pin the predecessor before staging truncation. A truncate+write
            // save publishes one successor at flush/fsync, including an empty
            // successor when the descriptor closes without any writes.
            let fh = self.open_handle_pinned(ino, flags, uid)?;
            let handle = self.handles.get(fh).ok_or(libc::EBADF)?;
            let result = self.journaled_txn(|| {
                let mut truncated = inode;
                truncated.size = 0;
                truncated.manifest = None;
                truncated.timestamps.mtime_ns = system_time_to_ns(SystemTime::now());
                self.store().update(&truncated).map_err(|_| libc::EIO)?;
                self.stage_portable_write(ino, &handle, true)
            });
            if let Err(error) = result {
                self.handles.close(fh);
                return Err(error);
            }
            // The staged write owns a disk spool, including empty files.
            return Ok(fh);
        }

        // O_TRUNC: empty the file at open. Journaled so the truncation survives crash
        // recovery; otherwise an open(O_TRUNC) + close-without-write would leave the
        // old content. (Old blocks become unreferenced — reclaimed by future GC.)
        if (flags & libc::O_TRUNC) != 0 {
            if inode.size != 0 || inode.manifest.is_some() {
                let mut truncated = inode;
                truncated.size = 0;
                truncated.manifest = None;
                truncated.timestamps.mtime_ns = system_time_to_ns(SystemTime::now());
                self.journaled_txn(|| {
                    self.store().update(&truncated).map_err(|e| {
                        tracing::error!(error = %e, "open O_TRUNC update failed");
                        libc::EIO
                    })
                })?;
            }
            // The truncation applies to the shared in-flight image too: bytes
            // another handle wrote but has not yet persisted are truncated away.
            self.handles.discard_buffer(ino);
        }

        self.open_handle_pinned(ino, flags, uid)
    }

    fn open_handle_pinned(
        &self,
        ino: u64,
        flags: i32,
        uid: u32,
    ) -> std::result::Result<u64, libc::c_int> {
        if self.sdo_context.is_some() {
            if let Some(version_id) = self
                .sdo_identity_store()
                .get(ino)
                .map_err(|_| libc::EIO)?
                .and_then(|identity| identity.latest_version_id)
            {
                return Ok(self.handles.open_pinned_sdo(ino, flags, uid, version_id));
            }
        }
        Ok(self.handles.open(ino, flags, uid))
    }

    /// Core of `read`: return the bytes for `[offset, offset+size)` of `ino`.
    /// Served from the handle's dirty write buffer if present, else reassembled
    /// from the manifest blocks. `inode.size` is the authoritative length: an
    /// in-bounds range that no block covers (a hole, or the zero-extended tail of a
    /// grow-truncate whose manifest is shorter than `inode.size`) returns zeros up
    /// to the file size (POSIX), and a ranged read past a shrunk size returns empty
    /// (the manifest may still describe more bytes). A required-but-unproducible
    /// block fails closed with `EIO`. Callable in-process for tests.
    fn read_impl(
        &self,
        ino: u64,
        fh: u64,
        req_uid: u32,
        offset: i64,
        size: u32,
    ) -> std::result::Result<Vec<u8>, libc::c_int> {
        // M1: file-handle ownership — only the opener or root may read through
        // this handle. (The in-flight buffer itself is per inode, so every handle
        // the kernel allowed to open the file sees its current content, as on any
        // POSIX filesystem.)
        let handle = self.handles.get(fh);
        if let Some(handle) = &handle {
            if req_uid != 0 && handle.uid != req_uid {
                return Err(libc::EACCES);
            }
            // Deleted file: never serve the bytes of a file that reused its number.
            if handle.stale {
                return Err(libc::ESTALE);
            }
        }

        let inode = match self.store().get(ino) {
            Ok(Some(i)) => i,
            Ok(None) => return Err(libc::ENOENT),
            Err(_) => return Err(libc::EIO),
        };
        if !inode.is_file() {
            return Err(libc::EISDIR);
        }
        // R4-H02: guard negative offset (OOM/wrap) + offset+size overflow.
        if offset < 0 {
            return Err(libc::EINVAL);
        }
        let offset = offset as usize;
        if offset.checked_add(size as usize).is_none() {
            return Err(libc::EINVAL);
        }

        let portable = self.sdo_context.is_some();
        if let Some(spool) = self
            .handles
            .spool(portable, if portable { fh } else { ino })
        {
            return spool
                .lock()
                .map_err(|_| libc::EIO)?
                .read_range(offset as u64, size as usize)
                .map_err(|_| libc::EIO);
        }
        if self.sdo_context.is_some() {
            if let Some(bytes) = self.handles.with_handle_buffer(fh, |buf| {
                if offset >= buf.len() {
                    Vec::new()
                } else {
                    let end = std::cmp::min(offset + size as usize, buf.len());
                    buf[offset..end].to_vec()
                }
            }) {
                return Ok(bytes);
            }
        }

        if let Some(version_id) = handle.as_ref().and_then(|h| h.pinned_sdo_version) {
            return self.read_sdo_version_range(ino, version_id, offset as u64, u64::from(size));
        }

        // In-flight write buffer first: the inode's not-yet-persisted bytes are the
        // file's current content, visible through every handle on it.
        let buffered = self.handles.with_buffer(ino, |buf| {
            if offset >= buf.len() {
                Vec::new()
            } else {
                let end = std::cmp::min(offset + size as usize, buf.len());
                buf[offset..end].to_vec()
            }
        });
        if let Some(bytes) = buffered {
            return Ok(bytes);
        }

        if self
            .sdo_identity_store()
            .get(ino)
            .map_err(|e| {
                tracing::error!(ino, error = %e, "portable file identity read failed");
                libc::EIO
            })?
            .is_some()
        {
            return self.read_sdo_range(ino, offset as u64, u64::from(size));
        }

        // No in-memory data — reassemble from manifest blocks.
        if let Some(ref manifest) = inode.manifest {
            if !manifest.blocks.is_empty() {
                let read_offset = offset as u64;
                let read_len = u64::from(size);
                let needed = manifest.blocks_in_range(read_offset, read_len);

                let mut result_buf = vec![0u8; size as usize];
                for bp in &needed {
                    // Fail-closed: a required block that can't be produced (transport
                    // error or T7 integrity refusal) fails the read with EIO rather
                    // than returning silently-zeroed data (a block-substitution
                    // attack would otherwise read as a quiet hole).
                    let data = self
                        .download_block(bp.message_id, &bp.block_id, bp.epoch)
                        .ok_or(libc::EIO)?;
                    let block_start = bp.file_offset;
                    let block_end = bp.file_offset + bp.length;
                    let read_start = read_offset.max(block_start);
                    let read_end = (read_offset + read_len).min(block_end);
                    if read_start < read_end {
                        let src_off = (read_start - block_start) as usize;
                        let dst_off = (read_start - read_offset) as usize;
                        let copy_len = (read_end - read_start) as usize;
                        let src_end = src_off + copy_len;
                        // A decrypted block shorter than its pointer claims cannot
                        // produce the requested bytes: fail closed rather than
                        // serve the gap as zeros.
                        if src_end > data.len() {
                            tracing::error!(
                                ino,
                                block_id = hex::encode(bp.block_id),
                                block_len = data.len(),
                                needed = src_end,
                                "block shorter than its manifest pointer — refusing read (EIO)"
                            );
                            return Err(libc::EIO);
                        }
                        result_buf[dst_off..dst_off + copy_len]
                            .copy_from_slice(&data[src_off..src_end]);
                    }
                }

                if !needed.is_empty() {
                    // Read-ahead: prefetch the blocks immediately after this read so a
                    // sequential reader finds them cached (best-effort, background).
                    self.trigger_prefetch(manifest, read_offset + read_len);

                    // Clamp to the authoritative size — a stale-longer manifest
                    // (post-shrink) must not return bytes past `inode.size`.
                    let actual_len =
                        std::cmp::min(u64::from(size), inode.size.saturating_sub(read_offset))
                            as usize;
                    return Ok(result_buf[..actual_len].to_vec());
                }
            }
        }

        // No block covers this range. If the offset is still within the file (a
        // hole, or the zero-extended tail of a grow-truncate), POSIX requires zeros
        // up to the file size — NOT EOF. Past the size, return empty.
        let off = offset as u64;
        if off < inode.size {
            let n = std::cmp::min(u64::from(size), inode.size - off) as usize;
            Ok(vec![0u8; n])
        } else {
            Ok(Vec::new())
        }
    }

    /// Core of `unlink`. Callable in-process for tests (the FUSE callback is a thin
    /// wrapper that adds the read-only guard).
    fn unlink_impl(
        &self,
        req_uid: u32,
        parent: u64,
        name: &OsStr,
    ) -> std::result::Result<(), libc::c_int> {
        let name_str = name.to_str().ok_or(libc::EINVAL)?;

        let store = self.store();

        // H11: Enforce ownership — caller must own the parent directory or be root.
        match store.get(parent) {
            Ok(Some(parent_inode)) => {
                if req_uid != 0 && req_uid != parent_inode.uid {
                    return Err(libc::EPERM);
                }
            }
            Ok(None) => return Err(libc::ENOENT),
            Err(_) => return Err(libc::EIO),
        }

        let inode = match store.lookup(parent, name_str) {
            Ok(Some(i)) => i,
            Ok(None) => return Err(libc::ENOENT),
            Err(_) => return Err(libc::EIO),
        };

        if inode.is_dir() {
            return Err(libc::EISDIR);
        }

        let pending_sdo = if self.sdo_context.is_some() {
            let path = self.path_for_inode(inode.ino)?;
            Some(self.upload_sdo_version(&inode, &path, &[], &[], &[], true, None)?)
        } else {
            None
        };

        self.journaled_txn(|| {
            let store = self.store();
            // Remove from parent's children. Every store error inside this
            // transaction propagates (EIO) so journaled_txn rolls the whole unlink
            // back — never a half-applied change reported as success.
            if let Some(mut parent_inode) = txn_get(&store, parent, "unlink parent")? {
                parent_inode.children.retain(|&c| c != inode.ino);
                txn_update(&store, &parent_inode, "unlink parent")?;
            }
            // Delete the inode.
            if let Err(e) = store.delete(inode.ino) {
                tracing::error!(error = %e, "unlink delete failed");
                return Err(libc::EIO);
            }
            // Destroy the inode's manifest history too: `next_ino` (= MAX(ino)+1)
            // can recycle this freed number, and a new file must NOT inherit this
            // file's version history or counter. Same journaled_txn as the inode
            // delete so recovery rebuilds a coherent state. (Blocks stay until GC.)
            if let Err(e) = self.manifest_store().delete_versions(inode.ino) {
                tracing::error!(error = %e, "unlink: manifest history cleanup failed");
                return Err(libc::EIO);
            }
            if let Some(pending) = &pending_sdo {
                self.commit_sdo_version(pending)?;
            }
            Ok(())
        })?;
        if let Some(pending) = pending_sdo {
            self.pending_sdo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&pending.stored.path_id);
        }
        // The inode is gone, and `next_ino` will hand its number to the next
        // create. Its dirty write buffer (keyed by ino) must go with it, or the
        // recycled inode would read — and persist — the deleted file's bytes; and
        // descriptors still open on it must not reach the file that reuses it.
        self.forget_deleted_inode(inode.ino);
        Ok(())
    }

    /// Core of `rmdir`. Callable in-process for tests (the FUSE callback is a thin
    /// wrapper that adds the read-only guard).
    fn rmdir_impl(
        &self,
        req_uid: u32,
        parent: u64,
        name: &OsStr,
    ) -> std::result::Result<(), libc::c_int> {
        let name_str = name.to_str().ok_or(libc::EINVAL)?;

        let store = self.store();

        // H11: Enforce ownership — caller must own the parent directory or be root.
        match store.get(parent) {
            Ok(Some(parent_inode)) => {
                if req_uid != 0 && req_uid != parent_inode.uid {
                    return Err(libc::EPERM);
                }
            }
            Ok(None) => return Err(libc::ENOENT),
            Err(_) => return Err(libc::EIO),
        }

        let inode = match store.lookup(parent, name_str) {
            Ok(Some(i)) => i,
            Ok(None) => return Err(libc::ENOENT),
            Err(_) => return Err(libc::EIO),
        };

        if !inode.is_dir() {
            return Err(libc::ENOTDIR);
        }

        if !inode.children.is_empty() {
            return Err(libc::ENOTEMPTY);
        }

        let pending_sdo = if self.sdo_context.is_some() {
            let path = self.path_for_inode(inode.ino)?;
            Some(self.upload_sdo_version(&inode, &path, &[], &[], &[], true, None)?)
        } else {
            None
        };

        self.journaled_txn(|| {
            let store = self.store();
            // Remove from parent's children. Store errors propagate (EIO) so
            // journaled_txn rolls the whole rmdir back (same rule as unlink).
            if let Some(mut parent_inode) = txn_get(&store, parent, "rmdir parent")? {
                parent_inode.children.retain(|&c| c != inode.ino);
                parent_inode.nlink = parent_inode.nlink.saturating_sub(1);
                txn_update(&store, &parent_inode, "rmdir parent")?;
            }
            if let Err(e) = store.delete(inode.ino) {
                tracing::error!(error = %e, "rmdir delete failed");
                return Err(libc::EIO);
            }
            if let Some(pending) = &pending_sdo {
                self.commit_sdo_version(pending)?;
            }
            Ok(())
        })?;
        if let Some(pending) = pending_sdo {
            self.pending_sdo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&pending.stored.path_id);
        }
        // The directory's number can be reused like a file's (see unlink_impl).
        self.forget_deleted_inode(inode.ino);
        Ok(())
    }

    /// Core of `rename`. Callable in-process for tests (the FUSE callback is a thin
    /// wrapper that adds the read-only guard).
    fn rename_impl(
        &self,
        req_uid: u32,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
    ) -> std::result::Result<(), libc::c_int> {
        // renameat2 flags: RENAME_NOREPLACE is honoured; RENAME_EXCHANGE,
        // RENAME_WHITEOUT and any unknown bit are refused with EINVAL before
        // anything is touched (treating EXCHANGE as a plain rename would delete
        // the target). Off Linux every flag is refused: Darwin's renamex_np values
        // differ (SWAP=2, EXCL=4) and are not mapped.
        if flags & !RENAME_NOREPLACE != 0 {
            return Err(libc::EINVAL);
        }
        // Off Linux RENAME_NOREPLACE is 0 (every flag was refused above), so this is
        // always false there; on Linux it is the real check.
        #[cfg_attr(not(target_os = "linux"), allow(clippy::bad_bit_mask))]
        let noreplace = flags & RENAME_NOREPLACE != 0;
        let name_str = name.to_str().ok_or(libc::EINVAL)?;
        let newname_str = newname.to_str().ok_or(libc::EINVAL)?;

        let store = self.store();

        // H11: Enforce ownership — caller must own both source and destination
        // parent directories, or be root.
        match store.get(parent) {
            Ok(Some(src_parent)) => {
                if req_uid != 0 && req_uid != src_parent.uid {
                    return Err(libc::EPERM);
                }
            }
            Ok(None) => return Err(libc::ENOENT),
            Err(_) => return Err(libc::EIO),
        }
        if newparent != parent {
            match store.get(newparent) {
                Ok(Some(dst_parent)) => {
                    if req_uid != 0 && req_uid != dst_parent.uid {
                        return Err(libc::EPERM);
                    }
                }
                Ok(None) => return Err(libc::ENOENT),
                Err(_) => return Err(libc::EIO),
            }
        }

        // Find source inode
        let mut inode = match store.lookup(parent, name_str) {
            Ok(Some(i)) => i,
            Ok(None) => return Err(libc::ENOENT),
            Err(_) => return Err(libc::EIO),
        };

        let target = store.lookup(newparent, newname_str).map_err(|error| {
            tracing::error!(%error, "rename: destination lookup failed");
            libc::EIO
        })?;
        if let Some(target) = &target {
            if noreplace {
                return Err(libc::EEXIST);
            }
            if target.ino == inode.ino {
                return Ok(());
            }
            if target.is_dir() && !target.children.is_empty() {
                return Err(libc::ENOTEMPTY);
            }
        }

        let rename_sdo = if self.sdo_context.is_some() {
            let old_root = self.path_for_inode(inode.ino)?;
            let parent_path = self.path_for_inode(newparent)?;
            let new_root = if parent_path.is_empty() {
                newname_str.to_owned()
            } else {
                format!("{parent_path}/{newname_str}")
            };
            let mut candidates: Vec<(String, Inode)> = store
                .list_all()
                .map_err(|e| {
                    tracing::error!(error = %e, "rename: portable descendant scan failed");
                    libc::EIO
                })?
                .into_iter()
                .filter(|child| child.is_file() || child.is_dir())
                .filter_map(|child| {
                    self.path_for_inode(child.ino)
                        .ok()
                        .filter(|path| {
                            path == &old_root || path.starts_with(&format!("{old_root}/"))
                        })
                        .map(|path| (path, child))
                })
                .collect();
            candidates.sort_by_key(|(path, _)| path.matches('/').count());
            let mut destinations = Vec::new();
            for (old_path, mut child) in candidates {
                let suffix = old_path.strip_prefix(&old_root).ok_or(libc::EIO)?;
                let new_path = format!("{new_root}{suffix}");
                let content = if child.is_dir() {
                    Vec::new()
                } else {
                    // Spools capture the path when they first become dirty.
                    // Commit them before publishing the move and tombstone.
                    self.persist_portable_rename_writes(child.ino)?;
                    child = store
                        .get(child.ino)
                        .map_err(|_| libc::EIO)?
                        .ok_or(libc::ENOENT)?;
                    self.current_inode_content(&child)?
                };
                let pointers = child
                    .manifest
                    .as_ref()
                    .map_or(&[][..], |m| m.blocks.as_slice());
                let current = self.upload_sdo_version(
                    &child,
                    &new_path,
                    &content,
                    pointers,
                    &[],
                    false,
                    None,
                )?;
                destinations.push((child, old_path, current));
            }
            let destination_versions: Vec<_> = destinations
                .iter()
                .map(|(_, _, version)| version.clone())
                .collect();
            let mut source_tombstones = Vec::with_capacity(destinations.len());
            for (child, old_path, current) in destinations.into_iter().rev() {
                let next_identity = SdoFileIdentity {
                    file_id: current.manifest.file_id,
                    origin_message_id: current
                        .manifest
                        .origin_message_id
                        .or(Some(current.stored.message_id)),
                    latest_version_id: Some(current.manifest.version_id),
                    local_version: current.manifest.local_version,
                };
                let tombstone = self.upload_sdo_version(
                    &child,
                    &old_path,
                    &[],
                    &[],
                    &[],
                    true,
                    Some(next_identity),
                )?;
                source_tombstones.push(tombstone);
            }
            Some((destination_versions, source_tombstones))
        } else {
            None
        };

        let replaced = self.journaled_txn(|| {
            let store = self.store();
            let mut replaced = None;
            if let Some(existing) = &target {
                store.delete(existing.ino).map_err(|e| {
                    tracing::error!(error = %e, "rename: destination delete failed");
                    libc::EIO
                })?;
                // Overwriting a target destroys its inode — drop its manifest
                // history so a recycled ino cannot inherit it (no-op for a dir).
                if let Err(e) = self.manifest_store().delete_versions(existing.ino) {
                    tracing::error!(error = %e, "rename: target manifest cleanup failed");
                    return Err(libc::EIO);
                }
                if let Some(mut np) = txn_get(&store, newparent, "rename destination parent")? {
                    np.children.retain(|&c| c != existing.ino);
                    txn_update(&store, &np, "rename destination parent")?;
                }
                replaced = Some(existing.ino);
            }

            // Remove from old parent.
            if let Some(mut old_parent) = txn_get(&store, parent, "rename source parent")? {
                old_parent.children.retain(|&c| c != inode.ino);
                if inode.is_dir() {
                    old_parent.nlink = old_parent.nlink.saturating_sub(1);
                }
                txn_update(&store, &old_parent, "rename source parent")?;
            }

            // Update inode.
            inode.name = newname_str.to_string();
            inode.parent = newparent;
            inode.timestamps.ctime_ns = system_time_to_ns(SystemTime::now());
            txn_update(&store, &inode, "rename inode")?;

            // Add to new parent.
            if let Some(mut new_parent) = txn_get(&store, newparent, "rename new parent")? {
                new_parent.children.push(inode.ino);
                if inode.is_dir() {
                    new_parent.nlink += 1;
                }
                txn_update(&store, &new_parent, "rename new parent")?;
            }
            if let Some(updates) = &rename_sdo {
                // Both records use the same inode. Install the destination
                // last so the local identity points at live content.
                for tombstone in &updates.1 {
                    self.commit_sdo_version(tombstone)?;
                }
                for version in &updates.0 {
                    self.commit_sdo_version(version)?;
                }
            }
            Ok(replaced)
        })?;
        if let Some((destinations, tombstones)) = rename_sdo {
            let mut pending = self
                .pending_sdo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for version in destinations.into_iter().chain(tombstones) {
                pending.remove(&version.stored.path_id);
            }
        }
        // A replaced target's inode was deleted; drop its dirty write buffer so a
        // recycled ino cannot inherit it (see `unlink_impl`).
        if let Some(ino) = replaced.filter(|&ino| ino != inode.ino) {
            self.forget_deleted_inode(ino);
        }
        Ok(())
    }

    /// Download and decrypt a block by message_id via transport.
    ///
    /// `epoch` must match the epoch used when the block was originally encrypted.
    pub fn download_block(
        &self,
        message_id: i64,
        block_id: &[u8; 32],
        epoch: u32,
    ) -> Option<Vec<u8>> {
        // Try cache first (cache stores plaintext).
        if let Some(cache) = &self.cache {
            if let Ok(data) = cache.get(block_id) {
                // Under fail-closed, a cache hit must still be verifiable: confirm
                // the cached plaintext matches the store record's hash. This keeps
                // the cache path fail-closed rather than relying on the incidental
                // property that the cache only ever holds previously-verified
                // entries (which a future cache-rehydration could break).
                if self.require_block_integrity {
                    let verified =
                        self.block_store()
                            .get(block_id)
                            .ok()
                            .flatten()
                            .is_some_and(|r| {
                                r.plaintext_sha256 != [0u8; 32]
                                    && sha256_bytes(&data) == r.plaintext_sha256
                            });
                    if !verified {
                        tracing::error!(
                            block_id = hex::encode(block_id),
                            "cached block failed integrity re-check — refusing"
                        );
                        return None;
                    }
                }
                return Some(data);
            }
        }

        // Fetch stored hashes for SRB2 integrity verification (non-fatal if missing)
        let stored_record = self.block_store().get(block_id).ok().flatten();

        // The block store is the source of truth for a block's CURRENT physical
        // location (message_id) and epoch. Key rotation re-uploads each block under
        // a new epoch and updates the store via `update_block_epoch`, but file
        // manifests keep their original embedded (message_id, epoch). Resolving from
        // the store here keeps reads correct across a rotation without rewriting every
        // manifest; the passed-in values are the fallback for blocks absent from the
        // store (legacy writes / direct callers).
        let (message_id, epoch) = match stored_record.as_ref() {
            Some(r) => (r.message_id, r.epoch),
            None => (message_id, epoch),
        };

        // Download from transport
        let transport = self.transport.as_ref()?;
        let rt = self.rt.as_ref()?;

        match rt
            .block_on(async {
                tokio::time::timeout(DOWNLOAD_TIMEOUT, transport.download_block(message_id)).await
            })
            .unwrap_or_else(|_| {
                tracing::error!(
                    "download_block hard-timed-out after {}s (transport stall guard should fire first)",
                    DOWNLOAD_TIMEOUT.as_secs()
                );
                Err(teagarden_telegram::error::TelegramError::Timeout)
            }) {
            Ok(result) => {
                let (cs, ps) = match stored_record.as_ref() {
                    Some(r) => (Some(r.ciphertext_sha256), Some(r.plaintext_sha256)),
                    None => (None, None),
                };
                let plaintext = Self::decrypt_and_verify_block(
                    &self.data_key,
                    self.block_v2_from_epoch,
                    self.require_block_integrity,
                    block_id,
                    epoch,
                    &result.data,
                    cs,
                    ps,
                )?;
                if let Some(cache) = &self.cache {
                    let _ = cache.put(block_id, &plaintext);
                }
                Some(plaintext)
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to download block");
                None
            }
        }
    }

    /// Integrity-check then decrypt a downloaded block's ciphertext. PURE — takes no
    /// `&self` and touches no SQLite — so it can run in a spawned read-ahead task off
    /// the FUSE thread (the block store's `rusqlite::Connection` is not `Send`). The
    /// caller fetches the block's expected SRB2 hashes (`stored_cipher_sha`,
    /// `stored_plain_sha`) from the block store first and passes them in.
    ///
    /// Same fail-closed semantics as the inline path: when integrity is required, a
    /// missing/zero-hash record refuses (returns `None`); the ciphertext hash is
    /// checked before decrypt (transit integrity) and the plaintext hash after
    /// (decryption integrity); block-v2 AAD binds the expected `block_id`.
    #[allow(clippy::too_many_arguments)]
    fn decrypt_and_verify_block(
        data_key: &SymmetricKey,
        block_v2_from_epoch: Option<u32>,
        require_integrity: bool,
        block_id: &[u8; 32],
        epoch: u32,
        ciphertext: &[u8],
        stored_cipher_sha: Option<[u8; 32]>,
        stored_plain_sha: Option<[u8; 32]>,
    ) -> Option<Vec<u8>> {
        if require_integrity {
            let verifiable = matches!(
                (stored_cipher_sha, stored_plain_sha),
                (Some(c), Some(p)) if c != [0u8; 32] && p != [0u8; 32]
            );
            if !verifiable {
                tracing::error!(
                    block_id = hex::encode(block_id),
                    "block integrity required but unverifiable (missing record or SRB1 block) — refusing"
                );
                return None;
            }
        }

        if let Some(cs) = stored_cipher_sha {
            if cs != [0u8; 32] && sha256_bytes(ciphertext) != cs {
                tracing::error!(
                    block_id = hex::encode(block_id),
                    "ciphertext SHA-256 mismatch — block corrupted in transit"
                );
                return None;
            }
        }

        let epoch_data_key = derive_epoch_key(data_key, epoch).ok()?;
        let aad = block_aad(epoch, block_id, block_v2_from_epoch);
        let plaintext = aead::decrypt(&epoch_data_key.key, ciphertext, &aad)
            .map_err(|e| tracing::error!(error = %e, "block decryption failed"))
            .ok()?;

        if let Some(ps) = stored_plain_sha {
            if ps != [0u8; 32] && sha256_bytes(&plaintext) != ps {
                tracing::error!(
                    block_id = hex::encode(block_id),
                    "plaintext SHA-256 mismatch — decryption produced wrong output"
                );
                return None;
            }
        }

        Some(plaintext)
    }

    /// Kick off background read-ahead: download + decrypt the next `PREFETCH_DEPTH`
    /// blocks after `after_offset` concurrently into the cache, so a sequential reader
    /// finds them already present instead of paying a serial round-trip per block
    /// (reads can't use the bot pool — bots are upload-only — so they go through the
    /// single MTProto session and benefit greatly from overlapping fetches).
    ///
    /// Each block is fetched in a spawned task: the download is async and the decrypt
    /// is pure ([`Self::decrypt_and_verify_block`]), so it runs off the FUSE thread
    /// without the non-`Send` SQLite connection — the block's integrity hashes are
    /// gathered here first and moved into the task. In-flight block IDs are deduped via
    /// `prefetch_inflight`, already-cached blocks are skipped, and the work is
    /// best-effort: a failed prefetch is silent (the real read re-fetches it and
    /// surfaces any error fail-closed).
    fn trigger_prefetch(&self, manifest: &FileManifest, after_offset: u64) {
        let (Some(rt), Some(transport), Some(cache)) = (
            self.rt.as_ref(),
            self.transport.as_ref(),
            self.cache.as_ref(),
        ) else {
            return;
        };
        let span = (PREFETCH_DEPTH as u64).saturating_mul(self.fuse_block_size as u64);
        if span == 0 {
            return;
        }
        for bp in manifest.blocks_in_range(after_offset, span) {
            if cache.contains(&bp.block_id) {
                continue;
            }
            // Claim the block; skip if another task is already prefetching it.
            match self.prefetch_inflight.lock() {
                Ok(mut inflight) => {
                    if !inflight.insert(bp.block_id) {
                        continue;
                    }
                }
                Err(_) => return,
            }
            // Gather the block's integrity hashes HERE (the block store is not Send).
            let stored = self.block_store().get(&bp.block_id).ok().flatten();
            let (cs, ps) = match &stored {
                Some(r) => (Some(r.ciphertext_sha256), Some(r.plaintext_sha256)),
                None => (None, None),
            };
            let transport = Arc::clone(transport);
            let cache = Arc::clone(cache);
            let inflight = Arc::clone(&self.prefetch_inflight);
            let data_key = self.data_key.clone();
            let block_v2 = self.block_v2_from_epoch;
            let require = self.require_block_integrity;
            let block_id = bp.block_id;
            // Source of truth for the block's current location/epoch is the store
            // (rotation updates it); the manifest pointer is the fallback. Mirrors
            // the resolution in `download_block`.
            let (message_id, epoch) = match &stored {
                Some(r) => (r.message_id, r.epoch),
                None => (bp.message_id, bp.epoch),
            };
            rt.spawn(async move {
                if let Ok(dl) = transport.download_block(message_id).await {
                    if let Some(pt) = CryptFs::decrypt_and_verify_block(
                        &data_key, block_v2, require, &block_id, epoch, &dl.data, cs, ps,
                    ) {
                        let _ = cache.put(&block_id, &pt);
                    }
                }
                if let Ok(mut g) = inflight.lock() {
                    g.remove(&block_id);
                }
            });
        }
    }
}

/// A zero-filled buffer of `size` bytes, refusing sizes past the cap (`EFBIG`)
/// and allocations the host cannot satisfy (`ENOSPC`) instead of aborting.
fn zeroed_buffer(size: u64) -> std::result::Result<Vec<u8>, libc::c_int> {
    if size > MAX_FILE_SIZE {
        return Err(libc::EFBIG);
    }
    let mut buf = Vec::new();
    buf.try_reserve_exact(size as usize)
        .map_err(|_| libc::ENOSPC)?;
    buf.resize(size as usize, 0);
    Ok(buf)
}

/// Inode read inside a journaled transaction: a store error is `EIO` (so the
/// transaction rolls back) rather than being treated like "no such inode".
fn txn_get(
    store: &InodeStore<'_>,
    ino: u64,
    what: &str,
) -> std::result::Result<Option<Inode>, libc::c_int> {
    store.get(ino).map_err(|e| {
        tracing::error!(ino, error = %e, "{what}: inode read failed");
        libc::EIO
    })
}

/// Inode update inside a journaled transaction: a store error is `EIO` (so the
/// transaction rolls back) rather than being ignored.
fn txn_update(
    store: &InodeStore<'_>,
    inode: &Inode,
    what: &str,
) -> std::result::Result<(), libc::c_int> {
    store.update(inode).map_err(|e| {
        tracing::error!(ino = inode.ino, error = %e, "{what}: inode update failed");
        libc::EIO
    })
}

fn ns_to_system_time(ns: i128) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH
    }
}

fn system_time_to_ns(t: SystemTime) -> i128 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

/// Trim a manifest's ordered block pointers so it describes exactly `new_size`
/// bytes: drop blocks fully beyond `new_size`, shorten the boundary block's
/// `length`, and set `total_size`. Metadata-only — no download or re-upload.
///
/// `file_hash` is left unchanged (it now describes a superset of the content); this
/// is a deliberate, accepted wart on the torn-state *heal* path: recomputing it
/// would force a download, and `file_hash` is never verified on read (it is only the
/// manifest's content-address). Used to reconcile a *torn* manifest
/// (`total_size > inode.size`, left by a dirty-shrink+crash or a pre-v0.4.7 lazy
/// shrink) down to the file size on a grow, so previously-truncated bytes never
/// resurrect. Blocks are sorted by `file_offset` (manifest invariant), so the first
/// block at/after `new_size` ends the kept range.
fn trim_manifest_blocks(m: &FileManifest, new_size: u64) -> FileManifest {
    let mut blocks = Vec::new();
    for bp in &m.blocks {
        if bp.file_offset >= new_size {
            break;
        }
        let mut b = bp.clone();
        if bp.file_offset + bp.length > new_size {
            b.length = new_size - bp.file_offset;
        }
        blocks.push(b);
    }
    FileManifest {
        inode: m.inode,
        version: m.version,
        total_size: new_size,
        file_hash: m.file_hash,
        blocks,
        parent_ids: m.parent_ids.clone(),
    }
}

fn time_or_now_to_ns(t: TimeOrNow) -> i128 {
    match t {
        TimeOrNow::SpecificTime(st) => system_time_to_ns(st),
        TimeOrNow::Now => system_time_to_ns(SystemTime::now()),
    }
}

/// Before the session's connection closes (it never checkpoints on close
/// itself), the session checkpoints the WAL into the main file, unless
/// another program wrote it.
impl Drop for CryptFs {
    fn drop(&mut self) {
        self.session_checkpoint(0);
    }
}

impl Filesystem for CryptFs {
    fn init(
        &mut self,
        _req: &Request<'_>,
        config: &mut fuser::KernelConfig,
    ) -> std::result::Result<(), libc::c_int> {
        if self.sdo_context.is_some() {
            // Otherwise the kernel implements open(O_TRUNC) as SETATTR(size=0)
            // followed by OPEN, publishing an unwanted empty version before cp.
            config
                .add_capabilities(fuser::consts::FUSE_ATOMIC_O_TRUNC)
                .map_err(|unsupported| {
                    tracing::error!(
                        unsupported,
                        "portable saves require FUSE atomic O_TRUNC support"
                    );
                    libc::ENOTSUP
                })?;
        }
        tracing::info!("CryptFs initialized");

        // Ensure root inode exists. Route the insert through the journal so that
        // on a brand-new volume — whose base snapshot is the empty initialized DB —
        // root creation is captured as a delta and survives recovery. For an
        // existing volume root is already present and this is a no-op (no delta).
        let root_missing = match self.store().get(1) {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(e) => {
                tracing::error!(error = %e, "failed to check root inode");
                return Err(libc::EIO);
            }
        };
        if root_missing {
            let uid = self.uid;
            let gid = self.gid;
            self.journaled_txn(|| {
                let mut root = Inode::root();
                root.uid = uid;
                root.gid = gid;
                self.store().insert(&root).map_err(|e| {
                    tracing::error!(error = %e, "failed to create root inode");
                    libc::EIO
                })
            })?;
        }

        Ok(())
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let store = self.store();
        match store.lookup(parent, name_str) {
            Ok(Some(inode)) => {
                let attr = Self::inode_to_attr(&inode);
                reply.entry(&TTL, &attr, self.generation(inode.ino));
            }
            Ok(None) => {
                reply.error(libc::ENOENT);
            }
            Err(e) => {
                tracing::error!(error = %e, "lookup failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, fh: Option<u64>, reply: ReplyAttr) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        // fstat through a descriptor of a deleted file must not report the
        // attributes of a file that reused its number.
        if let Err(e) = self.check_handle_live(fh) {
            reply.error(e);
            return;
        }
        let store = self.store();
        match store.get(ino) {
            Ok(Some(inode)) => {
                let mut attr = Self::inode_to_attr(&inode);
                // Overlay the in-flight size so a `stat` during an open write sees
                // the growing file, even though the buffered bytes are not yet
                // persisted to the (journaled) inode row.
                let live = fh
                    .and_then(|fh| self.handles.spool(true, fh))
                    .and_then(|spool| spool.lock().ok()?.len().ok())
                    .or_else(|| self.inflight_size(ino));
                if let Some(live) = live {
                    attr.size = live;
                    attr.blocks = attr.size.div_ceil(512);
                }
                reply.attr(&TTL, &attr);
            }
            Ok(None) => {
                reply.error(libc::ENOENT);
            }
            Err(e) => {
                tracing::error!(error = %e, "getattr failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }
        // ftruncate/fchmod/futimens through a descriptor of a deleted file must not
        // modify the file that reused its number.
        if let Err(e) = self.check_handle_live(fh) {
            reply.error(e);
            return;
        }
        // ftruncate belongs to this descriptor's pending portable image. Do not
        // materialize committed bytes or publish a separate truncate version.
        if let Some((new_size, spool)) = size.zip(fh.and_then(|fh| self.handles.spool(true, fh))) {
            let result = (|| {
                if new_size > self.sdo_context.map_or(MAX_FILE_SIZE, |c| c.max_file_size) {
                    return Err(libc::EFBIG);
                }
                let mut spool = spool.lock().map_err(|_| libc::EIO)?;
                if spool.intent.plan.is_some() {
                    return Err(libc::EIO);
                }
                let mut inode =
                    self.setattr_persist(ino, req.uid(), mode, uid, gid, None, atime, mtime, true)?;
                spool.resize(new_size).map_err(|_| libc::EIO)?;
                spool.intent.metadata.mode = inode.mode;
                spool.intent.metadata.mtime_ns = inode.timestamps.mtime_ns as i64;
                self.handles.mark_setattr(ino);
                inode.size = new_size;
                Ok(inode)
            })();
            match result {
                Ok(inode) => reply.attr(&TTL, &Self::inode_to_attr(&inode)),
                Err(error) => reply.error(error),
            }
            return;
        }
        let result = self
            .setattr_impl(ino, req.uid(), mode, uid, gid, size, atime, mtime)
            .and_then(|inode| {
                if let Some(fh) = fh.filter(|_| size.is_some() && self.sdo_context.is_some()) {
                    // A clean truncate published a successor. Subsequent partial
                    // writes on this descriptor must seed that successor.
                    let version = self
                        .sdo_identity_store()
                        .get(ino)
                        .map_err(|_| libc::EIO)?
                        .and_then(|identity| identity.latest_version_id)
                        .ok_or(libc::EIO)?;
                    self.handles.advance_sdo_version(fh, version);
                }
                Ok(inode)
            });
        match result {
            Ok(inode) => reply.attr(&TTL, &Self::inode_to_attr(&inode)),
            Err(e) => reply.error(e),
        }
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        self.mark_sdo_activity();
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let store = self.store();

        // Check parent exists and is a directory
        let mut parent_inode = match store.get(parent) {
            Ok(Some(i)) if i.is_dir() => i,
            Ok(Some(_)) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            Ok(None) => {
                reply.error(libc::ENOENT);
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, "mkdir parent lookup failed");
                reply.error(libc::EIO);
                return;
            }
        };

        // Check name doesn't already exist
        if let Ok(Some(_)) = store.lookup(parent, name_str) {
            reply.error(libc::EEXIST);
            return;
        }

        // Allocate new inode number
        let ino = match store.next_ino() {
            Ok(ino) => ino,
            Err(e) => {
                tracing::error!(error = %e, "mkdir next_ino failed");
                reply.error(libc::EIO);
                return;
            }
        };

        let dir = Inode::new_dir(
            ino,
            parent,
            name_str.to_string(),
            mode,
            req.uid(),
            req.gid(),
        );

        let pending_sdo = if self.sdo_context.is_some() {
            let parent_path = match self.path_for_inode(parent) {
                Ok(path) => path,
                Err(error) => {
                    reply.error(error);
                    return;
                }
            };
            let path = if parent_path.is_empty() {
                name_str.to_owned()
            } else {
                format!("{parent_path}/{name_str}")
            };
            match self.upload_sdo_version(&dir, &path, &[], &[], &[], false, None) {
                Ok(pending) => Some(pending),
                Err(error) => {
                    reply.error(error);
                    return;
                }
            }
        } else {
            None
        };

        let result = self.journaled_txn(|| {
            let store = self.store();
            if let Err(e) = store.insert(&dir) {
                tracing::error!(error = %e, "mkdir insert failed");
                return Err(libc::EIO);
            }
            // Update parent children list.
            parent_inode.children.push(ino);
            parent_inode.nlink += 1;
            if let Err(e) = store.update(&parent_inode) {
                tracing::error!(error = %e, "mkdir parent update failed");
                return Err(libc::EIO);
            }
            if let Some(pending) = &pending_sdo {
                self.commit_sdo_version(pending)?;
            }
            Ok(())
        });

        match result {
            Ok(()) => {
                if let Some(pending) = pending_sdo {
                    self.pending_sdo
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&pending.stored.path_id);
                }
                let attr = Self::inode_to_attr(&dir);
                reply.entry(&TTL, &attr, self.generation(dir.ino));
            }
            Err(e) => reply.error(e),
        }
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        self.mark_sdo_activity();
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let store = self.store();

        // Check parent
        let mut parent_inode = match store.get(parent) {
            Ok(Some(i)) if i.is_dir() => i,
            Ok(Some(_)) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            Ok(None) => {
                reply.error(libc::ENOENT);
                return;
            }
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        // Check name doesn't exist
        if let Ok(Some(_)) = store.lookup(parent, name_str) {
            reply.error(libc::EEXIST);
            return;
        }

        let ino = match store.next_ino() {
            Ok(ino) => ino,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let file = Inode::new_file(
            ino,
            parent,
            name_str.to_string(),
            mode,
            req.uid(),
            req.gid(),
        );

        // Stage the empty create durably, then fold subsequent writes into that
        // same pending version. Publishing an empty TGFV here produced a second
        // version for every ordinary cp before its payload was even written.
        let fh = self.handles.open(ino, flags, req.uid());
        let handle = self.handles.get(fh).expect("freshly allocated handle");
        let result = self.journaled_txn(|| {
            let store = self.store();
            if let Err(e) = store.insert(&file) {
                tracing::error!(error = %e, "create insert failed");
                return Err(libc::EIO);
            }
            parent_inode.children.push(ino);
            if let Err(e) = store.update(&parent_inode) {
                tracing::error!(error = %e, "create parent update failed");
                return Err(libc::EIO);
            }
            if self.sdo_context.is_some() {
                self.stage_portable_write(ino, &handle, true)?;
            }
            Ok(())
        });

        match result {
            Ok(()) => {
                if self.sdo_context.is_some() {
                    // Record the owed empty publication only once the create
                    // has committed. Marking it inside the transaction let a
                    // failed or interrupted create leave an intent that
                    // recovery would publish for a file the caller was told
                    // was never created.
                    let marked = self
                        .handles
                        .spool(true, fh)
                        .ok_or(libc::EIO)
                        .and_then(|spool| {
                            spool
                                .lock()
                                .map_err(|_| libc::EIO)?
                                .mark_empty_create()
                                .map_err(|_| libc::EIO)
                        });
                    if let Err(e) = marked {
                        // The create itself succeeded; release still publishes
                        // the empty file. Only crash recovery between close
                        // and release loses it, so warn rather than fail.
                        tracing::warn!(
                            ino,
                            errno = e,
                            "could not record owed empty-create publication"
                        );
                    }
                    self.handles.defer_empty_create(fh);
                }
                let attr = Self::inode_to_attr(&file);
                reply.created(
                    &TTL,
                    &attr,
                    self.generation(file.ino),
                    fh,
                    if self.sdo_context.is_some() {
                        fuser::consts::FOPEN_DIRECT_IO
                    } else {
                        0
                    },
                );
            }
            Err(e) => {
                // Remove any spool staged for this failed create so recovery
                // never sees an intent for a file that was not created.
                if let Some(spool) = self.handles.spool(true, fh) {
                    if let Ok(spool) = spool.lock() {
                        let _ = spool.cleanup();
                    }
                    self.handles.remove_spool(true, fh);
                }
                self.handles.close(fh);
                reply.error(e);
            }
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        // Refuse write-intent opens up front on a read-only mount, so the caller
        // gets EROFS at open() rather than at the first write. O_TRUNC is refused
        // even with O_RDONLY: `open_impl` empties the file at open time (a real
        // mutation), and `open(path, O_RDONLY|O_TRUNC)` is a legal syscall whose
        // ACCMODE is O_RDONLY — without the explicit O_TRUNC check it would slip
        // past and truncate on a read-only mount.
        if self.read_only
            && ((flags & libc::O_ACCMODE) != libc::O_RDONLY || (flags & libc::O_TRUNC) != 0)
        {
            reply.error(libc::EROFS);
            return;
        }
        match self.open_impl(ino, flags, _req.uid()) {
            Ok(fh) => reply.opened(
                fh,
                if self.sdo_context.is_some() {
                    fuser::consts::FOPEN_DIRECT_IO
                } else {
                    0
                },
            ),
            Err(e) => reply.error(e),
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // `flush` normally persisted the data already; this retries if it failed
        // (block uploads split into chunks; the metadata delta published before the
        // local commit carries blocks + manifest, so a crashed session's files are
        // fully recoverable). Always close the handle — the kernel discards a
        // release error, and once the last handle is gone nothing can reach the
        // buffer, so `close` discards it (the application already got `EIO` from
        // close(2) via `flush`).
        let result = self.release_impl(ino, fh);
        if let Err(e) = result {
            tracing::error!(ino, errno = e, "release: persisting buffered data failed");
        }
        self.handles.close(fh);
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    /// `close(2)` → FUSE `flush`: persist dirty data and report failure to the
    /// application (fuser's default replies `ENOSYS`, which the kernel treats as
    /// success — a failed upload then went unreported). On a read-only mount no
    /// buffer can exist, and `close(2)` must succeed.
    fn flush(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        if self.read_only {
            reply.ok();
            return;
        }
        match self.flush_impl(ino, fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    /// `fsync(2)` — durably commit the open handle's buffered writes (upload + manifest)
    /// before replying, so an application/gateway that fsyncs is guaranteed the data is
    /// on the transport and immediately readable. Without this, FUSE `fsync` defaulted
    /// to a no-op and uploads happened only on the async `release`, so a gateway PUT
    /// could report success before the data was durable. `datasync` is treated the same
    /// (block + manifest are committed together).
    fn fsync(&mut self, _req: &Request<'_>, ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
        // Deliberate deviation: a real read-only fs returns 0 for fsync on a clean fd.
        // We refuse with EROFS instead — on a read-only mount no handle can ever be
        // dirty (write/setattr/create are all refused), so there is nothing to sync;
        // EROFS keeps the "no mutation reaches storage" guarantee uniform and loud.
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }
        match self.fsync_impl(ino, fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        match self.read_impl(ino, fh, req.uid(), offset, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e),
        }
    }

    fn write(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        self.mark_sdo_activity();
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }
        match self.write_impl(ino, fh, req.uid(), offset, data) {
            Ok(n) => reply.written(n),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        self.mark_sdo_activity();
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }
        match self.unlink_impl(req.uid(), parent, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        self.mark_sdo_activity();
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }
        match self.rmdir_impl(req.uid(), parent, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        let store = self.store();

        let inode = match store.get(ino) {
            Ok(Some(i)) if i.is_dir() => i,
            Ok(Some(_)) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            Ok(None) => {
                reply.error(libc::ENOENT);
                return;
            }
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let mut entries: Vec<(u64, FuseFileType, String)> = Vec::new();
        entries.push((ino, FuseFileType::Directory, ".".to_string()));
        entries.push((
            inode.parent.max(1),
            FuseFileType::Directory,
            "..".to_string(),
        ));

        // Add child entries
        match store.list_children(ino) {
            Ok(children) => {
                for child in children {
                    let kind = match child.file_type {
                        FileType::RegularFile => FuseFileType::RegularFile,
                        FileType::Directory => FuseFileType::Directory,
                        FileType::Symlink => FuseFileType::Symlink,
                    };
                    entries.push((child.ino, kind, child.name.clone()));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "readdir list_children failed");
                reply.error(libc::EIO);
                return;
            }
        }

        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) {
                break;
            }
        }

        reply.ok();
    }

    fn rename(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        if let Err(error) = self.apply_pending_sdo_poll() {
            reply.error(error);
            return;
        }
        self.mark_sdo_activity();
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }
        match self.rename_impl(req.uid(), parent, name, newparent, newname, flags) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let store = self.store();
        match store.get(ino) {
            Ok(Some(inode)) => {
                if let Some(target) = &inode.symlink_target {
                    reply.data(target.as_bytes());
                } else {
                    reply.error(libc::EINVAL);
                }
            }
            Ok(None) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.sdo_context.is_some() {
            tracing::warn!("TGFV volumes do not support symbolic-link creation");
            reply.error(libc::ENOTSUP);
            return;
        }
        let name_str = match link_name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        let target_str = match target.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let store = self.store();

        let mut parent_inode = match store.get(parent) {
            Ok(Some(i)) if i.is_dir() => i,
            _ => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let ino = match store.next_ino() {
            Ok(ino) => ino,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let symlink = Inode::new_symlink(
            ino,
            parent,
            name_str.to_string(),
            target_str.to_string(),
            req.uid(),
            req.gid(),
        );

        // R4-M01: wrap both DB mutations in one transaction so a crash between the
        // inode insert and parent update cannot leave the filesystem inconsistent.
        let result = self.journaled_txn(|| {
            let store = self.store();
            if let Err(e) = store.insert(&symlink) {
                tracing::error!(error = %e, "symlink insert failed");
                return Err(libc::EIO);
            }
            parent_inode.children.push(ino);
            if let Err(e) = store.update(&parent_inode) {
                tracing::error!(error = %e, "symlink parent update failed");
                return Err(libc::EIO);
            }
            Ok(())
        });

        match result {
            Ok(()) => {
                let attr = Self::inode_to_attr(&symlink);
                reply.entry(&TTL, &attr, self.generation(symlink.ino));
            }
            Err(e) => reply.error(e),
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        // Report virtual filesystem stats
        reply.statfs(
            0, // blocks
            0, // bfree
            0, // bavail
            0, // files
            0, // ffree
            BLOCK_SIZE, 256, // namelen
            BLOCK_SIZE,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_quarantines_permanent_upload_refusals_and_retries_transient_ones() {
        for errno in [libc::EPERM, libc::EACCES, libc::ENOTSUP, libc::EFBIG] {
            assert!(recovery_upload_error_is_permanent(errno), "errno {errno}");
        }
        for errno in [libc::EIO, libc::ETIMEDOUT, libc::ECONNRESET, libc::EAGAIN] {
            assert!(!recovery_upload_error_is_permanent(errno), "errno {errno}");
        }
    }
    use teagarden_store::migrations::initialize_database;
    use teagarden_store::schema::logical_tables;

    #[test]
    fn ns_time_conversion() {
        let now = SystemTime::now();
        let ns = system_time_to_ns(now);
        assert!(ns > 0);

        let converted = ns_to_system_time(ns);
        let diff = now.duration_since(converted).unwrap_or_default();
        assert!(diff.as_nanos() < 1000); // Within 1 microsecond
    }

    #[test]
    fn inode_to_file_attr() {
        let inode = Inode::new_file(42, 1, "test.txt".into(), 0o644, 1000, 1000);
        let attr = CryptFs::inode_to_attr(&inode);
        assert_eq!(attr.ino, 42);
        assert_eq!(attr.kind, FuseFileType::RegularFile);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.nlink, 1);
    }

    #[test]
    fn dir_inode_to_attr() {
        let inode = Inode::new_dir(2, 1, "docs".into(), 0o755, 1000, 1000);
        let attr = CryptFs::inode_to_attr(&inode);
        assert_eq!(attr.kind, FuseFileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.nlink, 2);
    }

    #[test]
    fn symlink_inode_to_attr() {
        let inode = Inode::new_symlink(3, 1, "link".into(), "/target".into(), 1000, 1000);
        let attr = CryptFs::inode_to_attr(&inode);
        assert_eq!(attr.kind, FuseFileType::Symlink);
        assert_eq!(attr.size, 7);
    }

    fn setup_cryptfs_with_transport() -> (
        CryptFs,
        Arc<teagarden_telegram::mock::MockTransport>,
        tokio::runtime::Runtime,
    ) {
        let conn = Connection::open_in_memory().unwrap();
        let schema_key = SymmetricKey::from_bytes([0x42; 32]);
        let meta_key = SymmetricKey::from_bytes([0x43; 32]);
        let data_key = SymmetricKey::from_bytes([0x44; 32]);
        let block_id_key = SymmetricKey::from_bytes([0x45; 32]);
        let filename_key = SymmetricKey::from_bytes([0x46; 32]);
        let manifest_key = SymmetricKey::from_bytes([0x47; 32]);
        let schema = OpaqueSchema::new(schema_key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();

        let transport = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();

        let fs = CryptFs::new(conn, schema, meta_key, data_key, 1000, 1000)
            .with_block_keys(block_id_key, filename_key)
            .with_manifest_key(manifest_key)
            .with_transport(transport.clone())
            .with_runtime(rt.handle().clone());

        (fs, transport, rt)
    }

    #[test]
    fn persist_publishes_one_encrypted_object_for_a_file_version() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let author = uuid::Uuid::from_bytes([0x62; 16]);
        let fs = fs.with_sdo(volume_id, author);
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "nested.txt".into(),
                0o640,
                1000,
                1000,
            ))
            .unwrap();

        fs.persist_data(2, b"portable hello")
            .expect("file version persists");

        assert_eq!(transport.message_count(), 1, "one complete file object");
        let wire = transport.get_raw(1).expect("single upload is TGFV");
        assert_eq!(&wire[..4], b"TGFV");
        assert_eq!(u16::from_le_bytes(wire[4..6].try_into().unwrap()), 3);
        let object =
            teagarden_core::sdo::SdoFileObjectV3::decode(&wire, volume_id, 0, &fs.meta_key)
                .unwrap();
        assert_eq!(object.metadata.path.as_deref(), Some("nested.txt"));
        assert_eq!(object.metadata.size, 14);
        assert_eq!(object.metadata.author_device_id, author);
        assert!(object.metadata.clock_ms > 0 || object.metadata.clock_counter > 0);
        assert_eq!(
            fs.sdo_clock_store().get().unwrap(),
            Some((object.metadata.clock_ms, object.metadata.clock_counter)),
            "HLC must be durable before the upload is acknowledged"
        );
        assert_eq!(object.content, b"portable hello");
    }

    #[test]
    fn portable_directory_records_use_zero_segment_directory_metadata() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let fs = fs.with_sdo(volume_id, uuid::Uuid::from_bytes([0x62; 16]));
        fs.store().insert(&Inode::root()).unwrap();
        let directory = Inode::new_dir(2, 1, "empty".into(), 0o710, 1000, 1000);
        let pending = fs
            .upload_sdo_version(&directory, "empty", &[], &[], &[], false, None)
            .unwrap();
        fs.commit_sdo_version(&pending).unwrap();

        let wire = transport.get_raw(pending.stored.message_id).unwrap();
        let object =
            teagarden_core::sdo::SdoFileObjectV3::decode(&wire, volume_id, 0, &fs.meta_key)
                .unwrap();
        assert_eq!(
            object.metadata.kind,
            teagarden_core::sdo::SdoKind::Directory
        );
        assert_eq!(object.metadata.segment_count, 0);
        assert_eq!(object.content, b"");
    }

    #[test]
    fn rmdir_publishes_an_explicit_directory_tombstone() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let fs = fs.with_sdo(volume_id, uuid::Uuid::from_bytes([0x62; 16]));
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_dir(2, 1, "empty".into(), 0o755, 1000, 1000))
            .unwrap();

        fs.rmdir_impl(0, 1, OsStr::new("empty")).unwrap();

        let wire = transport.get_raw(1).unwrap();
        let object =
            teagarden_core::sdo::SdoFileObjectV3::decode(&wire, volume_id, 0, &fs.meta_key)
                .unwrap();
        assert_eq!(object.metadata.path.as_deref(), Some("empty"));
        assert_eq!(
            object.metadata.kind,
            teagarden_core::sdo::SdoKind::Directory
        );
        assert!(object.metadata.deleted);
        assert_eq!(object.metadata.segment_count, 0);
    }

    #[test]
    fn directory_rename_copies_explicit_directories_and_tombstones_child_first() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let fs = fs.with_sdo(volume_id, uuid::Uuid::from_bytes([0x62; 16]));
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_dir(2, 1, "old".into(), 0o755, 1000, 1000))
            .unwrap();
        fs.store()
            .insert(&Inode::new_dir(3, 2, "child".into(), 0o700, 1000, 1000))
            .unwrap();
        fs.store()
            .insert(&Inode::new_file(4, 3, "file.txt".into(), 0o600, 1000, 1000))
            .unwrap();

        fs.rename_impl(0, 1, OsStr::new("old"), 1, OsStr::new("new"), 0)
            .unwrap();

        let records: Vec<_> = (1..=6)
            .map(|id| {
                let wire = transport.get_raw(id).unwrap();
                teagarden_core::sdo::SdoFileObjectV3::decode(&wire, volume_id, 0, &fs.meta_key)
                    .unwrap()
                    .metadata
            })
            .collect();
        assert_eq!(records.len(), 6);
        assert_eq!(records[0].path.as_deref(), Some("new"));
        assert_eq!(records[0].kind, teagarden_core::sdo::SdoKind::Directory);
        assert!(!records[0].deleted);
        assert_eq!(records[1].path.as_deref(), Some("new/child"));
        assert_eq!(records[1].kind, teagarden_core::sdo::SdoKind::Directory);
        assert_eq!(records[2].path.as_deref(), Some("new/child/file.txt"));
        assert_eq!(records[3].path.as_deref(), Some("old/child/file.txt"));
        assert!(records[3].deleted);
        assert_eq!(records[4].path.as_deref(), Some("old/child"));
        assert!(records[4].deleted);
        assert_eq!(records[5].path.as_deref(), Some("old"));
        assert!(records[5].deleted);
    }

    #[test]
    fn device_announcement_is_encrypted_tgf3_without_a_filesystem_path() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let device_id = uuid::Uuid::from_bytes([0x62; 16]);
        let fs = fs.with_sdo(volume_id, device_id);
        fs.store().insert(&Inode::root()).unwrap();

        fs.publish_sdo_device_announcement("workstation", 7654321, Some(4567))
            .unwrap();

        let wire = transport.get_raw(1).unwrap();
        assert_eq!(wire.get(..4), Some(b"TGFV".as_slice()));
        let object =
            teagarden_core::sdo::SdoFileObjectV3::decode(&wire, volume_id, 0, &fs.meta_key)
                .unwrap();
        assert_eq!(object.metadata.kind, teagarden_core::sdo::SdoKind::Device);
        assert_eq!(object.metadata.path, None);
        assert_eq!(object.metadata.installation_id, Some(device_id));
        assert_eq!(object.metadata.label.as_deref(), Some("workstation"));
        assert_eq!(object.metadata.telegram_user_id, Some(7654321));
        assert_eq!(
            object.metadata.authorization_session_hash.as_deref(),
            Some("4567")
        );
        assert_eq!(object.metadata.segment_count, 0);
        fs.publish_sdo_device_announcement("renamed", 7654321, Some(4567))
            .unwrap();
        assert_eq!(
            transport.message_count(),
            1,
            "same account and authorization reuse the existing announcement"
        );
        fs.publish_sdo_device_announcement("workstation", 7654321, Some(8910))
            .unwrap();
        let wire = transport.get_raw(2).unwrap();
        let renewed =
            teagarden_core::sdo::SdoFileObjectV3::decode(&wire, volume_id, 0, &fs.meta_key)
                .unwrap();
        assert_eq!(
            renewed.metadata.previous_version_id,
            Some(object.metadata.version_id)
        );
        assert_eq!(
            renewed.metadata.created_at_ms,
            object.metadata.created_at_ms
        );
        assert_eq!(
            renewed.metadata.authorization_session_hash.as_deref(),
            Some("8910")
        );
        fs.publish_sdo_device_announcement("workstation", 7654321, Some(0))
            .unwrap();
        assert_eq!(
            transport.message_count(),
            2,
            "the masked current hash preserves the known binding"
        );
        fs.publish_sdo_device_announcement("workstation", 7654322, None)
            .unwrap();
        let wire = transport.get_raw(3).unwrap();
        let changed =
            teagarden_core::sdo::SdoFileObjectV3::decode(&wire, volume_id, 0, &fs.meta_key)
                .unwrap();
        assert_eq!(
            changed.metadata.previous_version_id,
            Some(renewed.metadata.version_id)
        );
        assert_eq!(changed.metadata.telegram_user_id, Some(7654322));
        assert_eq!(changed.metadata.authorization_session_hash, None);
    }

    #[test]
    fn device_announcement_ignores_legacy_file_header_in_local_index() {
        use teagarden_core::sdo::{SdoFileObject, SdoObjectMetadata, SDO_SEGMENT_SIZE};

        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let device_id = uuid::Uuid::from_bytes([0x62; 16]);
        let version_id = uuid::Uuid::new_v4();
        let fs = fs.with_sdo(volume_id, device_id);
        fs.store().insert(&Inode::root()).unwrap();
        let wire = SdoFileObject::encode(
            volume_id,
            &fs.meta_key,
            SdoObjectMetadata {
                file_id: uuid::Uuid::new_v4(),
                origin_message_id: None,
                path: "legacy.txt".into(),
                size: 0,
                mtime_ns: 0,
                mode: 0o600,
                version_id,
                author_device_id: device_id,
                previous_version_id: None,
                saved_at_ns: 0,
                local_version: 1,
                deleted: false,
                segment_size: SDO_SEGMENT_SIZE,
                segment_count: 0,
                content_sha256: String::new(),
            },
            b"",
        )
        .unwrap();
        let path_id = keyed_hash(
            fs.manifest_key.as_ref().unwrap(),
            &[b"teagarden.sdo.device.v1".as_slice(), device_id.as_bytes()].concat(),
        );
        fs.sdo_version_store()
            .insert(
                version_id.as_bytes(),
                &StoredSdoVersion {
                    path_id,
                    ino: 2,
                    message_id: 99,
                    wire,
                },
            )
            .unwrap();

        fs.publish_sdo_device_announcement("workstation", 7654321, Some(4567))
            .unwrap();

        assert_eq!(transport.message_count(), 1);
    }

    #[test]
    fn remote_clock_observation_is_persisted_before_local_writes() {
        let (fs, _transport, _rt) = setup_cryptfs_with_transport();
        let fs = fs.with_sdo(
            uuid::Uuid::from_bytes([0x61; 16]),
            uuid::Uuid::from_bytes([0x62; 16]),
        );
        fs.observe_sdo_clock(100, 22).unwrap();
        let stored = fs.sdo_clock_store().get().unwrap().unwrap();
        assert!(stored > (100, 22));
    }

    #[test]
    fn portable_staged_save_keeps_its_identity_across_an_intervening_publish() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let fs = fs.with_sdo(
            uuid::Uuid::from_bytes([0x61; 16]),
            uuid::Uuid::from_bytes([0x62; 16]),
        );
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(2, 1, "new.bin".into(), 0o600, 1000, 1000))
            .unwrap();
        let fh = fs
            .open_impl(2, libc::O_WRONLY | libc::O_TRUNC, 1000)
            .unwrap();
        let original = fs.test_pending_writes().unwrap().pop().unwrap();
        let captured = teagarden_core::sdo::SdoObjectMetadataV3::decode_snapshot(
            original.metadata_snapshot.as_ref().unwrap(),
        )
        .unwrap();
        fs.persist_data(2, b"intervening publish").unwrap();
        assert_ne!(
            fs.sdo_identity_store().get(2).unwrap().unwrap().file_id,
            captured.file_id
        );
        assert_eq!(fs.write_impl(2, fh, 1000, 0, b"my save"), Ok(7));
        fs.flush_impl(2, fh).unwrap();
        let stored = fs
            .sdo_version_store()
            .get(original.version_id.as_bytes())
            .unwrap()
            .unwrap();
        let metadata = decode_stored_sdo_header(
            &stored.wire,
            uuid::Uuid::from_bytes([0x61; 16]),
            &fs.meta_key,
            &fs.sdo_generation_meta_keys,
        )
        .unwrap();
        let RangedSdoHeader::V3(header) = metadata else {
            panic!("expected TGFV3");
        };
        assert_eq!(header.metadata.file_id, captured.file_id);
        assert_eq!(header.metadata.previous_version_id, None);
        assert_eq!(
            transport.message_count(),
            2,
            "one version for each explicit save"
        );
    }

    fn audit_portable_fixture() -> (
        CryptFs,
        Arc<teagarden_telegram::mock::MockTransport>,
        tokio::runtime::Runtime,
    ) {
        let (fs, transport, runtime) = setup_cryptfs_with_transport();
        let fs = fs.with_sdo(
            uuid::Uuid::from_bytes([0x61; 16]),
            uuid::Uuid::from_bytes([0x62; 16]),
        );
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "audit.bin".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        (fs, transport, runtime)
    }

    #[test]
    #[cfg(feature = "key-rotation")]
    fn immutable_spool_retry_survives_a_generation_handoff() {
        let (mut fs, transport, _runtime) = audit_portable_fixture();
        let fh = fs.open_impl(2, libc::O_WRONLY, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 0, b"save before handoff")
            .unwrap();
        transport.fail_file_part_once(0);
        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        let version = fs
            .handles
            .spool(true, fh)
            .unwrap()
            .lock()
            .unwrap()
            .intent
            .metadata
            .version_id;
        let key = SymmetricKey::from_bytes([0x2d; 32]);
        fs.sdo_generation_meta_keys.insert(1, key.clone());
        fs.sdo_key_generation = 1;
        fs.flush_impl(2, fh).unwrap();
        let object = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(1).unwrap(),
            uuid::Uuid::from_bytes([0x61; 16]),
            1,
            &key,
        )
        .unwrap();
        assert_eq!(object.metadata.version_id, version);
        assert_eq!(object.content, b"save before handoff");
    }

    #[test]
    fn bdc2_seed_crash_child() {
        let Some(root) = std::env::var_os("TEAGARDEN_TEST_SEED_CRASH_ROOT") else {
            return;
        };
        let (mut fs, _transport, _runtime) = audit_portable_fixture();
        fs.transient_spool_root = std::path::PathBuf::from(root);
        fs.persist_data(2, &vec![0x41; 4 * 1024 * 1024]).unwrap();
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 1, b"Z").unwrap();
        panic!("seed crash checkpoint was not reached");
    }

    #[test]
    fn bdc2_killed_seed_is_never_published_as_a_shorter_version() {
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fs::tests::bdc2_seed_crash_child", "--nocapture"])
            .env("TEAGARDEN_TEST_SEED_CRASH_ROOT", root.path())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let ready = root.path().join("seed-paused");
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !ready.exists() && std::time::Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("seed child exited: {status}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            ready.exists(),
            "child must reach the partial-seed checkpoint"
        );
        let (mut fs, transport, _runtime) = audit_portable_fixture();
        fs.transient_spool_root = root.path().to_owned();
        fs.persist_data(2, &vec![0x41; 4 * 1024 * 1024]).unwrap();
        let before = transport.message_count();
        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 0);
        assert_eq!(
            transport.message_count(),
            before,
            "never publish the seed prefix"
        );
        let fh = fs.open_impl(2, libc::O_RDONLY, 1000).unwrap();
        assert_eq!(
            fs.read_impl(2, fh, 1000, 0, 4 * 1024 * 1024).unwrap(),
            vec![0x41; 4 * 1024 * 1024]
        );
        assert!(!std::fs::read_dir(root.path()).unwrap().any(|e| e
            .unwrap()
            .path()
            .extension()
            .is_some_and(|e| e == "intent")));
    }

    #[test]
    fn last1_written_then_truncated_empty_is_not_an_untouched_create() {
        let (mut fs, _transport, _runtime) = audit_portable_fixture();
        let root = tempfile::tempdir().unwrap();
        fs.transient_spool_root = root.path().to_owned();
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.stage_portable_write(2, &fs.handles.get(fh).unwrap(), true)
            .unwrap();
        fs.handles
            .spool(true, fh)
            .unwrap()
            .lock()
            .unwrap()
            .mark_empty_create()
            .unwrap();
        fs.write_impl(2, fh, 1000, 0, b"ABC").unwrap();
        fs.handles
            .spool(true, fh)
            .unwrap()
            .lock()
            .unwrap()
            .resize(0)
            .unwrap();
        fs.handles.remove_spool(true, fh);
        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 0);
        assert_eq!(
            std::fs::read_dir(root.path().join("quarantine"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn recheck_low_dirty_spool_read_beyond_eof_returns_empty() {
        let (fs, _transport, _runtime) = audit_portable_fixture();
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 0, b"ABC").unwrap();
        assert_eq!(fs.read_impl(2, fh, 1000, 0, 10).unwrap(), b"ABC");
        assert!(fs.read_impl(2, fh, 1000, 30, 10).unwrap().is_empty());
        assert!(fs.read_impl(2, fh, 1000, 30, 0).unwrap().is_empty());
        let held = fs.handles.spool(true, fh).unwrap();
        let spool = held.lock().unwrap();
        assert!(spool.read_range(u64::MAX, 10).unwrap().is_empty());
        use std::io::{Read, Seek, SeekFrom};
        let mut reader = spool.file.try_clone().unwrap();
        reader.seek(SeekFrom::Start(30)).unwrap();
        assert_eq!(reader.read(&mut [0; 10]).unwrap(), 0);
    }

    #[test]
    fn recovery_b_bad_intents_do_not_block_healthy_prepared_writes() {
        for damage in ["initialization", "format", "intent", "prefix"] {
            let (mut fs, transport, _runtime) = audit_portable_fixture();
            let root = tempfile::tempdir().unwrap();
            fs.transient_spool_root = root.path().to_owned();
            let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
            fs.write_impl(2, fh, 1000, 0, &vec![0x41; 160 * 1024])
                .unwrap();
            transport.fail_file_part_once(0);
            assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
            let held = fs.handles.spool(true, fh).unwrap();
            let mut spool = held.lock().unwrap();
            match damage {
                "initialization" => {
                    spool.intent.initialized = false;
                    spool.save().unwrap();
                }
                "format" => {
                    let wire = std::fs::read(&spool.intent_path).unwrap();
                    let aad = b"teagarden.write-spool.intent.v1";
                    let plain =
                        teagarden_core::crypto::aead::decrypt(fs.spool_key(), &wire, aad).unwrap();
                    let mut json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
                    json["payload_format"] = 0.into();
                    let wire = teagarden_core::crypto::aead::encrypt(
                        fs.spool_key(),
                        &serde_json::to_vec(&json).unwrap(),
                        aad,
                    )
                    .unwrap();
                    std::fs::write(&spool.intent_path, wire).unwrap();
                }
                "intent" => std::fs::write(&spool.intent_path, b"unauthenticated").unwrap(),
                "prefix" => std::fs::OpenOptions::new()
                    .write(true)
                    .open(&spool.intent.spool)
                    .unwrap()
                    .set_len(65536 + 40)
                    .unwrap(),
                _ => panic!("unknown recovery damage case: {damage}"),
            }
            drop(spool);
            drop(held);
            fs.handles.remove_spool(true, fh);
            fs.store()
                .insert(&Inode::new_file(3, 1, "healthy".into(), 0o600, 1000, 1000))
                .unwrap();
            let healthy = fs.open_impl(3, libc::O_RDWR, 1000).unwrap();
            fs.write_impl(3, healthy, 1000, 0, b"healthy prepared write")
                .unwrap();
            transport.fail_file_part_once(0);
            assert_eq!(fs.flush_impl(3, healthy), Err(libc::EIO));
            fs.handles.remove_spool(true, healthy);
            assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 1, "{damage}");
            assert_eq!(transport.message_count(), 1, "{damage}");
            assert_eq!(
                std::fs::read_dir(root.path().join("quarantine"))
                    .unwrap()
                    .count(),
                1
            );
            let object = teagarden_core::sdo::SdoFileObjectV3::decode(
                &transport.get_raw(1).unwrap(),
                uuid::Uuid::from_bytes([0x61; 16]),
                0,
                &fs.meta_key,
            )
            .unwrap();
            assert_eq!(object.content, b"healthy prepared write");
        }
    }

    #[test]
    fn bdc3_spool_is_encrypted_and_recovers_after_restart() {
        let (mut fs, transport, _runtime) = audit_portable_fixture();
        let root = tempfile::tempdir().unwrap();
        fs.transient_spool_root = root.path().to_owned();
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        let marker = b"SPOOL_PLAINTEXT_MUST_NEVER_APPEAR_20261118";
        let mut content = marker.repeat(700);
        fs.write_impl(2, fh, 1000, 0, &content).unwrap();
        fs.write_impl(2, fh, 1000, 4090, b"cross-block overwrite")
            .unwrap();
        content[4090..4111].copy_from_slice(b"cross-block overwrite");
        transport.fail_file_part_once(0);
        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        let held = fs.handles.spool(true, fh).unwrap();
        let spool = held.lock().unwrap();
        let payload = std::fs::read(&spool.intent.spool).unwrap();
        assert!(
            !payload.windows(marker.len()).any(|bytes| bytes == marker),
            "the durable payload must not expose plaintext"
        );
        let path = spool.intent_path.clone();
        drop(spool);
        drop(held);
        fs.handles.remove_spool(true, fh);
        let recovered = crate::spool::WriteSpool::load(
            &path,
            fs.spool_key().clone(),
            fs.manifest_key.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(recovered.read_range(0, content.len()).unwrap(), content);
        drop(recovered);
        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 1);
        let object = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(1).unwrap(),
            uuid::Uuid::from_bytes([0x61; 16]),
            0,
            &fs.meta_key,
        )
        .unwrap();
        assert_eq!(object.content, content);
    }

    #[test]
    fn pending_write_above_current_upload_limit_is_quarantined() {
        let (mut fs, transport, _runtime) = audit_portable_fixture();
        let root = tempfile::tempdir().unwrap();
        fs.transient_spool_root = root.path().to_owned();
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 0, b"pending payload").unwrap();
        transport.fail_file_part_once(0);
        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        fs.handles.remove_spool(true, fh);

        fs.sdo_context.as_mut().unwrap().max_file_size = 1;
        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 0);
        assert_eq!(transport.message_count(), 0);
        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 0);
        assert_eq!(transport.file_upload_metrics().0, 1);
        assert_eq!(
            std::fs::read_dir(root.path().join("quarantine"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn older_pending_upload_survives_an_unavailable_transport_without_blocking_recovery() {
        let (mut fs, transport, _runtime) = audit_portable_fixture();
        let pending = SdoPendingWrite {
            version_id: uuid::Uuid::new_v4(),
            inode: 2,
            handle_id: 1,
            predecessor: None,
            clock_ms: 1,
            clock_counter: 1,
            bytes: b"pending upload".to_vec(),
            wire: None,
            metadata_snapshot: None,
        };
        fs.sdo_pending_write_store().put(&pending).unwrap();
        *transport.fail_uploads.lock().unwrap() = Some("transport offline".into());

        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 0);
        assert_eq!(transport.message_count(), 0);
        assert!(fs
            .sdo_pending_write_store()
            .get(&pending.version_id)
            .unwrap()
            .is_some());
    }

    #[test]
    fn bdc5_forgotten_server_parts_restart_upload_with_stable_publication() {
        let (mut fs, transport, _runtime) = audit_portable_fixture();
        let root = tempfile::tempdir().unwrap();
        fs.transient_spool_root = root.path().to_owned();
        transport.set_file_part_window(4);
        transport.fail_file_part_once(17);
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        let content = vec![0x51; 12 * 1024 * 1024];
        fs.write_impl(2, fh, 1000, 0, &content).unwrap();
        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        let held = fs.handles.spool(true, fh).unwrap();
        let mut spool = held.lock().unwrap();
        let version = spool.intent.metadata.version_id;
        let publication = spool.intent.publication_id;
        let upload = spool.intent.upload_id;
        assert!(!spool.intent.acknowledged.is_empty());
        transport.forget_file_parts();
        // Keep the new attempt interrupted so its durable identity can be inspected.
        transport.fail_file_part_once(0);
        assert!(fs.upload_spool(&mut spool).is_err());
        let recovered = crate::spool::WriteSpool::load(
            &spool.intent_path,
            fs.spool_key().clone(),
            fs.manifest_key.as_ref().unwrap(),
        )
        .unwrap();
        assert_ne!(recovered.intent.upload_id, upload);
        assert_eq!(recovered.intent.publication_id, publication);
        assert_eq!(recovered.intent.metadata.version_id, version);
        assert!(recovered.intent.acknowledged.is_empty());
        drop(recovered);
        drop(spool);
        drop(held);
        fs.handles.remove_spool(true, fh);
        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 1);
        assert_eq!(transport.message_count(), 1);
        let object = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(1).unwrap(),
            uuid::Uuid::from_bytes([0x61; 16]),
            0,
            &fs.meta_key,
        )
        .unwrap();
        assert_eq!(object.metadata.version_id, version);
        assert_eq!(object.content, content);
    }

    #[test]
    fn interrupted_part_upload_resumes_from_the_sole_spool_and_acknowledged_offsets() {
        let (mut fs, transport, _runtime) = audit_portable_fixture();
        let directory = tempfile::tempdir().unwrap();
        fs.transient_spool_root = directory.path().join("spools");
        transport.set_file_part_window(4);
        transport.fail_file_part_once(17);
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        let bytes = vec![0x52; 20 * 1024 * 1024];
        fs.write_impl(2, fh, 1000, 0, &bytes).unwrap();
        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        let held = fs.handles.spool(true, fh).unwrap();
        let spool = held.lock().unwrap();
        let path = spool.intent_path.clone();
        let version = spool.intent.metadata.version_id;
        let acknowledged = spool.intent.acknowledged.clone();
        let parts = spool
            .intent
            .plan
            .as_ref()
            .unwrap()
            .wire_len()
            .div_ceil(512 * 1024) as usize;
        assert!(acknowledged.len() > 4);
        assert!(acknowledged.len() < parts);
        let before = transport.file_upload_metrics().2;
        assert_eq!(spool.written, bytes.len() as u64);
        drop(spool);
        drop(held);
        // Reopen the durable files, rather than retaining the in-memory progress.
        fs.handles.remove_spool(true, fh);
        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 1);
        assert_eq!(
            transport.file_upload_metrics().2 - before,
            parts - acknowledged.len(),
            "acknowledged offsets must never be sent again"
        );
        assert_eq!(transport.message_count(), 1);
        assert!(!path.exists());
        let object = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(1).unwrap(),
            uuid::Uuid::from_bytes([0x61; 16]),
            0,
            &fs.meta_key,
        )
        .unwrap();
        assert_eq!(object.metadata.version_id, version);
        assert_eq!(object.content, bytes);
        assert_eq!(std::fs::read_dir(fs.spool_root()).unwrap().count(), 0);
    }

    #[test]
    fn upload_queue_is_bounded_by_resident_bytes_not_four_requests() {
        let (fs, transport, rt) = setup_cryptfs_with_transport();
        let fs = fs.with_upload_queue();
        let mut gates = Vec::new();
        let mut results = Vec::new();
        for n in 0..12 {
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let name = format!("memory-budget-{n}");
            transport.gate_next_upload(&name, entered.clone(), release.clone());
            let (tx, rx) = tokio::sync::oneshot::channel();
            let memory = rt
                .block_on(fs.upload_memory.clone().acquire_many_owned(1024))
                .unwrap();
            fs.upload_tx
                .as_ref()
                .unwrap()
                .send(PendingUpload {
                    ciphertext: vec![7; 1024],
                    _memory: memory,
                    filename: name,
                    timeout: Duration::from_secs(5),
                    result_tx: tx,
                })
                .unwrap();
            gates.push((entered, release));
            results.push(rx);
        }
        let all_entered = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(2),
                futures::future::join_all(gates.iter().map(|(entered, _)| entered.notified())),
            )
            .await
        });
        for (_, release) in &gates {
            release.notify_one();
        }
        assert!(
            all_entered.is_ok(),
            "twelve KiB fits the byte budget; a four-request cap must not stall it"
        );
        for result in results {
            assert!(rt.block_on(result).unwrap().is_ok());
        }
    }

    #[test]
    fn confirmed_spool_repairs_index_without_payload_or_a_second_upload() {
        let (mut fs, transport, _runtime) = audit_portable_fixture();
        let fh = fs.open_impl(2, libc::O_WRONLY, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 0, b"confirmed bytes").unwrap();
        let table = fs.schema.require_table("manifests").unwrap();
        fs.conn.execute_batch(&format!("CREATE TEMP TRIGGER fail_manifest BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'index fault'); END")).unwrap();
        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        let held = fs.handles.spool(true, fh).unwrap();
        let spool = held.lock().unwrap();
        assert_eq!(spool.intent.confirmed, Some(1));
        assert!(!spool.intent.spool.exists());
        assert!(spool.intent_path.exists());
        drop(spool);
        drop(held);
        fs.handles.remove_spool(true, fh);
        fs.conn.execute_batch("DROP TRIGGER fail_manifest").unwrap();
        let before = transport.bytes_served();
        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 1);
        assert_eq!(transport.bytes_served(), before);
        assert_eq!(transport.file_upload_metrics().0, 1);
        let inode = fs.store().lookup(1, "audit.bin").unwrap().unwrap();
        let read = fs.open_impl(inode.ino, libc::O_RDONLY, 1000).unwrap();
        assert_eq!(
            fs.read_impl(inode.ino, read, 1000, 0, 100).unwrap(),
            b"confirmed bytes"
        );
    }

    #[test]
    fn authenticated_read_cache_rechecks_changed_policy_before_cached_plaintext() {
        use teagarden_core::sdo::{HeaderDocument, RevocationCutoff, SigningKey};
        let (fs, transport, _runtime) = audit_portable_fixture();
        let mut hierarchy = teagarden_core::crypto::kdf::derive_hierarchy_v1(
            SymmetricKey::from_bytes([0x70; 32]),
            &[1; 32],
            -100,
            42,
        )
        .unwrap();
        hierarchy.meta = fs.meta_key.clone();
        let owner = SigningKey::from_bytes(&[0x71; 32]);
        let writer = SigningKey::from_bytes(&[0x72; 32]);
        let mut policy = HeaderDocument::test_fixture();
        policy.format = 2;
        policy.volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        policy.key_generation = Some(0);
        policy.owner_public_key = Some(hex::encode(owner.verifying_key().to_bytes()));
        let device = uuid::Uuid::from_bytes([0x62; 16]);
        policy
            .device_authorities
            .insert(device, hex::encode(writer.verifying_key().to_bytes()));
        let wire = policy.encode_v2(&hierarchy.integrity, &owner).unwrap();
        let mut fs = fs
            .with_sdo_signing_key(writer)
            .with_sdo_object_envelope(wire.clone(), hierarchy.clone());
        fs.persist_data(2, b"cached bytes").unwrap();
        let fh = fs.open_impl(2, libc::O_RDONLY, 1000).unwrap();
        assert_eq!(fs.read_impl(2, fh, 1000, 0, 12).unwrap(), b"cached bytes");
        let before = transport.bytes_served();
        assert_eq!(fs.read_impl(2, fh, 1000, 0, 12).unwrap(), b"cached bytes");
        assert_eq!(transport.bytes_served(), before);
        let mut invalid = wire;
        invalid[20] ^= 1;
        fs.sdo_object_envelope = Some((invalid, hierarchy.clone()));
        assert_eq!(
            fs.read_impl(2, fh, 1000, 0, 12),
            Err(libc::EIO),
            "a different policy must authenticate before cache reuse"
        );
        policy.revision += 1;
        policy.revoked_device_ids.push(device);
        policy.revocation_cutoffs.insert(
            device,
            RevocationCutoff {
                key_generation: 0,
                boundary_message_id: 1,
            },
        );
        fs.sdo_object_envelope = Some((
            policy.encode_v2(&hierarchy.integrity, &owner).unwrap(),
            hierarchy,
        ));
        assert_eq!(
            fs.read_impl(2, fh, 1000, 0, 12),
            Err(libc::EACCES),
            "revocation invalidates cached authority and plaintext"
        );
        assert_eq!(transport.bytes_served(), before);
    }

    #[test]
    fn shrink_of_a_large_dirty_spool_does_not_fail_on_an_obsolete_hash_read() {
        let (fs, _transport, _runtime) = setup_cryptfs_with_transport();
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "shrink.bin".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        let fh = fs.open_impl(2, libc::O_RDWR | libc::O_TRUNC, 1000).unwrap();
        let bytes = vec![0x53; 64 * 1024 * 1024];
        fs.write_impl(2, fh, 1000, 0, &bytes).unwrap();
        fs.setattr_impl(2, 1000, None, None, None, Some(11), None, None)
            .unwrap();
        assert_eq!(
            fs.flush_impl(2, fh),
            Ok(()),
            "a hash read for the old length must be discarded after truncate"
        );
        assert_eq!(fs.read_impl(2, fh, 1000, 0, 100).unwrap(), bytes[..11]);
    }

    #[test]
    fn audit_recovery_does_not_download_the_uploaded_object() {
        let (mut fs, transport, _runtime) = audit_portable_fixture();
        let fh = fs.handles.open(2, libc::O_WRONLY, 1000);
        fs.write_impl(2, fh, 1000, 0, b"durable local bytes")
            .unwrap();
        transport.fail_file_part_once(0);
        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        fs.handles.remove_spool(true, fh);
        let before = transport.bytes_served();
        assert_eq!(fs.retry_pending_sdo_writes().unwrap(), 1);
        assert_eq!(
            transport.bytes_served() - before,
            0,
            "upload acknowledgements and document size suffice; no full read-back"
        );
    }

    #[test]
    fn audit_upload_timeout_measures_a_part_not_the_entire_object() {
        let (fs, transport, _runtime) = audit_portable_fixture();
        let fs = fs.with_upload_timeout(Duration::from_millis(500));
        transport.record_file_parts(Duration::from_millis(100));
        transport.set_file_part_window(4);
        let fh = fs.handles.open(2, libc::O_WRONLY, 1000);
        let data = vec![0x3a; 20 * 1024 * 1024];
        fs.write_impl(2, fh, 1000, 0, &data).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(
            fs.flush_impl(2, fh),
            Ok(()),
            "healthy parts must survive a total transfer longer than the part timeout"
        );
        assert!(started.elapsed() > Duration::from_millis(500));
        assert_eq!(transport.file_upload_metrics().0, 1);
    }

    #[test]
    fn audit_dirty_portable_file_is_not_held_in_a_file_sized_vec() {
        let (fs, _transport, _runtime) = audit_portable_fixture();
        let fh = fs.handles.open(2, libc::O_RDWR, 1000);
        let chunk = vec![0x39; 128 * 1024];
        for n in 0..64 {
            fs.write_impl(2, fh, 1000, n * chunk.len() as i64, &chunk)
                .unwrap();
        }
        let resident = fs
            .handles
            .with_handle_buffer(fh, |buffer| buffer.capacity())
            .unwrap_or(0);
        assert!(
            resident <= 1024 * 1024,
            "dirty file retained {resident} bytes in RAM instead of a disk spool"
        );
        assert_eq!(
            fs.read_impl(2, fh, 1000, 7 * 1024 * 1024, 128 * 1024)
                .unwrap(),
            chunk
        );
    }

    #[test]
    fn portable_many_writes_have_linear_durable_byte_cost() {
        let (fs, _transport, _rt) = setup_cryptfs_with_transport();
        let fs = fs.with_sdo(
            uuid::Uuid::from_bytes([0x61; 16]),
            uuid::Uuid::from_bytes([0x62; 16]),
        );
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "large.bin".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        fs.conn.execute_batch("CREATE TEMP TABLE pending_byte_audit (n INTEGER NOT NULL); INSERT INTO pending_byte_audit VALUES (0)").unwrap();
        for table_name in ["sdo_pending_writes", "sdo_pending_chunks"] {
            let table = fs.schema.require_table(table_name).unwrap();
            let data = fs.schema.require_column(table_name, "data").unwrap();
            for event in ["INSERT", "UPDATE"] {
                fs.conn.execute_batch(&format!("CREATE TEMP TRIGGER audit_{table_name}_{event} AFTER {event} ON {table} BEGIN UPDATE pending_byte_audit SET n=n+length(new.{data}); END;")).unwrap();
            }
        }
        let fh = fs.handles.open(2, libc::O_WRONLY, 1000);
        let chunk = vec![0x3a; 128 * 1024];
        for n in 0..64 {
            assert_eq!(
                fs.write_impl(2, fh, 1000, n * chunk.len() as i64, &chunk),
                Ok(chunk.len() as u32)
            );
        }
        let written = 64 * chunk.len();
        let durable = fs
            .conn
            .query_row("SELECT n FROM pending_byte_audit", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap() as usize;
        assert!(
            durable < written * 2,
            "quadratic durable rewrites: {durable} encrypted bytes for {written} written bytes"
        );
        let retry = fs.test_pending_writes().unwrap().pop().unwrap();
        assert_eq!(retry.bytes, vec![0x3a; written]);
        assert_eq!(durable, 0, "new writes never store payloads in SQLite");
        let spool = fs.handles.spool(true, fh).unwrap();
        let spool = spool.lock().unwrap();
        assert_eq!(
            spool.written, written as u64,
            "the sole payload is the sequential write spool"
        );
        assert!(
            std::fs::metadata(&spool.intent_path).unwrap().len() < 16 * 1024,
            "intent contains metadata only"
        );
    }

    #[test]
    fn portable_write_is_durable_before_fuse_acknowledges_bytes() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let fs = fs.with_sdo(
            uuid::Uuid::from_bytes([0x61; 16]),
            uuid::Uuid::from_bytes([0x62; 16]),
        );
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "durable.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        fs.persist_data(2, b"base").unwrap();
        let predecessor = fs
            .sdo_identity_store()
            .get(2)
            .unwrap()
            .unwrap()
            .latest_version_id
            .unwrap();
        let fh = fs
            .handles
            .open_pinned_sdo(2, libc::O_RDWR, 1000, predecessor);

        assert_eq!(fs.write_impl(2, fh, 1000, 4, b" durable bytes"), Ok(14));
        let writes = fs.test_pending_writes().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].inode, 2);
        assert_eq!(writes[0].handle_id, fh);
        assert_eq!(writes[0].predecessor, Some(predecessor));
        assert_eq!(writes[0].bytes, b"base durable bytes");
        assert!(writes[0].clock_ms > 0);
        let retry_id = writes[0].version_id;
        let retry_clock = (writes[0].clock_ms, writes[0].clock_counter);
        transport.withhold_upload_acks(1);
        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        let after_lost_ack = fs.test_pending_get(&retry_id).unwrap().unwrap();
        let exact_retry_wire = after_lost_ack
            .wire
            .expect("ciphertext is reproducible from the spool and small immutable plan");
        assert_eq!(
            transport.message_count(),
            2,
            "server stored the unacknowledged object"
        );
        let before_parts = transport.file_upload_metrics().2;
        fs.flush_impl(2, fh).unwrap();
        assert_eq!(
            transport.file_upload_metrics().2,
            before_parts,
            "lost SendMedia acknowledgement must not reupload parts"
        );
        assert_eq!(
            transport.message_count(),
            2,
            "idempotent publication must not duplicate the version"
        );
        assert!(fs.test_pending_get(&retry_id).unwrap().is_none());
        let object = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(2).unwrap(),
            uuid::Uuid::from_bytes([0x61; 16]),
            0,
            &fs.meta_key,
        )
        .unwrap();
        assert_eq!(object.metadata.version_id, retry_id);
        assert_eq!(
            (object.metadata.clock_ms, object.metadata.clock_counter),
            retry_clock
        );
        assert_eq!(object.metadata.previous_version_id, Some(predecessor));
        assert_eq!(transport.get_raw(2).unwrap(), exact_retry_wire);
    }

    #[test]
    #[cfg(feature = "key-rotation")]
    fn mounted_fuse_reads_old_generation_object_through_header_bridge() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let old_meta = SymmetricKey::from_bytes([0x31; 32]);
        let active_meta = SymmetricKey::from_bytes([0x32; 32]);
        let version_id = uuid::Uuid::from_bytes([0x33; 16]);
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode(
            volume_id,
            0,
            &old_meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: uuid::Uuid::from_bytes([0x34; 16]),
                origin_message_id: Some(5),
                path: Some("bridged.txt".into()),
                size: 11,
                mtime_ns: 1,
                mode: 0o600,
                version_id,
                author_device_id: uuid::Uuid::from_bytes([0x35; 16]),
                previous_version_id: None,
                kind: teagarden_core::sdo::SdoKind::File,
                key_generation: 0,
                clock_ms: 2,
                clock_counter: 0,
                saved_at_ns: 0,
                local_version: 1,
                deleted: false,
                installation_id: None,
                label: None,
                telegram_user_id: None,
                authorization_session_hash: None,
                created_at_ms: None,
                device_public_key: None,
                device_key_update: None,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 1,
                content_sha256: hex::encode(sha256_bytes(b"old bytes!!")),
            },
            b"old bytes!!",
        )
        .unwrap();
        let header_len = u32::from_le_bytes(wire[30..34].try_into().unwrap()) as usize;
        let header_wire = wire[..34 + header_len].to_vec();
        transport.put_document(17, -100, 42, "bridged.tgf", wire);
        let fs = fs
            .with_sdo(volume_id, uuid::Uuid::from_bytes([0x36; 16]))
            .with_sdo_generation_keys(
                1,
                Some(20),
                std::collections::BTreeMap::from([(0, old_meta), (1, active_meta)]),
            );
        fs.sdo_version_store()
            .insert(
                version_id.as_bytes(),
                &StoredSdoVersion {
                    path_id: [0x37; 32],
                    ino: 2,
                    message_id: 17,
                    wire: header_wire,
                },
            )
            .unwrap();
        let stored = fs
            .sdo_version_store()
            .get(version_id.as_bytes())
            .unwrap()
            .unwrap();

        let content = fs
            .read_sdo_stored_range(2, version_id, stored, 0, 11)
            .unwrap();
        assert_eq!(content, b"old bytes!!");
    }

    #[test]
    #[cfg(feature = "key-rotation")]
    fn mounted_c_cold_reads_migrated_current_and_pinned_handles_after_original_deletion() {
        let (fs, transport, rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let old_meta = SymmetricKey::from_bytes([0x31; 32]);
        let active_meta = SymmetricKey::from_bytes([0x32; 32]);
        let version_id = uuid::Uuid::from_bytes([0x33; 16]);
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode(
            volume_id,
            0,
            &old_meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: uuid::Uuid::from_bytes([0x34; 16]),
                origin_message_id: Some(5),
                path: Some("bridged.txt".into()),
                size: 11,
                mtime_ns: 1,
                mode: 0o600,
                version_id,
                author_device_id: uuid::Uuid::from_bytes([0x35; 16]),
                previous_version_id: None,
                kind: teagarden_core::sdo::SdoKind::File,
                key_generation: 0,
                clock_ms: 2,
                clock_counter: 0,
                saved_at_ns: 0,
                local_version: 1,
                deleted: false,
                installation_id: None,
                label: None,
                telegram_user_id: None,
                authorization_session_hash: None,
                created_at_ms: None,
                device_public_key: None,
                device_key_update: None,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 1,
                content_sha256: hex::encode(sha256_bytes(b"old bytes!!")),
            },
            b"old bytes!!",
        )
        .unwrap();
        let header_len = u32::from_le_bytes(wire[30..34].try_into().unwrap()) as usize;
        let header_wire = wire[..34 + header_len].to_vec();
        let replacement = teagarden_core::sdo::reencrypt_v3_history(
            &wire,
            volume_id,
            0,
            &old_meta,
            1,
            &active_meta,
        )
        .unwrap();
        let replacement_header_len =
            u32::from_le_bytes(replacement[30..34].try_into().unwrap()) as usize;
        let replacement_header = replacement[..34 + replacement_header_len].to_vec();
        transport.put_document(17, -100, 42, "original.tgf", wire);
        transport.put_document(30, -100, 42, "replacement.tgf", replacement);
        let mut fs = fs
            .with_sdo(volume_id, uuid::Uuid::from_bytes([0x36; 16]))
            .with_sdo_generation_keys(
                1,
                Some(20),
                std::collections::BTreeMap::from([(0, old_meta), (1, active_meta)]),
            );
        fs.store().insert(&Inode::root()).unwrap();
        fs.apply_remote_sdo_batch(vec![(17, header_wire)], 17)
            .unwrap();
        let inode = fs.store().lookup(1, "bridged.txt").unwrap().unwrap();
        let pinned = fs.open_impl(inode.ino, libc::O_RDONLY, 1000).unwrap();
        fs.apply_remote_sdo_batch(vec![(30, replacement_header)], 30)
            .unwrap();
        rt.block_on(transport.delete_message(17)).unwrap();
        assert!(transport.get_raw(17).is_none());
        assert_eq!(
            fs.sdo_version_store()
                .get(version_id.as_bytes())
                .unwrap()
                .unwrap()
                .message_id,
            30
        );
        assert_eq!(
            fs.read_impl(inode.ino, pinned, 1000, 0, 11).unwrap(),
            b"old bytes!!"
        );
        let fresh = fs.open_impl(inode.ino, libc::O_RDONLY, 1000).unwrap();
        assert_eq!(
            fs.read_impl(inode.ino, fresh, 1000, 0, 11).unwrap(),
            b"old bytes!!"
        );
    }

    #[test]
    fn pending_portable_write_retries_after_filesystem_recreation() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let schema_key = SymmetricKey::from_bytes([0x42; 32]);
        let meta_key = SymmetricKey::from_bytes([0x43; 32]);
        let data_key = SymmetricKey::from_bytes([0x44; 32]);
        let transport = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let conn = Connection::open(&db_path).unwrap();
        let schema = OpaqueSchema::new(schema_key.clone(), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let fs = CryptFs::new(conn, schema, meta_key.clone(), data_key.clone(), 1000, 1000)
            .with_block_keys(
                SymmetricKey::from_bytes([0x45; 32]),
                SymmetricKey::from_bytes([0x46; 32]),
            )
            .with_manifest_key(SymmetricKey::from_bytes([0x47; 32]))
            .with_sdo(
                uuid::Uuid::from_bytes([0x61; 16]),
                uuid::Uuid::from_bytes([0x62; 16]),
            )
            .with_transport(transport.clone())
            .with_runtime(rt.handle().clone());
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "retry.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        fs.persist_data(2, b"base").unwrap();
        let predecessor = fs
            .sdo_identity_store()
            .get(2)
            .unwrap()
            .unwrap()
            .latest_version_id
            .unwrap();
        let fh = fs
            .handles
            .open_pinned_sdo(2, libc::O_RDWR, 1000, predecessor);
        fs.write_impl(2, fh, 1000, 4, b" edit").unwrap();
        transport.fail_file_part_once(0);
        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        let retry = fs.test_pending_writes().unwrap().pop().unwrap();
        assert!(retry.wire.is_some(), "recovery requires the synced plan");
        drop(fs);

        let conn = Connection::open(&db_path).unwrap();
        let schema = OpaqueSchema::new(schema_key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let mut recovered = CryptFs::new(conn, schema, meta_key.clone(), data_key, 1000, 1000)
            .with_block_keys(
                SymmetricKey::from_bytes([0x45; 32]),
                SymmetricKey::from_bytes([0x46; 32]),
            )
            .with_manifest_key(SymmetricKey::from_bytes([0x47; 32]))
            .with_sdo(
                uuid::Uuid::from_bytes([0x61; 16]),
                uuid::Uuid::from_bytes([0x62; 16]),
            )
            .with_transport(transport.clone())
            .with_runtime(rt.handle().clone());
        assert_eq!(recovered.retry_pending_sdo_writes().unwrap(), 1);
        assert!(recovered
            .test_pending_get(&retry.version_id)
            .unwrap()
            .is_none());
        let object = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(2).unwrap(),
            uuid::Uuid::from_bytes([0x61; 16]),
            0,
            &meta_key,
        )
        .unwrap();
        assert_eq!(object.metadata.version_id, retry.version_id);
        assert_eq!(
            (object.metadata.clock_ms, object.metadata.clock_counter),
            (retry.clock_ms, retry.clock_counter)
        );
        assert_eq!(object.metadata.previous_version_id, Some(predecessor));
    }

    #[test]
    fn stable_outbox_recovers_only_prepared_images_without_old_index() {
        for prepared in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let outbox_path = directory.path().join("outbox.db");
            let (fs, transport, rt) = setup_cryptfs_with_transport();
            let key = SymmetricKey::from_bytes([0x79; 32]);
            let outbox = Connection::open(&outbox_path).unwrap();
            let outbox_schema = OpaqueSchema::new(key.clone(), &logical_tables());
            initialize_database(&outbox, &outbox_schema).unwrap();
            let fs = fs
                .with_sdo(
                    uuid::Uuid::from_bytes([0x61; 16]),
                    uuid::Uuid::from_bytes([0x62; 16]),
                )
                .with_sdo_outbox(outbox, outbox_schema, key.clone());
            let mut root = Inode::root();
            root.uid = 1000;
            root.gid = 1000;
            fs.store().insert(&root).unwrap();
            let inode = Inode::new_file(2, 1, "unflushed.txt".into(), 0o600, 1000, 1000);
            fs.store().insert(&inode).unwrap();
            let mut root = fs.store().get(1).unwrap().unwrap();
            root.children.push(inode.ino);
            fs.store().update(&root).unwrap();
            let handle = fs.open_impl(inode.ino, libc::O_RDWR, 1000).unwrap();
            fs.write_impl(inode.ino, handle, 1000, 0, b"unflushed bytes")
                .unwrap();
            if prepared {
                transport.fail_file_part_once(0);
                assert_eq!(fs.flush_impl(inode.ino, handle), Err(libc::EIO));
            }
            let pending = fs.test_pending_writes().unwrap().pop().unwrap();
            assert_eq!(pending.wire.is_some(), prepared);
            let snapshot = teagarden_core::sdo::SdoObjectMetadataV3::decode_snapshot(
                pending.metadata_snapshot.as_deref().unwrap(),
            )
            .unwrap();
            assert_eq!(snapshot.path.as_deref(), Some("unflushed.txt"));
            drop(fs);
            let conn = Connection::open_in_memory().unwrap();
            let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
            initialize_database(&conn, &schema).unwrap();
            let outbox = Connection::open(outbox_path).unwrap();
            let outbox_schema = OpaqueSchema::new(key.clone(), &logical_tables());
            let mut recovered = CryptFs::new(
                conn,
                schema,
                SymmetricKey::from_bytes([0x43; 32]),
                SymmetricKey::from_bytes([0x44; 32]),
                1000,
                1000,
            )
            .with_sdo(
                uuid::Uuid::from_bytes([0x61; 16]),
                uuid::Uuid::from_bytes([0x62; 16]),
            )
            .with_manifest_key(SymmetricKey::from_bytes([0x47; 32]))
            .with_sdo_outbox(outbox, outbox_schema, key)
            .with_transport(transport.clone())
            .with_runtime(rt.handle().clone());
            let mut root = Inode::root();
            root.uid = 1000;
            root.gid = 1000;
            recovered.store().insert(&root).unwrap();
            assert!(recovered
                .store()
                .lookup(1, "unflushed.txt")
                .unwrap()
                .is_none());
            if !prepared {
                assert_eq!(recovered.retry_pending_sdo_writes().unwrap(), 0);
                assert!(recovered
                    .store()
                    .lookup(1, "unflushed.txt")
                    .unwrap()
                    .is_none());
                assert_eq!(transport.message_count(), 0);
                assert_eq!(
                    std::fs::read_dir(directory.path().join("write-spools/quarantine"))
                        .unwrap()
                        .count(),
                    1
                );
                continue;
            }
            assert_eq!(recovered.retry_pending_sdo_writes().unwrap(), 1);
            let file = recovered
                .store()
                .lookup(1, "unflushed.txt")
                .unwrap()
                .unwrap();
            let handle = recovered.open_impl(file.ino, libc::O_RDONLY, 1000).unwrap();
            assert_eq!(
                recovered.read_impl(file.ino, handle, 1000, 0, 15).unwrap(),
                b"unflushed bytes"
            );
            let stored = recovered
                .sdo_version_store()
                .get(pending.version_id.as_bytes())
                .unwrap()
                .unwrap();
            let RangedSdoHeader::V3(decoded) = decode_stored_sdo_header(
                &stored.wire,
                uuid::Uuid::from_bytes([0x61; 16]),
                &recovered.meta_key,
                &recovered.sdo_generation_meta_keys,
            )
            .unwrap() else {
                panic!("recovered write has a legacy header");
            };
            assert_eq!(decoded.metadata.clock_ms, pending.clock_ms);
            assert_eq!(decoded.metadata.previous_version_id, pending.predecessor);
            assert!(recovered.test_pending_writes().unwrap().is_empty());
        }
    }

    #[test]
    fn remote_poll_batch_reduces_and_commits_inode_and_cursor_together() {
        let (fs, _transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let mut fs = fs.with_sdo(volume_id, uuid::Uuid::from_bytes([0x62; 16]));
        fs.store().insert(&Inode::root()).unwrap();
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode(
            volume_id,
            0,
            &fs.meta_key,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: uuid::Uuid::from_bytes([0x72; 16]),
                origin_message_id: None,
                path: Some("remote.txt".into()),
                size: 0,
                mtime_ns: 10,
                mode: 0o600,
                version_id: uuid::Uuid::from_bytes([0x73; 16]),
                author_device_id: uuid::Uuid::from_bytes([0x74; 16]),
                previous_version_id: None,
                kind: teagarden_core::sdo::SdoKind::File,
                key_generation: 0,
                clock_ms: 500,
                clock_counter: 1,
                saved_at_ns: 0,
                local_version: 1,
                deleted: false,
                installation_id: None,
                label: None,
                telegram_user_id: None,
                authorization_session_hash: None,
                created_at_ms: None,
                device_public_key: None,
                device_key_update: None,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 0,
                content_sha256: hex::encode(teagarden_core::block::srb2::sha256(b"")),
            },
            b"",
        )
        .unwrap();
        let header_len = u32::from_le_bytes(wire[30..34].try_into().unwrap()) as usize;
        let header = wire[..34 + header_len].to_vec();

        fs.apply_remote_sdo_batch(vec![(12, header.clone())], 12)
            .expect("remote object and cursor apply atomically");

        let file = fs.store().lookup(1, "remote.txt").unwrap().unwrap();
        assert!(file.is_file());
        assert_eq!(file.ino, 2);
        assert_eq!(
            teagarden_store::sdo_cursor_store::SdoCursorStore::new(&fs.conn, &fs.schema)
                .get()
                .unwrap(),
            Some((12, 12))
        );
        assert_eq!(
            fs.sdo_identity_store()
                .get(file.ino)
                .unwrap()
                .unwrap()
                .latest_version_id,
            Some(uuid::Uuid::from_bytes([0x73; 16]))
        );
        assert_eq!(
            fs.apply_remote_sdo_batch(vec![(13, header), (14, b"corrupt".to_vec())], 14),
            Err(libc::EIO)
        );
        assert_eq!(
            teagarden_store::sdo_cursor_store::SdoCursorStore::new(&fs.conn, &fs.schema)
                .get()
                .unwrap(),
            Some((12, 12)),
            "a failed batch cannot move its durable cursor"
        );
    }

    #[test]
    #[cfg(feature = "key-rotation")]
    fn mounted_device_installs_handoff_keys_and_writes_without_new_credentials() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x81; 16]);
        let installation_id = uuid::Uuid::from_bytes([0x82; 16]);
        let fs = fs.with_sdo(volume_id, installation_id);
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "after-revoke.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        fs.persist_data(2, b"before rotation").unwrap();
        let predecessor = fs
            .sdo_identity_store()
            .get(2)
            .unwrap()
            .unwrap()
            .latest_version_id
            .unwrap();
        let fh = fs
            .handles
            .open_pinned_sdo(2, libc::O_RDWR, 1000, predecessor);
        fs.write_impl(2, fh, 1000, 15, b" plus new key").unwrap();

        let old_meta = fs.meta_key.clone();
        let new_meta = SymmetricKey::from_bytes([0xa3; 32]);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let mut fs = fs.with_sdo_poll_inbox(
            receiver,
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(tokio::sync::Notify::new()),
        );
        let (ack, acknowledged) = tokio::sync::oneshot::channel();
        sender
            .blocking_send(SdoPollBatch {
                high_water_id: 50,
                objects: Vec::new(),
                generation_update: Some(SdoGenerationUpdate {
                    active_generation: 1,
                    object_envelope: None,
                    boundary_message_id: Some(40),
                    generation_meta_keys: std::collections::BTreeMap::from([
                        (0, old_meta.clone()),
                        (1, new_meta.clone()),
                    ]),
                }),
                ack,
            })
            .unwrap();
        fs.apply_pending_sdo_poll().unwrap();
        acknowledged.blocking_recv().unwrap().unwrap();
        assert_eq!(fs.sdo_key_generation, 1);

        // Flush succeeds in the already-mounted process; it has not been given a
        // password or recovery sentence for the new generation.
        fs.flush_impl(2, fh).unwrap();
        let uploaded = transport.get_raw(2).unwrap();
        let object =
            teagarden_core::sdo::SdoFileObjectV3::decode(&uploaded, volume_id, 1, &new_meta)
                .unwrap();
        assert_eq!(object.content, b"before rotation plus new key");
        assert!(
            teagarden_core::sdo::SdoFileObjectV3::decode(&uploaded, volume_id, 1, &old_meta,)
                .is_err()
        );
    }

    #[test]
    fn sdo_partial_read_downloads_and_decrypts_only_the_touched_segment() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let fs = fs.with_sdo(volume_id, uuid::Uuid::from_bytes([0x62; 16]));
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "segments.bin".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        let content = (0..(2 * 1024 * 1024 + 29))
            .map(|n| (n % 251) as u8)
            .collect::<Vec<_>>();
        fs.persist_data(2, &content).unwrap();

        transport.reset_counters();
        let start = 1024 * 1024 + 17;
        let got = fs.read_sdo_range(2, start as u64, 83).unwrap();
        assert_eq!(got, content[start..start + 83]);
        assert_eq!(transport.bytes_served(), 1024 * 1024 + 16);
    }

    #[test]
    fn sdo_revert_reads_retained_single_object_versions() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let fs = fs.with_sdo(
            uuid::Uuid::from_bytes([0x61; 16]),
            uuid::Uuid::from_bytes([0x62; 16]),
        );
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "revert.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        fs.persist_data(2, b"first object").unwrap();
        fs.persist_data(2, b"second object").unwrap();

        fs.revert_impl(2, 1).unwrap();
        assert_eq!(
            fs.current_inode_content(&fs.store().get(2).unwrap().unwrap())
                .unwrap(),
            b"first object"
        );
        assert_eq!(
            transport.message_count(),
            3,
            "revert is a new object version"
        );
    }

    #[test]
    fn sdo_write_past_account_limit_fails_with_efbig_before_upload() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let fs = fs
            .with_sdo(
                uuid::Uuid::from_bytes([0x61; 16]),
                uuid::Uuid::from_bytes([0x62; 16]),
            )
            .with_sdo_file_limit(8);
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "limited.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        let fh = fs.handles.open(2, libc::O_WRONLY, 1000);
        assert_eq!(
            fs.write_impl(2, fh, 1000, 0, b"123456789"),
            Err(libc::EFBIG)
        );
        assert_eq!(transport.message_count(), 0);
        assert!(!fs.handles.has_buffer(2));
    }

    #[test]
    fn later_saves_keep_file_id_and_reference_first_manifest_message() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let fs = fs.with_sdo(volume_id, uuid::Uuid::from_bytes([0x62; 16]));
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "identity.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();

        fs.persist_data(2, b"first").unwrap();
        let first = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(1).unwrap(),
            volume_id,
            0,
            &fs.meta_key,
        )
        .unwrap();
        assert_eq!(first.metadata.origin_message_id, None);

        fs.persist_data(2, b"second").unwrap();
        let second = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(2).unwrap(),
            volume_id,
            0,
            &fs.meta_key,
        )
        .unwrap();
        assert_eq!(second.metadata.file_id, first.metadata.file_id);
        assert_eq!(second.metadata.origin_message_id, Some(1));
        assert_eq!(
            second.metadata.previous_version_id,
            Some(first.metadata.version_id)
        );
        assert!(
            (second.metadata.clock_ms, second.metadata.clock_counter)
                > (first.metadata.clock_ms, first.metadata.clock_counter),
            "successive local versions must advance the HLC"
        );
    }

    #[test]
    fn rename_keeps_file_identity_and_tombstones_link_to_the_new_path_version() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        let fs = fs.with_sdo(volume_id, uuid::Uuid::from_bytes([0x62; 16]));
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "before.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        fs.persist_data(2, b"rename identity").unwrap();
        let first = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(1).unwrap(),
            volume_id,
            0,
            &fs.meta_key,
        )
        .unwrap();

        let rename_result = fs.rename_impl(
            0,
            1,
            OsStr::new("before.txt"),
            1,
            OsStr::new("after.txt"),
            0,
        );
        assert_eq!(
            rename_result,
            Ok(()),
            "uploads={}",
            transport.message_count()
        );
        let moved = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(2).unwrap(),
            volume_id,
            0,
            &fs.meta_key,
        )
        .unwrap();
        let tombstone = teagarden_core::sdo::SdoFileObjectV3::decode(
            &transport.get_raw(3).unwrap(),
            volume_id,
            0,
            &fs.meta_key,
        )
        .unwrap();

        assert_eq!(moved.metadata.path.as_deref(), Some("after.txt"));
        assert_eq!(moved.metadata.file_id, first.metadata.file_id);
        assert_eq!(moved.metadata.origin_message_id, Some(1));
        assert_eq!(
            moved.metadata.previous_version_id,
            Some(first.metadata.version_id)
        );
        assert_eq!(tombstone.metadata.path.as_deref(), Some("before.txt"));
        assert!(tombstone.metadata.deleted);
        assert_eq!(tombstone.metadata.file_id, first.metadata.file_id);
        assert_eq!(tombstone.metadata.origin_message_id, Some(1));
        assert_eq!(
            tombstone.metadata.previous_version_id,
            Some(moved.metadata.version_id)
        );
    }

    #[test]
    fn rename_carries_dirty_writes_and_replays_under_the_new_path() {
        let (fs, transport, _rt) = audit_portable_fixture();
        fs.persist_data(2, b"original file").unwrap();
        let writer = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, writer, 1000, 0, b"pending").unwrap();

        fs.rename_impl(0, 1, OsStr::new("audit.bin"), 1, OsStr::new("moved.bin"), 0)
            .unwrap();
        let reader = fs.open_impl(2, libc::O_RDONLY, 1000).unwrap();
        assert_eq!(
            fs.read_impl(2, reader, 1000, 0, 64).unwrap(),
            b"pendingl file"
        );

        fs.write_impl(2, writer, 1000, 8, b"data").unwrap();
        fs.flush_impl(2, writer).unwrap();
        assert_eq!(transport.message_count(), 5);

        let (fresh, _, _fresh_rt) = setup_cryptfs_with_transport();
        let mut fresh = fresh
            .with_sdo(
                uuid::Uuid::from_bytes([0x61; 16]),
                uuid::Uuid::from_bytes([0x63; 16]),
            )
            .with_transport(transport.clone());
        fresh.store().insert(&Inode::root()).unwrap();
        let messages = (1..=5)
            .map(|id| (id, transport.get_raw(id).unwrap()))
            .collect();
        fresh.apply_remote_sdo_batch(messages, 5).unwrap();
        assert!(fresh.store().lookup(1, "audit.bin").unwrap().is_none());
        let moved = fresh.store().lookup(1, "moved.bin").unwrap().unwrap();
        let reader = fresh.open_impl(moved.ino, libc::O_RDONLY, 1000).unwrap();
        assert_eq!(
            fresh.read_impl(moved.ino, reader, 1000, 0, 64).unwrap(),
            b"pendingldatae"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn portable_noreplace_does_not_publish_a_failed_rename() {
        let (fs, transport, _rt) = audit_portable_fixture();
        fs.store()
            .insert(&Inode::new_file(3, 1, "occupied".into(), 0o600, 1000, 1000))
            .unwrap();
        let writer = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, writer, 1000, 0, b"pending write").unwrap();
        assert_eq!(
            fs.rename_impl(
                0,
                1,
                OsStr::new("audit.bin"),
                1,
                OsStr::new("occupied"),
                RENAME_NOREPLACE,
            ),
            Err(libc::EEXIST)
        );
        assert_eq!(transport.message_count(), 0);
        assert!(fs.handles.has_handle_buffer(writer));
    }

    #[test]
    fn portable_file_object_upload_failure_returns_eio_and_keeps_dirty_bytes() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let fs = fs.with_sdo(
            uuid::Uuid::from_bytes([0x61; 16]),
            uuid::Uuid::from_bytes([0x62; 16]),
        );
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "retry.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        let fh = fs.handles.open(2, libc::O_WRONLY, 1000);
        fs.handles.insert_buffer(2, b"retry me".to_vec());
        transport.set_fail_uploads_after(0); // the single TGFV object fails

        assert_eq!(fs.flush_impl(2, fh), Err(libc::EIO));
        assert_eq!(transport.message_count(), 0);
        assert!(fs.handles.has_buffer(2), "failed save retains dirty bytes");
    }

    #[test]
    fn portable_backfill_emits_only_missing_current_file_versions() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let fs = fs.with_sdo(
            uuid::Uuid::from_bytes([0x61; 16]),
            uuid::Uuid::from_bytes([0x62; 16]),
        );
        fs.store().insert(&Inode::root()).unwrap();
        fs.store()
            .insert(&Inode::new_file(
                2,
                1,
                "legacy.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();

        assert_eq!(fs.backfill_sdo_versions(), Ok(1));
        assert_eq!(fs.backfill_sdo_versions(), Ok(0));
        assert_eq!(transport.message_count(), 1);
    }

    /// Build a transport-backed CryptFs with the v0.4.3 metadata journal enabled.
    /// Returns the integrity key and HEAD path so tests can verify the floor.
    fn setup_cryptfs_with_journal() -> (
        CryptFs,
        Arc<teagarden_telegram::mock::MockTransport>,
        tokio::runtime::Runtime,
        tempfile::TempDir,
        SymmetricKey,
        std::path::PathBuf,
    ) {
        let conn = Connection::open_in_memory().unwrap();
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
        initialize_database(&conn, &schema).unwrap();

        let transport = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let head_path = dir.path().join("journal_head.json");
        let integrity_key = SymmetricKey::from_bytes([0x48; 32]);
        let initial = JournalHead {
            seq: 0,
            parent_msg_id: 0,
            base_snapshot_version: 0,
            base_snapshot_msg_id: 0,
            base_snapshot_hash: [0; 32],
            last_hash: None,
            lineage: None,
        };

        let fs = CryptFs::new(
            conn,
            schema,
            SymmetricKey::from_bytes([0x43; 32]),
            SymmetricKey::from_bytes([0x44; 32]),
            1000,
            1000,
        )
        .with_transport(transport.clone())
        .with_runtime(rt.handle().clone())
        .with_journal(integrity_key.clone(), head_path.clone(), initial);

        (fs, transport, rt, dir, integrity_key, head_path)
    }

    #[test]
    fn journaled_txn_publishes_delta_advances_head_and_replays() {
        let (fs, transport, _rt, _dir, integrity_key, head_path) = setup_cryptfs_with_journal();
        let data_key = SymmetricKey::from_bytes([0x44; 32]);
        let meta_key = SymmetricKey::from_bytes([0x43; 32]);

        // Seed the root inode OUTSIDE the journal (the session attaches per
        // journaled_txn, so only the journaled mutation below is captured).
        fs.store().insert(&Inode::root()).unwrap();

        let new_ino = fs.store().next_ino().unwrap();
        let file = Inode::new_file(new_ino, 1, "j.txt".into(), 0o644, 1000, 1000);
        let res = fs.journaled_txn(|| {
            fs.store().insert(&file).map_err(|_| libc::EIO)?;
            Ok(())
        });
        assert!(res.is_ok(), "journaled insert must succeed");

        // 1) Exactly one delta was published to the channel.
        assert_eq!(transport.message_count(), 1, "one delta per journaled op");

        // 2) The HMAC'd HEAD floor advanced to seq 1 and authenticates.
        let head = JournalHead::load(&head_path, &integrity_key)
            .unwrap()
            .unwrap();
        assert_eq!(head.seq, 1);
        assert_ne!(head.parent_msg_id, 0, "HEAD records the delta message id");

        // 3) Fetch + decrypt the delta and replay its changeset into a fresh DB.
        let blob = transport
            .get_raw(head.parent_msg_id)
            .expect("delta message present in the channel");
        let (hdr, changeset) =
            teagarden_core::volume::metadata_journal::decrypt_delta(&data_key, &blob).unwrap();
        assert_eq!(hdr.seq, 1);
        assert!(!changeset.is_empty(), "changeset captured the inode insert");

        let conn2 = Connection::open_in_memory().unwrap();
        let schema2 = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
        initialize_database(&conn2, &schema2).unwrap();
        conn2
            .apply_strm(
                &mut &changeset[..],
                None::<fn(&str) -> bool>,
                |_ct, _item| rusqlite::session::ConflictAction::SQLITE_CHANGESET_ABORT,
            )
            .unwrap();

        let store2 = InodeStore::new(&conn2, &schema2, &meta_key);
        let recovered = store2.get(new_ino).unwrap();
        assert!(
            recovered.is_some(),
            "replaying the delta reconstructs the journaled inode"
        );
        assert_eq!(recovered.unwrap().name, "j.txt");
    }

    /// Round 12: each journaled transaction records the journal position it
    /// produces in the DB's session record, in the same transaction (keeping
    /// the session's nonce), and the record never enters a delta.
    #[test]
    fn journaled_txn_records_the_journal_position_it_produces() {
        let (fs, transport, _rt, _dir, integrity_key, head_path) = setup_cryptfs_with_journal();
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
        teagarden_store::local_db::begin_session(&fs.conn, &schema, [7; 16], 0).unwrap();
        fs.store().insert(&Inode::root()).unwrap();
        for i in 0..3u64 {
            let ino = fs.store().next_ino().unwrap();
            let f = Inode::new_file(ino, 1, format!("f{i}"), 0o644, 1000, 1000);
            fs.journaled_txn(|| fs.store().insert(&f).map_err(|_| libc::EIO))
                .unwrap();
            let head = JournalHead::load(&head_path, &integrity_key)
                .unwrap()
                .unwrap();
            let rec = teagarden_store::local_db::read_session(&fs.conn, &schema)
                .unwrap()
                .expect("a session record");
            assert_eq!(rec.seq, head.seq, "after write {i}");
            assert_eq!(rec.nonce, Some([7; 16]), "after write {i}");
        }
        // A failed publish rolls the record back with the write.
        transport.set_metadata_budget(Some(0));
        let ino = fs.store().next_ino().unwrap();
        let f = Inode::new_file(ino, 1, "lost".into(), 0o644, 1000, 1000);
        assert!(fs
            .journaled_txn(|| fs.store().insert(&f).map_err(|_| libc::EIO))
            .is_err());
        let rec = teagarden_store::local_db::read_session(&fs.conn, &schema)
            .unwrap()
            .unwrap();
        assert_eq!(rec.seq, 3);
    }

    #[test]
    fn journaled_txn_rolls_back_when_publish_fails() {
        // If the channel publish fails, the whole write must roll back (EIO) and
        // leave NO local row — committed metadata is never orphaned.
        let (fs, transport, _rt, _dir, integrity_key, head_path) = setup_cryptfs_with_journal();
        fs.store().insert(&Inode::root()).unwrap();
        // Make the channel publish fail (sync_metadata checks `connected`).
        transport.set_connected(false);

        let new_ino = fs.store().next_ino().unwrap();
        let file = Inode::new_file(new_ino, 1, "lost.txt".into(), 0o644, 1000, 1000);
        let res = fs.journaled_txn(|| {
            fs.store().insert(&file).map_err(|_| libc::EIO)?;
            Ok(())
        });
        assert_eq!(res, Err(libc::EIO), "publish failure surfaces as EIO");

        // The local insert was rolled back...
        assert!(
            fs.store().get(new_ino).unwrap().is_none(),
            "rolled-back write leaves no local row"
        );
        // ...and the HEAD floor never advanced.
        assert!(JournalHead::load(&head_path, &integrity_key)
            .unwrap()
            .is_none());
    }

    #[test]
    fn journal_write_then_recover_round_trip() {
        // The user's orphan-fix, end to end with REAL journaled_txn deltas: mutate
        // through the journal, WIPE the local DB (crash sim), and rebuild it purely
        // from the channel (base snapshot + delta chain).
        use teagarden_core::volume::metadata_snapshot::encrypt_snapshot;
        use teagarden_store::journal_recovery::recover_from_head;

        let schema_key = SymmetricKey::from_bytes([0x42; 32]);
        let meta_key = SymmetricKey::from_bytes([0x43; 32]);
        let data_key = SymmetricKey::from_bytes([0x44; 32]);
        let integrity = SymmetricKey::from_bytes([0x48; 32]);
        let mk_schema = || OpaqueSchema::new(schema_key.clone(), &logical_tables());

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let head_path = dir.path().join("journal.head");

        // Seed a file-backed DB with the root inode, then close it to flush.
        {
            let conn = Connection::open(&db_path).unwrap();
            initialize_database(&conn, &mk_schema()).unwrap();
            InodeStore::new(&conn, &mk_schema(), &meta_key)
                .insert(&Inode::root())
                .unwrap();
        }

        let transport = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Publish the base snapshot (DB-with-root) to the channel + write HEAD.
        let base_blob = encrypt_snapshot(&data_key, 1, &std::fs::read(&db_path).unwrap()).unwrap();
        let base_msg_id = rt.block_on(transport.sync_metadata(&base_blob)).unwrap();
        let initial = JournalHead {
            seq: 0,
            parent_msg_id: base_msg_id,
            base_snapshot_version: 1,
            base_snapshot_msg_id: base_msg_id,
            base_snapshot_hash: *blake3::hash(&base_blob).as_bytes(),
            last_hash: None,
            lineage: None,
        };
        initial.store_atomic(&head_path, &integrity).unwrap();

        // Mount the journal over the same file DB and journal two file creations.
        {
            let conn = Connection::open(&db_path).unwrap();
            let fs = CryptFs::new(
                conn,
                mk_schema(),
                meta_key.clone(),
                data_key.clone(),
                1000,
                1000,
            )
            .with_transport(transport.clone())
            .with_runtime(rt.handle().clone())
            .with_journal(integrity.clone(), head_path.clone(), initial);
            for (ino, name) in [(2u64, "x.txt"), (3u64, "y.txt")] {
                let file = Inode::new_file(ino, 1, name.into(), 0o644, 1000, 1000);
                fs.journaled_txn(|| fs.store().insert(&file).map_err(|_| libc::EIO))
                    .unwrap();
            }
        }

        let final_head = JournalHead::load(&head_path, &integrity).unwrap().unwrap();
        assert_eq!(final_head.seq, 2, "two journaled ops");

        // CRASH SIM: the local metadata DB is gone.
        std::fs::remove_file(&db_path).unwrap();

        // Rebuild from the channel alone.
        let t2 = transport.clone();
        let recovered = recover_from_head(&data_key, final_head, &db_path, |id| {
            t2.get_raw(id)
                .ok_or_else(|| teagarden_core::error::CoreError::Snapshot(format!("msg {id} gone")))
        })
        .unwrap();
        assert_eq!(recovered, 2);

        // The reconstructed DB has root + both journaled files.
        let conn = Connection::open(&db_path).unwrap();
        let schema = mk_schema();
        let store = InodeStore::new(&conn, &schema, &meta_key);
        assert!(store.get(1).unwrap().is_some(), "root recovered");
        assert!(store.get(2).unwrap().is_some(), "x.txt recovered");
        assert!(store.get(3).unwrap().is_some(), "y.txt recovered");
    }

    #[test]
    fn journal_recovers_file_content_and_attrs_after_crash() {
        // The real-workload oracle (advisor): write file BYTES through the release
        // path (block-table rows + manifest) and chmod through the setattr path,
        // then WIPE the DB and rebuild from the channel. Asserts the block records
        // are recovered (the escape this test exists to catch), the content reads
        // back byte-for-byte, and the chmod survived — under require_block_integrity.
        use teagarden_core::volume::metadata_snapshot::encrypt_snapshot;
        use teagarden_store::block_store::BlockStore;
        use teagarden_store::journal_recovery::recover_from_head;

        let schema_key = SymmetricKey::from_bytes([0x42; 32]);
        let meta_key = SymmetricKey::from_bytes([0x43; 32]);
        let data_key = SymmetricKey::from_bytes([0x44; 32]);
        let bidk = SymmetricKey::from_bytes([0x45; 32]);
        let fnk = SymmetricKey::from_bytes([0x46; 32]);
        let mfk = SymmetricKey::from_bytes([0x47; 32]);
        let integrity = SymmetricKey::from_bytes([0x48; 32]);
        let mk_schema = || OpaqueSchema::new(schema_key.clone(), &logical_tables());

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let head_path = dir.path().join("journal.head");

        // Seed a file DB with root and checkpoint it to the main file.
        {
            let conn = Connection::open(&db_path).unwrap();
            initialize_database(&conn, &mk_schema()).unwrap();
            InodeStore::new(&conn, &mk_schema(), &meta_key)
                .insert(&Inode::root())
                .unwrap();
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }

        let transport = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Base snapshot (DB-with-root) + HEAD.
        let base_blob = encrypt_snapshot(&data_key, 1, &std::fs::read(&db_path).unwrap()).unwrap();
        let base_msg_id = rt.block_on(transport.sync_metadata(&base_blob)).unwrap();
        let initial = JournalHead {
            seq: 0,
            parent_msg_id: base_msg_id,
            base_snapshot_version: 1,
            base_snapshot_msg_id: base_msg_id,
            base_snapshot_hash: *blake3::hash(&base_blob).as_bytes(),
            last_hash: None,
            lineage: None,
        };
        initial.store_atomic(&head_path, &integrity).unwrap();

        let file_data = vec![0xABu8; 9000];
        let ino = 2u64;

        {
            let conn = Connection::open(&db_path).unwrap();
            let fs = CryptFs::new(
                conn,
                mk_schema(),
                meta_key.clone(),
                data_key.clone(),
                1000,
                1000,
            )
            .with_block_keys(bidk.clone(), fnk.clone())
            .with_manifest_key(mfk.clone())
            .with_block_integrity(true)
            .with_transport(transport.clone())
            .with_runtime(rt.handle().clone())
            .with_journal(integrity.clone(), head_path.clone(), initial);

            // Create the file inode (journaled).
            let file = Inode::new_file(ino, 1, "doc.bin".into(), 0o644, 1000, 1000);
            fs.journaled_txn(|| fs.store().insert(&file).map_err(|_| libc::EIO))
                .unwrap();

            // Write content through the real release path: upload + journaled persist.
            let outcomes = fs.flush_chunks_to_transport(ino, &file_data).unwrap();
            fs.persist_file_blocks(ino, &file_data, outcomes).unwrap();

            // chmod 0600 (journaled, mirroring setattr).
            let mut i = fs.store().get(ino).unwrap().unwrap();
            i.mode = 0o600;
            fs.journaled_txn(|| fs.store().update(&i).map_err(|_| libc::EIO))
                .unwrap();
        }

        let final_head = JournalHead::load(&head_path, &integrity).unwrap().unwrap();
        assert!(final_head.seq >= 3, "inode + blocks + chmod journaled");

        // CRASH SIM: the local DB and its WAL sidecars are gone.
        std::fs::remove_file(&db_path).unwrap();
        for sfx in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sfx}", db_path.display()));
        }

        // Rebuild from the channel alone.
        let t2 = transport.clone();
        recover_from_head(&data_key, final_head, &db_path, |id| {
            t2.get_raw(id)
                .ok_or_else(|| teagarden_core::error::CoreError::Snapshot(format!("msg {id} gone")))
        })
        .unwrap();

        // Inspect the recovered DB.
        let conn = Connection::open(&db_path).unwrap();
        let schema = mk_schema();
        let recovered = InodeStore::new(&conn, &schema, &meta_key)
            .get(ino)
            .unwrap()
            .expect("file inode recovered");
        assert_eq!(recovered.mode, 0o600, "chmod survived recovery");
        let manifest = recovered.manifest.as_ref().expect("manifest recovered");

        // The block records (block_id→message_id, SRB2 hashes) must be present —
        // this is the escape the oracle catches; without journaling them, recovery
        // yields a manifest pointing at rows that do not exist.
        let bstore = BlockStore::new(&conn, &schema);
        for bp in &manifest.blocks {
            assert!(
                bstore.find_by_block_id(&bp.block_id).unwrap().is_some(),
                "block record recovered (was the autocommit escape)"
            );
        }

        // The content must read back byte-for-byte from the channel.
        let conn2 = Connection::open(&db_path).unwrap();
        let fs2 = CryptFs::new(
            conn2,
            mk_schema(),
            meta_key.clone(),
            data_key.clone(),
            1000,
            1000,
        )
        .with_block_keys(bidk, fnk)
        .with_manifest_key(mfk)
        .with_block_integrity(true)
        .with_transport(transport.clone())
        .with_runtime(rt.handle().clone());
        let mut content = Vec::new();
        for bp in &manifest.blocks {
            let chunk = fs2
                .download_block(bp.message_id, &bp.block_id, bp.epoch)
                .expect("download recovered block");
            content.extend_from_slice(&chunk);
        }
        assert_eq!(
            content, file_data,
            "file content fully recovered from the journal"
        );
    }

    #[test]
    fn journal_recovers_mixed_workload_equality_to_live() {
        // The advisor's total oracle: drive a MIXED workload through the real
        // write_impl/release_impl/setattr_impl (+ journaled create), snapshot the
        // live logical state, WIPE the DB, recover, and assert the recovered state
        // EQUALS the pre-crash state — plus content reads back. This exercises the
        // callback INTERACTIONS the per-method tests miss (write→release→chmod→
        // rewrite before-image chain; intra-batch dedup), which is where the last
        // two criticals lived.
        use teagarden_core::volume::metadata_snapshot::encrypt_snapshot;
        use teagarden_store::block_store::BlockStore;
        use teagarden_store::journal_recovery::recover_from_head;

        let sk = SymmetricKey::from_bytes([0x42; 32]);
        let meta = SymmetricKey::from_bytes([0x43; 32]);
        let data = SymmetricKey::from_bytes([0x44; 32]);
        let bidk = SymmetricKey::from_bytes([0x45; 32]);
        let fnk = SymmetricKey::from_bytes([0x46; 32]);
        let mfk = SymmetricKey::from_bytes([0x47; 32]);
        let integ = SymmetricKey::from_bytes([0x48; 32]);
        let mk_schema = || OpaqueSchema::new(sk.clone(), &logical_tables());

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        let hp = dir.path().join("journal.head");

        {
            let c = Connection::open(&db).unwrap();
            initialize_database(&c, &mk_schema()).unwrap();
            InodeStore::new(&c, &mk_schema(), &meta)
                .insert(&Inode::root())
                .unwrap();
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        }

        let tx = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let base = encrypt_snapshot(&data, 1, &std::fs::read(&db).unwrap()).unwrap();
        let base_msg = rt.block_on(tx.sync_metadata(&base)).unwrap();
        let initial = JournalHead {
            seq: 0,
            parent_msg_id: base_msg,
            base_snapshot_version: 1,
            base_snapshot_msg_id: base_msg,
            base_snapshot_hash: *blake3::hash(&base).as_bytes(),
            last_hash: None,
            lineage: None,
        };
        initial.store_atomic(&hp, &integ).unwrap();

        let a1 = b"first version of file A".to_vec();
        let a2 = vec![0x41u8; 600]; // rewrite, different size
        let bdup = vec![0x55u8; 2 * UPLOAD_CHUNK_SIZE]; // two identical 512K chunks

        // Snapshot the FULL logical state of every inode 1..=6: parent, name, mode,
        // size, nlink, sorted children, current manifest block ids, AND the persisted
        // manifest version history (version, total_size, block ids) — so any
        // before-image drift from create/write/chmod/rename/unlink/truncate, or a
        // dropped/altered history version, shows up in the comparison.
        #[allow(clippy::type_complexity)]
        type ManHist = Vec<(u64, u64, Vec<[u8; 32]>)>;
        #[allow(clippy::type_complexity)]
        let dump = |db: &std::path::Path| -> Vec<(
            u64,
            u64,
            String,
            u32,
            u64,
            u32,
            Vec<u64>,
            Vec<[u8; 32]>,
            ManHist,
        )> {
            let c = Connection::open(db).unwrap();
            let sch = OpaqueSchema::new(sk.clone(), &logical_tables());
            let st = InodeStore::new(&c, &sch, &meta);
            let ms = ManifestStore::new(&c, &sch, &meta);
            let mut v = Vec::new();
            for ino in 1u64..=6 {
                if let Some(i) = st.get(ino).unwrap() {
                    let mut children = i.children.clone();
                    children.sort_unstable();
                    let blocks = i
                        .manifest
                        .as_ref()
                        .map(|m| m.blocks.iter().map(|b| b.block_id).collect())
                        .unwrap_or_default();
                    let history: ManHist = ms
                        .list_versions(ino)
                        .unwrap()
                        .into_iter()
                        .map(|ver| {
                            let m = ms.get(ino, ver).unwrap().unwrap();
                            (
                                ver,
                                m.total_size,
                                m.blocks.iter().map(|b| b.block_id).collect(),
                            )
                        })
                        .collect();
                    v.push((
                        ino, i.parent, i.name, i.mode, i.size, i.nlink, children, blocks, history,
                    ));
                }
            }
            v
        };

        {
            let c = Connection::open(&db).unwrap();
            let fs = CryptFs::new(c, mk_schema(), meta.clone(), data.clone(), 1000, 1000)
                .with_block_keys(bidk.clone(), fnk.clone())
                .with_manifest_key(mfk.clone())
                .with_block_integrity(true)
                .with_transport(tx.clone())
                .with_runtime(rt.handle().clone())
                .with_journal(integ.clone(), hp.clone(), initial);

            // create A, write v1, release, chmod, rewrite v2, release.
            fs.journaled_txn(|| {
                fs.store()
                    .insert(&Inode::new_file(2, 1, "A".into(), 0o644, 1000, 1000))
                    .map_err(|_| libc::EIO)
            })
            .unwrap();
            let fh = fs.handles.open(2, libc::O_RDWR, 1000);
            fs.write_impl(2, fh, 1000, 0, &a1).unwrap();
            fs.release_impl(2, fh).unwrap();
            fs.handles.close(fh);
            fs.setattr_impl(2, 1000, Some(0o600), None, None, None, None, None)
                .unwrap();
            let fh = fs.handles.open(2, libc::O_RDWR, 1000);
            fs.write_impl(2, fh, 1000, 0, &a2).unwrap();
            fs.release_impl(2, fh).unwrap();
            fs.handles.close(fh);
            // Truncate-shrink A on the CLOSED file to 50 — MATERIALIZES the manifest
            // to 50 bytes (v0.4.7) — then GROW it back to 80. The [50,80) region must
            // recover as ZEROS (it was truncated away), NOT the resurrected a2[50..80]
            // — the shrink-then-grow gate, validated through full crash recovery.
            fs.setattr_impl(2, 1000, None, None, None, Some(50), None, None)
                .unwrap();
            fs.setattr_impl(2, 1000, None, None, None, Some(80), None, None)
                .unwrap();

            // create B (duplicate-chunk file), write, release.
            fs.journaled_txn(|| {
                fs.store()
                    .insert(&Inode::new_file(3, 1, "B".into(), 0o644, 1000, 1000))
                    .map_err(|_| libc::EIO)
            })
            .unwrap();
            let fh = fs.handles.open(3, libc::O_RDWR, 1000);
            fs.write_impl(3, fh, 1000, 0, &bdup).unwrap();
            fs.release_impl(3, fh).unwrap();
            fs.handles.close(fh);

            // Multi-inode deltas (mirror create/write/unlink): create C, give it
            // manifest HISTORY (two versions), then DELETE it — including
            // delete_versions — in one journaled_txn. This exercises the multi-inode
            // changeset before-image chain AND verifies the manifest-history DELETE
            // replays correctly onto the rebuilt base (no recycled-inode bleed).
            fs.journaled_txn(|| {
                let st = fs.store();
                st.insert(&Inode::new_file(4, 1, "C".into(), 0o644, 1000, 1000))
                    .map_err(|_| libc::EIO)?;
                let mut root = st.get(1).map_err(|_| libc::EIO)?.ok_or(libc::EIO)?;
                root.children.push(4);
                st.update(&root).map_err(|_| libc::EIO)
            })
            .unwrap();
            let fh = fs.handles.open(4, libc::O_RDWR, 1000);
            fs.write_impl(4, fh, 1000, 0, b"C-version-one").unwrap();
            fs.release_impl(4, fh).unwrap();
            fs.handles.close(fh);
            let fh = fs.handles.open(4, libc::O_RDWR, 1000);
            fs.write_impl(4, fh, 1000, 0, b"C-version-two-longer")
                .unwrap();
            fs.release_impl(4, fh).unwrap();
            fs.handles.close(fh);
            assert_eq!(fs.manifest_store().max_version(4).unwrap(), 2);
            fs.journaled_txn(|| {
                let st = fs.store();
                let mut root = st.get(1).map_err(|_| libc::EIO)?.ok_or(libc::EIO)?;
                root.children.retain(|&c| c != 4);
                st.update(&root).map_err(|_| libc::EIO)?;
                st.delete(4).map_err(|_| libc::EIO)?;
                // Mirror unlink: destroy the inode's manifest history in the SAME txn.
                fs.manifest_store()
                    .delete_versions(4)
                    .map_err(|_| libc::EIO)
            })
            .unwrap();

            // create E (ino 5), write two versions, then REVERT to v1 — the reverted
            // current version (v1's content, reusing v1's blocks) must survive crash
            // recovery (the revert-recovery gate; revert is a journaled mutation).
            fs.journaled_txn(|| {
                fs.store()
                    .insert(&Inode::new_file(5, 1, "E".into(), 0o644, 1000, 1000))
                    .map_err(|_| libc::EIO)
            })
            .unwrap();
            let fh = fs.handles.open(5, libc::O_RDWR, 1000);
            fs.write_impl(5, fh, 1000, 0, b"E-version-one").unwrap();
            fs.release_impl(5, fh).unwrap();
            fs.handles.close(fh);
            let fh = fs.handles.open(5, libc::O_RDWR, 1000);
            fs.write_impl(5, fh, 1000, 0, b"E-version-two-longer")
                .unwrap();
            fs.release_impl(5, fh).unwrap();
            fs.handles.close(fh);
            fs.revert_impl(5, 1).unwrap(); // revert to v1 ("E-version-one")
            assert_eq!(read_stored(&fs, 5), b"E-version-one");
        }

        let live = dump(&db);
        let final_head = JournalHead::load(&hp, &integ).unwrap().unwrap();

        std::fs::remove_file(&db).unwrap();
        for sfx in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sfx}", db.display()));
        }

        let t2 = tx.clone();
        recover_from_head(&data, final_head, &db, |id| {
            t2.get_raw(id)
                .ok_or_else(|| teagarden_core::error::CoreError::Snapshot(format!("msg {id} gone")))
        })
        .unwrap();

        let recovered = dump(&db);
        assert_eq!(
            recovered, live,
            "recovered logical state must equal the pre-crash live state"
        );

        // Every referenced block row exists, and content reads back byte-for-byte.
        let c = Connection::open(&db).unwrap();
        let sch = mk_schema();
        let bstore = BlockStore::new(&c, &sch);

        // Inode 4 ("C") was written (2 versions) then deleted WITH delete_versions in
        // one journaled_txn. The dump can't see it (the inode is gone), so assert
        // explicitly that its manifest history did NOT bleed through recovery — the
        // history DELETE must have replayed onto the rebuilt base. (Remove the
        // delete_versions call above and this goes RED: orphaned versions survive.)
        assert!(
            ManifestStore::new(&c, &sch, &meta)
                .list_versions(4)
                .unwrap()
                .is_empty(),
            "a deleted inode's manifest history must not survive recovery"
        );
        let fs2 = CryptFs::new(
            Connection::open(&db).unwrap(),
            mk_schema(),
            meta.clone(),
            data.clone(),
            1000,
            1000,
        )
        .with_block_keys(bidk, fnk)
        .with_manifest_key(mfk)
        .with_block_integrity(true)
        .with_transport(tx.clone())
        .with_runtime(rt.handle().clone());
        let istore = InodeStore::new(&c, &sch, &meta);
        // A (ino 2) was shrunk to 50 (materialized) then grown to 80 — its LIVE
        // content is a2[..50] followed by 30 ZEROS (the truncated-away [50,80) must
        // NOT resurrect); B (ino 3) is unchanged. Reassemble the recovered manifest
        // then clamp to inode.size (mirroring read/write_impl).
        let a_expect = {
            let mut v = a2[..50].to_vec();
            v.resize(80, 0);
            v
        };
        // E (ino 5) was reverted to v1 — its recovered content is v1's bytes.
        for (ino, expect) in [
            (2u64, a_expect),
            (3u64, bdup.clone()),
            (5u64, b"E-version-one".to_vec()),
        ] {
            let inode = istore.get(ino).unwrap().unwrap();
            let manifest = inode.manifest.as_ref().unwrap();
            let mut content = Vec::new();
            for bp in &manifest.blocks {
                assert!(
                    bstore.find_by_block_id(&bp.block_id).unwrap().is_some(),
                    "block row recovered for ino {ino}"
                );
                content.extend_from_slice(
                    &fs2.download_block(bp.message_id, &bp.block_id, bp.epoch)
                        .expect("download recovered block"),
                );
            }
            content.resize(inode.size as usize, 0);
            assert_eq!(
                content, expect,
                "clamped content of ino {ino} recovered (no truncated-tail resurrection)"
            );
        }
    }

    // ---- v0.4.4 write-path correctness matrix (RED until the fix lands) ----
    //
    // These drive the real open_impl/write_impl/setattr_impl/release_impl and read
    // the stored content back, exercising the write model's data-integrity edge
    // cases the third journal audit surfaced. They are expected to FAIL against the
    // current write model and pass once read-modify-write seeding + truncate /
    // O_TRUNC reconciliation land.

    /// Reassemble a file's stored content from its manifest (downloads every block).
    fn read_stored(fs: &CryptFs, ino: u64) -> Vec<u8> {
        let inode = fs.store().get(ino).unwrap().expect("inode exists");
        let mut out = Vec::new();
        if let Some(m) = inode.manifest.as_ref() {
            for bp in &m.blocks {
                out.extend_from_slice(
                    &fs.download_block(bp.message_id, &bp.block_id, bp.epoch)
                        .expect("download block"),
                );
            }
        }
        // `inode.size` is the authoritative file length (the manifest may describe
        // more bytes after a shrink, or fewer after a grow). Mirror the production
        // `read`/`write_impl` clamp so the helper reflects the LIVE content.
        out.resize(inode.size as usize, 0);
        out
    }

    /// open → write at offset → release → close, via the real impls.
    fn write_via_impl(fs: &CryptFs, ino: u64, flags: i32, offset: i64, data: &[u8]) {
        let fh = fs.open_impl(ino, flags, 1000).unwrap();
        fs.write_impl(ino, fh, 1000, offset, data).unwrap();
        fs.release_impl(ino, fh).unwrap();
        fs.handles.close(fh);
    }

    fn seed_file(fs: &CryptFs, ino: u64, name: &str) {
        fs.store().insert(&Inode::root()).ok();
        fs.store()
            .insert(&Inode::new_file(ino, 1, name.into(), 0o644, 1000, 1000))
            .unwrap();
    }

    #[test]
    fn write_path_partial_overwrite_preserves_tail() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"AAAABBBB");
        assert_eq!(read_stored(&fs, 2), b"AAAABBBB");

        // Partial overwrite at offset 0 (no O_TRUNC) must be read-modify-write: the
        // untouched tail "BBBB" must survive.
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"XX");
        assert_eq!(
            read_stored(&fs, 2),
            b"XXAABBBB",
            "partial overwrite must preserve the untouched tail"
        );
    }

    #[test]
    fn write_path_truncate_via_setattr_is_authoritative() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        // write 500 bytes then ftruncate-shrink to 100 on the SAME open handle.
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 0, &vec![0x41u8; 500]).unwrap();
        fs.setattr_impl(2, 1000, None, None, None, Some(100), None, None)
            .unwrap();
        fs.release_impl(2, fh).unwrap();
        fs.handles.close(fh);
        assert_eq!(
            read_stored(&fs, 2).len(),
            100,
            "truncate must be authoritative over the dirty write buffer"
        );
        assert_eq!(fs.store().get(2).unwrap().unwrap().size, 100);
    }

    #[test]
    fn write_path_o_trunc_empties_file() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"existing content here");
        assert_eq!(read_stored(&fs, 2), b"existing content here");

        // Open with O_TRUNC and close without writing → file is emptied.
        let fh = fs
            .open_impl(2, libc::O_WRONLY | libc::O_TRUNC, 1000)
            .unwrap();
        fs.release_impl(2, fh).unwrap();
        fs.handles.close(fh);
        assert_eq!(
            read_stored(&fs, 2).len(),
            0,
            "O_TRUNC at open must truncate the file to zero"
        );
        assert_eq!(fs.store().get(2).unwrap().unwrap().size, 0);
    }

    #[test]
    fn write_path_closed_file_truncate_to_nonzero_is_authoritative() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"0123456789"); // 10 bytes, released

        // Truncate the CLOSED file to 4 (no open handle). `inode.size` is the
        // authority: the read/seed clamp makes the file 4 bytes even though the
        // manifest still describes 10 (lazy — no re-upload, single journaled txn).
        fs.setattr_impl(2, 1000, None, None, None, Some(4), None, None)
            .unwrap();
        assert_eq!(
            read_stored(&fs, 2),
            b"0123",
            "closed-file shrink is authoritative over the manifest length"
        );
        assert_eq!(fs.store().get(2).unwrap().unwrap().size, 4);

        // A later partial write must NOT resurrect the dropped tail "456789":
        // the seed clamps the stale 10-byte manifest to inode.size (4) first.
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"Z");
        assert_eq!(
            read_stored(&fs, 2),
            b"Z123",
            "a write after shrink must not resurrect truncated bytes"
        );
        assert_eq!(fs.store().get(2).unwrap().unwrap().size, 4);
    }

    #[test]
    fn write_path_dirty_handle_truncate_to_zero_no_resurrection() {
        // Finding #1/#3: ftruncate(0) on an OPEN dirty handle. The buffer is resized
        // to empty so release is a no-op; the journaled inode must carry size=0 AND
        // manifest=None so a later write can never re-seed the old (500-byte) blocks.
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 0, &vec![0x41u8; 500]).unwrap();
        fs.setattr_impl(2, 1000, None, None, None, Some(0), None, None)
            .unwrap();
        fs.release_impl(2, fh).unwrap();
        fs.handles.close(fh);

        let inode = fs.store().get(2).unwrap().unwrap();
        assert_eq!(inode.size, 0, "truncate-to-zero is authoritative");
        assert!(inode.manifest.is_none(), "stale manifest must be cleared");
        assert_eq!(read_stored(&fs, 2).len(), 0);

        // Reopen + write 10 bytes — must be exactly 10, no resurrection of the 500.
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"BBBBBBBBBB");
        assert_eq!(
            read_stored(&fs, 2),
            b"BBBBBBBBBB",
            "no truncated-away bytes may resurrect on the next write"
        );
    }

    #[test]
    fn write_path_grow_truncate_zero_fills_and_survives_rewrite() {
        // Findings #5/#8: ftruncate-GROW on a closed file. inode.size is the
        // authority; the manifest stays short. Reads of the hole return zeros, and a
        // later partial write must NOT shrink the file back to the manifest length.
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"0123456789"); // 10 bytes

        fs.setattr_impl(2, 1000, None, None, None, Some(100), None, None)
            .unwrap();
        let grown = read_stored(&fs, 2);
        assert_eq!(grown.len(), 100, "grow-truncate extends the file");
        assert_eq!(&grown[..10], b"0123456789");
        assert!(
            grown[10..].iter().all(|&b| b == 0),
            "the extended region must read as zeros (POSIX hole)"
        );
        assert_eq!(fs.store().get(2).unwrap().unwrap().size, 100);

        // A 1-byte overwrite at offset 0 must preserve the 100-byte length: the seed
        // zero-fills the short manifest up to inode.size before applying the write.
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"Z");
        let after = read_stored(&fs, 2);
        assert_eq!(
            after.len(),
            100,
            "a write after grow-truncate must not drop the extended tail"
        );
        assert_eq!(after[0], b'Z');
        assert_eq!(&after[1..10], b"123456789");
        assert!(after[10..].iter().all(|&b| b == 0));
    }

    #[test]
    fn write_path_shrink_then_grow_does_not_resurrect_truncated_bytes() {
        // v0.4.7 gate: a closed-file shrink then grow back INTO the old range must
        // read the grown region as ZEROS (it was truncated away), NOT resurrect the
        // stale manifest bytes. The v0.4.4 lazy-truncate left the manifest at full
        // length, so a grow clamped the read to the larger size and returned the old
        // bytes — the data-integrity bug the real-mount harness found. The fix
        // materializes (re-cuts) the manifest to the shrunk size on shrink.
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"0123456789"); // 10 bytes

        // Shrink to 4 (closed file).
        fs.setattr_impl(2, 1000, None, None, None, Some(4), None, None)
            .unwrap();
        assert_eq!(read_stored(&fs, 2), b"0123");

        // Grow to 8 — bytes [4,8) must be zeros (truncated away), not "4567".
        fs.setattr_impl(2, 1000, None, None, None, Some(8), None, None)
            .unwrap();
        let grown = read_stored(&fs, 2);
        assert_eq!(grown.len(), 8);
        assert_eq!(&grown[..4], b"0123");
        assert!(
            grown[4..].iter().all(|&b| b == 0),
            "grown region must read as zeros, not resurrected truncated bytes"
        );

        // Same through the real read path.
        let fh = fs.open_impl(2, libc::O_RDONLY, 1000).unwrap();
        assert_eq!(fs.read_impl(2, fh, 1000, 0, 8).unwrap(), b"0123\0\0\0\0");
        fs.handles.close(fh);
    }

    /// Forge a torn state (`manifest.total_size > inode.size`) as a dirty-shrink+crash
    /// or a pre-v0.4.7 lazy-shrink leaves it: write `content` then set `inode.size`
    /// to `torn` directly, bypassing the materialize path.
    fn forge_torn_state(fs: &CryptFs, ino: u64, content: &[u8], torn: u64) {
        write_via_impl(fs, ino, libc::O_RDWR, 0, content);
        let mut inode = fs.store().get(ino).unwrap().unwrap();
        inode.size = torn;
        fs.store().update(&inode).unwrap();
        assert!(
            inode.manifest.unwrap().total_size > torn,
            "torn precondition"
        );
    }

    fn read_all(fs: &CryptFs, ino: u64, len: u32) -> Vec<u8> {
        let fh = fs.open_impl(ino, libc::O_RDONLY, 1000).unwrap();
        let out = fs.read_impl(ino, fh, 1000, 0, len).unwrap();
        fs.handles.close(fh);
        out
    }

    #[test]
    fn write_path_grow_from_torn_state_mechanism_a_no_resurrect() {
        // Audit critical, Mechanism A: torn state (size 4, manifest 10), grow to 8
        // (old_size 4 < 8 < manifest.total_size 10). The grow must NOT resurrect
        // [4,8) — those bytes were truncated away and must read as zeros.
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        forge_torn_state(&fs, 2, b"0123456789", 4);
        fs.setattr_impl(2, 1000, None, None, None, Some(8), None, None)
            .unwrap();
        assert_eq!(
            read_all(&fs, 2, 8),
            b"0123\0\0\0\0",
            "torn-state grow (mech A) must zero the grown region"
        );
    }

    #[test]
    fn write_path_grow_from_torn_state_mechanism_b_no_resurrect() {
        // Audit critical, Mechanism B: torn state (size 4, manifest 10), grow to 12
        // (s 12 >= manifest.total_size 10). [4,12) must read as zeros, not the stale
        // manifest sub-tail [4,10).
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        forge_torn_state(&fs, 2, b"0123456789", 4);
        fs.setattr_impl(2, 1000, None, None, None, Some(12), None, None)
            .unwrap();
        let mut expect = b"0123".to_vec();
        expect.resize(12, 0);
        assert_eq!(
            read_all(&fs, 2, 12),
            expect,
            "torn-state grow (mech B) must zero the grown region"
        );
    }

    #[test]
    fn write_path_torn_state_read_without_grow_serves_valid_prefix() {
        // A torn state read AT its current size (no grow) serves the valid prefix —
        // no resurrection. This is why no pre-v0.4.7 migration is needed: plain reads
        // are already safe; the heal happens lazily on the first grow.
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        forge_torn_state(&fs, 2, b"0123456789", 4);
        assert_eq!(read_all(&fs, 2, 4), b"0123");
        assert_eq!(
            read_all(&fs, 2, 100),
            b"0123",
            "read past size returns only the valid prefix"
        );
    }

    #[test]
    fn write_path_dirty_handle_grow_reconciles_no_resurrect() {
        // Re-audit critical: the grow reconcile must fire even when a handle is
        // DIRTY. Open a handle, write (dirty), shrink, then grow while STILL dirty.
        // A read through a SEPARATE clean handle (or any post-crash read) must NOT
        // resurrect the truncated region, and the committed manifest must never
        // exceed inode.size.
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"0123456789"); // released: manifest=10, size=10

        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 0, b"X").unwrap(); // dirty
        fs.setattr_impl(2, 1000, None, None, None, Some(4), None, None)
            .unwrap(); // dirty shrink
        fs.setattr_impl(2, 1000, None, None, None, Some(8), None, None)
            .unwrap(); // dirty grow — must still reconcile

        let inode = fs.store().get(2).unwrap().unwrap();
        assert!(
            inode
                .manifest
                .as_ref()
                .is_none_or(|m| m.total_size <= inode.size),
            "committed manifest.total_size must not exceed inode.size"
        );

        // Read via a SEPARATE clean handle — [4,8) must be zeros, not resurrected.
        let r = read_all(&fs, 2, 8);
        assert_eq!(r.len(), 8);
        assert!(
            r[4..].iter().all(|&b| b == 0),
            "dirty-handle grow must zero the grown region; got {r:?}"
        );
        fs.handles.close(fh);
    }

    #[test]
    fn read_impl_grow_truncate_returns_zeros_for_hole() {
        // Findings #7/#9, tested against the REAL read path (not read_stored): a
        // grow-truncate leaves the manifest shorter than inode.size; read must
        // return zeros for an in-bounds hole, data-then-zeros across a covered+hole
        // span, and empty past EOF — never the stale manifest's idea of length.
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"0123456789"); // 10 bytes
        fs.setattr_impl(2, 1000, None, None, None, Some(100), None, None)
            .unwrap();

        // A clean (non-dirty) read handle so read_impl reads the manifest, not a buffer.
        let fh = fs.open_impl(2, libc::O_RDONLY, 1000).unwrap();

        // Pure hole entirely past the manifest but within size → zeros, not EOF.
        assert_eq!(
            fs.read_impl(2, fh, 1000, 50, 10).unwrap(),
            vec![0u8; 10],
            "pure-hole read returns zeros (POSIX), not EOF"
        );
        // Span covered [5,10) + hole [10,25) → 5 data bytes then 15 zeros.
        let span = fs.read_impl(2, fh, 1000, 5, 20).unwrap();
        assert_eq!(span.len(), 20);
        assert_eq!(&span[..5], b"56789");
        assert!(span[5..].iter().all(|&b| b == 0));
        // Fully past size → empty.
        assert!(fs.read_impl(2, fh, 1000, 100, 10).unwrap().is_empty());
        // Tail clamps to size: offset 95, size 20 → 5 zero bytes.
        assert_eq!(fs.read_impl(2, fh, 1000, 95, 20).unwrap(), vec![0u8; 5]);

        fs.handles.close(fh);
    }

    #[test]
    fn read_impl_shrunk_file_does_not_serve_stale_manifest_tail() {
        // After a shrink the manifest still describes the old longer content; the
        // real read path must clamp to inode.size — a ranged read starting past the
        // new size must return empty, NOT the dropped tail (the resurrection vector).
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"0123456789"); // 10 bytes
        fs.setattr_impl(2, 1000, None, None, None, Some(4), None, None)
            .unwrap();

        let fh = fs.open_impl(2, libc::O_RDONLY, 1000).unwrap();
        assert_eq!(
            fs.read_impl(2, fh, 1000, 0, 100).unwrap(),
            b"0123",
            "whole-file read clamps a shrunk file to inode.size"
        );
        assert!(
            fs.read_impl(2, fh, 1000, 6, 4).unwrap().is_empty(),
            "a read past the shrunk size must not resurrect the stale manifest tail"
        );
        fs.handles.close(fh);
    }

    #[test]
    fn manifest_history_persists_across_versions() {
        // v0.4.5 phase 1a: every committed write archives its manifest version, so
        // prior versions survive (history/diff/revert substrate). Three distinct
        // writes → versions 1,2,3 retrievable with the right size + blocks.
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        // O_TRUNC writes clear the current manifest before each write — exercising
        // the monotonic-versioning fix: prev.version resets to 0 each time, so
        // without sourcing the next version from history these would collide on the
        // (ino, version=1) PRIMARY KEY and fail with EIO.
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"AAAA"); // v1, size 4
        write_via_impl(&fs, 2, libc::O_WRONLY | libc::O_TRUNC, 0, b"BBBBBBBB"); // v2, size 8
        write_via_impl(&fs, 2, libc::O_WRONLY | libc::O_TRUNC, 0, b"CC"); // v3, size 2

        let ms = fs.manifest_store();
        let versions: Vec<u64> = ms.list_versions(2).unwrap();
        assert_eq!(
            versions,
            vec![1, 2, 3],
            "every write appends a monotonic version"
        );
        assert_eq!(ms.get(2, 1).unwrap().unwrap().total_size, 4);
        assert_eq!(ms.get(2, 2).unwrap().unwrap().total_size, 8);
        assert_eq!(ms.get(2, 3).unwrap().unwrap().total_size, 2);
        // The current inode manifest equals the latest archived version.
        let cur = fs.store().get(2).unwrap().unwrap().manifest.unwrap();
        assert_eq!(cur, ms.get(2, cur.version).unwrap().unwrap());
        assert_eq!(cur.version, 3);
    }

    #[test]
    fn manifest_history_sequential_writes_chain_parents() {
        // Non-O_TRUNC counterpart: normal sequential writes produce CONTIGUOUS
        // versions 1,2,3 (version# is a monotonic counter from max-persisted) AND a
        // correct content lineage (each version's parent_ids = the prior version's
        // manifest id). The two derivations (version from max_persisted, parent_ids
        // from the prior current manifest) must agree for a normally-written file.
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"aaaa"); // v1 (4)
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"bbbbbbbb"); // v2 (8, full overwrite)
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"cccccccccccc"); // v3 (12, full overwrite)

        let mk = SymmetricKey::from_bytes([0x47; 32]); // matches setup_cryptfs_with_transport
        let ms = fs.manifest_store();
        let versions: Vec<u64> = ms.list_versions(2).unwrap();
        assert_eq!(
            versions,
            vec![1, 2, 3],
            "sequential writes produce contiguous versions"
        );

        let v1 = ms.get(2, 1).unwrap().unwrap();
        let v2 = ms.get(2, 2).unwrap().unwrap();
        let v3 = ms.get(2, 3).unwrap().unwrap();
        // v1 chains to the genesis empty manifest created with the inode (v0); v2→v1,
        // v3→v2. Contiguous versions + an unbroken lineage = no version/parent desync.
        let genesis = teagarden_core::block::pointer::FileManifest::new(2);
        assert_eq!(
            v1.parent_ids,
            vec![genesis.compute_id(&mk)],
            "v1 chains to genesis"
        );
        assert_eq!(v2.parent_ids, vec![v1.compute_id(&mk)], "v2 chains to v1");
        assert_eq!(v3.parent_ids, vec![v2.compute_id(&mk)], "v3 chains to v2");
        // DAG edges mirror the content lineage.
        assert_eq!(
            fs.dag_store().get_parents(&v2.compute_id(&mk)).unwrap(),
            vec![v1.compute_id(&mk)]
        );
    }

    #[test]
    fn recycled_inode_does_not_inherit_manifest_history() {
        // next_ino = MAX(ino)+1, so deleting the highest inode frees its number for
        // reuse. unlink/rename clean the manifest history (delete_versions) in the
        // same journaled_txn as the inode delete, so a new file with the recycled
        // ino starts at version 1 with NO stale history (correctness + privacy).
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "old");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"old-v1");
        write_via_impl(&fs, 2, libc::O_WRONLY | libc::O_TRUNC, 0, b"old-v2");
        assert_eq!(fs.manifest_store().max_version(2).unwrap(), 2);

        // Replicate unlink's journaled body: delete the inode AND its history.
        fs.journaled_txn(|| {
            fs.store().delete(2).map_err(|_| libc::EIO)?;
            fs.manifest_store()
                .delete_versions(2)
                .map_err(|_| libc::EIO)
        })
        .unwrap();
        assert_eq!(
            fs.manifest_store().max_version(2).unwrap(),
            0,
            "history purged when the inode is destroyed"
        );

        // Recycle ino 2 for a NEW file and write it.
        fs.journaled_txn(|| {
            fs.store()
                .insert(&Inode::new_file(2, 1, "new".into(), 0o644, 1000, 1000))
                .map_err(|_| libc::EIO)
        })
        .unwrap();
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"new-content");

        let versions: Vec<u64> = fs.manifest_store().list_versions(2).unwrap();
        assert_eq!(
            versions,
            vec![1],
            "recycled inode starts fresh — no inherited history"
        );
        assert_eq!(
            fs.manifest_store().get(2, 1).unwrap().unwrap().total_size,
            11 // "new-content"
        );
    }

    #[test]
    fn revert_restores_prior_version_content_and_preserves_history() {
        // v0.4.8: revert appends a NEW version whose content is a prior version's
        // blocks (reused, no re-upload), descending from both head and target. Older
        // history is preserved (append-only).
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"AAAA"); // v1
        write_via_impl(&fs, 2, libc::O_WRONLY | libc::O_TRUNC, 0, b"BBBBBBBB"); // v2
        write_via_impl(&fs, 2, libc::O_WRONLY | libc::O_TRUNC, 0, b"CC"); // v3
        assert_eq!(read_stored(&fs, 2), b"CC");

        let inode = fs.revert_impl(2, 1).unwrap(); // revert to v1 ("AAAA")
        assert_eq!(inode.size, 4);
        assert_eq!(
            read_stored(&fs, 2),
            b"AAAA",
            "revert restores the target version's content"
        );

        let ms = fs.manifest_store();
        assert_eq!(
            ms.list_versions(2).unwrap(),
            vec![1, 2, 3, 4],
            "revert appends a new version and preserves history"
        );
        let cur = inode.manifest.unwrap();
        assert_eq!(cur.version, 4);
        let mk = SymmetricKey::from_bytes([0x47; 32]);
        let v1 = ms.get(2, 1).unwrap().unwrap();
        let v3 = ms.get(2, 3).unwrap().unwrap();
        assert!(
            cur.parent_ids.contains(&v3.compute_id(&mk)),
            "head (v3) parent"
        );
        assert!(
            cur.parent_ids.contains(&v1.compute_id(&mk)),
            "target (v1) parent"
        );
    }

    #[test]
    fn revert_to_missing_version_errors() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"AAAA"); // v1
        assert_eq!(fs.revert_impl(2, 9).unwrap_err(), libc::ENOENT);
        assert_eq!(fs.revert_impl(99, 1).unwrap_err(), libc::ENOENT); // no such inode
    }

    #[test]
    fn revert_to_version_with_missing_block_errors_not_silently_commits() {
        // audit v0.4.8 #6: revert reuses the target's blocks by reference and only
        // increment_ref's them (which silently no-ops on a missing row). If a block
        // is gone, revert must FAIL CLOSED (EIO) rather than commit a new head whose
        // blocks are dangling and report success. (Unreachable today — no path prunes
        // block rows — but a required precondition before block-GC lands.)
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"AAAA"); // v1
        write_via_impl(&fs, 2, libc::O_WRONLY | libc::O_TRUNC, 0, b"BBBB"); // v2 (current head)

        // Simulate a (future-GC) prune of v1's block, then attempt to revert to v1.
        let v1 = fs.manifest_store().get(2, 1).unwrap().unwrap();
        let v1_block = v1.blocks[0].block_id;
        fs.block_store().delete(&v1_block).unwrap();

        assert_eq!(
            fs.revert_impl(2, 1).unwrap_err(),
            libc::EIO,
            "revert to a version with a missing block must fail closed"
        );
        // Nothing was committed: head is still v2, history is unchanged.
        assert_eq!(fs.manifest_store().list_versions(2).unwrap(), vec![1, 2]);
        let head = fs.store().get(2).unwrap().unwrap().manifest.unwrap();
        assert_eq!(head.version, 2, "failed revert left the head untouched");
    }

    /// Like `setup_cryptfs_with_transport` but with T7 fail-closed integrity set.
    fn setup_cryptfs_integrity(
        required: bool,
    ) -> (
        CryptFs,
        Arc<teagarden_telegram::mock::MockTransport>,
        tokio::runtime::Runtime,
    ) {
        setup_cryptfs_full(required, None)
    }

    /// Build a transport-backed CryptFs with explicit T7 settings.
    fn setup_cryptfs_full(
        require_integrity: bool,
        block_v2_from_epoch: Option<u32>,
    ) -> (
        CryptFs,
        Arc<teagarden_telegram::mock::MockTransport>,
        tokio::runtime::Runtime,
    ) {
        let conn = Connection::open_in_memory().unwrap();
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let transport = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let fs = CryptFs::new(
            conn,
            schema,
            SymmetricKey::from_bytes([0x43; 32]),
            SymmetricKey::from_bytes([0x44; 32]),
            1000,
            1000,
        )
        .with_block_keys(
            SymmetricKey::from_bytes([0x45; 32]),
            SymmetricKey::from_bytes([0x46; 32]),
        )
        .with_manifest_key(SymmetricKey::from_bytes([0x47; 32]))
        .with_block_integrity(require_integrity)
        .with_block_v2_from_epoch(block_v2_from_epoch)
        .with_transport(transport.clone())
        .with_runtime(rt.handle().clone());
        (fs, transport, rt)
    }

    // T7 part 2 — THE security proof: under block-v2 the AEAD AAD binds the
    // expected block_id, so serving a real ciphertext under a DIFFERENT identity
    // fails to authenticate. Uses fail-OPEN (integrity off) + a block_id with no
    // store record so the metadata hash check cannot mask the AAD's own rejection.
    #[test]
    fn block_v2_aad_rejects_substitution_at_cipher_layer() {
        let (fs, _t, _rt) = setup_cryptfs_full(false, Some(0));
        let data = vec![0x11; 4096];
        let block = fs.flush_to_transport(1, &data).unwrap();
        // Correct identity reads fine.
        assert_eq!(
            fs.download_block(block.message_id, &block.block_id, 0),
            Some(data)
        );
        // Same ciphertext, WRONG expected block_id (and no record for it): the
        // block-v2 AAD makes decryption fail → refused.
        let wrong_id = [0x99u8; 32];
        assert_eq!(fs.download_block(block.message_id, &wrong_id, 0), None);
    }

    // Contrast: under block-v1 (constant AAD) the same substitution is NOT
    // rejected at the cipher layer — it decrypts to the wrong-identity plaintext.
    // This is exactly the gap block-v2 closes.
    #[test]
    fn block_v1_aad_does_not_reject_substitution() {
        let (fs, _t, _rt) = setup_cryptfs_full(false, None);
        let data = vec![0x11; 4096];
        let block = fs.flush_to_transport(1, &data).unwrap();
        let wrong_id = [0x99u8; 32];
        assert_eq!(
            fs.download_block(block.message_id, &wrong_id, 0),
            Some(data),
            "block-v1 constant AAD cannot detect substitution"
        );
    }

    // A v0.4.1-shaped volume has BOTH flags on (block-v2 + fail-closed). A block
    // written and read through the real path round-trips — proving the two
    // new-volume defaults interact correctly.
    #[test]
    fn block_v2_and_fail_closed_round_trip() {
        let (fs, _t, _rt) = setup_cryptfs_full(true, Some(0));
        let data = vec![0x22; 8192];
        let block = fs.flush_to_transport(2, &data).unwrap();
        assert_eq!(
            fs.download_block(block.message_id, &block.block_id, 0),
            Some(data)
        );
    }

    // Migration: a legacy block-v1 volume (threshold None) still reads after the
    // block-v2 code lands.
    #[test]
    fn legacy_block_v1_volume_still_reads() {
        let (fs, _t, _rt) = setup_cryptfs_full(false, None);
        let data = vec![0x33; 2048];
        let block = fs.flush_to_transport(3, &data).unwrap();
        assert_eq!(
            fs.download_block(block.message_id, &block.block_id, 0),
            Some(data)
        );
    }

    // T7 part 1: a block written through the real path records its SRB2 hashes,
    // so a fail-closed read accepts it (the analog of the boto3 real-client test).
    #[test]
    fn fail_closed_round_trip_through_real_write_path() {
        let (fs, _t, _rt) = setup_cryptfs_integrity(true);
        let data = vec![0xAB; 4096];
        let block = fs.flush_to_transport(7, &data).unwrap();
        assert_eq!(
            fs.download_block(block.message_id, &block.block_id, 0),
            Some(data)
        );
    }

    // A block whose store record is missing is unverifiable → refused (None),
    // which the read path maps to EIO instead of silent truncation.
    #[test]
    fn fail_closed_refuses_block_with_no_record() {
        let (fs, _t, _rt) = setup_cryptfs_integrity(true);
        let block = fs.flush_to_transport(9, &vec![0xCD; 2048]).unwrap();
        let fake_id = [0xFFu8; 32];
        assert_eq!(fs.download_block(block.message_id, &fake_id, 0), None);
        // The genuine block still reads (proves the refusal is targeted).
        assert!(fs
            .download_block(block.message_id, &block.block_id, 0)
            .is_some());
    }

    // Without the flag, the same unverifiable block is decrypted and served
    // (legacy SRB1 fail-open) — the behavior fail-closed is designed to replace.
    #[test]
    fn fail_open_serves_unverified_block_when_not_required() {
        let (fs, _t, _rt) = setup_cryptfs_integrity(false);
        let data = vec![0xCD; 2048];
        let block = fs.flush_to_transport(9, &data).unwrap();
        let fake_id = [0xFFu8; 32];
        assert_eq!(fs.download_block(block.message_id, &fake_id, 0), Some(data));
    }

    // Regression for the key-rotation data-loss bug: rotation re-encrypts a block
    // (fresh AEAD nonce => new ciphertext => new ciphertext hash) and MUST
    // refresh ciphertext_sha256, or a fail-closed read of the rotated block would
    // mismatch the stale hash and be refused. This simulates a real rotation end
    // to end (re-encrypt under epoch+1, upload, update_block_epoch with the new
    // hash) and asserts the rotated block still reads under fail-closed.
    #[test]
    fn rotation_refreshes_hash_so_fail_closed_read_succeeds() {
        let (fs, transport, rt) = setup_cryptfs_integrity(true);
        let data = vec![0x5A; 4096];
        let block = fs.flush_to_transport(11, &data).unwrap();
        assert_eq!(
            fs.download_block(block.message_id, &block.block_id, 0),
            Some(data.clone())
        );

        // Re-encrypt the same plaintext under epoch 1 and upload it.
        let new_key = derive_epoch_key(&fs.data_key, 1).unwrap();
        let new_ct = aead::encrypt(&new_key.key, &data, b"block-v1").unwrap();
        let new_ct_sha = teagarden_core::block::srb2::sha256(&new_ct);
        let new_msg = rt
            .block_on(transport.upload_block(&new_ct, &block.filename))
            .unwrap()
            .message_id;

        // The fix: update_block_epoch refreshes ciphertext_sha256.
        fs.block_store()
            .update_block_epoch(
                &block.block_id,
                1,
                new_msg,
                block.encrypted_size,
                &new_ct_sha,
            )
            .unwrap();

        // Fail-closed read of the rotated block at the new epoch succeeds.
        assert_eq!(fs.download_block(new_msg, &block.block_id, 1), Some(data));
    }

    // The core key-rotation read fix (re-enabling `key rotate`): after rotation
    // re-uploads a block under a NEW message_id + epoch and updates the store, a
    // file whose manifest still carries the PRE-rotation (message_id, epoch) must
    // still read back. download_block resolves the block's CURRENT location from
    // the store rather than trusting the stale manifest pointer — otherwise every
    // rotated file would be unreadable (the old message is re-encrypted/deleted).
    #[test]
    fn read_with_stale_manifest_pointer_resolves_current_location_after_rotation() {
        let (fs, transport, rt) = setup_cryptfs_integrity(true);
        let data = vec![0x5A; 4096];
        let block = fs.flush_to_transport(11, &data).unwrap();
        let stale_msg = block.message_id; // the value still embedded in the manifest
        assert_eq!(
            fs.download_block(stale_msg, &block.block_id, 0),
            Some(data.clone())
        );

        // Rotate: re-encrypt under epoch 1, upload a NEW message, update the store
        // (new message_id, new epoch, new ciphertext hash).
        let new_key = derive_epoch_key(&fs.data_key, 1).unwrap();
        let new_ct = aead::encrypt(&new_key.key, &data, b"block-v1").unwrap();
        let new_ct_sha = teagarden_core::block::srb2::sha256(&new_ct);
        let new_msg = rt
            .block_on(transport.upload_block(&new_ct, &block.filename))
            .unwrap()
            .message_id;
        assert_ne!(new_msg, stale_msg);
        fs.block_store()
            .update_block_epoch(
                &block.block_id,
                1,
                new_msg,
                block.encrypted_size,
                &new_ct_sha,
            )
            .unwrap();
        // The old message is gone after a real rotation; deleting it here makes a
        // stale-pointer read the ONLY way to fail.
        let _ = rt.block_on(transport.delete_message(stale_msg));

        // Read using the STALE manifest values (old message_id + old epoch). It
        // succeeds only because download_block resolves the current location from
        // the store; without that it would download the deleted message / mismatch
        // the refreshed ciphertext hash and return None.
        assert_eq!(fs.download_block(stale_msg, &block.block_id, 0), Some(data));
    }

    #[test]
    fn flush_to_transport_uploads_block() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();

        let data = vec![0xAA; 1024];
        let block = fs.flush_to_transport(42, &data);

        assert!(block.is_some());
        let block = block.unwrap();
        assert_eq!(block.ref_count, 1);
        assert_eq!(transport.message_count(), 1);

        // Transport stores ciphertext — it must not equal plaintext
        let raw = transport.get_raw(block.message_id).unwrap();
        assert_ne!(raw, data, "transport should hold ciphertext, not plaintext");

        // Round-trip via download_block returns the original plaintext
        let recovered = fs
            .download_block(block.message_id, &block.block_id, 0)
            .unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn flush_to_transport_dedup() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();

        let data = vec![0xBB; 512];

        // First upload
        let block1 = fs.flush_to_transport(42, &data).unwrap();

        // Second upload of same data — should dedup
        let block2 = fs.flush_to_transport(43, &data).unwrap();

        assert_eq!(block1.block_id, block2.block_id);
        assert_eq!(transport.message_count(), 1); // Only one upload happened

        // Ref count should have been incremented
        let stored = fs.block_store().get(&block1.block_id).unwrap().unwrap();
        assert_eq!(stored.ref_count, 2);
    }

    #[test]
    fn download_block_via_transport() {
        let (fs, _transport, _rt) = setup_cryptfs_with_transport();

        let data = vec![0xCC; 2048];
        let block = fs.flush_to_transport(42, &data).unwrap();

        // Download and decrypt the block by message_id and block_id
        let downloaded = fs.download_block(block.message_id, &block.block_id, 0);
        assert!(downloaded.is_some());
        assert_eq!(downloaded.unwrap(), data);
    }

    #[test]
    fn flush_no_transport_returns_none() {
        let conn = Connection::open_in_memory().unwrap();
        let schema_key = SymmetricKey::from_bytes([0x42; 32]);
        let meta_key = SymmetricKey::from_bytes([0x43; 32]);
        let data_key = SymmetricKey::from_bytes([0x44; 32]);
        let schema = OpaqueSchema::new(schema_key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();

        let fs = CryptFs::new(conn, schema, meta_key, data_key, 1000, 1000);

        // Without transport, flush returns None
        let block = fs.flush_to_transport(42, &[0xAA; 100]);
        assert!(block.is_none());
    }

    #[test]
    fn download_block_cache_hit() {
        let (_fs, _transport, _rt0) = setup_cryptfs_with_transport();

        // Set up cache
        let cache_dir = tempfile::TempDir::new().unwrap();
        let cache_config = teagarden_cache::block_cache::CacheConfig {
            cache_dir: cache_dir.path().to_path_buf(),
            max_size: 10 * 1024 * 1024,
            encrypt_at_rest: false,
        };
        let cache_key = SymmetricKey::from_bytes([0x55; 32]);
        let cache = Arc::new(
            teagarden_cache::block_cache::BlockCache::new(cache_config, cache_key).unwrap(),
        );

        // Rebuild CryptFs with cache
        let conn = Connection::open_in_memory().unwrap();
        let schema_key = SymmetricKey::from_bytes([0x42; 32]);
        let meta_key = SymmetricKey::from_bytes([0x43; 32]);
        let data_key = SymmetricKey::from_bytes([0x44; 32]);
        let schema = OpaqueSchema::new(schema_key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();

        let transport = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();

        let fs = CryptFs::new(conn, schema, meta_key, data_key, 1000, 1000)
            .with_transport(transport.clone())
            .with_cache(cache.clone())
            .with_runtime(rt.handle().clone());

        // Upload data
        let data = vec![0xDD; 256];
        let block = fs.flush_to_transport(42, &data).unwrap();

        // Data should be cached from the flush
        assert!(cache.contains(&block.block_id));

        // Download should hit cache (even if transport is disconnected)
        transport.set_connected(false);
        let downloaded = fs.download_block(block.message_id, &block.block_id, 0);
        assert!(downloaded.is_some());
        assert_eq!(downloaded.unwrap(), data);
    }

    /// Read-ahead prefetch correctness: after a read, `trigger_prefetch` fetches the
    /// upcoming blocks concurrently into the cache so a sequential reader isn't
    /// serialized one round-trip per block. Verify it populates the cache with the
    /// CORRECT plaintext for blocks ahead of the read, and that re-triggering while a
    /// fetch is in flight does not double-cache (dedup via prefetch_inflight).
    #[test]
    fn prefetch_populates_cache_with_correct_upcoming_blocks() {
        use std::time::Duration;

        let cache_dir = tempfile::TempDir::new().unwrap();
        let cache_config = teagarden_cache::block_cache::CacheConfig {
            cache_dir: cache_dir.path().to_path_buf(),
            max_size: 10 * 1024 * 1024,
            encrypt_at_rest: false,
        };
        let cache = Arc::new(
            teagarden_cache::block_cache::BlockCache::new(
                cache_config,
                SymmetricKey::from_bytes([0x55; 32]),
            )
            .unwrap(),
        );

        let conn = Connection::open_in_memory().unwrap();
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let transport = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let fs = CryptFs::new(
            conn,
            schema,
            SymmetricKey::from_bytes([0x43; 32]),
            SymmetricKey::from_bytes([0x44; 32]),
            1000,
            1000,
        )
        .with_transport(transport.clone())
        .with_cache(cache.clone())
        .with_runtime(rt.handle().clone());

        // Two distinct blocks (distinct content → distinct block_ids, no dedup).
        let data0 = vec![0xA1u8; 4096];
        let data1 = vec![0xB2u8; 4096];
        let rec0 = fs.flush_to_transport(7, &data0).unwrap();
        let rec1 = fs.flush_to_transport(7, &data1).unwrap();

        // A manifest describing the two blocks back-to-back.
        let mk_bp = |rec: &BlockRecord, off: u64| BlockPointer {
            block_id: rec.block_id,
            message_id: rec.message_id,
            file_offset: off,
            length: rec.plaintext_size as u64,
            block_data_offset: 0,
            encrypted_size: rec.encrypted_size as u64,
            compressed: rec.compressed,
            epoch: rec.epoch,
        };
        let manifest = FileManifest {
            inode: 7,
            version: 1,
            total_size: (data0.len() + data1.len()) as u64,
            file_hash: [0u8; 32],
            blocks: vec![mk_bp(&rec0, 0), mk_bp(&rec1, data0.len() as u64)],
            parent_ids: vec![],
        };

        // Evict everything the flush cached, so prefetch has real work to do.
        cache.clear().unwrap();
        assert!(!cache.contains(&rec0.block_id));
        assert!(!cache.contains(&rec1.block_id));

        // Prefetch from offset 0 → should pull both upcoming blocks into the cache.
        fs.trigger_prefetch(&manifest, 0);
        // Re-trigger immediately: in-flight blocks must be skipped (no double work),
        // and this must never panic or corrupt the cache.
        fs.trigger_prefetch(&manifest, 0);

        // The spawned tasks run on the multi-threaded runtime; the mock transport is
        // in-memory so they finish in microseconds. Poll briefly for determinism.
        let mut cached = false;
        for _ in 0..200 {
            if cache.contains(&rec0.block_id) && cache.contains(&rec1.block_id) {
                cached = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            cached,
            "prefetch must populate the cache with the upcoming blocks"
        );

        // And the cached bytes must be the correct decrypted plaintext.
        assert_eq!(cache.get(&rec0.block_id).unwrap(), data0);
        assert_eq!(cache.get(&rec1.block_id).unwrap(), data1);
    }

    // -----------------------------------------------------------------------
    // flush_chunks_to_transport — chunked upload logic
    // -----------------------------------------------------------------------

    /// Helper: create a CryptFs with upload queue enabled.
    ///
    /// Returns the runtime alongside the CryptFs so the caller can keep it
    /// alive for the duration of the test. Dropping the runtime before calling
    /// flush_chunks_to_transport would cancel the upload-queue worker task,
    /// causing the channel to close and uploads to fail.
    fn setup_cryptfs_with_queue() -> (
        CryptFs,
        Arc<teagarden_telegram::mock::MockTransport>,
        tokio::runtime::Runtime,
    ) {
        let conn = Connection::open_in_memory().unwrap();
        let schema_key = SymmetricKey::from_bytes([0x50; 32]);
        let meta_key = SymmetricKey::from_bytes([0x51; 32]);
        let data_key = SymmetricKey::from_bytes([0x52; 32]);
        let block_id_key = SymmetricKey::from_bytes([0x53; 32]);
        let filename_key = SymmetricKey::from_bytes([0x54; 32]);
        let manifest_key = SymmetricKey::from_bytes([0x55; 32]);
        let schema = OpaqueSchema::new(schema_key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();

        let transport = Arc::new(teagarden_telegram::mock::MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();

        let fs = CryptFs::new(conn, schema, meta_key, data_key, 1000, 1000)
            .with_block_keys(block_id_key, filename_key)
            .with_manifest_key(manifest_key)
            .with_transport(transport.clone())
            .with_runtime(rt.handle().clone())
            .with_upload_queue();

        (fs, transport, rt)
    }

    /// A small payload (< UPLOAD_CHUNK_SIZE) should produce exactly one block.
    #[test]
    fn flush_chunks_small_data_produces_one_block() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();

        let data = vec![0xAA; 1024]; // well below 512 KiB
        let records = fs.flush_chunks_to_transport(1, &data);

        assert!(records.is_some());
        let records = records.unwrap();
        assert_eq!(records.len(), 1, "one chunk → one block record");
        assert_eq!(transport.message_count(), 1, "one Telegram upload");
    }

    /// A payload exactly equal to UPLOAD_CHUNK_SIZE should produce one block.
    #[test]
    fn flush_chunks_exactly_chunk_size_produces_one_block() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();

        let data = vec![0xBB; UPLOAD_CHUNK_SIZE];
        let records = fs.flush_chunks_to_transport(2, &data);

        assert!(records.is_some());
        let records = records.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(transport.message_count(), 1);
    }

    /// A payload of 1.5 × UPLOAD_CHUNK_SIZE should produce two blocks.
    #[test]
    fn flush_chunks_one_and_half_chunks_produces_two_blocks() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();

        let size = UPLOAD_CHUNK_SIZE + UPLOAD_CHUNK_SIZE / 2;
        let data = vec![0xCC; size];
        let records = fs.flush_chunks_to_transport(3, &data);

        assert!(records.is_some());
        let records = records.unwrap();
        assert_eq!(records.len(), 2, "1.5 chunks → two block records");
        assert_eq!(transport.message_count(), 2);
    }

    /// A larger configured FUSE block size produces proportionally fewer blocks for
    /// the same data — the throughput lever (one block = one rate-limited message).
    #[test]
    fn flush_chunks_honors_custom_block_size() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        // 1 MiB blocks instead of the default 512 KiB.
        let fs = fs.with_fuse_block_size(2 * UPLOAD_CHUNK_SIZE);

        // 1.5 MiB of data → 2 blocks at 1 MiB (vs 3 at 512 KiB).
        let data = vec![0xDD; 3 * UPLOAD_CHUNK_SIZE];
        let records = fs.flush_chunks_to_transport(2, &data).expect("flush");
        assert_eq!(records.len(), 2, "1.5 MiB at 1 MiB blocks → two blocks");
        assert_eq!(transport.message_count(), 2);
    }

    /// A non-default `--block-size` must still round-trip a multi-block file:
    /// split at the custom size, upload every block, then download and reassemble
    /// bitwise. The unit-level counterpart to the live 50 MiB durability-e2e.sh
    /// check (which a CI box can't run); fail-closed integrity over a configured
    /// block size is separately proven by the rotation + block-v2 AAD tests.
    #[test]
    fn custom_block_size_multi_block_roundtrip() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();
        let block = 2 * UPLOAD_CHUNK_SIZE; // 1 MiB custom blocks
        let fs = fs.with_fuse_block_size(block);

        // 4.5 blocks of data → 5 blocks (4 full + a half tail). Position-dependent
        // bytes make every block distinct (no dedup) and catch any misordering.
        let total = 4 * block + block / 2;
        let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();

        let records = fs.flush_chunks_to_transport(7, &data).expect("flush");
        assert_eq!(records.len(), 5, "4.5 MiB at 1 MiB blocks → 5 blocks");
        assert_eq!(transport.message_count(), 5, "5 distinct blocks uploaded");

        // Reassemble from the transport in manifest order.
        let mut got = Vec::with_capacity(total);
        for o in &records {
            let chunk = fs
                .download_block(o.record.message_id, &o.record.block_id, o.record.epoch)
                .expect("each block downloads + verifies");
            got.extend_from_slice(&chunk);
        }
        assert_eq!(
            got.len(),
            data.len(),
            "reassembled length matches the source"
        );
        assert!(
            got == data,
            "reassembled bytes are bitwise-identical to the source"
        );
    }

    /// `with_fuse_block_size` clamps to the safe range even if a caller passes an
    /// out-of-range value (defensive backstop against exceeding the per-document limit).
    #[test]
    fn with_fuse_block_size_clamps_out_of_range() {
        let (fs, _t, _rt) = setup_cryptfs_with_transport();
        // Below floor clamps up; absurdly large clamps down to MAX_FUSE_BLOCK_SIZE.
        assert_eq!(fs.fuse_block_size, UPLOAD_CHUNK_SIZE); // default
        let small = setup_cryptfs_with_transport().0.with_fuse_block_size(1);
        assert_eq!(small.fuse_block_size, UPLOAD_CHUNK_SIZE);
        let big = setup_cryptfs_with_transport()
            .0
            .with_fuse_block_size(usize::MAX);
        assert_eq!(big.fuse_block_size, MAX_FUSE_BLOCK_SIZE);
    }

    /// Each block record carries the plaintext size of its chunk, not the total.
    #[test]
    fn flush_chunks_block_records_carry_correct_plaintext_sizes() {
        let (fs, _transport, _rt) = setup_cryptfs_with_transport();

        // Two chunks: first full-size, second partial.
        let partial = 4096_usize; // 4 KiB tail
        let data_size = UPLOAD_CHUNK_SIZE + partial;
        let data = vec![0x11u8; data_size];
        let records = fs.flush_chunks_to_transport(4, &data).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record.plaintext_size as usize, UPLOAD_CHUNK_SIZE);
        assert_eq!(records[1].record.plaintext_size as usize, partial);
    }

    /// Ciphertext in each block must differ from the corresponding plaintext.
    #[test]
    fn flush_chunks_ciphertext_differs_from_plaintext() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();

        let data = vec![0x22u8; 8192];
        let records = fs.flush_chunks_to_transport(5, &data).unwrap();
        assert_eq!(records.len(), 1);

        let raw = transport.get_raw(records[0].record.message_id).unwrap();
        assert_ne!(raw, data, "stored bytes must be encrypted, not plaintext");
    }

    /// Calling flush_chunks twice with the same data deduplicates across calls.
    ///
    /// Note: within a single call, identical chunks are each new to the DB (Phase 1
    /// reads before Phase 3 writes), so intra-call dedup is not guaranteed.
    /// Cross-call dedup is the primary dedup path.
    #[test]
    fn flush_chunks_cross_call_dedup() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();

        let data = vec![0x33u8; UPLOAD_CHUNK_SIZE];

        // First flush — uploads the block.
        let records1 = fs.flush_chunks_to_transport(6, &data).unwrap();
        assert_eq!(records1.len(), 1);
        assert_eq!(transport.message_count(), 1);
        // Persist the block (release does this via persist_file_blocks) so the next
        // flush's dedup check finds it.
        fs.block_store().insert(&records1[0].record).unwrap();
        let bid1 = records1[0].record.block_id;

        // Second flush with identical data — must dedup (no new upload).
        let records2 = fs.flush_chunks_to_transport(7, &data).unwrap();
        assert_eq!(records2.len(), 1);
        assert_eq!(
            bid1, records2[0].record.block_id,
            "same data → same block_id"
        );
        assert_eq!(
            transport.message_count(),
            1,
            "no new upload on second flush"
        );
    }

    /// Round-trip: flush_chunks_to_transport then download_block recovers the chunk data.
    #[test]
    fn flush_chunks_roundtrip_small_payload() {
        let (fs, _transport, _rt) = setup_cryptfs_with_transport();

        let data = b"roundtrip chunk data test".to_vec();
        let records = fs.flush_chunks_to_transport(7, &data).unwrap();
        assert_eq!(records.len(), 1);

        let recovered = fs
            .download_block(records[0].record.message_id, &records[0].record.block_id, 0)
            .unwrap();
        assert_eq!(recovered, data);
    }

    /// flush_chunks_to_transport returns None when no transport is configured.
    #[test]
    fn flush_chunks_no_transport_returns_none() {
        let conn = Connection::open_in_memory().unwrap();
        let schema_key = SymmetricKey::from_bytes([0x60; 32]);
        let meta_key = SymmetricKey::from_bytes([0x61; 32]);
        let data_key = SymmetricKey::from_bytes([0x62; 32]);
        let schema = OpaqueSchema::new(schema_key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();

        let fs = CryptFs::new(conn, schema, meta_key, data_key, 1000, 1000);
        let result = fs.flush_chunks_to_transport(8, &[0xFFu8; 512]);
        assert!(result.is_none(), "no transport → None");
    }

    /// flush_chunks_to_transport via the upload-queue path produces correct blocks.
    #[test]
    fn flush_chunks_upload_queue_path_small_data() {
        let (fs, transport, _rt) = setup_cryptfs_with_queue();

        let data = vec![0x77u8; 2048];
        let records = fs.flush_chunks_to_transport(9, &data);

        assert!(records.is_some());
        let records = records.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(transport.message_count(), 1);
    }

    /// Upload-queue path: multi-chunk data uploads all chunks and returns them in order.
    #[test]
    fn flush_chunks_upload_queue_path_multi_chunk() {
        let (fs, transport, _rt) = setup_cryptfs_with_queue();

        let size = UPLOAD_CHUNK_SIZE + 1024; // two chunks
        let data = vec![0x88u8; size];
        let records = fs.flush_chunks_to_transport(10, &data);

        assert!(records.is_some());
        let records = records.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(transport.message_count(), 2);

        // First chunk plaintext size must be exactly UPLOAD_CHUNK_SIZE.
        assert_eq!(records[0].record.plaintext_size as usize, UPLOAD_CHUNK_SIZE);
        // Second chunk is the 1024-byte tail.
        assert_eq!(records[1].record.plaintext_size as usize, 1024);
    }

    /// Upload-queue dedup: same data submitted twice only uploads once.
    #[test]
    fn flush_chunks_upload_queue_dedup() {
        let (fs, transport, _rt) = setup_cryptfs_with_queue();

        let data = vec![0x99u8; 4096];
        let r1 = fs.flush_chunks_to_transport(11, &data).unwrap();
        fs.block_store().insert(&r1[0].record).unwrap();
        let bid1 = r1[0].record.block_id;
        let r2 = fs.flush_chunks_to_transport(12, &data).unwrap();

        assert_eq!(bid1, r2[0].record.block_id, "same data deduplicates");
        assert_eq!(
            transport.message_count(),
            1,
            "second flush hits dedup, no new upload"
        );
    }

    /// Block records produced by flush_chunks have ref_count=1 for new blocks.
    #[test]
    fn flush_chunks_new_blocks_have_ref_count_one() {
        let (fs, _transport, _rt) = setup_cryptfs_with_transport();

        let data = vec![0xAAu8; 512];
        let records = fs.flush_chunks_to_transport(13, &data).unwrap();
        assert_eq!(records[0].record.ref_count, 1);
    }

    /// flush_chunks on an empty payload produces a single zero-size block.
    #[test]
    fn flush_chunks_empty_payload_produces_one_block() {
        let (fs, transport, _rt) = setup_cryptfs_with_transport();

        let records = fs.flush_chunks_to_transport(14, &[]);
        assert!(records.is_some(), "empty payload should not return None");
        let records = records.unwrap();
        assert_eq!(records.len(), 1, "empty data is still one chunk");
        assert_eq!(records[0].record.plaintext_size, 0);
        assert_eq!(transport.message_count(), 1);
    }

    // ---- Data-path regression tests (fuse-fixes brief: C2/C3/H1/H2/M1/M2/M3/M6/L1).
    // Each was written first and observed failing against the unfixed code.

    /// H1: fsync → ftruncate(0) → write on the SAME handle must not resurrect the
    /// pre-truncate bytes (fsync used to clear `dirty` but keep the buffer, which the
    /// truncate then skipped and the next write reused).
    #[test]
    fn h1_fsync_then_truncate_zero_then_write_does_not_resurrect() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 0, b"OLD-SECRET-CONTENT")
            .unwrap();
        fs.fsync_impl(2, fh).unwrap();
        fs.setattr_impl(2, 1000, None, None, None, Some(0), None, None)
            .unwrap();
        fs.write_impl(2, fh, 1000, 0, b"new").unwrap();
        assert_eq!(
            fs.read_impl(2, fh, 1000, 0, 100).unwrap(),
            b"new",
            "read through the handle after fsync+truncate(0)+write"
        );
        fs.release_impl(2, fh).unwrap();
        fs.handles.close(fh);
        assert_eq!(read_stored(&fs, 2), b"new", "persisted content");
    }

    /// M3: two handles on one inode must share one coherent buffer — a read via
    /// either sees both writes, and the persisted file holds both (no last-release-wins).
    #[test]
    fn m3_two_handles_one_inode_share_a_coherent_buffer() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        let fh1 = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        let fh2 = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh1, 1000, 0, b"AAAA").unwrap();
        fs.write_impl(2, fh2, 1000, 4, b"BBBB").unwrap();
        assert_eq!(fs.read_impl(2, fh1, 1000, 0, 64).unwrap(), b"AAAABBBB");
        assert_eq!(fs.read_impl(2, fh2, 1000, 0, 64).unwrap(), b"AAAABBBB");
        fs.release_impl(2, fh1).unwrap();
        fs.handles.close(fh1);
        fs.release_impl(2, fh2).unwrap();
        fs.handles.close(fh2);
        assert_eq!(read_stored(&fs, 2), b"AAAABBBB");
    }

    /// C3 (FS layer): with no transport, persisting dirty data must fail (EIO) —
    /// it used to return Ok for bytes that were never stored anywhere.
    #[test]
    fn c3_release_without_transport_is_an_error_not_silent_success() {
        let conn = Connection::open_in_memory().unwrap();
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let fs = CryptFs::new(
            conn,
            schema,
            SymmetricKey::from_bytes([0x43; 32]),
            SymmetricKey::from_bytes([0x44; 32]),
            1000,
            1000,
        )
        .with_manifest_key(SymmetricKey::from_bytes([0x47; 32]));
        seed_file(&fs, 2, "f");
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh, 1000, 0, b"unpersistable").unwrap();
        assert_eq!(fs.fsync_impl(2, fh), Err(libc::EIO), "fsync");
        assert_eq!(fs.release_impl(2, fh), Err(libc::EIO), "release");
        fs.handles.close(fh);
    }

    /// Install a TEMP trigger that makes any UPDATE of inode `ino` fail, so a
    /// swallowed `store.update` error inside a transaction becomes observable.
    fn inject_inode_update_failure(fs: &CryptFs, ino: u64) {
        let t = fs.schema.table("inodes").unwrap();
        let c = fs.schema.column("inodes", "ino").unwrap();
        fs.conn
            .execute_batch(&format!(
                "CREATE TEMP TRIGGER inject_update_failure BEFORE UPDATE ON {t} \
                 WHEN OLD.{c} = {ino} BEGIN SELECT RAISE(ABORT, 'injected update failure'); END;"
            ))
            .unwrap();
    }

    fn clear_inode_update_failure(fs: &CryptFs) {
        fs.conn
            .execute_batch("DROP TRIGGER temp.inject_update_failure")
            .unwrap();
    }

    /// M2: unlink must propagate a failed parent update (EIO) and roll back —
    /// it used to ignore it, delete the inode, and leave the parent inconsistent.
    #[test]
    fn m2_unlink_propagates_store_update_failure_and_rolls_back() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        inject_inode_update_failure(&fs, 1);
        let r = fs.unlink_impl(0, 1, OsStr::new("f"));
        clear_inode_update_failure(&fs);
        assert_eq!(r, Err(libc::EIO), "unlink result");
        assert!(
            fs.store().get(2).unwrap().is_some(),
            "a failed unlink must roll back the inode delete"
        );
        assert_eq!(fs.store().lookup(1, "f").unwrap().map(|i| i.ino), Some(2));
    }

    /// M2: rename-over-existing must propagate a failed source update (EIO) and
    /// roll back. It used to delete the destination, swallow the failed update of
    /// the source, and return success — destroying the destination's data.
    #[test]
    fn m2_rename_propagates_store_update_failure_and_rolls_back() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "a");
        fs.store()
            .insert(&Inode::new_file(3, 1, "b".into(), 0o644, 1000, 1000))
            .unwrap();
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"source");
        write_via_impl(&fs, 3, libc::O_RDWR, 0, b"destination");

        inject_inode_update_failure(&fs, 2);
        let r = fs.rename_impl(0, 1, OsStr::new("a"), 1, OsStr::new("b"), 0);
        clear_inode_update_failure(&fs);
        assert_eq!(r, Err(libc::EIO), "rename result");
        assert_eq!(fs.store().lookup(1, "a").unwrap().map(|i| i.ino), Some(2));
        assert_eq!(fs.store().lookup(1, "b").unwrap().map(|i| i.ino), Some(3));
        assert_eq!(read_stored(&fs, 3), b"destination", "destination survives");
    }

    /// M2 under the metadata journal: a failed rename publishes NO delta (HEAD
    /// unchanged) and leaves the tree unchanged.
    #[test]
    fn m2_journaled_rename_failure_publishes_nothing() {
        let (fs, _tx, _rt, _dir, ikey, head_path) = setup_cryptfs_with_journal();
        fs.journaled_txn(|| {
            let mut root = Inode::root();
            root.uid = 1000;
            fs.store().insert(&root).map_err(|_| libc::EIO)?;
            fs.store()
                .insert(&Inode::new_file(2, 1, "a".into(), 0o644, 1000, 1000))
                .map_err(|_| libc::EIO)?;
            fs.store()
                .insert(&Inode::new_file(3, 1, "b".into(), 0o644, 1000, 1000))
                .map_err(|_| libc::EIO)
        })
        .unwrap();
        let before = JournalHead::load(&head_path, &ikey).unwrap().unwrap().seq;

        inject_inode_update_failure(&fs, 2);
        let r = fs.rename_impl(0, 1, OsStr::new("a"), 1, OsStr::new("b"), 0);
        clear_inode_update_failure(&fs);
        assert_eq!(r, Err(libc::EIO), "rename result");
        let after = JournalHead::load(&head_path, &ikey).unwrap().unwrap().seq;
        assert_eq!(before, after, "a failed rename must not publish a delta");
        assert_eq!(fs.store().lookup(1, "b").unwrap().map(|i| i.ino), Some(3));
    }

    /// H2: RENAME_NOREPLACE onto an existing name is EEXIST, and both entries
    /// survive. (Flag values are the Linux ABI: NOREPLACE=1, EXCHANGE=2, WHITEOUT=4.)
    #[cfg(target_os = "linux")]
    #[test]
    fn h2_rename_noreplace_refuses_existing_target() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "a");
        fs.store()
            .insert(&Inode::new_file(3, 1, "b".into(), 0o644, 1000, 1000))
            .unwrap();
        write_via_impl(&fs, 3, libc::O_RDWR, 0, b"destination");
        let r = fs.rename_impl(0, 1, OsStr::new("a"), 1, OsStr::new("b"), 1);
        assert_eq!(r, Err(libc::EEXIST));
        assert_eq!(fs.store().lookup(1, "a").unwrap().map(|i| i.ino), Some(2));
        assert_eq!(read_stored(&fs, 3), b"destination");
        // NOREPLACE onto a free name is an ordinary rename.
        fs.rename_impl(0, 1, OsStr::new("a"), 1, OsStr::new("c"), 1)
            .unwrap();
        assert_eq!(fs.store().lookup(1, "c").unwrap().map(|i| i.ino), Some(2));
    }

    /// H2: RENAME_EXCHANGE (and any other unsupported flag) is EINVAL with no
    /// change — it used to be treated as a plain rename and delete the target.
    #[test]
    fn h2_rename_exchange_and_unknown_flags_are_einval() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "a");
        fs.store()
            .insert(&Inode::new_file(3, 1, "b".into(), 0o644, 1000, 1000))
            .unwrap();
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"source");
        write_via_impl(&fs, 3, libc::O_RDWR, 0, b"destination");
        for flags in [2u32, 4, 1 | 2, 0x80] {
            let r = fs.rename_impl(0, 1, OsStr::new("a"), 1, OsStr::new("b"), flags);
            assert_eq!(r, Err(libc::EINVAL), "flags {flags:#x}");
        }
        assert_eq!(fs.store().lookup(1, "a").unwrap().map(|i| i.ino), Some(2));
        assert_eq!(fs.store().lookup(1, "b").unwrap().map(|i| i.ino), Some(3));
        assert_eq!(read_stored(&fs, 2), b"source");
        assert_eq!(read_stored(&fs, 3), b"destination");
    }

    /// L1: a decrypted block shorter than its manifest pointer claims must fail the
    /// read with EIO — it used to be skipped and served as zeros.
    #[test]
    fn l1_block_shorter_than_pointer_is_eio_not_zeros() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"0123456789");
        let mut inode = fs.store().get(2).unwrap().unwrap();
        let mut m = inode.manifest.clone().unwrap();
        m.blocks[0].length = 20;
        m.total_size = 20;
        inode.manifest = Some(m);
        inode.size = 20;
        fs.store().update(&inode).unwrap();

        let fh = fs.open_impl(2, libc::O_RDONLY, 1000).unwrap();
        assert_eq!(fs.read_impl(2, fh, 1000, 0, 20), Err(libc::EIO));
        assert_eq!(fs.read_impl(2, fh, 1000, 12, 4), Err(libc::EIO));
        fs.handles.close(fh);
    }

    /// M6: a write whose end lies beyond the size cap is EFBIG, not a multi-TiB
    /// allocation (which aborted the daemon).
    #[test]
    fn m6_huge_offset_write_is_efbig_not_an_allocation() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        assert_eq!(
            fs.write_impl(2, fh, 1000, 1i64 << 40, b"x"),
            Err(libc::EFBIG)
        );
        // The handle is still usable for a sane write.
        fs.write_impl(2, fh, 1000, 0, b"ok").unwrap();
        fs.release_impl(2, fh).unwrap();
        fs.handles.close(fh);
        assert_eq!(read_stored(&fs, 2), b"ok");
    }

    /// M6: ftruncate beyond the cap is EFBIG (a closed-file grow used to be accepted,
    /// and the next write then allocated the whole size while seeding).
    #[test]
    fn m6_huge_truncate_is_efbig() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        assert_eq!(
            fs.setattr_impl(2, 1000, None, None, None, Some(1u64 << 40), None, None)
                .map(|i| i.size),
            Err(libc::EFBIG)
        );
        assert_eq!(fs.store().get(2).unwrap().unwrap().size, 0);
    }

    /// M6: an inode whose recorded size already exceeds the cap (legacy volume)
    /// is refused at seed time with EFBIG rather than allocated.
    #[test]
    fn m6_seed_of_oversized_inode_is_efbig() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        let mut inode = fs.store().get(2).unwrap().unwrap();
        inode.size = 1u64 << 40;
        fs.store().update(&inode).unwrap();
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        assert_eq!(fs.write_impl(2, fh, 1000, 0, b"x"), Err(libc::EFBIG));
        fs.handles.close(fh);
    }

    /// M1: on the upload-queue path a transport that never answers must yield a
    /// failure within the configured bound — `blocking_recv` used to wait forever.
    /// Also proves the worker releases its concurrency permits on timeout: after
    /// five hung uploads (more than the 4 permits), a later upload still succeeds.
    #[test]
    fn m1_upload_queue_hang_is_bounded_and_recovers() {
        let (fs, transport, _rt) = setup_cryptfs_with_queue();
        let fs = fs.with_upload_timeout(Duration::from_millis(500));
        transport.set_hang_uploads(true);
        let (tx, rx) = std::sync::mpsc::channel();
        let t = Arc::clone(&transport);
        std::thread::spawn(move || {
            let data: Vec<u8> = (0..(5 * UPLOAD_CHUNK_SIZE + 1))
                .map(|i| (i % 251) as u8)
                .collect();
            let started = std::time::Instant::now();
            let hung = fs.flush_chunks_to_transport(2, &data).is_none();
            let _ = tx.send(("hung", hung, started.elapsed()));
            // Let every hung upload's own timeout fire, then recover.
            std::thread::sleep(Duration::from_secs(2));
            t.set_hang_uploads(false);
            let started = std::time::Instant::now();
            let ok = fs.flush_chunks_to_transport(3, b"after recovery").is_some();
            let _ = tx.send(("recovered", ok, started.elapsed()));
        });
        let (_, failed, took) = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("flush_chunks_to_transport hung on a never-answering upload");
        assert!(failed, "a hung upload must fail the flush, not succeed");
        assert!(took < Duration::from_secs(5), "bounded wait took {took:?}");
        let (_, ok, took) = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("upload after recovery hung: worker permits leaked by hung uploads");
        assert!(ok, "upload after recovery must succeed");
        assert!(
            took < Duration::from_secs(5),
            "recovery upload took {took:?}"
        );
    }

    /// A dirty buffer must not outlive its inode. `next_ino` is MAX(ino)+1, so an
    /// unlinked file's number is reused by the next create; a per-inode buffer
    /// left behind would then be served to (and persisted into) the new file —
    /// another user's plaintext through a fresh descriptor.
    #[test]
    fn unlinked_inode_buffer_is_not_inherited_by_a_recycled_ino() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "a");
        let fh_a = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(2, fh_a, 1000, 0, b"SECRET-OF-A").unwrap();
        fs.unlink_impl(0, 1, OsStr::new("a")).unwrap();
        assert_eq!(fs.store().next_ino().unwrap(), 2, "ino 2 is recycled");

        fs.store()
            .insert(&Inode::new_file(2, 1, "b".into(), 0o644, 1001, 1001))
            .unwrap();
        let fh_b = fs.open_impl(2, libc::O_RDONLY, 1001).unwrap();
        assert_eq!(
            fs.read_impl(2, fh_b, 1001, 0, 64).unwrap(),
            b"",
            "the new file must not serve the unlinked file's buffered bytes"
        );
        // Closing the deleted file's descriptor must not write its bytes into b.
        fs.release_impl(2, fh_a).unwrap();
        fs.handles.close(fh_a);
        fs.handles.close(fh_b);
        assert_eq!(read_stored(&fs, 2), b"", "b stays empty");
    }

    /// Same for a rename that replaces (and so deletes) the target inode.
    #[test]
    fn replaced_rename_target_buffer_is_discarded() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "src");
        fs.store()
            .insert(&Inode::new_file(3, 1, "dst".into(), 0o644, 1000, 1000))
            .unwrap();
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"source");
        let fh_dst = fs.open_impl(3, libc::O_RDWR, 1000).unwrap();
        fs.write_impl(3, fh_dst, 1000, 0, b"SECRET-OF-DST").unwrap();
        fs.rename_impl(0, 1, OsStr::new("src"), 1, OsStr::new("dst"), 0)
            .unwrap();
        assert!(fs.store().get(3).unwrap().is_none(), "target inode deleted");
        assert!(
            !fs.handles.has_buffer(3),
            "the replaced target's buffer must be discarded"
        );
        fs.handles.close(fh_dst);
    }

    /// rmdir must propagate a failed parent update (EIO) and roll back — it used to
    /// ignore it, delete the directory, and leave the parent listing a ghost child.
    #[test]
    fn rmdir_propagates_store_update_failure_and_rolls_back() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        fs.store().insert(&Inode::root()).ok();
        fs.store()
            .insert(&Inode::new_dir(2, 1, "d".into(), 0o755, 1000, 1000))
            .unwrap();
        inject_inode_update_failure(&fs, 1);
        let r = fs.rmdir_impl(0, 1, OsStr::new("d"));
        clear_inode_update_failure(&fs);
        assert_eq!(r, Err(libc::EIO), "rmdir result");
        assert!(
            fs.store().get(2).unwrap().is_some(),
            "a failed rmdir must roll back the directory delete"
        );
        assert_eq!(fs.store().lookup(1, "d").unwrap().map(|i| i.ino), Some(2));
    }

    /// Torn state (size 4, one 10-byte block), grown to 8 (pointer trimmed to 4):
    /// a 1-byte write must seed EXACTLY the 4 bytes the pointer records — the
    /// truncated "4567" must not come back.
    #[test]
    fn seed_after_trimmed_grow_does_not_resurrect_truncated_bytes() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        forge_torn_state(&fs, 2, b"0123456789", 4);
        fs.setattr_impl(2, 1000, None, None, None, Some(8), None, None)
            .unwrap();
        assert_eq!(read_all(&fs, 2, 8), b"0123\0\0\0\0", "read after grow");
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"Z");
        assert_eq!(read_all(&fs, 2, 8), b"Z123\0\0\0\0", "after a 1-byte write");
        assert_eq!(read_stored(&fs, 2), b"Z123\0\0\0\0", "persisted content");
    }

    /// Forge a manifest whose single pointer claims 20 bytes of a 10-byte block.
    fn forge_short_block(fs: &CryptFs, ino: u64) {
        write_via_impl(fs, ino, libc::O_RDWR, 0, b"0123456789");
        let mut inode = fs.store().get(ino).unwrap().unwrap();
        let mut m = inode.manifest.clone().unwrap();
        m.blocks[0].length = 20;
        m.total_size = 20;
        inode.manifest = Some(m);
        inode.size = 20;
        fs.store().update(&inode).unwrap();
    }

    /// Seeding a write from a block shorter than its pointer must fail (EIO), not
    /// zero-fill the gap and persist that as the file.
    #[test]
    fn seed_from_block_shorter_than_pointer_is_eio() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        forge_short_block(&fs, 2);
        let fh = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        assert_eq!(fs.write_impl(2, fh, 1000, 0, b"Z"), Err(libc::EIO));
        fs.handles.close(fh);
    }

    /// The truncate-materialize path reassembles blocks the same way: a short block
    /// must fail the truncate (EIO) rather than commit a shorter file.
    #[test]
    fn materialize_from_block_shorter_than_pointer_is_eio() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "f");
        forge_short_block(&fs, 2);
        let before = fs.store().get(2).unwrap().unwrap();
        assert_eq!(
            fs.setattr_impl(2, 1000, None, None, None, Some(15), None, None)
                .map(|i| i.size),
            Err(libc::EIO)
        );
        assert_eq!(
            fs.store().get(2).unwrap().unwrap().manifest,
            before.manifest
        );
    }

    /// Inode-number reuse must not let a descriptor on a DELETED file reach the new
    /// file that inherited its number: writes, reads and fsync through the stale
    /// handle fail with ESTALE, the new file is untouched, and the generation the
    /// kernel sees for the number changes so it does not alias the two.
    #[test]
    fn stale_handle_on_recycled_ino_cannot_touch_the_new_file() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        seed_file(&fs, 2, "a");
        let fh_a = fs.open_impl(2, libc::O_RDWR, 1000).unwrap();
        let gen_a = fs.generation(2);
        fs.unlink_impl(0, 1, OsStr::new("a")).unwrap();
        assert_eq!(fs.store().next_ino().unwrap(), 2, "ino 2 is recycled");
        fs.store()
            .insert(&Inode::new_file(2, 1, "b".into(), 0o644, 1000, 1000))
            .unwrap();
        write_via_impl(&fs, 2, libc::O_RDWR, 0, b"content of b");
        assert_ne!(
            fs.generation(2),
            gen_a,
            "a recycled number gets a new generation"
        );

        assert_eq!(fs.write_impl(2, fh_a, 1000, 0, b"EVIL"), Err(libc::ESTALE));
        assert_eq!(fs.read_impl(2, fh_a, 1000, 0, 64), Err(libc::ESTALE));
        assert_eq!(fs.fsync_impl(2, fh_a), Err(libc::ESTALE));
        assert_eq!(fs.check_handle_live(Some(fh_a)), Err(libc::ESTALE));
        assert_eq!(fs.flush_impl(2, fh_a), Ok(()));
        fs.release_impl(2, fh_a).unwrap();
        fs.handles.close(fh_a);
        assert_eq!(read_stored(&fs, 2), b"content of b", "b is untouched");
    }

    /// rmdir and a replacing rename bump the generation of the deleted number too.
    #[test]
    fn generation_bumps_for_every_kind_of_delete() {
        let (fs, _tx, _rt) = setup_cryptfs_with_transport();
        fs.store().insert(&Inode::root()).ok();
        fs.store()
            .insert(&Inode::new_dir(2, 1, "d".into(), 0o755, 1000, 1000))
            .unwrap();
        fs.store()
            .insert(&Inode::new_file(3, 1, "x".into(), 0o644, 1000, 1000))
            .unwrap();
        fs.store()
            .insert(&Inode::new_file(4, 1, "y".into(), 0o644, 1000, 1000))
            .unwrap();
        assert_eq!((fs.generation(2), fs.generation(4)), (0, 0));
        fs.rmdir_impl(0, 1, OsStr::new("d")).unwrap();
        fs.rename_impl(0, 1, OsStr::new("x"), 1, OsStr::new("y"), 0)
            .unwrap();
        assert_eq!(fs.generation(2), 1, "rmdir");
        assert_eq!(fs.generation(4), 1, "replaced rename target");
        assert_eq!(
            fs.generation(3),
            0,
            "the renamed (surviving) inode keeps its generation"
        );
    }
}

/// F2: a journal delta must be bound to the exact predecessor it follows, so a
/// storage provider cannot answer a delta's message id with a different
/// authentic delta that carries the same header (e.g. one whose upload it
/// stored but never acknowledged).
#[cfg(test)]
mod journal_chain_tests {
    use super::*;
    use teagarden_core::volume::metadata_snapshot::encrypt_snapshot;
    use teagarden_store::journal_recovery::recover_from_head;
    use teagarden_store::migrations::initialize_database;
    use teagarden_store::schema::logical_tables;
    use teagarden_telegram::mock::MockTransport;

    const SCHEMA: [u8; 32] = [0x42; 32];
    const META: [u8; 32] = [0x43; 32];
    const DATA: [u8; 32] = [0x44; 32];
    const INTEG: [u8; 32] = [0x48; 32];

    fn k(b: [u8; 32]) -> SymmetricKey {
        SymmetricKey::from_bytes(b)
    }
    fn schema() -> OpaqueSchema {
        OpaqueSchema::new(k(SCHEMA), &logical_tables())
    }
    fn db_file_bytes(db_path: &Path) -> Vec<u8> {
        let c = Connection::open(db_path).unwrap();
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        drop(c);
        std::fs::read(db_path).unwrap()
    }
    fn wipe_sidecars(db_path: &Path) {
        for sfx in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sfx}", db_path.display()));
        }
    }
    /// What a clean unmount does: snapshot the DB, publish it, reset HEAD onto it.
    fn clean_unmount(
        rt: &tokio::runtime::Runtime,
        t: &MockTransport,
        db_path: &Path,
        head_path: &Path,
        version: u64,
    ) -> JournalHead {
        let blob = encrypt_snapshot(&k(DATA), version, &db_file_bytes(db_path)).unwrap();
        let id = rt.block_on(t.sync_metadata(&blob)).unwrap();
        let head = JournalHead::at_snapshot(
            id,
            version,
            *blake3::hash(&blob).as_bytes(),
            teagarden_core::volume::journal_head::Lineage::new(version),
        );
        head.store_atomic(head_path, &k(INTEG)).unwrap();
        head
    }
    fn mount_fs(
        db_path: &Path,
        t: Arc<dyn BlockTransport>,
        rt: &tokio::runtime::Runtime,
        head_path: &Path,
        head: JournalHead,
    ) -> CryptFs {
        CryptFs::new(
            Connection::open(db_path).unwrap(),
            schema(),
            k(META),
            k(DATA),
            1000,
            1000,
        )
        .with_transport(t)
        .with_runtime(rt.handle().clone())
        .with_journal(k(INTEG), head_path.to_path_buf(), head)
    }
    fn mode_of(db_path: &Path, ino: u64) -> Option<u32> {
        let c = Connection::open(db_path).unwrap();
        let (sc, mk) = (schema(), k(META));
        let m = InodeStore::new(&c, &sc, &mk)
            .get(ino)
            .unwrap()
            .map(|i| i.mode);
        m
    }
    fn recover_serving(
        mock: &MockTransport,
        head: JournalHead,
        db_path: &Path,
        swap: Option<(i64, i64)>,
    ) -> Result<u64, teagarden_core::error::CoreError> {
        recover_from_head(&k(DATA), head, db_path, |id| {
            let id = match swap {
                Some((real, served)) if id == real => served,
                _ => id,
            };
            mock.get_raw(id)
                .ok_or_else(|| teagarden_core::error::CoreError::Snapshot(format!("{id} gone")))
        })
    }
    /// One chmod whose publish is stored but never acknowledged (the user sees
    /// EIO and the change is rolled back), then one create that succeeds.
    /// Returns the id of the orphan delta on the server.
    fn withheld_chmod_then_create(
        fs: &CryptFs,
        mock: &MockTransport,
        ino: u64,
        new_ino: u64,
    ) -> i64 {
        let before = mock.message_count();
        mock.withhold_metadata_acks(1);
        let mut wide = fs.store().get(ino).unwrap().unwrap();
        let old_mode = wide.mode;
        wide.mode = 0o777;
        let r = fs.journaled_txn(|| fs.store().update(&wide).map_err(|_| libc::EIO));
        assert_eq!(r, Err(libc::EIO), "the user is told the chmod failed");
        assert_eq!(
            fs.store().get(ino).unwrap().unwrap().mode,
            old_mode,
            "rolled back"
        );
        assert_eq!(
            mock.message_count(),
            before + 1,
            "but the server kept the delta"
        );
        let orphan = (0..100_000)
            .rev()
            .find(|i| mock.get_raw(*i).is_some())
            .unwrap();
        let g = Inode::new_file(new_ino, 1, "notes.txt".into(), 0o644, 1000, 1000);
        fs.journaled_txn(|| fs.store().insert(&g).map_err(|_| libc::EIO))
            .unwrap();
        orphan
    }

    /// The review reproduction: the provider answers the acknowledged delta's id with the
    /// orphan. Recovery must refuse and leave the local DB as it was.
    #[test]
    fn substituted_delta_after_a_withheld_ack_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let head_path = dir.path().join("journal.head");
        {
            let c = Connection::open(&db_path).unwrap();
            initialize_database(&c, &schema()).unwrap();
            let (sc, mk) = (schema(), k(META));
            let st = InodeStore::new(&c, &sc, &mk);
            st.insert(&Inode::root()).unwrap();
            st.insert(&Inode::new_file(
                2,
                1,
                "private.txt".into(),
                0o600,
                1000,
                1000,
            ))
            .unwrap();
        }
        let mock = Arc::new(MockTransport::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let head0 = clean_unmount(&rt, &mock, &db_path, &head_path, 1);
        let orphan = {
            let fs = mount_fs(&db_path, mock.clone(), &rt, &head_path, head0);
            withheld_chmod_then_create(&fs, &mock, 2, 3)
        }; // crash: no unmount snapshot
        let head = JournalHead::load(&head_path, &k(INTEG)).unwrap().unwrap();
        assert_eq!(head.seq, 1);
        // A journal append carries the lineage of the DB's stamp unchanged.
        assert!(head0.lineage.is_some());
        assert_eq!(
            head.lineage, head0.lineage,
            "the append dropped the lineage"
        );
        assert_ne!(orphan, head.parent_msg_id);
        wipe_sidecars(&db_path);
        let local = std::fs::read(&db_path).unwrap();

        let err = recover_serving(&mock, head, &db_path, Some((head.parent_msg_id, orphan)))
            .expect_err("a substituted delta must be refused");
        assert!(err.to_string().contains("hash"), "clear error: {err}");
        assert_eq!(
            std::fs::read(&db_path).unwrap(),
            local,
            "local DB untouched"
        );

        // The honest chain still recovers, with the acknowledged state only.
        recover_serving(&mock, head, &db_path, None).unwrap();
        wipe_sidecars(&db_path);
        assert_eq!(
            mode_of(&db_path, 2),
            Some(0o600),
            "the failed chmod is not applied"
        );
        assert!(
            mode_of(&db_path, 3).is_some(),
            "the acknowledged create is kept"
        );
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/v1-journal-debb93b")
                .join(name),
        )
        .unwrap()
    }

    /// An authentic delta in the format debb93b wrote (`metadata-delta-v1`), as an
    /// old build would have left behind after a withheld acknowledgement.
    fn v1_orphan(seq: u64, base: u64, parent: i64, changeset: &[u8]) -> Vec<u8> {
        let mut pt = vec![];
        pt.extend_from_slice(&seq.to_le_bytes());
        pt.extend_from_slice(&base.to_le_bytes());
        pt.extend_from_slice(&parent.to_le_bytes());
        pt.extend_from_slice(changeset);
        aead::encrypt(&k(DATA), &pt, b"metadata-delta-v1").unwrap()
    }

    /// A journal written by debb93b (fixture: snapshot 99, v1 deltas 100 and 101,
    /// HEAD at seq 2 with the 64-byte MAC) recovers; the current code then keeps
    /// journaling on it, and the chain from there on is bound: substituting the
    /// last old delta or the new one is refused, the honest chain recovers.
    #[test]
    fn journal_written_by_debb93b_recovers_and_new_deltas_bind_it() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let head_path = dir.path().join("journal.head");
        std::fs::write(&head_path, fixture("journal.head")).unwrap();
        let mock = Arc::new(MockTransport::new());
        mock.put_raw(99, fixture("msg-99-snapshot.bin"));
        mock.put_raw(100, fixture("msg-100-delta.bin"));
        mock.put_raw(101, fixture("msg-101-delta.bin"));
        mock.set_next_id(1000);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let old_head = JournalHead::load(&head_path, &k(INTEG))
            .expect("debb93b HEAD MAC verifies")
            .unwrap();
        assert_eq!((old_head.seq, old_head.parent_msg_id), (2, 101));
        assert_eq!(recover_serving(&mock, old_head, &db_path, None).unwrap(), 2);
        wipe_sidecars(&db_path);
        for ino in [1, 2, 3] {
            assert!(
                mode_of(&db_path, ino).is_some(),
                "ino {ino} from the old chain"
            );
        }

        let orphan = {
            let fs = mount_fs(&db_path, mock.clone(), &rt, &head_path, old_head);
            withheld_chmod_then_create(&fs, &mock, 2, 4)
        }; // crash
        let head = JournalHead::load(&head_path, &k(INTEG)).unwrap().unwrap();
        assert_eq!(head.seq, 3);
        wipe_sidecars(&db_path);
        let local = std::fs::read(&db_path).unwrap();

        // New delta (seq 3) answered with the orphan: refused.
        let err = recover_serving(&mock, head, &db_path, Some((head.parent_msg_id, orphan)))
            .expect_err("substituted new delta must be refused");
        assert!(err.to_string().contains("hash"), "{err}");
        assert_eq!(std::fs::read(&db_path).unwrap(), local);

        // Last old delta (101) answered with another authentic v1 seq-2 delta
        // (an empty changeset): refused, because the new delta binds 101's bytes.
        mock.put_raw(5000, v1_orphan(2, 5, 100, &[]));
        let err = recover_serving(&mock, head, &db_path, Some((101, 5000)))
            .expect_err("substituted old delta below a new one must be refused");
        assert!(err.to_string().contains("hash"), "{err}");
        assert_eq!(std::fs::read(&db_path).unwrap(), local);

        // Honest chain: v1, v1, new.
        assert_eq!(recover_serving(&mock, head, &db_path, None).unwrap(), 3);
        wipe_sidecars(&db_path);
        assert_eq!(mode_of(&db_path, 2), Some(0o644));
        assert!(mode_of(&db_path, 4).is_some());
    }
}

#[cfg(test)]
impl CryptFs {
    // Inspect the new durable representation without adding a production body copy.
    fn test_pending_writes(&self) -> std::io::Result<Vec<SdoPendingWrite>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut writes = self
            .sdo_pending_write_store()
            .list()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let root = self.spool_root();
        if !root.exists() {
            return Ok(writes);
        }
        for entry in std::fs::read_dir(root)? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "intent") {
                continue;
            }
            let spool = crate::spool::WriteSpool::load(
                &path,
                self.spool_key().clone(),
                self.manifest_key.as_ref().unwrap(),
            )?;
            let intent = &spool.intent;
            let mut metadata = intent.metadata.clone();
            let mut file = spool.file.try_clone()?;
            file.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            metadata.size = bytes.len() as u64;
            let wire = if let Some(plan) = &intent.plan {
                let mut file = spool.file.try_clone()?;
                file.seek(SeekFrom::Start(0))?;
                let mut reader = plan
                    .clone()
                    .reader(
                        file,
                        self.sdo_meta_key_for_generation(plan.metadata.key_generation)
                            .clone(),
                        self.sdo_object_envelope.as_ref().map(|(_, h)| h.clone()),
                    )
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                let mut wire = Vec::new();
                reader.read_to_end(&mut wire)?;
                Some(wire)
            } else {
                None
            };
            writes.push(SdoPendingWrite {
                version_id: metadata.version_id,
                inode: intent.inode,
                handle_id: intent.handle,
                predecessor: metadata.previous_version_id,
                clock_ms: metadata.clock_ms,
                clock_counter: metadata.clock_counter,
                metadata_snapshot: Some(metadata.encode_snapshot().unwrap()),
                bytes,
                wire,
            });
        }
        Ok(writes)
    }
    fn test_pending_get(&self, id: &uuid::Uuid) -> std::io::Result<Option<SdoPendingWrite>> {
        Ok(self
            .test_pending_writes()?
            .into_iter()
            .find(|p| p.version_id == *id))
    }
}
