//! `TeaGardenDevice` — the async engine core (P1.5 write path, P1.6 read path,
//! flush barrier, seal+upload, discard).
//!
//! The write path is **write-back**: a write chunks its plaintext into records,
//! seals each ([`crate::sector_crypto`]) into the open segment
//! ([`crate::segment::SegmentBuilder`]), durably stages it ([`crate::staging`]),
//! and updates the in-RAM FTL — all locally, no Telegram round-trip. When the open
//! segment reaches the seal threshold (or on `close`) it is sealed and uploaded,
//! then cached as cloud-confirmed. The read path is **cache-first**: it plans the
//! read against the FTL and, per piece, serves read-your-writes from the open
//! segment, then the local cache, then a whole-segment fetch from Telegram.
//!
//! Capacity is enforced up front (`lba + count <= capacity_blocks`) so the FTL
//! only ever sees representable, in-bounds LBAs (per the M2a advisor note).
//!
//! M2b scope: single-writer, whole-segment cold fetch (the P1.14 locality gate
//! and the P1.6/G19 read-consistency snapshot for concurrent readers are later).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use teagarden_blockdev::LOGICAL_BLOCK_SIZE;
use teagarden_core::crypto::kdf;
use teagarden_core::crypto::keys::{KeyHierarchy, SymmetricKey};
use teagarden_telegram::client::BlockTransport;

use crate::cache::{CacheConfig, ScoredCache};
use crate::dirlock::DirLock;
use crate::error::{DeviceError, Result};
use crate::ftl::{Ftl, Phys, Source};
use crate::ftl_log::FtlDelta;
use crate::gc::{self, Candidate, GcConfig, GcReport};
use crate::head::{DeviceHead, HeadExtent};
use crate::segment::{SegmentBuilder, SegmentReader};
use crate::staging::{StagingLog, StagingReader, TailState};
use crate::superblock::Superblock;
use crate::{RECORD_MAX, SEGMENT_TARGET};

const BS: u64 = LOGICAL_BLOCK_SIZE;

/// Catalog sentinel for a garbage-collected segment (P4): the KEY stays (the
/// `cloud_watermark` contiguity scan and `open()`'s "confirmed ⇒ don't re-frame"
/// check both key off catalog membership) but the Telegram message is gone.
/// `0` is never a real message id (Telegram ids start at 1).
const TOMBSTONE_MSG_ID: i64 = 0;

/// Safety bound on the ranged-read heat map (P1.14 gate state): if more
/// segments than this have pending heat, the map is wholesale-cleared (a crude,
/// documented decay — the cost of forgetting is one extra whole-segment
/// promotion delay, never a correctness issue).
const SEG_READ_HITS_MAX: usize = 4096;

/// Scratch file a staging compaction (H4) writes before renaming it over
/// `staging.log`. Only ever a leftover of an interrupted compaction.
const STAGING_COMPACT_TMP: &str = "staging.log.compact";

/// Injected catalog fsync failures. Zero-sized in product builds.
#[derive(Default)]
struct DeviceFaults {
    #[cfg(any(test, feature = "fault-injection"))]
    fail_catalog_syncs: u32,
}

/// Marker that a `recover_from_head` is in progress in this directory. Written
/// (and fsynced) before recovery touches any device file, removed only once
/// the superblock, catalog and seeded staging log are all durable. `open()`
/// refuses a directory that still holds it: a crash mid-recovery must never
/// leave something that opens as a device with a silently partial FTL.
const RECOVERY_MARKER: &str = "recovery.incomplete";

/// The files whose presence means "this directory holds a device".
const DEVICE_FILES: [&str; 4] = ["superblock", "catalog", "staging.log", RECOVERY_MARKER];

/// Compaction floor, in segment targets (H4): below `segment_target × this`
/// the staging log is left alone. 8 × 45 MiB by default.
const STAGING_COMPACT_SEGMENTS: u64 = 8;

/// Per-logical-read locality-gate accounting ([`TeaGardenDevice::read_at`]).
/// `seen` dedupes charges within one read (a segment is charged at most once
/// however many FTL pieces it spans); `earned` holds the charges of pieces that
/// succeeded, committed to the persistent heat map only if the whole read does.
#[derive(Default)]
struct GateCharge {
    seen: HashSet<u64>,
    earned: HashSet<u64>,
}

/// The three symmetric keys the device needs (derived from the volume key
/// hierarchy upstream). `data_key` seals records, `meta_key` seals the segment
/// index + staging deltas, `integrity_key` MACs segments + the superblock.
#[derive(Clone)]
pub struct DeviceKeys {
    /// Seals record plaintext.
    pub data_key: SymmetricKey,
    /// Seals the segment index and staging deltas.
    pub meta_key: SymmetricKey,
    /// Keys the segment footer + superblock MAC.
    pub integrity_key: SymmetricKey,
}

impl DeviceKeys {
    /// Derive the device's three keys from a volume's audited [`KeyHierarchy`] —
    /// **the real key path (A4)**. A serve verb must obtain its keys this way; a
    /// hardcoded/test key must never reach one ("real keys ship or the verb does
    /// not exist").
    ///
    /// Each device key is domain-separated from the filesystem key it descends
    /// from, so the block device's keys are independent of the FUSE layer's even
    /// though both come from the same volume root: recovering one layer's key does
    /// not yield the other's (HKDF one-wayness).
    ///
    /// **These labels are frozen** — they define the on-disk keys of every
    /// TeaGarden block device, so changing one would make existing devices unreadable.
    pub fn from_hierarchy(h: &KeyHierarchy) -> Result<Self> {
        let d = |parent: &SymmetricKey, label: &[u8]| -> Result<SymmetricKey> {
            kdf::hkdf_derive(parent, label)
                .map_err(|e| DeviceError::Crypto(format!("derive device key: {e}")))
        };
        Ok(Self {
            data_key: d(&h.data, b"teagarden.v1:device-data")?,
            meta_key: d(&h.meta, b"teagarden.v1:device-meta")?,
            integrity_key: d(&h.integrity, b"teagarden.v1:device-integrity")?,
        })
    }

    /// The device UUID for a volume, deterministically derived from its hierarchy.
    ///
    /// The UUID must be known **before any superblock exists** — `recover_from_head`
    /// rebuilds a device from the cloud alone and needs it to verify segment AAD —
    /// so *deriving* it rather than storing it makes it durable by construction: the
    /// same volume always yields the same device UUID, on any machine, with no extra
    /// state that could be lost. It is an HKDF output, so publishing it (segment AAD
    /// / superblock) reveals nothing about the root.
    ///
    /// **Frozen** for the same reason as [`Self::from_hierarchy`].
    pub fn device_uuid_for(h: &KeyHierarchy) -> Result<[u8; 16]> {
        let k = kdf::hkdf_derive(&h.root, b"teagarden.v1:device-uuid")
            .map_err(|e| DeviceError::Crypto(format!("derive device uuid: {e}")))?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&k.as_bytes()[..16]);
        Ok(uuid)
    }

    /// Derive the per-epoch data key from the data master (`data_key`). Records
    /// sealed under epoch `E` use this key; a read resolves `E` from the FTL /
    /// segment header and re-derives it — so advancing the epoch (rotation) never
    /// re-encrypts existing data, yet each epoch has an independent key (HKDF-like
    /// one-wayness: one epoch's key does not reveal another's).
    pub fn epoch_data_key(&self, epoch: u32) -> SymmetricKey {
        let mut msg = [0u8; 20];
        msg[..16].copy_from_slice(b"tgdev-epoch-v1\0\0");
        msg[16..].copy_from_slice(&epoch.to_le_bytes());
        SymmetricKey::from_bytes(blake3::keyed_hash(self.data_key.as_bytes(), &msg).into())
    }
}

/// Cold-read policy (P3.1 ranged reads + the P1.14 locality gate).
#[derive(Clone, Copy, Debug)]
pub struct ReadConfig {
    /// Serve cold misses with RANGED fetches (≈ one record per read) instead of
    /// downloading the whole ~45 MiB segment. `false` restores the
    /// unconditional whole-segment behavior.
    pub ranged_reads: bool,
    /// The locality gate: promote a segment to ONE whole-segment fetch + cache
    /// once it has served this many cold ranged LOGICAL reads (a multi-piece
    /// `read_at` charges a segment once, so kernel readahead over a fragmented
    /// region cannot promote in a single request). `0` = never promote.
    /// Ignored when `ranged_reads` is off.
    pub whole_segment_after: u32,
    /// Tail-probe size (bytes) for the index bootstrap. Default 512 KiB — one
    /// aligned GetFile chunk that covers the WORST-CASE index (a hard-cap
    /// segment of single-block records ≈ 393 KiB sealed), so the common case is
    /// exactly one tail fetch; a still-larger (corrupt-claimed) index costs one
    /// exact-size refetch. `download_tail` is EOF-clamped, so segments smaller
    /// than the probe just return the whole (small) blob.
    pub index_tail_probe: u32,
    /// Byte budget for decrypted per-segment indexes kept in RAM (≈ 32 B per
    /// record + fixed overhead per segment; FIFO eviction). `0` disables index
    /// caching (every ranged read re-bootstraps from the tail).
    pub index_cache_budget: u64,
}

impl Default for ReadConfig {
    fn default() -> Self {
        Self {
            ranged_reads: true,
            whole_segment_after: 3,
            index_tail_probe: 512 * 1024,
            index_cache_budget: 32 * 1024 * 1024,
        }
    }
}

/// Device tunables.
#[derive(Clone)]
pub struct DeviceConfig {
    /// Seal + upload the open segment once it reaches this many bytes.
    pub segment_target: u64,
    /// Maximum plaintext bytes per record.
    pub record_max: u64,
    /// Cache policy.
    pub cache: CacheConfig,
    /// Garbage-collection policy (P4).
    pub gc: GcConfig,
    /// Cold-read policy (P3.1/P1.14).
    pub read: ReadConfig,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            segment_target: SEGMENT_TARGET,
            record_max: RECORD_MAX,
            cache: CacheConfig::default(),
            gc: GcConfig::default(),
            read: ReadConfig::default(),
        }
    }
}

struct OpenSegment {
    id: u64,
    /// The key epoch this segment's records are sealed under (fixed at creation,
    /// even if the device epoch later rotates).
    epoch: u32,
    builder: SegmentBuilder,
    /// `record_off -> plaintext` for read-your-writes before the segment seals.
    records: HashMap<u64, Vec<u8>>,
}

/// A staged record recovered from the staging log during [`TeaGardenDevice::open`],
/// carrying everything needed to re-frame it into its original segment.
struct StagedRecord {
    record_off: u64,
    lba: u64,
    count: u64,
    epoch: u32,
    sealed: Vec<u8>,
}

/// The encrypted, position-addressed block device.
pub struct TeaGardenDevice<T: BlockTransport> {
    transport: Arc<T>,
    keys: DeviceKeys,
    device_uuid: [u8; 16],
    capacity_blocks: u64,
    epoch: u32,
    /// Monotonic config-change counter (persisted in the superblock).
    generation: u64,
    /// The device directory holding `superblock`, `catalog`, and `staging.log`.
    dir: std::path::PathBuf,
    config: DeviceConfig,
    ftl: Ftl,
    cache: ScoredCache,
    staging: StagingLog,
    catalog: HashMap<u64, i64>, // segment_id -> confirmed Telegram message_id
    open: Option<OpenSegment>,
    next_segment_id: u64,
    /// Sealed segments whose upload has not yet been confirmed (retry queue).
    pending_upload: Vec<u64>,
    /// Per-session head counter, bumped on each successful `checkpoint`. NOT
    /// persisted across `open()` (resets to 0), so it is not yet durably monotonic
    /// — reserved for the P2.6/P3.2 freshness/pin work that will consume it.
    head_generation: u64,
    /// Message id of the last durably-uploaded `DeviceHead` this session, or
    /// `None`. Advances ONLY after a head upload succeeds. Not persisted across
    /// `open()` (fresh-machine recovery is handed the head id explicitly until
    /// P3.2 pins it).
    last_head_msg_id: Option<i64>,
    /// Watermark of the last head durably published this session — half of the
    /// GC delete gate (P4/I3). `None` after `open()`: nothing is deletable until
    /// a checkpoint has been published that provably no longer references the
    /// victim. Session state; every `checkpoint` recomputes it.
    last_head_watermark: Option<u64>,
    /// Segment ids referenced by that head's prefix extents (the other half of
    /// the delete gate): a victim may die only if the latest published head
    /// holds NO extent pointing into it.
    last_head_seg_refs: HashSet<u64>,
    /// Total logical blocks ever appended to each segment (P4 victim selection:
    /// `dead = total − live`; a segment with no dead bytes is never worth
    /// compacting — that guard is what stops GC re-churning its own output).
    /// Rebuilt from the staging replay on `open()`; seeded conservatively
    /// (total = live) on `recover_from_head`, so pre-recovery dead bytes are
    /// invisible and recovered segments only become victims via NEW overwrites.
    seg_total_blocks: HashMap<u64, u64>,
    /// Decrypted per-segment record indexes for the ranged cold-read path
    /// (P3.1), bounded by `ReadConfig::index_cache_budget` bytes with FIFO
    /// eviction. Session RAM only — rebuilt by one tail fetch per segment.
    index_cache: HashMap<u64, Vec<crate::segment::RecordLoc>>,
    /// FIFO order for `index_cache` eviction.
    index_cache_order: VecDeque<u64>,
    /// Approximate bytes held by `index_cache` (the eviction accounting).
    index_cache_bytes: u64,
    /// Ranged-read heat per segment (the P1.14 locality gate): reaching
    /// `ReadConfig::whole_segment_after` promotes the segment to one
    /// whole-segment fetch + cache. Session RAM; cleared wholesale past
    /// `SEG_READ_HITS_MAX`.
    seg_read_hits: HashMap<u64, u32>,
    /// Test-only fault hooks (zero-sized unless `cfg(test)` / `fault-injection`).
    #[cfg_attr(not(any(test, feature = "fault-injection")), allow(dead_code))]
    faults: DeviceFaults,
    /// STICKY durability failure: set when a staging or catalog fsync (or a
    /// catalog append) fails. From then on every write / discard / flush /
    /// close / checkpoint / gc / config change fails until the device is
    /// reopened — after a failed fsync the kernel may report a LATER fsync as
    /// successful although the earlier data never reached disk, so nothing
    /// after the failure may be acknowledged. Reads stay available.
    failed: Option<String>,
    /// Exclusive lock on `dir` for this device's lifetime: a second opener of
    /// a live device is refused (see [`crate::dirlock`]).
    _dir_lock: DirLock,
    /// Staging-log length right after the last compaction attempt (H4) — the
    /// hysteresis base for [`Self::maybe_compact_staging`]. Session RAM.
    staging_compacted_len: u64,
}

impl<T: BlockTransport> TeaGardenDevice<T> {
    /// Create a fresh device rooted at `dir`. The directory holds the sealed
    /// `superblock`, the confirmed-upload `catalog`, and the durable `staging.log`.
    /// Reopening (recovering) an existing device is [`Self::open`].
    pub fn create(
        transport: Arc<T>,
        keys: DeviceKeys,
        device_uuid: [u8; 16],
        capacity_blocks: u64,
        dir: impl AsRef<Path>,
        config: DeviceConfig,
    ) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let dir_lock = DirLock::acquire(&dir)?;
        // Never format over an existing device (or a half-done recovery):
        // `StagingLog::create` truncates and the superblock is replaced.
        if let Some(found) = DEVICE_FILES.iter().find(|f| dir.join(f).exists()) {
            return Err(DeviceError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to create a device in {}: it already holds one ({found} \
                     present). Open it instead, or move it aside first",
                    dir.display()
                ),
            )));
        }
        let staging =
            StagingLog::create(dir.join("staging.log"), keys.meta_key.clone(), device_uuid)?;
        let cache = ScoredCache::new(config.cache);
        let dev = Self {
            transport,
            keys,
            device_uuid,
            capacity_blocks,
            epoch: 0,
            generation: 0,
            dir,
            config,
            ftl: Ftl::new(),
            cache,
            staging,
            catalog: HashMap::new(),
            open: None,
            next_segment_id: 1,
            pending_upload: Vec::new(),
            head_generation: 0,
            last_head_msg_id: None,
            last_head_watermark: None,
            last_head_seg_refs: HashSet::new(),
            seg_total_blocks: HashMap::new(),
            index_cache: HashMap::new(),
            index_cache_order: VecDeque::new(),
            index_cache_bytes: 0,
            seg_read_hits: HashMap::new(),
            staging_compacted_len: 0,
            _dir_lock: dir_lock,
            faults: DeviceFaults::default(),
            failed: None,
        };
        dev.persist_superblock()?;
        Ok(dev)
    }

    /// Open (recover) an existing device rooted at `dir`, reconstructing the exact
    /// pre-crash state. The sealed superblock supplies identity/capacity/epoch, the
    /// catalog supplies the cloud-confirmed segments, and replaying the staging log
    /// rebuilds the FTL plus any UNCONFIRMED segment — re-framed from its durable
    /// sealed records and re-queued for upload. Recovery is **idempotent**:
    /// reopening twice yields the identical FTL. A torn staging tail (crash
    /// mid-append) recovers the durable **prefix**, not an error.
    pub fn open(
        transport: Arc<T>,
        keys: DeviceKeys,
        dir: impl AsRef<Path>,
        config: DeviceConfig,
    ) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        // 0) Single writer: refuse while another opener holds the directory —
        //    the trim in step 5 is only safe if nobody else is appending.
        let dir_lock = DirLock::acquire(&dir)?;
        if dir.join(RECOVERY_MARKER).exists() {
            return Err(DeviceError::Corruption(format!(
                "incomplete recovery in {}: a recover_from_head into this directory did \
                 not finish, so its device files may be partial. Rerun the recovery \
                 (recover_from_head_force, or move the directory aside and run \
                 `teagarden dev recover` again)",
                dir.display()
            )));
        }
        // A torn trailing catalog record (pre-fix short write) must go before
        // anything appends behind it.
        Self::repair_catalog_tail(&dir)?;

        // 1) Sealed superblock → identity / capacity / epoch / generation. Fails
        //    closed on a forged or torn superblock. An OLDER authentic superblock
        //    is accepted: nothing anchors `generation` externally (M4).
        let sb_blob = std::fs::read(dir.join("superblock"))?;
        let sb = Superblock::open(&sb_blob, &keys.integrity_key)?;

        // 2) Catalog → the cloud-confirmed segments (the confirmation authority).
        let catalog = Self::load_catalog(&dir)?;

        // A compaction interrupted before its rename leaves its scratch file
        // behind; the live log is still the old, complete one (H4).
        let _ = std::fs::remove_file(dir.join(STAGING_COMPACT_TMP));

        // 3) Stream the staging log → exact FTL + staged records (torn-tail-tolerant,
        //    AEAD-authenticated). The recoverable point is a durable prefix. Only
        //    records of segments NOT in the catalog are held in memory — those are
        //    the ones re-framed below; a confirmed segment's bytes are on the cloud.
        let log_path = dir.join("staging.log");
        let mut ftl = Ftl::new();
        let mut reader = StagingReader::open(&log_path, &keys.meta_key, sb.device_uuid)?;

        // 4) Group staged Map records by segment, preserving append order (which is
        //    record_off order within a segment), so unconfirmed segments can be
        //    re-framed byte-for-byte with their original offsets.
        let mut by_seg: BTreeMap<u64, Vec<StagedRecord>> = BTreeMap::new();
        let mut max_seg = 0u64;
        let mut seg_total_blocks: HashMap<u64, u64> = HashMap::new();
        let unconfirmed = |d: &FtlDelta| match d {
            FtlDelta::Map { phys, .. } | FtlDelta::Relocate { phys, .. } => {
                !catalog.contains_key(&phys.segment_id)
            }
            FtlDelta::Unmap { .. } => false,
        };
        while let Some(entry) = reader.next_entry(unconfirmed)? {
            entry.delta.apply(&mut ftl);
            // GC relocations (P4) carry re-sealed record bytes exactly like
            // writes do — an unconfirmed compaction segment is reconstructed
            // and re-uploaded the same way as an unconfirmed write segment.
            if let FtlDelta::Map { lba, count, phys } | FtlDelta::Relocate { lba, count, phys } =
                entry.delta
            {
                max_seg = max_seg.max(phys.segment_id);
                *seg_total_blocks.entry(phys.segment_id).or_insert(0) += count;
                if catalog.contains_key(&phys.segment_id) {
                    continue; // cloud-durable: not re-framed, bytes not kept
                }
                by_seg
                    .entry(phys.segment_id)
                    .or_default()
                    .push(StagedRecord {
                        record_off: phys.record_off,
                        lba,
                        count,
                        epoch: phys.epoch,
                        sealed: entry.sealed_record,
                    });
            }
        }
        let (valid_len, tail) = (
            reader.valid_len(),
            reader.tail_state().unwrap_or(TailState::Clean),
        );
        drop(reader);
        for &seg_id in catalog.keys() {
            max_seg = max_seg.max(seg_id);
        }

        // A fresh segment id must be strictly above every id ever used, or the
        // anti-substitution header check could be defeated by id reuse. Fail closed
        // if the space is exhausted rather than wrapping/reusing.
        let next_segment_id = max_seg.checked_add(1).ok_or_else(|| {
            DeviceError::Corruption("segment id space exhausted at recovery".into())
        })?;

        // 5) Reopen the staging log for APPEND — NOT create (which truncates and
        //    would silently discard every recovered record) — and FIRST trim any
        //    torn tail past the valid prefix (fsynced). Appending behind a tear
        //    would hide every new write from the next replay (C1).
        let staging = StagingLog::open_append_trimmed(
            &log_path,
            keys.meta_key.clone(),
            sb.device_uuid,
            valid_len,
            tail,
        )?;

        let mut cache = ScoredCache::new(config.cache);
        let mut pending_upload = Vec::new();

        // 6) Reconstruct every UNCONFIRMED segment from its staged sealed records.
        //    A segment already in the catalog is cloud-durable — the read path
        //    downloads it, so it is not rebuilt here.
        for (seg_id, recs) in by_seg {
            if catalog.contains_key(&seg_id) {
                continue;
            }
            let epoch = recs[0].epoch;
            let mut builder =
                SegmentBuilder::new(seg_id, sb.device_uuid, epoch, keys.epoch_data_key(epoch));
            for r in &recs {
                if r.epoch != epoch {
                    return Err(DeviceError::Corruption(format!(
                        "segment {seg_id} mixes epochs {epoch} and {} in staging",
                        r.epoch
                    )));
                }
                let off = builder.append_sealed_record(r.lba, r.count, &r.sealed)?;
                if off != r.record_off {
                    return Err(DeviceError::Corruption(format!(
                        "segment {seg_id} reconstructed record_off {off} != staged {}",
                        r.record_off
                    )));
                }
            }
            let blob = builder.seal(
                &keys.meta_key,
                &keys.integrity_key,
                Some(config.segment_target),
            )?;
            // Staged: readable now, never evicted, counts to backpressure, and
            // queued for (re)upload on the next drain/close.
            cache.insert(seg_id, blob, true);
            pending_upload.push(seg_id);
        }

        Ok(Self {
            transport,
            keys,
            device_uuid: sb.device_uuid,
            capacity_blocks: sb.capacity_blocks,
            epoch: sb.current_epoch,
            generation: sb.generation,
            dir,
            config,
            ftl,
            cache,
            staging,
            catalog,
            open: None,
            next_segment_id,
            pending_upload,
            head_generation: 0,
            last_head_msg_id: None,
            last_head_watermark: None,
            last_head_seg_refs: HashSet::new(),
            seg_total_blocks,
            index_cache: HashMap::new(),
            index_cache_order: VecDeque::new(),
            index_cache_bytes: 0,
            seg_read_hits: HashMap::new(),
            staging_compacted_len: 0,
            _dir_lock: dir_lock,
            faults: DeviceFaults::default(),
            failed: None,
        })
    }

    /// Serialize + atomically persist a sealed superblock with the given fields.
    /// Kept separate from the live fields so a config change (rotate/resize) can
    /// persist the *candidate* superblock BEFORE committing it in RAM — a persist
    /// error then leaves the device exactly as it was (no runtime/recovery drift).
    fn write_superblock(
        &self,
        capacity_blocks: u64,
        current_epoch: u32,
        generation: u64,
    ) -> Result<()> {
        let sb = Superblock {
            device_uuid: self.device_uuid,
            capacity_blocks,
            current_epoch,
            generation,
        };
        write_atomic(&self.dir, "superblock", &sb.seal(&self.keys.integrity_key))
    }

    /// Persist the current live superblock fields (used at `create`).
    fn persist_superblock(&self) -> Result<()> {
        self.write_superblock(self.capacity_blocks, self.epoch, self.generation)
    }

    /// Durably append a `(segment_id, message_id)` confirmation to `dir/catalog`.
    ///
    /// A segment counts as confirmed only once this returns `Ok`. On ANY
    /// failure (short write, ENOSPC, failed fsync) the file is cut back to its
    /// previous length — a partial 16-byte record would misalign every later
    /// record — and the device goes sticky-failed (see `failed`).
    fn append_catalog(&mut self, seg_id: u64, message_id: i64) -> Result<()> {
        self.ensure_healthy()?;
        let res = self.append_catalog_inner(seg_id, message_id);
        if let Err(e) = &res {
            self.fail_sticky(e);
        }
        res
    }

    fn append_catalog_inner(&mut self, seg_id: u64, message_id: i64) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("catalog"))?;
        let prev = f.metadata()?.len();
        let mut rec = [0u8; 16];
        rec[..8].copy_from_slice(&seg_id.to_le_bytes());
        rec[8..].copy_from_slice(&message_id.to_le_bytes());
        let written = f.write_all(&rec).and_then(|()| {
            #[cfg(any(test, feature = "fault-injection"))]
            if self.faults.fail_catalog_syncs > 0 {
                self.faults.fail_catalog_syncs -= 1;
                return Err(std::io::Error::other("injected fsync failure (catalog)"));
            }
            f.sync_all()
        });
        if let Err(e) = written {
            // best effort: do not leave a record we are reporting as failed,
            // nor a partial one (open() also trims a partial tail)
            let _ = f.set_len(prev).and_then(|()| f.sync_all());
            return Err(e.into());
        }
        Ok(())
    }

    /// `Err` if the device is sticky-failed (see `failed`).
    fn ensure_healthy(&self) -> Result<()> {
        match &self.failed {
            None => Ok(()),
            Some(why) => Err(DeviceError::Io(std::io::Error::other(format!(
                "device is failed after an earlier durability error ({why}); \
                 nothing further can be acknowledged — reopen the device"
            )))),
        }
    }

    /// Enter the sticky-failed state (first error wins).
    fn fail_sticky(&mut self, e: &DeviceError) {
        if self.failed.is_none() {
            tracing::error!(error = %e, "teagarden-dev: durability failure; device is now failed until reopen");
            self.failed = Some(e.to_string());
        }
    }

    /// fsync the staging log; a failure makes the device sticky-failed.
    fn staging_flush(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        let res = self.staging.flush();
        if let Err(e) = &res {
            self.fail_sticky(e);
        }
        res
    }

    /// Cut a torn trailing partial record off `dir/catalog` (fsynced), so a
    /// later append can never land misaligned behind it. Catalogs written by
    /// pre-fix binaries can carry one after a short write.
    fn repair_catalog_tail(dir: &Path) -> Result<()> {
        let path = dir.join("catalog");
        let f = match OpenOptions::new().write(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let len = f.metadata()?.len();
        if len % 16 != 0 {
            tracing::warn!(
                discarded = len % 16,
                "catalog: trimming a torn partial record (its segment re-uploads)"
            );
            f.set_len(len - len % 16)?;
            f.sync_all()?;
        }
        Ok(())
    }

    /// TEST-ONLY (`fault-injection`): make the next `staging` staging-log
    /// fsyncs and the next `catalog` catalog fsyncs fail without syncing.
    #[cfg(any(test, feature = "fault-injection"))]
    pub fn inject_fsync_failures(&mut self, staging: u32, catalog: u32) {
        self.staging.inject_sync_failures(staging);
        self.faults.fail_catalog_syncs = catalog;
    }

    /// Load `dir/catalog` into `segment_id → message_id`. A trailing partial
    /// record (a torn append) is ignored — that segment is treated as unconfirmed
    /// and reconstructed/re-uploaded, never mis-parsed.
    fn load_catalog(dir: &Path) -> Result<HashMap<u64, i64>> {
        let mut map = HashMap::new();
        let data = match std::fs::read(dir.join("catalog")) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(map),
            Err(e) => return Err(e.into()),
        };
        let (records, _) = data.as_chunks::<16>();
        for rec in records {
            let seg = u64::from_le_bytes(rec[..8].try_into().unwrap());
            let mid = i64::from_le_bytes(rec[8..16].try_into().unwrap());
            map.insert(seg, mid);
        }
        Ok(map)
    }

    /// Capacity in logical blocks.
    pub fn capacity_blocks(&self) -> u64 {
        self.capacity_blocks
    }

    fn oob(&self, lba: u64, count: u64) -> DeviceError {
        DeviceError::OutOfRange {
            lba,
            count: u32::try_from(count).unwrap_or(u32::MAX),
            capacity_blocks: self.capacity_blocks,
        }
    }

    fn bounds_ok(&self, lba: u64, count: u64) -> Result<()> {
        match lba.checked_add(count) {
            Some(end) if end <= self.capacity_blocks => Ok(()),
            _ => Err(self.oob(lba, count)),
        }
    }

    /// Write `data` (a non-empty multiple of the block size) starting at `lba`.
    pub async fn write_at(&mut self, lba: u64, data: &[u8]) -> Result<()> {
        self.ensure_healthy()?;
        if data.is_empty() || !data.len().is_multiple_of(BS as usize) {
            return Err(DeviceError::Corruption(
                "write must be a non-empty multiple of the block size".into(),
            ));
        }
        let count = data.len() as u64 / BS;
        self.bounds_ok(lba, count)?;
        if self.cache.under_backpressure() {
            return Err(DeviceError::StagingFull);
        }

        let max_blocks = (self.config.record_max / BS).max(1);
        let mut done = 0u64;
        while done < count {
            let chunk = (count - done).min(max_blocks);
            let s = (done * BS) as usize;
            let e = ((done + chunk) * BS) as usize;
            self.write_record(lba + done, chunk, &data[s..e], false)
                .await?;
            done += chunk;
            // Seal mid-write once the open segment reaches the target — a large
            // write may span several segments.
            if self
                .open
                .as_ref()
                .is_some_and(|o| o.builder.current_len() >= self.config.segment_target)
            {
                self.seal_open().await?;
            }
        }
        Ok(())
    }

    /// Seal one record of `plaintext` into the open segment (allocating one if
    /// needed), durably stage its delta + sealed bytes, then update the FTL.
    /// `relocate = true` marks a GC compaction move (P4): identical mechanics,
    /// but staged as [`FtlDelta::Relocate`] so the barrier-consistent prefix
    /// replay can tell "data moved" from "data written" (see
    /// [`Self::replay_prefix_ftl`]).
    async fn write_record(
        &mut self,
        lba: u64,
        count: u64,
        plaintext: &[u8],
        relocate: bool,
    ) -> Result<()> {
        // Remembered so a record that cannot be staged leaves NO trace (M5).
        let created_segment = self.open.is_none();
        let prev_next_segment_id = self.next_segment_id;
        if created_segment {
            let id = self.next_segment_id;
            // Fail closed rather than wrap/reuse an id (see recovery + the
            // anti-substitution header check): a reused segment_id would let an old
            // FTL mapping read a newer segment's record undetected.
            self.next_segment_id = id
                .checked_add(1)
                .ok_or_else(|| DeviceError::Corruption("segment id space exhausted".into()))?;
            let epoch = self.epoch;
            self.open = Some(OpenSegment {
                id,
                epoch,
                builder: SegmentBuilder::new(
                    id,
                    self.device_uuid,
                    epoch,
                    self.keys.epoch_data_key(epoch),
                ),
                records: HashMap::new(),
            });
        }
        let undo_segment = |dev: &mut Self| {
            if created_segment {
                dev.open = None;
                dev.next_segment_id = prev_next_segment_id;
            }
        };
        let (seg_id, seg_epoch) = {
            let o = self.open.as_ref().unwrap();
            (o.id, o.epoch)
        };
        let appended = self
            .open
            .as_mut()
            .unwrap()
            .builder
            .append_record(lba, count, plaintext);
        let (record_off, sealed) = match appended {
            Ok(x) => x,
            Err(e) => {
                undo_segment(self);
                return Err(e);
            }
        };
        let phys = Phys {
            segment_id: seg_id,
            record_off,
            data_off: 0,
            epoch: seg_epoch,
        };
        let delta = if relocate {
            FtlDelta::Relocate { lba, count, phys }
        } else {
            FtlDelta::Map { lba, count, phys }
        };
        // Durably stage the (delta, sealed record) BEFORE anything else observes
        // the record. If staging fails the record is rolled back out of the
        // segment builder, so the builder's offsets stay exactly the ones the
        // staging log holds — recovery re-frames them byte-for-byte (M5).
        if let Err(e) = self.staging.append(&delta, &sealed) {
            self.open
                .as_mut()
                .unwrap()
                .builder
                .rollback_record(record_off)?;
            undo_segment(self);
            return Err(e);
        }
        self.open
            .as_mut()
            .unwrap()
            .records
            .insert(record_off, plaintext.to_vec());
        self.ftl.map_range(lba, count, phys);
        *self.seg_total_blocks.entry(seg_id).or_insert(0) += count;
        Ok(())
    }

    async fn seal_open(&mut self) -> Result<()> {
        let Some(o) = self.open.take() else {
            return Ok(());
        };
        let seg_id = o.id;
        // Pad the sealed segment up to the segment target, so every uploaded
        // segment has the same size and its length does not show how much data a
        // segment sealed early (by a flush or close) holds.
        let blob = o.builder.seal(
            &self.keys.meta_key,
            &self.keys.integrity_key,
            Some(self.config.segment_target),
        )?;
        // Cache the sealed segment as STAGED first: it is now readable (reads for
        // seg_id resolve via the cache), never evicted, and counted toward
        // backpressure until its upload is CONFIRMED. If the upload then fails the
        // data is NOT lost — it stays cached + staging-durable + queued for retry.
        self.cache.insert(seg_id, blob, true);
        self.try_upload(seg_id).await
    }

    /// Best-effort upload of a sealed, staged segment. On success it is recorded
    /// in the catalog and marked cloud-confirmed (evictable); on failure it stays
    /// staged (readable + durable) and queued for a later retry (`drain_uploads`).
    ///
    /// A transport failure is not an error (the segment is queued). A failed
    /// CATALOG write is: the segment is NOT confirmed (it stays staged and
    /// queued), the device goes sticky-failed, and the error propagates — a
    /// segment never counts as confirmed unless its catalog entry is durable.
    async fn try_upload(&mut self, seg_id: u64) -> Result<()> {
        let Some(blob) = self.cache.get(seg_id) else {
            return Ok(());
        };
        let uploaded = self
            .transport
            .upload_block(&blob, &random_upload_name())
            .await;
        if let Ok(up) = &uploaded {
            if let Err(e) = self.append_catalog(seg_id, up.message_id) {
                if !self.pending_upload.contains(&seg_id) {
                    self.pending_upload.push(seg_id);
                }
                return Err(e);
            }
        }
        match uploaded {
            Ok(up) => {
                self.catalog.insert(seg_id, up.message_id);
                self.cache.mark_confirmed(seg_id);
                self.pending_upload.retain(|&s| s != seg_id);
            }
            Err(_) => {
                if !self.pending_upload.contains(&seg_id) {
                    self.pending_upload.push(seg_id);
                }
            }
        }
        Ok(())
    }

    /// Retry every pending (sealed-but-unuploaded) segment. Surfaces a persistent
    /// upload failure as an error so `close` fails loudly rather than silently
    /// leaving data non-offsite-durable.
    pub async fn drain_uploads(&mut self) -> Result<()> {
        for seg_id in self.pending_upload.clone() {
            let blob = self.cache.get(seg_id).ok_or_else(|| {
                DeviceError::Corruption("pending segment missing from cache".into())
            })?;
            let up = self
                .transport
                .upload_block(&blob, &random_upload_name())
                .await
                .map_err(|e| DeviceError::Transport(e.to_string()))?;
            // Confirmed only once the catalog entry is durable.
            self.append_catalog(seg_id, up.message_id)?;
            self.catalog.insert(seg_id, up.message_id);
            self.cache.mark_confirmed(seg_id);
            self.pending_upload.retain(|&s| s != seg_id);
        }
        Ok(())
    }

    /// Read `count` blocks starting at `lba`, zero-filling any unmapped holes.
    pub async fn read_at(&mut self, lba: u64, count: u64) -> Result<Vec<u8>> {
        self.bounds_ok(lba, count)?;
        let total = checked_bytes(count)?;
        let mut out = vec![0u8; total];
        // Locality-gate accounting for THIS logical read: `seen` dedupes so a
        // segment is charged at most once however many FTL pieces it resolves
        // into (advisor C2), and `earned` accumulates the charges of pieces that
        // completed successfully. Heat is committed to `seg_read_hits` only after
        // the WHOLE logical read succeeds (Codex P3.1 FIX-1): a fragmented read
        // whose first piece succeeds but a later piece fails must NOT creep the
        // first segment toward a whole-segment promotion — the read failed.
        let mut gate = GateCharge::default();
        let result = async {
            for pc in self.ftl.resolve_read(lba, count) {
                if let Source::Mapped(phys) = pc.source {
                    let data = self.read_mapped(&phys, pc.count, Some(&mut gate)).await?;
                    let dst = checked_bytes(pc.lba - lba)?;
                    out[dst..dst + data.len()].copy_from_slice(&data);
                }
                // Source::Hole → leave the zero fill in place
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                for seg in gate.earned {
                    *self.seg_read_hits.entry(seg).or_insert(0) += 1;
                }
                Ok(out)
            }
            Err(e) => Err(e), // pending charges dropped — the read did not complete
        }
    }

    /// `gate`: `Some(g)` = a foreground read participating in the P1.14 locality
    /// gate; `None` = a caller that manages its own fetch strategy (GC
    /// compaction) — never bumps heat, never promotes. Charges earned here are
    /// recorded in `g.earned` and committed by [`Self::read_at`] only if the
    /// whole logical read succeeds.
    ///
    /// Ranged-path errors PROPAGATE — there is deliberately NO silent fallback
    /// to a whole-segment download (a G17-shaped hole that would mask transport
    /// failures with ~45 MiB pulls). Only `ReadConfig::ranged_reads = false`
    /// selects the whole-segment path.
    async fn read_mapped(
        &mut self,
        phys: &Phys,
        count: u64,
        mut gate: Option<&mut GateCharge>,
    ) -> Result<Vec<u8>> {
        let want = checked_bytes(count)?;
        let off = phys.data_off as usize;

        // 1) read-your-writes: still in the open segment
        if let Some(o) = &self.open {
            if o.id == phys.segment_id {
                let pt = o
                    .records
                    .get(&phys.record_off)
                    .ok_or_else(|| DeviceError::Corruption("RYW record missing".into()))?;
                return slice_record(pt, off, want);
            }
        }

        // 2) a locally-held blob: staged (unconfirmed) or previously fetched whole
        if let Some(blob) = self.cache.get(phys.segment_id) {
            return self.read_from_blob(&blob, phys, off, want);
        }

        // 3) cold: resolve the message id; tombstone dereference fails loudly.
        //    The GC delete gate (P4/I3) guarantees no FTL extent references a
        //    tombstoned segment — hitting one means a corrupt FTL or a bug.
        let mid = *self
            .catalog
            .get(&phys.segment_id)
            .ok_or_else(|| DeviceError::Corruption("segment not in catalog".into()))?;
        if mid == TOMBSTONE_MSG_ID {
            return Err(DeviceError::Corruption(format!(
                "segment {} was garbage-collected but the FTL still references it",
                phys.segment_id
            )));
        }

        // 4) the P1.14 locality gate: a segment that keeps serving cold ranged
        //    LOGICAL reads is promoted to ONE whole-segment fetch + cache (after
        //    which reads are local); a lone random read never pulls the whole
        //    ~45 MiB (TC-INT-5). With ranged reads disabled, every cold miss is
        //    a whole-segment fetch (the M2b behavior).
        let mut charge = false;
        let promote = if !self.config.read.ranged_reads {
            true
        } else if let Some(g) = gate.as_deref_mut() {
            // crude, documented decay: wholesale-clear rather than grow without
            // bound; the worst case is one delayed promotion
            if self.seg_read_hits.len() > SEG_READ_HITS_MAX {
                self.seg_read_hits.clear();
            }
            charge = g.seen.insert(phys.segment_id);
            let committed = self
                .seg_read_hits
                .get(&phys.segment_id)
                .copied()
                .unwrap_or(0);
            // effective heat = committed + this logical read's single pending
            // charge (whether earned on an earlier piece or being earned now)
            let bump = charge || g.earned.contains(&phys.segment_id);
            let after = self.config.read.whole_segment_after;
            after > 0 && committed + u32::from(bump) >= after
        } else {
            false // gate-exempt caller (GC compaction)
        };
        if promote {
            self.seg_read_hits.remove(&phys.segment_id);
            if let Some(g) = gate.as_deref_mut() {
                g.earned.remove(&phys.segment_id); // now warm — no pending charge
            }
            let dl = self
                .transport
                .download_block(mid)
                .await
                .map_err(|e| DeviceError::Transport(e.to_string()))?;
            self.cache.insert(phys.segment_id, dl.data.clone(), false);
            return self.read_from_blob(&dl.data, phys, off, want);
        }

        // 5) ranged cold read (P3.1): index bootstrap → one record fetch. Record
        //    the pending charge only on SUCCESS; read_at commits it only if the
        //    whole logical read then succeeds.
        let result = self.read_ranged(mid, phys, off, want).await;
        if result.is_ok() && charge {
            if let Some(g) = gate {
                g.earned.insert(phys.segment_id);
            }
        }
        result
    }

    /// Serve a read from a whole segment blob (cached or just fetched): verify
    /// the MAC + header, bind the segment to what the FTL asked for, and decrypt
    /// the one record. The header is MAC-authenticated, so a swapped catalog
    /// entry (recovery makes the catalog load-bearing) or a wrong transport
    /// reply — a different but validly-MAC'd segment under the same integrity
    /// key — is rejected instead of returning its bytes as THIS LBA's data.
    /// `carve`/`resolve_read` preserve `segment_id`/`epoch` on splits, so this
    /// never false-fires on survivors.
    fn read_from_blob(&self, blob: &[u8], phys: &Phys, off: usize, want: usize) -> Result<Vec<u8>> {
        let reader = SegmentReader::open(blob, &self.keys.meta_key, &self.keys.integrity_key)?;
        let h = reader.header();
        if h.segment_id != phys.segment_id
            || h.epoch != phys.epoch
            || h.device_uuid != self.device_uuid
        {
            return Err(DeviceError::Corruption(format!(
                "segment header mismatch: got seg {} epoch {} but the FTL expected seg {} epoch {}",
                h.segment_id, h.epoch, phys.segment_id, phys.epoch
            )));
        }
        let index = reader.index(&self.keys.meta_key)?;
        let loc = index
            .iter()
            .find(|l| l.record_off == phys.record_off)
            .ok_or_else(|| DeviceError::Corruption("record_off not in segment index".into()))?;
        // Resolve the record's epoch from the segment header and re-derive its
        // data key — records written under an older epoch stay readable after a
        // rotation without any re-encryption.
        let dk = self.keys.epoch_data_key(reader.header().epoch);
        let pt = reader.read_record(loc, &dk)?;
        slice_record(&pt, off, want)
    }

    /// Cold ranged read (P3.1): fetch ≈ one record instead of the whole segment.
    ///
    /// Integrity on this path (see the segment-module docs): the whole-blob MAC
    /// cannot be verified without the whole blob, so the chain is trailer
    /// (position-fixed, sealed) → index (AAD binds the EXPECTED segment_id ‖
    /// epoch ‖ device_uuid from the FTL/device — a wrong segment's tail fails
    /// closed) → record (position AAD is the anti-substitution authority; a
    /// short, tampered, or relocated fetch fails closed). Errors only — never
    /// wrong plaintext.
    async fn read_ranged(
        &mut self,
        mid: i64,
        phys: &Phys,
        off: usize,
        want: usize,
    ) -> Result<Vec<u8>> {
        let seg = phys.segment_id;
        // index: cached, else bootstrap from the document tail
        let loc = match self.index_cache.get(&seg) {
            Some(locs) => locs
                .iter()
                .find(|l| l.record_off == phys.record_off)
                .copied(),
            None => {
                let locs = self.fetch_index_ranged(mid, seg, phys.epoch).await?;
                let loc = locs
                    .iter()
                    .find(|l| l.record_off == phys.record_off)
                    .copied();
                self.index_cache_insert(seg, locs);
                loc
            }
        }
        .ok_or_else(|| DeviceError::Corruption("record_off not in segment index".into()))?;

        // one ranged fetch of exactly the sealed record
        let sealed_len = loc
            .plain_len
            .checked_add(crate::sector_crypto::RECORD_OVERHEAD as u64)
            .and_then(|l| u32::try_from(l).ok())
            .ok_or_else(|| DeviceError::Corruption("record length overflow".into()))?;
        let sealed = self
            .transport
            .download_range(mid, loc.record_off, sealed_len)
            .await
            .map_err(|e| DeviceError::Transport(e.to_string()))?;
        let pt = crate::segment::open_record_ranged(
            &sealed,
            &self.keys.epoch_data_key(phys.epoch),
            self.device_uuid,
            phys.epoch,
            seg,
            &loc,
        )?;
        slice_record(&pt, off, want)
    }

    /// Bootstrap a segment's (decrypted) record index from its document tail,
    /// without knowing the document size: the tail is `…‖index‖trailer‖MAC`
    /// with the fixed-size trailer/MAC at the end and the index ending exactly
    /// at the trailer start, so everything parses relative to the buffer end.
    /// If the index is larger than the probe, exactly one exact-size refetch
    /// follows (`trailer+MAC+index_len` tail bytes).
    async fn fetch_index_ranged(
        &mut self,
        mid: i64,
        seg: u64,
        epoch: u32,
    ) -> Result<Vec<crate::segment::RecordLoc>> {
        use crate::segment::{MAC_LEN, TRAILER_LEN};
        let fixed = TRAILER_LEN + MAC_LEN;
        let probe = self.config.read.index_tail_probe.max(fixed as u32);
        let tail = self
            .transport
            .download_tail(mid, probe)
            .await
            .map_err(|e| DeviceError::Transport(e.to_string()))?;
        if tail.len() < fixed {
            return Err(DeviceError::Corruption(
                "segment tail shorter than trailer+MAC".into(),
            ));
        }
        let trl_start = tail.len() - fixed;
        let (_index_off, index_len) = crate::segment::open_trailer_ranged(
            &tail[trl_start..tail.len() - MAC_LEN],
            &self.keys.meta_key,
        )?;
        let index_len = index_len as usize;
        // an index cannot be larger than the biggest possible segment
        if index_len as u64 > crate::SEGMENT_HARD_CAP {
            return Err(DeviceError::Corruption(
                "segment trailer claims an impossible index length".into(),
            ));
        }
        let index_ct: Vec<u8> = if index_len <= trl_start {
            tail[trl_start - index_len..trl_start].to_vec()
        } else {
            // probe missed — refetch exactly index+trailer+MAC from the tail
            let need = index_len
                .checked_add(fixed)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| DeviceError::Corruption("index refetch length overflow".into()))?;
            let t2 = self
                .transport
                .download_tail(mid, need)
                .await
                .map_err(|e| DeviceError::Transport(e.to_string()))?;
            if t2.len() < need as usize {
                // the document is smaller than its own trailer claims → corrupt
                return Err(DeviceError::Corruption(
                    "segment shorter than its trailer-declared index".into(),
                ));
            }
            // RE-PARSE the trailer from the refetched buffer — never mix the
            // probe buffer's index_len with the refetch's bytes (a transport
            // alternating answers is denial-only either way, but only if the
            // slice comes from a self-consistent buffer; advisor A2).
            let s2 = t2.len() - fixed;
            let (_off2, len2) = crate::segment::open_trailer_ranged(
                &t2[s2..t2.len() - MAC_LEN],
                &self.keys.meta_key,
            )?;
            let len2 = len2 as usize;
            if len2 > s2 {
                return Err(DeviceError::Corruption(
                    "segment tail inconsistent across fetches".into(),
                ));
            }
            t2[s2 - len2..s2].to_vec()
        };
        crate::segment::open_index_ranged(
            &index_ct,
            &self.keys.meta_key,
            seg,
            epoch,
            self.device_uuid,
        )
        .map_err(|e| {
            // Classify like the whole-path header check: an index that fails to
            // authenticate under the EXPECTED identity means the transport served
            // some other segment's bytes (swapped catalog entry / substitution) —
            // a corruption-class event, not a key problem.
            DeviceError::Corruption(format!(
                "segment {seg} tail failed to authenticate as seg {seg} epoch {epoch} \
                 (swapped catalog entry or substituted segment?): {e}"
            ))
        })
    }

    /// Approximate RAM cost of one cached index (accounting unit for the
    /// byte-budgeted index cache): 32 B per `RecordLoc` + fixed map overhead.
    fn index_entry_cost(locs: &[crate::segment::RecordLoc]) -> u64 {
        (locs.len() as u64) * 32 + 64
    }

    /// Insert a decrypted index into the BYTE-budgeted per-segment cache
    /// (`ReadConfig::index_cache_budget`; FIFO eviction — indexes are cheap to
    /// re-bootstrap with one tail fetch, so recency tracking isn't worth the
    /// bookkeeping). An index alone larger than the whole budget is not cached.
    fn index_cache_insert(&mut self, seg: u64, locs: Vec<crate::segment::RecordLoc>) {
        let budget = self.config.read.index_cache_budget;
        let cost = Self::index_entry_cost(&locs);
        if budget == 0 || cost > budget {
            return;
        }
        self.index_cache_remove(seg); // replace-safe accounting
        while self.index_cache_bytes + cost > budget {
            match self.index_cache_order.pop_front() {
                Some(old) => {
                    if let Some(o) = self.index_cache.remove(&old) {
                        self.index_cache_bytes = self
                            .index_cache_bytes
                            .saturating_sub(Self::index_entry_cost(&o));
                    }
                }
                None => break,
            }
        }
        self.index_cache_bytes += cost;
        self.index_cache.insert(seg, locs);
        self.index_cache_order.push_back(seg);
    }

    /// Drop one segment's cached index (GC delete, replacement) with accounting.
    fn index_cache_remove(&mut self, seg: u64) {
        if let Some(old) = self.index_cache.remove(&seg) {
            self.index_cache_bytes = self
                .index_cache_bytes
                .saturating_sub(Self::index_entry_cost(&old));
            self.index_cache_order.retain(|&s| s != seg);
        }
    }

    /// Discard `count` blocks at `lba` — they become holes (read as zeros). The
    /// unmap is durably staged so it survives a crash.
    pub async fn discard(&mut self, lba: u64, count: u64) -> Result<()> {
        self.ensure_healthy()?;
        if count == 0 {
            return Ok(());
        }
        self.bounds_ok(lba, count)?;
        self.staging.append(&FtlDelta::Unmap { lba, count }, &[])?;
        self.ftl.unmap_range(lba, count);
        Ok(())
    }

    /// Flush barrier: fsync the local staging log (D8 default — local-durable, no
    /// Telegram round-trip). After this returns, all prior writes survive a
    /// process crash / power-cycle.
    pub async fn flush(&mut self) -> Result<()> {
        self.staging_flush()?;
        self.maybe_compact_staging();
        Ok(())
    }

    /// Seal + upload the open segment, then flush. Called on detach/unmount so no
    /// data is left only in the (local) open segment.
    pub async fn close(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        if self.open.is_some() {
            self.seal_open().await?;
        }
        self.drain_uploads().await?;
        self.staging_flush()?;
        self.maybe_compact_staging();
        Ok(())
    }

    /// Test/stat aid: number of cloud-confirmed segments.
    pub fn confirmed_segments(&self) -> usize {
        self.catalog.len()
    }

    /// The current key epoch (new writes seal under this).
    pub fn current_epoch(&self) -> u32 {
        self.epoch
    }

    /// Rotate the key epoch: seal + upload the current-epoch open segment, then
    /// advance the epoch so subsequent writes use a fresh per-epoch key. Existing
    /// data stays readable — each record resolves its own epoch key, so there is
    /// no re-encryption. Fails closed if the epoch counter would overflow.
    pub async fn rotate_epoch(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        self.seal_open().await?;
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| DeviceError::Corruption("epoch counter exhausted".into()))?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| DeviceError::Corruption("generation counter exhausted".into()))?;
        // Persist the candidate superblock FIRST; only commit in RAM once it is
        // durable. A persist error leaves the device exactly as it was — the live
        // epoch never gets ahead of what recovery would reconstruct.
        self.write_superblock(self.capacity_blocks, epoch, generation)?;
        self.epoch = epoch;
        self.generation = generation;
        Ok(())
    }

    /// Resize the device. Growing exposes new zero-filled blocks. Shrinking is
    /// refused if it would strand mapped data below the new capacity (the overlay
    /// filesystem must be shrunk first).
    pub fn resize(&mut self, new_capacity_blocks: u64) -> Result<()> {
        self.ensure_healthy()?;
        if new_capacity_blocks < self.capacity_blocks {
            if let Some(max_end) = self.ftl.max_mapped_end() {
                if max_end > new_capacity_blocks {
                    return Err(DeviceError::Corruption(format!(
                        "cannot shrink to {new_capacity_blocks} blocks: mapped data extends to {max_end}"
                    )));
                }
            }
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| DeviceError::Corruption("generation counter exhausted".into()))?;
        // Persist FIRST. If the durable write fails, the live capacity must NOT
        // change: otherwise a failed grow would let writes land above the old
        // capacity while recovery reopens the old (smaller) capacity and strands
        // those acknowledged blocks behind the bounds check.
        self.write_superblock(new_capacity_blocks, self.epoch, generation)?;
        self.capacity_blocks = new_capacity_blocks;
        self.generation = generation;
        Ok(())
    }

    /// Total logical blocks currently mapped (test/stat aid; live logical size).
    pub fn mapped_blocks(&self) -> u64 {
        self.ftl.mapped_blocks()
    }

    /// The cloud watermark: the highest segment id `W` such that segments `1..=W`
    /// are ALL confirmed (in the catalog). Because uploads are async + reordered,
    /// the confirmed *set* can have gaps (e.g. `{1, 3}` → watermark 1); only the
    /// contiguous confirmed **prefix** is barrier-consistent and cloud-recoverable.
    pub fn cloud_watermark(&self) -> u64 {
        let mut w = 0u64;
        while self.catalog.contains_key(&(w + 1)) {
            w += 1;
        }
        w
    }

    /// Uploaded segments in the contiguous confirmed prefix that the last head
    /// published this session does not cover: `cloud_watermark() −` that head's
    /// watermark (the whole watermark if no head was published since `open`).
    /// `0` means a [`Self::checkpoint`] now would publish nothing new. Records
    /// still in the open (unsealed) segment are not counted — no head can
    /// cover them until the segment is sealed and uploaded.
    pub fn unpublished_segments(&self) -> u64 {
        self.cloud_watermark()
            .saturating_sub(self.last_head_watermark.unwrap_or(0))
    }

    /// Message id of the last durably-published `DeviceHead`, if any. (In real
    /// Telegram this id is pinned so a fresh machine can find it — P3.2; the M2d-2
    /// test passes it to [`Self::recover_from_head`] directly.)
    pub fn last_head_msg_id(&self) -> Option<i64> {
        self.last_head_msg_id
    }

    /// Rebuild the FTL for the barrier-consistent prefix by **replaying** the
    /// op-log up to the watermark — NOT by filtering the live FTL. Filtering would
    /// silently corrupt: if an LBA was written into a confirmed segment and later
    /// overwritten into a not-yet-confirmed one, the live FTL points at the
    /// unconfirmed segment; dropping that entry would strand the LBA as a spurious
    /// hole even though its older, prefix-consistent value is durable. Replaying in
    /// order resolves the overwrite to the confirmed value and applies pre-barrier
    /// discards. Foreground segments are staged in id order, so the first `Map`
    /// past the watermark ends the prefix.
    ///
    /// GC relocations (P4) are the one exception to the id-order rule: a
    /// `Relocate` targets a fresh high segment id but changes NO logical content
    /// — it only moves bytes that already have a valid ≤-watermark mapping. So a
    /// `Relocate` past the watermark is **skipped** (the superseded old mapping
    /// stays authoritative for the prefix; the delete gate keeps the victim's
    /// message alive until a published head stops referencing it), while a
    /// `Relocate` at or below the watermark applies like a `Map`. Breaking on it
    /// — or staging it as a plain `Map` — would truncate the prefix mid-history
    /// and drop later pre-barrier writes/discards from the head.
    fn replay_prefix_ftl(&self, watermark: u64) -> Result<Ftl> {
        // Streamed, deltas only: the sealed records are skipped, so a long log
        // is never read whole into RAM (H4).
        let mut rd = StagingReader::open(
            self.dir.join("staging.log"),
            &self.keys.meta_key,
            self.device_uuid,
        )?;
        let mut ftl = Ftl::new();
        while let Some(entry) = rd.next_entry(|_| false)? {
            match entry.delta {
                FtlDelta::Map { lba, count, phys } => {
                    if phys.segment_id > watermark {
                        break; // first post-prefix write — everything after is post-barrier
                    }
                    ftl.map_range(lba, count, phys);
                }
                FtlDelta::Relocate { lba, count, phys } => {
                    if phys.segment_id > watermark {
                        continue; // content unchanged; the old ≤-watermark mapping stands
                    }
                    ftl.map_range(lba, count, phys);
                }
                FtlDelta::Unmap { lba, count } => ftl.unmap_range(lba, count),
            }
        }
        Ok(ftl)
    }

    /// Build + upload a `DeviceHead` pinning the current cloud watermark, then
    /// advance the recoverable point to it. The head is published ONLY after a
    /// durable upload — a failed head upload leaves the previous (lower-watermark)
    /// head in force, so recovery can never land on a torn or ahead-of-cloud state.
    pub async fn checkpoint(&mut self) -> Result<i64> {
        // The prefix is replayed from the staging FILE — make the file durable
        // (and byte-complete) first, so the published head can never be ahead of
        // what a local crash would recover (P4/H10).
        self.staging_flush()?;
        let watermark = self.cloud_watermark();
        let prefix = self.replay_prefix_ftl(watermark)?;
        let extents: Vec<HeadExtent> = prefix
            .extents()
            .into_iter()
            .map(|(lba, lba_count, phys)| HeadExtent {
                lba,
                lba_count,
                phys,
            })
            .collect();
        // The published head's segment references — half of the GC delete gate
        // (P4/I3): a victim may be deleted only once the LATEST head provably
        // holds no extent into it. Recorded on self after the durable upload.
        let seg_refs: HashSet<u64> = extents.iter().map(|e| e.phys.segment_id).collect();
        // catalog subset for the confirmed prefix (segments 1..=watermark)
        let mut catalog: Vec<(u64, i64)> = self
            .catalog
            .iter()
            .filter(|(&seg, _)| seg <= watermark)
            .map(|(&seg, &mid)| (seg, mid))
            .collect();
        catalog.sort_unstable();

        // FIX-2: checked head-generation candidate (never wrap/panic at u64::MAX);
        // committed only after a durable upload.
        let next_head_gen = self
            .head_generation
            .checked_add(1)
            .ok_or_else(|| DeviceError::Corruption("head generation exhausted".into()))?;
        // FIX-1: a fresh machine recovering THIS head must restart segment
        // allocation just ABOVE the prefix (watermark + 1), NOT at the live tail's
        // next id. The dropped unconfirmed segments — and any confirmed-but-past-gap
        // ones — are not on the recovered machine, so reusing the live next id would
        // leave a permanent hole in the id space and freeze the recovered machine's
        // watermark forever (its later checkpoints could never advance, silently
        // dropping post-recovery writes on a subsequent cloud recovery).
        let restart_id = watermark
            .checked_add(1)
            .ok_or_else(|| DeviceError::Corruption("segment id space exhausted".into()))?;

        let head = DeviceHead {
            device_uuid: self.device_uuid,
            generation: self.generation,
            head_generation: next_head_gen,
            capacity_blocks: self.capacity_blocks,
            current_epoch: self.epoch,
            next_segment_id: restart_id,
            watermark,
            extents,
            catalog,
        };
        let blob = head.seal(&self.keys.meta_key)?;
        let up = self
            .transport
            .upload_block(&blob, &random_upload_name())
            .await
            .map_err(|e| DeviceError::Transport(e.to_string()))?;
        // advance the recoverable point ONLY now that the head is durable
        self.head_generation = next_head_gen;
        self.last_head_msg_id = Some(up.message_id);
        self.last_head_watermark = Some(watermark);
        self.last_head_seg_refs = seg_refs;
        self.maybe_compact_staging();
        Ok(up.message_id)
    }

    /// Compact the staging log once it has grown well past what it must hold
    /// (H4). Triggered from `flush` / `close` / `checkpoint`, i.e. after the
    /// staging file is durable. Threshold: `STAGING_COMPACT_SEGMENTS` segment
    /// targets, or twice the size the last compaction left (hysteresis — an
    /// irreducible log, e.g. a large unconfirmed backlog, is not rescanned on
    /// every flush). Compaction is maintenance: a failure (say, ENOSPC while
    /// writing the scratch copy) leaves the old, complete log in force and is
    /// logged, never surfaced as a failed flush.
    fn maybe_compact_staging(&mut self) {
        if self.failed.is_some() {
            return;
        }
        let floor = self
            .config
            .segment_target
            .saturating_mul(STAGING_COMPACT_SEGMENTS);
        let threshold = floor.max(self.staging_compacted_len.saturating_mul(2));
        if self.staging.len() <= threshold {
            return;
        }
        match self.compact_staging() {
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "staging log compaction failed; old log kept"),
        }
        self.staging_compacted_len = self.staging.len();
    }

    /// Rewrite the staging log to the smallest log that replays to the same
    /// device (H4). Returns whether a new log was installed.
    ///
    /// Let `W` be the contiguous confirmed watermark of the DURABLE catalog
    /// file (not the in-RAM one — a swallowed catalog-append error must not let
    /// us drop the only local copy of a segment's bytes). The log is split at
    /// the first `Map`/`Relocate` into a segment above `W`; every entry before
    /// that cut touches only cloud-confirmed segments (or is an `Unmap`).
    /// The rewritten log is:
    ///
    /// 1. per still-live confirmed segment with dead blocks, a `Map` + `Unmap`
    ///    pair over `[0, dead)` — nets to nothing in the FTL but carries the
    ///    segment's historical block total, so GC's `dead = total − live`
    ///    victim selection survives a reopen;
    /// 2. the FTL state at the cut as `Map` deltas with EMPTY records (exactly
    ///    what `recover_from_head` seeds; the bytes are on the cloud);
    /// 3. every entry from the cut on, verbatim, records included.
    ///
    /// Equivalence (tested): live replay, `replay_prefix_ftl(W')` for every
    /// `W' >= W`, unconfirmed-segment re-framing and per-segment totals of live
    /// segments are unchanged. The log FORMAT is unchanged — an older binary
    /// reads a compacted log. Crash safety: the copy is written to
    /// `STAGING_COMPACT_TMP`, fsynced, renamed over `staging.log`, then the
    /// directory is fsynced; a crash leaves either the old or the new log,
    /// which replay identically. The new file's handle (already open) becomes
    /// the live log, so no append can go to the unlinked old inode.
    ///
    /// Cost of compaction (documented trade, as for `recover_from_head`): a
    /// compacted confirmed segment's bytes now exist only on the cloud, so the
    /// "catalog lost → reconstruct and re-upload from staging" self-heal no
    /// longer covers it; `open()` then fails closed instead.
    fn compact_staging(&mut self) -> Result<bool> {
        self.staging_flush()?;
        let durable = Self::load_catalog(&self.dir)?;
        let mut w = 0u64;
        while durable.contains_key(&(w + 1)) {
            w += 1;
        }
        let log_path = self.dir.join("staging.log");

        // pass 1: find the cut; build the FTL at the cut + per-segment totals
        let mut base = Ftl::new();
        let mut totals: BTreeMap<u64, (u64, u32)> = BTreeMap::new();
        let mut cut = 0usize;
        {
            let mut rd = StagingReader::open(&log_path, &self.keys.meta_key, self.device_uuid)?;
            while let Some(e) = rd.next_entry(|_| false)? {
                match e.delta {
                    FtlDelta::Map { phys, .. } | FtlDelta::Relocate { phys, .. }
                        if phys.segment_id > w =>
                    {
                        break;
                    }
                    FtlDelta::Map { lba, count, phys }
                    | FtlDelta::Relocate { lba, count, phys } => {
                        base.map_range(lba, count, phys);
                        let t = totals.entry(phys.segment_id).or_insert((0, phys.epoch));
                        t.0 += count;
                    }
                    FtlDelta::Unmap { lba, count } => base.unmap_range(lba, count),
                }
                cut += 1;
            }
            if rd.tail_state().is_some_and(|t| t != TailState::Clean) {
                return Err(DeviceError::Corruption(
                    "staging log has a torn tail mid-session; not compacting".into(),
                ));
            }
        }
        if cut == 0 {
            return Ok(false);
        }

        let tmp = self.dir.join(STAGING_COMPACT_TMP);
        let built = (|| -> Result<StagingLog> {
            let mut out = StagingLog::create(&tmp, self.keys.meta_key.clone(), self.device_uuid)?;
            for (&seg, &(total, epoch)) in &totals {
                let live = base.live_blocks(seg);
                if live == 0 || total <= live {
                    continue; // fully dead (never a GC victim) or nothing dead
                }
                let dead = total - live;
                let phys = Phys {
                    segment_id: seg,
                    record_off: 0,
                    data_off: 0,
                    epoch,
                };
                out.append(
                    &FtlDelta::Map {
                        lba: 0,
                        count: dead,
                        phys,
                    },
                    &[],
                )?;
                out.append(
                    &FtlDelta::Unmap {
                        lba: 0,
                        count: dead,
                    },
                    &[],
                )?;
            }
            for (lba, count, phys) in base.extents() {
                out.append(&FtlDelta::Map { lba, count, phys }, &[])?;
            }
            let mut rd = StagingReader::open(&log_path, &self.keys.meta_key, self.device_uuid)?;
            for _ in 0..cut {
                rd.next_entry(|_| false)?;
            }
            while let Some(e) = rd.next_entry(|_| true)? {
                out.append(&e.delta, &e.sealed_record)?;
            }
            if rd.tail_state() != Some(TailState::Clean) {
                return Err(DeviceError::Corruption(
                    "staging log changed during compaction".into(),
                ));
            }
            out.flush()?;
            Ok(out)
        })();
        let out = match built {
            Ok(out) => out,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        };
        if let Err(e) = std::fs::rename(&tmp, &log_path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        // The rename has replaced the old inode: from here the new handle is
        // the only correct one to append to, whatever the directory fsync says.
        self.staging = out;
        fsync_dir(&self.dir)?;
        Ok(true)
    }

    /// One garbage-collection pass (P4): reclaim Telegram storage held by dead
    /// or mostly-dead segments.
    ///
    /// Ordering (I4 — crash-safe at every step; a crash leaves at worst orphaned
    /// messages, never an unreadable LBA and never a published head referencing
    /// a deleted message):
    ///
    /// 1. seal + confirm everything outstanding (the watermark can then cover
    ///    all foreground segments; no foreground segment stays open while GC
    ///    relocates — segments never mix writes and relocations);
    /// 2. select victims (P4.2, [`gc::select_compaction_victims`]);
    /// 3. compact each victim's live extents into fresh segments sealed under
    ///    the **current** epoch (P4.3 + P2.3 lazy re-seal), staged as
    ///    [`FtlDelta::Relocate`] before each FTL repoint;
    /// 4. seal + confirm the compaction output;
    /// 5. `checkpoint()` — durably publish a head whose prefix no longer
    ///    references the victims (it also records the delete gate on `self`);
    /// 6. the delete gate (I3): a segment's message is deleted only if it is
    ///    confirmed and non-tombstoned, the LIVE FTL holds no extent into it,
    ///    it is at or below the just-published head's watermark, and that
    ///    head's prefix holds no extent into it. This sweeps both this pass's
    ///    victims and anything that died earlier (G18's "eventually after GC");
    /// 7. batch-delete + tombstone the catalog (key survives — watermark
    ///    contiguity; the message id becomes 0) + drop the victims' cached
    ///    ciphertext. A delete failure defers those victims to the next pass
    ///    (they stay readable orphans) — repoints are NEVER rolled back.
    ///
    /// Backpressure: compaction temporarily doubles the moved bytes locally
    /// (victim + successor coexist until the delete), so a pass refuses to
    /// start — and stops moving mid-pass — when the cache is at its staged
    /// budget. A partial pass is safe: moved extents are already repointed,
    /// unmoved ones keep the victim alive (not deletable) until a later pass.
    pub async fn gc(&mut self) -> Result<GcReport> {
        self.ensure_healthy()?;
        let mut report = GcReport::default();
        if self.cache.under_backpressure() {
            report.skipped = Some("cache under backpressure (staged bytes at budget)".into());
            return Ok(report);
        }

        // 1) barrier: everything sealed + confirmed (loud failure, nothing mutated)
        self.seal_open().await?;
        self.drain_uploads().await?;

        // 2) victims: confirmed, non-tombstoned segments holding DEAD bytes
        //    (total > live — without dead bytes a rewrite reclaims nothing, and
        //    GC's own padded output would otherwise be re-selected forever)
        let candidates: Vec<Candidate> = self
            .catalog
            .iter()
            .filter(|&(_, &mid)| mid != TOMBSTONE_MSG_ID)
            .map(|(&seg, _)| Candidate {
                segment_id: seg,
                live_blocks: self.ftl.live_blocks(seg),
                total_blocks: self.seg_total_blocks.get(&seg).copied().unwrap_or(0),
            })
            .filter(|c| c.live_blocks > 0)
            .collect();
        let victims =
            gc::select_compaction_victims(&candidates, self.config.segment_target, &self.config.gc);

        // fully-dead segments are delete-only candidates — if there is nothing to
        // compact AND nothing dead to sweep, the pass is a no-op (no head churn)
        let fully_dead_exists = self
            .catalog
            .iter()
            .any(|(&seg, &mid)| mid != TOMBSTONE_MSG_ID && self.ftl.live_blocks(seg) == 0);
        if victims.is_empty() && !fully_dead_exists {
            report.skipped = Some("nothing to collect".into());
            return Ok(report);
        }

        // 3) compact (stops early under backpressure — safe: moved extents are
        //    already repointed, unmoved ones keep the victim alive for later)
        for &victim in &victims {
            let stopped_early = if self.cache.under_backpressure() {
                true
            } else {
                let (extents, blocks, stopped) = self.compact_segment(victim).await?;
                report.extents_moved += extents;
                report.blocks_moved += blocks;
                if !stopped {
                    report.compacted.push(victim);
                }
                stopped
            };
            if stopped_early {
                report.skipped = Some(
                    "backpressure mid-pass: compaction stopped early; rerun gc after uploads drain"
                        .into(),
                );
                break;
            }
        }

        // 4) confirm the compaction output so the watermark can cover it. A
        //    drain failure here must NOT discard the report — the relocations
        //    are staged + durable; surface the partial pass honestly instead.
        self.seal_open().await?;
        if let Err(e) = self.drain_uploads().await {
            report.skipped = Some(format!(
                "upload drain failed after compaction ({e}); relocations are staged and durable — rerun gc"
            ));
            return Ok(report);
        }

        // 5) publish the head that stops referencing the victims
        let prev_head = self.last_head_msg_id;
        let head_msg_id = self.checkpoint().await?;
        report.head_msg_id = Some(head_msg_id);
        let head_watermark = self
            .last_head_watermark
            .expect("checkpoint() just published a head");
        report.watermark = head_watermark;

        // 6) the delete gate (I3) — pure predicate, unit-tested in crate::gc
        let catalog_view: Vec<(u64, i64)> = self.catalog.iter().map(|(&s, &m)| (s, m)).collect();
        let deletable = gc::deletable_segments(
            &catalog_view,
            |seg| self.ftl.live_blocks(seg),
            head_watermark,
            &self.last_head_seg_refs,
        );

        // 7) delete + tombstone (delete first: a crash in between only means an
        //    idempotent re-delete next pass — batch delete_messages skips ids
        //    that are already gone on both the mock and the real client)
        if !deletable.is_empty() {
            let mids: Vec<i64> = deletable.iter().map(|&s| self.catalog[&s]).collect();
            match self.transport.delete_messages(&mids).await {
                Ok(()) => {
                    for &seg in &deletable {
                        self.append_catalog(seg, TOMBSTONE_MSG_ID)?;
                        self.catalog.insert(seg, TOMBSTONE_MSG_ID);
                        self.cache.remove(seg);
                        self.seg_total_blocks.remove(&seg);
                        // ranged-read state for a deleted segment is garbage
                        self.index_cache_remove(seg);
                        self.seg_read_hits.remove(&seg);
                        report.deleted.push(seg);
                    }
                }
                Err(_) => {
                    // transient: victims stay as readable, unreferenced orphans;
                    // the next pass recomputes the same gate and retries
                    report.delete_deferred = deletable;
                }
            }
        }

        // 8) OPT-IN (advisor H1; default off): drop the head THIS pass
        //    superseded. Deleting old heads invalidates any operator-recorded
        //    recovery id, so until P3.2 pins the newest head this only runs
        //    where the caller re-records `report.head_msg_id` every pass.
        if self.config.gc.delete_superseded_head {
            if let (Some(prev), Some(cur)) = (prev_head, self.last_head_msg_id) {
                if prev != cur {
                    report.superseded_head_deleted =
                        self.transport.delete_messages(&[prev]).await.is_ok();
                }
            }
        }
        Ok(report)
    }

    /// Move every live extent of `victim` into the open (GC) segment, re-sealed
    /// under the CURRENT epoch (P2.3 — this is the lazy re-seal path: bytes
    /// written under a rotated-away epoch migrate to the newest key as they are
    /// compacted). LBA-adjacent extents are merged up to `record_max` so
    /// compaction also defragments. Checks backpressure between runs (a mid-pass
    /// upload failure can push staged bytes over budget between victim
    /// boundaries — advisor F2) and stops early rather than wedge the device.
    /// Returns `(merged_extents_moved, blocks_moved, stopped_early)`; a partial
    /// move is safe — the victim stays alive until every extent is gone.
    async fn compact_segment(&mut self, victim: u64) -> Result<(usize, u64, bool)> {
        let extents = self.ftl.extents_of_segment(victim);
        let max_blocks = (self.config.record_max / BS).max(1);

        // merge LBA-adjacent extents into runs of ≤ record_max
        let mut runs: Vec<Vec<(u64, u64, Phys)>> = Vec::new();
        for e in extents {
            match runs.last_mut() {
                Some(run) => {
                    let (last_lba, last_count, _) = *run.last().unwrap();
                    let run_blocks: u64 = run.iter().map(|&(_, c, _)| c).sum();
                    if last_lba + last_count == e.0 && run_blocks + e.1 <= max_blocks {
                        run.push(e);
                    } else {
                        runs.push(vec![e]);
                    }
                }
                None => runs.push(vec![e]),
            }
        }

        // Compaction chooses its fetch strategy EXPLICITLY instead of letting
        // the locality gate promote a dying segment mid-pass (advisor D1): a
        // victim still holding substantial live data gets ONE whole fetch
        // amortized across its runs; a mostly-empty victim is read ranged
        // (its reads below are gate-exempt either way).
        let live_bytes = self.ftl.live_blocks(victim).saturating_mul(BS);
        if self.config.read.ranged_reads
            && live_bytes >= self.config.segment_target / 4
            && self.cache.get(victim).is_none()
        {
            if let Some(&mid) = self.catalog.get(&victim) {
                if mid != TOMBSTONE_MSG_ID {
                    let dl = self
                        .transport
                        .download_block(mid)
                        .await
                        .map_err(|e| DeviceError::Transport(e.to_string()))?;
                    self.cache.insert(victim, dl.data, false);
                }
            }
        }

        let mut moved_extents = 0usize;
        let mut moved_blocks = 0u64;
        for run in runs {
            if self.cache.under_backpressure() {
                return Ok((moved_extents, moved_blocks, true));
            }
            let run_lba = run[0].0;
            let run_blocks: u64 = run.iter().map(|&(_, c, _)| c).sum();
            let mut plain = Vec::with_capacity(checked_bytes(run_blocks)?);
            for &(_, count, phys) in &run {
                plain.extend_from_slice(&self.read_mapped(&phys, count, None).await?);
            }
            self.write_record(run_lba, run_blocks, &plain, true).await?;
            moved_extents += 1;
            moved_blocks += run_blocks;
            // seal mid-pass at the target, exactly like the foreground write path
            if self
                .open
                .as_ref()
                .is_some_and(|o| o.builder.current_len() >= self.config.segment_target)
            {
                self.seal_open().await?;
            }
        }
        Ok((moved_extents, moved_blocks, false))
    }

    /// Fresh-machine recovery from a cloud `DeviceHead` (no local staging). Downloads
    /// and verifies the head, then materializes a full working device rooted at `dir`:
    /// the recovered FTL is the barrier-consistent prefix, reads fetch the confirmed
    /// segments the head references, and new writes continue above the head's
    /// `next_segment_id`. The device lands at the watermark and loses the unsynced
    /// tail by design (the local-fast durability contract). `dir` is seeded so a
    /// subsequent same-machine crash also recovers (superblock + catalog + a staging
    /// log carrying the prefix mapping for confirmed, downloadable segments).
    ///
    /// LIMITATION: the seeded staging holds the prefix as Map deltas with EMPTY
    /// sealed records (the real bytes are on the cloud, referenced by the catalog).
    /// So a head-recovered device relies on catalog durability MORE than a native
    /// one: if its catalog is later lost, M2d-1's reconstruct-and-reupload
    /// self-healing does not apply — a subsequent `open()` fails CLOSED (the empty
    /// record cannot be re-framed) rather than silently returning wrong data. The
    /// catalog is fsync-durable, so this only bites under external corruption.
    ///
    /// SAFETY OF THE TARGET (L4): recovery truncates `catalog` and `staging.log`
    /// and replaces `superblock` in `dir`. Pointed at a live device directory
    /// that would destroy its local state — including staged writes that never
    /// reached Telegram. So `dir` must be missing or EMPTY; anything else is
    /// refused (`ErrorKind::AlreadyExists`) before the head is even fetched.
    /// Overwriting is [`Self::recover_from_head_force`], and must be explicit.
    pub async fn recover_from_head(
        transport: Arc<T>,
        keys: DeviceKeys,
        device_uuid: [u8; 16],
        dir: impl AsRef<Path>,
        head_msg_id: i64,
        config: DeviceConfig,
    ) -> Result<Self> {
        Self::recover_from_head_into(
            transport,
            keys,
            device_uuid,
            dir.as_ref(),
            head_msg_id,
            config,
            true,
        )
        .await
    }

    /// [`Self::recover_from_head`] WITHOUT the empty-directory guard: replaces
    /// whatever device state `dir` holds with the head's prefix. Staged writes
    /// that never reached the head's watermark are destroyed. Only for an
    /// operator who has decided the local state is to be discarded.
    pub async fn recover_from_head_force(
        transport: Arc<T>,
        keys: DeviceKeys,
        device_uuid: [u8; 16],
        dir: impl AsRef<Path>,
        head_msg_id: i64,
        config: DeviceConfig,
    ) -> Result<Self> {
        Self::recover_from_head_into(
            transport,
            keys,
            device_uuid,
            dir.as_ref(),
            head_msg_id,
            config,
            false,
        )
        .await
    }

    /// The first entry of `dir`, or `None` if it is missing or empty.
    fn first_entry(dir: &Path) -> Result<Option<std::ffi::OsString>> {
        match std::fs::read_dir(dir) {
            Ok(mut it) => Ok(it.next().transpose()?.map(|e| e.file_name())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn recover_from_head_into(
        transport: Arc<T>,
        keys: DeviceKeys,
        device_uuid: [u8; 16],
        dir: &Path,
        head_msg_id: i64,
        config: DeviceConfig,
        require_empty: bool,
    ) -> Result<Self> {
        let dir = dir.to_path_buf();
        // L4 guard, decided under the single-writer lock so a device that is
        // live in `dir` (or a concurrent recovery) can never be overwritten —
        // forced or not. Checked before the head is fetched.
        std::fs::create_dir_all(&dir)?;
        let dir_lock = DirLock::acquire(&dir)?;
        if require_empty {
            if let Some(entry) = Self::first_entry(&dir)? {
                return Err(DeviceError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "refusing to recover into non-empty directory {} (contains {:?}): \
                         recovery would overwrite its superblock, catalog and staging log. Use \
                         an empty directory, or recover_from_head_force to overwrite deliberately",
                        dir.display(),
                        entry
                    ),
                )));
            }
        }
        let blob = transport
            .download_block(head_msg_id)
            .await
            .map_err(|e| DeviceError::Transport(e.to_string()))?
            .data;
        let head = DeviceHead::open(&blob, &keys.meta_key, &device_uuid)?;

        // 0) the in-progress marker, durable BEFORE any device file is touched
        {
            let m = std::fs::File::create(dir.join(RECOVERY_MARKER))?;
            m.sync_all()?;
            fsync_dir(&dir)?;
        }

        // 1) superblock from the head's config (persist for same-machine reopen)
        let sb = Superblock {
            device_uuid,
            capacity_blocks: head.capacity_blocks,
            current_epoch: head.current_epoch,
            generation: head.generation,
        };
        write_atomic(&dir, "superblock", &sb.seal(&keys.integrity_key))?;

        // 2) catalog file from the head's confirmed prefix
        let mut catalog = HashMap::new();
        {
            let mut cat = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(dir.join("catalog"))?;
            for &(seg, mid) in &head.catalog {
                catalog.insert(seg, mid);
                let mut rec = [0u8; 16];
                rec[..8].copy_from_slice(&seg.to_le_bytes());
                rec[8..].copy_from_slice(&mid.to_le_bytes());
                cat.write_all(&rec)?;
            }
            cat.sync_all()?;
        }

        // 3) fresh staging seeded with the prefix mapping as Map deltas (empty
        //    sealed records — the referenced segments are confirmed, so a later
        //    open() reconstruction skips them and reads download from the cloud),
        //    and the in-RAM FTL built from the same extents.
        let mut staging =
            StagingLog::create(dir.join("staging.log"), keys.meta_key.clone(), device_uuid)?;
        let mut ftl = Ftl::new();
        for e in &head.extents {
            staging.append(
                &FtlDelta::Map {
                    lba: e.lba,
                    count: e.lba_count,
                    phys: e.phys,
                },
                &[],
            )?;
            ftl.map_range(e.lba, e.lba_count, e.phys);
        }
        staging.flush()?;
        // 4) everything is durable: recovery is complete
        std::fs::remove_file(dir.join(RECOVERY_MARKER))?;
        fsync_dir(&dir)?;

        let cache = ScoredCache::new(config.cache);
        // The recovered head IS the latest published head: seed the GC delete
        // gate from it (its watermark + the segments its extents reference), so
        // a post-recovery gc() judges deletions against the same head a fresh
        // machine would recover from.
        let seg_refs: HashSet<u64> = head.extents.iter().map(|e| e.phys.segment_id).collect();
        // Conservative per-segment totals: total = live-at-recovery. Dead bytes
        // that predate the recovery are invisible, so those segments only become
        // compaction victims once new overwrites kill blocks (P4 selection).
        let mut seg_total_blocks: HashMap<u64, u64> = HashMap::new();
        for e in &head.extents {
            *seg_total_blocks.entry(e.phys.segment_id).or_insert(0) += e.lba_count;
        }
        Ok(Self {
            transport,
            keys,
            device_uuid,
            capacity_blocks: head.capacity_blocks,
            epoch: head.current_epoch,
            generation: head.generation,
            dir,
            config,
            ftl,
            cache,
            staging,
            catalog,
            open: None,
            next_segment_id: head.next_segment_id,
            pending_upload: Vec::new(),
            head_generation: head.head_generation,
            last_head_msg_id: Some(head_msg_id),
            last_head_watermark: Some(head.watermark),
            last_head_seg_refs: seg_refs,
            seg_total_blocks,
            index_cache: HashMap::new(),
            index_cache_order: VecDeque::new(),
            index_cache_bytes: 0,
            seg_read_hits: HashMap::new(),
            staging_compacted_len: 0,
            _dir_lock: dir_lock,
            faults: DeviceFaults::default(),
            failed: None,
        })
    }
}

/// The document name a segment or checkpoint is uploaded under: 12 random
/// lowercase hex characters, no extension. Nothing reads it back — segments and
/// the head are located by `message_id` via the catalog / `last_head_msg_id` — so
/// the name carries no segment id, no role and no format marker, and says
/// nothing about the content.
fn random_upload_name() -> String {
    let hex = uuid::Uuid::new_v4().simple().to_string();
    hex[..12].to_string()
}

/// Durably, atomically replace `dir/name` with `bytes`: write `dir/name.tmp`,
/// fsync it, rename over the target, then fsync the directory so the rename
/// survives a power cut. A crash leaves either the old file or the new one intact
/// — never a torn one (the superblock must never be half-written).
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(name))?;
    // fsync the directory so the rename is itself durable.
    fsync_dir(dir)
}

/// fsync a directory so entries created/renamed/removed in it are durable.
/// On Unix (where directory fsync IS the mechanism) a failure must surface —
/// never report a durable change that isn't. On other platforms directory
/// fsync is not the durability primitive (and opening a directory as a file
/// fails), so it is best-effort there rather than a spurious hard failure.
fn fsync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// Convert a block count to a byte length, failing closed if it overflows `u64`
/// or does not fit `usize` (a huge in-bounds block count on a huge-capacity
/// device must not panic/wrap the byte-size math).
fn checked_bytes(blocks: u64) -> Result<usize> {
    blocks
        .checked_mul(BS)
        .and_then(|b| usize::try_from(b).ok())
        .ok_or_else(|| DeviceError::Corruption("request too large to represent in bytes".into()))
}

fn slice_record(pt: &[u8], off: usize, want: usize) -> Result<Vec<u8>> {
    let end = off
        .checked_add(want)
        .filter(|&e| e <= pt.len())
        .ok_or_else(|| DeviceError::Corruption("record slice out of bounds".into()))?;
    Ok(pt[off..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staging::StagingLog;
    use std::fs::OpenOptions;
    use teagarden_telegram::mock::MockTransport;

    fn keys() -> DeviceKeys {
        DeviceKeys {
            data_key: SymmetricKey::from_bytes([1u8; 32]),
            meta_key: SymmetricKey::from_bytes([2u8; 32]),
            integrity_key: SymmetricKey::from_bytes([3u8; 32]),
        }
    }

    /// Build a real volume key hierarchy from a password, exactly as `open_volume`
    /// does — so the A4 tests exercise the genuine derivation path.
    fn hierarchy_for(password: &[u8], salt: [u8; 32]) -> KeyHierarchy {
        let root = kdf::derive_root_key(password, &salt, &Default::default()).unwrap();
        kdf::derive_hierarchy_v1(root, &salt, 0, 0).unwrap()
    }

    /// A4: device keys derive from a REAL volume hierarchy, are deterministic, are
    /// domain-separated from the filesystem keys they descend from, and differ per
    /// volume. This is what lets a serve verb drop the hardcoded `[0x11;32]`.
    #[test]
    fn device_keys_derive_from_hierarchy_domain_separated_and_deterministic() {
        let h = hierarchy_for(b"correct-horse", [7u8; 32]);
        let a = DeviceKeys::from_hierarchy(&h).unwrap();
        let b = DeviceKeys::from_hierarchy(&h).unwrap();

        // Deterministic: the same volume always yields the same device keys.
        assert_eq!(a.data_key.as_bytes(), b.data_key.as_bytes());
        assert_eq!(a.meta_key.as_bytes(), b.meta_key.as_bytes());
        assert_eq!(a.integrity_key.as_bytes(), b.integrity_key.as_bytes());

        // Domain-separated from the FILESYSTEM keys: a device key is never just a
        // copy of the hierarchy key it descends from (so compromising one layer
        // does not hand over the other).
        assert_ne!(a.data_key.as_bytes(), h.data.as_bytes());
        assert_ne!(a.meta_key.as_bytes(), h.meta.as_bytes());
        assert_ne!(a.integrity_key.as_bytes(), h.integrity.as_bytes());

        // The three device keys are independent of each other.
        assert_ne!(a.data_key.as_bytes(), a.meta_key.as_bytes());
        assert_ne!(a.data_key.as_bytes(), a.integrity_key.as_bytes());
        assert_ne!(a.meta_key.as_bytes(), a.integrity_key.as_bytes());

        // A different volume (different password) yields entirely different keys.
        let other =
            DeviceKeys::from_hierarchy(&hierarchy_for(b"other-password", [7u8; 32])).unwrap();
        assert_ne!(a.data_key.as_bytes(), other.data_key.as_bytes());

        // And none of them is the old hardcoded test key.
        assert_ne!(a.data_key.as_bytes(), &[0x11u8; 32]);
        assert_ne!(a.meta_key.as_bytes(), &[0x22u8; 32]);
        assert_ne!(a.integrity_key.as_bytes(), &[0x33u8; 32]);
    }

    /// A4: the device UUID is derived (durable by construction — available before
    /// any superblock exists, which `recover_from_head` needs), deterministic per
    /// volume, and distinct across volumes.
    #[test]
    fn device_uuid_is_derived_deterministic_and_volume_unique() {
        let h = hierarchy_for(b"correct-horse", [7u8; 32]);
        let u1 = DeviceKeys::device_uuid_for(&h).unwrap();
        let u2 = DeviceKeys::device_uuid_for(&h).unwrap();
        assert_eq!(u1, u2, "same volume ⇒ same device uuid, on any machine");

        let other = DeviceKeys::device_uuid_for(&hierarchy_for(b"other", [7u8; 32])).unwrap();
        assert_ne!(u1, other, "different volumes must not collide");
        assert_ne!(u1, [0x7du8; 16], "not the old hardcoded uuid");
    }

    fn small_config() -> DeviceConfig {
        DeviceConfig {
            segment_target: 32 * 1024, // small → seals after a few records
            record_max: 8 * 1024,      // 2 blocks per record
            cache: CacheConfig {
                budget_bytes: 1 << 30,
                ..Default::default()
            },
            gc: GcConfig::default(),
            read: ReadConfig::default(),
        }
    }

    // Seals after EVERY record → one segment per (≤2-block) write, giving precise
    // control over which segment is confirmed vs pending in the M2d-2 head tests.
    fn tiny_config() -> DeviceConfig {
        DeviceConfig {
            segment_target: 1,
            record_max: 8 * 1024,
            cache: CacheConfig {
                budget_bytes: 1 << 30,
                ..Default::default()
            },
            gc: GcConfig::default(),
            read: ReadConfig::default(),
        }
    }

    async fn dev(
        dir: &tempfile::TempDir,
        cap: u64,
        cfg: DeviceConfig,
    ) -> (TeaGardenDevice<MockTransport>, Arc<MockTransport>) {
        let t = Arc::new(MockTransport::new());
        let d = TeaGardenDevice::create(Arc::clone(&t), keys(), [7u8; 16], cap, dir.path(), cfg)
            .unwrap();
        (d, t)
    }

    // Reopen a device over the SAME transport + dir (recovery), as a fresh machine
    // process would (in-RAM state gone; superblock + catalog + staging on disk).
    fn reopen(
        t: &Arc<MockTransport>,
        dir: &tempfile::TempDir,
        cfg: DeviceConfig,
    ) -> TeaGardenDevice<MockTransport> {
        TeaGardenDevice::open(Arc::clone(t), keys(), dir.path(), cfg).unwrap()
    }

    #[tokio::test]
    async fn read_your_writes_before_seal() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 1024, small_config()).await;
        let block: Vec<u8> = (0..BS as usize).map(|i| i as u8).collect();
        d.write_at(3, &block).await.unwrap();
        // read it straight back from the open segment (no upload yet)
        assert_eq!(d.read_at(3, 1).await.unwrap(), block);
        // a neighbouring unwritten block reads as zeros
        assert_eq!(d.read_at(4, 1).await.unwrap(), vec![0u8; BS as usize]);
        assert_eq!(d.confirmed_segments(), 0);
    }

    #[tokio::test]
    async fn round_trip_through_seal_upload_and_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        // write enough (2-block records, 32 KiB target) to trigger a seal+upload
        let a = vec![0xAAu8; 4 * BS as usize]; // 4 blocks at lba 0
        let b = vec![0xBBu8; 4 * BS as usize]; // 4 blocks at lba 10
        d.write_at(0, &a).await.unwrap();
        d.write_at(10, &b).await.unwrap();
        d.close().await.unwrap(); // seal + upload remaining open segment
        assert!(d.confirmed_segments() >= 1);
        assert!(t.message_count() >= 1);

        // reads now come from the cache (sealed segment) — verify byte-exact
        assert_eq!(d.read_at(0, 4).await.unwrap(), a);
        assert_eq!(d.read_at(10, 4).await.unwrap(), b);
        // hole between them reads zeros
        assert_eq!(d.read_at(4, 6).await.unwrap(), vec![0u8; 6 * BS as usize]);
    }

    #[tokio::test]
    async fn cold_read_downloads_from_transport() {
        let dir = tempfile::tempdir().unwrap();
        // tiny cache budget so the sealed segment is evicted after upload
        let cfg = DeviceConfig {
            cache: CacheConfig {
                budget_bytes: 1,
                ..Default::default()
            },
            ..small_config()
        };
        let (mut d, t) = dev(&dir, 1024, cfg).await;
        let a = vec![0xCDu8; 4 * BS as usize];
        d.write_at(0, &a).await.unwrap();
        d.close().await.unwrap();
        // the segment was evicted from cache (budget 1) → this read must download
        assert!(t.message_count() >= 1);
        assert_eq!(d.read_at(0, 4).await.unwrap(), a);
    }

    #[tokio::test]
    async fn overwrite_supersedes() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x11u8; 2 * BS as usize]).await.unwrap();
        // overwrite the second block
        d.write_at(1, &vec![0x22u8; BS as usize]).await.unwrap();
        let r = d.read_at(0, 2).await.unwrap();
        assert!(r[..BS as usize].iter().all(|&x| x == 0x11));
        assert!(r[BS as usize..].iter().all(|&x| x == 0x22));
    }

    #[tokio::test]
    async fn discard_reads_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 1024, small_config()).await;
        d.write_at(5, &vec![0x99u8; 2 * BS as usize]).await.unwrap();
        d.discard(5, 1).await.unwrap();
        let r = d.read_at(5, 2).await.unwrap();
        assert!(r[..BS as usize].iter().all(|&x| x == 0)); // discarded → zeros
        assert!(r[BS as usize..].iter().all(|&x| x == 0x99)); // untouched
    }

    #[tokio::test]
    async fn capacity_bounds_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 8, small_config()).await; // 8-block device
                                                              // write past the end
        assert!(matches!(
            d.write_at(6, &vec![0u8; 4 * BS as usize]).await,
            Err(DeviceError::OutOfRange { .. })
        ));
        // read past the end
        assert!(matches!(
            d.read_at(6, 4).await,
            Err(DeviceError::OutOfRange { .. })
        ));
        // a non-block-aligned write is rejected
        assert!(d.write_at(0, &[0u8; 100]).await.is_err());
    }

    // The FTL↔record composition point: after a record is sealed and then a
    // middle block is overwritten (splitting the FTL extent), a partial read of a
    // SURVIVOR slice must fetch the (shorter) record at the correctly-adjusted
    // data_off without going out of bounds.
    #[tokio::test]
    async fn partial_read_across_split_after_seal() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 1024, small_config()).await;
        let orig: Vec<u8> = (0..4 * BS as usize).map(|i| i as u8).collect();
        d.write_at(0, &orig).await.unwrap();
        d.close().await.unwrap(); // seal + upload → survivors now served from cache
                                  // overwrite the middle block 1 (new open segment)
        let mid = vec![0xEEu8; BS as usize];
        d.write_at(1, &mid).await.unwrap();
        // read the whole [0,4): block0 + blocks 2,3 from the sealed segment's
        // records (adjusted data_off), block1 from read-your-writes
        let r = d.read_at(0, 4).await.unwrap();
        assert_eq!(&r[0..BS as usize], &orig[0..BS as usize]);
        assert_eq!(&r[BS as usize..2 * BS as usize], &mid[..]);
        assert_eq!(&r[2 * BS as usize..], &orig[2 * BS as usize..]);
    }

    // Crash consistency of the stage→FTL ordering: the device stages each write
    // (delta + sealed record) BEFORE touching the in-RAM FTL, so a crash at any
    // point recovers the exact mapping by replaying the staging file. (Device-level
    // recovery is M2d; this proves the staging substrate is already correct.)
    #[tokio::test]
    async fn staging_replay_reconstructs_written_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0xA1u8; 3 * BS as usize]).await.unwrap();
        d.write_at(5, &vec![0xB2u8; BS as usize]).await.unwrap();
        d.discard(1, 1).await.unwrap(); // punch a hole at block 1
        d.flush().await.unwrap(); // fsync the staging log

        // simulate a crash: the in-RAM FTL is gone; rebuild it from staging alone
        let rp = StagingLog::replay(
            dir.path().join("staging.log"),
            &SymmetricKey::from_bytes([2u8; 32]), // meta_key
            [7u8; 16],                            // device_uuid
        )
        .unwrap();
        assert!(!rp.torn_tail);
        // blocks 0 and 2 mapped (3-block write minus the discarded block 1) + block 5
        assert_eq!(rp.ftl.mapped_blocks(), 3);
        assert!(rp.ftl.lookup(0).is_some());
        assert!(rp.ftl.lookup(1).is_none()); // discarded → hole
        assert!(rp.ftl.lookup(2).is_some());
        assert!(rp.ftl.lookup(5).is_some());
    }

    // FIX-1: a failed upload during seal must NOT lose the data — it stays
    // readable (staged cache) and queued for retry.
    #[tokio::test]
    async fn failed_upload_keeps_data_readable_and_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        *t.fail_uploads.lock().unwrap() = Some("dc down".into());
        let data = vec![0x5Au8; 12 * BS as usize]; // > 32 KiB target → seals
        d.write_at(0, &data).await.unwrap();
        // sealed but upload failed → not confirmed, yet still readable
        assert_eq!(d.confirmed_segments(), 0);
        assert_eq!(d.read_at(0, 12).await.unwrap(), data);
        // allow uploads; close drains the pending upload and confirms
        *t.fail_uploads.lock().unwrap() = None;
        d.close().await.unwrap();
        assert!(d.confirmed_segments() >= 1);
        assert_eq!(d.read_at(0, 12).await.unwrap(), data);
    }

    // FIX-2: when sealed staged segments cannot upload and fill the cache budget,
    // the device applies backpressure (refuses new writes) rather than growing.
    #[tokio::test]
    async fn backpressure_when_staged_segments_cannot_upload() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DeviceConfig {
            cache: CacheConfig {
                budget_bytes: 1024,
                ..Default::default()
            },
            ..small_config()
        };
        let (mut d, t) = dev(&dir, 1024, cfg).await;
        *t.fail_uploads.lock().unwrap() = Some("offline".into());
        d.write_at(0, &vec![0u8; 12 * BS as usize]).await.unwrap(); // seals a staged seg
                                                                    // over budget with un-uploadable staged data → next write refused
        assert!(matches!(
            d.write_at(100, &vec![0u8; BS as usize]).await,
            Err(DeviceError::StagingFull)
        ));
        // the already-written data remains readable
        assert_eq!(d.read_at(0, 12).await.unwrap(), vec![0u8; 12 * BS as usize]);
    }

    // FIX-3: a block count that passes the block-bounds check but overflows the
    // byte-size math fails closed (no panic / no wrap).
    #[tokio::test]
    async fn huge_read_count_rejected_not_panicked() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, u64::MAX, small_config()).await;
        let err = d.read_at(0, u64::MAX / 2).await.unwrap_err();
        assert!(matches!(err, DeviceError::Corruption(_)));
    }

    // M2c: rotating the epoch advances the key for new writes but leaves data
    // written under the old epoch readable (each record resolves its own key).
    #[tokio::test]
    async fn epoch_rotation_keeps_old_data_readable() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 1024, small_config()).await;
        let old = vec![0x11u8; 2 * BS as usize];
        d.write_at(0, &old).await.unwrap();
        assert_eq!(d.current_epoch(), 0);
        d.rotate_epoch().await.unwrap(); // seals the epoch-0 segment, → epoch 1
        assert_eq!(d.current_epoch(), 1);
        let new = vec![0x22u8; 2 * BS as usize];
        d.write_at(10, &new).await.unwrap();
        d.close().await.unwrap();
        assert_eq!(d.read_at(0, 2).await.unwrap(), old); // epoch-0 key
        assert_eq!(d.read_at(10, 2).await.unwrap(), new); // epoch-1 key
    }

    // M2c: growing the device exposes new zero-filled blocks that can be written.
    #[tokio::test]
    async fn resize_grow_exposes_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 8, small_config()).await;
        assert!(d.write_at(10, &vec![0u8; BS as usize]).await.is_err()); // out of range
        d.resize(16).unwrap();
        assert_eq!(d.capacity_blocks(), 16);
        assert_eq!(d.read_at(10, 1).await.unwrap(), vec![0u8; BS as usize]); // zeros
        d.write_at(10, &vec![0x7u8; BS as usize]).await.unwrap();
        assert_eq!(d.read_at(10, 1).await.unwrap(), vec![0x7u8; BS as usize]);
    }

    // M2c: shrinking below mapped data is refused; shrinking after discard is OK.
    #[tokio::test]
    async fn resize_shrink_refused_when_data_would_be_stranded() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 100, small_config()).await;
        d.write_at(50, &vec![0x9u8; BS as usize]).await.unwrap();
        assert!(d.resize(40).is_err()); // block 50 would be stranded
        assert_eq!(d.capacity_blocks(), 100);
        d.resize(51).unwrap(); // exactly covers the mapped data
        assert_eq!(d.capacity_blocks(), 51);
        d.discard(50, 1).await.unwrap();
        d.resize(10).unwrap(); // nothing mapped → any shrink allowed
        assert_eq!(d.capacity_blocks(), 10);
    }

    // ===================== M2d-1: device recovery (open) =====================

    // Clean shutdown then reopen: everything is confirmed on the cloud, so a fresh
    // process rebuilds the FTL from staging + catalog and reads it all back
    // byte-exact from the transport (the reopened cache is cold).
    #[tokio::test]
    async fn recover_confirmed_after_close() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0xA1u8; 6 * BS as usize];
        let b = vec![0xB2u8; 3 * BS as usize];
        d.write_at(0, &a).await.unwrap();
        d.write_at(20, &b).await.unwrap();
        d.close().await.unwrap();
        let confirmed = d.confirmed_segments();
        let mapped = d.mapped_blocks();
        assert!(confirmed >= 1);
        drop(d);

        // fresh process: only superblock + catalog + staging survive on disk
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.confirmed_segments(), confirmed);
        assert_eq!(r.mapped_blocks(), mapped);
        assert_eq!(r.current_epoch(), 0);
        assert_eq!(r.capacity_blocks(), 1024);
        assert_eq!(r.read_at(0, 6).await.unwrap(), a);
        assert_eq!(r.read_at(20, 3).await.unwrap(), b);
        assert_eq!(r.read_at(9, 2).await.unwrap(), vec![0u8; 2 * BS as usize]); // hole
    }

    // Crash with UNSYNCED data: writes were staged + flushed but the open segment
    // never sealed/uploaded (no close). Recovery re-frames it from the staging log,
    // serves reads, and finishes the upload on the next close.
    #[tokio::test]
    async fn recover_unconfirmed_open_segment() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0x7Eu8; 4 * BS as usize]; // 16 KiB < 32 KiB target → never seals
        d.write_at(2, &a).await.unwrap();
        d.flush().await.unwrap(); // staging fsync — durable, but NOT uploaded
        assert_eq!(d.confirmed_segments(), 0);
        assert_eq!(t.message_count(), 0);
        drop(d); // crash: no close; the cache + open segment are gone

        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.confirmed_segments(), 0); // nothing was ever on the cloud
        assert_eq!(r.read_at(2, 4).await.unwrap(), a); // reconstructed from staging
                                                       // the recovered segment finishes uploading on close
        r.close().await.unwrap();
        assert!(r.confirmed_segments() >= 1);
        assert!(t.message_count() >= 1);
        assert_eq!(r.read_at(2, 4).await.unwrap(), a);
    }

    // Idempotent recovery — the threat model's written contract: reopening twice
    // (over the same on-disk state) yields the identical device (FTL + reads).
    #[tokio::test]
    async fn reopen_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x11u8; 5 * BS as usize]).await.unwrap();
        d.write_at(30, &vec![0x22u8; 2 * BS as usize])
            .await
            .unwrap();
        d.discard(2, 1).await.unwrap(); // punch a hole mid-extent
        d.flush().await.unwrap();
        drop(d);

        let mut r1 = reopen(&t, &dir, small_config());
        let m1 = r1.mapped_blocks();
        let read1 = r1.read_at(0, 40).await.unwrap();
        drop(r1); // no writes, no close → on-disk state unchanged

        let mut r2 = reopen(&t, &dir, small_config());
        assert_eq!(r2.mapped_blocks(), m1);
        assert_eq!(r2.read_at(0, 40).await.unwrap(), read1);
    }

    // A torn staging tail (crash mid-append) recovers the durable PREFIX through
    // open() without error — the partial trailing write is dropped, prior writes
    // survive.
    #[tokio::test]
    async fn recover_torn_staging_tail() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x33u8; 2 * BS as usize]).await.unwrap();
        d.flush().await.unwrap();
        drop(d);
        // corrupt the tail: append a sub-header fragment (< 4 bytes ⇒ torn)
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join("staging.log"))
                .unwrap();
            f.write_all(&[0x99, 0x99, 0x99]).unwrap();
            f.sync_all().unwrap();
        }
        let mut r = reopen(&t, &dir, small_config());
        // the good prefix survived; the torn fragment was ignored (no error)
        assert_eq!(
            r.read_at(0, 2).await.unwrap(),
            vec![0x33u8; 2 * BS as usize]
        );
        assert_eq!(r.mapped_blocks(), 2);
    }

    // C1: the torn tail must be TRIMMED, not just skipped. Replay stops at the
    // first bad entry, so if open() appends after the torn bytes every write
    // of the new session is silently lost on the next reopen.
    #[tokio::test]
    async fn torn_tail_is_trimmed_so_next_session_writes_survive() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0x33u8; 2 * BS as usize];
        d.write_at(0, &a).await.unwrap();
        d.flush().await.unwrap();
        drop(d);
        let log = dir.path().join("staging.log");
        let clean_len = std::fs::metadata(&log).unwrap().len();
        {
            let mut f = OpenOptions::new().append(true).open(&log).unwrap();
            f.write_all(&[0x99, 0x99, 0x99]).unwrap();
            f.sync_all().unwrap();
        }
        let mut r = reopen(&t, &dir, small_config());
        let b = vec![0x44u8; 2 * BS as usize];
        r.write_at(8, &b).await.unwrap();
        r.flush().await.unwrap();
        drop(r);
        let mut r2 = reopen(&t, &dir, small_config());
        assert_eq!(r2.read_at(0, 2).await.unwrap(), a);
        assert!(
            r2.read_at(8, 2).await.unwrap() == b,
            "write B (after the torn tail) was lost on reopen"
        );
        // and the 3 garbage bytes are gone from the file
        assert!(std::fs::metadata(&log).unwrap().len() > clean_len);
        let rp = StagingLog::replay(&log, &keys().meta_key, [7u8; 16]).unwrap();
        assert!(!rp.torn_tail);
    }

    // Large segment target: nothing seals/uploads, so every write stays in the
    // open segment + staging (the crash-before-upload window of M5).
    fn unsealed_config() -> DeviceConfig {
        DeviceConfig {
            segment_target: 4 << 20,
            ..small_config()
        }
    }

    /// Child body shared by the two M5 tests: write lba 0, then a write at
    /// lba 1 whose staging append fails after `extra` bytes, then a write at
    /// lba 2 once space is back; flush and "crash" (drop, no close).
    #[cfg(unix)]
    async fn m5_child(dir: &Path, extra: u64) {
        let t = Arc::new(MockTransport::new());
        let mut d =
            TeaGardenDevice::create(t, keys(), [7u8; 16], 1024, dir, unsealed_config()).unwrap();
        d.write_at(0, &vec![0xA0u8; BS as usize]).await.unwrap();
        d.flush().await.unwrap();
        crate::testutil::limit_file_size(d.staging.len() + extra);
        assert!(d.write_at(1, &vec![0xB0u8; BS as usize]).await.is_err());
        crate::testutil::unlimit_file_size();
        d.write_at(2, &vec![0xC0u8; BS as usize]).await.unwrap();
        d.flush().await.unwrap();
    }

    /// Parent half: reopen the crashed dir; lba 0 and 2 (acknowledged) must
    /// read back, lba 1 (failed, never acknowledged) must read as a hole.
    #[cfg(unix)]
    async fn m5_verify(dir: &tempfile::TempDir) {
        let t = Arc::new(MockTransport::new());
        let mut r = TeaGardenDevice::open(t, keys(), dir.path(), unsealed_config())
            .expect("reopen after a failed staging append");
        let ok = |v: Vec<u8>, b: u8| v == vec![b; BS as usize];
        assert!(ok(r.read_at(0, 1).await.unwrap(), 0xA0), "lba 0 lost");
        assert!(
            ok(r.read_at(1, 1).await.unwrap(), 0),
            "failed write resurrected"
        );
        assert!(
            ok(r.read_at(2, 1).await.unwrap(), 0xC0),
            "acknowledged write after the failed append was lost"
        );
    }

    // M5: a staging append that fails CLEANLY (no bytes written — the disk was
    // already full) must not leave the record in the segment builder, or every
    // later record's offset shifts and a crash before upload makes open() fail
    // with "record_off != staged".
    #[cfg(unix)]
    #[tokio::test]
    async fn failed_staging_append_does_not_shift_segment_offsets() {
        if let Some(dir) = crate::testutil::child_dir() {
            return m5_child(&dir, 0).await;
        }
        let dir = tempfile::tempdir().unwrap();
        crate::testutil::run_in_child(
            "device::tests::failed_staging_append_does_not_shift_segment_offsets",
            dir.path(),
        );
        m5_verify(&dir).await;
    }

    // M5 + C1 together: the failed append was a SHORT write (torn bytes).
    #[cfg(unix)]
    #[tokio::test]
    async fn short_staging_append_does_not_lose_later_writes() {
        if let Some(dir) = crate::testutil::child_dir() {
            return m5_child(&dir, 10).await;
        }
        let dir = tempfile::tempdir().unwrap();
        crate::testutil::run_in_child(
            "device::tests::short_staging_append_does_not_lose_later_writes",
            dir.path(),
        );
        m5_verify(&dir).await;
    }

    /// Block content for the kill test: identifies its own lba.
    fn kill_block(lba: u64) -> Vec<u8> {
        let mut b = vec![(lba as u8).wrapping_mul(7) | 1; BS as usize];
        b[..8].copy_from_slice(&lba.to_le_bytes());
        b
    }

    // Single writer, in-process and deterministic: while one handle is open a
    // second open / create / recover of the same directory is refused, and the
    // directory is free again once the first handle is dropped.
    #[tokio::test]
    async fn second_open_of_a_live_device_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, small_config()).await;
        d.write_at(0, &vec![0x5Au8; BS as usize]).await.unwrap();
        d.close().await.unwrap();
        let head = d.checkpoint().await.unwrap();
        let in_use = |r: Result<TeaGardenDevice<MockTransport>>| match r {
            Ok(_) => panic!("second opener got a live device"),
            Err(e) => assert!(e.to_string().contains("in use"), "unexpected: {e}"),
        };
        in_use(TeaGardenDevice::open(
            Arc::clone(&t),
            keys(),
            dir.path(),
            small_config(),
        ));
        in_use(TeaGardenDevice::create(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            64,
            dir.path(),
            small_config(),
        ));
        in_use(
            TeaGardenDevice::recover_from_head_force(
                Arc::clone(&t),
                keys(),
                [7u8; 16],
                dir.path(),
                head,
                small_config(),
            )
            .await,
        );
        drop(d);
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0x5Au8; BS as usize]);
    }

    // Two processes, one device directory: a live writer (what `dev serve nbd`
    // is) and a second opener (what `dev status` / `gc` / `resize` do). The
    // second opener must be REFUSED. If it gets in, its open() trims the log
    // to the length it scanned — truncating entries the live writer appended
    // and acknowledged meanwhile — and the writer keeps appending after the
    // cut. The writer paces its write+flush loop so the second opener's scan
    // overlaps it; afterwards every acknowledged write must read back.
    #[cfg(unix)]
    #[tokio::test]
    async fn second_opener_is_refused_while_a_writer_is_live() {
        let cfg = DeviceConfig {
            segment_target: 4 << 20,
            ..small_config()
        };
        if let Some(dir) = crate::testutil::child_dir() {
            let t = Arc::new(MockTransport::new());
            let mut d = TeaGardenDevice::create(t, keys(), [7u8; 16], 1 << 20, &dir, cfg).unwrap();
            std::fs::write(dir.join("ready"), b"").unwrap();
            for lba in 0..600u64 {
                d.write_at(lba, &kill_block(lba)).await.unwrap();
                d.flush().await.unwrap();
                std::fs::write(dir.join("progress.tmp"), lba.to_string()).unwrap();
                std::fs::rename(dir.join("progress.tmp"), dir.join("progress")).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            std::fs::write(dir.join("done"), b"").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(30)); // parent kills us
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut child = crate::testutil::spawn_child(
            "device::tests::second_opener_is_refused_while_a_writer_is_live",
            dir.path(),
        );
        let t0 = std::time::Instant::now();
        while !dir.path().join("ready").exists() {
            assert!(t0.elapsed().as_secs() < 60, "writer never became ready");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let (mut opened, mut refused) = (0u32, 0u32);
        while !dir.path().join("done").exists() {
            match TeaGardenDevice::open(
                Arc::new(MockTransport::new()),
                keys(),
                dir.path(),
                cfg.clone(),
            ) {
                Ok(second) => {
                    opened += 1;
                    drop(second);
                }
                Err(e) => {
                    refused += 1;
                    assert!(e.to_string().contains("in use"), "unexpected error: {e}");
                }
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let acked: u64 = std::fs::read_to_string(dir.path().join("progress"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        println!("SECOND-OPENER: {opened} opens succeeded, {refused} refused while the writer ran");
        let mut r = TeaGardenDevice::open(Arc::new(MockTransport::new()), keys(), dir.path(), cfg)
            .expect("reopen after the writer is gone");
        let got = r.read_at(0, acked + 1).await.unwrap();
        let lost = (0..=acked)
            .filter(|&l| got[(l * BS) as usize..((l + 1) * BS) as usize] != kill_block(l)[..])
            .count();
        assert_eq!(
            lost, 0,
            "{lost} acknowledged writes lost (second opener got in {opened}x)"
        );
        assert_eq!(
            opened, 0,
            "a second opener got the device while it was live"
        );
        assert!(refused > 0);
    }

    // Kill-and-resume at the process boundary (LOCAL-ONLY: nothing is
    // uploaded, the segment target is never reached). A real child process
    // appends write+flush in a loop, publishing the last ACKNOWLEDGED
    // (flushed) lba after each flush, and is SIGKILLed a few ms into its write
    // loop. Each time the parent reopens the same directory: every
    // acknowledged write must read back, the at-most-one in-flight write must
    // be all-or-nothing, nothing past it may appear, and the NEXT child must
    // resume on top of the reopened log. (SIGKILL cannot split one write(2)
    // to a regular file, so this does not itself produce torn tails; those are
    // exercised by the RLIMIT_FSIZE short-write tests. The printed summary
    // reports how many kills did leave one.)
    #[cfg(unix)]
    #[tokio::test]
    async fn killed_writer_resumes_without_losing_acknowledged_writes() {
        // 4 MiB target, <= 400 one-block writes per session: never seals, so
        // nothing is uploaded to the child's (in-memory, lost) mock cloud.
        let cfg = DeviceConfig {
            segment_target: 4 << 20,
            ..small_config()
        };
        if let Some(dir) = crate::testutil::child_dir() {
            let t = Arc::new(MockTransport::new());
            let progress = dir.join("progress");
            let mut d = if dir.join("superblock").exists() {
                TeaGardenDevice::open(t, keys(), &dir, cfg).unwrap()
            } else {
                TeaGardenDevice::create(t, keys(), [7u8; 16], 1 << 20, &dir, cfg).unwrap()
            };
            let mut lba = std::fs::read_to_string(&progress)
                .map(|s| s.trim().parse::<u64>().unwrap() + 1)
                .unwrap_or(0);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let session_end = lba + 400;
            std::fs::write(dir.join("ready"), b"").unwrap(); // device open, writing next
            while std::time::Instant::now() < deadline {
                if lba == session_end {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                d.write_at(lba, &kill_block(lba)).await.unwrap();
                d.flush().await.unwrap();
                std::fs::write(dir.join("progress.tmp"), lba.to_string()).unwrap();
                std::fs::rename(dir.join("progress.tmp"), &progress).unwrap();
                lba += 1;
            }
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut torn_kills = 0;
        for (round, delay_ms) in [1u64, 2, 3, 4, 5].into_iter().enumerate() {
            let _ = std::fs::remove_file(dir.path().join("ready"));
            let mut child = crate::testutil::spawn_child(
                "device::tests::killed_writer_resumes_without_losing_acknowledged_writes",
                dir.path(),
            );
            // kill DURING the write loop: wait for the child's device to be open
            let t0 = std::time::Instant::now();
            while !dir.path().join("ready").exists() {
                assert!(t0.elapsed().as_secs() < 60, "child never became ready");
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            child.kill().unwrap(); // SIGKILL
            child.wait().unwrap();
            let Ok(p) = std::fs::read_to_string(dir.path().join("progress")) else {
                continue; // killed before its first acknowledged write
            };
            let acked: u64 = p.trim().parse().unwrap();
            let log = dir.path().join("staging.log");
            let k = keys();
            let (len, tail) = {
                let mut rd = StagingReader::open(&log, &k.meta_key, [7u8; 16]).unwrap();
                while rd.next_entry(|_| false).unwrap().is_some() {}
                (rd.file_len(), rd.tail_state().unwrap())
            };
            if tail != TailState::Clean {
                torn_kills += 1;
            }
            let mut r = TeaGardenDevice::open(
                Arc::new(MockTransport::new()),
                keys(),
                dir.path(),
                cfg.clone(),
            )
            .expect("reopen after SIGKILL");
            let got = r.read_at(0, acked + 3).await.unwrap();
            for lba in 0..acked + 3 {
                let blk = &got[(lba * BS) as usize..((lba + 1) * BS) as usize];
                let ok = if lba <= acked {
                    blk == kill_block(lba).as_slice()
                } else if lba == acked + 1 {
                    blk == kill_block(lba).as_slice() || blk.iter().all(|&x| x == 0)
                } else {
                    blk.iter().all(|&x| x == 0)
                };
                assert!(ok, "round {round}: lba {lba} wrong (acked through {acked})");
            }
            println!(
                "KILL round {round}: SIGKILL {delay_ms} ms into writing; acked through lba {acked}; \
                 log {len} B, tail {tail:?} -> reopened, {} acked blocks verified, now {} B",
                acked + 1,
                std::fs::metadata(&log).unwrap().len()
            );
        }
        println!("KILL summary: {torn_kills} of 5 kills left a torn tail");
    }

    // H4: the staging log must stay bounded. Churn many times the cache budget
    // through a small region with periodic confirm + checkpoint; the log may
    // only hold what is not yet confirmed plus a compact base mapping.
    #[tokio::test]
    async fn staging_log_stays_bounded_under_churn() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DeviceConfig {
            cache: CacheConfig {
                budget_bytes: 256 * 1024,
                ..Default::default()
            },
            ..small_config()
        };
        let (mut d, t) = dev(&dir, 1024, cfg.clone()).await;
        let log = dir.path().join("staging.log");
        let region = 32u64; // blocks (128 KiB)
        let rounds = 100u8; // 12.5 MiB written ≈ 50x the cache budget
        let mut max_len = 0u64;
        for round in 0..rounds {
            let data = vec![round; (region * BS) as usize];
            d.write_at(0, &data).await.unwrap();
            d.flush().await.unwrap();
            if round % 10 == 9 {
                d.close().await.unwrap();
                d.checkpoint().await.unwrap();
            }
            max_len = max_len.max(std::fs::metadata(&log).unwrap().len());
        }
        d.close().await.unwrap();
        let head = d.checkpoint().await.unwrap();
        let written = u64::from(rounds) * region * BS;
        assert!(
            max_len <= 1 << 20,
            "staging.log reached {max_len} bytes after {written} bytes of churn (unbounded)"
        );
        drop(d);
        // still exact after reopen, and the head still recovers a fresh machine
        let last = vec![rounds - 1; (region * BS) as usize];
        let mut r = reopen(&t, &dir, cfg.clone());
        assert_eq!(r.read_at(0, region).await.unwrap(), last);
        let fresh = tempfile::tempdir().unwrap();
        let mut f = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            cfg,
        )
        .await
        .unwrap();
        assert_eq!(f.read_at(0, region).await.unwrap(), last);
    }

    /// Everything the staging log determines, for compaction equivalence:
    /// the live FTL, the prefix FTL at every watermark `W'` from `w_from` up
    /// past the last segment, and the block totals of live segments.
    type LogView = (
        Vec<(u64, u64, Phys)>,
        Vec<Vec<(u64, u64, Phys)>>,
        BTreeMap<u64, u64>,
    );

    fn log_view(d: &TeaGardenDevice<MockTransport>, w_from: u64) -> LogView {
        let prefixes = (w_from..=d.next_segment_id + 1)
            .map(|w| d.replay_prefix_ftl(w).unwrap().extents())
            .collect();
        let totals = d
            .seg_total_blocks
            .iter()
            .filter(|(&s, _)| d.ftl.live_blocks(s) > 0)
            .map(|(&s, &n)| (s, n))
            .collect();
        (d.ftl.extents(), prefixes, totals)
    }

    async fn read_all(d: &mut TeaGardenDevice<MockTransport>, cap: u64) -> Vec<u8> {
        d.read_at(0, cap).await.unwrap()
    }

    // H4 equivalence: compaction must not change ANYTHING the log determines.
    // The log here holds every hard case: confirmed writes, an overwrite, a
    // discard, a successful GC (relocations under the watermark), a GC whose
    // drain FAILED (relocations ABOVE the watermark) followed by a discard and
    // an overwrite of relocated blocks (the order-sensitive case), and an
    // unconfirmed foreground tail in the open segment.
    #[tokio::test]
    async fn staging_compaction_is_replay_equivalent() {
        let dir = tempfile::tempdir().unwrap();
        let cap = 64u64;
        let (mut d, t) = dev(&dir, cap, small_config()).await;
        d.write_at(0, &vec![0xA1u8; 16 * BS as usize])
            .await
            .unwrap();
        d.close().await.unwrap();
        d.write_at(0, &vec![0xB2u8; 6 * BS as usize]).await.unwrap();
        d.discard(10, 2).await.unwrap();
        d.close().await.unwrap();
        assert!(d.gc().await.unwrap().extents_moved > 0);
        d.write_at(16, &vec![0xC3u8; 16 * BS as usize])
            .await
            .unwrap();
        d.close().await.unwrap();
        d.write_at(16, &vec![0xD4u8; 14 * BS as usize])
            .await
            .unwrap();
        d.close().await.unwrap();
        // GC whose drain fails: relocations staged into segments above W
        *t.fail_uploads.lock().unwrap() = Some("offline".into());
        let rep = d.gc().await.unwrap();
        assert!(rep.extents_moved > 0 && rep.skipped.is_some(), "{rep:?}");
        *t.fail_uploads.lock().unwrap() = None;
        // discard + overwrite blocks that the unconfirmed relocation moved
        d.discard(30, 1).await.unwrap();
        d.write_at(31, &vec![0xE5u8; BS as usize]).await.unwrap();
        d.write_at(40, &vec![0xF6u8; 3 * BS as usize])
            .await
            .unwrap();
        d.flush().await.unwrap();

        let w = d.cloud_watermark();
        assert!(w >= 1);
        let before = log_view(&d, w);
        let data_before = read_all(&mut d, cap).await;
        let len_before = d.staging.len();
        assert!(d.compact_staging().unwrap(), "nothing was compacted");
        assert!(d.staging.len() < len_before);
        assert_eq!(
            std::fs::metadata(dir.path().join("staging.log"))
                .unwrap()
                .len(),
            d.staging.len()
        );
        // in-session: prefix replays (checkpoint input) are unchanged
        assert_eq!(log_view(&d, w).1, before.1, "prefix replay changed");
        // appends after compaction go to the NEW file
        d.write_at(50, &vec![0x77u8; BS as usize]).await.unwrap();
        d.flush().await.unwrap();
        drop(d);

        // crash + reopen: live FTL, prefixes, totals and data are unchanged
        let mut r = reopen(&t, &dir, small_config());
        let mut after = log_view(&r, w);
        // the post-compaction write (1 block at lba 50) is the only difference
        let seg50 = r.ftl.lookup(50).unwrap().segment_id;
        after.0.retain(|&(l, _, _)| l != 50);
        *after.2.get_mut(&seg50).unwrap() -= 1;
        after.2.retain(|_, n| *n > 0);
        assert_eq!(after.0, before.0, "live FTL changed");
        assert_eq!(after.1.len(), before.1.len());
        assert_eq!(after.2, before.2, "per-segment totals changed");
        for (s, n) in &before.2 {
            assert_eq!(after.2.get(s), Some(n), "segment {s} total changed");
        }
        let mut data_after = read_all(&mut r, cap).await;
        assert!(data_after[50 * BS as usize..51 * BS as usize]
            .iter()
            .all(|&x| x == 0x77));
        data_after[50 * BS as usize..51 * BS as usize].fill(0);
        assert!(data_after == data_before, "device contents changed");
        // the unconfirmed segments were re-framed from the compacted log and upload
        r.close().await.unwrap();
        let head = r.checkpoint().await.unwrap();
        let fresh = tempfile::tempdir().unwrap();
        let mut f = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            small_config(),
        )
        .await
        .unwrap();
        let mut from_head = read_all(&mut f, cap).await;
        from_head[50 * BS as usize..51 * BS as usize].fill(0);
        assert!(
            from_head == data_before,
            "head recovery after compaction differs"
        );
    }

    // H4 + GC: dead-block accounting survives compaction + reopen, so a
    // partially-dead confirmed segment is still picked as a GC victim.
    #[tokio::test]
    async fn gc_still_finds_partially_dead_victims_after_compaction_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 256, small_config()).await;
        d.write_at(0, &vec![0x10u8; 6 * BS as usize]).await.unwrap();
        d.close().await.unwrap(); // segment 1: 6 blocks
        d.write_at(0, &vec![0x20u8; 5 * BS as usize]).await.unwrap();
        d.close().await.unwrap(); // segment 1 now 1/6 live
        assert!(d.compact_staging().unwrap());
        drop(d);
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.seg_total_blocks.get(&1), Some(&6));
        let rep = r.gc().await.unwrap();
        assert!(
            rep.compacted.contains(&1),
            "segment 1 not a victim: {rep:?}"
        );
        assert_eq!(r.read_at(5, 1).await.unwrap(), vec![0x10u8; BS as usize]);
    }

    // H4 crash safety: a compaction interrupted before its rename leaves a
    // scratch file; open() discards it and the old log is authoritative.
    #[tokio::test]
    async fn interrupted_compaction_scratch_file_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, small_config()).await;
        d.write_at(0, &vec![0x31u8; 4 * BS as usize]).await.unwrap();
        d.close().await.unwrap();
        d.write_at(8, &vec![0x32u8; 2 * BS as usize]).await.unwrap();
        d.flush().await.unwrap();
        drop(d);
        std::fs::write(dir.path().join(STAGING_COMPACT_TMP), b"half-written").unwrap();
        let mut r = reopen(&t, &dir, small_config());
        assert!(!dir.path().join(STAGING_COMPACT_TMP).exists());
        assert_eq!(
            r.read_at(0, 4).await.unwrap(),
            vec![0x31u8; 4 * BS as usize]
        );
        assert_eq!(
            r.read_at(8, 2).await.unwrap(),
            vec![0x32u8; 2 * BS as usize]
        );
    }

    // H4 partial failure: the disk fills while the compacted copy is written.
    // The compaction fails, the scratch file is removed, the OLD log stays the
    // live one (appends still land in it) and a reopen recovers everything.
    #[cfg(unix)]
    #[tokio::test]
    async fn compaction_failing_on_full_disk_keeps_old_log() {
        if let Some(dir) = crate::testutil::child_dir() {
            let t = Arc::new(MockTransport::new());
            let mut d = TeaGardenDevice::create(
                Arc::clone(&t),
                keys(),
                [7u8; 16],
                64,
                &dir,
                small_config(),
            )
            .unwrap();
            d.write_at(0, &vec![0x41u8; 8 * BS as usize]).await.unwrap();
            d.close().await.unwrap();
            d.write_at(0, &vec![0x42u8; 8 * BS as usize]).await.unwrap();
            d.close().await.unwrap();
            d.write_at(20, &vec![0x43u8; 2 * BS as usize])
                .await
                .unwrap();
            d.flush().await.unwrap();
            let len = d.staging.len();
            // no file may grow past 200 bytes: the scratch copy fails early
            crate::testutil::limit_file_size(200);
            assert!(d.compact_staging().is_err());
            crate::testutil::unlimit_file_size();
            assert!(!dir.join(STAGING_COMPACT_TMP).exists());
            assert_eq!(d.staging.len(), len);
            d.write_at(30, &vec![0x44u8; BS as usize]).await.unwrap();
            d.flush().await.unwrap();
            // persist the mock cloud for the parent
            for id in 1..100i64 {
                if let Some(raw) = t.get_raw(id) {
                    std::fs::write(dir.join(format!("msg-{id}")), raw).unwrap();
                }
            }
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        crate::testutil::run_in_child(
            "device::tests::compaction_failing_on_full_disk_keeps_old_log",
            dir.path(),
        );
        let t = Arc::new(MockTransport::new());
        for id in 1..100i64 {
            if let Ok(raw) = std::fs::read(dir.path().join(format!("msg-{id}"))) {
                t.set_next_id(id);
                t.upload_block(&raw, "x").await.unwrap();
                std::fs::remove_file(dir.path().join(format!("msg-{id}"))).unwrap();
            }
        }
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(
            r.read_at(0, 8).await.unwrap(),
            vec![0x42u8; 8 * BS as usize]
        );
        assert_eq!(
            r.read_at(20, 2).await.unwrap(),
            vec![0x43u8; 2 * BS as usize]
        );
        assert_eq!(r.read_at(30, 1).await.unwrap(), vec![0x44u8; BS as usize]);
    }

    // H4 at scale with GC: random churn with discards, periodic GC, forced
    // compaction (with confirmed AND unconfirmed data in the log) and crash
    // reopens, checked against a reference model after every step.
    #[tokio::test]
    async fn churn_with_compaction_and_reopens_matches_reference_model() {
        let dir = tempfile::tempdir().unwrap();
        let cap = 256u64;
        let (mut d, t) = dev(&dir, cap, small_config()).await;
        let mut model: Vec<Option<u8>> = vec![None; cap as usize];
        let mut rng: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let check = |got: &[u8], model: &[Option<u8>], what: &str| {
            for (b, m) in model.iter().enumerate() {
                let want = m.unwrap_or(0);
                assert!(
                    got[b * BS as usize..(b + 1) * BS as usize]
                        .iter()
                        .all(|&x| x == want),
                    "block {b} mismatch {what}"
                );
            }
        };
        let mut deleted = 0usize;
        for op in 0..300u64 {
            let lba = next() % 240;
            let count = (1 + next() % 8).min(cap - lba);
            if next() % 4 == 0 {
                d.discard(lba, count).await.unwrap();
                model[lba as usize..(lba + count) as usize].fill(None);
            } else {
                let fill = ((op as u8).wrapping_mul(37)) | 1;
                d.write_at(lba, &vec![fill; (count * BS) as usize])
                    .await
                    .unwrap();
                model[lba as usize..(lba + count) as usize].fill(Some(fill));
            }
            match op % 50 {
                24 => {
                    // compact with an unconfirmed open segment in the log
                    d.flush().await.unwrap();
                    d.compact_staging().unwrap();
                    drop(d);
                    d = reopen(&t, &dir, small_config());
                    check(
                        &read_all(&mut d, cap).await,
                        &model,
                        "after mid-compaction reopen",
                    );
                }
                49 => {
                    d.close().await.unwrap();
                    deleted += d.gc().await.unwrap().deleted.len();
                    assert!(d.compact_staging().unwrap());
                    drop(d);
                    d = reopen(&t, &dir, small_config());
                    check(
                        &read_all(&mut d, cap).await,
                        &model,
                        "after gc+compaction reopen",
                    );
                }
                _ => {}
            }
        }
        assert!(deleted > 0, "GC must keep reclaiming across compactions");
        d.close().await.unwrap();
        let head = d.checkpoint().await.unwrap();
        let fresh = tempfile::tempdir().unwrap();
        let mut f = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            small_config(),
        )
        .await
        .unwrap();
        check(&read_all(&mut f, cap).await, &model, "after head recovery");
    }

    // L4 (explicit override): the force variant does overwrite, by request.
    #[tokio::test]
    async fn recover_from_head_force_overwrites_on_request() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x11u8; BS as usize]).await.unwrap();
        d.close().await.unwrap();
        let head = d.checkpoint().await.unwrap();
        d.write_at(5, &vec![0x22u8; BS as usize]).await.unwrap();
        d.flush().await.unwrap();
        drop(d);
        let mut r = TeaGardenDevice::recover_from_head_force(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            dir.path(),
            head,
            small_config(),
        )
        .await
        .unwrap();
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0x11u8; BS as usize]);
        // the never-uploaded write is gone: that is what force means
        assert_eq!(r.read_at(5, 1).await.unwrap(), vec![0u8; BS as usize]);
    }

    // L4: recover_from_head truncates `catalog` and `staging.log` in the target
    // directory. Pointed at a live device directory it would destroy the local
    // state (including staged, never-uploaded writes). It must refuse.
    #[tokio::test]
    async fn recover_from_head_refuses_non_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x11u8; BS as usize]).await.unwrap();
        d.close().await.unwrap();
        let head = d.checkpoint().await.unwrap();
        // a staged, never-uploaded write that only the local log holds
        d.write_at(5, &vec![0x22u8; BS as usize]).await.unwrap();
        d.flush().await.unwrap();
        drop(d);
        let before = std::fs::read(dir.path().join("staging.log")).unwrap();
        let res = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            dir.path(),
            head,
            small_config(),
        )
        .await;
        assert!(
            res.is_err(),
            "recover_from_head overwrote a non-empty device dir"
        );
        assert_eq!(
            std::fs::read(dir.path().join("staging.log")).unwrap(),
            before
        );
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.read_at(5, 1).await.unwrap(), vec![0x22u8; BS as usize]);
    }

    // M3/M4 (documents the REAL property, it is not a guarantee): rollback of
    // the superblock and replay of an older DeviceHead are both accepted.
    // If someone later adds anti-rollback, this test must be inverted along
    // with the docs in superblock.rs / head.rs / error.rs.
    #[tokio::test]
    async fn superblock_and_head_rollback_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x01u8; BS as usize]).await.unwrap();
        d.close().await.unwrap();
        let old_head = d.checkpoint().await.unwrap();
        let old_sb = std::fs::read(dir.path().join("superblock")).unwrap();
        d.resize(2048).unwrap();
        d.rotate_epoch().await.unwrap();
        d.write_at(0, &vec![0x02u8; BS as usize]).await.unwrap();
        d.close().await.unwrap();
        d.checkpoint().await.unwrap();
        drop(d);
        // M4: put the older, authentic superblock back — open() accepts it
        std::fs::write(dir.path().join("superblock"), &old_sb).unwrap();
        let r = reopen(&t, &dir, small_config());
        assert_eq!((r.capacity_blocks(), r.current_epoch()), (1024, 0));
        // M3: the older head still recovers, to the older prefix
        let fresh = tempfile::tempdir().unwrap();
        let mut f = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            old_head,
            small_config(),
        )
        .await
        .unwrap();
        assert_eq!(f.read_at(0, 1).await.unwrap(), vec![0x01u8; BS as usize]);
    }

    /// Persist a mock cloud to `dir/msg-<id>` files (child → parent hand-off).
    fn dump_mock(t: &MockTransport, dir: &Path) {
        for id in 1..1000i64 {
            if let Some(raw) = t.get_raw(id) {
                std::fs::write(dir.join(format!("msg-{id}")), raw).unwrap();
            }
        }
    }

    /// Rebuild a mock cloud from [`dump_mock`] files, same message ids.
    async fn load_mock(dir: &Path) -> Arc<MockTransport> {
        let t = Arc::new(MockTransport::new());
        for id in 1..1000i64 {
            let p = dir.join(format!("msg-{id}"));
            if let Ok(raw) = std::fs::read(&p) {
                t.set_next_id(id);
                assert_eq!(t.upload_block(&raw, "x").await.unwrap().message_id, id);
                std::fs::remove_file(&p).unwrap();
            }
        }
        t
    }

    // FSYNC-1: a failed staging fsync is STICKY. Linux drops the error state of
    // the dirty pages after reporting it once, so a later fsync can succeed
    // although the earlier data never reached disk ("fsyncgate"). If the
    // device then acked the next flush, a client would believe writes durable
    // that may be gone. Every later write/flush must fail until reopen.
    #[tokio::test]
    async fn failed_staging_fsync_is_sticky_until_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x61u8; BS as usize]).await.unwrap();
        d.inject_fsync_failures(1, 0);
        assert!(
            d.flush().await.is_err(),
            "injected fsync failure not reported"
        );
        assert!(
            d.flush().await.is_err(),
            "a flush after a failed fsync reported success"
        );
        assert!(d.write_at(1, &vec![0x62u8; BS as usize]).await.is_err());
        assert!(d.discard(0, 1).await.is_err());
        assert!(d.close().await.is_err());
        assert!(d.checkpoint().await.is_err());
        drop(d);
        // reopening re-reads what is actually on disk; the device works again
        let mut r = reopen(&t, &dir, small_config());
        r.write_at(2, &vec![0x63u8; BS as usize]).await.unwrap();
        r.flush().await.unwrap();
        assert_eq!(r.read_at(2, 1).await.unwrap(), vec![0x63u8; BS as usize]);
    }

    // FSYNC-2 / CATALOG: a catalog fsync failure during an upload must surface
    // (not be swallowed by try_upload), must NOT count the segment as
    // confirmed, and must make the device sticky-failed.
    #[tokio::test]
    async fn failed_catalog_fsync_is_not_a_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x71u8; 4 * BS as usize]).await.unwrap();
        d.flush().await.unwrap();
        d.inject_fsync_failures(0, 1);
        let res = d.close().await; // seal + upload + catalog append (fails)
        assert!(res.is_err(), "catalog fsync failure was swallowed");
        assert_eq!(d.confirmed_segments(), 0, "segment counted as confirmed");
        assert!(
            d.flush().await.is_err(),
            "device not sticky after catalog failure"
        );
        drop(d);
        // the staged bytes are still local: reopen re-frames and re-uploads
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.confirmed_segments(), 0);
        r.close().await.unwrap();
        assert!(r.confirmed_segments() >= 1);
        assert_eq!(
            r.read_at(0, 4).await.unwrap(),
            vec![0x71u8; 4 * BS as usize]
        );
    }

    // CATALOG (real short write): a catalog append that is cut short leaves 8
    // bytes of a 16-byte record. Pre-fix, the next append landed after them,
    // so every later record was misaligned and a reopen read garbage message
    // ids. RLIMIT_FSIZE in a child makes the kernel cut the write.
    #[cfg(unix)]
    #[tokio::test]
    async fn short_catalog_write_never_misaligns_or_counts_as_confirmed() {
        if let Some(dir) = crate::testutil::child_dir() {
            let t = Arc::new(MockTransport::new());
            let mut d = TeaGardenDevice::create(
                Arc::clone(&t),
                keys(),
                [7u8; 16],
                1024,
                &dir,
                small_config(),
            )
            .unwrap();
            let mut acked = Vec::new();
            d.write_at(0, &vec![0xA1u8; 8 * BS as usize]).await.unwrap();
            d.close().await.unwrap();
            acked.push("a");
            d.write_at(100, &vec![0xB2u8; 2 * BS as usize])
                .await
                .unwrap();
            let cat_len = std::fs::metadata(dir.join("catalog")).unwrap().len();
            crate::testutil::limit_file_size(cat_len + 8);
            let b_closed = d.close().await.is_ok();
            crate::testutil::unlimit_file_size();
            if b_closed {
                acked.push("b");
            }
            if d.write_at(200, &vec![0xC3u8; 2 * BS as usize])
                .await
                .is_ok()
                && d.close().await.is_ok()
            {
                acked.push("c");
            }
            std::fs::write(dir.join("acked"), acked.join(",")).unwrap();
            drop(d);
            dump_mock(&t, &dir);
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        crate::testutil::run_in_child(
            "device::tests::short_catalog_write_never_misaligns_or_counts_as_confirmed",
            dir.path(),
        );
        let acked = std::fs::read_to_string(dir.path().join("acked")).unwrap();
        let t = load_mock(dir.path()).await;
        assert_eq!(
            std::fs::metadata(dir.path().join("catalog")).unwrap().len() % 16,
            0,
            "catalog left with a partial record (acked: {acked})"
        );
        let mut r = reopen(&t, &dir, small_config());
        for (tag, lba, n, b) in [
            ("a", 0, 8, 0xA1u8),
            ("b", 100, 2, 0xB2),
            ("c", 200, 2, 0xC3),
        ] {
            let got = r.read_at(lba, n).await;
            if acked.split(',').any(|a| a == tag) {
                let got = got.unwrap_or_else(|e| panic!("acked write {tag} unreadable: {e}"));
                assert!(got == vec![b; (n * BS) as usize], "acked write {tag} wrong");
            }
        }
    }

    // CREATE: create() over a directory that already holds a device must
    // refuse — it used to truncate staging.log and replace the superblock.
    #[tokio::test]
    async fn create_refuses_a_directory_holding_a_device() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x81u8; BS as usize]).await.unwrap();
        d.flush().await.unwrap();
        drop(d);
        let res = TeaGardenDevice::create(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            1024,
            dir.path(),
            small_config(),
        );
        assert!(res.is_err(), "create() overwrote an existing device");
        drop(res);
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0x81u8; BS as usize]);
        // each marker file alone is enough to refuse
        for name in ["superblock", "catalog", "staging.log"] {
            let other = tempfile::tempdir().unwrap();
            std::fs::write(other.path().join(name), b"x").unwrap();
            let res = TeaGardenDevice::create(
                Arc::clone(&t),
                keys(),
                [7u8; 16],
                64,
                other.path(),
                small_config(),
            );
            assert!(res.is_err(), "create() accepted a dir holding {name}");
            assert_eq!(std::fs::read(other.path().join(name)).unwrap(), b"x");
        }
    }

    // RECOVERY: a recovery that dies part-way (here: the disk fills while the
    // staging log is seeded — a real short write in a child) must not leave a
    // directory that open() accepts as a device. Pre-fix it opened with a
    // silently partial FTL.
    #[cfg(unix)]
    #[tokio::test]
    async fn interrupted_recovery_is_refused_by_open() {
        if let Some(dir) = crate::testutil::child_dir() {
            let t = load_mock(&dir).await;
            let head: i64 = std::fs::read_to_string(dir.join("head"))
                .unwrap()
                .parse()
                .unwrap();
            let target = dir.join("rec");
            // superblock (80 B) + catalog fit; the seeded staging log does not
            crate::testutil::limit_file_size(120);
            let res = TeaGardenDevice::recover_from_head(
                Arc::clone(&t),
                keys(),
                [7u8; 16],
                &target,
                head,
                tiny_config(),
            )
            .await;
            crate::testutil::unlimit_file_size();
            assert!(res.is_err(), "recovery should have hit the file-size limit");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, tiny_config()).await;
        for lba in [0u64, 10, 20, 30] {
            d.write_at(lba, &vec![0x91u8; BS as usize]).await.unwrap();
        }
        d.close().await.unwrap();
        let head = d.checkpoint().await.unwrap();
        drop(d);
        let work = tempfile::tempdir().unwrap();
        dump_mock(&t, work.path());
        std::fs::write(work.path().join("head"), head.to_string()).unwrap();
        crate::testutil::run_in_child(
            "device::tests::interrupted_recovery_is_refused_by_open",
            work.path(),
        );
        let target = work.path().join("rec");
        assert!(target.join("superblock").exists(), "recovery got nowhere");
        match TeaGardenDevice::open(Arc::clone(&t), keys(), &target, tiny_config()) {
            Ok(r) => panic!(
                "open() accepted a half-recovered dir ({} of 4 blocks mapped)",
                r.mapped_blocks()
            ),
            Err(e) => assert!(e.to_string().contains("incomplete recovery"), "{e}"),
        }
        // a forced re-run completes it
        let mut r = TeaGardenDevice::recover_from_head_force(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            &target,
            head,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(r.mapped_blocks(), 4);
        assert_eq!(r.read_at(30, 1).await.unwrap(), vec![0x91u8; BS as usize]);
        drop(r);
        reopen_at(&t, &target).await;
    }

    async fn reopen_at(t: &Arc<MockTransport>, dir: &Path) {
        let mut r = TeaGardenDevice::open(Arc::clone(t), keys(), dir, tiny_config()).unwrap();
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0x91u8; BS as usize]);
    }

    // A forged (tampered) superblock fails open() closed. (A rolled-back but
    // authentic one does NOT — see superblock_and_head_rollback_are_accepted.)
    #[tokio::test]
    async fn tampered_superblock_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0u8; BS as usize]).await.unwrap();
        d.close().await.unwrap();
        drop(d);
        let sp = dir.path().join("superblock");
        let mut blob = std::fs::read(&sp).unwrap();
        blob[28] ^= 0xFF; // flip a capacity byte → MAC mismatch
        std::fs::write(&sp, &blob).unwrap();
        assert!(TeaGardenDevice::open(Arc::clone(&t), keys(), dir.path(), small_config()).is_err());
    }

    // A lost catalog record makes a confirmed segment look unconfirmed: recovery
    // reconstructs it from staging and re-uploads it — no crash, no wrong data
    // (idempotent re-confirmation; the old cloud copy is orphaned).
    #[tokio::test]
    async fn corrupt_catalog_reuploads_not_corrupts() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0xC4u8; 4 * BS as usize];
        d.write_at(0, &a).await.unwrap();
        d.close().await.unwrap();
        assert!(d.confirmed_segments() >= 1);
        let msgs_before = t.message_count();
        drop(d);
        std::fs::write(dir.path().join("catalog"), b"").unwrap(); // lose all confirmations

        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.confirmed_segments(), 0); // empty catalog → looks unconfirmed
        assert_eq!(r.read_at(0, 4).await.unwrap(), a); // reconstructed from staging
        r.close().await.unwrap(); // re-uploads
        assert!(r.confirmed_segments() >= 1);
        assert!(t.message_count() > msgs_before); // a NEW cloud copy (old orphaned)
        assert_eq!(r.read_at(0, 4).await.unwrap(), a);
    }

    // A trailing partial catalog record (torn append) is ignored on load: the full
    // records still parse, no crash, no misread.
    #[tokio::test]
    async fn corrupt_catalog_trailing_partial_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0xD5u8; 4 * BS as usize];
        d.write_at(0, &a).await.unwrap();
        d.close().await.unwrap();
        let confirmed = d.confirmed_segments();
        drop(d);
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join("catalog"))
                .unwrap();
            f.write_all(&[1, 2, 3, 4, 5]).unwrap(); // torn 16-byte record
            f.sync_all().unwrap();
        }
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.confirmed_segments(), confirmed); // full records intact
        assert_eq!(r.read_at(0, 4).await.unwrap(), a);
    }

    // Anti-substitution: if the (now load-bearing) catalog is corrupted to point a
    // segment at the WRONG cloud message, the read fails CLOSED on the
    // MAC-authenticated header mismatch instead of returning another segment's
    // bytes as this LBA's data.
    #[tokio::test]
    async fn swapped_catalog_entry_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        // two distinct confirmed segments (each 8-block write seals a full segment)
        d.write_at(0, &vec![0x01u8; 8 * BS as usize]).await.unwrap();
        d.write_at(100, &vec![0x02u8; 8 * BS as usize])
            .await
            .unwrap();
        d.close().await.unwrap();
        assert!(d.confirmed_segments() >= 2);
        drop(d);

        // swap the message_ids of segment 1 and segment 2 in the catalog
        let cat = dir.path().join("catalog");
        let data = std::fs::read(&cat).unwrap();
        let mut recs: Vec<(u64, i64)> = data
            .as_chunks::<16>()
            .0
            .iter()
            .map(|r| {
                (
                    u64::from_le_bytes(r[..8].try_into().unwrap()),
                    i64::from_le_bytes(r[8..16].try_into().unwrap()),
                )
            })
            .collect();
        let mid1 = recs.iter().find(|(s, _)| *s == 1).unwrap().1;
        let mid2 = recs.iter().find(|(s, _)| *s == 2).unwrap().1;
        assert_ne!(mid1, mid2);
        for (s, m) in recs.iter_mut() {
            if *s == 1 {
                *m = mid2;
            } else if *s == 2 {
                *m = mid1;
            }
        }
        let mut out = Vec::new();
        for (s, m) in &recs {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&m.to_le_bytes());
        }
        std::fs::write(&cat, &out).unwrap();

        // lba 0 maps to segment 1 → the transport serves segment 2's bytes.
        // RANGED path (default): the index AAD binds the expected identity →
        // fail closed.
        let mut r = reopen(&t, &dir, small_config());
        let err = r.read_at(0, 1).await.unwrap_err();
        assert!(matches!(err, DeviceError::Corruption(_)));
        drop(r);

        // WHOLE-segment path (ranged disabled): the MAC-authenticated header
        // check catches the same substitution.
        let cfg = DeviceConfig {
            read: ReadConfig {
                ranged_reads: false,
                ..Default::default()
            },
            ..small_config()
        };
        let mut r = reopen(&t, &dir, cfg);
        let err = r.read_at(0, 1).await.unwrap_err();
        assert!(matches!(err, DeviceError::Corruption(_)));
    }

    // A device created but never written, then reopened, recovers empty: no
    // mappings, reads are zeros, and writes still work (next segment id started 1).
    #[tokio::test]
    async fn recover_empty_device() {
        let dir = tempfile::tempdir().unwrap();
        let (d, t) = dev(&dir, 64, small_config()).await;
        drop(d); // created, never written
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.mapped_blocks(), 0);
        assert_eq!(r.confirmed_segments(), 0);
        assert_eq!(r.read_at(0, 4).await.unwrap(), vec![0u8; 4 * BS as usize]);
        r.write_at(0, &vec![0xEEu8; BS as usize]).await.unwrap();
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0xEEu8; BS as usize]);
    }

    // Recovery preserves the key epoch: after a rotation (persisted in the
    // superblock) and a crash, a reopen resumes at the new epoch and still reads
    // both the old- and new-epoch data.
    #[tokio::test]
    async fn recover_after_epoch_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let old = vec![0x0Au8; 2 * BS as usize];
        d.write_at(0, &old).await.unwrap();
        d.rotate_epoch().await.unwrap(); // seals epoch-0 seg + persists epoch=1
        let new = vec![0x0Bu8; 2 * BS as usize];
        d.write_at(10, &new).await.unwrap();
        d.close().await.unwrap();
        drop(d);

        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.current_epoch(), 1); // epoch restored from the superblock
        assert_eq!(r.read_at(0, 2).await.unwrap(), old); // epoch-0 record
        assert_eq!(r.read_at(10, 2).await.unwrap(), new); // epoch-1 record
        r.write_at(20, &vec![0x0Cu8; BS as usize]).await.unwrap(); // uses epoch 1
        r.close().await.unwrap();
        assert_eq!(r.read_at(20, 1).await.unwrap(), vec![0x0Cu8; BS as usize]);
    }

    // A BACKLOG of unconfirmed segments (Telegram down for a while): segment 1
    // seals but its upload fails (staged + pending), segment 2 is still open — BOTH
    // are recovered in ONE open(). After the outage clears they re-upload, and a
    // SECOND reopen reads them back through the real download → SegmentReader path,
    // closing the "re-framed blob survives an upload→download round-trip" gap.
    #[tokio::test]
    async fn recover_multiple_unconfirmed_segments() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        *t.fail_uploads.lock().unwrap() = Some("dc offline".into());
        let a = vec![0xA0u8; 8 * BS as usize]; // fills + seals segment 1 (upload fails)
        let b = vec![0xB0u8; 4 * BS as usize]; // segment 2 (stays open)
        d.write_at(0, &a).await.unwrap();
        d.write_at(200, &b).await.unwrap();
        d.flush().await.unwrap();
        assert_eq!(d.confirmed_segments(), 0); // dc offline → nothing uploaded
        assert_eq!(t.message_count(), 0);
        drop(d);

        // recover BOTH unconfirmed segments in a single open()
        let mut r = reopen(&t, &dir, small_config());
        assert_eq!(r.confirmed_segments(), 0);
        assert_eq!(r.read_at(0, 8).await.unwrap(), a); // reconstructed segment 1
        assert_eq!(r.read_at(200, 4).await.unwrap(), b); // reconstructed segment 2

        // outage clears → close re-uploads BOTH recovered segments
        *t.fail_uploads.lock().unwrap() = None;
        r.close().await.unwrap();
        assert!(r.confirmed_segments() >= 2);
        drop(r);

        // SECOND reopen: both are confirmed now → served via the real download →
        // SegmentReader path (not the reconstruction cache). This proves the
        // re-framed blobs are valid, uploadable, downloadable segments.
        let mut r2 = reopen(&t, &dir, small_config());
        assert!(r2.confirmed_segments() >= 2);
        assert_eq!(r2.read_at(0, 8).await.unwrap(), a);
        assert_eq!(r2.read_at(200, 4).await.unwrap(), b);
    }

    // AUDIT M2d-1 FIX-1: a config change (rotate/resize) whose superblock persist
    // FAILS must leave the live device unchanged — never let the runtime epoch or
    // capacity get ahead of what recovery would reconstruct.
    #[cfg(unix)]
    #[tokio::test]
    async fn config_change_atomic_on_persist_failure() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 100, small_config()).await;
        let (epoch0, cap0, gen0) = (d.current_epoch(), d.capacity_blocks(), d.generation);
        // make the device dir read-only so the superblock tmp-write fails
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        // root bypasses the mode bits, so this fault can't fire there — skip rather
        // than false-fail (still exercises the real path for a normal user).
        if std::fs::File::create(dir.path().join(".probe")).is_ok() {
            let _ = std::fs::remove_file(dir.path().join(".probe"));
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        assert!(d.rotate_epoch().await.is_err());
        assert_eq!((d.current_epoch(), d.generation), (epoch0, gen0)); // rolled back

        assert!(d.resize(200).is_err());
        assert_eq!((d.capacity_blocks(), d.generation), (cap0, gen0)); // rolled back
                                                                       // a rejected grow must not have exposed the new range either
        assert!(matches!(
            d.write_at(150, &vec![0u8; BS as usize]).await,
            Err(DeviceError::OutOfRange { .. })
        ));

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    // AUDIT M2d-1 FIX-3: recovery must fail CLOSED if the id space is exhausted
    // (a staged/cataloged segment at u64::MAX) rather than reuse/wrap an id — id
    // reuse would defeat the anti-substitution header check.
    #[tokio::test]
    async fn recovery_fails_closed_on_exhausted_segment_id() {
        let dir = tempfile::tempdir().unwrap();
        let (d, t) = dev(&dir, 1024, small_config()).await; // lays down superblock + staging
        drop(d);
        // inject a staged Map delta at segment_id u64::MAX directly into the log
        {
            let mut log = StagingLog::open_append(
                dir.path().join("staging.log"),
                SymmetricKey::from_bytes([2u8; 32]), // meta_key (matches keys())
                [7u8; 16],                           // device_uuid (matches dev())
            )
            .unwrap();
            let phys = Phys {
                segment_id: u64::MAX,
                record_off: 40,
                data_off: 0,
                epoch: 0,
            };
            log.append(
                &FtlDelta::Map {
                    lba: 0,
                    count: 1,
                    phys,
                },
                &[0u8; 64],
            )
            .unwrap();
            log.flush().unwrap();
        }
        let res = TeaGardenDevice::open(Arc::clone(&t), keys(), dir.path(), small_config());
        assert!(matches!(res, Err(DeviceError::Corruption(_))));
    }

    // ============= M2d-2: DeviceHead / cloud watermark / prefix-consistency ==========

    // Fresh-machine recovery from a cloud head: everything confirmed → the head's
    // prefix reconstructs the device; reads fetch the referenced segments; the
    // fresh machine can keep writing; and a same-machine reopen of the seeded dir
    // also recovers.
    #[tokio::test]
    async fn head_round_trip_and_fresh_machine_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0xA1u8; 4 * BS as usize];
        d.write_at(0, &a).await.unwrap();
        d.close().await.unwrap();
        assert!(d.cloud_watermark() >= 1);
        let head = d.checkpoint().await.unwrap();
        assert_eq!(d.last_head_msg_id(), Some(head));

        // fresh machine (new dir), same cloud (shared transport), head id only
        let fresh = tempfile::tempdir().unwrap();
        let mut r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            small_config(),
        )
        .await
        .unwrap();
        assert_eq!(r.read_at(0, 4).await.unwrap(), a);
        // the recovered machine is a full device: keep writing
        r.write_at(20, &vec![0xB2u8; BS as usize]).await.unwrap();
        r.close().await.unwrap();
        assert_eq!(r.read_at(20, 1).await.unwrap(), vec![0xB2u8; BS as usize]);

        // a same-machine crash of the FRESH dir still recovers (seeded superblock +
        // catalog + staging carrying the prefix mapping for confirmed segments)
        drop(r);
        let mut r2 = reopen(&t, &fresh, small_config());
        assert_eq!(r2.read_at(0, 4).await.unwrap(), a);
        assert_eq!(r2.read_at(20, 1).await.unwrap(), vec![0xB2u8; BS as usize]);
    }

    // THE prefix-consistency case (advisor): an LBA written into a confirmed
    // segment then overwritten into a NOT-yet-confirmed one. The head must carry
    // the OLDER, confirmed value (built by replaying the op-log prefix) — never a
    // spurious hole (the bug if the checkpoint filtered the live FTL) and never the
    // newer, non-durable value.
    #[tokio::test]
    async fn head_overwrite_into_unconfirmed_reads_older_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0xAAu8; BS as usize]).await.unwrap(); // seg1: confirmed
        assert_eq!(d.confirmed_segments(), 1);
        *t.fail_uploads.lock().unwrap() = Some("dc down".into());
        d.write_at(0, &vec![0xBBu8; BS as usize]).await.unwrap(); // seg2: overwrite, pending
        assert_eq!(d.confirmed_segments(), 1); // seg2 upload failed → not confirmed
        *t.fail_uploads.lock().unwrap() = None;
        assert_eq!(d.cloud_watermark(), 1); // seg2 (id 2) is past the watermark
        let head = d.checkpoint().await.unwrap();

        let fresh = tempfile::tempdir().unwrap();
        let mut r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            tiny_config(),
        )
        .await
        .unwrap();
        // prefix-consistent value = seg1's 0xAA (NOT a hole, NOT seg2's 0xBB)
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0xAAu8; BS as usize]);
    }

    // The discard case (advisor): a discard is an Unmap, NOT a record — so it lives
    // only in the op-log, never in a segment index. Building the checkpoint by
    // REPLAYING (not index-scanning) is why Option A captures it. A discard of a
    // confirmed-prefix block must recover as zeros.
    #[tokio::test]
    async fn head_discard_in_prefix_recovers_as_hole() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0xCCu8; BS as usize]).await.unwrap(); // seg1: confirmed
        d.discard(0, 1).await.unwrap(); // staged Unmap (metadata only, in the prefix)
        assert_eq!(d.cloud_watermark(), 1);
        let head = d.checkpoint().await.unwrap();

        let fresh = tempfile::tempdir().unwrap();
        let mut r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0u8; BS as usize]); // discarded → zeros
        assert_eq!(r.mapped_blocks(), 0);
    }

    // The watermark is a contiguous PREFIX, not the confirmed set: with confirmed
    // {1, 3} (segment 2 pending), the watermark is 1 — segment 3's data is NOT
    // recoverable even though it is on the cloud, because the gap at 2 breaks the
    // prefix (else an overlay FS could replay a journal over absent segment-2 data).
    #[tokio::test]
    async fn head_watermark_stops_at_first_gap() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0x1u8; BS as usize]).await.unwrap(); // seg1: confirmed
        *t.fail_uploads.lock().unwrap() = Some("down".into());
        d.write_at(10, &vec![0x2u8; BS as usize]).await.unwrap(); // seg2: pending (the gap)
        *t.fail_uploads.lock().unwrap() = None;
        d.write_at(20, &vec![0x3u8; BS as usize]).await.unwrap(); // seg3: confirmed but past gap
        assert_eq!(d.cloud_watermark(), 1); // {1,3} confirmed → contiguous prefix {1}
        let head = d.checkpoint().await.unwrap();

        let fresh = tempfile::tempdir().unwrap();
        let mut r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0x1u8; BS as usize]); // in prefix
        assert_eq!(r.read_at(10, 1).await.unwrap(), vec![0u8; BS as usize]); // pending → hole
        assert_eq!(r.read_at(20, 1).await.unwrap(), vec![0u8; BS as usize]); // past gap → hole
    }

    // A failed head upload must NOT advance the recoverable point: the previous
    // head stays in force, so recovery lands on the prior consistent prefix, never
    // a torn or ahead-of-cloud state.
    #[tokio::test]
    async fn failed_head_upload_keeps_prior_recoverable_point() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0x1u8; BS as usize]).await.unwrap(); // seg1: confirmed
        let head1 = d.checkpoint().await.unwrap();
        assert_eq!(d.last_head_msg_id(), Some(head1));

        d.write_at(1, &vec![0x2u8; BS as usize]).await.unwrap(); // seg2: confirmed
        *t.fail_uploads.lock().unwrap() = Some("head upload down".into());
        assert!(d.checkpoint().await.is_err()); // head upload fails
        assert_eq!(d.last_head_msg_id(), Some(head1)); // recoverable point did NOT advance
        *t.fail_uploads.lock().unwrap() = None;

        // recovery from the still-valid head1 yields the prior (watermark-1) prefix
        let fresh = tempfile::tempdir().unwrap();
        let mut r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head1,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0x1u8; BS as usize]);
        assert_eq!(r.read_at(1, 1).await.unwrap(), vec![0u8; BS as usize]); // seg2 not in head1
    }

    // The watermark ADVANCES across checkpoints (advisor): with the gap segment
    // pending, checkpoint pins prefix {1}; once the gap fills, a later checkpoint
    // pins {1,2,3} and supersedes the earlier head.
    #[tokio::test]
    async fn head_watermark_advances_across_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0x1u8; BS as usize]).await.unwrap(); // seg1 confirmed
        *t.fail_uploads.lock().unwrap() = Some("down".into());
        d.write_at(10, &vec![0x2u8; BS as usize]).await.unwrap(); // seg2 pending (gap)
        *t.fail_uploads.lock().unwrap() = None;
        d.write_at(20, &vec![0x3u8; BS as usize]).await.unwrap(); // seg3 confirmed (past gap)
        assert_eq!(d.cloud_watermark(), 1);
        let head_a = d.checkpoint().await.unwrap();

        // recovery from head_a sees only seg 1
        let fa = tempfile::tempdir().unwrap();
        let mut ra = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fa.path(),
            head_a,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(ra.read_at(0, 1).await.unwrap(), vec![0x1u8; BS as usize]);
        assert_eq!(ra.read_at(20, 1).await.unwrap(), vec![0u8; BS as usize]); // past the gap

        // fill the gap: seg 2 confirms → the contiguous prefix jumps to 3
        d.drain_uploads().await.unwrap();
        assert_eq!(d.cloud_watermark(), 3);
        let head_b = d.checkpoint().await.unwrap();
        assert_ne!(head_a, head_b); // a new, superseding head

        // recovery from head_b now sees all three
        let fb = tempfile::tempdir().unwrap();
        let mut rb = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fb.path(),
            head_b,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(rb.read_at(0, 1).await.unwrap(), vec![0x1u8; BS as usize]);
        assert_eq!(rb.read_at(10, 1).await.unwrap(), vec![0x2u8; BS as usize]);
        assert_eq!(rb.read_at(20, 1).await.unwrap(), vec![0x3u8; BS as usize]);
    }

    // Honesty (advisor): a head-recovered device seeds staging with EMPTY-record
    // Map deltas, so it depends on catalog durability more than a native device. If
    // its catalog is later lost, M2d-1's reconstruct-and-reupload self-healing does
    // NOT apply — a reopen fails CLOSED (empty record cannot be re-framed) rather
    // than returning wrong data or panicking.
    #[tokio::test]
    async fn head_recovered_device_fails_closed_if_catalog_lost() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0x5u8; BS as usize]).await.unwrap();
        d.close().await.unwrap();
        let head = d.checkpoint().await.unwrap();

        let fresh = tempfile::tempdir().unwrap();
        let r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            tiny_config(),
        )
        .await
        .unwrap();
        drop(r);
        // lose the catalog on the head-recovered machine
        std::fs::write(fresh.path().join("catalog"), b"").unwrap();
        // reopen must fail closed (not panic, not wrong data): the seeded empty
        // record for the now-"unconfirmed" segment cannot be re-framed
        let res = TeaGardenDevice::open(Arc::clone(&t), keys(), fresh.path(), tiny_config());
        assert!(matches!(res, Err(DeviceError::Corruption(_))));
    }

    // AUDIT M2d-2 FIX-1: a fresh machine recovering a head that dropped an
    // unconfirmed tail must restart segment allocation just above the PREFIX
    // (watermark+1), not at the live tail id — otherwise its watermark freezes and
    // its own later checkpoints silently drop post-recovery writes.
    #[tokio::test]
    async fn head_recovery_restarts_ids_so_watermark_can_advance() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0x1u8; BS as usize]).await.unwrap(); // seg1 confirmed
        *t.fail_uploads.lock().unwrap() = Some("down".into());
        d.write_at(10, &vec![0x2u8; BS as usize]).await.unwrap(); // seg2 pending (gap)
        *t.fail_uploads.lock().unwrap() = None;
        d.write_at(20, &vec![0x3u8; BS as usize]).await.unwrap(); // seg3 confirmed past gap
        assert_eq!(d.cloud_watermark(), 1);
        let head = d.checkpoint().await.unwrap();
        drop(d);

        // fresh machine recovers prefix {1}; ids must restart at watermark+1 = 2
        let fresh = tempfile::tempdir().unwrap();
        let mut r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(r.cloud_watermark(), 1);
        // write + confirm a new block: the new segment is id 2 (contiguous with the
        // prefix), so the watermark can ADVANCE — pre-fix it would freeze at 1.
        r.write_at(30, &vec![0x9u8; BS as usize]).await.unwrap();
        r.close().await.unwrap();
        assert_eq!(r.cloud_watermark(), 2);
        let head2 = r.checkpoint().await.unwrap();

        // recovery from the new head sees seg 1 AND the post-recovery write
        let fresh2 = tempfile::tempdir().unwrap();
        let mut r2 = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh2.path(),
            head2,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(r2.read_at(0, 1).await.unwrap(), vec![0x1u8; BS as usize]);
        assert_eq!(r2.read_at(30, 1).await.unwrap(), vec![0x9u8; BS as usize]);
    }

    // M2e WIRE OPACITY (verified on the REAL uploaded bytes + filenames, not just
    // round-trip): no document Telegram receives contains a plaintext format
    // magic, and its name is 12 random hex characters carrying no role, id or
    // extension, so the name does not tell a segment from the recovery head or
    // give the order of segments.
    /// Every upload name is exactly 12 random lowercase hex characters: no
    /// extension, no role, no id.
    fn assert_upload_name(name: &str) {
        assert_eq!(name.len(), 12, "upload name {name:?} is not 12 characters");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "upload name {name:?} is not lowercase hex"
        );
    }

    #[test]
    fn upload_names_are_random_12_hex_without_extension() {
        let names: std::collections::HashSet<String> =
            (0..64).map(|_| random_upload_name()).collect();
        assert_eq!(names.len(), 64, "names repeat");
        for n in &names {
            assert_upload_name(n);
        }
    }

    #[tokio::test]
    async fn uploaded_bytes_and_filenames_are_opaque() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        // write enough to seal + upload several segments, then publish a head
        d.write_at(0, &vec![0x5au8; 20 * BS as usize])
            .await
            .unwrap();
        d.close().await.unwrap();
        d.checkpoint().await.unwrap();
        assert!(t.message_count() >= 2); // ≥1 segment + the head

        // (1) filenames: 12 random hex characters, no role marker, no id, no extension
        let names = t.uploaded_filenames();
        assert!(!names.is_empty());
        for name in &names {
            let lower = name.to_lowercase();
            assert!(!lower.contains("seg"), "filename leaks role: {name}");
            assert!(!lower.contains("head"), "filename leaks role: {name}");
            assert!(!lower.contains("dev"), "filename leaks role: {name}");
            assert!(!lower.ends_with(".bin"), "filename leaks format: {name}");
            assert_upload_name(name);
        }

        // (2) document BODIES: no plaintext format magics anywhere. (ASCII magics
        // in random ciphertext have ~2^-64 collision odds — a real leak, not flake.)
        for mid in 1..=t.message_count() as i64 {
            let Some(bytes) = t.get_raw(mid) else {
                continue;
            };
            for magic in [
                &b"TGDEVSG2"[..],
                b"TGDEVTR2",
                b"TGDEVHD1",
                b"TGDEVSG1",
                b"TGDEVEND",
            ] {
                assert!(
                    !bytes.windows(magic.len()).any(|w| w == magic),
                    "plaintext magic {:?} leaked into uploaded message {mid}",
                    std::str::from_utf8(magic).unwrap()
                );
            }
        }
    }

    // AUDIT M2d-2 FIX-2: checkpoint fails CLOSED at the head-generation ceiling
    // (no wrap/panic), leaving the recoverable point unchanged.
    // ── P4 garbage collection ────────────────────────────────────────────────

    // TC-GC-2 + TC-INT-4/G18: a mostly-dead segment is compacted (its live tail
    // moved, byte-exact) and its Telegram message deleted — the message count
    // actually drops after GC. A healthy device then has nothing to collect.
    #[tokio::test]
    async fn gc_compacts_and_deletes_dead_segments() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0xA1u8; 8 * BS as usize];
        let b = vec![0xB2u8; 8 * BS as usize];
        d.write_at(0, &a).await.unwrap(); // seg1 (seals at 4 records)
        d.write_at(100, &b).await.unwrap(); // seg2
        let over = vec![0xC3u8; 6 * BS as usize];
        d.write_at(0, &over).await.unwrap(); // seg3: kills 6/8 of seg1
        d.close().await.unwrap();
        assert_eq!(d.confirmed_segments(), 3);

        let before = t.message_count();
        let rep = d.gc().await.unwrap();
        assert_eq!(rep.compacted, vec![1]);
        assert_eq!(rep.blocks_moved, 2);
        assert_eq!(rep.extents_moved, 1); // blocks 6..8 = one merged run
        assert_eq!(rep.deleted, vec![1]);
        assert!(rep.delete_deferred.is_empty());
        assert!(rep.watermark >= 3);
        // +1 compaction segment, +1 head, -1 deleted victim
        assert_eq!(t.message_count(), before + 1 + 1 - 1);

        // byte-exact after the move
        let r = d.read_at(0, 8).await.unwrap();
        assert_eq!(&r[..6 * BS as usize], &over[..]);
        assert_eq!(&r[6 * BS as usize..], &a[6 * BS as usize..]);
        assert_eq!(d.read_at(100, 8).await.unwrap(), b);

        // nothing left to collect → the next pass is a cheap no-op (no head churn)
        let count = t.message_count();
        let rep2 = d.gc().await.unwrap();
        assert!(rep2.skipped.is_some());
        assert!(rep2.deleted.is_empty());
        assert_eq!(t.message_count(), count);
    }

    // TC-GC-3 (device half): a fully-dead segment needs no compaction — GC
    // deletes its message directly; live segments are untouched.
    #[tokio::test]
    async fn gc_deletes_fully_dead_segment_without_compaction() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0x11u8; BS as usize]).await.unwrap(); // seg1
        d.write_at(0, &vec![0x22u8; BS as usize]).await.unwrap(); // seg2 → seg1 dead
        d.write_at(5, &vec![0x33u8; BS as usize]).await.unwrap(); // seg3
        let before = t.message_count();

        let rep = d.gc().await.unwrap();
        assert!(rep.compacted.is_empty());
        assert_eq!(rep.blocks_moved, 0);
        assert_eq!(rep.deleted, vec![1]);
        // -1 victim, +1 head, no compaction segment
        assert_eq!(t.message_count(), before - 1 + 1);
        assert_eq!(d.read_at(0, 1).await.unwrap(), vec![0x22u8; BS as usize]);
        assert_eq!(d.read_at(5, 1).await.unwrap(), vec![0x33u8; BS as usize]);
    }

    // P2.3 lazy re-seal: after an epoch rotation, GC-moved extents are re-sealed
    // under the CURRENT epoch (the FTL's phys.epoch migrates), stay readable, and
    // the old-epoch victim message is deleted.
    #[tokio::test]
    async fn gc_lazy_reseals_old_epoch_records() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0xE5u8; 8 * BS as usize];
        d.write_at(0, &a).await.unwrap(); // seg1 sealed under epoch 0
        d.rotate_epoch().await.unwrap();
        assert_eq!(d.current_epoch(), 1);
        let over = vec![0xF6u8; 6 * BS as usize];
        d.write_at(0, &over).await.unwrap(); // epoch-1 records
        d.close().await.unwrap();

        let rep = d.gc().await.unwrap();
        assert_eq!(rep.compacted, vec![1]);
        assert_eq!(rep.deleted, vec![1]);
        // every surviving extent (incl. the moved epoch-0 tail) now carries the
        // current epoch — the lazy re-seal migrated it
        assert!(d
            .ftl
            .extents()
            .iter()
            .all(|&(_, _, p)| p.epoch == d.current_epoch()));
        let r = d.read_at(0, 8).await.unwrap();
        assert_eq!(&r[..6 * BS as usize], &over[..]);
        assert_eq!(&r[6 * BS as usize..], &a[6 * BS as usize..]);

        // recovery across the rotation + GC still reads byte-exact
        drop(d);
        let mut d2 = reopen(&t, &dir, small_config());
        let r = d2.read_at(0, 8).await.unwrap();
        assert_eq!(&r[..6 * BS as usize], &over[..]);
        assert_eq!(&r[6 * BS as usize..], &a[6 * BS as usize..]);
    }

    // H9: a transient delete failure defers the victims (repoints stand, data
    // stays readable as an orphan) and the next pass retries + succeeds. The
    // second pass also reclaims the superseded head message.
    #[tokio::test]
    async fn gc_defers_deletes_on_transport_failure_then_retries() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0x44u8; BS as usize]).await.unwrap(); // seg1
        d.write_at(0, &vec![0x55u8; BS as usize]).await.unwrap(); // seg2 → seg1 dead

        t.set_fail_deletes(true);
        let rep = d.gc().await.unwrap();
        assert!(rep.deleted.is_empty());
        assert_eq!(rep.delete_deferred, vec![1]);
        assert!(!rep.superseded_head_deleted); // opt-in is off: never attempted
        assert_eq!(t.message_count(), 3); // seg1 + seg2 + head1: nothing deleted
        assert_eq!(d.read_at(0, 1).await.unwrap(), vec![0x55u8; BS as usize]);

        t.set_fail_deletes(false);
        let rep2 = d.gc().await.unwrap();
        assert_eq!(rep2.deleted, vec![1]);
        // superseded-head deletion is OPT-IN (advisor H1) — default off, so
        // head1 survives: seg2 + head1 + head2 remain (only the victim is gone)
        assert!(!rep2.superseded_head_deleted);
        assert_eq!(t.message_count(), 3);
        assert_eq!(d.read_at(0, 1).await.unwrap(), vec![0x55u8; BS as usize]);
    }

    // H1: with `delete_superseded_head` opted in, each pass reclaims the head it
    // replaced, and the report carries the NEW head id (the only remaining valid
    // recovery point) so the operator can re-record it.
    #[tokio::test]
    async fn gc_opt_in_deletes_superseded_head_and_reports_new_head() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DeviceConfig {
            gc: GcConfig {
                delete_superseded_head: true,
                ..Default::default()
            },
            ..tiny_config()
        };
        let (mut d, t) = dev(&dir, 64, cfg).await;
        d.write_at(0, &vec![0x66u8; BS as usize]).await.unwrap(); // seg1
        d.write_at(0, &vec![0x77u8; BS as usize]).await.unwrap(); // seg2 → seg1 dead
        let rep = d.gc().await.unwrap();
        assert_eq!(rep.deleted, vec![1]);
        assert!(!rep.superseded_head_deleted); // no prior head existed
        assert_eq!(rep.head_msg_id, d.last_head_msg_id());
        let head1 = rep.head_msg_id.unwrap();

        d.write_at(0, &vec![0x88u8; BS as usize]).await.unwrap(); // seg3 → seg2 dead
        let rep2 = d.gc().await.unwrap();
        assert_eq!(rep2.deleted, vec![2]);
        assert!(rep2.superseded_head_deleted, "head1 reclaimed");
        assert!(t.get_raw(head1).is_none(), "superseded head is gone");
        let head2 = rep2.head_msg_id.unwrap();
        assert_ne!(head1, head2);

        // the reported (newest) head is a working recovery point
        let fresh = tempfile::tempdir().unwrap();
        let mut r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head2,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0x88u8; BS as usize]);
    }

    // I3.3 fail-safe: while the cloud state is GAPPED (an earlier segment cannot
    // confirm), gc() refuses the pass outright — it never deletes a fully-dead
    // segment above the watermark, because a FUTURE head could re-reference it
    // once the gap heals. After the gap heals, the sweep proceeds.
    #[tokio::test]
    async fn gc_refuses_when_gapped_then_sweeps_after_heal() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0xAAu8; BS as usize]).await.unwrap(); // seg1 confirmed
        *t.fail_uploads.lock().unwrap() = Some("dc down".into());
        d.write_at(10, &vec![0xBBu8; BS as usize]).await.unwrap(); // seg2 pending
        *t.fail_uploads.lock().unwrap() = None;
        d.write_at(20, &vec![0xCCu8; BS as usize]).await.unwrap(); // seg3 confirmed
        d.write_at(20, &vec![0xDDu8; BS as usize]).await.unwrap(); // seg4 → seg3 dead
        assert_eq!(d.cloud_watermark(), 1); // gap at seg2

        // with the gap unhealable, the pass fails loudly at the drain barrier —
        // and deletes nothing
        *t.fail_uploads.lock().unwrap() = Some("dc still down".into());
        let before = t.message_count();
        assert!(d.gc().await.is_err());
        assert_eq!(t.message_count(), before);
        assert_eq!(d.read_at(20, 1).await.unwrap(), vec![0xDDu8; BS as usize]);

        // heal → drain confirms seg2 → watermark covers seg3 → swept
        *t.fail_uploads.lock().unwrap() = None;
        let rep = d.gc().await.unwrap();
        assert_eq!(rep.deleted, vec![3]);
        assert!(rep.watermark >= 4);
        assert_eq!(d.read_at(0, 1).await.unwrap(), vec![0xAAu8; BS as usize]);
        assert_eq!(d.read_at(10, 1).await.unwrap(), vec![0xBBu8; BS as usize]);
        assert_eq!(d.read_at(20, 1).await.unwrap(), vec![0xDDu8; BS as usize]);
    }

    // THE I2 case: a Relocate whose target segment is past the watermark must be
    // SKIPPED by the prefix replay (not break it, not apply it): the published
    // head keeps referencing the victim (which therefore must stay alive — the
    // delete gate), and a fresh machine recovering that head reads the moved
    // blocks byte-exact from the VICTIM's still-existing message. Once the
    // relocation confirms, the next gc() retires the victim and a fresh machine
    // reads from the successor.
    #[tokio::test]
    async fn checkpoint_with_unconfirmed_relocation_keeps_victim_alive() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0x77u8; 8 * BS as usize];
        d.write_at(0, &a).await.unwrap(); // seg1 confirmed
        let over = vec![0x88u8; 6 * BS as usize];
        d.write_at(0, &over).await.unwrap(); // seg2 (open)
        d.close().await.unwrap(); // seg2 confirmed; seg1 live = blocks 6..8

        // compact seg1 while uploads are down: the relocation (→ seg3) stages
        // durably but seg3 cannot confirm
        *t.fail_uploads.lock().unwrap() = Some("dc down".into());
        d.compact_segment(1).await.unwrap();
        d.seal_open().await.unwrap(); // sealed, upload failed → pending
        *t.fail_uploads.lock().unwrap() = None;
        assert_eq!(d.cloud_watermark(), 2); // seg3 unconfirmed

        let head = d.checkpoint().await.unwrap();
        // the head's prefix must still reference the victim (Relocate skipped)…
        assert!(d.last_head_seg_refs.contains(&1));
        assert_eq!(d.last_head_watermark, Some(2));

        // …and a fresh machine recovering it reads the moved blocks from seg1
        let fresh = tempfile::tempdir().unwrap();
        let mut r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            small_config(),
        )
        .await
        .unwrap();
        let got = r.read_at(0, 8).await.unwrap();
        assert_eq!(&got[..6 * BS as usize], &over[..]);
        assert_eq!(&got[6 * BS as usize..], &a[6 * BS as usize..]);

        // back on the original device: confirm the relocation, gc retires seg1
        let rep = d.gc().await.unwrap();
        assert!(rep.deleted.contains(&1));
        let fresh2 = tempfile::tempdir().unwrap();
        let mut r2 = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh2.path(),
            d.last_head_msg_id().unwrap(),
            small_config(),
        )
        .await
        .unwrap();
        let got = r2.read_at(0, 8).await.unwrap();
        assert_eq!(&got[..6 * BS as usize], &over[..]);
        assert_eq!(&got[6 * BS as usize..], &a[6 * BS as usize..]);
    }

    // TC-GC-CHURN-2: crash mid-GC — after compaction staged its relocations but
    // BEFORE the segment sealed/confirmed/deleted anything. open() re-frames the
    // unconfirmed compaction segment from its staged sealed bytes, re-uploads it,
    // and a subsequent gc() completes the retirement. Data is readable at every
    // point (old copy or new — never neither).
    #[tokio::test]
    async fn gc_crash_before_delete_recovers_and_completes() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0x99u8; 8 * BS as usize];
        d.write_at(0, &a).await.unwrap(); // seg1
        let over = vec![0xABu8; 6 * BS as usize];
        d.write_at(0, &over).await.unwrap();
        d.close().await.unwrap(); // seg2; seg1 live = 2 blocks

        // crash right after compaction staged its relocations (GC segment still
        // open — not sealed, not uploaded, nothing deleted)
        d.compact_segment(1).await.unwrap();
        d.flush().await.unwrap();
        drop(d);

        let mut d2 = reopen(&t, &dir, small_config());
        // the reconstructed (unconfirmed) compaction segment serves the moved
        // blocks; everything is byte-exact before any further GC
        let r = d2.read_at(0, 8).await.unwrap();
        assert_eq!(&r[..6 * BS as usize], &over[..]);
        assert_eq!(&r[6 * BS as usize..], &a[6 * BS as usize..]);

        // a full pass now completes the retirement
        let rep = d2.gc().await.unwrap();
        assert!(rep.deleted.contains(&1));
        let r = d2.read_at(0, 8).await.unwrap();
        assert_eq!(&r[..6 * BS as usize], &over[..]);
        assert_eq!(&r[6 * BS as usize..], &a[6 * BS as usize..]);

        // and the state survives another reopen
        drop(d2);
        let mut d3 = reopen(&t, &dir, small_config());
        let r = d3.read_at(0, 8).await.unwrap();
        assert_eq!(&r[..6 * BS as usize], &over[..]);
        assert_eq!(&r[6 * BS as usize..], &a[6 * BS as usize..]);
    }

    // I1: tombstones survive reopen — the collected segment is never zombie-
    // re-uploaded (its staged bytes are still in the staging log), the watermark
    // keeps its contiguity across the tombstone, and a fresh machine recovered
    // from a post-GC head inherits both properties.
    #[tokio::test]
    async fn gc_tombstones_survive_reopen_and_fresh_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0x10u8; BS as usize]).await.unwrap(); // seg1
        d.write_at(0, &vec![0x20u8; BS as usize]).await.unwrap(); // seg2 → seg1 dead
        let rep = d.gc().await.unwrap();
        assert_eq!(rep.deleted, vec![1]);
        assert_eq!(d.cloud_watermark(), 2, "tombstone preserves contiguity");
        let msgs = t.message_count();
        drop(d);

        // same-machine reopen: no zombie re-upload of the tombstoned segment
        let mut d2 = reopen(&t, &dir, small_config());
        d2.close().await.unwrap(); // would re-upload anything pending
        assert_eq!(t.message_count(), msgs);
        assert_eq!(d2.cloud_watermark(), 2);
        assert_eq!(d2.read_at(0, 1).await.unwrap(), vec![0x20u8; BS as usize]);
        // nothing to collect — the tombstone is not re-deleted
        let rep2 = d2.gc().await.unwrap();
        assert!(rep2.skipped.is_some());

        // fresh machine from a post-GC head: tombstone + contiguity inherited
        let head = d2.checkpoint().await.unwrap();
        let fresh = tempfile::tempdir().unwrap();
        let mut r = TeaGardenDevice::recover_from_head(
            Arc::clone(&t),
            keys(),
            [7u8; 16],
            fresh.path(),
            head,
            tiny_config(),
        )
        .await
        .unwrap();
        assert_eq!(r.cloud_watermark(), 2);
        assert_eq!(r.read_at(0, 1).await.unwrap(), vec![0x20u8; BS as usize]);
    }

    // I5: GC output uses the same random 12-hex names as every other upload and
    // has no plaintext structure in any stored message.
    #[tokio::test]
    async fn gc_uploads_are_opaque() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        d.write_at(0, &vec![0x5Au8; 8 * BS as usize]).await.unwrap();
        d.write_at(0, &vec![0x6Bu8; 6 * BS as usize]).await.unwrap();
        d.close().await.unwrap();
        let rep = d.gc().await.unwrap();
        assert_eq!(rep.compacted, vec![1]);

        for name in t.uploaded_filenames() {
            assert_upload_name(&name);
        }
        for mid in 1..=1000i64 {
            if let Some(body) = t.get_raw(mid) {
                assert!(
                    !body.windows(5).any(|w| w == b"TGDEV"),
                    "plaintext format magic leaked in message {mid}"
                );
            }
        }
    }

    // TC-GC-CHURN-1: randomized write/overwrite/discard churn with periodic GC
    // passes stays byte-exact against a per-block reference model, and GC keeps
    // the message count bounded (segments actually get reclaimed). Runs with
    // superseded-head deletion opted in — the managed-GC configuration — so
    // heads don't accumulate one per pass.
    #[tokio::test]
    async fn gc_churn_matches_reference_model() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DeviceConfig {
            gc: GcConfig {
                delete_superseded_head: true,
                ..Default::default()
            },
            ..small_config()
        };
        let (mut d, t) = dev(&dir, 256, cfg).await;
        let mut model: Vec<Option<u8>> = vec![None; 256];
        let mut rng: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };

        let mut total_deleted = 0usize;
        for op in 0..200u64 {
            let lba = next() % 240;
            let count = (1 + next() % 8).min(256 - lba);
            if next() % 4 == 0 {
                d.discard(lba, count).await.unwrap();
                for b in lba..lba + count {
                    model[b as usize] = None;
                }
            } else {
                let fill = ((op as u8).wrapping_mul(37)) | 1;
                d.write_at(lba, &vec![fill; (count * BS) as usize])
                    .await
                    .unwrap();
                for b in lba..lba + count {
                    model[b as usize] = Some(fill);
                }
            }
            if op % 40 == 39 {
                d.close().await.unwrap();
                let rep = d.gc().await.unwrap();
                total_deleted += rep.deleted.len();
                let got = d.read_at(0, 256).await.unwrap();
                for b in 0..256usize {
                    let want = model[b].unwrap_or(0);
                    assert!(
                        got[b * BS as usize..(b + 1) * BS as usize]
                            .iter()
                            .all(|&x| x == want),
                        "block {b} mismatch after gc at op {op}"
                    );
                }
            }
        }
        d.close().await.unwrap();
        d.gc().await.unwrap();
        let got = d.read_at(0, 256).await.unwrap();
        for b in 0..256usize {
            let want = model[b].unwrap_or(0);
            assert!(
                got[b * BS as usize..(b + 1) * BS as usize]
                    .iter()
                    .all(|&x| x == want),
                "block {b} mismatch at end"
            );
        }
        assert!(total_deleted > 0, "churn must actually reclaim segments");
        // reclamation keeps the store bounded: far fewer messages than the ~50
        // segments this churn sealed
        assert!(
            t.message_count() < 40,
            "message count {} suggests GC reclaimed nothing",
            t.message_count()
        );

        // and the post-churn state survives recovery
        drop(d);
        let mut d2 = reopen(&t, &dir, small_config());
        let got = d2.read_at(0, 256).await.unwrap();
        for b in 0..256usize {
            let want = model[b].unwrap_or(0);
            assert!(
                got[b * BS as usize..(b + 1) * BS as usize]
                    .iter()
                    .all(|&x| x == want),
                "block {b} mismatch after reopen"
            );
        }
    }

    // ── P3.1 ranged cold reads + P1.14 locality gate ─────────────────────────

    /// 32 two-block records in one ~258 KiB segment; reopen = cold cache.
    fn ranged_config() -> DeviceConfig {
        DeviceConfig {
            segment_target: 256 * 1024,
            record_max: 8 * 1024,
            cache: CacheConfig {
                budget_bytes: 1 << 30,
                ..Default::default()
            },
            gc: GcConfig::default(),
            read: ReadConfig {
                // tests use small segments; an explicit small probe keeps the
                // byte-accounting assertions meaningful (the production default
                // would clamp to the whole small blob)
                index_tail_probe: 64 * 1024,
                ..Default::default()
            },
        }
    }

    // TC-INT-3 (G3/G12, byte-accounted) + the P1.14 gate: a cold 4 KiB read
    // fetches ≈ tail-probe + one sealed record — NOT the whole segment; the
    // second read costs exactly one sealed record (index cached); the third
    // (gate default 3) promotes to ONE whole-segment fetch; after that reads
    // are free.
    #[tokio::test]
    async fn ranged_read_amplification_and_gate_promotion() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, ranged_config()).await;
        let data: Vec<u8> = (0..64 * BS as usize).map(|i| (i / 7) as u8).collect();
        d.write_at(0, &data).await.unwrap(); // 32 records → seals one segment
        d.close().await.unwrap();
        drop(d);

        let mut d = reopen(&t, &dir, ranged_config());
        let blob_len = t.get_raw(1).map(|b| b.len() as u64).unwrap();
        assert!(blob_len > 256 * 1024, "test premise: a full segment");
        t.reset_counters();

        // 1st cold read: tail probe (64 KiB) + one sealed record (8232 B)
        let sealed_rec = 8192 + 40;
        let r = d.read_at(0, 1).await.unwrap();
        assert_eq!(&r[..], &data[..BS as usize]);
        assert_eq!(t.read_count(), 2, "tail probe + record fetch");
        assert_eq!(t.bytes_served(), 64 * 1024 + sealed_rec);
        assert!(t.bytes_served() < blob_len / 3, "not the whole segment");

        // 2nd cold read, different record: index cached → exactly one record
        let before = t.bytes_served();
        let r = d.read_at(10, 1).await.unwrap();
        assert_eq!(&r[..], &data[10 * BS as usize..11 * BS as usize]);
        assert_eq!(t.read_count(), 3);
        assert_eq!(t.bytes_served() - before, sealed_rec);

        // 3rd cold read: gate (default 3) promotes → ONE whole-segment fetch
        let before = t.bytes_served();
        let r = d.read_at(20, 1).await.unwrap();
        assert_eq!(&r[..], &data[20 * BS as usize..21 * BS as usize]);
        assert_eq!(t.read_count(), 4);
        assert_eq!(t.bytes_served() - before, blob_len, "promotion fetch");

        // 4th read: served from the cached blob — zero transport activity
        let r = d.read_at(30, 1).await.unwrap();
        assert_eq!(&r[..], &data[30 * BS as usize..31 * BS as usize]);
        assert_eq!(t.read_count(), 4, "warm read costs 0 RTT");
    }

    // TC-INT-5: with promotion disabled, lone random reads NEVER pull the
    // whole segment — amplification stays bounded by the heuristic.
    #[tokio::test]
    async fn lone_random_reads_never_pull_whole_segment() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DeviceConfig {
            read: ReadConfig {
                whole_segment_after: 0, // never promote
                ..ranged_config().read
            },
            ..ranged_config()
        };
        let (mut d, t) = dev(&dir, 1024, cfg.clone()).await;
        let data: Vec<u8> = (0..64 * BS as usize).map(|i| (i / 11) as u8).collect();
        d.write_at(0, &data).await.unwrap();
        d.close().await.unwrap();
        drop(d);

        let mut d = reopen(&t, &dir, cfg);
        let blob_len = t.get_raw(1).map(|b| b.len() as u64).unwrap();
        t.reset_counters();
        for i in [0u64, 8, 16, 24, 32, 40, 48, 56] {
            let r = d.read_at(i, 1).await.unwrap();
            assert_eq!(&r[..], &data[(i * BS) as usize..((i + 1) * BS) as usize]);
        }
        // 1 tail probe + 8 record fetches; nowhere near the whole segment
        assert_eq!(t.read_count(), 9);
        assert_eq!(t.bytes_served(), 64 * 1024 + 8 * (8192 + 40));
        assert!(t.bytes_served() < blob_len / 2);
    }

    // The fallback: ranged reads disabled → the M2b whole-segment behavior
    // (first cold read downloads the blob, everything after is warm).
    #[tokio::test]
    async fn ranged_disabled_restores_whole_segment_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DeviceConfig {
            read: ReadConfig {
                ranged_reads: false,
                ..Default::default()
            },
            ..ranged_config()
        };
        let (mut d, t) = dev(&dir, 1024, cfg.clone()).await;
        let data: Vec<u8> = (0..64 * BS as usize).map(|i| (i / 13) as u8).collect();
        d.write_at(0, &data).await.unwrap();
        d.close().await.unwrap();
        drop(d);

        let mut d = reopen(&t, &dir, cfg);
        let blob_len = t.get_raw(1).map(|b| b.len() as u64).unwrap();
        t.reset_counters();
        assert_eq!(d.read_at(0, 1).await.unwrap(), data[..BS as usize].to_vec());
        assert_eq!(t.read_count(), 1);
        assert_eq!(t.bytes_served(), blob_len, "whole segment on first miss");
        assert_eq!(
            d.read_at(63, 1).await.unwrap(),
            data[63 * BS as usize..].to_vec()
        );
        assert_eq!(t.read_count(), 1, "second read is warm");
    }

    // A ranged read of a SURVIVOR slice (FTL split with data_off > 0) after an
    // overwrite: the whole record is fetched, decrypted under its position AAD,
    // and sliced at data_off — byte-exact.
    #[tokio::test]
    async fn ranged_read_slices_split_survivors() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, ranged_config()).await;
        let orig: Vec<u8> = (0..2 * BS as usize).map(|i| i as u8).collect();
        d.write_at(0, &orig).await.unwrap(); // one 2-block record
        d.close().await.unwrap();
        drop(d);

        let mut d = reopen(&t, &dir, ranged_config());
        // overwrite block 0 → the old record's survivor is block 1 (data_off 4096)
        let over = vec![0xEEu8; BS as usize];
        d.write_at(0, &over).await.unwrap();
        t.reset_counters();
        let r = d.read_at(0, 2).await.unwrap();
        assert_eq!(&r[..BS as usize], &over[..]);
        assert_eq!(&r[BS as usize..], &orig[BS as usize..]); // ranged + data_off
        assert!(t.read_count() >= 2, "survivor came over the wire");
    }

    // A trailer-declared index larger than the tail probe triggers exactly one
    // exact-size refetch — reads stay byte-exact and accounted.
    #[tokio::test]
    async fn ranged_index_refetch_when_probe_too_small() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DeviceConfig {
            read: ReadConfig {
                index_tail_probe: 100, // < trailer+MAC+index → forces the refetch
                whole_segment_after: 0,
                ..Default::default()
            },
            ..ranged_config()
        };
        let (mut d, t) = dev(&dir, 1024, cfg.clone()).await;
        let data: Vec<u8> = (0..64 * BS as usize).map(|i| (i / 17) as u8).collect();
        d.write_at(0, &data).await.unwrap();
        d.close().await.unwrap();
        drop(d);

        let mut d = reopen(&t, &dir, cfg);
        t.reset_counters();
        let r = d.read_at(0, 1).await.unwrap();
        assert_eq!(&r[..], &data[..BS as usize]);
        // probe + exact-size tail refetch + record fetch
        assert_eq!(t.read_count(), 3);
        // and the index is now cached: the next read costs one record fetch
        let r = d.read_at(10, 1).await.unwrap();
        assert_eq!(&r[..], &data[10 * BS as usize..11 * BS as usize]);
        assert_eq!(t.read_count(), 4);
    }

    // GC invalidates the ranged-read state of a deleted victim (index cache +
    // heat), and relocated data ranged-reads byte-exact from its NEW segment.
    #[tokio::test]
    async fn gc_invalidates_ranged_state_and_relocated_data_ranged_reads() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, small_config()).await;
        let a = vec![0x3Cu8; 8 * BS as usize];
        d.write_at(0, &a).await.unwrap(); // seg1
        d.close().await.unwrap();
        drop(d);

        let mut d = reopen(&t, &dir, small_config());
        // a cold ranged read populates seg1's index cache
        assert_eq!(
            d.read_at(6, 1).await.unwrap(),
            a[6 * BS as usize..7 * BS as usize].to_vec()
        );
        assert!(d.index_cache.contains_key(&1));

        // kill most of seg1, GC compacts + deletes it
        let over = vec![0x4Du8; 6 * BS as usize];
        d.write_at(0, &over).await.unwrap();
        d.close().await.unwrap();
        let rep = d.gc().await.unwrap();
        assert!(rep.deleted.contains(&1));
        assert!(!d.index_cache.contains_key(&1), "stale index dropped");
        assert!(!d.seg_read_hits.contains_key(&1));

        // cold reopen: the moved tail now ranged-reads from the NEW segment
        drop(d);
        let mut d = reopen(&t, &dir, small_config());
        let r = d.read_at(0, 8).await.unwrap();
        assert_eq!(&r[..6 * BS as usize], &over[..]);
        assert_eq!(&r[6 * BS as usize..], &a[6 * BS as usize..]);
    }

    // H3 (advisor): a failing ranged fetch PROPAGATES — there is no silent
    // fallback to a whole-segment download masking the failure with a ~45 MiB
    // pull. Exactly one gated transport attempt, zero bytes served.
    #[tokio::test]
    async fn ranged_failure_does_not_fall_back_to_whole_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, ranged_config()).await;
        d.write_at(0, &vec![0x42u8; 8 * BS as usize]).await.unwrap();
        d.close().await.unwrap();
        drop(d);

        let mut d = reopen(&t, &dir, ranged_config());
        t.reset_counters();
        t.set_flood_after(0); // every read attempt is rate-limited
        let err = d.read_at(0, 1).await.unwrap_err();
        assert!(matches!(err, DeviceError::Transport(_)));
        assert_eq!(
            t.read_count(),
            1,
            "one ranged attempt, no whole-segment fallback"
        );
        assert_eq!(t.bytes_served(), 0);
        // and the failure did not creep the segment toward promotion
        assert!(!d.seg_read_hits.contains_key(&1));
    }

    // Codex P3.1 FIX-1: a logical read whose EARLIER piece succeeds but a LATER
    // piece fails must NOT commit the earlier segment's gate charge — the read
    // failed, so repeating it cannot creep that segment toward promotion.
    #[tokio::test]
    async fn failed_logical_read_does_not_commit_earlier_charge() {
        let dir = tempfile::tempdir().unwrap();
        // two segments; block 0 in seg1, a later block in seg2
        let (mut d, t) = dev(&dir, 1024, ranged_config()).await;
        let a = vec![0x1Au8; 8 * BS as usize]; // seg1 (seals at 256 KiB target? no — 8 blocks)
        d.write_at(0, &a).await.unwrap();
        d.close().await.unwrap();
        let b = vec![0x2Bu8; 8 * BS as usize];
        d.write_at(100, &b).await.unwrap(); // seg2
        d.close().await.unwrap();
        drop(d);

        let mut d = reopen(&t, &dir, ranged_config());
        // drop seg2's message so the SECOND piece of a spanning read fails, while
        // seg1's first piece succeeds
        let seg2_mid = 2i64; // second uploaded message
        assert!(t.get_raw(seg2_mid).is_some());
        t.drop_message(seg2_mid);

        // a read covering block 0 (seg1, ok) and block 100 (seg2, gone) fails
        for _ in 0..5 {
            // read the two mapped extents in one logical read via a range that
            // spans them (holes between are fine)
            let err = d.read_at(0, 101).await.unwrap_err();
            assert!(matches!(
                err,
                DeviceError::Transport(_) | DeviceError::Corruption(_)
            ));
        }
        // despite 5 failed logical reads, seg1 earned NO committed heat →
        // a subsequent successful read of seg1 alone still goes ranged
        assert!(
            !d.seg_read_hits.contains_key(&1),
            "failed reads did not commit charge"
        );
        t.reset_counters();
        let blob_len = t.get_raw(1).map(|b| b.len() as u64).unwrap();
        let r = d.read_at(0, 1).await.unwrap();
        assert_eq!(&r[..], &a[..BS as usize]);
        assert!(t.bytes_served() < blob_len, "still ranged, not promoted");
    }

    // C2 (advisor): ONE logical read spanning many FTL pieces of the same
    // segment charges the locality gate ONCE — kernel readahead over a
    // fragmented region cannot promote by itself.
    #[tokio::test]
    async fn multi_piece_read_charges_gate_once() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, t) = dev(&dir, 1024, ranged_config()).await;
        let data: Vec<u8> = (0..64 * BS as usize).map(|i| (i / 19) as u8).collect();
        d.write_at(0, &data).await.unwrap(); // 32 two-block records, one segment
        d.close().await.unwrap();
        drop(d);

        let mut d = reopen(&t, &dir, ranged_config());
        let blob_len = t.get_raw(1).map(|b| b.len() as u64).unwrap();
        t.reset_counters();
        // one logical read over 16 blocks = 8 records = 8 pieces in segment 1
        let r = d.read_at(0, 16).await.unwrap();
        assert_eq!(&r[..], &data[..16 * BS as usize]);
        assert_eq!(d.seg_read_hits.get(&1).copied(), Some(1), "charged once");
        // 1 tail probe + 8 record fetches — NOT promoted to the whole blob
        assert_eq!(t.read_count(), 9);
        assert!(t.bytes_served() < blob_len);
        // second logical read charges again; third promotes (default gate = 3)
        let _ = d.read_at(16, 16).await.unwrap();
        assert_eq!(d.seg_read_hits.get(&1).copied(), Some(2));
        let before = t.bytes_served();
        let _ = d.read_at(32, 16).await.unwrap();
        assert_eq!(
            t.bytes_served() - before,
            blob_len,
            "third logical read promotes"
        );
        assert!(!d.seg_read_hits.contains_key(&1));
    }

    // The index cache honors its byte budget (FIFO eviction).
    #[tokio::test]
    async fn index_cache_fifo_bound_holds() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DeviceConfig {
            read: ReadConfig {
                // budget for exactly two single-record indexes (each 32+64 B)
                index_cache_budget: 200,
                whole_segment_after: 0,
                ..Default::default()
            },
            ..tiny_config()
        };
        let (mut d, t) = dev(&dir, 64, cfg.clone()).await;
        d.write_at(0, &vec![0x01u8; BS as usize]).await.unwrap(); // seg1
        d.write_at(1, &vec![0x02u8; BS as usize]).await.unwrap(); // seg2
        d.write_at(2, &vec![0x03u8; BS as usize]).await.unwrap(); // seg3
        drop(d);

        let mut d = reopen(&t, &dir, cfg);
        for lba in 0..3u64 {
            let _ = d.read_at(lba, 1).await.unwrap();
        }
        assert!(d.index_cache.len() <= 2, "FIFO bound exceeded");
        // the evicted segment still reads correctly (one re-bootstrap)
        assert_eq!(d.read_at(0, 1).await.unwrap(), vec![0x01u8; BS as usize]);
    }

    #[tokio::test]
    async fn checkpoint_fails_closed_at_head_generation_max() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _t) = dev(&dir, 64, tiny_config()).await;
        d.write_at(0, &vec![0x1u8; BS as usize]).await.unwrap();
        let head1 = d.checkpoint().await.unwrap();
        d.head_generation = u64::MAX; // at the ceiling
        assert!(matches!(
            d.checkpoint().await,
            Err(DeviceError::Corruption(_))
        ));
        assert_eq!(d.last_head_msg_id(), Some(head1)); // did not advance
        assert_eq!(d.head_generation, u64::MAX); // did not wrap to 0
    }
}
