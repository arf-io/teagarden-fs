use std::path::{Path, PathBuf};

use crate::crypto::kdf;
use crate::crypto::keys::{KeyHierarchy, SymmetricKey};
use crate::error::{CoreError, Result};
use crate::volume::config::VolumeConfig;
use crate::volume::lockout::LockoutState;
use crate::volume::names;
use crate::volume::shared::SharedDerivation;

/// Derive a verification key from the key hierarchy and hash it.
/// This allows checking if a password is correct without exposing any real keys.
///
/// Uses `blake3::keyed_hash` with `hierarchy.integrity` so the hash is
/// preimage-resistant even to an attacker who knows the verification_key
/// derivation path (M13 fix: prevents offline precomputation without the full
/// key hierarchy).
fn compute_verification_hash(hierarchy: &KeyHierarchy) -> String {
    let verification_key = kdf::hkdf_derive(&hierarchy.root, b"password-verification").unwrap();
    let hash = blake3::keyed_hash(hierarchy.integrity.as_bytes(), verification_key.as_bytes());
    hex::encode(hash.as_bytes())
}

/// Compute a BLAKE3-keyed HMAC over the cryptographic fields of the volume
/// config, protecting against KDF-parameter downgrade attacks.
///
/// `telegram_group_id` and `telegram_topic_id` ARE covered: they are set before
/// key derivation and are part of the cryptographic identity (a tampered topic id
/// would mismatch the derived hierarchy and fail open anyway). `telegram_channel_access_hash`
/// is EXCLUDED — it is a session-scoped routing value re-resolved on every mount,
/// so including it would brick the volume the moment the hash changes. `metadata_snapshot_id`
/// is excluded for the same post-creation-mutation reason.
fn compute_config_integrity(config: &VolumeConfig, hierarchy: &KeyHierarchy) -> String {
    let mut c = config.clone();
    c.config_integrity = None;
    c.metadata_snapshot_id = None;
    // Routing value, re-resolved each session — not part of the signed identity.
    c.telegram_channel_access_hash = 0;
    let json = serde_json::to_vec(&c).unwrap_or_default();
    let hash = blake3::keyed_hash(hierarchy.integrity.as_bytes(), &json);
    hex::encode(hash.as_bytes())
}

/// Constant-time byte-slice comparison (equal length only).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Atomically persist a volume config to `config_path`: pretty-serialize to a
/// sibling temp file (0600) whose name is unique to this write, fsync it, rename
/// it over the target, then fsync the directory. A SIGKILL / power loss
/// mid-write never leaves a partial or corrupt `volume.json`, and two concurrent
/// writers never share (and truncate) one temp inode — with a fixed temp name a
/// torn file could be renamed into place and the loser's rename failed. The
/// caller is responsible for having set `config_integrity` first.
fn write_config_atomic(config: &VolumeConfig, config_path: &Path) -> Result<()> {
    let config_json = serde_json::to_string_pretty(config)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    let tmp_path = {
        use rand::RngCore as _;
        let name = config_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "volume.json".into());
        config_path.with_file_name(format!(
            ".{name}.{}.{:016x}.tmp",
            std::process::id(),
            rand::rngs::OsRng.next_u64()
        ))
    };
    let result = write_then_rename(config_json.as_bytes(), &tmp_path, config_path);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

fn write_then_rename(bytes: &[u8], tmp_path: &Path, config_path: &Path) -> Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    {
        let mut opts = std::fs::OpenOptions::new();
        // create_new: a stale or attacker-planted temp of the same name is an
        // error, never something we write through.
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts
            .open(tmp_path)
            .map_err(|e| CoreError::Volume(format!("write config tmp: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| CoreError::Volume(format!("write config data: {e}")))?;
        f.sync_all()
            .map_err(|e| CoreError::Volume(format!("fsync config: {e}")))?;
    }
    std::fs::rename(tmp_path, config_path)
        .map_err(|e| CoreError::Volume(format!("rename config: {e}")))?;
    #[cfg(unix)]
    if let Some(dir) = config_path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all(); // best effort: the rename itself already landed
        }
    }
    Ok(())
}

/// Load the installation's independent owner signing capability. It is never
/// wrapped by a shared volume password and must be a private, regular 32-byte seed.
pub fn load_owner_capability(config_path: &Path) -> Result<ed25519_dalek::SigningKey> {
    let base = config_path
        .parent()
        .ok_or_else(|| CoreError::Volume("volume configuration has no parent".into()))?;
    let path = base.join("owner-signing.key");
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|e| CoreError::Volume(format!("read owner signing capability: {e}")))?;
    if !metadata.file_type().is_file() {
        return Err(CoreError::Volume(
            "owner signing capability is not a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(CoreError::Volume(
                "owner signing capability must have mode 0600".into(),
            ));
        }
    }
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(&path)
            .map_err(|e| CoreError::Volume(format!("read owner signing capability bytes: {e}")))?,
    );
    let seed: zeroize::Zeroizing<[u8; 32]> =
        zeroize::Zeroizing::new(bytes.as_slice().try_into().map_err(|_| {
            CoreError::Volume("owner signing capability must contain exactly 32 bytes".into())
        })?);
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// Exact last acknowledged owner header used when producing a slot-only update.
pub const OWNER_HEADER_FILENAME: &str = "owner-header.tgh";

/// One administration transaction for a volume's policy, vault anchors and
/// pending-header state. Independent of the mounted data/index lock.
#[derive(Debug)]
pub struct OwnerAdminLock {
    _file: crate::fsutil::ScopedFileLock,
    config_path: PathBuf,
}

impl OwnerAdminLock {
    /// Acquire without waiting, before reading mutable administration state.
    /// The stable sibling lock survives deletion of the volume directory.
    pub fn acquire(base_dir: &Path) -> Result<Self> {
        use fs2::FileExt;
        if !base_dir.is_dir() {
            return Err(CoreError::Volume(
                "owner administration volume directory is missing".into(),
            ));
        }
        let parent = base_dir
            .parent()
            .ok_or_else(|| CoreError::Volume("owner administration volume has no parent".into()))?;
        let name = base_dir
            .file_name()
            .ok_or_else(|| CoreError::Volume("owner administration volume has no name".into()))?;
        let mut lock_name = std::ffi::OsString::from(".");
        lock_name.push(name);
        lock_name.push(".owner-admin.lock");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(parent.join(lock_name))
            .map_err(|e| CoreError::Volume(format!("open owner administration lock: {e}")))?;
        file.try_lock_exclusive().map_err(|e| CoreError::Volume(format!("owner administration is already in progress or unavailable; retry after it completes: {e}")))?;
        let file = crate::fsutil::ScopedFileLock::from_locked_file(file);
        if !base_dir.is_dir() {
            return Err(CoreError::Volume(
                "owner administration volume was deleted".into(),
            ));
        }
        Ok(Self {
            _file: file,
            config_path: base_dir.join("volume.json"),
        })
    }

    /// Check that a mutator carries the transaction for this exact volume.
    pub fn require_config(&self, config_path: &Path) -> Result<()> {
        if self.config_path != config_path {
            return Err(CoreError::Volume(
                "owner administration transaction belongs to another volume".into(),
            ));
        }
        Ok(())
    }
}

fn refuse_stale_owner_policy(config: &VolumeConfig, config_path: &Path) -> Result<()> {
    let current: VolumeConfig = match std::fs::read(config_path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| CoreError::Serialization(e.to_string()))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(CoreError::Volume(format!(
                "read current owner configuration: {e}"
            )))
        }
    };
    if current.sdo_owner_public_key.is_none() {
        return Ok(());
    }
    let root_changed = current.salt != config.salt
        || current.password_verification_hash != config.password_verification_hash;
    let stale_vault = match (&current.key_protection, &config.key_protection) {
        (Some(old), Some(new)) if !root_changed => {
            new.vault_generation < old.vault_generation
                || (new.vault_generation == old.vault_generation
                    && new.vault_digest != old.vault_digest)
        }
        (Some(_), None) => true,
        _ => false,
    };
    let loses_pending = current
        .sdo_header_pending_bytes
        .as_ref()
        .is_some_and(|bytes| {
            config.sdo_header_revision_reserved <= current.sdo_header_revision_reserved
                && config.sdo_header_revision_published < current.sdo_header_revision_reserved
                && config.sdo_header_pending_bytes.as_ref() != Some(bytes)
        });
    if config.sdo_owner_public_key != current.sdo_owner_public_key
        || config.sdo_author_device_id != current.sdo_author_device_id
        || config.sdo_header_revision_published < current.sdo_header_revision_published
        || config.sdo_header_revision_reserved < current.sdo_header_revision_reserved
        || stale_vault
        || loses_pending
    {
        return Err(CoreError::Volume("refusing stale owner configuration: reread policy and vault anchors under the owner administration transaction".into()));
    }
    Ok(())
}

/// Reseal inside an already owned administration transaction. Callers spanning
/// an await must reload and update only their acknowledged fields before saving.
pub fn save_config_resealed_in_transaction(
    config: &mut VolumeConfig,
    hierarchy: &KeyHierarchy,
    config_path: &Path,
    admin: &OwnerAdminLock,
) -> Result<()> {
    admin.require_config(config_path)?;
    refuse_stale_owner_policy(config, config_path)?;
    config.config_integrity = Some(compute_config_integrity(config, hierarchy));
    write_config_atomic(config, config_path)
}

/// Re-sign and atomically persist a volume config after a mutation that the
/// `config_integrity` HMAC covers (e.g. a metadata-version bump, an epoch
/// advance, or — K0b — a slot-vault `(generation, digest)` re-pin after an
/// enroll/remove).
///
/// Recomputes `config_integrity` so the next open verifies. Without this,
/// mutating an HMAC-covered field and writing the config directly would brick the
/// volume on next open.
pub fn save_config_resealed(
    config: &mut VolumeConfig,
    hierarchy: &KeyHierarchy,
    config_path: &Path,
) -> Result<()> {
    let admin = OwnerAdminLock::acquire(
        config_path
            .parent()
            .ok_or_else(|| CoreError::Volume("configuration has no volume directory".into()))?,
    )?;
    save_config_resealed_in_transaction(config, hierarchy, config_path, &admin)
}

/// Authenticate a parsed config against a key hierarchy: BOTH the verification
/// hash and the config-integrity HMAC must be present and match — the same two
/// checks, in the same order, every open path performs.
///
/// For mutators that re-sign a config they read from disk (mfa-H1): re-signing
/// an unverified config turns a local tamperer's edit (a dropped
/// `require_block_integrity`, a lowered `metadata_version`) into an authentic
/// one. Verify with this, then mutate the SAME struct, then
/// [`save_config_resealed`]. This does not check the `key_protection` anchor
/// against a live vault — callers that hold the pre-mutation vault use
/// [`open_volume_with_master_key`] for that.
pub fn verify_config_anchors(config: &VolumeConfig, hierarchy: &KeyHierarchy) -> Result<()> {
    let expected_hash = config.password_verification_hash.as_ref().ok_or_else(|| {
        CoreError::Volume(
            "volume config is missing its verification hash — refusing to re-sign it".into(),
        )
    })?;
    if !ct_eq(
        compute_verification_hash(hierarchy).as_bytes(),
        expected_hash.as_bytes(),
    ) {
        return Err(CoreError::Decryption(
            "the key does not match this volume's verification hash — refusing to re-sign its \
             config"
                .into(),
        ));
    }
    let expected_hmac = config.config_integrity.as_ref().ok_or_else(|| {
        CoreError::Volume(
            "volume config is missing its integrity HMAC — refusing to re-sign it".into(),
        )
    })?;
    if !ct_eq(
        compute_config_integrity(config, hierarchy).as_bytes(),
        expected_hmac.as_bytes(),
    ) {
        return Err(CoreError::Volume(
            "volume config integrity check failed — volume.json was modified outside \
             teagarden; refusing to re-sign (and thereby authenticate) the change"
                .into(),
        ));
    }
    Ok(())
}

/// Derive a shared volume's hierarchy from its transferred root (the recipient
/// side of sharing): the same derivation [`open_volume_shared`] performs.
pub fn derive_shared_hierarchy(
    root: &[u8; 32],
    derivation: SharedDerivation,
    config: &VolumeConfig,
) -> Result<KeyHierarchy> {
    match derivation {
        SharedDerivation::HierarchyRootV1 => kdf::derive_hierarchy_v1(
            SymmetricKey::from_bytes(*root),
            &config.salt,
            config.telegram_group_id,
            config.telegram_topic_id,
        ),
    }
}

/// Recompute a config's verification hash and then its config-integrity HMAC
/// (in that order — the HMAC covers the hash) under `hierarchy`.
///
/// Both are deterministic functions of the hierarchy and the other config
/// fields, so a config whose anchors were stripped for transport (a v3 share
/// grant — sharing-M1) gets back exactly the bytes the owner has. Only call
/// this with a hierarchy that is authentic for the config (e.g. an AEAD-unwrapped
/// root bound to this exact config): it AUTHENTICATES whatever config it is given.
pub fn restore_config_anchors(config: &mut VolumeConfig, hierarchy: &KeyHierarchy) {
    config.config_integrity = None;
    config.password_verification_hash = Some(compute_verification_hash(hierarchy));
    config.config_integrity = Some(compute_config_integrity(config, hierarchy));
}

/// Paths associated with a volume on disk.
#[derive(Debug, Clone)]
pub struct VolumePaths {
    /// Base directory for volume data (e.g., `~/.teagarden/volumes/<id>/`)
    pub base_dir: PathBuf,
    /// SQLite metadata database path
    pub db_path: PathBuf,
    /// Serialized volume config path
    pub config_path: PathBuf,
    /// Cache directory
    pub cache_dir: PathBuf,
}

impl VolumePaths {
    /// Derive the standard volume paths (database, config, cache) from a base directory.
    pub fn new(base_dir: PathBuf) -> Self {
        let db_path = base_dir.join("metadata.db");
        let config_path = base_dir.join("volume.json");
        let cache_dir = base_dir.join("cache");
        Self {
            base_dir,
            db_path,
            config_path,
            cache_dir,
        }
    }

    /// Create all required directories.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.base_dir)?;
        std::fs::create_dir_all(&self.cache_dir)?;
        Ok(())
    }
}

/// An exclusive, advisory, cross-process lock on a single volume — the
/// single-writer correctness backstop.
///
/// Held via a non-blocking OS advisory lock on a dedicated `volume.lock` file in
/// the volume's base dir — deliberately NOT a SQLite sidecar, because `restore`
/// renames `metadata.db` and unlinks `-wal`/`-shm`/`-journal`, which would clobber
/// a sidecar lock mid-operation. The lock is released when the guard is dropped (or
/// the process exits), so it covers exactly the lifetime of the holder: a FUSE
/// mount holds it for the whole mount; an offline mutator (`revert` / `restore`)
/// holds it across the entire recover → mutate → publish → checkpoint sequence.
///
/// This serializes FUSE-vs-offline AND offline-vs-offline writers (which the
/// per-process `/proc/mounts` heuristic cannot — it sees neither a second offline
/// mutator nor any mount on a platform without `/proc/mounts`). A journaled write
/// concurrent with another writer interleaves the changeset before-image chain and
/// aborts crash recovery; this lock makes that unrepresentable for the holders that
/// take it.
#[derive(Debug)]
pub struct VolumeLock {
    // Explicit owner-process unlock ends the guard's lifetime even if a
    // concurrent fork still holds a copy of the open file description.
    _file: crate::fsutil::ScopedFileLock,
}

impl VolumeLock {
    /// Try to take the exclusive lock WITHOUT blocking. Returns a `CoreError::Volume`
    /// with a clear "in use by another process" message if another holder (a mount,
    /// or another offline mutator) currently owns it.
    pub fn acquire_exclusive(base_dir: &Path) -> Result<Self> {
        use fs2::FileExt as _;
        let path = base_dir.join("volume.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| CoreError::Volume(format!("open volume lock {}: {e}", path.display())))?;
        if let Err(err) = file.try_lock_exclusive() {
            return if err.kind() == std::io::ErrorKind::WouldBlock {
                Err(CoreError::Volume(
                    "volume is in use by another process (a mount, `key rotate`, `restore`, \
                     `republish`, `revert`, `delete` or a key-slot change is active); stop it \
                     and retry"
                        .into(),
                ))
            } else {
                Err(CoreError::Volume(format!("lock volume: {err}")))
            };
        }
        Ok(Self {
            _file: crate::fsutil::ScopedFileLock::from_locked_file(file),
        })
    }

    /// Take the lock SHARED, without blocking, for a command that only reads the
    /// volume's metadata DB (`volume history`, `volume diff`). Any number of
    /// shared holders coexist; a shared holder and an exclusive one exclude each
    /// other, so a reader never sees the DB while a mount, `restore` or `key
    /// rotate` is changing or replacing it.
    pub fn acquire_shared(base_dir: &Path) -> Result<Self> {
        let path = base_dir.join("volume.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| CoreError::Volume(format!("open volume lock {}: {e}", path.display())))?;
        // fs2's, not std's inherent `File::try_lock_shared` (other error type).
        if let Err(err) = fs2::FileExt::try_lock_shared(&file) {
            return if err.kind() == std::io::ErrorKind::WouldBlock {
                Err(CoreError::Volume(
                    "volume is in use by another process (a mount, `key rotate`, `restore`, \
                     `republish`, `revert`, `delete` or a key-slot change is active); stop it \
                     and retry"
                        .into(),
                ))
            } else {
                Err(CoreError::Volume(format!("lock volume: {err}")))
            };
        }
        Ok(Self {
            _file: crate::fsutil::ScopedFileLock::from_locked_file(file),
        })
    }

    /// Probe whether a WRITER (an exclusive holder: a mount, `restore`, `revert`,
    /// `delete`, `key rotate`, a key-slot change) holds the volume's lock now,
    /// WITHOUT keeping it. A shared holder (`volume history` / `volume diff`)
    /// is not a writer and does not count. `Ok(true)` = a writer is live,
    /// `Ok(false)` = no writer, `Err` = the lock file could not be opened/checked
    /// (a real fault — e.g. permissions — not contention). Used to wait for a
    /// mount's writer to finish draining on unmount without conflating "still
    /// flushing" with "the lock path is broken", or with a reader.
    pub fn is_held(base_dir: &Path) -> std::io::Result<bool> {
        let path = base_dir.join("volume.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        // A shared probe succeeds beside readers and fails only beside a writer.
        match fs2::FileExt::try_lock_shared(&file) {
            // The shared probe must end here even if an unrelated fork inherited
            // its descriptor before this return.
            Ok(()) => {
                let _probe = crate::fsutil::ScopedFileLock::from_locked_file(file);
                Ok(false)
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
            Err(err) => Err(err),
        }
    }
}

/// File name of the journal HEAD in a volume directory
/// ([`crate::volume::journal_head::JournalHead`]).
pub const JOURNAL_HEAD_FILE: &str = "journal.head";

/// Whether the volume in `base_dir` (configuration `config`) has published
/// metadata to Telegram, so that its local metadata DB may only be rebuilt from
/// there and never created empty.
///
/// True when volume.json records a published or a reserved snapshot version
/// (`metadata_version`, `metadata_version_reserved`: both covered by the
/// configuration MAC, so editing volume.json cannot clear them), names a
/// snapshot (`metadata_snapshot_id`, outside the MAC), or a journal HEAD
/// exists. The MAC-covered versions are what makes this hold against a
/// volume.json whose snapshot id was removed and a deleted journal.head.
/// Every opener of a volume's metadata DB decides with this one function.
pub fn has_published(config: &VolumeConfig, base_dir: &Path) -> bool {
    config.metadata_version > 0
        || config.metadata_version_reserved > 0
        || config.metadata_snapshot_id.is_some()
        || base_dir.join(JOURNAL_HEAD_FILE).exists()
}

/// Whether the volume in `base_dir` has SUCCESSFULLY published a metadata
/// snapshot, so there is something on Telegram to rebuild its local metadata
/// DB from: volume.json records a published version (`metadata_version`,
/// MAC-covered) or names a snapshot, or a journal HEAD exists (only a
/// successful publish or a restore writes one).
///
/// [`has_published`] without this is a volume whose first mount reserved a
/// snapshot version and failed to publish its base snapshot ("reserved-only"):
/// nothing on Telegram, and no user data either, because that first mount
/// stops before the filesystem is served when its base publish fails. Its
/// local DB may then be created (again) like a new volume's.
pub fn has_published_snapshot(config: &VolumeConfig, base_dir: &Path) -> bool {
    config.metadata_version > 0
        || config.metadata_snapshot_id.is_some()
        || base_dir.join(JOURNAL_HEAD_FILE).exists()
}

/// Result of creating a new volume.
#[derive(Debug)]
pub struct CreateVolumeResult {
    /// Configuration of the newly created volume.
    pub config: VolumeConfig,
    /// On-disk paths for the new volume.
    pub paths: VolumePaths,
    /// Derived key hierarchy for the new volume.
    pub hierarchy: KeyHierarchy,
}

/// Result of opening an existing volume.
#[derive(Debug)]
pub struct OpenVolumeResult {
    /// Configuration of the opened volume.
    pub config: VolumeConfig,
    /// On-disk paths for the opened volume.
    pub paths: VolumePaths,
    /// Derived key hierarchy for the opened volume.
    pub hierarchy: KeyHierarchy,
}

/// Compute the default base directory for volumes.
///
/// Returns the platform data directory (e.g. `~/.local/share/teagarden/volumes`
/// on Linux, `~/Library/Application Support/teagarden/volumes` on macOS).
///
/// # Panics
///
/// Panics if the platform data directory cannot be determined. This should
/// never happen on supported platforms (Linux, macOS).
pub fn default_volumes_dir() -> PathBuf {
    // Honor an explicit override (also the documented escape hatch in the panic
    // message below, and what makes offline CLI e2e tests possible).
    if let Some(dir) = std::env::var_os("TEAGARDEN_VOLUMES_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    dirs::data_dir()
        .expect("unable to determine platform data directory; set TEAGARDEN_VOLUMES_DIR")
        .join("teagarden")
        .join("volumes")
}

/// Build a fresh volume config (unique id, random salt, defaults) bound to the
/// given forum group + topic, and create its on-disk directories. Shared by the
/// password-rooted [`create_volume`] and the MK-rooted [`prepare_volume_mk_rooted`]
/// paths — everything up to the point where the key hierarchy is derived.
fn new_volume_config(
    name: Option<&str>,
    volumes_dir: &Path,
    group_id: i64,
    group_access_hash: i64,
    topic_id: i64,
    block_size: Option<u64>,
) -> Result<(VolumeConfig, VolumePaths)> {
    let display_name = name
        .map(std::string::ToString::to_string)
        .unwrap_or_else(names::generate_group_name);
    let group_name = names::generate_group_name();
    let mut config = VolumeConfig::new(display_name, group_name);

    // Optional per-volume block size override (default is BlockConfig::default()).
    // Set before config_integrity so the HMAC covers the chosen size; it is part of
    // the serialized config. The effective FUSE chunk size is clamped at mount via
    // BlockConfig::fuse_chunk_size().
    if let Some(bs) = block_size {
        config.block_config.target_block_size = bs;
    }

    // Bind the shared forum group + this volume's topic into the cryptographic
    // identity. Set before the KDF call so they are part of the derived hierarchy.
    config.volume_version = 1;
    config.telegram_group_id = group_id;
    config.telegram_channel_access_hash = group_access_hash;
    config.telegram_topic_id = topic_id;

    // The volumes directory holds every volume's database and slot vault: 0700
    // whatever the umask (an existing one is tightened).
    crate::fsutil::ensure_private_dir(volumes_dir)
        .map_err(|e| CoreError::Volume(format!("create volumes dir: {e}")))?;
    let paths = VolumePaths::new(volumes_dir.join(config.volume_id.to_string()));
    paths
        .ensure_dirs()
        .map_err(|e| CoreError::Volume(format!("create dirs: {e}")))?;
    Ok((config, paths))
}

/// Create a new **password-rooted** (legacy) volume: generate config, derive keys
/// from the password, persist config to disk.
///
/// When `channel_id` is non-zero (v1 volumes), the Telegram channel must have
/// been created before this call so that the channel_id can be mixed into the
/// HKDF salt, cryptographically binding the key hierarchy to that channel.
///
/// Pass `channel_id = 0, channel_access_hash = 0` to create an offline volume
/// (v0 semantics: key hierarchy is not channel-bound).
///
/// For real multi-factor protection use the MK-rooted path
/// ([`prepare_volume_mk_rooted`] + [`commit_prepared_volume`]) instead.
pub fn create_volume(
    name: Option<&str>,
    password: &[u8],
    volumes_dir: &Path,
    group_id: i64,
    group_access_hash: i64,
    topic_id: i64,
    block_size: Option<u64>,
) -> Result<CreateVolumeResult> {
    let (mut config, paths) = new_volume_config(
        name,
        volumes_dir,
        group_id,
        group_access_hash,
        topic_id,
        block_size,
    )?;

    // Derive key hierarchy — bound to (group_id, topic_id) so each volume's topic
    // yields a unique hierarchy.
    let root_key = kdf::derive_root_key(password, &config.salt, &config.kdf_params)?;
    let hierarchy = kdf::derive_hierarchy_v1(
        root_key,
        &config.salt,
        config.telegram_group_id,
        config.telegram_topic_id,
    )?;

    // Store password verification hash (allows "wrong password" detection on open)
    config.password_verification_hash = Some(compute_verification_hash(&hierarchy));
    // Store config integrity HMAC (detects KDF-parameter tampering)
    config.config_integrity = Some(compute_config_integrity(&config, &hierarchy));

    let _admin = OwnerAdminLock::acquire(&paths.base_dir)?;
    write_config_atomic(&config, &paths.config_path)?;

    Ok(CreateVolumeResult {
        config,
        paths,
        hierarchy,
    })
}

/// A MK-rooted volume that has been fully prepared in memory (config, dirs, keys)
/// but whose `volume.json` has **not** yet been written. See
/// [`prepare_volume_mk_rooted`].
#[derive(Debug)]
pub struct PreparedVolume {
    /// The prepared (unsigned-on-disk) volume config, with `key_protection`,
    /// verification hash and integrity HMAC already populated.
    pub config: VolumeConfig,
    /// On-disk paths (the base dir already exists; `volume.json` does not).
    pub paths: VolumePaths,
    /// The MK-derived key hierarchy.
    pub hierarchy: KeyHierarchy,
}

/// Phase 1 of MK-rooted create (K0b): mint the config + dirs, derive the key
/// hierarchy from the slot-vault **master key**, and populate the
/// `key_protection` anchor, verification hash, and config-integrity HMAC — but do
/// **not** write `volume.json` yet.
///
/// The caller (`mfa::unlock::create_protected_volume`) must, in order:
/// 1. mint the vault + MK and enroll **all** initial slots (so `vault_generation`
///    / `vault_digest` reflect the final opening state),
/// 2. call this with that `mk` + `vault_generation` + `vault_digest`,
/// 3. save `slot_vault.json` into `prepared.paths.base_dir` (**vault before
///    config**, so a crash here orphans a harmless vault rather than bricking a
///    config whose vault is missing),
/// 4. call [`commit_prepared_volume`] to atomically write `volume.json`.
#[allow(clippy::too_many_arguments)] // volume identity: name + mk + anchor + (group,topic) + block size
pub fn prepare_volume_mk_rooted(
    name: Option<&str>,
    mk: &[u8; 32],
    vault_generation: u64,
    vault_digest: &[u8; 32],
    volumes_dir: &Path,
    group_id: i64,
    group_access_hash: i64,
    topic_id: i64,
    block_size: Option<u64>,
) -> Result<PreparedVolume> {
    let (mut config, paths) = new_volume_config(
        name,
        volumes_dir,
        group_id,
        group_access_hash,
        topic_id,
        block_size,
    )?;

    // The RANDOM master key is the root — a factor is genuinely required to
    // reconstruct these keys (real protection, not a gate).
    let hierarchy = kdf::derive_hierarchy_from_master_key(
        mk,
        &config.salt,
        config.telegram_group_id,
        config.telegram_topic_id,
    )?;

    // Anchor the vault's post-enroll state; set BEFORE the integrity HMAC so the
    // anchor is signed and cannot be forged or rolled back without the MK.
    config.key_protection = Some(crate::volume::config::KeyProtection {
        vault_generation,
        vault_digest: hex::encode(vault_digest),
    });
    config.password_verification_hash = Some(compute_verification_hash(&hierarchy));
    config.config_integrity = Some(compute_config_integrity(&config, &hierarchy));

    Ok(PreparedVolume {
        config,
        paths,
        hierarchy,
    })
}

/// Prepare an existing volume config to use a fresh random master key and salt
/// while preserving its Telegram topic and stable volume UUID. The caller must
/// verify the old config before calling this function, persist the new slot vault
/// before the returned config, then publish the owner-signed generation header.
#[cfg(feature = "key-rotation")]
pub fn prepare_rotated_volume_config(
    original: &VolumeConfig,
    master_key: &[u8; 32],
    salt: [u8; 32],
    vault_generation: u64,
    vault_digest: &[u8; 32],
) -> Result<(VolumeConfig, KeyHierarchy)> {
    if vault_generation == 0 {
        return Err(CoreError::Volume(
            "rotation slot vault generation must be nonzero".into(),
        ));
    }
    let hierarchy = kdf::derive_hierarchy_from_master_key(
        master_key,
        &salt,
        original.telegram_group_id,
        original.telegram_topic_id,
    )?;
    let mut rotated = original.clone();
    rotated.salt = salt;
    rotated.key_protection = Some(crate::volume::config::KeyProtection {
        vault_generation,
        vault_digest: hex::encode(vault_digest),
    });
    restore_config_anchors(&mut rotated, &hierarchy);
    Ok((rotated, hierarchy))
}

/// Phase 2 of MK-rooted create: atomically write `volume.json` for a prepared
/// volume (call only after `slot_vault.json` has been saved — see
/// [`prepare_volume_mk_rooted`]).
pub fn commit_prepared_volume(prepared: PreparedVolume) -> Result<CreateVolumeResult> {
    let _admin = OwnerAdminLock::acquire(&prepared.paths.base_dir)?;
    write_config_atomic(&prepared.config, &prepared.paths.config_path)?;
    Ok(CreateVolumeResult {
        config: prepared.config,
        paths: prepared.paths,
        hierarchy: prepared.hierarchy,
    })
}

/// Open an existing volume: load config, derive keys from password.
///
/// Enforces per-volume exponential-backoff lockout: repeated wrong-password
/// attempts trigger increasing delays (1 s → 2 s → 4 s → … → 3600 s).
/// State is persisted in `{volume_dir}/auth_lockout.json`.
pub fn open_volume(
    volume_id: &str,
    password: &[u8],
    volumes_dir: &Path,
) -> Result<OpenVolumeResult> {
    let paths = VolumePaths::new(volumes_dir.join(volume_id));

    if !paths.config_path.exists() {
        return Err(CoreError::Volume(format!(
            "volume not found: {}",
            volume_id
        )));
    }

    // Enforce exponential-backoff lockout before running the expensive KDF.
    let lockout_path = paths.base_dir.join("auth_lockout.json");
    // Fails closed (core-M6): an unreadable or corrupt lockout file is an error,
    // not a reset.
    let mut lockout = LockoutState::load(&lockout_path)?;
    if let Some(remaining) = lockout.check_locked() {
        return Err(CoreError::Locked {
            retry_after_secs: remaining,
        });
    }

    let config_json = std::fs::read_to_string(&paths.config_path)
        .map_err(|e| CoreError::Volume(format!("read config: {e}")))?;
    let config: VolumeConfig = serde_json::from_str(&config_json)
        .map_err(|e| CoreError::Serialization(format!("parse config: {e}")))?;

    // K0b fail-closed linchpin: a MK-rooted (key-protected) volume derives its
    // hierarchy from the vault's random master key, NOT the password. A bare
    // password can neither reproduce those keys nor bypass the factor, so refuse
    // here and route the caller to the vault unlock path
    // (`mfa::unlock::open_volume` → `open_volume_with_master_key`). This is the
    // single check that makes every legacy/un-migrated open-site safe at once: an
    // un-wired caller fails closed rather than opening. (Don't touch lockout — a
    // mis-route is not an authentication attempt.)
    if config.key_protection.is_some() {
        return Err(CoreError::Volume(
            "this volume is key-protected (its keys derive from a key-slot vault's random \
             master key); open it through one of its key slots (passphrase slot, recovery \
             sentence, or an enrolled device), not the bare-password path"
                .into(),
        ));
    }

    let root_key = kdf::derive_root_key(password, &config.salt, &config.kdf_params)?;
    let hierarchy = kdf::derive_hierarchy_v1(
        root_key,
        &config.salt,
        config.telegram_group_id,
        config.telegram_topic_id,
    )?;

    // Both anchors are mandatory in 1.0. Treating their *presence* as optional
    // let an attacker delete config_integrity, lower an HMAC-covered security
    // field such as metadata_version, and skip the check entirely. Pre-release
    // configs without both anchors cannot be authenticated and fail closed.
    let expected_hash = config.password_verification_hash.as_ref().ok_or_else(|| {
        CoreError::Volume(
            "volume is missing its password verification hash — refusing an unauthenticated open"
                .into(),
        )
    })?;
    let actual_hash = compute_verification_hash(&hierarchy);
    if !ct_eq(actual_hash.as_bytes(), expected_hash.as_bytes()) {
        // A failure that cannot be recorded must not pass silently: report it
        // alongside the wrong-password error (the open is refused either way).
        if let Err(e) = lockout.record_failure(&lockout_path) {
            return Err(CoreError::Decryption(format!(
                "wrong password: verification hash mismatch (and the failed attempt could \
                 not be recorded: {e})"
            )));
        }
        return Err(CoreError::Decryption(
            "wrong password: verification hash mismatch".into(),
        ));
    }

    let expected_hmac = config.config_integrity.as_ref().ok_or_else(|| {
        CoreError::Volume(
            "volume is missing its config integrity HMAC — refusing an unauthenticated open".into(),
        )
    })?;
    let actual_hmac = compute_config_integrity(&config, &hierarchy);
    if !ct_eq(actual_hmac.as_bytes(), expected_hmac.as_bytes()) {
        // Config tampering is not a user error — don't burn a lockout slot.
        return Err(CoreError::Volume(
            "volume config integrity check failed — KDF parameters may have been tampered".into(),
        ));
    }

    // Successful open — reset the lockout counter. A reset that cannot be
    // persisted is an error: the next open would otherwise see a stale lockout
    // with no explanation.
    lockout.record_success(&lockout_path)?;

    Ok(OpenVolumeResult {
        config,
        paths,
        hierarchy,
    })
}

/// Open a **MK-rooted** (key-protected) volume once its master key has been
/// recovered from the slot vault. This is the K0b counterpart to [`open_volume`]:
/// the caller (`mfa::unlock::open_volume`) loads `slot_vault.json`, unlocks it with
/// the operator's factors to obtain `mk`, and passes it here together with the
/// **live** vault `(vault_generation, vault_digest)`.
///
/// Ordering is load-bearing (recover-then-verify, design §4): the config-integrity
/// HMAC key is itself MK-derived, so we (1) derive the hierarchy from the MK,
/// then (2) verify the verification hash + config integrity, then (3) check the
/// anti-rollback anchor — which is only trustworthy once the HMAC over the config
/// carrying it has verified.
///
/// **Lockout parity (documented, deliberate — advisor):** unlike [`open_volume`],
/// this path enforces no exponential-backoff lockout. Wrong-factor guesses for a
/// passphrase slot are rate-limited only by that slot's Argon2id cost (inside
/// `SlotVault::unlock`, before this function is reached); a wrong *master key*
/// (vault-swap) is a config/vault mismatch, not a user typo, so it does not burn
/// a lockout slot either. The local backoff file adds little against an offline
/// attacker who ignores it, so its absence here is an accepted residual, not an
/// oversight.
pub fn open_volume_with_master_key(
    volume_id: &str,
    mk: &[u8; 32],
    vault_generation: u64,
    vault_digest: &[u8; 32],
    volumes_dir: &Path,
) -> Result<OpenVolumeResult> {
    let paths = VolumePaths::new(volumes_dir.join(volume_id));

    if !paths.config_path.exists() {
        return Err(CoreError::Volume(format!(
            "volume not found: {}",
            volume_id
        )));
    }

    let config_json = std::fs::read_to_string(&paths.config_path)
        .map_err(|e| CoreError::Volume(format!("read config: {e}")))?;
    let config: VolumeConfig = serde_json::from_str(&config_json)
        .map_err(|e| CoreError::Serialization(format!("parse config: {e}")))?;

    // This entry point is ONLY for MK-rooted volumes. A legacy (password-rooted)
    // volume routed here is a caller bug — refuse rather than derive wrong keys.
    let kp = config.key_protection.clone().ok_or_else(|| {
        CoreError::Volume(
            "open_volume_with_master_key called on a volume that is not key-protected; \
             use open_volume"
                .into(),
        )
    })?;

    // (1) Derive the hierarchy from the MASTER KEY (not the password).
    let hierarchy = kdf::derive_hierarchy_from_master_key(
        mk,
        &config.salt,
        config.telegram_group_id,
        config.telegram_topic_id,
    )?;

    // (2a) Verify the verification hash. A vault-SWAP (an attacker's own valid
    // vault carrying a DIFFERENT master key) recovers a wrong mk → wrong
    // hierarchy → mismatch here. Fail closed. Both the hash and the integrity HMAC
    // are MANDATORY for a protected volume (they are always written at MK-rooted
    // create), so a strip-then-tamper edit cannot skip these checks to reach the
    // anchor (advisor hardening).
    let expected_hash = config.password_verification_hash.as_ref().ok_or_else(|| {
        CoreError::Volume(
            "key-protected volume is missing its verification hash — refusing to open".into(),
        )
    })?;
    let actual_hash = compute_verification_hash(&hierarchy);
    if !ct_eq(actual_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err(CoreError::Decryption(
            "vault master key does not match this volume (wrong or substituted vault)".into(),
        ));
    }

    // (2b) Verify config integrity — the HMAC key is the MK-derived
    // `hierarchy.integrity`, so this simultaneously AUTHENTICATES the
    // `key_protection` anchor checked next.
    let expected_hmac = config.config_integrity.as_ref().ok_or_else(|| {
        CoreError::Volume(
            "key-protected volume is missing its config integrity HMAC — refusing to open".into(),
        )
    })?;
    let actual_hmac = compute_config_integrity(&config, &hierarchy);
    if !ct_eq(actual_hmac.as_bytes(), expected_hmac.as_bytes()) {
        return Err(CoreError::Volume(
            "volume config integrity check failed — config may have been tampered".into(),
        ));
    }

    // (3) Anti-rollback: the LIVE vault's (generation, digest) must match the
    // now-authenticated anchor. A vault-only rollback (revert `slot_vault.json`
    // alone to re-enable a removed slot) trips this. NOTE: a whole-volume
    // rollback (revert `volume.json` AND `slot_vault.json` together to an earlier
    // consistent snapshot) is NOT caught by this anchor — see design §4a; closing
    // it needs external monotonic state (TPM NV counter / server epoch).
    let want_digest = hex::decode(&kp.vault_digest)
        .map_err(|e| CoreError::Volume(format!("bad key_protection digest: {e}")))?;
    if vault_generation != kp.vault_generation || !ct_eq(vault_digest, &want_digest) {
        return Err(CoreError::Volume(
            "the key vault is stale or was rolled back (generation/digest mismatch); a removed \
             slot cannot be re-enabled by reverting the vault file"
                .into(),
        ));
    }

    Ok(OpenVolumeResult {
        config,
        paths,
        hierarchy,
    })
}

/// Write a volume config verbatim to `config_path` (recipient side of sharing).
///
/// The owner ships the exact serialized `VolumeConfig` — including its
/// `config_integrity` HMAC — and the recipient writes it byte-for-byte so the
/// shared open's self-check verifies against the owner's own anchor. This is a
/// thin public wrapper over the atomic writer; it does NOT recompute integrity
/// (that would defeat the point).
pub fn write_shared_config(config: &VolumeConfig, config_path: &Path) -> Result<()> {
    let _admin = OwnerAdminLock::acquire(
        config_path
            .parent()
            .ok_or_else(|| CoreError::Volume("shared configuration has no parent".into()))?,
    )?;
    refuse_stale_owner_policy(config, config_path)?;
    write_config_atomic(config, config_path)
}

/// Open a **shared** volume from its hierarchy root directly — no password, no
/// master-key vault of our own.
///
/// This is the recipient side of volume sharing (and of multi-computer
/// single-operator onboarding). The owner wraps their `hierarchy.root` — the raw
/// 32-byte root that the internal `kdf::derive_hierarchy_raw` helper consumes, which is
/// `KeyHierarchy::root` for **every** volume regardless of how the owner rooted
/// it (Argon2 password or MK vault) — and transmits it (ML-KEM-wrapped) plus the
/// non-secret [`VolumeConfig`]. The recipient materializes the config locally and
/// calls this with the unwrapped root.
///
/// Because `derive_hierarchy_v1` is the common tail of both root derivations
/// (see `kdf`), reconstructing from `root` reproduces the owner's hierarchy
/// exactly — there is no derivation-kind branch to get wrong.
///
/// **The self-check is load-bearing.** A wrong root (corrupted transfer, wrong
/// recipient key, a tampered grant) yields a different hierarchy, which fails the
/// verification-hash and config-integrity checks below. Both anchors MUST be
/// present and valid; accepting one while the other is stripped would leave
/// either the root or config fields unauthenticated. There is no lockout here:
/// the root is a cryptographic secret, not a
/// guessable password, so a mismatch is a transfer/identity error, not an auth
/// attempt.
pub fn open_volume_shared(
    volume_id: &str,
    root: &[u8; 32],
    derivation: SharedDerivation,
    volumes_dir: &Path,
) -> Result<OpenVolumeResult> {
    let paths = VolumePaths::new(volumes_dir.join(volume_id));
    if !paths.config_path.exists() {
        return Err(CoreError::Volume(format!(
            "volume not found: {}",
            volume_id
        )));
    }
    let config_json = std::fs::read_to_string(&paths.config_path)
        .map_err(|e| CoreError::Volume(format!("read config: {e}")))?;
    let config: VolumeConfig = serde_json::from_str(&config_json)
        .map_err(|e| CoreError::Serialization(format!("parse config: {e}")))?;

    // Exhaustive match so a future SharedDerivation variant forces a decision here
    // rather than silently mis-deriving.
    let hierarchy = match derivation {
        SharedDerivation::HierarchyRootV1 => kdf::derive_hierarchy_v1(
            SymmetricKey::from_bytes(*root),
            &config.salt,
            config.telegram_group_id,
            config.telegram_topic_id,
        )?,
    };

    // Both anchors are mandatory. The verification hash authenticates the
    // transferred root; the HMAC authenticates every security-relevant config
    // field. Accepting only one allowed an attacker to strip the other.
    let expected_hash = config.password_verification_hash.as_ref().ok_or_else(|| {
        CoreError::Volume(
            "shared volume is missing its verification hash — refusing an unauthenticated open"
                .into(),
        )
    })?;
    let actual_hash = compute_verification_hash(&hierarchy);
    if !ct_eq(actual_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err(CoreError::Decryption(
            "shared root does not open this volume (wrong grant, wrong recipient key, or \
             corrupted transfer)"
                .into(),
        ));
    }
    let expected_hmac = config.config_integrity.as_ref().ok_or_else(|| {
        CoreError::Volume(
            "shared volume is missing its config integrity HMAC — refusing an unauthenticated open"
                .into(),
        )
    })?;
    let actual_hmac = compute_config_integrity(&config, &hierarchy);
    if !ct_eq(actual_hmac.as_bytes(), expected_hmac.as_bytes()) {
        return Err(CoreError::Volume(
            "shared volume config integrity check failed — config may have been tampered, or \
             the root is wrong"
                .into(),
        ));
    }

    Ok(OpenVolumeResult {
        config,
        paths,
        hierarchy,
    })
}

/// List all volumes in the volumes directory.
pub fn list_volumes(volumes_dir: &Path) -> Result<Vec<VolumeConfig>> {
    if !volumes_dir.exists() {
        return Ok(Vec::new());
    }

    let mut volumes = Vec::new();
    let entries = std::fs::read_dir(volumes_dir)
        .map_err(|e| CoreError::Volume(format!("read volumes dir: {e}")))?;

    for entry in entries {
        let entry = entry.map_err(|e| CoreError::Volume(format!("dir entry: {e}")))?;
        let config_path = entry.path().join("volume.json");
        if config_path.exists() {
            if let Ok(json) = std::fs::read_to_string(&config_path) {
                if let Ok(config) = serde_json::from_str::<VolumeConfig>(&json) {
                    volumes.push(config);
                }
            }
        }
    }

    Ok(volumes)
}

/// Delete a volume's local directory.
///
/// Every file in it is overwritten once, in place, with random data, flushed to
/// disk, and then deleted; then the directory is removed. The overwrite is best
/// effort only: it does not guarantee that the old bytes are gone from the
/// storage device. SSDs remap writes to fresh flash cells, copy-on-write
/// filesystems (APFS, Btrfs, ZFS) write the new data to new blocks, journaling
/// filesystems may keep copies in their journal, and snapshots and backups keep
/// their own copies.
pub fn delete_volume(volume_id: &str, volumes_dir: &Path) -> Result<()> {
    let vol_dir = volumes_dir.join(volume_id);
    if std::fs::symlink_metadata(&vol_dir).is_err() {
        return Err(CoreError::Volume(format!(
            "volume not found: {}",
            volume_id
        )));
    }
    delete_dir_overwriting(&vol_dir)
}

/// Overwrite and delete a directory of teagarden-owned state: the removal
/// [`delete_volume`] performs, for a directory that is not a volume (a block
/// device's state directory).
///
/// `dir` must be a real directory: a symlink, or anything else, standing in for
/// it is refused and never followed. Inside it, symlinks are removed as links
/// and special files without being opened (see [`delete_volume`] for the
/// best-effort limits of the overwrite).
pub fn delete_dir_overwriting(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Err(e) => {
            return Err(CoreError::Volume(format!(
                "cannot delete {}: {e}",
                dir.display()
            )));
        }
        Ok(meta) if !meta.file_type().is_dir() => {
            // Never follow a symlink (or anything else) standing in for the
            // directory: deleting must touch only the directory's own files.
            return Err(CoreError::Volume(format!(
                "refusing to delete {}: it is not a directory",
                dir.display()
            )));
        }
        Ok(_) => {}
    }
    overwrite_and_remove_dir(dir)?;
    std::fs::remove_dir_all(dir)
        .map_err(|e| CoreError::Volume(format!("delete {}: {e}", dir.display())))?;
    Ok(())
}

/// Overwrite and delete every file below `dir` (best effort; see
/// [`delete_volume`]). Directories themselves are left for the caller.
///
/// Symlinks are never followed: a symlink is removed as a link and its target is
/// left alone. Only regular files are opened and overwritten; anything else (FIFO,
/// socket, device node) is removed without being opened.
fn overwrite_and_remove_dir(dir: &Path) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CoreError::Volume(format!("read dir for overwrite and delete: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| CoreError::Volume(format!("dir entry: {e}")))?;
        let path = entry.path();
        // DirEntry::file_type does not follow symlinks.
        let ft = entry
            .file_type()
            .map_err(|e| CoreError::Volume(format!("file type: {e}")))?;
        if ft.is_dir() {
            overwrite_and_remove_dir(&path)?;
        } else if ft.is_file() {
            overwrite_and_remove_file(&path)?;
        } else {
            std::fs::remove_file(&path).map_err(|e| CoreError::Volume(format!("delete: {e}")))?;
        }
    }
    Ok(())
}

/// Overwrite one file in place with random data, once, flush it, then delete it.
fn overwrite_and_remove_file(path: &Path) -> Result<()> {
    overwrite_file_in_place(path)?;
    std::fs::remove_file(path)
        .map_err(|e| CoreError::Volume(format!("delete after overwrite: {e}")))?;
    Ok(())
}

/// Overwrite a file's existing bytes with random data, without truncating it.
///
/// The file is opened for writing WITHOUT `O_TRUNC`, so on a filesystem that
/// overwrites in place (for example ext4 without data journaling) the new bytes
/// land in the blocks the old ones occupied. (Truncating first, as
/// `std::fs::write` does, frees those blocks and writes the new data wherever the
/// allocator puts it, leaving the old bytes untouched.)
fn overwrite_file_in_place(path: &Path) -> Result<()> {
    use rand::RngCore;
    use std::io::Write as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    // Refuse a symlink swapped in after the type check, and never block on a FIFO.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| CoreError::Volume(format!("open for overwrite: {e}")))?;
    let meta = f
        .metadata()
        .map_err(|e| CoreError::Volume(format!("stat for overwrite: {e}")))?;
    if !meta.is_file() {
        return Err(CoreError::Volume(format!(
            "refusing to overwrite {}: not a regular file",
            path.display()
        )));
    }
    let mut remaining = meta.len();
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        rand::rngs::OsRng.fill_bytes(&mut buf[..n]);
        f.write_all(&buf[..n])
            .map_err(|e| CoreError::Volume(format!("overwrite write: {e}")))?;
        remaining -= n as u64;
    }
    f.sync_all()
        .map_err(|e| CoreError::Volume(format!("overwrite sync: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "key-rotation")]
    fn root_rotation_prepares_same_volume_for_fresh_master_key_and_salt() {
        let volumes = tempfile::tempdir().unwrap();
        let original = create_volume(
            Some("root-rotation"),
            b"old password",
            volumes.path(),
            -100,
            77,
            900,
            None,
        )
        .unwrap();
        let new_salt = [0x5a; 32];
        let new_master_key = [0xa6; 32];
        let (rotated, new_hierarchy) = prepare_rotated_volume_config(
            &original.config,
            &new_master_key,
            new_salt,
            4,
            &[0x39; 32],
        )
        .unwrap();
        assert_eq!(rotated.volume_id, original.config.volume_id);
        assert_eq!(rotated.telegram_group_id, original.config.telegram_group_id);
        assert_eq!(rotated.telegram_topic_id, original.config.telegram_topic_id);
        assert_eq!(rotated.salt, new_salt);
        assert!(rotated.key_protection.is_some());
        verify_config_anchors(&rotated, &new_hierarchy).unwrap();
        assert!(verify_config_anchors(&rotated, &original.hierarchy).is_err());
    }

    /// Deleting a volume overwrites only the volume's own regular files. A symlink
    /// inside the volume directory (to a file or to a directory outside it) is
    /// removed as a link; its target is never opened, overwritten or deleted. A
    /// FIFO is removed without being opened (opening it for writing would block).
    #[cfg(unix)]
    #[test]
    fn delete_volume_never_follows_symlinks_or_opens_special_files() {
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim.txt");
        std::fs::write(&victim, b"must stay exactly like this").unwrap();
        let victim_dir = outside.path().join("victim-dir");
        std::fs::create_dir(&victim_dir).unwrap();
        let inner = victim_dir.join("inner.txt");
        std::fs::write(&inner, b"inner must survive").unwrap();

        let volumes = tempfile::tempdir().unwrap();
        let vol = volumes.path().join("vol-1");
        std::fs::create_dir_all(vol.join("sub")).unwrap();
        std::fs::write(vol.join("metadata.db"), b"volume bytes").unwrap();
        std::fs::write(vol.join("sub/cache.bin"), b"more volume bytes").unwrap();
        std::os::unix::fs::symlink(&victim, vol.join("link-to-file")).unwrap();
        std::os::unix::fs::symlink(&victim_dir, vol.join("sub/link-to-dir")).unwrap();
        let fifo = std::ffi::CString::new(vol.join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        super::delete_volume("vol-1", volumes.path()).unwrap();

        assert!(!vol.exists(), "the volume directory must be gone");
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"must stay exactly like this"
        );
        assert_eq!(std::fs::read(&inner).unwrap(), b"inner must survive");
    }

    /// The directory-removal helper `dev delete` uses: nested files go, a symlink
    /// inside is removed as a link (its target survives), and a symlink standing
    /// in for the directory itself is refused.
    #[cfg(unix)]
    #[test]
    fn delete_dir_overwriting_removes_a_state_dir_and_refuses_a_symlink() {
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim.txt");
        std::fs::write(&victim, b"keep").unwrap();

        let base = tempfile::tempdir().unwrap();
        let state = base.path().join("state");
        std::fs::create_dir_all(state.join("sub")).unwrap();
        std::fs::write(state.join("staging.log"), b"staged bytes").unwrap();
        std::os::unix::fs::symlink(&victim, state.join("sub/link")).unwrap();
        super::delete_dir_overwriting(&state).unwrap();
        assert!(!state.exists(), "the state directory must be gone");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");

        let link = base.path().join("link-to-outside");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        assert!(super::delete_dir_overwriting(&link).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    /// A volume directory that is itself a symlink is refused, not followed.
    #[cfg(unix)]
    #[test]
    fn delete_volume_refuses_a_volume_dir_that_is_a_symlink() {
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim.txt");
        std::fs::write(&victim, b"keep").unwrap();
        let volumes = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), volumes.path().join("vol-2")).unwrap();

        assert!(super::delete_volume("vol-2", volumes.path()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    /// The volumes directory holds every volume's database and slot vault: it is
    /// created 0700 whatever the umask, and an existing one is tightened to 0700.
    #[cfg(unix)]
    #[test]
    fn a_new_volume_creates_or_tightens_the_volumes_dir_to_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let t = tempfile::tempdir().unwrap();

        let fresh = t.path().join("fresh").join("volumes");
        let (_, paths) = new_volume_config(None, &fresh, 0, 0, 0, None).unwrap();
        assert_eq!(mode(&fresh), 0o700);
        assert!(paths.base_dir.is_dir());

        let existing = t.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        new_volume_config(None, &existing, 0, 0, 0, None).unwrap();
        assert_eq!(mode(&existing), 0o700);
    }

    /// Two writers of the same `volume.json` at once (a mount bumping the
    /// metadata version while `key rotate` or an enroll re-pins the vault). With
    /// one fixed temp name they truncate and write the SAME temp inode, so a torn
    /// file can be renamed into place and the loser's rename hits ENOENT. Every
    /// write must succeed, every observed file must parse, the final file must
    /// be 0600, and no temp file may be left behind.
    #[test]
    fn concurrent_config_writes_never_tear_or_fail() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let dir = tempfile::TempDir::new().unwrap();
        let path = Arc::new(dir.path().join("volume.json"));
        let base = VolumeConfig::new("race".into(), String::new());
        write_config_atomic(&base, &path).unwrap();

        let errors = Arc::new(AtomicUsize::new(0));
        let first_error = Arc::new(std::sync::Mutex::new(None::<String>));
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let (path, errors, first_error) =
                    (path.clone(), errors.clone(), first_error.clone());
                let mut cfg = base.clone();
                // Different lengths per thread, so a torn write is also a parse error.
                cfg.display_name = format!("writer-{t}-{}", "x".repeat(t * 97));
                std::thread::spawn(move || {
                    for i in 0..200u64 {
                        cfg.metadata_version = i;
                        let r = write_config_atomic(&cfg, &path)
                            .map_err(|e| e.to_string())
                            .and_then(|()| {
                                let raw = std::fs::read(&*path).map_err(|e| e.to_string())?;
                                serde_json::from_slice::<VolumeConfig>(&raw)
                                    .map(|_| ())
                                    .map_err(|e| format!("torn volume.json: {e}"))
                            });
                        if let Err(e) = r {
                            errors.fetch_add(1, Ordering::Relaxed);
                            first_error.lock().unwrap().get_or_insert(e);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            errors.load(Ordering::Relaxed),
            0,
            "concurrent config writes must never fail or tear; first error: {:?}",
            first_error.lock().unwrap()
        );
        let raw = std::fs::read(&*path).unwrap();
        serde_json::from_slice::<VolumeConfig>(&raw).expect("final volume.json parses");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&*path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "volume.json must be 0600");
        }
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| n != "volume.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[test]
    fn volume_lock_is_exclusive_then_released_on_drop() {
        let dir = tempfile::TempDir::new().unwrap();

        // First holder takes the lock.
        let lock = VolumeLock::acquire_exclusive(dir.path()).expect("first acquire succeeds");

        // A second concurrent acquirer is refused (single-writer) with a clear,
        // non-blocking error — this is the cross-process backstop that serializes
        // mount / revert / restore.
        let err = VolumeLock::acquire_exclusive(dir.path())
            .expect_err("second acquire while held must fail, not block");
        match err {
            CoreError::Volume(msg) => assert!(
                msg.contains("in use by another process"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected CoreError::Volume, got {other:?}"),
        }

        // Releasing the first holder frees the lock for the next writer.
        drop(lock);
        let _reacquired =
            VolumeLock::acquire_exclusive(dir.path()).expect("re-acquire after drop succeeds");
    }

    /// Shared holders coexist; a shared holder and an exclusive one exclude
    /// each other in both orders.
    #[test]
    fn shared_lock_excludes_exclusive_and_admits_shared() {
        let dir = tempfile::tempdir().unwrap();
        let a = VolumeLock::acquire_shared(dir.path()).expect("first shared");
        let b = VolumeLock::acquire_shared(dir.path()).expect("second shared coexists");
        let err = VolumeLock::acquire_exclusive(dir.path()).expect_err("exclusive under shared");
        assert!(
            err.to_string().contains("in use by another process"),
            "{err}"
        );
        drop((a, b));
        let w = VolumeLock::acquire_exclusive(dir.path()).expect("exclusive once free");
        let err = VolumeLock::acquire_shared(dir.path()).expect_err("shared under exclusive");
        assert!(
            err.to_string().contains("in use by another process"),
            "{err}"
        );
        drop(w);
        VolumeLock::acquire_shared(dir.path()).expect("shared once free");
    }

    /// RV8 (N4): `is_held` reports a writer, i.e. an exclusive holder. A
    /// shared holder (`volume history` / `volume diff`) is not a writer still
    /// flushing, so `volume unmount` does not wait for it; it still keeps a
    /// writer out, and two readers coexist.
    #[test]
    fn is_held_reports_a_writer_not_a_reader() {
        let dir = tempfile::tempdir().unwrap();
        let reader = VolumeLock::acquire_shared(dir.path()).unwrap();
        assert!(
            !VolumeLock::is_held(dir.path()).unwrap(),
            "a shared (history) holder reads as a writer"
        );
        assert!(
            VolumeLock::acquire_exclusive(dir.path()).is_err(),
            "a writer got in beside a reader"
        );
        drop(VolumeLock::acquire_shared(dir.path()).expect("a second reader"));
        drop(reader);
        let writer = VolumeLock::acquire_exclusive(dir.path()).unwrap();
        assert!(
            VolumeLock::is_held(dir.path()).unwrap(),
            "a writer reads as free"
        );
        drop(writer);
        assert!(!VolumeLock::is_held(dir.path()).unwrap());
    }

    /// Each of the four records alone makes a volume published; none of
    /// them, a volume that never published.
    #[test]
    fn has_published_counts_each_mac_covered_version_and_the_head() {
        let dir = tempfile::tempdir().unwrap();
        let created =
            create_volume(Some("p"), b"pass-has-published", dir.path(), 0, 0, 0, None).unwrap();
        let base = created.paths.base_dir.clone();
        let fresh = created.config.clone();
        assert!(!has_published(&fresh, &base));
        assert!(!has_published_snapshot(&fresh, &base));
        let mut c = fresh.clone();
        c.metadata_version = 1;
        assert!(has_published(&c, &base), "metadata_version");
        assert!(has_published_snapshot(&c, &base), "metadata_version");
        let mut c = fresh.clone();
        c.metadata_version_reserved = 1;
        assert!(has_published(&c, &base), "metadata_version_reserved");
        // Reserved only: a failed first publish left nothing to rebuild from.
        assert!(
            !has_published_snapshot(&c, &base),
            "metadata_version_reserved"
        );
        let mut c = fresh.clone();
        c.metadata_snapshot_id = Some(7);
        assert!(has_published(&c, &base), "metadata_snapshot_id");
        assert!(has_published_snapshot(&c, &base), "metadata_snapshot_id");
        std::fs::write(base.join(JOURNAL_HEAD_FILE), b"{}").unwrap();
        assert!(has_published(&fresh, &base), "journal.head");
        assert!(has_published_snapshot(&fresh, &base), "journal.head");
    }

    /// Durability regression: `volume unmount` waits for the writer (the mount
    /// process) to finish draining its in-flight uploads + release the lock before
    /// returning, by polling `VolumeLock::is_held`. If that probe ever reported a
    /// live writer as "free", unmount would return early and a kill/poweroff in
    /// that window would lose the not-yet-uploaded blocks (the silent 64 MiB -> 0
    /// data-loss bug). This pins the exact primitive the drain-wait relies on:
    /// free -> not held; a live writer -> held; released -> not held again.
    #[test]
    fn is_held_tracks_writer_lock_for_unmount_drain() {
        let dir = tempfile::TempDir::new().unwrap();

        // No writer yet — unmount on a never-mounted volume must not block.
        assert!(
            !VolumeLock::is_held(dir.path()).expect("probe a free lock"),
            "no holder must read as not-held"
        );

        // A writer is live and still flushing — the drain-wait must keep waiting.
        let writer = VolumeLock::acquire_exclusive(dir.path()).expect("writer acquires");
        assert!(
            VolumeLock::is_held(dir.path()).expect("probe a held lock"),
            "a live writer must read as held (drain not complete) — else unmount \
             returns mid-upload and data is lost"
        );

        // Writer drained and exited (released the lock) — drain-wait can proceed.
        drop(writer);
        assert!(
            !VolumeLock::is_held(dir.path()).expect("probe after release"),
            "after the writer releases the lock, the drain is complete and unmount \
             may safely return"
        );
    }

    #[test]
    fn create_and_open_volume() {
        let dir = tempfile::TempDir::new().unwrap();

        let created =
            create_volume(Some("test-vol"), b"password123", dir.path(), 0, 0, 0, None).unwrap();
        assert_eq!(created.config.display_name, "test-vol");
        assert!(created.paths.config_path.exists());

        // Open with correct password
        let opened = open_volume(
            &created.config.volume_id.to_string(),
            b"password123",
            dir.path(),
        )
        .unwrap();
        assert_eq!(opened.config.volume_id, created.config.volume_id);

        // Keys should match
        assert_eq!(
            opened.hierarchy.data.as_bytes(),
            created.hierarchy.data.as_bytes()
        );
    }

    #[test]
    fn shared_root_reconstructs_the_owners_hierarchy() {
        // The recipient side of sharing: given only the owner's hierarchy root
        // (what gets ML-KEM-wrapped) plus the non-secret config on disk, a volume
        // opens with the identical key hierarchy — no password anywhere.
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(
            Some("shared"),
            b"owner-password",
            dir.path(),
            42,
            -7,
            999,
            None,
        )
        .unwrap();
        let volume_id = created.config.volume_id.to_string();
        let root: [u8; 32] = *created.hierarchy.root.as_bytes();

        let opened = open_volume_shared(
            &volume_id,
            &root,
            SharedDerivation::HierarchyRootV1,
            dir.path(),
        )
        .unwrap();

        // Every tier must match the owner's, or a recipient could not read/write.
        assert_eq!(
            opened.hierarchy.data.as_bytes(),
            created.hierarchy.data.as_bytes()
        );
        assert_eq!(
            opened.hierarchy.meta.as_bytes(),
            created.hierarchy.meta.as_bytes()
        );
        assert_eq!(
            opened.hierarchy.schema.as_bytes(),
            created.hierarchy.schema.as_bytes()
        );
        assert_eq!(
            opened.hierarchy.integrity.as_bytes(),
            created.hierarchy.integrity.as_bytes()
        );
        assert_eq!(opened.config.volume_id, created.config.volume_id);
    }

    #[test]
    fn shared_open_rejects_a_wrong_root() {
        // A wrong grant / wrong recipient key / corrupted transfer yields a
        // different hierarchy, which the verification-hash self-check must catch.
        let dir = tempfile::TempDir::new().unwrap();
        let created =
            create_volume(Some("shared"), b"owner-password", dir.path(), 1, 2, 3, None).unwrap();
        let volume_id = created.config.volume_id.to_string();

        let mut wrong = *created.hierarchy.root.as_bytes();
        wrong[0] ^= 0x01;
        let result = open_volume_shared(
            &volume_id,
            &wrong,
            SharedDerivation::HierarchyRootV1,
            dir.path(),
        );
        assert!(result.is_err(), "a wrong root must be refused, not opened");
    }

    #[test]
    fn create_and_open_v1_channel_bound() {
        let dir = tempfile::TempDir::new().unwrap();

        // Simulate creating the shared forum group + this volume's topic first.
        let channel_id: i64 = 1234567890;
        let channel_hash: i64 = -9876543210;
        let topic_id: i64 = 777;

        let created = create_volume(
            Some("v1-vol"),
            b"password123",
            dir.path(),
            channel_id,
            channel_hash,
            topic_id,
            None,
        )
        .unwrap();
        assert_eq!(created.config.volume_version, 1);
        assert_eq!(created.config.telegram_group_id, channel_id);
        assert_eq!(created.config.telegram_topic_id, topic_id);

        let opened = open_volume(
            &created.config.volume_id.to_string(),
            b"password123",
            dir.path(),
        )
        .unwrap();
        assert_eq!(
            opened.hierarchy.data.as_bytes(),
            created.hierarchy.data.as_bytes()
        );
    }

    #[test]
    fn different_topics_in_same_group_give_distinct_keys() {
        let dir = tempfile::TempDir::new().unwrap();
        let group = 99999_i64;
        // Same shared group, different topics → distinct key hierarchies (the
        // per-volume anti-substitution property).
        let a =
            create_volume(Some("a"), b"same-password", dir.path(), group, 0, 100, None).unwrap();
        let b =
            create_volume(Some("b"), b"same-password", dir.path(), group, 0, 200, None).unwrap();
        assert_ne!(a.hierarchy.data.as_bytes(), b.hierarchy.data.as_bytes());
    }

    #[test]
    fn wrong_password_returns_error() {
        let dir = tempfile::TempDir::new().unwrap();

        let created = create_volume(Some("test"), b"correct", dir.path(), 0, 0, 0, None).unwrap();
        let result = open_volume(&created.config.volume_id.to_string(), b"wrong", dir.path());

        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("wrong password"),
            "expected wrong password error, got: {msg}"
        );
    }

    #[test]
    fn password_open_rejects_stripped_integrity_hmac() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("test"), b"correct", dir.path(), 0, 0, 0, None).unwrap();
        let volume_id = created.config.volume_id.to_string();
        let mut stripped = created.config;
        stripped.config_integrity = None;
        write_config_atomic(&stripped, &created.paths.config_path).unwrap();

        let error = open_volume(&volume_id, b"correct", dir.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing its config integrity HMAC"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn password_open_rejects_stripped_verification_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("test"), b"correct", dir.path(), 0, 0, 0, None).unwrap();
        let volume_id = created.config.volume_id.to_string();
        let mut stripped = created.config;
        stripped.password_verification_hash = None;
        write_config_atomic(&stripped, &created.paths.config_path).unwrap();

        let error = open_volume(&volume_id, b"correct", dir.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing its password verification hash"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn shared_open_rejects_stripped_integrity_hmac() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("shared"), b"owner", dir.path(), 1, 2, 3, None).unwrap();
        let volume_id = created.config.volume_id.to_string();
        let root = *created.hierarchy.root.as_bytes();
        let mut stripped = created.config;
        stripped.config_integrity = None;
        write_config_atomic(&stripped, &created.paths.config_path).unwrap();

        let error = open_volume_shared(
            &volume_id,
            &root,
            SharedDerivation::HierarchyRootV1,
            dir.path(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing its config integrity HMAC"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn shared_open_rejects_stripped_verification_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("shared"), b"owner", dir.path(), 1, 2, 3, None).unwrap();
        let volume_id = created.config.volume_id.to_string();
        let root = *created.hierarchy.root.as_bytes();
        let mut stripped = created.config;
        stripped.password_verification_hash = None;
        write_config_atomic(&stripped, &created.paths.config_path).unwrap();

        let error = open_volume_shared(
            &volume_id,
            &root,
            SharedDerivation::HierarchyRootV1,
            dir.path(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("missing its verification hash"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn list_volumes() {
        let dir = tempfile::TempDir::new().unwrap();

        create_volume(Some("vol1"), b"pw1", dir.path(), 0, 0, 0, None).unwrap();
        create_volume(Some("vol2"), b"pw2", dir.path(), 0, 0, 0, None).unwrap();

        let volumes = super::list_volumes(dir.path()).unwrap();
        assert_eq!(volumes.len(), 2);
    }

    #[test]
    fn delete_volume() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("temp"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        let vol_id = created.config.volume_id.to_string();

        assert!(dir.path().join(&vol_id).exists());
        super::delete_volume(&vol_id, dir.path()).unwrap();
        assert!(!dir.path().join(&vol_id).exists());
    }

    #[test]
    fn overwrite_is_in_place_once_and_keeps_the_length() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("f");
        // Larger than one 64 KiB chunk, and not a multiple of it.
        let original: Vec<u8> = (0..200_003u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &original).unwrap();
        // A second name for the same inode sees whatever is written to it.
        let link = dir.path().join("link");
        std::fs::hard_link(&p, &link).unwrap();
        let ino_before = std::fs::metadata(&p).unwrap().ino();

        super::overwrite_file_in_place(&p).unwrap();

        let after = std::fs::read(&link).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().ino(), ino_before);
        assert_eq!(after.len(), original.len(), "length must be unchanged");
        let same = after.iter().zip(&original).filter(|(a, b)| a == b).count();
        // Random bytes match a fixed byte with p = 1/256; allow a wide margin.
        assert!(same < original.len() / 100, "{same} bytes unchanged");

        super::overwrite_and_remove_file(&p).unwrap();
        assert!(!p.exists());
        assert!(link.exists(), "only the given name is removed");
    }

    #[test]
    fn delete_volume_overwrites_and_removes_nested_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("nested"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        let vol = dir.path().join(created.config.volume_id.to_string());
        std::fs::create_dir_all(vol.join("cache/ab")).unwrap();
        std::fs::write(vol.join("cache/ab/block"), vec![7u8; 5000]).unwrap();
        std::fs::write(vol.join("empty"), b"").unwrap();
        // Hard links outside the volume observe what happened to the bytes.
        let witness = dir.path().join("witness");
        std::fs::hard_link(vol.join("cache/ab/block"), &witness).unwrap();

        super::delete_volume(&created.config.volume_id.to_string(), dir.path()).unwrap();

        assert!(!vol.exists());
        let w = std::fs::read(&witness).unwrap();
        assert_eq!(w.len(), 5000);
        assert!(w.iter().filter(|&&b| b == 7).count() < 100);
    }

    #[test]
    fn open_nonexistent() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = open_volume("nonexistent", b"pw", dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn auto_generated_name() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(None, b"pw", dir.path(), 0, 0, 0, None).unwrap();
        assert!(!created.config.display_name.is_empty());
    }

    // ── core-L1: hostile kdf_params reach the KDF before authentication ──────

    #[test]
    fn open_with_hostile_kdf_output_len_is_an_error_not_a_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("kdf"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        let id = created.config.volume_id.to_string();
        let mut evil = created.config;
        evil.kdf_params.output_len = 16;
        write_config_atomic(&evil, &created.paths.config_path).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            open_volume(&id, b"pw", dir.path()).is_err()
        }));
        assert_eq!(
            r.ok(),
            Some(true),
            "must be Err, not a panic and not an open"
        );
    }

    // ── core-M6: the lockout file must fail closed and be written atomically ──

    #[test]
    fn corrupt_lockout_file_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("lk"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        let id = created.config.volume_id.to_string();
        let lockout = created.paths.base_dir.join("auth_lockout.json");
        std::fs::write(&lockout, b"{ \"failure_count\": 9, \"locked_unt").unwrap();
        let r = open_volume(&id, b"pw", dir.path());
        assert!(
            r.is_err(),
            "a corrupt lockout file must not be read as 'unlocked'"
        );
        let msg = format!("{}", r.unwrap_err());
        assert!(
            msg.contains("auth_lockout.json"),
            "error must name the file: {msg}"
        );
    }

    #[test]
    fn unreadable_lockout_file_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("lk"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        let id = created.config.volume_id.to_string();
        // A directory at the path is unreadable as a file for every uid, root
        // included (chmod 000 is not, under root).
        std::fs::create_dir(created.paths.base_dir.join("auth_lockout.json")).unwrap();
        assert!(
            open_volume(&id, b"pw", dir.path()).is_err(),
            "an unreadable lockout file must not be read as 'unlocked'"
        );
    }

    #[test]
    fn missing_lockout_file_is_a_fresh_state() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("lk"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        let id = created.config.volume_id.to_string();
        assert!(!created.paths.base_dir.join("auth_lockout.json").exists());
        open_volume(&id, b"pw", dir.path()).expect("no lockout file = never failed");
    }

    #[cfg(unix)]
    #[test]
    fn lockout_save_is_atomic() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("lk"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        let id = created.config.volume_id.to_string();
        let lockout = created.paths.base_dir.join("auth_lockout.json");

        assert!(open_volume(&id, b"wrong", dir.path()).is_err());
        let first = std::fs::read(&lockout).expect("first failure is persisted");

        // A hardlink to the current inode: an in-place rewrite (fs::write) is
        // visible through it; temp + rename replaces the inode and leaves it alone.
        let link = created.paths.base_dir.join("lockout.hardlink");
        std::fs::hard_link(&lockout, &link).unwrap();

        // Wait out the 1 s lockout, then fail again.
        std::thread::sleep(std::time::Duration::from_millis(2100));
        assert!(open_volume(&id, b"wrong", dir.path()).is_err());

        let second = std::fs::read(&lockout).unwrap();
        assert_ne!(first, second, "the second failure must be recorded");
        assert_eq!(
            std::fs::read(&link).unwrap(),
            first,
            "the old inode was rewritten in place — the save is not temp + rename"
        );
    }

    #[cfg(unix)]
    #[test]
    fn lockout_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("lk"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        let id = created.config.volume_id.to_string();
        let lockout = created.paths.base_dir.join("auth_lockout.json");
        assert!(open_volume(&id, b"wrong", dir.path()).is_err());
        let mode = std::fs::metadata(&lockout).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "lockout state must be 0600");
    }

    // ── mfa-H1: the verifier mutators use agrees with the open paths ──────────

    #[test]
    fn verify_config_anchors_accepts_authentic_and_rejects_tampered_configs() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("va"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        verify_config_anchors(&created.config, &created.hierarchy).expect("authentic");

        let mut downgraded = created.config.clone();
        downgraded.require_block_integrity = false;
        assert!(verify_config_anchors(&downgraded, &created.hierarchy).is_err());

        let mut stripped = created.config.clone();
        stripped.config_integrity = None;
        assert!(verify_config_anchors(&stripped, &created.hierarchy).is_err());

        let mut no_hash = created.config.clone();
        no_hash.password_verification_hash = None;
        assert!(verify_config_anchors(&no_hash, &created.hierarchy).is_err());

        let other = create_volume(Some("vb"), b"pw", dir.path(), 0, 0, 0, None).unwrap();
        assert!(
            verify_config_anchors(&created.config, &other.hierarchy).is_err(),
            "a different volume's keys must not authenticate this config"
        );
    }

    // ── sharing-M1 investigation: what a grant's plaintext config reveals ─────

    /// A grant ships the owner's `VolumeConfig`. For a password-rooted volume,
    /// stripping only `password_verification_hash` does NOT remove the offline
    /// password-guessing oracle: `config_integrity` is keyed by the same
    /// password-derived hierarchy, so it confirms a guess exactly as well. This
    /// test pins that, so nobody "fixes" the leak by deleting one field.
    #[test]
    fn config_integrity_alone_is_a_password_oracle() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = create_volume(Some("oracle"), b"hunter2", dir.path(), 7, 0, 9, None).unwrap();
        let mut seen = created.config.clone();
        seen.password_verification_hash = None; // the proposed strip
        let shipped_hmac = created.config.config_integrity.clone().unwrap();

        let confirm = |guess: &[u8]| {
            let root = kdf::derive_root_key(guess, &seen.salt, &seen.kdf_params).unwrap();
            let h = kdf::derive_hierarchy_v1(
                root,
                &seen.salt,
                seen.telegram_group_id,
                seen.telegram_topic_id,
            )
            .unwrap();
            // The HMAC input includes the hash, which the guesser recomputes too.
            let mut c = seen.clone();
            c.password_verification_hash = Some(compute_verification_hash(&h));
            compute_config_integrity(&c, &h) == shipped_hmac
        };
        assert!(!confirm(b"wrong-guess"));
        assert!(
            confirm(b"hunter2"),
            "the HMAC alone confirms the right password"
        );
    }
}
