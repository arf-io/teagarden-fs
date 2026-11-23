use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::block::compress::CompressionAlgorithm;
use crate::crypto::keys::Argon2Params;
use crate::error::CoreError;

/// Volume configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeConfig {
    /// Unique volume identifier
    pub volume_id: Uuid,
    /// Human-readable volume name
    pub display_name: String,
    /// Random Telegram volume codename (8-char alphanumeric) used as the forum
    /// topic title.
    pub group_name: String,
    /// ID of the shared TeaGarden supergroup forum that stores all volumes. The
    /// same value for every volume of a given TeaGarden identity.
    pub telegram_group_id: i64,
    /// Access hash of the shared forum group (session-scoped; re-resolved at mount).
    #[serde(default)]
    pub telegram_channel_access_hash: i64,
    /// This volume's forum topic id (the topic's root message id) within the shared
    /// group. Unique per volume; mixed into the key hierarchy alongside the group id.
    #[serde(default)]
    pub telegram_topic_id: i64,
    /// Message ID of the latest metadata snapshot in the channel (for disaster recovery)
    #[serde(default)]
    pub metadata_snapshot_id: Option<i64>,
    /// Current encryption epoch
    pub current_epoch: u32,
    /// HKDF salt (32 bytes, generated once)
    pub salt: [u8; 32],
    /// KDF parameters
    pub kdf_params: Argon2Params,
    /// Block size configuration
    pub block_config: BlockConfig,
    /// Default mutability policy ID
    pub default_policy_id: u32,
    /// Cache configuration
    pub cache_config: CacheConfig,
    /// Creation timestamp (seconds since epoch)
    pub created_at: i64,
    /// BLAKE3 hash of a derived verification key, for password checking.
    /// Hex-encoded. Populated on create; verified on open.
    #[serde(default)]
    pub password_verification_hash: Option<String>,

    /// BLAKE3-keyed HMAC over the canonical config JSON (this field excluded),
    /// using `hierarchy.integrity` as the key. Detects tampering with KDF
    /// parameters (e.g. Argon2id memory/iteration downgrade attacks).
    /// Hex-encoded. Populated on create; verified on open.
    #[serde(default)]
    pub config_integrity: Option<String>,

    /// Volume format version.
    ///
    /// 0 (default): legacy — key hierarchy derived from salt only.
    /// 1: channel-bound — Telegram channel created before key derivation;
    ///    channel_id is mixed into the HKDF salt so keys are unique per channel.
    #[serde(default)]
    pub volume_version: u32,

    /// Require per-block integrity (T7 fail-closed). When `true`, a block whose
    /// store record is missing or whose SRB2 hashes are zero is refused at read
    /// time rather than served unverified, closing the block-substitution gap on
    /// an untrusted transport. Enabled by default on volumes created at v0.3.0+;
    /// legacy SRB1 volumes leave it `false` so they remain readable.
    ///
    /// `skip_serializing_if` keeps it absent from the JSON when `false`, so
    /// existing volumes' `config_integrity` HMAC (computed over the serialized
    /// config) still verifies byte-for-byte. When `true` it is serialized and
    /// therefore covered by the HMAC — it cannot be flipped to `false` without
    /// invalidating the config.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_block_integrity: bool,

    /// Block-v2 AAD epoch threshold (T7 part 2). A block whose epoch is `>=` this
    /// value is sealed/verified with the block-v2 AAD (`"block-v2" || epoch ||
    /// block_id`), which binds the ciphertext to its content identity at the
    /// cipher layer. `None` (legacy / absent) means all blocks are block-v1.
    /// `Some(0)` on volumes created at v0.4.1+ makes every block block-v2.
    ///
    /// WRITE-ONCE: must only ever be set to a value strictly greater than every
    /// existing block's epoch (see `crate::block::aad`). `skip_serializing_if`
    /// keeps it absent when `None` so existing volumes' `config_integrity` HMAC
    /// is byte-for-byte unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_v2_from_epoch: Option<u32>,

    /// Monotonic metadata-snapshot version (anti-rollback). Incremented each time
    /// a metadata snapshot is published to the channel and embedded in that
    /// snapshot. On restore, a snapshot whose embedded version is older than this
    /// value is refused, so a transport-level attacker cannot roll the volume back
    /// by serving a stale snapshot. HMAC-covered (so it cannot be lowered by
    /// tampering the local config) and `skip_serializing_if = 0` for byte-exact
    /// compatibility with pre-existing configs that never had the field.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub metadata_version: u64,

    /// Hex BLAKE3 of the exact snapshot blob `metadata_snapshot_id` names (the
    /// one published at `metadata_version`). Unlike the message id it is covered
    /// by `config_integrity`, so a restore of the recorded version can check it
    /// was served exactly that snapshot and not another one with the same version
    /// (an orphan from a publish whose acknowledgement was lost). Absent in
    /// configs written before the field existed (then nothing is checked), and
    /// `skip_serializing_if = None` keeps those configs' HMAC byte-exact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_snapshot_hash: Option<String>,

    /// Highest snapshot version ever handed to a publish attempt. Saved BEFORE the
    /// upload, so a publish that Telegram stored but never acknowledged still uses
    /// up its version, and the retry gets a new one: no two different snapshots
    /// share a version. Only picks the next version; the restore floor remains
    /// `metadata_version`. `0` (absent) in older configs.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub metadata_version_reserved: u64,

    /// Multi-factor key protection (K0b). `None` = legacy **password-rooted**
    /// volume: the key hierarchy derives from `Argon2id(password)` and the volume
    /// opens with the password alone. `Some` = this volume is **MK-rooted** behind
    /// a [`crate`]-external slot vault (`mfa_vault.json`): the hierarchy derives
    /// from the vault's *random* master key, so reconstructing the data keys
    /// genuinely requires unlocking a factor — it is real protection, not a
    /// bypassable prompt. Its mere presence flips `open_volume` to fail **closed**
    /// (a bare password cannot open it; unlock via the vault).
    ///
    /// The `(vault_generation, vault_digest)` anchor is re-pinned into
    /// `config_integrity` on every slot mutation, so reverting `mfa_vault.json`
    /// alone to re-enable a removed slot is refused (anti-rollback, closes the
    /// vault-only case of K0A-1). `skip_serializing_if = None` keeps legacy
    /// configs byte-exact so their existing HMAC still verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_protection: Option<KeyProtection>,

    /// Greatest TGHD revision reserved before an upload attempt.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sdo_header_revision_reserved: u64,

    /// Greatest TGHD revision whose upload was acknowledged.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sdo_header_revision_published: u64,

    /// True while a reserved header revision still needs publication or repair.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sdo_header_pending: bool,

    /// SHA-256 of the exact reserved header bytes, for identical retry enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdo_header_pending_sha256: Option<String>,

    /// Base64-encoded exact reserved header bytes, retained so a lost upload
    /// acknowledgement can retry the identical signed revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdo_header_pending_bytes: Option<String>,

    /// Stable random local author identity used in encrypted file-version objects.
    /// It is deliberately omitted from Telegram headers and never derived from
    /// Telegram account identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdo_author_device_id: Option<Uuid>,

    /// Owner key TOFU pin captured on attach for signed TGHD2 headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdo_owner_public_key: Option<String>,

    /// Greatest authenticated remote HLC observed during attach.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sdo_initial_clock_ms: u64,

    /// Counter paired with `sdo_initial_clock_ms`.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sdo_initial_clock_counter: u64,
}

/// Anchor binding a volume to its multi-factor slot vault (K0b). Stored in
/// [`VolumeConfig::key_protection`] and therefore covered by `config_integrity`,
/// so an attacker cannot forge or roll it back without the master key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyProtection {
    /// `SlotVault::generation()` at the last reseal — monotonic; a loaded vault
    /// with a lower generation is a rollback and is refused at open.
    pub vault_generation: u64,
    /// Hex-encoded `SlotVault::state_digest()` — the authenticated snapshot of the
    /// vault's opening state (slots, commitments, policy). A substituted or stale
    /// vault whose digest differs from this anchor is refused at open.
    pub vault_digest: String,
}

/// Serde helper: skip serializing a `u64` field when it is `0`.
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Serde helper: skip serializing a `bool` field when it is `false`.
fn is_false(b: &bool) -> bool {
    !*b
}

/// Block size configuration for CDC and storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockConfig {
    /// Minimum block size (default: 4 KB)
    pub min_block_size: u64,
    /// Maximum block size (default: 50 MB)
    pub max_block_size: u64,
    /// Target average block size for CDC (default: 1 MB)
    pub target_block_size: u64,
    /// Compression algorithm
    pub compression: CompressionAlgorithm,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            min_block_size: 4 * 1024,
            max_block_size: 50 * 1024 * 1024,
            // 45 MiB: each block is exactly one Telegram document, and a single
            // document can never be split across bots (parts are bound to one
            // auth_key), so the only multi-bot speedup is splitting a file into many
            // independent blocks round-robined across the pool. We therefore make a
            // block as large as the *cloud Bot API document ceiling* safely allows:
            // a file ≤ this size is one message (beats the per-message rate limit),
            // while a larger file fans out across all 5 bots in parallel. The cap is
            // the binding cloud-bot limit (see `fuse_chunk_size`), not 2 GiB, because
            // a >50 MB block cannot go through a cloud bot at all. Per-upload memory
            // stays bounded — the FUSE pool keeps at most 4 blocks in flight.
            target_block_size: 45 * 1024 * 1024,
            compression: CompressionAlgorithm::Lz4,
        }
    }
}

impl BlockConfig {
    /// Plaintext chunk size the FUSE write path splits files into: the configured
    /// `target_block_size` clamped to a Telegram-safe range and rounded down to a
    /// 512-byte multiple (the upload part unit).
    ///
    /// The binding ceiling is the **cloud Bot API document limit**, not
    /// `max_block_size`: a block's ciphertext is one `sendDocument`, and a single
    /// document cannot be split across bots, so it must fit one bot's upload. The
    /// Bot API documents this as "50 MB"; we treat it conservatively as the decimal
    /// 50_000_000 bytes and reserve ~2 MB for SRB2/AEAD per-block overhead (~90 B)
    /// plus slack, so a block's ciphertext always uploads through the 5-bot pool and
    /// never trips `BlockTooLarge`. (A local Bot API server / user-session-only
    /// setup could raise this, but the default pool is cloud bots.)
    pub fn fuse_chunk_size(&self) -> usize {
        const FLOOR: u64 = 512 * 1024; // 512 KiB
                                       // Largest plaintext whose ciphertext stays under the conservative decimal
                                       // 50 MB cloud-bot document cap (≈45.8 MiB → ciphertext ≈ 48 MB).
        const CLOUD_BOT_CEILING: u64 = 48_000_000;
        let ceiling = self.max_block_size.clamp(FLOOR, CLOUD_BOT_CEILING);
        let size = self.target_block_size.clamp(FLOOR, ceiling) & !511;
        size as usize
    }
}

/// Local cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable block cache
    pub enabled: bool,
    /// Maximum cache size in bytes (default: 1 GB)
    pub max_size: u64,
    /// Enable metadata cache
    pub metadata_cache: bool,
    /// Prefetch depth (0 = disabled)
    pub prefetch_depth: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: 1024 * 1024 * 1024,
            metadata_cache: true,
            prefetch_depth: 4,
        }
    }
}

impl VolumeConfig {
    /// The version the next snapshot publish must use: above both the restore
    /// floor and every version an earlier attempt may already have uploaded.
    pub fn next_snapshot_version(&self) -> u64 {
        self.metadata_version
            .max(self.metadata_version_reserved)
            .saturating_add(1)
    }

    /// [`Self::metadata_snapshot_hash`] decoded; `None` if absent or malformed.
    pub fn recorded_snapshot_hash(&self) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(self.metadata_snapshot_hash.as_deref()?, &mut out).ok()?;
        Some(out)
    }

    /// Increment the epoch counter and return the new epoch value.
    /// Returns `Err(CoreError::EpochOverflow)` if the counter would wrap past `u32::MAX`.
    pub fn increment_epoch(&mut self) -> Result<u32, CoreError> {
        self.current_epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or(CoreError::EpochOverflow)?;
        Ok(self.current_epoch)
    }

    /// Create a new volume configuration with sensible defaults.
    pub fn new(display_name: String, group_name: String) -> Self {
        let mut salt = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);

        Self {
            volume_id: Uuid::new_v4(),
            display_name,
            group_name,
            telegram_group_id: 0,
            telegram_channel_access_hash: 0,
            telegram_topic_id: 0,
            metadata_snapshot_id: None,
            current_epoch: 0,
            salt,
            kdf_params: Argon2Params::default(),
            block_config: BlockConfig::default(),
            default_policy_id: 0,
            cache_config: CacheConfig::default(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            password_verification_hash: None,
            config_integrity: None,
            volume_version: 0,
            // New volumes enforce per-block integrity (T7 fail-closed). Every
            // block written through the FUSE path records its SRB2 hashes, so a
            // fresh volume is always readable under this flag.
            require_block_integrity: true,
            // New volumes seal every block with the block-v2 AAD from epoch 0
            // (T7 part 2: substitution rejected at the cipher layer). Set before
            // any block exists, so the write-once threshold invariant holds.
            block_v2_from_epoch: Some(0),
            // No metadata snapshot published yet.
            metadata_version: 0,
            metadata_snapshot_hash: None,
            metadata_version_reserved: 0,
            // Legacy password-rooted by default; set to Some only by the MK-rooted
            // create path (`create_volume_mk_rooted`) / a future rekey (K0c).
            key_protection: None,
            sdo_header_revision_reserved: 0,
            sdo_header_revision_published: 0,
            sdo_header_pending: false,
            sdo_header_pending_sha256: None,
            sdo_header_pending_bytes: None,
            sdo_author_device_id: Some(Uuid::new_v4()),
            sdo_owner_public_key: None,
            sdo_initial_clock_ms: 0,
            sdo_initial_clock_counter: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_volume_has_unique_id() {
        let v1 = VolumeConfig::new("vol1".into(), "noun verb adj".into());
        let v2 = VolumeConfig::new("vol2".into(), "noun verb adj".into());
        assert_ne!(v1.volume_id, v2.volume_id);
    }

    #[test]
    fn new_volume_enables_block_integrity() {
        let v = VolumeConfig::new("v".into(), "a b c".into());
        assert!(v.require_block_integrity, "new volumes are fail-closed");
    }

    #[test]
    fn new_volume_enables_block_v2() {
        let v = VolumeConfig::new("v".into(), "a b c".into());
        assert_eq!(v.block_v2_from_epoch, Some(0), "new volumes seal block-v2");
    }

    #[test]
    fn block_v2_from_epoch_none_is_omitted_for_hmac_compat() {
        // Same migration guarantee as require_block_integrity: when None the
        // field is absent from JSON, so a legacy volume's config_integrity HMAC
        // is byte-for-byte unchanged; when Some it is serialized (HMAC-covered).
        let mut c = VolumeConfig::new("v".into(), "a b c".into());
        c.block_v2_from_epoch = None;
        let json_none = serde_json::to_string(&c).unwrap();
        assert!(
            !json_none.contains("block_v2_from_epoch"),
            "None must be omitted: {json_none}"
        );
        c.block_v2_from_epoch = Some(0);
        assert!(serde_json::to_string(&c)
            .unwrap()
            .contains("block_v2_from_epoch"));
    }

    #[test]
    fn metadata_version_zero_is_omitted_for_hmac_compat() {
        // Same migration guarantee as the block-integrity fields: when 0 the field
        // must be ABSENT from the JSON so a pre-existing config's config_integrity
        // HMAC verifies byte-for-byte; when non-zero it is serialized (HMAC-covered),
        // so an attacker cannot lower it without invalidating the config.
        let mut c = VolumeConfig::new("v".into(), "a b c".into());

        c.metadata_version = 0;
        let json_zero = serde_json::to_string(&c).unwrap();
        assert!(
            !json_zero.contains("metadata_version"),
            "0 must be omitted for HMAC compat: {json_zero}"
        );

        c.metadata_version = 7;
        let json_set = serde_json::to_string(&c).unwrap();
        assert!(json_set.contains("metadata_version"));

        // An old-shape config (field absent) round-trips to identical bytes.
        let reparsed: VolumeConfig = serde_json::from_str(&json_zero).unwrap();
        assert_eq!(reparsed.metadata_version, 0);
        assert_eq!(serde_json::to_string(&reparsed).unwrap(), json_zero);
    }

    #[test]
    fn require_block_integrity_false_is_omitted_for_hmac_compat() {
        // CRITICAL migration guarantee: when false, the field must be ABSENT from
        // the serialized JSON, so an existing volume's config_integrity HMAC
        // (computed over the serialized config before this field existed) still
        // verifies byte-for-byte. When true it must be present (so the HMAC
        // covers it and it cannot be silently flipped off).
        let mut c = VolumeConfig::new("v".into(), "a b c".into());

        c.require_block_integrity = false;
        let json_false = serde_json::to_string(&c).unwrap();
        assert!(
            !json_false.contains("require_block_integrity"),
            "false must be omitted from JSON for HMAC compat: {json_false}"
        );

        c.require_block_integrity = true;
        let json_true = serde_json::to_string(&c).unwrap();
        assert!(json_true.contains("require_block_integrity"));

        // An old-shape config (field absent) deserializes to false and, crucially,
        // re-serializes to the identical bytes — so its HMAC is unchanged.
        let reparsed: VolumeConfig = serde_json::from_str(&json_false).unwrap();
        assert!(!reparsed.require_block_integrity);
        assert_eq!(serde_json::to_string(&reparsed).unwrap(), json_false);
    }

    #[test]
    fn new_volume_has_random_salt() {
        let v1 = VolumeConfig::new("vol1".into(), "a b c".into());
        let v2 = VolumeConfig::new("vol2".into(), "d e f".into());
        assert_ne!(v1.salt, v2.salt);
    }

    #[test]
    fn default_block_config() {
        let bc = BlockConfig::default();
        assert_eq!(bc.min_block_size, 4096);
        assert_eq!(bc.max_block_size, 50 * 1024 * 1024);
        assert_eq!(bc.target_block_size, 45 * 1024 * 1024);
    }

    #[test]
    fn fuse_chunk_size_clamps_and_aligns() {
        // Default: target 45 MiB sits inside [512 KiB, cloud-bot ceiling] and is aligned.
        assert_eq!(BlockConfig::default().fuse_chunk_size(), 45 * 1024 * 1024);
        // Below the floor clamps up to 512 KiB.
        let small = BlockConfig {
            target_block_size: 4096,
            ..Default::default()
        };
        assert_eq!(small.fuse_chunk_size(), 512 * 1024);
        // Above the cloud-bot ceiling clamps down to it (never exceeds a single
        // bot's 50 MB document limit). 48_000_000 is already 512-aligned.
        let big = BlockConfig {
            target_block_size: 100 * 1024 * 1024,
            ..Default::default()
        };
        assert_eq!(big.fuse_chunk_size(), 48_000_000);
        assert!(big.fuse_chunk_size() as u64 <= 48_000_000);
        // Non-512-aligned target rounds down.
        let odd = BlockConfig {
            target_block_size: 1024 * 1024 + 300,
            ..Default::default()
        };
        assert_eq!(odd.fuse_chunk_size() % 512, 0);
    }

    #[test]
    fn increment_epoch() {
        let mut v = VolumeConfig::new("test".into(), "a b c".into());
        assert_eq!(v.current_epoch, 0);
        assert_eq!(v.increment_epoch().unwrap(), 1);
        assert_eq!(v.current_epoch, 1);
        assert_eq!(v.increment_epoch().unwrap(), 2);
        assert_eq!(v.current_epoch, 2);
    }

    #[test]
    fn increment_epoch_overflow() {
        let mut v = VolumeConfig::new("test".into(), "a b c".into());
        v.current_epoch = u32::MAX;
        let err = v.increment_epoch().unwrap_err();
        assert!(matches!(err, crate::error::CoreError::EpochOverflow));
    }
}
