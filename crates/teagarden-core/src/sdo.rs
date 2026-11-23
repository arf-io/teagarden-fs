//! Portable self-describing Telegram objects (TGHD and TGFV).
//!
//! Byte codecs over supplied buffers/readers; no files or network connections are opened.

/// Bounded-memory TGFV3 encoding over an existing plaintext reader.
pub mod streaming;

use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
/// Installation signing capability used by portable writers.
pub use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::crypto::{
    aead, blake3,
    keys::{Argon2Params, SymmetricKey},
};
use crate::error::{CoreError, Result};

/// Maximum encoded TGHD document size (including framing and MAC).
pub const MAX_HEADER_SIZE: usize = 4 * 1024 * 1024;
/// Maximum encoded TGFV object size.
pub const MAX_MANIFEST_SIZE: usize = 128 * 1024 * 1024;
/// Maximum number of block references in one file version.
pub const MAX_BLOCK_REFS: usize = 131_072;
const HEADER_MAC_CONTEXT: &[u8] = b"teagarden.sdo.header.v1";
const MANIFEST_AAD_CONTEXT: &[u8] = b"teagarden.sdo.file.v1";
const SEGMENT_AAD_CONTEXT: &[u8] = b"teagarden.sdo.segment.v2";
/// Fixed plaintext segment size for TGFV v2 (1 MiB).
pub const SDO_SEGMENT_SIZE: u32 = 1024 * 1024;
/// Bound on a newly encoded TGFV3 prefix and encrypted metadata, including nonce/tag.
pub const MAX_TGFV3_HEADER_BYTES: u64 = 64 * 1024;
/// Maximum credential-envelope JSON plus its MAC, length and TGFE marker.
pub const MAX_TGFE_BYTES: u64 = MAX_HEADER_SIZE as u64 + 40;
const DOCUMENT_CAPS: [u64; 2] = [2_000 * 1024 * 1024, 4_000 * 1024 * 1024];

/// Worst-case complete wire size, reserving all supported v3/TGFE framing.
pub const fn sdo_v3_upload_bound(plaintext: u64) -> Option<u64> {
    let segments = plaintext.div_ceil(SDO_SEGMENT_SIZE as u64);
    match plaintext.checked_add(segments * 16) {
        Some(n) => n.checked_add(MAX_TGFV3_HEADER_BYTES + MAX_TGFE_BYTES),
        None => None,
    }
}

const fn supported_plaintext_max(cap: u64) -> u64 {
    let (mut low, mut high) = (0, cap);
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if matches!(sdo_v3_upload_bound(mid), Some(n) if n <= cap) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
}

/// Authoritative supported plaintext maxima: [ordinary account, Premium].
/// Reserve the maximum metadata/envelope and every segment's authentication tag.
pub const SDO_PLAINTEXT_MAX_BYTES: [u64; 2] = [
    supported_plaintext_max(DOCUMENT_CAPS[0]),
    supported_plaintext_max(DOCUMENT_CAPS[1]),
];
/// Supported plaintext bytes per ordinary-account save.
pub const MAX_SDO_FILE_BYTES: u64 = SDO_PLAINTEXT_MAX_BYTES[0];
/// Supported plaintext bytes per Premium save.
pub const MAX_SDO_FILE_BYTES_PREMIUM: u64 = SDO_PLAINTEXT_MAX_BYTES[1];
// Read bounds retain the whole wire limit, so tightening new-save admission
// does not hide existing objects that used smaller metadata/envelope overhead.
const MAX_SDO_OBJECT_BYTES: u64 = DOCUMENT_CAPS[1];

/// Record type used by the multi-computer namespace reducer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdoKind {
    /// A regular file.
    File,
    /// An explicit directory.
    Directory,
    /// An installation registry announcement.
    Device,
}

/// The authenticated fields needed to order one multi-computer record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdoRecord {
    /// Safe relative path. Device records use their installation UUID string.
    pub path: String,
    /// Record kind.
    pub kind: SdoKind,
    /// Hybrid logical clock physical component in milliseconds.
    pub clock_ms: u64,
    /// Hybrid logical clock counter component.
    pub clock_counter: u64,
    /// Installation that authored the record.
    pub author_device_id: Uuid,
    /// Immutable logical version identifier.
    pub version_id: Uuid,
    /// Whether this file record is a deletion tombstone.
    pub deleted: bool,
    /// Marks a record imported from legacy TGFV1/TGFV2 metadata.
    pub legacy: bool,
    /// Marks a synthesized clock-zero parent directory.
    pub implicit: bool,
}

/// One encrypted device announcement as represented after decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAnnouncement {
    /// Random installation UUID, distinct from every other installation.
    pub installation_id: Uuid,
    /// User-selected label, at most 128 UTF-8 bytes.
    pub label: String,
    /// Telegram account user id.
    pub telegram_user_id: i64,
    /// Optional hash identifying this Telegram authorization session.
    pub authorization_session_hash: Option<String>,
    /// ML-KEM-768 public key used to receive replacement volume roots.
    pub public_key: Option<String>,
    /// Replacement root package posted in this device's encrypted registry record.
    pub key_update: Option<SdoDeviceKeyUpdate>,
    /// Creation time in Unix milliseconds.
    pub created_at_ms: u64,
    /// Hybrid clock physical component.
    pub clock_ms: u64,
    /// Hybrid clock counter component.
    pub clock_counter: u64,
    /// Authoring installation UUID.
    pub author_device_id: Uuid,
    /// Immutable announcement version UUID.
    pub version_id: Uuid,
}

/// Per-installation key handoff stored only inside that installation's encrypted
/// device record. The KEM payload is AEAD-bound to all fields in this structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdoDeviceKeyUpdate {
    /// Device installation that may unwrap this package.
    pub installation_id: Uuid,
    /// New object key generation.
    pub key_generation: u64,
    /// Salt used to derive this generation's key hierarchy.
    pub salt: [u8; 32],
    /// Postcard-serialized `teagarden_sharing::key_exchange::WrappedKey`.
    pub wrapped_root: Vec<u8>,
}

/// Reconstructed encrypted device registry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceRegistry {
    devices: BTreeMap<Uuid, DeviceAnnouncement>,
}

impl DeviceRegistry {
    /// Reduce announcements by installation UUID and enforce the 1024-device limit.
    pub fn from_announcements<I>(announcements: I) -> Result<Self>
    where
        I: IntoIterator<Item = DeviceAnnouncement>,
    {
        let mut by_version = BTreeMap::<Uuid, DeviceAnnouncement>::new();
        for announcement in announcements {
            if announcement.label.len() > 128 {
                return Err(CoreError::Manifest(
                    "device label exceeds 128 UTF-8 bytes".into(),
                ));
            }
            if let Some(previous) = by_version.get(&announcement.version_id) {
                if previous != &announcement {
                    return Err(CoreError::Manifest(
                        "conflicting plaintext for device version UUID".into(),
                    ));
                }
            } else {
                by_version.insert(announcement.version_id, announcement);
            }
        }
        let mut devices = BTreeMap::<Uuid, DeviceAnnouncement>::new();
        for announcement in by_version.into_values() {
            let id = announcement.installation_id;
            let replace = devices
                .get(&id)
                .is_none_or(|old| device_order(old) < device_order(&announcement));
            if replace {
                devices.insert(id, announcement);
            }
        }
        if devices.len() > 1024 {
            return Err(CoreError::Manifest(
                "device registry exceeds 1024 installations".into(),
            ));
        }
        Ok(Self { devices })
    }

    /// Number of registered installations.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether the registry has no announcements.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Find one installation by its full UUID.
    pub fn get(&self, id: &Uuid) -> Option<&DeviceAnnouncement> {
        self.devices.get(id)
    }

    /// Iterate over active announcements in installation UUID order.
    pub fn iter(&self) -> impl Iterator<Item = (&Uuid, &DeviceAnnouncement)> {
        self.devices.iter()
    }

    /// Remove installations and account bindings revoked by the signed header.
    pub fn apply_revocations(&mut self, device_ids: &[Uuid], account_bindings: &[String]) {
        self.devices.retain(|id, device| {
            !device_ids.contains(id)
                && device
                    .authorization_session_hash
                    .as_ref()
                    .is_none_or(|binding| !account_bindings.contains(binding))
        });
    }

    /// Resolve a unique label or report missing/ambiguous labels.
    pub fn resolve_label(&self, label: &str) -> std::result::Result<Uuid, &'static str> {
        let mut matches = self.devices.values().filter(|device| device.label == label);
        let first = matches.next().ok_or("unknown label")?;
        if matches.next().is_some() {
            return Err("ambiguous label");
        }
        Ok(first.installation_id)
    }
}

fn device_order(device: &DeviceAnnouncement) -> (u64, u64, [u8; 16], [u8; 16]) {
    (
        device.clock_ms,
        device.clock_counter,
        *device.author_device_id.as_bytes(),
        *device.version_id.as_bytes(),
    )
}

/// Convert one legacy TGFV1 manifest into reducer fields using the specified clock mapping.
pub fn legacy_record(manifest: &SdoManifest) -> SdoRecord {
    SdoRecord {
        path: manifest.path.clone(),
        kind: SdoKind::File,
        clock_ms: u64::try_from(manifest.saved_at_ns / 1_000_000).unwrap_or(0),
        clock_counter: 0,
        author_device_id: manifest.author_device_id,
        version_id: manifest.version_id,
        deleted: manifest.deleted,
        legacy: true,
        implicit: false,
    }
}

/// Convert one legacy TGFV2 object metadata value into reducer fields.
pub fn legacy_object_record(metadata: &SdoObjectMetadata) -> SdoRecord {
    SdoRecord {
        path: metadata.path.clone(),
        kind: SdoKind::File,
        clock_ms: u64::try_from(metadata.saved_at_ns / 1_000_000).unwrap_or(0),
        clock_counter: 0,
        author_device_id: metadata.author_device_id,
        version_id: metadata.version_id,
        deleted: metadata.deleted,
        legacy: true,
        implicit: false,
    }
}

/// Deterministic winning records and retained per-path histories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdoView {
    history: BTreeMap<String, Vec<SdoRecord>>,
}

impl SdoView {
    /// All unique versions seen for a path, in ascending winner order.
    pub fn history(&self, path: &str) -> &[SdoRecord] {
        self.history.get(path).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The deterministic winner for a path, including tombstones.
    pub fn winner(&self, path: &str) -> Option<&SdoRecord> {
        self.history(path).last()
    }

    /// Whether a file or directory is visible through live directory ancestors.
    pub fn is_visible(&self, path: &str) -> bool {
        let Some(record) = self.winner(path) else {
            return false;
        };
        if record.deleted || !matches!(record.kind, SdoKind::File | SdoKind::Directory) {
            return false;
        }
        let mut ancestor = String::new();
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_some() {
                if !ancestor.is_empty() {
                    ancestor.push('/');
                }
                ancestor.push_str(part);
                if !matches!(
                    self.winner(&ancestor).map(|r| r.kind),
                    Some(SdoKind::Directory)
                ) {
                    return false;
                }
            }
        }
        true
    }
}

/// Reduce records independent of delivery order, deduplicating identical versions.
pub fn reduce_records<I>(records: I) -> Result<SdoView>
where
    I: IntoIterator<Item = SdoRecord>,
{
    let mut versions: BTreeMap<Uuid, SdoRecord> = BTreeMap::new();
    let mut input: Vec<SdoRecord> = records.into_iter().collect();
    let explicit_paths: std::collections::BTreeSet<String> = input
        .iter()
        .filter(|record| !record.implicit)
        .map(|record| record.path.clone())
        .collect();
    let mut defaults = Vec::new();
    for record in input
        .iter()
        .filter(|record| record.legacy && !record.implicit)
    {
        let mut ancestor = String::new();
        let mut components = record.path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_some() {
                if !ancestor.is_empty() {
                    ancestor.push('/');
                }
                ancestor.push_str(component);
                if !explicit_paths.contains(&ancestor) {
                    let hash = crate::crypto::blake3::hash(ancestor.as_bytes());
                    let mut id = [0; 16];
                    id.copy_from_slice(&hash[..16]);
                    defaults.push(SdoRecord {
                        path: ancestor.clone(),
                        kind: SdoKind::Directory,
                        clock_ms: 0,
                        clock_counter: 0,
                        author_device_id: Uuid::nil(),
                        version_id: Uuid::from_bytes(id),
                        deleted: false,
                        legacy: true,
                        implicit: true,
                    });
                }
            }
        }
    }
    input.extend(defaults);
    for record in input {
        if let Some(previous) = versions.get(&record.version_id) {
            if previous != &record {
                return Err(CoreError::Manifest(format!(
                    "conflicting plaintext for version {}",
                    record.version_id
                )));
            }
        } else {
            versions.insert(record.version_id, record);
        }
    }
    let mut history: BTreeMap<String, Vec<SdoRecord>> = BTreeMap::new();
    for record in versions.into_values() {
        history.entry(record.path.clone()).or_default().push(record);
    }
    for records in history.values_mut() {
        records.sort_by_key(|record| {
            (
                !record.implicit,
                record.clock_ms,
                record.clock_counter,
                *record.author_device_id.as_bytes(),
                *record.version_id.as_bytes(),
            )
        });
    }
    Ok(SdoView { history })
}

/// Durable hybrid logical clock state for one installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HybridLogicalClock {
    physical_ms: u64,
    counter: u64,
}

impl HybridLogicalClock {
    /// Start from persisted local state.
    pub const fn new(physical_ms: u64, counter: u64) -> Self {
        Self {
            physical_ms,
            counter,
        }
    }

    /// Return the current persisted-state pair.
    pub const fn as_pair(self) -> (u64, u64) {
        (self.physical_ms, self.counter)
    }

    /// Advance before creating a local version; caller must persist returned state before upload.
    pub fn tick(&mut self, utc_ms: u64) -> Result<(u64, u64)> {
        let physical = utc_ms.max(self.physical_ms);
        let counter = if physical == self.physical_ms {
            self.counter.checked_add(1)
        } else {
            Some(0)
        }
        .ok_or_else(|| CoreError::Manifest("hybrid clock counter overflow".into()))?;
        self.physical_ms = physical;
        self.counter = counter;
        Ok((physical, counter))
    }

    /// Observe a received clock and advance beyond both local and remote state.
    pub fn receive(
        &mut self,
        remote_ms: u64,
        remote_counter: u64,
        utc_ms: u64,
    ) -> Result<(u64, u64)> {
        let physical = utc_ms.max(self.physical_ms).max(remote_ms);
        let counter = match (physical == self.physical_ms, physical == remote_ms) {
            (true, true) => self.counter.max(remote_counter).checked_add(1),
            (true, false) => self.counter.checked_add(1),
            (false, true) => remote_counter.checked_add(1),
            (false, false) => Some(0),
        }
        .ok_or_else(|| CoreError::Manifest("hybrid clock counter overflow".into()))?;
        self.physical_ms = physical;
        self.counter = counter;
        Ok((physical, counter))
    }
}

/// Root material mode declared in a portable volume header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootKind {
    /// Root is derived from a password using Argon2id.
    Password,
    /// Root is derived from a master key recovered through a slot vault.
    MasterKey,
}

/// Previous-generation root wrapped by the current generation's wrapping key.
/// The value belongs inside the owner-signed TGHD2 `rotation_state` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyGenerationBridge {
    /// Key generation whose root this bridge recovers.
    pub key_generation: u64,
    /// Lowercase hex salt used to derive that generation's hierarchy.
    pub salt: String,
    /// XChaCha20-Poly1305 nonce and ciphertext, lowercase hex.
    pub wrapped_root: String,
}

/// Whether an object may be consumed under the current header's generation.
///
/// `generation_boundary_message_id` is the first TGHD2 header message for the
/// active generation. Old-generation objects at or after that message are
/// rejected even if their logical clock predates the rotation.
pub fn generation_is_acceptable(
    object_generation: u64,
    active_generation: u64,
    object_message_id: i64,
    generation_boundary_message_id: i64,
) -> bool {
    object_generation == active_generation
        || (object_generation < active_generation
            && object_message_id < generation_boundary_message_id)
}

#[cfg(feature = "key-rotation")]
impl KeyGenerationBridge {
    /// Wrap an earlier hierarchy root and its salt under the active hierarchy's
    /// wrapping key. The generation and salt are authenticated as AAD.
    pub fn wrap(
        key_generation: u64,
        salt: &[u8; 32],
        root: &SymmetricKey,
        wrapping_key: &SymmetricKey,
    ) -> Result<Self> {
        let mut plaintext = Vec::with_capacity(64);
        plaintext.extend_from_slice(root.as_bytes());
        plaintext.extend_from_slice(salt);
        let aad = key_bridge_aad(key_generation, salt);
        let wrapped = aead::encrypt(wrapping_key, &plaintext, &aad)?;
        Ok(Self {
            key_generation,
            salt: hex::encode(salt),
            wrapped_root: hex::encode(wrapped),
        })
    }

    /// Recover an earlier root and salt with the current generation's wrapping
    /// key. Unknown generations, malformed encodings and authentication failures
    /// are rejected.
    pub fn unwrap(&self, wrapping_key: &SymmetricKey) -> Result<(SymmetricKey, [u8; 32])> {
        let salt_bytes = hex::decode(&self.salt)
            .map_err(|e| CoreError::Manifest(format!("invalid bridge salt: {e}")))?;
        let salt: [u8; 32] = salt_bytes
            .try_into()
            .map_err(|_| CoreError::Manifest("bridge salt must contain 32 bytes".into()))?;
        if self.salt != hex::encode(salt) {
            return Err(CoreError::Manifest(
                "bridge salt must use lowercase hexadecimal".into(),
            ));
        }
        let wrapped = hex::decode(&self.wrapped_root)
            .map_err(|e| CoreError::Manifest(format!("invalid wrapped bridge root: {e}")))?;
        let plaintext = aead::decrypt(
            wrapping_key,
            &wrapped,
            &key_bridge_aad(self.key_generation, &salt),
        )?;
        if plaintext.len() != 64 {
            return Err(CoreError::Manifest(
                "wrapped bridge root must recover 64 bytes".into(),
            ));
        }
        let root = SymmetricKey::from_bytes(plaintext[..32].try_into().unwrap());
        let recovered_salt: [u8; 32] = plaintext[32..].try_into().unwrap();
        if recovered_salt != salt {
            return Err(CoreError::Manifest(
                "bridge salt does not match authenticated plaintext".into(),
            ));
        }
        Ok((root, recovered_salt))
    }
}

#[cfg(feature = "key-rotation")]
fn key_bridge_aad(key_generation: u64, salt: &[u8; 32]) -> Vec<u8> {
    [
        b"teagarden.sdo.header.key-bridge.v1".as_slice(),
        &key_generation.to_le_bytes(),
        salt,
    ]
    .concat()
}

/// Immutable first revocation boundary for one installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationCutoff {
    /// First generation that excludes this installation.
    pub key_generation: u64,
    /// First owner-header message establishing that generation.
    pub boundary_message_id: i64,
}

/// Authenticated JSON payload carried by a TGHD header.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderDocument {
    /// Header schema version (must be 1).
    pub format: u16,
    /// Stable volume identifier.
    pub volume_id: Uuid,
    /// Monotonic header revision.
    pub revision: u64,
    /// Volume format/version label.
    pub volume_version: String,
    /// Root derivation mode.
    pub root_kind: RootKind,
    /// Lowercase hexadecimal 32-byte volume salt.
    pub salt: String,
    /// Password KDF parameters, required for password-rooted volumes.
    pub kdf_params: Option<Argon2Params>,
    /// Telegram group identifier.
    pub group_id: i64,
    /// Telegram topic identifier.
    pub topic_id: i64,
    /// Current data epoch.
    pub current_epoch: u32,
    /// First epoch using block-v2 authentication, if enabled.
    pub block_v2_from_epoch: Option<u32>,
    /// Require per-block integrity authentication.
    pub require_block_integrity: bool,
    /// Maximum plaintext block size.
    pub block_size: u64,
    /// Public key-protection anchor or null.
    pub key_protection: Option<Value>,
    /// Complete existing v2 slot-vault JSON for protected volumes.
    pub slot_vault: Option<Value>,
    /// Owner Ed25519 public key as lowercase 32-byte hexadecimal (TGHD2 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_public_key: Option<String>,
    /// Active data key generation (TGHD2 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_generation: Option<u64>,
    /// Owner-revoked installation UUIDs (TGHD2 only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_device_ids: Vec<Uuid>,
    /// Owner-revoked Telegram account/session binding hashes (TGHD2 only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_account_bindings: Vec<String>,
    /// Bounded key-rotation phase information (TGHD2 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_state: Option<Value>,
    /// Authenticated old-generation bridges retained for delayed concurrent saves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_key_bridges: Vec<KeyGenerationBridge>,
    /// Device signing keys frozen by the owner before the generation transition.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub device_authorities: BTreeMap<Uuid, String>,
    /// First message id which establishes this generation boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation_boundary_message_id: Option<i64>,
    /// Immutable first publication boundary for each generation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub generation_cutoffs: BTreeMap<u64, i64>,
    /// Immutable first access cutoff for each revoked installation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub revocation_cutoffs: BTreeMap<Uuid, RevocationCutoff>,
}

impl HeaderDocument {
    /// A reader that has observed an owner policy must not forget its cutoffs
    /// when an older signed revision is replayed or a later update drops them.
    pub fn require_policy_successor(&self, previous: &Self) -> Result<()> {
        if self.volume_id != previous.volume_id
            || self.group_id != previous.group_id
            || self.topic_id != previous.topic_id
            || self.owner_public_key != previous.owner_public_key
            || self.revision < previous.revision
            || (self.revision == previous.revision && self != previous)
            || self.key_generation.unwrap_or(0) < previous.key_generation.unwrap_or(0)
            || previous
                .revoked_device_ids
                .iter()
                .any(|id| !self.revoked_device_ids.contains(id))
            || previous
                .revocation_cutoffs
                .iter()
                .any(|(id, cutoff)| self.revocation_cutoffs.get(id) != Some(cutoff))
            || previous
                .device_authorities
                .iter()
                .any(|(id, key)| self.device_authorities.get(id) != Some(key))
            || previous
                .generation_cutoffs
                .iter()
                .any(|(generation, cutoff)| self.generation_cutoffs.get(generation) != Some(cutoff))
        {
            return Err(CoreError::Manifest(
                "owner policy rollback or changed immutable cutoff; retaining the observed policy"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Namespace consumers must distinguish missing revocation evidence from
    /// a proven unauthorized object. Never reconstruct a partial view silently.
    /// Header codecs remain usable by interrupted owner publication/resume.
    pub fn require_complete_revocation_cutoffs(&self) -> Result<()> {
        let missing: Vec<_> = self
            .revoked_device_ids
            .iter()
            .filter(|id| !self.revocation_cutoffs.contains_key(id))
            .map(ToString::to_string)
            .collect();
        if !missing.is_empty() {
            return Err(CoreError::Manifest(format!(
                "incomplete revocation policy: {} revoked device(s) missing recorded cutoff: {}; refusing to omit history",
                missing.len(), missing.join(", ")
            )));
        }
        Ok(())
    }

    /// Encode this header and append a keyed BLAKE3 MAC over the exact bytes.
    pub fn encode(&self, integrity_key: &SymmetricKey) -> Result<Vec<u8>> {
        self.validate()?;
        if self.format != 1 {
            return Err(CoreError::Serialization(
                "TGHD2 requires encode_v2 and an owner signing key".into(),
            ));
        }
        let json = serde_json::to_vec(self).map_err(|e| CoreError::Serialization(e.to_string()))?;
        let total = 10usize
            .checked_add(json.len())
            .and_then(|n| n.checked_add(32))
            .ok_or_else(|| CoreError::Serialization("header length overflow".into()))?;
        if total > MAX_HEADER_SIZE || json.len() > u32::MAX as usize {
            return Err(CoreError::Serialization("header exceeds size limit".into()));
        }
        let mut wire = Vec::with_capacity(total);
        wire.extend_from_slice(b"TGHD");
        wire.extend_from_slice(&1u16.to_le_bytes());
        wire.extend_from_slice(&(json.len() as u32).to_le_bytes());
        wire.extend_from_slice(&json);
        let mut authenticated = Vec::with_capacity(HEADER_MAC_CONTEXT.len() + wire.len());
        authenticated.extend_from_slice(HEADER_MAC_CONTEXT);
        authenticated.extend_from_slice(&wire);
        wire.extend_from_slice(&blake3::keyed_hash(integrity_key, &authenticated));
        Ok(wire)
    }

    /// Encode a TGHD2 header with its detached owner signature and keyed MAC.
    pub fn encode_v2(
        &self,
        integrity_key: &SymmetricKey,
        signing_key: &SigningKey,
    ) -> Result<Vec<u8>> {
        self.validate()?;
        if self.format != 2
            || self.owner_public_key.as_deref()
                != Some(hex::encode(signing_key.verifying_key().to_bytes()).as_str())
        {
            return Err(CoreError::Serialization(
                "TGHD2 owner key or format is inconsistent".into(),
            ));
        }
        let json = serde_json::to_vec(self).map_err(|e| CoreError::Serialization(e.to_string()))?;
        let total = 12usize
            .checked_add(json.len())
            .and_then(|n| n.checked_add(2 + 64 + 32))
            .ok_or_else(|| CoreError::Serialization("TGHD2 length overflow".into()))?;
        if total > MAX_HEADER_SIZE || json.len() > u32::MAX as usize {
            return Err(CoreError::Serialization(
                "TGHD2 header exceeds size limit".into(),
            ));
        }
        let mut wire = Vec::with_capacity(total);
        wire.extend_from_slice(b"TGHD");
        wire.extend_from_slice(&2u16.to_le_bytes());
        wire.extend_from_slice(&(json.len() as u32).to_le_bytes());
        wire.extend_from_slice(&json);
        let signature = signing_key.sign(&wire);
        wire.extend_from_slice(&(64u16).to_le_bytes());
        wire.extend_from_slice(&signature.to_bytes());
        let mut authenticated = b"teagarden.sdo.header.v2".to_vec();
        authenticated.extend_from_slice(&wire);
        wire.extend_from_slice(&blake3::keyed_hash(integrity_key, &authenticated));
        Ok(wire)
    }

    /// Authenticate a header while retaining an established owner trust anchor.
    /// A pinned consumer never accepts TGHD1 or a different self-signed owner.
    pub fn decode_pinned(
        wire: &[u8],
        integrity_key: &SymmetricKey,
        owner_public_key: Option<&str>,
    ) -> Result<Self> {
        let header = Self::decode(wire, integrity_key)?;
        if let Some(owner) = owner_public_key {
            if header.format != 2 || header.owner_public_key.as_deref() != Some(owner) {
                return Err(CoreError::Manifest(
                    "TGHD2 owner pin mismatch or header downgrade".into(),
                ));
            }
        }
        Ok(header)
    }

    /// Verify framing and MAC, then parse the exact stored JSON bytes.
    pub fn decode(wire: &[u8], integrity_key: &SymmetricKey) -> Result<Self> {
        if wire.len() >= 6 && u16::from_le_bytes([wire[4], wire[5]]) == 2 {
            return Self::decode_v2(wire, integrity_key);
        }
        if wire.len() > MAX_HEADER_SIZE || wire.len() < 42 || &wire[..4] != b"TGHD" {
            return Err(CoreError::Serialization("invalid TGHD framing".into()));
        }
        if u16::from_le_bytes([wire[4], wire[5]]) != 1 {
            return Err(CoreError::Serialization(
                "unsupported TGHD wire format".into(),
            ));
        }
        let json_len = u32::from_le_bytes(wire[6..10].try_into().unwrap()) as usize;
        let expected_len = 10usize
            .checked_add(json_len)
            .and_then(|n| n.checked_add(32))
            .ok_or_else(|| CoreError::Serialization("TGHD length overflow".into()))?;
        if expected_len != wire.len() {
            return Err(CoreError::Serialization("TGHD length mismatch".into()));
        }
        let mac_at = 10 + json_len;
        let expected: [u8; 32] = wire[mac_at..].try_into().unwrap();
        let mut authenticated = Vec::with_capacity(HEADER_MAC_CONTEXT.len() + mac_at);
        authenticated.extend_from_slice(HEADER_MAC_CONTEXT);
        authenticated.extend_from_slice(&wire[..mac_at]);
        if !blake3::verify_mac(integrity_key, &authenticated, &expected) {
            return Err(CoreError::IntegrityError {
                expected: "header MAC".into(),
                actual: "invalid".into(),
            });
        }
        let document: Self = serde_json::from_slice(&wire[10..mac_at])
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        document.validate()?;
        Ok(document)
    }

    fn decode_v2(wire: &[u8], integrity_key: &SymmetricKey) -> Result<Self> {
        if wire.len() > MAX_HEADER_SIZE
            || wire.len() < 12 + 2 + 64 + 32
            || &wire[..4] != b"TGHD"
            || u16::from_le_bytes(wire[4..6].try_into().unwrap()) != 2
        {
            return Err(CoreError::Serialization("invalid TGHD2 framing".into()));
        }
        let json_len = u32::from_le_bytes(wire[6..10].try_into().unwrap()) as usize;
        let sig_len_at = 10usize
            .checked_add(json_len)
            .ok_or_else(|| CoreError::Serialization("TGHD2 JSON length overflow".into()))?;
        if sig_len_at
            .checked_add(2 + 32)
            .is_none_or(|end| end > wire.len())
        {
            return Err(CoreError::Serialization("TGHD2 length mismatch".into()));
        }
        let signature_len =
            u16::from_le_bytes(wire[sig_len_at..sig_len_at + 2].try_into().unwrap()) as usize;
        let mac_at = sig_len_at + 2 + signature_len;
        if signature_len != 64 || mac_at.checked_add(32) != Some(wire.len()) {
            return Err(CoreError::Serialization(
                "TGHD2 signature or total length mismatch".into(),
            ));
        }
        let mut authenticated = b"teagarden.sdo.header.v2".to_vec();
        authenticated.extend_from_slice(&wire[..mac_at]);
        let expected: [u8; 32] = wire[mac_at..].try_into().unwrap();
        if !blake3::verify_mac(integrity_key, &authenticated, &expected) {
            return Err(CoreError::IntegrityError {
                expected: "header MAC".into(),
                actual: "invalid".into(),
            });
        }
        let document: Self = serde_json::from_slice(&wire[10..sig_len_at])
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        document.validate()?;
        let public_bytes = hex::decode(document.owner_public_key.as_deref().unwrap())
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let public_array: [u8; 32] = public_bytes.try_into().map_err(|_| {
            CoreError::Serialization("invalid TGHD2 owner public key length".into())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&public_array)
            .map_err(|e| CoreError::Serialization(format!("invalid TGHD2 owner key: {e}")))?;
        let signature = Signature::from_slice(&wire[sig_len_at + 2..mac_at])
            .map_err(|e| CoreError::Serialization(format!("invalid TGHD2 signature: {e}")))?;
        verifying_key
            .verify(&wire[..sig_len_at], &signature)
            .map_err(|_| CoreError::IntegrityError {
                expected: "owner signature".into(),
                actual: "invalid".into(),
            })?;
        Ok(document)
    }

    fn validate(&self) -> Result<()> {
        if !matches!(self.format, 1 | 2) || self.volume_version.is_empty() || self.block_size == 0 {
            return Err(CoreError::Serialization("invalid TGHD fields".into()));
        }
        if self.format == 1
            && (self.owner_public_key.is_some()
                || self.key_generation.is_some()
                || !self.revoked_device_ids.is_empty()
                || !self.revoked_account_bindings.is_empty()
                || self.rotation_state.is_some()
                || self.generation_boundary_message_id.is_some())
        {
            return Err(CoreError::Serialization(
                "TGHD1 cannot carry TGHD2 fields".into(),
            ));
        }
        if self.format == 2 {
            let key = self
                .owner_public_key
                .as_deref()
                .ok_or_else(|| CoreError::Serialization("TGHD2 owner key is missing".into()))?;
            let bytes = hex::decode(key).map_err(|e| CoreError::Serialization(e.to_string()))?;
            if bytes.len() != 32 || key != key.to_ascii_lowercase() || self.key_generation.is_none()
            {
                return Err(CoreError::Serialization(
                    "invalid TGHD2 owner key or generation".into(),
                ));
            }
        }
        let salt = hex::decode(&self.salt).map_err(|e| CoreError::Serialization(e.to_string()))?;
        if salt.len() != 32 || self.salt != self.salt.to_ascii_lowercase() {
            return Err(CoreError::Serialization(
                "TGHD salt must be 32-byte lowercase hex".into(),
            ));
        }
        match (&self.root_kind, &self.kdf_params, &self.slot_vault) {
            (RootKind::Password, Some(params), None) => params
                .validate()
                .map_err(|e| CoreError::KeyDerivation(e.to_string()))?,
            (RootKind::MasterKey, None, Some(_)) => {}
            _ => {
                return Err(CoreError::Serialization(
                    "TGHD root-kind fields disagree".into(),
                ))
            }
        }
        Ok(())
    }

    /// Test-only representative header. Kept public to support downstream codec fixtures.
    #[doc(hidden)]
    pub fn test_fixture() -> Self {
        Self {
            format: 1,
            volume_id: Uuid::from_bytes([3; 16]),
            revision: 1,
            volume_version: "1.0.0".into(),
            root_kind: RootKind::Password,
            salt: "01".repeat(32),
            kdf_params: Some(Argon2Params {
                memory_kib: 1024,
                iterations: 1,
                parallelism: 1,
                output_len: 32,
            }),
            group_id: -100,
            topic_id: 42,
            current_epoch: 0,
            block_v2_from_epoch: None,
            require_block_integrity: false,
            block_size: 1024 * 1024,
            key_protection: None,
            slot_vault: None,
            owner_public_key: None,
            key_generation: None,
            revoked_device_ids: Vec::new(),
            revoked_account_bindings: Vec::new(),
            retained_key_bridges: Vec::new(),
            device_authorities: std::collections::BTreeMap::new(),
            rotation_state: None,
            generation_boundary_message_id: None,
            generation_cutoffs: Default::default(),
            revocation_cutoffs: Default::default(),
        }
    }
}

/// One ordered reference to encrypted block bytes in a TGFV manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdoBlockRef {
    /// Telegram document message id.
    pub message_id: i64,
    /// Lowercase hexadecimal block identity.
    pub block_id: String,
    /// Original plaintext block length.
    pub plaintext_size: u64,
    /// Encryption epoch.
    pub epoch: u32,
    /// Logical file offset of the referenced slice.
    pub file_offset: u64,
    /// Offset into decrypted block plaintext.
    pub block_data_offset: u64,
    /// Number of plaintext bytes in this slice.
    pub length: u64,
    /// Stored encrypted object length.
    pub encrypted_size: u64,
    /// Whether the stored block is compressed.
    pub compressed: bool,
    /// SHA-256 of the complete encrypted object, lowercase hex.
    pub cipher_sha256: String,
    /// SHA-256 of complete plaintext block, lowercase hex.
    pub plain_sha256: String,
}

/// Decrypted TGFV v1 file-version payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdoManifest {
    /// Permanent file identity shared by every revision and rename.
    pub file_id: Uuid,
    /// Message id of the first TGFV version; null only in that first object.
    pub origin_message_id: Option<i64>,
    /// Safe relative UTF-8 path.
    pub path: String,
    /// Logical file size.
    pub size: u64,
    /// Modification time in Unix nanoseconds.
    pub mtime_ns: i64,
    /// POSIX mode bits.
    pub mode: u32,
    /// Unique version identifier.
    pub version_id: Uuid,
    /// Stable random author-device identifier.
    pub author_device_id: Uuid,
    /// Previous version identifier, if any.
    pub previous_version_id: Option<Uuid>,
    /// Save time in Unix nanoseconds.
    pub saved_at_ns: i64,
    /// Local monotonic version number.
    pub local_version: u64,
    /// Ordered block slices.
    pub blocks: Vec<SdoBlockRef>,
    /// True when this version deletes the path.
    #[serde(default)]
    pub deleted: bool,
}

/// Encrypted metadata carried in a single TGFV v2 file object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdoObjectMetadata {
    /// Permanent identity shared by revisions and renames.
    pub file_id: Uuid,
    /// Telegram message id of the first version, null in that first object.
    pub origin_message_id: Option<i64>,
    /// Safe relative UTF-8 path.
    pub path: String,
    /// Plaintext content size.
    pub size: u64,
    /// Modification time in Unix nanoseconds.
    pub mtime_ns: i64,
    /// POSIX mode bits.
    pub mode: u32,
    /// Unique version identifier.
    pub version_id: Uuid,
    /// Stable random author-device identifier.
    pub author_device_id: Uuid,
    /// Previous version identifier, if any.
    pub previous_version_id: Option<Uuid>,
    /// Save time in Unix nanoseconds.
    pub saved_at_ns: i64,
    /// Local monotonic version number.
    pub local_version: u64,
    /// Whether this object is a deletion tombstone.
    pub deleted: bool,
    /// Fixed plaintext segment size.
    pub segment_size: u32,
    /// Number of encrypted segments following the header.
    pub segment_count: u32,
    /// SHA-256 of the complete plaintext file, lowercase hex.
    pub content_sha256: String,
}

/// An installation signature over a complete logical file version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectAuthority {
    /// Ed25519 public key, lowercase hexadecimal.
    pub public_key: String,
    /// Signature over normalized logical metadata (including the content hash).
    pub signature: String,
}

/// Owner attestation preserving the original acknowledged location in migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceipt {
    /// Actual Telegram message id authenticated by the owner before replacement.
    pub source_message_id: i64,
    /// Owner signature over logical metadata and source message id.
    pub signature: String,
}

/// Derive a separate installation signing capability from its existing private
/// receiving-key seed; the public receiving key cannot derive this capability.
pub fn device_signing_key(private_seed: &[u8]) -> SigningKey {
    let mut input = b"teagarden.installation-signing.v1".to_vec();
    input.extend_from_slice(private_seed);
    let mut seed = crate::crypto::blake3::hash(&input);
    let key = SigningKey::from_bytes(&seed);
    use zeroize::Zeroize;
    seed.zeroize();
    input.zeroize();
    key
}

/// Encrypted metadata carried by a TGFV format 3 object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdoObjectMetadataV3 {
    /// Optional device signature; mandatory for old-generation work after rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<ObjectAuthority>,
    /// Owner proof retaining pre-boundary history across physical migration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_receipt: Option<MigrationReceipt>,
    /// Permanent identity shared by file revisions and renames.
    pub file_id: Uuid,
    /// Telegram message id of the first version, or null in that first object.
    pub origin_message_id: Option<i64>,
    /// Filesystem path; absent on a device registry record.
    pub path: Option<String>,
    /// Plaintext content size.
    pub size: u64,
    /// Filesystem modification time in Unix nanoseconds.
    pub mtime_ns: i64,
    /// POSIX mode bits.
    pub mode: u32,
    /// Unique immutable version identifier.
    pub version_id: Uuid,
    /// Stable installation UUID that authored this record.
    pub author_device_id: Uuid,
    /// Previous version identifier, if any.
    pub previous_version_id: Option<Uuid>,
    /// Record kind.
    pub kind: SdoKind,
    /// Encryption key generation.
    pub key_generation: u64,
    /// Hybrid logical clock physical component in milliseconds.
    pub clock_ms: u64,
    /// Hybrid logical clock counter component.
    pub clock_counter: u64,
    /// Compatibility save timestamp in Unix nanoseconds; not used for ordering.
    pub saved_at_ns: i64,
    /// Compatibility file-local version counter.
    pub local_version: u64,
    /// Whether this file record deletes its path.
    pub deleted: bool,
    /// Installation UUID for a device registry announcement.
    pub installation_id: Option<Uuid>,
    /// Human-readable device label (at most 128 UTF-8 bytes).
    pub label: Option<String>,
    /// Telegram user id bound to this installation.
    pub telegram_user_id: Option<i64>,
    /// Hash of the authorization session, when available.
    pub authorization_session_hash: Option<String>,
    /// Device registration time in Unix milliseconds.
    pub created_at_ms: Option<u64>,
    /// ML-KEM-768 public key in lowercase hex for key handoff; device records only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_public_key: Option<String>,
    /// New generation package for this installation; device records only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key_update: Option<SdoDeviceKeyUpdate>,
    /// Fixed plaintext segment size.
    pub segment_size: u32,
    /// Number of encrypted content segments.
    pub segment_count: u32,
    /// SHA-256 of complete plaintext content.
    pub content_sha256: String,
}

impl SdoObjectMetadataV3 {
    /// Encode logical metadata for an encrypted durable outbox. JSON preserves
    /// optional wire fields independently of the outbox's binary struct layout.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| CoreError::Serialization(error.to_string()))
    }

    /// Decode one durable metadata snapshot before normal object validation.
    pub fn decode_snapshot(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANIFEST_SIZE {
            return Err(CoreError::Manifest("metadata snapshot is overlong".into()));
        }
        serde_json::from_slice(bytes).map_err(|error| CoreError::Serialization(error.to_string()))
    }

    fn authority_bytes(&self, volume_id: Uuid, receipt: bool, source: i64) -> Result<Vec<u8>> {
        let mut normalized = self.clone();
        normalized.key_generation = 0;
        normalized.migration_receipt = None;
        if !receipt {
            normalized.authority = None;
        }
        let mut bytes = if receipt {
            b"teagarden.sdo.migration-authority.v1".to_vec()
        } else {
            b"teagarden.sdo.writer-authority.v1".to_vec()
        };
        bytes.extend_from_slice(volume_id.as_bytes());
        if receipt {
            bytes.extend_from_slice(&source.to_le_bytes());
        }
        bytes.extend_from_slice(
            &serde_json::to_vec(&normalized)
                .map_err(|e| CoreError::Serialization(e.to_string()))?,
        );
        Ok(bytes)
    }

    /// Bind this version's complete logical metadata and content to its author.
    pub fn sign_authority(
        &mut self,
        volume_id: Uuid,
        signing_key: &SigningKey,
        content: &[u8],
    ) -> Result<()> {
        self.sign_authority_digest(volume_id, signing_key, crate::block::srb2::sha256(content))
    }

    /// Sign a precomputed digest of the complete local plaintext image.
    /// Streaming publishers verify those bytes again before publishing the message.
    pub fn sign_authority_digest(
        &mut self,
        volume_id: Uuid,
        signing_key: &SigningKey,
        digest: [u8; 32],
    ) -> Result<()> {
        self.segment_size = SDO_SEGMENT_SIZE;
        self.segment_count = if self.kind == SdoKind::File && !self.deleted {
            self.size.div_ceil(u64::from(SDO_SEGMENT_SIZE)) as u32
        } else {
            0
        };
        self.content_sha256 = hex::encode(digest);
        self.migration_receipt = None;
        let bytes = self.authority_bytes(volume_id, false, 0)?;
        self.authority = Some(ObjectAuthority {
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            signature: hex::encode(signing_key.sign(&bytes).to_bytes()),
        });
        Ok(())
    }

    /// Verify an installation's signature when this is a signed version.
    pub fn verify_authority(&self, volume_id: Uuid) -> Result<()> {
        if let Some(proof) = &self.authority {
            verify_object_signature(
                &proof.public_key,
                &proof.signature,
                &self.authority_bytes(volume_id, false, 0)?,
            )?;
        }
        Ok(())
    }

    /// Attest a verified source before deleting it during owner migration.
    #[cfg(feature = "key-rotation")]
    pub fn attest_migration(
        &mut self,
        volume_id: Uuid,
        source_message_id: i64,
        owner: &SigningKey,
    ) -> Result<()> {
        let bytes = self.authority_bytes(volume_id, true, source_message_id)?;
        self.migration_receipt = Some(MigrationReceipt {
            source_message_id,
            signature: hex::encode(owner.sign(&bytes).to_bytes()),
        });
        Ok(())
    }

    /// Verify that the owner retained this exact logical version from before the boundary.
    #[cfg(feature = "key-rotation")]
    pub fn has_valid_migration_receipt(&self, volume_id: Uuid, owner: &str, boundary: i64) -> bool {
        let Some(receipt) = &self.migration_receipt else {
            return false;
        };
        receipt.source_message_id > 0
            && receipt.source_message_id < boundary
            && self
                .authority_bytes(volume_id, true, receipt.source_message_id)
                .is_ok_and(|bytes| {
                    verify_object_signature(owner, &receipt.signature, &bytes).is_ok()
                })
    }

    /// Validate owner provenance against the immutable author cutoff, or the
    /// pinned surviving writer proof for a legitimate post-boundary save.
    #[cfg(feature = "key-rotation")]
    pub fn has_authorized_migration_receipt(&self, header: &HeaderDocument) -> bool {
        let Some(owner) = header.owner_public_key.as_deref() else {
            return false;
        };
        let revoked = header.revoked_device_ids.contains(&self.author_device_id);
        let boundary = if revoked {
            let Some(cutoff) = header.revocation_cutoffs.get(&self.author_device_id) else {
                return false;
            };
            cutoff.boundary_message_id
        } else {
            header.generation_boundary_message_id.unwrap_or(i64::MAX)
        };
        if self.has_valid_migration_receipt(header.volume_id, owner, boundary) {
            return true;
        }
        !revoked
            && self.has_valid_migration_receipt(header.volume_id, owner, i64::MAX)
            && self.verify_authority(header.volume_id).is_ok()
            && self.authority.as_ref().is_some_and(|proof| {
                header.device_authorities.get(&self.author_device_id) == Some(&proof.public_key)
                    || (self.kind == SdoKind::Device
                        && self.device_key_update.is_some()
                        && proof.public_key == owner)
            })
    }

    /// Validate path, device registry fields, and the zero-segment rules.
    pub fn validate(&self) -> Result<()> {
        match self.kind {
            SdoKind::Device => {
                if self.path.is_some()
                    || self.installation_id.is_none()
                    || self.label.as_ref().is_none_or(|s| s.len() > 128)
                    || self.telegram_user_id.is_none()
                    || self.created_at_ms.is_none()
                    || self.device_public_key.as_ref().is_some_and(|key| {
                        key.len() != 2368 || !key.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    // A retained handoff keeps its logical target generation even
                    // after its enclosing history object is re-encrypted again.
                    || self.device_key_update.as_ref().is_some_and(|update| {
                        Some(update.installation_id) != self.installation_id
                            || update.wrapped_root.len() > 4096
                    })
                    || self.size != 0
                    || self.segment_count != 0
                {
                    return Err(CoreError::Manifest("invalid device registry record".into()));
                }
            }
            SdoKind::File | SdoKind::Directory => {
                let path = self.path.as_deref().ok_or_else(|| {
                    CoreError::Manifest("filesystem record is missing its path".into())
                })?;
                validate_sdo_path(path)?;
                if self.installation_id.is_some()
                    || self.label.is_some()
                    || self.telegram_user_id.is_some()
                    || self.authorization_session_hash.is_some()
                    || self.created_at_ms.is_some()
                    || self.device_public_key.is_some()
                    || self.device_key_update.is_some()
                {
                    return Err(CoreError::Manifest(
                        "filesystem record has device fields".into(),
                    ));
                }
                let zero_segments = self.deleted || self.kind == SdoKind::Directory;
                if (zero_segments && (self.size != 0 || self.segment_count != 0))
                    || (!zero_segments
                        && self.segment_count
                            != self.size.div_ceil(u64::from(SDO_SEGMENT_SIZE)) as u32)
                {
                    return Err(CoreError::Manifest("invalid TGFV v3 segment layout".into()));
                }
            }
        }
        if self.segment_size != SDO_SEGMENT_SIZE || self.size > MAX_SDO_OBJECT_BYTES {
            return Err(CoreError::Manifest("TGFV v3 size bounds exceeded".into()));
        }
        let digest = hex::decode(&self.content_sha256)
            .map_err(|e| CoreError::Manifest(format!("invalid content hash: {e}")))?;
        if digest.len() != 32 || self.content_sha256 != self.content_sha256.to_ascii_lowercase() {
            return Err(CoreError::Manifest("invalid content SHA-256".into()));
        }
        if let Some(label) = &self.label {
            if label.len() > 128 {
                return Err(CoreError::Manifest(
                    "device label exceeds 128 UTF-8 bytes".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Credential bootstrap carried by one complete TGFV3 document. The exact TGHD
/// bytes retain the password KDF or encrypted password/recovery slots. Both key
/// wraps authenticate the bootstrap and the complete original object digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectEnvelope {
    /// Exact authenticated TGHD bytes from the generation that wrote this object.
    pub header_wire: Vec<u8>,
    /// SHA-256 of the TGFV prefix, encrypted metadata and every content segment.
    pub object_sha256: String,
    /// Generation metadata key wrapped under the password-unlocked root KEK.
    pub password_wrapped_key: Vec<u8>,
    /// Generation metadata key wrapped under the recovery-unlocked root KEK.
    pub recovery_wrapped_key: Vec<u8>,
}

impl ObjectEnvelope {
    fn aad(&self) -> Result<Vec<u8>> {
        let mut aad = b"teagarden.sdo.credential-envelope.v1".to_vec();
        aad.extend_from_slice(&(self.header_wire.len() as u64).to_le_bytes());
        aad.extend_from_slice(&self.header_wire);
        aad.extend_from_slice(self.object_sha256.as_bytes());
        Ok(aad)
    }

    /// Append a bounded authenticated credential trailer without changing segment
    /// offsets. `header_wire` must be the authenticated header for these keys.
    pub fn seal(
        wire: &[u8],
        header_wire: &[u8],
        hierarchy: &crate::crypto::keys::KeyHierarchy,
    ) -> Result<Vec<u8>> {
        let header = HeaderDocument::decode(header_wire, &hierarchy.integrity)?;
        if wire.len() < 34
            || &wire[..4] != b"TGFV"
            || wire[4..6] != 3u16.to_le_bytes()
            || &wire[6..22] != header.volume_id.as_bytes()
            || u64::from_le_bytes(wire[22..30].try_into().unwrap())
                != header.key_generation.unwrap_or(0)
        {
            return Err(CoreError::Manifest(
                "credential envelope and object identity disagree".into(),
            ));
        }
        // Refuse nesting trailers and malformed objects before wrapping a key.
        SdoFileObjectV3::decode(
            wire,
            header.volume_id,
            header.key_generation.unwrap_or(0),
            &hierarchy.meta,
        )?;
        if Self::parse(wire)?.is_some() {
            return Err(CoreError::Manifest(
                "object already has a credential envelope".into(),
            ));
        }
        let mut envelope = Self {
            header_wire: header_wire.to_vec(),
            object_sha256: hex::encode(crate::block::srb2::sha256(wire)),
            password_wrapped_key: Vec::new(),
            recovery_wrapped_key: Vec::new(),
        };
        let aad = envelope.aad()?;
        let password_kek = crate::crypto::kdf::hkdf_derive(
            &hierarchy.root,
            b"teagarden.sdo.envelope.password.v1",
        )?;
        let recovery_kek = crate::crypto::kdf::hkdf_derive(
            &hierarchy.root,
            b"teagarden.sdo.envelope.recovery.v1",
        )?;
        envelope.password_wrapped_key =
            aead::encrypt(&password_kek, hierarchy.meta.as_bytes(), &aad)?;
        envelope.recovery_wrapped_key =
            aead::encrypt(&recovery_kek, hierarchy.meta.as_bytes(), &aad)?;
        let json =
            serde_json::to_vec(&envelope).map_err(|e| CoreError::Serialization(e.to_string()))?;
        if json.len() > MAX_HEADER_SIZE {
            return Err(CoreError::Manifest(
                "credential envelope exceeds size limit".into(),
            ));
        }
        let mut mac_input = b"teagarden.sdo.envelope.framing.v1".to_vec();
        mac_input.extend_from_slice(&json);
        mac_input.extend_from_slice(&(wire.len() as u64).to_le_bytes());
        let mac = blake3::keyed_hash(&hierarchy.meta, &mac_input);
        let mut result = wire.to_vec();
        result.extend_from_slice(&json);
        result.extend_from_slice(&mac);
        result.extend_from_slice(&(json.len() as u32).to_le_bytes());
        result.extend_from_slice(b"TGFE");
        if result.len() as u64 > MAX_SDO_OBJECT_BYTES {
            return Err(CoreError::Manifest(
                "enveloped TGFV exceeds size limit".into(),
            ));
        }
        Ok(result)
    }

    fn framing(wire: &[u8]) -> Result<Option<(usize, usize)>> {
        if !wire.ends_with(b"TGFE") {
            return Ok(None);
        }
        if wire.len() < 40 {
            return Err(CoreError::Manifest("truncated credential envelope".into()));
        }
        let length =
            u32::from_le_bytes(wire[wire.len() - 8..wire.len() - 4].try_into().unwrap()) as usize;
        if length > MAX_HEADER_SIZE || length > wire.len() - 40 {
            return Err(CoreError::Manifest(
                "invalid credential envelope length".into(),
            ));
        }
        Ok(Some((wire.len() - 40 - length, length)))
    }

    /// Parse untrusted bootstrap data; no field is trusted until `open` succeeds.
    pub fn parse(wire: &[u8]) -> Result<Option<Self>> {
        let Some((offset, length)) = Self::framing(wire)? else {
            return Ok(None);
        };
        serde_json::from_slice(&wire[offset..offset + length])
            .map(Some)
            .map_err(|e| CoreError::Serialization(e.to_string()))
    }

    fn authenticate(wire: &[u8], meta_key: &SymmetricKey) -> Result<usize> {
        let (offset, length) = Self::framing(wire)?
            .ok_or_else(|| CoreError::Manifest("missing credential envelope".into()))?;
        let envelope = Self::parse(wire)?.unwrap();
        let mut mac_input = b"teagarden.sdo.envelope.framing.v1".to_vec();
        mac_input.extend_from_slice(&wire[offset..offset + length]);
        mac_input.extend_from_slice(&(offset as u64).to_le_bytes());
        let expected: &[u8; 32] = wire[offset + length..offset + length + 32]
            .try_into()
            .unwrap();
        if !blake3::verify_mac(meta_key, &mac_input, expected)
            || envelope.object_sha256 != hex::encode(crate::block::srb2::sha256(&wire[..offset]))
        {
            return Err(CoreError::Manifest(
                "credential envelope authentication failed".into(),
            ));
        }
        Ok(offset)
    }

    /// Unwrap the generation key after the caller unlocks and authenticates the
    /// embedded TGHD using the password or recovery sentence.
    pub fn open(&self, wire: &[u8], root: &SymmetricKey, recovery: bool) -> Result<SymmetricKey> {
        let label: &[u8] = if recovery {
            b"teagarden.sdo.envelope.recovery.v1"
        } else {
            b"teagarden.sdo.envelope.password.v1"
        };
        let kek = crate::crypto::kdf::hkdf_derive(root, label)?;
        let wrapped = if recovery {
            &self.recovery_wrapped_key
        } else {
            &self.password_wrapped_key
        };
        let mut plain = aead::decrypt(&kek, wrapped, &self.aad()?)?;
        let bytes: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Manifest("invalid enveloped key length".into()))?;
        use zeroize::Zeroize;
        plain.zeroize();
        let key = SymmetricKey::from_bytes(bytes);
        Self::authenticate(wire, &key)?;
        Ok(key)
    }
}

fn verify_object_signature(public: &str, signature: &str, bytes: &[u8]) -> Result<()> {
    if public.len() != 64 || signature.len() != 128 {
        return Err(CoreError::Manifest(
            "invalid object authority length".into(),
        ));
    }
    let public: [u8; 32] = hex::decode(public)
        .map_err(|e| CoreError::Manifest(e.to_string()))?
        .try_into()
        .map_err(|_| CoreError::Manifest("invalid device signing key length".into()))?;
    let public =
        VerifyingKey::from_bytes(&public).map_err(|e| CoreError::Manifest(e.to_string()))?;
    let signature = hex::decode(signature).map_err(|e| CoreError::Manifest(e.to_string()))?;
    let signature =
        Signature::from_slice(&signature).map_err(|e| CoreError::Manifest(e.to_string()))?;
    public
        .verify(bytes, &signature)
        .map_err(|e| CoreError::Manifest(format!("object author signature failed: {e}")))
}

/// Convert authenticated legacy file metadata into the portable logical shape.
pub fn legacy_metadata_v3(metadata: &SdoObjectMetadata) -> SdoObjectMetadataV3 {
    SdoObjectMetadataV3 {
        authority: None,
        migration_receipt: None,
        file_id: metadata.file_id,
        origin_message_id: metadata.origin_message_id,
        path: Some(metadata.path.clone()),
        size: metadata.size,
        mtime_ns: metadata.mtime_ns,
        mode: metadata.mode,
        version_id: metadata.version_id,
        author_device_id: metadata.author_device_id,
        previous_version_id: metadata.previous_version_id,
        kind: SdoKind::File,
        key_generation: 0,
        clock_ms: u64::try_from(metadata.saved_at_ns.max(0) / 1_000_000).unwrap_or_default(),
        clock_counter: 0,
        saved_at_ns: metadata.saved_at_ns,
        local_version: metadata.local_version,
        deleted: metadata.deleted,
        installation_id: None,
        label: None,
        telegram_user_id: None,
        authorization_session_hash: None,
        created_at_ms: None,
        device_public_key: None,
        device_key_update: None,
        segment_size: metadata.segment_size,
        segment_count: metadata.segment_count,
        content_sha256: metadata.content_sha256.clone(),
    }
}

/// Authorship evidence independent of source-position or generation admission.
/// Recovery may explicitly relax missing source provenance, never a frozen key.
pub fn object_authority_is_acceptable(
    header: &HeaderDocument,
    metadata: &SdoObjectMetadataV3,
) -> bool {
    if metadata.verify_authority(header.volume_id).is_err() {
        return false;
    }
    if let Some(expected) = header.device_authorities.get(&metadata.author_device_id) {
        if metadata
            .authority
            .as_ref()
            .is_none_or(|proof| &proof.public_key != expected)
        {
            return false;
        }
    }
    !(metadata.kind == SdoKind::Device
        && !is_owner_key_update(header, metadata)
        && metadata.installation_id.is_some_and(|id| {
            header.device_authorities.contains_key(&id) && id != metadata.author_device_id
        }))
}

fn is_owner_key_update(header: &HeaderDocument, metadata: &SdoObjectMetadataV3) -> bool {
    cfg!(feature = "key-rotation")
        && metadata.author_device_id.is_nil()
        && metadata.kind == SdoKind::Device
        && metadata.device_key_update.is_some()
        && metadata.authority.as_ref().is_some_and(|proof| {
            Some(proof.public_key.as_str()) == header.owner_public_key.as_deref()
        })
}

/// One transition rule for scans, live apply, retries and migration. Old work
/// after the boundary requires the surviving installation's pinned signature.
pub fn object_transition_is_acceptable(
    header: &HeaderDocument,
    metadata: &SdoObjectMetadataV3,
    message_id: i64,
) -> bool {
    let active = header.key_generation.unwrap_or(0);
    if metadata.key_generation > active || !object_authority_is_acceptable(header, metadata) {
        return false;
    }
    let control = is_owner_key_update(header, metadata);
    let boundary = header
        .revocation_cutoffs
        .get(&metadata.author_device_id)
        .map(|cutoff| cutoff.boundary_message_id)
        .unwrap_or_else(|| header.generation_boundary_message_id.unwrap_or(i64::MAX));
    #[cfg(feature = "key-rotation")]
    let receipt = metadata.has_authorized_migration_receipt(header);
    #[cfg(not(feature = "key-rotation"))]
    let receipt = false;
    let source_boundary = header
        .generation_cutoffs
        .get(&metadata.key_generation.saturating_add(1))
        .copied()
        .or_else(|| (metadata.key_generation.saturating_add(1) == active).then_some(boundary));
    let historical =
        metadata.key_generation < active && source_boundary.is_some_and(|cut| message_id < cut);
    if header
        .revoked_device_ids
        .contains(&metadata.author_device_id)
    {
        let Some(cutoff) = header.revocation_cutoffs.get(&metadata.author_device_id) else {
            return false; // No authenticated original cutoff: never infer one from a later rotation.
        };
        return (metadata.key_generation <= cutoff.key_generation
            && message_id < cutoff.boundary_message_id)
            || receipt;
    }
    let pinned = metadata.authority.as_ref().is_some_and(|proof| {
        header.device_authorities.get(&metadata.author_device_id) == Some(&proof.public_key)
    });
    if metadata.key_generation < active {
        return historical || receipt || pinned || control;
    }
    if receipt || control || pinned {
        return true;
    }
    if header
        .device_authorities
        .contains_key(&metadata.author_device_id)
    {
        return false;
    }
    active == 0 || metadata.authority.is_some()
}

/// A complete TGFV format 3 object and its decrypted content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdoFileObjectV3 {
    /// Decrypted authenticated metadata.
    pub metadata: SdoObjectMetadataV3,
    /// Complete decrypted content (empty for zero-segment records).
    pub content: Vec<u8>,
}

/// Parsed TGFV3 framing and authenticated metadata for ranged reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdoObjectHeaderV3 {
    /// Authenticated object metadata.
    pub metadata: SdoObjectMetadataV3,
    /// Header/content boundary in the complete wire object.
    header_end: u64,
}

impl SdoObjectHeaderV3 {
    /// Absolute byte offset of one encrypted segment.
    pub fn segment_offset(&self, index: u32) -> Result<u64> {
        if index >= self.metadata.segment_count {
            return Err(CoreError::Manifest("segment index out of range".into()));
        }
        self.header_end
            .checked_add(u64::from(index) * (u64::from(self.metadata.segment_size) + 16))
            .ok_or_else(|| CoreError::Manifest("segment offset overflow".into()))
    }

    /// Encrypted length of one segment, including its Poly1305 tag.
    pub fn encrypted_segment_len(&self, index: u32) -> Result<u32> {
        if index >= self.metadata.segment_count {
            return Err(CoreError::Manifest("segment index out of range".into()));
        }
        let start = u64::from(index) * u64::from(self.metadata.segment_size);
        Ok((self.metadata.size - start).min(u64::from(self.metadata.segment_size)) as u32 + 16)
    }
}

impl SdoFileObjectV3 {
    /// Authenticate a TGFV3 prefix and encrypted metadata without fetching content segments.
    pub fn decode_header(
        wire: &[u8],
        volume_id: Uuid,
        key_generation: u64,
        meta_key: &SymmetricKey,
    ) -> Result<SdoObjectHeaderV3> {
        if wire.len() < 74
            || &wire[..4] != b"TGFV"
            || u16::from_le_bytes(wire[4..6].try_into().unwrap()) != 3
            || &wire[6..22] != volume_id.as_bytes()
            || u64::from_le_bytes(wire[22..30].try_into().unwrap()) != key_generation
        {
            return Err(CoreError::Manifest(
                "invalid TGFV v3 framing or generation".into(),
            ));
        }
        let body_len = u32::from_le_bytes(wire[30..34].try_into().unwrap()) as usize;
        let header_end = 34usize
            .checked_add(body_len)
            .ok_or_else(|| CoreError::Manifest("TGFV v3 header length overflow".into()))?;
        if body_len < 40 || header_end > wire.len() {
            return Err(CoreError::Manifest("TGFV v3 header length mismatch".into()));
        }
        let mut aad = b"teagarden.sdo.file.v3".to_vec();
        aad.extend_from_slice(&wire[..34]);
        let plain = aead::decrypt(meta_key, &wire[34..header_end], &aad)?;
        let metadata: SdoObjectMetadataV3 =
            serde_json::from_slice(&plain).map_err(|e| CoreError::Serialization(e.to_string()))?;
        metadata.validate()?;
        metadata.verify_authority(volume_id)?;
        if metadata.key_generation != key_generation {
            return Err(CoreError::Manifest(
                "TGFV v3 metadata generation mismatch".into(),
            ));
        }
        let total = (header_end as u64)
            .checked_add(metadata.size)
            .and_then(|n| n.checked_add(u64::from(metadata.segment_count) * 16))
            .ok_or_else(|| CoreError::Manifest("TGFV v3 size overflow".into()))?;
        if total > MAX_SDO_OBJECT_BYTES {
            return Err(CoreError::Manifest(
                "TGFV v3 object exceeds size limit".into(),
            ));
        }
        Ok(SdoObjectHeaderV3 {
            metadata,
            header_end: header_end as u64,
        })
    }

    /// Decrypt one independently authenticated TGFV3 segment.
    pub fn decrypt_segment(
        header: &SdoObjectHeaderV3,
        meta_key: &SymmetricKey,
        index: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let expected = header.encrypted_segment_len(index)? as usize;
        if ciphertext.len() != expected {
            return Err(CoreError::Manifest(
                "TGFV v3 segment length mismatch".into(),
            ));
        }
        let content_key = sdo_v3_content_key(meta_key, header.metadata.version_id)?;
        decrypt_segment_v3(
            &content_key,
            header.metadata.version_id,
            header.metadata.segment_count,
            index,
            ciphertext,
        )
    }

    /// Encode a newly authored record with the installation's signature.
    pub fn encode_with_signer(
        volume_id: Uuid,
        generation: u64,
        meta_key: &SymmetricKey,
        mut metadata: SdoObjectMetadataV3,
        content: &[u8],
        signer: Option<&SigningKey>,
    ) -> Result<Vec<u8>> {
        if let Some(signer) = signer {
            metadata.sign_authority(volume_id, signer, content)?;
        }
        Self::encode(volume_id, generation, meta_key, metadata, content)
    }

    /// Encode metadata and content using a generation-bound TGFV v3 prefix.
    pub fn encode(
        volume_id: Uuid,
        key_generation: u64,
        meta_key: &SymmetricKey,
        mut metadata: SdoObjectMetadataV3,
        content: &[u8],
    ) -> Result<Vec<u8>> {
        if metadata.size > MAX_SDO_FILE_BYTES_PREMIUM {
            return Err(CoreError::Manifest(
                "file exceeds the supported plaintext maximum".into(),
            ));
        }
        if metadata.key_generation != key_generation
            || u64::try_from(content.len()).unwrap_or(u64::MAX) != metadata.size
        {
            return Err(CoreError::Manifest(
                "TGFV v3 generation or content size mismatch".into(),
            ));
        }
        metadata.segment_size = SDO_SEGMENT_SIZE;
        metadata.segment_count = if metadata.kind == SdoKind::File && !metadata.deleted {
            metadata.size.div_ceil(u64::from(SDO_SEGMENT_SIZE)) as u32
        } else {
            0
        };
        metadata.content_sha256 = hex::encode(crate::block::srb2::sha256(content));
        metadata.validate()?;
        metadata.verify_authority(volume_id)?;
        let plain =
            serde_json::to_vec(&metadata).map_err(|e| CoreError::Serialization(e.to_string()))?;
        let body_len = plain
            .len()
            .checked_add(40)
            .ok_or_else(|| CoreError::Manifest("TGFV v3 header length overflow".into()))?;
        if body_len as u64 + 34 > MAX_TGFV3_HEADER_BYTES {
            return Err(CoreError::Manifest("TGFV v3 header too large".into()));
        }
        let mut prefix = Vec::with_capacity(34);
        prefix.extend_from_slice(b"TGFV");
        prefix.extend_from_slice(&3u16.to_le_bytes());
        prefix.extend_from_slice(volume_id.as_bytes());
        prefix.extend_from_slice(&key_generation.to_le_bytes());
        prefix.extend_from_slice(&(body_len as u32).to_le_bytes());
        let mut aad = b"teagarden.sdo.file.v3".to_vec();
        aad.extend_from_slice(&prefix);
        let mut wire = prefix;
        wire.extend_from_slice(&aead::encrypt(meta_key, &plain, &aad)?);
        let content_key = sdo_v3_content_key(meta_key, metadata.version_id)?;
        for (index, chunk) in content.chunks(SDO_SEGMENT_SIZE as usize).enumerate() {
            wire.extend_from_slice(&encrypt_segment_v3(
                &content_key,
                metadata.version_id,
                metadata.segment_count,
                index as u32,
                chunk,
            )?);
        }
        if wire.len() as u64 > MAX_SDO_OBJECT_BYTES {
            return Err(CoreError::Manifest(
                "TGFV v3 object exceeds Telegram limit".into(),
            ));
        }
        Ok(wire)
    }

    /// Decrypt and authenticate a complete TGFV v3 object.
    pub fn decode(
        wire: &[u8],
        volume_id: Uuid,
        key_generation: u64,
        meta_key: &SymmetricKey,
    ) -> Result<Self> {
        if wire.len() < 74
            || &wire[..4] != b"TGFV"
            || u16::from_le_bytes(wire[4..6].try_into().unwrap()) != 3
            || &wire[6..22] != volume_id.as_bytes()
            || u64::from_le_bytes(wire[22..30].try_into().unwrap()) != key_generation
        {
            return Err(CoreError::Manifest(
                "invalid TGFV v3 framing or generation".into(),
            ));
        }
        let body_len = u32::from_le_bytes(wire[30..34].try_into().unwrap()) as usize;
        let header_end = 34usize
            .checked_add(body_len)
            .ok_or_else(|| CoreError::Manifest("TGFV v3 header length overflow".into()))?;
        if body_len < 40 || header_end > wire.len() {
            return Err(CoreError::Manifest("TGFV v3 header length mismatch".into()));
        }
        let mut aad = b"teagarden.sdo.file.v3".to_vec();
        aad.extend_from_slice(&wire[..34]);
        let plain = aead::decrypt(meta_key, &wire[34..header_end], &aad)?;
        let metadata: SdoObjectMetadataV3 =
            serde_json::from_slice(&plain).map_err(|e| CoreError::Serialization(e.to_string()))?;
        metadata.validate()?;
        metadata.verify_authority(volume_id)?;
        if metadata.key_generation != key_generation {
            return Err(CoreError::Manifest(
                "TGFV v3 metadata generation mismatch".into(),
            ));
        }
        let total = (header_end as u64)
            .checked_add(metadata.size)
            .and_then(|n| n.checked_add(u64::from(metadata.segment_count) * 16))
            .ok_or_else(|| CoreError::Manifest("TGFV v3 size overflow".into()))?;
        if total != wire.len() as u64 {
            let payload_end = ObjectEnvelope::authenticate(wire, meta_key)?;
            if total != payload_end as u64 {
                return Err(CoreError::Manifest(
                    "TGFV v3 length mismatch before credential envelope".into(),
                ));
            }
        }
        let content_key = sdo_v3_content_key(meta_key, metadata.version_id)?;
        let mut content = Vec::with_capacity(metadata.size as usize);
        let mut offset = header_end;
        for index in 0..metadata.segment_count {
            let start = u64::from(index) * u64::from(metadata.segment_size);
            let plain_len = (metadata.size - start).min(u64::from(metadata.segment_size)) as usize;
            let end = offset + plain_len + 16;
            content.extend_from_slice(&decrypt_segment_v3(
                &content_key,
                metadata.version_id,
                metadata.segment_count,
                index,
                &wire[offset..end],
            )?);
            offset = end;
        }
        let actual = hex::encode(crate::block::srb2::sha256(&content));
        if actual != metadata.content_sha256 {
            return Err(CoreError::IntegrityError {
                expected: metadata.content_sha256,
                actual,
            });
        }
        Ok(Self { metadata, content })
    }
}

/// Re-encrypt one complete TGFV3 history object under a newer key generation.
/// Authenticated logical metadata and plaintext stay byte-for-byte equivalent;
/// only the generation field and physical ciphertext change.
#[cfg(feature = "key-rotation")]
pub fn reencrypt_v3_history(
    wire: &[u8],
    volume_id: Uuid,
    old_generation: u64,
    old_meta_key: &SymmetricKey,
    new_generation: u64,
    new_meta_key: &SymmetricKey,
) -> Result<Vec<u8>> {
    if new_generation <= old_generation {
        return Err(CoreError::Manifest(
            "history migration requires a strictly newer key generation".into(),
        ));
    }
    let mut object = SdoFileObjectV3::decode(wire, volume_id, old_generation, old_meta_key)?;
    object.metadata.key_generation = new_generation;
    SdoFileObjectV3::encode(
        volume_id,
        new_generation,
        new_meta_key,
        object.metadata,
        &object.content,
    )
}

fn validate_sdo_path(path: &str) -> Result<()> {
    let parts: Vec<&str> = path.split('/').collect();
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.contains('\0')
        || parts.len() > 256
        || parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(CoreError::Manifest("invalid relative path".into()));
    }
    Ok(())
}

fn sdo_v3_content_key(meta_key: &SymmetricKey, version_id: Uuid) -> Result<SymmetricKey> {
    let mut info = b"teagarden.sdo.content.v3".to_vec();
    info.extend_from_slice(version_id.as_bytes());
    crate::crypto::kdf::hkdf_derive(meta_key, &info)
}

fn sdo_v3_segment_nonce(key: &SymmetricKey, version_id: Uuid, index: u32) -> [u8; 24] {
    let mut input = b"teagarden.sdo.segment.v3nonce".to_vec();
    input.extend_from_slice(version_id.as_bytes());
    input.extend_from_slice(&index.to_le_bytes());
    crate::crypto::blake3::keyed_hash(key, &input)[..24]
        .try_into()
        .unwrap()
}

fn encrypt_segment_v3(
    key: &SymmetricKey,
    version_id: Uuid,
    count: u32,
    index: u32,
    plain: &[u8],
) -> Result<Vec<u8>> {
    let nonce = sdo_v3_segment_nonce(key, version_id, index);
    let mut aad = b"teagarden.sdo.segment.v3".to_vec();
    aad.extend_from_slice(version_id.as_bytes());
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&count.to_le_bytes());
    aad.push(u8::from(index + 1 == count));
    XChaCha20Poly1305::new(key.as_bytes().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|e| CoreError::Encryption(e.to_string()))
}

fn decrypt_segment_v3(
    key: &SymmetricKey,
    version_id: Uuid,
    count: u32,
    index: u32,
    cipher: &[u8],
) -> Result<Vec<u8>> {
    let nonce = sdo_v3_segment_nonce(key, version_id, index);
    let mut aad = b"teagarden.sdo.segment.v3".to_vec();
    aad.extend_from_slice(version_id.as_bytes());
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&count.to_le_bytes());
    aad.push(u8::from(index + 1 == count));
    XChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: cipher,
                aad: &aad,
            },
        )
        .map_err(|e| CoreError::Decryption(e.to_string()))
}

impl SdoObjectMetadata {
    /// Test fixture containing a zero-length file.
    #[doc(hidden)]
    pub fn test_fixture() -> Self {
        Self {
            file_id: Uuid::from_bytes([6; 16]),
            origin_message_id: None,
            path: "hello.txt".into(),
            size: 0,
            mtime_ns: 0,
            mode: 0o600,
            version_id: Uuid::from_bytes([4; 16]),
            author_device_id: Uuid::from_bytes([5; 16]),
            previous_version_id: None,
            saved_at_ns: 1,
            local_version: 1,
            deleted: false,
            segment_size: SDO_SEGMENT_SIZE,
            segment_count: 0,
            content_sha256: hex::encode(crate::block::srb2::sha256(b"")),
        }
    }

    fn validate(&self) -> Result<()> {
        let components: Vec<&str> = self.path.split('/').collect();
        if self.path.is_empty()
            || self.path.len() > 4096
            || self.path.starts_with('/')
            || self.path.contains('\0')
            || components.len() > 256
            || components
                .iter()
                .any(|p| p.is_empty() || *p == "." || *p == "..")
        {
            return Err(CoreError::Manifest("invalid relative path".into()));
        }
        if self.size > MAX_SDO_OBJECT_BYTES || self.segment_size != SDO_SEGMENT_SIZE {
            return Err(CoreError::Manifest(
                "TGFV v2 size or segment bounds exceeded".into(),
            ));
        }
        let expected = self.size.div_ceil(u64::from(self.segment_size));
        if expected != u64::from(self.segment_count) || (self.deleted && self.size != 0) {
            return Err(CoreError::Manifest("invalid TGFV v2 segment layout".into()));
        }
        let digest = hex::decode(&self.content_sha256)
            .map_err(|e| CoreError::Manifest(format!("invalid content hash: {e}")))?;
        if digest.len() != 32 || self.content_sha256 != self.content_sha256.to_ascii_lowercase() {
            return Err(CoreError::Manifest("invalid content SHA-256".into()));
        }
        Ok(())
    }
}

/// Parsed public framing plus authenticated encrypted metadata for a TGFV v2 object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdoObjectHeader {
    /// Volume identity from the public framing.
    pub volume_id: Uuid,
    /// Decrypted, authenticated object metadata.
    pub metadata: SdoObjectMetadata,
    header_end: u64,
}

impl SdoObjectHeader {
    /// Compute the absolute byte offset of a segment in the complete object.
    pub fn segment_offset(&self, index: u32) -> Result<u64> {
        if index >= self.metadata.segment_count {
            return Err(CoreError::Manifest("segment index out of range".into()));
        }
        self.header_end
            .checked_add(u64::from(index) * (u64::from(self.metadata.segment_size) + 16))
            .ok_or_else(|| CoreError::Manifest("segment offset overflow".into()))
    }

    /// Ciphertext length for one segment, including the 16-byte AEAD tag.
    pub fn encrypted_segment_len(&self, index: u32) -> Result<u32> {
        if index >= self.metadata.segment_count {
            return Err(CoreError::Manifest("segment index out of range".into()));
        }
        let start = u64::from(index) * u64::from(self.metadata.segment_size);
        let plain = (self.metadata.size - start).min(u64::from(self.metadata.segment_size));
        Ok(plain as u32 + 16)
    }
}

/// One complete TGFV v2 Telegram object, with authenticated per-segment content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdoFileObject {
    /// Decrypted metadata.
    pub metadata: SdoObjectMetadata,
    /// Complete decrypted file content.
    pub content: Vec<u8>,
}

impl SdoFileObject {
    /// Encode one whole file as an encrypted metadata header and encrypted segments.
    pub fn encode(
        volume_id: Uuid,
        meta_key: &SymmetricKey,
        mut metadata: SdoObjectMetadata,
        content: &[u8],
    ) -> Result<Vec<u8>> {
        if u64::try_from(content.len()).unwrap_or(u64::MAX) != metadata.size {
            return Err(CoreError::Manifest(
                "content size does not match metadata".into(),
            ));
        }
        metadata.segment_size = SDO_SEGMENT_SIZE;
        metadata.segment_count = metadata.size.div_ceil(u64::from(SDO_SEGMENT_SIZE)) as u32;
        metadata.content_sha256 = hex::encode(crate::block::srb2::sha256(content));
        metadata.validate()?;
        let plain =
            serde_json::to_vec(&metadata).map_err(|e| CoreError::Serialization(e.to_string()))?;
        let body_len = plain
            .len()
            .checked_add(40)
            .ok_or_else(|| CoreError::Manifest("TGFV header length overflow".into()))?;
        if body_len > u32::MAX as usize {
            return Err(CoreError::Manifest("TGFV header too large".into()));
        }
        let mut prefix = Vec::with_capacity(26);
        prefix.extend_from_slice(b"TGFV");
        prefix.extend_from_slice(&2u16.to_le_bytes());
        prefix.extend_from_slice(volume_id.as_bytes());
        prefix.extend_from_slice(&(body_len as u32).to_le_bytes());
        let mut aad = b"teagarden.sdo.file.v2".to_vec();
        aad.extend_from_slice(&prefix);
        let encrypted_header = aead::encrypt(meta_key, &plain, &aad)?;
        let mut wire = prefix;
        wire.extend_from_slice(&encrypted_header);
        let content_key = sdo_content_key(meta_key, metadata.version_id)?;
        for (index, chunk) in content.chunks(SDO_SEGMENT_SIZE as usize).enumerate() {
            wire.extend_from_slice(&encrypt_segment(
                &content_key,
                &metadata,
                index as u32,
                chunk,
            )?);
        }
        if wire.len() as u64 > MAX_SDO_OBJECT_BYTES {
            return Err(CoreError::Manifest(
                "TGFV v2 object exceeds Telegram limit".into(),
            ));
        }
        Ok(wire)
    }

    /// Authenticate and decode only the TGFV v2 framing and encrypted header.
    pub fn decode_header(
        wire: &[u8],
        volume_id: Uuid,
        meta_key: &SymmetricKey,
    ) -> Result<SdoObjectHeader> {
        if wire.len() < 66
            || &wire[..4] != b"TGFV"
            || u16::from_le_bytes([wire[4], wire[5]]) != 2
            || &wire[6..22] != volume_id.as_bytes()
        {
            return Err(CoreError::Manifest(
                "invalid TGFV v2 framing or volume id".into(),
            ));
        }
        let body_len = u32::from_le_bytes(wire[22..26].try_into().unwrap()) as usize;
        if body_len < 40 || wire.len() < 26 + body_len {
            return Err(CoreError::Manifest("TGFV v2 header length mismatch".into()));
        }
        let header_end = 26 + body_len;
        let mut aad = b"teagarden.sdo.file.v2".to_vec();
        aad.extend_from_slice(&wire[..26]);
        let plain = aead::decrypt(meta_key, &wire[26..header_end], &aad)?;
        let metadata: SdoObjectMetadata =
            serde_json::from_slice(&plain).map_err(|e| CoreError::Serialization(e.to_string()))?;
        metadata.validate()?;
        let total = (header_end as u64)
            .checked_add(metadata.size)
            .and_then(|n| n.checked_add(u64::from(metadata.segment_count) * 16))
            .ok_or_else(|| CoreError::Manifest("TGFV v2 object size overflow".into()))?;
        if total > MAX_SDO_OBJECT_BYTES {
            return Err(CoreError::Manifest(
                "TGFV v2 object exceeds Telegram limit".into(),
            ));
        }
        Ok(SdoObjectHeader {
            volume_id,
            metadata,
            header_end: header_end as u64,
        })
    }

    /// Decrypt one independently authenticated content segment.
    pub fn decrypt_segment(
        header: &SdoObjectHeader,
        meta_key: &SymmetricKey,
        index: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let expected = header.encrypted_segment_len(index)? as usize;
        if ciphertext.len() != expected {
            return Err(CoreError::Manifest(
                "TGFV v2 segment length mismatch".into(),
            ));
        }
        let content_key = sdo_content_key(meta_key, header.metadata.version_id)?;
        let nonce = segment_nonce(&content_key, header.metadata.version_id, index);
        let aad = segment_aad(&header.metadata, index);
        let cipher = XChaCha20Poly1305::new(content_key.as_bytes().into());
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| CoreError::Decryption(e.to_string()))
    }

    /// Decrypt a complete downloaded object and verify the whole-content digest.
    pub fn decode(wire: &[u8], volume_id: Uuid, meta_key: &SymmetricKey) -> Result<Self> {
        let header = Self::decode_header(wire, volume_id, meta_key)?;
        let expected_len = header.header_end
            + header.metadata.size
            + u64::from(header.metadata.segment_count) * 16;
        if expected_len != wire.len() as u64 {
            return Err(CoreError::Manifest(
                "TGFV v2 object is truncated or has trailing bytes".into(),
            ));
        }
        let mut content = Vec::with_capacity(header.metadata.size as usize);
        for index in 0..header.metadata.segment_count {
            let start = header.segment_offset(index)? as usize;
            let len = header.encrypted_segment_len(index)? as usize;
            content.extend_from_slice(&Self::decrypt_segment(
                &header,
                meta_key,
                index,
                &wire[start..start + len],
            )?);
        }
        if hex::encode(crate::block::srb2::sha256(&content)) != header.metadata.content_sha256 {
            return Err(CoreError::IntegrityError {
                expected: header.metadata.content_sha256,
                actual: hex::encode(crate::block::srb2::sha256(&content)),
            });
        }
        Ok(Self {
            metadata: header.metadata,
            content,
        })
    }
}

fn sdo_content_key(meta_key: &SymmetricKey, version_id: Uuid) -> Result<SymmetricKey> {
    let mut info = b"teagarden.sdo.content.v2".to_vec();
    info.extend_from_slice(version_id.as_bytes());
    crate::crypto::kdf::hkdf_derive(meta_key, &info)
}

fn segment_nonce(key: &SymmetricKey, version_id: Uuid, index: u32) -> [u8; 24] {
    let mut input = SEGMENT_AAD_CONTEXT.to_vec();
    input.extend_from_slice(b"nonce");
    input.extend_from_slice(version_id.as_bytes());
    input.extend_from_slice(&index.to_le_bytes());
    crate::crypto::blake3::keyed_hash(key, &input)[..24]
        .try_into()
        .unwrap()
}

fn segment_aad(metadata: &SdoObjectMetadata, index: u32) -> Vec<u8> {
    let mut aad = SEGMENT_AAD_CONTEXT.to_vec();
    aad.extend_from_slice(metadata.version_id.as_bytes());
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&metadata.segment_count.to_le_bytes());
    aad.push(u8::from(index + 1 == metadata.segment_count));
    aad
}

fn encrypt_segment(
    key: &SymmetricKey,
    metadata: &SdoObjectMetadata,
    index: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = segment_nonce(key, metadata.version_id, index);
    let aad = segment_aad(metadata, index);
    XChaCha20Poly1305::new(key.as_bytes().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| CoreError::Encryption(e.to_string()))
}

impl SdoManifest {
    /// Encrypt a TGFV object using the metadata key and volume-bound AAD.
    pub fn encode(&self, volume_id: Uuid, meta_key: &SymmetricKey) -> Result<Vec<u8>> {
        self.validate()?;
        let plain =
            serde_json::to_vec(self).map_err(|e| CoreError::Serialization(e.to_string()))?;
        let body_len = plain
            .len()
            .checked_add(40)
            .ok_or_else(|| CoreError::Manifest("TGFV length overflow".into()))?;
        if body_len > u32::MAX as usize || body_len + 26 > MAX_MANIFEST_SIZE {
            return Err(CoreError::Manifest("TGFV exceeds size limit".into()));
        }
        let mut prefix = Vec::with_capacity(26);
        prefix.extend_from_slice(b"TGFV");
        prefix.extend_from_slice(&1u16.to_le_bytes());
        prefix.extend_from_slice(volume_id.as_bytes());
        prefix.extend_from_slice(&(body_len as u32).to_le_bytes());
        let mut aad = Vec::with_capacity(MANIFEST_AAD_CONTEXT.len() + prefix.len());
        aad.extend_from_slice(MANIFEST_AAD_CONTEXT);
        aad.extend_from_slice(&prefix);
        let body = aead::encrypt(meta_key, &plain, &aad)?;
        let mut wire = prefix;
        wire.extend_from_slice(&body);
        Ok(wire)
    }

    /// Decrypt and validate a TGFV object for the expected volume.
    pub fn decode(wire: &[u8], volume_id: Uuid, meta_key: &SymmetricKey) -> Result<Self> {
        if wire.len() < 66 || wire.len() > MAX_MANIFEST_SIZE || &wire[..4] != b"TGFV" {
            return Err(CoreError::Manifest("invalid TGFV framing".into()));
        }
        if u16::from_le_bytes([wire[4], wire[5]]) != 1 || &wire[6..22] != volume_id.as_bytes() {
            return Err(CoreError::Manifest(
                "unsupported TGFV version or volume id".into(),
            ));
        }
        let body_len = u32::from_le_bytes(wire[22..26].try_into().unwrap()) as usize;
        if body_len != wire.len() - 26 || body_len < 40 {
            return Err(CoreError::Manifest("TGFV body length mismatch".into()));
        }
        let mut aad = Vec::with_capacity(MANIFEST_AAD_CONTEXT.len() + 26);
        aad.extend_from_slice(MANIFEST_AAD_CONTEXT);
        aad.extend_from_slice(&wire[..26]);
        let plain = aead::decrypt(meta_key, &wire[26..], &aad)?;
        let manifest: Self =
            serde_json::from_slice(&plain).map_err(|e| CoreError::Serialization(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        let components: Vec<&str> = self.path.split('/').collect();
        if self.path.is_empty()
            || self.path.len() > 4096
            || self.path.starts_with('/')
            || self.path.contains('\0')
            || components.len() > 256
            || components
                .iter()
                .any(|p| p.is_empty() || *p == "." || *p == "..")
        {
            return Err(CoreError::Manifest("invalid relative path".into()));
        }
        if self.size > 64 * 1024 * 1024 * 1024 || self.blocks.len() > MAX_BLOCK_REFS {
            return Err(CoreError::Manifest("manifest bounds exceeded".into()));
        }
        if self.deleted && (!self.blocks.is_empty() || self.size != 0) {
            return Err(CoreError::Manifest(
                "tombstone must not contain file data".into(),
            ));
        }
        let mut cursor = 0u64;
        for block in &self.blocks {
            if block.file_offset != cursor || block.length == 0 {
                return Err(CoreError::Manifest(
                    "block refs must be ordered, non-overlapping, and contiguous".into(),
                ));
            }
            let slice_end = block
                .block_data_offset
                .checked_add(block.length)
                .ok_or_else(|| CoreError::Manifest("block slice overflow".into()))?;
            cursor = block
                .file_offset
                .checked_add(block.length)
                .ok_or_else(|| CoreError::Manifest("file offset overflow".into()))?;
            if slice_end > block.plaintext_size {
                return Err(CoreError::Manifest("block slice exceeds plaintext".into()));
            }
            for value in [&block.block_id, &block.cipher_sha256, &block.plain_sha256] {
                let decoded = hex::decode(value)
                    .map_err(|e| CoreError::Manifest(format!("invalid hash: {e}")))?;
                if decoded.len() != 32 || value != &value.to_ascii_lowercase() {
                    return Err(CoreError::Manifest(
                        "hash must be 32-byte lowercase hex".into(),
                    ));
                }
            }
        }
        if cursor != self.size {
            return Err(CoreError::Manifest(
                "block refs do not cover the file size".into(),
            ));
        }
        Ok(())
    }

    /// Test-only simple file version fixture.
    #[doc(hidden)]
    pub fn test_fixture() -> Self {
        Self {
            file_id: Uuid::from_bytes([6; 16]),
            origin_message_id: None,
            path: "hello.txt".into(),
            size: 0,
            mtime_ns: 0,
            mode: 0o600,
            version_id: Uuid::from_bytes([4; 16]),
            author_device_id: Uuid::from_bytes([5; 16]),
            previous_version_id: None,
            saved_at_ns: 1,
            local_version: 1,
            blocks: vec![],
            deleted: false,
        }
    }
}

#[cfg(test)]
mod vector_fixture {
    use super::*;
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};

    fn fixed_nonce_encrypt(
        key: &SymmetricKey,
        nonce: [u8; 24],
        plain: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload { msg: plain, aad },
            )
            .unwrap();
        [nonce.as_slice(), encrypted.as_slice()].concat()
    }

    #[test]
    fn password_header_manifest_block_vector_matches_committed_fixture() {
        use crate::crypto::kdf::{derive_epoch_key, derive_hierarchy_v1, derive_root_key};

        let salt = [0x01; 32];
        let group = -100123i64;
        let topic = 456i64;
        let root = derive_root_key(
            b"vector-password",
            &salt,
            &Argon2Params {
                memory_kib: 1024,
                iterations: 1,
                parallelism: 1,
                output_len: 32,
            },
        )
        .unwrap();
        let hierarchy = derive_hierarchy_v1(root, &salt, group, topic).unwrap();

        let mut header = HeaderDocument::test_fixture();
        header.volume_id = Uuid::from_bytes([0x11; 16]);
        header.salt = hex::encode(salt);
        header.group_id = group;
        header.topic_id = topic;
        let header_wire = header.encode(&hierarchy.integrity).unwrap();

        let epoch_key = derive_epoch_key(&hierarchy.data, 0).unwrap();
        let block_id = crate::crypto::blake3::keyed_hash(&epoch_key.key, b"hello\n");
        let block_aad = crate::block::aad::block_aad(0, &block_id, Some(0));
        let block_wire = fixed_nonce_encrypt(&epoch_key.key, [0x33; 24], b"hello\n", &block_aad);
        let cipher_hash = crate::block::srb2::sha256(&block_wire);
        let plain_hash = crate::block::srb2::sha256(b"hello\n");

        let manifest = SdoManifest {
            file_id: Uuid::from_bytes([0x66; 16]),
            origin_message_id: None,
            path: "hello.txt".into(),
            size: 6,
            mtime_ns: 1_700_000_000,
            mode: 0o600,
            version_id: Uuid::from_bytes([0x22; 16]),
            author_device_id: Uuid::from_bytes([0x33; 16]),
            previous_version_id: None,
            saved_at_ns: 1_700_000_001,
            local_version: 1,
            deleted: false,
            blocks: vec![SdoBlockRef {
                message_id: 77,
                block_id: hex::encode(block_id),
                plaintext_size: 6,
                epoch: 0,
                file_offset: 0,
                block_data_offset: 0,
                length: 6,
                encrypted_size: block_wire.len() as u64,
                compressed: false,
                cipher_sha256: hex::encode(cipher_hash),
                plain_sha256: hex::encode(plain_hash),
            }],
        };
        let plain = serde_json::to_vec(&manifest).unwrap();
        let body_len = plain.len() + 40;
        let mut prefix = b"TGFV\x01\x00".to_vec();
        prefix.extend_from_slice(Uuid::from_bytes([0x11; 16]).as_bytes());
        prefix.extend_from_slice(&(body_len as u32).to_le_bytes());
        let mut aad = MANIFEST_AAD_CONTEXT.to_vec();
        aad.extend_from_slice(&prefix);
        let body = fixed_nonce_encrypt(&hierarchy.meta, [0x44; 24], &plain, &aad);
        let mut manifest_wire = prefix;
        manifest_wire.extend_from_slice(&body);

        let generated = format!(
            "root={}\nheader={}\nblock={}\nmanifest={}\nmanifest_plain={}\n",
            hex::encode(hierarchy.root.as_bytes()),
            hex::encode(header_wire),
            hex::encode(block_wire),
            hex::encode(manifest_wire),
            String::from_utf8(plain).unwrap(),
        );
        assert_eq!(
            generated,
            include_str!("sdo_password_block_vector.fixture"),
            "synthetic password/header/block/manifest fixture changed"
        );
    }
}

#[cfg(test)]
mod registry_revocation_tests {
    use super::*;

    #[test]
    fn owner_revocations_filter_device_ids_and_session_bindings() {
        let make = |id: u8, binding: &str| DeviceAnnouncement {
            installation_id: Uuid::from_bytes([id; 16]),
            label: "computer".into(),
            telegram_user_id: 42,
            authorization_session_hash: Some(binding.into()),
            public_key: None,
            key_update: None,
            created_at_ms: 1,
            clock_ms: 1,
            clock_counter: 0,
            author_device_id: Uuid::from_bytes([id; 16]),
            version_id: Uuid::from_bytes([id + 10; 16]),
        };
        let mut registry =
            DeviceRegistry::from_announcements([make(1, "session-a"), make(2, "session-b")])
                .unwrap();
        registry.apply_revocations(&[Uuid::from_bytes([2; 16])], &["session-a".into()]);
        assert!(registry.is_empty());
    }
}

#[cfg(test)]
#[cfg(feature = "key-rotation")]
mod key_generation_bridge_tests {
    use super::*;

    #[test]
    fn generation_boundary_accepts_old_objects_only_before_header_message() {
        assert!(generation_is_acceptable(0, 1, 41, 42));
        assert!(!generation_is_acceptable(0, 1, 42, 42));
        assert!(!generation_is_acceptable(0, 1, 43, 42));
        assert!(generation_is_acceptable(1, 1, 43, 42));
        assert!(!generation_is_acceptable(2, 1, 41, 42));
    }

    #[test]
    fn reencrypt_v3_history_preserves_logical_metadata_and_plaintext() {
        let volume_id = Uuid::new_v4();
        let old_key = SymmetricKey::from_bytes([0x51; 32]);
        let new_key = SymmetricKey::from_bytes([0x62; 32]);
        let content = b"retained historical bytes";
        let metadata = SdoObjectMetadataV3 {
            authority: None,
            migration_receipt: None,
            file_id: Uuid::new_v4(),
            origin_message_id: Some(41),
            path: Some("archive/old.txt".into()),
            size: content.len() as u64,
            mtime_ns: 77,
            mode: 0o640,
            version_id: Uuid::new_v4(),
            author_device_id: Uuid::new_v4(),
            previous_version_id: Some(Uuid::new_v4()),
            kind: SdoKind::File,
            key_generation: 0,
            clock_ms: 88,
            clock_counter: 3,
            saved_at_ns: 66,
            local_version: 9,
            deleted: false,
            installation_id: None,
            label: None,
            telegram_user_id: None,
            authorization_session_hash: None,
            created_at_ms: None,
            device_public_key: None,
            device_key_update: None,
            segment_size: SDO_SEGMENT_SIZE,
            segment_count: 1,
            content_sha256: hex::encode(crate::block::srb2::sha256(content)),
        };
        let original =
            SdoFileObjectV3::encode(volume_id, 0, &old_key, metadata.clone(), content).unwrap();
        let replacement =
            reencrypt_v3_history(&original, volume_id, 0, &old_key, 1, &new_key).unwrap();
        let decoded = SdoFileObjectV3::decode(&replacement, volume_id, 1, &new_key).unwrap();
        let mut expected = metadata;
        expected.key_generation = 1;
        assert_eq!(decoded.metadata, expected);
        assert_eq!(decoded.content, content);
        assert!(SdoFileObjectV3::decode(&replacement, volume_id, 0, &old_key).is_err());
    }

    #[test]
    fn generation_bridge_wraps_previous_root_and_salt_under_new_hierarchy() {
        let old_root = SymmetricKey::from_bytes([0x19; 32]);
        let new_wrapping_key = SymmetricKey::from_bytes([0x2a; 32]);
        let wrong_wrapping_key = SymmetricKey::from_bytes([0x3b; 32]);
        let old_salt = [0x4c; 32];
        let bridge = KeyGenerationBridge::wrap(1, &old_salt, &old_root, &new_wrapping_key).unwrap();
        let (recovered_root, recovered_salt) = bridge.unwrap(&new_wrapping_key).unwrap();
        assert_eq!(recovered_root.as_bytes(), old_root.as_bytes());
        assert_eq!(recovered_salt, old_salt);
        assert!(bridge.unwrap(&wrong_wrapping_key).is_err());

        let mut altered = bridge;
        altered.key_generation = 2;
        assert!(altered.unwrap(&new_wrapping_key).is_err());
    }
}

#[cfg(test)]
mod multicomputer_acceptance;

#[cfg(test)]
#[cfg(feature = "key-rotation")]
mod transition_tests {
    use super::*;
    #[test]
    fn transition_authority_blocks_impersonation_and_preserves_attested_history() {
        let c = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c_key = SigningKey::from_bytes(&[0x11; 32]);
        let b_key = SigningKey::from_bytes(&[0x22; 32]);
        let owner = SigningKey::from_bytes(&[0x33; 32]);
        let mut header = HeaderDocument::test_fixture();
        header.format = 2;
        header.key_generation = Some(1);
        header.generation_boundary_message_id = Some(100);
        header.owner_public_key = Some(hex::encode(owner.verifying_key().to_bytes()));
        header
            .device_authorities
            .insert(c, hex::encode(c_key.verifying_key().to_bytes()));
        header.revoked_device_ids.push(b);
        header.revocation_cutoffs.insert(
            b,
            RevocationCutoff {
                key_generation: 1,
                boundary_message_id: 100,
            },
        );
        header.generation_cutoffs.insert(1, 100);
        let mut metadata = legacy_metadata_v3(&SdoObjectMetadata::test_fixture());
        metadata.author_device_id = c;
        metadata
            .sign_authority(header.volume_id, &c_key, &[])
            .unwrap();
        assert!(object_transition_is_acceptable(&header, &metadata, 101));
        metadata
            .sign_authority(header.volume_id, &b_key, &[])
            .unwrap();
        assert!(
            !object_transition_is_acceptable(&header, &metadata, 101),
            "a shared-key holder cannot claim C's authority"
        );
        metadata.author_device_id = b;
        metadata
            .sign_authority(header.volume_id, &b_key, &[])
            .unwrap();
        assert!(!object_transition_is_acceptable(&header, &metadata, 101));
        assert!(object_transition_is_acceptable(&header, &metadata, 99));
        metadata.key_generation = 1;
        metadata
            .attest_migration(header.volume_id, 99, &owner)
            .unwrap();
        assert!(
            object_transition_is_acceptable(&header, &metadata, 150),
            "owner-attested pre-revoke history is retained"
        );
        metadata.clock_counter += 1;
        assert!(!object_transition_is_acceptable(&header, &metadata, 150));
    }
}
