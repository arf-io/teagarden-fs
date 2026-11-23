//! The key-slot vault (v2) core — the ONLY code that touches the master key and
//! the uniform AEAD wrap. Slot-agnostic: every slot, whatever its factor, ends in
//! `payload_ct = aead::encrypt(KEK, payload_plain, slot_aad(...))`; how the KEK is
//! obtained is the protector's job ([`crate::kslot::SlotProtector`]).
//!
//! ## Security model (user-facing summary: `docs/SECURITY_MODEL.md` §8; the
//! on-disk format is in `docs/FORMAT.md` §5)
//!
//! - MK is random at [`SlotVault::create`]; each any-1 slot wraps MK, each
//!   threshold-group member wraps a Shamir share of MK.
//! - Each payload's AAD binds `vault_uuid ‖ slot_id ‖ slot_type ‖ share_gen ‖
//!   payload_kind` — defeating cross-vault / cross-slot / cross-generation /
//!   share-vs-key swaps (all fail closed).
//! - The full policy is NOT in the per-slot AAD (that would force re-wrapping
//!   every slot on any policy edit — impossible for `Derived` factors without
//!   their live input). Instead the policy is protected by `policy_mac`, a keyed
//!   BLAKE3 under a key derived from MK, verified AFTER MK recovery. Downgrade is
//!   also defeated structurally: payload CONTENT (MK vs share) is fixed at enroll
//!   and cannot change without MK, and the recovered MK is checked against
//!   `mk_commitment` (constant-time).
//! - Adding an independent (any-1) slot re-wraps NOTHING else; only creating or
//!   re-splitting a threshold group touches its members (which needs their inputs,
//!   the LUKS2 "need a key to change keys" reality).

use std::io::Write as IoWrite;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use teagarden_core::crypto::aead;

use crate::error::{MfaError, Result};

use super::aad::{mk_commitment, policy_mac, slot_aad};
use super::policy::{combine_shares, split_master_key, Policy, PolicyEntry};
use super::protector::{KekTransport, SlotProtector};
use super::types::{zeroize_vec, MasterKey, PayloadKind, SlotId, SlotType};

/// Current on-disk vault format version.
pub const VAULT_V2_VERSION: u32 = 2;

/// Maximum number of slots a vault may hold (mfa-L2). Same as LUKS2's keyslot
/// limit. Enforced at enroll and at load: every KDF-backed slot is an Argon2
/// run of up to 4 GiB, so an unbounded slot list in an attacker-writable file
/// turned one unlock attempt into an arbitrary amount of work.
pub const MAX_SLOTS: usize = 32;

/// One persisted slot record.
#[derive(Clone, Serialize, Deserialize)]
struct SlotRecord {
    slot_id: SlotId,
    slot_type: SlotType,
    label: String,
    enabled: bool,
    /// Non-secret per-factor params.
    params: serde_json::Value,
    kek_transport: KekTransport,
    /// `true` if the payload is a Shamir share; `false` if it is the full MK.
    payload_is_share: bool,
    /// Threshold generation (0 for MK-payload slots); bound into the AAD.
    share_gen: u32,
    /// `aead::encrypt(KEK, payload_plain, aad)` — nonce embedded — base64.
    payload_ct_b64: String,
}

impl SlotRecord {
    fn payload_kind(&self) -> PayloadKind {
        if self.payload_is_share {
            PayloadKind::Share
        } else {
            PayloadKind::MasterKey
        }
    }
}

/// The persisted v2 vault file.
#[derive(Clone, Serialize, Deserialize)]
struct VaultFileV2 {
    version: u32,
    vault_uuid_hex: String,
    subject_id: String,
    mk_commitment_hex: String,
    policy_mac_hex: String,
    next_slot_id: SlotId,
    next_share_gen: u32,
    /// Monotonic generation, bumped on EVERY mutation (enroll / remove / policy
    /// change). By itself this does NOT prove freshness — a self-contained MAC
    /// inside a rollbackable file cannot (audit K0A-1). K0b anchors
    /// `(generation, state_digest)` in the volume/device config-integrity chain
    /// (which the master key authenticates) and refuses a stale vault. Until
    /// then, replacing `mfa_vault.json` with an older copy is an accepted,
    /// documented residual — do NOT claim revocation is enforced pre-K0b.
    #[serde(default)]
    vault_generation: u64,
    policy: Policy,
    slots: Vec<SlotRecord>,
}

#[cfg(test)]
impl SlotVault {
    /// TEST FIXTURE: graft a slot of an arbitrary `SlotType` into the vault.
    ///
    /// The durable-opener invariant only triggers when a **device-bound** slot
    /// (FIDO2 / TPM2 / PKCS#11 / Tang) survives a removal, and none of those can
    /// be enrolled in a unit test without the physical hardware. Without this the
    /// invariant would be shipped untested — which is how the FIDO2 lockout got
    /// as far as it did.
    ///
    /// This inserts a record and a matching policy entry directly. It is a
    /// fixture over our own struct, not a mock of behaviour: `remove_slot` sees
    /// exactly the shape a real device enrollment would produce.
    pub(crate) fn test_graft_slot(
        &mut self,
        mk: &MasterKey,
        slot_type: SlotType,
        label: &str,
    ) -> SlotId {
        let slot_id = self.file.next_slot_id;
        self.file.next_slot_id += 1;
        self.file.slots.push(SlotRecord {
            slot_id,
            slot_type,
            label: label.to_string(),
            enabled: true,
            params: serde_json::json!({}),
            kek_transport: KekTransport::Derived,
            payload_is_share: false,
            share_gen: 0,
            payload_ct_b64: String::new(),
        });
        self.file.policy.entries.push(PolicyEntry::Slot { slot_id });
        self.bump_generation();
        self.refresh_policy_mac(mk);
        slot_id
    }

    /// TEST FIXTURE: replace the policy with a single k-of-n group over existing
    /// slots, without re-splitting the master key.
    ///
    /// The durable-opener invariant has to reason about groups, and a group whose
    /// members are device-bound cannot be built in a unit test for the same reason
    /// as `test_graft_slot`. This rewrites only the policy — the slot records are
    /// whatever the caller grafted — which is exactly the shape `remove_slot`
    /// inspects.
    pub(crate) fn test_set_group_policy(&mut self, mk: &MasterKey, k: u32, members: &[SlotId]) {
        self.file.policy.entries = vec![PolicyEntry::Group {
            k,
            member_slot_ids: members.to_vec(),
            share_gen: 0,
        }];
        self.bump_generation();
        self.refresh_policy_mac(mk);
    }

    /// TEST FIXTURE: append a standalone-slot entry to the policy, so a test can
    /// build an any-1 policy mixing a group with an independent opener.
    pub(crate) fn file_policy_push_slot_for_test(&mut self, mk: &MasterKey, slot_id: SlotId) {
        self.file.policy.entries.push(PolicyEntry::Slot { slot_id });
        self.bump_generation();
        self.refresh_policy_mac(mk);
    }
}

/// A read-only description of one enrolled slot (carries no key material), for
/// listing slots and choosing one to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotInfo {
    /// The slot's id (what `remove_slot` takes).
    pub slot_id: SlotId,
    /// The factor kind.
    pub slot_type: SlotType,
    /// The operator-visible label given at enroll (e.g. `passphrase`, `tpm2`).
    pub label: String,
    /// `true` if the slot is a member of a k-of-n threshold group rather than a
    /// standalone (any-one-opens) slot.
    pub in_group: bool,
    /// For a slot whose KEK is stored encrypted to a key pair (PKCS#11, age):
    /// the wrapping scheme recorded at enroll, e.g. `pkcs11-rsa-oaep-sha256`.
    pub kek_scheme: Option<String>,
}

/// An in-memory key-slot vault. Mutations require MK in hand (LUKS2 semantic);
/// [`SlotVault::save`] persists it atomically at 0o600.
pub struct SlotVault {
    file: VaultFileV2,
    uuid: [u8; 16],
    path: Option<PathBuf>,
}

impl SlotVault {
    /// Create a fresh vault around a NEW random master key. Returns the vault
    /// (in memory — call [`Self::save`] after enrolling at least one slot) and
    /// the master key the caller uses to derive the volume/device key hierarchy.
    pub fn create(subject_id: impl Into<String>) -> (Self, MasterKey) {
        let mk = MasterKey::random();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let policy = Policy::default();
        let file = VaultFileV2 {
            version: VAULT_V2_VERSION,
            vault_uuid_hex: hex::encode(uuid),
            subject_id: subject_id.into(),
            mk_commitment_hex: hex::encode(mk_commitment(mk.as_bytes())),
            policy_mac_hex: hex::encode(policy_mac(mk.as_bytes(), &policy)),
            next_slot_id: 0,
            next_share_gen: 1,
            vault_generation: 1,
            policy,
            slots: Vec::new(),
        };
        (
            Self {
                file,
                uuid,
                path: None,
            },
            mk,
        )
    }

    /// SHARING-ONLY. Create a vault whose master key is a CALLER-SUPPLIED secret
    /// — the foreign volume **root** of an accepted share — instead of a fresh
    /// random one. The caller already holds the secret, so this returns only the
    /// vault. Every vault invariant is unchanged: `mk_commitment` / `policy_mac`
    /// are computed over the supplied bytes, and `unlock` recovers exactly those
    /// bytes.
    ///
    /// **Never** use this for a normal K0b volume: a real volume's master key must
    /// be unknowable and random ([`Self::create`]). Here the "master key" is only
    /// a passphrase/factor-gated container for the 32 shared bytes, which the
    /// caller feeds to `open_volume_shared` (via `derive_hierarchy_v1`), NOT to
    /// `open_volume_with_master_key` (which would apply an extra MK-HKDF and
    /// derive the wrong keys).
    pub fn create_around(subject_id: impl Into<String>, secret: &[u8; 32]) -> Self {
        let mk = MasterKey::from_bytes(*secret);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let policy = Policy::default();
        let file = VaultFileV2 {
            version: VAULT_V2_VERSION,
            vault_uuid_hex: hex::encode(uuid),
            subject_id: subject_id.into(),
            mk_commitment_hex: hex::encode(mk_commitment(mk.as_bytes())),
            policy_mac_hex: hex::encode(policy_mac(mk.as_bytes(), &policy)),
            next_slot_id: 0,
            next_share_gen: 1,
            vault_generation: 1,
            policy,
            slots: Vec::new(),
        };
        Self {
            file,
            uuid,
            path: None,
        }
    }

    /// Load a vault from disk (v2 only; v1 vaults migrate via a separate path).
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let data = std::fs::read(&path).map_err(MfaError::Io)?;
        let mut vault = Self::from_bytes(&data)?;
        vault.path = Some(path);
        Ok(vault)
    }

    /// Import a complete v2 vault JSON document from portable object bytes.
    /// The same structural and hostile-parameter validation as [`Self::load`] is applied.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() > 4 * 1024 * 1024 {
            return Err(MfaError::Factor(
                "vault exceeds 4 MiB portable limit".into(),
            ));
        }
        let file: VaultFileV2 = serde_json::from_slice(data).map_err(MfaError::Serialization)?;
        if file.version != VAULT_V2_VERSION {
            return Err(MfaError::UnsupportedVersion(file.version));
        }
        let uuid_vec =
            hex::decode(&file.vault_uuid_hex).map_err(|e| MfaError::Factor(e.to_string()))?;
        let uuid: [u8; 16] = uuid_vec
            .as_slice()
            .try_into()
            .map_err(|_| MfaError::Factor("vault uuid is not 16 bytes".into()))?;
        let v = Self {
            file,
            uuid,
            path: None,
        };
        v.validate()?; // reject hostile params / malformed policy up front
        Ok(v)
    }

    /// Export this complete v2 vault as JSON bytes, preserving encrypted slot payloads.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.file).map_err(MfaError::Serialization)
    }

    /// Fail-closed semantic validation of a loaded vault (audit finding E): a
    /// vault file is attacker-writable, so before any Argon2 run or Shamir
    /// combine we reject out-of-range Argon2 costs and malformed policies rather
    /// than let a crafted file OOM/CPU-exhaust the victim's unlock.
    fn validate(&self) -> Result<()> {
        if self.file.slots.len() > MAX_SLOTS {
            return Err(MfaError::Factor(format!(
                "vault holds {} slots; at most {MAX_SLOTS} slots are allowed",
                self.file.slots.len()
            )));
        }
        // Unique slot ids; per-factor param sanity.
        let mut seen = std::collections::HashSet::new();
        for s in &self.file.slots {
            if !seen.insert(s.slot_id) {
                return Err(MfaError::Factor(format!("duplicate slot id {}", s.slot_id)));
            }
            if s.slot_type == SlotType::Passphrase {
                crate::kslot::protectors::passphrase::validate_params(&s.params)?;
            }
        }
        // Policy invariants: entries reference existing slots of the right kind.
        for e in &self.file.policy.entries {
            match e {
                PolicyEntry::Slot { slot_id } => {
                    let rec = self.slot(*slot_id).ok_or_else(|| {
                        MfaError::Factor(format!("policy references missing slot {slot_id}"))
                    })?;
                    if rec.payload_is_share {
                        return Err(MfaError::Factor(format!(
                            "slot entry {slot_id} points at a share payload"
                        )));
                    }
                }
                PolicyEntry::Group {
                    k,
                    member_slot_ids,
                    share_gen,
                } => {
                    let n = member_slot_ids.len();
                    if *k == 0 || *k as usize > n || n > 255 {
                        return Err(MfaError::Factor(format!(
                            "group threshold invalid: need 1 <= k({k}) <= n({n}) <= 255"
                        )));
                    }
                    let mut ms = std::collections::HashSet::new();
                    for sid in member_slot_ids {
                        if !ms.insert(*sid) {
                            return Err(MfaError::Factor(format!(
                                "group has duplicate member {sid}"
                            )));
                        }
                        let rec = self.slot(*sid).ok_or_else(|| {
                            MfaError::Factor(format!("group references missing slot {sid}"))
                        })?;
                        if !rec.payload_is_share || rec.share_gen != *share_gen {
                            return Err(MfaError::Factor(format!(
                                "group member {sid} payload/share_gen mismatch"
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// This vault's current monotonic generation (K0b anchors it externally).
    pub fn generation(&self) -> u64 {
        self.file.vault_generation
    }

    /// A stable digest of the vault's authenticated state, for K0b to pin in the
    /// config-integrity chain (so a stale/substituted vault is rejected). Covers
    /// generation + uuid + subject + commitments/MACs + every slot's identity and
    /// ciphertext — i.e. everything whose rollback would change what opens.
    pub fn state_digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("teagarden.v2:vault-state-digest");
        h.update(&self.file.vault_generation.to_le_bytes());
        h.update(&self.uuid);
        h.update(self.file.subject_id.as_bytes());
        h.update(self.file.mk_commitment_hex.as_bytes());
        h.update(self.file.policy_mac_hex.as_bytes());
        h.update(&(self.file.slots.len() as u32).to_le_bytes());
        for s in &self.file.slots {
            h.update(&s.slot_id.to_le_bytes());
            h.update(&[s.slot_type.tag(), s.payload_is_share as u8]);
            h.update(&s.share_gen.to_le_bytes());
            h.update(s.payload_ct_b64.as_bytes());
        }
        *h.finalize().as_bytes()
    }

    fn bump_generation(&mut self) {
        self.file.vault_generation = self.file.vault_generation.saturating_add(1);
    }

    /// The subject id (`volume:<uuid>` / `device:<uuid>`).
    pub fn subject_id(&self) -> &str {
        &self.file.subject_id
    }

    /// Number of enrolled slots.
    pub fn slot_count(&self) -> usize {
        self.file.slots.len()
    }

    /// Every enrolled slot, in enroll order. Carries no key material.
    pub fn slots(&self) -> Vec<SlotInfo> {
        self.file
            .slots
            .iter()
            .map(|s| SlotInfo {
                slot_id: s.slot_id,
                slot_type: s.slot_type,
                label: s.label.clone(),
                in_group: s.payload_is_share,
                kek_scheme: match &s.kek_transport {
                    KekTransport::EncryptedKek { scheme, .. } => Some(scheme.clone()),
                    _ => None,
                },
            })
            .collect()
    }

    /// The current policy (read-only view).
    pub fn policy(&self) -> &Policy {
        &self.file.policy
    }

    /// Refuse an enroll that would take the vault past [`MAX_SLOTS`], before
    /// anything is mutated.
    fn check_room(&self, adding: usize) -> Result<()> {
        if self.file.slots.len().saturating_add(adding) > MAX_SLOTS {
            return Err(MfaError::Factor(format!(
                "this vault already holds {} slots; at most {MAX_SLOTS} slots are allowed — \
                 remove one first",
                self.file.slots.len()
            )));
        }
        Ok(())
    }

    /// Defensive: confirm a caller-held MK matches this vault's commitment.
    fn check_mk(&self, mk: &MasterKey) -> Result<()> {
        let want = hex::decode(&self.file.mk_commitment_hex)
            .map_err(|e| MfaError::Factor(e.to_string()))?;
        let got = mk_commitment(mk.as_bytes());
        if got.ct_eq(want.as_slice()).into() {
            Ok(())
        } else {
            Err(MfaError::Factor(
                "master key does not match this vault (wrong MK)".into(),
            ))
        }
    }

    fn refresh_policy_mac(&mut self, mk: &MasterKey) {
        self.file.policy_mac_hex = hex::encode(policy_mac(mk.as_bytes(), &self.file.policy));
    }

    /// Wrap `payload_plain` for a new slot and append the record. Returns the id.
    fn wrap_and_push(
        &mut self,
        protector: &mut dyn SlotProtector,
        label: &str,
        payload_plain: &[u8],
        payload_kind: PayloadKind,
        share_gen: u32,
    ) -> Result<SlotId> {
        let slot_id = self.file.next_slot_id;
        self.file.next_slot_id = slot_id
            .checked_add(1)
            .ok_or_else(|| MfaError::Factor("slot id space exhausted".into()))?;
        let slot_type = protector.slot_type();
        let enrollment = protector.enroll()?;
        let aad = slot_aad(&self.uuid, slot_id, slot_type, share_gen, payload_kind);
        let ct = aead::encrypt(&enrollment.kek.to_symmetric(), payload_plain, &aad)
            .map_err(|e| MfaError::Factor(format!("payload wrap failed: {e}")))?;
        self.file.slots.push(SlotRecord {
            slot_id,
            slot_type,
            label: label.to_string(),
            enabled: true,
            params: enrollment.params,
            kek_transport: enrollment.transport,
            payload_is_share: matches!(payload_kind, PayloadKind::Share),
            share_gen,
            payload_ct_b64: b64(&ct),
        });
        Ok(slot_id)
    }

    /// Enroll a standalone (any-1) slot whose payload is the master key. Requires
    /// MK. Re-wraps nothing else. Returns the new slot id.
    pub fn add_independent_slot(
        &mut self,
        mk: &MasterKey,
        protector: &mut dyn SlotProtector,
        label: &str,
    ) -> Result<SlotId> {
        self.check_mk(mk)?;
        self.check_room(1)?;
        let slot_id =
            self.wrap_and_push(protector, label, mk.as_bytes(), PayloadKind::MasterKey, 0)?;
        self.file.policy.entries.push(PolicyEntry::Slot { slot_id });
        self.bump_generation();
        self.refresh_policy_mac(mk);
        Ok(slot_id)
    }

    /// Enroll a k-of-n threshold group from `n` protectors: MK is Shamir-split and
    /// each member wraps one share. Any `k` members reconstruct MK. Requires MK.
    pub fn add_threshold_group(
        &mut self,
        mk: &MasterKey,
        k: u32,
        members: &mut [(&mut dyn SlotProtector, String)],
    ) -> Result<Vec<SlotId>> {
        self.check_mk(mk)?;
        let n = members.len();
        self.check_room(n)?;
        let mut shares = split_master_key(mk.as_bytes(), k, n)?;
        let share_gen = self.file.next_share_gen;
        self.file.next_share_gen = share_gen
            .checked_add(1)
            .ok_or_else(|| MfaError::Factor("share generation space exhausted".into()))?;
        let mut ids = Vec::with_capacity(n);
        for (i, (protector, label)) in members.iter_mut().enumerate() {
            let id =
                self.wrap_and_push(*protector, label, &shares[i], PayloadKind::Share, share_gen)?;
            ids.push(id);
        }
        for s in shares.iter_mut() {
            zeroize_vec(s);
        }
        self.file.policy.entries.push(PolicyEntry::Group {
            k,
            member_slot_ids: ids.clone(),
            share_gen,
        });
        self.bump_generation();
        self.refresh_policy_mac(mk);
        Ok(ids)
    }

    /// Remove a slot by id. If it belongs to a threshold group, the WHOLE group is
    /// removed (its remaining members' shares become unusable — re-enroll the group
    /// to change membership; in-place membership edits are a later milestone).
    /// Removing the last opener leaves the vault unopenable (refused).
    pub fn remove_slot(&mut self, mk: &MasterKey, slot_id: SlotId) -> Result<()> {
        self.check_mk(mk)?;
        // Which entry references this slot?
        let mut remove_group: Option<u32> = None;
        let mut is_standalone = false;
        for e in &self.file.policy.entries {
            match e {
                PolicyEntry::Slot { slot_id: sid } if *sid == slot_id => is_standalone = true,
                PolicyEntry::Group {
                    member_slot_ids,
                    share_gen,
                    ..
                } if member_slot_ids.contains(&slot_id) => remove_group = Some(*share_gen),
                _ => {}
            }
        }
        if !is_standalone && remove_group.is_none() {
            return Err(MfaError::Factor(format!("no such slot {slot_id}")));
        }
        // Compute the drop set and the RESULTING policy BEFORE mutating anything
        // (audit K0A-2): a refusal must leave the vault object untouched, so a
        // caller that retries or saves after the error can't brick the vault.
        let drop_ids: Vec<SlotId> = if let Some(gen) = remove_group {
            self.file
                .slots
                .iter()
                .filter(|s| s.payload_is_share && s.share_gen == gen)
                .map(|s| s.slot_id)
                .collect()
        } else {
            vec![slot_id]
        };
        let new_entries: Vec<PolicyEntry> = self
            .file
            .policy
            .entries
            .iter()
            .filter(|e| match e {
                PolicyEntry::Slot { slot_id: sid } => !drop_ids.contains(sid),
                PolicyEntry::Group { share_gen, .. } => Some(*share_gen) != remove_group,
            })
            .cloned()
            .collect();
        if new_entries.is_empty() {
            return Err(MfaError::Factor(
                "refusing to remove the last opener — the vault would be permanently locked".into(),
            ));
        }

        // DURABLE-OPENER INVARIANT.
        //
        // "At least one opener remains" is not enough. If every remaining opener is
        // DEVICE-BOUND (FIDO2 key, this machine's TPM, an HSM token, a reachable
        // Tang server), then losing one physical object destroys the volume: the
        // master key is random and this vault is its only wrapping. That is
        // permanent, unrecoverable data loss caused by a lost keyring.
        //
        // So a removal must leave behind at least one DURABLE opener — a
        // passphrase, a recovery sentence, or a keypair whose private half can be
        // backed up off-box. Adding device factors is always fine; it is removing
        // the last non-device path that is refused.
        //
        // The test is per-ENTRY, not over the flattened slot set: the policy is
        // any-1 over entries, so the volume survives a lost device only if some
        // single entry can be satisfied by durable slots ALONE. A k-of-n group
        // needs at least k durable members — a {k:2, [passphrase, fido2]} group
        // still strands the volume when the FIDO2 key is lost, even though it
        // contains a durable slot.
        let is_durable = |slot_id: &SlotId| {
            self.file
                .slots
                .iter()
                .any(|s| s.slot_id == *slot_id && s.slot_type.is_durable())
        };
        let any_durable = new_entries.iter().any(|e| match e {
            PolicyEntry::Slot { slot_id } => is_durable(slot_id),
            PolicyEntry::Group {
                k, member_slot_ids, ..
            } => member_slot_ids.iter().filter(|id| is_durable(id)).count() as u32 >= *k,
        });
        if !any_durable {
            return Err(MfaError::Factor(
                "refusing: every remaining opener would be device-bound (FIDO2 / TPM2 / \
                 HSM / Tang). Losing that one device would destroy this volume \
                 permanently — the master key is random and this vault is its only \
                 wrapping. Keep at least one durable factor (passphrase, recovery \
                 sentence, or keypair), or enroll one before removing this slot."
                    .into(),
            ));
        }
        // Only now mutate.
        self.file.slots.retain(|s| !drop_ids.contains(&s.slot_id));
        self.file.policy.entries = new_entries;
        self.bump_generation();
        self.refresh_policy_mac(mk);
        Ok(())
    }

    /// Speculative auto-try unlock: recover MK from any policy entry the supplied
    /// protectors can satisfy. Only **counter-free** slots (passphrase / recovery /
    /// keypair — [`SlotType::is_counter_free`]) are attempted; slots for factors
    /// with a retry/lockout counter or user-presence requirement (FIDO2 / TPM2 /
    /// PKCS#11 / Tang) are **skipped** here and must be opened via
    /// [`Self::unlock_targeted`]. This is now ENFORCED, not just documented (advisor):
    /// passing a device protector to `unlock` can never speculatively burn its
    /// counter or force a spurious touch.
    ///
    /// On success the reconstructed MK is verified against `mk_commitment` AND the
    /// stored policy against `policy_mac` (both constant-time); a mismatch is a hard
    /// error.
    pub fn unlock(&self, protectors: &[&dyn SlotProtector]) -> Result<MasterKey> {
        self.unlock_inner(protectors, false)
    }

    /// **Targeted** unlock for a caller-directed factor: like [`Self::unlock`] but
    /// also attempts counter / user-presence slots (FIDO2 / TPM2 / PKCS#11 / Tang).
    /// The caller has explicitly chosen these protectors and accepts the cost of a
    /// touch / a counter decrement, so trying them is intentional, not speculative.
    pub fn unlock_targeted(&self, protectors: &[&dyn SlotProtector]) -> Result<MasterKey> {
        self.unlock_inner(protectors, true)
    }

    /// Unlock WITHOUT using slot `exclude` — nor the threshold group containing
    /// it. For removing a slot: the operator must prove they can open the
    /// volume with a factor that will still exist afterwards, so a removal can
    /// never be authorised by the very slot being removed.
    ///
    /// `targeted` selects [`Self::unlock_targeted`] semantics (device factors
    /// are attempted) over [`Self::unlock`] (counter-free factors only).
    pub fn unlock_excluding(
        &self,
        protectors: &[&dyn SlotProtector],
        targeted: bool,
        exclude: SlotId,
    ) -> Result<MasterKey> {
        let mut failures = Vec::new();
        for entry in &self.file.policy.entries {
            let uses_excluded = match entry {
                PolicyEntry::Slot { slot_id } => *slot_id == exclude,
                PolicyEntry::Group {
                    member_slot_ids, ..
                } => member_slot_ids.contains(&exclude),
            };
            if uses_excluded {
                continue;
            }
            if let Some(mk) = self.try_entry(entry, protectors, targeted, &mut failures)? {
                return Ok(mk);
            }
        }
        Err(unlock_error(failures))
    }

    fn unlock_inner(
        &self,
        protectors: &[&dyn SlotProtector],
        allow_counter: bool,
    ) -> Result<MasterKey> {
        let mut failures = Vec::new();
        for entry in &self.file.policy.entries {
            if let Some(mk) = self.try_entry(entry, protectors, allow_counter, &mut failures)? {
                return Ok(mk);
            }
        }
        Err(unlock_error(failures))
    }

    fn try_entry(
        &self,
        entry: &PolicyEntry,
        protectors: &[&dyn SlotProtector],
        allow_counter: bool,
        failures: &mut Vec<(SlotId, String)>,
    ) -> Result<Option<MasterKey>> {
        match entry {
            PolicyEntry::Slot { slot_id } => {
                let rec = match self.slot(*slot_id) {
                    Some(r) => r,
                    None => return Ok(None),
                };
                // `plain` is Zeroizing: it is scrubbed on scope exit even when
                // finish_mk returns Err via `?` (the policy-MAC-mismatch path) —
                // audit D#2, the true MK must not leak there.
                if let Some(plain) = self.open_payload(rec, protectors, allow_counter, failures)? {
                    return self.finish_mk(&plain);
                }
                Ok(None)
            }
            PolicyEntry::Group {
                k, member_slot_ids, ..
            } => {
                let mut shares: Vec<Zeroizing<Vec<u8>>> = Vec::new();
                for sid in member_slot_ids {
                    if let Some(rec) = self.slot(*sid) {
                        if let Some(share) =
                            self.open_payload(rec, protectors, allow_counter, failures)?
                        {
                            shares.push(share);
                            if shares.len() >= *k as usize {
                                break;
                            }
                        }
                    }
                }
                if shares.len() < *k as usize {
                    return Ok(None);
                }
                let share_bytes: Vec<Vec<u8>> = shares.iter().map(|s| s.to_vec()).collect();
                let mut recon = combine_shares(*k, &share_bytes)?;
                let plain = Zeroizing::new(recon.to_vec());
                recon.zeroize(); // scrub the raw [u8;32] copy
                self.finish_mk(&plain)
            }
        }
    }

    /// Try to AEAD-open a slot's payload with any supplied protector of the same
    /// factor kind. Returns the plaintext (MK or a share) on the first success,
    /// as a `Zeroizing` buffer so the secret is scrubbed even on error paths.
    ///
    /// Counter / user-presence slots are skipped unless `allow_counter` (the
    /// targeted path) — so the speculative `unlock` never touches a device factor.
    fn open_payload(
        &self,
        rec: &SlotRecord,
        protectors: &[&dyn SlotProtector],
        allow_counter: bool,
        failures: &mut Vec<(SlotId, String)>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if !rec.enabled {
            return Ok(None);
        }
        // Enforce the counter-free contract: a speculative unlock never attempts a
        // slot whose factor has a lockout counter / user-presence requirement.
        if !allow_counter && !rec.slot_type.is_counter_free() {
            return Ok(None);
        }
        let aad = slot_aad(
            &self.uuid,
            rec.slot_id,
            rec.slot_type,
            rec.share_gen,
            rec.payload_kind(),
        );
        let ct = unb64(&rec.payload_ct_b64)?;
        for p in protectors {
            if p.slot_type() != rec.slot_type {
                continue;
            }
            // recover_kek reads only stored params + transport + the protector's
            // own input; a wrong input yields a wrong KEK → AEAD tag fails below.
            let kek = match p.recover_kek(&rec.params, &rec.kek_transport) {
                Ok(k) => k,
                Err(e) => {
                    // Keep why a FIDO2 slot failed (the last reason per slot) so the final
                    // error can say "wrong PIN" or "no key attached" instead of only
                    // "decryption failed". The protector's error never holds a secret.
                    if rec.slot_type == SlotType::Fido2Hmac {
                        failures.retain(|(id, _)| *id != rec.slot_id);
                        failures.push((rec.slot_id, failure_reason(&e)));
                    }
                    continue; // this protector cannot serve this slot
                }
            };
            match aead::decrypt(&kek.to_symmetric(), &ct, &aad) {
                Ok(plain) => return Ok(Some(Zeroizing::new(plain))),
                Err(_) => continue, // wrong KEK for this slot — try the next protector
            }
        }
        Ok(None)
    }

    /// Verify a recovered MK candidate against the commitment + policy MAC.
    fn finish_mk(&self, plain: &[u8]) -> Result<Option<MasterKey>> {
        // Hold the candidate in a Zeroizing box so a wrong candidate (Ok(None)
        // branch) is also scrubbed (audit D#4).
        let arr: Zeroizing<[u8; 32]> = match <[u8; 32]>::try_from(plain) {
            Ok(a) => Zeroizing::new(a),
            Err(_) => return Ok(None), // wrong length ⇒ not a master key payload
        };
        let want_commit = hex::decode(&self.file.mk_commitment_hex)
            .map_err(|e| MfaError::Factor(e.to_string()))?;
        if mk_commitment(&arr).ct_eq(want_commit.as_slice()).into() {
            // Also verify the policy was not tampered (downgrade defence).
            let want_mac = hex::decode(&self.file.policy_mac_hex)
                .map_err(|e| MfaError::Factor(e.to_string()))?;
            if !bool::from(policy_mac(&arr, &self.file.policy).ct_eq(want_mac.as_slice())) {
                return Err(MfaError::Factor(
                    "policy integrity MAC mismatch — the vault policy was tampered".into(),
                ));
            }
            Ok(Some(MasterKey::from_bytes(*arr)))
        } else {
            Ok(None)
        }
    }

    fn slot(&self, slot_id: SlotId) -> Option<&SlotRecord> {
        self.file.slots.iter().find(|s| s.slot_id == slot_id)
    }

    /// Persist atomically at 0o600: write a sibling temp file whose name is
    /// unique to this save, fsync it, rename it over the target, then fsync the
    /// directory. Concurrent savers (an enroll racing a remove-slot) never share
    /// one temp inode, so a torn vault can never be renamed into place.
    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref().to_path_buf();
        let json = serde_json::to_vec_pretty(&self.file).map_err(MfaError::Serialization)?;
        let tmp = {
            use rand::RngCore as _;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "slot_vault.json".into());
            path.with_file_name(format!(
                ".{name}.{}.{:016x}.tmp",
                std::process::id(),
                rand::rngs::OsRng.next_u64()
            ))
        };
        let result = write_then_rename(&json, &tmp, &path);
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
            return result;
        }
        self.path = Some(path);
        Ok(())
    }
}

/// The error when no slot opened. With FIDO2 slots that failed for a reason their
/// protector reported (wrong PIN, no key attached, no touch), say so per slot;
/// otherwise the generic decryption failure.
fn unlock_error(failures: Vec<(SlotId, String)>) -> MfaError {
    if failures.is_empty() {
        return MfaError::DecryptionFailed;
    }
    let reasons: Vec<String> = failures
        .iter()
        .map(|(slot_id, reason)| format!("FIDO2 slot {slot_id}: {reason}"))
        .collect();
    MfaError::UnlockFailed(reasons.join("; "))
}

/// A protector error's own words, without the `factor error:` prefix.
fn failure_reason(error: &MfaError) -> String {
    match error {
        MfaError::Factor(reason) => reason.clone(),
        other => other.to_string(),
    }
}

fn write_then_rename(json: &[u8], tmp: &Path, path: &Path) -> Result<()> {
    {
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(tmp)
            .map_err(MfaError::Io)?;
        f.write_all(json).map_err(MfaError::Io)?;
        f.sync_all().map_err(MfaError::Io)?;
    }
    std::fs::rename(tmp, path).map_err(MfaError::Io)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all(); // best effort: the rename itself already landed
        }
    }
    Ok(())
}

fn b64(b: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(b)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(s).map_err(|e| MfaError::Factor(format!("bad base64: {e}")))
}

// `Zeroize` for the reconstructed-share buffers.
use zeroize::Zeroize;
