//! Core secret types for the key-slot vault (v2). Zeroized on drop.

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use teagarden_core::crypto::keys::SymmetricKey;

/// The 32-byte volume/device **master key** (MK). Random at create, never
/// factor-derived (for random-root volumes). Every slot independently wraps it
/// (or a Shamir share of it). Zeroized on drop; no `Debug` that could leak it.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Generate a fresh random master key from the OS CSPRNG.
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }

    /// Wrap raw bytes (recovery / migration only — new volumes use [`Self::random`]).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Borrow the raw bytes (for KDF input / hierarchy derivation).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// View as a core [`SymmetricKey`] (for AEAD as a wrap target — used by
    /// tests; the vault wraps MK *under* KEKs, so MK is a plaintext there).
    pub fn to_symmetric(&self) -> SymmetricKey {
        SymmetricKey::from_bytes(self.0)
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// A 32-byte **key-encryption key** produced by a factor to (un)wrap a slot's
/// payload. Each slot obtains its KEK differently (see [`crate::kslot::KekTransport`]),
/// but the wrap itself is uniform AEAD. Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Kek([u8; 32]);

impl Kek {
    /// A random KEK (for `EncryptedKek`/`Sealed` factors that generate one at enroll).
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }

    /// Construct from raw bytes (a factor's derived output).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The AEAD key this KEK represents.
    pub fn to_symmetric(&self) -> SymmetricKey {
        SymmetricKey::from_bytes(self.0)
    }
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kek(<redacted>)")
    }
}

/// Monotonic per-vault slot identifier. Never reused (see `next_slot_id`).
pub type SlotId = u32;

/// The factor kind behind a slot. The stable string form is stored in the vault
/// and bound into each slot's AEAD AAD, so a slot's kind cannot be altered
/// without invalidating its wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SlotType {
    /// Argon2id-stretched passphrase → derived KEK.
    Passphrase,
    /// 22-word recovery sentence (256-bit entropy) → derived KEK.
    Recovery,
    /// Asymmetric keypair (age X25519 / ssh-ed25519): random KEK encrypted to a recipient.
    Keypair,
    /// FIDO2 CTAP2 `hmac-secret` → derived KEK (K1).
    Fido2Hmac,
    /// TPM2-sealed random KEK (K2).
    Tpm2,
    /// PKCS#11/HSM-wrapped random KEK (K3).
    Pkcs11,
    /// Tang / Clevis NBDE exchange (K4).
    Tang,
}

impl SlotType {
    /// Whether losing a single physical object (or one machine, or one server)
    /// destroys this factor's ability to open the volume.
    ///
    /// A **device** factor is bound to hardware the operator can lose, have
    /// stolen, or watch die: a FIDO2 key, a specific machine's TPM, an HSM token,
    /// or a reachable Tang server. A **durable** factor survives that — a
    /// passphrase lives in the operator's head, a recovery sentence on paper, and
    /// a keypair is a file that can be backed up off-box.
    ///
    /// This distinction exists because a vault whose only opener is a device
    /// factor is one lost object away from **permanent, unrecoverable data
    /// loss** — the master key is random and the vault is its only wrapping.
    pub fn is_device_bound(&self) -> bool {
        matches!(
            self,
            SlotType::Fido2Hmac | SlotType::Tpm2 | SlotType::Pkcs11 | SlotType::Tang
        )
    }

    /// The inverse of [`Self::is_device_bound`]: this factor survives the loss of
    /// any single piece of hardware, so it can serve as the recovery path.
    pub fn is_durable(&self) -> bool {
        !self.is_device_bound()
    }

    /// Whether this factor is free of a retry/lockout counter and of a
    /// user-presence requirement, so the vault may try it **speculatively** in the
    /// auto-try [`crate::kslot::SlotVault::unlock`]. Counter / user-presence factors
    /// (FIDO2 touch+PIN, TPM2 dictionary-attack lockout, PKCS#11 PIN retry, Tang
    /// network round-trip) must be opened only through the *targeted*
    /// [`crate::kslot::SlotVault::unlock_targeted`] — trying them speculatively
    /// could burn a lockout counter or force a spurious touch (design contract,
    /// now enforced rather than documentation-only).
    pub fn is_counter_free(self) -> bool {
        matches!(
            self,
            SlotType::Passphrase | SlotType::Recovery | SlotType::Keypair
        )
    }

    /// Stable 1-byte tag bound into the AAD (distinct from the serde string).
    pub fn tag(self) -> u8 {
        match self {
            SlotType::Passphrase => 1,
            SlotType::Recovery => 2,
            SlotType::Keypair => 3,
            SlotType::Fido2Hmac => 4,
            SlotType::Tpm2 => 5,
            SlotType::Pkcs11 => 6,
            SlotType::Tang => 7,
        }
    }
}

/// What a slot's wrapped payload contains — bound into the AAD so a Shamir share
/// can never be mis-interpreted as (or swapped for) a full master key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadKind {
    /// The full 32-byte master key (a standalone / any-1 slot).
    MasterKey,
    /// One 33-byte Shamir share of the master key (a threshold-group member).
    Share,
}

impl PayloadKind {
    /// 1-byte AAD tag.
    pub fn tag(self) -> u8 {
        match self {
            PayloadKind::MasterKey => 0xA0,
            PayloadKind::Share => 0xA1,
        }
    }
}

/// Domain-separation contexts (versioned; never reuse a v1 context).
pub mod context {
    /// `blake3::derive_key` context committing to MK for post-recovery verification.
    pub const MK_COMMITMENT: &str = "teagarden.v2:mk-commitment";
    /// `blake3::derive_key` context for the policy-integrity MAC key.
    pub const POLICY_MAC: &str = "teagarden.v2:policy-mac";
    /// AAD prefix for every slot payload wrap.
    pub const SLOT_WRAP: &[u8] = b"teagarden.v2:slot-wrap";
    /// Passphrase KEK derivation context (over the Argon2id output).
    pub const KEK_PASSPHRASE: &str = "teagarden.v2:kek:passphrase";
    /// Recovery-sentence KEK derivation context.
    pub const KEK_RECOVERY: &str = "teagarden.v2:kek:recovery";
    /// FIDO2 hmac-secret KEK derivation context (over the authenticator's
    /// per-(credential,salt) HMAC output).
    pub const KEK_FIDO2: &str = "teagarden.v2:kek:fido2-hmac-secret";
}

/// Zeroize a byte buffer in place (helper for share material).
pub(crate) fn zeroize_vec(v: &mut Vec<u8>) {
    v.zeroize();
}
