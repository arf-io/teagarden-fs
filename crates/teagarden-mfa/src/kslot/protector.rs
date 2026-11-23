//! The `SlotProtector` trait + KEK transport model.
//!
//! A factor backend does exactly two things: **enroll** (create fresh factor
//! state and hand back the params to persist, how the KEK is transported, and the
//! KEK itself for the vault core to wrap the payload with) and **recover_kek**
//! (reproduce the KEK from stored params + transport + the factor's live input).
//!
//! The distinction between "derive a KEK", "decrypt a wrapped KEK", "unseal", and
//! "network exchange" lives in the [`KekTransport`] *data*, not in the trait
//! shape — so all seven factor kinds share one object-safe trait, and the vault
//! core stays factor-agnostic (one audited AEAD wrap path).

use serde::{Deserialize, Serialize};

use crate::error::Result;

use super::types::{Kek, SlotType};

/// How a slot's KEK is transported at rest / recovered at unlock.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum KekTransport {
    /// The KEK is re-derived live from the factor input (passphrase, recovery
    /// sentence, FIDO2 hmac-secret). Nothing KEK-related is stored beyond the
    /// non-secret params.
    Derived,
    /// The KEK was random at enroll and stored encrypted to an asymmetric
    /// recipient (age / PKCS#11 RSA-OAEP); unlock decrypts it with the identity.
    EncryptedKek {
        /// Wrapping scheme id (e.g. `"age-x25519"`, `"pkcs11-rsa-oaep-sha256"`).
        scheme: String,
        /// The encrypted KEK (base64 in JSON via serde bytes-as-string not used;
        /// stored as a byte vec, serialized as an array by serde_json — small).
        ciphertext: Vec<u8>,
    },
    /// The KEK was random at enroll and sealed inside a hardware object (TPM2
    /// KeyedHash public+private blobs); unlock loads + unseals it under a policy.
    Sealed {
        /// The object's public blob.
        public: Vec<u8>,
        /// The object's (TPM-encrypted) private blob.
        private: Vec<u8>,
    },
    /// The KEK is recoverable only via a live network exchange (Tang JWE state).
    Exchange {
        /// Serialized exchange state (Clevis/Tang JWE).
        jwe: String,
    },
}

/// The result of enrolling a factor into a new slot.
pub struct Enrollment {
    /// Non-secret, plaintext params persisted in the slot (salts, recipients,
    /// PCR selection, credential ids, …). MUST NOT contain secret material.
    pub params: serde_json::Value,
    /// How the KEK is transported at rest.
    pub transport: KekTransport,
    /// The KEK the vault core uses to wrap this slot's payload, then drops.
    pub kek: Kek,
}

/// One factor backend. Object-safe, `Send + Sync`.
///
/// A protector instance carries its own factor **input** (the passphrase to
/// stretch, the recipient to encrypt to, the identity to decrypt with, a device
/// handle, …), supplied by the caller. This keeps the crate UI-free: interactive
/// prompting happens in the caller, not here.
pub trait SlotProtector {
    /// The factor kind this protector implements.
    fn slot_type(&self) -> SlotType;

    /// Create fresh factor state and return `(params, transport, kek)`. Called
    /// once, at enrollment. The only place secrets / hardware objects are created.
    fn enroll(&mut self) -> Result<Enrollment>;

    /// Reproduce the KEK from the stored `params` + `transport` + this
    /// protector's live factor input. Strictly read-only against factor state.
    ///
    /// MUST NOT be invoked speculatively by the vault for factors with a
    /// retry/lockout counter or a user-presence requirement — the caller directs
    /// which protectors are tried (advisor R3: no auto-burning of PIN / TPM-DA
    /// counters, no spurious FIDO2 touch).
    fn recover_kek(&self, params: &serde_json::Value, transport: &KekTransport) -> Result<Kek>;
}
