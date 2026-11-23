//! Key-slot vault v2 — a LUKS2 / `systemd-cryptenroll` / Clevis-style multi-factor
//! key-enrollment subsystem. The volume/device **master key** is random and wrapped
//! in independent **slots**, each protecting it (or a Shamir share of it) via a
//! different factor, under an **any-1 / N-of-M policy**.
//!
//! This replaces the old AND-only `KeyFactor`/`derive_kwrap` composition (which
//! could not express OR/threshold and — critically — did not enforce anything:
//! volume open never consulted the vault). The user-facing model is in
//! `docs/SECURITY_MODEL.md` §8 (Key slots); the vault format is in `docs/FORMAT.md` §5.
//!
//! K0a (this module) ships the crate-local vault + the three pure-software factors
//! (passphrase, recovery sentence, keypair). Hardware factors (FIDO2 / TPM2 /
//! PKCS#11 / Tang) land in K1–K4; enforcement wiring into volume open is K0b.

/// Canonical AAD + policy encoding + commitments/MACs.
pub mod aad;
/// Unlock policy + Shamir threshold splitting.
pub mod policy;
/// The `SlotProtector` trait + KEK transport model.
pub mod protector;
/// Concrete slot protectors (passphrase / recovery / keypair).
pub mod protectors;
#[cfg(test)]
mod tests;
/// Core secret types (MasterKey, Kek, SlotType, …).
pub mod types;
/// The slot-vault core (create / enroll / unlock / persist).
pub mod vault;

pub use policy::{Policy, PolicyEntry};
pub use protector::{Enrollment, KekTransport, SlotProtector};
#[cfg(feature = "factor-pkcs11")]
pub use protectors::Pkcs11Protector;
pub use protectors::{
    Argon2Cost, KeypairProtector, PassphraseProtector, RecoveryProtector, TangProtector,
    Tpm2SealProtector,
};
pub use types::{Kek, MasterKey, PayloadKind, SlotId, SlotType};
pub use vault::{SlotInfo, SlotVault, MAX_SLOTS};
