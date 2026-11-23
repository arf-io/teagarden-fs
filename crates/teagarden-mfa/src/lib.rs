//! Multi-factor key protection for TeaGarden volumes.
//!
//! # The enforcing layer: the key-slot vault ([`kslot`] + [`unlock`])
//!
//! A volume created with `--key-protection` is **MK-rooted**: its master key is
//! random, and the only wrapping of that key lives in the slot vault
//! (`slot_vault.json`). Opening such a volume *requires* satisfying the vault's
//! policy — any one independent slot, or a k-of-n threshold group — because
//! there is nothing to derive the key hierarchy from without it. This is the
//! LUKS2/systemd-cryptenroll model: passphrase, recovery-sentence, keypair,
//! TPM2, FIDO2 hmac-secret, PKCS#11, and Tang protectors each wrap a KEK that
//! opens an AEAD-sealed payload bound to `vault_uuid ‖ slot_id ‖ slot_type ‖
//! share_gen ‖ payload_kind`. See [`kslot`] for the design and its tests, and
//! [`unlock`] for the CLI-facing enroll/unlock bridge.
//!
//! # The legacy layer: [`vault`] and [`factors`] — NOT enforcing, kept for cleanup
//!
//! The original `MfaVault` (a composite "all factors" wrapping of a
//! password-derived master key) shipped in versions up to 1.0.0-rc.2 behind
//! `mfa setup` — **and volume open never consulted it**. A volume "protected"
//! by it was protected by its password alone; the removal is documented in the
//! CHANGELOG's rc.3 security notes. The [`vault`] and [`factors`] modules
//! remain **only** so `teagarden mfa status`/`mfa remove` can report and delete
//! leftover legacy state. Do not build on them; nothing in the open path reads
//! them.
//!
//! # TPM2
//!
//! The enforcing TPM2 protector (`kslot/protectors/tpm2.rs`, behind
//! `feature = "tpm2"`) shells out to `tpm2-tools` to seal the slot KEK under
//! the owner hierarchy, optionally bound to PCR values. (The legacy
//! `factors::tpm2` NV-storage design is part of the non-enforcing layer above.)

#![deny(missing_docs)]

/// Error type and `Result` alias for MFA operations.
pub mod error;
/// LEGACY (non-enforcing): the `KeyFactor` trait and composite `Kwrap` derivation.
pub mod factor;
/// LEGACY (non-enforcing): factor implementations for the removed `mfa setup`
/// vault. Volume open never consulted these; retained for state cleanup only.
pub mod factors;
/// Key-slot vault v2 — LUKS2-style multi-factor key enrollment. **This is the
/// enforcing layer.**
pub mod kslot;
/// K0b enforcement wiring — open/create key-protected (MK-rooted) volumes via the vault.
pub mod unlock;
/// LEGACY (non-enforcing): the on-disk `MfaVault` of the removed `mfa setup`.
/// Retained so leftover state can be reported and deleted, nothing more.
pub mod vault;

pub use error::MfaError;
pub use factor::{FactorDescriptor, KeyFactor};
pub use vault::MfaVault;
