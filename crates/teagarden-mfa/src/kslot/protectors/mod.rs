//! Concrete slot protectors. K0a ships the three pure-software factors
//! (passphrase, recovery, keypair); hardware factors (FIDO2/TPM2/PKCS11/Tang)
//! land in K1–K4 behind their own features.

/// Keypair (age X25519 / ssh-ed25519) protector.
pub mod keypair;
/// Argon2id passphrase protector.
pub mod passphrase;
/// 22-word recovery-sentence protector.
pub mod recovery;
/// K4: Tang/Clevis NBDE protector (via the `clevis` CLI; no compile-time dep, so
/// always compiled — runtime-gated on clevis + a reachable Tang server).
pub mod tang;
/// K2: TPM2 sealing protector (via `tpm2-tools`; no compile-time TPM lib, so
/// always compiled — runtime-gated on tpm2-tools + a reachable TPM).
pub mod tpm2;

pub use keypair::KeypairProtector;
pub use passphrase::{Argon2Cost, PassphraseProtector};
pub use recovery::RecoveryProtector;
pub use tang::TangProtector;
pub use tpm2::Tpm2SealProtector;

/// K1: real FIDO2 hmac-secret protector (feature `factor-fido2`).
#[cfg(feature = "factor-fido2")]
pub mod fido2;
#[cfg(feature = "factor-fido2")]
mod fido2_mode;
#[cfg(feature = "factor-fido2")]
mod fido2_ux;
#[cfg(feature = "factor-fido2")]
pub use fido2::{Fido2GenerationOptions, Fido2HmacProtector};
#[cfg(feature = "factor-fido2")]
pub use fido2_mode::Fido2Mode;

/// K3: real PKCS#11 / HSM protector (feature `factor-pkcs11`).
#[cfg(feature = "factor-pkcs11")]
pub mod pkcs11;
#[cfg(feature = "factor-pkcs11")]
pub use pkcs11::Pkcs11Protector;
