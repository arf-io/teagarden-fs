//! Password factor — derives a 32-byte contribution via Argon2id.
//!
//! Uses a separate salt and lightweight params from the volume KDF so that:
//! 1. The contribution is independent of the volume's Argon2id derivation.
//! 2. Compromise of this salt does not reveal the volume key.

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, Params, PasswordHasher};
use serde_json::json;

use crate::error::{MfaError, Result};
use crate::factor::{FactorDescriptor, KeyFactor};

const FACTOR_TYPE: &str = "password";
/// Lightweight params for the factor KDF (password is already slow via volume KDF).
const M_COST: u32 = 65536; // 64 MiB
const T_COST: u32 = 2;
const P_COST: u32 = 1;

/// Key factor that derives its 32-byte contribution from a password via Argon2id,
/// using a dedicated salt independent of the volume's own KDF.
pub struct PasswordFactor {
    password: String,
    /// Base64 salt; generated at create time, stored in the descriptor.
    salt: String,
}

impl PasswordFactor {
    /// Create a new factor for `password`.
    /// A fresh random salt is generated — use this when setting up MFA.
    pub fn new(password: impl Into<String>) -> Self {
        let salt = SaltString::generate(&mut OsRng).to_string();
        Self {
            password: password.into(),
            salt,
        }
    }

    /// Reconstruct from a persisted descriptor (existing salt).
    pub fn from_descriptor(password: impl Into<String>, salt: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            salt: salt.into(),
        }
    }
}

impl KeyFactor for PasswordFactor {
    fn factor_type(&self) -> &'static str {
        FACTOR_TYPE
    }

    fn descriptor(&self) -> FactorDescriptor {
        FactorDescriptor::new(FACTOR_TYPE, json!({ "salt": self.salt }))
    }

    fn derive_contribution(&self) -> Result<[u8; 32]> {
        let params = Params::new(M_COST, T_COST, P_COST, Some(32))
            .map_err(|e| MfaError::Factor(format!("argon2 params: {e}")))?;

        let salt = argon2::password_hash::SaltString::from_b64(&self.salt)
            .map_err(|e| MfaError::Factor(format!("invalid salt: {e}")))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let hash = argon2
            .hash_password(self.password.as_bytes(), &salt)
            .map_err(|e| MfaError::Factor(format!("argon2 hash: {e}")))?;

        let hash_bytes = hash
            .hash
            .ok_or_else(|| MfaError::Factor("no hash output".into()))?;
        let bytes = hash_bytes.as_bytes();

        if bytes.len() < 32 {
            return Err(MfaError::Factor("argon2 output too short".into()));
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_password_same_salt_gives_same_contribution() {
        let f1 = PasswordFactor::from_descriptor("hunter2", "c29tZXNhbHRzdHJpbmcx");
        let f2 = PasswordFactor::from_descriptor("hunter2", "c29tZXNhbHRzdHJpbmcx");
        assert_eq!(
            f1.derive_contribution().unwrap(),
            f2.derive_contribution().unwrap()
        );
    }

    #[test]
    fn different_password_different_contribution() {
        let f1 = PasswordFactor::from_descriptor("password1", "c29tZXNhbHRzdHJpbmcx");
        let f2 = PasswordFactor::from_descriptor("password2", "c29tZXNhbHRzdHJpbmcx");
        assert_ne!(
            f1.derive_contribution().unwrap(),
            f2.derive_contribution().unwrap()
        );
    }

    #[test]
    fn different_salt_different_contribution() {
        let f1 = PasswordFactor::from_descriptor("same", "c29tZXNhbHRzdHJpbmcx");
        let f2 = PasswordFactor::new("same"); // generates new random salt
        assert_ne!(
            f1.derive_contribution().unwrap(),
            f2.derive_contribution().unwrap()
        );
    }
}
