//! TOTP/HOTP factor — ties the vault to time-based one-time passwords.
//!
//! Unlike other factors whose contribution is static, a TOTP contribution
//! changes every 30 seconds. The vault unwrap logic must therefore try the
//! current window **and** the previous window to handle clock skew.
//!
//! # Secret storage
//!
//! The TOTP `base32_secret` is NOT stored in the plaintext `FactorDescriptor.params`.
//! Instead it is stored in the vault's `encrypted_factor_secrets` blob, which is
//! XChaCha20-Poly1305-encrypted under a key derived from `Kwrap`. See `vault.rs`
//! for the encryption design.
//!
//! The plaintext descriptor contains only display metadata (issuer, account,
//! algorithm parameters) needed to render the "which factors are enrolled?" UI.

use serde_json::json;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::{MfaError, Result};
use crate::factor::{FactorDescriptor, KeyFactor};

const FACTOR_TYPE: &str = "totp";

/// Key factor whose contribution is derived from a time-based one-time password,
/// pairing the stored TOTP secret with a user-supplied OTP code at unwrap time.
pub struct TotpFactor {
    /// Raw TOTP secret bytes.
    secret: Vec<u8>,
    /// The TOTP OTP value to use for contribution (supplied by user at runtime).
    otp: String,
    issuer: String,
    account: String,
}

impl TotpFactor {
    /// Construct from an existing secret bytes + user-supplied OTP value.
    pub fn from_otp(
        secret: &[u8],
        otp: impl Into<String>,
        issuer: impl Into<String>,
        account: impl Into<String>,
    ) -> Self {
        Self {
            secret: secret.to_vec(),
            otp: otp.into(),
            issuer: issuer.into(),
            account: account.into(),
        }
    }

    /// Construct from a base32-encoded secret + user-supplied OTP.
    pub fn from_base32_otp(
        base32_secret: &str,
        otp: impl Into<String>,
        issuer: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<Self> {
        let secret_bytes = Secret::Encoded(base32_secret.to_string())
            .to_bytes()
            .map_err(|e| MfaError::Factor(format!("base32 decode: {e}")))?;
        Ok(Self::from_otp(&secret_bytes, otp, issuer, account))
    }

    /// Return a copy of this factor with a new OTP (used after `generate` to bind the OTP).
    pub fn with_otp(mut self, otp: impl Into<String>) -> Self {
        self.otp = otp.into();
        self
    }

    /// Generate a new random TOTP secret and return (factor, base32_secret).
    pub fn generate(issuer: impl Into<String>, account: impl Into<String>) -> (Self, String) {
        let secret = Secret::generate_secret();
        let secret_bytes = secret.to_bytes().unwrap();
        let base32_str = secret.to_encoded().to_string();
        let f = Self {
            secret: secret_bytes,
            otp: String::new(),
            issuer: issuer.into(),
            account: account.into(),
        };
        (f, base32_str)
    }

    /// Get the current OTP value (useful for setup verification).
    pub fn current_otp(&self) -> Result<String> {
        let totp = self.build_totp()?;
        totp.generate_current()
            .map_err(|e| MfaError::Factor(format!("TOTP generate: {e}")))
    }

    fn build_totp(&self) -> Result<TOTP> {
        TOTP::new(Algorithm::SHA1, 6, 1, 30, self.secret.clone())
            .map_err(|e| MfaError::Factor(format!("TOTP init: {e}")))
    }
}

impl KeyFactor for TotpFactor {
    fn factor_type(&self) -> &'static str {
        FACTOR_TYPE
    }

    fn descriptor(&self) -> FactorDescriptor {
        // SECURITY: `base32_secret` is intentionally NOT included here.
        // It is stored exclusively in the vault's `encrypted_factor_secrets`
        // blob (H14 fix). Only display metadata is stored in the plaintext
        // `FactorDescriptor.params`.
        FactorDescriptor::new(
            FACTOR_TYPE,
            json!({
                "issuer": self.issuer,
                "account": self.account,
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
            }),
        )
    }

    fn sensitive_params(&self) -> Option<serde_json::Value> {
        let base32 = Secret::Raw(self.secret.clone()).to_encoded().to_string();
        Some(json!({ "base32_secret": base32 }))
    }

    fn derive_contribution(&self) -> Result<[u8; 32]> {
        // Contribution = BLAKE3_keyed(derive_key(secret_bytes), otp.as_bytes())
        // This cryptographically binds the contribution to both:
        // - the TOTP secret (something the user has)
        // - the OTP value (something the user knows at this moment)
        //
        // blake3::derive_key is used to produce a full-entropy 32-byte key from
        // the raw secret regardless of its length, avoiding the entropy-lossy
        // XOR-fold that was previously used for secrets longer than 32 bytes.
        if self.otp.is_empty() {
            return Err(MfaError::Factor("OTP value not set".into()));
        }
        let key = blake3::derive_key("teagarden.v1:totp-contribution", &self.secret);
        Ok(blake3::keyed_hash(&key, self.otp.as_bytes()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_totp() {
        let (factor, secret_b32) = TotpFactor::generate("teagarden", "user@example.com");
        assert!(!secret_b32.is_empty());

        let current = factor.current_otp().unwrap();
        assert_eq!(current.len(), 6);
        assert!(current.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn same_otp_same_contribution() {
        let secret = b"TESTSECRETFORTEST".to_vec();
        let f1 = TotpFactor::from_otp(&secret, "123456", "test", "test");
        let f2 = TotpFactor::from_otp(&secret, "123456", "test", "test");
        assert_eq!(
            f1.derive_contribution().unwrap(),
            f2.derive_contribution().unwrap()
        );
    }

    #[test]
    fn different_otp_different_contribution() {
        let secret = b"TESTSECRETFORTEST".to_vec();
        let f1 = TotpFactor::from_otp(&secret, "123456", "test", "test");
        let f2 = TotpFactor::from_otp(&secret, "654321", "test", "test");
        assert_ne!(
            f1.derive_contribution().unwrap(),
            f2.derive_contribution().unwrap()
        );
    }

    #[test]
    fn empty_otp_returns_error() {
        let secret = b"TESTSECRETFORTEST".to_vec();
        let f = TotpFactor::from_otp(&secret, "", "test", "test");
        assert!(matches!(f.derive_contribution(), Err(MfaError::Factor(_))));
    }
}
