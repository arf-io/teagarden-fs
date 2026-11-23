use thiserror::Error;

/// Errors raised while deriving factors, building, or unwrapping an MFA vault.
#[derive(Debug, Error)]
pub enum MfaError {
    /// A key factor failed to produce its contribution (factor-specific reason).
    #[error("factor error: {0}")]
    Factor(String),

    /// AEAD decryption of the wrapped master key failed — a wrong factor value
    /// was supplied or the vault file has been tampered with.
    #[error("vault decryption failed — wrong factor value or tampered vault")]
    DecryptionFailed,

    /// No slot opened, and at least one device slot said why (wrong PIN, no key
    /// attached, no touch). The text is per slot and never holds a secret.
    #[error("could not unlock: {0}")]
    UnlockFailed(String),

    /// No vault file exists at the given path.
    #[error("vault not found at {0}")]
    VaultNotFound(String),

    /// Reading or writing the vault file failed.
    #[error("vault file error: {0}")]
    Io(#[from] std::io::Error),

    /// (De)serializing the vault JSON failed.
    #[error("vault serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The vault file declares a format version this build cannot read.
    #[error("vault format version {0} is unsupported (expected 1)")]
    UnsupportedVersion(u32),

    /// The supplied TOTP code did not match the current or previous time window.
    #[error("TOTP window exhausted — OTP may be expired")]
    TotpExpired,

    /// Failure deriving or validating the hardware-binding factor.
    #[error("hardware binding: {0}")]
    HardwareBinding(String),

    /// A TPM2 operation (via `tpm2-tools`) failed.
    #[error("TPM2 error: {0}")]
    Tpm2(String),

    /// A PKCS#11 / HSM operation (via the cryptoki bindings) failed.
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    /// A macOS Secure Enclave / Touch ID operation failed.
    #[error("macOS SEP/Touch ID error: {0}")]
    Sep(String),

    /// A wrapped `teagarden-core` volume error surfaced while unlocking or
    /// creating a key-protected volume (config read, MK-rooted key derivation,
    /// verification-hash / integrity / anti-rollback checks). K0b.
    #[error("volume error: {0}")]
    Core(String),
}

/// Convenience alias for fallible MFA operations returning `MfaError`.
pub type Result<T> = std::result::Result<T, MfaError>;
