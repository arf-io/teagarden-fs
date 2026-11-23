use thiserror::Error;

/// Errors that can occur during volume sharing operations.
#[derive(Debug, Error)]
pub enum SharingError {
    /// ML-KEM encapsulation or decapsulation failed, e.g. a malformed or
    /// incompatible recipient public key.
    #[error("key exchange failed: {0}")]
    KeyExchange(String),

    /// The referenced user could not be found.
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// The caller lacks permission for the requested operation.
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// The invite token is malformed, expired, revoked, or already exhausted.
    #[error("invalid invite: {0}")]
    InvalidInvite(String),

    /// A cryptographic operation (AEAD wrap/unwrap, serialization) failed.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl SharingError {
    /// Returns a user-facing suggestion for how to resolve this error.
    pub fn suggestion(&self) -> &'static str {
        match self {
            SharingError::KeyExchange(_) => {
                "The recipient's public key may be invalid or from an incompatible version"
            }
            SharingError::UserNotFound(_) => {
                "Verify the user ID; they may need to create an account first"
            }
            SharingError::AccessDenied(_) => {
                "You do not have permission for this operation; contact the volume owner"
            }
            SharingError::InvalidInvite(_) => {
                "The invite code may have expired or already been used"
            }
            SharingError::Crypto(_) => {
                "Cryptographic operation failed; ensure both parties use compatible versions"
            }
        }
    }
}

/// Convenience alias for results returned by sharing operations.
pub type Result<T> = std::result::Result<T, SharingError>;
