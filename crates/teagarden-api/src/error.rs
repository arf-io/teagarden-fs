use serde::Serialize;
use thiserror::Error;

/// Structured, serializable error report (message, stable code, suggestion).
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    /// Human-readable error message.
    pub error: String,
    /// Stable machine-readable error code (e.g. `VOLUME_NOT_FOUND`).
    pub code: String,
    /// Actionable hint for how the caller can resolve the error.
    pub suggestion: String,
}

/// All error conditions the service layer can return, each mapped to a stable
/// error code and a user-facing suggestion.
#[derive(Debug, Error)]
pub enum ApiError {
    /// No volume exists with the given ID.
    #[error("volume not found: {0}")]
    VolumeNotFound(String),

    /// A volume with the requested name/ID already exists.
    #[error("volume already exists: {0}")]
    VolumeAlreadyExists(String),

    /// The operation requires the volume to be unmounted, but it is mounted.
    #[error("volume is mounted: {0}")]
    VolumeIsMounted(String),

    /// The operation requires the volume to be mounted, but it is not.
    #[error("volume is not mounted: {0}")]
    VolumeNotMounted(String),

    /// An authenticated Telegram session is required but absent.
    #[error("authentication required")]
    AuthRequired,

    /// The Telegram backend returned an error.
    #[error("telegram error: {0}")]
    Telegram(String),

    /// A cryptographic operation failed, e.g. key derivation or decryption.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// The storage backend (database / disk) failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// A request parameter or body was malformed or invalid.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The volume must be opened first; no live session exists.
    #[error("session not open: {0}")]
    SessionNotOpen(String),

    /// The volume already has an open session.
    #[error("session already open: {0}")]
    SessionAlreadyOpen(String),

    /// An unexpected internal failure.
    #[error("internal error: {0}")]
    Internal(String),

    /// A wrapped `std::io::Error`.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Too many attempts; the caller is throttled until `retry_after_secs` elapses.
    #[error("rate limit exceeded; retry after {retry_after_secs}s")]
    RateLimited {
        /// Seconds the caller should wait before retrying.
        retry_after_secs: u64,
    },
}

impl ApiError {
    /// Returns a user-facing suggestion for how to resolve this error.
    pub fn suggestion(&self) -> &'static str {
        match self {
            ApiError::VolumeNotFound(_) => {
                "Check the volume name or ID with `teagarden volume list`"
            }
            ApiError::VolumeAlreadyExists(_) => {
                "Use a different name or delete the existing volume first"
            }
            ApiError::VolumeIsMounted(_) => {
                "Unmount the volume first with `teagarden volume unmount`"
            }
            ApiError::VolumeNotMounted(_) => "Mount the volume with `teagarden volume mount`",
            ApiError::AuthRequired => "Authenticate first with `teagarden auth login`",
            ApiError::Telegram(_) => "Check your Telegram connection and try again",
            ApiError::Crypto(_) => "Verify your password is correct",
            ApiError::Storage(_) => "The storage backend encountered an error; check disk space",
            ApiError::SessionNotOpen(_) => "The volume has no open session; open it and retry",
            ApiError::SessionAlreadyOpen(_) => {
                "The volume is already open in this process; close it before reopening"
            }
            ApiError::InvalidArgument(_) => "Check the command arguments and try again",
            ApiError::Internal(_) => {
                "An unexpected error occurred; re-run with --verbose for details"
            }
            ApiError::Io(_) => "Check file permissions and available disk space",
            ApiError::RateLimited { .. } => {
                "Wait before retrying; repeated failed attempts are throttled"
            }
        }
    }

    /// Returns a short error code string for programmatic consumption.
    pub fn error_code(&self) -> &'static str {
        match self {
            ApiError::VolumeNotFound(_) => "VOLUME_NOT_FOUND",
            ApiError::VolumeAlreadyExists(_) => "VOLUME_EXISTS",
            ApiError::VolumeIsMounted(_) => "VOLUME_MOUNTED",
            ApiError::VolumeNotMounted(_) => "VOLUME_NOT_MOUNTED",
            ApiError::AuthRequired => "AUTH_REQUIRED",
            ApiError::Telegram(_) => "TELEGRAM_ERROR",
            ApiError::Crypto(_) => "CRYPTO_ERROR",
            ApiError::Storage(_) => "STORAGE_ERROR",
            ApiError::SessionNotOpen(_) => "SESSION_NOT_OPEN",
            ApiError::SessionAlreadyOpen(_) => "SESSION_ALREADY_OPEN",
            ApiError::InvalidArgument(_) => "INVALID_ARGUMENT",
            ApiError::Internal(_) => "INTERNAL_ERROR",
            ApiError::Io(_) => "IO_ERROR",
            ApiError::RateLimited { .. } => "RATE_LIMITED",
        }
    }

    /// Builds the structured ErrorResponse for this error.
    pub fn to_error_response(&self) -> ErrorResponse {
        ErrorResponse {
            error: self.to_string(),
            code: self.error_code().to_string(),
            suggestion: self.suggestion().to_string(),
        }
    }
}

/// Convenience alias for results that fail with an `ApiError`.
pub type Result<T> = std::result::Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_response_serializes_to_json() {
        let err = ApiError::VolumeNotFound("test-vol".into());
        let resp = err.to_error_response();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("VOLUME_NOT_FOUND"));
        assert!(json.contains("test-vol"));
        assert!(json.contains("suggestion"));
    }

    #[test]
    fn all_variants_have_suggestions() {
        let errors: Vec<ApiError> = vec![
            ApiError::VolumeNotFound("x".into()),
            ApiError::VolumeAlreadyExists("x".into()),
            ApiError::VolumeIsMounted("x".into()),
            ApiError::VolumeNotMounted("x".into()),
            ApiError::AuthRequired,
            ApiError::Telegram("x".into()),
            ApiError::Crypto("x".into()),
            ApiError::Storage("x".into()),
            ApiError::SessionNotOpen("x".into()),
            ApiError::SessionAlreadyOpen("x".into()),
            ApiError::InvalidArgument("x".into()),
            ApiError::Internal("x".into()),
        ];

        for err in &errors {
            assert!(!err.suggestion().is_empty(), "Empty suggestion for: {err}");
            assert!(!err.error_code().is_empty(), "Empty error code for: {err}");
        }
    }

    #[test]
    fn auth_required_suggests_auth_login() {
        let err = ApiError::AuthRequired;
        assert!(err.suggestion().contains("teagarden auth login"));
    }

    #[test]
    fn no_suggestion_points_at_a_removed_http_endpoint() {
        // The REST server was removed for 1.0; suggestions are shown by the CLI
        // and must not send users to HTTP routes that no longer exist.
        let errors: Vec<ApiError> = vec![
            ApiError::VolumeNotFound("x".into()),
            ApiError::VolumeAlreadyExists("x".into()),
            ApiError::VolumeIsMounted("x".into()),
            ApiError::VolumeNotMounted("x".into()),
            ApiError::AuthRequired,
            ApiError::Telegram("x".into()),
            ApiError::Crypto("x".into()),
            ApiError::Storage("x".into()),
            ApiError::SessionNotOpen("x".into()),
            ApiError::SessionAlreadyOpen("x".into()),
            ApiError::InvalidArgument("x".into()),
            ApiError::Internal("x".into()),
            ApiError::RateLimited {
                retry_after_secs: 1,
            },
        ];
        for err in &errors {
            let s = err.suggestion();
            assert!(!s.contains("/api/"), "HTTP route in suggestion: {s}");
            assert!(
                !s.contains("POST ") && !s.contains("GET "),
                "HTTP verb in suggestion: {s}"
            );
        }
    }
}
