use thiserror::Error;

/// Errors raised by the Telegram block transport layer.
#[derive(Debug, Error)]
pub enum TelegramError {
    /// The transport has no active Telegram connection.
    #[error("not connected")]
    NotConnected,

    /// An operation requires a logged-in session, but none is authenticated.
    #[error("authentication required")]
    AuthRequired,

    /// Uploading a block to Telegram failed; carries the failure detail.
    #[error("upload failed: {0}")]
    Upload(String),

    /// Downloading a block from Telegram failed; carries the failure detail.
    #[error("download failed: {0}")]
    Download(String),

    /// No Telegram message exists for the given message ID (block missing or deleted).
    #[error("message not found: {0}")]
    MessageNotFound(i64),

    /// Deleting a Telegram message failed; carries the failure detail.
    #[error("delete failed: {0}")]
    Delete(String),

    /// A block exceeds the maximum allowed upload size.
    #[error("block too large: {size} bytes (max {max})")]
    BlockTooLarge {
        /// Actual block size in bytes.
        size: usize,
        /// Maximum permitted block size in bytes.
        max: usize,
    },

    /// A session file or login-state error occurred.
    #[error("session error: {0}")]
    Session(String),

    /// Telegram rate-limited the request; retry after the given number of seconds.
    #[error("rate limited, retry after {seconds}s")]
    RateLimited {
        /// Seconds to wait before retrying, as reported by Telegram.
        seconds: u32,
    },

    /// A generic Telegram API error returned by the server.
    #[error("telegram API error: {0}")]
    Api(String),

    /// An underlying I/O error (e.g. reading a session or local file).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The transport operation exceeded its time budget.
    #[error("transport timed out")]
    Timeout,
}

impl TelegramError {
    /// Telegram discarded or rejected the temporary multipart upload.
    pub fn requires_new_upload(&self) -> bool {
        match self {
            Self::Api(message) | Self::Upload(message) => {
                let message = message.to_ascii_uppercase();
                (message.contains("FILE_PART")
                    && ["MISSING", "INVALID", "EMPTY", "SIZE_CHANGED"]
                        .iter()
                        .any(|s| message.contains(s)))
                    || message.contains("FILE_ID_INVALID")
            }
            _ => false,
        }
    }

    /// Returns a user-facing suggestion for how to resolve this error.
    pub fn suggestion(&self) -> &'static str {
        match self {
            TelegramError::NotConnected => "Run `teagarden auth login` to connect to Telegram",
            TelegramError::AuthRequired => {
                "Run `teagarden auth login` to authenticate with your Telegram account"
            }
            TelegramError::Upload(_) => "Check your internet connection and try again",
            TelegramError::Download(_) => {
                "Check your internet connection; the message may have been deleted from Telegram"
            }
            TelegramError::MessageNotFound(_) => {
                "The block may have been deleted from the Telegram group"
            }
            TelegramError::Delete(_) => "You may lack admin permissions in the storage group",
            TelegramError::BlockTooLarge { .. } => "Reduce the volume's block size configuration",
            TelegramError::Session(_) => {
                "Try `teagarden auth logout` then `teagarden auth login` to reset the session"
            }
            TelegramError::RateLimited { seconds } => {
                if *seconds > 60 {
                    "Telegram is rate-limiting requests; wait and try again later"
                } else {
                    "Telegram is rate-limiting requests; retrying automatically"
                }
            }
            TelegramError::Api(_) => {
                "Check Telegram service status; this may be a temporary outage"
            }
            TelegramError::Io(_) => "Check file permissions and available disk space",
            TelegramError::Timeout => "Transport timed out; check network connectivity",
        }
    }
}

/// Convenience result type for Telegram transport operations.
pub type Result<T> = std::result::Result<T, TelegramError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_have_suggestions() {
        let errors: Vec<TelegramError> = vec![
            TelegramError::NotConnected,
            TelegramError::AuthRequired,
            TelegramError::Upload("test".into()),
            TelegramError::Download("test".into()),
            TelegramError::MessageNotFound(42),
            TelegramError::Delete("test".into()),
            TelegramError::BlockTooLarge { size: 100, max: 50 },
            TelegramError::Session("test".into()),
            TelegramError::RateLimited { seconds: 30 },
            TelegramError::Api("test".into()),
            TelegramError::Timeout,
        ];

        for err in &errors {
            assert!(!err.suggestion().is_empty(), "Empty suggestion for: {err}");
        }
    }

    #[test]
    fn not_connected_suggests_login() {
        let err = TelegramError::NotConnected;
        assert!(err.suggestion().contains("login"));
    }

    #[test]
    fn rate_limit_long_wait_suggests_later() {
        let err = TelegramError::RateLimited { seconds: 120 };
        assert!(err.suggestion().contains("later"));
    }

    #[test]
    fn rate_limit_short_wait_suggests_auto_retry() {
        let err = TelegramError::RateLimited { seconds: 10 };
        assert!(err.suggestion().contains("automatically"));
    }
}
