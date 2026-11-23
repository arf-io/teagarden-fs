use thiserror::Error;

/// Errors that can occur while reading from or writing to the block cache.
#[derive(Debug, Error)]
pub enum CacheError {
    /// The requested block is not present in the cache (carries the block RID).
    #[error("block not in cache: {0}")]
    Miss(String),

    /// An underlying filesystem I/O error while accessing the cache directory.
    #[error("cache IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Encrypting a block before writing it to disk failed.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// Decrypting a cached block after reading it from disk failed.
    #[error("decryption error: {0}")]
    Decryption(String),

    /// The cache is full and eviction could not free enough space.
    #[error("cache full, eviction failed")]
    EvictionFailed,
}

impl CacheError {
    /// Returns a user-facing suggestion for how to resolve this error.
    pub fn suggestion(&self) -> &'static str {
        match self {
            CacheError::Miss(_) => {
                "Block will be fetched from Telegram; this is normal on first access"
            }
            CacheError::Io(_) => "Check available disk space and cache directory permissions",
            CacheError::Encryption(_) => {
                "Cache encryption key may be invalid; try remounting the volume"
            }
            CacheError::Decryption(_) => {
                "Cached block is corrupted; it will be re-fetched from Telegram"
            }
            CacheError::EvictionFailed => {
                "Increase cache size or free disk space in the cache directory"
            }
        }
    }
}

/// Convenience alias for results returned by cache operations.
pub type Result<T> = std::result::Result<T, CacheError>;
