use thiserror::Error;

/// All errors produced by the `teagarden-core` crate.
#[derive(Debug, Error)]
pub enum CoreError {
    /// AEAD encryption of a block or metadata record failed.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// AEAD decryption failed (wrong key, tampering, or corruption).
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// Argon2id/HKDF key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// Key material is invalid, truncated, or version-incompatible.
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    /// An integrity hash did not match the expected value.
    ///
    /// The hash values are intentionally not exposed in the `Display` output to
    /// avoid leaking them.
    #[error("integrity check failed: hash mismatch")]
    IntegrityError {
        /// The hash the data was expected to have (per the stored metadata).
        expected: String,
        /// The hash actually computed over the data on read.
        actual: String,
    },

    /// A stored block is malformed or has an unrecognized format.
    #[error("block format error: {0}")]
    BlockFormat(String),

    /// Compressing plaintext before encryption failed.
    #[error("compression error: {0}")]
    Compression(String),

    /// Decompressing a stored block failed.
    #[error("decompression error: {0}")]
    Decompression(String),

    /// Content-defined chunking of input data failed.
    #[error("CDC chunking error: {0}")]
    Chunking(String),

    /// A volume policy was violated or is misconfigured.
    #[error("policy error: {0}")]
    Policy(String),

    /// Encoding or decoding a sentence reference failed.
    #[error("sentence encoding error: {0}")]
    SentenceEncoding(String),

    /// An inode record is invalid or corrupted.
    #[error("invalid inode: {0}")]
    InvalidInode(String),

    /// A file manifest is inconsistent or corrupted.
    #[error("manifest error: {0}")]
    Manifest(String),

    /// Snapshot metadata is corrupted or could not be processed.
    #[error("snapshot error: {0}")]
    Snapshot(String),

    /// An authenticated journal entry could not be applied to the database
    /// rebuilt so far (its base snapshot and the entries before it): the entry
    /// was written against a different database. Fetch, MAC and hash failures
    /// are never this variant.
    #[error("journal entry seq {seq} does not apply to its base snapshot: {detail}")]
    JournalApply {
        /// `seq` of the entry that did not apply.
        seq: u64,
        /// What SQLite reported.
        detail: String,
    },

    /// A volume-level operation failed (missing/inaccessible volume, etc.).
    #[error("volume error: {0}")]
    Volume(String),

    /// (De)serialization of an on-disk structure failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Volume is temporarily locked after repeated wrong-password attempts.
    #[error("volume locked after too many failed attempts; retry in {retry_after_secs}s")]
    Locked {
        /// Seconds remaining before the lockout expires and retries are allowed.
        retry_after_secs: u64,
    },

    /// Epoch counter has reached u32::MAX and cannot be incremented further.
    #[error("epoch counter overflow: maximum epoch reached")]
    EpochOverflow,
}

impl CoreError {
    /// Returns a user-facing suggestion for how to resolve this error.
    pub fn suggestion(&self) -> &'static str {
        match self {
            CoreError::Encryption(_) => {
                "Check that the key material is valid and the plaintext is not corrupted"
            }
            CoreError::Decryption(_) => {
                "Verify your password is correct, or the volume may be corrupted"
            }
            CoreError::KeyDerivation(_) => {
                "Ensure sufficient system memory for Argon2 KDF parameters"
            }
            CoreError::InvalidKey(_) => {
                "Key material may be truncated or from an incompatible version"
            }
            CoreError::IntegrityError { .. } => {
                "Data may have been tampered with or corrupted in transit"
            }
            CoreError::BlockFormat(_) => "Block data is malformed; the volume may need repair",
            CoreError::Compression(_) => "Input data may be too large or corrupted",
            CoreError::Decompression(_) => {
                "Stored block is corrupted or was compressed with an unsupported algorithm"
            }
            CoreError::Chunking(_) => "Input data may be empty or exceed maximum chunk size",
            CoreError::Policy(_) => {
                "Review volume policy configuration with `teagarden volume info`"
            }
            CoreError::SentenceEncoding(_) => {
                "Sentence reference may be from an incompatible version"
            }
            CoreError::InvalidInode(_) => {
                "The file or directory metadata is corrupted; consider restoring from a snapshot"
            }
            CoreError::Manifest(_) => {
                "File manifest is inconsistent; try unmounting and remounting the volume"
            }
            CoreError::Snapshot(_) => {
                "The metadata snapshot was refused (older than the volume's anti-rollback floor, \
                 not the one the volume recorded, or damaged); `teagarden volume restore <volume>` \
                 restores the snapshot the volume names"
            }
            CoreError::JournalApply { .. } => {
                "The journal was written against another database than its base snapshot; \
                 `teagarden volume restore <volume> --discard-journal` puts the snapshot back"
            }
            CoreError::Volume(_) => "Check that the volume directory exists and is accessible",
            CoreError::Serialization(_) => "Data format may be incompatible with this version",
            CoreError::Locked { retry_after_secs } => {
                let _ = retry_after_secs;
                "Too many wrong-password attempts; wait for the lockout to expire"
            }
            CoreError::EpochOverflow => {
                "Volume epoch has reached its maximum value; create a new volume"
            }
        }
    }
}

/// Convenience result type with [`CoreError`] as the error variant.
pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_have_suggestions() {
        let errors: Vec<CoreError> = vec![
            CoreError::Encryption("test".into()),
            CoreError::Decryption("test".into()),
            CoreError::KeyDerivation("test".into()),
            CoreError::InvalidKey("test".into()),
            CoreError::IntegrityError {
                expected: "a".into(),
                actual: "b".into(),
            },
            CoreError::BlockFormat("test".into()),
            CoreError::Compression("test".into()),
            CoreError::Decompression("test".into()),
            CoreError::Chunking("test".into()),
            CoreError::Policy("test".into()),
            CoreError::JournalApply {
                seq: 1,
                detail: "test".into(),
            },
            CoreError::SentenceEncoding("test".into()),
            CoreError::InvalidInode("test".into()),
            CoreError::Manifest("test".into()),
            CoreError::Snapshot("test".into()),
            CoreError::Volume("test".into()),
            CoreError::Serialization("test".into()),
            CoreError::Locked {
                retry_after_secs: 30,
            },
            CoreError::EpochOverflow,
        ];

        for err in &errors {
            let suggestion = err.suggestion();
            assert!(!suggestion.is_empty(), "Empty suggestion for: {err}");
        }
    }

    #[test]
    fn decryption_error_suggests_password_check() {
        let err = CoreError::Decryption("aead failure".into());
        assert!(
            err.suggestion().contains("password"),
            "Decryption suggestion should mention password"
        );
    }

    #[test]
    fn integrity_error_does_not_leak_hashes() {
        let err = CoreError::IntegrityError {
            expected: "abc123deadbeef".into(),
            actual: "def456cafebabe".into(),
        };
        let display = format!("{err}");
        // Hash values should NOT appear in the display string
        assert!(!display.contains("abc123deadbeef"));
        assert!(!display.contains("def456cafebabe"));
        assert!(display.contains("hash mismatch"));
    }
}
