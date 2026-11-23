//! Error type for the block device.

use std::io;

/// Errors from the `teagarden-dev` engine. Maps to [`std::io::Error`] at the
/// [`crate::adapter::BlockDeviceAdapter`] boundary so the block seam stays
/// `io::Result`-based.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// A local I/O error (staging log, cache, superblock file).
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// AEAD open/seal failure, or an integrity/AAD mismatch (fail-closed).
    #[error("crypto: {0}")]
    Crypto(String),

    /// A Telegram transport error (upload / ranged download / delete).
    #[error("transport: {0}")]
    Transport(String),

    /// On-disk or on-wire structure failed verification (torn/forged segment,
    /// bad footer MAC, non-contiguous FTL-delta log).
    #[error("corruption: {0}")]
    Corruption(String),

    /// Reserved for an anti-rollback check (a stale generation / rolled-back
    /// head). No code path returns it today: neither the superblock nor the
    /// `DeviceHead` generation is anchored externally, so rollback of either
    /// is currently NOT detected (M3/M4).
    #[error("rollback rejected: {0}")]
    Rollback(String),

    /// A request addressed an LBA beyond the device capacity.
    #[error("out of range: lba {lba} count {count} exceeds capacity {capacity_blocks} blocks")]
    OutOfRange {
        /// First logical block of the offending request.
        lba: u64,
        /// Number of logical blocks requested.
        count: u32,
        /// Device capacity in logical blocks.
        capacity_blocks: u64,
    },

    /// Writes are blocked because the local staging cannot drain to Telegram
    /// (offline / full) — the device is read-only until it drains.
    #[error("staging full / offline: writes blocked until drain")]
    StagingFull,
}

impl From<DeviceError> for io::Error {
    fn from(e: DeviceError) -> Self {
        match e {
            DeviceError::Io(io) => io,
            DeviceError::OutOfRange { .. } => io::Error::new(io::ErrorKind::InvalidInput, e),
            // `StagingFull` semantically wants ENOSPC/`StorageFull`, but that
            // `ErrorKind` is MSRV 1.83+ (workspace is 1.75). The NBD/iSCSI
            // adapter (P5) matches the `DeviceError` variant directly for a
            // precise SCSI sense / NBD errno; this conversion is the fallback.
            _ => io::Error::other(e),
        }
    }
}

/// Convenience result alias for engine methods.
pub type Result<T> = std::result::Result<T, DeviceError>;
