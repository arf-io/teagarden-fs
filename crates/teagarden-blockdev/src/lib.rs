//! Shared block-device abstraction for TeaGarden.
//!
//! [`BlockDevice`] is the single seam that storage back-ends implement and that
//! block-protocol front-ends consume. `teagarden-dev` (the encrypted, Telegram
//! -backed log-structured block device) and the in-memory test double both
//! implement it; the NBD server is written generically over it. Keeping the trait in its own leaf crate lets the front-ends depend
//! on the seam without pulling in the (heavy) back-end, and lets the back-end
//! be tested against a trivial in-memory device.
//!
//! The trait is deliberately **synchronous**: the SCSI/NBD command handlers are
//! sync, and async back-ends (e.g. `teagarden-dev` over Telegram) bridge to async
//! internally while the front-end invokes them from `spawn_blocking`.

#![deny(missing_docs)]

use std::io;

/// Logical block size (bytes) presented to the OS / initiator. Every `lba` and
/// `count` argument in [`BlockDevice`] is expressed in units of this size.
pub const LOGICAL_BLOCK_SIZE: u64 = 4096;

/// A synchronous, position-addressed block device.
pub trait BlockDevice: Send + Sync + 'static {
    /// Total capacity in bytes (a multiple of [`LOGICAL_BLOCK_SIZE`]).
    fn capacity(&self) -> u64;

    /// Read `count` logical blocks starting at `lba` into `buf`.
    /// `buf.len()` must equal `count as usize * LOGICAL_BLOCK_SIZE as usize`.
    fn read_blocks(&self, lba: u64, count: u32, buf: &mut [u8]) -> io::Result<()>;

    /// Write `count` logical blocks starting at `lba` from `data`.
    /// `data.len()` must equal `count as usize * LOGICAL_BLOCK_SIZE as usize`.
    fn write_blocks(&self, lba: u64, count: u32, data: &[u8]) -> io::Result<()>;

    /// Flush buffered writes to durable storage (SCSI SYNCHRONIZE CACHE / NBD
    /// FLUSH). The default is a no-op for volatile devices; durable devices
    /// override it so they never falsely report durability to the initiator.
    fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    /// Hint that `count` logical blocks starting at `lba` are no longer in use
    /// (SCSI UNMAP / NBD TRIM). The default is a no-op; log-structured devices
    /// override it to mark the extent dead so GC can reclaim the space. An
    /// implementation must never corrupt or expose neighbouring live data.
    fn discard(&self, _lba: u64, _count: u32) -> io::Result<()> {
        Ok(())
    }

    /// Durably tear the device down on clean detach (the export is being torn
    /// down / the server is stopping). The default just [`flush`](Self::flush)es;
    /// a cloud-backed device overrides it to *finalize offsite durability* — seal
    /// and upload any still-open segment — so a clean detach never leaves data
    /// reachable only from a local buffer. A front-end should call this when it
    /// stops serving an export, distinct from a per-request `flush`.
    fn shutdown(&self) -> io::Result<()> {
        self.flush()
    }
}

/// A cloud-backed device that publishes **recovery points**: records a fresh
/// machine can rebuild the device from (for TeaGarden block devices, a `DeviceHead`
/// checkpoint). A front-end that serves such a device publishes one
/// periodically and one after [`BlockDevice::shutdown`], so a crash or the loss
/// of the machine costs at most what was not yet published.
///
/// Like [`BlockDevice`], the methods are synchronous and are called from
/// blocking threads (`spawn_blocking`), never from an async task.
pub trait RecoveryPoints: BlockDevice {
    /// Durable-offsite progress not yet covered by a published recovery point,
    /// in the device's own units (TeaGarden block device: uploaded segments). `0` = a new
    /// recovery point would add nothing.
    fn unpublished(&self) -> io::Result<u64>;

    /// Publish a recovery point covering everything that is durable offsite now.
    /// Returns its id (TeaGarden block device: the head's Telegram message id), which is what
    /// recovery needs.
    fn publish_recovery_point(&self) -> io::Result<i64>;
}

#[cfg(feature = "test-util")]
mod mem;
#[cfg(feature = "test-util")]
pub use mem::MemBlockDevice;
