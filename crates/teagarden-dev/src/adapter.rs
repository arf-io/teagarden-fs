//! `BlockDeviceAdapter` — bridges the async [`TeaGardenDevice`] engine to the
//! synchronous [`teagarden_blockdev::BlockDevice`] seam (P5.1).
//!
//! The block-protocol front-ends (the iSCSI target, the NBD server) are written
//! against the **synchronous** `BlockDevice` trait and invoke it from
//! `spawn_blocking` threads. The engine underneath is **async** and takes
//! `&mut self` (it mutates the open segment, FTL, staging, and cache on every
//! I/O). This adapter reconciles the two: it owns the device behind an async
//! [`tokio::sync::Mutex`] (interior mutability + single-writer serialization,
//! matching the engine's single-writer scope) and drives each call to completion
//! with a stored [`tokio::runtime::Handle`].
//!
//! `Handle::block_on` is safe here because the front-ends call the sync trait from
//! `spawn_blocking` worker threads (or any non-async thread), never from inside an
//! async task on the same runtime — so it never blocks a runtime worker.
//!
//! ## Contracts and known properties (advisor review, P5.1)
//!
//! - **The runtime MUST be multi-threaded.** `Handle::block_on` from a blocking
//!   thread is only reliably safe on a `multi_thread` runtime; on a
//!   `current_thread` runtime it deadlocks. The serve entrypoints (NBD / iSCSI)
//!   must run under `#[tokio::main(flavor = "multi_thread")]` — this is a contract,
//!   not an assumption.
//! - **Global serialization.** A single async `Mutex` serializes *every*
//!   read/write/flush across all connections. This is correct for the engine's
//!   single-writer scope and the archival positioning, but it is a real throughput
//!   ceiling: a filesystem's parallel metadata reads get no concurrency (the
//!   per-reader snapshot is future work, plan P1.6/G19).
//! - **`flush` is D8 local-durable, not cloud-durable.** A SCSI SYNCHRONIZE CACHE /
//!   NBD FLUSH acks after the local staging fsync — it survives a process crash,
//!   NOT loss of the machine before the tail uploads. A journaling filesystem
//!   mounted on top treats FLUSH as an offsite barrier; it is not one unless
//!   cloud-durable mode is enabled. This must be stated plainly in the user docs.
//! - **Live-load risk (tracked, P3).** Each in-flight request pins a blocking-pool
//!   thread for the whole operation; cold Telegram reads can take seconds, and if
//!   the real transport itself uses `spawn_blocking` inside `read_at`, the
//!   `spawn_blocking → block_on → spawn_blocking` nesting can saturate the bounded
//!   pool. The mock cannot surface this; it is load-tested under the live transport
//!   at P3, with the actor pattern (one owning task + `mpsc`/`oneshot`) as the
//!   fallback architecture if it bites.

use std::io;
use std::sync::Arc;

use tokio::runtime::Handle;
use tokio::sync::Mutex;

use teagarden_blockdev::{BlockDevice, RecoveryPoints, LOGICAL_BLOCK_SIZE};
use teagarden_telegram::client::BlockTransport;

use crate::device::TeaGardenDevice;
use crate::error::DeviceError;

fn to_io(e: DeviceError) -> io::Error {
    match e {
        DeviceError::OutOfRange { .. } => {
            io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
        }
        DeviceError::StagingFull => io::Error::new(io::ErrorKind::WouldBlock, e.to_string()),
        other => io::Error::other(other.to_string()),
    }
}

/// A synchronous [`BlockDevice`] view over an async [`TeaGardenDevice`].
pub struct BlockDeviceAdapter<T: BlockTransport + 'static> {
    dev: Arc<Mutex<TeaGardenDevice<T>>>,
    handle: Handle,
    /// Capacity presented to the OS/initiator, snapshotted at construction. The
    /// device is only resized through its async handle before it is wrapped, so
    /// once adapted the capacity is fixed (a live resize would need an OS rescan
    /// anyway).
    capacity_bytes: u64,
}

impl<T: BlockTransport + 'static> BlockDeviceAdapter<T> {
    /// Wrap `device`, driving its async I/O on `handle`. `handle` must belong to a
    /// live runtime and the sync trait must be invoked from non-async threads
    /// (e.g. `spawn_blocking`).
    pub fn new(device: TeaGardenDevice<T>, handle: Handle) -> Self {
        let capacity_bytes = device.capacity_blocks().saturating_mul(LOGICAL_BLOCK_SIZE);
        Self {
            dev: Arc::new(Mutex::new(device)),
            handle,
            capacity_bytes,
        }
    }
}

impl<T: BlockTransport + 'static> BlockDevice for BlockDeviceAdapter<T> {
    fn capacity(&self) -> u64 {
        self.capacity_bytes
    }

    fn read_blocks(&self, lba: u64, count: u32, buf: &mut [u8]) -> io::Result<()> {
        let expect = count as usize * LOGICAL_BLOCK_SIZE as usize;
        if buf.len() != expect {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "read buffer len {} != {expect} for {count} blocks",
                    buf.len()
                ),
            ));
        }
        let dev = Arc::clone(&self.dev);
        let data = self
            .handle
            .block_on(async move { dev.lock().await.read_at(lba, count as u64).await })
            .map_err(to_io)?;
        if data.len() != buf.len() {
            return Err(io::Error::other(format!(
                "device returned {} bytes, expected {}",
                data.len(),
                buf.len()
            )));
        }
        buf.copy_from_slice(&data);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, count: u32, data: &[u8]) -> io::Result<()> {
        let expect = count as usize * LOGICAL_BLOCK_SIZE as usize;
        if data.len() != expect {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "write data len {} != {expect} for {count} blocks",
                    data.len()
                ),
            ));
        }
        let dev = Arc::clone(&self.dev);
        let owned = data.to_vec();
        self.handle
            .block_on(async move { dev.lock().await.write_at(lba, &owned).await })
            .map_err(to_io)
    }

    fn flush(&self) -> io::Result<()> {
        let dev = Arc::clone(&self.dev);
        self.handle
            .block_on(async move { dev.lock().await.flush().await })
            .map_err(to_io)
    }

    fn discard(&self, lba: u64, count: u32) -> io::Result<()> {
        let dev = Arc::clone(&self.dev);
        self.handle
            .block_on(async move { dev.lock().await.discard(lba, count as u64).await })
            .map_err(to_io)
    }

    /// Finalize offsite durability on clean detach: seal the open segment, drain
    /// pending uploads, and flush staging (`TeaGardenDevice::close`). The front-end
    /// calls this when it stops serving the export.
    fn shutdown(&self) -> io::Result<()> {
        let dev = Arc::clone(&self.dev);
        self.handle
            .block_on(async move { dev.lock().await.close().await })
            .map_err(to_io)
    }
}

/// Recovery points are `DeviceHead` checkpoints: `publish_recovery_point` is
/// [`TeaGardenDevice::checkpoint`] (the head pins the contiguous confirmed prefix;
/// its message id is what `recover_from_head` takes), and `unpublished` counts
/// the uploaded segments the last head does not cover.
impl<T: BlockTransport + 'static> RecoveryPoints for BlockDeviceAdapter<T> {
    fn unpublished(&self) -> io::Result<u64> {
        let dev = Arc::clone(&self.dev);
        Ok(self
            .handle
            .block_on(async move { dev.lock().await.unpublished_segments() }))
    }

    fn publish_recovery_point(&self) -> io::Result<i64> {
        let dev = Arc::clone(&self.dev);
        self.handle
            .block_on(async move { dev.lock().await.checkpoint().await })
            .map_err(to_io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheConfig;
    use crate::device::{DeviceConfig, DeviceKeys};
    use teagarden_core::crypto::keys::SymmetricKey;
    use teagarden_telegram::mock::MockTransport;

    const BS: usize = LOGICAL_BLOCK_SIZE as usize;

    fn keys() -> DeviceKeys {
        DeviceKeys {
            data_key: SymmetricKey::from_bytes([1u8; 32]),
            meta_key: SymmetricKey::from_bytes([2u8; 32]),
            integrity_key: SymmetricKey::from_bytes([3u8; 32]),
        }
    }

    fn cfg() -> DeviceConfig {
        DeviceConfig {
            segment_target: 32 * 1024,
            record_max: 8 * 1024,
            cache: CacheConfig {
                budget_bytes: 1 << 30,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn adapter(dir: &tempfile::TempDir, cap: u64) -> BlockDeviceAdapter<MockTransport> {
        let rt = Handle::try_current();
        // build the device synchronously (create is sync)
        let t = Arc::new(MockTransport::new());
        let dev = TeaGardenDevice::create(t, keys(), [7u8; 16], cap, dir.path(), cfg()).unwrap();
        // in tests we run inside a current-thread runtime; use its handle
        BlockDeviceAdapter::new(dev, rt.expect("test must run in a tokio runtime"))
    }

    // The sync BlockDevice seam round-trips data through the async engine: write,
    // read back byte-exact, holes read zeros, flush + discard work, capacity is
    // reported in bytes. Driven from spawn_blocking so block_on runs off-worker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sync_seam_round_trips_over_async_engine() {
        let dir = tempfile::tempdir().unwrap();
        let dev = adapter(&dir, 1024);
        // exercise the SYNC trait from a blocking thread, as iSCSI/NBD do
        tokio::task::spawn_blocking(move || {
            assert_eq!(dev.capacity(), 1024 * LOGICAL_BLOCK_SIZE);

            // write 4 blocks at lba 0, 2 blocks at lba 10
            let a = vec![0xA1u8; 4 * BS];
            let b = vec![0xB2u8; 2 * BS];
            dev.write_blocks(0, 4, &a).unwrap();
            dev.write_blocks(10, 2, &b).unwrap();
            dev.flush().unwrap();

            // read them back byte-exact
            let mut buf = vec![0u8; 4 * BS];
            dev.read_blocks(0, 4, &mut buf).unwrap();
            assert_eq!(buf, a);
            let mut buf2 = vec![0u8; 2 * BS];
            dev.read_blocks(10, 2, &mut buf2).unwrap();
            assert_eq!(buf2, b);

            // a hole reads zeros
            let mut hole = vec![0xFFu8; BS];
            dev.read_blocks(5, 1, &mut hole).unwrap();
            assert_eq!(hole, vec![0u8; BS]);

            // discard → zeros
            dev.discard(0, 1).unwrap();
            let mut d0 = vec![0xFFu8; BS];
            dev.read_blocks(0, 1, &mut d0).unwrap();
            assert_eq!(d0, vec![0u8; BS]);

            // out-of-range and length-mismatch fail cleanly (no panic)
            assert!(dev.read_blocks(2000, 1, &mut vec![0u8; BS]).is_err());
            assert!(dev.write_blocks(0, 4, &[0u8; 100]).is_err());

            dev.shutdown().unwrap();
        })
        .await
        .unwrap();
    }

    // AUDIT P5 FIX-1: shutdown() finalizes OFFSITE durability — a partial (unsealed)
    // write is sealed + uploaded on clean detach, not left local-only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_finalizes_offsite_durability() {
        let dir = tempfile::tempdir().unwrap();
        let t = Arc::new(MockTransport::new());
        let dev =
            TeaGardenDevice::create(Arc::clone(&t), keys(), [7u8; 16], 1024, dir.path(), cfg())
                .unwrap();
        let adapter = BlockDeviceAdapter::new(dev, Handle::current());
        let t_in = Arc::clone(&t);
        tokio::task::spawn_blocking(move || {
            // a single block (< the 32 KiB seal target) stays in the open segment
            adapter.write_blocks(0, 1, &vec![0x11u8; BS]).unwrap();
            adapter.flush().unwrap();
            assert_eq!(t_in.message_count(), 0); // flushed locally, NOT uploaded
            adapter.shutdown().unwrap();
            assert!(t_in.message_count() >= 1); // shutdown sealed + uploaded it
        })
        .await
        .unwrap();
    }
}
