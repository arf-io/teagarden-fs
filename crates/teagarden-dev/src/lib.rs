//! `teagarden-dev` — an encrypted, position-addressed, **log-structured block
//! device** backed by Telegram (LUKS-like at the crypto layer).
//!
//! It presents a mutable `LBA → bytes` device via the shared
//! [`teagarden_blockdev::BlockDevice`] seam, so any overlay filesystem
//! (ext4 / xfs / zfs / TeaGarden) can `mkfs` and mount on it over NBD.
//! Storage is append-only ~45 MiB **segments** (one
//! Telegram message each) indexed by an in-RAM **FTL** (`LBA → segment/offset/
//! len/epoch`), made durable by a custom on-segment **FTL-delta log** plus
//! periodic checkpoints — no SQLite (D2). A local durable **write-back staging**
//! log is the default fsync barrier and a **persistent scored cache** keeps the
//! hot working set warm; Telegram is the offsite/cold tier.
//!
//! Positioning: an **archival, non-critical cold/warm store** (logs, CCTV,
//! backups, media) — fast when warm, slow/variable on cold misses; not a rootfs
//! or a write-churn subsystem. User documentation: `docs/BLOCK_DEVICE.md`; formats:
//! `docs/FORMAT.md` §7–§12.
//!
//! **Status (2026-07-02).** The storage engine is implemented and audited: record
//! crypto + segment framing + FTL + FTL-delta log (M2a), superblock + durable
//! write-back staging + scored persistent cache + write/read paths (M2b), per-epoch
//! keys + rotation + resize (M2c), full crash + fresh-machine recovery — local
//! staging replay (M2d-1) and the cloud-consistent `DeviceHead` watermark (M2d-2) —
//! the **opaque on-wire format v2** (M2e: sealed header/trailer/records, random
//! names, size padding), live-Telegram e2e ([`device::TeaGardenDevice`] over the real
//! transport, P3), the OS block exposure ([`adapter::BlockDeviceAdapter`] + the
//! `teagarden-nbd` server, P5.1/P5.2, kernel-proven ext4/xfs/btrfs), and **garbage
//! collection** ([`device::TeaGardenDevice::gc`] + [`gc`] policy, P4: liveness
//! accounting, dead-bytes victim selection, epoch-re-sealing compaction, and the
//! crash-safe compact→confirm→checkpoint→delete ordering with catalog tombstones).
//! Still ahead for 1.0.0: ranged reads (P3.1), the rate governor (P3.4), head
//! pinning/discovery (P3.2), and CLI serve entrypoints (P7). An iSCSI front-end is
//! not part of 1.0 (the experimental crate was removed); NBD is the only block
//! export.

pub mod adapter;
pub mod cache;
pub mod device;
mod dirlock;
pub mod error;
pub mod ftl;
pub mod ftl_log;
pub mod gc;
pub mod head;
pub mod recovery;
pub mod sector_crypto;
pub mod segment;
pub mod staging;
pub mod superblock;
pub mod wal;

#[cfg(all(test, unix))]
pub(crate) mod testutil;

pub use dirlock::DeviceDirGuard;
pub use error::DeviceError;

/// Logical block size presented to the OS (re-exported from the shared seam).
pub use teagarden_blockdev::LOGICAL_BLOCK_SIZE;

/// Target size of a sealed segment (one Telegram document). ~45 MiB — the
/// largest cloud-bot-safe document, matching TeaGarden's block size.
pub const SEGMENT_TARGET: u64 = 45 * 1024 * 1024;
/// Hard cap on a sealed segment before it must be flushed to Telegram.
pub const SEGMENT_HARD_CAP: u64 = 49 * 1024 * 1024;
/// Maximum plaintext bytes in one record within a segment.
pub const RECORD_MAX: u64 = 1024 * 1024;
