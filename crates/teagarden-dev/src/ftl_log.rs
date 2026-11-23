//! Append-only FTL-delta log (P1.4a) — the durable authority for the FTL.
//!
//! Per decision **D2** (no SQLite), the FTL's durability comes from an
//! append-only journal of the mutations applied to it: each write records a
//! [`FtlDelta::Map`], each discard an [`FtlDelta::Unmap`]. Replaying the log onto
//! an empty (or checkpointed) [`Ftl`] reconstructs the exact mapping. The log is
//! **torn-tail tolerant**: replay applies every complete frame and stops at the
//! first partial/corrupt frame (the crash point), so a write interrupted mid-append
//! never corrupts recovery — it just isn't replayed.
//!
//! This module owns only the delta **serialization + framing + replay** — a pure,
//! transport-free unit. Encryption-at-rest and fsync are the staging layer's job
//! ([`crate::staging`]); on-Telegram, a sealed segment's index (see
//! [`crate::segment`]) is the equivalent per-segment delta record.

use crate::error::{DeviceError, Result};
use crate::ftl::{Ftl, Phys};

const TAG_MAP: u8 = 1;
const TAG_UNMAP: u8 = 2;
const TAG_RELOCATE: u8 = 3;

/// One mutation of the FTL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FtlDelta {
    /// Map `[lba, lba+count)` to `phys` (a write / overwrite).
    Map {
        /// First logical block.
        lba: u64,
        /// Number of logical blocks.
        count: u64,
        /// Physical location the blocks now live at.
        phys: Phys,
    },
    /// Unmap `[lba, lba+count)` (a discard / trim).
    Unmap {
        /// First logical block.
        lba: u64,
        /// Number of logical blocks.
        count: u64,
    },
    /// GC compaction repoint (P4): `[lba, lba+count)` now lives at `phys`, but the
    /// logical CONTENT is unchanged — the bytes were moved from a victim segment,
    /// not written. For the live FTL this applies exactly like [`FtlDelta::Map`];
    /// the barrier-consistent prefix replay treats it differently (skip, not
    /// break, when `phys.segment_id` is past the watermark): the superseded ≤-
    /// watermark mapping is still byte-correct for the prefix, and the delete gate
    /// keeps the victim's message alive until a published head stops referencing
    /// it. Staged with the re-sealed record bytes, so an unconfirmed compaction
    /// segment is reconstructed on `open()` like any other.
    Relocate {
        /// First logical block.
        lba: u64,
        /// Number of logical blocks.
        count: u64,
        /// Physical location the (unchanged) blocks moved to.
        phys: Phys,
    },
}

impl FtlDelta {
    /// Serialize the delta body (without the length frame).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match *self {
            FtlDelta::Map { lba, count, phys } | FtlDelta::Relocate { lba, count, phys } => {
                v.push(if matches!(self, FtlDelta::Map { .. }) {
                    TAG_MAP
                } else {
                    TAG_RELOCATE
                });
                v.extend_from_slice(&lba.to_le_bytes());
                v.extend_from_slice(&count.to_le_bytes());
                v.extend_from_slice(&phys.segment_id.to_le_bytes());
                v.extend_from_slice(&phys.record_off.to_le_bytes());
                v.extend_from_slice(&phys.data_off.to_le_bytes());
                v.extend_from_slice(&phys.epoch.to_le_bytes());
            }
            FtlDelta::Unmap { lba, count } => {
                v.push(TAG_UNMAP);
                v.extend_from_slice(&lba.to_le_bytes());
                v.extend_from_slice(&count.to_le_bytes());
            }
        }
        v
    }

    /// Parse a delta body. Returns an error (never panics) on a bad tag or a
    /// short buffer.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let bad = || DeviceError::Corruption("malformed FTL delta".into());
        let &tag = b.first().ok_or_else(bad)?;
        let body = &b[1..];
        let ru = |o: usize| -> Result<u64> {
            body.get(o..o + 8)
                .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
                .ok_or_else(bad)
        };
        match tag {
            TAG_MAP | TAG_RELOCATE => {
                if body.len() != 8 * 5 + 4 {
                    return Err(bad());
                }
                let epoch = u32::from_le_bytes(body[8 * 5..8 * 5 + 4].try_into().unwrap());
                let (lba, count) = (ru(0)?, ru(8)?);
                let phys = Phys {
                    segment_id: ru(16)?,
                    record_off: ru(24)?,
                    data_off: ru(32)?,
                    epoch,
                };
                Ok(if tag == TAG_MAP {
                    FtlDelta::Map { lba, count, phys }
                } else {
                    FtlDelta::Relocate { lba, count, phys }
                })
            }
            TAG_UNMAP => {
                if body.len() != 16 {
                    return Err(bad());
                }
                Ok(FtlDelta::Unmap {
                    lba: ru(0)?,
                    count: ru(8)?,
                })
            }
            _ => Err(bad()),
        }
    }

    /// Apply this delta to an FTL. A `Relocate` applies exactly like a `Map` —
    /// the live FTL always points at the newest physical home; the two kinds
    /// differ only in how the barrier-consistent prefix replay treats them.
    pub fn apply(&self, ftl: &mut Ftl) {
        match *self {
            FtlDelta::Map { lba, count, phys } | FtlDelta::Relocate { lba, count, phys } => {
                ftl.map_range(lba, count, phys)
            }
            FtlDelta::Unmap { lba, count } => ftl.unmap_range(lba, count),
        }
    }

    /// True if the delta's LBA range is representable (`lba + count` fits in
    /// `u64`). `replay` rejects a non-representable delta (a corrupt frame)
    /// rather than applying it — the FTL would no-op it anyway, but recovery
    /// should fail closed at the corruption, not silently skip it.
    pub fn is_representable(&self) -> bool {
        let (lba, count) = match *self {
            FtlDelta::Map { lba, count, .. }
            | FtlDelta::Relocate { lba, count, .. }
            | FtlDelta::Unmap { lba, count } => (lba, count),
        };
        lba.checked_add(count).is_some()
    }
}

/// Append a delta to a log buffer as a length-framed record `[u32 len][body]`.
pub fn append(log: &mut Vec<u8>, delta: &FtlDelta) {
    let body = delta.to_bytes();
    log.extend_from_slice(&(body.len() as u32).to_le_bytes());
    log.extend_from_slice(&body);
}

/// Outcome of replaying a delta log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayResult {
    /// Number of deltas successfully applied.
    pub applied: usize,
    /// Number of bytes consumed (the position of the torn/clean tail).
    pub consumed: usize,
    /// True if replay stopped early at a partial/corrupt frame (a torn tail).
    pub torn_tail: bool,
}

/// Replay a framed delta log onto `ftl`, applying every complete frame in order.
/// Stops at the first partial or malformed frame (the crash point) and reports it
/// as a torn tail rather than failing — the good prefix is always applied.
pub fn replay(log: &[u8], ftl: &mut Ftl) -> ReplayResult {
    let mut pos = 0usize;
    let mut applied = 0usize;
    while pos + 4 <= log.len() {
        let len = u32::from_le_bytes(log[pos..pos + 4].try_into().unwrap()) as usize;
        if len == 0 || pos + 4 + len > log.len() {
            return ReplayResult {
                applied,
                consumed: pos,
                torn_tail: true,
            };
        }
        let body = &log[pos + 4..pos + 4 + len];
        match FtlDelta::from_bytes(body) {
            // A well-formed AND representable delta is applied; a parse error or
            // an overflowing range stops replay fail-closed at the corruption.
            Ok(d) if d.is_representable() => {
                d.apply(ftl);
                applied += 1;
                pos += 4 + len;
            }
            _ => {
                return ReplayResult {
                    applied,
                    consumed: pos,
                    torn_tail: true,
                }
            }
        }
    }
    ReplayResult {
        applied,
        consumed: pos,
        torn_tail: pos != log.len(), // trailing <4 bytes counts as torn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ftl::{Ftl, Phys, ReadPiece, Source};

    fn phys(seg: u64) -> Phys {
        Phys {
            segment_id: seg,
            record_off: seg * 10,
            data_off: 0,
            epoch: (seg % 3) as u32,
        }
    }

    /// `p` with `data_off` advanced by `blocks` logical blocks (for the split
    /// expectations after replay).
    fn at(mut p: Phys, blocks: u64) -> Phys {
        p.data_off += blocks * teagarden_blockdev::LOGICAL_BLOCK_SIZE;
        p
    }

    #[test]
    fn delta_bytes_round_trip() {
        let m = FtlDelta::Map {
            lba: 42,
            count: 7,
            phys: phys(5),
        };
        assert_eq!(FtlDelta::from_bytes(&m.to_bytes()).unwrap(), m);
        let u = FtlDelta::Unmap { lba: 3, count: 9 };
        assert_eq!(FtlDelta::from_bytes(&u.to_bytes()).unwrap(), u);
        // P4: Relocate round-trips as its own kind (never decodes as a Map — the
        // prefix replay treats the two differently) and applies like a Map.
        let r = FtlDelta::Relocate {
            lba: 42,
            count: 7,
            phys: phys(6),
        };
        assert_eq!(FtlDelta::from_bytes(&r.to_bytes()).unwrap(), r);
        assert_ne!(r.to_bytes()[0], m.to_bytes()[0], "distinct wire tags");
        let mut via_map = Ftl::new();
        let mut via_reloc = Ftl::new();
        FtlDelta::Map {
            lba: 42,
            count: 7,
            phys: phys(6),
        }
        .apply(&mut via_map);
        r.apply(&mut via_reloc);
        assert_eq!(
            via_map.resolve_read(40, 12),
            via_reloc.resolve_read(40, 12),
            "Relocate applies to the live FTL exactly like Map"
        );
    }

    #[test]
    fn from_bytes_rejects_garbage() {
        assert!(FtlDelta::from_bytes(&[]).is_err()); // empty
        assert!(FtlDelta::from_bytes(&[9, 0, 0]).is_err()); // bad tag
        assert!(FtlDelta::from_bytes(&[TAG_UNMAP, 0, 0]).is_err()); // short body
    }

    // Replaying the log reconstructs exactly the FTL that direct application does.
    #[test]
    fn replay_reconstructs_the_ftl() {
        let deltas = vec![
            FtlDelta::Map {
                lba: 0,
                count: 10,
                phys: phys(1),
            },
            FtlDelta::Map {
                lba: 3,
                count: 2,
                phys: phys(2),
            },
            FtlDelta::Unmap { lba: 8, count: 1 },
            FtlDelta::Map {
                lba: 100,
                count: 4,
                phys: phys(3),
            },
        ];

        // reference: apply directly
        let mut want = Ftl::new();
        for d in &deltas {
            d.apply(&mut want);
        }

        // replay from a serialized log
        let mut log = Vec::new();
        for d in &deltas {
            append(&mut log, d);
        }
        let mut got = Ftl::new();
        let res = replay(&log, &mut got);
        assert_eq!(res.applied, 4);
        assert!(!res.torn_tail);
        assert_eq!(res.consumed, log.len());

        // compare via resolve_read over the whole touched range
        assert_eq!(got.resolve_read(0, 110), want.resolve_read(0, 110));
        assert_eq!(got.mapped_blocks(), want.mapped_blocks());
    }

    // A torn tail (write interrupted mid-append) applies the good prefix and
    // reports the tear — recovery is not corrupted.
    #[test]
    fn torn_tail_applies_prefix_and_reports() {
        let mut log = Vec::new();
        append(
            &mut log,
            &FtlDelta::Map {
                lba: 0,
                count: 5,
                phys: phys(1),
            },
        );
        append(
            &mut log,
            &FtlDelta::Map {
                lba: 5,
                count: 5,
                phys: phys(2),
            },
        );
        let clean_len = log.len();
        // append a third delta, then truncate it halfway (a crash mid-write)
        append(
            &mut log,
            &FtlDelta::Map {
                lba: 10,
                count: 5,
                phys: phys(3),
            },
        );
        log.truncate(clean_len + 6);

        let mut ftl = Ftl::new();
        let res = replay(&log, &mut ftl);
        assert_eq!(res.applied, 2);
        assert!(res.torn_tail);
        assert_eq!(res.consumed, clean_len);
        // blocks 0..10 mapped, 10.. is a hole (the torn write was not applied)
        assert_eq!(ftl.mapped_blocks(), 10);
        let r = ftl.resolve_read(8, 5);
        assert_eq!(
            r,
            vec![
                ReadPiece {
                    lba: 8,
                    count: 2,
                    source: Source::Mapped(at(phys(2), 3))
                },
                ReadPiece {
                    lba: 10,
                    count: 3,
                    source: Source::Hole
                },
            ]
        );
    }

    // A corrupt frame (bad tag) mid-log stops replay at that point, good prefix intact.
    #[test]
    fn corrupt_frame_stops_replay() {
        let mut log = Vec::new();
        append(
            &mut log,
            &FtlDelta::Map {
                lba: 0,
                count: 3,
                phys: phys(1),
            },
        );
        // hand-write a framed but malformed delta (len=3, bad tag)
        log.extend_from_slice(&3u32.to_le_bytes());
        log.extend_from_slice(&[0xFF, 0x00, 0x00]);
        append(
            &mut log,
            &FtlDelta::Map {
                lba: 3,
                count: 3,
                phys: phys(2),
            },
        );

        let mut ftl = Ftl::new();
        let res = replay(&log, &mut ftl);
        assert_eq!(res.applied, 1); // only the first good delta
        assert!(res.torn_tail);
        assert_eq!(ftl.mapped_blocks(), 3);
    }

    // A well-formed but OVERFLOWING delta (lba+count wraps u64) is rejected:
    // replay stops fail-closed at it, applying only the good prefix.
    #[test]
    fn replay_rejects_overflowing_delta() {
        let mut log = Vec::new();
        append(
            &mut log,
            &FtlDelta::Map {
                lba: 0,
                count: 4,
                phys: phys(1),
            },
        );
        append(
            &mut log,
            &FtlDelta::Map {
                lba: u64::MAX,
                count: 4,
                phys: phys(2),
            },
        );
        append(
            &mut log,
            &FtlDelta::Map {
                lba: 10,
                count: 4,
                phys: phys(3),
            },
        );

        let mut ftl = Ftl::new();
        let res = replay(&log, &mut ftl);
        assert_eq!(res.applied, 1); // only the first, good delta
        assert!(res.torn_tail);
        assert_eq!(ftl.mapped_blocks(), 4);
    }
}
