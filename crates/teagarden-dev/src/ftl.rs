//! In-RAM flash-translation-layer (FTL): the LBA → physical-location index.
//!
//! The FTL is an **interval map** from logical block ranges to the physical
//! record that currently holds their data. It is the freshness authority for
//! the device: a write appends a new record and re-points the LBA range at it
//! (superseding the old mapping); a read plans its fetches from the current
//! mapping, returning zeros for any unmapped ("hole") range. `discard` unmaps.
//!
//! This module is pure and transport-free — it owns no crypto and no network,
//! only the mapping — so it is exhaustively unit- and property-testable. Its
//! **durability** comes from the append-only FTL-delta log ([`crate::ftl_log`])
//! plus periodic checkpoints, per decision D2 (no SQLite).

use std::collections::{BTreeMap, HashMap};

use teagarden_blockdev::LOGICAL_BLOCK_SIZE;

/// Where an extent's data physically lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phys {
    /// The segment (one Telegram document) holding the record.
    pub segment_id: u64,
    /// Byte offset of the record within the (plaintext framing of the) segment.
    pub record_off: u64,
    /// Byte offset within the record's plaintext at which THIS extent's first
    /// logical block begins. Splitting an extent adjusts this without rewriting
    /// the underlying record.
    pub data_off: u64,
    /// Key epoch the record was sealed under (read resolves the epoch per record).
    pub epoch: u32,
}

/// One contiguous LBA extent and where it maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    lba_count: u64,
    phys: Phys,
}

/// The source of a resolved read piece.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Data lives at this physical location; `phys.data_off` already points at
    /// the first logical block of THIS piece.
    Mapped(Phys),
    /// Unmapped hole — the reader fills it with zeros.
    Hole,
}

/// One contiguous sub-range of a read, resolved to a single source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPiece {
    /// First logical block of the piece.
    pub lba: u64,
    /// Number of logical blocks in the piece.
    pub count: u64,
    /// Where to get the data.
    pub source: Source,
}

/// The flash-translation-layer index. `start_lba → entry` covering
/// `[start_lba, start_lba + lba_count)`, with the invariant that entries never
/// overlap (maintained by carving before every insert).
#[derive(Default, Debug)]
pub struct Ftl {
    map: BTreeMap<u64, Entry>,
    /// Per-segment liveness (P4.1): `segment_id → currently-mapped logical
    /// blocks`. Maintained incrementally by the same insert/remove paths that
    /// uphold the non-overlap invariant, so it is exact by construction (and
    /// re-verified against a full recompute in the property test). A segment
    /// that drops to zero is removed from the map — absence means dead.
    seg_live: HashMap<u64, u64>,
}

impl Ftl {
    /// Empty FTL — every LBA reads as a zero-filled hole.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of extents currently mapped (test/stat aid).
    pub fn extent_count(&self) -> usize {
        self.map.len()
    }

    /// Total number of logical blocks currently mapped (live logical size).
    pub fn mapped_blocks(&self) -> u64 {
        self.map.values().map(|e| e.lba_count).sum()
    }

    /// Export the current extents as `(lba, lba_count, phys)` in LBA order — used
    /// to serialize an FTL checkpoint into the `DeviceHead` (M2d-2). The extents
    /// are non-overlapping, so re-`map_range`-ing them into a fresh FTL reproduces
    /// this exact mapping.
    pub fn extents(&self) -> Vec<(u64, u64, Phys)> {
        self.map
            .iter()
            .map(|(&k, e)| (k, e.lba_count, e.phys))
            .collect()
    }

    /// Currently-mapped logical blocks living in `segment_id` (P4.1 liveness).
    /// Zero means the segment is fully dead (no extent references it).
    pub fn live_blocks(&self, segment_id: u64) -> u64 {
        self.seg_live.get(&segment_id).copied().unwrap_or(0)
    }

    /// Every segment with at least one live block, as `(segment_id, live_blocks)`
    /// in unspecified order (victim-selection input).
    pub fn live_segments(&self) -> Vec<(u64, u64)> {
        self.seg_live.iter().map(|(&s, &n)| (s, n)).collect()
    }

    /// All extents currently mapped into `segment_id`, in LBA order — the
    /// compaction input. A full-map walk (no reverse index); GC passes are rare
    /// relative to reads/writes, so the walk is the right cost trade.
    pub fn extents_of_segment(&self, segment_id: u64) -> Vec<(u64, u64, Phys)> {
        self.map
            .iter()
            .filter(|(_, e)| e.phys.segment_id == segment_id)
            .map(|(&k, e)| (k, e.lba_count, e.phys))
            .collect()
    }

    fn live_add(&mut self, seg: u64, blocks: u64) {
        if blocks > 0 {
            *self.seg_live.entry(seg).or_insert(0) += blocks;
        }
    }

    fn live_sub(&mut self, seg: u64, blocks: u64) {
        if blocks == 0 {
            return;
        }
        if let Some(v) = self.seg_live.get_mut(&seg) {
            *v = v.saturating_sub(blocks);
            if *v == 0 {
                self.seg_live.remove(&seg);
            }
        }
    }

    /// The exclusive end (highest mapped LBA + 1) of the highest extent, or
    /// `None` if nothing is mapped. Used to refuse a resize that would strand
    /// mapped data below the new capacity.
    pub fn max_mapped_end(&self) -> Option<u64> {
        self.map
            .iter()
            .next_back()
            .map(|(&k, e)| k.saturating_add(e.lba_count))
    }

    /// Map `[lba, lba+count)` to `phys`, superseding any prior mapping of those
    /// LBAs (an overwrite). A zero count, or an **unrepresentable** range whose
    /// `lba+count` overflows `u64`, is ignored: the device bounds every LBA by
    /// capacity before reaching the FTL (M2b), so a wrapping range only ever
    /// arrives from corrupt replay input, and it must never be allowed to break
    /// the non-overlap / no-wrap invariant.
    pub fn map_range(&mut self, lba: u64, count: u64, phys: Phys) {
        if count == 0 || lba.checked_add(count).is_none() {
            return;
        }
        self.carve(lba, count);
        self.map.insert(
            lba,
            Entry {
                lba_count: count,
                phys,
            },
        );
        self.live_add(phys.segment_id, count);
    }

    /// Unmap `[lba, lba+count)` — those LBAs become holes (read as zeros). A zero
    /// count or an unrepresentable (`lba+count` overflows `u64`) range is a no-op.
    pub fn unmap_range(&mut self, lba: u64, count: u64) {
        if count == 0 || lba.checked_add(count).is_none() {
            return;
        }
        self.carve(lba, count);
    }

    /// Point lookup for a single logical block: the physical location of `lba`,
    /// or `None` if it is a hole.
    pub fn lookup(&self, lba: u64) -> Option<Phys> {
        let (&k, &e) = self.map.range(..=lba).next_back()?;
        let e_end = k.saturating_add(e.lba_count);
        if lba < e_end {
            let mut p = e.phys;
            p.data_off = p
                .data_off
                .saturating_add((lba - k).saturating_mul(LOGICAL_BLOCK_SIZE));
            Some(p)
        } else {
            None
        }
    }

    /// Plan a read of `[lba, lba+count)`: an ordered list of contiguous pieces,
    /// each either `Mapped` (with `data_off` adjusted to the piece's first block)
    /// or a `Hole`. The pieces exactly tile the request with no gaps or overlaps.
    pub fn resolve_read(&self, lba: u64, count: u64) -> Vec<ReadPiece> {
        let mut pieces = Vec::new();
        if count == 0 {
            return pieces;
        }
        // Exclusive end as u128 so a read touching the very top block
        // (`end == 2^64`) still tiles correctly instead of saturating to
        // `u64::MAX` and under-covering the last block.
        let end: u128 = lba as u128 + count as u128;
        let mut cur = lba;

        // The possible left-neighbour (entry starting before `lba` that reaches
        // into the range), then every entry starting within `[lba, end)`.
        let left = self
            .map
            .range(..lba)
            .next_back()
            .filter(|(&k, &e)| k.saturating_add(e.lba_count) > lba)
            .map(|(&k, &e)| (k, e));
        let inner = self
            .map
            .range(lba..)
            .map(|(&k, &e)| (k, e))
            .take_while(|&(k, _)| (k as u128) < end);

        for (k, e) in left.into_iter().chain(inner) {
            let e_end = k.saturating_add(e.lba_count); // representable (no-wrap invariant)
            let seg_start = k.max(lba);
            let seg_end = ((e_end as u128).min(end)) as u64; // ≤ e_end ≤ u64::MAX
            if seg_start > cur {
                pieces.push(ReadPiece {
                    lba: cur,
                    count: seg_start - cur,
                    source: Source::Hole,
                });
            }
            let blocks_in = seg_start - k;
            let mut p = e.phys;
            p.data_off = p
                .data_off
                .saturating_add(blocks_in.saturating_mul(LOGICAL_BLOCK_SIZE));
            pieces.push(ReadPiece {
                lba: seg_start,
                count: seg_end - seg_start,
                source: Source::Mapped(p),
            });
            cur = seg_end;
        }
        if (cur as u128) < end {
            pieces.push(ReadPiece {
                lba: cur,
                count: (end - cur as u128) as u64,
                source: Source::Hole,
            });
        }
        pieces
    }

    /// Remove `[lba, lba+count)` from the map, splitting boundary entries so the
    /// range is left fully unmapped and all other entries are untouched. This is
    /// the single primitive under both `map_range` (carve-then-insert) and
    /// `unmap_range`. Preserves the non-overlap invariant.
    fn carve(&mut self, lba: u64, count: u64) {
        let end = lba.saturating_add(count);
        let mut to_remove: Vec<u64> = Vec::new();
        let mut to_insert: Vec<(u64, Entry)> = Vec::new();

        // 1) Entry starting strictly before `lba` that reaches into the range.
        if let Some((&k, &e)) = self.map.range(..lba).next_back() {
            let e_end = k.saturating_add(e.lba_count);
            if e_end > lba {
                to_remove.push(k);
                // left survivor [k, lba)
                to_insert.push((
                    k,
                    Entry {
                        lba_count: lba - k,
                        phys: e.phys,
                    },
                ));
                // right survivor [end, e_end) if the entry spans past the range
                if e_end > end {
                    let dropped = end - k;
                    let mut p = e.phys;
                    p.data_off = p
                        .data_off
                        .saturating_add(dropped.saturating_mul(LOGICAL_BLOCK_SIZE));
                    to_insert.push((
                        end,
                        Entry {
                            lba_count: e_end - end,
                            phys: p,
                        },
                    ));
                }
            }
        }
        // 2) Entries starting within `[lba, end)`.
        for (&k, &e) in self.map.range(lba..end) {
            let e_end = k.saturating_add(e.lba_count);
            to_remove.push(k);
            if e_end > end {
                let dropped = end - k;
                let mut p = e.phys;
                p.data_off = p
                    .data_off
                    .saturating_add(dropped.saturating_mul(LOGICAL_BLOCK_SIZE));
                to_insert.push((
                    end,
                    Entry {
                        lba_count: e_end - end,
                        phys: p,
                    },
                ));
            }
        }
        for k in to_remove {
            if let Some(e) = self.map.remove(&k) {
                self.live_sub(e.phys.segment_id, e.lba_count);
            }
        }
        for (k, e) in to_insert {
            self.live_add(e.phys.segment_id, e.lba_count);
            self.map.insert(k, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BS: u64 = LOGICAL_BLOCK_SIZE;

    fn phys(seg: u64, rec: u64, data_off: u64, epoch: u32) -> Phys {
        Phys {
            segment_id: seg,
            record_off: rec,
            data_off,
            epoch,
        }
    }

    // TC-FTL-1: a single-block mapping resolves to exactly that physical location.
    #[test]
    fn point_map() {
        let mut ftl = Ftl::new();
        ftl.map_range(7, 1, phys(1, 0, 0, 0));
        assert_eq!(ftl.lookup(7), Some(phys(1, 0, 0, 0)));
        assert_eq!(ftl.lookup(6), None);
        assert_eq!(ftl.lookup(8), None);
        let r = ftl.resolve_read(7, 1);
        assert_eq!(
            r,
            vec![ReadPiece {
                lba: 7,
                count: 1,
                source: Source::Mapped(phys(1, 0, 0, 0))
            }]
        );
    }

    // TC-FTL-2: an overwrite in the middle of an extent supersedes only the
    // overwritten blocks; the surviving halves keep the OLD record with
    // correctly adjusted data offsets.
    #[test]
    fn overwrite_supersedes_and_splits() {
        let mut ftl = Ftl::new();
        ftl.map_range(0, 10, phys(1, 0, 0, 5)); // A: blocks 0..10 → seg1
        ftl.map_range(3, 2, phys(2, 100, 0, 6)); // B: blocks 3..5 → seg2
        let r = ftl.resolve_read(0, 10);
        assert_eq!(
            r,
            vec![
                ReadPiece {
                    lba: 0,
                    count: 3,
                    source: Source::Mapped(phys(1, 0, 0, 5))
                },
                ReadPiece {
                    lba: 3,
                    count: 2,
                    source: Source::Mapped(phys(2, 100, 0, 6))
                },
                // survivor of A: blocks 5..10, data_off advanced by 5 blocks
                ReadPiece {
                    lba: 5,
                    count: 5,
                    source: Source::Mapped(phys(1, 0, 5 * BS, 5))
                },
            ]
        );
        assert_eq!(ftl.extent_count(), 3);
        assert_eq!(ftl.mapped_blocks(), 10);
    }

    // TC-FTL-3: unmapping the middle of an extent splits it into three regions
    // (mapped, hole, mapped) — the classic interval carve.
    #[test]
    fn unmap_splits_into_three() {
        let mut ftl = Ftl::new();
        ftl.map_range(0, 10, phys(1, 0, 0, 0));
        ftl.unmap_range(4, 2); // punch a hole at blocks 4..6
        let r = ftl.resolve_read(0, 10);
        assert_eq!(
            r,
            vec![
                ReadPiece {
                    lba: 0,
                    count: 4,
                    source: Source::Mapped(phys(1, 0, 0, 0))
                },
                ReadPiece {
                    lba: 4,
                    count: 2,
                    source: Source::Hole
                },
                ReadPiece {
                    lba: 6,
                    count: 4,
                    source: Source::Mapped(phys(1, 0, 6 * BS, 0))
                },
            ]
        );
        assert_eq!(ftl.extent_count(), 2);
    }

    // TC-FTL-4: reads over sparse/unmapped regions come back as holes (zeros),
    // including leading, interior, and trailing holes.
    #[test]
    fn sparse_reads_are_holes() {
        let mut ftl = Ftl::new();
        assert_eq!(
            ftl.resolve_read(5, 3),
            vec![ReadPiece {
                lba: 5,
                count: 3,
                source: Source::Hole
            }]
        );
        ftl.map_range(10, 2, phys(1, 0, 0, 0));
        let r = ftl.resolve_read(8, 6); // 8,9 hole | 10,11 mapped | 12,13 hole
        assert_eq!(
            r,
            vec![
                ReadPiece {
                    lba: 8,
                    count: 2,
                    source: Source::Hole
                },
                ReadPiece {
                    lba: 10,
                    count: 2,
                    source: Source::Mapped(phys(1, 0, 0, 0))
                },
                ReadPiece {
                    lba: 12,
                    count: 2,
                    source: Source::Hole
                },
            ]
        );
    }

    // TC-FTL-5: boundary / overflow guards — zero counts are no-ops, and mapping
    // near u64::MAX must not panic (saturating arithmetic).
    #[test]
    fn boundary_and_overflow_guards() {
        let mut ftl = Ftl::new();
        ftl.map_range(100, 0, phys(1, 0, 0, 0)); // zero count → no-op
        assert_eq!(ftl.extent_count(), 0);
        assert!(ftl.resolve_read(0, 0).is_empty());

        // near the top of the address space: no overflow panic
        ftl.map_range(u64::MAX - 4, 4, phys(2, 0, 0, 0));
        assert_eq!(ftl.lookup(u64::MAX - 1), Some(phys(2, 0, 3 * BS, 0)));
        let r = ftl.resolve_read(u64::MAX - 2, 2);
        assert_eq!(
            r,
            vec![ReadPiece {
                lba: u64::MAX - 2,
                count: 2,
                source: Source::Mapped(phys(2, 0, 2 * BS, 0)),
            }]
        );
    }

    // Unrepresentable ranges (lba+count overflows u64) are ignored consistently:
    // no panic, no "reported-but-unlookupable" block, and the top block still
    // tiles as a hole when nothing is mapped there. (The device also bounds LBAs
    // by capacity upstream in M2b; this is the FTL's own robustness against a
    // corrupt replayed delta.)
    #[test]
    fn top_of_address_space_is_consistent() {
        let mut ftl = Ftl::new();
        // map at the very top: (u64::MAX)+1 wraps → no-op
        ftl.map_range(u64::MAX, 1, phys(1, 0, 0, 0));
        assert_eq!(ftl.mapped_blocks(), 0);
        assert_eq!(ftl.lookup(u64::MAX), None);
        // resolve_read of the last block tiles as a single hole (not empty)
        assert_eq!(
            ftl.resolve_read(u64::MAX, 1),
            vec![ReadPiece {
                lba: u64::MAX,
                count: 1,
                source: Source::Hole
            }]
        );
        // a range straddling the top that would wrap is a no-op too
        ftl.map_range(u64::MAX - 1, 2, phys(2, 0, 0, 0)); // (u64::MAX-1)+2 wraps
        assert_eq!(ftl.mapped_blocks(), 0);
        // but a range ending exactly at u64::MAX (no wrap) maps fine
        ftl.map_range(u64::MAX - 1, 1, phys(3, 0, 0, 0));
        assert_eq!(ftl.mapped_blocks(), 1);
        assert_eq!(ftl.lookup(u64::MAX - 1), Some(phys(3, 0, 0, 0)));
    }

    // The carve branch for an entry STARTING INSIDE the carved range must adjust
    // `data_off` without panicking even when the offset is near u64::MAX (a
    // corrupt/extreme record) — saturating, never wrapping. (This is the branch
    // the earlier fix missed; the property test's small values never reach it.)
    #[test]
    fn carve_inside_range_data_off_saturates() {
        let mut ftl = Ftl::new();
        // A: blocks [10,20) with a near-max data_off
        ftl.map_range(10, 10, phys(1, 0, u64::MAX - 100, 0));
        // overwrite [5,13): A (key 10, inside [5,13)) splits — right survivor [13,20)
        ftl.map_range(5, 8, phys(2, 0, 0, 0));
        let p = ftl.lookup(13).unwrap();
        assert_eq!(p.segment_id, 1); // the survivor of A
        assert_eq!(p.data_off, u64::MAX); // saturated, not wrapped or panicked
    }

    // Property test: apply the same random map/unmap ops to the FTL and to a
    // per-LBA reference model, then verify resolve_read matches block-for-block
    // over random ranges. Deterministic xorshift — reproducible, no extra deps.
    #[test]
    fn property_matches_reference_model() {
        const N: u64 = 256; // logical block space for the model
        let mut ftl = Ftl::new();
        let mut model: Vec<Option<Phys>> = vec![None; N as usize];
        let mut rng: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };

        for op in 0..4000u64 {
            let lba = next() % N;
            let count = (1 + next() % 16).min(N - lba);
            if next() % 4 == 0 {
                ftl.unmap_range(lba, count);
                for b in lba..lba + count {
                    model[b as usize] = None;
                }
            } else {
                let base = phys(op, op * 7, 0, (op % 5) as u32);
                ftl.map_range(lba, count, base);
                for (i, b) in (lba..lba + count).enumerate() {
                    let mut p = base;
                    p.data_off += i as u64 * LOGICAL_BLOCK_SIZE;
                    model[b as usize] = Some(p);
                }
            }

            for _ in 0..3 {
                let rl = next() % N;
                let rc = (1 + next() % 32).min(N - rl);
                let pieces = ftl.resolve_read(rl, rc);
                let mut at = rl;
                for pc in &pieces {
                    assert_eq!(pc.lba, at, "pieces must tile with no gap");
                    for j in 0..pc.count {
                        let expect = model[(at + j) as usize];
                        match pc.source {
                            Source::Hole => assert_eq!(expect, None),
                            Source::Mapped(p) => {
                                let mut pb = p;
                                pb.data_off += j * LOGICAL_BLOCK_SIZE;
                                assert_eq!(Some(pb), expect);
                            }
                        }
                    }
                    at += pc.count;
                }
                assert_eq!(at, rl + rc, "pieces must cover the whole range");
            }
        }
        let model_mapped = model.iter().filter(|x| x.is_some()).count() as u64;
        assert_eq!(ftl.mapped_blocks(), model_mapped);

        // P4.1: the incremental per-segment liveness must equal a full recompute
        // from the reference model after 4000 random ops.
        let mut want: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        for p in model.iter().flatten() {
            *want.entry(p.segment_id).or_insert(0) += 1;
        }
        let mut got: Vec<(u64, u64)> = ftl.live_segments();
        got.sort_unstable();
        let mut want: Vec<(u64, u64)> = want.into_iter().collect();
        want.sort_unstable();
        assert_eq!(got, want, "incremental liveness diverged from recompute");
    }

    // TC-GC-1 (P4.1): overwrites and discards decrement the superseded segment's
    // live count exactly; a fully-superseded segment reads as dead (0 live blocks).
    #[test]
    fn liveness_tracks_overwrite_and_discard() {
        let mut ftl = Ftl::new();
        ftl.map_range(0, 10, phys(1, 0, 0, 0));
        assert_eq!(ftl.live_blocks(1), 10);

        // overwrite the middle 4 blocks into segment 2
        ftl.map_range(3, 4, phys(2, 0, 0, 0));
        assert_eq!(ftl.live_blocks(1), 6);
        assert_eq!(ftl.live_blocks(2), 4);

        // discard 2 blocks of the survivor
        ftl.unmap_range(0, 2);
        assert_eq!(ftl.live_blocks(1), 4);

        // supersede everything that remains of segment 1
        ftl.map_range(2, 1, phys(3, 0, 0, 0));
        ftl.map_range(7, 3, phys(3, 100, 0, 0));
        assert_eq!(ftl.live_blocks(1), 0, "segment 1 is fully dead");
        assert!(!ftl.live_segments().iter().any(|&(s, _)| s == 1));
        assert_eq!(ftl.live_blocks(3), 4);

        // extents_of_segment returns the live extents in LBA order
        let ext = ftl.extents_of_segment(3);
        assert_eq!(ext.len(), 2);
        assert_eq!((ext[0].0, ext[0].1), (2, 1));
        assert_eq!((ext[1].0, ext[1].1), (7, 3));
        assert!(ftl.extents_of_segment(1).is_empty());
    }
}
