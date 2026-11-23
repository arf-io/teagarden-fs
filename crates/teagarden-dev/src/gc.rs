//! Garbage-collection / compaction **policy** (P4).
//!
//! The *mechanism* — compaction, FTL repoint, the crash-safe
//! compact→confirm→checkpoint→delete ordering — lives in
//! [`crate::device::TeaGardenDevice::gc`], because it needs the device's private
//! state. This module owns the policy surface: the tunables ([`GcConfig`]), the
//! per-pass accounting ([`GcReport`]), and pure, unit-testable victim selection
//! (P4.2).
//!
//! Selection model: every segment is padded to the same `segment_target` bucket
//! on the wire (M2e), so the *fixed bucket* is the fair cost denominator — a
//! segment's live ratio is `live_bytes / segment_target`. A segment below
//! [`GcConfig::live_ratio_max`] is worth rewriting (its ~45 MiB Telegram message
//! is mostly dead bytes); fully-dead segments need no rewrite at all and are
//! swept by the delete gate directly. Greedy lowest-live-first is the F2FS-style
//! cost-benefit order: the emptier the victim, the fewer bytes moved per message
//! reclaimed.

use std::collections::HashSet;

use teagarden_blockdev::LOGICAL_BLOCK_SIZE;

/// GC tunables (carried in [`crate::device::DeviceConfig`]).
#[derive(Clone, Copy, Debug)]
pub struct GcConfig {
    /// A confirmed segment whose live ratio (`live_bytes / segment_target`) is
    /// strictly below this becomes a compaction candidate. Fully-dead segments
    /// are delete candidates regardless of this threshold.
    pub live_ratio_max: f64,
    /// Upper bound on segments *compacted* (data rewritten) per [`gc`] pass —
    /// bounds a pass's write amplification and upload burst. Delete-only
    /// (fully-dead) victims are not counted: deleting is O(1).
    ///
    /// [`gc`]: crate::device::TeaGardenDevice::gc
    pub max_compactions_per_pass: usize,
    /// Also delete the `DeviceHead` message each pass supersedes. **Default
    /// OFF** (advisor H1): until P3.2 head-pinning lands, the documented
    /// fresh-machine recovery input is a manually recorded head message id —
    /// deleting superseded heads silently invalidates the id the operator wrote
    /// down. Turn this on only where the newest head id is re-recorded after
    /// every pass ([`GcReport::head_msg_id`] carries it).
    pub delete_superseded_head: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            live_ratio_max: 0.30,
            max_compactions_per_pass: 8,
            delete_superseded_head: false,
        }
    }
}

/// What one [`gc`] pass actually did — honest per-pass accounting.
///
/// [`gc`]: crate::device::TeaGardenDevice::gc
#[derive(Clone, Debug, Default)]
pub struct GcReport {
    /// `Some(reason)` if the pass refused to run (e.g. cache backpressure).
    pub skipped: Option<String>,
    /// Victim segments whose live extents were rewritten into fresh segments.
    pub compacted: Vec<u64>,
    /// Number of (merged) extents moved during compaction.
    pub extents_moved: usize,
    /// Logical blocks moved during compaction.
    pub blocks_moved: u64,
    /// Segments whose Telegram messages were deleted (now tombstoned).
    pub deleted: Vec<u64>,
    /// Segments that passed the delete gate but whose deletion failed — they
    /// stay orphaned (readable, unreferenced) and are retried next pass.
    pub delete_deferred: Vec<u64>,
    /// Whether this pass deleted the superseded `DeviceHead` message it replaced
    /// (only ever true under [`GcConfig::delete_superseded_head`]).
    pub superseded_head_deleted: bool,
    /// The cloud watermark of the head this pass published.
    pub watermark: u64,
    /// Message id of the head this pass published — **after GC has run, only
    /// the newest head is a viable recovery point** (older heads may reference
    /// deleted messages), so the operator-recorded recovery id must be updated
    /// to this after every pass.
    pub head_msg_id: Option<i64>,
}

/// One victim-selection candidate: a cloud-confirmed, non-tombstoned segment
/// with at least one live block.
#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    /// Segment id.
    pub segment_id: u64,
    /// Live logical blocks currently mapped into it.
    pub live_blocks: u64,
    /// Total logical blocks ever written into it (records appended). For a
    /// head-recovered device this is seeded from the head's live extents — a
    /// conservative under-estimate (pre-recovery dead bytes are invisible), so
    /// recovered segments only become victims once NEW overwrites kill blocks.
    pub total_blocks: u64,
}

/// Pure victim selection (P4.2): candidates strictly below the live-ratio
/// threshold **that actually contain dead bytes** (`total > live`), greedily
/// lowest-live-first (ties broken by lower id for determinism), capped at
/// `max_compactions_per_pass`.
///
/// The dead-bytes requirement is load-bearing, not an optimisation: a
/// compaction OUTPUT segment holding (say) two live blocks in a padded bucket
/// scores far below any live-ratio threshold, but rewriting it reclaims
/// nothing — without the `total > live` gate GC would churn its own output
/// forever (upload a new segment + delete the old one every pass, net zero).
/// Fully-dead segments must not be passed in — they are swept by the delete
/// gate without compaction.
pub fn select_compaction_victims(
    candidates: &[Candidate],
    segment_target: u64,
    cfg: &GcConfig,
) -> Vec<u64> {
    let mut below: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| c.live_blocks > 0 && c.total_blocks > c.live_blocks)
        .filter(|c| {
            let live_bytes = (c.live_blocks.saturating_mul(LOGICAL_BLOCK_SIZE)) as f64;
            live_bytes < cfg.live_ratio_max * segment_target.max(1) as f64
        })
        .collect();
    below.sort_unstable_by_key(|c| (c.live_blocks, c.segment_id));
    below
        .into_iter()
        .take(cfg.max_compactions_per_pass)
        .map(|c| c.segment_id)
        .collect()
}

/// The delete gate (P4.4 / design invariant I3), as a pure predicate over the
/// post-checkpoint state: a segment's Telegram message may be deleted iff
///
/// 1. it is confirmed and not already tombstoned (`message_id != 0`),
/// 2. the LIVE FTL holds no extent into it (`live_blocks == 0`),
/// 3. it is at or below the just-published head's watermark — a fully-dead
///    segment ABOVE the watermark must survive, because a FUTURE head at a
///    higher watermark can re-reference it (its repoints may still be past
///    that head's watermark when a gap below it heals), and
/// 4. that head's prefix extents hold no reference into it.
///
/// Returns the deletable segment ids, sorted. Pure so the gate — including the
/// gap case (3), which `gc()`'s drain-first barrier makes unreachable through
/// the public API today — is directly unit-testable.
pub fn deletable_segments(
    catalog: &[(u64, i64)],
    live_blocks: impl Fn(u64) -> u64,
    head_watermark: u64,
    head_seg_refs: &HashSet<u64>,
) -> Vec<u64> {
    let mut out: Vec<u64> = catalog
        .iter()
        .filter(|&&(_, mid)| mid != 0)
        .map(|&(seg, _)| seg)
        .filter(|&seg| live_blocks(seg) == 0)
        .filter(|&seg| seg <= head_watermark)
        .filter(|&seg| !head_seg_refs.contains(&seg))
        .collect();
    out.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BS: u64 = LOGICAL_BLOCK_SIZE;

    fn cand(segment_id: u64, live_blocks: u64, total_blocks: u64) -> Candidate {
        Candidate {
            segment_id,
            live_blocks,
            total_blocks,
        }
    }

    // TC-GC-3 (selection half): below-threshold segments are picked lowest-live
    // first; healthy segments are never victims.
    #[test]
    fn selects_below_threshold_lowest_first() {
        let target = 100 * BS; // 100-block bucket, threshold 0.30 → < 30 blocks
        let cfg = GcConfig::default();
        let picked = select_compaction_victims(
            &[
                cand(1, 90, 100),
                cand(2, 29, 100),
                cand(3, 5, 100),
                cand(4, 30, 100),
                cand(5, 10, 100),
            ],
            target,
            &cfg,
        );
        // 4 is exactly AT the threshold (30/100 = 0.30, not strictly below) → out;
        // 1 is healthy → out; order = live ascending.
        assert_eq!(picked, vec![3, 5, 2]);
    }

    #[test]
    fn honors_the_per_pass_compaction_cap() {
        let target = 100 * BS;
        let cfg = GcConfig {
            max_compactions_per_pass: 2,
            ..Default::default()
        };
        let picked = select_compaction_victims(
            &[cand(1, 1, 10), cand(2, 2, 10), cand(3, 3, 10)],
            target,
            &cfg,
        );
        assert_eq!(picked, vec![1, 2]);
    }

    #[test]
    fn ties_break_by_lower_segment_id_and_dead_are_excluded() {
        let target = 100 * BS;
        let cfg = GcConfig::default();
        let picked =
            select_compaction_victims(&[cand(9, 4, 8), cand(2, 4, 8), cand(7, 0, 8)], target, &cfg);
        // equal live counts → deterministic id order; live_blocks == 0 is the
        // delete gate's job, not compaction's.
        assert_eq!(picked, vec![2, 9]);
    }

    // The self-churn guard: a segment with NO dead bytes (total == live) must
    // never be a victim, however small its live ratio — rewriting it reclaims
    // nothing. This is exactly the shape of GC's own output segments.
    #[test]
    fn no_dead_bytes_is_never_a_victim() {
        let target = 100 * BS;
        let cfg = GcConfig::default();
        let picked = select_compaction_victims(&[cand(1, 2, 2), cand(2, 2, 3)], target, &cfg);
        assert_eq!(picked, vec![2], "total==live (seg 1) must be excluded");
    }

    // I3, tested directly on the pure gate (advisor H4: gc()'s drain-first
    // barrier makes the gap case unreachable through the public API today, so
    // the predicate itself must be pinned): a fully-dead segment ABOVE the
    // head's watermark is NOT deletable — a future head can re-reference it.
    #[test]
    fn delete_gate_blocks_dead_segment_above_watermark() {
        let catalog = [(1, 101i64), (3, 103i64)]; // seg 2 unconfirmed → watermark 1
        let live = |seg: u64| if seg == 3 { 0 } else { 5 };
        let refs: HashSet<u64> = [1u64].into_iter().collect();
        // seg 3 is fully dead and unreferenced by the head — but ABOVE the
        // watermark (3 > 1), so it must survive.
        assert!(deletable_segments(&catalog, live, 1, &refs).is_empty());
        // once the gap heals and a head at watermark ≥ 3 stops referencing it,
        // it becomes deletable.
        let refs2: HashSet<u64> = [1u64, 2u64].into_iter().collect();
        assert_eq!(deletable_segments(&catalog, live, 3, &refs2), vec![3]);
    }

    // The rest of the gate: tombstones (mid 0) are never re-deleted, live
    // segments never die, and a head-referenced segment survives even when the
    // live FTL no longer references it (unconfirmed-relocation case, I2).
    #[test]
    fn delete_gate_respects_tombstones_liveness_and_head_refs() {
        let catalog = [(1, 0i64), (2, 102i64), (3, 103i64), (4, 104i64)];
        let live = |seg: u64| if seg == 2 { 4 } else { 0 };
        // head still references seg 3 (its relocation target is past the
        // watermark) → only seg 4 may die.
        let refs: HashSet<u64> = [2u64, 3u64].into_iter().collect();
        assert_eq!(deletable_segments(&catalog, live, 4, &refs), vec![4]);
    }
}
