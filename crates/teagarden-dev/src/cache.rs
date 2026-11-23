//! Persistent, user-configurable, SCORED read/write cache (P1.13).
//!
//! This is the answer to the P-1 finding that Telegram reads are slow and
//! variable: the hot working set is kept warm locally so the device is usable.
//! The cache holds **ciphertext** segments (encrypted at rest — never plaintext),
//! is bounded by a user-configurable byte budget, and **persists across dismount**
//! (an offline/nearline warm store) via [`ScoredCache::serialize`] /
//! [`ScoredCache::load`].
//!
//! Eviction is **score-based, not plain LRU**. Every cached segment carries four
//! factors, and the lowest-scoring *confirmed* segment is evicted first when over
//! budget. Retention priority is **3 > 2 > 1 > 4** (per the owner's spec):
//!
//! - **f3 · Most-Recently-Written (MRW)** — recency of the last write.
//! - **f2 · Most-Frequently-Accessed (MFA)** — access frequency (count / age).
//! - **f1 · Most-Recently-Fetched (MRF)** — recency of the last read fetch.
//! - **f4 · Speculative-Prefetch (SP)** — how many in-cache extents reference it.
//!
//! `score = w3·f3 + w2·f2 + w1·f1 + w4·f4`, each factor normalised to `[0,1]`, the
//! weights ordered `w3 > w2 > w1 > w4` so the priority holds; the weights are
//! user-tunable. A segment that is still **staged** (unsynced — the only durable
//! copy) is *never* an eviction candidate; if the budget is full of staged data
//! the cache reports **backpressure** (writes must block / go read-only) rather
//! than drop the only copy.
//!
//! Time is a monotonic logical tick (not wall-clock) so scoring is deterministic
//! and testable.

use std::collections::HashMap;

use crate::error::{DeviceError, Result};

/// Tunable cache policy. Defaults target large-object archival streaming.
#[derive(Clone, Copy, Debug)]
pub struct CacheConfig {
    /// Byte budget for CONFIRMED segments before eviction kicks in.
    pub budget_bytes: u64,
    /// Weight of Most-Recently-Written (factor 3 — highest).
    pub w_mrw: f64,
    /// Weight of Most-Frequently-Accessed (factor 2).
    pub w_mfa: f64,
    /// Weight of Most-Recently-Fetched (factor 1).
    pub w_mrf: f64,
    /// Weight of Speculative-Prefetch reference count (factor 4 — lowest).
    pub w_sp: f64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            budget_bytes: 256 * 1024 * 1024,
            // 3 > 2 > 1 > 4
            w_mrw: 8.0,
            w_mfa: 4.0,
            w_mrf: 2.0,
            w_sp: 1.0,
        }
    }
}

#[derive(Clone, Debug)]
struct Entry {
    bytes: Vec<u8>,
    staged: bool,
    insert_tick: u64,
    last_write_tick: u64,
    last_fetch_tick: u64,
    access_count: u64,
    sp: u64,
}

/// A bounded, score-evicted, persistable cache of ciphertext segments keyed by
/// `segment_id`.
pub struct ScoredCache {
    config: CacheConfig,
    entries: HashMap<u64, Entry>,
    confirmed_bytes: u64,
    staged_bytes: u64,
    tick: u64,
}

impl ScoredCache {
    /// New empty cache with the given policy.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            confirmed_bytes: 0,
            staged_bytes: 0,
            tick: 0,
        }
    }

    fn now(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Number of cached segments.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// True if the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Bytes held by confirmed (evictable) segments.
    pub fn confirmed_bytes(&self) -> u64 {
        self.confirmed_bytes
    }
    /// Bytes held by staged (never-evicted) segments.
    pub fn staged_bytes(&self) -> u64 {
        self.staged_bytes
    }

    /// True when the budget cannot be honoured because it is full of staged data
    /// — the device must apply backpressure (block writes / go read-only) until
    /// staged segments are uploaded and confirmed.
    ///
    /// Staged bytes are the un-evictable floor: once they reach the budget, no
    /// amount of confirmed eviction can make room for more, so backpressure fires
    /// regardless of whether a confirmed segment happens to be present. (Confirmed
    /// segments over budget are already evicted by `evict_to_budget`, so they can
    /// never mask this condition.)
    pub fn under_backpressure(&self) -> bool {
        self.staged_bytes >= self.config.budget_bytes
    }

    fn account_add(&mut self, staged: bool, n: u64) {
        if staged {
            self.staged_bytes += n;
        } else {
            self.confirmed_bytes += n;
        }
    }
    fn account_sub(&mut self, staged: bool, n: u64) {
        if staged {
            self.staged_bytes = self.staged_bytes.saturating_sub(n);
        } else {
            self.confirmed_bytes = self.confirmed_bytes.saturating_sub(n);
        }
    }

    /// Insert (or replace) a segment's ciphertext. `staged = true` marks it as an
    /// unsynced local write (never evicted until confirmed). Runs eviction after.
    pub fn insert(&mut self, segment_id: u64, bytes: Vec<u8>, staged: bool) {
        let tick = self.now();
        let len = bytes.len() as u64;
        if let Some(old) = self.entries.remove(&segment_id) {
            self.account_sub(old.staged, old.bytes.len() as u64);
        }
        self.account_add(staged, len);
        self.entries.insert(
            segment_id,
            Entry {
                bytes,
                staged,
                insert_tick: tick,
                last_write_tick: tick,
                last_fetch_tick: tick,
                access_count: 0,
                sp: 0,
            },
        );
        self.evict_to_budget();
    }

    /// Fetch a segment's ciphertext, updating its read-recency + frequency.
    pub fn get(&mut self, segment_id: u64) -> Option<Vec<u8>> {
        let tick = self.now();
        let e = self.entries.get_mut(&segment_id)?;
        e.last_fetch_tick = tick;
        e.access_count += 1;
        Some(e.bytes.clone())
    }

    /// Record that a segment was (over)written — bumps its write recency.
    pub fn note_write(&mut self, segment_id: u64) {
        let tick = self.now();
        if let Some(e) = self.entries.get_mut(&segment_id) {
            e.last_write_tick = tick;
        }
    }

    /// Set a segment's speculative-prefetch reference count (locality degree).
    pub fn set_sp(&mut self, segment_id: u64, sp: u64) {
        if let Some(e) = self.entries.get_mut(&segment_id) {
            e.sp = sp;
        }
    }

    /// Drop a CONFIRMED segment from the cache (P4: its message was deleted by
    /// GC, so the cached ciphertext is garbage). Refuses to drop a STAGED entry —
    /// staged bytes are the only durable copy and must never leave via this path
    /// (GC only ever removes confirmed victims; the refusal is defensive).
    /// Returns whether an entry was removed.
    pub fn remove(&mut self, segment_id: u64) -> bool {
        match self.entries.get(&segment_id) {
            Some(e) if !e.staged => {
                let n = self
                    .entries
                    .remove(&segment_id)
                    .map_or(0, |e| e.bytes.len() as u64);
                self.confirmed_bytes = self.confirmed_bytes.saturating_sub(n);
                true
            }
            _ => false,
        }
    }

    /// Mark a staged segment as cloud-confirmed — it becomes evictable.
    pub fn mark_confirmed(&mut self, segment_id: u64) {
        if let Some(e) = self.entries.get_mut(&segment_id) {
            if e.staged {
                let n = e.bytes.len() as u64;
                e.staged = false;
                self.staged_bytes = self.staged_bytes.saturating_sub(n);
                self.confirmed_bytes += n;
            }
        }
        self.evict_to_budget();
    }

    fn score(&self, e: &Entry) -> f64 {
        let now = self.tick.max(1) as f64;
        let age = (self.tick - e.insert_tick + 1) as f64;
        let f3 = e.last_write_tick as f64 / now; // MRW recency, 0..1
        let f2 = (e.access_count as f64 / age).min(1.0); // MFA frequency, capped 0..1
        let f1 = e.last_fetch_tick as f64 / now; // MRF recency, 0..1
        let f4 = e.sp as f64 / (e.sp as f64 + 4.0); // SP, diminishing 0..1
        self.config.w_mrw * f3
            + self.config.w_mfa * f2
            + self.config.w_mrf * f1
            + self.config.w_sp * f4
    }

    /// Evict lowest-scoring CONFIRMED segments until the TOTAL cached bytes
    /// (staged + confirmed) are within budget — or only staged segments remain,
    /// in which case the cache is over budget on un-evictable data (backpressure).
    fn evict_to_budget(&mut self) {
        while self.staged_bytes + self.confirmed_bytes > self.config.budget_bytes {
            // pick the lowest-scoring confirmed entry
            let victim = self
                .entries
                .iter()
                .filter(|(_, e)| !e.staged)
                .map(|(&k, e)| (k, self.score(e)))
                .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(k, _)| k);
            match victim {
                Some(k) => {
                    if let Some(e) = self.entries.remove(&k) {
                        self.confirmed_bytes =
                            self.confirmed_bytes.saturating_sub(e.bytes.len() as u64);
                    }
                }
                None => break, // nothing evictable (all staged) → backpressure
            }
        }
    }

    // ── persistence ─────────────────────────────────────────────────────────

    /// Serialize the cache contents (ciphertext + scoring factors) for on-disk
    /// persistence across a dismount. The `config` is not stored (it is supplied
    /// on `load`). Only CONFIRMED segments persist — staged segments live in the
    /// staging log, which is the authoritative unsynced store.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let confirmed = self.entries.iter().filter(|(_, e)| !e.staged);
        let count = confirmed.clone().count() as u32;
        out.extend_from_slice(b"TGDEVC1\0");
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&self.tick.to_le_bytes());
        for (&k, e) in confirmed {
            out.extend_from_slice(&k.to_le_bytes());
            out.extend_from_slice(&e.insert_tick.to_le_bytes());
            out.extend_from_slice(&e.last_write_tick.to_le_bytes());
            out.extend_from_slice(&e.last_fetch_tick.to_le_bytes());
            out.extend_from_slice(&e.access_count.to_le_bytes());
            out.extend_from_slice(&e.sp.to_le_bytes());
            out.extend_from_slice(&(e.bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&e.bytes);
        }
        out
    }

    /// Load a persisted cache under a fresh `config`. Fails closed on a malformed
    /// blob (never panics).
    pub fn load(blob: &[u8], config: CacheConfig) -> Result<Self> {
        let bad = || DeviceError::Corruption("malformed cache blob".into());
        if blob.len() < 20 || &blob[0..8] != b"TGDEVC1\0" {
            return Err(bad());
        }
        let count = u32::from_le_bytes(blob[8..12].try_into().unwrap()) as usize;
        let tick = u64::from_le_bytes(blob[12..20].try_into().unwrap());
        let mut cache = Self::new(config);
        cache.tick = tick;
        let mut pos = 20usize;
        let ru = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        for _ in 0..count {
            if pos + 48 + 4 > blob.len() {
                return Err(bad());
            }
            let k = ru(blob, pos);
            let insert_tick = ru(blob, pos + 8);
            let last_write_tick = ru(blob, pos + 16);
            let last_fetch_tick = ru(blob, pos + 24);
            let access_count = ru(blob, pos + 32);
            let sp = ru(blob, pos + 40);
            let blen = u32::from_le_bytes(blob[pos + 48..pos + 52].try_into().unwrap()) as usize;
            let bstart = pos + 52;
            let bend = bstart.checked_add(blen).ok_or_else(bad)?;
            if bend > blob.len() {
                return Err(bad());
            }
            let bytes = blob[bstart..bend].to_vec();
            cache.confirmed_bytes += bytes.len() as u64;
            cache.entries.insert(
                k,
                Entry {
                    bytes,
                    staged: false,
                    insert_tick,
                    last_write_tick,
                    last_fetch_tick,
                    access_count,
                    sp,
                },
            );
            pos = bend;
        }
        // a restored cache honours the (possibly smaller) new budget
        cache.evict_to_budget();
        Ok(cache)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(budget: u64) -> CacheConfig {
        CacheConfig {
            budget_bytes: budget,
            ..Default::default()
        }
    }

    #[test]
    fn insert_get_and_confirmed_accounting() {
        let mut c = ScoredCache::new(cfg(1_000_000));
        c.insert(1, vec![0u8; 100], false);
        c.insert(2, vec![0u8; 200], false);
        assert_eq!(c.len(), 2);
        assert_eq!(c.confirmed_bytes(), 300);
        assert_eq!(c.get(1).unwrap().len(), 100);
        assert_eq!(c.get(99), None);
    }

    // TC-CACHE-4: a recently-written + frequently-accessed segment outscores a
    // stale, merely-prefetched one; eviction removes the lowest scorer.
    #[test]
    fn score_priority_evicts_stalest() {
        // budget for exactly 2 of the 100-byte segments
        let mut c = ScoredCache::new(cfg(200));
        c.insert(1, vec![0u8; 100], false); // will be kept warm (written+accessed)
        c.insert(2, vec![0u8; 100], false); // will be a stale prefetch
        c.set_sp(2, 5); // 2 has some prefetch references but is otherwise cold
                        // make 1 hot: recent write + repeated access
        for _ in 0..10 {
            let _ = c.get(1);
        }
        c.note_write(1);
        // insert a third → must evict the lowest scorer (the stale #2, not hot #1)
        c.insert(3, vec![0u8; 100], false);
        assert!(c.get(1).is_some(), "hot recently-written segment retained");
        assert!(c.get(2).is_none(), "stale prefetched segment evicted");
        assert!(c.get(3).is_some());
        assert!(c.confirmed_bytes() <= 200);
    }

    // Staged (unsynced) segments are NEVER evicted; a budget full of them reports
    // backpressure instead of dropping the only durable copy.
    #[test]
    fn never_evicts_staged_and_reports_backpressure() {
        let mut c = ScoredCache::new(cfg(150));
        c.insert(1, vec![0u8; 100], true); // staged
        c.insert(2, vec![0u8; 100], true); // staged → over budget, but can't evict
        assert_eq!(c.len(), 2, "staged segments are not evicted");
        assert_eq!(c.staged_bytes(), 200);
        assert!(c.under_backpressure());
        // confirming one makes it evictable; now a confirmed insert can reclaim
        c.mark_confirmed(1);
        assert!(!c.under_backpressure());
        c.insert(3, vec![0u8; 100], false);
        // #1 (confirmed, now evictable) may be dropped; #2 (still staged) stays
        assert!(c.get(2).is_some(), "staged #2 never evicted");
    }

    // The Codex M2b FIX-2 edge: staged bytes reaching the budget must trip
    // backpressure even when an (evictable) confirmed segment is also present —
    // total-bytes eviction removes the confirmed, and the un-evictable staged
    // floor still exceeds the budget.
    #[test]
    fn backpressure_fires_when_staged_reaches_budget_despite_confirmed() {
        let mut c = ScoredCache::new(cfg(150));
        c.insert(1, vec![0u8; 60], false); // a small confirmed segment
        c.insert(2, vec![0u8; 160], true); // staged, exceeds the budget on its own
                                           // total 220 > 150 → the confirmed #1 is evicted; staged (160) ≥ budget
        assert!(c.under_backpressure());
        assert!(c.get(2).is_some(), "staged data is never dropped");
    }

    // P4: remove() drops a confirmed entry (with accounting) but REFUSES a staged
    // one — staged bytes are the only durable copy.
    #[test]
    fn remove_drops_confirmed_but_refuses_staged() {
        let mut c = ScoredCache::new(cfg(1_000_000));
        c.insert(1, vec![0u8; 100], false);
        c.insert(2, vec![0u8; 100], true);
        assert!(c.remove(1));
        assert_eq!(c.get(1), None);
        assert_eq!(c.confirmed_bytes(), 0);
        assert!(!c.remove(2), "staged entries are not removable");
        assert!(c.get(2).is_some());
        assert_eq!(c.staged_bytes(), 100);
        assert!(!c.remove(99), "absent id is a no-op");
    }

    // Persistence: serialize → load round-trips the CONFIRMED entries + bytes; a
    // smaller budget on load triggers eviction.
    #[test]
    fn serialize_load_round_trips() {
        let mut c = ScoredCache::new(cfg(1_000_000));
        c.insert(10, vec![0xaa; 100], false);
        c.insert(11, vec![0xbb; 100], false);
        c.insert(12, vec![0xcc; 100], true); // staged → NOT persisted
        let blob = c.serialize();

        let loaded = ScoredCache::load(&blob, cfg(1_000_000)).unwrap();
        assert_eq!(loaded.len(), 2); // only confirmed
        assert_eq!(loaded.confirmed_bytes(), 200);

        // a malformed blob fails closed
        assert!(ScoredCache::load(&[0u8; 4], cfg(100)).is_err());
        assert!(ScoredCache::load(&blob[..30], cfg(100)).is_err());
    }

    #[test]
    fn load_with_smaller_budget_evicts() {
        let mut c = ScoredCache::new(cfg(1_000_000));
        for i in 0..5 {
            c.insert(i, vec![0u8; 100], false);
        }
        let blob = c.serialize();
        // reload with room for only ~2 segments
        let loaded = ScoredCache::load(&blob, cfg(250)).unwrap();
        assert!(loaded.confirmed_bytes() <= 250);
        assert!(loaded.len() <= 2);
    }
}
