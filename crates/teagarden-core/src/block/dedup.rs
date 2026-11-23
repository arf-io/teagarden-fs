use std::collections::HashMap;

/// In-memory deduplication index mapping block identities to reference counts.
///
/// This index is used during write sessions to avoid redundant uploads within
/// a single session. It is never persisted to disk. For persistent dedup across
/// sessions, use `BlockStore::find_by_block_id`.
///
/// The key type is `[u8; 32]` — the caller is responsible for providing a
/// keyed block identity (see CABS spec §3) rather than an unkeyed content hash.
#[derive(Debug, Default)]
pub struct DedupIndex {
    /// block_id → (block_id, reference_count)
    entries: HashMap<[u8; 32], DedupEntry>,
}

/// A tracked block identity and its current reference count.
#[derive(Debug, Clone)]
pub struct DedupEntry {
    /// Block identity (caller-supplied keyed hash)
    pub block_id: [u8; 32],
    /// Number of file manifests referencing this block
    pub ref_count: u32,
}

/// Result of a dedup check.
#[derive(Debug)]
pub enum DedupResult {
    /// Block identity already tracked; reuse this block_id.
    Duplicate {
        /// The existing block identity to reuse instead of uploading.
        block_id: [u8; 32],
    },
    /// Block identity is new; upload required.
    Unique,
}

impl DedupIndex {
    /// Create an empty dedup index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a block with the given identity already exists in the index.
    pub fn check(&self, block_id: &[u8; 32]) -> DedupResult {
        match self.entries.get(block_id) {
            Some(entry) => DedupResult::Duplicate {
                block_id: entry.block_id,
            },
            None => DedupResult::Unique,
        }
    }

    /// Register a block identity in the dedup index.
    pub fn insert(&mut self, block_id: [u8; 32]) {
        self.entries
            .entry(block_id)
            .and_modify(|e| e.ref_count += 1)
            .or_insert(DedupEntry {
                block_id,
                ref_count: 1,
            });
    }

    /// Decrement reference count; returns `true` if the block can be garbage collected.
    pub fn release(&mut self, block_id: &[u8; 32]) -> bool {
        if let Some(entry) = self.entries.get_mut(block_id) {
            entry.ref_count = entry.ref_count.saturating_sub(1);
            if entry.ref_count == 0 {
                self.entries.remove(block_id);
                return true;
            }
        }
        false
    }

    /// Number of unique blocks tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no blocks are currently tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_block_is_unique() {
        let idx = DedupIndex::new();
        assert!(matches!(idx.check(&[0x42; 32]), DedupResult::Unique));
    }

    #[test]
    fn inserted_block_is_duplicate() {
        let mut idx = DedupIndex::new();
        let bid = [0x42; 32];
        idx.insert(bid);

        match idx.check(&bid) {
            DedupResult::Duplicate { block_id } => assert_eq!(block_id, bid),
            DedupResult::Unique => panic!("should be duplicate"),
        }
    }

    #[test]
    fn release_removes_at_zero_refs() {
        let mut idx = DedupIndex::new();
        let bid = [0x01; 32];
        idx.insert(bid);
        assert_eq!(idx.len(), 1);

        let gc = idx.release(&bid);
        assert!(gc);
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn release_decrements_refs() {
        let mut idx = DedupIndex::new();
        let bid = [0x01; 32];
        idx.insert(bid);
        idx.insert(bid); // ref_count = 2

        let gc = idx.release(&bid);
        assert!(!gc);
        assert_eq!(idx.len(), 1);

        let gc = idx.release(&bid);
        assert!(gc);
        assert_eq!(idx.len(), 0);
    }
}
