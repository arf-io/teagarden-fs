use serde::{Deserialize, Serialize};

use crate::crypto::keys::SymmetricKey;

/// A single block's location and metadata within the filesystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockPointer {
    /// Keyed block identity: `BLAKE3_keyed(Kblocks_epoch, plaintext)`.
    /// This is the canonical address of the block within the volume.
    /// Never derived from an unkeyed hash — see CABS spec §2 (Forensic Hash Problem).
    pub block_id: [u8; 32],
    /// Telegram message ID where this block is stored
    pub message_id: i64,
    /// Start offset within the file this block covers
    pub file_offset: u64,
    /// Number of bytes from the file this block contains (plaintext)
    pub length: u64,
    /// Offset within the Telegram message/block data
    pub block_data_offset: u64,
    /// Size of the encrypted block on Telegram (includes SRB1 overhead)
    pub encrypted_size: u64,
    /// Whether this block is compressed
    pub compressed: bool,
    /// Epoch this block was encrypted under
    pub epoch: u32,
}

/// Complete file manifest: ordered list of block pointers covering the file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileManifest {
    /// Inode this manifest belongs to
    pub inode: u64,
    /// Manifest version (incremented on each write)
    pub version: u64,
    /// Total file size (uncompressed)
    pub total_size: u64,
    /// BLAKE3 hash of the complete file content
    pub file_hash: [u8; 32],
    /// Ordered block pointers covering [0, total_size)
    /// Invariant: no gaps, no overlaps, sorted by file_offset
    pub blocks: Vec<BlockPointer>,
    /// Parent manifest IDs — prior versions of this file that this version succeeds.
    /// Empty for the first version. Usually one entry; two for merge-writes.
    #[serde(default)]
    pub parent_ids: Vec<[u8; 32]>,
}

impl FileManifest {
    /// Create a new empty manifest for an inode.
    pub fn new(inode: u64) -> Self {
        Self {
            inode,
            version: 0,
            total_size: 0,
            file_hash: [0u8; 32],
            blocks: Vec::new(),
            parent_ids: Vec::new(),
        }
    }

    /// Compute the manifest identity: `BLAKE3_keyed(key, canonical_bytes)`.
    ///
    /// The canonical bytes cover all content fields including `parent_ids`
    /// but NOT the manifest_id itself (it's derived, not stored).
    /// This gives each version a stable, volume-scoped, tamper-evident ID.
    pub fn compute_id(&self, key: &SymmetricKey) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(key.as_bytes());
        hasher.update(&self.inode.to_le_bytes());
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.total_size.to_le_bytes());
        hasher.update(&self.file_hash);
        hasher.update(&(self.blocks.len() as u64).to_le_bytes());
        for bp in &self.blocks {
            hasher.update(&bp.block_id);
            hasher.update(&bp.message_id.to_le_bytes());
            hasher.update(&bp.file_offset.to_le_bytes());
            hasher.update(&bp.length.to_le_bytes());
            hasher.update(&bp.block_data_offset.to_le_bytes());
            hasher.update(&bp.encrypted_size.to_le_bytes());
            hasher.update(&[bp.compressed as u8]);
            hasher.update(&bp.epoch.to_le_bytes());
        }
        hasher.update(&(self.parent_ids.len() as u64).to_le_bytes());
        for pid in &self.parent_ids {
            hasher.update(pid);
        }
        *hasher.finalize().as_bytes()
    }

    /// Validate manifest invariants: no gaps, no overlaps, sorted by offset.
    pub fn validate(&self) -> Result<(), String> {
        if self.blocks.is_empty() {
            if self.total_size != 0 {
                return Err("empty manifest with non-zero total_size".into());
            }
            return Ok(());
        }

        // First block must start at 0
        if self.blocks[0].file_offset != 0 {
            return Err(format!(
                "first block starts at {} instead of 0",
                self.blocks[0].file_offset
            ));
        }

        // core-L3: offsets/lengths come from decoded metadata; an overflowing
        // `file_offset + length` is an invalid manifest, never a panic or a wrap.
        let end_of = |i: usize| {
            let b = &self.blocks[i];
            b.file_offset
                .checked_add(b.length)
                .ok_or_else(|| format!("block {i}: file_offset + length overflows u64"))
        };

        for (i, curr) in self.blocks.iter().enumerate().skip(1) {
            let prev_end = end_of(i - 1)?;
            let curr_start = curr.file_offset;

            if curr_start < prev_end {
                return Err(format!(
                    "overlap at block {i}: prev ends at {prev_end}, this starts at {curr_start}"
                ));
            }
            if curr_start > prev_end {
                return Err(format!(
                    "gap at block {i}: prev ends at {prev_end}, this starts at {curr_start}"
                ));
            }
        }

        // Last block must end at total_size
        let end = end_of(self.blocks.len() - 1)?;
        if end != self.total_size {
            return Err(format!(
                "blocks end at {end} but total_size is {}",
                self.total_size
            ));
        }

        Ok(())
    }

    /// Find blocks that overlap with the given byte range [offset, offset+length).
    pub fn blocks_in_range(&self, offset: u64, length: u64) -> Vec<&BlockPointer> {
        // core-L3: saturate ("end of address space")
        // rather than overflow — a range or block that runs past u64::MAX simply
        // extends to the end.
        let range_end = offset.saturating_add(length);
        self.blocks
            .iter()
            .filter(|bp| {
                let block_end = bp.file_offset.saturating_add(bp.length);
                bp.file_offset < range_end && block_end > offset
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(offset: u64, length: u64) -> BlockPointer {
        BlockPointer {
            block_id: [0; 32],
            message_id: 0,
            file_offset: offset,
            length,
            block_data_offset: 0,
            encrypted_size: length.saturating_add(40),
            compressed: false,
            epoch: 0,
        }
    }

    #[test]
    fn empty_manifest_valid() {
        let m = FileManifest::new(1);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn empty_manifest_with_size_invalid() {
        let mut m = FileManifest::new(1);
        m.total_size = 100;
        assert!(m.validate().is_err());
    }

    #[test]
    fn single_block_manifest_valid() {
        let mut m = FileManifest::new(1);
        m.total_size = 1000;
        m.blocks = vec![make_block(0, 1000)];
        assert!(m.validate().is_ok());
    }

    #[test]
    fn contiguous_blocks_valid() {
        let mut m = FileManifest::new(1);
        m.total_size = 3000;
        m.blocks = vec![
            make_block(0, 1000),
            make_block(1000, 1000),
            make_block(2000, 1000),
        ];
        assert!(m.validate().is_ok());
    }

    #[test]
    fn gap_detected() {
        let mut m = FileManifest::new(1);
        m.total_size = 3000;
        m.blocks = vec![make_block(0, 1000), make_block(1500, 1500)];
        assert!(m.validate().is_err());
    }

    #[test]
    fn overlap_detected() {
        let mut m = FileManifest::new(1);
        m.total_size = 2500;
        m.blocks = vec![make_block(0, 1500), make_block(1000, 1500)];
        assert!(m.validate().is_err());
    }

    #[test]
    fn blocks_in_range_finds_overlapping() {
        let mut m = FileManifest::new(1);
        m.total_size = 3000;
        m.blocks = vec![
            make_block(0, 1000),
            make_block(1000, 1000),
            make_block(2000, 1000),
        ];
        let result = m.blocks_in_range(500, 1000);
        assert_eq!(result.len(), 2); // blocks 0 and 1
    }

    #[test]
    fn blocks_in_range_exact_boundary() {
        let mut m = FileManifest::new(1);
        m.total_size = 2000;
        m.blocks = vec![make_block(0, 1000), make_block(1000, 1000)];
        // Range [1000, 1500) should only match block 1
        let result = m.blocks_in_range(1000, 500);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_offset, 1000);
    }

    // core-L3: manifests are decoded from (attacker-influenced) metadata, so
    // `file_offset + length` must never overflow — a debug build panicked and a
    // release build wrapped, which let a crafted manifest pass `validate`.

    #[test]
    fn validate_rejects_offset_plus_length_overflow() {
        let mut m = FileManifest::new(1);
        // prev_end = 0 + u64::MAX; next block "starts" where a wrapped sum lands.
        m.blocks = vec![make_block(0, u64::MAX), make_block(u64::MAX, 2)];
        m.total_size = 1; // == wrapped (u64::MAX + 2)
        let r = std::panic::catch_unwind(|| m.validate());
        match r {
            Ok(res) => assert!(res.is_err(), "an overflowing manifest must be invalid"),
            Err(_) => panic!("validate panicked on overflow instead of returning Err"),
        }
    }

    #[test]
    fn validate_rejects_overflow_in_last_block() {
        let mut m = FileManifest::new(1);
        m.blocks = vec![make_block(0, 10), make_block(10, u64::MAX)];
        m.total_size = 9; // == wrapped (10 + u64::MAX)
        let r = std::panic::catch_unwind(|| m.validate());
        match r {
            Ok(res) => assert!(res.is_err(), "an overflowing last block must be invalid"),
            Err(_) => panic!("validate panicked on overflow instead of returning Err"),
        }
    }

    #[test]
    fn blocks_in_range_does_not_overflow() {
        let mut m = FileManifest::new(1);
        m.total_size = 3000;
        m.blocks = vec![make_block(0, 1000), make_block(1000, 2000)];
        // offset + length overflows u64: the range is "from 1500 to the end".
        let r = std::panic::catch_unwind(|| m.blocks_in_range(1500, u64::MAX).len());
        match r {
            Ok(n) => assert_eq!(n, 1, "range [1500, end) overlaps exactly the second block"),
            Err(_) => panic!("blocks_in_range panicked on overflow"),
        }
        // A block whose own end overflows must not panic either.
        m.blocks.push(make_block(3000, u64::MAX));
        let r = std::panic::catch_unwind(|| m.blocks_in_range(0, 10).len());
        assert!(
            r.is_ok(),
            "blocks_in_range panicked on a block-end overflow"
        );
    }
}
