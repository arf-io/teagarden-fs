//! Block AEAD Additional-Authenticated-Data (AAD) selection (T7 part 2).
//!
//! Two on-disk block formats exist:
//!
//! - **block-v1**: a constant AAD (`b"block-v1"`). The AEAD tag does not bind the
//!   ciphertext to its logical identity, so defense against block substitution
//!   relies entirely on the metadata SHA-256 records (T7 part 1).
//! - **block-v2**: `AAD = "block-v2" || epoch_le || block_id`. Because `block_id`
//!   is the keyed BLAKE3 of the *plaintext* (identical for every deduplicated
//!   reference), dedup is preserved — yet the AEAD tag now binds the ciphertext
//!   to its content identity and epoch. A substituted block (sealed under a
//!   different `block_id`) fails authentication at the cipher layer, so
//!   substitution is rejected even without consulting the metadata hashes.
//!
//! Which format a block uses is decided by a per-volume epoch threshold,
//! `block_v2_from_epoch`: a block whose epoch is `>=` the threshold is block-v2.
//!
//! **WRITE-ONCE INVARIANT.** The AAD must be byte-identical at encrypt and
//! decrypt for a given block. Since the format is derived from
//! `(block.epoch >= threshold)` using the *current* threshold, the threshold
//! must be set **exactly once**, to a value **strictly greater than every
//! existing block's epoch** at the moment it is set. Otherwise a block sealed
//! under one format would later be read under the other and fail to decrypt
//! (a silent brick). Today the invariant holds **by construction**: the only
//! production setter is volume creation, which sets `Some(0)` before any block
//! exists.
//!
//! INTENTIONAL_STUB: the block-v1 → block-v2 upgrade path is not yet implemented,
//! and that is deliberate. It would set `Some(new_epoch)`; today, volume
//! creation sets `Some(0)`, so every volume ever created seals block-v2 from
//! epoch 0 and no volume in existence requires the upgrade. Building a migration
//! for a corpus that does not exist would be speculative code on the security
//! path, so the guard rail ships instead of the migration: if that setter is ever
//! added it MUST call `validate_block_v2_threshold` before setting the threshold.
//! That helper is implemented and unit-tested now, reserved for that future
//! setter — it is a real, exercised function, not a placeholder.

/// The constant AAD used by the legacy block-v1 format.
pub const BLOCK_V1_AAD: &[u8] = b"block-v1";

/// Version tag prefix for the block-v2 AAD.
const BLOCK_V2_TAG: &[u8] = b"block-v2";

/// Compute the AEAD AAD for a block at `epoch` with identity `block_id`, given
/// the volume's `block_v2_from_epoch` threshold (`None` = always block-v1).
///
/// The same `(epoch, block_id, threshold)` must be supplied at decrypt as was
/// used at encrypt — `block_id` is the value the metadata says the block *should*
/// be, so a substituted ciphertext sealed under a different identity fails.
pub fn block_aad(epoch: u32, block_id: &[u8; 32], block_v2_from_epoch: Option<u32>) -> Vec<u8> {
    match block_v2_from_epoch {
        Some(threshold) if epoch >= threshold => {
            let mut aad = Vec::with_capacity(BLOCK_V2_TAG.len() + 4 + 32);
            aad.extend_from_slice(BLOCK_V2_TAG);
            aad.extend_from_slice(&epoch.to_le_bytes());
            aad.extend_from_slice(block_id);
            aad
        }
        _ => BLOCK_V1_AAD.to_vec(),
    }
}

/// Validate a proposed `block_v2_from_epoch` threshold against the write-once
/// invariant: it must strictly exceed every existing block's epoch.
/// `max_existing_epoch` is `None` when the volume has no blocks yet.
pub fn validate_block_v2_threshold(new_threshold: u32, max_existing_epoch: Option<u32>) -> bool {
    match max_existing_epoch {
        Some(max) => new_threshold > max,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BID: [u8; 32] = [0xAB; 32];

    #[test]
    fn none_threshold_is_always_block_v1() {
        assert_eq!(block_aad(0, &BID, None), BLOCK_V1_AAD);
        assert_eq!(block_aad(99, &BID, None), BLOCK_V1_AAD);
    }

    #[test]
    fn below_threshold_is_block_v1_above_is_block_v2() {
        assert_eq!(block_aad(2, &BID, Some(5)), BLOCK_V1_AAD);
        let v2 = block_aad(5, &BID, Some(5));
        assert!(v2.starts_with(BLOCK_V2_TAG));
        assert_eq!(v2.len(), BLOCK_V2_TAG.len() + 4 + 32);
        assert_eq!(&v2[BLOCK_V2_TAG.len() + 4..], &BID);
    }

    #[test]
    fn block_v2_aad_binds_epoch_and_block_id() {
        // Different block_id or epoch ⇒ different AAD ⇒ AEAD auth would differ.
        let a = block_aad(5, &[0x01; 32], Some(0));
        let b = block_aad(5, &[0x02; 32], Some(0));
        let c = block_aad(6, &[0x01; 32], Some(0));
        assert_ne!(a, b, "block_id must change the AAD");
        assert_ne!(a, c, "epoch must change the AAD");
    }

    #[test]
    fn threshold_guard_enforces_write_once_invariant() {
        assert!(validate_block_v2_threshold(0, None)); // creation, no blocks
        assert!(validate_block_v2_threshold(6, Some(5))); // strictly greater — ok
        assert!(!validate_block_v2_threshold(5, Some(5))); // equal — would brick
        assert!(!validate_block_v2_threshold(3, Some(5))); // less — would brick
    }
}
