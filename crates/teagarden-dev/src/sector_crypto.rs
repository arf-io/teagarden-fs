//! Position-addressed record cryptography.
//!
//! A **record** is the unit the block device seals and uploads: the plaintext for a
//! contiguous LBA extent, encrypted with XChaCha20-Poly1305 (reusing
//! [`teagarden_core::crypto::aead`]) under the volume's epoch key. Two properties
//! matter and are enforced here:
//!
//! 1. **Fresh nonce per PHYSICAL write.** The underlying `aead::encrypt` draws a
//!    fresh 192-bit `OsRng` nonce on every call — never a per-LBA deterministic
//!    nonce — so rewriting the same LBA can never reuse a nonce. This is the
//!    classic position-addressed-crypto trap and the reason the log is
//!    append-only.
//! 2. **Position binding (anti-relocation).** The AAD binds the record to its
//!    place: `device_uuid ‖ epoch ‖ segment_id ‖ record_off ‖ lba_start ‖
//!    plain_len`. A record moved to a different LBA, segment, offset, epoch, or
//!    device fails to decrypt — fail-closed, no partial plaintext.

use teagarden_core::crypto::aead;
use teagarden_core::crypto::keys::SymmetricKey;

use crate::error::{DeviceError, Result};

/// Domain-separation tag + version for the record AAD. Bump the version if the
/// AAD layout ever changes (it is part of the on-wire durability contract).
pub const RECORD_AAD_CONTEXT: &[u8] = b"tgdev-rec-v1";

/// Bytes of overhead a sealed record adds over its plaintext (nonce + tag).
pub const RECORD_OVERHEAD: usize = aead::NONCE_SIZE + aead::TAG_SIZE;

/// The fields bound into a record's AEAD associated data. Getting the field
/// order or width wrong silently weakens anti-relocation, so the layout is fixed
/// and little-endian, prefixed by [`RECORD_AAD_CONTEXT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordAad {
    /// Stable per-device identifier (binds the record to THIS device).
    pub device_uuid: [u8; 16],
    /// Key epoch the record is sealed under.
    pub epoch: u32,
    /// Segment (Telegram document) the record lives in.
    pub segment_id: u64,
    /// Byte offset of the record within the segment's plaintext framing.
    pub record_off: u64,
    /// First logical block this record's plaintext covers.
    pub lba_start: u64,
    /// Plaintext length of the record in bytes (anti-truncation).
    pub plain_len: u64,
}

impl RecordAad {
    /// Serialize to the fixed little-endian AAD byte string.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(RECORD_AAD_CONTEXT.len() + 16 + 4 + 8 * 4);
        v.extend_from_slice(RECORD_AAD_CONTEXT);
        v.extend_from_slice(&self.device_uuid);
        v.extend_from_slice(&self.epoch.to_le_bytes());
        v.extend_from_slice(&self.segment_id.to_le_bytes());
        v.extend_from_slice(&self.record_off.to_le_bytes());
        v.extend_from_slice(&self.lba_start.to_le_bytes());
        v.extend_from_slice(&self.plain_len.to_le_bytes());
        v
    }
}

/// Seal `plaintext` under `key` bound to its position (`aad`). Returns
/// `nonce ‖ ciphertext ‖ tag`. A fresh random nonce is drawn per call.
///
/// `aad.plain_len` must equal `plaintext.len()`; a mismatch is rejected so a
/// caller cannot accidentally seal a length the framing will later disbelieve.
pub fn seal_record(key: &SymmetricKey, plaintext: &[u8], aad: &RecordAad) -> Result<Vec<u8>> {
    if aad.plain_len != plaintext.len() as u64 {
        return Err(DeviceError::Crypto(format!(
            "record AAD plain_len {} != plaintext len {}",
            aad.plain_len,
            plaintext.len()
        )));
    }
    aead::encrypt(key, plaintext, &aad.to_bytes()).map_err(|e| DeviceError::Crypto(e.to_string()))
}

/// Open a sealed record, verifying the position-binding `aad`. Fails closed
/// (returns `Err`, never partial plaintext) if the record was tampered,
/// truncated, or relocated to a different LBA / segment / offset / epoch / device.
pub fn open_record(key: &SymmetricKey, sealed: &[u8], aad: &RecordAad) -> Result<Vec<u8>> {
    let pt = aead::decrypt(key, sealed, &aad.to_bytes())
        .map_err(|e| DeviceError::Crypto(e.to_string()))?;
    if pt.len() as u64 != aad.plain_len {
        return Err(DeviceError::Crypto(format!(
            "opened record len {} != AAD plain_len {}",
            pt.len(),
            aad.plain_len
        )));
    }
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::from_bytes([0x42u8; 32])
    }

    fn aad(lba: u64, seg: u64, off: u64, epoch: u32, len: u64) -> RecordAad {
        RecordAad {
            device_uuid: [7u8; 16],
            epoch,
            segment_id: seg,
            record_off: off,
            lba_start: lba,
            plain_len: len,
        }
    }

    // TC-CRY-1: round-trip.
    #[test]
    fn round_trip() {
        let pt = b"the quick brown fox jumps over the lazy dog".to_vec();
        let a = aad(10, 1, 0, 3, pt.len() as u64);
        let sealed = seal_record(&key(), &pt, &a).unwrap();
        assert_eq!(sealed.len(), pt.len() + RECORD_OVERHEAD);
        assert_eq!(open_record(&key(), &sealed, &a).unwrap(), pt);
    }

    // TC-CRY-2: rewriting the SAME LBA yields a different nonce AND ciphertext —
    // the fresh-nonce-per-physical-write property (no nonce reuse on overwrite).
    #[test]
    fn rewrite_same_lba_uses_fresh_nonce() {
        let pt = vec![0xabu8; 4096];
        let a = aad(10, 1, 0, 3, pt.len() as u64);
        let s1 = seal_record(&key(), &pt, &a).unwrap();
        let s2 = seal_record(&key(), &pt, &a).unwrap();
        // nonce is the first 24 bytes
        assert_ne!(&s1[..aead::NONCE_SIZE], &s2[..aead::NONCE_SIZE]);
        // ...and therefore the ciphertext differs too
        assert_ne!(s1, s2);
        // both still open to the same plaintext
        assert_eq!(open_record(&key(), &s1, &a).unwrap(), pt);
        assert_eq!(open_record(&key(), &s2, &a).unwrap(), pt);
    }

    // TC-CRY-3: a record cannot be opened under a DIFFERENT position — changing
    // any AAD field (lba/segment/offset/epoch/device/len) fails closed.
    #[test]
    fn relocation_and_wrong_context_fail_closed() {
        let pt = vec![0x11u8; 512];
        let good = aad(10, 1, 0, 3, pt.len() as u64);
        let sealed = seal_record(&key(), &pt, &good).unwrap();

        assert!(open_record(&key(), &sealed, &aad(11, 1, 0, 3, pt.len() as u64)).is_err()); // wrong lba
        assert!(open_record(&key(), &sealed, &aad(10, 2, 0, 3, pt.len() as u64)).is_err()); // wrong segment
        assert!(open_record(&key(), &sealed, &aad(10, 1, 64, 3, pt.len() as u64)).is_err()); // wrong offset
        assert!(open_record(&key(), &sealed, &aad(10, 1, 0, 4, pt.len() as u64)).is_err()); // wrong epoch
        let mut wrong_dev = good;
        wrong_dev.device_uuid = [9u8; 16];
        assert!(open_record(&key(), &sealed, &wrong_dev).is_err()); // wrong device
                                                                    // wrong key
        let other = SymmetricKey::from_bytes([0x00u8; 32]);
        assert!(open_record(&other, &sealed, &good).is_err());
    }

    // TC-CRY tamper/truncation: a flipped byte or a truncated record fails closed.
    #[test]
    fn tamper_and_truncation_fail_closed() {
        let pt = vec![0x33u8; 200];
        let a = aad(5, 1, 0, 0, pt.len() as u64);
        let sealed = seal_record(&key(), &pt, &a).unwrap();

        // flip a ciphertext byte (after the nonce)
        let mut bad = sealed.clone();
        bad[aead::NONCE_SIZE] ^= 0xFF;
        assert!(open_record(&key(), &bad, &a).is_err());

        // truncate the tag
        let truncated = &sealed[..sealed.len() - 1];
        assert!(open_record(&key(), truncated, &a).is_err());

        // a too-short blob (shorter than nonce+tag) is rejected, not panicked
        assert!(open_record(&key(), &[0u8; 8], &a).is_err());
    }

    // seal rejects a plain_len that disagrees with the plaintext (defensive).
    #[test]
    fn seal_rejects_len_mismatch() {
        let pt = vec![0u8; 100];
        let a = aad(0, 0, 0, 0, 99); // wrong len
        assert!(seal_record(&key(), &pt, &a).is_err());
    }
}
