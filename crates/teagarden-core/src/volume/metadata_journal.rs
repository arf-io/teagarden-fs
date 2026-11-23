//! Metadata journal delta codec (v0.4.3 durability journal).
//!
//! Blocks upload to Telegram synchronously on every write, but the *metadata*
//! that maps blocks to files lives only in local SQLite, snapshotted just at
//! unmount. A crash before that snapshot leaves the blocks durable in the channel
//! but **orphaned**. The journal closes that gap: each committed metadata
//! transaction is captured as a SQLite changeset and published to the channel as
//! an encrypted, versioned **delta**, *with* the write. Recovery = the last full
//! snapshot (see [`super::metadata_snapshot`]) + replay of the deltas after it,
//! in `seq` order.
//!
//! Each delta binds three header fields inside the AEAD plaintext, so the
//! authentication tag covers them:
//! - `seq` — a strictly monotonic per-volume counter. Replay refuses gaps or
//!   regressions, so a transport attacker cannot drop, reorder, or truncate the
//!   log without detection (truncation is caught by comparing the recovered HEAD
//!   `seq` against the HMAC-covered HEAD recorded in the volume config).
//! - `base_snapshot_version` — the [`super::metadata_snapshot`] version this delta
//!   applies on top of, so a delta can never be replayed against the wrong base.
//! - `parent_msg_id` — the channel message id of the predecessor delta (or the
//!   snapshot), forming a back-linked chain the recovery walk can follow.
//! - `prev_hash` (format v2 only) — BLAKE3 of the predecessor's exact ciphertext
//!   blob (the previous delta, or the base snapshot for `seq` 1). A message id is
//!   only a name the storage provider resolves; the hash binds the bytes. Without
//!   it, a provider that stored a delta but withheld the acknowledgement (the
//!   client rolled the write back and reused the header for the next write) could
//!   later serve that orphan in place of the acknowledged delta, and recovery
//!   would accept it. The journal HEAD records the hash of the newest delta, so
//!   the whole chain is pinned from the authenticated HEAD down to the snapshot.
//!
//! The format is versioned by the AAD tag so a delta can never be confused with
//! a `metadata-snapshot-v2` blob or any other ciphertext sealed under the same
//! data key. This build writes only `metadata-delta-v2`; it still reads
//! `metadata-delta-v1` (no `prev_hash`), accepting such deltas as they are, and
//! only below the first v2 delta of a chain.

use crate::crypto::aead;
use crate::crypto::keys::SymmetricKey;
use crate::error::CoreError;

/// AEAD AAD tag of the delta format this build writes (header with `prev_hash`).
const DELTA_AAD_V2: &[u8] = b"metadata-delta-v2";
/// AEAD AAD tag of the earlier delta format (no `prev_hash`), read-only.
const DELTA_AAD_V1: &[u8] = b"metadata-delta-v1";

/// v1 header length: `seq(8) || base_snapshot_version(8) || parent_msg_id(8)`.
const HEADER_LEN_V1: usize = 24;
/// v2 header length: the v1 header followed by `prev_hash(32)`.
const HEADER_LEN_V2: usize = HEADER_LEN_V1 + 32;

/// Authenticated header carried in every journal delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaHeader {
    /// Strictly monotonic per-volume sequence number (the previous delta's
    /// `seq` + 1; the first delta after a snapshot uses `seq = 1`).
    pub seq: u64,
    /// The metadata-snapshot version this delta is applied on top of.
    pub base_snapshot_version: u64,
    /// Channel message id of the predecessor delta, or the snapshot's message id
    /// for the first delta in a chain. `0` marks "no recorded parent".
    pub parent_msg_id: i64,
    /// BLAKE3 of the predecessor's ciphertext blob (previous delta, or the base
    /// snapshot for `seq` 1). `Some` for every delta this build writes; `None`
    /// only for a `metadata-delta-v1` delta read from an older chain.
    pub prev_hash: Option<[u8; 32]>,
}

/// BLAKE3 of a published blob, as `prev_hash` and the journal HEAD record it.
pub fn blob_hash(blob: &[u8]) -> [u8; 32] {
    *blake3::hash(blob).as_bytes()
}

/// Encrypt a journal delta (format v2), binding `header` to the `changeset` bytes.
///
/// Layout (plaintext, before AEAD, AAD `metadata-delta-v2`):
/// `seq(8 LE) || base_snapshot_version(8 LE) || parent_msg_id(8 LE) ||
/// prev_hash(32) || changeset`. `header.prev_hash` must be `Some`: this build
/// never writes the unbound v1 format.
pub fn encrypt_delta(
    data_key: &SymmetricKey,
    header: DeltaHeader,
    changeset: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let prev_hash = header.prev_hash.ok_or_else(|| {
        CoreError::Encryption("metadata delta: the predecessor's hash is required".into())
    })?;
    let mut plaintext = Vec::with_capacity(HEADER_LEN_V2 + changeset.len());
    plaintext.extend_from_slice(&header.seq.to_le_bytes());
    plaintext.extend_from_slice(&header.base_snapshot_version.to_le_bytes());
    plaintext.extend_from_slice(&header.parent_msg_id.to_le_bytes());
    plaintext.extend_from_slice(&prev_hash);
    plaintext.extend_from_slice(changeset);
    aead::encrypt(data_key, &plaintext, DELTA_AAD_V2)
        .map_err(|e| CoreError::Encryption(format!("metadata delta: {e}")))
}

/// Decrypt a journal delta of either format, returning `(header, changeset_bytes)`.
/// A `metadata-delta-v1` delta comes back with `prev_hash: None`.
///
/// The AEAD tag authenticates the header and the changeset, so a tampered seq,
/// base version, parent link, predecessor hash or changeset is rejected before
/// any bytes return. The AAD fixes the format, so a v2 blob cannot be read as v1.
pub fn decrypt_delta(
    data_key: &SymmetricKey,
    blob: &[u8],
) -> Result<(DeltaHeader, Vec<u8>), CoreError> {
    let (plaintext, header_len) = match aead::decrypt(data_key, blob, DELTA_AAD_V2) {
        Ok(p) => (p, HEADER_LEN_V2),
        Err(_) => (
            aead::decrypt(data_key, blob, DELTA_AAD_V1)
                .map_err(|e| CoreError::Decryption(format!("metadata delta: {e}")))?,
            HEADER_LEN_V1,
        ),
    };
    if plaintext.len() < header_len {
        return Err(CoreError::Snapshot(
            "metadata delta too short to contain a header".into(),
        ));
    }
    let seq = u64::from_le_bytes(plaintext[0..8].try_into().unwrap());
    let base_snapshot_version = u64::from_le_bytes(plaintext[8..16].try_into().unwrap());
    let parent_msg_id = i64::from_le_bytes(plaintext[16..24].try_into().unwrap());
    let prev_hash = (header_len == HEADER_LEN_V2)
        .then(|| <[u8; 32]>::try_from(&plaintext[HEADER_LEN_V1..HEADER_LEN_V2]).unwrap());
    let header = DeltaHeader {
        seq,
        base_snapshot_version,
        parent_msg_id,
        prev_hash,
    };
    Ok((header, plaintext[header_len..].to_vec()))
}

/// Verify that a contiguous chain (already checked by
/// [`verify_chain_contiguous`], `headers[i]` is seq `i + 1`) is made of exactly
/// the blobs the authenticated HEAD and each delta name.
///
/// - `blob_hashes[i]` is [`blob_hash`] of the blob `headers[i]` came from;
/// - every v2 delta's `prev_hash` must equal the hash of the blob before it
///   (`base_snapshot_hash` for the first);
/// - no v1 delta may follow a v2 delta (this build never writes v1);
/// - `head_hash`, when the HEAD records one, must equal the hash of the newest
///   delta (or `base_snapshot_hash` for an empty chain).
///
/// v1 deltas below the first v2 one carry no link and are accepted as they are.
pub fn verify_chain_links(
    headers: &[DeltaHeader],
    blob_hashes: &[[u8; 32]],
    base_snapshot_hash: [u8; 32],
    head_hash: Option<[u8; 32]>,
) -> Result<(), CoreError> {
    if headers.len() != blob_hashes.len() {
        return Err(CoreError::Snapshot(
            "journal chain: header and blob counts differ".into(),
        ));
    }
    let mut seen_v2 = false;
    for (i, h) in headers.iter().enumerate() {
        match h.prev_hash {
            Some(prev) => {
                seen_v2 = true;
                let expected = if i == 0 {
                    base_snapshot_hash
                } else {
                    blob_hashes[i - 1]
                };
                if prev != expected {
                    return Err(CoreError::Snapshot(format!(
                        "journal delta seq {} names a predecessor whose hash does not match                          the blob served for it; the storage provider substituted a message                          (refusing to recover)",
                        h.seq
                    )));
                }
            }
            None if seen_v2 => {
                return Err(CoreError::Snapshot(format!(
                    "journal delta seq {} is in the unbound v1 format but follows a v2 delta;                      refusing to recover",
                    h.seq
                )));
            }
            None => {}
        }
    }
    if let Some(want) = head_hash {
        let newest = blob_hashes.last().copied().unwrap_or(base_snapshot_hash);
        if newest != want {
            return Err(CoreError::Snapshot(
                "journal recovery: the newest delta's hash does not match the HMAC-covered                  HEAD; the storage provider served a different message (refusing to recover)"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// Verify that `headers` form a contiguous, strictly-increasing chain starting at
/// `expected_first_seq` and reaching at least `required_head_seq`, all sharing the
/// same `base_snapshot_version`.
///
/// This is the chain generalization of the scalar anti-rollback check used for
/// snapshots: a transport attacker's move against a log is to serve a *prefix*
/// (truncation) or a gapped/reordered set. Recovery must refuse to proceed unless
/// the channel presents an authenticated, contiguous chain up to `>=` the
/// HMAC-covered HEAD `seq` recorded in the volume config.
///
/// `headers` must already be sorted by `seq` ascending by the caller; this checks
/// contiguity, the start point, the base, and that the head reaches the floor.
pub fn verify_chain_contiguous(
    headers: &[DeltaHeader],
    expected_first_seq: u64,
    base_snapshot_version: u64,
    required_head_seq: u64,
) -> Result<(), CoreError> {
    // An empty log is valid only when nothing is required beyond the snapshot.
    if headers.is_empty() {
        if required_head_seq < expected_first_seq {
            return Ok(());
        }
        return Err(CoreError::Snapshot(format!(
            "journal truncated: no deltas present but the config requires the log \
             to reach seq {required_head_seq}"
        )));
    }

    let mut expected = expected_first_seq;
    for (i, h) in headers.iter().enumerate() {
        if h.base_snapshot_version != base_snapshot_version {
            return Err(CoreError::Snapshot(format!(
                "journal delta #{i} has base snapshot version {} but the local base is {}",
                h.base_snapshot_version, base_snapshot_version
            )));
        }
        if h.seq != expected {
            return Err(CoreError::Snapshot(format!(
                "journal not contiguous: expected seq {expected} at position {i}, found {}",
                h.seq
            )));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| CoreError::Snapshot("journal seq overflow".into()))?;
    }

    let head_seq = headers[headers.len() - 1].seq;
    if head_seq < required_head_seq {
        return Err(CoreError::Snapshot(format!(
            "journal truncated: chain reaches seq {head_seq} but the config (HMAC-covered) \
             requires at least {required_head_seq}; refusing to recover a rolled-back log"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::from_bytes([0x3C; 32])
    }

    fn hdr(seq: u64, base: u64, parent: i64) -> DeltaHeader {
        DeltaHeader {
            seq,
            base_snapshot_version: base,
            parent_msg_id: parent,
            prev_hash: Some([seq as u8; 32]),
        }
    }

    /// A delta in the v1 layout debb93b wrote (no `prev_hash`, AAD v1).
    fn v1_blob(seq: u64, base: u64, parent: i64, cs: &[u8]) -> Vec<u8> {
        let mut pt = vec![];
        pt.extend_from_slice(&seq.to_le_bytes());
        pt.extend_from_slice(&base.to_le_bytes());
        pt.extend_from_slice(&parent.to_le_bytes());
        pt.extend_from_slice(cs);
        aead::encrypt(&key(), &pt, DELTA_AAD_V1).unwrap()
    }

    #[test]
    fn v1_delta_still_decrypts_without_a_link() {
        let (h, cs) = decrypt_delta(&key(), &v1_blob(4, 2, 77, b"cs")).unwrap();
        assert_eq!(
            (h.seq, h.base_snapshot_version, h.parent_msg_id),
            (4, 2, 77)
        );
        assert_eq!(h.prev_hash, None);
        assert_eq!(cs, b"cs");
    }

    #[test]
    fn writing_without_a_predecessor_hash_is_refused() {
        let mut h = hdr(1, 0, 0);
        h.prev_hash = None;
        assert!(encrypt_delta(&key(), h, b"x").is_err());
    }

    #[test]
    fn v2_blob_is_not_readable_under_the_v1_tag() {
        let blob = encrypt_delta(&key(), hdr(1, 0, 0), b"x").unwrap();
        assert!(aead::decrypt(&key(), &blob, DELTA_AAD_V1).is_err());
    }

    fn linked(n: u64, base: [u8; 32]) -> (Vec<DeltaHeader>, Vec<[u8; 32]>) {
        let (mut hs, mut hashes) = (vec![], vec![]);
        let mut prev = base;
        for seq in 1..=n {
            let mut h = hdr(seq, 4, 0);
            h.prev_hash = Some(prev);
            let blob = encrypt_delta(&key(), h, &[seq as u8]).unwrap();
            prev = blob_hash(&blob);
            hs.push(h);
            hashes.push(prev);
        }
        (hs, hashes)
    }

    #[test]
    fn linked_chain_verifies_against_base_and_head() {
        let base = [0x5B; 32];
        let (hs, hashes) = linked(3, base);
        verify_chain_links(&hs, &hashes, base, Some(hashes[2])).unwrap();
        verify_chain_links(&hs, &hashes, base, None).unwrap();
        // Empty chain: the HEAD hash is the base snapshot's.
        verify_chain_links(&[], &[], base, Some(base)).unwrap();
        assert!(verify_chain_links(&[], &[], base, Some([0; 32])).is_err());
    }

    #[test]
    fn substituted_blob_anywhere_in_the_chain_is_refused() {
        let base = [0x5B; 32];
        let (hs, hashes) = linked(3, base);
        for i in 0..3 {
            let mut bad = hashes.clone();
            bad[i] = [0xEE; 32];
            // Below the newest delta the next delta's link catches it; the newest
            // one is caught by the HEAD hash.
            assert!(
                verify_chain_links(&hs, &bad, base, Some(hashes[2])).is_err(),
                "substitution at {i} accepted"
            );
        }
        assert!(
            verify_chain_links(&hs, &hashes, [0; 32], None).is_err(),
            "wrong base"
        );
    }

    #[test]
    fn v1_below_v2_is_accepted_v1_above_v2_is_not() {
        let base = [0x5B; 32];
        let v1 = |seq| DeltaHeader {
            prev_hash: None,
            ..hdr(seq, 4, 0)
        };
        let mut h3 = hdr(3, 4, 0);
        h3.prev_hash = Some([0x22; 32]);
        let hashes = [[0x11; 32], [0x22; 32], [0x33; 32]];
        verify_chain_links(&[v1(1), v1(2), h3], &hashes, base, Some([0x33; 32])).unwrap();
        // A v1 delta answered in place of the v2 one is refused by the HEAD hash
        // and, above a v2 delta, by format.
        let mut h2 = hdr(2, 4, 0);
        h2.prev_hash = Some([0x11; 32]);
        assert!(verify_chain_links(&[v1(1), h2, v1(3)], &hashes, base, None).is_err());
    }

    #[test]
    fn delta_round_trips_header_and_changeset() {
        let cs = b"sqlite-changeset-bytes \x00\x01\x02".to_vec();
        let h = hdr(7, 3, 42);
        let blob = encrypt_delta(&key(), h, &cs).unwrap();
        let (got_h, got_cs) = decrypt_delta(&key(), &blob).unwrap();
        assert_eq!(got_h, h);
        assert_eq!(got_cs, cs);
    }

    #[test]
    fn empty_changeset_round_trips() {
        let h = hdr(1, 0, 0);
        let blob = encrypt_delta(&key(), h, &[]).unwrap();
        let (got_h, got_cs) = decrypt_delta(&key(), &blob).unwrap();
        assert_eq!(got_h, h);
        assert!(got_cs.is_empty());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let blob = encrypt_delta(&key(), hdr(1, 0, 0), b"x").unwrap();
        let other = SymmetricKey::from_bytes([0x11; 32]);
        assert!(decrypt_delta(&other, &blob).is_err());
    }

    #[test]
    fn tampered_header_byte_is_rejected() {
        // The seq lives in the AEAD plaintext, so flipping any ciphertext byte
        // fails authentication — an attacker cannot renumber a delta.
        let mut blob = encrypt_delta(&key(), hdr(5, 2, 9), b"hello").unwrap();
        blob[0] ^= 0x01;
        assert!(decrypt_delta(&key(), &blob).is_err());
    }

    #[test]
    fn cross_format_blob_is_rejected() {
        // A metadata-snapshot-v2 blob must not decrypt as a delta (distinct AAD).
        let snap = super::super::metadata_snapshot::encrypt_snapshot(&key(), 1, b"db").unwrap();
        assert!(decrypt_delta(&key(), &snap).is_err());
    }

    #[test]
    fn contiguous_chain_accepts() {
        let hs = [hdr(1, 4, 0), hdr(2, 4, 0), hdr(3, 4, 0)];
        assert!(verify_chain_contiguous(&hs, 1, 4, 3).is_ok());
        // Reaching beyond the required head is fine.
        assert!(verify_chain_contiguous(&hs, 1, 4, 2).is_ok());
    }

    #[test]
    fn truncated_chain_is_rejected() {
        // Config requires the log to reach seq 3, but only 1..=2 are served.
        let hs = [hdr(1, 4, 0), hdr(2, 4, 0)];
        assert!(verify_chain_contiguous(&hs, 1, 4, 3).is_err());
    }

    #[test]
    fn gapped_chain_is_rejected() {
        let hs = [hdr(1, 4, 0), hdr(3, 4, 0)];
        assert!(verify_chain_contiguous(&hs, 1, 4, 3).is_err());
    }

    #[test]
    fn wrong_base_version_is_rejected() {
        let hs = [hdr(1, 4, 0), hdr(2, 9, 0)];
        assert!(verify_chain_contiguous(&hs, 1, 4, 2).is_err());
    }

    #[test]
    fn empty_log_ok_when_nothing_required() {
        // Just after a fresh snapshot: no deltas, required head below the first seq.
        assert!(verify_chain_contiguous(&[], 1, 4, 0).is_ok());
        // But required head at/after the first seq with no deltas is truncation.
        assert!(verify_chain_contiguous(&[], 1, 4, 1).is_err());
    }
}
