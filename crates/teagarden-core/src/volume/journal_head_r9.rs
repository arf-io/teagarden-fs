//! TEST ONLY: the journal HEAD loader of the round-9 build (2f21a9f), verbatim
//! below this header, kept to show what an older build does with a HEAD this
//! build writes (version skew; see SECURITY_MODEL.md section 5).

//! On-disk journal HEAD pointer with an anti-rollback MAC.
//!
//! The metadata journal (see [`super::metadata_journal`]) publishes one encrypted
//! delta per filesystem operation to the channel. The **HEAD** records the highest
//! published delta (`seq`), its channel message id (`parent_msg_id`, the parent for
//! the next delta), and the snapshot version the current delta chain applies on
//! top of (`base_snapshot_version`).
//!
//! HEAD is the anti-rollback **floor** for recovery: a transport attacker who
//! truncates the channel log is caught by comparing the recovered, authenticated
//! delta chain against this floor (see
//! [`super::metadata_journal::verify_chain_contiguous`]). For that to hold, the
//! floor itself must be tamper-proof, so HEAD is authenticated with a BLAKE3-keyed
//! MAC over its fields using the hierarchy **integrity** key — the same key that
//! protects the volume config. It cannot be lowered by editing the local file.
//!
//! HEAD lives in its own tiny file rather than `volume.json` because it is
//! rewritten on **every** journaled transaction; rewriting the full config (with
//! its KDF parameters) per op would be needless write amplification. It is written
//! atomically (temp + fsync + rename) and persisted *before* the local `COMMIT`,
//! so a crash can only leave the floor ahead of the DB (fail-closed), never behind
//! — the same invariant as the v0.4.2 restore floor.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::keys::SymmetricKey;
use crate::error::CoreError;

/// The journaled HEAD: highest published delta and the chain's snapshot base.
///
/// HEAD is **self-contained**: it carries both the base snapshot's version AND its
/// channel message id, so recovery can fetch the base + walk the deltas entirely
/// from this one atomically-written, MAC'd unit — it never has to cross-reference
/// `volume.json`. That avoids a brick: at compaction, the snapshot publish, the
/// config rewrite, and the HEAD reset are three writes; if recovery read the base
/// id from the config but the version from HEAD, a crash between those writes would
/// leave them disagreeing and recovery would reject a valid chain. Reading both
/// from HEAD makes every crash window converge on "use the old HEAD, rebuild the
/// last consistent state; the new snapshot is just an orphan."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalHead {
    /// Sequence number of the highest published delta (0 = no deltas since the
    /// base snapshot).
    pub seq: u64,
    /// Channel message id of that delta (parent for the next one). 0 = none.
    pub parent_msg_id: i64,
    /// Snapshot version the current delta chain applies on top of.
    pub base_snapshot_version: u64,
    /// Channel message id of the base snapshot (what recovery fetches first).
    pub base_snapshot_msg_id: i64,
    /// BLAKE3 of the base snapshot's *ciphertext blob* (the exact bytes published
    /// to the channel). Recovery recomputes this over the fetched blob and rejects
    /// any mismatch, so the transport cannot substitute a *different* snapshot that
    /// merely shares the same version id — version equality alone is not enough.
    pub base_snapshot_hash: [u8; 32],
    /// BLAKE3 of the blob at `parent_msg_id`: the newest delta's ciphertext, or
    /// the base snapshot's when `seq` is 0. The next delta carries it as its
    /// `prev_hash`, and recovery checks the newest delta it is served against it,
    /// so the whole chain is pinned by this MAC'd file. `None` only in a HEAD
    /// written before the field existed (format v1; see [`Self::chain_hash`]).
    pub last_hash: Option<[u8; 32]>,
}

/// Domain tag that starts the MAC preimage of a HEAD carrying `last_hash`, so
/// it can never collide with the 64-byte preimage of a v1 HEAD.
const MAC_V2_TAG: &[u8] = b"teagarden.journal-head.v2";

/// On-disk representation: the fields plus a hex MAC over them.
#[derive(Debug, Serialize, Deserialize)]
struct JournalHeadFile {
    seq: u64,
    parent_msg_id: i64,
    base_snapshot_version: u64,
    base_snapshot_msg_id: i64,
    /// Hex of the base snapshot ciphertext BLAKE3.
    base_snapshot_hash: String,
    /// Hex of [`JournalHead::last_hash`]; absent in a v1 HEAD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_hash: Option<String>,
    /// Hex BLAKE3-keyed MAC over the fields, keyed by the hierarchy integrity key.
    mac: String,
}

impl JournalHead {
    /// The HEAD of a chain that has just been compacted onto a freshly published
    /// snapshot: no deltas yet (`seq` 0), the snapshot is both the base and the
    /// parent of the first delta. `blob_hash` is BLAKE3 of the snapshot blob.
    pub fn at_snapshot(snapshot_msg_id: i64, version: u64, blob_hash: [u8; 32]) -> Self {
        JournalHead {
            seq: 0,
            parent_msg_id: snapshot_msg_id,
            base_snapshot_version: version,
            base_snapshot_msg_id: snapshot_msg_id,
            base_snapshot_hash: blob_hash,
            last_hash: Some(blob_hash),
        }
    }

    /// The hash the next delta must carry as `prev_hash`, if known without
    /// fetching anything: `last_hash`, or for a v1 HEAD at `seq` 0 the base
    /// snapshot's hash (the parent then is the snapshot). `None` for a v1 HEAD
    /// with deltas: the caller has to hash the blob at `parent_msg_id`.
    pub fn chain_hash(&self) -> Option<[u8; 32]> {
        self.last_hash
            .or((self.seq == 0).then_some(self.base_snapshot_hash))
    }

    /// Bytes the MAC authenticates: `seq || parent_msg_id || base_snapshot_version
    /// || base_snapshot_msg_id || base_snapshot_hash`, the scalars little-endian. A
    /// fixed-layout preimage (not the JSON) so formatting can never change the input.
    /// With `last_hash` (v2) the preimage is `MAC_V2_TAG || those 64 bytes ||
    /// last_hash`; without it (v1) exactly the 64 bytes, so a HEAD written before
    /// the field existed still verifies, and dropping the field from a v2 HEAD
    /// fails the MAC.
    fn mac_preimage(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(MAC_V2_TAG.len() + 96);
        if self.last_hash.is_some() {
            p.extend_from_slice(MAC_V2_TAG);
        }
        p.extend_from_slice(&self.seq.to_le_bytes());
        p.extend_from_slice(&self.parent_msg_id.to_le_bytes());
        p.extend_from_slice(&self.base_snapshot_version.to_le_bytes());
        p.extend_from_slice(&self.base_snapshot_msg_id.to_le_bytes());
        p.extend_from_slice(&self.base_snapshot_hash);
        if let Some(h) = &self.last_hash {
            p.extend_from_slice(h);
        }
        p
    }

    fn mac(&self, integrity_key: &SymmetricKey) -> String {
        let tag = blake3::keyed_hash(integrity_key.as_bytes(), &self.mac_preimage());
        hex::encode(tag.as_bytes())
    }

    /// Load and authenticate HEAD from `path`. Returns `Ok(None)` if the file is
    /// absent (a volume with no journal yet), and `Err` if the MAC does not verify
    /// (tampering / wrong key) — fail-closed, so a forged lower floor is rejected.
    pub fn load(path: &Path, integrity_key: &SymmetricKey) -> Result<Option<Self>, CoreError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(CoreError::Volume(format!("read journal head: {e}"))),
        };
        let f: JournalHeadFile = serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::Serialization(format!("journal head: {e}")))?;
        let mut base_snapshot_hash = [0u8; 32];
        hex::decode_to_slice(&f.base_snapshot_hash, &mut base_snapshot_hash).map_err(|e| {
            CoreError::Serialization(format!("journal head base_snapshot_hash: {e}"))
        })?;
        let last_hash = f
            .last_hash
            .as_deref()
            .map(|h| {
                let mut out = [0u8; 32];
                hex::decode_to_slice(h, &mut out).map(|()| out)
            })
            .transpose()
            .map_err(|e| CoreError::Serialization(format!("journal head last_hash: {e}")))?;
        let head = JournalHead {
            seq: f.seq,
            parent_msg_id: f.parent_msg_id,
            base_snapshot_version: f.base_snapshot_version,
            base_snapshot_msg_id: f.base_snapshot_msg_id,
            base_snapshot_hash,
            last_hash,
        };
        let expected = head.mac(integrity_key);
        if !ct_eq(expected.as_bytes(), f.mac.as_bytes()) {
            return Err(CoreError::Volume(
                "journal head MAC mismatch — the anti-rollback HEAD has been tampered with".into(),
            ));
        }
        Ok(Some(head))
    }

    /// Atomically persist `self` to `path`, MAC'd with `integrity_key`.
    ///
    /// Writes a temp file (0600), fsyncs it, renames it over `path`, then fsyncs
    /// the directory — so a crash never leaves a torn HEAD.
    pub fn store_atomic(&self, path: &Path, integrity_key: &SymmetricKey) -> Result<(), CoreError> {
        let f = JournalHeadFile {
            seq: self.seq,
            parent_msg_id: self.parent_msg_id,
            base_snapshot_version: self.base_snapshot_version,
            base_snapshot_msg_id: self.base_snapshot_msg_id,
            base_snapshot_hash: hex::encode(self.base_snapshot_hash),
            last_hash: self.last_hash.map(hex::encode),
            mac: self.mac(integrity_key),
        };
        let json = serde_json::to_vec(&f)
            .map_err(|e| CoreError::Serialization(format!("journal head: {e}")))?;

        crate::fsutil::write_file_atomic(path, &json, "journal head")
    }
}

/// Constant-time equality for equal-length byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod skew_tests {
    use crate::crypto::keys::SymmetricKey;
    use crate::volume::journal_head as current;

    /// S4: the round-9 build reads a journal.head written by this build
    /// (format v3, with `lineage`) as TAMPERED. A user may delete it on that
    /// advice; this build's mount then refuses instead of replacing the DB
    /// (cli: `s4_deleting_journal_head_makes_the_mount_refuse_not_replace`).
    #[test]
    fn a_round9_build_reads_a_v3_head_as_tampered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.head");
        let k = SymmetricKey::from_bytes([0x9A; 32]);
        let h = current::JournalHead::at_snapshot(50, 3, [0xC3; 32], current::Lineage::new(3));
        h.store_atomic(&path, &k).unwrap();
        assert!(current::JournalHead::load(&path, &k).unwrap().is_some());
        let got = super::JournalHead::load(&path, &k);
        let e = got
            .map(|_| ())
            .expect_err("the round-9 loader accepted a v3 HEAD");
        eprintln!("S4: the round-9 loader on a v3 HEAD: {e}");
        assert!(e.to_string().contains("tampered"), "{e}");
    }
}
