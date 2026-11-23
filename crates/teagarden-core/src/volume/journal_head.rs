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
//!
//! HEAD also records the volume's metadata **lineage** ([`Lineage`]): the
//! snapshot version and the random nonce stamped into the local metadata DB
//! when it became, or was published as, that snapshot. A local DB whose stamp
//! differs is not the volume's current database and is rebuilt (see
//! `teagarden_store::local_db`). A HEAD written before the field existed has
//! none and reads as legacy.

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
    /// The lineage of the volume's current local metadata DB: the stamp the DB
    /// must carry to be used as it is. Carried unchanged by every journal
    /// append; replaced when a snapshot is published or restored, or when a
    /// rebuild stamps the DB. `None` in a HEAD written before the field existed
    /// (formats v1 and v2): legacy, every DB then needs a rebuild. Format v3
    /// requires [`Self::last_hash`].
    pub lineage: Option<Lineage>,
}

/// Which state of the volume's metadata a local metadata DB holds: the
/// snapshot version it represents and a random nonce, fresh each time a DB
/// becomes or is published as a snapshot version. Recorded in the DB (its
/// stamp, outside the journal) and in the HEAD; the two must be equal for the
/// DB to be used as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lineage {
    /// Snapshot version the DB represents.
    pub version: u64,
    /// Random; tells apart two DBs stamped at the same version.
    pub nonce: [u8; 16],
}

impl Lineage {
    /// A new lineage at `version` with a fresh random nonce.
    pub fn new(version: u64) -> Self {
        use rand::RngCore as _;
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Lineage { version, nonce }
    }
}

impl std::fmt::Display for Lineage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "snapshot version {} (lineage {})",
            self.version,
            hex::encode(&self.nonce[..4])
        )
    }
}

/// Domain tag that starts the MAC preimage of a HEAD carrying `last_hash`, so
/// it can never collide with the 64-byte preimage of a v1 HEAD.
const MAC_V2_TAG: &[u8] = b"teagarden.journal-head.v2";

/// Domain tag that starts the MAC preimage of a HEAD carrying a lineage (v3),
/// so dropping the lineage (or reading a v3 HEAD as v2) fails the MAC.
const MAC_V3_TAG: &[u8] = b"teagarden.journal-head.v3";

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
    /// [`JournalHead::lineage`]; absent in a v1 or v2 HEAD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lineage: Option<LineageFile>,
    /// Hex BLAKE3-keyed MAC over the fields, keyed by the hierarchy integrity key.
    mac: String,
}

/// On-disk form of a [`Lineage`].
#[derive(Debug, Serialize, Deserialize)]
struct LineageFile {
    version: u64,
    /// Hex of the 16-byte nonce.
    nonce: String,
}

impl JournalHead {
    /// The HEAD of a chain that has just been compacted onto a freshly published
    /// (or restored) snapshot: no deltas yet (`seq` 0), the snapshot is both the
    /// base and the parent of the first delta. `blob_hash` is BLAKE3 of the
    /// snapshot blob; `lineage` is the stamp the local DB carries for it.
    pub fn at_snapshot(
        snapshot_msg_id: i64,
        version: u64,
        blob_hash: [u8; 32],
        lineage: Lineage,
    ) -> Self {
        JournalHead {
            seq: 0,
            parent_msg_id: snapshot_msg_id,
            base_snapshot_version: version,
            base_snapshot_msg_id: snapshot_msg_id,
            base_snapshot_hash: blob_hash,
            last_hash: Some(blob_hash),
            lineage: Some(lineage),
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
    /// fails the MAC. With a lineage (v3; `last_hash` required) it is
    /// `MAC_V3_TAG || the 64 bytes || last_hash || lineage version (LE) ||
    /// lineage nonce`.
    fn mac_preimage(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(MAC_V3_TAG.len() + 120);
        if self.lineage.is_some() {
            p.extend_from_slice(MAC_V3_TAG);
        } else if self.last_hash.is_some() {
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
        if let Some(l) = &self.lineage {
            p.extend_from_slice(&l.version.to_le_bytes());
            p.extend_from_slice(&l.nonce);
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
        let lineage = f
            .lineage
            .as_ref()
            .map(|l| {
                let mut nonce = [0u8; 16];
                hex::decode_to_slice(&l.nonce, &mut nonce).map(|()| Lineage {
                    version: l.version,
                    nonce,
                })
            })
            .transpose()
            .map_err(|e| CoreError::Serialization(format!("journal head lineage: {e}")))?;
        if lineage.is_some() && last_hash.is_none() {
            return Err(CoreError::Serialization(
                "journal head: a lineage without last_hash is not a valid v3 HEAD".into(),
            ));
        }
        let head = JournalHead {
            seq: f.seq,
            parent_msg_id: f.parent_msg_id,
            base_snapshot_version: f.base_snapshot_version,
            base_snapshot_msg_id: f.base_snapshot_msg_id,
            base_snapshot_hash,
            last_hash,
            lineage,
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
        if self.lineage.is_some() && self.last_hash.is_none() {
            return Err(CoreError::Volume(
                "journal head: a lineage requires last_hash (format v3)".into(),
            ));
        }
        let f = JournalHeadFile {
            seq: self.seq,
            parent_msg_id: self.parent_msg_id,
            base_snapshot_version: self.base_snapshot_version,
            base_snapshot_msg_id: self.base_snapshot_msg_id,
            base_snapshot_hash: hex::encode(self.base_snapshot_hash),
            last_hash: self.last_hash.map(hex::encode),
            lineage: self.lineage.map(|l| LineageFile {
                version: l.version,
                nonce: hex::encode(l.nonce),
            }),
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
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::from_bytes([0x9A; 32])
    }

    fn head(seq: u64) -> JournalHead {
        JournalHead {
            seq,
            parent_msg_id: 1000 + seq as i64,
            base_snapshot_version: 3,
            base_snapshot_msg_id: 50,
            base_snapshot_hash: [0xC3; 32],
            last_hash: Some([0xD4; 32]),
            lineage: Some(Lineage {
                version: 3,
                nonce: [0xE5; 16],
            }),
        }
    }

    /// A HEAD written by debb93b (no `last_hash`, 64-byte MAC preimage): the
    /// journal.head of crates/teagarden-store/tests/fixtures/v1-journal-debb93b,
    /// sha256 9e9f460b8186e09353265ee4dc25f0bd2ce1579738b35797358dbbba03083ca6,
    /// under the integrity key `[0x48; 32]`.
    const V1_HEAD_DEBB93B: &str = r#"{"seq":2,"parent_msg_id":101,"base_snapshot_version":5,"base_snapshot_msg_id":99,"base_snapshot_hash":"2b6b92ee2239c4b078453ff0042e4400aecb62b71d7ea97226c506ffb994045b","mac":"f60cf4d9420d517234261d9c41c552e854127b5fda87b1ec9983748615885323"}"#;

    #[test]
    fn head_written_by_debb93b_still_loads_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.head");
        std::fs::write(&path, V1_HEAD_DEBB93B).unwrap();
        let k = SymmetricKey::from_bytes([0x48; 32]);
        let h = JournalHead::load(&path, &k).unwrap().unwrap();
        assert_eq!((h.seq, h.parent_msg_id, h.last_hash), (2, 101, None));
        assert_eq!(
            h.chain_hash(),
            None,
            "v1 HEAD with deltas: hash must be fetched"
        );
        // Re-storing a v1 HEAD keeps it byte-identical (no field, same MAC).
        h.store_atomic(&path, &k).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), V1_HEAD_DEBB93B);
    }

    #[test]
    fn dropping_last_hash_from_a_v2_head_fails_the_mac() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        head(4).store_atomic(&path, &key()).unwrap();
        let mut f: JournalHeadFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(f.last_hash.is_some());
        f.last_hash = None;
        std::fs::write(&path, serde_json::to_vec(&f).unwrap()).unwrap();
        assert!(JournalHead::load(&path, &key()).is_err());
        // ...and so does changing it.
        head(4).store_atomic(&path, &key()).unwrap();
        let mut f: JournalHeadFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        f.last_hash = Some(hex::encode([0x00; 32]));
        std::fs::write(&path, serde_json::to_vec(&f).unwrap()).unwrap();
        assert!(JournalHead::load(&path, &key()).is_err());
    }

    #[test]
    fn chain_hash_of_a_snapshot_head_is_the_snapshot_hash() {
        let h = JournalHead::at_snapshot(7, 3, [0x31; 32], Lineage::new(3));
        assert_eq!(h.chain_hash(), Some([0x31; 32]));
        let legacy = JournalHead {
            last_hash: None,
            lineage: None,
            ..h
        };
        assert_eq!(legacy.chain_hash(), Some([0x31; 32]));
    }

    #[test]
    fn round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal_head.json");
        head(7).store_atomic(&path, &key()).unwrap();
        let loaded = JournalHead::load(&path, &key()).unwrap().unwrap();
        assert_eq!(loaded, head(7));
    }

    #[test]
    fn absent_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        assert!(JournalHead::load(&path, &key()).unwrap().is_none());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        head(2).store_atomic(&path, &key()).unwrap();
        let other = SymmetricKey::from_bytes([0x11; 32]);
        assert!(JournalHead::load(&path, &other).is_err());
    }

    #[test]
    fn tampered_seq_is_rejected() {
        // Editing the local file to lower the floor must fail the MAC — this is the
        // anti-rollback property (a transport attacker cannot lower the floor).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        head(9).store_atomic(&path, &key()).unwrap();

        let mut f: JournalHeadFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        f.seq = 1; // attacker tries to roll the floor back to 1
        std::fs::write(&path, serde_json::to_vec(&f).unwrap()).unwrap();

        assert!(JournalHead::load(&path, &key()).is_err());
    }

    #[test]
    fn overwrite_advances_floor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        head(1).store_atomic(&path, &key()).unwrap();
        head(2).store_atomic(&path, &key()).unwrap();
        assert_eq!(JournalHead::load(&path, &key()).unwrap().unwrap().seq, 2);
        // No leftover temp file: the directory holds only the HEAD itself.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("h.json")]);
    }

    /// Eight writers hammer `store_atomic` while reading back. With a fixed temp
    /// name they share one inode, so a torn HEAD can be renamed into place and the
    /// loser's rename fails; with a unique temp per call neither happens.
    #[test]
    fn concurrent_stores_never_tear_or_fail() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("journal_head.json"));
        head(0).store_atomic(&path, &key()).unwrap();

        let errors = Arc::new(AtomicUsize::new(0));
        let first_error = Arc::new(Mutex::new(None::<String>));
        let threads: Vec<_> = (0..8u64)
            .map(|t| {
                let (path, errors, first_error) =
                    (path.clone(), errors.clone(), first_error.clone());
                std::thread::spawn(move || {
                    for i in 0..200u64 {
                        let h = head(t * 1000 + i);
                        let r = h
                            .store_atomic(&path, &key())
                            .map_err(|e| e.to_string())
                            .and_then(|()| match JournalHead::load(&path, &key()) {
                                Ok(Some(_)) => Ok(()),
                                Ok(None) => Err("HEAD vanished".to_string()),
                                Err(e) => Err(format!("torn journal head: {e}")),
                            });
                        if let Err(e) = r {
                            errors.fetch_add(1, Ordering::Relaxed);
                            first_error.lock().unwrap().get_or_insert(e);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            errors.load(Ordering::Relaxed),
            0,
            "concurrent stores must never fail or tear; first error: {:?}",
            first_error.lock().unwrap()
        );
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("journal_head.json")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&*path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// A HEAD written by the round-9 build (format v2: `last_hash`, no
    /// lineage) loads as legacy (no lineage) and re-stores byte-identically,
    /// checked here under a test key.
    #[test]
    fn a_v2_head_has_no_lineage_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.head");
        let v2 = JournalHead {
            lineage: None,
            ..head(0)
        };
        v2.store_atomic(&path, &key()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("lineage"), "{text}");
        let loaded = JournalHead::load(&path, &key()).unwrap().unwrap();
        assert_eq!(loaded.lineage, None);
        loaded.store_atomic(&path, &key()).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }

    /// The lineage is MAC-covered (v3): dropping it, changing its version or
    /// its nonce fails the MAC; a lineage without `last_hash` is refused on
    /// store and on load.
    #[test]
    fn the_lineage_is_covered_by_the_mac() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        let edit = |f: &dyn Fn(&mut serde_json::Value)| {
            head(2).store_atomic(&path, &key()).unwrap();
            let mut j: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            f(&mut j);
            std::fs::write(&path, serde_json::to_vec(&j).unwrap()).unwrap();
            JournalHead::load(&path, &key())
        };
        assert_eq!(edit(&|_| {}).unwrap().unwrap(), head(2));
        assert!(edit(&|j| {
            j.as_object_mut().unwrap().remove("lineage");
        })
        .is_err());
        assert!(edit(&|j| j["lineage"]["version"] = 4.into()).is_err());
        assert!(edit(&|j| j["lineage"]["nonce"] = hex::encode([0u8; 16]).into()).is_err());
        assert!(edit(&|j| {
            j.as_object_mut().unwrap().remove("last_hash");
        })
        .is_err());
        let bad = JournalHead {
            last_hash: None,
            ..head(2)
        };
        assert!(bad.store_atomic(&path, &key()).is_err());
    }

    #[test]
    fn every_new_lineage_has_a_fresh_nonce() {
        let a = Lineage::new(5);
        let b = Lineage::new(5);
        assert_eq!((a.version, b.version), (5, 5));
        assert_ne!(a.nonce, b.nonce);
    }
}
