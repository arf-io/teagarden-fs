//! Rebuild the metadata DB from a base snapshot + an ordered metadata-delta chain.
//!
//! This is the read side of the v0.4.3 durability journal. On an unclean shutdown
//! (or a lost local DB), the volume is reconstructed deterministically:
//!
//! 1. decrypt the base metadata snapshot (`teagarden_core::volume::metadata_snapshot`),
//! 2. decrypt the delta chain and verify it is contiguous from seq 1, shares the
//!    snapshot's version as its base, and reaches at least the HMAC-covered HEAD
//!    `seq` (`teagarden_core::volume::metadata_journal::verify_chain_contiguous`) —
//!    fail-closed against a transport attacker who truncates the channel log,
//!    Then verify the chain is made of exactly the blobs the HEAD names: the
//!    newest delta's hash matches the HEAD's `last_hash`, and each v2 delta's
//!    `prev_hash` matches the blob before it (`verify_chain_links`) — fail-closed
//!    against a transport that answers a message id with a different authentic
//!    delta,
//! 3. apply each delta's SQLite changeset in order onto a temp copy of the
//!    snapshot DB,
//! 4. atomically install the result (reusing the audited v0.4.2 swap).
//!
//! Applying changesets needs rusqlite, so recovery lives here in the store crate
//! rather than core. It is a *full* deterministic rebuild (no incremental /
//! idempotent replay — that is the multi-device milestone), so it is always safe
//! to run: the result is exactly snapshot + deltas[1..=head.seq].

use std::path::{Path, PathBuf};

use rusqlite::session::ConflictAction;
use rusqlite::Connection;

use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::error::CoreError;
use teagarden_core::volume::journal_head::JournalHead;
use teagarden_core::volume::metadata_journal::{
    blob_hash, decrypt_delta, verify_chain_contiguous, verify_chain_links,
};
use teagarden_core::volume::metadata_snapshot::{
    decrypt_snapshot, ensure_sqlite_db, restore_db_atomically,
};

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Rebuild the metadata DB at `db_path` from `snapshot_blob` + `delta_blobs`
/// (the chain that reaches `head`, in ascending `seq` order) and atomically
/// install it. Returns the recovered HEAD `seq`.
///
/// On any verification failure (bad snapshot, wrong base, gapped/truncated chain)
/// the existing `db_path` is left untouched — the install is the last step.
pub fn rebuild_db_from_journal(
    data_key: &SymmetricKey,
    snapshot_blob: &[u8],
    delta_blobs: &[Vec<u8>],
    head: JournalHead,
    db_path: &Path,
) -> Result<u64, CoreError> {
    rebuild_db_from_journal_then(data_key, snapshot_blob, delta_blobs, head, db_path, || {
        Ok(())
    })
}

/// [`rebuild_db_from_journal`] with one more step, `before_install`, run once
/// the rebuilt DB is complete and verified and right before it is installed
/// at `db_path` (a mount uses it to keep the DB being replaced). An `Err` from
/// it stops the rebuild before the install.
pub fn rebuild_db_from_journal_then<B>(
    data_key: &SymmetricKey,
    snapshot_blob: &[u8],
    delta_blobs: &[Vec<u8>],
    head: JournalHead,
    db_path: &Path,
    before_install: B,
) -> Result<u64, CoreError>
where
    B: FnOnce() -> Result<(), CoreError>,
{
    // 1. Bind the base snapshot by IDENTITY, not just version: the HEAD authenticates
    //    the BLAKE3 of the exact ciphertext blob it was built against. This rejects a
    //    transport that serves a different snapshot sharing the same version id (the
    //    same-version base-substitution rollback). Checked before decryption.
    if blob_hash(snapshot_blob) != head.base_snapshot_hash {
        return Err(CoreError::Snapshot(
            "journal recovery: base snapshot hash does not match the HMAC-covered HEAD; \
             the transport served a different snapshot (rollback attempt refused)"
                .into(),
        ));
    }
    let (snap_version, db_bytes) = decrypt_snapshot(data_key, snapshot_blob)?;
    ensure_sqlite_db(&db_bytes)?;
    if snap_version != head.base_snapshot_version {
        return Err(CoreError::Snapshot(format!(
            "journal recovery: snapshot version {snap_version} does not match HEAD base {}",
            head.base_snapshot_version
        )));
    }

    // 2. Decrypt the deltas, collecting headers + changesets (ascending seq).
    let mut headers = Vec::with_capacity(delta_blobs.len());
    let mut changesets = Vec::with_capacity(delta_blobs.len());
    for blob in delta_blobs {
        let (hdr, cs) = decrypt_delta(data_key, blob)?;
        headers.push(hdr);
        changesets.push(cs);
    }

    // 3. Anti-truncation: the chain must be contiguous from seq 1, on this base,
    //    and reach the HMAC-covered HEAD floor.
    verify_chain_contiguous(&headers, 1, snap_version, head.seq)?;

    // 3b. Anti-substitution: only deltas up to the floor are applied, and they
    //     must be exactly the blobs the HEAD and each delta name.
    let applied = usize::try_from(head.seq)
        .map_err(|_| CoreError::Snapshot("journal seq overflow".into()))?;
    let hashes: Vec<[u8; 32]> = delta_blobs[..applied]
        .iter()
        .map(|b| blob_hash(b))
        .collect();
    verify_chain_links(
        &headers[..applied],
        &hashes,
        head.base_snapshot_hash,
        head.last_hash,
    )?;

    // 4. Build into a temp DB: write the snapshot, then apply each changeset.
    let tmp_path = sibling(db_path, ".journal-rebuild.tmp");
    std::fs::write(&tmp_path, &db_bytes)
        .map_err(|e| CoreError::Volume(format!("write rebuild tmp: {e}")))?;
    let rebuilt = (|| -> Result<Vec<u8>, CoreError> {
        let conn = Connection::open(&tmp_path)
            .map_err(|e| CoreError::Volume(format!("open rebuild tmp: {e}")))?;
        // DELETE journal mode so no -wal/-shm sidecar lingers next to the temp.
        let _ = conn.execute_batch("PRAGMA journal_mode=DELETE;");
        for (hdr, cs) in headers.iter().zip(changesets.iter()) {
            if hdr.seq > head.seq {
                break; // never apply past the authenticated floor
            }
            conn.apply_strm(
                &mut &cs[..],
                None::<fn(&str) -> bool>,
                |_conflict, _item| ConflictAction::SQLITE_CHANGESET_ABORT,
            )
            .map_err(|e| CoreError::JournalApply {
                seq: hdr.seq,
                detail: e.to_string(),
            })?;
        }
        drop(conn);
        std::fs::read(&tmp_path).map_err(|e| CoreError::Volume(format!("read rebuilt db: {e}")))
    })();
    // Always clean up the temp (and any stray sidecars) regardless of outcome.
    let _ = std::fs::remove_file(&tmp_path);
    for sfx in ["-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(sibling(&tmp_path, sfx));
    }
    let rebuilt = rebuilt?;
    before_install()?;

    // 5. Atomically install the rebuilt DB (validates magic, fsync+rename, strips
    //    stale sidecars at db_path).
    restore_db_atomically(db_path, &rebuilt)?;
    Ok(head.seq)
}

/// Recover a volume from `head` by walking the channel: fetch the base snapshot
/// (`head.base_snapshot_msg_id`), then walk the back-linked delta chain from
/// `head.parent_msg_id` collecting `head.seq` deltas, and rebuild the DB at
/// `db_path`. `fetch` returns the raw bytes of a channel message by id.
///
/// The walk is bounded by `head.seq` iterations and rejects a chain that ends
/// early (`parent` reaches 0), is out of order (fetched `seq` != expected), or is
/// otherwise inconsistent — and [`rebuild_db_from_journal`] re-verifies contiguity
/// against the HMAC-covered floor. A truncated channel (the transport attacker's
/// move) is therefore refused and `db_path` is left untouched.
pub fn recover_from_head<F>(
    data_key: &SymmetricKey,
    head: JournalHead,
    db_path: &Path,
    fetch: F,
) -> Result<u64, CoreError>
where
    F: FnMut(i64) -> Result<Vec<u8>, CoreError>,
{
    recover_from_head_then(data_key, head, db_path, fetch, || Ok(()))
}

/// [`recover_from_head`], running `before_install` right before the rebuilt
/// DB is installed (see [`rebuild_db_from_journal_then`]).
pub fn recover_from_head_then<F, B>(
    data_key: &SymmetricKey,
    head: JournalHead,
    db_path: &Path,
    mut fetch: F,
    before_install: B,
) -> Result<u64, CoreError>
where
    F: FnMut(i64) -> Result<Vec<u8>, CoreError>,
    B: FnOnce() -> Result<(), CoreError>,
{
    let snapshot_blob = fetch(head.base_snapshot_msg_id)?;

    // Walk newest → oldest, bounded by head.seq (parent pointers are
    // attacker-controlled bytes, so cap the loop and authenticate each hop).
    let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(head.seq as usize);
    let mut cursor = head.parent_msg_id;
    let mut expect_seq = head.seq;
    while expect_seq > 0 {
        if cursor == 0 {
            return Err(CoreError::Snapshot(
                "journal walk: parent chain ended before reaching the base snapshot".into(),
            ));
        }
        let blob = fetch(cursor)?;
        let (hdr, _) = decrypt_delta(data_key, &blob)?;
        if hdr.seq != expect_seq {
            return Err(CoreError::Snapshot(format!(
                "journal walk: expected delta seq {expect_seq}, fetched seq {}",
                hdr.seq
            )));
        }
        cursor = hdr.parent_msg_id;
        blobs.push(blob);
        expect_seq -= 1;
    }
    blobs.reverse(); // ascending seq order for rebuild

    rebuild_db_from_journal_then(
        data_key,
        &snapshot_blob,
        &blobs,
        head,
        db_path,
        before_install,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode_store::InodeStore;
    use crate::migrations::initialize_database;
    use crate::opaque_schema::OpaqueSchema;
    use crate::schema::logical_tables;
    use rusqlite::session::Session;
    use teagarden_core::metadata::inode::Inode;
    use teagarden_core::volume::metadata_journal::{encrypt_delta, DeltaHeader};
    use teagarden_core::volume::metadata_snapshot::encrypt_snapshot;

    const SCHEMA_KEY: [u8; 32] = [0x42; 32];
    const META_KEY: [u8; 32] = [0x43; 32];
    const DATA_KEY: [u8; 32] = [0x44; 32];

    fn data_key() -> SymmetricKey {
        SymmetricKey::from_bytes(DATA_KEY)
    }

    fn fresh_db() -> (Connection, OpaqueSchema) {
        let conn = Connection::open_in_memory().unwrap();
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes(SCHEMA_KEY), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        (conn, schema)
    }

    fn db_bytes(conn: &Connection) -> Vec<u8> {
        // Serialize the in-memory DB to bytes via the SQLite backup API path:
        // VACUUM INTO a temp file, then read it.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("dump.db");
        conn.execute("VACUUM INTO ?1", [p.to_str().unwrap()])
            .unwrap();
        std::fs::read(&p).unwrap()
    }

    /// Build a base snapshot at `version` containing the root inode, and two
    /// deltas inserting two files. Returns (snapshot_blob, [delta1, delta2], head).
    fn scenario() -> (Vec<u8>, Vec<Vec<u8>>, JournalHead) {
        let (conn, schema) = fresh_db();
        let mk = SymmetricKey::from_bytes(META_KEY);
        let store = InodeStore::new(&conn, &schema, &mk);
        store.insert(&Inode::root()).unwrap();

        let snapshot = encrypt_snapshot(&data_key(), 5, &db_bytes(&conn)).unwrap();

        // Delta 1: insert file ino=2.
        let mut s1 = Session::new(&conn).unwrap();
        s1.attach(None::<&str>).unwrap();
        store
            .insert(&Inode::new_file(2, 1, "a.txt".into(), 0o644, 1000, 1000))
            .unwrap();
        let mut cs1 = Vec::new();
        s1.changeset_strm(&mut cs1).unwrap();
        let d1 = encrypt_delta(
            &data_key(),
            DeltaHeader {
                seq: 1,
                base_snapshot_version: 5,
                parent_msg_id: 99, // points back to the base snapshot (id 99)
                prev_hash: Some(blob_hash(&snapshot)),
            },
            &cs1,
        )
        .unwrap();

        // Delta 2: insert file ino=3.
        let mut s2 = Session::new(&conn).unwrap();
        s2.attach(None::<&str>).unwrap();
        store
            .insert(&Inode::new_file(3, 1, "b.txt".into(), 0o644, 1000, 1000))
            .unwrap();
        let mut cs2 = Vec::new();
        s2.changeset_strm(&mut cs2).unwrap();
        let d2 = encrypt_delta(
            &data_key(),
            DeltaHeader {
                seq: 2,
                base_snapshot_version: 5,
                parent_msg_id: 100, // points back to delta 1 (id 100)
                prev_hash: Some(blob_hash(&d1)),
            },
            &cs2,
        )
        .unwrap();

        let head = JournalHead {
            seq: 2,
            parent_msg_id: 101,
            base_snapshot_version: 5,
            base_snapshot_msg_id: 99,
            base_snapshot_hash: *blake3::hash(&snapshot).as_bytes(),
            last_hash: Some(blob_hash(&d2)),
            lineage: None,
        };
        (snapshot, vec![d1, d2], head)
    }

    fn assert_db_has(db_path: &Path, inos: &[u64]) {
        let conn = Connection::open(db_path).unwrap();
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes(SCHEMA_KEY), &logical_tables());
        let mk = SymmetricKey::from_bytes(META_KEY);
        let store = InodeStore::new(&conn, &schema, &mk);
        for &ino in inos {
            assert!(
                store.get(ino).unwrap().is_some(),
                "ino {ino} must be present"
            );
        }
    }

    /// An authentic, correctly chained entry that was written against another
    /// database than its base snapshot (here: it inserts an inode the snapshot
    /// already has) fails as [`CoreError::JournalApply`], naming its seq, and
    /// leaves the DB file as it was.
    #[test]
    fn an_entry_written_against_another_database_is_a_journal_apply_error() {
        let (conn, schema) = fresh_db();
        let mk = SymmetricKey::from_bytes(META_KEY);
        let store = InodeStore::new(&conn, &schema, &mk);
        store.insert(&Inode::root()).unwrap();
        let mut s1 = Session::new(&conn).unwrap();
        s1.attach(None::<&str>).unwrap();
        store
            .insert(&Inode::new_file(2, 1, "a.txt".into(), 0o644, 1000, 1000))
            .unwrap();
        let mut cs1 = Vec::new();
        s1.changeset_strm(&mut cs1).unwrap();
        // The snapshot already holds ino 2: the entry's insert conflicts.
        let snapshot = encrypt_snapshot(&data_key(), 5, &db_bytes(&conn)).unwrap();
        let d1 = encrypt_delta(
            &data_key(),
            DeltaHeader {
                seq: 1,
                base_snapshot_version: 5,
                parent_msg_id: 99,
                prev_hash: Some(blob_hash(&snapshot)),
            },
            &cs1,
        )
        .unwrap();
        let head = JournalHead {
            seq: 1,
            parent_msg_id: 100,
            base_snapshot_version: 5,
            base_snapshot_msg_id: 99,
            base_snapshot_hash: *blake3::hash(&snapshot).as_bytes(),
            last_hash: Some(blob_hash(&d1)),
            lineage: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        std::fs::write(&db_path, b"previous").unwrap();
        let err = rebuild_db_from_journal(&data_key(), &snapshot, &[d1], head, &db_path)
            .expect_err("the entry must not apply");
        assert!(
            matches!(&err, CoreError::JournalApply { seq: 1, .. }),
            "{err:?}"
        );
        assert_eq!(std::fs::read(&db_path).unwrap(), b"previous");
    }

    #[test]
    fn rebuild_applies_full_chain() {
        let (snap, deltas, head) = scenario();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");

        let recovered =
            rebuild_db_from_journal(&data_key(), &snap, &deltas, head, &db_path).unwrap();
        assert_eq!(recovered, 2);
        // Root from snapshot + both files from the deltas.
        assert_db_has(&db_path, &[1, 2, 3]);
    }

    /// The journal debb93b wrote: base snapshot (msg 99), two `metadata-delta-v1`
    /// deltas (msgs 100, 101), and its 64-byte-MAC journal.head at seq 2 (integrity
    /// key `[0x48; 32]`). sha256: snapshot 4f3eec91947bc8a40ad0bb738af4db3d59fe34061171f697d07babbfc125c24a,
    /// delta 100 632c48a1de37647719069a8694e53a071879c92a4e4fcaa75d31ceac37518325,
    /// delta 101 8e683cf8a95153819187a4d4ee3ef4489695beab3d95c72140baa0e1597abd35,
    /// head 9e9f460b8186e09353265ee4dc25f0bd2ce1579738b35797358dbbba03083ca6.
    fn v1_fixture() -> (std::collections::HashMap<i64, Vec<u8>>, JournalHead) {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1-journal-debb93b");
        let mut ch = std::collections::HashMap::new();
        ch.insert(99, std::fs::read(dir.join("msg-99-snapshot.bin")).unwrap());
        ch.insert(100, std::fs::read(dir.join("msg-100-delta.bin")).unwrap());
        ch.insert(101, std::fs::read(dir.join("msg-101-delta.bin")).unwrap());
        let head = JournalHead::load(
            &dir.join("journal.head"),
            &SymmetricKey::from_bytes([0x48; 32]),
        )
        .unwrap()
        .unwrap();
        (ch, head)
    }

    #[test]
    fn journal_written_by_debb93b_still_recovers() {
        let (ch, head) = v1_fixture();
        assert_eq!((head.seq, head.last_hash), (2, None));
        for id in [100, 101] {
            let (h, _) = decrypt_delta(&data_key(), &ch[&id]).unwrap();
            assert_eq!(h.prev_hash, None, "fixture delta {id} is v1");
        }
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let seq = recover_from_head(&data_key(), head, &db_path, |id| {
            ch.get(&id)
                .cloned()
                .ok_or_else(|| CoreError::Snapshot(format!("missing channel msg {id}")))
        })
        .unwrap();
        assert_eq!(seq, 2);
        assert_db_has(&db_path, &[1, 2, 3]);
    }

    #[test]
    fn v1_head_upgraded_with_the_hash_of_its_last_delta_pins_it() {
        // What mount does after recovering a v1 journal: record the hash of the
        // delta it rebuilt from, so a later substitution of that delta is refused.
        let (mut ch, mut head) = v1_fixture();
        head.last_hash = Some(blob_hash(&ch[&101]));
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let fetch = |ch: &std::collections::HashMap<i64, Vec<u8>>, id: i64| {
            ch.get(&id)
                .cloned()
                .ok_or_else(|| CoreError::Snapshot(format!("missing channel msg {id}")))
        };
        recover_from_head(&data_key(), head, &db_path, |id| fetch(&ch, id)).unwrap();
        // Another authentic v1 seq-2 delta answered for 101.
        let other = ch[&101].clone();
        let (h, cs) = decrypt_delta(&data_key(), &other).unwrap();
        let mut pt = vec![];
        pt.extend_from_slice(&h.seq.to_le_bytes());
        pt.extend_from_slice(&h.base_snapshot_version.to_le_bytes());
        pt.extend_from_slice(&h.parent_msg_id.to_le_bytes());
        pt.extend_from_slice(&cs);
        let resealed =
            teagarden_core::crypto::aead::encrypt(&data_key(), &pt, b"metadata-delta-v1").unwrap();
        ch.insert(101, resealed);
        let err = recover_from_head(&data_key(), head, &db_path, |id| fetch(&ch, id)).unwrap_err();
        assert!(err.to_string().contains("hash"), "{err}");
    }

    #[test]
    fn substituted_delta_is_refused_and_db_untouched() {
        // Delta 1 answered with a re-encryption of the same plaintext: same header,
        // same changeset, different bytes. Delta 2 binds delta 1's exact blob.
        let (snap, deltas, head) = scenario();
        let (h1, cs1) = decrypt_delta(&data_key(), &deltas[0]).unwrap();
        let other = encrypt_delta(&data_key(), h1, &cs1).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        std::fs::write(&db_path, b"SENTINEL").unwrap();
        let err = rebuild_db_from_journal(
            &data_key(),
            &snap,
            &[other, deltas[1].clone()],
            head,
            &db_path,
        )
        .unwrap_err();
        assert!(err.to_string().contains("hash"), "{err}");
        assert_eq!(std::fs::read(&db_path).unwrap(), b"SENTINEL");
        // The newest delta replaced: caught by the HEAD's hash.
        let (h2, cs2) = decrypt_delta(&data_key(), &deltas[1]).unwrap();
        let other2 = encrypt_delta(&data_key(), h2, &cs2).unwrap();
        let err = rebuild_db_from_journal(
            &data_key(),
            &snap,
            &[deltas[0].clone(), other2],
            head,
            &db_path,
        )
        .unwrap_err();
        assert!(err.to_string().contains("hash"), "{err}");
        assert_eq!(std::fs::read(&db_path).unwrap(), b"SENTINEL");
    }

    #[test]
    fn truncated_chain_is_refused_and_db_untouched() {
        // HEAD requires seq 2, but only delta 1 is served (attacker truncation).
        let (snap, deltas, head) = scenario();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        std::fs::write(&db_path, b"SENTINEL").unwrap();

        let only_first = vec![deltas[0].clone()];
        let err =
            rebuild_db_from_journal(&data_key(), &snap, &only_first, head, &db_path).unwrap_err();
        assert!(matches!(err, CoreError::Snapshot(_)));
        assert_eq!(std::fs::read(&db_path).unwrap(), b"SENTINEL");
    }

    #[test]
    fn base_snapshot_substitution_is_refused() {
        // The transport serves a DIFFERENT snapshot that shares the same version (5)
        // as the one the HEAD was built against. Version equality passes, but the
        // HMAC-covered base_snapshot_hash does not — recovery refuses it.
        let (_snap, deltas, head) = scenario();

        let (conn, schema) = fresh_db();
        let mk = SymmetricKey::from_bytes(META_KEY);
        let store = InodeStore::new(&conn, &schema, &mk);
        store.insert(&Inode::root()).unwrap();
        store
            .insert(&Inode::new_file(99, 1, "evil.txt".into(), 0o600, 0, 0))
            .unwrap();
        let snap2 = encrypt_snapshot(&data_key(), 5, &db_bytes(&conn)).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        std::fs::write(&db_path, b"SENTINEL").unwrap();

        let err =
            rebuild_db_from_journal(&data_key(), &snap2, &deltas, head, &db_path).unwrap_err();
        assert!(matches!(err, CoreError::Snapshot(_)));
        assert_eq!(std::fs::read(&db_path).unwrap(), b"SENTINEL");
    }

    #[test]
    fn wrong_base_version_is_refused() {
        let (snap, deltas, mut head) = scenario();
        head.base_snapshot_version = 9; // snapshot is version 5
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let err = rebuild_db_from_journal(&data_key(), &snap, &deltas, head, &db_path).unwrap_err();
        assert!(matches!(err, CoreError::Snapshot(_)));
    }

    /// Build a HashMap "channel" from a scenario: snapshot at 99, deltas at 100/101.
    fn channel(snap: Vec<u8>, deltas: &[Vec<u8>]) -> std::collections::HashMap<i64, Vec<u8>> {
        let mut c = std::collections::HashMap::new();
        c.insert(99, snap);
        c.insert(100, deltas[0].clone());
        c.insert(101, deltas[1].clone());
        c
    }

    #[test]
    fn recover_from_head_walks_chain_and_rebuilds() {
        // The crash-sim: a journaled volume's local DB is gone; recovery walks the
        // channel from HEAD (base snapshot + back-linked deltas) and rebuilds it.
        let (snap, deltas, head) = scenario();
        let ch = channel(snap, &deltas);
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");

        let recovered = recover_from_head(&data_key(), head, &db_path, |id| {
            ch.get(&id)
                .cloned()
                .ok_or_else(|| CoreError::Snapshot(format!("missing channel msg {id}")))
        })
        .unwrap();
        assert_eq!(recovered, 2);
        assert_db_has(&db_path, &[1, 2, 3]); // root + both journaled files
    }

    #[test]
    fn recover_from_head_refuses_truncated_channel() {
        // The transport attacker drops the latest delta (id 101). HEAD still requires
        // seq 2, so the walk cannot complete — recovery refuses, DB left untouched.
        let (snap, deltas, head) = scenario();
        let mut ch = channel(snap, &deltas);
        ch.remove(&101);
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        std::fs::write(&db_path, b"SENTINEL").unwrap();

        let err = recover_from_head(&data_key(), head, &db_path, |id| {
            ch.get(&id)
                .cloned()
                .ok_or_else(|| CoreError::Snapshot(format!("missing channel msg {id}")))
        })
        .unwrap_err();
        assert!(matches!(err, CoreError::Snapshot(_)));
        assert_eq!(std::fs::read(&db_path).unwrap(), b"SENTINEL");
    }

    #[test]
    fn empty_chain_at_seq_zero_restores_just_the_snapshot() {
        // Clean state: HEAD seq 0, no deltas — recovery installs the snapshot alone.
        let (snap, _deltas, _head) = scenario();
        let head = JournalHead {
            seq: 0,
            parent_msg_id: 100,
            base_snapshot_version: 5,
            base_snapshot_msg_id: 99,
            base_snapshot_hash: *blake3::hash(&snap).as_bytes(),
            last_hash: None,
            lineage: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let recovered = rebuild_db_from_journal(&data_key(), &snap, &[], head, &db_path).unwrap();
        assert_eq!(recovered, 0);
        assert_db_has(&db_path, &[1]); // only the root from the snapshot
    }

    // ---- Across the schema-version-1 migration (legacy table dropped) ----
    //
    // Base snapshots are whole DB files, so a snapshot uploaded by a build from
    // before the migration still contains the legacy table and `user_version` 0.
    // Rebuild/restore install those bytes as they are; the migration then runs on
    // the next `initialize_database`, which every open path calls.

    use crate::migrations::tests::{FIXTURE_LEGACY_TABLE, PRE_MIGRATION_DB};
    use crate::migrations::SCHEMA_VERSION;
    use teagarden_core::volume::metadata_snapshot::restore_with_floor;

    /// `PRE_MIGRATION_DB` encrypted as a version-7 metadata snapshot under
    /// `DATA_KEY`, by the code at 9a3a97a.
    /// sha256 c32482b3369a762c983bc06b0a815cf44690e3bdbb2cc152c66e761c17bdd350.
    const PRE_MIGRATION_SNAPSHOT: &[u8] =
        include_bytes!("../tests/fixtures/pre_migration_snapshot.bin");

    fn schema() -> OpaqueSchema {
        OpaqueSchema::new(SymmetricKey::from_bytes(SCHEMA_KEY), &logical_tables())
    }

    fn has_table(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            == 1
    }

    fn user_version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    }

    /// Open `db_path` the way every production path does, and check that it is
    /// migrated and holds `inos`.
    fn open_migrated_and_check(db_path: &Path, inos: &[u64]) {
        let conn = Connection::open(db_path).unwrap();
        initialize_database(&conn, &schema()).unwrap();
        assert_eq!(user_version(&conn), SCHEMA_VERSION);
        assert!(!has_table(&conn, FIXTURE_LEGACY_TABLE));
        drop(conn);
        assert_db_has(db_path, inos);
    }

    fn capture<F: FnOnce(&Connection)>(conn: &Connection, f: F) -> Vec<u8> {
        let mut s = Session::new(conn).unwrap();
        s.attach(None::<&str>).unwrap();
        f(conn);
        let mut cs = Vec::new();
        s.changeset_strm(&mut cs).unwrap();
        assert!(!cs.is_empty());
        cs
    }

    #[test]
    fn fixture_snapshot_is_the_pre_migration_db() {
        let (v, db) = decrypt_snapshot(&data_key(), PRE_MIGRATION_SNAPSHOT).unwrap();
        assert_eq!(v, 7);
        assert_eq!(db, PRE_MIGRATION_DB);
    }

    #[test]
    fn pre_migration_snapshot_restore_then_open_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let v = restore_with_floor(
            &data_key(),
            PRE_MIGRATION_SNAPSHOT,
            &db_path,
            0,
            None,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(v, 7);
        {
            // Restore installs the old bytes verbatim.
            let c = Connection::open(&db_path).unwrap();
            assert_eq!(user_version(&c), 0);
            assert!(has_table(&c, FIXTURE_LEGACY_TABLE));
        }
        open_migrated_and_check(&db_path, &[1, 2]);
    }

    #[test]
    fn pre_migration_base_snapshot_plus_new_build_deltas_rebuilds_and_migrates() {
        // The upgrade path: the chain's base snapshot was uploaded by an older
        // build; the new build migrated its live DB and kept journaling on that
        // base. Recovery must still reproduce every write.
        let dir = tempfile::tempdir().unwrap();
        let live_path = dir.path().join("live.db");
        std::fs::write(&live_path, PRE_MIGRATION_DB).unwrap();
        let live = Connection::open(&live_path).unwrap();
        let sch = schema();
        initialize_database(&live, &sch).unwrap();
        assert!(!has_table(&live, FIXTURE_LEGACY_TABLE));
        let mk = SymmetricKey::from_bytes(META_KEY);
        let cs = capture(&live, |c| {
            InodeStore::new(c, &sch, &mk)
                .insert(&Inode::new_file(
                    3,
                    1,
                    "after-upgrade.txt".into(),
                    0o644,
                    1000,
                    1000,
                ))
                .unwrap();
        });
        let d1 = encrypt_delta(
            &data_key(),
            DeltaHeader {
                seq: 1,
                base_snapshot_version: 7,
                parent_msg_id: 99,
                prev_hash: Some(blob_hash(PRE_MIGRATION_SNAPSHOT)),
            },
            &cs,
        )
        .unwrap();
        let head = JournalHead {
            seq: 1,
            parent_msg_id: 100,
            base_snapshot_version: 7,
            base_snapshot_msg_id: 99,
            base_snapshot_hash: *blake3::hash(PRE_MIGRATION_SNAPSHOT).as_bytes(),
            last_hash: Some(blob_hash(&d1)),
            lineage: None,
        };

        let db_path = dir.path().join("metadata.db");
        let mut ch = std::collections::HashMap::new();
        ch.insert(99_i64, PRE_MIGRATION_SNAPSHOT.to_vec());
        ch.insert(100_i64, d1);
        let seq = recover_from_head(&data_key(), head, &db_path, |id| {
            ch.get(&id)
                .cloned()
                .ok_or_else(|| CoreError::Snapshot(format!("missing channel msg {id}")))
        })
        .unwrap();
        assert_eq!(seq, 1);
        open_migrated_and_check(&db_path, &[1, 2, 3]);
    }

    #[test]
    fn old_build_delta_touching_the_legacy_table_replays_onto_a_migrated_base() {
        // A journal entry written by an older build may in principle carry a row
        // change for the legacy table (no released build wrote one). Replayed
        // onto a base snapshot that no longer has the table, that change must be
        // skipped and the rest of the delta must still apply.
        let dir = tempfile::tempdir().unwrap();
        let sch = schema();
        let mk = SymmetricKey::from_bytes(META_KEY);

        // Base snapshot from the new build (migrated).
        let base_path = dir.path().join("base.db");
        std::fs::write(&base_path, PRE_MIGRATION_DB).unwrap();
        let base = Connection::open(&base_path).unwrap();
        initialize_database(&base, &sch).unwrap();
        let snap = encrypt_snapshot(&data_key(), 8, &db_bytes(&base)).unwrap();
        drop(base);

        // Delta from an old build, on an un-migrated DB.
        let old_path = dir.path().join("old.db");
        std::fs::write(&old_path, PRE_MIGRATION_DB).unwrap();
        let old = Connection::open(&old_path).unwrap();
        let cs = capture(&old, |c| {
            // Its column names are opaque; delete its one row by rowid.
            let n = c
                .execute(
                    &format!(
                        "DELETE FROM {FIXTURE_LEGACY_TABLE} WHERE rowid = \
                         (SELECT MIN(rowid) FROM {FIXTURE_LEGACY_TABLE})"
                    ),
                    [],
                )
                .unwrap();
            assert_eq!(n, 1);
            InodeStore::new(c, &sch, &mk)
                .insert(&Inode::new_file(
                    4,
                    1,
                    "old-build.txt".into(),
                    0o644,
                    1000,
                    1000,
                ))
                .unwrap();
        });
        // The changeset really does name the legacy table.
        let legacy = FIXTURE_LEGACY_TABLE.as_bytes();
        assert!(cs.windows(legacy.len()).any(|w| w == legacy));
        let d1 = encrypt_delta(
            &data_key(),
            DeltaHeader {
                seq: 1,
                base_snapshot_version: 8,
                parent_msg_id: 99,
                prev_hash: Some(blob_hash(&snap)),
            },
            &cs,
        )
        .unwrap();
        let head = JournalHead {
            seq: 1,
            parent_msg_id: 100,
            base_snapshot_version: 8,
            base_snapshot_msg_id: 99,
            base_snapshot_hash: *blake3::hash(&snap).as_bytes(),
            last_hash: Some(blob_hash(&d1)),
            lineage: None,
        };

        let db_path = dir.path().join("metadata.db");
        let seq = rebuild_db_from_journal(&data_key(), &snap, &[d1], head, &db_path).unwrap();
        assert_eq!(seq, 1);
        open_migrated_and_check(&db_path, &[1, 2, 4]);
    }
}
