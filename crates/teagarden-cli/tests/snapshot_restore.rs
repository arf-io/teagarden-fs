//! End-to-end metadata-snapshot restore tests.
//!
//! These exercise the full transport round-trip that `teagarden volume restore`
//! performs: a snapshot is published to a mock Telegram transport, fetched back,
//! and applied with anti-rollback enforcement. The CLI command itself adds only
//! password prompting and a live Telegram connection on top of this seam.

use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::error::CoreError;
use teagarden_core::volume::metadata_snapshot;
use teagarden_telegram::client::BlockTransport;
use teagarden_telegram::mock::MockTransport;

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\x00";

/// A byte string that passes the SQLite magic-header gate in `restore_db_atomically`.
fn fake_db(tag: u8) -> Vec<u8> {
    let mut db = SQLITE_MAGIC.to_vec();
    db.extend_from_slice(&[tag; 128]);
    db
}

fn key() -> SymmetricKey {
    SymmetricKey::from_bytes([0x5A; 32])
}

#[tokio::test]
async fn snapshot_round_trips_through_transport_and_restores() {
    let transport = MockTransport::new();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("metadata.db");
    std::fs::write(&db_path, fake_db(0x00)).unwrap();

    // Publish snapshot version 2 to the channel.
    let new_db = fake_db(0x22);
    let blob = metadata_snapshot::encrypt_snapshot(&key(), 2, &new_db).unwrap();
    let msg_id = transport.sync_metadata(&blob).await.unwrap();

    // Fetch it back and restore (local floor 0 → accepts v2, raises floor, swaps).
    let fetched = transport.fetch_metadata(msg_id).await.unwrap();
    let persisted = std::cell::Cell::new(None);
    let version = metadata_snapshot::restore_with_floor(&key(), &fetched, &db_path, 0, None, |v| {
        persisted.set(Some(v));
        Ok(())
    })
    .unwrap();

    assert_eq!(version, 2);
    assert_eq!(persisted.get(), Some(2), "floor persisted before swap");
    assert_eq!(std::fs::read(&db_path).unwrap(), new_db);
}

#[tokio::test]
async fn stale_snapshot_from_transport_is_refused_and_db_untouched() {
    // The core security property, end to end: an attacker serving an OLD snapshot
    // (version 1) while the local floor is 2 is refused, and the on-disk DB is
    // never modified.
    let transport = MockTransport::new();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("metadata.db");
    let original = fake_db(0x11);
    std::fs::write(&db_path, &original).unwrap();

    let stale = fake_db(0x99);
    let blob = metadata_snapshot::encrypt_snapshot(&key(), 1, &stale).unwrap();
    let msg_id = transport.sync_metadata(&blob).await.unwrap();

    let fetched = transport.fetch_metadata(msg_id).await.unwrap();
    let persisted = std::cell::Cell::new(None);
    let err = metadata_snapshot::restore_with_floor(&key(), &fetched, &db_path, 2, None, |v| {
        persisted.set(Some(v));
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(err, CoreError::Snapshot(_)));
    assert_eq!(
        persisted.get(),
        None,
        "rejected snapshot must not raise the floor"
    );
    assert_eq!(std::fs::read(&db_path).unwrap(), original);
}

#[tokio::test]
async fn substituted_blob_from_transport_fails_auth_and_db_untouched() {
    // A transport-level attacker replaces the snapshot with a blob sealed under a
    // different key. AEAD authentication fails; the DB is never touched.
    let transport = MockTransport::new();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("metadata.db");
    let original = fake_db(0x11);
    std::fs::write(&db_path, &original).unwrap();

    let attacker_key = SymmetricKey::from_bytes([0xEE; 32]);
    let blob = metadata_snapshot::encrypt_snapshot(&attacker_key, 5, &fake_db(0x99)).unwrap();
    let msg_id = transport.sync_metadata(&blob).await.unwrap();

    let fetched = transport.fetch_metadata(msg_id).await.unwrap();
    let persisted = std::cell::Cell::new(None);
    let err = metadata_snapshot::restore_with_floor(&key(), &fetched, &db_path, 0, None, |v| {
        persisted.set(Some(v));
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(err, CoreError::Decryption(_)));
    assert_eq!(persisted.get(), None);
    assert_eq!(std::fs::read(&db_path).unwrap(), original);
}
