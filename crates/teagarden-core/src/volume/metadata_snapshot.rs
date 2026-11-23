//! Metadata-snapshot codec with anti-rollback version binding.
//!
//! On unmount, TeaGarden uploads an encrypted copy of the SQLite metadata DB to
//! the Telegram channel for disaster recovery. To stop a transport-level
//! attacker from rolling the volume back by serving an *older* snapshot, each
//! snapshot embeds a monotonic `version`. The version is part of the AEAD
//! plaintext, so the authentication tag covers it — a tampered version is
//! rejected. On restore, the caller refuses any snapshot whose embedded version
//! is older than the version recorded (HMAC-protected) in the local volume
//! config.
//!
//! The format is versioned by the AAD tag (`metadata-snapshot-v2`) so it cannot
//! be confused with the previous write-only `metadata-snapshot-v1` blobs (which
//! had no embedded version and were never restorable).

use std::path::{Path, PathBuf};

use crate::crypto::aead;
use crate::crypto::keys::SymmetricKey;
use crate::error::CoreError;

/// AEAD AAD tag for the versioned metadata-snapshot format.
const SNAPSHOT_AAD: &[u8] = b"metadata-snapshot-v2";
const VERSION_LEN: usize = 8;

/// SQLite database file magic header (`"SQLite format 3\0"`).
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\x00";

/// Encrypt a metadata snapshot, binding the monotonic `version` to the DB bytes.
///
/// Layout (plaintext, before AEAD): `version_le(8) || db_bytes`.
pub fn encrypt_snapshot(
    data_key: &SymmetricKey,
    version: u64,
    db_bytes: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut plaintext = Vec::with_capacity(VERSION_LEN + db_bytes.len());
    plaintext.extend_from_slice(&version.to_le_bytes());
    plaintext.extend_from_slice(db_bytes);
    aead::encrypt(data_key, &plaintext, SNAPSHOT_AAD)
        .map_err(|e| CoreError::Encryption(format!("metadata snapshot: {e}")))
}

/// Decrypt a metadata snapshot, returning `(version, db_bytes)`.
///
/// The AEAD tag authenticates both the version and the DB, so a tampered version
/// or DB is rejected before any bytes are returned.
pub fn decrypt_snapshot(data_key: &SymmetricKey, blob: &[u8]) -> Result<(u64, Vec<u8>), CoreError> {
    let plaintext = aead::decrypt(data_key, blob, SNAPSHOT_AAD)
        .map_err(|e| CoreError::Decryption(format!("metadata snapshot: {e}")))?;
    if plaintext.len() < VERSION_LEN {
        return Err(CoreError::Snapshot(
            "metadata snapshot too short to contain a version header".into(),
        ));
    }
    let version = u64::from_le_bytes(plaintext[..VERSION_LEN].try_into().unwrap());
    Ok((version, plaintext[VERSION_LEN..].to_vec()))
}

/// Anti-rollback check: a restored snapshot's `snapshot_version` must be at least
/// the `local_version` recorded (HMAC-protected) in the volume config. A strictly
/// older snapshot is a rollback attempt and is rejected.
pub fn check_not_rolled_back(snapshot_version: u64, local_version: u64) -> Result<(), CoreError> {
    if snapshot_version < local_version {
        return Err(CoreError::Snapshot(format!(
            "rollback detected: snapshot metadata version {snapshot_version} is older than \
             the locally-known version {local_version}; refusing to restore a stale snapshot"
        )));
    }
    Ok(())
}

/// Append a sidecar suffix to a DB path (e.g. `metadata.db` + `-wal` →
/// `metadata.db-wal`). SQLite names sidecars by appending to the full filename,
/// so this is a byte-append on the path, not an extension replacement.
fn sidecar_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Defense-in-depth: confirm a decrypted snapshot payload looks like a SQLite
/// database before it is allowed to overwrite the metadata DB. Lets a caller
/// reject a non-DB payload *before* taking any irreversible step (e.g. raising
/// the HMAC-covered anti-rollback floor).
pub fn ensure_sqlite_db(db_bytes: &[u8]) -> Result<(), CoreError> {
    if db_bytes.len() < SQLITE_MAGIC.len() || &db_bytes[..SQLITE_MAGIC.len()] != SQLITE_MAGIC {
        return Err(CoreError::Snapshot(
            "restored snapshot is not a valid SQLite database (bad magic header); \
             refusing to overwrite the metadata DB"
                .into(),
        ));
    }
    Ok(())
}

/// Atomically replace the SQLite metadata DB at `db_path` with `db_bytes`.
///
/// The bytes must already be decrypted and version-checked. Validates the SQLite
/// magic header (defense-in-depth against swapping in a non-DB blob), removes the
/// stale SQLite sidecars (`-wal`, `-shm`, `-journal`) and fsyncs the directory,
/// then writes a sibling temp file with fsync and renames it over `db_path`
/// (atomic on the same filesystem). The sidecars go first: a crash between the
/// two steps then leaves the old DB without its sidecars (callers rebuild in
/// that window, see `rebuild_marker`), never the restored DB beside an old
/// `-wal` that SQLite would replay into it.
///
/// The caller MUST ensure the volume is not currently open (mounted / served) —
/// swapping the file under a live SQLite handle corrupts the database. The caller
/// is also responsible for raising the anti-rollback floor BEFORE calling this so
/// a crash mid-swap can only leave the floor *ahead* of the DB (fail-closed),
/// never behind it.
pub fn restore_db_atomically(db_path: &Path, db_bytes: &[u8]) -> Result<(), CoreError> {
    ensure_sqlite_db(db_bytes)?;

    // Remove stale sidecars first, durably; a leftover -wal/-journal would be
    // replayed over the restored DB and corrupt it. A missing sidecar is the
    // normal case.
    remove_sidecars(db_path)?;
    fsync_parent(db_path)?;

    // A uniquely named sibling temp file (0600, fsynced) renamed over the DB, so
    // the swap is atomic and concurrent restores cannot tear each other's file.
    crate::fsutil::write_file_atomic(db_path, db_bytes, "restored metadata db")?;

    // fsync the directory so the rename is durable across a crash.
    fsync_parent(db_path)?;
    Ok(())
}

/// Remove the SQLite sidecars (`-wal`, `-shm`, `-journal`) of `db_path`. A
/// missing sidecar is not an error.
fn remove_sidecars(db_path: &Path) -> Result<(), CoreError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let side = sidecar_path(db_path, suffix);
        match std::fs::remove_file(&side) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(CoreError::Volume(format!(
                    "remove stale sidecar {}: {e}",
                    side.display()
                )))
            }
        }
    }
    Ok(())
}

fn fsync_parent(db_path: &Path) -> Result<(), CoreError> {
    if let Some(parent) = db_path.parent() {
        let dir = std::fs::File::open(parent)
            .map_err(|e| CoreError::Volume(format!("open {}: {e}", parent.display())))?;
        dir.sync_all()
            .map_err(|e| CoreError::Volume(format!("fsync {}: {e}", parent.display())))?;
    }
    Ok(())
}

/// Decrypt a fetched snapshot blob, reject a rollback against `local_version`,
/// raise the anti-rollback floor (via `persist_floor`) BEFORE the destructive
/// swap, then atomically swap the DB into `db_path`. Returns the restored version.
///
/// `recorded_hash` is the HMAC-covered BLAKE3 of the snapshot the config records
/// at `local_version` (`None` for a config written before that was recorded). A
/// blob AT the floor version must be exactly that snapshot: an older state can
/// carry the same version when a publish was stored by Telegram but never
/// acknowledged, and version equality alone would let it be installed.
///
/// This is the single source of truth for the restore sequence — both the
/// `volume restore` command and auto-reconcile-on-mount go through it, so the
/// security-critical ordering is exercised by the same path tests cover.
///
/// Ordering and failure semantics:
/// 1. decrypt (authenticates the blob + version) — failure leaves the DB untouched.
/// 2. version gate (`check_not_rolled_back`) — an older snapshot leaves it untouched;
///    at the floor version, the blob's hash must equal `recorded_hash` if known.
/// 3. SQLite magic check — a non-DB payload leaves it untouched AND does not raise
///    the floor (so a corrupt-but-authentic snapshot can't bump the floor for free).
/// 4. `persist_floor(snapshot_version)` — called only when the snapshot is strictly
///    newer than `local_version`. If it returns `Err`, the swap does NOT happen and
///    the DB is left untouched.
/// 5. atomic swap.
///
/// Persisting the floor *before* the swap is the fail-closed choice: a crash
/// between step 4 and step 5 leaves the floor *ahead* of the DB (future restores
/// merely require a snapshot `>=` it — recoverable by re-running restore), never
/// *behind* it (which would reopen a multi-version rollback window).
pub fn restore_with_floor<F>(
    data_key: &SymmetricKey,
    blob: &[u8],
    db_path: &Path,
    local_version: u64,
    recorded_hash: Option<[u8; 32]>,
    persist_floor: F,
) -> Result<u64, CoreError>
where
    F: FnOnce(u64) -> Result<(), CoreError>,
{
    restore_with_floor_then(
        data_key,
        blob,
        db_path,
        local_version,
        recorded_hash,
        persist_floor,
        |_| Ok(()),
    )
}

/// [`restore_with_floor`] with one more step, `before_swap(snapshot_version)`,
/// run after the floor is persisted and before the DB is swapped in, whether or
/// not the floor moved. An `Err` from it stops the restore before the swap.
/// `volume restore` uses it to remove the local DB and reset the journal HEAD
/// onto the snapshot being installed (see [`remove_db_files`]).
pub fn restore_with_floor_then<F, G>(
    data_key: &SymmetricKey,
    blob: &[u8],
    db_path: &Path,
    local_version: u64,
    recorded_hash: Option<[u8; 32]>,
    persist_floor: F,
    before_swap: G,
) -> Result<u64, CoreError>
where
    F: FnOnce(u64) -> Result<(), CoreError>,
    G: FnOnce(u64) -> Result<(), CoreError>,
{
    restore_prepared_with_floor_then(
        data_key,
        blob,
        db_path,
        local_version,
        recorded_hash,
        |_, bytes| Ok(bytes),
        persist_floor,
        before_swap,
    )
}

/// [`restore_with_floor_then`] installing `prepare(snapshot_version,
/// db_bytes)` instead of the snapshot's bytes as they are. `prepare` runs
/// after the snapshot is checked and before anything is persisted or
/// removed (an `Err` changes nothing); its output must be a SQLite database
/// too. `volume restore` uses it to install the DB already stamped with the
/// lineage and journal position its new HEAD records.
#[allow(clippy::too_many_arguments)]
pub fn restore_prepared_with_floor_then<P, F, G>(
    data_key: &SymmetricKey,
    blob: &[u8],
    db_path: &Path,
    local_version: u64,
    recorded_hash: Option<[u8; 32]>,
    prepare: P,
    persist_floor: F,
    before_swap: G,
) -> Result<u64, CoreError>
where
    P: FnOnce(u64, Vec<u8>) -> Result<Vec<u8>, CoreError>,
    F: FnOnce(u64) -> Result<(), CoreError>,
    G: FnOnce(u64) -> Result<(), CoreError>,
{
    let (snapshot_version, db_bytes) = decrypt_snapshot(data_key, blob)?;
    check_not_rolled_back(snapshot_version, local_version)?;
    if snapshot_version == local_version {
        if let Some(want) = recorded_hash {
            if *blake3::hash(blob).as_bytes() != want {
                return Err(CoreError::Snapshot(format!(
                    "snapshot version {snapshot_version} was served, but it is not the                      snapshot this volume recorded for that version (its hash differs);                      refusing to restore a different state under the same version"
                )));
            }
        }
    }
    ensure_sqlite_db(&db_bytes)?;
    let db_bytes = prepare(snapshot_version, db_bytes)?;
    ensure_sqlite_db(&db_bytes)?;
    if snapshot_version > local_version {
        persist_floor(snapshot_version)?;
    }
    before_swap(snapshot_version)?;
    restore_db_atomically(db_path, &db_bytes)?;
    Ok(snapshot_version)
}

/// Remove the metadata DB at `db_path` and its SQLite sidecars, then fsync the
/// directory. A missing file is not an error. The sidecars (`-wal`, `-shm`,
/// `-journal`) are removed and the directory fsynced BEFORE the main DB: a crash
/// part way then leaves the main DB without sidecars, never a stale `-wal` with
/// no DB, which SQLite would replay into the next DB created at that path.
/// After this the DB is *absent*, which a mount treats as "rebuild it from the
/// channel" (journal recovery from the HEAD, or the snapshot volume.json names).
pub fn remove_db_files(db_path: &Path) -> Result<(), CoreError> {
    remove_sidecars(db_path)?;
    fsync_parent(db_path)?;
    match std::fs::remove_file(db_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(CoreError::Volume(format!(
                "remove {}: {e}",
                db_path.display()
            )))
        }
    }
    fsync_parent(db_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::from_bytes([0x7E; 32])
    }

    #[test]
    fn snapshot_round_trips_version_and_db() {
        let db = b"sqlite db bytes \x00\x01\x02".to_vec();
        let blob = encrypt_snapshot(&key(), 42, &db).unwrap();
        let (version, got) = decrypt_snapshot(&key(), &blob).unwrap();
        assert_eq!(version, 42);
        assert_eq!(got, db);
    }

    #[test]
    fn empty_db_round_trips() {
        let blob = encrypt_snapshot(&key(), 0, &[]).unwrap();
        let (version, got) = decrypt_snapshot(&key(), &blob).unwrap();
        assert_eq!(version, 0);
        assert!(got.is_empty());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let blob = encrypt_snapshot(&key(), 1, b"x").unwrap();
        let other = SymmetricKey::from_bytes([0x11; 32]);
        assert!(decrypt_snapshot(&other, &blob).is_err());
    }

    #[test]
    fn tampered_blob_is_rejected() {
        let mut blob = encrypt_snapshot(&key(), 5, b"hello").unwrap();
        let n = blob.len();
        blob[n - 1] ^= 0xFF; // flip a tag byte
        assert!(decrypt_snapshot(&key(), &blob).is_err());
    }

    #[test]
    fn rollback_is_rejected_equal_or_newer_ok() {
        assert!(check_not_rolled_back(5, 5).is_ok()); // same — latest
        assert!(check_not_rolled_back(6, 5).is_ok()); // newer than config knew
        assert!(check_not_rolled_back(4, 5).is_err()); // older — rollback
    }

    /// A minimal byte string that passes the SQLite magic-header gate.
    fn fake_db(tag: u8) -> Vec<u8> {
        let mut db = SQLITE_MAGIC.to_vec();
        db.extend_from_slice(&[tag; 64]);
        db
    }

    /// A `persist_floor` closure that records the version it was called with.
    fn record(
        slot: &std::cell::Cell<Option<u64>>,
    ) -> impl FnOnce(u64) -> Result<(), CoreError> + '_ {
        move |v| {
            slot.set(Some(v));
            Ok(())
        }
    }

    #[test]
    fn restore_swaps_db_and_raises_floor_when_newer() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        std::fs::write(&db_path, fake_db(0xAA)).unwrap();

        let new_db = fake_db(0xBB);
        let blob = encrypt_snapshot(&key(), 9, &new_db).unwrap();

        let persisted = std::cell::Cell::new(None);
        let restored =
            restore_with_floor(&key(), &blob, &db_path, 5, None, record(&persisted)).unwrap();
        assert_eq!(restored, 9);
        assert_eq!(persisted.get(), Some(9), "floor raised before swap");
        assert_eq!(std::fs::read(&db_path).unwrap(), new_db);
    }

    /// `before_swap` runs after the floor and before the swap, also at the
    /// floor version; an error from it leaves the DB as `before_swap` left it.
    /// `remove_db_files` removes the DB and every sidecar.
    #[test]
    fn before_swap_runs_between_floor_and_swap_and_can_stop_it() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        for local in [5, 9] {
            std::fs::write(&db_path, fake_db(0xAA)).unwrap();
            for s in ["-wal", "-shm", "-journal"] {
                std::fs::write(sidecar_path(&db_path, s), b"x").unwrap();
            }
            let blob = encrypt_snapshot(&key(), 9, &fake_db(0xBB)).unwrap();
            let persisted = std::cell::Cell::new(None);
            let seen = std::cell::Cell::new(None);
            let err = restore_with_floor_then(
                &key(),
                &blob,
                &db_path,
                local,
                None,
                record(&persisted),
                |v| {
                    seen.set(Some(v));
                    remove_db_files(&db_path)?;
                    Err(CoreError::Volume("stop".into()))
                },
            )
            .unwrap_err();
            assert!(err.to_string().contains("stop"));
            assert_eq!(seen.get(), Some(9));
            assert_eq!(persisted.get(), (local < 9).then_some(9));
            for s in ["", "-wal", "-shm", "-journal"] {
                assert!(!sidecar_path(&db_path, s).exists(), "{s} left");
            }
        }
    }

    #[test]
    fn restore_equal_version_swaps_without_raising_floor() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        std::fs::write(&db_path, fake_db(0xAA)).unwrap();

        let new_db = fake_db(0xBB);
        let blob = encrypt_snapshot(&key(), 9, &new_db).unwrap();

        let persisted = std::cell::Cell::new(None);
        let restored =
            restore_with_floor(&key(), &blob, &db_path, 9, None, record(&persisted)).unwrap();
        assert_eq!(restored, 9);
        assert_eq!(
            persisted.get(),
            None,
            "equal version must not re-persist the floor"
        );
        assert_eq!(std::fs::read(&db_path).unwrap(), new_db);
    }

    /// The review reproduction: session k published v5 but its ack was withheld, so
    /// session k+1 published another v5 and recorded it. Telegram answers the
    /// recorded id with the orphan. With the recorded hash, restore refuses it.
    #[test]
    fn same_version_older_snapshot_is_refused_when_the_hash_is_recorded() {
        let older = fake_db(0x01);
        let newer = fake_db(0x02);
        let orphan_v5 = encrypt_snapshot(&key(), 5, &older).unwrap();
        let recorded_v5 = encrypt_snapshot(&key(), 5, &newer).unwrap();
        let recorded_hash = Some(*blake3::hash(&recorded_v5).as_bytes());
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        std::fs::write(&db, &newer).unwrap();

        let persisted = std::cell::Cell::new(None);
        let err = restore_with_floor(
            &key(),
            &orphan_v5,
            &db,
            5,
            recorded_hash,
            record(&persisted),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Snapshot(_)), "{err}");
        assert!(err.to_string().contains("hash"), "{err}");
        assert_eq!(persisted.get(), None);
        assert_eq!(std::fs::read(&db).unwrap(), newer, "DB untouched");

        // The recorded snapshot itself restores.
        restore_with_floor(&key(), &recorded_v5, &db, 5, recorded_hash, |_| Ok(())).unwrap();
        assert_eq!(std::fs::read(&db).unwrap(), newer);
        // A newer version than the floor is not bound to the recorded hash (the
        // config may lag a published snapshot), and a config without a recorded
        // hash keeps the old behaviour.
        let v6 = encrypt_snapshot(&key(), 6, &older).unwrap();
        restore_with_floor(&key(), &v6, &db, 5, recorded_hash, |_| Ok(())).unwrap();
        restore_with_floor(&key(), &orphan_v5, &db, 5, None, |_| Ok(())).unwrap();
    }

    #[test]
    fn restore_refuses_rollback_and_leaves_db_untouched() {
        // The end-to-end security property: with a local floor of 5, a snapshot at
        // version 4 is refused, the floor is never persisted, AND the on-disk DB is
        // never modified.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let original = fake_db(0xAA);
        std::fs::write(&db_path, &original).unwrap();

        let stale = fake_db(0xBB);
        let blob = encrypt_snapshot(&key(), 4, &stale).unwrap();

        let persisted = std::cell::Cell::new(None);
        let err =
            restore_with_floor(&key(), &blob, &db_path, 5, None, record(&persisted)).unwrap_err();
        assert!(matches!(err, CoreError::Snapshot(_)));
        assert_eq!(persisted.get(), None);
        assert_eq!(std::fs::read(&db_path).unwrap(), original);
    }

    #[test]
    fn restore_rejects_non_sqlite_payload_without_raising_floor() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let original = fake_db(0xAA);
        std::fs::write(&db_path, &original).unwrap();

        // Authentic (correctly keyed) snapshot newer than the floor, but the payload
        // is not a DB — it must be rejected BEFORE the floor is bumped.
        let blob = encrypt_snapshot(&key(), 7, b"not a sqlite file").unwrap();
        let persisted = std::cell::Cell::new(None);
        let err =
            restore_with_floor(&key(), &blob, &db_path, 0, None, record(&persisted)).unwrap_err();
        assert!(matches!(err, CoreError::Snapshot(_)));
        assert_eq!(
            persisted.get(),
            None,
            "garbage payload must not raise the floor"
        );
        assert_eq!(std::fs::read(&db_path).unwrap(), original);
    }

    #[test]
    fn restore_leaves_db_untouched_when_floor_persist_fails() {
        // Fail-closed proof: if persisting the raised floor fails, the destructive
        // swap must NOT happen — the DB is left intact. This is the real production
        // ordering (CLI passes save_config_resealed as persist_floor).
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let original = fake_db(0xAA);
        std::fs::write(&db_path, &original).unwrap();

        let blob = encrypt_snapshot(&key(), 9, &fake_db(0xBB)).unwrap();
        let err = restore_with_floor(&key(), &blob, &db_path, 5, None, |_| {
            Err(CoreError::Volume("simulated config write failure".into()))
        })
        .unwrap_err();
        assert!(matches!(err, CoreError::Volume(_)));
        assert_eq!(
            std::fs::read(&db_path).unwrap(),
            original,
            "DB must be untouched when the floor cannot be persisted"
        );
    }

    #[test]
    fn restore_removes_stale_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        std::fs::write(&db_path, fake_db(0xAA)).unwrap();
        // Simulate a leftover WAL + shm from a prior crash.
        std::fs::write(sidecar_path(&db_path, "-wal"), b"stale wal").unwrap();
        std::fs::write(sidecar_path(&db_path, "-shm"), b"stale shm").unwrap();

        restore_db_atomically(&db_path, &fake_db(0xBB)).unwrap();

        assert!(
            !sidecar_path(&db_path, "-wal").exists(),
            "stale -wal removed"
        );
        assert!(
            !sidecar_path(&db_path, "-shm").exists(),
            "stale -shm removed"
        );
        assert_eq!(std::fs::read(&db_path).unwrap(), fake_db(0xBB));
    }

    #[test]
    fn tampered_version_in_snapshot_is_rejected_before_swap() {
        // The version is inside the AEAD plaintext, so flipping a ciphertext byte
        // fails decryption — restore never reaches the swap.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        let original = fake_db(0xAA);
        std::fs::write(&db_path, &original).unwrap();

        let mut blob = encrypt_snapshot(&key(), 3, &fake_db(0xBB)).unwrap();
        blob[0] ^= 0x01; // corrupt the ciphertext/version region
        let persisted = std::cell::Cell::new(None);
        let err =
            restore_with_floor(&key(), &blob, &db_path, 0, None, record(&persisted)).unwrap_err();
        assert!(matches!(err, CoreError::Decryption(_)));
        assert_eq!(persisted.get(), None);
        assert_eq!(std::fs::read(&db_path).unwrap(), original);
    }

    /// Eight restorers hammer `restore_db_atomically` while reading back. With a
    /// fixed temp name they share one inode, so a torn DB can be renamed into place
    /// and the loser's rename fails; with a unique temp per call neither happens.
    /// Every observed file must be exactly one writer's whole payload.
    #[test]
    fn concurrent_restores_never_tear_or_fail() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(dir.path().join("metadata.db"));
        let payload = |t: usize| {
            let mut p = SQLITE_MAGIC.to_vec();
            // Different length and fill byte per writer: a torn file is detectable.
            p.extend(std::iter::repeat_n(t as u8 + 1, 4096 + t * 1531));
            p
        };

        let errors = Arc::new(AtomicUsize::new(0));
        let first_error = Arc::new(Mutex::new(None::<String>));
        let threads: Vec<_> = (0..8usize)
            .map(|t| {
                let (db, errors, first_error) = (db.clone(), errors.clone(), first_error.clone());
                let mine = payload(t);
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        let r = restore_db_atomically(&db, &mine)
                            .map_err(|e| e.to_string())
                            .and_then(|()| {
                                let got = std::fs::read(&*db).map_err(|e| e.to_string())?;
                                let whole = (0..8).any(|w| got == payload(w));
                                if whole {
                                    Ok(())
                                } else {
                                    Err(format!("torn metadata.db ({} bytes)", got.len()))
                                }
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
            "concurrent restores must never fail or tear; first error: {:?}",
            first_error.lock().unwrap()
        );
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("metadata.db")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&*db).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// A sidecar that cannot be removed (a non-empty directory stands in for
    /// EIO/EPERM). The main DB must still be there afterwards: removing it
    /// first would leave a stale `-wal` beside no DB, which SQLite replays into
    /// whatever DB is created at that path next.
    #[test]
    fn remove_db_files_removes_sidecars_before_the_main_db() {
        for suffix in ["-wal", "-shm", "-journal"] {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("metadata.db");
            std::fs::write(&db_path, fake_db(0xAA)).unwrap();
            let side = sidecar_path(&db_path, suffix);
            std::fs::create_dir(&side).unwrap();
            std::fs::write(side.join("x"), b"x").unwrap();
            assert!(remove_db_files(&db_path).is_err(), "{suffix}");
            assert!(
                db_path.exists(),
                "{suffix}: the main DB was removed while its {suffix} sidecar stayed"
            );
        }
    }

    /// Same order when a DB is installed: a stale sidecar that cannot be
    /// removed must stop the install before the new DB is renamed into place
    /// (otherwise the new DB sits beside the old DB's `-wal`).
    #[test]
    fn restore_db_atomically_clears_sidecars_before_installing() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metadata.db");
        std::fs::write(&db_path, fake_db(0xAA)).unwrap();
        let side = sidecar_path(&db_path, "-wal");
        std::fs::create_dir(&side).unwrap();
        std::fs::write(side.join("x"), b"x").unwrap();
        assert!(restore_db_atomically(&db_path, &fake_db(0xBB)).is_err());
        assert_eq!(
            std::fs::read(&db_path).unwrap(),
            fake_db(0xAA),
            "the new DB was installed beside a stale -wal"
        );
    }
}
