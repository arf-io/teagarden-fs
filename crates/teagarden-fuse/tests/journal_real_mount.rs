//! Real FUSE mounts with the v0.4.3 metadata journal ON — the production
//! configuration (`volume mount` wires transport + upload queue + journal).
//!
//! The other real-mount suites run un-journaled. This one mounts `CryptFs` over a
//! file-backed DB with `with_journal(..)` and `with_upload_queue()` and drives it
//! through real binaries and syscalls:
//!
//!   Phase 1 — `cp` a file in (byte-exact), and `cp` a second file while block
//!             uploads fail: `cp` must exit non-zero with an I/O error and the
//!             journal must not record a manifest for the failed data.
//!   Phase 2 — clean unmount, remount the SAME DB with the HEAD loaded from disk,
//!             read back byte-exact.
//!   Phase 3 — crash simulation: delete the local DB, rebuild it purely from the
//!             channel (base snapshot + journaled deltas), mount the rebuilt DB and
//!             read back byte-exact.
//!
//! Requirements: an unprivileged FUSE mount (`/dev/fuse` + `fusermount3`). When that
//! is unavailable the test SKIPS — unless `TEAGARDEN_REQUIRE_FUSE` is set, in which
//! case a missing/failed mount is a hard FAILURE.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::metadata::inode::Inode;
use teagarden_core::volume::journal_head::JournalHead;
use teagarden_core::volume::metadata_snapshot::encrypt_snapshot;
use teagarden_fuse::fs::CryptFs;
use teagarden_store::inode_store::InodeStore;
use teagarden_store::journal_recovery::recover_from_head;
use teagarden_store::migrations::initialize_database;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::schema::logical_tables;
use teagarden_telegram::client::BlockTransport;
use teagarden_telegram::mock::MockTransport;

const SCHEMA_KEY: [u8; 32] = [0x42; 32];
const META_KEY: [u8; 32] = [0x43; 32];
const DATA_KEY: [u8; 32] = [0x44; 32];
const BLOCK_ID_KEY: [u8; 32] = [0x45; 32];
const FILENAME_KEY: [u8; 32] = [0x46; 32];
const MANIFEST_KEY: [u8; 32] = [0x47; 32];
const INTEGRITY_KEY: [u8; 32] = [0x48; 32];

fn fuse_available() -> bool {
    let which = |bin: &str| {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
            .unwrap_or(false)
    };
    Path::new("/dev/fuse").exists() && (which("fusermount3") || which("fusermount"))
}

fn require_fuse() -> bool {
    std::env::var_os("TEAGARDEN_REQUIRE_FUSE").is_some()
}

fn force_unmount(mp: &Path) {
    for bin in ["fusermount3", "fusermount"] {
        let _ = std::process::Command::new(bin).arg("-u").arg(mp).output();
    }
}

fn schema() -> OpaqueSchema {
    OpaqueSchema::new(SymmetricKey::from_bytes(SCHEMA_KEY), &logical_tables())
}

struct Mount {
    mountpoint: PathBuf,
    session: Option<fuser::BackgroundSession>,
    _rt: tokio::runtime::Runtime,
    _mp_dir: tempfile::TempDir,
}

impl Drop for Mount {
    fn drop(&mut self) {
        // Clean unmount: the FS (and its DB connection) is dropped, flushing the DB.
        self.session.take();
        force_unmount(&self.mountpoint);
    }
}

/// Mount the file DB at `db_path` journaled against `transport`, continuing from
/// the HEAD stored at `head_path` — exactly as `volume mount` does for an
/// already-journaled volume. Returns `None` (skip) only when FUSE is unavailable
/// and not required.
fn mount_journaled(
    db_path: &Path,
    head_path: &Path,
    transport: Arc<MockTransport>,
) -> Option<Mount> {
    if !fuse_available() {
        assert!(
            !require_fuse(),
            "TEAGARDEN_REQUIRE_FUSE set but /dev/fuse or fusermount is unavailable"
        );
        eprintln!("SKIP: /dev/fuse or fusermount not available");
        return None;
    }
    let integrity = SymmetricKey::from_bytes(INTEGRITY_KEY);
    let head = JournalHead::load(head_path, &integrity)
        .unwrap()
        .expect("journal HEAD present");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fs = CryptFs::new(
        Connection::open(db_path).unwrap(),
        schema(),
        SymmetricKey::from_bytes(META_KEY),
        SymmetricKey::from_bytes(DATA_KEY),
        unsafe { libc::getuid() },
        unsafe { libc::getgid() },
    )
    .with_block_keys(
        SymmetricKey::from_bytes(BLOCK_ID_KEY),
        SymmetricKey::from_bytes(FILENAME_KEY),
    )
    .with_manifest_key(SymmetricKey::from_bytes(MANIFEST_KEY))
    .with_block_integrity(true)
    .with_transport(transport)
    .with_runtime(rt.handle().clone())
    .with_upload_queue()
    .with_journal(integrity, head_path.to_path_buf(), head);

    let dir = tempfile::tempdir().unwrap();
    let mountpoint = dir.path().to_path_buf();
    let opts = [fuser::MountOption::FSName(
        "teagarden-journal-test".to_string(),
    )];
    let session = match fuser::spawn_mount2(fs, &mountpoint, &opts) {
        Ok(s) => s,
        Err(e) => {
            assert!(
                !require_fuse(),
                "TEAGARDEN_REQUIRE_FUSE set but mount failed: {e}"
            );
            eprintln!("SKIP: spawn_mount2 failed: {e}");
            return None;
        }
    };
    Some(Mount {
        mountpoint,
        session: Some(session),
        _rt: rt,
        _mp_dir: dir,
    })
}

/// Run `body` under a hard watchdog that force-unmounts on timeout.
fn watchdog<F: FnOnce()>(secs: u64, mp: &Path, body: F) {
    let done = Arc::new(AtomicBool::new(false));
    let done_wd = done.clone();
    let mp_wd = mp.to_path_buf();
    let wd = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        while std::time::Instant::now() < deadline {
            if done_wd.load(Ordering::Relaxed) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        force_unmount(&mp_wd);
        false
    });
    body();
    done.store(true, Ordering::Relaxed);
    assert!(wd.join().unwrap(), "watchdog fired after {secs}s");
}

fn payload(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x & 0xff) as u8
        })
        .collect()
}

fn head_seq(head_path: &Path) -> u64 {
    JournalHead::load(head_path, &SymmetricKey::from_bytes(INTEGRITY_KEY))
        .unwrap()
        .unwrap()
        .seq
}

#[test]
fn journaled_mount_write_close_remount_recover_and_failed_upload() {
    if !fuse_available() {
        assert!(
            !require_fuse(),
            "TEAGARDEN_REQUIRE_FUSE set but /dev/fuse or fusermount is unavailable"
        );
        eprintln!("SKIP: /dev/fuse or fusermount not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("metadata.db");
    let head_path = dir.path().join("journal.head");
    let src_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("src.bin");
    let data = payload(1_300_000, 11); // three upload chunks
    std::fs::write(&src, &data).unwrap();
    // Different content for the failing copy: identical chunks would dedup against
    // good.bin's blocks and need no upload at all.
    let src2 = src_dir.path().join("src2.bin");
    std::fs::write(&src2, payload(1_300_000, 12)).unwrap();

    // Fresh volume: DB with the root inode, published as the base snapshot, and a
    // seq-0 HEAD pointing at it (what `volume mount` does on first journaled mount).
    {
        let conn = Connection::open(&db_path).unwrap();
        initialize_database(&conn, &schema()).unwrap();
        let mut root = Inode::root();
        root.uid = unsafe { libc::getuid() };
        root.gid = unsafe { libc::getgid() };
        InodeStore::new(&conn, &schema(), &SymmetricKey::from_bytes(META_KEY))
            .insert(&root)
            .unwrap();
    }
    let transport = Arc::new(MockTransport::new());
    let data_key = SymmetricKey::from_bytes(DATA_KEY);
    let base_blob = encrypt_snapshot(&data_key, 1, &std::fs::read(&db_path).unwrap()).unwrap();
    let base_msg_id = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(transport.sync_metadata(&base_blob))
        .unwrap();
    JournalHead {
        seq: 0,
        parent_msg_id: base_msg_id,
        base_snapshot_version: 1,
        base_snapshot_msg_id: base_msg_id,
        base_snapshot_hash: *blake3::hash(&base_blob).as_bytes(),
        last_hash: None,
        lineage: None,
    }
    .store_atomic(&head_path, &SymmetricKey::from_bytes(INTEGRITY_KEY))
    .unwrap();

    // ---- Phase 1: journaled writes through real cp ----
    let mut seq_after_good = 0;
    {
        let Some(m) = mount_journaled(&db_path, &head_path, transport.clone()) else {
            return;
        };
        let mp = m.mountpoint.clone();
        watchdog(90, &mp, || {
            let out = std::process::Command::new("cp")
                .arg(&src)
                .arg(mp.join("good.bin"))
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "journaled cp: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(std::fs::read(mp.join("good.bin")).unwrap(), data);
            seq_after_good = head_seq(&head_path);
            assert!(
                seq_after_good >= 2,
                "create + data journaled: {seq_after_good}"
            );

            *transport.fail_uploads.lock().unwrap() = Some("injected".into());
            let out = std::process::Command::new("cp")
                .arg(&src2)
                .arg(mp.join("failed.bin"))
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            eprintln!(
                "journaled cp with failing uploads: status={:?} stderr={stderr:?}",
                out.status.code()
            );
            assert!(!out.status.success(), "cp must fail when uploads fail");
            assert!(stderr.contains("Input/output error"), "got {stderr:?}");
        });
        // Keep the fault armed until the mount is gone: the kernel sends RELEASE
        // asynchronously after close(2), and release RETRIES the persist — with a
        // healthy transport that retry would (correctly) still save the file.
        drop(m);
    }
    *transport.fail_uploads.lock().unwrap() = None;
    // Only the create of failed.bin was journaled — no manifest delta for data
    // that never reached the channel (neither the flush nor the release retry).
    assert_eq!(
        head_seq(&head_path),
        seq_after_good + 1,
        "a failed data persist must publish no delta"
    );

    // ---- Phase 2: remount the same DB from the on-disk HEAD ----
    {
        let Some(m) = mount_journaled(&db_path, &head_path, transport.clone()) else {
            return;
        };
        let mp = m.mountpoint.clone();
        watchdog(60, &mp, || {
            assert_eq!(
                std::fs::read(mp.join("good.bin")).unwrap(),
                data,
                "remount reads back byte-exact"
            );
            assert_eq!(std::fs::metadata(mp.join("failed.bin")).unwrap().len(), 0);
        });
    }

    // ---- Phase 3: crash simulation — rebuild the DB from the channel alone ----
    let final_head = JournalHead::load(&head_path, &SymmetricKey::from_bytes(INTEGRITY_KEY))
        .unwrap()
        .unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{suffix}", db_path.display()));
        let _ = std::fs::remove_file(p);
    }
    let t = transport.clone();
    let replayed = recover_from_head(&data_key, final_head, &db_path, |id| {
        t.get_raw(id)
            .ok_or_else(|| teagarden_core::error::CoreError::Snapshot(format!("msg {id} gone")))
    })
    .unwrap();
    eprintln!("recovered DB from channel: {replayed} deltas replayed");
    {
        let Some(m) = mount_journaled(&db_path, &head_path, transport.clone()) else {
            return;
        };
        let mp = m.mountpoint.clone();
        watchdog(60, &mp, || {
            assert_eq!(
                std::fs::read(mp.join("good.bin")).unwrap(),
                data,
                "a DB rebuilt from the channel reads back byte-exact"
            );
            assert_eq!(std::fs::metadata(mp.join("failed.bin")).unwrap().len(), 0);
        });
    }
}
