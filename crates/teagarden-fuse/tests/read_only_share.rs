//! Read-only-share enforcement — a volume mounted read-only must refuse writes.
//!
//! The sharing feature can hand a recipient a *read-only* view of a volume. That
//! promise has to hold at the surface a user actually touches: a real kernel FUSE
//! mount, exercised through genuine syscalls (`std::fs`, `libc`), not merely a CLI
//! affordance. This test mounts `CryptFs` built with `.with_read_only(true)` and
//! asserts that every mutating op (`write`, create, `mkdir`, `unlink`, `rmdir`,
//! `rename`, chmod→`setattr`, O_TRUNC truncation, `symlink`) fails with `EROFS`,
//! while reads and `readdir` succeed byte-exact.
//!
//! Because file content lives in manifest blocks on the transport (there is no
//! inline seeding), the harness is two-phase over ONE file-backed DB + ONE shared
//! `MockTransport`:
//!   Phase 1 — mount read-WRITE, write known bytes + a dir, `fsync` to persist the
//!             manifest+blocks synchronously, then drop for a clean unmount. This
//!             doubles as the read-only-false control (writes and reads back fine).
//!   Phase 2 — reopen the SAME DB with the SAME transport, mount read-ONLY, assert.
//!
//! Requirements: an unprivileged FUSE mount (`/dev/fuse` + `fusermount3`). When that
//! is unavailable the test SKIPS (print and return) — UNLESS `TEAGARDEN_REQUIRE_FUSE`
//! is set (CI), in which case a missing/failed mount is a hard FAILURE.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::metadata::inode::Inode;
use teagarden_fuse::fs::CryptFs;
use teagarden_store::inode_store::InodeStore;
use teagarden_store::migrations::initialize_database;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::schema::logical_tables;
use teagarden_telegram::mock::MockTransport;

// Fixed keys — EVERY key must be byte-identical across the two phases or phase 2
// (read-only) decrypts nothing. These mirror real_mount.rs's fixtures.
const SCHEMA_KEY: [u8; 32] = [0x42; 32];
const META_KEY: [u8; 32] = [0x43; 32];
const DATA_KEY: [u8; 32] = [0x44; 32];
const BLOCK_ID_KEY: [u8; 32] = [0x45; 32];
const FILENAME_KEY: [u8; 32] = [0x46; 32];
const MANIFEST_KEY: [u8; 32] = [0x47; 32];

/// True when an unprivileged FUSE mount is plausible on this host.
fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists() && (which("fusermount3") || which("fusermount"))
}

/// When `TEAGARDEN_REQUIRE_FUSE` is set (CI does this), a missing/failed mount is a
/// hard FAILURE rather than a skip — so a runner that cannot mount FUSE surfaces
/// loudly instead of silently passing. Locally (env unset) the test skips cleanly.
fn require_fuse() -> bool {
    std::env::var_os("TEAGARDEN_REQUIRE_FUSE").is_some()
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|p| {
                let f = p.join(bin);
                f.exists()
            })
        })
        .unwrap_or(false)
}

/// Best-effort unmount of `mp` via whichever fusermount is present.
fn force_unmount(mp: &Path) {
    for bin in ["fusermount3", "fusermount"] {
        let _ = std::process::Command::new(bin).arg("-u").arg(mp).output();
    }
}

/// Serializes real mounts across the test binary (see real_mount.rs). Poison-tolerant.
fn mount_lock() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// A live real-mount session. Owns everything that must outlive the mount: the
/// serialization guard, the background FUSE session, the tokio runtime (its handle
/// is used by the FS for transport calls), and the mountpoint tempdir. The DB and
/// the transport are owned by the test so they persist across both phases.
struct Mount {
    mountpoint: PathBuf,
    session: Option<fuser::BackgroundSession>,
    _rt: tokio::runtime::Runtime,
    _mp_dir: tempfile::TempDir,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Mount {
    fn path(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        // Drop the session first (clean unmount → the FS and its DB connection are
        // dropped, flushing the file-backed DB), then belt-and-suspenders force.
        self.session.take();
        force_unmount(&self.mountpoint);
    }
}

/// One-time initialization of the file-backed DB: create the schema and insert the
/// root inode owned by the mounting user. Called ONCE, before phase 1 — the schema
/// is deterministic from `SCHEMA_KEY`, so reopening the file in either phase yields
/// the same obfuscated table names without re-initializing.
fn seed_db(db_path: &Path) {
    let conn = Connection::open(db_path).unwrap();
    let schema = OpaqueSchema::new(SymmetricKey::from_bytes(SCHEMA_KEY), &logical_tables());
    initialize_database(&conn, &schema).unwrap();
    let meta_key = SymmetricKey::from_bytes(META_KEY);
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let mut root = Inode::root();
    root.uid = uid;
    root.gid = gid;
    InodeStore::new(&conn, &schema, &meta_key)
        .insert(&root)
        .unwrap();
}

/// Mount the already-seeded DB at a fresh mountpoint over the shared transport.
/// `read_only` selects `.with_read_only(true)`. Returns `None` (skip) when FUSE is
/// unavailable — unless `TEAGARDEN_REQUIRE_FUSE` forces a hard failure.
fn mount(db_path: &Path, transport: Arc<MockTransport>, read_only: bool) -> Option<Mount> {
    if !fuse_available() {
        assert!(
            !require_fuse(),
            "TEAGARDEN_REQUIRE_FUSE set but /dev/fuse or fusermount is unavailable"
        );
        eprintln!("SKIP: /dev/fuse or fusermount not available");
        return None;
    }
    let guard = mount_lock();

    let conn = Connection::open(db_path).unwrap();
    let schema = OpaqueSchema::new(SymmetricKey::from_bytes(SCHEMA_KEY), &logical_tables());
    let meta_key = SymmetricKey::from_bytes(META_KEY);
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let fs = CryptFs::new(
        conn,
        schema,
        meta_key,
        SymmetricKey::from_bytes(DATA_KEY),
        uid,
        gid,
    )
    .with_block_keys(
        SymmetricKey::from_bytes(BLOCK_ID_KEY),
        SymmetricKey::from_bytes(FILENAME_KEY),
    )
    .with_manifest_key(SymmetricKey::from_bytes(MANIFEST_KEY))
    .with_transport(transport)
    .with_runtime(rt.handle().clone())
    .with_read_only(read_only);

    let dir = tempfile::tempdir().unwrap();
    let mountpoint = dir.path().to_path_buf();
    let opts = [fuser::MountOption::FSName("teagarden-ro-test".to_string())];
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
        _guard: guard,
    })
}

/// Run `body` under a hard watchdog: if it does not finish within `secs`, the
/// watchdog force-unmounts `mp` (unblocking any hung syscall) and the test panics.
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
    let ok = wd.join().unwrap();
    assert!(
        ok,
        "watchdog fired after {secs}s — possible mount hang or CPU runaway"
    );
}

fn at(m: &Mount, name: &str) -> PathBuf {
    m.path().join(name)
}

/// Assert that `err` is exactly `EROFS`, with a labelled message.
fn assert_erofs(op: &str, err: &std::io::Error) {
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EROFS),
        "{op}: expected EROFS on a read-only mount, got {err:?}"
    );
}

const SEED_BYTES: &[u8] = b"read-only share payload \x00\x01\x02 end";

#[test]
fn read_only_mount_refuses_writes_but_serves_reads() {
    if !fuse_available() {
        assert!(
            !require_fuse(),
            "TEAGARDEN_REQUIRE_FUSE set but /dev/fuse or fusermount is unavailable"
        );
        eprintln!("SKIP: /dev/fuse or fusermount not available");
        return;
    }

    // The DB file and the transport must outlive BOTH phases.
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("meta.db");
    let transport = Arc::new(MockTransport::new());
    seed_db(&db_path);

    // ---- Phase 1: read-WRITE mount (also the read_only=false control) ----
    {
        let Some(m) = mount(&db_path, transport.clone(), false) else {
            return;
        };
        watchdog(60, m.path(), || {
            // Write via create+write+fsync so the manifest+blocks are persisted
            // synchronously (fsync uploads and journals before returning), then
            // close. Do NOT rely on async release having completed at teardown.
            let mut f = File::create(at(&m, "seed.txt")).unwrap();
            f.write_all(SEED_BYTES).unwrap();
            f.sync_all().unwrap();
            drop(f);
            std::fs::create_dir(at(&m, "seeddir")).unwrap();

            // Control: the read-WRITE mount reads its own bytes back exactly.
            assert_eq!(
                std::fs::read(at(&m, "seed.txt")).unwrap(),
                SEED_BYTES,
                "read_only=false control: write then read-back must be byte-exact"
            );
            // Blocks actually reached the transport (so phase 2 can download them).
            assert!(
                transport.message_count() > 0,
                "seed block must be uploaded before phase 2"
            );
        });
        // m dropped here → clean unmount → FS + DB connection dropped, DB flushed,
        // and the mount_lock guard released before phase 2 re-acquires it.
    }

    // ---- Phase 2: read-ONLY mount over the SAME DB + SAME transport ----
    let Some(m) = mount(&db_path, transport.clone(), true) else {
        return;
    };
    watchdog(60, m.path(), || {
        // READS SUCCEED, byte-exact.
        assert_eq!(
            std::fs::read(at(&m, "seed.txt")).unwrap(),
            SEED_BYTES,
            "read-only mount must still serve the pre-seeded file byte-exact"
        );

        // close(2) of a read descriptor SUCCEEDS: the FUSE `flush` a close issues
        // must not be refused on a read-only mount (File's drop ignores close
        // errors, so check close(2) directly).
        {
            use std::os::unix::io::IntoRawFd;
            let fd = std::fs::File::open(at(&m, "seed.txt"))
                .unwrap()
                .into_raw_fd();
            let rc = unsafe { libc::close(fd) };
            assert_eq!(
                rc,
                0,
                "close(2) on a read-only mount failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // readdir SUCCEEDS and sees both entries.
        let mut names: Vec<String> = std::fs::read_dir(m.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["seed.txt".to_string(), "seeddir".to_string()]);

        // ---- every mutating op is refused with EROFS ----

        // write to a NEW file: create() is refused.
        let e = std::fs::write(at(&m, "new.txt"), b"nope").unwrap_err();
        assert_erofs("create/write new file", &e);

        // write to the EXISTING file via a write-intent open: open() is refused.
        let e = OpenOptions::new()
            .write(true)
            .open(at(&m, "seed.txt"))
            .unwrap_err();
        assert_erofs("open(O_WRONLY) existing file", &e);

        // O_TRUNC truncation on a write-intent open: refused at open.
        let e = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(at(&m, "seed.txt"))
            .unwrap_err();
        assert_erofs("open(O_WRONLY|O_TRUNC) truncate", &e);

        // O_RDONLY|O_TRUNC — a legal syscall whose ACCMODE is O_RDONLY. `open_impl`
        // truncates at open time, so this MUST be refused too or a "read-only" mount
        // would empty the file. std OpenOptions can't express read+truncate, so
        // drive open(2) directly and pin the byte-exact content afterward.
        let cpath = std::ffi::CString::new(at(&m, "seed.txt").as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_TRUNC) };
        // Capture errno immediately (portable; `__errno_location` is Linux-only).
        let errno = std::io::Error::last_os_error().raw_os_error();
        if fd >= 0 {
            unsafe { libc::close(fd) };
            panic!(
                "open(O_RDONLY|O_TRUNC) succeeded on a read-only mount — truncation slipped past"
            );
        }
        assert_eq!(
            errno,
            Some(libc::EROFS),
            "open(O_RDONLY|O_TRUNC): expected EROFS, got errno {errno:?}"
        );
        assert_eq!(
            std::fs::read(at(&m, "seed.txt")).unwrap(),
            SEED_BYTES,
            "O_RDONLY|O_TRUNC must not have truncated the file"
        );

        // mkdir: refused.
        let e = std::fs::create_dir(at(&m, "newdir")).unwrap_err();
        assert_erofs("mkdir", &e);

        // unlink: refused.
        let e = std::fs::remove_file(at(&m, "seed.txt")).unwrap_err();
        assert_erofs("unlink", &e);

        // rmdir: refused.
        let e = std::fs::remove_dir(at(&m, "seeddir")).unwrap_err();
        assert_erofs("rmdir", &e);

        // rename: refused.
        let e = std::fs::rename(at(&m, "seed.txt"), at(&m, "renamed.txt")).unwrap_err();
        assert_erofs("rename", &e);

        // chmod → setattr with NO write-intent open: proves the setattr guard
        // itself (not the open guard) refuses. Truncation-via-setattr rides the
        // same guard, so this is what actually closes the truncate hole.
        let e =
            std::fs::set_permissions(at(&m, "seed.txt"), std::fs::Permissions::from_mode(0o600))
                .unwrap_err();
        assert_erofs("chmod (setattr)", &e);

        // symlink: refused.
        let e = std::os::unix::fs::symlink("seed.txt", at(&m, "link.txt")).unwrap_err();
        assert_erofs("symlink", &e);

        // Nothing above mutated state: the file and dir still read/list unchanged.
        assert_eq!(std::fs::read(at(&m, "seed.txt")).unwrap(), SEED_BYTES);
        assert!(at(&m, "seeddir").is_dir());
        assert!(
            !at(&m, "new.txt").exists() && !at(&m, "newdir").exists(),
            "refused ops must not have created anything"
        );
    });
}
