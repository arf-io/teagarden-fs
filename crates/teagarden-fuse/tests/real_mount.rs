//! Real FUSE-mount end-to-end tests — the actual in-application surface.
//!
//! Unlike `e2e_filesystem.rs` (which drives `CryptFs` methods directly), these tests
//! mount a real filesystem via `fuser::spawn_mount2` and exercise it through genuine
//! OS syscalls (`std::fs`, `libc`), so the kernel ↔ FUSE ↔ `CryptFs` path is what is
//! validated — including the v0.4.4 write-path and v0.4.5 manifest-history behaviour
//! as actually shipped.
//!
//! Requirements: an unprivileged FUSE mount (`/dev/fuse` + `fusermount3`). When that
//! is unavailable the tests SKIP (print and return) rather than fail, so the suite is
//! portable; CI installs `fuse3` and provides `/dev/fuse`.
//!
//! Every test runs under a hard watchdog: a background thread force-unmounts the
//! mountpoint after a timeout, so a hung mount or a CPU-runaway can never block the
//! run for hours — the watchdog turns a hang into a fast, visible failure.

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

/// True when an unprivileged FUSE mount is plausible on this host.
fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists() && (which("fusermount3") || which("fusermount"))
}

/// When `TEAGARDEN_REQUIRE_FUSE` is set (CI does this), a missing/failed mount is a
/// hard FAILURE rather than a skip — so a runner that cannot mount FUSE surfaces
/// loudly instead of silently passing. Locally (env unset) the tests skip cleanly.
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

/// Serializes real mounts across the test binary. cargo runs tests in parallel by
/// default; ~12 concurrent FUSE mounts (each its own session + tokio runtime) on a
/// 2-core CI runner causes contention flakes. Holding this lock for a mount's whole
/// lifetime keeps the suite reliable; the per-test watchdog still catches a true
/// hang. Poison-tolerant (a panicking test must not wedge the rest).
fn mount_lock() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// A live real-mount session. Owns everything that must outlive the mount: the
/// serialization guard, the background FUSE session, the tokio runtime (its handle
/// is used by the FS for transport calls), the transport, and the mountpoint tempdir.
struct Mount {
    mountpoint: PathBuf,
    session: Option<fuser::BackgroundSession>,
    _rt: tokio::runtime::Runtime,
    transport: Arc<MockTransport>,
    _dir: tempfile::TempDir,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Mount {
    fn path(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        // Drop the session first (clean unmount), then belt-and-suspenders force.
        self.session.take();
        force_unmount(&self.mountpoint);
    }
}

// Delegate real FUSE requests while stopping RELEASE before it prepares a plan.
struct PauseEmptyRelease {
    inner: CryptFs,
    root: PathBuf,
}
impl fuser::Filesystem for PauseEmptyRelease {
    fn init(
        &mut self,
        req: &fuser::Request<'_>,
        config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        self.inner.init(req, config)
    }
    fn lookup(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        self.inner.lookup(req, parent, name, reply);
    }
    fn getattr(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: Option<u64>,
        reply: fuser::ReplyAttr,
    ) {
        self.inner.getattr(req, ino, fh, reply);
    }
    fn create(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        self.inner
            .create(req, parent, name, mode, umask, flags, reply);
    }
    fn flush(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        owner: u64,
        reply: fuser::ReplyEmpty,
    ) {
        self.inner.flush(req, ino, fh, owner, reply);
    }
    fn release(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        owner: Option<u64>,
        flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !self.root.join("closed").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            self.root.join("closed").exists(),
            "close must succeed before RELEASE"
        );
        std::fs::rename(
            self.root.join("release-checkpoint"),
            self.root.join("ready"),
        )
        .unwrap();
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
        self.inner.release(req, ino, fh, flags, owner, flush, reply);
    }
}

/// Build a `CryptFs` over a fresh in-memory DB + `MockTransport` and mount it at a
/// unique temp mountpoint, using the inline (no upload queue) write path. Returns
/// `None` if FUSE is unavailable.
fn mount() -> Option<Mount> {
    mount_with(false)
}

/// As [`mount`]; `upload_queue` selects the background upload-queue write path
/// (`CryptFs::with_upload_queue`) that the production CLI mount uses.
fn mount_with(upload_queue: bool) -> Option<Mount> {
    mount_with_format(upload_queue, false)
}

fn mount_with_format(upload_queue: bool, portable: bool) -> Option<Mount> {
    mount_with_audit(upload_queue, portable, false)
}

fn mount_with_audit(upload_queue: bool, portable: bool, audit: bool) -> Option<Mount> {
    mount_with_recovery_root(upload_queue, portable, audit, None)
}

fn mount_with_recovery_root(
    upload_queue: bool,
    portable: bool,
    audit: bool,
    recovery: Option<&Path>,
) -> Option<Mount> {
    mount_with_recovery_transport(upload_queue, portable, audit, recovery, None)
}

fn mount_with_recovery_transport(
    upload_queue: bool,
    portable: bool,
    audit: bool,
    recovery: Option<&Path>,
    transport: Option<Arc<MockTransport>>,
) -> Option<Mount> {
    if !fuse_available() {
        assert!(
            !require_fuse(),
            "TEAGARDEN_REQUIRE_FUSE set but /dev/fuse or fusermount is unavailable"
        );
        eprintln!("SKIP: /dev/fuse or fusermount not available");
        return None;
    }
    // Serialize mounts for the whole session lifetime (held in the returned Mount).
    let guard = mount_lock();

    let dir = tempfile::tempdir().unwrap();
    let conn = if audit {
        Connection::open(recovery.unwrap_or(dir.path()).join("audit.db")).unwrap()
    } else {
        Connection::open_in_memory().unwrap()
    };
    let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
    initialize_database(&conn, &schema).unwrap();
    if audit {
        conn.execute_batch("CREATE TABLE IF NOT EXISTS pending_byte_audit (n INTEGER NOT NULL); INSERT INTO pending_byte_audit SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM pending_byte_audit)").unwrap();
        for name in ["sdo_pending_writes", "sdo_pending_chunks"] {
            let Ok(table) = schema.require_table(name) else {
                continue;
            };
            let data = schema.require_column(name, "data").unwrap();
            for event in ["INSERT", "UPDATE"] {
                conn.execute_batch(&format!("CREATE TEMP TRIGGER audit_{name}_{event} AFTER {event} ON {table} BEGIN UPDATE pending_byte_audit SET n=n+length(new.{data}); END;")).unwrap();
            }
        }
    }

    let meta_key = SymmetricKey::from_bytes([0x43; 32]);
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    {
        // The mount's root must exist for the first getattr(1) (stat of the
        // mountpoint), and must be OWNED by the mounting user — matching how the
        // real mount auto-creates root (fs.rs) — or ownership checks reject the
        // user's mkdir/rename/unlink on root's children.
        let mut root = Inode::root();
        root.uid = uid;
        root.gid = gid;
        let store = InodeStore::new(&conn, &schema, &meta_key);
        if store.get(1).unwrap().is_none() {
            store.insert(&root).unwrap();
        }
    }

    let transport = transport.unwrap_or_else(|| Arc::new(MockTransport::new()));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fs = CryptFs::new(
        conn,
        schema,
        meta_key,
        SymmetricKey::from_bytes([0x44; 32]),
        uid,
        gid,
    )
    .with_block_keys(
        SymmetricKey::from_bytes([0x45; 32]),
        SymmetricKey::from_bytes([0x46; 32]),
    )
    .with_manifest_key(SymmetricKey::from_bytes([0x47; 32]))
    .with_transport(transport.clone())
    .with_runtime(rt.handle().clone());
    let fs = if portable {
        fs.with_sdo(
            uuid::Uuid::from_bytes([0x61; 16]),
            uuid::Uuid::from_bytes([0x62; 16]),
        )
    } else {
        fs
    };
    let fs = if portable && audit {
        use teagarden_core::sdo::{HeaderDocument, SigningKey};
        let mut hierarchy = teagarden_core::crypto::kdf::derive_hierarchy_v1(
            SymmetricKey::from_bytes([0x66; 32]),
            &[1; 32],
            -100,
            42,
        )
        .unwrap();
        hierarchy.meta = SymmetricKey::from_bytes([0x43; 32]);
        let owner = SigningKey::from_bytes(&[0x67; 32]);
        let writer = SigningKey::from_bytes(&[0x68; 32]);
        let mut header = HeaderDocument::test_fixture();
        header.format = 2;
        header.volume_id = uuid::Uuid::from_bytes([0x61; 16]);
        header.key_generation = Some(0);
        header.owner_public_key = Some(hex::encode(owner.verifying_key().to_bytes()));
        header.device_authorities.insert(
            uuid::Uuid::from_bytes([0x62; 16]),
            hex::encode(writer.verifying_key().to_bytes()),
        );
        let bootstrap = header.encode_v2(&hierarchy.integrity, &owner).unwrap();
        fs.with_sdo_signing_key(writer)
            .with_sdo_object_envelope(bootstrap, hierarchy)
    } else {
        fs
    };
    let mut fs = if upload_queue {
        fs.with_upload_queue()
    } else {
        fs
    };

    if recovery.is_some() {
        fs.retry_pending_sdo_writes().unwrap();
    }

    let mountpoint = dir.path().join("mount");
    std::fs::create_dir(&mountpoint).unwrap();
    // NOTE: no `AutoUnmount` — fuser implicitly adds `allow_other` alongside it, which
    // a stock runner rejects ("allow_other only allowed if 'user_allow_other' is set
    // in /etc/fuse.conf"). Unmounting is handled explicitly: `BackgroundSession`'s drop
    // unmounts on a clean exit, the `Mount` drop force-unmounts, and the watchdog
    // force-unmounts on timeout — so we don't need the kernel-side auto-unmount.
    let opts = [fuser::MountOption::FSName("teagarden-test".to_string())];
    let mounted = if std::env::var_os("TEAGARDEN_TEST_EMPTY_RELEASE_PAUSE").is_some() {
        fuser::spawn_mount2(
            PauseEmptyRelease {
                inner: fs,
                root: recovery.unwrap().to_owned(),
            },
            &mountpoint,
            &opts,
        )
    } else {
        fuser::spawn_mount2(fs, &mountpoint, &opts)
    };
    let session = match mounted {
        Ok(s) => s,
        Err(e) => {
            // A runner that cannot mount unprivileged: skip — unless CI requires it.
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
        transport,
        _dir: dir,
        _guard: guard,
    })
}

/// Run `body` under a hard watchdog. If it does not finish within `secs`, the
/// watchdog force-unmounts `mp` (unblocking any hung syscall) and the test panics —
/// so a mount hang or CPU-runaway becomes a fast failure, never a multi-hour block.
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
        // Timed out — break any hung syscall by force-unmounting.
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

/// SMOKE TEST (gates the full matrix): can this host mount the real filesystem
/// unprivileged and stat its root? On a runner without FUSE this SKIPS.
#[test]
fn real_mount_smoke_stat_root() {
    let Some(m) = mount() else { return };
    watchdog(15, m.path(), || {
        let md = std::fs::metadata(m.path()).expect("stat mounted root");
        assert!(md.is_dir(), "mounted root should be a directory");
        // The transport is wired and idle on a bare mount.
        assert_eq!(m.transport.message_count(), 0);
    });
}

// ---- Real-syscall matrix: kernel ↔ FUSE ↔ CryptFs, validating the v0.4.4
// write-path and POSIX semantics through genuine open/write/ftruncate/read/rename/
// unlink syscalls (what the mock `e2e_filesystem.rs` cannot reach). ----

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};

fn at(m: &Mount, name: &str) -> PathBuf {
    m.path().join(name)
}

#[test]
fn real_write_read_roundtrip() {
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "hello.txt");
        std::fs::write(&f, b"hello world").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"hello world");
        assert_eq!(std::fs::metadata(&f).unwrap().len(), 11);
    });
}

#[test]
fn real_partial_overwrite_preserves_tail() {
    // v0.4.4 read-modify-write through real pwrite: overwrite the head, the tail
    // must survive (the bug was: release uploaded only the written range).
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "rmw.bin");
        std::fs::write(&f, b"AAAABBBBCCCC").unwrap();
        let mut fh = OpenOptions::new().write(true).open(&f).unwrap();
        fh.seek(SeekFrom::Start(0)).unwrap();
        fh.write_all(b"xx").unwrap();
        drop(fh); // close → flush + release
        assert_eq!(std::fs::read(&f).unwrap(), b"xxAABBBBCCCC");
    });
}

#[test]
fn real_ftruncate_shrink_then_grow() {
    // v0.4.4: ftruncate is authoritative; a shrink drops the tail, a grow zero-fills
    // the hole — both observed through real set_len + read.
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "trunc.bin");
        std::fs::write(&f, b"0123456789").unwrap();

        // Shrink to 4.
        OpenOptions::new()
            .write(true)
            .open(&f)
            .unwrap()
            .set_len(4)
            .unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"0123");
        assert_eq!(std::fs::metadata(&f).unwrap().len(), 4);

        // Grow to 8 — the new region reads as zeros (POSIX hole).
        OpenOptions::new()
            .write(true)
            .open(&f)
            .unwrap()
            .set_len(8)
            .unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().len(), 8);
        assert_eq!(std::fs::read(&f).unwrap(), b"0123\0\0\0\0");
    });
}

#[test]
fn real_o_trunc_empties_file() {
    // v0.4.4: opening O_TRUNC empties the file even with no subsequent write.
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "otrunc.txt");
        std::fs::write(&f, b"existing content").unwrap();
        // O_WRONLY|O_TRUNC then close without writing.
        let fh = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&f)
            .unwrap();
        drop(fh);
        assert_eq!(std::fs::metadata(&f).unwrap().len(), 0);
        assert!(std::fs::read(&f).unwrap().is_empty());
    });
}

#[test]
fn real_sparse_write_high_offset_zero_fills() {
    // Writing at a high offset into a small file zero-fills the gap (the seed pads
    // to inode.size before applying the write).
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "sparse.bin");
        std::fs::write(&f, b"head").unwrap();
        let mut fh = OpenOptions::new().write(true).open(&f).unwrap();
        fh.seek(SeekFrom::Start(20)).unwrap();
        fh.write_all(b"tail").unwrap();
        drop(fh);
        let data = std::fs::read(&f).unwrap();
        assert_eq!(data.len(), 24);
        assert_eq!(&data[..4], b"head");
        assert!(data[4..20].iter().all(|&b| b == 0), "gap is zero-filled");
        assert_eq!(&data[20..], b"tail");
    });
}

#[test]
fn real_large_multiblock_roundtrip() {
    // A file spanning multiple upload chunks round-trips byte-for-byte through real
    // syscalls (chunking + reassembly across the transport).
    let Some(m) = mount() else { return };
    watchdog(60, m.path(), || {
        let f = at(&m, "large.bin");
        let mut data = Vec::with_capacity(2_000_000);
        for i in 0..2_000_000u32 {
            data.push((i % 251) as u8);
        }
        std::fs::write(&f, &data).unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().len(), data.len() as u64);
        let read = std::fs::read(&f).unwrap();
        assert_eq!(read, data, "multi-block content round-trips exactly");
    });
}

#[test]
fn real_rename_over_existing() {
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let a = at(&m, "src.txt");
        let b = at(&m, "dst.txt");
        std::fs::write(&a, b"source").unwrap();
        std::fs::write(&b, b"old destination").unwrap();
        std::fs::rename(&a, &b).unwrap();
        assert!(!a.exists(), "source gone after rename");
        assert_eq!(std::fs::read(&b).unwrap(), b"source");
    });
}

#[test]
fn real_unlink_and_mkdir_readdir() {
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        // mkdir + nested file, readdir sees it.
        let d = at(&m, "dir");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("inside.txt"), b"x").unwrap();
        let names: Vec<String> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["inside.txt"]);

        // unlink removes the file.
        let f = at(&m, "doomed.txt");
        std::fs::write(&f, b"bye").unwrap();
        assert!(f.exists());
        std::fs::remove_file(&f).unwrap();
        assert!(!f.exists());
    });
}

#[test]
fn real_append_extends_file() {
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "log.txt");
        std::fs::write(&f, b"line1\n").unwrap();
        let mut fh = OpenOptions::new().append(true).open(&f).unwrap();
        fh.write_all(b"line2\n").unwrap();
        drop(fh);
        assert_eq!(std::fs::read(&f).unwrap(), b"line1\nline2\n");
    });
}

#[test]
fn real_getattr_size_visible_mid_write() {
    // While a handle is open and dirty, stat must reflect the in-flight size (the
    // getattr inflight-overlay), even before release persists it.
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "growing.bin");
        let mut fh = File::create(&f).unwrap();
        fh.write_all(&vec![0x7u8; 5000]).unwrap();
        fh.flush().unwrap();
        // stat the path (separate getattr) sees at least the written size.
        let sz = std::fs::metadata(&f).unwrap().len();
        assert!(sz >= 5000, "in-flight size visible via stat: {sz}");
        drop(fh);
        assert_eq!(std::fs::read(&f).unwrap().len(), 5000);
    });
}

#[test]
fn real_cpu_runaway_soak_many_files() {
    // CPU-runaway guard: a bounded soak (many small files + one large file) must
    // finish well within the watchdog. If any operation spun or blew up memory, the
    // watchdog force-unmounts and this fails fast instead of hanging CI.
    let Some(m) = mount() else { return };
    watchdog(90, m.path(), || {
        for i in 0..200 {
            let f = at(&m, &format!("soak-{i}.dat"));
            std::fs::write(&f, format!("file number {i}").as_bytes()).unwrap();
        }
        // Read a sample back.
        assert_eq!(
            std::fs::read(at(&m, "soak-137.dat")).unwrap(),
            b"file number 137"
        );
        // One larger file in the same session.
        let big = at(&m, "soak-big.bin");
        std::fs::write(&big, vec![0xABu8; 1_500_000]).unwrap();
        assert_eq!(std::fs::metadata(&big).unwrap().len(), 1_500_000);
    });
}

// ---- Transport-boundary secrecy ------------------------------------------
//
// The README's headline claim is "Telegram holds ciphertext only, never keys."
// That property held by construction and by code inspection, but nothing
// asserted it AT THE TRANSPORT BOUNDARY — so a future refactor that uploaded a
// plaintext buffer (an `unwrap_or(data)` fallback, a debug path, a
// wrong-variable slip) would have broken the product's central promise while
// every existing test stayed green.
//
// This closes that: it writes through a REAL kernel FUSE mount and then inspects
// the exact bytes the transport received.

/// Plaintext written through a real mount must never appear in what is uploaded.
#[test]
fn uploaded_bytes_never_contain_the_plaintext() {
    let Some(m) = mount() else { return };
    watchdog(60, m.path(), || {
        // A distinctive, incompressible-looking marker: if this sequence shows up
        // in an uploaded blob, plaintext escaped.
        let marker: &[u8] = b"TEAGARDEN-PLAINTEXT-CANARY-9f3a1c7e-DO-NOT-UPLOAD";
        let mut plaintext = Vec::new();
        while plaintext.len() < 64 * 1024 {
            plaintext.extend_from_slice(marker);
        }

        let f = at(&m, "canary.bin");
        std::fs::write(&f, &plaintext).expect("write through the mount");
        // Read back so the write path has definitely completed end-to-end.
        assert_eq!(
            std::fs::read(&f).unwrap(),
            plaintext,
            "round-trip must be exact"
        );

        // Force the upload: blocks are sealed and uploaded on release.
        drop(std::fs::File::open(&f).unwrap());
        for _ in 0..100 {
            if m.transport.message_count() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let n = m.transport.message_count();
        assert!(n > 0, "expected at least one uploaded block; got {n}");

        // THE ASSERTION: no uploaded blob may contain the marker, and none may
        // equal the plaintext.
        let mut checked = 0usize;
        for msg_id in 1..=(n as i64 + 8) {
            let Some(raw) = m.transport.get_raw(msg_id) else {
                continue;
            };
            checked += 1;
            assert!(
                !raw.windows(marker.len()).any(|w| w == marker),
                "message {msg_id}: PLAINTEXT MARKER FOUND IN UPLOADED BYTES — \
                 the transport received unencrypted data ({} bytes)",
                raw.len()
            );
            assert_ne!(
                raw.as_slice(),
                plaintext.as_slice(),
                "message {msg_id}: uploaded bytes are byte-identical to the plaintext"
            );
        }
        assert!(checked > 0, "no uploaded blobs were actually inspected");
        eprintln!("transport-boundary check: {checked} uploaded blob(s) inspected, no plaintext");
    });
}

/// Uploaded document filenames must not leak content or role either.
#[test]
fn uploaded_filenames_do_not_leak_the_file_name() {
    let Some(m) = mount() else { return };
    watchdog(60, m.path(), || {
        let secret_name = "quarterly-layoffs-confidential.txt";
        std::fs::write(at(&m, secret_name), vec![0xABu8; 32 * 1024]).unwrap();
        for _ in 0..100 {
            if m.transport.message_count() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        for name in m.transport.uploaded_filenames() {
            assert!(
                !name.contains("quarterly")
                    && !name.contains("layoffs")
                    && !name.contains("confidential"),
                "uploaded document name leaked the user's filename: {name}"
            );
        }
    });
}

// ---- Data-path regression tests (fuse-fixes brief). Each drives the kernel ↔
// FUSE ↔ CryptFs path through real syscalls or real binaries (`cp`, `sh`). ----

use std::os::unix::fs::FileExt;
use std::os::unix::io::IntoRawFd;

/// Deterministic pseudo-random payload (incompressible enough, byte-exact checks).
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

/// `close(2)` a file and return its result (`std::fs::File`'s drop ignores errors,
/// which is exactly the signal these tests need).
fn close_fd(f: File) -> std::io::Result<()> {
    let fd = f.into_raw_fd();
    if unsafe { libc::close(fd) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn arm_upload_failure(m: &Mount, on: bool) {
    *m.transport.fail_uploads.lock().unwrap() = on.then(|| "injected upload failure".to_string());
}

/// C2, user level: when the block upload fails, `cp` into the mount must exit
/// non-zero with an I/O error (it used to exit 0 and silently lose the file),
/// and with the transport healthy `cp` must round-trip byte-exact. Run on both
/// the inline and the upload-queue write paths.
fn c2_cp_reports_upload_failure(upload_queue: bool) {
    let Some(m) = mount_with(upload_queue) else {
        return;
    };
    let src_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("src.bin");
    let data = payload(1_300_000, 7); // > 2 upload chunks
    std::fs::write(&src, &data).unwrap();
    watchdog(60, m.path(), || {
        arm_upload_failure(&m, true);
        let out = std::process::Command::new("cp")
            .arg(&src)
            .arg(at(&m, "failed.bin"))
            .output()
            .unwrap();
        arm_upload_failure(&m, false);
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!(
            "[queue={upload_queue}] cp with failing transport: status={:?} stderr={stderr:?}",
            out.status.code()
        );
        assert!(
            !out.status.success(),
            "cp must fail when the upload fails; it exited 0"
        );
        assert!(
            stderr.contains("Input/output error"),
            "cp must report an I/O error, got: {stderr:?}"
        );

        let out = std::process::Command::new("cp")
            .arg(&src)
            .arg(at(&m, "ok.bin"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "cp with a healthy transport: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read(at(&m, "ok.bin")).unwrap(),
            data,
            "happy path is byte-exact"
        );
        let cmp = std::process::Command::new("cmp")
            .arg(&src)
            .arg(at(&m, "ok.bin"))
            .status()
            .unwrap();
        assert!(cmp.success(), "cmp(1) agrees the copy is byte-exact");
    });
}

#[test]
fn real_c2_cp_reports_upload_failure_inline_path() {
    c2_cp_reports_upload_failure(false);
}

#[test]
fn real_c2_cp_reports_upload_failure_upload_queue_path() {
    c2_cp_reports_upload_failure(true);
}

/// C2: close(2) returns EIO on a failed upload, and the dirty data is NOT dropped
/// while another descriptor still has the file open: once the transport recovers,
/// closing the remaining descriptor persists the full content.
#[test]
fn real_c2_failed_close_keeps_data_while_file_still_open() {
    let Some(m) = mount() else { return };
    watchdog(60, m.path(), || {
        let f = at(&m, "kept.bin");
        let data = payload(200_000, 3);
        let fh = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&f)
            .unwrap();
        fh.write_all_at(&data, 0).unwrap();
        let dup = fh.try_clone().unwrap();

        arm_upload_failure(&m, true);
        let first = close_fd(fh);
        arm_upload_failure(&m, false);
        eprintln!("close(2) with failing transport: {first:?}");
        let err = first.expect_err("close(2) must report the failed upload");
        assert_eq!(err.raw_os_error(), Some(libc::EIO), "errno: {err}");

        close_fd(dup).expect("close(2) of the remaining fd after recovery");
        assert_eq!(std::fs::read(&f).unwrap(), data, "no data was dropped");
    });
}

/// Shell redirection opens O_TRUNC once and each child flushes on exit; the second
/// child's write must land after (not over) the first child's persisted bytes.
#[test]
fn real_shell_redirect_sequential_writers_keep_all_output() {
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "redir.txt");
        std::fs::write(&f, b"previous content that is longer").unwrap();
        let st = std::process::Command::new("sh")
            .arg("-c")
            .arg("( /bin/echo a; /bin/echo b ) > \"$1\"")
            .arg("sh")
            .arg(&f)
            .status()
            .unwrap();
        assert!(st.success());
        assert_eq!(std::fs::read(&f).unwrap(), b"a\nb\n");
    });
}

/// H1, user level: write → fsync → ftruncate(0) → write "B" → close → reopen must
/// read exactly "B" (it used to resurrect the pre-truncate bytes).
#[test]
fn real_h1_fsync_truncate_write_does_not_resurrect() {
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "h1.bin");
        let fh = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&f)
            .unwrap();
        fh.write_all_at(&[0x5Au8; 64], 0).unwrap();
        fh.sync_all().unwrap();
        fh.set_len(0).unwrap();
        fh.write_all_at(b"B", 0).unwrap();
        close_fd(fh).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"B");
    });
}

/// M3, user level: two descriptors on one file write disjoint ranges; after both
/// close, a fresh open must see both writes (it used to be last-close-wins).
#[test]
fn real_m3_two_descriptors_one_file_both_writes_survive() {
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "m3.bin");
        std::fs::write(&f, b"").unwrap();
        let a = OpenOptions::new().read(true).write(true).open(&f).unwrap();
        let b = OpenOptions::new().read(true).write(true).open(&f).unwrap();
        a.write_all_at(b"AAAA", 0).unwrap();
        b.write_all_at(b"BBBB", 4).unwrap();
        close_fd(a).unwrap();
        close_fd(b).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"AAAABBBB");
    });
}

#[cfg(target_os = "linux")]
fn renameat2(from: &Path, to: &Path, flags: libc::c_uint) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(from.as_os_str().as_bytes()).unwrap();
    let to = std::ffi::CString::new(to.as_os_str().as_bytes()).unwrap();
    let r = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            flags,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// renameat2 flags at the user surface (audit finding H2). The daemon honours
/// RENAME_NOREPLACE and refuses RENAME_EXCHANGE / WHITEOUT / unknown flags with
/// EINVAL (it used to ignore `flags`, so EXCHANGE deleted the target). In the
/// default build the FUSE protocol fuser negotiates (ABI 7.18, no `abi-7-23`
/// feature) predates RENAME2, so the kernel itself refuses flagged renames with
/// EINVAL and the VFS answers NOREPLACE onto an existing name with EEXIST; with
/// `--features fuser/abi-7-23` the flags reach the daemon and this test exercises
/// its handling. Either way the target must never be destroyed.
#[cfg(target_os = "linux")]
#[test]
fn real_rename_flags_never_destroy_the_target() {
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let a = at(&m, "xa.txt");
        let b = at(&m, "xb.txt");
        std::fs::write(&a, b"content of a").unwrap();
        std::fs::write(&b, b"content of b").unwrap();

        let r = renameat2(&a, &b, libc::RENAME_EXCHANGE);
        eprintln!("renameat2(RENAME_EXCHANGE) -> {r:?}");
        assert!(
            r.is_err(),
            "RENAME_EXCHANGE is not supported; it must not succeed"
        );
        assert_eq!(std::fs::read(&a).unwrap(), b"content of a");
        assert_eq!(std::fs::read(&b).unwrap(), b"content of b");

        let r = renameat2(&a, &b, libc::RENAME_NOREPLACE);
        eprintln!("renameat2(RENAME_NOREPLACE, existing) -> {r:?}");
        assert_eq!(
            r.as_ref().map_err(|e| e.raw_os_error()),
            Err(Some(libc::EEXIST))
        );
        assert_eq!(std::fs::read(&a).unwrap(), b"content of a");
        assert_eq!(std::fs::read(&b).unwrap(), b"content of b");

        // NOREPLACE onto a free name: either the rename happens, or (this ABI) the
        // kernel refuses it with EINVAL — and then nothing moved.
        let c = at(&m, "xc.txt");
        match renameat2(&a, &c, libc::RENAME_NOREPLACE) {
            Ok(()) => {
                assert!(!a.exists());
                assert_eq!(std::fs::read(&c).unwrap(), b"content of a");
            }
            Err(e) => {
                eprintln!("renameat2(RENAME_NOREPLACE, free name) -> {e:?}");
                assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
                assert_eq!(std::fs::read(&a).unwrap(), b"content of a");
                assert!(!c.exists());
            }
        }
    });
}

/// M6, user level: a pwrite at a 1 TiB offset is EFBIG and the daemon survives
/// (it used to try to allocate 1 TiB and abort the mount). NOTE: on the unfixed
/// code this aborts the whole test process, so its red run is the in-process
/// `m6_*` unit tests.
#[test]
fn real_m6_huge_offset_pwrite_is_efbig_and_mount_survives() {
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let f = at(&m, "huge.bin");
        let fh = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&f)
            .unwrap();
        let err = fh.write_at(b"x", 1u64 << 40).unwrap_err();
        eprintln!("pwrite at 1 TiB -> {err}");
        assert_eq!(err.raw_os_error(), Some(libc::EFBIG));
        let err = fh.set_len(1u64 << 40).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EFBIG));
        fh.write_all_at(b"still alive", 0).unwrap();
        close_fd(fh).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"still alive");
    });
}

/// Inode-number reuse, user level: keep A open, unlink A, create B (which gets
/// A's inode number), then write and read through A's descriptor. The stale
/// descriptor must fail, and B must be unaffected (it used to receive A's write
/// at close and serve B's bytes to A's reader).
#[test]
fn real_stale_fd_after_unlink_cannot_touch_file_that_reused_the_inode() {
    use std::os::unix::fs::MetadataExt;
    let Some(m) = mount() else { return };
    watchdog(30, m.path(), || {
        let a = at(&m, "a.bin");
        let b = at(&m, "b.bin");
        std::fs::write(&a, b"content of a").unwrap();
        let fd_a = OpenOptions::new().read(true).write(true).open(&a).unwrap();
        let ino_a = fd_a.metadata().unwrap().ino();
        std::fs::remove_file(&a).unwrap();
        std::fs::write(&b, b"content of b").unwrap();
        let ino_b = std::fs::metadata(&b).unwrap().ino();
        assert_eq!(ino_a, ino_b, "precondition: B reused A's inode number");

        let w = fd_a.write_at(b"EVIL", 0);
        let mut buf = [0u8; 64];
        let r = fd_a.read_at(&mut buf, 0);
        eprintln!("stale fd: write -> {w:?}, read -> {r:?}");
        let c = close_fd(fd_a);
        eprintln!("stale fd: close -> {c:?}");
        assert!(
            w.is_err(),
            "a write through the deleted file's fd must fail"
        );
        assert!(
            r.is_err(),
            "a read through the deleted file's fd must not serve B's bytes"
        );
        assert_eq!(std::fs::read(&b).unwrap(), b"content of b", "B unaffected");
    });
}

#[test]
fn real_sdo_mount_refuses_symlink_creation() {
    let Some(m) = mount_with_format(false, true) else {
        return;
    };
    watchdog(30, m.path(), || {
        let error = std::os::unix::fs::symlink("target", m.path().join("link"))
            .expect_err("TGFV symlinks must not be acknowledged");
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::EPERM) | Some(libc::ENOTSUP)
        ));
        assert!(m.path().join("link").symlink_metadata().is_err());
    });
}

#[test]
fn real_sdo_mount_directory_attributes_are_portable_or_refused() {
    use std::os::unix::fs::PermissionsExt;
    let Some(m) = mount_with_format(false, true) else {
        return;
    };
    watchdog(30, m.path(), || {
        let path = m.path().join("directory");
        std::fs::create_dir(&path).unwrap();
        let directory = std::fs::File::open(&path).unwrap();
        let error = directory
            .set_times(std::fs::FileTimes::new().set_accessed(std::time::UNIX_EPOCH))
            .expect_err("portable directory atime must be refused");
        assert_eq!(error.raw_os_error(), Some(libc::ENOTSUP));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut persisted = false;
        for id in 1..=m.transport.message_count() as i64 {
            if let Some(wire) = m.transport.get_raw(id) {
                if wire.starts_with(b"TGFV") {
                    let object = teagarden_core::sdo::SdoFileObjectV3::decode(
                        &wire,
                        uuid::Uuid::from_bytes([0x61; 16]),
                        0,
                        &SymmetricKey::from_bytes([0x43; 32]),
                    )
                    .unwrap();
                    persisted |= object.metadata.path.as_deref() == Some("directory")
                        && object.metadata.mode & 0o777 == 0o700;
                }
            }
        }
        assert!(
            persisted,
            "portable directory mode must be published as a TGFV record"
        );
    });
}

#[test]
fn real_large_dirty_spool_can_shrink_and_fsync_without_an_obsolete_hash_error() {
    let Some(m) = mount() else {
        return;
    };
    watchdog(60, m.path(), || {
        let path = m.path().join("shrink-after-write");
        std::fs::write(&path, b"before").unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let bytes = vec![0x53; 64 * 1024 * 1024];
        file.write_all(&bytes).unwrap();
        file.set_len(11).unwrap();
        file.sync_all()
            .expect("a superseded old-length hash must not fail fsync");
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), bytes[..11]);
    });
}

fn process_write_counters() -> (u64, u64) {
    let Ok(text) = std::fs::read_to_string("/proc/self/io") else {
        return (0, 0);
    };
    let value = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|n| n.trim().parse().ok())
            .unwrap_or(0)
    };
    (value("wchar:"), value("write_bytes:"))
}

/// A normal cp closes once: there must be one complete portable version, one
/// upload, no duplicated payload bytes and bounded parallel MTProto parts.
#[test]
fn real_sdo_large_cp_uploads_one_version_once_with_parallel_parts() {
    let Some(m) = mount_with_audit(false, true, true) else {
        return;
    };
    m.transport.record_file_parts(Duration::ZERO);
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("source.bin");
    let bytes = payload(100 * 1024 * 1024, 71);
    std::fs::write(&source, &bytes).unwrap();
    watchdog(3600, m.path(), || {
        let io_before = process_write_counters();
        let start = std::time::Instant::now();
        let output = std::process::Command::new("cp")
            .args(["--reflink=never", "--sparse=never"])
            .arg(&source)
            .arg(m.path().join("large.bin"))
            .output()
            .unwrap();
        let elapsed = start.elapsed();
        let io_after = process_write_counters();
        eprintln!(
            "LARGE_CP_PROCESS_IO wchar_delta={} storage_write_delta={}",
            io_after.0.saturating_sub(io_before.0),
            io_after.1.saturating_sub(io_before.1)
        );
        assert!(
            output.status.success(),
            "cp failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut versions = Vec::new();
        let mut wire_bytes = 0;
        let mut content_matches = true;
        for id in 1..=m.transport.message_count() as i64 {
            let wire = m.transport.get_raw(id).unwrap();
            if wire.starts_with(b"TGFV") {
                let object = teagarden_core::sdo::SdoFileObjectV3::decode(
                    &wire,
                    uuid::Uuid::from_bytes([0x61; 16]),
                    0,
                    &SymmetricKey::from_bytes([0x43; 32]),
                )
                .unwrap();
                if object.metadata.path.as_deref() == Some("large.bin") {
                    assert!(
                        object.metadata.authority.is_some(),
                        "normal saves are installation-signed"
                    );
                    let envelope = teagarden_core::sdo::ObjectEnvelope::parse(&wire)
                        .unwrap()
                        .expect("normal saves carry a credential envelope");
                    assert_eq!(&envelope.header_wire[..6], b"TGHD\x02\0");
                    content_matches &= object.content == bytes;
                    versions.push(object.metadata.version_id);
                    wire_bytes += wire.len();
                }
            }
        }
        let (calls, uploaded, parts, peak) = m.transport.file_upload_metrics();
        let audit = Connection::open(m._dir.path().join("audit.db")).unwrap();
        let pending_bytes = audit
            .query_row("SELECT n FROM pending_byte_audit", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap() as u64;
        eprintln!("LARGE_CP_MOCK plaintext={} elapsed_s={:.3} mib_s={:.3} versions={} uploads={calls} wire_bytes={uploaded} parts={parts} peak_parts={peak} pending_encoded_bytes={pending_bytes}",
            bytes.len(),elapsed.as_secs_f64(),100.0/elapsed.as_secs_f64(),versions.len());
        assert_eq!(versions.len(), 1, "one cp publishes one version");
        assert!(
            content_matches,
            "the published content must match the complete source"
        );
        assert_eq!(calls, 1, "one upload, including attempts");
        assert_eq!(uploaded, wire_bytes, "no payload re-upload amplification");
        assert_eq!(parts, uploaded.div_ceil(512 * 1024));
        assert!(
            pending_bytes < bytes.len() as u64 * 8,
            "pending storage must have linear byte cost: {pending_bytes}"
        );
        assert!(
            (16..=32).contains(&peak),
            "parts must overlap with a bounded window: {peak}"
        );
        assert_eq!(pending_bytes, 0, "no payload copies in SQLite");
        let (payload_written, intent_written) = m.transport.local_write_bytes().unwrap();
        assert_eq!(
            payload_written,
            bytes.len() as u64 + (bytes.len() as u64).div_ceil(64 * 1024) * 40,
            "sole encrypted spool: plaintext length plus one nonce/tag per 64 KiB block"
        );
        assert!(
            intent_written < 64 * 1024,
            "small intent and offset records only"
        );
        eprintln!("LARGE_CP_LOCAL_WRITES payload={payload_written} intent_and_offsets={intent_written} total={}",payload_written+intent_written);
        let before_read = m.transport.bytes_served();
        let read_start = std::time::Instant::now();
        let read = std::fs::read(m.path().join("large.bin")).unwrap();
        let read_elapsed = read_start.elapsed();
        assert_eq!(read, bytes);
        let read_bytes = m.transport.bytes_served() - before_read;
        eprintln!("LARGE_CP_LOCAL_CEILING write_mib_s={:.3} read_mib_s={:.3} read_wire_bytes={read_bytes} write_s={:.6} read_s={:.6}",100.0/elapsed.as_secs_f64(),100.0/read_elapsed.as_secs_f64(),elapsed.as_secs_f64(),read_elapsed.as_secs_f64());
        assert!(
            read_bytes >= bytes.len() as u64,
            "read must reach the cold mock transport"
        );
        assert!(
            read_bytes < (bytes.len() + 1024 * 1024) as u64,
            "bounded range reads must not duplicate segments"
        );
    });
}

#[test]
fn real_sdo_cp_overwrite_and_empty_close_publish_one_version_per_save() {
    let Some(m) = mount_with_format(false, true) else {
        return;
    };
    let src_dir = tempfile::tempdir().unwrap();
    let source = src_dir.path().join("source");
    std::fs::write(&source, payload(1024 * 1024, 17)).unwrap();
    watchdog(120, m.path(), || {
        let destination = m.path().join("file");
        for expected in 1..=2 {
            let output = std::process::Command::new("cp")
                .args(["--reflink=never", "--sparse=never"])
                .arg(&source)
                .arg(&destination)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let records: Vec<_> = (1..=m.transport.message_count() as i64)
                .filter_map(|id| {
                    let wire = m.transport.get_raw(id)?;
                    let object = teagarden_core::sdo::SdoFileObjectV3::decode(
                        &wire,
                        uuid::Uuid::from_bytes([0x61; 16]),
                        0,
                        &SymmetricKey::from_bytes([0x43; 32]),
                    )
                    .ok()?;
                    Some((
                        object.metadata.size,
                        object.metadata.local_version,
                        object.metadata.mode,
                    ))
                })
                .collect();
            assert_eq!(
                m.transport.file_upload_metrics().0,
                expected,
                "one upload per new/overwrite cp; records={records:?}"
            );
            assert_eq!(
                std::fs::read(&destination).unwrap(),
                std::fs::read(&source).unwrap()
            );
        }
        std::fs::File::create(m.path().join("empty")).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while m.transport.file_upload_metrics().0 < 3 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            m.transport.file_upload_metrics().0,
            3,
            "empty create publishes on close"
        );
        std::fs::File::create(&destination).unwrap();
        assert_eq!(
            m.transport.file_upload_metrics().0,
            4,
            "O_TRUNC without writes publishes an empty successor"
        );
        assert!(std::fs::read(&destination).unwrap().is_empty());
    });
}

fn redirect_versions(m: &Mount) -> Vec<teagarden_core::sdo::SdoFileObjectV3> {
    (1..=m.transport.message_count() as i64)
        .filter_map(|id| {
            let wire = m.transport.get_raw(id)?;
            teagarden_core::sdo::SdoFileObjectV3::decode(
                &wire,
                uuid::Uuid::from_bytes([0x61; 16]),
                0,
                &SymmetricKey::from_bytes([0x43; 32]),
            )
            .ok()
        })
        .collect()
}

// Reconstruct a fresh index from Telegram, then mount it with no warm local state.
fn remount_portable(m: &mut Mount) {
    m.session.take();
    force_unmount(&m.mountpoint);
    let conn = Connection::open_in_memory().unwrap();
    let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
    initialize_database(&conn, &schema).unwrap();
    let key = SymmetricKey::from_bytes([0x43; 32]);
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let mut root = Inode::root();
    root.uid = uid;
    root.gid = gid;
    InodeStore::new(&conn, &schema, &key).insert(&root).unwrap();
    let mut fs = CryptFs::new(
        conn,
        schema,
        key,
        SymmetricKey::from_bytes([0x44; 32]),
        uid,
        gid,
    )
    .with_manifest_key(SymmetricKey::from_bytes([0x47; 32]))
    .with_transport(m.transport.clone())
    .with_runtime(m._rt.handle().clone())
    .with_sdo(
        uuid::Uuid::from_bytes([0x61; 16]),
        uuid::Uuid::from_bytes([0x62; 16]),
    );
    let documents = (1..=m.transport.message_count() as i64)
        .filter_map(|id| m.transport.get_raw(id).map(|wire| (id, wire)))
        .collect();
    fs.apply_remote_sdo_batch(documents, 0).unwrap();
    m.session = Some(fuser::spawn_mount2(fs, &m.mountpoint, &[]).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn real_portable_rename_replays_open_descriptor_writes() {
    let Some(mut m) = mount_with_format(false, true) else {
        return;
    };
    let original = m.path().join("before");
    let renamed = m.path().join("after");
    watchdog(30, m.path(), || {
        std::fs::write(&original, b"original file").unwrap();
        let mut file = OpenOptions::new().write(true).open(&original).unwrap();
        file.write_all(b"pending").unwrap();
        std::fs::rename(&original, &renamed).unwrap();
        assert_eq!(std::fs::read(&renamed).unwrap(), b"pendingl file");
        file.seek(SeekFrom::Start(8)).unwrap();
        file.write_all(b"data").unwrap();
        file.sync_all().unwrap();
    });
    remount_portable(&mut m);
    assert!(!original.exists());
    assert_eq!(std::fs::read(renamed).unwrap(), b"pendingldatae");
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_b_crash_child() {
    let Some(root) = std::env::var_os("TEAGARDEN_TEST_RECOVERY_B_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let m = mount_with_recovery_root(false, true, true, Some(&root)).unwrap();
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(m.path().join("unfinished"))
        .unwrap();
    if std::env::var_os("TEAGARDEN_TEST_EMPTY_RELEASE_PAUSE").is_some() {
        use std::os::{fd::IntoRawFd, unix::fs::MetadataExt};
        let connection = libc::minor(std::fs::metadata(m.path()).unwrap().dev());
        std::fs::write(
            root.join("release-checkpoint"),
            format!("{}\n{}", m.path().display(), connection),
        )
        .unwrap();
        assert_eq!(unsafe { libc::close(f.into_raw_fd()) }, 0);
        std::fs::write(root.join("closed"), b"successful close").unwrap();
        loop {
            std::thread::park();
        }
    }
    f.write_all(b"uncommitted pending content").unwrap();
    if std::env::var_os("TEAGARDEN_TEST_RECOVERY_B_CORRUPT").is_some() {
        use std::os::unix::fs::FileExt;
        m.transport.fail_file_part_once(0);
        assert!(f.sync_all().is_err());
        let payload = std::fs::read_dir(root.join("write-spools"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "spool"))
            .unwrap();
        OpenOptions::new()
            .write(true)
            .open(payload)
            .unwrap()
            .write_all_at(&[0xff; 24], 0)
            .unwrap();
    }
    use std::os::unix::fs::MetadataExt;
    let connection = libc::minor(std::fs::metadata(m.path()).unwrap().dev());
    std::fs::write(
        root.join("ready"),
        format!("{}\n{}", m.path().display(), connection),
    )
    .unwrap();
    unsafe {
        libc::raise(libc::SIGSTOP);
    }
    panic!("parent must kill the writer before close");
}

#[cfg(target_os = "linux")]
fn killed_pending_remount(corrupt: bool) {
    killed_pending_remount_mode(corrupt, false);
}

#[cfg(target_os = "linux")]
fn killed_pending_remount_mode(corrupt: bool, empty: bool) {
    use std::process::{Command, Stdio};
    if !fuse_available() {
        assert!(!require_fuse());
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "recovery_b_crash_child", "--nocapture"])
        .env("TEAGARDEN_TEST_RECOVERY_B_ROOT", root.path())
        .stdout(Stdio::null());
    if corrupt {
        command.env("TEAGARDEN_TEST_RECOVERY_B_CORRUPT", "1");
    }
    if empty {
        command.env("TEAGARDEN_TEST_EMPTY_RELEASE_PAUSE", "1");
    }
    let mut child = command.spawn().unwrap();
    let ready = root.path().join("ready");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !ready.exists() && std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("writer exited: {status}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    assert!(ready.exists(), "writer must reach crash checkpoint");
    let checkpoint = std::fs::read_to_string(ready).unwrap();
    let (old_mount, connection) = checkpoint.split_once('\n').unwrap();
    std::fs::write(format!("/sys/fs/fuse/connections/{connection}/abort"), b"1").unwrap();
    // Detach the dead daemon before reaping its threads: closing its own open
    // FUSE file can otherwise wait on the daemon being reaped.
    let status = std::process::Command::new("fusermount3")
        .args(["-uz", old_mount])
        .status()
        .unwrap();
    assert!(status.success());
    child.wait().unwrap();
    let m = mount_with_recovery_root(false, true, true, Some(root.path())).unwrap();
    if empty {
        assert!(root.path().join("closed").exists());
        assert_eq!(
            m.transport.message_count(),
            1,
            "successful empty close is owed one publication"
        );
        assert_eq!(m.transport.file_upload_metrics().0, 1);
        assert!(std::fs::read(m.path().join("unfinished"))
            .unwrap()
            .is_empty());
        assert!(!root.path().join("write-spools/quarantine").exists());
        return;
    }
    assert_eq!(
        m.transport.message_count(),
        0,
        "unsafe pending image must never publish"
    );
    assert!(m.path().is_dir(), "mount is ready");
    let quarantine = root.path().join("write-spools/quarantine");
    assert_eq!(std::fs::read_dir(&quarantine).unwrap().count(), 1);
    assert!(!std::fs::read_dir(root.path().join("write-spools"))
        .unwrap()
        .any(|e| e.unwrap().path().extension().is_some_and(|e| e == "intent")));
    std::fs::write(m.path().join("healthy"), b"other files work").unwrap();
    assert_eq!(
        std::fs::read(m.path().join("healthy")).unwrap(),
        b"other files work"
    );
}

#[test]
fn last2_recovery_upload_failure_keeps_pending_and_mounts() {
    use std::os::fd::IntoRawFd;
    if !fuse_available() {
        assert!(!require_fuse());
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let transport = Arc::new(MockTransport::new());
    *transport.fail_uploads.lock().unwrap() = Some("offline while preparing".into());
    {
        let m = mount_with_recovery_transport(
            false,
            true,
            true,
            Some(root.path()),
            Some(transport.clone()),
        )
        .unwrap();
        watchdog(30, m.path(), || {
            for (name, content) in [("first", "one"), ("second", "two")] {
                let mut file = std::fs::File::create(m.path().join(name)).unwrap();
                file.write_all(content.as_bytes()).unwrap();
                assert_eq!(unsafe { libc::close(file.into_raw_fd()) }, -1);
            }
        });
    }
    let pending_count = || {
        std::fs::read_dir(root.path().join("write-spools"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "intent")
            })
            .count()
    };
    assert_eq!(pending_count(), 2);
    assert_eq!(transport.message_count(), 0);
    *transport.fail_uploads.lock().unwrap() = None;
    transport.fail_file_part_once(0);
    {
        let m = mount_with_recovery_transport(
            false,
            true,
            true,
            Some(root.path()),
            Some(transport.clone()),
        )
        .unwrap();
        assert!(
            m.path().is_dir(),
            "recovery upload failure must not block mount readiness"
        );
        assert_eq!(
            transport.message_count(),
            1,
            "the other intent is processed"
        );
        assert_eq!(pending_count(), 1, "failed valid intent stays pending");
        assert!(!root.path().join("write-spools/quarantine").exists());
    }
    {
        let m = mount_with_recovery_transport(
            false,
            true,
            true,
            Some(root.path()),
            Some(transport.clone()),
        )
        .unwrap();
        assert_eq!(
            transport.message_count(),
            2,
            "next mount retries the pending intent"
        );
        assert_eq!(pending_count(), 0);
        assert_eq!(std::fs::read(m.path().join("first")).unwrap(), b"one");
        assert_eq!(std::fs::read(m.path().join("second")).unwrap(), b"two");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn last1_empty_close_killed_before_release_publishes_once_on_remount() {
    killed_pending_remount_mode(false, true);
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_b_kill_before_flush_quarantines_and_mounts() {
    killed_pending_remount(false);
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_b_corrupt_prepared_block_quarantines_and_mounts() {
    killed_pending_remount(true);
}

#[test]
fn real_sdo_bdc1_same_fd_partial_write_after_fsync_preserves_committed_bytes() {
    use std::os::unix::fs::FileExt;
    let Some(mut m) = mount_with_format(false, true) else {
        return;
    };
    let path = m.path().join("partial");
    watchdog(30, m.path(), || {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        f.write_all(b"ABC").unwrap();
        f.sync_all().unwrap();
        f.write_all_at(b"Z", 1).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let versions = redirect_versions(&m);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[1].content, b"AZC");
    });
    remount_portable(&mut m);
    assert_eq!(std::fs::read(&path).unwrap(), b"AZC");
}

#[test]
fn recheck_a_clean_ftruncate_advances_the_pinned_descriptor() {
    use std::os::unix::fs::FileExt;
    let Some(mut m) = mount_with_format(false, true) else {
        return;
    };
    let path = m.path().join("clean-truncate");
    watchdog(30, m.path(), || {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        f.write_all(b"ABCDEF").unwrap();
        f.sync_all().unwrap();
        f.set_len(2).unwrap();
        f.write_all_at(b"Z", 1).unwrap();
        drop(f);
        assert_eq!(redirect_versions(&m).last().unwrap().content, b"AZ");
        assert_eq!(std::fs::read(&path).unwrap(), b"AZ");
    });
    remount_portable(&mut m);
    assert_eq!(std::fs::read(path).unwrap(), b"AZ");
}

#[test]
fn recheck_c_getattr_reports_the_dirty_shrunk_size() {
    use std::os::unix::fs::FileExt;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    const CHILD: &str = "TEAGARDEN_TEST_DIRTY_GETATTR_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Other tests spawn subprocesses. A child that inherits this test's
        // CLOEXEC descriptor sends FUSE FLUSH on exec, invalidating the
        // premise that the dirty spool is still unpublished before GETATTR.
        let _mount_guard = mount_lock();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recheck_c_getattr_reports_the_dirty_shrunk_size",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let Some(m) = mount_with_format(false, true) else {
        return;
    };
    watchdog(30, m.path(), || {
        let dirty_versions = || {
            redirect_versions(&m)
                .into_iter()
                .filter(|version| version.metadata.path.as_deref() == Some("dirty-size"))
                .collect::<Vec<_>>()
        };
        let assert_unpublished = |stage| {
            let versions = dirty_versions();
            assert_eq!(
                versions.len(),
                1,
                "{stage} must leave only the synchronized baseline"
            );
            assert_eq!(
                versions[0].content, b"ABCDEF",
                "{stage} changed the baseline"
            );
            versions[0].metadata.version_id
        };
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(m.path().join("dirty-size"))
            .unwrap();
        f.write_all(b"ABCDEF").unwrap();
        f.sync_all().unwrap();
        let baseline = assert_unpublished("fsync");
        f.write_all_at(b"X", 0).unwrap();
        assert_unpublished("buffered write");
        f.set_len(2).unwrap();
        assert_unpublished("dirty truncate");
        // Expire the one-second attribute cache: this must exercise GETATTR,
        // rather than reuse the correct size from the SETATTR reply.
        std::thread::sleep(Duration::from_millis(1100));
        assert_unpublished("attribute-cache expiry");
        assert_eq!(f.metadata().unwrap().len(), 2);
        assert_unpublished("GETATTR");
        // Deliberately exercise the inherited-descriptor close that this
        // isolated child avoids above. The pre-exec callback forces a fork.
        let mut unrelated = Command::new("true");
        unsafe { unrelated.pre_exec(|| Ok(())) };
        assert!(unrelated.status().unwrap().success());
        assert_eq!(
            dirty_versions().len(),
            2,
            "closing the inherited writer on exec sends FUSE FLUSH"
        );
        drop(f);
        let versions = dirty_versions();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[1].content, b"XB");
        assert_eq!(versions[1].metadata.previous_version_id, Some(baseline));
    });
}

#[test]
fn real_sdo_bdc4_ftruncate_resizes_dirty_portable_handle() {
    let Some(mut m) = mount_with_format(false, true) else {
        return;
    };
    let path = m.path().join("truncate-dirty");
    watchdog(30, m.path(), || {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        f.write_all(b"ABCDEF").unwrap();
        f.set_len(2).unwrap();
        drop(f);
        let versions = redirect_versions(&m);
        assert_eq!(
            versions.len(),
            1,
            "truncate and close publish one dirty image"
        );
        assert_eq!(versions[0].content, b"AB");
        assert_eq!(std::fs::read(&path).unwrap(), b"AB");
    });
    remount_portable(&mut m);
    assert_eq!(std::fs::read(&path).unwrap(), b"AB");
}

#[test]
fn real_sdo_redirect_dup_close_before_write_publishes_one_version() {
    use std::os::fd::{FromRawFd, IntoRawFd};
    let Some(m) = mount_with_format(false, true) else {
        return;
    };
    watchdog(30, m.path(), || {
        let original = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(m.path().join("redirect"))
            .unwrap()
            .into_raw_fd();
        let duplicate = unsafe { libc::dup(original) };
        assert!(duplicate >= 0);
        assert_eq!(unsafe { libc::close(original) }, 0);
        let mut output = unsafe { std::fs::File::from_raw_fd(duplicate) };
        assert_eq!(
            redirect_versions(&m).len(),
            0,
            "the dup's early close must not publish an unwritten create"
        );
        output.write_all(b"x").unwrap();
        assert_eq!(
            unsafe { libc::close(output.into_raw_fd()) },
            0,
            "written close must still flush synchronously"
        );
        let versions = redirect_versions(&m);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].content, b"x");
    });
}

#[test]
fn real_sdo_redirect_touch_only_publishes_one_empty_version_at_release() {
    use std::os::fd::{FromRawFd, IntoRawFd};
    let Some(m) = mount_with_format(false, true) else {
        return;
    };
    watchdog(30, m.path(), || {
        let original = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(m.path().join("touch-only"))
            .unwrap()
            .into_raw_fd();
        let duplicate = unsafe { libc::dup(original) };
        assert!(duplicate >= 0);
        assert_eq!(unsafe { libc::close(original) }, 0);
        let remaining = unsafe { std::fs::File::from_raw_fd(duplicate) };
        assert_eq!(
            redirect_versions(&m).len(),
            0,
            "an unwritten create remains staged while a dup is open"
        );
        assert_eq!(unsafe { libc::close(remaining.into_raw_fd()) }, 0);
        // RELEASE follows the last close asynchronously; wait for that event.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while redirect_versions(&m).is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let versions = redirect_versions(&m);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].metadata.size, 0);
        assert!(versions[0].content.is_empty());
    });
}
