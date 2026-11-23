//! K0b real-mount end-to-end — the advisor's "done bar": prove multi-factor
//! enforcement works through a genuine kernel ↔ FUSE ↔ CryptFs mount, not just at
//! the library layer.
//!
//! Unlike `real_mount.rs` (which hand-builds CryptFs from constant keys), these
//! tests derive the mount's key hierarchy from the REAL open path
//! (`mfa::unlock::open_volume`), so the whole K0b chain is exercised:
//!   factor unlock → MK-rooted hierarchy → real mount → file round-trip.
//!
//! Proven here on a real mount:
//!   - a **protected** (MK-rooted) volume opens ONLY with a valid factor (a bare
//!     password fails closed at the core chokepoint; no factor at all fails), and
//!     once opened its filesystem round-trips a file through real syscalls;
//!   - a **legacy** password-rooted volume still opens + mounts unchanged.
//!
//! FUSE availability is required; without `/dev/fuse` + `fusermount` the mounting
//! tests SKIP (print + return) unless `TEAGARDEN_REQUIRE_FUSE` is set.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use teagarden_core::crypto::keys::KeyHierarchy;
use teagarden_core::metadata::inode::Inode;
use teagarden_core::volume::config::VolumeConfig;
use teagarden_core::volume::manager;
use teagarden_fuse::fs::CryptFs;
use teagarden_mfa::unlock::{self, create_protected_volume, UnlockInputs};
use teagarden_store::inode_store::InodeStore;
use teagarden_store::migrations::initialize_database;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::schema::logical_tables;
use teagarden_telegram::mock::MockTransport;

const PW: &[u8] = b"correct-horse-battery-staple";

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists() && (which("fusermount3") || which("fusermount"))
}
fn require_fuse() -> bool {
    std::env::var_os("TEAGARDEN_REQUIRE_FUSE").is_some()
}
fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(bin).exists()))
        .unwrap_or(false)
}
fn force_unmount(mp: &Path) {
    for bin in ["fusermount3", "fusermount"] {
        let _ = std::process::Command::new(bin).arg("-u").arg(mp).output();
    }
}
fn mount_lock() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct Mount {
    mountpoint: PathBuf,
    session: Option<fuser::BackgroundSession>,
    _rt: tokio::runtime::Runtime,
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
        self.session.take();
        force_unmount(&self.mountpoint);
    }
}

/// Mount a real FUSE filesystem whose keys come from `hierarchy` (as produced by
/// `mfa::unlock::open_volume`) over a fresh in-memory DB + `MockTransport`. This
/// is the same CryptFs wiring the CLI `volume mount` builds from `result.hierarchy`.
fn mount_with_hierarchy(hierarchy: &KeyHierarchy, config: &VolumeConfig) -> Option<Mount> {
    if !fuse_available() {
        assert!(
            !require_fuse(),
            "TEAGARDEN_REQUIRE_FUSE set but FUSE unavailable"
        );
        eprintln!("SKIP: /dev/fuse or fusermount not available");
        return None;
    }
    let guard = mount_lock();

    let conn = Connection::open_in_memory().unwrap();
    let schema = OpaqueSchema::new(hierarchy.schema.clone(), &logical_tables());
    initialize_database(&conn, &schema).unwrap();
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    {
        let mut root = Inode::root();
        root.uid = uid;
        root.gid = gid;
        InodeStore::new(&conn, &schema, &hierarchy.meta)
            .insert(&root)
            .unwrap();
    }

    let transport = Arc::new(MockTransport::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    // EXACT mapping the CLI `volume mount` uses (volume.rs) — the only difference is
    // an in-memory DB + mock transport instead of the on-disk DB + Telegram.
    let fs = CryptFs::new(
        conn,
        schema,
        hierarchy.meta.clone(),
        hierarchy.data.clone(),
        uid,
        gid,
    )
    .with_epoch(config.current_epoch)
    .with_block_keys(hierarchy.block_id.clone(), hierarchy.filename.clone())
    .with_manifest_key(hierarchy.manifest.clone())
    .with_block_integrity(config.require_block_integrity)
    .with_block_v2_from_epoch(config.block_v2_from_epoch)
    .with_fuse_block_size(config.block_config.fuse_chunk_size())
    .with_transport(transport)
    .with_runtime(rt.handle().clone());

    let dir = tempfile::tempdir().unwrap();
    let mountpoint = dir.path().to_path_buf();
    let opts = [fuser::MountOption::FSName("teagarden-k0b".to_string())];
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
        _dir: dir,
        _guard: guard,
    })
}

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

/// A protected (MK-rooted) volume: refuses the bare-password path and the
/// no-factor path, opens with the recovery factor, and — mounted for real — round
/// trips a file through genuine syscalls.
#[test]
fn k0b_protected_volume_refuses_then_mounts_with_factor() {
    let vols = tempfile::TempDir::new().unwrap();
    let pc = create_protected_volume(Some("prot"), PW, vols.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();

    // Fail closed: the legacy bare-password chokepoint refuses a protected volume.
    assert!(
        manager::open_volume(&id, PW, vols.path()).is_err(),
        "bare password must not open a protected volume"
    );
    // No factor at all also fails.
    assert!(
        unlock::open_volume(&id, &UnlockInputs::default(), vols.path()).is_err(),
        "no factor must not open a protected volume"
    );

    // Open with the recovery factor → the REAL MK-rooted hierarchy.
    let sentence = pc.recovery_sentence.to_string();
    let opened = unlock::open_volume(
        &id,
        &UnlockInputs {
            recovery_sentence: Some(&sentence),
            ..Default::default()
        },
        vols.path(),
    )
    .expect("recovery factor must open the protected volume");

    // Sanity: the opened hierarchy is exactly what create derived.
    assert_eq!(
        opened.hierarchy.data.as_bytes(),
        pc.created.hierarchy.data.as_bytes()
    );

    // Mount it for real and round-trip a file.
    let Some(m) = mount_with_hierarchy(&opened.hierarchy, &opened.config) else {
        return;
    };
    watchdog(30, m.path(), || {
        let f = m.path().join("secret.txt");
        let payload = b"protected by a real multi-factor vault";
        std::fs::write(&f, payload).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), payload);
        assert_eq!(std::fs::metadata(&f).unwrap().len(), payload.len() as u64);
    });
}

/// A legacy password-rooted volume still opens + mounts unchanged through the same
/// entry point.
#[test]
fn k0b_legacy_volume_still_mounts() {
    let vols = tempfile::TempDir::new().unwrap();
    let created = manager::create_volume(Some("legacy"), PW, vols.path(), 0, 0, 0, None).unwrap();
    let id = created.config.volume_id.to_string();
    assert!(created.config.key_protection.is_none());

    let opened = unlock::open_volume(
        &id,
        &UnlockInputs {
            password: Some(PW),
            ..Default::default()
        },
        vols.path(),
    )
    .expect("legacy volume must open with its password");

    let Some(m) = mount_with_hierarchy(&opened.hierarchy, &opened.config) else {
        return;
    };
    watchdog(30, m.path(), || {
        let f = m.path().join("legacy.txt");
        std::fs::write(&f, b"still works").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"still works");
    });
}
