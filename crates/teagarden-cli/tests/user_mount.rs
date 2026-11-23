//! `volume mount` as an ordinary (non-root) user on a stock Linux host, through
//! the shipped binary and a real FUSE mount.
//!
//! `volume mount` used to always pass `allow_root`. `fusermount3` refuses that
//! (and `allow_other`) for a non-root user unless `/etc/fuse.conf` has
//! `user_allow_other`, which stock Linux leaves commented out, so ordinary users
//! could not mount at all. These tests prove that:
//!   - a plain mount works as this user, and the kernel mount options contain
//!     neither `allow_other` nor `allow_root`;
//!   - `--allow-other` is still honoured, or refused clearly when fuse.conf does
//!     not permit it, leaving nothing mounted;
//!   - a mount process killed with SIGKILL (now stale, since `auto_unmount`
//!     is only used with `--allow-other`) is cleared by `volume unmount`, and
//!     the volume mounts again afterwards.
//!
//! The fixture is an ordinary locally-created volume with an offline
//! read-only marker; it is mounted through the real `volume mount` command.
//! No share grant/import path or Telegram account is involved.
//!
//! Every child gets an isolated HOME, config dir and volumes dir, and no
//! Telegram credentials. `TEAGARDEN_REQUIRE_FUSE` turns a missing FUSE, or
//! running as root (which would not prove the non-root path), into a failure.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use tempfile::TempDir;

fn require_fuse() -> bool {
    std::env::var_os("TEAGARDEN_REQUIRE_FUSE").is_some()
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
        .unwrap_or(false)
}

fn uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_string))
        })
        .and_then(|u| u.parse().ok())
        .expect("read uid from /proc/self/status")
}

fn fuse_conf_allows_other() -> bool {
    std::fs::read_to_string("/etc/fuse.conf")
        .unwrap_or_default()
        .lines()
        .any(|l| l.trim() == "user_allow_other")
}

/// `true` when the test may run; panics instead of skipping under
/// `TEAGARDEN_REQUIRE_FUSE`.
fn preflight() -> bool {
    let fuse = Path::new("/dev/fuse").exists() && (on_path("fusermount3") || on_path("fusermount"));
    if !fuse {
        assert!(
            !require_fuse(),
            "TEAGARDEN_REQUIRE_FUSE set but /dev/fuse + fusermount are missing"
        );
        eprintln!("SKIP: FUSE not available");
        return false;
    }
    if uid() == 0 {
        assert!(
            !require_fuse(),
            "TEAGARDEN_REQUIRE_FUSE set but the test runs as root; it exists to prove \
             the NON-root mount path"
        );
        eprintln!("SKIP: running as root; this test proves the non-root path");
        return false;
    }
    eprintln!(
        "uid {} ; /etc/fuse.conf user_allow_other: {}",
        uid(),
        fuse_conf_allows_other()
    );
    true
}

/// One isolated "machine".
struct Side {
    volumes: TempDir,
    home: TempDir,
}

impl Side {
    fn new() -> Self {
        Self {
            volumes: TempDir::new().unwrap(),
            home: TempDir::new().unwrap(),
        }
    }

    fn apply(&self, c: &mut StdCommand) {
        c.env("TEAGARDEN_VOLUMES_DIR", self.volumes.path())
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env(
                "TEAGARDEN_CONFIG_DIR",
                self.home.path().join(".config").join("teagarden"),
            )
            .env("XDG_DATA_HOME", self.home.path().join(".local/share"))
            .env(
                "TEAGARDEN_SESSION_PATH",
                self.home.path().join("none.session"),
            )
            .env_remove("TG_API_ID")
            .env_remove("TG_API_HASH");
    }

    fn std_cmd(&self) -> StdCommand {
        #[allow(deprecated)]
        let mut c = StdCommand::new(assert_cmd::cargo::cargo_bin("teagarden"));
        self.apply(&mut c);
        c
    }

    fn cli(&self) -> Command {
        Command::from_std(self.std_cmd())
    }

    fn file(&self, name: &str, contents: &str) -> PathBuf {
        let p = self.home.path().join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }
}

/// Create an ordinary local volume, seed its local root database, and prepare a
/// read-only offline fixture. The only test-only marker is the existing local
/// read-only routing signal; no share grant or import command is involved.
fn normal_local_volume(side: &Side) -> (String, PathBuf) {
    const PASSWORD: &str = "local-volume-password";
    let created = teagarden_core::volume::manager::create_volume(
        Some("user-mount-local"),
        PASSWORD.as_bytes(),
        side.volumes.path(),
        0,
        0,
        0,
        None,
    )
    .unwrap();
    teagarden_mfa::unlock::setup_shared_recipient(
        &created.paths.base_dir,
        created.hierarchy.root.as_bytes(),
        PASSWORD.as_bytes(),
    )
    .unwrap();
    let id = created.config.volume_id.to_string();
    let password = side.file("local-volume-password.txt", PASSWORD);
    seed_volume_db(
        &created.paths.db_path,
        &created.hierarchy.schema,
        &created.hierarchy.meta,
    );

    let exported = side
        .cli()
        .args(["key", "export", &id, "--password-file"])
        .arg(&password)
        .output()
        .unwrap();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let sentence = String::from_utf8_lossy(&exported.stdout)
        .lines()
        .map(str::trim)
        .find(|line| line.split_whitespace().count() == 22)
        .expect("exported hierarchy root")
        .to_owned();
    let recovery = side.file("local-volume-root.txt", &sentence);
    teagarden_core::volume::shared::SharedOrigin {
        derivation: teagarden_core::volume::shared::SharedDerivation::HierarchyRootV1,
        access_level: "read-only".into(),
        granted_by: "local user-mount fixture".into(),
        volume_id: id.clone(),
    }
    .save(&side.volumes.path().join(&id))
    .unwrap();
    (id, recovery)
}

/// Initialize a regular local volume's encrypted metadata database with its root inode.
fn seed_volume_db(
    db_path: &Path,
    schema_key: &teagarden_core::crypto::keys::SymmetricKey,
    meta_key: &teagarden_core::crypto::keys::SymmetricKey,
) {
    use teagarden_store::opaque_schema::OpaqueSchema;
    let schema = OpaqueSchema::new(
        schema_key.clone(),
        &teagarden_store::schema::logical_tables(),
    );
    let conn = rusqlite::Connection::open(db_path).unwrap();
    teagarden_store::migrations::initialize_database(&conn, &schema).unwrap();
    teagarden_store::inode_store::InodeStore::new(&conn, &schema, meta_key)
        .insert(&teagarden_core::metadata::inode::Inode::root())
        .unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
}

/// The `/proc/mounts` line for `mp`, if mounted.
fn mount_line(mp: &Path) -> Option<String> {
    let want = mp.to_str().unwrap().to_string();
    std::fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(want.as_str()))
        .map(str::to_string)
}

fn spawn_mount(side: &Side, id: &str, mp: &Path, extra: &[&str], recovery: &Path) -> Child {
    side.std_cmd()
        .args([
            "volume",
            "mount",
            id,
            mp.to_str().unwrap(),
            "--recovery-file",
        ])
        .arg(recovery)
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn teagarden volume mount")
}

fn spawn_mount_with_password(side: &Side, id: &str, mp: &Path, password: &Path) -> Child {
    side.std_cmd()
        .args([
            "volume",
            "mount",
            id,
            mp.to_str().unwrap(),
            "--password-file",
        ])
        .arg(password)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn password-file mount")
}

/// Wait until `mp` shows in /proc/mounts; panics with the child's output if
/// the mount process exits first or nothing appears within 120 s.
fn wait_mounted(child: &mut Child, mp: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if let Some(line) = mount_line(mp) {
            return line;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let out = std::mem::replace(child, StdCommand::new("true").spawn().unwrap())
                .wait_with_output()
                .unwrap();
            panic!(
                "mount exited early ({status}):\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    panic!("mount never appeared in /proc/mounts");
}

fn volume_unmount(side: &Side, mp: &Path) -> std::process::Output {
    side.std_cmd()
        .args(["volume", "unmount", mp.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn wait_exit(child: &mut Child, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    panic!("{what}: mount process did not exit after unmount");
}

/// A plain mount as this user: works, carries no allow_other/allow_root, is
/// usable through real syscalls, and unmounts with `volume unmount`.
#[test]
fn plain_mount_works_as_a_non_root_user_with_stock_fuse_conf() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, _root_sentence) = normal_local_volume(&me);
    let mp_dir = TempDir::new().unwrap();
    let mp = mp_dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();

    // Exercise the read-only local-origin password-file unlock route on a
    // normal locally-created volume.
    let password = me.home.path().join("local-volume-password.txt");
    let mut child = spawn_mount_with_password(&me, &id, &mp, &password);
    let line = wait_mounted(&mut child, &mp);
    eprintln!("/proc/mounts: {line}");
    let opts = line.split_whitespace().nth(3).unwrap().to_string();
    assert!(line.contains("fuse.teagarden"), "{line}");
    assert!(
        !opts.contains("allow_other") && !opts.contains("allow_root"),
        "a plain mount must carry neither allow option: {opts}"
    );
    assert!(
        opts.split(',').any(|o| o == "ro"),
        "read-only local volume: {opts}"
    );

    let ls = StdCommand::new("ls").arg("-la").arg(&mp).output().unwrap();
    assert!(
        ls.status.success(),
        "readdir on the live mount failed: {}",
        String::from_utf8_lossy(&ls.stderr)
    );
    eprintln!("ls -la:\n{}", String::from_utf8_lossy(&ls.stdout));
    let write = std::fs::write(mp.join("nope.txt"), b"x");
    assert!(
        write.is_err(),
        "a read-only local volume must refuse writes"
    );

    let un = volume_unmount(&me, &mp);
    assert!(
        un.status.success(),
        "volume unmount failed: {}",
        String::from_utf8_lossy(&un.stderr)
    );
    wait_exit(&mut child, "plain mount");
    assert!(mount_line(&mp).is_none(), "still mounted after unmount");
}

/// A readable metadata database without the published snapshot's lineage stamp
/// must still be refused on an offline mount.
#[test]
fn offline_mount_of_a_normal_volume_with_an_unstamped_db_refuses() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, recovery) = normal_local_volume(&me);
    let cfg = me.volumes.path().join(&id).join("volume.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
    config["metadata_snapshot_id"] = serde_json::json!(4242);
    std::fs::write(&cfg, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let db = me.volumes.path().join(&id).join("metadata.db");
    let before = std::fs::read(&db).unwrap();
    let mp_dir = TempDir::new().unwrap();
    let mp = mp_dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();
    let mut child = spawn_mount(&me, &id, &mp, &[], &recovery);
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if mount_line(&mp).is_some() || Instant::now() > deadline {
            let _ = volume_unmount(&me, &mp);
            let _ = child.kill();
            panic!("offline mount of a readable but unstamped DB was NOT refused");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!status.success());
    assert!(
        stderr.contains("rebuilt from Telegram") && stderr.contains("no lineage stamp"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "refusal changed the readable DB"
    );
    assert!(mount_line(&mp).is_none());
}

/// `--allow-other` is passed only when asked: refused clearly (nothing left
/// mounted) when fuse.conf does not permit it, honoured when it does.
#[test]
fn allow_other_is_only_used_when_asked() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, recovery) = normal_local_volume(&me);
    let mp_dir = TempDir::new().unwrap();
    let mp = mp_dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();

    let mut child = spawn_mount(&me, &id, &mp, &["--allow-other"], &recovery);
    if fuse_conf_allows_other() {
        let line = wait_mounted(&mut child, &mp);
        assert!(line.contains("allow_other"), "{line}");
        assert!(volume_unmount(&me, &mp).status.success());
        wait_exit(&mut child, "allow-other mount");
    } else {
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("--allow-other refused: {}", stderr.trim());
        assert!(!out.status.success(), "--allow-other must fail here");
        assert!(
            stderr.contains("user_allow_other"),
            "unclear error: {stderr}"
        );
        assert!(mount_line(&mp).is_none(), "a refused mount left a mount");
    }
}

/// Killed and resumed: SIGKILL the mount process, observe the stale mount,
/// clear it with `volume unmount`, and mount the same volume again.
#[test]
fn killed_mount_is_cleared_by_volume_unmount_and_remounts() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, recovery) = normal_local_volume(&me);
    let mp_dir = TempDir::new().unwrap();
    let mp = mp_dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();

    let mut child = spawn_mount(&me, &id, &mp, &[], &recovery);
    wait_mounted(&mut child, &mp);
    child.kill().unwrap(); // SIGKILL: no signal handler runs
    child.wait().unwrap();

    let stale = mount_line(&mp);
    let access = std::fs::read_dir(&mp)
        .map(|_| ())
        .map_err(|e| e.to_string());
    eprintln!("after SIGKILL: /proc/mounts={stale:?} readdir={access:?}");
    assert!(
        stale.is_some(),
        "without auto_unmount a SIGKILLed mount stays (stale) until unmounted"
    );
    assert!(access.is_err(), "a dead mount cannot serve readdir");

    // Mounting again over the stale mount, without unmounting first, must say
    // what happened and how to clear it, and must not touch the mount.
    let over = me
        .std_cmd()
        .args([
            "volume",
            "mount",
            &id,
            mp.to_str().unwrap(),
            "--recovery-file",
        ])
        .arg(&recovery)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let over_err = String::from_utf8_lossy(&over.stderr);
    eprintln!("mount over the stale mount: {}", over_err.trim());
    assert!(
        !over.status.success(),
        "mounting over a stale mount must fail"
    );
    assert!(
        over_err.contains("stale mount") && over_err.contains("teagarden volume unmount"),
        "unclear error for a stale mountpoint: {over_err}"
    );
    assert!(
        mount_line(&mp).is_some(),
        "the refusal must leave the stale mount alone"
    );

    let un = volume_unmount(&me, &mp);
    eprintln!(
        "volume unmount of the stale mount: {}{}",
        String::from_utf8_lossy(&un.stdout),
        String::from_utf8_lossy(&un.stderr)
    );
    assert!(
        un.status.success(),
        "volume unmount must clear a stale mount"
    );
    assert!(mount_line(&mp).is_none(), "stale mount still listed");

    let mut again = spawn_mount(&me, &id, &mp, &[], &recovery);
    let line = wait_mounted(&mut again, &mp);
    eprintln!("remounted: {line}");
    assert!(
        std::fs::read_dir(&mp).is_ok(),
        "remounted volume serves readdir"
    );
    assert!(volume_unmount(&me, &mp).status.success());
    wait_exit(&mut again, "remount");
}

/// `key rotate` must refuse while the volume is FUSE-mounted (the mount holds
/// the single-writer lock for its whole lifetime), and say so.
#[test]
fn key_rotate_refuses_while_the_volume_is_mounted() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, recovery) = normal_local_volume(&me);
    let mp_dir = TempDir::new().unwrap();
    let mp = mp_dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();
    let cfg = me.volumes.path().join(&id).join("volume.json");
    let before = std::fs::read(&cfg).unwrap();

    let mut child = spawn_mount(&me, &id, &mp, &[], &recovery);
    wait_mounted(&mut child, &mp);
    let rot = me
        .std_cmd()
        .args(["key", "rotate", &id, "--recovery-file"])
        .arg(&recovery)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&rot.stderr);
    eprintln!("key rotate while mounted: {}", err.trim());
    assert!(
        !rot.status.success(),
        "key rotate must refuse a mounted volume"
    );
    assert!(
        err.contains("refusing to rotate") && err.contains("mounted at"),
        "unclear refusal: {err}"
    );
    assert_eq!(std::fs::read(&cfg).unwrap(), before, "volume.json changed");
    assert!(volume_unmount(&me, &mp).status.success());
    wait_exit(&mut child, "mount under rotate");
}

/// The `key export` sentence mounts a locally-created volume through the real
/// `volume mount --recovery-file` entry point.
#[test]
fn exported_root_mounts_through_recovery_file() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, rec) = normal_local_volume(&me);
    let mp_dir = TempDir::new().unwrap();
    let mp = mp_dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();

    let mut child = me
        .std_cmd()
        .args([
            "volume",
            "mount",
            &id,
            mp.to_str().unwrap(),
            "--recovery-file",
        ])
        .arg(&rec)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let line = wait_mounted(&mut child, &mp);
    eprintln!("mounted with the exported root: {line}");
    assert!(std::fs::read_dir(&mp).is_ok(), "the mount serves readdir");
    assert!(volume_unmount(&me, &mp).status.success());
    wait_exit(&mut child, "recovery-file mount");
}

/// A failed snapshot publish is recorded in the volume directory by the mount
/// process; `volume unmount`, a DIFFERENT process, must report it as an error
/// once the writer has exited, and a mount must warn while it is present. The
/// record is planted here to exercise exactly the drain-then-read path of
/// `volume unmount`.
#[test]
fn volume_unmount_reports_a_stale_cloud_snapshot_as_an_error() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, recovery) = normal_local_volume(&me);
    let marker = me
        .volumes
        .path()
        .join(&id)
        .join("snapshot_publish_failed.json");
    std::fs::write(
        &marker,
        r#"{"failed_at_unix": 1, "reason": "publishing the metadata snapshot failed: not connected", "stale_snapshot_message_id": 4242, "stale_snapshot_version": 3}"#,
    )
    .unwrap();
    let mp_dir = TempDir::new().unwrap();
    let mp = mp_dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();

    let mut child = spawn_mount(&me, &id, &mp, &[], &recovery);
    wait_mounted(&mut child, &mp);
    let un = volume_unmount(&me, &mp);
    let un_err = String::from_utf8_lossy(&un.stderr);
    eprintln!(
        "volume unmount: status {:?}\nstdout: {}stderr: {}",
        un.status.code(),
        String::from_utf8_lossy(&un.stdout),
        un_err
    );
    assert!(
        !un.status.success(),
        "a stale cloud snapshot must fail the unmount"
    );
    assert!(
        un_err.contains("STALE") && un_err.contains("message_id=4242"),
        "the error must say the cloud metadata is stale and name the snapshot: {un_err}"
    );
    let un_out = String::from_utf8_lossy(&un.stdout);
    assert!(
        !un_out.contains("Unmounted.") && !un_out.contains("safe to remount"),
        "stdout must not read as a clean success before the stale error: {un_out}"
    );
    assert!(
        un_err.contains("The filesystem was unmounted, but"),
        "the error must state the unmount neutrally, as a fact, not as success: {un_err}"
    );
    wait_exit(&mut child, "mount with a stale snapshot record");
    let out = child.wait_with_output().unwrap();
    let mount_err = String::from_utf8_lossy(&out.stderr);
    assert!(
        mount_err.contains("WARNING") && mount_err.contains("STALE"),
        "the mount must warn while the record is present: {mount_err}"
    );
    assert!(
        mount_line(&mp).is_none(),
        "the volume is unmounted all the same"
    );
}

/// A normal volume with a recorded snapshot and corrupt local DB must refuse an
/// offline mount without changing the DB or mounting anything.
#[test]
fn offline_mount_of_a_normal_volume_with_a_corrupt_db_refuses() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, recovery) = normal_local_volume(&me);
    let cfg = me.volumes.path().join(&id).join("volume.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
    config["metadata_snapshot_id"] = serde_json::json!(4242);
    std::fs::write(&cfg, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let db = me.volumes.path().join(&id).join("metadata.db");
    std::fs::write(&db, b"not a SQLite database").unwrap();
    let before = std::fs::read(&db).unwrap();
    let mp_dir = TempDir::new().unwrap();
    let mp = mp_dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();
    let mut child = spawn_mount(&me, &id, &mp, &[], &recovery);
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if mount_line(&mp).is_some() || Instant::now() > deadline {
            let _ = volume_unmount(&me, &mp);
            let _ = child.kill();
            panic!("the offline mount of a corrupt DB was NOT refused");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!(
        "offline mount of a corrupt DB ({status}): {}",
        stderr.trim()
    );
    assert!(!status.success());
    assert!(
        stderr.contains("rebuilt from Telegram") || stderr.contains("cannot be used"),
        "{stderr}"
    );
    assert!(
        std::fs::read(&db).unwrap() == before,
        "the refused mount changed the DB"
    );
    assert!(mount_line(&mp).is_none());
}

/// A normal volume with a recorded snapshot but no local DB cannot be rebuilt
/// offline and must not create an empty replacement database.
#[test]
fn offline_mount_without_a_local_db_refuses_and_creates_none() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, recovery) = normal_local_volume(&me);
    let cfg = me.volumes.path().join(&id).join("volume.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
    config["metadata_snapshot_id"] = serde_json::json!(4242);
    std::fs::write(&cfg, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    std::fs::remove_file(me.volumes.path().join(&id).join("metadata.db")).unwrap();
    let db = me.volumes.path().join(&id).join("metadata.db");
    assert!(!db.exists(), "the fixture must have no metadata DB");
    let mp_dir = TempDir::new().unwrap();
    let mp = mp_dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();

    let mut child = spawn_mount(&me, &id, &mp, &[], &recovery);
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if mount_line(&mp).is_some() || Instant::now() > deadline {
            let _ = volume_unmount(&me, &mp);
            let _ = child.kill();
            panic!("the offline mount without a local DB was NOT refused (an empty filesystem was served)");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("offline mount without a DB ({status}): {}", stderr.trim());
    assert!(!status.success());
    assert!(
        stderr.contains("rebuilt from Telegram"),
        "the refusal must say the DB must be rebuilt from Telegram: {stderr}"
    );
    assert!(!db.exists(), "the refused mount created a metadata DB");
    assert!(mount_line(&mp).is_none());
}
