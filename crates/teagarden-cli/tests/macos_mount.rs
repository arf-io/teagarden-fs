//! A real macFUSE mount through the shipped `teagarden` binary on macOS.
//!
//! The Linux mount tests (`user_mount.rs`) need `/dev/fuse` and `fusermount3`, so
//! on a Mac they never run. This test mounts a read-only share (which needs no
//! Telegram connection), lists it with `ls`, checks that a write is refused,
//! unmounts it with `volume unmount`, and checks that the mount is gone.
//!
//! Needs macFUSE installed (and its system extension or FSKit backend allowed).
//! Without macFUSE it skips; with `TEAGARDEN_REQUIRE_FUSE` set a skip is a failure.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use tempfile::TempDir;

/// macFUSE mounts need its kernel extension loaded. Installing macFUSE is not
/// enough: on Apple silicon the extension must also be allowed (Recovery: reduced
/// security with kernel extensions from identified developers; then approve it in
/// System Settings > Privacy & Security, and restart).
fn macfuse_kext_loaded() -> bool {
    StdCommand::new("/usr/bin/kmutil")
        .arg("showloaded")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("io.macfuse"))
        .unwrap_or(false)
}

fn preflight() -> bool {
    let reason = if !Path::new("/Library/Filesystems/macfuse.fs").exists() {
        Some("macFUSE is not installed")
    } else if !macfuse_kext_loaded() {
        // load_macfuse is what mount_macfuse runs; try it once before deciding.
        let _ = StdCommand::new("/Library/Filesystems/macfuse.fs/Contents/Resources/load_macfuse")
            .status();
        (!macfuse_kext_loaded())
            .then_some("the macFUSE kernel extension is not loaded (not yet allowed on this Mac)")
    } else {
        None
    };
    if let Some(reason) = reason {
        assert!(
            std::env::var_os("TEAGARDEN_REQUIRE_FUSE").is_none(),
            "TEAGARDEN_REQUIRE_FUSE set but {reason}"
        );
        eprintln!("SKIP: {reason}");
        return false;
    }
    true
}

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

    fn std_cmd(&self) -> StdCommand {
        #[allow(deprecated)]
        let mut c = StdCommand::new(assert_cmd::cargo::cargo_bin("teagarden"));
        c.env("TEAGARDEN_VOLUMES_DIR", self.volumes.path())
            .env("HOME", self.home.path())
            .env(
                "TEAGARDEN_CONFIG_DIR",
                self.home.path().join(".config").join("teagarden"),
            )
            .env(
                "TEAGARDEN_SESSION_PATH",
                self.home.path().join("none.session"),
            )
            .env_remove("TG_API_ID")
            .env_remove("TG_API_HASH");
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

fn stdout_of(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A read-only share of a fresh owner volume, imported on `recipient`.
fn read_only_share(recipient: &Side) -> (String, PathBuf) {
    let owner = Side::new();
    let created = teagarden_core::volume::manager::create_volume(
        Some("mac-mount"),
        b"owner-password-1",
        owner.volumes.path(),
        7,
        0,
        11,
        None,
    )
    .unwrap();
    let id = created.config.volume_id.to_string();
    // `share grant` refuses a volume that never published a snapshot; the id is
    // outside the config MAC, so a test can set it without Telegram.
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&created.paths.config_path).unwrap()).unwrap();
    v["metadata_snapshot_id"] = serde_json::json!(4242);
    std::fs::write(
        &created.paths.config_path,
        serde_json::to_vec_pretty(&v).unwrap(),
    )
    .unwrap();

    recipient
        .cli()
        .args(["share", "key", "generate"])
        .assert()
        .success();
    let ek = stdout_of(recipient.cli().args(["share", "key", "show"]))
        .lines()
        .map(str::trim)
        .find(|l| l.len() > 64 && l.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("encapsulation key")
        .to_string();
    let grant = owner.home.path().join("grant.tgci");
    let pw = owner.file("pw.txt", "owner-password-1");
    let granted = stdout_of(owner.cli().args([
        "share",
        "grant",
        "--volume",
        &id,
        "--access",
        "read-only",
        "--recipient-key",
        &ek,
        "--out",
        grant.to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ]));
    let fingerprint = granted
        .split_whitespace()
        .find(|w| w.starts_with("b3:"))
        .expect("fingerprint")
        .to_string();
    let local = recipient.file("local-pass.txt", "recipient-local-passphrase");
    recipient
        .cli()
        .args(["share", "import"])
        .arg(&grant)
        .args(["--expected-fingerprint", &fingerprint, "--passphrase-file"])
        .arg(&local)
        .assert()
        .success();
    seed_recipient_db(
        owner.volumes.path(),
        recipient.volumes.path(),
        &id,
        b"owner-password-1",
    );
    (id, local)
}

/// Give the imported share the local metadata DB its first ONLINE mount would
/// have restored from the owner's snapshot: the owner's DB (schema and root
/// directory), copied into the recipient's volume directory. A share that
/// names a snapshot but has no local DB cannot be mounted offline at all
/// (`offline_mount_without_a_local_db_refuses_and_creates_none`).
fn seed_recipient_db(owner_volumes: &Path, recipient_volumes: &Path, id: &str, owner_pw: &[u8]) {
    use teagarden_store::opaque_schema::OpaqueSchema;
    let r = teagarden_core::volume::manager::open_volume(id, owner_pw, owner_volumes).unwrap();
    let schema = OpaqueSchema::new(
        r.hierarchy.schema.clone(),
        &teagarden_store::schema::logical_tables(),
    );
    {
        let conn = rusqlite::Connection::open(&r.paths.db_path).unwrap();
        teagarden_store::migrations::initialize_database(&conn, &schema).unwrap();
        teagarden_store::inode_store::InodeStore::new(&conn, &schema, &r.hierarchy.meta)
            .insert(&teagarden_core::metadata::inode::Inode::root())
            .unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }
    std::fs::copy(
        &r.paths.db_path,
        recipient_volumes.join(id).join("metadata.db"),
    )
    .unwrap();
}

/// The `mount(8)` line for `mp` ("<source> on <mountpoint> (<options>)"), if any.
fn mount_line(mp: &Path) -> Option<String> {
    let out = StdCommand::new("/sbin/mount").output().ok()?;
    let needle = format!(" on {} (", mp.display());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.contains(&needle))
        .map(str::to_string)
}

fn wait_mounted(child: &mut Child, mp: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if let Some(line) = mount_line(mp) {
            return line;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let mut out = String::new();
            if let Some(mut e) = child.stderr.take() {
                use std::io::Read as _;
                let _ = e.read_to_string(&mut out);
            }
            panic!("mount exited early ({status}): {out}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    panic!("mount never appeared in mount(8) output");
}

#[test]
fn read_only_share_mounts_lists_refuses_writes_and_unmounts_on_macos() {
    if !preflight() {
        return;
    }
    let me = Side::new();
    let (id, pass) = read_only_share(&me);
    let mp_dir = TempDir::new().unwrap();
    // mount(8) reports the resolved path (/private/var/... for temp dirs).
    let mp = mp_dir.path().canonicalize().unwrap().join("mnt");
    std::fs::create_dir(&mp).unwrap();

    let mut child = me
        .std_cmd()
        .args([
            "volume",
            "mount",
            &id,
            mp.to_str().unwrap(),
            "--password-file",
        ])
        .arg(&pass)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn teagarden volume mount");
    let line = wait_mounted(&mut child, &mp);
    eprintln!("mount(8): {line}");
    assert!(line.contains("read-only"), "read-only share: {line}");

    let ls = StdCommand::new("ls").arg("-la").arg(&mp).output().unwrap();
    assert!(
        ls.status.success(),
        "readdir on the live mount failed: {}",
        String::from_utf8_lossy(&ls.stderr)
    );
    eprintln!("ls -la:\n{}", String::from_utf8_lossy(&ls.stdout));
    assert!(
        std::fs::write(mp.join("nope.txt"), b"x").is_err(),
        "a read-only share must refuse writes"
    );

    let un = me
        .std_cmd()
        .args(["volume", "unmount", mp.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        un.status.success(),
        "volume unmount failed: {}",
        String::from_utf8_lossy(&un.stderr)
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "mount process did not exit");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(mount_line(&mp).is_none(), "still mounted after unmount");
}
