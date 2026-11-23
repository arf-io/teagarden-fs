//! `key rotate` versus the single-writer lock, and the `--recovery-file`
//! promise that `key export` makes, both through the shipped binary.
//!
//! Every child gets an isolated HOME / config dir / volumes dir / session path
//! and no Telegram credentials, so nothing reads a real `.env` and every open is
//! offline. The volumes have no blocks, which is what lets `key rotate` finish
//! offline (it only advances the epoch), and `--local-only` is what lets
//! `volume delete` finish offline.

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;
use teagarden_core::volume::manager;
use tempfile::TempDir;

const PW: &str = "owner-password-1";

struct Env {
    volumes: TempDir,
    home: TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            volumes: TempDir::new().unwrap(),
            home: TempDir::new().unwrap(),
        }
    }

    fn cli(&self) -> Command {
        #[allow(deprecated)]
        let mut c = StdCommand::new(assert_cmd::cargo::cargo_bin("teagarden"));
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
            .env(
                "TEAGARDEN_DEV_REGISTRY_DIR",
                self.home.path().join("devices"),
            )
            .env_remove("TG_API_ID")
            .env_remove("TG_API_HASH")
            .env_remove("TEAGARDEN_DEV_PASSWORD");
        Command::from_std(c)
    }

    fn file(&self, name: &str, contents: &str) -> PathBuf {
        let p = self.home.path().join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    fn base(&self, id: &str) -> PathBuf {
        self.volumes.path().join(id)
    }

    /// A password-rooted (legacy) volume with no Telegram binding.
    fn password_volume(&self, name: &str, password: &str) -> String {
        manager::create_volume(
            Some(name),
            password.as_bytes(),
            self.volumes.path(),
            0,
            0,
            0,
            None,
        )
        .unwrap()
        .config
        .volume_id
        .to_string()
    }
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(cmd: &mut Command) -> Out {
    let o = cmd.output().unwrap();
    Out {
        ok: o.status.success(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn epoch(env: &Env, id: &str) -> u64 {
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.base(id).join("volume.json")).unwrap()).unwrap();
    v["current_epoch"].as_u64().unwrap()
}

// ── item 4: key rotate takes the single-writer lock ─────────────────────────

/// While another process holds the volume's single-writer lock (what a mount,
/// `restore` and `revert` hold for their whole lifetime), `key rotate` must
/// refuse, change nothing, and say why. Once the lock is free it must work.
#[test]
fn key_rotate_refuses_while_the_single_writer_lock_is_held() {
    let env = Env::new();
    let id = env.password_volume("rot", PW);
    let pw = env.file("pw.txt", PW);

    // The test process holds the lock; flock is per open file description, so
    // the child `teagarden` cannot take it.
    let held = manager::VolumeLock::acquire_exclusive(&env.base(id.as_str())).unwrap();
    let out = run(env
        .cli()
        .args(["key", "rotate", &id, "--password-file"])
        .arg(&pw));
    assert!(
        !out.ok,
        "key rotate must refuse while the volume is in use:\n{}{}",
        out.stdout, out.stderr
    );
    assert!(
        out.stderr.contains("in use") && out.stderr.contains("refusing to rotate"),
        "the refusal must say why: {}",
        out.stderr
    );
    assert_eq!(
        epoch(&env, &id),
        0,
        "a refused rotation must not advance the epoch"
    );
    assert!(!env.base(&id).join("rotation_pending.json").exists());
    drop(held);

    let out = run(env
        .cli()
        .args(["key", "rotate", &id, "--password-file"])
        .arg(&pw));
    assert!(
        out.ok,
        "rotate with the lock free: {}{}",
        out.stdout, out.stderr
    );
    assert_eq!(epoch(&env, &id), 1);
    // The rotation released the lock when it exited.
    assert!(!manager::VolumeLock::is_held(&env.base(&id)).unwrap());
}

// ── item 1: --recovery-file opens a volume with the exported root ───────────

/// The 22-word line `key export` prints.
fn exported_sentence(env: &Env, id: &str, password_file: &Path) -> String {
    let out = run(env
        .cli()
        .args(["key", "export", id, "--password-file"])
        .arg(password_file));
    assert!(out.ok, "key export: {}{}", out.stdout, out.stderr);
    out.stdout
        .lines()
        .map(str::trim)
        .find(|l| l.split_whitespace().count() == 22)
        .expect("a 22-word sentence in the key export output")
        .to_string()
}

/// No two consecutive words of the sentence appear in the output. (Single words
/// can legitimately coincide with ordinary English in an error message, e.g.
/// "check"; an echoed fragment of the sentence would carry adjacent words.)
fn assert_no_word_echo(out: &Out, sentence: &str) {
    let words: Vec<&str> = sentence.split_whitespace().collect();
    for pair in words.windows(2) {
        let frag = format!("{} {}", pair[0], pair[1]);
        assert!(
            !out.stderr.contains(&frag) && !out.stdout.contains(&frag),
            "output echoes part of the recovery sentence"
        );
    }
}

/// `key export` says its sentence opens the volume through a command's
/// `--recovery-file`. For a password-rooted volume that used to fail with "this
/// volume needs a password". Every offline-capable command must now open with
/// it: history, key export, key rotate, restore (up to the snapshot fetch) and
/// delete.
#[test]
fn exported_root_opens_a_password_volume_through_every_recovery_file_command() {
    let env = Env::new();
    let id = env.password_volume("rooted", PW);
    let pw = env.file("pw.txt", PW);
    let sentence = exported_sentence(&env, &id, &pw);
    let rec = env.file("root.txt", &sentence);

    let out = run(env
        .cli()
        .args(["volume", "history", &id, "--recovery-file"])
        .arg(&rec));
    assert!(
        out.ok,
        "history --recovery-file: {}{}",
        out.stdout, out.stderr
    );

    // key export through the sentence reproduces the same root.
    let out = run(env
        .cli()
        .args(["key", "export", &id, "--recovery-file"])
        .arg(&rec));
    assert!(
        out.ok,
        "key export --recovery-file: {}{}",
        out.stdout, out.stderr
    );
    assert!(out.stdout.contains(&sentence));

    let out = run(env
        .cli()
        .args(["key", "rotate", &id, "--recovery-file"])
        .arg(&rec));
    assert!(
        out.ok,
        "key rotate --recovery-file: {}{}",
        out.stdout, out.stderr
    );
    assert_eq!(epoch(&env, &id), 1);
    // The root survives rotation (rotation re-seals the config, not the root).
    let out = run(env
        .cli()
        .args(["volume", "history", &id, "--recovery-file"])
        .arg(&rec));
    assert!(out.ok, "history after rotate: {}{}", out.stdout, out.stderr);

    // restore opens, then stops at "no snapshot recorded" (offline volume).
    let out = run(env
        .cli()
        .args(["volume", "restore", &id, "--force", "--recovery-file"])
        .arg(&rec));
    assert!(!out.ok);
    assert!(
        out.stdout.contains("authenticated successfully")
            && out.stderr.contains("no metadata snapshot recorded"),
        "restore must get past the open: {}{}",
        out.stdout,
        out.stderr
    );

    let out = run(env
        .cli()
        .args([
            "volume",
            "delete",
            &id,
            "--force",
            "--local-only",
            "--recovery-file",
        ])
        .arg(&rec));
    assert!(
        out.ok,
        "delete --recovery-file: {}{}",
        out.stdout, out.stderr
    );
    assert!(!env.base(&id).exists(), "delete must remove the volume");
}

/// A sentence that is a valid export of ANOTHER volume, and a tampered
/// volume.json, must both fail closed, without echoing any word.
#[test]
fn foreign_root_and_tampered_config_fail_closed() {
    let env = Env::new();
    let id = env.password_volume("mine", PW);
    let other = env.password_volume("theirs", "their-password-2");
    let pw = env.file("pw.txt", PW);
    let other_pw = env.file("other-pw.txt", "their-password-2");
    let mine = exported_sentence(&env, &id, &pw);
    let foreign = exported_sentence(&env, &other, &other_pw);
    assert_ne!(mine, foreign);
    let foreign_file = env.file("foreign.txt", &foreign);
    let mine_file = env.file("mine.txt", &mine);

    let out = run(env
        .cli()
        .args(["volume", "history", &id, "--recovery-file"])
        .arg(&foreign_file));
    assert!(!out.ok, "a foreign root must not open the volume");
    assert_no_word_echo(&out, &foreign);

    // Tamper an HMAC-covered field (the display name). Address the volume by
    // UUID so the lookup does not depend on the edited name.
    let cfg_path = env.base(&id).join("volume.json");
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    v["display_name"] = serde_json::json!("renamed-by-attacker");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let out = run(env
        .cli()
        .args(["volume", "history", &id, "--recovery-file"])
        .arg(&mine_file));
    assert!(
        !out.ok,
        "a tampered volume.json must not open with the real root:\n{}{}",
        out.stdout, out.stderr
    );
    assert!(
        out.stderr.contains("integrity"),
        "the refusal should name the integrity check: {}",
        out.stderr
    );
    assert_no_word_echo(&out, &mine);
}

/// A key-protected volume: its recovery SLOT sentence still opens it, and the
/// exported hierarchy root (a different sentence) now opens it too.
#[test]
fn protected_volume_opens_with_recovery_slot_and_with_exported_root() {
    let env = Env::new();
    let pc = teagarden_mfa::unlock::create_protected_volume(
        Some("protected"),
        PW.as_bytes(),
        env.volumes.path(),
        0,
        0,
        0,
        None,
    )
    .unwrap();
    let id = pc.created.config.volume_id.to_string();
    let pw = env.file("pw.txt", PW);
    let slot = env.file("slot.txt", pc.recovery_sentence.as_str());
    let root = exported_sentence(&env, &id, &pw);
    assert_ne!(root, pc.recovery_sentence.as_str());
    let root_file = env.file("root.txt", &root);

    for (what, f) in [("recovery slot", &slot), ("exported root", &root_file)] {
        let out = run(env
            .cli()
            .args(["volume", "history", &id, "--recovery-file"])
            .arg(f));
        assert!(out.ok, "{what}: {}{}", out.stdout, out.stderr);
    }
}
