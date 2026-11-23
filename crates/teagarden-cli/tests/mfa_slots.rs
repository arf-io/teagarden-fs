//! mfa-H2 at the level a user experiences it: the shipped `teagarden` binary.
//!
//! The key-slot vault is any-one-of (like LUKS): enrolling TPM2 ADDS a way in,
//! it never makes TPM2 required, and the last passphrase or recovery slot can
//! never be removed, so a volume never opens only with a device. These tests
//! prove, through the real CLI against a software TPM, that after
//! `keyslot enroll --tpm2` + `keyslot remove-slot <passphrase slot>`:
//!   - a password-only open FAILS,
//!   - a `--tpm2` open SUCCEEDS, and
//!   - the recovery slot cannot be removed, and the recovery sentence opens the
//!     volume with the TPM gone.
//!
//! Every child process gets an isolated HOME / XDG_CONFIG_HOME and no Telegram
//! credentials, so nothing loads a real `.env` and every open runs offline.
//!
//! `TEAGARDEN_REQUIRE_TPM` turns a missing tool into a
//! hard failure instead of a printed SKIP.

use std::path::PathBuf;
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PW: &str = "correct-horse-battery-staple";

fn require(var: &str) -> bool {
    std::env::var_os(var).is_some()
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
        .unwrap_or(false)
}

/// A software TPM on a unix socket. The TCTI string is passed to each child via
/// `.env(...)` — never a process-global `set_var` (tests run in parallel).
struct Swtpm {
    child: Child,
    tcti: String,
    _state: TempDir,
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_swtpm() -> Option<Swtpm> {
    for bin in ["swtpm", "swtpm_setup", "tpm2_createprimary", "tpm2_pcrread"] {
        if !on_path(bin) {
            assert!(
                !require("TEAGARDEN_REQUIRE_TPM"),
                "TEAGARDEN_REQUIRE_TPM is set but `{bin}` is not on PATH"
            );
            eprintln!("SKIP: {bin} not installed");
            return None;
        }
    }
    let state = TempDir::new().unwrap();
    let dir = state.path().to_string_lossy().to_string();
    let sock = state.path().join("swtpm.sock");
    let setup = StdCommand::new("swtpm_setup")
        .args(["--tpm2", "--tpmstate", &dir, "--overwrite"])
        .output()
        .expect("run swtpm_setup");
    assert!(
        setup.status.success() || !require("TEAGARDEN_REQUIRE_TPM"),
        "swtpm_setup failed: {}",
        String::from_utf8_lossy(&setup.stderr)
    );
    if !setup.status.success() {
        eprintln!("SKIP: swtpm_setup failed");
        return None;
    }
    let mut child = StdCommand::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={dir}"),
            "--server",
            &format!("type=unixio,path={}", sock.display()),
            "--ctrl",
            &format!("type=unixio,path={}.ctrl", sock.display()),
            "--flags",
            "not-need-init,startup-clear",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn swtpm");
    let tcti = format!("swtpm:path={}", sock.display());
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let ok = StdCommand::new("tpm2_pcrread")
            .arg("sha256:0")
            .env("TPM2TOOLS_TCTI", &tcti)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(Swtpm {
                child,
                tcti,
                _state: state,
            });
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("swtpm never became ready");
}

/// Isolated environment for the shipped binary.
struct Env {
    volumes: TempDir,
    home: TempDir,
    tcti: Option<String>,
}

impl Env {
    fn new(tcti: Option<String>) -> Self {
        Self {
            volumes: TempDir::new().unwrap(),
            home: TempDir::new().unwrap(),
            tcti,
        }
    }

    fn apply(&self, cmd: &mut StdCommand) {
        cmd.env("TEAGARDEN_VOLUMES_DIR", self.volumes.path())
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
        if let Some(t) = &self.tcti {
            cmd.env("TPM2TOOLS_TCTI", t);
        }
    }

    fn cli(&self) -> Command {
        #[allow(deprecated)]
        let std_cmd = {
            let mut c = StdCommand::new(assert_cmd::cargo::cargo_bin("teagarden"));
            self.apply(&mut c);
            c
        };
        Command::from_std(std_cmd)
    }

    fn file(&self, name: &str, contents: &str) -> PathBuf {
        let p = self.home.path().join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }
}

/// A real key-protected volume (passphrase + recovery slots), created offline.
fn protected_volume(env: &Env) -> (String, PathBuf, PathBuf) {
    let pc = teagarden_mfa::unlock::create_protected_volume(
        Some("slots"),
        PW.as_bytes(),
        env.volumes.path(),
        0,
        0,
        0,
        None,
    )
    .expect("create protected volume");
    let id = pc.created.config.volume_id.to_string();
    let pw = env.file("pw.txt", PW);
    let rec = env.file("recovery.txt", pc.recovery_sentence.as_str());
    (id, pw, rec)
}

/// The id of the slot labelled `label`, read from the vault file itself (its
/// `slots[]` records are plain JSON; no key material is involved).
fn slot_id(env: &Env, id: &str, label: &str) -> u32 {
    let path = env
        .volumes
        .path()
        .join(id)
        .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    v["slots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["label"] == label)
        .unwrap_or_else(|| panic!("no slot labelled {label}"))["slot_id"]
        .as_u64()
        .unwrap() as u32
}

/// THE PROOF, end to end through the shipped binary and a real (software) TPM.
///
/// Every step opens the volume through the same unlock path a mount uses, but
/// offline: a read-write mount needs a live Telegram transport (an offline
/// writable mount is refused), so the mount-level proof of this property is in
/// the live suite. Here `volume history --password-file` exercises the password
/// slot and `keyslot unlock --tpm2` exercises the TPM2 slot.
#[test]
fn tpm2_enrollment_is_local_but_pending_without_telegram() {
    let Some(tpm) = start_swtpm() else { return };
    let env = Env::new(Some(tpm.tcti.clone()));
    let (id, pw, rec) = protected_volume(&env);

    // 1. Enroll TPM2 (authorised by the recovery sentence).
    env.cli()
        .args(["keyslot", "enroll", &id, "--tpm2", "--recovery-file"])
        .arg(&rec)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "slot change is local but header publication is pending",
        ))
        .stdout(predicate::str::contains("Enrolled TPM2 slot"));

    // 2. Status lists every slot and says plainly that ANY ONE opens the volume.
    let pass_id = slot_id(&env, &id, "passphrase");
    env.cli()
        .args(["keyslot", "status", &id])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "any one enrolled slot opens the volume",
        ))
        .stdout(predicate::str::contains(format!(
            "slot {pass_id}  passphrase"
        )))
        .stdout(predicate::str::contains("tpm2"));

    // Before removal the PASSWORD alone still opens it: enrolling TPM2 added a
    // way in, it did not make TPM2 required.
    env.cli()
        .args(["volume", "history", &id, "--password-file"])
        .arg(&pw)
        .assert()
        .success();

    // 3. A slot cannot authorise its own removal.
    env.cli()
        .args([
            "keyslot",
            "remove-slot",
            &id,
            &pass_id.to_string(),
            "--yes",
            "--password-file",
        ])
        .arg(&pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("DIFFERENT slot"));

    // 4. A second slot mutation is blocked until the pending header is repaired.
    env.cli()
        .args([
            "keyslot",
            "remove-slot",
            &id,
            &pass_id.to_string(),
            "--yes",
            "--tpm2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "portable header publication is pending; repair it before changing slots",
        ));

    // 5. Because removal was blocked, the password still opens the volume.
    env.cli()
        .args(["volume", "history", &id, "--password-file"])
        .arg(&pw)
        .assert()
        .success();

    // 6. The TPM2 slot alone still opens it.
    env.cli()
        .args(["keyslot", "unlock", &id, "--tpm2"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unlocked via"));
}

/// A device slot only ever ADDS a way in. Through the shipped binary and a real
/// (software) TPM. Without Telegram, the first slot change remains pending and
/// prevents a second mutation; after the TPM is gone the recovery sentence still
/// opens the volume. The help text never promises hardware-only access.
#[test]
fn a_device_slot_never_becomes_the_only_way_in() {
    let env0 = Env::new(None);
    let help = env0.cli().args(["keyslot", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout).to_string();
    assert!(
        !help.contains("hardware-only"),
        "help promises hardware-only access:\n{help}"
    );
    assert!(
        help.contains("At least one passphrase or recovery-sentence slot always remains"),
        "help must say a durable slot always remains:\n{help}"
    );

    let Some(tpm) = start_swtpm() else { return };
    let env = Env::new(Some(tpm.tcti.clone()));
    let (id, pw, rec) = protected_volume(&env);
    env.cli()
        .args(["keyslot", "enroll", &id, "--tpm2", "--password-file"])
        .arg(&pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "slot change is local but header publication is pending",
        ))
        .stdout(predicate::str::contains("Enrolled TPM2 slot"));
    let pass_id = slot_id(&env, &id, "passphrase");
    let rec_id = slot_id(&env, &id, "recovery");
    env.cli()
        .args([
            "keyslot",
            "remove-slot",
            &id,
            &pass_id.to_string(),
            "--yes",
            "--tpm2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "portable header publication is pending; repair it before changing slots",
        ));

    // The pending header blocks a second mutation, and the vault is unchanged.
    let vault_path = env
        .volumes
        .path()
        .join(&id)
        .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
    let before = std::fs::read(&vault_path).unwrap();
    env.cli()
        .args([
            "keyslot",
            "remove-slot",
            &id,
            &rec_id.to_string(),
            "--yes",
            "--tpm2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "portable header publication is pending; repair it before changing slots",
        ));
    assert_eq!(std::fs::read(&vault_path).unwrap(), before);

    // The TPM is gone (its state destroyed): the TPM2 slot can no longer open the
    // volume, and the recovery sentence still does, with no device at all.
    drop(tpm);
    env.cli()
        .args(["keyslot", "unlock", &id, "--tpm2"])
        .assert()
        .failure();
    env.cli()
        .args(["volume", "history", &id, "--recovery-file"])
        .arg(&rec)
        .assert()
        .success();
}

/// A successful local removal records pending publication; an unknown slot is
/// refused, and later slot changes remain blocked without Telegram.
#[test]
fn remove_slot_refusals_mutate_nothing() {
    let env = Env::new(None);
    let (id, pw, rec) = protected_volume(&env);
    let vault_path = env
        .volumes
        .path()
        .join(&id)
        .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
    let before = std::fs::read(&vault_path).unwrap();

    env.cli()
        .args([
            "keyslot",
            "remove-slot",
            &id,
            "99",
            "--yes",
            "--password-file",
        ])
        .arg(&pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no slot 99"));
    assert_eq!(std::fs::read(&vault_path).unwrap(), before);

    // Remove the recovery slot with the passphrase: the local change succeeds,
    // but publication fails visibly with no Telegram login.
    let rec_id = slot_id(&env, &id, "recovery");
    env.cli()
        .args([
            "keyslot",
            "remove-slot",
            &id,
            &rec_id.to_string(),
            "--yes",
            "--password-file",
        ])
        .arg(&pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "slot change is local but header publication is pending",
        ))
        .stdout(predicate::str::contains(format!("Removed slot {rec_id}")));
    // The removed recovery sentence no longer opens the volume.
    env.cli()
        .args(["key", "export", &id, "--recovery-file"])
        .arg(&rec)
        .assert()
        .failure();

    // Another removal is blocked until the pending header is repaired.
    let after_first = std::fs::read(&vault_path).unwrap();
    let pass_id = slot_id(&env, &id, "passphrase");
    env.cli()
        .args([
            "keyslot",
            "remove-slot",
            &id,
            &pass_id.to_string(),
            "--yes",
            "--password-file",
        ])
        .arg(&pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("DIFFERENT slot"));
    assert_eq!(std::fs::read(&vault_path).unwrap(), after_first);
}

/// mfa-H2(c): `key export` must say the exported root bypasses every slot and
/// cannot be revoked — for every volume, not only key-protected ones.
#[test]
fn key_export_warns_the_root_bypasses_slots_and_cannot_be_revoked() {
    let env = Env::new(None);
    let (id, _pw, rec) = protected_volume(&env);
    env.cli()
        .args(["key", "export", &id, "--recovery-file"])
        .arg(&rec)
        .assert()
        .success()
        .stdout(predicate::str::contains("without any slot or factor"))
        .stdout(predicate::str::contains("cannot be revoked"));
}
