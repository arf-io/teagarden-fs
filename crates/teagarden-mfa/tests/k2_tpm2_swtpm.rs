//! K2 TPM2 sealing protector — REAL end-to-end against a software TPM (`swtpm`).
//!
//! Proves the `Tpm2SealProtector` seals a KEK into a TPM and recovers it, and that
//! it plugs into the K0a slot vault so a master key can be protected by, and
//! recovered from, the TPM — the same seal/unseal path `systemd-cryptenroll
//! --tpm2-device` / Clevis `tpm2` use, exercised via `tpm2-tools`.
//!
//! Requires `swtpm` + `swtpm_setup` + `tpm2-tools`. Without them the tests SKIP
//! (print + return) unless `TEAGARDEN_REQUIRE_TPM` is set, so the suite stays
//! portable while CI can force a hard failure. Tests are serialized (one swtpm +
//! one process-global `TPM2TOOLS_TCTI` at a time).

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use teagarden_mfa::kslot::protector::SlotProtector;
use teagarden_mfa::kslot::{SlotVault, Tpm2SealProtector};

fn have(bin: &str) -> bool {
    // Spawning at all proves the binary is on PATH — the exit code is NOT a
    // presence signal. swtpm 0.6.3 (what Ubuntu 22.04, and therefore CI, ships)
    // prints `swtpm_setup --version` to stdout and then exits 1; 0.10 exits 0.
    // Probing `status.success()` therefore reported swtpm missing on every
    // 22.04 machine, and TEAGARDEN_REQUIRE_TPM turned that into a hard failure
    // on a host that had a perfectly usable swtpm installed. Matches the same
    // is_ok() probe in k3_pkcs11_softhsm.rs and k4_tang_clevis.rs.
    Command::new(bin).arg("--version").output().is_ok()
}

/// `None` when every tool is present, otherwise the name of the first missing
/// one — so a REQUIRE_TPM failure says *which* binary to install instead of
/// making the reader bisect four of them out of a CI log.
fn missing_tool() -> Option<&'static str> {
    ["swtpm", "swtpm_setup", "tpm2_createprimary", "tpm2_startup"]
        .into_iter()
        .find(|b| !have(b))
}

fn require_tpm() -> bool {
    std::env::var_os("TEAGARDEN_REQUIRE_TPM").is_some()
}

/// Serialize TPM tests: one swtpm instance + one process-global TCTI at a time.
fn tpm_lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// A running software TPM. Sets `TPM2TOOLS_TCTI` so every `tpm2_*` subprocess (incl.
/// the protector's) targets it; kills it on drop.
struct Swtpm {
    child: Child,
    _state: tempfile::TempDir,
    _guard: MutexGuard<'static, ()>,
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::env::remove_var("TPM2TOOLS_TCTI");
    }
}

/// Provision + launch swtpm on a unix socket and wait until it answers. Returns
/// `None` (skip) if the tools are unavailable or setup fails on this host.
fn start_swtpm() -> Option<Swtpm> {
    let guard = tpm_lock();
    if let Some(missing) = missing_tool() {
        assert!(
            !require_tpm(),
            "TEAGARDEN_REQUIRE_TPM is set but `{missing}` is not on PATH \
             (Debian/Ubuntu: apt-get install swtpm swtpm-tools tpm2-tools)"
        );
        eprintln!("SKIP: swtpm / tpm2-tools not available");
        return None;
    }
    let state = tempfile::tempdir().unwrap();
    let state_dir = state.path().to_string_lossy().to_string();
    let sock: PathBuf = state.path().join("swtpm.sock");

    let setup = Command::new("swtpm_setup")
        .args(["--tpm2", "--tpmstate", &state_dir, "--overwrite"])
        .output();
    match setup {
        Ok(o) if o.status.success() => {}
        other => {
            assert!(
                !require_tpm(),
                "TEAGARDEN_REQUIRE_TPM set but swtpm_setup failed: {other:?}"
            );
            eprintln!("SKIP: swtpm_setup failed");
            return None;
        }
    }

    let child = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={state_dir}"),
            "--server",
            &format!("type=unixio,path={}", sock.display()),
            "--ctrl",
            &format!("type=unixio,path={}.ctrl", sock.display()),
            "--flags",
            "not-need-init,startup-clear",
        ])
        .spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) => {
            assert!(
                !require_tpm(),
                "TEAGARDEN_REQUIRE_TPM set but swtpm spawn failed: {e}"
            );
            eprintln!("SKIP: swtpm spawn failed: {e}");
            return None;
        }
    };

    std::env::set_var("TPM2TOOLS_TCTI", format!("swtpm:path={}", sock.display()));

    // Wait until the TPM answers (a bare tpm2 command succeeds).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    while Instant::now() < deadline {
        let ok = Command::new("tpm2_pcrread")
            .arg("sha256:0")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let sw = Swtpm {
        child,
        _state: state,
        _guard: guard,
    };
    if !ready {
        assert!(
            !require_tpm(),
            "TEAGARDEN_REQUIRE_TPM set but swtpm never became ready"
        );
        eprintln!("SKIP: swtpm did not become ready");
        return None; // `sw` drops here → child killed, TCTI cleared
    }
    Some(sw)
}

/// (1) The protector seals a random KEK into the TPM and recovers exactly that KEK
/// (TPM-only bind, no PCR policy).
#[test]
fn tpm2_seal_unseal_roundtrip() {
    let Some(_sw) = start_swtpm() else { return };

    let mut p = Tpm2SealProtector::new(None);
    let enrollment = p.enroll().expect("enroll seals a KEK into the TPM");
    let sealed_kek = *enrollment.kek.as_bytes();

    let recovered = p
        .recover_kek(&enrollment.params, &enrollment.transport)
        .expect("recover unseals the KEK from the TPM");

    assert_eq!(
        &sealed_kek,
        recovered.as_bytes(),
        "the TPM must unseal exactly the KEK that was sealed"
    );
}

/// (2) THE INTEGRATION: a slot vault's master key is protected by, and recovered
/// from, the TPM — the real K0a-vault + K2-factor path end to end.
#[test]
fn tpm2_slot_protects_and_recovers_master_key() {
    let Some(_sw) = start_swtpm() else { return };

    let (mut vault, mk) = SlotVault::create("k2-tpm2-test");
    let mk_bytes = *mk.as_bytes();

    // Enroll a TPM2 slot (seals a per-slot KEK; the vault wraps MK under it).
    let mut enroll_p = Tpm2SealProtector::new(None);
    vault
        .add_independent_slot(&mk, &mut enroll_p, "tpm2")
        .expect("enroll a TPM2 slot into the vault");

    // Persist + reload, then recover MK via the TPM alone.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.json");
    vault.save(&path).unwrap();
    let reloaded = SlotVault::load(&path).unwrap();

    let unlock_p = Tpm2SealProtector::new(None);
    let refs: Vec<&dyn SlotProtector> = vec![&unlock_p];
    let recovered_mk = reloaded
        .unlock_targeted(&refs) // TPM2 is counter-bearing → targeted, not speculative
        .expect("the TPM slot must recover the master key");

    assert_eq!(
        &mk_bytes,
        recovered_mk.as_bytes(),
        "MK recovered via the TPM must equal the original"
    );
}

/// (3) PCR-bound seal: binding to a PCR set still round-trips while the PCRs are
/// unchanged (exercises the policy-session unseal path with a software TPM).
#[test]
fn tpm2_pcr_bound_seal_roundtrips_when_pcrs_unchanged() {
    let Some(_sw) = start_swtpm() else { return };

    let mut p = Tpm2SealProtector::new(Some("sha256:0,1,7".to_string()));
    let enrollment = p.enroll().expect("enroll seals under a PCR policy");
    let sealed = *enrollment.kek.as_bytes();

    // PCRs 0,1,7 are unchanged since enroll → the policy is satisfiable → unseal.
    let recovered = p
        .recover_kek(&enrollment.params, &enrollment.transport)
        .expect("PCR-bound unseal must succeed while PCRs are unchanged");

    assert_eq!(&sealed, recovered.as_bytes());
    // Confirm the slot really recorded the PCR binding.
    assert_eq!(
        enrollment.params.get("pcrs").and_then(|v| v.as_str()),
        Some("sha256:0,1,7")
    );
}

/// (4) NEGATIVE — a seal bound to a selected PCR
/// unseals while that PCR is unchanged, but is REFUSED once the PCR is extended
/// (i.e. the boot state changed). Proves the policy is enforced, not decorative.
#[test]
fn tpm2_pcr_binding_rejects_a_changed_pcr() {
    let Some(_sw) = start_swtpm() else { return };

    // Bind to PCR 23 — a resettable/extendable debug PCR available on swtpm.
    let mut p = Tpm2SealProtector::new(Some("sha256:23".to_string()));
    let enrollment = p.enroll().expect("enroll seals under PCR 23");

    // Unseal succeeds while PCR 23 is unchanged.
    assert!(
        p.recover_kek(&enrollment.params, &enrollment.transport)
            .is_ok(),
        "unseal must work while the bound PCR is unchanged"
    );

    // Change PCR 23 (simulate a boot-state / evil-maid change).
    let ext = Command::new("tpm2_pcrextend")
        .arg("23:sha256=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .output()
        .expect("run tpm2_pcrextend");
    assert!(
        ext.status.success(),
        "pcrextend failed: {}",
        String::from_utf8_lossy(&ext.stderr)
    );

    // Unseal MUST now be refused — the policy no longer matches the PCR state.
    assert!(
        p.recover_kek(&enrollment.params, &enrollment.transport)
            .is_err(),
        "unseal must be REFUSED after the selected PCR value changed"
    );
}

// ── mfa-H1: enroll must verify the volume BEFORE mutating anything ──────────

const PW: &[u8] = b"correct-horse-battery-staple";

fn pw_inputs() -> teagarden_mfa::unlock::UnlockInputs<'static> {
    teagarden_mfa::unlock::UnlockInputs {
        password: Some(PW),
        ..Default::default()
    }
}

/// A local tamperer drops `require_block_integrity` from volume.json. The
/// owner's next `mfa enroll --tpm2` must refuse, and must leave BOTH files
/// exactly as they were (a vault saved before the refusal would strand the
/// volume one generation ahead of its anchor).
#[test]
fn tpm2_enroll_refuses_a_tampered_config_and_mutates_nothing() {
    let Some(_sw) = start_swtpm() else { return };
    use teagarden_mfa::unlock::{self, EnrollFactor, SLOT_VAULT_FILENAME};

    let dir = tempfile::tempdir().unwrap();
    let pc = unlock::create_protected_volume(Some("h1"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();
    let base = dir.path().join(&id);
    let config_path = base.join("volume.json");
    let vault_path = base.join(SLOT_VAULT_FILENAME);

    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    assert!(v
        .as_object_mut()
        .unwrap()
        .remove("require_block_integrity")
        .is_some());
    std::fs::write(&config_path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let config_before = std::fs::read(&config_path).unwrap();
    let vault_before = std::fs::read(&vault_path).unwrap();

    let r = unlock::enroll_factor(
        &id,
        &pw_inputs(),
        EnrollFactor::Tpm2 { pcrs: None },
        dir.path(),
    );
    assert!(r.is_err(), "enroll must refuse a tampered config");
    assert_eq!(
        std::fs::read(&config_path).unwrap(),
        config_before,
        "volume.json rewritten"
    );
    assert_eq!(
        std::fs::read(&vault_path).unwrap(),
        vault_before,
        "slot vault mutated"
    );
}

/// A local attacker rolls `slot_vault.json` back to an earlier generation (to
/// resurrect a slot). The open path refuses that; enroll must not re-anchor the
/// rolled-back vault and thereby make the resurrection authentic.
#[test]
fn tpm2_enroll_refuses_a_rolled_back_vault() {
    let Some(_sw) = start_swtpm() else { return };
    use teagarden_mfa::kslot::{Argon2Cost, PassphraseProtector};
    use teagarden_mfa::unlock::{self, EnrollFactor, SLOT_VAULT_FILENAME};

    let dir = tempfile::tempdir().unwrap();
    let pc = unlock::create_protected_volume(Some("h1rb"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();
    let vault_path = dir.path().join(&id).join(SLOT_VAULT_FILENAME);
    let old_vault = std::fs::read(&vault_path).unwrap();

    // Legitimate change: add a slot and reseal (anchor advances).
    {
        let mut vault = SlotVault::load(&vault_path).unwrap();
        let pp = PassphraseProtector::new(PW.to_vec(), Argon2Cost::default());
        let refs: Vec<&dyn SlotProtector> = vec![&pp];
        let mk = vault.unlock(&refs).unwrap();
        let mut q = PassphraseProtector::new(b"second-pw".to_vec(), Argon2Cost::default());
        vault.add_independent_slot(&mk, &mut q, "p2").unwrap();
        vault.save(&vault_path).unwrap();
        unlock::reseal_after_slot_change(&id, &mk, &vault, dir.path()).unwrap();
    }
    // Attack: vault-only rollback. Open refuses it (pre-existing property).
    std::fs::write(&vault_path, &old_vault).unwrap();
    assert!(unlock::open_volume(&id, &pw_inputs(), dir.path()).is_err());

    let r = unlock::enroll_factor(
        &id,
        &pw_inputs(),
        EnrollFactor::Tpm2 { pcrs: None },
        dir.path(),
    );
    assert!(
        r.is_err(),
        "enroll must refuse a vault that does not match the anchor"
    );
    assert_eq!(
        std::fs::read(&vault_path).unwrap(),
        old_vault,
        "slot vault mutated"
    );
    assert!(
        unlock::open_volume(&id, &pw_inputs(), dir.path()).is_err(),
        "the rollback must stay detectable"
    );
}
