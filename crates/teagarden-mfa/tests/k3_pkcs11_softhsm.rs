//! K3 PKCS#11 protector — REAL end-to-end against a software HSM (SoftHSM2).
//!
//! Proves the `Pkcs11Protector` RSA-OAEP-wraps a KEK to a keypair on the token and
//! recovers it via the token's private key, and that it plugs into the K0a slot
//! vault so a master key is protected by, and recovered from, the HSM — the same
//! path `systemd-cryptenroll --pkcs11-token` uses, via the cryptoki bindings.
//!
//! Requires `softhsm2-util` + `pkcs11-tool` + `libsofthsm2.so`. Without them the
//! tests SKIP unless `TEAGARDEN_REQUIRE_HSM` is set. Serialized (one process-global
//! `SOFTHSM2_CONF` + token at a time). Only compiled with `--features factor-pkcs11`.
#![cfg(feature = "factor-pkcs11")]

use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use teagarden_mfa::kslot::protector::{KekTransport, SlotProtector};
use teagarden_mfa::kslot::{Pkcs11Protector, SlotVault};

const PIN: &str = "1234";
const LABEL: &str = "k3test";

fn have(bin: &str) -> bool {
    // Spawning at all proves the binary is on PATH — exit code is irrelevant
    // (softhsm2-util/pkcs11-tool return various codes for --version/--help).
    Command::new(bin).arg("--version").output().is_ok()
}

fn module_path() -> Option<String> {
    for p in [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", // Debian/Ubuntu multiarch
        "/usr/lib/pkcs11/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
    ] {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

fn require_hsm() -> bool {
    std::env::var_os("TEAGARDEN_REQUIRE_HSM").is_some()
}

fn hsm_lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// A provisioned SoftHSM2 token with one RSA keypair (CKA_ID = 0x01). Sets
/// `SOFTHSM2_CONF` so the in-process module + pkcs11-tool use its token dir.
struct SoftHsm {
    _work: tempfile::TempDir,
    _guard: MutexGuard<'static, ()>,
    module: String,
    key_id: Vec<u8>,
}

impl Drop for SoftHsm {
    fn drop(&mut self) {
        std::env::remove_var("SOFTHSM2_CONF");
    }
}

fn setup() -> Option<SoftHsm> {
    let guard = hsm_lock();
    let Some(module) = module_path() else {
        assert!(
            !require_hsm(),
            "TEAGARDEN_REQUIRE_HSM set but libsofthsm2.so not found"
        );
        eprintln!("SKIP: libsofthsm2.so not found");
        return None;
    };
    if !have("softhsm2-util") || !have("pkcs11-tool") {
        assert!(
            !require_hsm(),
            "TEAGARDEN_REQUIRE_HSM set but softhsm2-util/pkcs11-tool missing"
        );
        eprintln!("SKIP: softhsm2-util / pkcs11-tool not available");
        return None;
    }

    let work = tempfile::tempdir().unwrap();
    let tokens = work.path().join("tokens");
    std::fs::create_dir_all(&tokens).unwrap();
    let conf = work.path().join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .unwrap();
    std::env::set_var("SOFTHSM2_CONF", &conf);

    // Init a token in a free slot.
    let init = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            LABEL,
            "--so-pin",
            PIN,
            "--pin",
            PIN,
        ])
        .output()
        .expect("run softhsm2-util");
    if !init.status.success() {
        assert!(
            !require_hsm(),
            "TEAGARDEN_REQUIRE_HSM set but init-token failed"
        );
        eprintln!(
            "SKIP: softhsm2 init-token failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        return None;
    }

    // Generate an RSA keypair (CKA_ID = 01) on the token.
    let gen = Command::new("pkcs11-tool")
        .args([
            "--module",
            &module,
            "--login",
            "--pin",
            PIN,
            "--keypairgen",
            "--key-type",
            "rsa:2048",
            "--id",
            "01",
            "--label",
            "kek",
        ])
        .output()
        .expect("run pkcs11-tool");
    if !gen.status.success() {
        assert!(
            !require_hsm(),
            "TEAGARDEN_REQUIRE_HSM set but keypairgen failed"
        );
        eprintln!(
            "SKIP: pkcs11-tool keypairgen failed: {}",
            String::from_utf8_lossy(&gen.stderr)
        );
        return None;
    }

    Some(SoftHsm {
        _work: work,
        _guard: guard,
        module,
        key_id: vec![0x01],
    })
}

/// (1) The protector RSA-OAEP-wraps a KEK to the token and recovers exactly it.
#[test]
fn pkcs11_wrap_unwrap_roundtrip() {
    let Some(hsm) = setup() else { return };

    let mut p = Pkcs11Protector::new(
        &hsm.module,
        Some(LABEL.to_string()),
        hsm.key_id.clone(),
        PIN,
    );
    let enrollment = p.enroll().expect("enroll wraps a KEK to the HSM key");
    let wrapped_kek = *enrollment.kek.as_bytes();

    let recovered = p
        .recover_kek(&enrollment.params, &enrollment.transport)
        .expect("recover unwraps the KEK via the HSM private key");

    assert_eq!(
        &wrapped_kek,
        recovered.as_bytes(),
        "the HSM must unwrap exactly the KEK that was wrapped"
    );
}

/// (1b) The wrap scheme the protector chose is recorded in the transport, the
/// key unwraps under exactly that scheme and NOT under the other one, so unlock
/// really depends on the recorded scheme. Prints which one this token took:
/// SoftHSM2 2.x rejects SHA-256 OAEP, so it is expected to take the SHA-1
/// fallback (and the SHA-256 path is then not exercised here).
#[test]
fn pkcs11_records_the_oaep_scheme_it_used_and_unwraps_only_with_it() {
    let Some(hsm) = setup() else { return };
    let mut p = Pkcs11Protector::new(
        &hsm.module,
        Some(LABEL.to_string()),
        hsm.key_id.clone(),
        PIN,
    );
    let enrollment = p.enroll().expect("enroll");
    let (scheme, ciphertext) = match &enrollment.transport {
        KekTransport::EncryptedKek { scheme, ciphertext } => (scheme.clone(), ciphertext.clone()),
        _ => panic!("expected an EncryptedKek transport"),
    };
    let other = match scheme.as_str() {
        "pkcs11-rsa-oaep-sha256" => "pkcs11-rsa-oaep-sha1",
        "pkcs11-rsa-oaep-sha1" => "pkcs11-rsa-oaep-sha256",
        s => panic!("unexpected scheme {s}"),
    };
    eprintln!("SoftHSM2 took OAEP scheme {scheme}");
    let kek = p
        .recover_kek(&enrollment.params, &enrollment.transport)
        .expect("unwrap under the recorded scheme");
    assert_eq!(kek.as_bytes(), enrollment.kek.as_bytes());
    let swapped = KekTransport::EncryptedKek {
        scheme: other.to_string(),
        ciphertext,
    };
    assert!(
        p.recover_kek(&enrollment.params, &swapped)
            .map(|k| k.as_bytes() != enrollment.kek.as_bytes())
            .unwrap_or(true),
        "the key must not unwrap under {other}"
    );
}

/// (2) THE INTEGRATION: a slot vault's master key is protected by, and recovered
/// from, the HSM — the real K0a-vault + K3-factor path end to end.
#[test]
fn pkcs11_slot_protects_and_recovers_master_key() {
    let Some(hsm) = setup() else { return };

    let (mut vault, mk) = SlotVault::create("k3-pkcs11-test");
    let mk_bytes = *mk.as_bytes();

    let mut enroll_p = Pkcs11Protector::new(
        &hsm.module,
        Some(LABEL.to_string()),
        hsm.key_id.clone(),
        PIN,
    );
    vault
        .add_independent_slot(&mk, &mut enroll_p, "pkcs11")
        .expect("enroll a PKCS#11 slot into the vault");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.json");
    vault.save(&path).unwrap();
    let reloaded = SlotVault::load(&path).unwrap();

    let unlock_p = Pkcs11Protector::new(
        &hsm.module,
        Some(LABEL.to_string()),
        hsm.key_id.clone(),
        PIN,
    );
    let refs: Vec<&dyn SlotProtector> = vec![&unlock_p];
    let recovered_mk = reloaded
        .unlock_targeted(&refs) // PKCS#11 is PIN-counter-bearing → targeted
        .expect("the HSM slot must recover the master key");

    assert_eq!(
        &mk_bytes,
        recovered_mk.as_bytes(),
        "MK recovered via the HSM must equal the original"
    );
}

/// (3) NEGATIVE — recovery is refused for a wrong PIN, a tampered ciphertext, and a
/// wrong key id. Proves the factor actually gates on the real secret + integrity,
/// not merely that the happy path round-trips.
#[test]
fn pkcs11_wrong_pin_tampered_ct_and_wrong_key_are_refused() {
    let Some(hsm) = setup() else { return };

    let mut p = Pkcs11Protector::new(
        &hsm.module,
        Some(LABEL.to_string()),
        hsm.key_id.clone(),
        PIN,
    );
    let enrollment = p.enroll().expect("enroll");

    // Wrong PIN → C_Login fails, no KEK.
    let wrong_pin = Pkcs11Protector::new(
        &hsm.module,
        Some(LABEL.to_string()),
        hsm.key_id.clone(),
        "9999",
    );
    assert!(
        wrong_pin
            .recover_kek(&enrollment.params, &enrollment.transport)
            .is_err(),
        "a wrong PIN must not recover the KEK"
    );

    // Tampered ciphertext → RSA-OAEP unwrap fails.
    let tampered = match &enrollment.transport {
        KekTransport::EncryptedKek { scheme, ciphertext } => {
            let mut ct = ciphertext.clone();
            ct[0] ^= 0xFF;
            KekTransport::EncryptedKek {
                scheme: scheme.clone(),
                ciphertext: ct,
            }
        }
        _ => panic!("expected an EncryptedKek transport"),
    };
    assert!(
        p.recover_kek(&enrollment.params, &tampered).is_err(),
        "a tampered ciphertext must not recover the KEK"
    );

    // Wrong key id in params → key not found on the token.
    let mut bad_params = enrollment.params.clone();
    bad_params["key_id"] = serde_json::json!("99");
    assert!(
        p.recover_kek(&bad_params, &enrollment.transport).is_err(),
        "a wrong key id must not recover the KEK"
    );
}
