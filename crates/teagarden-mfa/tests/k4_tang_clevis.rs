//! K4 Tang/Clevis protector — REAL end-to-end against a locally-served `tangd`.
//!
//! Proves the `TangProtector` binds a KEK to a Tang server via `clevis encrypt
//! tang` and recovers it via `clevis decrypt` (the McCallum–Relyea exchange), and
//! that it plugs into the K0a slot vault so a master key is protected by, and
//! recovered from, network reach to the Tang endpoint.
//!
//! Requires `clevis` + `tangd` + `tangd-keygen` + `socat`. Without them the tests
//! SKIP unless `TEAGARDEN_REQUIRE_TANG` is set. Serialized (one tangd at a time).

use std::io::Read as _;
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use teagarden_mfa::kslot::protector::{KekTransport, SlotProtector};
use teagarden_mfa::kslot::{SlotVault, TangProtector};

fn find_bin(names: &[&str]) -> Option<String> {
    for n in names {
        if std::path::Path::new(n).exists() {
            return Some(n.to_string());
        }
    }
    // Fall back to PATH lookup.
    for n in names {
        if !n.contains('/') && Command::new(n).arg("--help").output().is_ok() {
            return Some(n.to_string());
        }
    }
    None
}

fn tangd() -> Option<String> {
    find_bin(&[
        "/usr/lib/tangd",
        "/usr/libexec/tangd",
        "/usr/lib/x86_64-linux-gnu/tangd",
    ])
}
fn tangd_keygen() -> Option<String> {
    find_bin(&[
        "/usr/lib/tangd-keygen",
        "/usr/libexec/tangd-keygen",
        "/usr/lib/x86_64-linux-gnu/tangd-keygen",
        "tangd-keygen",
    ])
}
fn have(bin: &str) -> bool {
    Command::new(bin).arg("--help").output().is_ok()
}

fn require_tang() -> bool {
    std::env::var_os("TEAGARDEN_REQUIRE_TANG").is_some()
}

fn tang_lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l); // small race window before socat rebinds — fine for a serialized test
    p
}

/// A running tangd served over HTTP via socat. Killed on drop.
struct Tang {
    socat: Child,
    _keys: tempfile::TempDir,
    url: String,
    _guard: MutexGuard<'static, ()>,
}

impl Drop for Tang {
    fn drop(&mut self) {
        let _ = self.socat.kill();
        let _ = self.socat.wait();
    }
}

fn start_tang() -> Option<Tang> {
    let guard = tang_lock();
    let (Some(tangd), Some(keygen)) = (tangd(), tangd_keygen()) else {
        assert!(
            !require_tang(),
            "TEAGARDEN_REQUIRE_TANG set but tangd/tangd-keygen missing"
        );
        eprintln!("SKIP: tangd / tangd-keygen not found");
        return None;
    };
    if !have("clevis") || !have("socat") {
        assert!(
            !require_tang(),
            "TEAGARDEN_REQUIRE_TANG set but clevis/socat missing"
        );
        eprintln!("SKIP: clevis / socat not available");
        return None;
    }

    let keys = tempfile::tempdir().unwrap();
    let keydir = keys.path().to_string_lossy().to_string();
    // Generate the Tang signing + exchange keys (owner/group warnings are harmless
    // when not running as the tang user).
    let kg = Command::new(&keygen)
        .arg(&keydir)
        .output()
        .expect("run tangd-keygen");
    if !kg.status.success() {
        assert!(
            !require_tang(),
            "TEAGARDEN_REQUIRE_TANG set but tangd-keygen failed"
        );
        eprintln!(
            "SKIP: tangd-keygen failed: {}",
            String::from_utf8_lossy(&kg.stderr)
        );
        return None;
    }

    let port = free_port();
    let socat = Command::new("socat")
        .arg(format!("TCP-LISTEN:{port},fork,reuseaddr"))
        .arg(format!("SYSTEM:{tangd} {keydir}"))
        .spawn();
    let socat = match socat {
        Ok(c) => c,
        Err(e) => {
            assert!(
                !require_tang(),
                "TEAGARDEN_REQUIRE_TANG set but socat spawn failed: {e}"
            );
            eprintln!("SKIP: socat spawn failed: {e}");
            return None;
        }
    };

    // Wait until tangd answers a GET /adv with 200 through socat.
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut ready = false;
    while Instant::now() < deadline {
        if adv_ok(port) {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let tang = Tang {
        socat,
        _keys: keys,
        url: format!("http://127.0.0.1:{port}"),
        _guard: guard,
    };
    if !ready {
        assert!(
            !require_tang(),
            "TEAGARDEN_REQUIRE_TANG set but tangd never became ready"
        );
        eprintln!("SKIP: tangd did not become ready");
        return None;
    }
    Some(tang)
}

/// Minimal HTTP GET /adv, returning true on a 200 response line.
fn adv_ok(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    use std::io::Write as _;
    if s.write_all(b"GET /adv HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).contains(" 200"),
        _ => false,
    }
}

/// (1) The protector binds a KEK to the Tang server and recovers exactly it.
#[test]
fn tang_bind_recover_roundtrip() {
    let Some(tang) = start_tang() else { return };

    let mut p = TangProtector::new(&tang.url, None);
    let enrollment = p.enroll().expect("enroll binds a KEK to the Tang server");
    let bound_kek = *enrollment.kek.as_bytes();

    let recovered = p
        .recover_kek(&enrollment.params, &enrollment.transport)
        .expect("recover unbinds the KEK via the Tang exchange");

    assert_eq!(
        &bound_kek,
        recovered.as_bytes(),
        "the Tang exchange must recover exactly the bound KEK"
    );
}

/// (2) THE INTEGRATION: a slot vault's master key is protected by, and recovered
/// from, the Tang server — the real K0a-vault + K4-factor path end to end.
#[test]
fn tang_slot_protects_and_recovers_master_key() {
    let Some(tang) = start_tang() else { return };

    let (mut vault, mk) = SlotVault::create("k4-tang-test");
    let mk_bytes = *mk.as_bytes();

    let mut enroll_p = TangProtector::new(&tang.url, None);
    vault
        .add_independent_slot(&mk, &mut enroll_p, "tang")
        .expect("enroll a Tang slot into the vault");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.json");
    vault.save(&path).unwrap();
    let reloaded = SlotVault::load(&path).unwrap();

    let unlock_p = TangProtector::new(&tang.url, None);
    let refs: Vec<&dyn SlotProtector> = vec![&unlock_p];
    let recovered_mk = reloaded
        .unlock_targeted(&refs) // Tang requires a network round-trip → targeted
        .expect("the Tang slot must recover the master key");

    assert_eq!(
        &mk_bytes,
        recovered_mk.as_bytes(),
        "MK recovered via Tang must equal the original"
    );
}

/// (3) NEGATIVE — a tampered JWE is refused: clevis decrypt fails rather than
/// yielding a wrong-but-accepted KEK.
#[test]
fn tang_tampered_jwe_is_refused() {
    let Some(tang) = start_tang() else { return };

    let mut p = TangProtector::new(&tang.url, None);
    let enrollment = p.enroll().expect("enroll binds a KEK to Tang");

    let tampered = match &enrollment.transport {
        KekTransport::Exchange { jwe } => {
            // Flip a byte in the middle of the JWE — corrupts the ciphertext/tag.
            let mut b = jwe.clone().into_bytes();
            let mid = b.len() / 2;
            b[mid] = if b[mid] == b'A' { b'B' } else { b'A' };
            KekTransport::Exchange {
                jwe: String::from_utf8_lossy(&b).into_owned(),
            }
        }
        _ => panic!("expected an Exchange transport"),
    };
    assert!(
        p.recover_kek(&enrollment.params, &tampered).is_err(),
        "a tampered JWE must not recover the KEK"
    );
}
