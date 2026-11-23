//! macOS Secure Enclave Processor (SEP) / Touch ID factor.
//!
//! # How it works
//!
//! A random 32-byte secret is generated and stored in the macOS Keychain
//! protected by an Access Control that requires user presence (Touch ID,
//! or the system password as a fallback). The secret is **never written to
//! disk** outside of the Keychain — the vault descriptor only stores a
//! BLAKE3 commitment so retrieval can be verified.
//!
//! On Apple Silicon the Keychain encryption keys are managed by the SEP;
//! on Intel Macs with T2 chip the T2 plays the same role. Intel Macs
//! without T2 use software-backed Keychain and provide no hardware binding.
//!
//! # Requirements
//!
//! - macOS 10.15 or later
//! - Touch ID hardware (optional — system password is accepted as fallback)
//! - Xcode Command Line Tools (`xcrun` must be on PATH)
//!
//! # Security properties
//!
//! - **Hardware binding** (Apple Silicon / T2): The secret is sealed inside
//!   the SEP and cannot be extracted without user presence.
//! - **Confidentiality**: The secret never appears in the descriptor file.
//! - **Tamper detection**: The stored BLAKE3 commitment catches truncation or
//!   substitution attacks on the descriptor.
//!
//! # Limitations
//!
//! - Requires `xcrun swift` (Xcode Command Line Tools).
//! - The Keychain entry is device-local. Migrating to a new Mac requires
//!   removing and re-creating the MFA vault.
//! - If the Keychain entry is deleted (e.g. by the user in Keychain Access),
//!   the vault cannot be opened. Back up `Kmaster` via `teagarden key export`.

use rand::RngCore;
use serde_json::json;
use std::io::Write;
use std::process::Command;

use crate::error::{MfaError, Result};
use crate::factor::{FactorDescriptor, KeyFactor};

const FACTOR_TYPE: &str = "sep_macos";
const KEYCHAIN_SERVICE: &str = "dev.teagarden.sep";

/// MFA key factor backed by the macOS Secure Enclave (SEP), accessed via the
/// Keychain / Touch ID. Holds the Keychain key tag and a BLAKE3 commitment to the
/// derived factor material so the descriptor can detect substitution of the
/// Keychain entry. macOS-only.
pub struct SepFactor {
    key_tag: String,
    commitment: [u8; 32],
}

impl SepFactor {
    /// Provision a new SEP secret: generates a random 32-byte secret, stores it
    /// in the macOS Keychain with Touch ID / user presence ACL, and returns a
    /// factor whose descriptor holds only the tag and a BLAKE3 commitment.
    pub fn provision() -> Result<Self> {
        let key_tag = format!("teagarden.{}", random_hex(16));

        let script_path = write_script()?;
        let out = Command::new("xcrun")
            .args(["swift", &script_path, "provision", &key_tag])
            .output()
            .map_err(|e| MfaError::Sep(format!("xcrun: {e}")))?;
        let _ = std::fs::remove_file(&script_path);

        if !out.status.success() {
            return Err(MfaError::Sep(format!(
                "provision failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        let hex = String::from_utf8_lossy(&out.stdout);
        let secret = hex_to_32(hex.trim())?;
        let commitment = *blake3::hash(&secret).as_bytes();

        Ok(Self {
            key_tag,
            commitment,
        })
    }

    /// Reconstruct from a persisted descriptor (does NOT call the Keychain).
    pub fn from_descriptor(key_tag: impl Into<String>, commitment_hex: &str) -> Result<Self> {
        let bytes = hex::decode(commitment_hex)
            .map_err(|e| MfaError::Sep(format!("commitment decode: {e}")))?;
        if bytes.len() != 32 {
            return Err(MfaError::Sep("commitment must be 32 bytes".into()));
        }
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&bytes);
        Ok(Self {
            key_tag: key_tag.into(),
            commitment,
        })
    }

    /// Remove the Keychain entry.  Called when the MFA vault is removed.
    pub fn deprovision(&self) -> Result<()> {
        let script_path = write_script()?;
        let out = Command::new("xcrun")
            .args(["swift", &script_path, "delete", &self.key_tag])
            .output()
            .map_err(|e| MfaError::Sep(format!("xcrun delete: {e}")))?;
        let _ = std::fs::remove_file(&script_path);
        if !out.status.success() {
            return Err(MfaError::Sep(format!(
                "delete failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    /// Check that `xcrun swift` is available (i.e. Xcode CLT is installed).
    pub fn is_available() -> bool {
        Command::new("xcrun")
            .args(["swift", "--version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

impl KeyFactor for SepFactor {
    fn factor_type(&self) -> &'static str {
        FACTOR_TYPE
    }

    fn descriptor(&self) -> FactorDescriptor {
        FactorDescriptor::new(
            FACTOR_TYPE,
            json!({
                "key_tag": self.key_tag,
                "commitment": hex::encode(self.commitment),
                "keychain_service": KEYCHAIN_SERVICE,
            }),
        )
    }

    fn derive_contribution(&self) -> Result<[u8; 32]> {
        let script_path = write_script()?;
        let reason = "TeaGarden requires Touch ID to unlock your encrypted volume.";
        let out = Command::new("xcrun")
            .args(["swift", &script_path, "retrieve", &self.key_tag, reason])
            .output()
            .map_err(|e| MfaError::Sep(format!("xcrun retrieve: {e}")))?;
        let _ = std::fs::remove_file(&script_path);

        if !out.status.success() {
            return Err(MfaError::Sep(format!(
                "Touch ID authentication failed or key not provisioned: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        let hex = String::from_utf8_lossy(&out.stdout);
        let secret = hex_to_32(hex.trim())?;

        // Verify commitment to catch truncation / substitution attacks
        let actual = *blake3::hash(&secret).as_bytes();
        if !constant_time_eq_32(&actual, &self.commitment) {
            return Err(MfaError::Sep(
                "SEP commitment mismatch — Keychain entry may have been tampered".into(),
            ));
        }

        Ok(secret)
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

fn hex_to_32(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex).map_err(|e| MfaError::Sep(format!("hex decode: {e}")))?;
    if bytes.len() != 32 {
        return Err(MfaError::Sep(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Write the embedded Swift script to a unique temp path and return it.
fn write_script() -> Result<String> {
    let path = format!("/tmp/teagarden_sep_{}.swift", random_hex(8));
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(SWIFT_SCRIPT.as_bytes()))
        .map_err(|e| MfaError::Sep(format!("write script: {e}")))?;
    Ok(path)
}

/// Embedded Swift helper that manages the Keychain entry.
///
/// Commands:
///   provision <tag>              — create entry, print 32-byte secret as hex
///   retrieve  <tag> [reason]    — fetch entry (Touch ID prompt), print hex
///   delete    <tag>              — remove entry, print "deleted"
const SWIFT_SCRIPT: &str = r#"
import Foundation
import Security
import LocalAuthentication

let SERVICE = "dev.teagarden.sep"
let args = CommandLine.arguments

func bail(_ msg: String, code: Int32 = 1) -> Never {
    fputs("\(msg)\n", stderr)
    exit(code)
}

func provision(tag: String) {
    var buf = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, &buf) == errSecSuccess else {
        bail("SecRandomCopyBytes failed", code: 2)
    }
    let secret = Data(buf)

    var cfErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .userPresence,
        &cfErr
    ) else { bail("access control: \(cfErr!.takeRetainedValue())", code: 3) }

    let attrs: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: SERVICE,
        kSecAttrAccount as String: tag,
        kSecValueData as String: secret,
        kSecAttrAccessControl as String: access,
    ]
    SecItemDelete(attrs as CFDictionary)
    let st = SecItemAdd(attrs as CFDictionary, nil)
    guard st == errSecSuccess else { bail("SecItemAdd: \(st)", code: 4) }

    print(secret.map { String(format: "%02x", $0) }.joined())
}

func retrieve(tag: String, reason: String) {
    let ctx = LAContext()
    ctx.localizedReason = reason

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: SERVICE,
        kSecAttrAccount as String: tag,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecReturnData as String: true,
        kSecUseAuthenticationContext as String: ctx,
    ]

    var item: CFTypeRef?
    let st = SecItemCopyMatching(query as CFDictionary, &item)
    guard st == errSecSuccess, let data = item as? Data else {
        bail("SecItemCopyMatching: \(st)", code: 5)
    }
    print(data.map { String(format: "%02x", $0) }.joined())
}

func deleteEntry(tag: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: SERVICE,
        kSecAttrAccount as String: tag,
    ]
    SecItemDelete(query as CFDictionary)
    print("deleted")
}

guard args.count >= 3 else {
    bail("usage: \(args[0]) <provision|retrieve|delete> <tag> [reason]")
}
switch args[1] {
case "provision": provision(tag: args[2])
case "retrieve":  retrieve(tag: args[2], reason: args.count >= 4 ? args[3] : "TeaGarden vault unlock")
case "delete":    deleteEntry(tag: args[2])
default:          bail("unknown command: \(args[1])")
}
"#;
