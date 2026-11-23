//! Hardware serial / machine identity factor.
//!
//! Derives a contribution from stable hardware identifiers:
//! - `/etc/machine-id` (Linux systemd machine ID — survives reboots)
//! - `/sys/class/dmi/id/board_serial` (motherboard serial number)
//! - `/sys/class/dmi/id/product_uuid` (system UUID from UEFI)
//! - `/proc/cpuinfo` Serial field (if exposed by CPU)
//!
//! A random `machine_salt` (stored in the descriptor) prevents an attacker
//! who knows the hardware identifiers from pre-computing the contribution
//! without the vault file.
//!
//! # Security note
//!
//! This factor binds the vault to a specific machine. Migrating to new
//! hardware requires removing and re-creating the MFA vault. It is intended
//! as a **secondary** factor alongside password, not as the sole factor.

use rand::RngCore;
use serde_json::json;

use crate::error::{MfaError, Result};
use crate::factor::{FactorDescriptor, KeyFactor};

const FACTOR_TYPE: &str = "hardware_serial";

/// Key factor that binds the vault to this machine's stable hardware identifiers,
/// blended with a per-vault random salt so the contribution can't be precomputed.
pub struct HardwareSerialFactor {
    machine_salt: [u8; 32],
}

impl HardwareSerialFactor {
    /// Create with a fresh random salt.
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        Self { machine_salt: salt }
    }

    /// Reconstruct from a persisted salt (hex-encoded in descriptor).
    pub fn from_salt_hex(salt_hex: &str) -> Result<Self> {
        let bytes = hex::decode(salt_hex)
            .map_err(|e| MfaError::HardwareBinding(format!("invalid salt hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(MfaError::HardwareBinding("salt must be 32 bytes".into()));
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes);
        Ok(Self { machine_salt: salt })
    }
}

impl Default for HardwareSerialFactor {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyFactor for HardwareSerialFactor {
    fn factor_type(&self) -> &'static str {
        FACTOR_TYPE
    }

    fn descriptor(&self) -> FactorDescriptor {
        FactorDescriptor::new(
            FACTOR_TYPE,
            json!({ "machine_salt": hex::encode(self.machine_salt) }),
        )
    }

    fn derive_contribution(&self) -> Result<[u8; 32]> {
        let machine_id = collect_machine_identifiers()?;
        Ok(blake3::keyed_hash(&self.machine_salt, machine_id.as_bytes()).into())
    }
}

/// Collect stable hardware identifiers from the system, concatenated.
fn collect_machine_identifiers() -> Result<String> {
    let mut parts = Vec::new();

    // Primary: systemd machine-id (stable across reboots, unique per install)
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        parts.push(format!("machine-id:{}", id.trim()));
    }

    // Motherboard serial
    if let Ok(s) = std::fs::read_to_string("/sys/class/dmi/id/board_serial") {
        let s = s.trim();
        if !s.is_empty() && s != "To be filled by O.E.M." && s != "None" {
            parts.push(format!("board_serial:{s}"));
        }
    }

    // System UUID (from UEFI/BIOS)
    if let Ok(uuid) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
        let uuid = uuid.trim();
        if !uuid.is_empty() && uuid != "None" {
            parts.push(format!("product_uuid:{uuid}"));
        }
    }

    // CPU serial (usually only available on embedded/server CPUs)
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if line.starts_with("Serial") {
                if let Some(serial) = line.split(':').nth(1) {
                    let serial = serial.trim();
                    if !serial.is_empty() && serial != "0000000000000000" {
                        parts.push(format!("cpu_serial:{serial}"));
                    }
                }
            }
        }
    }

    // macOS: the IOKit platform UUID + hardware serial are the stable per-machine
    // identifiers (the equivalent of /etc/machine-id), read via `ioreg`.
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for (key, label) in [
                ("IOPlatformUUID", "platform_uuid"),
                ("IOPlatformSerialNumber", "platform_serial"),
            ] {
                if let Some(val) = text
                    .lines()
                    .find(|l| l.contains(key))
                    .and_then(|l| l.split('"').nth(3))
                {
                    let val = val.trim();
                    if !val.is_empty() {
                        parts.push(format!("{label}:{val}"));
                    }
                }
            }
        }
    }

    if parts.is_empty() {
        return Err(MfaError::HardwareBinding(
            "no stable hardware identifiers found (Linux: /etc/machine-id or DMI; \
             macOS: IOPlatformUUID via ioreg)"
                .into(),
        ));
    }

    Ok(parts.join("|"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contribution_is_deterministic() {
        let f = HardwareSerialFactor::new();
        let c1 = f.derive_contribution();
        let c2 = f.derive_contribution();
        // Both may fail on machines without hardware IDs, or both succeed
        match (c1, c2) {
            (Ok(a), Ok(b)) => assert_eq!(a, b),
            (Err(_), Err(_)) => {}
            _ => panic!("inconsistent results"),
        }
    }

    #[test]
    fn different_salt_different_contribution() {
        let f1 = HardwareSerialFactor::new();
        let f2 = HardwareSerialFactor::new(); // different salt
        if let (Ok(a), Ok(b)) = (f1.derive_contribution(), f2.derive_contribution()) {
            assert_ne!(a, b);
        }
    }

    #[test]
    fn salt_hex_roundtrip() {
        let f = HardwareSerialFactor::new();
        let salt_hex = hex::encode(f.machine_salt);
        let f2 = HardwareSerialFactor::from_salt_hex(&salt_hex).unwrap();
        assert_eq!(f.machine_salt, f2.machine_salt);
    }
}
