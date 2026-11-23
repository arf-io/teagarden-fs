//! TPM2 factor — derives a contribution via TPM2 HMAC sealed to PCR values.
//!
//! # Architecture
//!
//! Uses `tpm2-tools` CLI commands (must be installed: `pacman -S tpm2-tools`).
//! Does NOT require a Rust TPM2 library at compile time.
//!
//! ## Setup (`teagarden mfa setup --tpm2`)
//!
//! 1. Create a primary key under the Owner hierarchy.
//! 2. Create an HMAC key sealed to PCR digest (PCRs 0,1,7: firmware, bootloader,
//!    Secure Boot state).
//! 3. Persist the HMAC key at a fixed NV handle (0x81000001).
//! 4. Store the handle and challenge in the vault descriptor.
//!
//! ## Usage (`teagarden volume open --volume X`)
//!
//! 1. Run `tpm2_hmac --hex -c 0x81000001 -- <challenge>`.
//! 2. The TPM2 runs the policy (PCR check) and returns the HMAC output.
//! 3. If PCRs changed (firmware update, kernel swap), the policy fails.
//!
//! # Security properties
//!
//! - **Hardware binding**: Key is in TPM2 NV storage; exportable only via HMAC.
//! - **PCR sealing**: Refuses to operate if boot measurements changed (evil maid).
//! - **Dictionary attack protection**: TPM2 DA lockout limits wrong attempts.
//!
//! # Limitations
//!
//! - Requires physical TPM2 chip (most x86-64 systems since 2016).
//! - PCR binding means firmware/kernel updates invalidate the factor.
//!   Re-create the vault after updates (use `teagarden mfa rotate`).
//! - Virtual machines typically have vTPM — works but PCR values may differ.

use rand::RngCore;
use serde_json::json;
use std::process::Command;

use crate::error::{MfaError, Result};
use crate::factor::{FactorDescriptor, KeyFactor};

const FACTOR_TYPE: &str = "tpm2";
const DEFAULT_HANDLE: &str = "0x81000001";
const PCRS: &str = "0,1,7";

/// Legacy TPM2 factor (old `factors::` path) — HMAC sealed to PCRs via the
/// `tpm2-tools` CLI. Superseded by the K0a key-slot vault; kept behind the
/// `tpm2` feature until the K2 kslot TPM2 protector replaces it.
pub struct Tpm2Factor {
    /// TPM2 persistent handle for the HMAC key.
    handle: String,
    /// Random 32-byte challenge (hex-encoded in descriptor).
    challenge: [u8; 32],
}

impl Tpm2Factor {
    /// Create a new factor, provisioning the TPM2 HMAC key.
    ///
    /// Requires `tpm2-tools` to be installed and a writable TPM2.
    pub fn provision() -> Result<Self> {
        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);

        // 1. Create primary key
        let primary = run_tpm2(
            "tpm2_createprimary",
            &[
                "-C",
                "o",
                "-G",
                "ecc",
                "-c",
                "/tmp/teagarden_tpm2_primary.ctx",
            ],
        )?;
        if !primary.status.success() {
            return Err(MfaError::Tpm2(
                String::from_utf8_lossy(&primary.stderr).to_string(),
            ));
        }

        // 2. Create HMAC key with PCR policy (PCRs 0,1,7)
        let policy = run_tpm2(
            "tpm2_createpolicy",
            &[
                "--policy-pcr",
                "-l",
                &format!("sha256:{PCRS}"),
                "-L",
                "/tmp/teagarden_pcr.policy",
            ],
        )?;
        if !policy.status.success() {
            return Err(MfaError::Tpm2(format!(
                "PCR policy: {}",
                String::from_utf8_lossy(&policy.stderr)
            )));
        }

        let create = run_tpm2(
            "tpm2_create",
            &[
                "-G",
                "hmac",
                "-C",
                "/tmp/teagarden_tpm2_primary.ctx",
                "-L",
                "/tmp/teagarden_pcr.policy",
                "-u",
                "/tmp/teagarden_hmac.pub",
                "-r",
                "/tmp/teagarden_hmac.priv",
            ],
        )?;
        if !create.status.success() {
            return Err(MfaError::Tpm2(format!(
                "create HMAC key: {}",
                String::from_utf8_lossy(&create.stderr)
            )));
        }

        // 3. Load and persist
        let load = run_tpm2(
            "tpm2_load",
            &[
                "-C",
                "/tmp/teagarden_tpm2_primary.ctx",
                "-u",
                "/tmp/teagarden_hmac.pub",
                "-r",
                "/tmp/teagarden_hmac.priv",
                "-c",
                "/tmp/teagarden_hmac.ctx",
            ],
        )?;
        if !load.status.success() {
            return Err(MfaError::Tpm2(
                String::from_utf8_lossy(&load.stderr).to_string(),
            ));
        }

        let evict = run_tpm2(
            "tpm2_evictcontrol",
            &["-C", "o", "-c", "/tmp/teagarden_hmac.ctx", DEFAULT_HANDLE],
        )?;
        if !evict.status.success() {
            return Err(MfaError::Tpm2(format!(
                "persist key: {}",
                String::from_utf8_lossy(&evict.stderr)
            )));
        }

        // Clean up temp files
        for f in [
            "/tmp/teagarden_tpm2_primary.ctx",
            "/tmp/teagarden_pcr.policy",
            "/tmp/teagarden_hmac.pub",
            "/tmp/teagarden_hmac.priv",
            "/tmp/teagarden_hmac.ctx",
        ] {
            let _ = std::fs::remove_file(f);
        }

        Ok(Self {
            handle: DEFAULT_HANDLE.to_string(),
            challenge,
        })
    }

    /// Reconstruct from a persisted descriptor.
    pub fn from_descriptor(handle: impl Into<String>, challenge_hex: &str) -> Result<Self> {
        let bytes = hex::decode(challenge_hex)
            .map_err(|e| MfaError::Tpm2(format!("challenge decode: {e}")))?;
        if bytes.len() != 32 {
            return Err(MfaError::Tpm2("challenge must be 32 bytes".into()));
        }
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&bytes);
        Ok(Self {
            handle: handle.into(),
            challenge,
        })
    }

    /// Check whether `tpm2-tools` is available on this system.
    pub fn is_available() -> bool {
        Command::new("tpm2_hmac").arg("--version").output().is_ok()
    }
}

impl KeyFactor for Tpm2Factor {
    fn factor_type(&self) -> &'static str {
        FACTOR_TYPE
    }

    fn descriptor(&self) -> FactorDescriptor {
        FactorDescriptor::new(
            FACTOR_TYPE,
            json!({
                "handle": self.handle,
                "challenge": hex::encode(self.challenge),
                "pcrs": PCRS,
                "policy": "pcr-sha256",
            }),
        )
    }

    fn derive_contribution(&self) -> Result<[u8; 32]> {
        // tpm2_hmac --hex -c <handle> -- <challenge_hex>
        let challenge_hex = hex::encode(self.challenge);
        let out = run_tpm2(
            "tpm2_hmac",
            &["--hex", "-c", &self.handle, "--", &challenge_hex],
        )?;

        if !out.status.success() {
            return Err(MfaError::Tpm2(format!(
                "HMAC failed (PCR mismatch or key not provisioned): {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }

        let hex_output = String::from_utf8_lossy(&out.stdout);
        let hex_output = hex_output.trim();

        let hmac_bytes = hex::decode(hex_output)
            .map_err(|e| MfaError::Tpm2(format!("HMAC output decode: {e}")))?;

        // The TPM2 HMAC output may be any length; hash it to 32 bytes
        Ok(blake3::hash(&hmac_bytes).into())
    }
}

fn run_tpm2(command: &str, args: &[&str]) -> Result<std::process::Output> {
    Command::new(command)
        .args(args)
        .output()
        .map_err(|e| MfaError::Tpm2(format!("{command}: {e}")))
}
