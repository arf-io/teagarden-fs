//! K2: TPM2 **sealing** slot protector — a real TPM2 factor via `tpm2-tools`.
//!
//! This is the mechanism `systemd-cryptenroll --tpm2-device` / Clevis `tpm2` use:
//! a random KEK is **sealed** into a TPM2 keyedhash object under the owner
//! hierarchy's storage root key (SRK). The sealed private blob is encrypted by the
//! SRK, which never leaves the TPM — so the KEK can only be recovered by *that*
//! physical TPM ("something you have", hardware-bound). Optionally the seal is
//! bound to a **PCR policy** (e.g. firmware/bootloader/Secure-Boot measurements),
//! so unseal of this slot is refused when the selected PCR values change.
//!
//! Uses the `tpm2-tools` CLI (no compile-time TPM library), so it is always
//! compiled; `is_available()` / a clear error covers a host without tpm2-tools or a
//! TPM. Tests drive it against a software TPM (`swtpm`) via `TPM2TOOLS_TCTI`, which
//! the subprocesses inherit.
//!
//! Transport: `KekTransport::Sealed` carries the object's public + private blobs
//! (the only per-slot state); `params` records the PCR selection. No secret is
//! stored in the vault — the KEK exists only inside the TPM's sealed private blob.
//!
//! Per the trait contract, the caller directs *when* this runs (the vault never
//! tries it speculatively — a wrong PCR state would consume a TPM dictionary-attack
//! attempt).

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use zeroize::Zeroizing;

use crate::error::{MfaError, Result};

use super::super::protector::{Enrollment, KekTransport, SlotProtector};
use super::super::types::{Kek, SlotType};

/// A TPM2 sealing protector. Its factor "input" is the (optional) PCR selection to
/// bind to at enroll; at unlock the PCR selection is read back from the slot params
/// so the same policy is reproduced.
pub struct Tpm2SealProtector {
    /// PCR selection to bind the seal to, in tpm2-tools syntax
    /// (e.g. `"sha256:0,1,7"`). `None` = bind to the TPM only (no boot-state
    /// policy) — still hardware-bound, just not evil-maid-resistant.
    pcrs: Option<String>,
}

impl Tpm2SealProtector {
    /// A protector binding to `pcrs` (e.g. `Some("sha256:0,1,7")`), or `None` for a
    /// TPM-only seal.
    pub fn new(pcrs: Option<String>) -> Self {
        Self { pcrs }
    }

    /// Whether `tpm2-tools` is present (does not prove a TPM is reachable).
    pub fn is_available() -> bool {
        Command::new("tpm2_createprimary")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Run a `tpm2_*` tool in `dir`, mapping failure (non-zero exit) to a Tpm2 error
    /// carrying stderr. The subprocess inherits `TPM2TOOLS_TCTI` from our env.
    fn run(cmd: &str, args: &[&str], dir: &Path) -> Result<Output> {
        let out = Command::new(cmd)
            .args(args)
            .current_dir(dir)
            .output()
            .map_err(|e| MfaError::Tpm2(format!("{cmd}: {e} (is tpm2-tools installed?)")))?;
        if !out.status.success() {
            return Err(MfaError::Tpm2(format!(
                "{cmd} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out)
    }

    /// Like [`Self::run`] but feeds `stdin_bytes` on the child's stdin — used to
    /// pass the KEK to `tpm2_create -i -` without ever writing it to a file
    /// (advisor: keep the cleartext KEK off disk). Returns the captured stdout.
    fn run_stdin(cmd: &str, args: &[&str], dir: &Path, stdin_bytes: &[u8]) -> Result<Output> {
        let mut child = Command::new(cmd)
            .args(args)
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| MfaError::Tpm2(format!("{cmd}: {e} (is tpm2-tools installed?)")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| MfaError::Tpm2("no stdin pipe".into()))?
            .write_all(stdin_bytes)
            .map_err(|e| MfaError::Tpm2(format!("{cmd} write stdin: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| MfaError::Tpm2(format!("{cmd} wait: {e}")))?;
        if !out.status.success() {
            return Err(MfaError::Tpm2(format!(
                "{cmd} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out)
    }

    /// Best-effort flush of all TRANSIENT objects. A TPM has very few transient
    /// object slots (often 3) and, unlike a fresh reset, a persistent software TPM
    /// keeps objects resident across separate `tpm2_*` process invocations — so
    /// without this a multi-step seal/unseal hits `TPM_RC_OBJECT_MEMORY`. Ignoring
    /// the result is intentional: a clean TPM has nothing to flush.
    fn flush_transient(dir: &Path) {
        let _ = Command::new("tpm2_flushcontext")
            .arg("-t")
            .current_dir(dir)
            .output();
    }

    /// Create the owner-hierarchy SRK primary into `primary.ctx`. Deterministic for
    /// a fixed template + hierarchy seed, so recreating it at unseal yields the same
    /// key that the sealed object is encrypted to (systemd/Clevis rely on this).
    ///
    /// The template is **pinned explicitly** (`ecc256:aes128cfb`) rather than left to
    /// tpm2-tools' bare `-G ecc` default (advisor): the SRK is derived from
    /// (hierarchy seed, template) via KDFa, so if a future tpm2-tools release changed
    /// its default `ecc` template the recreated primary would differ and every sealed
    /// blob would fail to unseal — silent data loss on a tool upgrade. An explicit
    /// curve+symmetric fixes that contract; it is verified deterministic against swtpm.
    ///
    /// Flushes transient objects before (clear leftovers) and after (the primary is
    /// saved in the context file, so the resident copy is not needed and would only
    /// consume a slot the subsequent create/load reload needs).
    fn create_primary(dir: &Path) -> Result<()> {
        Self::flush_transient(dir);
        Self::run(
            "tpm2_createprimary",
            &["-C", "o", "-G", "ecc256:aes128cfb", "-c", "primary.ctx"],
            dir,
        )?;
        Self::flush_transient(dir);
        Ok(())
    }

    /// Build a PCR policy digest into `policy.dat` for the configured PCRs.
    fn build_pcr_policy(dir: &Path, pcrs: &str) -> Result<()> {
        Self::run(
            "tpm2_createpolicy",
            &["--policy-pcr", "-l", pcrs, "-L", "policy.dat"],
            dir,
        )?;
        Ok(())
    }
}

impl SlotProtector for Tpm2SealProtector {
    fn slot_type(&self) -> SlotType {
        SlotType::Tpm2
    }

    fn enroll(&mut self) -> Result<Enrollment> {
        let tmp = tempfile::tempdir().map_err(MfaError::Io)?;
        let dir = tmp.path();

        Self::create_primary(dir)?;

        // Seal the random KEK into a keyedhash object under the SRK. The KEK is fed
        // to `tpm2_create -i -` on STDIN — never written to a file (advisor). With a
        // PCR policy the object is usable ONLY via that policy (drop userwithauth so
        // an empty password cannot unseal it); without one it is a plain TPM-bound
        // seal. (seal.pub/seal.priv are non-secret — a public + TPM-encrypted blob.)
        let kek = Kek::random();
        let mut create_args: Vec<&str> = vec![
            "-C",
            "primary.ctx",
            "-i",
            "-",
            "-u",
            "seal.pub",
            "-r",
            "seal.priv",
        ];
        if let Some(ref pcrs) = self.pcrs {
            Self::build_pcr_policy(dir, pcrs)?;
            create_args.extend_from_slice(&["-L", "policy.dat", "-a", "fixedtpm|fixedparent"]);
        }
        Self::run_stdin("tpm2_create", &create_args, dir, kek.as_bytes())?;

        let public = std::fs::read(dir.join("seal.pub")).map_err(MfaError::Io)?;
        let private = std::fs::read(dir.join("seal.priv")).map_err(MfaError::Io)?;

        let params = serde_json::json!({
            "version": 1,
            "pcrs": self.pcrs,
        });
        Ok(Enrollment {
            params,
            transport: KekTransport::Sealed { public, private },
            kek,
        })
    }

    fn recover_kek(&self, params: &serde_json::Value, transport: &KekTransport) -> Result<Kek> {
        let (public, private) = match transport {
            KekTransport::Sealed { public, private } => (public, private),
            _ => {
                return Err(MfaError::Tpm2(
                    "tpm2 slot has a non-sealed transport".into(),
                ))
            }
        };
        // The PCR selection to satisfy is authoritative from the stored params (the
        // caller-supplied one is only used at enroll).
        let pcrs = params
            .get("pcrs")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let tmp = tempfile::tempdir().map_err(MfaError::Io)?;
        let dir = tmp.path();
        std::fs::write(dir.join("seal.pub"), public).map_err(MfaError::Io)?;
        std::fs::write(dir.join("seal.priv"), private).map_err(MfaError::Io)?;

        Self::create_primary(dir)?;
        Self::run(
            "tpm2_load",
            &[
                "-C",
                "primary.ctx",
                "-u",
                "seal.pub",
                "-r",
                "seal.priv",
                "-c",
                "seal.ctx",
            ],
            dir,
        )?;

        // Unseal to STDOUT (no `-o` file) so the cleartext KEK never touches disk.
        let unseal_out = if let Some(ref pcrs) = pcrs {
            // Satisfy the PCR policy in a live policy session, then unseal under it.
            Self::run(
                "tpm2_startauthsession",
                &["--policy-session", "-S", "session.ctx"],
                dir,
            )?;
            let res = Self::run("tpm2_policypcr", &["-S", "session.ctx", "-l", pcrs], dir)
                .and_then(|_| {
                    Self::run(
                        "tpm2_unseal",
                        &["-p", "session:session.ctx", "-c", "seal.ctx"],
                        dir,
                    )
                });
            // Always flush the session, even if unseal failed (a wrong PCR state).
            let _ = Self::run("tpm2_flushcontext", &["session.ctx"], dir);
            res.map_err(|e| {
                MfaError::Tpm2(format!(
                    "TPM2 unseal refused (PCR state changed since enroll?): {e}"
                ))
            })?
        } else {
            Self::run("tpm2_unseal", &["-c", "seal.ctx"], dir)?
        };

        let raw = Zeroizing::new(unseal_out.stdout);
        let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
            raw.as_slice()
                .try_into()
                .map_err(|_| MfaError::Tpm2("unsealed KEK is not 32 bytes".into()))?,
        );
        Ok(Kek::from_bytes(*arr))
    }
}
