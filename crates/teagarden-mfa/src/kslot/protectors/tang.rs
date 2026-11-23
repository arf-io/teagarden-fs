//! K4: Tang / Clevis NBDE slot protector — a network-bound "something you can
//! reach" factor.
//!
//! This is the mechanism Clevis / `systemd-cryptenroll`-style network-bound disk
//! encryption use: a random per-slot KEK is bound to a **Tang server** via
//! `clevis encrypt tang` (a McCallum–Relyea blinded key exchange). The resulting
//! JWE stores no key material and the Tang server never learns the KEK — but the
//! KEK can only be recovered by a party that can **reach that Tang server** at
//! unlock (`clevis decrypt`). So the data is bound to network presence /
//! possession of the escrow endpoint, not to a local secret. Optionally the
//! server's advertisement **thumbprint** is pinned to defeat a first-contact MITM.
//!
//! Uses the `clevis` CLI (no compile-time dependency), so it is always compiled;
//! `is_available()` / a clear error covers a host without clevis. The KEK is passed
//! to/from clevis over **stdin/stdout** — never written to a temp file. Tests drive
//! it against a locally-served `tangd`.
//!
//! Transport: `KekTransport::Exchange` carries the self-describing JWE (it embeds
//! the Tang URL + key id, so unlock needs only the JWE + network). `params` record
//! the URL + pinned thumbprint for auditing/re-enroll.
//!
//! Per the trait contract the caller directs *when* this runs (unlock contacts the
//! network — not something to do speculatively).

use std::io::Write as _;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use crate::error::{MfaError, Result};

use super::super::protector::{Enrollment, KekTransport, SlotProtector};
use super::super::types::{Kek, SlotType};

fn e(msg: impl std::fmt::Display) -> MfaError {
    MfaError::Factor(format!("tang/clevis: {msg}"))
}

/// A Tang / Clevis protector. Its config is the Tang server URL (+ optional pinned
/// advertisement thumbprint); there is no client secret — recovery requires
/// reaching the server.
pub struct TangProtector {
    url: String,
    thumbprint: Option<String>,
}

impl TangProtector {
    /// A protector binding to the Tang server at `url`. If `thumbprint` is set, the
    /// server's signing-key thumbprint must match it at enroll (defeats a
    /// trust-on-first-use MITM); `None` trusts the first advertisement.
    pub fn new(url: impl Into<String>, thumbprint: Option<String>) -> Self {
        Self {
            url: url.into(),
            thumbprint,
        }
    }

    /// Whether the `clevis` CLI is present.
    pub fn is_available() -> bool {
        Command::new("clevis")
            .arg("--help")
            .output()
            .map(|o| o.status.success() || o.status.code().is_some())
            .unwrap_or(false)
    }

    /// Run `clevis <args>` feeding `input` on stdin, returning stdout. `input` is
    /// zeroized by the caller; stdout (a secret on decrypt) is returned in a
    /// `Zeroizing` buffer.
    fn run_clevis(args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut child = Command::new("clevis")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| e(format!("spawn clevis: {err} (is clevis installed?)")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| e("no stdin pipe"))?
            .write_all(input)
            .map_err(|err| e(format!("write stdin: {err}")))?;
        let out = child
            .wait_with_output()
            .map_err(|err| e(format!("wait clevis: {err}")))?;
        if !out.status.success() {
            return Err(e(format!(
                "clevis {} failed: {}",
                args.first().copied().unwrap_or(""),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(Zeroizing::new(out.stdout))
    }
}

impl SlotProtector for TangProtector {
    fn slot_type(&self) -> SlotType {
        SlotType::Tang
    }

    fn enroll(&mut self) -> Result<Enrollment> {
        // clevis tang config: {"url": "...", "thp": "..."} — thp pins the server's
        // advertisement thumbprint; without it we pass -y to trust first contact.
        let cfg = match &self.thumbprint {
            Some(thp) => serde_json::json!({ "url": self.url, "thp": thp }).to_string(),
            None => serde_json::json!({ "url": self.url }).to_string(),
        };

        let kek = Kek::random();
        let mut args = vec!["encrypt", "tang", cfg.as_str()];
        if self.thumbprint.is_none() {
            args.push("-y"); // trust the advertisement on first contact (TOFU)
        }
        let jwe = Self::run_clevis(&args, kek.as_bytes())?;
        let jwe = String::from_utf8(jwe.to_vec())
            .map_err(|err| e(format!("clevis produced non-utf8 JWE: {err}")))?;

        let params = serde_json::json!({
            "version": 1,
            "url": self.url,
            "thumbprint": self.thumbprint,
        });
        Ok(Enrollment {
            params,
            transport: KekTransport::Exchange { jwe },
            kek,
        })
    }

    fn recover_kek(&self, _params: &serde_json::Value, transport: &KekTransport) -> Result<Kek> {
        // The JWE is self-describing (embeds the Tang URL + kid), so decrypt needs
        // only the JWE + network reach to the server.
        let jwe = match transport {
            KekTransport::Exchange { jwe } => jwe,
            _ => return Err(e("tang slot has a non-Exchange transport")),
        };
        let plain = Self::run_clevis(&["decrypt"], jwe.as_bytes())?;
        let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| e("recovered KEK is not 32 bytes"))?,
        );
        Ok(Kek::from_bytes(*arr))
    }
}
