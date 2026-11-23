//! K1: FIDO2 hmac-secret slot, via the `age-plugin-fido2-hmac` plugin.
//!
//! ## Why this delegates instead of speaking CTAP directly
//!
//! This protector previously drove `ctap-hid-fido2` itself. That **did not work**
//! on FIDO2.1 authenticators with `alwaysUv` (typically the biometric ones):
//! `mfa enroll` succeeded and wrote a well-formed slot, and `mfa unlock` then
//! failed with *"vault decryption failed — wrong factor value"*. Two causes,
//! both fatal:
//!
//! 1. **PIN protocol.** `ctap-hid-fido2` hardcodes `pin_protocol_version: 1`.
//!    A FIDO2.1 `alwaysUv` token advertises `pin protocols: 2, 1` and expects the
//!    protocol-2 `pinUvAuthToken` construction; a protocol-1 `pinUvAuthParam`
//!    returns `CTAP2_ERR_PIN_INVALID` **even for a correct PIN** — burning a
//!    retry and tripping the three-strike lockout.
//! 2. **UV-keyed hmac-secret.** CTAP2 keeps two per-credential secrets,
//!    `CredRandomWithUV` and `CredRandomWithoutUV`, and `hmac-secret` returns
//!    whichever matches *that assertion's* UV state. The old code recorded
//!    neither which state it used at enroll nor pinned it at unlock, so the two
//!    could land on different secrets and derive different KEKs.
//!
//! Both are protocol-negotiation problems that `libfido2` — the C reference
//! implementation — already solves. `age-plugin-fido2-hmac` is built on it, so
//! this delegates rather than re-implementing CTAP badly.
//!
//! ## Shape
//!
//! The operator chooses a verification mode ([`Fido2Mode`]) before anything
//! touches the key. Enrollment then wraps a random KEK with the plugin's
//! *data-less* identity used as a recipient — the path `age -e -j fido2-hmac`
//! takes (main.go `HandleIdentityEncodingAsRecipient`, which calls
//! `NewCredentials(..., askForIdentity=false)`). The plugin creates a new
//! credential and embeds its descriptor in the age stanza; there is no separate
//! identity and no question about one. The plugin's one remaining question,
//! whether to require the PIN for decryption, arrives over the age plugin
//! protocol and is answered from the chosen mode.
//!
//! The slot records the mode. The plugin records the PIN requirement in the
//! stanza, and the authenticator binds it: a PIN-verified assertion releases
//! `CredRandomWithUV`, an unverified one `CredRandomWithoutUV` (CTAP 2.1
//! section 12.5), so a stanza whose flag was flipped derives the wrong key. Both
//! records are checked against each other at enrollment (before the slot is
//! saved) and at unlock (before the plugin runs).
//!
//! The embedded descriptor is **not** key material. Without the physical
//! authenticator it opens nothing.

use std::io::Write as _;
use std::str::FromStr;
use std::sync::Arc;

use age::plugin::{Identity as PluginIdentity, IdentityPluginV1, RecipientPluginV1};
use age::Callbacks;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{MfaError, Result};

use super::super::protector::{Enrollment, KekTransport, SlotProtector};
use super::super::types::{Kek, SlotType};
use super::fido2_mode::Fido2Mode;
use super::fido2_ux::{describe_failure, Announcer, TouchPlan, TouchSession};

/// age plugin name; also the binary suffix (`age-plugin-fido2-hmac`).
const PLUGIN: &str = "fido2-hmac";
/// Wrapping scheme id recorded in the slot transport.
const SCHEME: &str = "age-fido2-hmac";
/// The plugin's data-less identity (`age-plugin-fido2-hmac -m`). As a recipient it
/// makes the plugin create a new credential; as an identity it makes the plugin
/// read the credential from the stanza.
const MAGIC_IDENTITY: &str = "AGE-PLUGIN-FIDO2-HMAC-1VE5KGMEJ945X6CTRM2TF76";
/// Slot params version. 4 records the verification mode; earlier slots did not.
const SLOT_VERSION: u64 = 4;
/// pkg/plugin/cli.go `NewCredentials`, asked only when the key has a PIN set.
const PIN_QUESTION: &str = "Do you want to require a PIN for decryption?";
/// cmd/age-plugin-fido2-hmac/main.go `shouldUsePQ`, asked unless FIDO2_HMAC_PQ is set.
const PQ_QUESTION: &str = "Use post-quantum encryption (MLKEM768X25519)?";
/// Stanza format version 2 (`STANZA_FORMAT_VERSION`), base64 of `[0x00, 0x02]`.
const STANZA_V2: &str = "AAI";
/// Base64 length of a 32-byte X25519 share; a hybrid stanza's share is longer.
const X25519_SHARE_LEN: usize = 43;

/// What the operator chose for a newly enrolled credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fido2GenerationOptions {
    /// What the key must check at every unlock.
    pub mode: Fido2Mode,
    /// Use the plugin's ML-KEM-768/X25519 hybrid stanza instead of X25519.
    pub post_quantum: bool,
}

impl Fido2GenerationOptions {
    /// `mode`, with the classical X25519 stanza.
    pub fn new(mode: Fido2Mode) -> Self {
        Self {
            mode,
            post_quantum: false,
        }
    }
}

/// The PIN, read for the plugin from the terminal. `None` when there is none,
/// with the reason noted for the error message.
fn operator_pin(ux: &TouchSession, description: &str) -> Option<age::secrecy::SecretString> {
    let pin = read_tty_secret(description);
    if pin.is_none() {
        ux.note(
            "the security key needs its PIN but there is no terminal to ask for it on \
             (run this from an interactive terminal)",
        );
    }
    pin.map(age::secrecy::SecretString::from)
}

/// Callbacks for an operator-attended unlock.
///
/// The token may demand a PIN. It is read from `/dev/tty` with echo off and
/// dropped immediately: never stored, never logged, never passed via an argument
/// or environment variable. If there is no terminal this returns `None` and the
/// unlock fails — the correct outcome for an unattended process, because software
/// that can answer a PIN prompt is software that holds the PIN.
#[derive(Clone)]
struct OperatorCallbacks {
    ux: Arc<TouchSession>,
}

impl Callbacks for OperatorCallbacks {
    fn display_message(&self, message: &str) {
        // The human needs to know the token is waiting for a touch: the plugin's
        // notice becomes a numbered banner on the terminal, not a line on stderr.
        self.ux.on_message(message);
    }

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        // A confirmation answered by software is an approval nobody gave.
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<age::secrecy::SecretString> {
        operator_pin(&self.ux, description)
    }
}

/// The answer to a plugin question during enrollment, when the operator already
/// gave it: the PIN requirement comes from the mode, the recipient kind from the
/// post-quantum option. Any other question gets no answer.
fn enroll_answer(question: &str, mode: Fido2Mode, post_quantum: bool) -> Option<bool> {
    match question.trim() {
        PIN_QUESTION => Some(mode.requires_pin()),
        PQ_QUESTION => Some(post_quantum),
        _ => None,
    }
}

/// Callbacks for enrollment: as for unlock, except that the two questions the
/// operator answered by choosing a mode are answered for them.
#[derive(Clone)]
struct EnrollCallbacks {
    ux: Arc<TouchSession>,
    options: Fido2GenerationOptions,
}

impl Callbacks for EnrollCallbacks {
    fn display_message(&self, message: &str) {
        self.ux.on_message(message);
    }

    fn confirm(&self, message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        let answer = enroll_answer(message, self.options.mode, self.options.post_quantum);
        if answer.is_none() {
            self.ux.note(&format!(
                "age-plugin-fido2-hmac asked a question TeaGarden does not answer for you: \
                 {:?}. TeaGarden answers only whether to require the PIN (from the chosen \
                 mode) and whether to use post-quantum encryption (from \
                 --fido2-post-quantum). The slot was NOT saved.",
                message.trim()
            ));
        }
        answer
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<age::secrecy::SecretString> {
        operator_pin(&self.ux, description)
    }
}

/// Read one secret from the controlling terminal with echo disabled.
/// `None` when there is no terminal, so an unattended caller cannot succeed.
fn read_tty_secret(prompt: &str) -> Option<String> {
    use std::io::{BufRead, BufReader};
    use std::os::fd::AsFd;

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let original = nix::sys::termios::tcgetattr(tty.as_fd()).ok()?;
    let mut quiet = original.clone();
    quiet
        .local_flags
        .remove(nix::sys::termios::LocalFlags::ECHO);
    nix::sys::termios::tcsetattr(tty.as_fd(), nix::sys::termios::SetArg::TCSANOW, &quiet).ok()?;

    let mut out = &tty;
    let _ = write!(out, "{}", super::fido2_ux::pin_prompt(prompt));
    let _ = out.flush();

    // `read_line` can return an error after placing partial input in the
    // buffer. Keep the buffer zeroizing so every return path scrubs it.
    let mut line = Zeroizing::new(String::new());
    let read = BufReader::new(&tty).read_line(&mut line).ok();

    // Always restore the terminal, even if the read failed. A failed restore is
    // surfaced and the secret is discarded: continuing with a terminal left in
    // no-echo mode would hide subsequent input from the operator.
    let restored =
        nix::sys::termios::tcsetattr(tty.as_fd(), nix::sys::termios::SetArg::TCSANOW, &original);
    let _ = writeln!(out);

    if let Err(error) = restored {
        let _ = writeln!(
            std::io::stderr(),
            "warning: could not restore terminal echo: {error}; run `stty echo` in this terminal"
        );
        return None;
    }

    read?;
    let secret = line.trim_end_matches(['\r', '\n']).to_string();
    Some(secret)
}

/// What the plugin recorded about the credential in a wrapped KEK's age header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CredentialShape {
    /// The stanza's require-PIN flag: the plugin will ask for the PIN and pass it
    /// to the key, which then releases `CredRandomWithUV`.
    requires_pin: bool,
    /// The stanza wraps to ML-KEM-768/X25519 rather than X25519.
    post_quantum: bool,
}

/// Read the plugin's stanza from the age header of `ciphertext`.
///
/// The v2 stanza is `-> fido2-hmac <version> <share> <require-pin> <salt>
/// <credential id>` (pkg/plugin/recipient.go `Wrap`, parsed by plugin.go
/// `ParseFido2HmacStanza`). Exactly one is expected: TeaGarden wraps to one
/// recipient. The header text ends at the `---` MAC line, before any binary data.
fn credential_shape(ciphertext: &[u8]) -> Result<CredentialShape> {
    let malformed = |what: &str| MfaError::Factor(format!("fido2 slot: {what}"));
    let end = ciphertext
        .windows(4)
        .position(|w| w == b"\n---")
        .ok_or_else(|| malformed("the wrapped key is not an age file"))?;
    let header = std::str::from_utf8(&ciphertext[..end])
        .map_err(|_| malformed("the wrapped key is not an age file"))?;
    let mut lines = header.lines();
    if lines.next() != Some("age-encryption.org/v1") {
        return Err(malformed("the wrapped key is not an age file"));
    }
    let stanzas: Vec<Vec<&str>> = lines
        .filter_map(|line| line.strip_prefix("-> "))
        .map(|line| line.split(' ').collect::<Vec<_>>())
        .filter(|args| args.first() == Some(&PLUGIN))
        .collect();
    let [stanza] = stanzas.as_slice() else {
        return Err(malformed(&format!(
            "expected exactly one fido2-hmac stanza in the wrapped key, found {}",
            stanzas.len()
        )));
    };
    let args = &stanza[1..];
    if args.len() != 5 || args[0] != STANZA_V2 {
        return Err(malformed(
            "the fido2-hmac stanza is not the plugin's version 2 format",
        ));
    }
    let requires_pin = match args[2] {
        "AQ" => true,
        "AA" => false,
        other => {
            return Err(malformed(&format!(
                "the fido2-hmac stanza has an unknown require-PIN flag {other:?}"
            )))
        }
    };
    Ok(CredentialShape {
        requires_pin,
        post_quantum: args[1].len() != X25519_SHARE_LEN,
    })
}

/// Refuse a freshly wrapped KEK whose credential is not what the operator chose.
fn check_enrolled(ciphertext: &[u8], options: Fido2GenerationOptions) -> Result<()> {
    let shape = credential_shape(ciphertext)?;
    let mode = options.mode;
    if shape.requires_pin != mode.requires_pin() {
        return Err(MfaError::Factor(if mode.requires_pin() {
            format!(
                "FIDO2 enrollment refused: mode {} needs a credential that requires the key's \
                 PIN, but the plugin created one that does not. That happens when the key has \
                 no PIN set, because the plugin then never asks. The slot was NOT saved. Set a \
                 PIN with `fido2-token -S <device>` (see `fido2-token -L`) and enroll again, or \
                 choose --fido2-mode up.",
                mode.title()
            )
        } else {
            format!(
                "FIDO2 enrollment refused: mode {} needs a credential that does not require \
                 the key's PIN, but the plugin created one that does. The slot was NOT saved.",
                mode.title()
            )
        }));
    }
    if shape.post_quantum != options.post_quantum {
        return Err(MfaError::Factor(format!(
            "FIDO2 enrollment refused: --fido2-post-quantum was {}, but the plugin wrapped \
             the key {} post-quantum encryption. FIDO2_HMAC_PQ in the environment overrides \
             the choice; unset it. The slot was NOT saved.",
            if options.post_quantum {
                "given"
            } else {
                "not given"
            },
            if shape.post_quantum {
                "with"
            } else {
                "without"
            },
        )));
    }
    Ok(())
}

/// The non-secret slot params: the mode the slot unlocks with.
fn slot_params(mode: Fido2Mode) -> serde_json::Value {
    serde_json::json!({
        "version": SLOT_VERSION,
        "plugin": PLUGIN,
        "mode": mode.as_str(),
    })
}

/// The mode a slot recorded at enrollment. Slots that recorded none were made
/// before modes existed and are refused.
fn recorded_mode(params: &serde_json::Value) -> Result<Fido2Mode> {
    let version = params.get("version").and_then(serde_json::Value::as_u64);
    let mode = params.get("mode").and_then(serde_json::Value::as_str);
    match (version, mode) {
        (Some(SLOT_VERSION), Some(name)) => {
            let mode = Fido2Mode::from_name(name).ok_or_else(|| {
                MfaError::Factor(format!("fido2 slot: unknown verification mode {name:?}"))
            })?;
            mode.ensure_available()?;
            Ok(mode)
        }
        _ => Err(MfaError::Factor(
            "fido2 slot: this slot records no verification mode (it was enrolled by an \
             earlier build). Remove it and re-enroll the factor with --fido2-mode."
                .into(),
        )),
    }
}

/// A FIDO2 hmac-secret protector backed by `age-plugin-fido2-hmac`.
pub struct Fido2HmacProtector {
    /// The operator's choices for a credential enrolled by this protector.
    generation: Option<Fido2GenerationOptions>,
    /// Name shown in the unlock notice.
    volume_label: Option<String>,
}

impl Fido2HmacProtector {
    fn plugin_help_has_required_capabilities(help: &str) -> bool {
        help.contains("--post-quantum")
            && help.contains("-y [FILE]")
            && help.contains("--algorithm")
    }

    /// A protector that unlocks with the mode stored in the slot. To enroll, add
    /// the operator's choices with [`Self::with_generation_options`].
    pub fn new() -> Self {
        Self {
            generation: None,
            volume_label: None,
        }
    }

    /// Name the volume being unlocked, for the notice shown to the operator.
    pub fn with_volume_label(mut self, label: impl Into<String>) -> Self {
        self.volume_label = Some(label.into());
        self
    }

    /// The operator's choices for a newly enrolled credential. A mode that cannot
    /// be enforced is refused here, with the reason, before anything runs.
    pub fn with_generation_options(mut self, options: Fido2GenerationOptions) -> Result<Self> {
        options.mode.ensure_available()?;
        self.generation = Some(options);
        Ok(self)
    }

    /// Locate the plugin binary and verify the command surface TeaGarden uses.
    ///
    /// Version text is not reliable for locally built Go binaries (the upstream
    /// version variable is populated only by release linker flags), so this is a
    /// capability check. The required surface first shipped together in v0.5.0.
    fn require_plugin() -> Result<()> {
        let bin = format!("age-plugin-{PLUGIN}");
        let path = std::env::var_os("PATH")
            .and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|path| path.join(&bin))
                    .find(|path| path.is_file())
            })
            .ok_or_else(|| {
                MfaError::Factor(format!(
                    "{bin} not found on PATH — the FIDO2 factor needs it. \
                 Install v0.5.0 or later from \
                 https://github.com/olastor/age-plugin-fido2-hmac"
                ))
            })?;
        let output = std::process::Command::new(&path)
            .arg("--help")
            .output()
            .map_err(|e| MfaError::Factor(format!("cannot execute {}: {e}", path.display())))?;
        let help = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !output.status.success() || !Self::plugin_help_has_required_capabilities(&help) {
            return Err(MfaError::Factor(format!(
                "{bin} is incompatible — TeaGarden requires v0.5.0 or later \
                 with --post-quantum, identity-to-recipient (-y), and --algorithm support"
            )));
        }
        Ok(())
    }

    fn magic_identity() -> Result<PluginIdentity> {
        PluginIdentity::from_str(MAGIC_IDENTITY)
            .map_err(|_| MfaError::Factor("the plugin's data-less identity is malformed".into()))
    }

    /// Wrap `plaintext` to a credential the plugin creates now, answering its
    /// questions from `options`.
    fn wrap_to_new_credential(
        plaintext: &[u8],
        options: Fido2GenerationOptions,
        ux: &Arc<TouchSession>,
    ) -> Result<Vec<u8>> {
        let callbacks = EnrollCallbacks {
            ux: Arc::clone(ux),
            options,
        };
        let recipient: Box<dyn age::Recipient> = Box::new(
            RecipientPluginV1::new(PLUGIN, &[], &[Self::magic_identity()?], callbacks).map_err(
                |e| MfaError::Factor(format!("age-plugin-{PLUGIN} is unavailable: {e}")),
            )?,
        );
        // age 0.11 runs the plugin inside `with_recipients`.
        let failed =
            |e: &dyn std::fmt::Display| enroll_failure(&e.to_string(), ux.take_note().as_deref());
        let enc = age::Encryptor::with_recipients(std::iter::once(recipient.as_ref()))
            .map_err(|e| failed(&e))?;
        let mut out = Vec::new();
        let mut w = enc.wrap_output(&mut out).map_err(|e| failed(&e))?;
        w.write_all(plaintext)
            .map_err(|e| MfaError::Factor(format!("age write: {e}")))?;
        w.finish()
            .map_err(|e| MfaError::Factor(format!("age finish: {e}")))?;
        Ok(out)
    }

    /// The plugin identity that reads the credential from the stanza.
    fn age_identity(ux: &Arc<TouchSession>) -> Result<IdentityPluginV1<OperatorCallbacks>> {
        let callbacks = OperatorCallbacks { ux: Arc::clone(ux) };
        IdentityPluginV1::new(PLUGIN, &[Self::magic_identity()?], callbacks)
            .map_err(|e| MfaError::Factor(format!("age-plugin-{PLUGIN} is unavailable: {e}")))
    }
}

/// The error for a failed key operation: what the operator-side steps noted (no
/// terminal for the PIN, an unanswered question), else the plugin's own words,
/// put plainly. Neither contains the PIN.
fn unwrap_failure(text: &str, note: Option<&str>) -> MfaError {
    MfaError::Factor(match note {
        Some(note) => note.to_string(),
        None => describe_failure(text),
    })
}

/// The error for a failed enrollment wrap. When the plugin fails it sends an
/// `error` stanza and exits without `done` (age plugin.go `identityError`), and
/// age 0.11 then reports only that it died: name the likely causes instead.
fn enroll_failure(text: &str, note: Option<&str>) -> MfaError {
    if let Some(note) = note {
        return MfaError::Factor(note.to_string());
    }
    let said = if text.contains("unexpectedly died") || text.contains("incomplete response") {
        "age-plugin-fido2-hmac stopped without saying why (the age library drops a plugin's \
         error report when the plugin exits during encryption). The usual causes are a wrong \
         PIN, no touch in time, or the key being removed. A wrong PIN uses up one of the key's \
         PIN attempts: check how many are left with `fido2-token -I <device>` (see \
         `fido2-token -L`) before trying again."
            .to_string()
    } else {
        describe_failure(text)
    };
    MfaError::Factor(format!(
        "FIDO2 credential creation failed: {said} The slot was NOT saved."
    ))
}

impl Default for Fido2HmacProtector {
    fn default() -> Self {
        Self::new()
    }
}

fn age_decrypt(
    identity: &dyn age::Identity,
    ciphertext: &[u8],
    ux: &TouchSession,
) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read as _;
    let dec = age::Decryptor::new(ciphertext)
        .map_err(|e| MfaError::Factor(format!("age decryptor: {e}")))?;
    let mut r = dec.decrypt(std::iter::once(identity)).map_err(|e| {
        unwrap_failure(
            &format!("FIDO2 unwrap failed: {e}"),
            ux.take_note().as_deref(),
        )
    })?;
    let mut buf = Zeroizing::new(Vec::new());
    r.read_to_end(&mut buf)
        .map_err(|e| MfaError::Factor(format!("age read: {e}")))?;
    Ok(buf)
}

impl SlotProtector for Fido2HmacProtector {
    fn slot_type(&self) -> SlotType {
        SlotType::Fido2Hmac
    }

    fn enroll(&mut self) -> Result<Enrollment> {
        let options = self.generation.ok_or_else(|| {
            MfaError::Factor(
                "FIDO2 enrollment needs a verification mode and no verification mode was \
                 chosen (pass --fido2-mode)"
                    .into(),
            )
        })?;
        options.mode.ensure_available()?;
        Self::require_plugin()?;

        let ux = TouchSession::new(TouchPlan::enrollment(options.mode), Announcer::open());
        ux.announce_plan();

        // Random KEK, wrapped to a credential the plugin creates now.
        let mut kek_bytes = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut kek_bytes);
        let kek = Kek::from_bytes(kek_bytes);
        let wrapped = Self::wrap_to_new_credential(&kek_bytes, options, &ux);
        kek_bytes.zeroize();
        let ciphertext = wrapped?;

        // The plugin decides the PIN requirement only when the key has a PIN set;
        // check what it actually recorded before anything is saved.
        check_enrolled(&ciphertext, options)?;
        ux.finish_ok();

        Ok(Enrollment {
            params: slot_params(options.mode),
            transport: KekTransport::EncryptedKek {
                scheme: SCHEME.to_string(),
                ciphertext,
            },
            kek,
        })
    }

    fn recover_kek(&self, params: &serde_json::Value, transport: &KekTransport) -> Result<Kek> {
        let mode = recorded_mode(params)?;
        let ciphertext = match transport {
            KekTransport::EncryptedKek { scheme, ciphertext } if scheme == SCHEME => ciphertext,
            KekTransport::EncryptedKek { scheme, .. } => {
                return Err(MfaError::Factor(format!(
                    "fido2 slot: unexpected wrapping scheme '{scheme}'"
                )))
            }
            KekTransport::Derived => {
                return Err(MfaError::Factor(
                    "fido2 slot: this slot predates the age-plugin rewrite \
                     (derived-KEK format) and cannot be unlocked; re-enroll it."
                        .into(),
                ))
            }
            other => {
                return Err(MfaError::Factor(format!(
                    "fido2 slot: unsupported KEK transport {other:?}; re-enroll the factor"
                )))
            }
        };

        // The prompts follow the recorded mode and the plugin follows the stanza:
        // refuse before either runs if they disagree.
        let shape = credential_shape(ciphertext)?;
        if shape.requires_pin != mode.requires_pin() {
            return Err(MfaError::Factor(format!(
                "fido2 slot: the slot records mode {} but its credential {} the key's PIN. \
                 The slot file was altered or damaged; refusing to unlock with it. Open the \
                 volume with another slot and re-enroll this one.",
                mode.title(),
                if shape.requires_pin {
                    "requires"
                } else {
                    "does not require"
                }
            )));
        }

        let ux = TouchSession::new(
            TouchPlan::unlock(mode, self.volume_label.as_deref()),
            Announcer::open(),
        );
        Self::require_plugin()?;
        ux.announce_plan();
        let id = Self::age_identity(&ux)?;
        let plain = age_decrypt(&id, ciphertext, &ux)?;
        ux.finish_ok();
        let bytes: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| MfaError::Factor("fido2 slot: unwrapped KEK is not 32 bytes".into()))?;
        Ok(Kek::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The questions age-plugin-fido2-hmac v0.5.0 asks through the age plugin
    /// protocol, verbatim: pkg/plugin/cli.go `NewCredentials` (the PIN and the
    /// separate-identity questions) and cmd/age-plugin-fido2-hmac/main.go
    /// `shouldUsePQ`.
    const SEPARATE_IDENTITY_QUESTION: &str =
        "Are you fine with having a separate identity (better privacy)?\n";

    /// 43 base64 characters: the length of an X25519 share or a 32-byte value.
    const B43: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// An age header carrying one plugin stanza shaped as the plugin's v2
    /// `Fido2HmacRecipient.Wrap` writes it (pkg/plugin/recipient.go): stanza
    /// version, native share, require-PIN flag, salt, credential id.
    fn header(stanzas: &[(&str, &str)]) -> Vec<u8> {
        let mut text = String::from("age-encryption.org/v1\n");
        for (pin_flag, share) in stanzas {
            text.push_str(&format!(
                "-> fido2-hmac AAI {share} {pin_flag} {B43} cmVkYWN0ZWQ\n{B43}\n"
            ));
        }
        text.push_str(&format!("--- {B43}\n"));
        let mut bytes = text.into_bytes();
        bytes.extend_from_slice(&[0xff, 0x00, 0x0a, 0x2d]);
        bytes
    }

    fn transport(ciphertext: Vec<u8>) -> KekTransport {
        KekTransport::EncryptedKek {
            scheme: SCHEME.to_string(),
            ciphertext,
        }
    }

    /// A `Write` whose contents the test can read back.
    #[derive(Clone, Default)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn quiet() -> Arc<TouchSession> {
        TouchSession::new(
            TouchPlan::enrollment(Fido2Mode::PinUp),
            Announcer::from_writer(Box::new(Capture::default())),
        )
    }

    #[test]
    fn enrollment_answers_the_pin_question_with_the_chosen_mode() {
        assert_eq!(
            enroll_answer(PIN_QUESTION, Fido2Mode::PinUp, false),
            Some(true)
        );
        assert_eq!(
            enroll_answer(PIN_QUESTION, Fido2Mode::Up, false),
            Some(false)
        );
        assert_eq!(
            enroll_answer(PIN_QUESTION, Fido2Mode::Up, true),
            Some(false)
        );
    }

    #[test]
    fn enrollment_answers_the_post_quantum_question_with_the_chosen_option() {
        assert_eq!(
            enroll_answer(PQ_QUESTION, Fido2Mode::PinUp, true),
            Some(true)
        );
        assert_eq!(
            enroll_answer(PQ_QUESTION, Fido2Mode::Up, false),
            Some(false)
        );
    }

    #[test]
    fn enrollment_never_answers_the_separate_identity_question() {
        // The data-less path TeaGarden uses never asks it; if a plugin ever does,
        // nobody chose an answer, so none is given and enrollment fails closed.
        assert_eq!(
            enroll_answer(SEPARATE_IDENTITY_QUESTION, Fido2Mode::PinUp, false),
            None
        );
        let ux = quiet();
        let callbacks = EnrollCallbacks {
            ux: Arc::clone(&ux),
            options: Fido2GenerationOptions::new(Fido2Mode::Up),
        };
        assert_eq!(
            callbacks.confirm(SEPARATE_IDENTITY_QUESTION, "yes", Some("no")),
            None
        );
        let note = ux.take_note().expect("the refusal is explained");
        assert!(note.contains("separate identity"), "{note}");
        assert!(note.contains("NOT saved"), "{note}");
    }

    #[test]
    fn unlock_answers_no_question_at_all() {
        let callbacks = OperatorCallbacks { ux: quiet() };
        for question in [PIN_QUESTION, PQ_QUESTION, SEPARATE_IDENTITY_QUESTION] {
            assert_eq!(callbacks.confirm(question, "yes", Some("no")), None);
        }
    }

    #[test]
    fn the_header_says_whether_the_credential_requires_a_pin() {
        let shape = credential_shape(&header(&[("AQ", B43)])).unwrap();
        assert_eq!(
            shape,
            CredentialShape {
                requires_pin: true,
                post_quantum: false
            }
        );
        let shape = credential_shape(&header(&[("AA", B43)])).unwrap();
        assert!(!shape.requires_pin);
        // A hybrid stanza carries the ML-KEM-768/X25519 encapsulation, not a
        // 32-byte X25519 share.
        let long = "A".repeat(1500);
        assert!(
            credential_shape(&header(&[("AA", &long)]))
                .unwrap()
                .post_quantum
        );
    }

    #[test]
    fn a_header_without_exactly_one_plugin_stanza_is_refused() {
        for bad in [header(&[]), header(&[("AQ", B43), ("AA", B43)])] {
            let err = credential_shape(&bad).unwrap_err();
            assert!(format!("{err}").contains("exactly one"), "{err}");
        }
        let err = credential_shape(&header(&[("Ag", B43)])).unwrap_err();
        assert!(format!("{err}").contains("require-PIN flag"), "{err}");
        let err = credential_shape(b"not an age file").unwrap_err();
        assert!(format!("{err}").contains("not an age"), "{err}");
    }

    #[test]
    fn enrollment_refuses_a_pin_up_credential_created_without_a_pin() {
        // A key with no PIN set: the plugin never asks the PIN question and
        // silently creates a credential that does not require one.
        let options = Fido2GenerationOptions::new(Fido2Mode::PinUp);
        let err = check_enrolled(&header(&[("AA", B43)]), options).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("NOT saved"), "{msg}");
        assert!(msg.contains("fido2-token -S"), "{msg}");
        assert!(msg.contains("--fido2-mode up"), "{msg}");
        assert!(check_enrolled(&header(&[("AQ", B43)]), options).is_ok());
    }

    #[test]
    fn enrollment_refuses_an_up_credential_that_requires_a_pin() {
        let options = Fido2GenerationOptions::new(Fido2Mode::Up);
        let err = check_enrolled(&header(&[("AQ", B43)]), options).unwrap_err();
        assert!(format!("{err}").contains("NOT saved"), "{err}");
        assert!(check_enrolled(&header(&[("AA", B43)]), options).is_ok());
    }

    #[test]
    fn enrollment_refuses_a_recipient_kind_other_than_the_one_chosen() {
        // FIDO2_HMAC_PQ in the environment overrides the plugin's question.
        let options = Fido2GenerationOptions {
            mode: Fido2Mode::Up,
            post_quantum: false,
        };
        let long = "A".repeat(1500);
        let err = check_enrolled(&header(&[("AA", &long)]), options).unwrap_err();
        assert!(format!("{err}").contains("FIDO2_HMAC_PQ"), "{err}");
    }

    #[test]
    fn the_slot_records_the_mode() {
        let params = slot_params(Fido2Mode::PinUp);
        assert_eq!(params["version"], 4);
        assert_eq!(params["plugin"], "fido2-hmac");
        assert_eq!(params["mode"], "pin-up");
        assert_eq!(slot_params(Fido2Mode::Up)["mode"], "up");
        assert_eq!(
            recorded_mode(&slot_params(Fido2Mode::Up)).unwrap(),
            Fido2Mode::Up
        );
    }

    #[test]
    fn unlock_refuses_a_slot_without_a_recorded_mode() {
        let old = serde_json::json!({
            "version": 3,
            "plugin": "fido2-hmac",
            "identity": MAGIC_IDENTITY,
            "recipient": "age1fido2-hmac1fixture",
        });
        let err = Fido2HmacProtector::new()
            .recover_kek(&old, &transport(header(&[("AQ", B43)])))
            .unwrap_err();
        assert!(format!("{err}").contains("re-enroll"), "{err}");
    }

    #[test]
    fn unlock_refuses_a_recorded_mode_that_cannot_be_enforced() {
        let params = serde_json::json!({"version": 4, "plugin": "fido2-hmac", "mode": "uv"});
        let err = Fido2HmacProtector::new()
            .recover_kek(&params, &transport(header(&[("AA", B43)])))
            .unwrap_err();
        assert!(format!("{err}").contains("is not available"), "{err}");
    }

    #[test]
    fn unlock_refuses_a_slot_whose_record_and_credential_disagree() {
        // Checked before the plugin runs: no prompt is shown for a mode the
        // credential does not have.
        let err = Fido2HmacProtector::new()
            .recover_kek(
                &slot_params(Fido2Mode::Up),
                &transport(header(&[("AQ", B43)])),
            )
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("UP only"), "{msg}");
        assert!(msg.contains("requires the key's PIN"), "{msg}");
        let err = Fido2HmacProtector::new()
            .recover_kek(
                &slot_params(Fido2Mode::PinUp),
                &transport(header(&[("AA", B43)])),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("does not require"), "{err}");
    }

    #[test]
    fn generation_options_refuse_a_mode_that_cannot_be_enforced() {
        for mode in [Fido2Mode::Pin, Fido2Mode::PinUv, Fido2Mode::Uv] {
            let err = Fido2HmacProtector::new()
                .with_generation_options(Fido2GenerationOptions::new(mode))
                .err()
                .expect("refused");
            assert!(
                format!("{err}").contains(mode.unavailable_reason().unwrap()),
                "{err}"
            );
        }
        for mode in [Fido2Mode::PinUp, Fido2Mode::Up] {
            assert!(Fido2HmacProtector::new()
                .with_generation_options(Fido2GenerationOptions::new(mode))
                .is_ok());
        }
    }

    #[test]
    fn enrolling_without_a_chosen_mode_is_refused_before_the_plugin_runs() {
        let err = Fido2HmacProtector::new().enroll().err().expect("refused");
        assert!(format!("{err}").contains("no verification mode"), "{err}");
    }

    #[test]
    fn plugin_capability_check_rejects_pre_hybrid_command_surface() {
        let legacy = "Usage: age-plugin-fido2-hmac [-s] [-a ALG] -g\n\
                      --generate --symmetric --algorithm";
        assert!(!Fido2HmacProtector::plugin_help_has_required_capabilities(
            legacy
        ));

        let current = "--generate --symmetric --post-quantum -y [FILE] --algorithm";
        assert!(Fido2HmacProtector::plugin_help_has_required_capabilities(
            current
        ));
    }

    #[test]
    fn missing_plugin_is_a_clear_error_not_a_panic() {
        // With a PATH containing no plugin, the error must name the binary and
        // say how to get it, rather than failing opaquely inside age.
        let saved = std::env::var_os("PATH");
        std::env::set_var("PATH", "/nonexistent-for-teagarden-test");
        let r = Fido2HmacProtector::require_plugin();
        if let Some(p) = saved {
            std::env::set_var("PATH", p);
        }
        let e = r.expect_err("must fail when the plugin is absent");
        let msg = format!("{e}");
        assert!(
            msg.contains("age-plugin-fido2-hmac"),
            "error should name the binary: {msg}"
        );
    }

    #[test]
    fn a_wrong_pin_while_unlocking_is_reported_as_such() {
        let text =
            "FIDO2 unwrap failed: 'age-plugin-fido2-hmac' couldn't use an identity: pin invalid";
        let err = unwrap_failure(text, None);
        assert!(format!("{err}").contains("wrong PIN"), "{err}");
        // An operator-side cause noted during the operation wins.
        let err = unwrap_failure("whatever", Some("no terminal to ask for the PIN"));
        assert!(format!("{err}").contains("no terminal"), "{err}");
    }

    #[test]
    fn a_plugin_that_dies_during_enrollment_is_explained() {
        // The plugin reports an error stanza and exits without `done`
        // (age plugin.go recipientError/identityError); age 0.11 then reports
        // only that the plugin died.
        let died = "'age-plugin-fido2-hmac' unexpectedly died.";
        let msg = format!("{}", enroll_failure(died, None));
        assert!(msg.contains("wrong PIN"), "{msg}");
        assert!(msg.contains("fido2-token -I"), "{msg}");
        assert!(msg.contains("NOT saved"), "{msg}");
        // An operator-side cause noted during the run wins.
        let msg = format!("{}", enroll_failure(died, Some("no terminal for the PIN")));
        assert_eq!(msg, "factor error: no terminal for the PIN");
        // Text the plugin did deliver is described as usual.
        let msg = format!("{}", enroll_failure("pin invalid", None));
        assert!(msg.contains("wrong PIN for the security key"), "{msg}");
        assert!(msg.contains("NOT saved"), "{msg}");
    }

    #[test]
    fn a_derived_transport_slot_is_refused_with_guidance() {
        // Slots written by the pre-rewrite CTAP-direct code used Derived; they
        // cannot unlock, and the error must say to re-enroll rather than just
        // reporting a decryption failure.
        let e = Fido2HmacProtector::new()
            .recover_kek(&slot_params(Fido2Mode::PinUp), &KekTransport::Derived)
            .expect_err("legacy derived slot must be refused");
        assert!(
            format!("{e}").contains("re-enroll"),
            "should tell the user to re-enroll"
        );
    }
}
