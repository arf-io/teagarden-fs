use std::io::Write;

use anyhow::{Context, Result};
use teagarden_core::volume::manager;
use teagarden_mfa::kslot::protectors::Fido2Mode;
use teagarden_mfa::unlock::{self, EnrollFactor, UnlockInputs};
use teagarden_mfa::vault::MfaVault;

use super::utils;

/// `--fido2-mode`: what the security key must check each time the slot unlocks.
/// All five are accepted so that the three that cannot be enforced are refused
/// with their reason rather than with a parse error.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Fido2ModeChoice {
    /// PIN only: NOT AVAILABLE (every FIDO2 unlock needs a touch); refused with the reason.
    Pin,
    /// PIN + UP: the key's PIN and a touch.
    PinUp,
    /// PIN + UV: NOT AVAILABLE (CTAP2 cannot require both); refused with the reason.
    PinUv,
    /// UP only: a touch.
    Up,
    /// UV only: NOT AVAILABLE (the plugin never requests it); refused with the reason.
    Uv,
}

impl From<Fido2ModeChoice> for Fido2Mode {
    fn from(value: Fido2ModeChoice) -> Self {
        match value {
            Fido2ModeChoice::Pin => Self::Pin,
            Fido2ModeChoice::PinUp => Self::PinUp,
            Fido2ModeChoice::PinUv => Self::PinUv,
            Fido2ModeChoice::Up => Self::Up,
            Fido2ModeChoice::Uv => Self::Uv,
        }
    }
}

/// The question asked after the mode menu, until an available mode is chosen.
const MODE_PROMPT: &str = "Mode (1-5, or its name such as pin-up): ";

/// The mode menu, every mode in [`Fido2Mode::ALL`] order with the unavailable
/// ones marked.
fn fido2_mode_menu() -> String {
    let mut menu = String::from(
        "Choose what your security key must check each time this slot unlocks the volume:\n",
    );
    for (n, mode) in Fido2Mode::ALL.iter().enumerate() {
        let mark = if mode.unavailable_reason().is_some() {
            "  [not available]"
        } else {
            ""
        };
        menu.push_str(&format!(
            "  {}) {:<9} {}{mark}\n",
            n + 1,
            mode.title(),
            mode.description()
        ));
    }
    menu.push_str(
        "Modes marked [not available] cannot be enforced with age-plugin-fido2-hmac v0.5.0; \
         choose one to see why.\n",
    );
    menu
}

/// A menu answer: the mode's number or its `--fido2-mode` name.
fn parse_mode_answer(answer: &str) -> Option<Fido2Mode> {
    let answer = answer.trim();
    answer
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| Fido2Mode::ALL.get(i).copied())
        .or_else(|| Fido2Mode::from_name(answer))
}

/// Show the mode menu and read answers until an available mode is chosen. An
/// unavailable choice prints why and asks again; no answer enrolls nothing.
fn ask_fido2_mode(input: &mut dyn std::io::BufRead, output: &mut dyn Write) -> Result<Fido2Mode> {
    write!(output, "{}", fido2_mode_menu())?;
    loop {
        write!(output, "{MODE_PROMPT}")?;
        output.flush()?;
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            writeln!(output)?;
            anyhow::bail!("no FIDO2 verification mode was chosen; nothing was enrolled");
        }
        match parse_mode_answer(&line) {
            None => writeln!(output, "  '{}' is not one of the choices.", line.trim())?,
            Some(mode) => match mode.unavailable_reason() {
                None => {
                    writeln!(output, "  Mode {}: {}.", mode.title(), mode.description())?;
                    return Ok(mode);
                }
                Some(reason) => writeln!(output, "  {} is not available: {reason}", mode.title())?,
            },
        }
    }
}

/// Ask for the mode on the controlling terminal, before anything touches the key.
fn ask_fido2_mode_on_tty() -> Result<Fido2Mode> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            anyhow::anyhow!(
                "there is no terminal to ask for the FIDO2 verification mode on: pass \
                 --fido2-mode pin-up (the key's PIN and a touch) or --fido2-mode up (a touch)"
            )
        })?;
    let mut input = std::io::BufReader::new(tty.try_clone().context("open /dev/tty")?);
    let mut output = tty;
    ask_fido2_mode(&mut input, &mut output)
}

/// The FIDO2 mode for this enrollment: the flag, refused with its reason when it
/// cannot be enforced, or else the operator's answer to the menu. `None` when
/// FIDO2 is not the factor being enrolled.
fn resolve_fido2_mode(sel: &FactorSelect) -> Result<Option<Fido2Mode>> {
    if !sel.fido2 {
        return Ok(None);
    }
    let mode = match sel.fido2_mode {
        Some(choice) => {
            let mode = Fido2Mode::from(choice);
            mode.ensure_available()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            mode
        }
        None => ask_fido2_mode_on_tty()?,
    };
    Ok(Some(mode))
}

/// REMOVED (was fake security): the legacy `mfa setup` built an `MfaVault` that
/// **volume open never consulted** — the password alone still opened the volume,
/// while the command told the operator "if you lose a factor you cannot open this
/// volume". That claim was false, so the verb is refused rather than shipped.
///
/// The real, enforced path is K0b: an MK-rooted volume (`volume create
/// --key-protection`) whose data keys derive from a random master key, so a bare
/// password fails closed — plus `mfa enroll` to add hardware factors.
pub async fn setup(
    volume: &str,
    _totp: bool,
    _hardware: bool,
    _tpm2: bool,
    _sep: bool,
) -> Result<()> {
    anyhow::bail!(
        "`keyslot setup` (formerly `mfa setup`) has been REMOVED — it was fake security.\n\
         \n\
         It created a vault that volume open NEVER consulted: the password alone\n\
         still opened the volume, yet the command claimed losing a factor would lock\n\
         you out. Shipping that would misrepresent your security.\n\
         \n\
         Use key slots instead — any one enrolled slot opens the volume (like LUKS):\n\
         \n\
           1. Create a key-protected volume (passphrase slot + recovery slot):\n\
                teagarden volume create --name <name> --key-protection\n\
         \n\
           2. Add a hardware slot (an ADDITIONAL way in, not a requirement):\n\
                teagarden keyslot enroll {volume} --tpm2\n\
         \n\
           3. Verify it actually opens the volume:\n\
                teagarden keyslot unlock {volume} --tpm2\n\
         \n\
           4. To make the hardware necessary, remove the passphrase slot\n\
              (ids from `teagarden keyslot status {volume}`):\n\
                teagarden keyslot remove-slot {volume} <SLOT> --tpm2\n\
         \n\
         If a legacy (non-enforcing) vault exists, delete it:\n\
           teagarden keyslot remove {volume}"
    );
}

/// Show a volume's key slots and what actually gates `open`.
///
/// The vault is any-one-of (mfa-H2): every listed slot opens the volume on its
/// own. The old wording ("ACTIVE (enforced)… REQUIRES a factor") let an
/// operator believe enrolling TPM2 made TPM2 necessary while the passphrase
/// slot still opened the volume. A legacy `MfaVault`, if present, is reported
/// as **NOT enforced** — open never consults it.
pub async fn status(volume: &str) -> Result<()> {
    let volumes_dir = manager::default_volumes_dir();
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;
    let base_dir = volumes_dir.join(&volume_id);

    let config: teagarden_core::volume::config::VolumeConfig = serde_json::from_str(
        &std::fs::read_to_string(base_dir.join("volume.json")).context("read volume config")?,
    )
    .context("parse volume config")?;

    match &config.key_protection {
        Some(kp) => {
            println!(
                "Key slots for '{volume}' — any one enrolled slot opens the volume (like LUKS)."
            );
            println!("  The volume's keys derive from a random master key that each slot wraps");
            println!("  independently. ANY ONE slot below opens the volume on its own; enrolling");
            println!("  a device adds a way in and never makes it required. At least one");
            println!("  passphrase or recovery slot always remains, so a device is never the");
            println!("  only way in.");
            println!(
                "  Vault generation: {} (anti-rollback anchored in config integrity)",
                kp.vault_generation
            );
            match teagarden_mfa::kslot::SlotVault::load(base_dir.join(unlock::SLOT_VAULT_FILENAME))
            {
                Ok(v) => {
                    println!("  Enrolled slots: {}", v.slot_count());
                    for s in v.slots() {
                        println!(
                            "    slot {}  {}  ({}{})",
                            s.slot_id,
                            s.label,
                            slot_type_name(s.slot_type),
                            if s.in_group {
                                ", member of a threshold group"
                            } else {
                                ""
                            }
                        );
                    }
                }
                Err(e) => println!(
                    "  WARNING: slot vault unreadable ({e}) — this volume cannot be opened!"
                ),
            }
            println!();
            println!("  Add a slot:     teagarden keyslot enroll {volume} --tpm2");
            println!("  Remove a slot:  teagarden keyslot remove-slot {volume} <SLOT> --tpm2");
            println!("                  (authorise with a DIFFERENT slot that will remain)");
        }
        None => {
            println!("Key protection: NOT ACTIVE for '{volume}'");
            println!("  This volume is password-rooted: the password ALONE opens it. No factor");
            println!("  can protect it (a factor would only be a bypassable prompt).");
            println!("  Real protection requires an MK-rooted volume:");
            println!("    teagarden volume create --name <name> --key-protection");
        }
    }

    // A legacy vault is NOT enforcement — say so plainly.
    let legacy = MfaVault::path_for_volume(&base_dir);
    if MfaVault::exists(&legacy) {
        println!();
        println!("NOTE: a LEGACY mfa vault exists ({}).", legacy.display());
        println!("  It is NOT enforced — volume open never consults it, so it protects");
        println!("  nothing. Remove it:  teagarden keyslot remove {volume}");
    }

    Ok(())
}

/// Delete a LEGACY (non-enforcing) `MfaVault`.
///
/// **Fails closed on a key-protected volume.** A K0b volume's master key is random
/// and its slot vault is the only ordinary wrapping of it. Deleting that file is
/// unrecoverable data loss unless the operator already holds a separately
/// exported hierarchy-root sentence. The enrolled recovery sentence is itself
/// an in-vault slot and goes through this file. This command cannot prove that a
/// separate root export exists, so the guard is deliberately independent of the
/// filename and always refuses (a critical finding in security review; defense
/// in depth).
pub async fn remove(volume: &str, force: bool) -> Result<()> {
    let volumes_dir = manager::default_volumes_dir();
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;
    let base_dir = volumes_dir.join(&volume_id);
    let vault_path = MfaVault::path_for_volume(&base_dir);

    // HARD refusal: never touch a volume whose keys live in a slot vault.
    if let Ok(json) = std::fs::read_to_string(base_dir.join("volume.json")) {
        if let Ok(config) =
            serde_json::from_str::<teagarden_core::volume::config::VolumeConfig>(&json)
        {
            if config.key_protection.is_some() {
                anyhow::bail!(
                    "REFUSING: '{volume}' is key-protected (MK-rooted). Its master key is\n\
                     random and the slot vault is the ONLY wrapping of it — deleting it\n\
                     would normally destroy the volume permanently (the enrolled\n\
                     recovery sentence depends on that vault). A separately exported\n\
                     hierarchy-root sentence could bypass the vault, but this command\n\
                     cannot prove you hold a valid one.\n\
                     \n\
                     `keyslot remove` only deletes a LEGACY non-enforcing vault. To manage a\n\
                     protected volume's factors:  teagarden keyslot status {volume}"
                );
            }
        }
    }

    if !MfaVault::exists(&vault_path) {
        anyhow::bail!("No legacy MFA vault found for '{volume}'.");
    }

    if !force {
        println!("This deletes a LEGACY mfa vault from '{volume}'.");
        println!("That vault was never enforced (volume open never consulted it), so this");
        println!("does not change who can open the volume — it only removes the misleading");
        println!("file. This volume is password-rooted: the password alone already opens it.");
        let confirm = utils::prompt("Type 'yes' to confirm: ")?;
        if confirm.trim() != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    MfaVault::load(&vault_path)
        .remove()
        .context("remove vault")?;
    println!("Legacy (non-enforcing) mfa vault deleted. Access to '{volume}' is unchanged.");

    Ok(())
}

/// REMOVED alongside [`setup`]: re-wrapping a vault that open never consults is
/// security theatre — it changes nothing about who can open the volume.
pub async fn rotate(volume: &str) -> Result<()> {
    anyhow::bail!(
        "`keyslot rotate` (formerly `mfa rotate`) has been REMOVED — it re-wrapped the legacy vault that volume\n\
         open NEVER consulted, so it changed nothing about who could open the volume.\n\
         \n\
         For a real (MK-rooted) volume, add or replace factors with:\n\
           teagarden keyslot enroll {volume} --tpm2      # add a factor\n\
           teagarden keyslot status {volume}             # see what actually gates open\n\
         \n\
         (A TPM2 slot invalidated by a PCR change is replaced by enrolling a new one\n\
          with your passphrase or recovery sentence — the recovery co-slot exists\n\
          precisely for that.)"
    );
}

// ── K5: slot-vault (K0b) device-factor enrollment / unlock ──────────────────

/// Read the "existing factor" that unlocks the current vault so a NEW slot can be
/// added: the recovery sentence from `recovery_file` if given, else prompt for the
/// passphrase.
fn read_existing_factor(
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<(Option<utils::SecretString>, Option<utils::SecretString>)> {
    match (password_file, recovery_file) {
        (_, Some("-")) => {
            let mut s = String::new();
            std::io::stdin()
                .read_line(&mut s)
                .context("read recovery sentence from stdin")?;
            Ok((None, Some(utils::trimmed_secret(s))))
        }
        (_, Some(path)) => std::fs::read_to_string(path)
            .map(utils::trimmed_secret)
            .map(|recovery| (None, Some(recovery)))
            .with_context(|| format!("read recovery file: {path}")),
        (Some(pw), None) => Ok((Some(utils::read_password_input(Some(pw))?), None)),
        (None, None) => Ok((
            Some(utils::prompt_password(
                "Enter volume passphrase (an existing factor): ",
            )?),
            None,
        )),
    }
}

/// K5: enroll a hardware/device factor into a key-protected volume's slot vault.
/// Local slot unlock check; enrollment and removal publish the owner-signed vault to Telegram.
/// Options selecting which device factor a `mfa enroll` / `mfa unlock` acts on.
///
/// Exactly one must be chosen. These are all *targeted* factors: each either
/// consumes a retry against a PIN counter, requires physical presence, or makes a
/// network round-trip, so none may be attempted speculatively.
#[derive(Default, Clone)]
pub struct FactorSelect {
    /// TPM2 sealing slot.
    pub tpm2: bool,
    /// PCR selection for the TPM2 bind (e.g. `sha256:0,1,7`).
    pub pcrs: Option<String>,
    /// Tang server URL (network-bound decryption).
    pub tang: Option<String>,
    /// Pin the Tang server's advertised-key thumbprint.
    pub tang_thumbprint: Option<String>,
    /// PKCS#11 provider module path.
    pub pkcs11_module: Option<String>,
    /// PKCS#11 token label.
    pub pkcs11_token_label: Option<String>,
    /// PKCS#11 key id (hex).
    pub pkcs11_key_id: Option<String>,
    /// Enroll/unlock with a FIDO2 hardware authenticator.
    pub fido2: bool,
    /// Enrollment only: what the key must check at every unlock. `None` asks
    /// the operator on the terminal.
    pub fido2_mode: Option<Fido2ModeChoice>,
    /// Enrollment only: wrap with the plugin's ML-KEM-768/X25519 hybrid stanza.
    pub fido2_post_quantum: bool,
}

impl FactorSelect {
    /// How many device-factor flags are set. `volume mount` uses this to tell
    /// "no factor requested, fall back to password/recovery" (0) apart from
    /// "a factor was requested" (>=1, which then must be exactly 1).
    pub(crate) fn chosen(&self) -> usize {
        [
            self.tpm2,
            self.tang.is_some(),
            self.pkcs11_module.is_some(),
            self.fido2,
        ]
        .iter()
        .filter(|b| **b)
        .count()
    }

    pub(crate) fn require_exactly_one(&self) -> Result<()> {
        match self.chosen() {
            1 => Ok(()),
            0 => anyhow::bail!(
                "select a factor: --tpm2, --tang <URL>, --pkcs11-module <PATH>, or --fido2"
            ),
            _ => anyhow::bail!(
                "select exactly ONE factor per slot (each enrolls its own independent slot; \
                 run the command once per factor)"
            ),
        }
    }
}

fn parse_key_id(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str.trim().trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("--pkcs11-key-id must be hex: {e}"))
}

/// Prompt for a PKCS#11 PIN without echoing so it never appears in shell
/// history, `ps` output, or a process's argv. FIDO2 PIN input belongs to the
/// external plugin and is deliberately never routed through this function.
fn prompt_pin(what: &str) -> Result<utils::SecretString> {
    if let Ok(p) = std::env::var("TEAGARDEN_FACTOR_PIN") {
        // Non-interactive path for scripted enrollment and the CI factor proofs.
        return Ok(zeroize::Zeroizing::new(p));
    }
    Ok(zeroize::Zeroizing::new(rpassword::prompt_password(
        format!("{what}: "),
    )?))
}

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_ENROLL_FACTOR: std::cell::RefCell<Option<EnrollFactor>> = const { std::cell::RefCell::new(None) };
}

fn build_enroll_factor(sel: &FactorSelect, fido2_mode: Option<Fido2Mode>) -> Result<EnrollFactor> {
    #[cfg(test)]
    if let Some(factor) = TEST_ENROLL_FACTOR.with(|factor| factor.borrow_mut().take()) {
        return Ok(factor);
    }
    if sel.tpm2 {
        return Ok(EnrollFactor::Tpm2 {
            pcrs: sel.pcrs.clone(),
        });
    }
    if let Some(url) = &sel.tang {
        return Ok(EnrollFactor::Tang {
            url: url.clone(),
            thumbprint: sel.tang_thumbprint.clone(),
        });
    }
    if let Some(module) = &sel.pkcs11_module {
        let key_id = parse_key_id(sel.pkcs11_key_id.as_deref().unwrap_or("01"))?;
        return Ok(EnrollFactor::Pkcs11(teagarden_mfa::unlock::Pkcs11Inputs {
            module: module.clone(),
            token_label: sel.pkcs11_token_label.clone(),
            key_id,
            pin: prompt_pin("PKCS#11 user PIN")?,
        }));
    }
    if sel.fido2 {
        // No PIN parameter: the PIN is read from the terminal when the key asks
        // for it, so it never passes through argv or the environment.
        let mode =
            fido2_mode.ok_or_else(|| anyhow::anyhow!("no FIDO2 verification mode was chosen"))?;
        let generation = teagarden_mfa::kslot::protectors::Fido2GenerationOptions {
            mode,
            post_quantum: sel.fido2_post_quantum,
        };
        return Ok(EnrollFactor::Fido2 { generation });
    }
    anyhow::bail!("factor selection invariant violated after validation")
}

pub(crate) fn build_unlock_inputs(sel: &FactorSelect) -> Result<UnlockInputs<'static>> {
    let mut inputs = UnlockInputs {
        tpm2: sel.tpm2,
        ..Default::default()
    };
    if let Some(url) = &sel.tang {
        inputs.tang = Some((url.clone(), sel.tang_thumbprint.clone()));
    }
    if let Some(module) = &sel.pkcs11_module {
        inputs.pkcs11 = Some(teagarden_mfa::unlock::Pkcs11Inputs {
            module: module.clone(),
            token_label: sel.pkcs11_token_label.clone(),
            key_id: parse_key_id(sel.pkcs11_key_id.as_deref().unwrap_or("01"))?,
            pin: prompt_pin("PKCS#11 user PIN")?,
        });
    }
    inputs.fido2 = sel.fido2;
    Ok(inputs)
}

pub(crate) fn factor_label(sel: &FactorSelect) -> &'static str {
    if sel.tpm2 {
        "TPM2"
    } else if sel.tang.is_some() {
        "Tang"
    } else if sel.pkcs11_module.is_some() {
        "PKCS#11"
    } else {
        "FIDO2"
    }
}

pub async fn enroll(
    volume: &str,
    sel: FactorSelect,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    sel.require_exactly_one()?;
    // The FIDO2 mode is settled first: before any secret is asked for, and long
    // before anything touches the key. A mode that cannot be enforced stops here.
    let fido2_mode = resolve_fido2_mode(&sel)?;
    let volumes_dir = manager::default_volumes_dir();
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;
    let admin = manager::OwnerAdminLock::acquire(&volumes_dir.join(&volume_id))?;

    let (password, recovery) = read_existing_factor(password_file, recovery_file)?;
    let inputs = UnlockInputs {
        password: password.as_deref().map(String::as_bytes),
        recovery_sentence: recovery.as_ref().map(|secret| secret.as_str()),
        ..Default::default()
    };

    prepare_changed_slot_header(&volume_id, &inputs, &volumes_dir, &admin).await?;
    let factor = build_enroll_factor(&sel, fido2_mode)?;
    let label = factor_label(&sel);

    let slot_id =
        unlock::enroll_factor_in_transaction(&volume_id, &inputs, factor, &volumes_dir, &admin)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("Enrolled {label} slot {slot_id} into volume {volume_id}.");
    if sel.tpm2 {
        match &sel.pcrs {
            Some(p) => println!(
                "  Bound to PCRs {p}: changed selected PCR values refuse unseal of this slot; other slots remain independent."
            ),
            None => println!("  TPM-bound (recoverable only by this TPM)."),
        }
    }
    if let Some(url) = &sel.tang {
        println!(
            "  This Tang slot needs server {url} to be reachable; other slots remain independent."
        );
    }
    if sel.pkcs11_module.is_some() {
        println!("  {}", pkcs11_wrap_line(&volumes_dir, &volume_id, slot_id)?);
    }
    if let Some(mode) = fido2_mode {
        println!("  {}", fido2_mode_line(mode));
    }
    println!(
        "  You can now unlock this volume with {label}, in addition to your existing factors."
    );
    println!(
        "  Key slots are any-one-of (like LUKS): your existing slots still open the volume on"
    );
    println!(
        "  their own. To stop the passphrase opening it, remove its slot:  teagarden keyslot \
         remove-slot {} <SLOT> {}",
        quote(volume),
        verify_flags(&sel)
    );
    println!(
        "  At least one passphrase or recovery slot always remains, so the recovery sentence \
         keeps opening the volume without {label}."
    );
    println!(
        "  Verify:  teagarden keyslot unlock {} {}",
        quote(volume),
        verify_flags(&sel)
    );
    if sel.fido2 {
        // A credential created here is not test-unlocked at enrollment: that would
        // cost another touch, and a slot that fails later costs no data.
        println!(
            "  Enrollment did not test-unlock this slot (that would have cost another touch). \
             Run the Verify command once, with the key attached, to confirm it unlocks."
        );
    }
    publish_changed_slot_header(&volume_id, &inputs, &volumes_dir, &admin).await?;
    Ok(())
}

/// The line `keyslot enroll` prints for a FIDO2 slot: the mode it recorded.
fn fido2_mode_line(mode: Fido2Mode) -> String {
    let unlock = if mode.requires_pin() {
        "the key's PIN, then a touch"
    } else {
        "a touch, and no PIN"
    };
    format!(
        "Mode {} ({}), recorded in the slot: every unlock and mount asks for {unlock}.",
        mode.title(),
        mode.as_str()
    )
}

/// Human name for a slot type in `mfa status` / `mfa remove-slot` output.
fn slot_type_name(t: teagarden_mfa::kslot::SlotType) -> &'static str {
    use teagarden_mfa::kslot::SlotType;
    match t {
        SlotType::Passphrase => "passphrase",
        SlotType::Recovery => "recovery sentence",
        SlotType::Keypair => "keypair",
        SlotType::Fido2Hmac => "FIDO2",
        SlotType::Tpm2 => "TPM2",
        SlotType::Pkcs11 => "PKCS#11",
        SlotType::Tang => "Tang",
    }
}

/// mfa-H2: remove one key slot, authorised by a DIFFERENT slot that remains.
///
/// The authorising factor is exactly one of: a device factor flag, a
/// `--recovery-file`, a `--password-file`, or (none given) a passphrase
/// prompt. The library refuses the last slot, the last durable slot, a
/// tampered volume, and an opener that only works through the slot being
/// removed — all before anything is written.
pub async fn remove_slot(
    volume: &str,
    slot: u32,
    sel: FactorSelect,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    yes: bool,
) -> Result<()> {
    let volumes_dir = manager::default_volumes_dir();
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;
    let admin = manager::OwnerAdminLock::acquire(&volumes_dir.join(&volume_id))?;

    let given =
        sel.chosen() + usize::from(password_file.is_some()) + usize::from(recovery_file.is_some());
    if given > 1 {
        anyhow::bail!(
            "authorise the removal with exactly ONE remaining slot: a device flag, \
             --recovery-file, or --password-file"
        );
    }

    // Describe the target before asking (no secret needed to read slot labels).
    let vault_path = volumes_dir
        .join(&volume_id)
        .join(unlock::SLOT_VAULT_FILENAME);
    let target = teagarden_mfa::kslot::SlotVault::load(&vault_path)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .slots()
        .into_iter()
        .find(|s| s.slot_id == slot)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no slot {slot} in this volume's vault — see `teagarden keyslot status {}`",
                quote(volume)
            )
        })?;

    if !yes {
        println!(
            "This removes slot {slot} ('{}', {}) from '{volume}'. That factor will no longer",
            target.label,
            slot_type_name(target.slot_type)
        );
        println!("open the volume. Removing a slot does NOT revoke a hierarchy-root sentence");
        println!("exported with `key export`, nor a share grant already issued.");
        let confirm = utils::prompt("Type 'yes' to confirm: ")?;
        if confirm.trim() != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    let mut password: Option<utils::SecretString> = None;
    let mut recovery: Option<utils::SecretString> = None;
    let inputs = if sel.chosen() == 1 {
        build_unlock_inputs(&sel)?
    } else {
        if let Some(rf) = recovery_file {
            recovery = read_existing_factor(None, Some(rf))?.1;
        } else {
            password = Some(utils::read_password_input(password_file)?);
        }
        UnlockInputs::default()
    };
    let inputs = UnlockInputs {
        password: password.as_deref().map(String::as_bytes),
        recovery_sentence: recovery.as_ref().map(|secret| secret.as_str()),
        ..inputs
    };

    prepare_changed_slot_header(&volume_id, &inputs, &volumes_dir, &admin).await?;
    let removed =
        unlock::remove_factor_slot_in_transaction(&volume_id, &inputs, slot, &volumes_dir, &admin)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "Removed slot {} ('{}', {}) from volume {volume_id}.",
        removed.slot_id,
        removed.label,
        slot_type_name(removed.slot_type)
    );
    println!(
        "  It can no longer open the volume. Remaining slots:  teagarden keyslot status {}",
        quote(volume)
    );
    publish_changed_slot_header(&volume_id, &inputs, &volumes_dir, &admin).await?;
    Ok(())
}

async fn prepare_changed_slot_header(
    volume_id: &str,
    inputs: &UnlockInputs<'_>,
    volumes_dir: &std::path::Path,
    admin: &manager::OwnerAdminLock,
) -> Result<()> {
    let opened =
        unlock::open_volume(volume_id, inputs, volumes_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    // Legacy local/block volumes have no owner header. Preserve their local
    // slot mutation and pending-publication behavior. Every TGHD2 volume takes
    // the owner-authenticated preflight below before any vault change.
    if opened.config.sdo_owner_public_key.is_none() {
        return Ok(());
    }
    #[cfg(test)]
    if let Ok(client) = super::key::TEST_PORTABLE_TRANSPORT.try_with(std::sync::Arc::clone) {
        return super::volume::prepare_slot_header_update(client.as_ref(), &opened, admin).await;
    }
    let client = super::volume::connect_user_session().await?;
    super::volume::prepare_slot_header_update(&client, &opened, admin).await
}

/// Republish the self-describing volume header after an authenticated slot change.
async fn publish_changed_slot_header(
    volume_id: &str,
    inputs: &UnlockInputs<'_>,
    volumes_dir: &std::path::Path,
    admin: &manager::OwnerAdminLock,
) -> Result<()> {
    let opened = unlock::open_volume(volume_id, inputs, volumes_dir).map_err(|e| {
        anyhow::anyhow!("slot change is local but header publication is pending: {e}")
    })?;
    #[cfg(test)]
    if let Ok(client) = super::key::TEST_PORTABLE_TRANSPORT.try_with(std::sync::Arc::clone) {
        return super::volume::publish_slot_header_update_in_transaction(
            client.as_ref(),
            &opened,
            admin,
        )
        .await;
    }
    let client = super::volume::connect_user_session().await.map_err(|e| {
        anyhow::anyhow!("slot change is local but header publication is pending: {e}")
    })?;
    use teagarden_telegram::client::ForumAdmin;
    client
        .select_topic(
            opened.config.telegram_group_id,
            opened.config.telegram_channel_access_hash,
            opened.config.telegram_topic_id,
        )
        .map_err(|e| {
            anyhow::anyhow!("slot change is local but header publication is pending: {e}")
        })?;
    super::volume::publish_slot_header_update_in_transaction(&client, &opened, admin).await
}

/// The line `keyslot enroll` prints for a PKCS#11 slot: which RSA-OAEP hash
/// wrapped its key, as recorded in the vault (the token may refuse SHA-256).
fn pkcs11_wrap_line(
    volumes_dir: &std::path::Path,
    volume_id: &str,
    slot_id: teagarden_mfa::kslot::types::SlotId,
) -> Result<String> {
    let vault = teagarden_mfa::kslot::SlotVault::load(
        volumes_dir
            .join(volume_id)
            .join(unlock::SLOT_VAULT_FILENAME),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let scheme = vault
        .slots()
        .into_iter()
        .find(|s| s.slot_id == slot_id)
        .and_then(|s| s.kek_scheme)
        .unwrap_or_default();
    Ok(match scheme.as_str() {
        "pkcs11-rsa-oaep-sha256" => {
            "Key wrap: RSA-OAEP with SHA-256 (pkcs11-rsa-oaep-sha256).".to_string()
        }
        "pkcs11-rsa-oaep-sha1" => "Key wrap: RSA-OAEP with SHA-1 (pkcs11-rsa-oaep-sha1): the \
             token refused RSA-OAEP with SHA-256. SHA-1 inside OAEP has no known weakness for \
             wrapping a random key."
            .to_string(),
        other => format!("Key wrap: {other:?} (unrecognised scheme)."),
    })
}

/// K5: verify a key-protected volume opens via a device factor (offline check;
/// does NOT mount). Proves the enrolled factor works end-to-end.
pub async fn unlock(volume: &str, sel: FactorSelect) -> Result<()> {
    sel.require_exactly_one()?;
    let volumes_dir = manager::default_volumes_dir();
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;

    let inputs = build_unlock_inputs(&sel)?;
    let label = factor_label(&sel);
    let _opened = unlock::open_volume(&volume_id, &inputs, &volumes_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("✓ volume {volume_id} unlocked via {label} — the factor works end-to-end.");
    Ok(())
}

/// Shell-quote a volume name so printed suggestions are runnable verbatim.
/// (Multi-word display names previously produced un-runnable hints.)
fn quote(volume: &str) -> String {
    if volume.contains(char::is_whitespace) {
        format!("'{}'", volume.replace('\'', r"'\''"))
    } else {
        volume.to_string()
    }
}

fn verify_flags(sel: &FactorSelect) -> String {
    if sel.tpm2 {
        "--tpm2".into()
    } else if let Some(url) = &sel.tang {
        format!("--tang {url}")
    } else if let Some(m) = &sel.pkcs11_module {
        format!("--pkcs11-module {m}")
    } else if sel.fido2 {
        "--fido2".into()
    } else {
        String::new()
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

fn resolve_volume_id(volume: &str, volumes_dir: &std::path::Path) -> Result<String> {
    if volumes_dir.join(volume).join("volume.json").exists() {
        return Ok(volume.to_string());
    }
    let all = manager::list_volumes(volumes_dir).map_err(utils::core_err)?;
    let needle = volume.to_lowercase();
    let matches: Vec<_> = all
        .iter()
        .filter(|c| {
            c.display_name.to_lowercase() == needle || c.volume_id.to_string().starts_with(volume)
        })
        .collect();
    match matches.len() {
        0 => anyhow::bail!(
            "volume not found: '{volume}'\nUse `teagarden volume list` to see available volumes."
        ),
        1 => Ok(matches[0].volume_id.to_string()),
        _ => {
            let names: Vec<_> = matches.iter().map(|c| &c.display_name).collect();
            anyhow::bail!("ambiguous volume name '{volume}' — matches: {names:?}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use teagarden_mfa::kslot::protectors::Fido2Mode;

    #[test]
    fn every_mode_flag_value_maps_to_its_mode() {
        let pairs = [
            (Fido2ModeChoice::Pin, Fido2Mode::Pin),
            (Fido2ModeChoice::PinUp, Fido2Mode::PinUp),
            (Fido2ModeChoice::PinUv, Fido2Mode::PinUv),
            (Fido2ModeChoice::Up, Fido2Mode::Up),
            (Fido2ModeChoice::Uv, Fido2Mode::Uv),
        ];
        for (choice, mode) in pairs {
            assert_eq!(Fido2Mode::from(choice), mode);
            // The flag value is the name the slot records.
            let value = clap::ValueEnum::to_possible_value(&choice).unwrap();
            assert_eq!(value.get_name(), mode.as_str());
        }
    }

    #[test]
    fn the_mode_menu_lists_all_five_modes_and_marks_the_unavailable_ones() {
        assert_eq!(
            fido2_mode_menu(),
            "\
Choose what your security key must check each time this slot unlocks the volume:
  1) PIN only  the key's PIN, without a touch  [not available]
  2) PIN + UP  the key's PIN and a touch
  3) PIN + UV  the key's PIN and a fingerprint (built-in user verification)  [not available]
  4) UP only   a touch
  5) UV only   a fingerprint (built-in user verification), without a PIN  [not available]
Modes marked [not available] cannot be enforced with age-plugin-fido2-hmac v0.5.0; choose one to see why.
"
        );
    }

    #[test]
    fn a_menu_answer_selects_a_mode_by_number_or_by_name() {
        assert_eq!(parse_mode_answer("2\n"), Some(Fido2Mode::PinUp));
        assert_eq!(parse_mode_answer(" 4 "), Some(Fido2Mode::Up));
        assert_eq!(parse_mode_answer("pin-up"), Some(Fido2Mode::PinUp));
        assert_eq!(parse_mode_answer("uv"), Some(Fido2Mode::Uv));
        for bad in ["", "0", "6", "touch", "PIN + UP"] {
            assert_eq!(parse_mode_answer(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn choosing_an_unavailable_mode_prints_the_reason_and_asks_again() {
        let mut input = std::io::Cursor::new(b"5\nnonsense\n4\n".to_vec());
        let mut output = Vec::new();
        let mode = ask_fido2_mode(&mut input, &mut output).unwrap();
        assert_eq!(mode, Fido2Mode::Up);
        let shown = String::from_utf8(output).unwrap();
        assert!(shown.starts_with(&fido2_mode_menu()), "{shown}");
        assert!(
            shown.contains(&format!(
                "  UV only is not available: {}",
                Fido2Mode::Uv.unavailable_reason().unwrap()
            )),
            "{shown}"
        );
        assert!(
            shown.contains("'nonsense' is not one of the choices"),
            "{shown}"
        );
        assert!(shown.contains("Mode UP only: a touch."), "{shown}");
        assert_eq!(shown.matches(MODE_PROMPT).count(), 3, "{shown}");
    }

    #[test]
    fn no_answer_enrolls_nothing() {
        let mut input = std::io::Cursor::new(Vec::new());
        let mut output = Vec::new();
        let err = ask_fido2_mode(&mut input, &mut output).unwrap_err();
        assert!(format!("{err}").contains("nothing was enrolled"), "{err}");
    }

    #[test]
    fn a_mode_flag_that_cannot_be_enforced_is_refused_with_its_reason() {
        let sel = FactorSelect {
            fido2: true,
            fido2_mode: Some(Fido2ModeChoice::PinUv),
            ..Default::default()
        };
        let err = resolve_fido2_mode(&sel).unwrap_err();
        assert!(
            format!("{err}").contains(Fido2Mode::PinUv.unavailable_reason().unwrap()),
            "{err}"
        );
        let sel = FactorSelect {
            fido2: true,
            fido2_mode: Some(Fido2ModeChoice::PinUp),
            ..Default::default()
        };
        assert_eq!(resolve_fido2_mode(&sel).unwrap(), Some(Fido2Mode::PinUp));
        assert_eq!(resolve_fido2_mode(&FactorSelect::default()).unwrap(), None);
    }
}
