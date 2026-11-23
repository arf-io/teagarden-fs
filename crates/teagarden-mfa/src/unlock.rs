//! K0b enforcement wiring — the dependency-inverted bridge between the K0a slot
//! vault and the `teagarden-core` volume open/create chokepoint.
//!
//! `teagarden-core` (which owns `open_volume` / `create_volume`) cannot depend on
//! this crate — `teagarden-mfa` already depends on core, so the reverse would be
//! a cycle. So the vault-unlock step lives here, one layer up: core exposes the
//! MK-rooted primitives (`manager::open_volume_with_master_key`,
//! `manager::prepare_volume_mk_rooted` / `manager::commit_prepared_volume`)
//! and fails **closed** when a bare password is used against a key-protected
//! volume; this module recovers the master key from the vault and drives those
//! primitives.
//!
//! ## Why this is real protection (not a gate)
//!
//! A key-protected volume is **MK-rooted**: its data/meta/integrity keys derive
//! from the vault's *random* master key, not the password. An open-site that has
//! not been wired to this module and still calls `manager::open_volume` with a
//! password cannot reconstruct those keys *and* is refused up front — it fails
//! closed, never open. The confidentiality boundary is MK-rooting itself; the
//! fail-closed guard just turns "opens then every block fails to decrypt" into a
//! clear "unlock via the vault" error. So the remaining un-wired open-sites
//! (restore/revert/key/sharing/history, and the API — which has no mfa dep) are a
//! functionality gap, not a security bypass.

use std::path::Path;

use zeroize::Zeroizing;

use teagarden_core::volume::config::VolumeConfig;
use teagarden_core::volume::manager::{self, CreateVolumeResult, OpenVolumeResult};
use teagarden_core::volume::shared::SharedOrigin;

use crate::error::{MfaError, Result};
#[cfg(feature = "factor-pkcs11")]
use crate::kslot::protectors::Pkcs11Protector;
use crate::kslot::protectors::{
    Argon2Cost, KeypairProtector, PassphraseProtector, RecoveryProtector, TangProtector,
    Tpm2SealProtector,
};
#[cfg(feature = "factor-fido2")]
use crate::kslot::protectors::{Fido2GenerationOptions, Fido2HmacProtector};
use crate::kslot::{MasterKey, SlotId, SlotProtector, SlotVault};

/// The slot vault lives beside `volume.json` in the volume's base directory.
///
/// **Deliberately NOT `mfa_vault.json`** — that name belongs to the legacy v1
/// `MfaVault`, whose `remove()` is an unconditional `remove_file`. Sharing the
/// name made `teagarden keyslot remove` silently delete a key-protected volume's slot
/// vault: the master key is random and this file is its ONLY wrapping, so that was
/// total, unrecoverable data loss (a critical finding in security review).
/// Distinct names make the collision unrepresentable; `mfa remove` additionally
/// fails closed on a key-protected volume (defense in depth).
pub const SLOT_VAULT_FILENAME: &str = "slot_vault.json";

/// The factor inputs an operator supplies to open a volume. Only **counter-free**
/// factors (passphrase / recovery / keypair) are auto-tried here; device factors
/// with a retry counter or user-presence requirement (FIDO2/TPM2/…) are opened
/// through a targeted API and must never be tried speculatively (advisor R3).
#[derive(Default)]
pub struct UnlockInputs<'a> {
    /// The passphrase — the sole credential for a legacy volume, or a
    /// passphrase-slot input for a protected volume.
    pub password: Option<&'a [u8]>,
    /// A recovery sentence (recovery slot).
    pub recovery_sentence: Option<&'a str>,
    /// age X25519 identity strings (keypair slots).
    pub age_identities: Vec<String>,
    /// ssh private keys, PEM-encoded (keypair slots).
    pub ssh_identities: Vec<Vec<u8>>,
    /// K5: try the TPM2 slot (a **targeted** device factor — set only when the
    /// operator explicitly asks, e.g. `mount --unlock-with tpm2`). When set, the
    /// open uses the vault's `unlock_targeted` so counter/user-presence slots are
    /// eligible; the PCR selection is read from the slot's stored params.
    pub tpm2: bool,
    /// K4: open via a Tang (network-bound decryption) slot. Targeted, like TPM2:
    /// it performs a network round-trip to the Tang server, so it must never be
    /// tried speculatively. `(url, thumbprint)`.
    pub tang: Option<(String, Option<String>)>,
    /// K3: open via a PKCS#11 / HSM slot. Targeted — the token has a PIN retry
    /// counter, so a speculative attempt could lock the operator's token out.
    /// `(module_path, token_label, key_id, pin)`.
    pub pkcs11: Option<Pkcs11Inputs>,
    /// K1: open via a FIDO2 hmac-secret slot. Targeted — it requires physical user
    /// presence (a touch), so it must never be tried speculatively.
    ///
    /// No PIN field: the PIN (if the token demands one) is read from the terminal
    /// by the protector at the moment the token asks. Carrying it here would mean
    /// it travelled through argv or an environment variable.
    pub fido2: bool,
}

/// Inputs identifying a PKCS#11 token and the key within it.
#[derive(Clone, Default)]
pub struct Pkcs11Inputs {
    /// Path to the PKCS#11 provider module (e.g. `/usr/lib/softhsm/libsofthsm2.so`).
    pub module: String,
    /// Optional token label to select among multiple tokens.
    pub token_label: Option<String>,
    /// CKA_ID of the keypair to use.
    pub key_id: Vec<u8>,
    /// User PIN.
    pub pin: Zeroizing<String>,
}

/// A device factor to enroll into an existing protected volume (K5).
///
/// All four device factors are wired end-to-end through the CLI. `Fido2` and
/// `Pkcs11` require their respective Cargo features (both are enabled by default);
/// building without them removes the variant, so an unsupported build cannot even
/// construct the request.
pub enum EnrollFactor {
    /// Inject a software protector while retaining the production slot mutation pipeline.
    #[cfg(feature = "test-util")]
    Test(Box<dyn SlotProtector + Send>),
    /// A TPM2 sealing slot; selected PCR values must match those recorded at enrollment.
    Tpm2 {
        /// PCR selection to bind the seal to (e.g. `Some("sha256:0,1,7")`); `None`
        /// = TPM-only bind (hardware-bound but not boot-state-bound).
        pcrs: Option<String>,
    },
    /// K4: a Tang (network-bound decryption) slot. Opens only when the Tang server
    /// is reachable — the "this machine is on my network" factor.
    Tang {
        /// Tang server URL, e.g. `http://tang.local:8080`.
        url: String,
        /// Optional advertised-key thumbprint to pin the server identity. Omitting
        /// it trusts the advertisement on first use.
        thumbprint: Option<String>,
    },
    /// K3: a PKCS#11 / HSM slot (RSA-OAEP KEK wrap) on a hardware or software token.
    #[cfg(feature = "factor-pkcs11")]
    Pkcs11(Pkcs11Inputs),
    /// K1: a FIDO2 hmac-secret slot on a hardware authenticator (requires touch).
    ///
    /// The credential is created by `age-plugin-fido2-hmac`, which owns the
    /// relying-party id, with the plugin's default embedded (data-less)
    /// identity. The operator's verification mode answers the plugin's
    /// require-PIN question and is recorded in the slot.
    #[cfg(feature = "factor-fido2")]
    Fido2 {
        /// The verification mode and recipient kind the operator chose.
        generation: Fido2GenerationOptions,
    },
}

/// The outcome of creating a key-protected (MK-rooted) volume.
pub struct ProtectedCreate {
    /// The created volume (config, paths, MK-derived hierarchy).
    pub created: CreateVolumeResult,
    /// The recovery sentence for the auto-enrolled recovery co-slot. Show it to
    /// the operator **once** and do not persist it — it is the mandated fallback
    /// if the passphrase is lost. Zeroized on drop.
    pub recovery_sentence: Zeroizing<String>,
}

/// Create a fresh master key protected by a new passphrase slot and an
/// independently generated recovery slot. The returned vault is in memory and
/// must be saved before any config referencing it is committed.
#[cfg(feature = "key-rotation")]
pub fn create_rotation_credentials(
    passphrase: &[u8],
) -> Result<(SlotVault, MasterKey, Zeroizing<String>)> {
    if passphrase.len() < 8 {
        return Err(MfaError::Factor(
            "new volume passphrase must be at least 8 bytes".into(),
        ));
    }
    let (mut vault, master_key) = SlotVault::create("teagarden-volume-rotation");
    let mut passphrase_slot = PassphraseProtector::new(passphrase.to_vec(), Argon2Cost::default());
    vault.add_independent_slot(&master_key, &mut passphrase_slot, "passphrase")?;
    let mut recovery_slot = RecoveryProtector::for_enroll();
    vault.add_independent_slot(&master_key, &mut recovery_slot, "recovery")?;
    let sentence = recovery_slot
        .enrolled_sentence()
        .ok_or_else(|| MfaError::Factor("recovery enroll did not yield a sentence".into()))?
        .to_owned();
    Ok((vault, master_key, Zeroizing::new(sentence)))
}

fn load_config(config_path: &Path) -> Result<VolumeConfig> {
    let json = std::fs::read_to_string(config_path).map_err(MfaError::Io)?;
    serde_json::from_str(&json).map_err(MfaError::Serialization)
}

/// Build the **counter-free** protectors (passphrase / recovery / keypair) an
/// `UnlockInputs` carries. Device factors are handled separately (targeted).
fn build_counter_free_protectors(inputs: &UnlockInputs<'_>) -> Result<Vec<Box<dyn SlotProtector>>> {
    let mut protectors: Vec<Box<dyn SlotProtector>> = Vec::new();
    if let Some(pw) = inputs.password {
        protectors.push(Box::new(PassphraseProtector::new(
            pw.to_vec(),
            Argon2Cost::default(), // unlock reads the stored cost from the slot params
        )));
    }
    if let Some(sentence) = inputs.recovery_sentence {
        protectors.push(Box::new(RecoveryProtector::from_sentence(sentence)?));
    }
    for id in &inputs.age_identities {
        protectors.push(Box::new(KeypairProtector::for_unlock_age(id)?));
    }
    for pem in &inputs.ssh_identities {
        protectors.push(Box::new(KeypairProtector::for_unlock_ssh(pem)?));
    }
    Ok(protectors)
}

/// Open a volume, transparently handling both legacy (password-rooted) and
/// key-protected (MK-rooted) volumes.
///
/// - **Legacy** (`key_protection == None`): requires `inputs.password`; delegates
///   straight to `manager::open_volume`.
/// - **Protected** (`key_protection == Some`): loads `slot_vault.json`, builds
///   counter-free protectors from `inputs`, recovers the master key, and drives
///   `manager::open_volume_with_master_key` (which re-derives the hierarchy from
///   the MK, verifies the config, and enforces the anti-rollback anchor).
/// - **Recovery sentence**: tried first as the volume's recovery SLOT (protected
///   and shared volumes); when there is no such slot, or it does not open, the
///   sentence is decoded as the key-hierarchy root `key export` printed and the
///   volume is opened with it, which requires the config's verification hash AND
///   integrity HMAC to verify against that root (fail closed). This is what makes
///   `key export`'s promise true for every command's `--recovery-file`.
pub fn open_volume(
    volume_id: &str,
    inputs: &UnlockInputs<'_>,
    volumes_dir: &Path,
) -> Result<OpenVolumeResult> {
    let base_dir = volumes_dir.join(volume_id);
    let config_path = base_dir.join("volume.json");
    if !config_path.exists() {
        return Err(MfaError::Core(format!("volume not found: {volume_id}")));
    }
    let config = load_config(&config_path)?;

    // Shared volume (accepted from a grant, or a second machine): the recipient's
    // OWN factor vault wraps the foreign volume root. This must be checked before
    // the key_protection branch, because a K0b-sourced share carries the owner's
    // `key_protection` anchor in its config yet must open via the shared path.
    if let Some(origin) =
        SharedOrigin::load(&base_dir).map_err(|e| MfaError::Core(e.to_string()))?
    {
        let vault_path = base_dir.join(SLOT_VAULT_FILENAME);
        if !vault_path.exists() {
            return Err(MfaError::VaultNotFound(vault_path.display().to_string()));
        }
        let vault = SlotVault::load(&vault_path)?;
        let opened =
            unlock_vault_master_key(&vault, inputs, &config.display_name).and_then(|root| {
                manager::open_volume_shared(
                    volume_id,
                    root.as_bytes(),
                    origin.derivation,
                    volumes_dir,
                )
                .map_err(|e| MfaError::Core(e.to_string()))
            });
        return or_exported_root(opened, inputs, volume_id, volumes_dir);
    }

    if config.key_protection.is_none() {
        // Legacy password-rooted volume — the password IS the credential; a
        // recovery sentence can only be the hierarchy root `key export` printed.
        return match (inputs.password, inputs.recovery_sentence) {
            (Some(pw), _) => manager::open_volume(volume_id, pw, volumes_dir)
                .map_err(|e| MfaError::Core(e.to_string())),
            (None, Some(sentence)) => open_with_exported_root(sentence, volume_id, volumes_dir),
            (None, None) => Err(MfaError::Factor("this volume needs a password".into())),
        };
    }

    // MK-rooted: recover the master key from the vault.
    let vault_path = base_dir.join(SLOT_VAULT_FILENAME);
    if !vault_path.exists() {
        return Err(MfaError::VaultNotFound(vault_path.display().to_string()));
    }
    let vault = SlotVault::load(&vault_path)?;
    let opened = unlock_vault_master_key(&vault, inputs, &config.display_name).and_then(|mk| {
        repair_authenticated_pending_slot_anchor(&config, &mk, &vault, &config_path)?;
        manager::open_volume_with_master_key(
            volume_id,
            mk.as_bytes(),
            vault.generation(),
            &vault.state_digest(),
            volumes_dir,
        )
        .map_err(|e| MfaError::Core(e.to_string()))
    });
    or_exported_root(opened, inputs, volume_id, volumes_dir)
}

/// The slot transaction stores an owner-signed intent before advancing its
/// vault. After interruption between vault save and local reseal, accept only
/// that exact intended anchor, authenticated by BOTH owner signature and root.
fn repair_authenticated_pending_slot_anchor(
    config: &VolumeConfig,
    mk: &MasterKey,
    vault: &SlotVault,
    config_path: &Path,
) -> Result<()> {
    let actual = teagarden_core::volume::config::KeyProtection {
        vault_generation: vault.generation(),
        vault_digest: hex::encode(vault.state_digest()),
    };
    if config.key_protection.as_ref() == Some(&actual)
        || !config.sdo_header_pending
        || config.sdo_owner_public_key.is_none()
    {
        return Ok(());
    }
    let hierarchy = slot_hierarchy(config, mk)?;
    manager::verify_config_anchors(config, &hierarchy)
        .map_err(|e| MfaError::Core(e.to_string()))?;
    let bytes =
        hex::decode(config.sdo_header_pending_bytes.as_deref().ok_or_else(|| {
            MfaError::Core("pending slot intent has no exact retry bytes".into())
        })?)
        .map_err(|e| MfaError::Core(e.to_string()))?;
    let header = teagarden_core::sdo::HeaderDocument::decode_pinned(
        &bytes,
        &hierarchy.integrity,
        config.sdo_owner_public_key.as_deref(),
    )
    .map_err(|e| MfaError::Core(e.to_string()))?;
    if header.volume_id != config.volume_id
        || header.group_id != config.telegram_group_id
        || header.topic_id != config.telegram_topic_id
        || header.salt != hex::encode(config.salt)
        || header.revision != config.sdo_header_revision_reserved
        || header.key_protection != Some(serde_json::to_value(&actual)?)
        || header.slot_vault != Some(serde_json::from_slice(&vault.to_bytes()?)?)
        || config.sdo_header_pending_sha256.as_deref()
            != Some(hex::encode(teagarden_core::block::srb2::sha256(&bytes)).as_str())
    {
        return Err(MfaError::Core("live vault differs from the exact owner-signed pending slot intent; refusing anchor repair".into()));
    }
    let admin = manager::OwnerAdminLock::acquire(config_path.parent().unwrap())
        .map_err(|e| MfaError::Core(e.to_string()))?;
    let mut current = load_config(config_path)?;
    manager::verify_config_anchors(&current, &hierarchy)
        .map_err(|e| MfaError::Core(e.to_string()))?;
    if serde_json::to_vec(&current)? != serde_json::to_vec(config)? {
        return Err(MfaError::Core(
            "owner configuration changed before slot anchor repair; retry".into(),
        ));
    }
    current.key_protection = Some(actual);
    manager::save_config_resealed_in_transaction(&mut current, &hierarchy, config_path, &admin)
        .map_err(|e| MfaError::Core(e.to_string()))
}

/// After a vault-based open failed: if the operator supplied a recovery
/// sentence, it may be the hierarchy root `key export` printed rather than the
/// volume's recovery-slot sentence (both are 22 words of the same encoding).
/// Try it as a root; if that fails too, report the ORIGINAL error, so a wrong
/// recovery-slot sentence still reads as a slot failure.
fn or_exported_root(
    opened: Result<OpenVolumeResult>,
    inputs: &UnlockInputs<'_>,
    volume_id: &str,
    volumes_dir: &Path,
) -> Result<OpenVolumeResult> {
    match (opened, inputs.recovery_sentence) {
        (Ok(r), _) => Ok(r),
        (Err(slot_err), Some(sentence)) => {
            open_with_exported_root(sentence, volume_id, volumes_dir).map_err(|_| slot_err)
        }
        (Err(e), None) => Err(e),
    }
}

/// Open a volume with the hierarchy root that `teagarden key export` encodes as
/// a 22-word sentence.
///
/// Fails closed: `manager::open_volume_shared` re-derives the hierarchy from the
/// root and REQUIRES both the volume's verification hash and its config-integrity
/// HMAC to be present and to verify (constant-time comparisons), so a foreign
/// root, a corrupted sentence, or a tampered `volume.json` is refused. The root
/// is a full 256-bit secret, not a guessable password, so no lockout applies
/// (exactly as for a share grant's root). The error never echoes a word.
fn open_with_exported_root(
    sentence: &str,
    volume_id: &str,
    volumes_dir: &Path,
) -> Result<OpenVolumeResult> {
    use teagarden_core::sentence::{decode, wordlists};
    use teagarden_core::volume::shared::SharedDerivation;

    let refused = || {
        MfaError::Factor(
            "the recovery sentence does not open this volume (it is neither this volume's \
             recovery-slot sentence nor its exported key-hierarchy root)"
                .into(),
        )
    };
    let lists = wordlists::production_wordlists();
    let lookups: [std::collections::HashMap<String, u16>; 4] =
        core::array::from_fn(|i| wordlists::build_reverse_lookup(&lists[i]));
    let decoded = Zeroizing::new(
        decode::decode_ref_string(sentence, &lists, &lookups).map_err(|_| refused())?,
    );
    let root: Zeroizing<[u8; 32]> =
        Zeroizing::new(decoded.as_slice().try_into().map_err(|_| refused())?);
    manager::open_volume_shared(
        volume_id,
        &root,
        SharedDerivation::HierarchyRootV1,
        volumes_dir,
    )
    .map_err(|e| match e {
        // A tampered config is worth naming; a wrong root is just "refused".
        teagarden_core::error::CoreError::Volume(msg) if msg.contains("integrity") => {
            MfaError::Core(format!(
                "{msg} (the recovery sentence was tried as this volume's exported root)"
            ))
        }
        _ => refused(),
    })
}

/// Recover a slot vault's master key from the supplied factor inputs.
///
/// Shared by the K0b open path and the shared-volume open path — the only
/// difference between them is what the recovered 32 bytes are then fed to
/// (`derive_hierarchy_from_master_key` vs `derive_hierarchy_v1`), not how the
/// vault is unlocked.
fn unlock_vault_master_key(
    vault: &SlotVault,
    inputs: &UnlockInputs<'_>,
    volume: &str,
) -> Result<MasterKey> {
    unlock_vault_master_key_excluding(vault, inputs, None, volume)
}

/// As [`unlock_vault_master_key`], optionally refusing to use slot `exclude`
/// (and any threshold group containing it) — see [`SlotVault::unlock_excluding`].
#[cfg_attr(not(feature = "factor-fido2"), allow(unused_variables))]
fn unlock_vault_master_key_excluding(
    vault: &SlotVault,
    inputs: &UnlockInputs<'_>,
    exclude: Option<SlotId>,
    volume: &str,
) -> Result<MasterKey> {
    let mut protectors = build_counter_free_protectors(inputs)?;
    // Device factors are TARGETED: each one either costs a retry against a counter
    // (PKCS#11 PIN), requires physical user presence (FIDO2 touch), or makes a
    // network round-trip (Tang). None may be tried speculatively, so requesting any
    // of them switches the open to `unlock_targeted`.
    let use_targeted =
        inputs.tpm2 || inputs.tang.is_some() || inputs.pkcs11.is_some() || inputs.fido2;
    if inputs.tpm2 {
        protectors.push(Box::new(Tpm2SealProtector::new(None))); // PCRs from slot params
    }
    if let Some((url, thumbprint)) = &inputs.tang {
        protectors.push(Box::new(TangProtector::new(url, thumbprint.clone())));
    }
    #[cfg(feature = "factor-pkcs11")]
    if let Some(p) = &inputs.pkcs11 {
        protectors.push(Box::new(Pkcs11Protector::new(
            &p.module,
            p.token_label.clone(),
            p.key_id.clone(),
            p.pin.as_str(),
        )));
    }
    #[cfg(feature = "factor-fido2")]
    if inputs.fido2 {
        protectors.push(Box::new(
            Fido2HmacProtector::new().with_volume_label(volume),
        ));
    }
    // A build without a factor feature must REFUSE a request for it rather than
    // silently ignore the flag and fall through to another slot.
    #[cfg(not(feature = "factor-pkcs11"))]
    if inputs.pkcs11.is_some() {
        return Err(MfaError::Factor(
            "this build has no PKCS#11 support (rebuild with --features factor-pkcs11)".into(),
        ));
    }
    #[cfg(not(feature = "factor-fido2"))]
    if inputs.fido2 {
        return Err(MfaError::Factor(
            "this build has no FIDO2 support (rebuild with --features factor-fido2)".into(),
        ));
    }
    if protectors.is_empty() {
        return Err(MfaError::Factor(
            "no unlock factor supplied for a key-protected volume (need a passphrase, \
             recovery sentence, keypair identity, or a device factor like --tpm2, \
             --tang, --pkcs11, --fido2)"
                .into(),
        ));
    }
    let refs: Vec<&dyn SlotProtector> = protectors.iter().map(AsRef::as_ref).collect();
    match exclude {
        Some(slot_id) => vault.unlock_excluding(&refs, use_targeted, slot_id),
        None if use_targeted => vault.unlock_targeted(&refs),
        None => vault.unlock(&refs),
    }
}

/// Create a **key-protected** (MK-rooted) volume: mint a random master key behind
/// a slot vault, enroll the passphrase as a slot plus a recovery co-slot (so a
/// forgotten passphrase is not instant data loss), and root the volume's key
/// hierarchy in that master key.
///
/// Ordering is durability-critical (see `manager::prepare_volume_mk_rooted`):
/// enroll **all** slots first (so the anchor reflects the final vault state), then
/// save `slot_vault.json` **before** writing `volume.json`.
#[allow(clippy::too_many_arguments)]
pub fn create_protected_volume(
    name: Option<&str>,
    password: &[u8],
    volumes_dir: &Path,
    group_id: i64,
    group_access_hash: i64,
    topic_id: i64,
    block_size: Option<u64>,
) -> Result<ProtectedCreate> {
    // 1) Mint the vault + random master key.
    let (mut vault, mk) = SlotVault::create("teagarden-volume");

    // 2) Enroll the passphrase slot.
    let mut pp = PassphraseProtector::new(password.to_vec(), Argon2Cost::default());
    vault.add_independent_slot(&mk, &mut pp, "passphrase")?;

    // 3) Enroll a recovery co-slot (mandated fallback).
    let mut rec = RecoveryProtector::for_enroll();
    vault.add_independent_slot(&mk, &mut rec, "recovery")?;
    let sentence = rec
        .enrolled_sentence()
        .ok_or_else(|| MfaError::Factor("recovery enroll did not yield a sentence".into()))?
        .to_string();

    // 4) Prepare the MK-rooted volume config (dirs created; volume.json NOT written
    //    yet). Read the vault anchor AFTER all enrolls so it matches what we save.
    let prepared = manager::prepare_volume_mk_rooted(
        name,
        mk.as_bytes(),
        vault.generation(),
        &vault.state_digest(),
        volumes_dir,
        group_id,
        group_access_hash,
        topic_id,
        block_size,
    )
    .map_err(|e| MfaError::Core(e.to_string()))?;

    // 5) Save the vault BEFORE volume.json — a crash here orphans a harmless vault
    //    rather than bricking a config whose vault is missing.
    let vault_path = prepared.paths.base_dir.join(SLOT_VAULT_FILENAME);
    vault.save(&vault_path)?;

    // 6) Commit volume.json.
    let created =
        manager::commit_prepared_volume(prepared).map_err(|e| MfaError::Core(e.to_string()))?;

    Ok(ProtectedCreate {
        created,
        recovery_sentence: Zeroizing::new(sentence),
    })
}

/// Result of setting up the recipient side of an accepted share.
pub struct SharedRecipientSetup {
    /// A local recovery sentence for the recipient's OWN vault (distinct from the
    /// owner's). Write it down: it, or the chosen passphrase, opens this machine's
    /// copy of the shared volume.
    pub recovery_sentence: Zeroizing<String>,
}

/// Build the recipient's LOCAL factor vault around an accepted share's foreign
/// root and save it as `{base_dir}/slot_vault.json`.
///
/// The recipient protects THEIR copy with their own passphrase (plus a recovery
/// co-slot) — unrelated to the owner's vault, which the recipient never receives.
/// The vault's "master key" is the foreign root, gated behind the recipient's
/// factors; opening later feeds it to `open_volume_shared`.
///
/// Does NOT write `volume.json` or `shared_origin.json` — the caller writes those
/// (the config comes verbatim from the grant).
pub fn setup_shared_recipient(
    base_dir: &Path,
    foreign_root: &[u8; 32],
    recipient_passphrase: &[u8],
) -> Result<SharedRecipientSetup> {
    let mut vault = SlotVault::create_around("teagarden-shared", foreign_root);
    let mk = MasterKey::from_bytes(*foreign_root);

    let mut pp = PassphraseProtector::new(recipient_passphrase.to_vec(), Argon2Cost::default());
    vault.add_independent_slot(&mk, &mut pp, "passphrase")?;

    let mut rec = RecoveryProtector::for_enroll();
    vault.add_independent_slot(&mk, &mut rec, "recovery")?;
    let sentence = rec
        .enrolled_sentence()
        .ok_or_else(|| MfaError::Factor("recovery enroll did not yield a sentence".into()))?
        .to_string();

    std::fs::create_dir_all(base_dir)
        .map_err(|e| MfaError::Core(format!("create shared volume dir: {e}")))?;
    vault.save(base_dir.join(SLOT_VAULT_FILENAME))?;

    Ok(SharedRecipientSetup {
        recovery_sentence: Zeroizing::new(sentence),
    })
}

/// Enroll a new device-factor slot into an existing **key-protected** volume (K5).
///
/// Unlocks the vault via `existing` (an already-enrolled **counter-free** factor —
/// passphrase / recovery / keypair) to recover the master key, adds the new slot,
/// saves the vault and re-pins its anti-rollback anchor. This local mutation
/// persists exact pending header bytes; the CLI publishes the changed vault and
/// the next mount retries an interrupted publication.
///
/// Refuses a volume that is not key-protected (a factor cannot protect
/// password-rooted data — create with `--key-protection`).
pub fn enroll_factor(
    volume_id: &str,
    existing: &UnlockInputs<'_>,
    factor: EnrollFactor,
    volumes_dir: &Path,
) -> Result<SlotId> {
    let admin = manager::OwnerAdminLock::acquire(&volumes_dir.join(volume_id))
        .map_err(|e| MfaError::Core(e.to_string()))?;
    enroll_factor_in_transaction(volume_id, existing, factor, volumes_dir, &admin)
}

/// The production mutation inside the caller's full owner-administration transaction.
pub fn enroll_factor_in_transaction(
    volume_id: &str,
    existing: &UnlockInputs<'_>,
    factor: EnrollFactor,
    volumes_dir: &Path,
    admin: &manager::OwnerAdminLock,
) -> Result<SlotId> {
    admin
        .require_config(&volumes_dir.join(volume_id).join("volume.json"))
        .map_err(|e| MfaError::Core(e.to_string()))?;
    let base_dir = volumes_dir.join(volume_id);
    let config_path = base_dir.join("volume.json");
    if !config_path.exists() {
        return Err(MfaError::Core(format!("volume not found: {volume_id}")));
    }
    // A shared copy carries the OWNER's config (and its `key_protection` anchor)
    // verbatim; re-signing config_integrity here would diverge it from the owner's
    // shipped bytes and break the shared self-check. Refuse — the recipient
    // manages their own local vault's factors separately (follow-up verb).
    if SharedOrigin::exists(&base_dir) {
        return Err(MfaError::Core(
            "this is a shared volume; its config anchors the owner's vault and must not be \
             re-signed here — manage the local copy's factors with the recipient vault directly"
                .into(),
        ));
    }
    // R3: the single-writer lock (the one a mount, `key rotate`, `restore` and
    // `revert` hold) is taken BEFORE volume.json is read, and held until the
    // reseal below has written it: a config read before the lock could be one a
    // concurrent `key rotate` replaces, and the reseal would write its old epoch
    // and snapshot fields back.
    let _volume_lock = manager::VolumeLock::acquire_exclusive(&base_dir)
        .map_err(|e| MfaError::Core(e.to_string()))?;
    let mut config = load_config(&config_path)?;
    if config.key_protection.is_none() {
        return Err(MfaError::Core(
            "this volume is not key-protected; a factor cannot protect password-rooted \
             data — create the volume with --key-protection"
                .into(),
        ));
    }

    let vault_path = base_dir.join(SLOT_VAULT_FILENAME);
    let mut vault = SlotVault::load(&vault_path)?;

    // Recover the master key via an existing counter-free factor (LUKS2 "need a key
    // to add a key"). Device factors are not accepted as the *existing* opener here
    // — enroll with the passphrase or the recovery sentence.
    let existing_protectors = build_counter_free_protectors(existing)?;
    if existing_protectors.is_empty() {
        return Err(MfaError::Factor(
            "enrolling a new factor needs an existing passphrase or recovery sentence \
             to unlock the vault"
                .into(),
        ));
    }
    let refs: Vec<&dyn SlotProtector> = existing_protectors.iter().map(AsRef::as_ref).collect();
    let mk = vault.unlock(&refs)?;

    // mfa-H1: verify the volume exactly as open does — verification hash,
    // config HMAC, AND the anti-rollback anchor against this PRE-mutation vault —
    // before touching either file. Otherwise the reseal below would re-sign a
    // tampered volume.json, or re-anchor a rolled-back slot_vault.json and so
    // make a resurrected slot authentic.
    verify_before_slot_change(volume_id, &mk, &vault, volumes_dir)?;
    slot_header_base(&config, &mk, &config_path)?;

    let slot_id = match factor {
        #[cfg(feature = "test-util")]
        EnrollFactor::Test(mut protector) => {
            vault.add_independent_slot(&mk, protector.as_mut(), "software test factor")?
        }
        EnrollFactor::Tpm2 { pcrs } => {
            let mut p = Tpm2SealProtector::new(pcrs);
            vault.add_independent_slot(&mk, &mut p, "tpm2")?
        }
        EnrollFactor::Tang { url, thumbprint } => {
            let mut p = TangProtector::new(url, thumbprint);
            vault.add_independent_slot(&mk, &mut p, "tang")?
        }
        #[cfg(feature = "factor-pkcs11")]
        EnrollFactor::Pkcs11(i) => {
            let mut p = Pkcs11Protector::new(&i.module, i.token_label, i.key_id, i.pin.as_str());
            vault.add_independent_slot(&mk, &mut p, "pkcs11")?
        }
        #[cfg(feature = "factor-fido2")]
        EnrollFactor::Fido2 { generation } => {
            let mut p = Fido2HmacProtector::new().with_generation_options(generation)?;
            vault.add_independent_slot(&mk, &mut p, "fido2")?
        }
    };

    reserve_pending_header_revision(&mut config, &mk, &vault, &config_path, admin)?;

    // Save the vault, then re-pin the (generation, digest) anchor into the config so
    // the next open verifies (order: vault first — a crash before the reseal leaves
    // the vault one generation ahead of the anchor, which the next reseal repairs).
    vault.save(&vault_path)?;
    reseal_after_slot_change_in_transaction(volume_id, &mk, &vault, volumes_dir, admin)?;
    Ok(slot_id)
}

/// Remove slot `slot_id` from a **key-protected** volume's slot vault (mfa-H2).
///
/// The vault is any-one-of (like LUKS): every enrolled slot opens the volume on
/// its own, so ADDING a factor never makes it required. Removing the slots you
/// no longer want is how an operator actually restricts who can open it — e.g.
/// enroll TPM2, then remove the passphrase slot, so a passphrase alone no
/// longer opens the volume.
///
/// Rules, all enforced before anything is written:
/// - `opener` must unlock the vault through a slot OTHER than `slot_id` (and
///   not through a threshold group containing it): a removal can never be
///   authorised by the slot being removed. Device factors in `opener` are
///   tried (targeted), counter-free ones as usual.
/// - The volume must verify fully (hash, HMAC, anchor) — see mfa-H1.
/// - [`SlotVault::remove_slot`] refuses removing the last opener and removing
///   the last *durable* opener (passphrase / recovery / keypair).
/// - A shared (recipient-side) copy is refused, as for enroll.
///
/// Then: vault saved first, config resealed second (same crash ordering and
/// repair as enroll). Returns the removed slot's description.
pub fn remove_factor_slot(
    volume_id: &str,
    opener: &UnlockInputs<'_>,
    slot_id: SlotId,
    volumes_dir: &Path,
) -> Result<crate::kslot::SlotInfo> {
    let admin = manager::OwnerAdminLock::acquire(&volumes_dir.join(volume_id))
        .map_err(|e| MfaError::Core(e.to_string()))?;
    remove_factor_slot_in_transaction(volume_id, opener, slot_id, volumes_dir, &admin)
}

/// The production mutation inside the caller's full owner-administration transaction.
pub fn remove_factor_slot_in_transaction(
    volume_id: &str,
    opener: &UnlockInputs<'_>,
    slot_id: SlotId,
    volumes_dir: &Path,
    admin: &manager::OwnerAdminLock,
) -> Result<crate::kslot::SlotInfo> {
    admin
        .require_config(&volumes_dir.join(volume_id).join("volume.json"))
        .map_err(|e| MfaError::Core(e.to_string()))?;
    let base_dir = volumes_dir.join(volume_id);
    let config_path = base_dir.join("volume.json");
    if !config_path.exists() {
        return Err(MfaError::Core(format!("volume not found: {volume_id}")));
    }
    if SharedOrigin::exists(&base_dir) {
        return Err(MfaError::Core(
            "this is a shared volume; its config anchors the owner's vault and must not be \
             re-signed here"
                .into(),
        ));
    }
    // R3: the single-writer lock (the one a mount, `key rotate`, `restore` and
    // `revert` hold) is taken BEFORE volume.json is read, and held until the
    // reseal below has written it: a config read before the lock could be one a
    // concurrent `key rotate` replaces, and the reseal would write its old epoch
    // and snapshot fields back.
    let _volume_lock = manager::VolumeLock::acquire_exclusive(&base_dir)
        .map_err(|e| MfaError::Core(e.to_string()))?;
    let mut config = load_config(&config_path)?;
    if config.key_protection.is_none() {
        return Err(MfaError::Core(
            "this volume is not key-protected (password-rooted): it has no slots to remove".into(),
        ));
    }

    let vault_path = base_dir.join(SLOT_VAULT_FILENAME);
    let mut vault = SlotVault::load(&vault_path)?;
    let info = vault
        .slots()
        .into_iter()
        .find(|s| s.slot_id == slot_id)
        .ok_or_else(|| {
            MfaError::Factor(format!(
                "no slot {slot_id} in this volume's vault (see `teagarden keyslot status`)"
            ))
        })?;

    let mk = unlock_vault_master_key_excluding(&vault, opener, Some(slot_id), &config.display_name)
        .map_err(|e| match e {
            MfaError::DecryptionFailed => MfaError::Factor(format!(
                "the factor you supplied does not open this volume through any slot other than \
                 slot {slot_id} — removing a slot requires unlocking with a DIFFERENT slot that \
                 will remain"
            )),
            other => other,
        })?;
    verify_before_slot_change(volume_id, &mk, &vault, volumes_dir)?;
    slot_header_base(&config, &mk, &config_path)?;

    vault.remove_slot(&mk, slot_id)?;
    reserve_pending_header_revision(&mut config, &mk, &vault, &config_path, admin)?;
    vault.save(&vault_path)?;
    reseal_after_slot_change_in_transaction(volume_id, &mk, &vault, volumes_dir, admin)?;
    Ok(info)
}

/// Authenticate the complete TGHD2 policy and require the independent owner
/// capability before a global slot mutation. Legacy block volumes have no pin.
fn slot_header_base(
    config: &VolumeConfig,
    mk: &MasterKey,
    config_path: &Path,
) -> Result<Option<teagarden_core::sdo::HeaderDocument>> {
    let Some(pin) = config.sdo_owner_public_key.as_deref() else {
        return Ok(None);
    };
    let key = manager::load_owner_capability(config_path).map_err(|e| {
        MfaError::Core(format!(
            "global slot changes require the owner capability: {e}"
        ))
    })?;
    if hex::encode(key.verifying_key().to_bytes()) != pin {
        return Err(MfaError::Core(
            "owner capability differs from the pinned owner".into(),
        ));
    }
    let hierarchy = slot_hierarchy(config, mk)?;
    let bytes = std::fs::read(
        config_path
            .parent()
            .unwrap()
            .join(manager::OWNER_HEADER_FILENAME),
    )
    .map_err(|e| {
        MfaError::Core(format!(
            "authenticated current owner header is required before changing slots: {e}"
        ))
    })?;
    let header =
        teagarden_core::sdo::HeaderDocument::decode_pinned(&bytes, &hierarchy.integrity, Some(pin))
            .map_err(|e| MfaError::Core(e.to_string()))?;
    if header.format != 2
        || header.root_kind != teagarden_core::sdo::RootKind::MasterKey
        || header.volume_id != config.volume_id
        || header.group_id != config.telegram_group_id
        || header.topic_id != config.telegram_topic_id
        || header.revision != config.sdo_header_revision_published
        || header.key_protection
            != config
                .key_protection
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?
    {
        return Err(MfaError::Core("current owner header and local published vault anchors disagree; refresh owner state before changing slots".into()));
    }
    Ok(Some(header))
}

fn slot_hierarchy(
    config: &VolumeConfig,
    mk: &MasterKey,
) -> Result<teagarden_core::crypto::keys::KeyHierarchy> {
    teagarden_core::crypto::kdf::derive_hierarchy_from_master_key(
        mk.as_bytes(),
        &config.salt,
        config.telegram_group_id,
        config.telegram_topic_id,
    )
    .map_err(|e| MfaError::Core(e.to_string()))
}

/// Reserve the full signed intent BEFORE writing the changed vault. No pending
/// revision can exist without the exact authenticated bytes needed for retry.
fn reserve_pending_header_revision(
    config: &mut VolumeConfig,
    mk: &MasterKey,
    vault: &SlotVault,
    config_path: &Path,
    admin: &manager::OwnerAdminLock,
) -> Result<()> {
    if config.sdo_header_pending {
        return Err(MfaError::Core(
            "portable header publication is pending; repair it before changing slots".into(),
        ));
    }
    let revision = config
        .sdo_header_revision_reserved
        .max(config.sdo_header_revision_published)
        .checked_add(1)
        .ok_or_else(|| MfaError::Core("portable header revision overflow".into()))?;
    let bytes = encode_slot_header(config, mk, vault, config_path, revision)?;
    config.sdo_header_revision_reserved = revision;
    config.sdo_header_pending = true;
    config.sdo_header_pending_sha256 =
        Some(hex::encode(teagarden_core::block::srb2::sha256(&bytes)));
    config.sdo_header_pending_bytes = Some(hex::encode(bytes));
    let hierarchy = slot_hierarchy(config, mk)?;
    manager::save_config_resealed_in_transaction(config, &hierarchy, config_path, admin)
        .map_err(|e| MfaError::Core(e.to_string()))
}

/// Verify a protected volume fully — verification hash, config HMAC and the
/// `(generation, digest)` anti-rollback anchor against `vault` — before a slot
/// mutation (mfa-H1). `vault` must be the vault as loaded, BEFORE any change.
///
/// A refusal here leaves both files untouched. A vault one generation ahead of
/// its anchor (a crash between `vault.save` and the reseal) is refused too: it
/// cannot be told apart from a substituted vault without trusting the vault
/// file, so it is reported rather than silently re-anchored.
fn verify_before_slot_change(
    volume_id: &str,
    mk: &MasterKey,
    vault: &SlotVault,
    volumes_dir: &Path,
) -> Result<()> {
    manager::open_volume_with_master_key(
        volume_id,
        mk.as_bytes(),
        vault.generation(),
        &vault.state_digest(),
        volumes_dir,
    )
    .map(|_| ())
    .map_err(|e| {
        MfaError::Core(format!(
            "refusing to change this volume's slots: it does not verify as it is ({e}). \
             Nothing was modified."
        ))
    })
}

/// Re-pin the vault's CURRENT `(generation, state_digest)` into the volume's
/// `config_integrity` after a slot mutation (enroll / remove). Required after ANY
/// change to a protected volume's vault (design §6): the anti-rollback anchor is
/// checked at open, so without a reseal the next open would trip the stale-vault
/// check against the now-advanced live vault.
///
/// Refuses (and writes nothing) unless the on-disk config authenticates under
/// `mk` — verification hash and config HMAC (mfa-H1): re-signing an unverified
/// config would launder a local edit into an authentic one.
///
/// The caller must pass the vault in its post-mutation state (already `save`d) and
/// the recovered master key (needed to re-derive the integrity HMAC key). The
/// order that keeps the volume openable across a crash is: `vault.save` → this
/// reseal; a crash between them leaves the live vault one generation ahead of the
/// anchor (open refuses, but re-running the reseal repairs it — no data loss).
pub fn reseal_after_slot_change(
    volume_id: &str,
    mk: &MasterKey,
    vault: &SlotVault,
    volumes_dir: &Path,
) -> Result<()> {
    let admin = manager::OwnerAdminLock::acquire(&volumes_dir.join(volume_id))
        .map_err(|e| MfaError::Core(e.to_string()))?;
    reseal_after_slot_change_in_transaction(volume_id, mk, vault, volumes_dir, &admin)
}

/// The production mutation inside the caller's full owner-administration transaction.
pub fn reseal_after_slot_change_in_transaction(
    volume_id: &str,
    mk: &MasterKey,
    vault: &SlotVault,
    volumes_dir: &Path,
    admin: &manager::OwnerAdminLock,
) -> Result<()> {
    admin
        .require_config(&volumes_dir.join(volume_id).join("volume.json"))
        .map_err(|e| MfaError::Core(e.to_string()))?;
    let config_path = volumes_dir.join(volume_id).join("volume.json");
    let mut config = load_config(&config_path)?;
    if config.key_protection.is_none() {
        return Err(MfaError::Core(
            "refusing to reseal: volume.json is not key-protected".into(),
        ));
    }
    let hierarchy = teagarden_core::crypto::kdf::derive_hierarchy_from_master_key(
        mk.as_bytes(),
        &config.salt,
        config.telegram_group_id,
        config.telegram_topic_id,
    )
    .map_err(|e| MfaError::Core(e.to_string()))?;
    // mfa-H1: authenticate the struct we are about to re-sign (hash + HMAC under
    // this MK). The anchor is deliberately NOT compared here: the caller has
    // already advanced the vault, and re-running this after a crash between
    // `vault.save` and the reseal is the documented repair. The anchor is checked
    // against the pre-mutation vault by `verify_before_slot_change`.
    manager::verify_config_anchors(&config, &hierarchy)
        .map_err(|e| MfaError::Core(e.to_string()))?;
    config.key_protection = Some(teagarden_core::volume::config::KeyProtection {
        vault_generation: vault.generation(),
        vault_digest: hex::encode(vault.state_digest()),
    });
    if !config.sdo_header_pending {
        // Direct library callers resealing an already-persisted legacy vault.
        reserve_pending_header_revision(&mut config, mk, vault, &config_path, admin)?;
    }
    let bytes = hex::decode(
        config
            .sdo_header_pending_bytes
            .as_deref()
            .ok_or_else(|| MfaError::Core("pending slot header has no retry bytes".into()))?,
    )
    .map_err(|e| MfaError::Core(e.to_string()))?;
    let header = teagarden_core::sdo::HeaderDocument::decode_pinned(
        &bytes,
        &hierarchy.integrity,
        config.sdo_owner_public_key.as_deref(),
    )
    .map_err(|e| MfaError::Core(e.to_string()))?;
    if header.revision != config.sdo_header_revision_reserved
        || header.key_protection
            != config
                .key_protection
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?
        || header.slot_vault != Some(serde_json::from_slice(&vault.to_bytes()?)?)
        || config.sdo_header_pending_sha256.as_deref()
            != Some(hex::encode(teagarden_core::block::srb2::sha256(&bytes)).as_str())
    {
        return Err(MfaError::Core(
            "pending signed slot intent differs from the persisted vault".into(),
        ));
    }
    manager::save_config_resealed_in_transaction(&mut config, &hierarchy, &config_path, admin)
        .map_err(|e| MfaError::Core(e.to_string()))
}

fn encode_slot_header(
    config: &VolumeConfig,
    mk: &MasterKey,
    vault: &SlotVault,
    config_path: &Path,
    revision: u64,
) -> Result<Vec<u8>> {
    let hierarchy = slot_hierarchy(config, mk)?;
    let vault_bytes = vault.to_bytes()?;
    let anchor = teagarden_core::volume::config::KeyProtection {
        vault_generation: vault.generation(),
        vault_digest: hex::encode(vault.state_digest()),
    };
    if let Some(mut header) = slot_header_base(config, mk, config_path)? {
        header.revision = revision;
        header.slot_vault = Some(serde_json::from_slice(&vault_bytes)?);
        header.key_protection = Some(serde_json::to_value(anchor)?);
        let key = manager::load_owner_capability(config_path)
            .map_err(|e| MfaError::Core(e.to_string()))?;
        return header
            .encode_v2(&hierarchy.integrity, &key)
            .map_err(|e| MfaError::Core(e.to_string()));
    }
    let mut config = config.clone();
    config.key_protection = Some(anchor);
    let header = teagarden_core::sdo::HeaderDocument {
        format: 1,
        volume_id: config.volume_id,
        revision,
        volume_version: config.volume_version.to_string(),
        root_kind: teagarden_core::sdo::RootKind::MasterKey,
        salt: hex::encode(config.salt),
        kdf_params: None,
        group_id: config.telegram_group_id,
        topic_id: config.telegram_topic_id,
        current_epoch: config.current_epoch,
        block_v2_from_epoch: config.block_v2_from_epoch,
        require_block_integrity: config.require_block_integrity,
        block_size: config.block_config.target_block_size,
        key_protection: config
            .key_protection
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| MfaError::Core(e.to_string()))?,
        slot_vault: Some(
            serde_json::from_slice(&vault_bytes).map_err(|e| MfaError::Core(e.to_string()))?,
        ),
        owner_public_key: None,
        key_generation: None,
        revoked_device_ids: Vec::new(),
        revoked_account_bindings: Vec::new(),
        retained_key_bridges: Vec::new(),
        device_authorities: std::collections::BTreeMap::new(),
        rotation_state: None,
        generation_boundary_message_id: None,
        generation_cutoffs: Default::default(),
        revocation_cutoffs: Default::default(),
    };
    header
        .encode(&hierarchy.integrity)
        .map_err(|e| MfaError::Core(e.to_string()))
}

#[cfg(all(test, feature = "key-rotation"))]
mod rotation_tests {
    use super::*;

    #[test]
    #[cfg(feature = "key-rotation")]
    fn rotation_credentials_use_fresh_root_and_new_independent_slots() {
        let (_old_vault, old_master_key, old_recovery) =
            create_rotation_credentials(b"old volume password").unwrap();
        let (new_vault, new_master_key, new_recovery) =
            create_rotation_credentials(b"new volume password").unwrap();
        assert_ne!(old_master_key.as_bytes(), new_master_key.as_bytes());
        assert_ne!(old_recovery.as_str(), new_recovery.as_str());

        let mut old_passphrase =
            PassphraseProtector::new(b"old volume password".to_vec(), Argon2Cost::default());
        let old_passphrase: &dyn SlotProtector = &mut old_passphrase;
        assert!(new_vault.unlock(&[old_passphrase]).is_err());

        let mut old_recovery = RecoveryProtector::from_sentence(old_recovery.as_str()).unwrap();
        let old_recovery: &dyn SlotProtector = &mut old_recovery;
        assert!(new_vault.unlock(&[old_recovery]).is_err());

        let mut new_passphrase =
            PassphraseProtector::new(b"new volume password".to_vec(), Argon2Cost::default());
        let new_passphrase: &dyn SlotProtector = &mut new_passphrase;
        assert_eq!(
            new_vault.unlock(&[new_passphrase]).unwrap().as_bytes(),
            new_master_key.as_bytes()
        );
        let mut new_recovery = RecoveryProtector::from_sentence(new_recovery.as_str()).unwrap();
        let new_recovery: &dyn SlotProtector = &mut new_recovery;
        assert_eq!(
            new_vault.unlock(&[new_recovery]).unwrap().as_bytes(),
            new_master_key.as_bytes()
        );
    }
}
