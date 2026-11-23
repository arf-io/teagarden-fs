//! K0b enforcement — the crux tests that prove multi-factor protection is REAL,
//! not decoration (design §8 / advisor "spine"). Each test drives the public
//! `mfa::unlock` API + the `teagarden-core` chokepoint exactly as the CLI does.
//!
//! The load-bearing properties:
//!   1. a protected volume round-trips through BOTH its passphrase and its
//!      recovery co-slot (real MK recovery);
//!   2. a legacy password-rooted volume still opens unchanged;
//!   3. a protected volume refuses to open without a valid factor;
//!   4. a bare password against a protected volume fails CLOSED at the core
//!      chokepoint (the linchpin — no un-wired caller can bypass);
//!   5. a vault-SWAP (attacker's own valid vault, different MK) is refused;
//!   6. a vault-only generation ROLLBACK is refused (closes K0A-1's vault-only
//!      case);
//!   7. a whole-volume (both files) rollback is NOT caught — the honest residual.

use teagarden_core::volume::manager;
use teagarden_mfa::kslot::{Argon2Cost, PassphraseProtector, SlotProtector, SlotVault};
use teagarden_mfa::unlock::{
    self, create_protected_volume, open_volume, UnlockInputs, SLOT_VAULT_FILENAME,
};

const PW: &[u8] = b"correct-horse-battery-staple";

fn tmp() -> tempfile::TempDir {
    tempfile::TempDir::new().unwrap()
}

/// (1) A protected volume is recoverable via its passphrase AND its recovery
/// co-slot, and both paths reconstruct the identical MK-derived hierarchy.
#[test]
fn protected_roundtrip_via_passphrase_and_recovery() {
    let dir = tmp();
    let pc = create_protected_volume(Some("prot"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();

    // The volume is recorded as key-protected (MK-rooted), not legacy.
    assert!(
        pc.created.config.key_protection.is_some(),
        "protected create must set key_protection"
    );

    // Open with the passphrase.
    let via_pw = open_volume(
        &id,
        &UnlockInputs {
            password: Some(PW),
            ..Default::default()
        },
        dir.path(),
    )
    .expect("passphrase must open a protected volume");

    // Open with the recovery sentence.
    let sentence = pc.recovery_sentence.to_string();
    let via_rec = open_volume(
        &id,
        &UnlockInputs {
            recovery_sentence: Some(&sentence),
            ..Default::default()
        },
        dir.path(),
    )
    .expect("recovery sentence must open a protected volume");

    // Both factors recover the SAME master key → identical data key.
    assert_eq!(
        via_pw.hierarchy.data.as_bytes(),
        via_rec.hierarchy.data.as_bytes(),
        "passphrase and recovery must yield the same MK-rooted hierarchy"
    );
    assert_eq!(
        via_pw.hierarchy.data.as_bytes(),
        pc.created.hierarchy.data.as_bytes(),
        "opened hierarchy must match the one create derived"
    );
}

/// (2) A legacy password-rooted volume (no vault) still opens unchanged through
/// the same entry point — the wiring is transparent to existing volumes.
#[test]
fn legacy_password_volume_still_opens() {
    let dir = tmp();
    let created = manager::create_volume(Some("legacy"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = created.config.volume_id.to_string();
    assert!(created.config.key_protection.is_none());

    let opened = open_volume(
        &id,
        &UnlockInputs {
            password: Some(PW),
            ..Default::default()
        },
        dir.path(),
    )
    .expect("legacy volume must open with its password");
    assert_eq!(
        opened.hierarchy.data.as_bytes(),
        created.hierarchy.data.as_bytes()
    );
}

/// (3) A protected volume refuses to open without a valid factor: no factor at
/// all, and a wrong passphrase, both fail.
#[test]
fn protected_refuses_without_valid_factor() {
    let dir = tmp();
    let pc = create_protected_volume(Some("prot"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();

    // No factor supplied.
    assert!(
        open_volume(&id, &UnlockInputs::default(), dir.path()).is_err(),
        "opening a protected volume with no factor must fail"
    );

    // Wrong passphrase.
    assert!(
        open_volume(
            &id,
            &UnlockInputs {
                password: Some(b"wrong-password"),
                ..Default::default()
            },
            dir.path(),
        )
        .is_err(),
        "opening a protected volume with the wrong passphrase must fail"
    );
}

/// (4) THE LINCHPIN: a bare password routed to the legacy core chokepoint
/// (`manager::open_volume`) against a protected volume fails CLOSED. This is what
/// makes every un-wired open-site safe — it cannot open, and cannot bypass.
#[test]
fn bare_password_at_core_chokepoint_fails_closed() {
    let dir = tmp();
    let pc = create_protected_volume(Some("prot"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();

    let err = manager::open_volume(&id, PW, dir.path())
        .expect_err("a protected volume must not open via the bare-password path");
    let msg = format!("{err}");
    assert!(
        msg.contains("key-slot vault"),
        "fail-closed error should route the caller to the vault: {msg}"
    );
}

/// (5) A vault-SWAP — the attacker replaces `mfa_vault.json` with their OWN valid
/// vault (a different master key they can open) — is refused: the wrong MK
/// derives a hierarchy whose verification hash does not match this volume.
#[test]
fn vault_swap_is_refused() {
    let dir = tmp();
    let pc = create_protected_volume(Some("victim"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();
    let vault_path = dir.path().join(&id).join(SLOT_VAULT_FILENAME);

    // Attacker builds their own valid vault (fresh random MK) with a passphrase
    // slot they control, and overwrites the victim's vault file.
    let (mut evil, evil_mk) = SlotVault::create("attacker");
    let mut evil_pp = PassphraseProtector::new(b"attacker-pw".to_vec(), Argon2Cost::default());
    evil.add_independent_slot(&evil_mk, &mut evil_pp, "attacker")
        .unwrap();
    evil.save(&vault_path).unwrap();

    // Opening with the attacker's (valid-for-their-vault) password recovers the
    // WRONG master key → refused by the volume's verification hash.
    let err = open_volume(
        &id,
        &UnlockInputs {
            password: Some(b"attacker-pw"),
            ..Default::default()
        },
        dir.path(),
    )
    .expect_err("a swapped vault with a different MK must not open the volume");
    let msg = format!("{err}");
    assert!(
        msg.contains("does not match this volume") || msg.contains("substituted"),
        "expected a vault-mismatch error, got: {msg}"
    );
}

/// (6) A vault-only generation ROLLBACK is refused. This is the K0A-1 closure:
/// reverting `mfa_vault.json` alone to an earlier generation (e.g. to re-enable a
/// since-removed slot) trips the `(generation, digest)` anchor.
#[test]
fn stale_vault_generation_rollback_is_refused() {
    let dir = tmp();
    let pc = create_protected_volume(Some("prot"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();
    let vault_path = dir.path().join(&id).join(SLOT_VAULT_FILENAME);

    // Snapshot the vault at its create-time generation.
    let old_vault_bytes = std::fs::read(&vault_path).unwrap();

    // Enroll a second passphrase slot and reseal the config anchor to the new gen.
    {
        let mut vault = SlotVault::load(&vault_path).unwrap();
        let pp = PassphraseProtector::new(PW.to_vec(), Argon2Cost::default());
        let refs: Vec<&dyn SlotProtector> = vec![&pp];
        let mk = vault.unlock(&refs).unwrap();
        let mut q = PassphraseProtector::new(b"second-pw".to_vec(), Argon2Cost::default());
        vault
            .add_independent_slot(&mk, &mut q, "passphrase2")
            .unwrap();
        vault.save(&vault_path).unwrap();
        unlock::reseal_after_slot_change(&id, &mk, &vault, dir.path()).unwrap();
    }

    // Sanity: the new slot opens now (anchor and vault are both advanced).
    assert!(open_volume(
        &id,
        &UnlockInputs {
            password: Some(b"second-pw"),
            ..Default::default()
        },
        dir.path(),
    )
    .is_ok());

    // Attacker rolls the vault file back to the create-time generation.
    std::fs::write(&vault_path, &old_vault_bytes).unwrap();

    // Even the ORIGINAL passphrase (present in the old vault) is now refused: the
    // live vault's generation no longer matches the authenticated anchor.
    let err = open_volume(
        &id,
        &UnlockInputs {
            password: Some(PW),
            ..Default::default()
        },
        dir.path(),
    )
    .expect_err("a rolled-back (older-generation) vault must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("stale") || msg.contains("rolled back") || msg.contains("mismatch"),
        "expected a stale-vault error, got: {msg}"
    );
}

/// (7) HONEST RESIDUAL: a whole-volume rollback — reverting `volume.json` AND
/// `mfa_vault.json` TOGETHER to an earlier consistent snapshot — is NOT caught by
/// the anchor (the old config's HMAC re-verifies and the old anchor matches the
/// old vault). Documented in design §4a; closing it needs external monotonic
/// state. This test PINS that behavior so the residual is stated, not hidden.
#[test]
fn whole_volume_rollback_is_not_caught_documented_residual() {
    let dir = tmp();
    let pc = create_protected_volume(Some("prot"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();
    let base = dir.path().join(&id);
    let vault_path = base.join(SLOT_VAULT_FILENAME);
    let config_path = base.join("volume.json");

    // Snapshot BOTH files at the create-time generation (a consistent pair).
    let old_vault = std::fs::read(&vault_path).unwrap();
    let old_config = std::fs::read(&config_path).unwrap();

    // Advance the vault + reseal (as in test 6).
    {
        let mut vault = SlotVault::load(&vault_path).unwrap();
        let pp = PassphraseProtector::new(PW.to_vec(), Argon2Cost::default());
        let refs: Vec<&dyn SlotProtector> = vec![&pp];
        let mk = vault.unlock(&refs).unwrap();
        let mut q = PassphraseProtector::new(b"second-pw".to_vec(), Argon2Cost::default());
        vault
            .add_independent_slot(&mk, &mut q, "passphrase2")
            .unwrap();
        vault.save(&vault_path).unwrap();
        unlock::reseal_after_slot_change(&id, &mk, &vault, dir.path()).unwrap();
    }

    // Roll BOTH files back together to the earlier consistent snapshot.
    std::fs::write(&vault_path, &old_vault).unwrap();
    std::fs::write(&config_path, &old_config).unwrap();

    // The volume opens — the anchor cannot distinguish a consistent whole-volume
    // rollback from the legitimate current state. This is the accepted residual.
    open_volume(
        &id,
        &UnlockInputs {
            password: Some(PW),
            ..Default::default()
        },
        dir.path(),
    )
    .expect("whole-volume rollback opens (documented residual — anchor cannot catch it)");
}

/// Drop `require_block_integrity` from volume.json the way a local tamperer
/// would (no key needed — it is a plain JSON edit). The field is serialized only
/// when true, so removing it is the "false" downgrade.
fn tamper_drop_block_integrity(config_path: &std::path::Path) -> Vec<u8> {
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
    assert_eq!(
        v.get("require_block_integrity"),
        Some(&serde_json::Value::Bool(true)),
        "fixture: a new volume enforces block integrity"
    );
    v.as_object_mut().unwrap().remove("require_block_integrity");
    let bytes = serde_json::to_vec_pretty(&v).unwrap();
    std::fs::write(config_path, &bytes).unwrap();
    bytes
}

/// (8) mfa-H1: the reseal after a slot change must NOT launder a tampered
/// config. Before the fix it re-read volume.json unverified and re-signed it, so
/// the owner's next enroll made a local downgrade (here: dropping
/// require_block_integrity) authentic.
#[test]
fn reseal_refuses_to_resign_a_tampered_config() {
    let dir = tmp();
    let pc = create_protected_volume(Some("prot"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();
    let base = dir.path().join(&id);
    let vault_path = base.join(SLOT_VAULT_FILENAME);
    let config_path = base.join("volume.json");

    let tampered = tamper_drop_block_integrity(&config_path);

    // The owner adds a slot, exactly as enroll does, then reseals.
    let mut vault = SlotVault::load(&vault_path).unwrap();
    let pp = PassphraseProtector::new(PW.to_vec(), Argon2Cost::default());
    let refs: Vec<&dyn SlotProtector> = vec![&pp];
    let mk = vault.unlock(&refs).unwrap();
    let mut q = PassphraseProtector::new(b"second-pw".to_vec(), Argon2Cost::default());
    vault
        .add_independent_slot(&mk, &mut q, "passphrase2")
        .unwrap();
    vault.save(&vault_path).unwrap();
    let r = unlock::reseal_after_slot_change(&id, &mk, &vault, dir.path());

    assert!(
        r.is_err(),
        "reseal must refuse a config whose HMAC does not verify"
    );
    assert_eq!(
        std::fs::read(&config_path).unwrap(),
        tampered,
        "a refused reseal must not rewrite volume.json"
    );
    // And the downgrade stays detectable: the volume still refuses to open.
    assert!(open_volume(
        &id,
        &UnlockInputs {
            password: Some(PW),
            ..Default::default()
        },
        dir.path(),
    )
    .is_err());
}

/// (9) mfa-H1: a legitimate reseal still works (and the crash-repair property
/// the design relies on — "re-running the reseal repairs a vault one generation
/// ahead of the anchor" — still holds, since reseal does not check the anchor).
#[test]
fn reseal_still_repairs_a_vault_ahead_of_its_anchor() {
    let dir = tmp();
    let pc = create_protected_volume(Some("prot"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();
    let vault_path = dir.path().join(&id).join(SLOT_VAULT_FILENAME);

    let mut vault = SlotVault::load(&vault_path).unwrap();
    let pp = PassphraseProtector::new(PW.to_vec(), Argon2Cost::default());
    let refs: Vec<&dyn SlotProtector> = vec![&pp];
    let mk = vault.unlock(&refs).unwrap();
    let mut q = PassphraseProtector::new(b"second-pw".to_vec(), Argon2Cost::default());
    vault
        .add_independent_slot(&mk, &mut q, "passphrase2")
        .unwrap();
    vault.save(&vault_path).unwrap();

    // "Crash" here: vault saved, config not resealed → open refuses.
    let inputs = UnlockInputs {
        password: Some(b"second-pw"),
        ..Default::default()
    };
    assert!(open_volume(&id, &inputs, dir.path()).is_err());

    // Re-running the reseal repairs it.
    unlock::reseal_after_slot_change(&id, &mk, &vault, dir.path()).unwrap();
    open_volume(&id, &inputs, dir.path()).expect("repaired by the reseal");
}

/// (10) mfa-H2 + H1: removing a slot also verifies first, and a refusal writes
/// nothing; a slot can never authorise its own removal.
#[test]
fn remove_factor_slot_verifies_first_and_needs_a_different_slot() {
    let dir = tmp();
    let pc = create_protected_volume(Some("rm"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();
    let base = dir.path().join(&id);
    let vault_path = base.join(SLOT_VAULT_FILENAME);
    let vault = SlotVault::load(&vault_path).unwrap();
    let slot = |label: &str| {
        vault
            .slots()
            .into_iter()
            .find(|s| s.label == label)
            .unwrap()
            .slot_id
    };
    let (pass_id, rec_id) = (slot("passphrase"), slot("recovery"));
    let pw_in = UnlockInputs {
        password: Some(PW),
        ..Default::default()
    };

    // Self-authorisation is refused, nothing written.
    let before = std::fs::read(&vault_path).unwrap();
    let err = unlock::remove_factor_slot(&id, &pw_in, pass_id, dir.path()).unwrap_err();
    assert!(format!("{err}").contains("DIFFERENT slot"), "{err}");
    assert_eq!(std::fs::read(&vault_path).unwrap(), before);

    // A tampered config is refused before the vault is touched.
    let config_path = base.join("volume.json");
    let good_config = std::fs::read(&config_path).unwrap();
    tamper_drop_block_integrity(&config_path);
    assert!(unlock::remove_factor_slot(&id, &pw_in, rec_id, dir.path()).is_err());
    assert_eq!(std::fs::read(&vault_path).unwrap(), before);
    std::fs::write(&config_path, &good_config).unwrap();

    // Legitimate removal: the recovery slot, authorised by the passphrase.
    let removed = unlock::remove_factor_slot(&id, &pw_in, rec_id, dir.path()).unwrap();
    assert_eq!(removed.slot_id, rec_id);
    let config: teagarden_core::volume::config::VolumeConfig =
        serde_json::from_slice(&std::fs::read(base.join("volume.json")).unwrap()).unwrap();
    assert!(config.sdo_header_pending);
    assert_eq!(config.sdo_header_revision_reserved, 1);
    assert!(config.sdo_header_pending_sha256.is_some());
    open_volume(&id, &pw_in, dir.path()).expect("passphrase still opens");
    let rec_in = UnlockInputs {
        recovery_sentence: Some(pc.recovery_sentence.as_str()),
        ..Default::default()
    };
    assert!(
        open_volume(&id, &rec_in, dir.path()).is_err(),
        "the removed recovery slot must no longer open the volume"
    );
}

/// R3: `keyslot enroll` and `keyslot remove-slot` re-seal volume.json, so they
/// take the volume's single-writer lock BEFORE reading the config. While another
/// command (a mount, `key rotate`, ...) holds it, both refuse with the lock
/// error (never with a config error, which is what a command that read
/// volume.json first reports here: the config below fails its MAC) and write
/// nothing.
#[test]
fn slot_changes_take_the_volume_lock_before_reading_the_config() {
    let dir = tmp();
    let pc = create_protected_volume(Some("lock"), PW, dir.path(), 0, 0, 0, None).unwrap();
    let id = pc.created.config.volume_id.to_string();
    let base = dir.path().join(&id);
    let vault_path = base.join(SLOT_VAULT_FILENAME);
    let rec_id = SlotVault::load(&vault_path)
        .unwrap()
        .slots()
        .into_iter()
        .find(|s| s.label == "recovery")
        .unwrap()
        .slot_id;
    let pw_in = UnlockInputs {
        password: Some(PW),
        ..Default::default()
    };
    let held = manager::VolumeLock::acquire_exclusive(&base).unwrap();
    let tampered = tamper_drop_block_integrity(&base.join("volume.json"));
    let vault_before = std::fs::read(&vault_path).unwrap();

    let err = unlock::enroll_factor(
        &id,
        &pw_in,
        unlock::EnrollFactor::Tang {
            url: "http://127.0.0.1:9".into(),
            thumbprint: None,
        },
        dir.path(),
    )
    .unwrap_err();
    eprintln!("enroll under a held lock: {err}");
    assert!(
        format!("{err}").contains("in use by another process"),
        "{err}"
    );
    let err = unlock::remove_factor_slot(&id, &pw_in, rec_id, dir.path()).unwrap_err();
    eprintln!("remove-slot under a held lock: {err}");
    assert!(
        format!("{err}").contains("in use by another process"),
        "{err}"
    );

    assert_eq!(std::fs::read(base.join("volume.json")).unwrap(), tampered);
    assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before);
    drop(held);
}
