//! K0a slot-vault tests: enroll/unlock round-trips, the tamper matrix (every
//! field flip must hard-fail), threshold + share-mixing, wrong-passphrase, and
//! REAL age / ssh-keygen interop. No test bypasses a protector to build a KEK.

#![cfg(test)]

use super::policy::PolicyEntry;
use super::protector::SlotProtector; // brings enroll/recover_kek into scope
use super::protectors::{Argon2Cost, KeypairProtector, PassphraseProtector, RecoveryProtector};
use super::vault::SlotVault;

// Fast Argon2 for tests (real KDF, tiny cost).
fn fast() -> Argon2Cost {
    Argon2Cost {
        m_kib: 8,
        t: 1,
        p: 1,
    }
}

fn pass(s: &str) -> PassphraseProtector {
    PassphraseProtector::new(s.as_bytes().to_vec(), fast())
}

// ── round-trips ───────────────────────────────────────────────────────────────

#[test]
fn passphrase_slot_round_trips_and_wrong_passphrase_fails() {
    let (mut v, mk) = SlotVault::create("volume:test");
    v.add_independent_slot(&mk, &mut pass("correct horse"), "laptop")
        .unwrap();
    let mk_bytes = *mk.as_bytes();

    // right passphrase opens and yields the SAME master key
    let opener = pass("correct horse");
    let got = v.unlock(&[&opener]).unwrap();
    assert_eq!(got.as_bytes(), &mk_bytes);

    // wrong passphrase fails closed
    let wrong = pass("battery staple");
    assert!(v.unlock(&[&wrong]).is_err());
}

#[test]
fn recovery_slot_round_trips_through_the_sentence() {
    let (mut v, mk) = SlotVault::create("volume:test");
    let mut rec = RecoveryProtector::for_enroll();
    v.add_independent_slot(&mk, &mut rec, "recovery").unwrap();
    let sentence = rec.enrolled_sentence().unwrap().to_string();
    let mk_bytes = *mk.as_bytes();

    let opener = RecoveryProtector::from_sentence(&sentence).unwrap();
    let got = v.unlock(&[&opener]).unwrap();
    assert_eq!(got.as_bytes(), &mk_bytes);

    // a different (freshly generated) recovery secret must not open it
    let mut other = RecoveryProtector::for_enroll();
    let _ = other.enroll();
    assert!(v.unlock(&[&other]).is_err());
}

#[test]
fn keypair_slot_round_trips_with_a_real_age_identity() {
    let id = age::x25519::Identity::generate();
    let recipient = id.to_public().to_string();
    let identity = {
        use age::secrecy::ExposeSecret;
        id.to_string().expose_secret().to_string()
    };

    let (mut v, mk) = SlotVault::create("volume:test");
    let mut kp = KeypairProtector::for_enroll(&recipient).unwrap();
    v.add_independent_slot(&mk, &mut kp, "yubikey-age").unwrap();
    let mk_bytes = *mk.as_bytes();

    let opener = KeypairProtector::for_unlock_age(&identity).unwrap();
    let got = v.unlock(&[&opener]).unwrap();
    assert_eq!(got.as_bytes(), &mk_bytes);

    // a different age identity cannot open it
    let other = age::x25519::Identity::generate();
    let other_id = {
        use age::secrecy::ExposeSecret;
        other.to_string().expose_secret().to_string()
    };
    let wrong = KeypairProtector::for_unlock_age(&other_id).unwrap();
    assert!(v.unlock(&[&wrong]).is_err());
}

#[test]
fn any_of_several_independent_slots_opens_the_vault() {
    let (mut v, mk) = SlotVault::create("volume:test");
    v.add_independent_slot(&mk, &mut pass("pw-a"), "a").unwrap();
    let mut rec = RecoveryProtector::for_enroll();
    v.add_independent_slot(&mk, &mut rec, "rec").unwrap();
    let sentence = rec.enrolled_sentence().unwrap().to_string();
    let mk_bytes = *mk.as_bytes();

    // either factor alone opens it (any-1 policy)
    assert_eq!(v.unlock(&[&pass("pw-a")]).unwrap().as_bytes(), &mk_bytes);
    let opener = RecoveryProtector::from_sentence(&sentence).unwrap();
    assert_eq!(v.unlock(&[&opener]).unwrap().as_bytes(), &mk_bytes);
}

// ── threshold ─────────────────────────────────────────────────────────────────

#[test]
fn two_of_three_threshold_needs_two_factors() {
    let (mut v, mk) = SlotVault::create("volume:test");
    let mut a = pass("m-a");
    let mut b = pass("m-b");
    let mut c = pass("m-c");
    v.add_threshold_group(
        &mk,
        2,
        &mut [
            (&mut a as &mut dyn super::SlotProtector, "a".into()),
            (&mut b, "b".into()),
            (&mut c, "c".into()),
        ],
    )
    .unwrap();
    let mk_bytes = *mk.as_bytes();

    // ONE member is insufficient
    assert!(v.unlock(&[&pass("m-a")]).is_err());
    // any TWO reconstruct
    assert_eq!(
        v.unlock(&[&pass("m-a"), &pass("m-b")]).unwrap().as_bytes(),
        &mk_bytes
    );
    assert_eq!(
        v.unlock(&[&pass("m-a"), &pass("m-c")]).unwrap().as_bytes(),
        &mk_bytes
    );
}

#[test]
fn mixed_policy_passphrase_or_two_of_two() {
    // "recovery OR (pw-x AND pw-y)"
    let (mut v, mk) = SlotVault::create("volume:test");
    let mut rec = RecoveryProtector::for_enroll();
    v.add_independent_slot(&mk, &mut rec, "rec").unwrap();
    let sentence = rec.enrolled_sentence().unwrap().to_string();
    let mut x = pass("pw-x");
    let mut y = pass("pw-y");
    v.add_threshold_group(
        &mk,
        2,
        &mut [
            (&mut x as &mut dyn super::SlotProtector, "x".into()),
            (&mut y, "y".into()),
        ],
    )
    .unwrap();
    let mk_bytes = *mk.as_bytes();

    // recovery alone opens (the OR branch)
    let opener = RecoveryProtector::from_sentence(&sentence).unwrap();
    assert_eq!(v.unlock(&[&opener]).unwrap().as_bytes(), &mk_bytes);
    // both group members open (the AND branch)
    assert_eq!(
        v.unlock(&[&pass("pw-x"), &pass("pw-y")])
            .unwrap()
            .as_bytes(),
        &mk_bytes
    );
    // one group member alone does NOT
    assert!(v.unlock(&[&pass("pw-x")]).is_err());
}

// ── persistence ───────────────────────────────────────────────────────────────

#[test]
fn vault_persists_and_reloads_and_still_unlocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mfa_vault.json");
    let mk_bytes;
    {
        let (mut v, mk) = SlotVault::create("volume:persist");
        v.add_independent_slot(&mk, &mut pass("pw"), "a").unwrap();
        mk_bytes = *mk.as_bytes();
        v.save(&path).unwrap();
        // 0o600
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let v2 = SlotVault::load(&path).unwrap();
    assert_eq!(v2.unlock(&[&pass("pw")]).unwrap().as_bytes(), &mk_bytes);
}

// ── tamper matrix (every field flip must hard-fail) ──────────────────────────────

fn built_vault_json() -> (serde_json::Value, [u8; 32]) {
    let (mut v, mk) = SlotVault::create("volume:tamper");
    v.add_independent_slot(&mk, &mut pass("pw"), "a").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.json");
    v.save(&path).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    (json, *mk.as_bytes())
}

fn reload_from_json(json: &serde_json::Value) -> SlotVault {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let path = dir.path().join("v.json");
    std::fs::write(&path, serde_json::to_vec(json).unwrap()).unwrap();
    SlotVault::load(&path).unwrap()
}

#[test]
fn tamper_flipping_payload_ciphertext_fails_closed() {
    let (mut json, _mk) = built_vault_json();
    let ct = json["slots"][0]["payload_ct_b64"]
        .as_str()
        .unwrap()
        .to_string();
    // flip a byte of the base64 ciphertext
    let mut chars: Vec<char> = ct.chars().collect();
    chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
    json["slots"][0]["payload_ct_b64"] = serde_json::Value::String(chars.into_iter().collect());
    let v = reload_from_json(&json);
    assert!(
        v.unlock(&[&pass("pw")]).is_err(),
        "flipped ciphertext must fail"
    );
}

#[test]
fn tamper_changing_slot_id_breaks_the_aad() {
    let (mut json, _mk) = built_vault_json();
    // slot_id is bound into the AAD; changing it (record + policy entry) must break decrypt
    json["slots"][0]["slot_id"] = serde_json::json!(999);
    json["policy"]["entries"][0]["slot_id"] = serde_json::json!(999);
    let v = reload_from_json(&json);
    assert!(
        v.unlock(&[&pass("pw")]).is_err(),
        "slot_id in AAD must bind"
    );
}

#[test]
fn tamper_changing_share_gen_breaks_the_aad() {
    let (mut json, _mk) = built_vault_json();
    json["slots"][0]["share_gen"] = serde_json::json!(7);
    let v = reload_from_json(&json);
    assert!(
        v.unlock(&[&pass("pw")]).is_err(),
        "share_gen in AAD must bind"
    );
}

#[test]
fn tamper_flipping_mk_commitment_fails_closed() {
    let (mut json, _mk) = built_vault_json();
    let mut c = json["mk_commitment_hex"].as_str().unwrap().to_string();
    c.replace_range(0..1, if c.starts_with('a') { "b" } else { "a" });
    json["mk_commitment_hex"] = serde_json::Value::String(c);
    let v = reload_from_json(&json);
    // wrong commitment ⇒ the correctly-decrypted MK no longer matches ⇒ closed
    assert!(
        v.unlock(&[&pass("pw")]).is_err(),
        "commitment must be checked"
    );
}

#[test]
fn tamper_downgrading_the_policy_mac_fails_closed() {
    // A 2-of-2 group downgraded to any-1 in the policy without MK: even after
    // an attacker who knows ONE member opens their share, the payload is a SHARE
    // (not MK) and the policy MAC will not verify. Build a 2-of-2 group, then
    // rewrite the policy to make member-0 a standalone slot.
    let (mut v, mk) = SlotVault::create("volume:tamper");
    let mut x = pass("pw-x");
    let mut y = pass("pw-y");
    let ids = v
        .add_threshold_group(
            &mk,
            2,
            &mut [
                (&mut x as &mut dyn super::SlotProtector, "x".into()),
                (&mut y, "y".into()),
            ],
        )
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.json");
    v.save(&path).unwrap();
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    // attacker downgrades: replace the group entry with a standalone-slot entry
    json["policy"]["entries"] = serde_json::json!([{ "kind": "slot", "slot_id": ids[0] }]);
    // Fails closed at load() now — validate() rejects a Slot entry pointing at a
    // share payload (an even earlier gate than unlock). Either way, member-0's
    // passphrase can never yield MK from one share.
    let dir2 = tempfile::tempdir().unwrap();
    let path2 = dir2.path().join("v.json");
    std::fs::write(&path2, serde_json::to_vec(&json).unwrap()).unwrap();
    match SlotVault::load(&path2) {
        Err(_) => {} // rejected at load — strongest outcome
        Ok(v2) => assert!(
            v2.unlock(&[&pass("pw-x")]).is_err(),
            "policy downgrade must not extract MK from one share"
        ),
    }
}

#[test]
fn policy_mac_mismatch_is_actually_reached_and_hard_fails() {
    // Audit G#1: exercise the policy_mac Err branch itself (the earlier tamper
    // test hit the payload-length gate first). Two standalone MK-slots, any-1
    // policy; REORDER the two (structurally valid — both slots exist, so load()
    // validate passes) so a real slot recovers MK (32B, commitment passes) but
    // the MAC, which binds entry order, mismatches → hard Err on the MAC branch.
    let (mut v, mk) = SlotVault::create("volume:macbranch");
    v.add_independent_slot(&mk, &mut pass("pw-a"), "a").unwrap();
    v.add_independent_slot(&mk, &mut pass("pw-b"), "b").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.json");
    v.save(&path).unwrap();
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["policy"]["entries"].as_array_mut().unwrap().swap(0, 1);
    let v2 = reload_from_json(&json);
    let got = v2.unlock(&[&pass("pw-a")]);
    assert!(
        matches!(got, Err(crate::error::MfaError::Factor(ref m)) if m.contains("policy integrity MAC")),
        "reordered policy must fail the policy MAC, got {got:?}"
    );
}

#[test]
fn ssh_rsa_recipients_are_rejected() {
    let err = KeypairProtector::for_enroll("ssh-rsa AAAAB3NzaC1yc2E fake");
    assert!(err.is_err(), "ssh-rsa recipients must be rejected");
}

#[test]
fn hostile_argon2_cost_is_rejected_at_load_not_ooming_unlock() {
    // A crafted vault with an absurd Argon2 m_kib must be refused at load()
    // rather than OOM the victim's unlock (audit finding E).
    let (mut v, mk) = SlotVault::create("volume:dos");
    v.add_independent_slot(&mk, &mut pass("pw"), "a").unwrap();
    let _ = mk;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.json");
    v.save(&path).unwrap();
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["slots"][0]["params"]["argon2"]["m_kib"] = serde_json::json!(4_000_000_000u64);
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    let loaded = SlotVault::load(&path);
    assert!(
        loaded.is_err(),
        "hostile Argon2 m_kib must be rejected at load"
    );
}

#[test]
fn generation_bumps_on_every_mutation() {
    let (mut v, mk) = SlotVault::create("volume:gen");
    let g0 = v.generation();
    v.add_independent_slot(&mk, &mut pass("a"), "a").unwrap();
    let g1 = v.generation();
    v.add_independent_slot(&mk, &mut pass("b"), "b").unwrap();
    let g2 = v.generation();
    v.remove_slot(&mk, 0).unwrap();
    let g3 = v.generation();
    assert!(
        g0 < g1 && g1 < g2 && g2 < g3,
        "generation must be monotonic: {g0} {g1} {g2} {g3}"
    );
    // digest changes with state
    let d_before = v.state_digest();
    v.add_independent_slot(&mk, &mut pass("c"), "c").unwrap();
    assert_ne!(d_before, v.state_digest());
}

#[test]
fn remove_last_opener_refused_without_mutating() {
    // Audit K0A-2: a refused last-opener removal must leave the vault openable.
    let (mut v, mk) = SlotVault::create("volume:lastopener");
    v.add_independent_slot(&mk, &mut pass("only"), "only")
        .unwrap();
    let mk_bytes = *mk.as_bytes();
    assert!(
        v.remove_slot(&mk, 0).is_err(),
        "removing the only opener must refuse"
    );
    // the slot is still there and still opens
    assert_eq!(v.unlock(&[&pass("only")]).unwrap().as_bytes(), &mk_bytes);
}

// ── share-mixing across generations ──────────────────────────────────────────────

#[test]
fn shares_from_different_generations_cannot_be_combined() {
    // Two separate 2-of-2 groups (distinct share_gen) protecting the SAME MK.
    // A share from group-1 and a share from group-2 must NOT reconstruct MK: the
    // AAD binds share_gen, so an attacker cannot even open them under a forged
    // single group, and combine across gens yields garbage caught by commitment.
    let (mut v, mk) = SlotVault::create("volume:gens");
    let mut a1 = pass("g1-a");
    let mut b1 = pass("g1-b");
    v.add_threshold_group(
        &mk,
        2,
        &mut [
            (&mut a1 as &mut dyn super::SlotProtector, "a1".into()),
            (&mut b1, "b1".into()),
        ],
    )
    .unwrap();
    let mut a2 = pass("g2-a");
    let mut b2 = pass("g2-b");
    v.add_threshold_group(
        &mk,
        2,
        &mut [
            (&mut a2 as &mut dyn super::SlotProtector, "a2".into()),
            (&mut b2, "b2".into()),
        ],
    )
    .unwrap();
    let mk_bytes = *mk.as_bytes();

    // within a generation, both members reconstruct
    assert_eq!(
        v.unlock(&[&pass("g1-a"), &pass("g1-b")])
            .unwrap()
            .as_bytes(),
        &mk_bytes
    );
    // one member from each generation: neither group has k=2 satisfied → closed
    assert!(v.unlock(&[&pass("g1-a"), &pass("g2-b")]).is_err());
}

// ── real ssh-keygen interop (the factor traverses a real ssh key) ─────────────────

#[test]
fn keypair_slot_interops_with_a_real_ssh_ed25519_key() {
    // Generate a real ed25519 keypair with ssh-keygen; enroll to the public
    // recipient; unlock with the private key. Skips loudly only if ssh-keygen is
    // genuinely absent (never silently green).
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_ed25519");
    let out = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "kslot-test", "-f"])
        .arg(&key)
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        Ok(o) => panic!("ssh-keygen failed: {}", String::from_utf8_lossy(&o.stderr)),
        Err(e) => panic!("ssh-keygen not available: {e}"),
    };
    let _ = out;
    let recipient = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let recipient = recipient.trim();
    let priv_pem = std::fs::read(&key).unwrap();

    let (mut v, mk) = SlotVault::create("volume:ssh");
    let mut kp = KeypairProtector::for_enroll(recipient).unwrap();
    v.add_independent_slot(&mk, &mut kp, "ssh").unwrap();
    let mk_bytes = *mk.as_bytes();

    let opener = KeypairProtector::for_unlock_ssh(&priv_pem).unwrap();
    assert_eq!(v.unlock(&[&opener]).unwrap().as_bytes(), &mk_bytes);
}

// ── canonical AAD determinism ─────────────────────────────────────────────────────

#[test]
fn policy_encoding_is_deterministic_across_reserialization() {
    // Re-serialize the vault JSON (which reorders nothing here) and confirm the
    // canonical policy bytes — and therefore unlock — are stable.
    let (json, mk_bytes) = built_vault_json();
    let round = serde_json::to_vec(&json).unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&round).unwrap();
    let v = reload_from_json(&json2);
    assert_eq!(v.unlock(&[&pass("pw")]).unwrap().as_bytes(), &mk_bytes);
    // member-id order within a group must not matter for the MAC input
    let g = super::policy::Policy {
        entries: vec![PolicyEntry::Group {
            k: 2,
            member_slot_ids: vec![3, 1, 2],
            share_gen: 1,
        }],
    };
    let g_sorted = super::policy::Policy {
        entries: vec![PolicyEntry::Group {
            k: 2,
            member_slot_ids: vec![1, 2, 3],
            share_gen: 1,
        }],
    };
    assert_eq!(
        super::aad::canonical_policy_bytes(&g),
        super::aad::canonical_policy_bytes(&g_sorted)
    );
}

/// A volume must never be left openable ONLY by hardware you can lose.
///
/// `remove_slot` already refused to remove the *last* opener, but that is not
/// enough: with `recovery + fido2`, removing recovery leaves FIDO2 alone, and a
/// lost key is then permanent, unrecoverable data loss — the master key is random
/// and the vault is its only wrapping.
#[test]
fn removing_the_last_durable_opener_is_refused() {
    use crate::kslot::types::SlotType;
    let (mut v, mk) = SlotVault::create("volume:durable");

    // One durable opener + one device-bound opener — the exact shape that the
    // old "last opener" check waves through.
    let pass_id = v
        .add_independent_slot(&mk, &mut pass("pw"), "passphrase")
        .unwrap();
    let _fido_id = v.test_graft_slot(&mk, SlotType::Fido2Hmac, "fido2");

    // Removing the ONLY durable opener would leave FIDO2 alone. Refused.
    let err = v
        .remove_slot(&mk, pass_id)
        .expect_err("removing the last DURABLE opener must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("device-bound"),
        "must refuse for the device-bound reason, not the last-opener one: {msg}"
    );

    // And the refusal must not have mutated anything (audit K0A-2).
    assert!(
        v.unlock(&[&pass("pw") as &dyn SlotProtector]).is_ok(),
        "a refused removal must leave the vault openable"
    );
}

/// The inverse: removing the DEVICE factor must still be allowed.
///
/// A guard that refused this would trap the operator into keeping a lost or dead
/// FIDO2 key enrolled forever — turning a data-loss fix into a different usability
/// trap.
#[test]
fn removing_a_device_factor_is_still_allowed() {
    use crate::kslot::types::SlotType;
    let (mut v, mk) = SlotVault::create("volume:durable2");
    let _pass_id = v
        .add_independent_slot(&mk, &mut pass("pw"), "passphrase")
        .unwrap();
    let fido_id = v.test_graft_slot(&mk, SlotType::Fido2Hmac, "fido2");

    v.remove_slot(&mk, fido_id)
        .expect("removing a device factor while a durable opener remains must be allowed");
    assert!(
        v.unlock(&[&pass("pw") as &dyn SlotProtector]).is_ok(),
        "the durable opener must still work afterwards"
    );
}

/// Two device factors and one durable: removing a device factor is fine, but the
/// durable one is still pinned.
#[test]
fn durable_opener_is_pinned_even_with_several_device_factors() {
    use crate::kslot::types::SlotType;
    let (mut v, mk) = SlotVault::create("volume:durable3");
    let pass_id = v
        .add_independent_slot(&mk, &mut pass("pw"), "passphrase")
        .unwrap();
    let tpm_id = v.test_graft_slot(&mk, SlotType::Tpm2, "tpm2");
    let _tang_id = v.test_graft_slot(&mk, SlotType::Tang, "tang");

    v.remove_slot(&mk, tpm_id).expect("device removal allowed");
    let err = v
        .remove_slot(&mk, pass_id)
        .expect_err("the sole durable opener stays pinned behind any number of device factors");
    assert!(format!("{err}").contains("device-bound"), "got: {err}");
}

/// A durable slot INSIDE a threshold group does not make the group durable.
///
/// The policy is any-1 over entries, so surviving a lost device requires some
/// single entry to be satisfiable by durable slots alone. A `{k:2, [passphrase,
/// fido2]}` group needs the FIDO2 key as well, so losing that key still destroys
/// the volume — even though a durable slot appears in the surviving slot set.
/// Flattening members into one set hides exactly this case.
#[test]
fn a_durable_slot_inside_a_threshold_group_does_not_satisfy_the_invariant() {
    use crate::kslot::types::SlotType;
    let (mut v, mk) = SlotVault::create("volume:durable-group");

    let pass_id = v
        .add_independent_slot(&mk, &mut pass("pw"), "passphrase")
        .unwrap();
    let fido_id = v.test_graft_slot(&mk, SlotType::Fido2Hmac, "fido2");
    let recovery_id = v
        .add_independent_slot(&mk, &mut pass("recovery-sentence"), "recovery")
        .unwrap();

    // Policy: EITHER the 2-of-2 {passphrase, fido2} group, OR recovery alone.
    v.test_set_group_policy(&mk, 2, &[pass_id, fido_id]);
    v.file_policy_push_slot_for_test(&mk, recovery_id);

    // Dropping recovery leaves only the group, which cannot be opened without
    // the FIDO2 key. Refused.
    let err = v
        .remove_slot(&mk, recovery_id)
        .expect_err("a group needing a device must not count as a durable opener");
    assert!(format!("{err}").contains("device-bound"), "got: {err}");
}

/// The inverse: a group whose threshold is met by durable members alone IS a
/// durable opener, and removing an unrelated device slot stays allowed.
#[test]
fn a_group_satisfiable_by_durable_members_alone_is_a_durable_opener() {
    use crate::kslot::types::SlotType;
    let (mut v, mk) = SlotVault::create("volume:durable-group-ok");

    let pass_id = v
        .add_independent_slot(&mk, &mut pass("pw"), "passphrase")
        .unwrap();
    let recovery_id = v
        .add_independent_slot(&mk, &mut pass("recovery-sentence"), "recovery")
        .unwrap();
    let tpm_id = v.test_graft_slot(&mk, SlotType::Tpm2, "tpm2");

    // A 2-of-2 group of two DURABLE slots: no physical object can be lost.
    v.test_set_group_policy(&mk, 2, &[pass_id, recovery_id]);
    v.file_policy_push_slot_for_test(&mk, tpm_id);

    v.remove_slot(&mk, tpm_id)
        .expect("an all-durable group is a durable opener, so the device slot may go");
}

/// The classification that the invariant rests on.
#[test]
fn device_bound_factors_are_classified_correctly() {
    use crate::kslot::types::SlotType;
    // Lose the object, lose the factor.
    for t in [
        SlotType::Fido2Hmac,
        SlotType::Tpm2,
        SlotType::Pkcs11,
        SlotType::Tang,
    ] {
        assert!(t.is_device_bound(), "{t:?} must count as device-bound");
        assert!(!t.is_durable(), "{t:?} must not count as a recovery path");
    }
    // Survives losing any single device.
    for t in [SlotType::Passphrase, SlotType::Recovery, SlotType::Keypair] {
        assert!(t.is_durable(), "{t:?} must count as durable");
        assert!(!t.is_device_bound(), "{t:?} must not count as device-bound");
    }
}

// ── mfa-M5: default cost of a new passphrase slot ─────────────────────────────

#[test]
fn default_passphrase_cost_is_at_least_the_core_default() {
    // The core password KDF default is 256 MiB / t=4 / p=4. A new passphrase
    // slot must not be cheaper to grind than a password-rooted volume.
    let core = teagarden_core::crypto::keys::Argon2Params::default();
    let slot = Argon2Cost::default();
    assert!(
        slot.m_kib >= core.memory_kib,
        "m_kib {} < {}",
        slot.m_kib,
        core.memory_kib
    );
    assert!(
        slot.t >= core.iterations,
        "t {} < {}",
        slot.t,
        core.iterations
    );
    assert!(
        slot.p >= core.parallelism,
        "p {} < {}",
        slot.p,
        core.parallelism
    );
}

#[test]
fn a_slot_enrolled_at_the_old_default_still_opens() {
    // Existing slots keep their STORED cost: unlock reads it from the slot
    // params, whatever cost the opener was constructed with.
    let old = Argon2Cost {
        m_kib: 65536,
        t: 2,
        p: 1,
    };
    let (mut v, mk) = SlotVault::create("volume:old-cost");
    v.add_independent_slot(
        &mk,
        &mut PassphraseProtector::new(b"pw".to_vec(), old),
        "old",
    )
    .unwrap();
    let opener = PassphraseProtector::new(b"pw".to_vec(), Argon2Cost::default());
    assert_eq!(v.unlock(&[&opener]).unwrap().as_bytes(), mk.as_bytes());
}

// ── mfa-L2: slot-count cap ────────────────────────────────────────────────────

#[test]
fn enrolling_past_the_slot_cap_is_refused() {
    let (mut v, mk) = SlotVault::create("volume:cap");
    for i in 0..32 {
        v.add_independent_slot(&mk, &mut pass("pw"), &format!("s{i}"))
            .unwrap_or_else(|e| panic!("slot {i} of 32 must enroll: {e}"));
    }
    let before = v.generation();
    let err = v
        .add_independent_slot(&mk, &mut pass("pw"), "s32")
        .expect_err("the 33rd slot must be refused");
    assert!(format!("{err}").contains("32"), "unexpected error: {err}");
    assert_eq!(v.slot_count(), 32, "a refused enroll must not add a slot");
    assert_eq!(
        v.generation(),
        before,
        "a refused enroll must not bump the generation"
    );
}

#[test]
fn a_vault_file_with_too_many_slots_is_refused_at_load() {
    // A hostile vault with thousands of passphrase slots turns one unlock into
    // thousands of Argon2 runs. Refuse it before any KDF.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("slot_vault.json");
    let (mut v, mk) = SlotVault::create("volume:hostile");
    v.add_independent_slot(&mk, &mut pass("pw"), "real")
        .unwrap();
    for i in 0..40 {
        v.test_graft_slot(&mk, super::types::SlotType::Recovery, &format!("g{i}"));
    }
    v.save(&path).unwrap();
    let err = match SlotVault::load(&path) {
        Ok(_) => panic!("a 41-slot vault must be refused at load"),
        Err(e) => e,
    };
    assert!(
        format!("{err}").contains("slots"),
        "unexpected error: {err}"
    );
}

// ── mfa-L4: recovery-sentence errors never echo a word ────────────────────────

#[test]
fn a_mistyped_recovery_word_is_not_echoed() {
    let mut rec = RecoveryProtector::for_enroll();
    let _ = rec.enroll().unwrap();
    let sentence = rec.enrolled_sentence().unwrap().to_string();
    let mut words: Vec<&str> = sentence.split_whitespace().collect();
    words[4] = "zzsecretzz";
    let typo = words.join(" ");
    let err = match RecoveryProtector::from_sentence(&typo) {
        Ok(_) => panic!("a sentence with an unknown word must be refused"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        !msg.contains("zzsecretzz"),
        "the mistyped word leaked: {msg}"
    );
    assert!(
        msg.contains("word 5"),
        "the position must be reported: {msg}"
    );
}

// ── concurrent saves ─────────────────────────────────────────────────────────

/// Two processes saving the same vault at once (an enroll racing a
/// remove-slot, or two enrolls). With one fixed temp name they truncate and
/// write the SAME temp inode, so a torn vault can be renamed into place — which
/// `load` refuses, locking the owner out — and the loser's rename hits ENOENT.
/// Every save must succeed, every observed file must load, the file must stay
/// 0600, and no temp file may be left behind.
#[test]
fn concurrent_saves_never_tear_or_fail() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().join("slot_vault.json"));
    let errors = Arc::new(AtomicUsize::new(0));
    let first_error = Arc::new(std::sync::Mutex::new(None::<String>));
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let (path, errors, first_error) = (path.clone(), errors.clone(), first_error.clone());
            // Each thread saves its OWN vault, with a different number of slots,
            // so files differ in length and a torn write cannot parse.
            let (mut v, mk) = SlotVault::create(format!("volume:race-{t}"));
            for s in 0..=(t % 3) {
                v.add_independent_slot(&mk, &mut pass("pw"), &format!("s{s}"))
                    .unwrap();
            }
            std::thread::spawn(move || {
                for _ in 0..150 {
                    let r = v.save(&*path).map_err(|e| e.to_string()).and_then(|()| {
                        SlotVault::load(&*path)
                            .map(|_| ())
                            .map_err(|e| format!("torn vault: {e}"))
                    });
                    if let Err(e) = r {
                        errors.fetch_add(1, Ordering::Relaxed);
                        first_error.lock().unwrap().get_or_insert(e);
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(
        errors.load(Ordering::Relaxed),
        0,
        "concurrent vault saves must never fail or tear; first error: {:?}",
        first_error.lock().unwrap()
    );
    SlotVault::load(&*path).expect("final vault loads");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&*path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .filter(|n| n != "slot_vault.json")
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
}

// ── a failed device unlock says why ───────────────────────────────────────────

/// A FIDO2 protector whose key unwrap fails with a fixed, already-worded reason.
/// It is a fixture over `SlotProtector`, not a stand-in for the key: it exercises
/// only what the vault does with the error a real protector returns.
struct FailingFido2(&'static str);

impl SlotProtector for FailingFido2 {
    fn slot_type(&self) -> crate::kslot::types::SlotType {
        crate::kslot::types::SlotType::Fido2Hmac
    }

    fn enroll(&mut self) -> crate::error::Result<super::protector::Enrollment> {
        Err(crate::error::MfaError::Factor("not enrollable".into()))
    }

    fn recover_kek(
        &self,
        _params: &serde_json::Value,
        _transport: &super::protector::KekTransport,
    ) -> crate::error::Result<crate::kslot::types::Kek> {
        Err(crate::error::MfaError::Factor(self.0.into()))
    }
}

#[test]
fn a_failed_fido2_unlock_reports_the_reason_per_slot() {
    use crate::kslot::types::SlotType;
    let (mut v, mk) = SlotVault::create("volume:fido-why");
    v.add_independent_slot(&mk, &mut pass("pw"), "passphrase")
        .unwrap();
    let fido_id = v.test_graft_slot(&mk, SlotType::Fido2Hmac, "fido2");

    let err = v
        .unlock_targeted(&[&FailingFido2("wrong PIN for the security key") as &dyn SlotProtector])
        .expect_err("the only protector failed");
    let msg = format!("{err}");
    assert!(msg.contains("wrong PIN for the security key"), "{msg}");
    assert!(msg.contains(&format!("slot {fido_id}")), "{msg}");
    assert!(msg.contains("FIDO2"), "{msg}");
}

#[test]
fn a_failure_with_no_recorded_reason_is_still_decryption_failed() {
    let (mut v, mk) = SlotVault::create("volume:no-reason");
    v.add_independent_slot(&mk, &mut pass("pw"), "passphrase")
        .unwrap();
    let err = v
        .unlock(&[&pass("not-the-passphrase") as &dyn SlotProtector])
        .expect_err("wrong passphrase");
    assert!(
        matches!(err, crate::error::MfaError::DecryptionFailed),
        "{err}"
    );
}

#[test]
fn a_fido2_failure_does_not_mask_a_slot_that_opens() {
    use crate::kslot::types::SlotType;
    let (mut v, mk) = SlotVault::create("volume:fido-then-pass");
    v.test_graft_slot(&mk, SlotType::Fido2Hmac, "fido2");
    v.add_independent_slot(&mk, &mut pass("pw"), "passphrase")
        .unwrap();
    let mk_bytes = *mk.as_bytes();
    let opener = pass("pw");
    let got = v
        .unlock_targeted(&[
            &FailingFido2("no key attached") as &dyn SlotProtector,
            &opener,
        ])
        .expect("the passphrase slot opens the volume");
    assert_eq!(got.as_bytes(), &mk_bytes);
}
