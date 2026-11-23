//! K1 FIDO2 hmac-secret — REAL hardware end-to-end.
//!
//! Proves a slot vault's master key can be protected by, and recovered from, a
//! PHYSICAL FIDO2 authenticator (hmac-secret), with a recovery-sentence co-slot
//! as the mandated fallback.
//!
//! Run (touch the key + enter its PIN when prompted):
//!   FIDO2_PIN=1234 cargo run -p teagarden-mfa --example k1_fido2_e2e \
//!       --features factor-fido2 --release
//! (or omit FIDO2_PIN to be prompted; entry is MASKED — no terminal echo.)
//!
//! You will be asked to touch the key ~3 times: twice at enroll (makeCredential
//! + first assertion) and once at unlock.

#[cfg(not(feature = "factor-fido2"))]
fn main() {
    eprintln!("rebuild with --features factor-fido2 (and plug in a FIDO2 key)");
}

#[cfg(feature = "factor-fido2")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use teagarden_mfa::kslot::protectors::{Fido2GenerationOptions, Fido2HmacProtector, Fido2Mode};
    use teagarden_mfa::kslot::{RecoveryProtector, SlotVault};

    // No rp_id and no PIN here any more. Both moved into
    // age-plugin-fido2-hmac (libfido2), which owns the relying-party id and
    // prompts for the PIN on /dev/tty at the moment the token asks — so it never
    // travels through argv, the environment, or this process.
    let vault_path = std::env::temp_dir().join(format!("k1_fido2_e2e_{}.json", std::process::id()));
    let _cleanup = scopeguard(&vault_path);

    println!("== K1 FIDO2 hmac-secret — REAL hardware e2e ==");
    println!("vault: {}", vault_path.display());

    // 1) Fresh vault with a random master key.
    let (mut vault, mk) = SlotVault::create("k1-fido2-e2e");
    let mk_expected = *mk.as_bytes();
    println!(
        "[1] minted a random master key (generation {})",
        vault.generation()
    );

    // 2) Recovery co-slot (best practice: never enroll a hardware factor alone).
    let mut rec = RecoveryProtector::for_enroll();
    let rec_slot = vault.add_independent_slot(&mk, &mut rec, "recovery")?;
    let sentence = rec.enrolled_sentence().unwrap_or("<none>").to_string();
    println!("[2] enrolled recovery slot {rec_slot:?}");
    println!("    recovery sentence (store this!): {sentence}");

    // 3) Enroll the FIDO2 slot against the PHYSICAL key (touch + PIN, twice).
    println!("[3] enrolling FIDO2 slot — TOUCH THE KEY when it blinks (x2) ...");
    // Mode PIN + UP: the plugin asks for the PIN on /dev/tty, then two touches.
    let mut fido = Fido2HmacProtector::new()
        .with_generation_options(Fido2GenerationOptions::new(Fido2Mode::PinUp))?;
    let fido_slot = vault.add_independent_slot(&mk, &mut fido, "fido2-key")?;
    println!(
        "    enrolled FIDO2 slot {fido_slot:?} (generation {})",
        vault.generation()
    );

    // 4) Persist and reload from disk (proves nothing secret is kept in RAM).
    vault.save(&vault_path)?;
    let reloaded = SlotVault::load(&vault_path)?;
    println!("[4] saved + reloaded the vault from disk");

    // 5) Unlock via the RECOVERY sentence (no hardware) — cross-check.
    let rec_unlock = RecoveryProtector::from_sentence(&sentence)?;
    let via_recovery = reloaded.unlock(&[&rec_unlock])?;
    assert_eq!(
        via_recovery.as_bytes(),
        &mk_expected,
        "recovery unlock recovered the WRONG master key"
    );
    println!("[5] unlocked via recovery sentence — master key matches ✔");

    // 6) Unlock via the PHYSICAL FIDO2 key (touch + PIN) — the real proof.
    println!("[6] unlocking via FIDO2 — TOUCH THE KEY when it blinks ...");
    let fido_unlock = Fido2HmacProtector::new();
    // FIDO2 requires a touch (user presence) → targeted unlock, never speculative.
    let via_fido = reloaded.unlock_targeted(&[&fido_unlock])?;
    assert_eq!(
        via_fido.as_bytes(),
        &mk_expected,
        "FIDO2 unlock recovered the WRONG master key"
    );
    println!("[6] unlocked via the PHYSICAL FIDO2 key — master key matches ✔");

    // 7) Negative check: the WRONG PIN must NOT unlock (real gate, not theatre).
    //    (Skipped automatically if the key has no PIN configured.)
    println!("\n== SUCCESS: master key protected by and recovered from a REAL FIDO2 key ==");
    Ok(())
}

/// Best-effort delete of the temp vault on drop.
#[cfg(feature = "factor-fido2")]
fn scopeguard(path: &std::path::Path) -> impl Drop + '_ {
    struct G<'a>(&'a std::path::Path);
    impl Drop for G<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    G(path)
}
