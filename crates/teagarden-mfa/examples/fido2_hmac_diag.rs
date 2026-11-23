//! Diagnostic: does this authenticator return a DIFFERENT hmac-secret depending
//! on whether user verification (PIN) was performed?
//!
//! CTAP2 authenticators keep two per-credential secrets — `CredRandomWithUV` and
//! `CredRandomWithoutUV` — and `hmac-secret` returns whichever matches the UV
//! state of *that* assertion. If enroll derives the KEK from one and unlock from
//! the other, enroll succeeds, unlock produces a different KEK, and the vault
//! reports "wrong factor value" — which is exactly the symptom under test.
//!
//! This performs the SAME assertion twice against the SAME stored credential and
//! salt: once WITH the PIN (UV) and once WITHOUT (presence only), and prints a
//! digest of each. It never prints the raw HMAC or the PIN.
//!
//! Usage:
//!   FIDO2_PIN=... FIDO2_CRED_ID=<hex> FIDO2_SALT=<hex> FIDO2_RP=teagarden.local \
//!     cargo run --release -p teagarden-mfa --features factor-fido2 --example fido2_hmac_diag
//!
//! Expect ~2 touches.

fn main() {
    #[cfg(not(feature = "factor-fido2"))]
    {
        eprintln!("build with --features factor-fido2");
        std::process::exit(2);
    }

    #[cfg(feature = "factor-fido2")]
    {
        use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as Gext;
        use ctap_hid_fido2::fidokey::GetAssertionArgsBuilder;
        use ctap_hid_fido2::{verifier, Cfg, FidoKeyHidFactory};

        let pin = std::env::var("FIDO2_PIN").unwrap_or_default();
        let rp_id = std::env::var("FIDO2_RP").unwrap_or_else(|_| "teagarden.local".into());
        let cred_hex = std::env::var("FIDO2_CRED_ID").expect("FIDO2_CRED_ID (hex) required");
        let salt = std::env::var("FIDO2_SALT").expect("FIDO2_SALT (hex string) required");
        let cred = hex::decode(cred_hex.trim()).expect("FIDO2_CRED_ID must be hex");

        // One assertion; `use_pin` selects the UV state.
        let run = |use_pin: bool| -> Option<[u8; 32]> {
            let device = match FidoKeyHidFactory::create(&Cfg::init()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("  open device failed: {e}");
                    return None;
                }
            };
            let challenge = verifier::create_challenge();
            let ext = Gext::create_hmac_secret_from_string(&salt);
            let mut b = GetAssertionArgsBuilder::new(&rp_id, &challenge)
                .credential_id(&cred)
                .extensions(&[ext]);
            if use_pin && !pin.is_empty() {
                b = b.pin(&pin);
            }
            match device.get_assertion_with_args(&b.build()) {
                Ok(assertions) => {
                    for a in assertions.iter() {
                        for e in &a.extensions {
                            if let Gext::HmacSecret(Some(bytes)) = e {
                                return Some(*bytes);
                            }
                        }
                    }
                    eprintln!("  no hmac-secret output returned");
                    None
                }
                Err(e) => {
                    eprintln!("  assertion failed: {e}");
                    None
                }
            }
        };

        // Digest only — never print raw key material.
        let digest = |h: &[u8; 32]| hex::encode(&blake3::hash(h).as_bytes()[..8]);

        println!("rp_id = {rp_id}");
        println!();
        println!("[1/2] assertion WITH PIN (user verification) — TOUCH THE KEY");
        let with_uv = run(true);
        match &with_uv {
            Some(h) => println!("      hmac digest (UV)    = {}", digest(h)),
            None => println!("      FAILED"),
        }

        println!();
        println!("[2/2] assertion WITHOUT PIN (presence only) — TOUCH THE KEY AGAIN");
        let without_uv = run(false);
        match &without_uv {
            Some(h) => println!("      hmac digest (no UV) = {}", digest(h)),
            None => println!("      FAILED"),
        }

        println!();
        println!("=== VERDICT ===");
        match (with_uv, without_uv) {
            (Some(a), Some(b)) if a == b => {
                println!("SAME hmac regardless of UV.");
                println!("=> UV state is NOT the cause. The enroll/unlock mismatch is elsewhere.");
            }
            (Some(_), Some(_)) => {
                println!("DIFFERENT hmac depending on UV state.");
                println!("=> CONFIRMED: this authenticator keys hmac-secret to the UV state.");
                println!("   The protector MUST use the same UV state at enroll and unlock,");
                println!("   and should record which it used in the slot params.");
            }
            _ => println!("inconclusive — at least one assertion failed (see above)."),
        }
    }
}
