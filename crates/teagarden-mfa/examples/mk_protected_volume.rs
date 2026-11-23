//! Dev helper: create a **key-protected (MK-rooted) volume OFFLINE** so the K5 CLI
//! verbs (`teagarden mfa enroll` / `mfa unlock`) can be exercised end-to-end without
//! Telegram.
//!
//! The real `teagarden volume create --key-protection` provisions a Telegram forum
//! topic first, so it cannot run offline. A volume's *vault + config* are purely
//! local, though — only block **data** needs Telegram — so a volume created here is
//! byte-identical for every MFA purpose (enroll / unlock / anchor), just with no
//! storage backend behind it. Used by `scripts/test/mfa-tpm2-cli-e2e.sh`.
//!
//! Usage:
//!   TEAGARDEN_VOLUMES_DIR=/tmp/vols cargo run -p teagarden-mfa \
//!       --example mk_protected_volume -- <name> <passphrase>
//!
//! Prints `VOLUME_ID=<uuid>` and `RECOVERY=<22-word sentence>` for the caller to parse.

use teagarden_core::volume::manager;
use teagarden_mfa::unlock::create_protected_volume;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = args.next().unwrap_or_else(|| "k5-e2e".to_string());
    let passphrase = args
        .next()
        .unwrap_or_else(|| "correct-horse-battery-staple".to_string());

    let volumes_dir = manager::default_volumes_dir();
    std::fs::create_dir_all(&volumes_dir)?;

    // group/topic = 0 → offline (v0 semantics); MK-rooting + the vault are unaffected.
    let pc = create_protected_volume(
        Some(&name),
        passphrase.as_bytes(),
        &volumes_dir,
        0,
        0,
        0,
        None,
    )?;

    println!("VOLUME_ID={}", pc.created.config.volume_id);
    println!("RECOVERY={}", pc.recovery_sentence.as_str());
    eprintln!(
        "created offline key-protected volume {} in {}",
        pc.created.config.volume_id,
        volumes_dir.display()
    );
    Ok(())
}
