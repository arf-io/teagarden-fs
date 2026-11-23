//! Old-format artifacts still open (brief hard rule).
//!
//! Everything under `tests/fixtures/base-55b5334/` was written by the code at
//! commit 55b5334 — the branch point, before any of the crypto / key-slot
//! hardening — by a throwaway generator run in a `git archive 55b5334` tree.
//! The volumes, passphrases and vault keys are test-only values; nothing here
//! protects real data.
//!
//! The parser touched since then — the passphrase-slot default (mfa-M5) —
//! must still accept these.
//! The artifacts whose contents are sealed under the key-derivation and MAC
//! labels (the old vaults, the protected volume's slots and recovery sentence)
//! are gone: those labels changed with the product rename and the artifacts
//! cannot be regenerated, so only the label-independent checks remain. The
//! legacy volume, whose password verification derives from the hierarchy
//! labels, went with the `teagarden.v1` hierarchy labels (round 13).

use std::path::{Path, PathBuf};

use teagarden_mfa::unlock::SLOT_VAULT_FILENAME;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base-55b5334")
}

fn read(name: &str) -> String {
    std::fs::read_to_string(fixtures().join(name)).unwrap()
}

/// Copy fixture volume `kind` (`protected`) into a fresh volumes dir.
fn volume(kind: &str) -> (tempfile::TempDir, String) {
    let id = read(&format!("{kind}.id")).trim().to_string();
    let dir = tempfile::TempDir::new().unwrap();
    let dst = dir.path().join(&id);
    std::fs::create_dir_all(&dst).unwrap();
    for entry in std::fs::read_dir(fixtures().join(kind).join(&id)).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
        }
    }
    (dir, id)
}

/// mfa-M5: the old passphrase slot really is at the old cost, and still opens.
#[test]
fn old_passphrase_slot_keeps_its_stored_cost() {
    let (dir, id) = volume("protected");
    let v: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join(&id).join(SLOT_VAULT_FILENAME)).unwrap(),
    )
    .unwrap();
    let slot = v["slots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["label"] == "passphrase")
        .unwrap();
    let cost = &slot["params"]["argon2"];
    assert_eq!(
        (
            cost["m_kib"].as_u64(),
            cost["t"].as_u64(),
            cost["p"].as_u64()
        ),
        (Some(65536), Some(2), Some(1)),
        "fixture: the pre-M5 slot was enrolled at 64 MiB / t=2 / p=1"
    );
}
