//! sharing-M1: a grant artifact travels over channels the owner does not
//! control (chat, mail, a USB stick). For a password-rooted volume its plaintext
//! config must not let a holder of the FILE (not just the intended recipient)
//! confirm password guesses offline.
//!
//! Both `password_verification_hash` and `config_integrity` are keyed by the
//! password-derived hierarchy, so EITHER one is such an oracle (pinned in core:
//! `config_integrity_alone_is_a_password_oracle`). New grants carry neither.

use teagarden_core::crypto::kdf;
use teagarden_core::volume::manager;
use teagarden_core::volume::shared::SharedDerivation;
use teagarden_sharing::access::AccessLevel;
use teagarden_sharing::grant::SharedVolumeGrant;
use teagarden_sharing::key_exchange::UserKeyPair;

#[test]
fn a_new_grant_carries_no_password_oracle() {
    let dir = tempfile::TempDir::new().unwrap();
    let owner =
        manager::create_volume(Some("v"), b"hunter2-reused", dir.path(), 1, 0, 2, None).unwrap();
    let recipient = UserKeyPair::generate().unwrap();
    let grant = SharedVolumeGrant::seal(
        &owner.config,
        &owner.hierarchy.root,
        AccessLevel::ReadWrite,
        SharedDerivation::HierarchyRootV1,
        "alice",
        &recipient.encapsulation_key,
    )
    .unwrap();

    // What anyone holding the artifact can read:
    let shipped = SharedVolumeGrant::from_bytes(&grant.to_bytes().unwrap()).unwrap();
    assert!(
        shipped.config.password_verification_hash.is_none(),
        "the grant ships the password verification hash (an offline guessing oracle)"
    );
    assert!(
        shipped.config.config_integrity.is_none(),
        "the grant ships config_integrity, which confirms a password guess just as well"
    );

    // And concretely: the right password cannot be confirmed from the file.
    let c = &shipped.config;
    let root = kdf::derive_root_key(b"hunter2-reused", &c.salt, &c.kdf_params).unwrap();
    let h =
        kdf::derive_hierarchy_v1(root, &c.salt, c.telegram_group_id, c.telegram_topic_id).unwrap();
    assert!(
        manager::verify_config_anchors(c, &h).is_err(),
        "the shipped config confirmed the correct password"
    );
}
