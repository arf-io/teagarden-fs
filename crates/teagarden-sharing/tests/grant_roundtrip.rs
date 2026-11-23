//! The cryptographic heart of real sharing: an owner wraps the volume root for a
//! recipient, the recipient unwraps it and re-derives the identical key
//! hierarchy, and a block the owner encrypted decrypts byte-exact under the
//! recipient's derived keys. Fully offline — no Telegram, no mount.

use teagarden_core::crypto::{aead, kdf};
use teagarden_core::volume::manager;
use teagarden_core::volume::shared::SharedDerivation;
use teagarden_sharing::access::AccessLevel;
use teagarden_sharing::grant::SharedVolumeGrant;
use teagarden_sharing::key_exchange::UserKeyPair;

/// Prove the full handoff for BOTH a legacy password volume and a K0b MK-rooted
/// volume — the K0b case is where root != mk, so the legacy case alone would not
/// catch a regression that leaks the mk instead of the root.
#[test]
fn owner_wraps_root_recipient_derives_identical_hierarchy_and_decrypts() {
    for protected in [false, true] {
        let dir = tempfile::TempDir::new().unwrap();

        // --- Owner side: create a volume and its hierarchy. ---
        let owner = if protected {
            // A K0b MK-rooted volume, opened to obtain its real hierarchy.
            let created = teagarden_mfa::unlock::create_protected_volume(
                Some("shared-k0b"),
                b"owner-pass",
                dir.path(),
                7,
                0,
                11,
                None,
            )
            .expect("create protected volume");
            let vid = created.created.config.volume_id.to_string();
            let inputs = teagarden_mfa::unlock::UnlockInputs {
                password: Some(b"owner-pass"),
                ..Default::default()
            };
            teagarden_mfa::unlock::open_volume(&vid, &inputs, dir.path()).expect("open k0b")
        } else {
            manager::create_volume(
                Some("shared-legacy"),
                b"owner-pass",
                dir.path(),
                7,
                0,
                11,
                None,
            )
            .map(|c| manager::OpenVolumeResult {
                config: c.config,
                paths: c.paths,
                hierarchy: c.hierarchy,
            })
            .expect("create legacy volume")
        };

        // Owner encrypts a data block under the epoch data key.
        let plaintext = b"the owner's secret bytes";
        let epoch = owner.config.current_epoch;
        let ek = kdf::derive_epoch_key(&owner.hierarchy.data, epoch).unwrap();
        let aad = b"block-test-aad";
        let ciphertext = aead::encrypt(&ek.key, plaintext, aad).unwrap();

        // --- Recipient side: generate an identity, owner seals a grant to it. ---
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

        // Artifact survives serialization.
        let grant = SharedVolumeGrant::from_bytes(&grant.to_bytes().unwrap()).unwrap();

        // Recipient unwraps the root and re-derives the hierarchy.
        let root = grant.open_root(&recipient.decapsulation_key).unwrap();
        let derived = kdf::derive_hierarchy_v1(
            teagarden_core::crypto::keys::SymmetricKey::from_bytes(*root),
            &owner.config.salt,
            owner.config.telegram_group_id,
            owner.config.telegram_topic_id,
        )
        .unwrap();

        // The whole hierarchy matches — not just the data key.
        assert_eq!(
            derived.data.as_bytes(),
            owner.hierarchy.data.as_bytes(),
            "data key mismatch (protected={protected})"
        );
        assert_eq!(derived.meta.as_bytes(), owner.hierarchy.meta.as_bytes());
        assert_eq!(derived.schema.as_bytes(), owner.hierarchy.schema.as_bytes());
        assert_eq!(
            derived.integrity.as_bytes(),
            owner.hierarchy.integrity.as_bytes()
        );

        // And the recipient decrypts the owner's block byte-exact.
        let rek = kdf::derive_epoch_key(&derived.data, epoch).unwrap();
        let recovered = aead::decrypt(&rek.key, &ciphertext, aad).unwrap();
        assert_eq!(
            recovered, plaintext,
            "recipient could not decrypt (protected={protected})"
        );
    }
}

#[test]
fn wrong_recipient_key_cannot_open() {
    let dir = tempfile::TempDir::new().unwrap();
    let owner = manager::create_volume(Some("v"), b"pw", dir.path(), 1, 0, 2, None).unwrap();
    let intended = UserKeyPair::generate().unwrap();
    let attacker = UserKeyPair::generate().unwrap();
    let grant = SharedVolumeGrant::seal(
        &owner.config,
        &owner.hierarchy.root,
        AccessLevel::ReadWrite,
        SharedDerivation::HierarchyRootV1,
        "alice",
        &intended.encapsulation_key,
    )
    .unwrap();
    assert!(
        grant.open_root(&attacker.decapsulation_key).is_err(),
        "a different recipient key must not unwrap the root"
    );
}

#[test]
fn tampered_access_level_fails_the_aad_binding() {
    let dir = tempfile::TempDir::new().unwrap();
    let owner = manager::create_volume(Some("v"), b"pw", dir.path(), 1, 0, 2, None).unwrap();
    let recipient = UserKeyPair::generate().unwrap();
    let mut grant = SharedVolumeGrant::seal(
        &owner.config,
        &owner.hierarchy.root,
        AccessLevel::ReadOnly,
        SharedDerivation::HierarchyRootV1,
        "alice",
        &recipient.encapsulation_key,
    )
    .unwrap();
    // A relay tries to escalate read-only -> admin. The AAD no longer matches.
    grant.access_level = AccessLevel::Admin;
    assert!(
        grant.open_root(&recipient.decapsulation_key).is_err(),
        "tampering the access level must break the AEAD unwrap"
    );
}

#[test]
fn tampered_claimed_creator_fails_the_aad_binding() {
    let dir = tempfile::TempDir::new().unwrap();
    let owner = manager::create_volume(Some("v"), b"pw", dir.path(), 1, 0, 2, None).unwrap();
    let recipient = UserKeyPair::generate().unwrap();
    let mut grant = SharedVolumeGrant::seal(
        &owner.config,
        &owner.hierarchy.root,
        AccessLevel::ReadWrite,
        SharedDerivation::HierarchyRootV1,
        "alice",
        &recipient.encapsulation_key,
    )
    .unwrap();
    grant.granted_by = "mallory".into();
    assert!(
        grant.open_root(&recipient.decapsulation_key).is_err(),
        "tampering the claimed creator must break the AEAD unwrap"
    );
}

#[test]
fn tampered_config_fails_the_aad_binding_before_import() {
    let dir = tempfile::TempDir::new().unwrap();
    let owner = manager::create_volume(Some("v"), b"pw", dir.path(), 1, 0, 2, None).unwrap();
    let recipient = UserKeyPair::generate().unwrap();
    let mut grant = SharedVolumeGrant::seal(
        &owner.config,
        &owner.hierarchy.root,
        AccessLevel::ReadWrite,
        SharedDerivation::HierarchyRootV1,
        "alice",
        &recipient.encapsulation_key,
    )
    .unwrap();
    grant.config.display_name = "relay replacement".into();
    assert!(
        grant.open_root(&recipient.decapsulation_key).is_err(),
        "tampering any config field must break the AEAD unwrap"
    );
}
