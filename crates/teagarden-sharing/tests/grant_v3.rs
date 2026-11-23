//! Grant format v3 (sharing-M1): the config travels without its verification
//! hash and integrity HMAC, the recipient recomputes them from the unwrapped
//! root.

use teagarden_core::volume::config::VolumeConfig;
use teagarden_core::volume::manager;
use teagarden_core::volume::shared::SharedDerivation;
use teagarden_sharing::access::AccessLevel;
use teagarden_sharing::grant::{SharedVolumeGrant, GRANT_VERSION, GRANT_VERSION_V2};
use teagarden_sharing::key_exchange::UserKeyPair;

/// Materialize `config` the way `share import` does and run the shared open.
fn import_and_open(config: &VolumeConfig, root: &[u8; 32]) {
    let dir = tempfile::TempDir::new().unwrap();
    let id = config.volume_id.to_string();
    std::fs::create_dir_all(dir.path().join(&id)).unwrap();
    manager::write_shared_config(config, &dir.path().join(&id).join("volume.json")).unwrap();
    manager::open_volume_shared(&id, root, SharedDerivation::HierarchyRootV1, dir.path())
        .expect("the recipient's materialized volume must pass the shared self-check");
}

fn owner_volumes(dir: &std::path::Path) -> Vec<manager::OpenVolumeResult> {
    let legacy = manager::create_volume(Some("legacy"), b"owner-pw", dir, 7, 0, 11, None)
        .map(|c| manager::OpenVolumeResult {
            config: c.config,
            paths: c.paths,
            hierarchy: c.hierarchy,
        })
        .unwrap();
    let pc = teagarden_mfa::unlock::create_protected_volume(
        Some("k0b"),
        b"owner-pass",
        dir,
        7,
        0,
        12,
        None,
    )
    .unwrap();
    let protected = teagarden_mfa::unlock::open_volume(
        &pc.created.config.volume_id.to_string(),
        &teagarden_mfa::unlock::UnlockInputs {
            password: Some(b"owner-pass"),
            ..Default::default()
        },
        dir,
    )
    .unwrap();
    vec![legacy, protected]
}

#[test]
fn v3_recipient_config_is_byte_identical_to_the_owners() {
    let dir = tempfile::TempDir::new().unwrap();
    for owner in owner_volumes(dir.path()) {
        let recipient = UserKeyPair::generate().unwrap();
        let grant = SharedVolumeGrant::seal(
            &owner.config,
            &owner.hierarchy.root,
            AccessLevel::ReadOnly,
            SharedDerivation::HierarchyRootV1,
            "alice",
            &recipient.encapsulation_key,
        )
        .unwrap();
        assert_eq!(grant.version, GRANT_VERSION);
        let grant = SharedVolumeGrant::from_bytes(&grant.to_bytes().unwrap()).unwrap();
        let root = grant.open_root(&recipient.decapsulation_key).unwrap();
        let config = grant.recipient_config(&root).unwrap();
        assert_eq!(
            serde_json::to_vec(&config).unwrap(),
            serde_json::to_vec(&owner.config).unwrap(),
            "recomputed anchors must reproduce the owner's config exactly"
        );
        import_and_open(&config, &root);
    }
}

#[test]
fn relabelling_the_version_breaks_the_unwrap() {
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
    grant.version = GRANT_VERSION_V2;
    assert!(
        grant.open_root(&recipient.decapsulation_key).is_err(),
        "a v3 grant relabelled v2 must not unwrap (version is bound in the AAD)"
    );
    grant.version = 99;
    assert!(grant.open_root(&recipient.decapsulation_key).is_err());
}

#[test]
fn a_v3_grant_carrying_anchors_is_refused() {
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
    let root = grant.open_root(&recipient.decapsulation_key).unwrap();
    grant.config.config_integrity = owner.config.config_integrity.clone();
    assert!(grant.recipient_config(&root).is_err());
}

#[test]
fn seal_refuses_a_root_that_does_not_authenticate_the_config() {
    let dir = tempfile::TempDir::new().unwrap();
    let a = manager::create_volume(Some("a"), b"pw", dir.path(), 1, 0, 2, None).unwrap();
    let b = manager::create_volume(Some("b"), b"pw", dir.path(), 1, 0, 3, None).unwrap();
    let recipient = UserKeyPair::generate().unwrap();
    let r = SharedVolumeGrant::seal(
        &a.config,
        &b.hierarchy.root,
        AccessLevel::ReadWrite,
        SharedDerivation::HierarchyRootV1,
        "alice",
        &recipient.encapsulation_key,
    );
    assert!(r.is_err(), "sealing another volume's root must be refused");
}
