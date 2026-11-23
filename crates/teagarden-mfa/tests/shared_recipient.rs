//! The recipient side of real sharing, end-to-end through the mfa open router:
//! materialize a shared volume from a grant's root (config + local vault +
//! shared_origin marker), then open it with the recipient's OWN passphrase and
//! get back the owner's identical hierarchy — no owner password anywhere.

use teagarden_core::volume::manager;
use teagarden_core::volume::shared::{SharedDerivation, SharedOrigin};
use teagarden_mfa::unlock::{self, UnlockInputs};

/// Simulate `share accept` locally: given the owner's config + hierarchy root,
/// write the recipient's volume dir and return its id.
fn materialize_recipient(
    owner_config: &teagarden_core::volume::config::VolumeConfig,
    root: &[u8; 32],
    recipient_dir: &std::path::Path,
    recipient_pass: &[u8],
    access_level: &str,
) -> String {
    let vol_id = owner_config.volume_id.to_string();
    let base_dir = recipient_dir.join(&vol_id);
    std::fs::create_dir_all(&base_dir).unwrap();

    // Owner's config, byte-verbatim (so its integrity anchor still verifies).
    manager::write_shared_config(owner_config, &base_dir.join("volume.json")).unwrap();

    // Recipient's own factor vault around the foreign root.
    unlock::setup_shared_recipient(&base_dir, root, recipient_pass).unwrap();

    // The marker that routes open down the shared path.
    SharedOrigin {
        derivation: SharedDerivation::HierarchyRootV1,
        access_level: access_level.into(),
        granted_by: "owner".into(),
        volume_id: vol_id.clone(),
    }
    .save(&base_dir)
    .unwrap();

    vol_id
}

/// Both volume types: the recipient opens with THEIR passphrase and derives the
/// owner's exact hierarchy. The K0b case is the important one — its config
/// carries a `key_protection` anchor, and the router must still take the shared
/// path (not the vault-MK path, which would derive different keys).
#[test]
fn recipient_opens_shared_volume_with_own_passphrase() {
    for protected in [false, true] {
        let owner_dir = tempfile::TempDir::new().unwrap();
        let recipient_dir = tempfile::TempDir::new().unwrap();

        let owner = if protected {
            let created = unlock::create_protected_volume(
                Some("v"),
                b"owner-pass",
                owner_dir.path(),
                3,
                0,
                9,
                None,
            )
            .unwrap();
            let vid = created.created.config.volume_id.to_string();
            let inputs = UnlockInputs {
                password: Some(b"owner-pass"),
                ..Default::default()
            };
            unlock::open_volume(&vid, &inputs, owner_dir.path()).unwrap()
        } else {
            let c =
                manager::create_volume(Some("v"), b"owner-pass", owner_dir.path(), 3, 0, 9, None)
                    .unwrap();
            manager::OpenVolumeResult {
                config: c.config,
                paths: c.paths,
                hierarchy: c.hierarchy,
            }
        };
        let root = *owner.hierarchy.root.as_bytes();

        let vol_id = materialize_recipient(
            &owner.config,
            &root,
            recipient_dir.path(),
            b"recipient-pass",
            "read-write",
        );

        // The owner's password must NOT open the recipient copy...
        let owner_pw = UnlockInputs {
            password: Some(b"owner-pass"),
            ..Default::default()
        };
        assert!(
            unlock::open_volume(&vol_id, &owner_pw, recipient_dir.path()).is_err(),
            "the recipient's local vault is gated by the recipient's OWN passphrase"
        );

        // ...the recipient's own passphrase does, yielding the owner's hierarchy.
        let recipient_pw = UnlockInputs {
            password: Some(b"recipient-pass"),
            ..Default::default()
        };
        let opened = unlock::open_volume(&vol_id, &recipient_pw, recipient_dir.path()).unwrap();
        assert_eq!(
            opened.hierarchy.data.as_bytes(),
            owner.hierarchy.data.as_bytes(),
            "recipient must derive the owner's data key (protected={protected})"
        );
        assert_eq!(
            opened.hierarchy.integrity.as_bytes(),
            owner.hierarchy.integrity.as_bytes()
        );
    }
}

/// A shared volume refuses `mfa enroll` — its config anchors the owner's vault.
#[test]
fn enroll_factor_refuses_a_shared_volume() {
    let owner_dir = tempfile::TempDir::new().unwrap();
    let recipient_dir = tempfile::TempDir::new().unwrap();
    let created =
        unlock::create_protected_volume(Some("v"), b"owner-pass", owner_dir.path(), 1, 0, 2, None)
            .unwrap();
    let vid = created.created.config.volume_id.to_string();
    let owner = unlock::open_volume(
        &vid,
        &UnlockInputs {
            password: Some(b"owner-pass"),
            ..Default::default()
        },
        owner_dir.path(),
    )
    .unwrap();
    let root = *owner.hierarchy.root.as_bytes();
    let vol_id = materialize_recipient(
        &owner.config,
        &root,
        recipient_dir.path(),
        b"recipient-pass",
        "read-write",
    );

    let err = unlock::enroll_factor(
        &vol_id,
        &UnlockInputs {
            password: Some(b"recipient-pass"),
            ..Default::default()
        },
        teagarden_mfa::unlock::EnrollFactor::Tpm2 { pcrs: None },
        recipient_dir.path(),
    );
    assert!(err.is_err(), "mfa enroll must refuse a shared volume");
}
