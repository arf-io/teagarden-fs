use teagarden_core::crypto::kdf::{derive_hierarchy_from_master_key, derive_hierarchy_v1};
use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::sdo::{HeaderDocument, RootKind};
use teagarden_core::sentence::{encode::encode_ref_string, wordlists::production_wordlists};
use teagarden_mfa::kslot::{
    Argon2Cost, PassphraseProtector, RecoveryProtector, SlotProtector, SlotVault,
};
use uuid::Uuid;

#[test]
fn portable_vault_roundtrip_and_password_recovery_and_exported_root_authenticate_header() {
    let (mut vault, mk) = SlotVault::create("volume:sdo-fixture");
    let mut password = PassphraseProtector::new(
        b"portable password".to_vec(),
        Argon2Cost {
            m_kib: 1024,
            t: 1,
            p: 1,
        },
    );
    let mut recovery = RecoveryProtector::for_enroll();
    vault
        .add_independent_slot(&mk, &mut password, "password")
        .unwrap();
    vault
        .add_independent_slot(&mk, &mut recovery, "recovery")
        .unwrap();
    let sentence = recovery.enrolled_sentence().unwrap().to_owned();
    let bytes = vault.to_bytes().unwrap();
    let imported = SlotVault::from_bytes(&bytes).unwrap();

    let opened_password = imported.unlock(&[&password as &dyn SlotProtector]).unwrap();
    let wrong_password = PassphraseProtector::new(
        b"incorrect password".to_vec(),
        Argon2Cost {
            m_kib: 1024,
            t: 1,
            p: 1,
        },
    );
    assert!(imported
        .unlock(&[&wrong_password as &dyn SlotProtector])
        .is_err());
    let opened_recovery_protector = RecoveryProtector::from_sentence(&sentence).unwrap();
    let opened_recovery = imported
        .unlock(&[&opened_recovery_protector as &dyn SlotProtector])
        .unwrap();
    assert_eq!(opened_password.as_bytes(), opened_recovery.as_bytes());

    let salt = [0x31; 32];
    let group_id = -100123;
    let topic_id = 456;
    let hierarchy =
        derive_hierarchy_from_master_key(opened_password.as_bytes(), &salt, group_id, topic_id)
            .unwrap();
    let mut header = HeaderDocument::test_fixture();
    header.volume_id = Uuid::from_bytes([0x11; 16]);
    header.root_kind = RootKind::MasterKey;
    header.kdf_params = None;
    header.salt = hex::encode(salt);
    header.group_id = group_id;
    header.topic_id = topic_id;
    header.slot_vault = Some(serde_json::from_slice(&bytes).unwrap());
    let wire = header.encode(&hierarchy.integrity).unwrap();
    assert_eq!(
        HeaderDocument::decode(&wire, &hierarchy.integrity).unwrap(),
        header
    );

    let root_sentence =
        encode_ref_string(hierarchy.root.as_bytes(), &production_wordlists()).unwrap();
    let wordlists = production_wordlists();
    let lookups = wordlists
        .each_ref()
        .map(|w| teagarden_core::sentence::wordlists::build_reverse_lookup(w));
    let recovered_root =
        teagarden_core::sentence::decode::decode_ref_string(&root_sentence, &wordlists, &lookups)
            .unwrap();
    let root_hierarchy = derive_hierarchy_v1(
        SymmetricKey::from_bytes(recovered_root),
        &salt,
        group_id,
        topic_id,
    )
    .unwrap();
    assert!(HeaderDocument::decode(&wire, &root_hierarchy.integrity).is_ok());

    let mut tampered = bytes.clone();
    tampered[0] ^= 0x20;
    assert!(SlotVault::from_bytes(&tampered).is_err());

    let mut altered_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    altered_json["slots"][0]["payload_ct_b64"] = serde_json::json!("AA==");
    let altered_bytes = serde_json::to_vec(&altered_json).unwrap();
    let altered = SlotVault::from_bytes(&altered_bytes).unwrap();
    assert!(altered.unlock(&[&password as &dyn SlotProtector]).is_err());
}
