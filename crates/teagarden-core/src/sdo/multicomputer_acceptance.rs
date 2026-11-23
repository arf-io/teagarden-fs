use super::{
    reduce_records, DeviceAnnouncement, DeviceRegistry, HybridLogicalClock, SdoFileObjectV3,
    SdoKind, SdoObjectMetadataV3, SdoRecord, SDO_SEGMENT_SIZE,
};
use crate::crypto::keys::SymmetricKey;
use uuid::Uuid;

fn record(
    path: &str,
    kind: SdoKind,
    clock_ms: u64,
    clock_counter: u64,
    author: u8,
    version: u8,
) -> SdoRecord {
    SdoRecord {
        path: path.into(),
        kind,
        clock_ms,
        clock_counter,
        author_device_id: Uuid::from_bytes([author; 16]),
        version_id: Uuid::from_bytes([version; 16]),
        deleted: false,
        legacy: false,
        implicit: false,
    }
}

#[test]
fn reducer_is_order_independent_and_keeps_every_version() {
    let records = vec![
        record("note", SdoKind::File, 12, 1, 2, 4),
        record("note", SdoKind::File, 12, 1, 1, 3),
        record("note", SdoKind::File, 12, 1, 2, 4),
    ];
    let forward = reduce_records(records.clone()).unwrap();
    let reverse = reduce_records(records.into_iter().rev()).unwrap();
    assert_eq!(forward, reverse);
    assert_eq!(forward.history("note").len(), 2);
    assert_eq!(
        forward.winner("note").unwrap().version_id,
        Uuid::from_bytes([4; 16])
    );
}

#[test]
fn tombstones_and_ancestor_types_control_the_visible_tree() {
    let mut gone = record("gone", SdoKind::File, 2, 0, 1, 4);
    gone.deleted = true;
    let view = reduce_records(vec![
        record("empty", SdoKind::Directory, 1, 0, 1, 1),
        record("empty/child", SdoKind::File, 2, 0, 1, 2),
        record("gone", SdoKind::File, 1, 0, 1, 3),
        gone,
        record("collision", SdoKind::File, 1, 0, 1, 5),
        record("collision/hidden", SdoKind::File, 2, 0, 1, 6),
    ])
    .unwrap();
    assert!(view.is_visible("empty"));
    assert!(view.is_visible("empty/child"));
    assert!(!view.is_visible("gone"));
    assert!(!view.is_visible("collision/hidden"));
    assert_eq!(view.history("gone").len(), 2);
}

#[test]
fn local_hybrid_clock_handles_rollback_and_overflow() {
    let mut clock = HybridLogicalClock::new(100, 7);
    assert_eq!(clock.tick(90).unwrap(), (100, 8));
    assert_eq!(clock.tick(101).unwrap(), (101, 0));
    assert_eq!(clock.receive(99, 10, 101).unwrap(), (101, 1));
    assert!(HybridLogicalClock::new(u64::MAX, u64::MAX)
        .tick(u64::MAX)
        .is_err());
}

#[test]
fn format_three_round_trips_clock_generation_and_content() {
    let key = SymmetricKey::from_bytes([0x71; 32]);
    let metadata = SdoObjectMetadataV3 {
        authority: None,
        migration_receipt: None,
        file_id: Uuid::from_bytes([6; 16]),
        origin_message_id: None,
        path: Some("dir/hello.txt".into()),
        size: 5,
        mtime_ns: 8,
        mode: 0o600,
        version_id: Uuid::from_bytes([4; 16]),
        author_device_id: Uuid::from_bytes([5; 16]),
        previous_version_id: None,
        kind: SdoKind::File,
        key_generation: 3,
        clock_ms: 100,
        clock_counter: 2,
        saved_at_ns: 100_000_000,
        local_version: 1,
        deleted: false,
        installation_id: None,
        label: None,
        telegram_user_id: None,
        authorization_session_hash: None,
        created_at_ms: None,
        device_public_key: None,
        device_key_update: None,
        segment_size: SDO_SEGMENT_SIZE,
        segment_count: 1,
        content_sha256: hex::encode(crate::block::srb2::sha256(b"hello")),
    };
    let volume = Uuid::from_bytes([9; 16]);
    let wire = SdoFileObjectV3::encode(volume, 3, &key, metadata, b"hello").unwrap();
    let decoded = SdoFileObjectV3::decode(&wire, volume, 3, &key).unwrap();
    assert_eq!(decoded.content, b"hello");
    assert_eq!(decoded.metadata.clock_ms, 100);
    assert_eq!(decoded.metadata.key_generation, 3);
}

#[test]
fn device_registry_keeps_latest_per_installation_and_allows_duplicate_labels() {
    let first = DeviceAnnouncement {
        installation_id: Uuid::from_bytes([1; 16]),
        label: "laptop".into(),
        telegram_user_id: 50,
        authorization_session_hash: None,
        public_key: None,
        key_update: None,
        created_at_ms: 1,
        clock_ms: 1,
        clock_counter: 0,
        author_device_id: Uuid::from_bytes([1; 16]),
        version_id: Uuid::from_bytes([2; 16]),
    };
    let mut updated = first.clone();
    updated.clock_counter = 1;
    updated.version_id = Uuid::from_bytes([3; 16]);
    let other = DeviceAnnouncement {
        installation_id: Uuid::from_bytes([4; 16]),
        label: "laptop".into(),
        telegram_user_id: 50,
        authorization_session_hash: Some("private-hash".into()),
        public_key: None,
        key_update: None,
        created_at_ms: 2,
        clock_ms: 2,
        clock_counter: 0,
        author_device_id: Uuid::from_bytes([4; 16]),
        version_id: Uuid::from_bytes([5; 16]),
    };
    let registry = DeviceRegistry::from_announcements([first, other, updated]).unwrap();
    assert_eq!(registry.len(), 2);
    assert_eq!(
        registry.get(&Uuid::from_bytes([1; 16])).unwrap().label,
        "laptop"
    );
    assert_eq!(
        registry.get(&Uuid::from_bytes([1; 16])).unwrap().version_id,
        Uuid::from_bytes([3; 16])
    );
    assert_eq!(registry.resolve_label("laptop"), Err("ambiguous label"));
}

#[test]
fn legacy_versions_synthesize_missing_parents_but_explicit_records_override() {
    let mut legacy = record("old/sub/file", SdoKind::File, 500, 0, 1, 2);
    legacy.legacy = true;
    let defaults = reduce_records([legacy.clone()]).unwrap();
    assert!(defaults.is_visible("old"));
    assert!(defaults.is_visible("old/sub"));
    assert!(defaults.is_visible("old/sub/file"));

    let explicit = record("old", SdoKind::File, 0, 0, 2, 3);
    let blocked = reduce_records([legacy, explicit]).unwrap();
    assert!(!blocked.is_visible("old/sub/file"));
}

#[test]
fn header_v2_verifies_detached_signature_after_mac() {
    use super::HeaderDocument;
    use ed25519_dalek::SigningKey;
    let key = SymmetricKey::from_bytes([0x31; 32]);
    let signer = SigningKey::from_bytes(&[0x42; 32]);
    let mut header = HeaderDocument::test_fixture();
    header.format = 2;
    header.owner_public_key = Some(hex::encode(signer.verifying_key().to_bytes()));
    header.key_generation = Some(7);
    let wire = header.encode_v2(&key, &signer).unwrap();
    assert_eq!(HeaderDocument::decode(&wire, &key).unwrap(), header);
    let mut corrupt_signature = wire.clone();
    let sig_at = corrupt_signature.len() - 32 - 64;
    corrupt_signature[sig_at] ^= 1;
    assert!(HeaderDocument::decode(&corrupt_signature, &key).is_err());
}
