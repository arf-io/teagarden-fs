use teagarden_core::crypto::blake3::keyed_hash;
use teagarden_core::crypto::kdf::{derive_hierarchy, derive_hierarchy_v1, derive_root_key};
use teagarden_core::crypto::keys::{Argon2Params, SymmetricKey};
use teagarden_core::sdo::{HeaderDocument, SdoFileObject, SdoManifest, SdoObjectMetadata};
use uuid::Uuid;

fn hierarchy() -> teagarden_core::crypto::keys::KeyHierarchy {
    let root = derive_root_key(
        b"portable-test-password",
        &[1; 32],
        &Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        },
    )
    .unwrap();
    derive_hierarchy(root, &[1; 32]).unwrap()
}

#[test]
fn header_authenticates_exact_wire_bytes_and_rejects_changes() {
    let h = hierarchy();
    let document = HeaderDocument::test_fixture();
    let encoded = document.encode(&h.integrity).unwrap();
    assert_eq!(&encoded[..4], b"TGHD");
    assert_eq!(
        HeaderDocument::decode(&encoded, &h.integrity).unwrap(),
        document
    );

    let mut changed = encoded.clone();
    let json_byte = 10;
    changed[json_byte] ^= 1;
    assert!(HeaderDocument::decode(&changed, &h.integrity).is_err());
}

#[test]
fn header_rejects_trailing_bytes_unknown_fields_and_hostile_kdf_costs() {
    let h = hierarchy();
    let encoded = HeaderDocument::test_fixture().encode(&h.integrity).unwrap();
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(HeaderDocument::decode(&trailing, &h.integrity).is_err());
    let mut wrong_length = encoded.clone();
    wrong_length[6] ^= 1;
    assert!(HeaderDocument::decode(&wrong_length, &h.integrity).is_err());

    let mut invalid = HeaderDocument::test_fixture();
    invalid.kdf_params = Some(Argon2Params {
        memory_kib: u32::MAX,
        iterations: 1,
        parallelism: 1,
        output_len: 32,
    });
    assert!(invalid.encode(&h.integrity).is_err());
}

#[test]
fn header_rejects_duplicate_json_keys_and_wrong_channel_binding() {
    let h = hierarchy();
    let document = HeaderDocument::test_fixture();
    let encoded = document.encode(&h.integrity).unwrap();
    let json_len = u32::from_le_bytes(encoded[6..10].try_into().unwrap()) as usize;
    let json = std::str::from_utf8(&encoded[10..10 + json_len]).unwrap();
    let duplicate = json.replacen("{", "{\"format\":1,", 1);
    let mut wire = b"TGHD\x01\x00".to_vec();
    wire.extend_from_slice(&(duplicate.len() as u32).to_le_bytes());
    wire.extend_from_slice(duplicate.as_bytes());
    let mut mac_input = b"teagarden.sdo.header.v1".to_vec();
    mac_input.extend_from_slice(&wire);
    wire.extend_from_slice(&keyed_hash(&h.integrity, &mac_input));
    assert!(HeaderDocument::decode(&wire, &h.integrity).is_err());

    let wrong_channel = derive_hierarchy_v1(
        h.root.clone(),
        &[1; 32],
        document.group_id + 1,
        document.topic_id,
    )
    .unwrap();
    assert!(HeaderDocument::decode(&encoded, &wrong_channel.integrity).is_err());
}

#[test]
fn manifest_is_bound_to_volume_and_authenticates_aad() {
    let h = hierarchy();
    let volume_id = Uuid::from_bytes([7; 16]);
    let manifest = SdoManifest::test_fixture();
    let encoded = manifest.encode(volume_id, &h.meta).unwrap();
    assert_eq!(&encoded[..4], b"TGFV");
    assert_eq!(
        SdoManifest::decode(&encoded, volume_id, &h.meta).unwrap(),
        manifest
    );
    assert!(SdoManifest::decode(&encoded, Uuid::from_bytes([8; 16]), &h.meta).is_err());

    let other_key = SymmetricKey::from_bytes([0x99; 32]);
    assert!(SdoManifest::decode(&encoded, volume_id, &other_key).is_err());
}

#[test]
fn revisions_keep_file_identity_and_link_back_to_the_first_message() {
    let h = hierarchy();
    let volume_id = Uuid::from_bytes([7; 16]);
    let file_id = Uuid::from_bytes([6; 16]);
    let first = SdoManifest::test_fixture();
    assert_eq!(first.file_id, file_id);
    assert_eq!(first.origin_message_id, None);
    let first_wire = first.encode(volume_id, &h.meta).unwrap();
    let first_roundtrip = SdoManifest::decode(&first_wire, volume_id, &h.meta).unwrap();
    let first_message_id = 41;

    let mut revision = first_roundtrip.clone();
    revision.file_id = file_id;
    revision.origin_message_id = Some(first_message_id);
    revision.version_id = Uuid::from_bytes([0x44; 16]);
    revision.previous_version_id = Some(first.version_id);
    revision.local_version = 2;
    revision.saved_at_ns += 1;
    let revision_wire = revision.encode(volume_id, &h.meta).unwrap();
    let decoded = SdoManifest::decode(&revision_wire, volume_id, &h.meta).unwrap();

    assert_eq!(decoded.file_id, first.file_id);
    assert_eq!(decoded.origin_message_id, Some(first_message_id));
    assert_eq!(decoded.previous_version_id, Some(first.version_id));
}

#[test]
fn format_two_is_one_segmented_object_with_authenticated_ranges() {
    let h = hierarchy();
    let volume_id = Uuid::from_bytes([7; 16]);
    let mut metadata = SdoObjectMetadata::test_fixture();
    metadata.size = 2 * 1024 * 1024 + 37;
    metadata.content_sha256 = hex::encode(teagarden_core::block::srb2::sha256(&vec![
        0x5a;
        metadata.size
            as usize
    ]));
    metadata.segment_count = 3;
    let plaintext = vec![0x5a; metadata.size as usize];

    let wire = SdoFileObject::encode(volume_id, &h.meta, metadata.clone(), &plaintext).unwrap();
    assert_eq!(&wire[..4], b"TGFV");
    assert_eq!(u16::from_le_bytes([wire[4], wire[5]]), 2);
    let object = SdoFileObject::decode(&wire, volume_id, &h.meta).unwrap();
    assert_eq!(object.metadata, metadata);
    assert_eq!(object.content, plaintext);

    let header_len = u32::from_le_bytes(wire[22..26].try_into().unwrap()) as usize;
    let header_end = 26 + header_len;
    let header = SdoFileObject::decode_header(&wire[..header_end], volume_id, &h.meta).unwrap();
    let middle = header.segment_offset(1).unwrap() as usize;
    let middle_len = header.encrypted_segment_len(1).unwrap() as usize;
    let segment =
        SdoFileObject::decrypt_segment(&header, &h.meta, 1, &wire[middle..middle + middle_len])
            .unwrap();
    assert_eq!(segment, vec![0x5a; 1024 * 1024]);

    let mut tampered = wire.clone();
    tampered[middle + 10] ^= 1;
    assert!(SdoFileObject::decode(&tampered, volume_id, &h.meta).is_err());

    let mut reordered = wire.clone();
    let first = header.segment_offset(0).unwrap() as usize;
    let first_len = header.encrypted_segment_len(0).unwrap() as usize;
    let second_len = header.encrypted_segment_len(1).unwrap() as usize;
    let first_segment = reordered[first..first + first_len].to_vec();
    let second_segment = reordered[middle..middle + second_len].to_vec();
    reordered[first..first + first_len].copy_from_slice(&second_segment);
    reordered[middle..middle + second_len].copy_from_slice(&first_segment);
    assert!(SdoFileObject::decode(&reordered, volume_id, &h.meta).is_err());

    let truncated = wire[..wire.len() - 1].to_vec();
    assert!(SdoFileObject::decode(&truncated, volume_id, &h.meta).is_err());
}

#[test]
fn meta_hierarchy_matches_published_known_answer_test() {
    let root = SymmetricKey::from_bytes([0x42; 32]);
    let h = derive_hierarchy(root, &[1; 32]).unwrap();
    assert_eq!(
        hex::encode(h.meta.as_bytes()),
        "dd6df5ae57f5ee71aecb91d6006b136f3342c451a88878e8b299ea98a917e263"
    );
}
