//! Offline decryption for downloaded TGFV v2 file objects.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use teagarden_core::crypto::kdf::{
    derive_hierarchy_from_master_key, derive_hierarchy_v1, derive_root_key,
};
use teagarden_core::crypto::keys::{KeyHierarchy, SymmetricKey};
use teagarden_core::sdo::{
    reduce_records, HeaderDocument, RootKind, SdoFileObject, SdoFileObjectV3, SdoKind, SdoRecord,
};
use teagarden_mfa::kslot::protector::SlotProtector;
use teagarden_mfa::kslot::protectors::{Argon2Cost, PassphraseProtector, RecoveryProtector};
use teagarden_mfa::kslot::vault::SlotVault;
use uuid::Uuid;

#[derive(Clone)]
struct DecodedVersion {
    metadata: teagarden_core::sdo::SdoObjectMetadata,
    content: Vec<u8>,
    record: SdoRecord,
    kind: SdoKind,
    unverified: bool,
}

/// Decrypt one downloaded object or all TGFV objects in a directory.
pub fn run(
    input: &Path,
    output: Option<&Path>,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    only_file_id: Option<Uuid>,
    owner_public_key: Option<&str>,
    include_unverified: bool,
) -> Result<()> {
    if password_file.is_some() && recovery_file.is_some() {
        bail!("choose only one of --password-file and --recovery-file");
    }
    let is_recovery = recovery_file.is_some();
    let credential = if is_recovery {
        super::utils::read_recovery_sentence(recovery_file)?
            .context("a recovery file is required with --recovery-file")?
    } else {
        super::utils::read_password_input(password_file)?
    };
    let input_meta =
        fs::symlink_metadata(input).with_context(|| format!("inspect {}", input.display()))?;
    if input_meta.file_type().is_symlink() {
        bail!("input must not be a symbolic link");
    }
    let (directory, requested_objects) = if input_meta.is_dir() {
        let mut objects = Vec::new();
        for entry in fs::read_dir(input).with_context(|| format!("read {}", input.display()))? {
            let entry = entry?;
            let meta = entry.file_type()?;
            if meta.is_symlink() || !meta.is_file() {
                continue;
            }
            let path = entry.path();
            if has_magic(&path, b"TGFV")? {
                objects.push(path);
            }
        }
        (input.to_path_buf(), objects)
    } else if input_meta.is_file() {
        if !has_magic(input, b"TGFV")? {
            bail!("input is not a TGFV v2 file object");
        }
        (
            input
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            vec![input.to_path_buf()],
        )
    } else {
        bail!("input must be a regular TGFV object or a directory");
    };
    if requested_objects.is_empty() {
        bail!("no TGFV objects found in {}", directory.display());
    }

    let mut local_header = if input_meta.is_dir() {
        Some(
            open_local_header(
                &directory,
                credential.as_bytes(),
                is_recovery,
                owner_public_key,
            )
            .context(
                "current-state directory restore requires its authenticated current TGHD policy",
            )?,
        )
    } else {
        eprintln!("Forensic single-object recovery: recovering authenticated historical bytes; current revocation and namespace policy is not asserted.");
        None
    };
    let provenance = if input_meta.is_dir() {
        let (header, hierarchy) = local_header.as_ref().unwrap();
        header.require_complete_revocation_cutoffs()?;
        read_export_provenance(&directory, header, &hierarchy.integrity)?
    } else {
        None
    };
    if let Some(bundle) = &provenance {
        let mut missing = Vec::new();
        for name in bundle.payload["objects"].as_object().unwrap().keys() {
            let relative = Path::new(name);
            if relative.components().count() != 1 || validate_relative_path(relative).is_err() {
                missing.push(format!("{name}: invalid exported object name"));
                continue;
            }
            let path = directory.join(relative);
            if !requested_objects.contains(&path) {
                missing.push(format!("{name}: missing, non-regular, or unrecognized TGFV object listed in export provenance"));
            }
        }
        if !missing.is_empty() {
            bail!("directory restore refused: {} object(s) from the export inventory are missing or invalid; no files written. {}. --include-unverified cannot recover absent or unrecognized ciphertext.", missing.len(), missing.join("; "));
        }
    }
    anyhow::ensure!(!include_unverified || input_meta.is_dir(),
        "--include-unverified requires directory input; a single object already uses forensic recovery");
    let mut versions = Vec::with_capacity(requested_objects.len());
    let mut refused = Vec::new();
    for object_path in requested_objects {
        if fs::metadata(&object_path)?.len()
            > teagarden_core::sdo::MAX_SDO_FILE_BYTES_PREMIUM + 16 * 1024 * 1024
        {
            bail!(
                "TGFV object {} exceeds the supported size limit",
                object_path.display()
            );
        }
        let wire =
            fs::read(&object_path).with_context(|| format!("read {}", object_path.display()))?;
        let generation = if wire.get(4..6) == Some(&[3, 0]) && wire.len() >= 30 {
            u64::from_le_bytes(wire[22..30].try_into().unwrap())
        } else {
            0
        };
        let envelope_keys = (|| -> Result<Option<(Uuid, SymmetricKey)>> {
            let Some(envelope) = teagarden_core::sdo::ObjectEnvelope::parse(&wire)? else {
                return Ok(None);
            };
            let candidate = parse_header_json(&envelope.header_wire)?;
            let hierarchy =
                derive_header_hierarchy(&candidate, credential.as_bytes(), is_recovery)?;
            let header = HeaderDocument::decode_pinned(
                &envelope.header_wire,
                &hierarchy.integrity,
                owner_public_key,
            )
            .context("authenticate embedded TGHD credential bootstrap")?;
            let key = envelope
                .open(&wire, &hierarchy.root, is_recovery)
                .context("authenticate standalone object credential envelope")?;
            Ok(Some((header.volume_id, key)))
        })();
        let (volume_id, meta_key) = match envelope_keys {
            Ok(Some(keys)) => keys,
            envelope_result => {
                if local_header.is_none() {
                    local_header = match open_local_header(
                        &directory,
                        credential.as_bytes(),
                        is_recovery,
                        owner_public_key,
                    ) {
                        Ok(header) => Some(header),
                        Err(error) => {
                            return Err(envelope_result.err().unwrap_or(error)).with_context(|| {
                                format!("unlock file object {}", object_path.display())
                            })
                        }
                    };
                }
                let (header, hierarchy) = local_header.as_ref().unwrap();
                let keys = super::volume::generation_meta_keys(header, hierarchy)?;
                let key = keys.get(&generation).with_context(|| {
                    format!("no authenticated key for object generation {generation}")
                })?;
                (header.volume_id, key.clone())
            }
        };
        if let Some((header, _)) = local_header.as_ref().filter(|_| input_meta.is_dir()) {
            if header.volume_id != volume_id {
                bail!("directory object belongs to another volume");
            }
        }
        let authority_metadata;
        let (metadata, content, record, kind) = match wire.get(4..6) {
            Some([2, 0]) => {
                let object =
                    SdoFileObject::decode(&wire, volume_id, &meta_key).with_context(|| {
                        format!("authenticate file object {}", object_path.display())
                    })?;
                authority_metadata = teagarden_core::sdo::legacy_metadata_v3(&object.metadata);
                let record = teagarden_core::sdo::legacy_object_record(&object.metadata);
                (object.metadata, object.content, record, SdoKind::File)
            }
            Some([3, 0]) => {
                if wire.len() < 30 {
                    bail!("truncated TGFV v3 prefix");
                }
                let generation = u64::from_le_bytes(wire[22..30].try_into().unwrap());
                let object = SdoFileObjectV3::decode(&wire, volume_id, generation, &meta_key)
                    .with_context(|| {
                        format!("authenticate file object {}", object_path.display())
                    })?;
                authority_metadata = object.metadata.clone();
                let m = object.metadata;
                let path = m.path.clone().unwrap_or_default();
                let legacy_shape = teagarden_core::sdo::SdoObjectMetadata {
                    file_id: m.file_id,
                    origin_message_id: m.origin_message_id,
                    path: path.clone(),
                    size: m.size,
                    mtime_ns: m.mtime_ns,
                    mode: m.mode,
                    version_id: m.version_id,
                    author_device_id: m.author_device_id,
                    previous_version_id: m.previous_version_id,
                    saved_at_ns: m.saved_at_ns,
                    local_version: m.local_version,
                    deleted: m.deleted,
                    segment_size: m.segment_size,
                    segment_count: m.segment_count,
                    content_sha256: m.content_sha256,
                };
                let record = SdoRecord {
                    path,
                    kind: m.kind,
                    clock_ms: m.clock_ms,
                    clock_counter: m.clock_counter,
                    author_device_id: m.author_device_id,
                    version_id: m.version_id,
                    deleted: m.deleted,
                    legacy: false,
                    implicit: false,
                };
                (legacy_shape, object.content, record, m.kind)
            }
            _ => bail!(
                "unsupported TGFV object format in {}",
                object_path.display()
            ),
        };
        let mut unverified = false;
        if input_meta.is_dir() {
            let (policy, _) = local_header.as_ref().unwrap();
            if !teagarden_core::sdo::object_authority_is_acceptable(policy, &authority_metadata) {
                refused.push(format!(
                    "{}: rejected by frozen installation signing-key policy",
                    object_path.display()
                ));
                continue;
            }
            let message_id = export_source_message_id(provenance.as_ref(), &object_path, &wire)?;
            if !teagarden_core::sdo::object_transition_is_acceptable(
                policy,
                &authority_metadata,
                message_id,
            ) {
                if message_id == i64::MAX {
                    let reason = format!("{}: missing owner provenance for its source position; current authority cannot be verified", object_path.display());
                    if !include_unverified {
                        refused.push(reason);
                        continue;
                    }
                    eprintln!("UNVERIFIED object included by --include-unverified: {reason}");
                    unverified = true;
                } else {
                    refused.push(format!("{}: rejected by current authority/transition policy at authenticated source message {message_id}", object_path.display()));
                    continue;
                }
            }
        }
        if only_file_id.is_none_or(|id| id == metadata.file_id) {
            versions.push(DecodedVersion {
                metadata,
                content,
                record,
                kind,
                unverified,
            });
        }
    }
    if !refused.is_empty() {
        bail!("directory restore refused: {} object(s) cannot be included safely; no files written. {}. Use --include-unverified to recover objects with missing owner provenance, labelled UNVERIFIED; it does not override a proven policy rejection.", refused.len(), refused.join("; "));
    }
    if let Some(id) = only_file_id {
        if versions.is_empty() {
            bail!("no versions found for file_id {id}");
        }
    }
    versions.sort_by(|a, b| {
        a.metadata
            .file_id
            .cmp(&b.metadata.file_id)
            .then(a.metadata.local_version.cmp(&b.metadata.local_version))
            .then(a.metadata.saved_at_ns.cmp(&b.metadata.saved_at_ns))
            .then(
                a.metadata
                    .version_id
                    .as_bytes()
                    .cmp(b.metadata.version_id.as_bytes()),
            )
    });
    for version in &versions {
        println!(
            "file_id={} version={} version_id={} previous={} origin_message_id={} path={}{}{}",
            version.metadata.file_id,
            version.metadata.local_version,
            version.metadata.version_id,
            version
                .metadata
                .previous_version_id
                .map_or_else(|| "-".into(), |id| id.to_string()),
            version
                .metadata
                .origin_message_id
                .map_or_else(|| "-".into(), |id| id.to_string()),
            version.metadata.path,
            if version.unverified {
                " [UNVERIFIED: missing owner provenance]"
            } else {
                ""
            },
            if version.metadata.deleted {
                " [deleted]"
            } else {
                ""
            },
        );
    }
    if only_file_id.is_some() && input_meta.is_dir() {
        return Ok(());
    }

    // A directory may contain every historical version. Resolve the newest record
    // independently for each path so a rename tombstone only hides the old path.
    let view = reduce_records(versions.iter().map(|version| version.record.clone()))
        .context("reduce decrypted file versions")?;
    let selected: Vec<_> = if input_meta.is_file() {
        let version = versions
            .first()
            .context("requested object did not match the selected file id")?;
        if version.kind != SdoKind::File || version.metadata.deleted {
            bail!("requested object is a directory, registry record, or deletion tombstone; it has no recoverable file content");
        }
        vec![version]
    } else {
        versions
            .iter()
            .filter(|version| {
                matches!(version.kind, SdoKind::File | SdoKind::Directory)
                    && view.is_visible(&version.record.path)
                    && view
                        .winner(&version.record.path)
                        .is_some_and(|winner| winner.version_id == version.record.version_id)
            })
            .collect()
    };
    let out_dir = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| directory.join("decrypted"));
    write_files(&out_dir, &selected)?;
    let unverified_count = versions.iter().filter(|version| version.unverified).count();
    if unverified_count > 0 {
        eprintln!("UNVERIFIED recovery: included {unverified_count} object(s) without verified owner provenance; current namespace authority is not asserted for those objects.");
    }
    println!(
        "decrypted {} file(s) and {} explicit directory(s) to {}",
        selected
            .iter()
            .filter(|version| version.kind == SdoKind::File)
            .count(),
        selected
            .iter()
            .filter(|version| version.kind == SdoKind::Directory)
            .count(),
        out_dir.display()
    );
    Ok(())
}

fn has_magic(path: &Path, magic: &[u8; 4]) -> Result<bool> {
    let mut file = fs::File::open(path)?;
    let mut prefix = [0; 4];
    use std::io::Read;
    match file.read_exact(&mut prefix) {
        Ok(()) => Ok(&prefix == magic),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn provenance_bytes(payload: &serde_json::Value) -> Result<Vec<u8>> {
    let mut bytes = b"teagarden.export-provenance.v1".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(payload)?);
    Ok(bytes)
}

pub(super) fn write_export_provenance(
    directory: &Path,
    payload: serde_json::Value,
    key: &SymmetricKey,
    owner: Option<&ed25519_dalek::SigningKey>,
) -> Result<()> {
    let mac = blake3::keyed_hash(key.as_bytes(), &provenance_bytes(&payload)?);
    use ed25519_dalek::Signer;
    let mut source_authority = b"teagarden.export-source-authority.v1".to_vec();
    source_authority.extend_from_slice(&serde_json::to_vec(&payload)?);
    let owner_signature = owner.map(|owner| hex::encode(owner.sign(&source_authority).to_bytes()));
    let wire = serde_json::to_vec(&serde_json::json!({
        "payload": payload, "mac": mac.to_hex().to_string(), "owner_signature": owner_signature,
    }))?;
    teagarden_core::fsutil::write_file_atomic(
        &directory.join("export-provenance.json"),
        &wire,
        "authenticated export provenance",
    )?;
    Ok(())
}

struct ExportProvenance {
    payload: serde_json::Value,
    owner_authorized: bool,
}

fn read_export_provenance(
    directory: &Path,
    header: &HeaderDocument,
    key: &SymmetricKey,
) -> Result<Option<ExportProvenance>> {
    let path = directory.join("export-provenance.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.len() > 16 * 1024 * 1024 {
        bail!("invalid export provenance file");
    }
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    let payload = &value["payload"];
    let mac: [u8; 32] = hex::decode(
        value["mac"]
            .as_str()
            .context("missing export provenance authentication")?,
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("invalid export provenance MAC"))?;
    if blake3::Hash::from_bytes(mac)
        != blake3::keyed_hash(key.as_bytes(), &provenance_bytes(payload)?)
    {
        bail!("export provenance authentication failed");
    }
    let expected_header = hex::encode(teagarden_core::block::srb2::sha256(&serde_json::to_vec(
        header,
    )?));
    if payload["format"] != 1
        || payload["volume_id"].as_str() != Some(header.volume_id.to_string().as_str())
        || payload["header_revision"].as_u64() != Some(header.revision)
        || payload["header_sha256"].as_str() != Some(expected_header.as_str())
        || !payload["objects"].is_object()
    {
        bail!("export provenance does not match the authenticated current header");
    }
    let owner_authorized = match value.get("owner_signature") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::String(signature)) => {
            let owner = header
                .owner_public_key
                .as_deref()
                .context("source authorization requires an owner anchor")?;
            let public: [u8; 32] = hex::decode(owner)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid owner source key"))?;
            let signature = ed25519_dalek::Signature::from_slice(&hex::decode(signature)?)?;
            let mut signed = b"teagarden.export-source-authority.v1".to_vec();
            signed.extend_from_slice(&serde_json::to_vec(payload)?);
            ed25519_dalek::VerifyingKey::from_bytes(&public)?
                .verify_strict(&signed, &signature)
                .context("export owner source authorization failed")?;
            true
        }
        Some(_) => bail!("invalid export owner source authorization"),
    };
    Ok(Some(ExportProvenance {
        payload: payload.clone(),
        owner_authorized,
    }))
}

fn export_source_message_id(
    provenance: Option<&ExportProvenance>,
    path: &Path,
    wire: &[u8],
) -> Result<i64> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid object filename")?;
    let Some(entry) = provenance.and_then(|bundle| bundle.payload["objects"].get(name)) else {
        // A bare local filename cannot prove pre-boundary provenance. Signed
        // survivors and owner receipts still pass the same transition predicate.
        return Ok(i64::MAX);
    };
    let digest = hex::encode(teagarden_core::block::srb2::sha256(wire));
    if entry["sha256"].as_str() != Some(digest.as_str()) {
        bail!("export object digest disagrees with authenticated provenance");
    }
    if !provenance.is_some_and(|bundle| bundle.owner_authorized) {
        return Ok(i64::MAX);
    }
    entry["message_id"]
        .as_i64()
        .filter(|id| *id > 0)
        .context("invalid authenticated source message ID")
}

fn open_local_header(
    directory: &Path,
    credential: &[u8],
    recovery: bool,
    owner_public_key: Option<&str>,
) -> Result<(HeaderDocument, KeyHierarchy)> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("find TGHD header in {}", directory.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.file_type()?.is_symlink() {
            continue;
        }
        let path = entry.path();
        if !has_magic(&path, b"TGHD")? {
            continue;
        }
        if entry.metadata()?.len() > teagarden_core::sdo::MAX_HEADER_SIZE as u64 {
            bail!("TGHD header {} exceeds the size limit", path.display());
        }
        let bytes = fs::read(&path)?;
        let untrusted: HeaderDocument = parse_header_json(&bytes)?;
        candidates.push((untrusted, path, bytes));
    }
    if candidates.is_empty() {
        bail!("no TGHD header object found beside the file objects");
    }
    candidates.sort_by_key(|(header, _, _)| header.revision);
    let directory_owner = candidates.iter().find_map(|(header, _, _)| {
        (header.format == 2)
            .then(|| header.owner_public_key.clone())
            .flatten()
    });
    let owner_public_key = owner_public_key.or(directory_owner.as_deref());
    let highest = candidates.last().unwrap().0.revision;
    let highest_set: Vec<_> = candidates
        .into_iter()
        .filter(|(h, _, _)| h.revision == highest)
        .collect();
    if highest_set
        .iter()
        .skip(1)
        .any(|candidate| candidate.2 != highest_set[0].2)
    {
        bail!("conflicting authenticated TGHD headers have revision {highest}");
    }
    let (untrusted, path, bytes) = highest_set.into_iter().next().unwrap();
    let hierarchy = derive_header_hierarchy(&untrusted, credential, recovery)
        .with_context(|| format!("unlock newest header {}", path.display()))?;
    let header = HeaderDocument::decode_pinned(&bytes, &hierarchy.integrity, owner_public_key)
        .with_context(|| format!("authenticate newest header {}", path.display()))?;
    Ok((header, hierarchy))
}

pub(crate) fn parse_header_json(wire: &[u8]) -> Result<HeaderDocument> {
    if wire.len() < 10 || wire.len() > teagarden_core::sdo::MAX_HEADER_SIZE || &wire[..4] != b"TGHD"
    {
        bail!("invalid TGHD framing");
    }
    let wire_format = u16::from_le_bytes([wire[4], wire[5]]);
    let len = u32::from_le_bytes(wire[6..10].try_into()?) as usize;
    let json_end = 10usize
        .checked_add(len)
        .context("TGHD JSON length overflow")?;
    match wire_format {
        1 if json_end.checked_add(32) == Some(wire.len()) => {}
        2 if json_end.checked_add(2).is_some_and(|end| end <= wire.len()) => {
            let signature_len = u16::from_le_bytes(
                wire.get(json_end..)
                    .and_then(|tail| tail.get(..2))
                    .context("truncated TGHD2 signature length")?
                    .try_into()?,
            ) as usize;
            if signature_len != 64
                || json_end.checked_add(2 + signature_len + 32) != Some(wire.len())
            {
                bail!("TGHD2 signature or total length mismatch");
            }
        }
        _ => bail!("TGHD length mismatch"),
    }
    let header: HeaderDocument =
        serde_json::from_slice(&wire[10..json_end]).context("parse TGHD fields")?;
    if header.format != wire_format {
        bail!("TGHD JSON and framing formats disagree");
    }
    Ok(header)
}

pub(crate) fn derive_header_hierarchy(
    header: &HeaderDocument,
    credential: &[u8],
    recovery: bool,
) -> Result<KeyHierarchy> {
    let salt: [u8; 32] = hex::decode(&header.salt)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid header salt"))?;
    match &header.root_kind {
        RootKind::Password => {
            let root = if recovery {
                decode_exported_root(credential)?
            } else {
                let params = header
                    .kdf_params
                    .as_ref()
                    .context("password header has no KDF parameters")?;
                derive_root_key(credential, &salt, params)?
            };
            Ok(derive_hierarchy_v1(
                root,
                &salt,
                header.group_id,
                header.topic_id,
            )?)
        }
        RootKind::MasterKey => {
            let slot_result = (|| -> Result<KeyHierarchy> {
                let vault_bytes = serde_json::to_vec(
                    header
                        .slot_vault
                        .as_ref()
                        .context("protected header has no slot vault")?,
                )?;
                let vault =
                    SlotVault::from_bytes(&vault_bytes).context("validate embedded slot vault")?;
                let master_key = if recovery {
                    let phrase = std::str::from_utf8(credential)
                        .context("recovery sentence is not UTF-8")?;
                    let protector = RecoveryProtector::from_sentence(phrase)
                        .context("parse recovery sentence")?;
                    vault
                        .unlock(&[&protector as &dyn SlotProtector])
                        .context("unlock recovery slot")?
                } else {
                    let protector =
                        PassphraseProtector::new(credential.to_vec(), Argon2Cost::default());
                    vault
                        .unlock(&[&protector as &dyn SlotProtector])
                        .context("unlock passphrase slot")?
                };
                let anchor: teagarden_core::volume::config::KeyProtection = serde_json::from_value(
                    header
                        .key_protection
                        .clone()
                        .context("protected header has no vault anchor")?,
                )
                .context("parse vault anchor")?;
                if anchor.vault_generation != vault.generation()
                    || anchor.vault_digest != hex::encode(vault.state_digest())
                {
                    bail!("embedded slot vault does not match the authenticated header anchor");
                }
                Ok(derive_hierarchy_from_master_key(
                    master_key.as_bytes(),
                    &salt,
                    header.group_id,
                    header.topic_id,
                )?)
            })();
            match slot_result {
                Ok(hierarchy) => Ok(hierarchy),
                Err(slot_error) if recovery => {
                    // As with local unlock, a recovery input can instead be the
                    // exported hierarchy root. The caller still authenticates
                    // the exact TGHD wire (and owner pin) with these keys.
                    decode_exported_root(credential)
                        .and_then(|root| {
                            Ok(derive_hierarchy_v1(
                                root,
                                &salt,
                                header.group_id,
                                header.topic_id,
                            )?)
                        })
                        .map_err(|_| slot_error)
                }
                Err(error) => Err(error),
            }
        }
    }
}

fn decode_exported_root(credential: &[u8]) -> Result<SymmetricKey> {
    let sentence = std::str::from_utf8(credential).context("recovery sentence is not UTF-8")?;
    let lists = teagarden_core::sentence::wordlists::production_wordlists();
    let reverse = core::array::from_fn(|i| {
        teagarden_core::sentence::wordlists::build_reverse_lookup(&lists[i])
    });
    let bytes = zeroize::Zeroizing::new(teagarden_core::sentence::decode::decode_ref_string(
        sentence, &lists, &reverse,
    )?);
    let root = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("exported root sentence must contain 32 bytes"))?;
    Ok(SymmetricKey::from_bytes(root))
}

fn write_files(out_dir: &Path, selected: &[&DecodedVersion]) -> Result<()> {
    let checked_output = check_output_ancestors(out_dir)?;
    let out_dir = checked_output.as_path();
    if fs::symlink_metadata(out_dir).is_ok() {
        bail!("output directory already exists: {}", out_dir.display());
    }
    fs::create_dir(out_dir)
        .with_context(|| format!("create output directory {}", out_dir.display()))?;
    let result = (|| -> Result<()> {
        for version in selected {
            let relative = Path::new(&version.metadata.path);
            validate_relative_path(relative)?;
            let mut parent = out_dir.to_path_buf();
            let components: Vec<_> = relative.components().collect();
            let parent_count = if version.kind == SdoKind::Directory {
                components.len()
            } else {
                components.len().saturating_sub(1)
            };
            for component in components.iter().take(parent_count) {
                parent.push(component.as_os_str());
                match fs::create_dir(&parent) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        if fs::symlink_metadata(&parent)?.file_type().is_symlink()
                            || !parent.is_dir()
                        {
                            bail!(
                                "output path contains a symbolic link or non-directory: {}",
                                parent.display()
                            );
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if version.kind == SdoKind::Directory {
                continue;
            }
            let path = out_dir.join(relative);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| {
                    format!("create output file {} without overwrite", path.display())
                })?;
            file.write_all(&version.content)
                .with_context(|| format!("write {}", path.display()))?;
            file.sync_all()?;
        }
        // Apply attributes after creating all children: child creation changes a
        // directory's mtime, and a restrictive parent mode must not block restore.
        let mut attributes = selected.to_vec();
        attributes.sort_by_key(|version| {
            std::cmp::Reverse(Path::new(&version.metadata.path).components().count())
        });
        for version in attributes {
            let path = out_dir.join(&version.metadata.path);
            let file = fs::File::open(&path)?;
            let modified = if version.metadata.mtime_ns >= 0 {
                std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_nanos(
                    version.metadata.mtime_ns as u64,
                ))
            } else {
                std::time::UNIX_EPOCH.checked_sub(std::time::Duration::from_nanos(
                    version.metadata.mtime_ns.unsigned_abs(),
                ))
            }
            .context("file modification time is out of range")?;
            file.set_times(std::fs::FileTimes::new().set_modified(modified))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(version.metadata.mode & 0o777),
                )?;
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(out_dir);
    }
    result
}

fn check_output_ancestors(out_dir: &Path) -> Result<std::path::PathBuf> {
    use std::path::Component;
    let absolute = if out_dir.is_absolute() {
        out_dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(out_dir)
    };
    #[cfg(target_os = "macos")]
    let absolute = physical_macos_temp_path(absolute);
    let mut current = std::path::PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        bail!(
                            "output path traverses a symbolic link: {}",
                            current.display()
                        );
                    }
                    Ok(metadata) if !metadata.is_dir() => {
                        bail!("output parent is not a directory: {}", current.display());
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if current != absolute {
                            bail!(
                                "output parent directory does not exist: {}",
                                current.display()
                            );
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Component::CurDir => {}
            Component::ParentDir => bail!("output path must not contain '..'"),
        }
    }
    Ok(absolute)
}

#[cfg(target_os = "macos")]
fn physical_macos_temp_path(absolute: std::path::PathBuf) -> std::path::PathBuf {
    use std::os::unix::fs::MetadataExt;

    // These system-owned aliases are part of a standard macOS installation.
    // Validate and write through the physical path, with the same checks on
    // each component below it as on every other output path.
    for (alias, target) in [("/var", "/private/var"), ("/tmp", "/private/tmp")] {
        let Ok(suffix) = absolute.strip_prefix(alias) else {
            continue;
        };
        let target = Path::new(target);
        if fs::symlink_metadata(alias)
            .is_ok_and(|metadata| metadata.file_type().is_symlink() && metadata.uid() == 0)
            && fs::read_link(alias).is_ok_and(|dest| Path::new("/").join(dest) == target)
        {
            return target.join(suffix);
        }
    }
    absolute
}

fn validate_relative_path(path: &Path) -> Result<()> {
    use std::path::Component;
    if path.as_os_str().is_empty()
        || path.as_os_str().to_string_lossy().len() > 4096
        || path.components().count() > 256
    {
        bail!("invalid or overlong file object path");
    }
    for component in path.components() {
        match component {
            Component::Normal(value) if !value.to_string_lossy().contains('\0') => {}
            _ => bail!("unsafe path in file object: {}", path.display()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_tmp_alias_restores_into_its_physical_directory() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let leaf = dir.path().file_name().unwrap();
        let requested = Path::new("/tmp").join(leaf).join("restored");
        let physical = Path::new("/private/tmp").join(leaf).join("restored");
        assert_eq!(check_output_ancestors(&requested).unwrap(), physical);
        write_files(&requested, &[]).unwrap();
        assert!(physical.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn refuse_user_controlled_symlink_under_output_parent() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("target");
        let link = dir.path().join("user-link");
        fs::create_dir(&dest).unwrap();
        std::os::unix::fs::symlink(&dest, &link).unwrap();
        let error = write_files(&link.join("restored"), &[]).unwrap_err();
        assert!(error.to_string().contains("user-link"));
        assert!(!dest.join("restored").exists());
    }
    use teagarden_core::crypto::kdf::{derive_hierarchy_v1, derive_root_key};
    use teagarden_core::crypto::keys::Argon2Params;

    #[test]
    fn a2_n2_directory_refuses_missing_or_unrecognized_export_objects() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("objects");
        fs::create_dir(&input).unwrap();
        let mut header = HeaderDocument::test_fixture();
        header.kdf_params = Some(Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        });
        let hierarchy = derive_header_hierarchy(&header, b"password", false).unwrap();
        fs::write(
            input.join("header.tgh"),
            header.encode(&hierarchy.integrity).unwrap(),
        )
        .unwrap();
        let present = SdoFileObject::encode(
            header.volume_id,
            &hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadata::test_fixture(),
            b"",
        )
        .unwrap();
        fs::write(input.join("present.tgf"), &present).unwrap();
        let payload = serde_json::json!({ "format": 1, "volume_id": header.volume_id,
            "header_revision": header.revision,
            "header_sha256": hex::encode(teagarden_core::block::srb2::sha256(&serde_json::to_vec(&header).unwrap())),
            "objects": { "present.tgf": { "message_id": 1, "sha256": hex::encode(teagarden_core::block::srb2::sha256(&present)) },
                "lost.tgf": { "message_id": 2, "sha256": "00" } }
        });
        write_export_provenance(&input, payload, &hierarchy.integrity, None).unwrap();
        let password = temp.path().join("password");
        fs::write(&password, "password").unwrap();
        for include_unverified in [false, true] {
            let out = temp.path().join(format!("missing-{include_unverified}"));
            let error = run(
                &input,
                Some(&out),
                Some(password.to_str().unwrap()),
                None,
                None,
                None,
                include_unverified,
            )
            .expect_err("a provenance-listed missing object must not be silently omitted");
            assert!(format!("{error:#}").contains("1 object(s)"), "{error:#}");
            assert!(!out.exists());
        }
        fs::write(input.join("lost.tgf"), b"broken framing").unwrap();
        let out = temp.path().join("bad-magic");
        let error = run(
            &input,
            Some(&out),
            Some(password.to_str().unwrap()),
            None,
            None,
            None,
            true,
        )
        .expect_err("a provenance-listed object with destroyed framing must not be ignored");
        assert!(format!("{error:#}").contains("1 object(s)"), "{error:#}");
        assert!(!out.exists());
    }

    #[test]
    fn round3_65_directory_decrypt_restores_explicit_empty_directories() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("objects");
        fs::create_dir(&input).unwrap();
        let mut header = HeaderDocument::test_fixture();
        header.kdf_params = Some(Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        });
        let hierarchy = derive_header_hierarchy(&header, b"password", false).unwrap();
        fs::write(
            input.join("header.tgh"),
            header.encode(&hierarchy.integrity).unwrap(),
        )
        .unwrap();
        for (i, path, deleted) in [
            (1, "empty", false),
            (2, "parent", false),
            (3, "parent/leaf", false),
            (4, "gone", false),
            (5, "gone", true),
        ] {
            let mut m = teagarden_core::sdo::legacy_metadata_v3(
                &teagarden_core::sdo::SdoObjectMetadata::test_fixture(),
            );
            m.file_id = Uuid::from_u128(if path == "gone" { 4 } else { i });
            m.version_id = Uuid::from_u128(100 + i);
            m.path = Some(path.into());
            m.kind = SdoKind::Directory;
            m.size = 0;
            m.mode = 0o750;
            m.mtime_ns = 123_000_000_000;
            m.clock_ms = i as u64;
            m.deleted = deleted;
            let wire =
                SdoFileObjectV3::encode(header.volume_id, 0, &hierarchy.meta, m, b"").unwrap();
            fs::write(input.join(format!("{i}.tgf")), wire).unwrap();
        }
        let password = temp.path().join("password");
        fs::write(&password, b"password").unwrap();
        let output = temp.path().join("restored");
        run(
            &input,
            Some(&output),
            Some(password.to_str().unwrap()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        for path in ["empty", "parent", "parent/leaf"] {
            let meta = fs::metadata(output.join(path))
                .expect("explicit empty directories must be restored");
            assert!(meta.is_dir());
            assert_eq!(
                meta.modified()
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                123_000_000_000
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(meta.permissions().mode() & 0o777, 0o750);
            }
        }
        assert!(
            !output.join("gone").exists(),
            "directory tombstones must remain effective"
        );
    }

    #[test]
    fn single_nested_v3_recovers_without_directory_records() {
        single_nested_v3(false);
    }

    #[test]
    fn single_downloaded_v3_recovers_without_tghd() {
        single_nested_v3(true);
    }

    fn single_nested_v3(without_header: bool) {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("objects");
        fs::create_dir(&input).unwrap();
        let password = "offline-test-password";
        let mut header = HeaderDocument::test_fixture();
        header.salt = hex::encode([0x21; 32]);
        header.root_kind = RootKind::Password;
        header.kdf_params = Some(Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        });
        let volume_id = header.volume_id;
        let hierarchy = derive_header_hierarchy(&header, password.as_bytes(), false).unwrap();
        if !without_header {
            fs::write(
                input.join("header.tgh"),
                header.encode(&hierarchy.integrity).unwrap(),
            )
            .unwrap();
        }
        let v3 = SdoFileObjectV3::encode(
            volume_id,
            0,
            &hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: Uuid::from_bytes([0x42; 16]),
                origin_message_id: None,
                path: Some("nested/format-three.txt".into()),
                size: 4,
                mtime_ns: 0,
                mode: 0o600,
                version_id: Uuid::from_bytes([0x53; 16]),
                author_device_id: Uuid::from_bytes([0x61; 16]),
                previous_version_id: None,
                kind: SdoKind::File,
                key_generation: 0,
                clock_ms: 10,
                clock_counter: 0,
                saved_at_ns: 10_000_000,
                local_version: 1,
                deleted: false,
                installation_id: None,
                label: None,
                telegram_user_id: None,
                authorization_session_hash: None,
                created_at_ms: None,
                device_public_key: None,
                device_key_update: None,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 1,
                content_sha256: String::new(),
            },
            b"v3!!",
        )
        .unwrap();
        let v3 = if without_header {
            teagarden_core::sdo::ObjectEnvelope::seal(
                &v3,
                &header.encode(&hierarchy.integrity).unwrap(),
                &hierarchy,
            )
            .unwrap()
        } else {
            v3
        };
        fs::write(input.join("only.tgf"), v3).unwrap();
        let password_file = temp.path().join("pass");
        fs::write(&password_file, password).unwrap();
        let output = temp.path().join("restored");
        run(
            &input.join("only.tgf"),
            Some(&output),
            Some(password_file.to_str().unwrap()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            fs::read(output.join("nested/format-three.txt")).unwrap(),
            b"v3!!"
        );
        if without_header {
            let words = teagarden_core::sentence::wordlists::production_wordlists();
            let sentence = teagarden_core::sentence::encode::encode_ref_string(
                hierarchy.root.as_bytes(),
                &words,
            )
            .unwrap();
            let recovery = temp.path().join("recovery");
            fs::write(&recovery, sentence).unwrap();
            let recovered = temp.path().join("recovered");
            run(
                &input.join("only.tgf"),
                Some(&recovered),
                None,
                Some(recovery.to_str().unwrap()),
                None,
                None,
                false,
            )
            .unwrap();
            assert_eq!(
                fs::read(recovered.join("nested/format-three.txt")).unwrap(),
                b"v3!!"
            );
            fs::write(&password_file, "wrong-password").unwrap();
            assert!(run(
                &input.join("only.tgf"),
                Some(&temp.path().join("wrong")),
                Some(password_file.to_str().unwrap()),
                None,
                None,
                None,
                false
            )
            .is_err());
            fs::write(&password_file, password).unwrap();
            let mut tampered = fs::read(input.join("only.tgf")).unwrap();
            // The trailer is bound to the complete wire, including its encrypted segments.
            let length = tampered.len();
            tampered[length - 41] ^= 1;
            fs::write(input.join("only.tgf"), tampered).unwrap();
            assert!(run(
                &input.join("only.tgf"),
                Some(&temp.path().join("tampered")),
                Some(password_file.to_str().unwrap()),
                None,
                None,
                None,
                false
            )
            .is_err());
        }
    }

    #[test]
    fn offline_selects_newest_header_before_unlocking_obsolete_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let mut header = HeaderDocument::test_fixture();
        header.revision = 2;
        let hierarchy = derive_header_hierarchy(&header, b"current-password", false).unwrap();
        fs::write(
            temp.path().join("new.tgh"),
            header.encode(&hierarchy.integrity).unwrap(),
        )
        .unwrap();
        let mut old_header = header.clone();
        old_header.revision = 1;
        old_header.salt = hex::encode([0xaa; 32]);
        let old_keys = derive_header_hierarchy(&old_header, b"obsolete-password", false).unwrap();
        fs::write(
            temp.path().join("old.tgh"),
            old_header.encode(&old_keys.integrity).unwrap(),
        )
        .unwrap();
        let volume_id = header.volume_id;
        let v3 = SdoFileObjectV3::encode(
            volume_id,
            0,
            &hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: Uuid::from_bytes([0x42; 16]),
                origin_message_id: None,
                path: Some("nested/format-three.txt".into()),
                size: 4,
                mtime_ns: 0,
                mode: 0o600,
                version_id: Uuid::from_bytes([0x53; 16]),
                author_device_id: Uuid::from_bytes([0x61; 16]),
                previous_version_id: None,
                kind: SdoKind::File,
                key_generation: 0,
                clock_ms: 10,
                clock_counter: 0,
                saved_at_ns: 10_000_000,
                local_version: 1,
                deleted: false,
                installation_id: None,
                label: None,
                telegram_user_id: None,
                authorization_session_hash: None,
                created_at_ms: None,
                device_public_key: None,
                device_key_update: None,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 1,
                content_sha256: String::new(),
            },
            b"v3!!",
        )
        .unwrap();
        let input = temp.path().join("one.tgf");
        fs::write(&input, v3).unwrap();
        let password = temp.path().join("password");
        fs::write(&password, b"current-password").unwrap();
        let output = temp.path().join("restored");
        run(
            &input,
            Some(&output),
            Some(password.to_str().unwrap()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            fs::read(output.join("nested/format-three.txt")).unwrap(),
            b"v3!!"
        );
    }

    #[test]
    fn bootstrap_parser_reads_tgdh2_json_before_credential_unlock() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]);
        let integrity = SymmetricKey::from_bytes([0x66; 32]);
        let mut header = HeaderDocument::test_fixture();
        header.format = 2;
        header.owner_public_key = Some(hex::encode(signing_key.verifying_key().to_bytes()));
        header.key_generation = Some(0);
        let wire = header.encode_v2(&integrity, &signing_key).unwrap();
        let untrusted = parse_header_json(&wire).unwrap();
        assert_eq!(untrusted.format, 2);
        assert_eq!(untrusted.volume_id, header.volume_id);
    }

    #[test]
    fn offline_directory_decrypts_latest_file_and_keeps_history_linkage() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("objects");
        fs::create_dir(&input).unwrap();
        let password = "offline-test-password";
        let salt = [0x21; 32];
        let volume_id = Uuid::from_bytes([0x31; 16]);
        let hierarchy = derive_hierarchy_v1(
            derive_root_key(
                password.as_bytes(),
                &salt,
                &Argon2Params {
                    memory_kib: 1024,
                    iterations: 1,
                    parallelism: 1,
                    output_len: 32,
                },
            )
            .unwrap(),
            &salt,
            -100123,
            77,
        )
        .unwrap();
        let header = HeaderDocument {
            format: 1,
            volume_id,
            revision: 1,
            volume_version: "1.0.0".into(),
            root_kind: RootKind::Password,
            salt: hex::encode(salt),
            kdf_params: Some(Argon2Params {
                memory_kib: 1024,
                iterations: 1,
                parallelism: 1,
                output_len: 32,
            }),
            group_id: -100123,
            topic_id: 77,
            current_epoch: 1,
            block_v2_from_epoch: None,
            require_block_integrity: false,
            block_size: 64 * 1024,
            key_protection: None,
            slot_vault: None,
            owner_public_key: None,
            key_generation: None,
            revoked_device_ids: Vec::new(),
            revoked_account_bindings: Vec::new(),
            retained_key_bridges: Vec::new(),
            device_authorities: std::collections::BTreeMap::new(),
            rotation_state: None,
            generation_boundary_message_id: None,
            generation_cutoffs: Default::default(),
            revocation_cutoffs: Default::default(),
        };
        fs::write(
            input.join("teagarden-header-v1.tgh"),
            header.encode(&hierarchy.integrity).unwrap(),
        )
        .unwrap();
        let file_id = Uuid::from_bytes([0x41; 16]);
        let first_id = Uuid::from_bytes([0x51; 16]);
        let first = SdoFileObject::encode(
            volume_id,
            &hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadata {
                file_id,
                origin_message_id: None,
                path: "nested/hello.txt".into(),
                size: 5,
                mtime_ns: 0,
                mode: 0o640,
                version_id: first_id,
                author_device_id: Uuid::from_bytes([0x61; 16]),
                previous_version_id: None,
                saved_at_ns: 1,
                local_version: 1,
                deleted: false,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 1,
                content_sha256: String::new(),
            },
            b"first",
        )
        .unwrap();
        let second = SdoFileObject::encode(
            volume_id,
            &hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadata {
                file_id,
                origin_message_id: Some(1),
                path: "nested/hello.txt".into(),
                size: 6,
                mtime_ns: 0,
                mode: 0o600,
                version_id: Uuid::from_bytes([0x52; 16]),
                author_device_id: Uuid::from_bytes([0x61; 16]),
                previous_version_id: Some(first_id),
                saved_at_ns: 2,
                local_version: 2,
                deleted: false,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 1,
                content_sha256: String::new(),
            },
            b"second",
        )
        .unwrap();
        fs::write(input.join("first.tgf"), first).unwrap();
        fs::write(input.join("second.tgf"), second).unwrap();
        let v3 = SdoFileObjectV3::encode(
            volume_id,
            0,
            &hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: Uuid::from_bytes([0x42; 16]),
                origin_message_id: None,
                path: Some("nested/format-three.txt".into()),
                size: 4,
                mtime_ns: 0,
                mode: 0o600,
                version_id: Uuid::from_bytes([0x53; 16]),
                author_device_id: Uuid::from_bytes([0x61; 16]),
                previous_version_id: None,
                kind: SdoKind::File,
                key_generation: 0,
                clock_ms: 10,
                clock_counter: 0,
                saved_at_ns: 10_000_000,
                local_version: 1,
                deleted: false,
                installation_id: None,
                label: None,
                telegram_user_id: None,
                authorization_session_hash: None,
                created_at_ms: None,
                device_public_key: None,
                device_key_update: None,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 1,
                content_sha256: String::new(),
            },
            b"v3!!",
        )
        .unwrap();
        fs::write(input.join("third.tgf"), v3).unwrap();
        let password_file = temp.path().join("pass");
        fs::write(&password_file, password).unwrap();

        run(
            &input,
            None,
            Some(password_file.to_str().unwrap()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        let output = input.join("decrypted/nested/hello.txt");
        assert_eq!(fs::read(output).unwrap(), b"second");
        assert_eq!(
            fs::read(input.join("decrypted/nested/format-three.txt")).unwrap(),
            b"v3!!"
        );

        let single_out = temp.path().join("single-output");
        run(
            &input.join("first.tgf"),
            Some(&single_out),
            Some(password_file.to_str().unwrap()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            fs::read(single_out.join("nested/hello.txt")).unwrap(),
            b"first"
        );

        assert!(run(
            &input,
            None,
            Some(password_file.to_str().unwrap()),
            None,
            None,
            None,
            false
        )
        .is_err());

        let corrupt = temp.path().join("corrupt");
        fs::create_dir(&corrupt).unwrap();
        fs::copy(
            input.join("teagarden-header-v1.tgh"),
            corrupt.join("header.tgh"),
        )
        .unwrap();
        let mut changed = fs::read(input.join("second.tgf")).unwrap();
        *changed.last_mut().unwrap() ^= 1;
        fs::write(corrupt.join("bad.tgf"), changed).unwrap();
        assert!(run(
            &corrupt,
            None,
            Some(password_file.to_str().unwrap()),
            None,
            None,
            None,
            false
        )
        .is_err());
        assert!(
            !corrupt.join("decrypted").exists(),
            "tamper must fail before output creation"
        );

        let history_out = temp.path().join("history-only");
        run(
            &input,
            Some(&history_out),
            Some(password_file.to_str().unwrap()),
            None,
            Some(file_id),
            None,
            false,
        )
        .unwrap();
        assert!(!history_out.exists(), "history query must not write files");
    }

    #[test]
    fn offline_header_unlock_supports_exported_root_and_protected_slots() {
        use teagarden_core::volume::config::KeyProtection;
        use teagarden_mfa::kslot::protectors::RecoveryProtector;
        use teagarden_mfa::kslot::types::MasterKey;

        let salt = [0x12; 32];
        let group_id = -100222;
        let topic_id = 88;
        let password_params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        };
        let root_hierarchy = derive_hierarchy_v1(
            derive_root_key(b"portable-password", &salt, &password_params).unwrap(),
            &salt,
            group_id,
            topic_id,
        )
        .unwrap();
        let wordlists = teagarden_core::sentence::wordlists::production_wordlists();
        let exported_root = teagarden_core::sentence::encode::encode_ref_string(
            root_hierarchy.root.as_bytes(),
            &wordlists,
        )
        .unwrap();
        let password_header = HeaderDocument {
            format: 1,
            volume_id: Uuid::from_bytes([0x71; 16]),
            revision: 1,
            volume_version: "1.0.0".into(),
            root_kind: RootKind::Password,
            salt: hex::encode(salt),
            kdf_params: Some(password_params),
            group_id,
            topic_id,
            current_epoch: 1,
            block_v2_from_epoch: None,
            require_block_integrity: false,
            block_size: 64 * 1024,
            key_protection: None,
            slot_vault: None,
            owner_public_key: None,
            key_generation: None,
            revoked_device_ids: Vec::new(),
            revoked_account_bindings: Vec::new(),
            retained_key_bridges: Vec::new(),
            device_authorities: std::collections::BTreeMap::new(),
            rotation_state: None,
            generation_boundary_message_id: None,
            generation_cutoffs: Default::default(),
            revocation_cutoffs: Default::default(),
        };
        assert_eq!(
            derive_header_hierarchy(&password_header, exported_root.as_bytes(), true)
                .unwrap()
                .meta
                .as_bytes(),
            root_hierarchy.meta.as_bytes()
        );

        let master = MasterKey::from_bytes([0x72; 32]);
        let mut vault = SlotVault::create_around("portable-unlock", master.as_bytes());
        let mut passphrase = PassphraseProtector::new(
            b"protected-password".to_vec(),
            Argon2Cost {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        );
        vault
            .add_independent_slot(&master, &mut passphrase, "offline password")
            .unwrap();
        let mut recovery = RecoveryProtector::for_enroll();
        vault
            .add_independent_slot(&master, &mut recovery, "offline recovery")
            .unwrap();
        let protected_hierarchy =
            derive_hierarchy_from_master_key(master.as_bytes(), &salt, group_id, topic_id).unwrap();
        let protected_header = HeaderDocument {
            format: 1,
            volume_id: Uuid::from_bytes([0x73; 16]),
            revision: 1,
            volume_version: "1.0.0".into(),
            root_kind: RootKind::MasterKey,
            salt: hex::encode(salt),
            kdf_params: None,
            group_id,
            topic_id,
            current_epoch: 1,
            block_v2_from_epoch: None,
            require_block_integrity: false,
            block_size: 64 * 1024,
            key_protection: Some(
                serde_json::to_value(KeyProtection {
                    vault_generation: vault.generation(),
                    vault_digest: hex::encode(vault.state_digest()),
                })
                .unwrap(),
            ),
            slot_vault: Some(serde_json::from_slice(&vault.to_bytes().unwrap()).unwrap()),
            owner_public_key: None,
            key_generation: None,
            revoked_device_ids: Vec::new(),
            revoked_account_bindings: Vec::new(),
            retained_key_bridges: Vec::new(),
            device_authorities: std::collections::BTreeMap::new(),
            rotation_state: None,
            generation_boundary_message_id: None,
            generation_cutoffs: Default::default(),
            revocation_cutoffs: Default::default(),
        };
        assert_eq!(
            derive_header_hierarchy(&protected_header, b"protected-password", false)
                .unwrap()
                .meta
                .as_bytes(),
            protected_hierarchy.meta.as_bytes()
        );
        let sentence = recovery.enrolled_sentence().unwrap().to_owned();
        assert_eq!(
            derive_header_hierarchy(&protected_header, sentence.as_bytes(), true)
                .unwrap()
                .meta
                .as_bytes(),
            protected_hierarchy.meta.as_bytes()
        );
        let volume_id = protected_header.volume_id;
        let hierarchy = &protected_hierarchy;
        let v3 = SdoFileObjectV3::encode(
            volume_id,
            0,
            &hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: Uuid::from_bytes([0x42; 16]),
                origin_message_id: None,
                path: Some("nested/format-three.txt".into()),
                size: 4,
                mtime_ns: 0,
                mode: 0o600,
                version_id: Uuid::from_bytes([0x53; 16]),
                author_device_id: Uuid::from_bytes([0x61; 16]),
                previous_version_id: None,
                kind: SdoKind::File,
                key_generation: 0,
                clock_ms: 10,
                clock_counter: 0,
                saved_at_ns: 10_000_000,
                local_version: 1,
                deleted: false,
                installation_id: None,
                label: None,
                telegram_user_id: None,
                authorization_session_hash: None,
                created_at_ms: None,
                device_public_key: None,
                device_key_update: None,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 1,
                content_sha256: String::new(),
            },
            b"v3!!",
        )
        .unwrap();
        let wire = teagarden_core::sdo::ObjectEnvelope::seal(
            &v3,
            &protected_header
                .encode(&protected_hierarchy.integrity)
                .unwrap(),
            &protected_hierarchy,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("one.tgf");
        fs::write(&input, wire).unwrap();
        let password_file = temp.path().join("password");
        let recovery_file = temp.path().join("recovery");
        fs::write(&password_file, b"protected-password").unwrap();
        fs::write(&recovery_file, sentence).unwrap();
        for (credential, recovery) in [(&password_file, false), (&recovery_file, true)] {
            let output = temp
                .path()
                .join(if recovery { "recovered" } else { "decrypted" });
            run(
                &input,
                Some(&output),
                (!recovery).then(|| credential.to_str().unwrap()),
                recovery.then(|| credential.to_str().unwrap()),
                None,
                None,
                false,
            )
            .unwrap();
            assert_eq!(
                fs::read(output.join("nested/format-three.txt")).unwrap(),
                b"v3!!"
            );
        }
    }
}
