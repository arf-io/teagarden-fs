use std::io::{IsTerminal as _, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::Connection;

use teagarden_api::service::volume::VolumeService;
use teagarden_cache::block_cache::{BlockCache, CacheConfig};
use teagarden_core::crypto::keys::KeyHierarchy;
use teagarden_core::metadata::inode::Inode;
use teagarden_core::sdo::{HeaderDocument, RootKind};
use teagarden_core::volume::config::VolumeConfig;
use teagarden_core::volume::journal_head::{JournalHead, Lineage};
use teagarden_core::volume::manager;
use teagarden_core::volume::names as volume_names;
use teagarden_core::volume::rebuild_marker;
use teagarden_fuse::fs::CryptFs;
use teagarden_store::inode_store::InodeStore;
use teagarden_store::local_db::{self, LocalDb};
use teagarden_store::migrations::initialize_database;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::schema::logical_tables;
use teagarden_telegram::client::{BlockTransport, ForumAdmin, TelegramClient};
use teagarden_telegram::types::{ChannelRef, TelegramConfig};

use super::mfa::{build_unlock_inputs, factor_label, FactorSelect};
use super::utils;
mod policy;
mod revocation;

/// Path to the owner signing secret, stored beside but independently from the
/// shared-password volume configuration.
#[allow(dead_code)]
fn owner_capability_path(config_path: &std::path::Path) -> Result<PathBuf> {
    let parent = config_path
        .parent()
        .context("volume configuration has no parent directory")?;
    Ok(parent.join("owner-signing.key"))
}

/// Create the owner capability once. Its raw Ed25519 seed is never written into
/// volume.json or wrapped by the shared volume credential.
#[allow(dead_code)]
fn ensure_owner_capability(config_path: &std::path::Path) -> Result<ed25519_dalek::SigningKey> {
    let path = owner_capability_path(config_path)?;
    if path.exists() {
        return load_owner_capability(config_path);
    }
    use rand::RngCore as _;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("create owner signing capability at {}", path.display()))?;
    file.write_all(&seed)
        .context("write owner signing capability")?;
    file.sync_all().context("sync owner signing capability")?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    use zeroize::Zeroize as _;
    seed.zeroize();
    Ok(key)
}

/// Load the owner capability, refusing non-regular, malformed, or permissive files.
#[allow(dead_code)]
fn load_owner_capability(config_path: &std::path::Path) -> Result<ed25519_dalek::SigningKey> {
    manager::load_owner_capability(config_path).map_err(Into::into)
}

fn read_device_keypair(base_dir: &std::path::Path) -> Result<serde_json::Value> {
    let path = base_dir.join("device-keypair.json");
    let metadata = std::fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.len() <= 1024 * 1024,
        "device keypair must be a bounded regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "device keypair permissions are broader than 0600"
        );
    }
    serde_json::from_slice(&std::fs::read(path)?).context("parse local device keypair")
}

fn device_wrap_id(key: &teagarden_core::crypto::keys::SymmetricKey) -> String {
    blake3::keyed_hash(key.as_bytes(), b"teagarden.device-private-key-id.v2")
        .to_hex()
        .to_string()
}

fn device_private_aad(public: &[u8]) -> Vec<u8> {
    let mut aad = b"teagarden.device-private.v2".to_vec();
    aad.extend_from_slice(public);
    aad
}

fn store_device_key_wrap(
    base_dir: &std::path::Path,
    wrapping_key: &teagarden_core::crypto::keys::SymmetricKey,
    private: &teagarden_core::crypto::mlkem::MlKemDecapsulationKey,
    public: &teagarden_core::crypto::mlkem::MlKemEncapsulationKey,
) -> Result<()> {
    let path = base_dir.join("device-keypair.json");
    let mut value = if path.exists() {
        read_device_keypair(base_dir)?
    } else {
        serde_json::json!({"format": 2, "public": hex::encode(&public.0), "private_wraps": {}})
    };
    anyhow::ensure!(
        value["public"].as_str() == Some(hex::encode(&public.0).as_str()),
        "device keypair public key changed"
    );
    if let Some(serde_json::Value::String(mut legacy)) = value
        .as_object_mut()
        .context("invalid device keypair")?
        .remove("private")
    {
        use zeroize::Zeroize;
        legacy.zeroize();
    }
    value["format"] = serde_json::json!(2);
    if value.get("private_wraps").is_none() {
        value["private_wraps"] = serde_json::json!({});
    }
    let wraps = value["private_wraps"]
        .as_object_mut()
        .context("invalid device private wraps")?;
    let id = device_wrap_id(wrapping_key);
    if !wraps.contains_key(&id) {
        let wrapped = teagarden_core::crypto::aead::encrypt(
            wrapping_key,
            &private.0,
            &device_private_aad(&public.0),
        )?;
        wraps.insert(id, serde_json::json!(hex::encode(wrapped)));
    }
    teagarden_core::fsutil::write_file_atomic(
        &path,
        &serde_json::to_vec(&value)?,
        "encrypted device receiving key",
    )?;
    Ok(())
}

pub(crate) fn load_or_create_device_keypair(
    base_dir: &std::path::Path,
    wrapping_key: &teagarden_core::crypto::keys::SymmetricKey,
) -> Result<(
    teagarden_core::crypto::mlkem::MlKemDecapsulationKey,
    teagarden_core::crypto::mlkem::MlKemEncapsulationKey,
)> {
    if base_dir.join("device-keypair.json").exists() {
        let mut value = read_device_keypair(base_dir)?;
        let public = hex::decode(
            value["public"]
                .as_str()
                .context("device public key missing")?,
        )?;
        anyhow::ensure!(
            public.len() == 1184,
            "local ML-KEM public key has invalid length"
        );
        let private = if let Some(serde_json::Value::String(mut legacy)) = value
            .as_object_mut()
            .context("invalid device keypair")?
            .remove("private")
        {
            let decoded = hex::decode(&legacy);
            use zeroize::Zeroize;
            legacy.zeroize();
            decoded?
        } else {
            let wrapped = hex::decode(
                value["private_wraps"][device_wrap_id(wrapping_key)]
                    .as_str()
                    .context(
                        "device receiving key requires this installation's existing local unlock",
                    )?,
            )?;
            teagarden_core::crypto::aead::decrypt(
                wrapping_key,
                &wrapped,
                &device_private_aad(&public),
            )?
        };
        let private = teagarden_core::crypto::mlkem::MlKemDecapsulationKey(private);
        anyhow::ensure!(
            private.0.len() == 64,
            "local ML-KEM private key seed has invalid length"
        );
        let public = teagarden_core::crypto::mlkem::MlKemEncapsulationKey(public);
        store_device_key_wrap(base_dir, wrapping_key, &private, &public)?;
        return Ok((private, public));
    }
    let (private, public) = teagarden_core::crypto::mlkem::generate_keypair()
        .context("generate per-installation ML-KEM keypair")?;
    store_device_key_wrap(base_dir, wrapping_key, &private, &public)?;
    Ok((private, public))
}

/// Resolve the authenticated account's group peer before requiring a channel
/// cache. `connect_user_session` intentionally starts without a selected topic.
async fn bind_opened_topic(transport: &dyn ForumAdmin, config: &VolumeConfig) -> Result<i64> {
    transport
        .list_topic_page(
            config.telegram_group_id,
            config.telegram_topic_id,
            None,
            None,
            None,
            1,
        )
        .await
        .context("resolve the opened volume's Telegram group and topic")?;
    let (group, access_hash, topic) = transport
        .channel_ref()
        .context("Telegram did not resolve the opened volume's storage group")?;
    anyhow::ensure!(
        group == config.telegram_group_id && topic == config.telegram_topic_id,
        "resolved Telegram peer does not match the opened volume's group and topic"
    );
    transport.select_topic(group, access_hash, topic)?;
    Ok(access_hash)
}

#[cfg(test)]
async fn upgrade_owner_command<T: ForumAdmin + 'static>(
    client: Arc<T>,
    opened: &manager::OpenVolumeResult,
) -> Result<()> {
    let group_access_hash = bind_opened_topic(client.as_ref(), &opened.config).await?;
    upgrade_owner_with_transport(client, group_access_hash, opened).await
}

/// Authenticate the owner, cut Telegram access, and publish the signed cutoff.
pub async fn revoke_device(
    volume: &str,
    installation_id: uuid::Uuid,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    telegram_session: Option<i64>,
    log_out_all_other_telegram_sessions: bool,
    confirmed_session_map: Option<&std::path::Path>,
) -> Result<()> {
    anyhow::ensure!(
        !installation_id.is_nil(),
        "device revoke requires a real installation UUID"
    );
    anyhow::ensure!(password_file.is_some() || recovery_file.is_some() || std::io::stdin().is_terminal(),
        "device revoke requires the existing volume credential: without a terminal, supply --password-file PATH (`-` reads stdin) or --recovery-file PATH");
    let all_confirmed = if log_out_all_other_telegram_sessions {
        eprintln!("WARNING: This signs out EVERY other Telegram session on the account. Type YES to continue.");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        anyhow::ensure!(
            answer.trim() == "YES",
            "confirmation declined; no Telegram sessions were reset"
        );
        true
    } else {
        false
    };
    let confirmed_sessions = confirmed_session_map
        .map(revocation::load_confirmed_session_map)
        .transpose()?
        .unwrap_or_default();
    let volumes_dir = manager::default_volumes_dir();
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;
    let admin = revocation::lock_owner_administration(&volumes_dir.join(&volume_id))?;
    let opened = utils::open_volume_any(&volume_id, password_file, recovery_file, &volumes_dir)?;
    #[cfg(test)]
    if let Ok(client) = super::key::TEST_PORTABLE_TRANSPORT.try_with(Arc::clone) {
        return revocation::command_in_transaction(
            client,
            &opened,
            installation_id,
            telegram_session,
            all_confirmed,
            &confirmed_sessions,
            &admin,
        )
        .await;
    }
    let client = Arc::new(connect_user_session().await?);
    revocation::command_in_transaction(
        client,
        &opened,
        installation_id,
        telegram_session,
        all_confirmed,
        &confirmed_sessions,
        &admin,
    )
    .await
}

/// Check the candidate against current local credential policy without prompting
/// or incrementing password lockout counters. No remote access has been cut yet.
#[cfg(feature = "key-rotation")]
pub(crate) fn validate_replacement_password(
    opened: &manager::OpenVolumeResult,
    password: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        password.len() >= 8,
        "new volume passphrase must be at least 8 bytes"
    );
    let reused = if opened.config.key_protection.is_some() {
        use teagarden_mfa::kslot::{
            protector::SlotProtector,
            protectors::{Argon2Cost, PassphraseProtector},
            vault::SlotVault,
        };
        let vault = SlotVault::load(
            opened
                .paths
                .base_dir
                .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME),
        )?;
        let protector = PassphraseProtector::new(password.to_vec(), Argon2Cost::default());
        vault.unlock(&[&protector as &dyn SlotProtector]).is_ok()
    } else {
        let root = teagarden_core::crypto::kdf::derive_root_key(
            password,
            &opened.config.salt,
            &opened.config.kdf_params,
        )?;
        root.as_bytes() == opened.hierarchy.root.as_bytes()
    };
    anyhow::ensure!(
        !reused,
        "replacement password must differ from every current password credential"
    );
    Ok(())
}

#[cfg(feature = "key-rotation")]
pub(crate) async fn rotate_root_command<T: ForumAdmin + 'static>(
    transport: Arc<T>,
    opened: &manager::OpenVolumeResult,
    password: &[u8],
) -> Result<()> {
    let access_hash = bind_opened_topic(transport.as_ref(), &opened.config).await?;
    revoke_device_with_transport(
        transport,
        access_hash,
        opened,
        uuid::Uuid::nil(),
        password,
        None,
        false,
        true,
    )
    .await
}

#[cfg(all(test, feature = "key-rotation"))]
async fn revoke_and_rotate_command<T: ForumAdmin + 'static>(
    client: Arc<T>,
    opened: &manager::OpenVolumeResult,
    installation_id: uuid::Uuid,
    new_password: &[u8],
    telegram_session: Option<i64>,
    log_out_all_other_telegram_sessions: bool,
) -> Result<()> {
    let group_access_hash = bind_opened_topic(client.as_ref(), &opened.config).await?;
    revoke_device_with_transport(
        client,
        group_access_hash,
        opened,
        installation_id,
        new_password,
        telegram_session,
        log_out_all_other_telegram_sessions,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "key-rotation")]
async fn revoke_device_with_transport<T: ForumAdmin + 'static>(
    transport: Arc<T>,
    group_access_hash: i64,
    opened: &manager::OpenVolumeResult,
    installation_id: uuid::Uuid,
    new_password: &[u8],
    telegram_session: Option<i64>,
    log_out_all_other_telegram_sessions: bool,
    confirmation_accepted: bool,
) -> Result<()> {
    anyhow::ensure!(
        !log_out_all_other_telegram_sessions || confirmation_accepted,
        "confirmation declined; no Telegram sessions were reset"
    );

    let admin = manager::OwnerAdminLock::acquire(&opened.paths.base_dir)?;
    let config: VolumeConfig = serde_json::from_slice(&std::fs::read(&opened.paths.config_path)?)?;
    manager::verify_config_anchors(&config, &opened.hierarchy)?;
    let refreshed = manager::OpenVolumeResult {
        config,
        paths: manager::VolumePaths::new(opened.paths.base_dir.clone()),
        hierarchy: opened.hierarchy.clone(),
    };
    let opened = &refreshed;
    let rotation_only = installation_id.is_nil();
    transport.select_topic(
        opened.config.telegram_group_id,
        group_access_hash,
        opened.config.telegram_topic_id,
    )?;
    let signing_key = load_owner_capability(&opened.paths.config_path)
        .context("owner signing capability is required before revocation")?;
    let pinned = opened
        .config
        .sdo_owner_public_key
        .as_deref()
        .context("volume has not been upgraded to owner-signed TGHD2")?;
    anyhow::ensure!(
        hex::encode(signing_key.verifying_key().to_bytes()) == pinned,
        "owner capability does not match the pinned TGHD2 public key"
    );
    let operation_path = opened
        .paths
        .base_dir
        .join(format!("owner-revoke-{installation_id}.json"));
    if opened.config.sdo_header_pending
        || operation_path.exists()
            && std::fs::read(&operation_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .and_then(|state| {
                    state
                        .get("phase")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .is_some_and(|phase| {
                    matches!(
                        phase.as_str(),
                        "generation_header_published"
                            | "migration_pending"
                            | "history_migration_complete"
                    )
                })
    {
        let mut operation: serde_json::Value = if operation_path.exists()
            && !(rotation_only
                && std::fs::read(&operation_path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .is_some_and(|operation| operation["phase"] == "complete"))
        {
            serde_json::from_slice(&std::fs::read(&operation_path)?)
                .context("read resumable owner revocation state")?
        } else {
            serde_json::json!({"installation_id": installation_id, "phase":"access_cut"})
        };
        anyhow::ensure!(
            operation
                .get("installation_id")
                .and_then(serde_json::Value::as_str)
                == Some(installation_id.to_string().as_str()),
            "resumable owner operation belongs to a different installation"
        );
        let mut header = if opened.config.sdo_header_pending {
            let bytes = hex::decode(
                opened
                    .config
                    .sdo_header_pending_bytes
                    .as_deref()
                    .context("pending rotation header bytes are missing")?,
            )
            .context("decode pending rotation header")?;
            let pending = HeaderDocument::decode(&bytes, &opened.hierarchy.integrity)
                .context("authenticate exact pending rotation header")?;
            let mut scan_header = pending.clone();
            scan_header.generation_boundary_message_id = Some(i64::MAX);
            let resumed_scan = scan_topic_sdo_objects(
                transport.as_ref(),
                opened.config.telegram_group_id,
                opened.config.telegram_topic_id,
                &scan_header,
                &opened.hierarchy,
            )
            .await
            .context("rebuild registry before resuming per-device key handoff")?;
            let new_salt: [u8; 32] = hex::decode(&pending.salt)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("pending TGHD2 salt is not 32 bytes"))?;
            publish_missing_device_key_updates(
                transport.as_ref(),
                &resumed_scan,
                &pending,
                &opened.hierarchy,
                opened.hierarchy.root.as_bytes(),
                &new_salt,
                installation_id,
                &signing_key,
            )
            .await
            .context("publish remaining-device key handoffs before retrying the rotation header")?;
            let first_id = publish_signed_header_update_in_transaction(
                transport.as_ref(),
                &opened.config,
                &opened.hierarchy,
                &opened.paths.config_path,
                opened.config.sdo_header_revision_published,
                pending.clone(),
                &admin,
            )
            .await
            .context("retry exact pending rotation header")?;
            operation["phase"] = serde_json::Value::String("generation_header_published".into());
            operation["generation_boundary_message_id"] = serde_json::json!(first_id);
            teagarden_core::fsutil::write_file_atomic(
                &operation_path,
                &serde_json::to_vec_pretty(&operation)?,
                "owner revocation state",
            )?;
            pending
        } else {
            let (info, header, _) = discover_latest_header(
                transport.as_ref(),
                opened.config.telegram_group_id,
                opened.config.telegram_topic_id,
                &opened.hierarchy.integrity,
                Some(pinned),
            )
            .await?
            .context("discover rotated owner header while resuming migration")?;
            if header.generation_boundary_message_id.is_none() {
                operation["generation_boundary_message_id"] = operation
                    .get("generation_boundary_message_id")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(info.message_id));
            }
            header
        };
        anyhow::ensure!(
            header.owner_public_key.as_deref() == Some(pinned)
                && if rotation_only {
                    operation["access_removal"] == "none_root_rotation"
                        && !header.revoked_device_ids.contains(&uuid::Uuid::nil())
                } else {
                    header.revoked_device_ids.contains(&installation_id)
                },
            "rotated header does not authenticate the requested device revocation"
        );
        if header.generation_boundary_message_id.is_none() {
            let first_id = operation
                .get("generation_boundary_message_id")
                .and_then(serde_json::Value::as_i64)
                .context("first rotation header message ID was not persisted")?;
            set_generation_boundary(&mut header, first_id, installation_id)?;
            let expected_revision = header.revision;
            publish_signed_header_update_in_transaction(
                transport.as_ref(),
                &opened.config,
                &opened.hierarchy,
                &opened.paths.config_path,
                expected_revision,
                header,
                &admin,
            )
            .await
            .context("publish persisted generation boundary during migration resume")?;
        }
        operation["phase"] = serde_json::Value::String("migration_pending".into());
        teagarden_core::fsutil::write_file_atomic(
            &operation_path,
            &serde_json::to_vec_pretty(&operation)?,
            "owner revocation state",
        )?;
        let migrated = finish_history_migration(
            transport.as_ref(),
            &opened.config,
            &opened.hierarchy,
            &opened.paths.config_path,
            &operation_path,
            &mut operation,
            &admin,
        )
        .await?;
        println!("Revocation complete. Re-encrypted {migrated} retained history version(s).");
        return Ok(());
    }
    validate_replacement_password(opened, new_password)?;
    let (_header_info, mut header, _) = discover_latest_header(
        transport.as_ref(),
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &opened.hierarchy.integrity,
        Some(pinned),
    )
    .await?
    .context("no authenticated portable header exists")?;
    anyhow::ensure!(
        header.format == 2,
        "device revocation requires an owner-signed TGHD2 header"
    );
    anyhow::ensure!(
        header.owner_public_key.as_deref() == Some(pinned),
        "latest TGHD2 owner key does not match the local capability"
    );
    if header.revoked_device_ids.contains(&installation_id) {
        if operation_path.exists() {
            let mut operation: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&operation_path)?)
                    .context("read resumable owner revocation state")?;
            if operation.get("phase").and_then(serde_json::Value::as_str) == Some("access_cut") {
                operation["phase"] =
                    serde_json::Value::String("header_published_rotation_pending".into());
                operation["header_message_id"] = serde_json::json!(_header_info.message_id);
                teagarden_core::fsutil::write_file_atomic(
                    &operation_path,
                    &serde_json::to_vec_pretty(&operation)?,
                    "owner revocation state",
                )?;
            }
            anyhow::bail!("access removal and signed revocation are recorded, but credential rotation and history migration are not complete; operation state is retained at {}", operation_path.display());
        }
        anyhow::bail!("installation {installation_id} is already revoked");
    }
    let scan = scan_topic_sdo_objects(
        transport.as_ref(),
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &header,
        &opened.hierarchy,
    )
    .await?;
    let device = if rotation_only {
        None
    } else {
        Some(
            scan.registry
                .get(&installation_id)
                .cloned()
                .with_context(|| {
                    format!("installation {installation_id} is not in the active registry")
                })?,
        )
    };
    if let Some(explicit) = telegram_session {
        let target = device
            .as_ref()
            .context("session override requires a device target")?;
        let bound = target
            .authorization_session_hash
            .as_deref()
            .and_then(parse_authorization_hash)
            .context(
                "authenticated target binding is missing; cannot correlate a session override",
            )?;
        anyhow::ensure!(
            explicit == bound,
            "Telegram session override does not match the authenticated target binding"
        );
    }
    let devices_without_handoff_key: Vec<_> = scan
        .registry
        .iter()
        .filter(|(id, _)| **id != installation_id)
        .filter_map(|(id, announcement)| {
            (announcement.public_key.is_none() || !scan.device_authorities.contains_key(id))
                .then_some(*id)
        })
        .collect();
    anyhow::ensure!(
        devices_without_handoff_key.is_empty(),
        "cannot rotate while remaining installations lack key-handoff public keys: {}. Mount each remaining installation with a current TeaGarden client so it publishes its per-device keypair, then retry",
        devices_without_handoff_key.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
    );

    let mut operation: serde_json::Value = if operation_path.exists() {
        serde_json::from_slice(&std::fs::read(&operation_path)?)
            .context("read resumable owner revocation state")?
    } else {
        serde_json::json!({
            "installation_id": installation_id,
            "phase": "prepared",
            "created_at_unix": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    };
    anyhow::ensure!(
        operation
            .get("installation_id")
            .and_then(serde_json::Value::as_str)
            == Some(installation_id.to_string().as_str()),
        "resumable owner operation belongs to a different installation"
    );
    if operation.get("phase").and_then(serde_json::Value::as_str) == Some("prepared") {
        if rotation_only {
            operation["access_removal"] = serde_json::json!("none_root_rotation");
        } else {
            let device = device.as_ref().context("revocation target is missing")?;
            let current_user = transport.telegram_user_id().await?;
            if current_user != Some(device.telegram_user_id) {
                transport
                    .ban_group_member(
                        opened.config.telegram_group_id,
                        group_access_hash,
                        device.telegram_user_id,
                    )
                    .await
                    .context("access cut FAILED: Telegram refused channels.editBanned")?;
                operation["access_removal"] = serde_json::Value::String("group_ban".into());
            } else if let Some(hash) = telegram_session.or_else(|| {
                device
                    .authorization_session_hash
                    .as_deref()
                    .and_then(parse_authorization_hash)
            }) {
                let authorizations = transport.authorizations().await?;
                let target = authorizations
                    .iter()
                    .find(|authorization| authorization.hash == hash)
                    .context(
                        "the specified Telegram authorization hash was not found on this account",
                    )?;
                anyhow::ensure!(!target.current, "cannot revoke the owner's current Telegram authorization; run from a separate owner session");
                transport
                    .reset_authorization(hash)
                    .await
                    .context("access cut FAILED: Telegram refused account.resetAuthorization")?;
                operation["access_removal"] =
                    serde_json::Value::String("authorization_reset".into());
                header.revoked_account_bindings.push(
                    device
                        .authorization_session_hash
                        .clone()
                        .unwrap_or_default(),
                );
            } else if log_out_all_other_telegram_sessions {
                transport
                    .reset_other_authorizations()
                    .await
                    .context("access cut FAILED: Telegram refused auth.resetAuthorizations")?;
                operation["access_removal"] =
                    serde_json::Value::String("all_other_authorizations_reset".into());
            } else {
                let authorizations = transport.authorizations().await?;
                let listing = authorizations
                    .iter()
                    .filter(|a| !a.current)
                    .map(|a| {
                        format!(
                            "  hash={} | device model={} | app name={} | last active Unix={} ",
                            a.hash, a.device_model, a.app_name, a.date_active
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                anyhow::bail!("cannot safely identify the Telegram session for installation {installation_id}: its Telegram binding is unknown. No session was reset. Other account authorizations:\n{}\nUse 'teagarden device revoke <dev> --telegram-session <hash>' to end one specific session, or pass '--log-out-all-other-telegram-sessions' to sign out every other session.", if listing.is_empty() { "  (none)" } else { &listing });
            }
        }
        operation["phase"] = serde_json::Value::String("access_cut".into());
        teagarden_core::fsutil::write_file_atomic(
            &operation_path,
            &serde_json::to_vec_pretty(&operation)?,
            "owner revocation state",
        )?;
    }
    if !rotation_only {
        header.revoked_device_ids.push(installation_id);
    }
    let (mut slot_vault, master_key, recovery_sentence) =
        teagarden_mfa::unlock::create_rotation_credentials(new_password)
            .context("create independent replacement password and recovery credentials")?;
    let mut new_salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut new_salt);
    let vault_digest = slot_vault.state_digest();
    let (mut rotated_config, new_hierarchy) = manager::prepare_rotated_volume_config(
        &opened.config,
        master_key.as_bytes(),
        new_salt,
        slot_vault.generation(),
        &vault_digest,
    )
    .context("prepare volume config for the new master key")?;
    let vault_path = opened
        .paths
        .base_dir
        .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
    if opened.paths.base_dir.join("device-keypair.json").exists() {
        let (private, public) =
            load_or_create_device_keypair(&opened.paths.base_dir, &opened.hierarchy.wrapping)?;
        store_device_key_wrap(
            &opened.paths.base_dir,
            &new_hierarchy.wrapping,
            &private,
            &public,
        )?;
    }
    slot_vault
        .save(&vault_path)
        .context("persist replacement credential vault before its config anchor")?;
    let slot_vault_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vault_path)?)
            .context("read persisted replacement credential vault")?;
    let key_protection = serde_json::to_value(
        rotated_config
            .key_protection
            .as_ref()
            .context("replacement volume config has no key protection anchor")?,
    )?;
    let mut rotated_header = make_rotated_header(
        &header,
        &opened.hierarchy,
        &new_hierarchy,
        &new_salt,
        key_protection,
        slot_vault_json,
    )?;
    rotated_header
        .device_authorities
        .extend(scan.device_authorities.clone());
    let signing_key = load_owner_capability(&opened.paths.config_path)?;
    rotated_header.revision = rotated_config
        .sdo_header_revision_published
        .checked_add(1)
        .context("TGHD revision overflow")?;
    let pending_bytes = rotated_header
        .encode_v2(&new_hierarchy.integrity, &signing_key)
        .context("encode replacement-key revocation header")?;
    rotated_config.sdo_header_revision_reserved = rotated_header.revision;
    rotated_config.sdo_header_pending = true;
    rotated_config.sdo_header_pending_sha256 = Some(hex::encode(
        teagarden_core::block::srb2::sha256(&pending_bytes),
    ));
    rotated_config.sdo_header_pending_bytes = Some(hex::encode(&pending_bytes));
    manager::save_config_resealed_in_transaction(
        &mut rotated_config,
        &new_hierarchy,
        &opened.paths.config_path,
        &admin,
    )
    .context("persist exact replacement-key header bytes before upload")?;
    let new_key_generation = rotated_header.key_generation.unwrap_or_default();
    publish_missing_device_key_updates(
        transport.as_ref(),
        &scan,
        &rotated_header,
        &new_hierarchy,
        master_key.as_bytes(),
        &new_salt,
        installation_id,
        &signing_key,
    )
    .await
    .context("publish remaining-device key handoffs before the rotation header")?;
    let first_header_id = publish_signed_header_update_in_transaction(
        transport.as_ref(),
        &rotated_config,
        &new_hierarchy,
        &opened.paths.config_path,
        rotated_header.revision - 1,
        rotated_header.clone(),
        &admin,
    )
    .await
    .context("access was removed; replacement-key header publication remains pending")?;
    operation["phase"] = serde_json::Value::String("generation_header_published".into());
    operation["generation_boundary_message_id"] = serde_json::json!(first_header_id);
    teagarden_core::fsutil::write_file_atomic(
        &operation_path,
        &serde_json::to_vec_pretty(&operation)?,
        "owner revocation state",
    )?;

    set_generation_boundary(&mut rotated_header, first_header_id, installation_id)?;
    let boundary_header_id = publish_signed_header_update_in_transaction(
        transport.as_ref(),
        &rotated_config,
        &new_hierarchy,
        &opened.paths.config_path,
        rotated_header.revision,
        rotated_header,
        &admin,
    )
    .await
    .context("first generation header landed; persisting its boundary remains pending")?;
    operation["phase"] = serde_json::Value::String("migration_pending".into());
    operation["header_message_id"] = serde_json::json!(boundary_header_id);
    operation["new_key_generation"] = serde_json::json!(new_key_generation);
    teagarden_core::fsutil::write_file_atomic(
        &operation_path,
        &serde_json::to_vec_pretty(&operation)?,
        "owner revocation state",
    )?;
    eprintln!(
        "New volume recovery sentence (save it now): {}",
        recovery_sentence.as_str()
    );
    let migrated = finish_history_migration(
        transport.as_ref(),
        &rotated_config,
        &new_hierarchy,
        &opened.paths.config_path,
        &operation_path,
        &mut operation,
&admin,
)
    .await
    .context("replacement credentials and signed revocation are active; history migration remains resumable")?;
    println!("{} complete. Re-encrypted {migrated} retained history version(s) under key generation {new_key_generation}.", if rotation_only { "Root rotation" } else { "Revocation" });
    Ok(())
}

fn parse_authorization_hash(value: &str) -> Option<i64> {
    value
        .parse::<i64>()
        .ok()
        .or_else(|| {
            let bytes = hex::decode(value).ok()?;
            let bytes: [u8; 8] = bytes.try_into().ok()?;
            Some(i64::from_be_bytes(bytes))
        })
        .filter(|hash| *hash != 0)
}

#[cfg(test)]
async fn upgrade_owner_with_transport<T: ForumAdmin + 'static>(
    transport: Arc<T>,
    group_access_hash: i64,
    opened: &manager::OpenVolumeResult,
) -> Result<()> {
    let admin = manager::OwnerAdminLock::acquire(&opened.paths.base_dir)?;
    transport.select_topic(
        opened.config.telegram_group_id,
        group_access_hash,
        opened.config.telegram_topic_id,
    )?;
    let (_, _, credential_header_wire) = discover_latest_header(
        transport.as_ref(),
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &opened.hierarchy.integrity,
        opened.config.sdo_owner_public_key.as_deref(),
    )
    .await?
    .context("volume has no authenticated portable header")?;
    let legacy = super::decrypt::parse_header_json(&credential_header_wire)?;
    anyhow::ensure!(
        opened.config.sdo_owner_public_key.is_none() && legacy.format == 1,
        "owner upgrade is TGHD1 to TGHD2 only; an established owner cannot be replaced"
    );
    let signing_key = ensure_owner_capability(&opened.paths.config_path)?;
    let author_device_id = opened
        .config
        .sdo_author_device_id
        .unwrap_or_else(uuid::Uuid::new_v4);
    let (device_private, _) =
        load_or_create_device_keypair(&opened.paths.base_dir, &opened.hierarchy.wrapping)?;
    let conn = open_volume_db(opened)?;
    let schema = OpaqueSchema::new(opened.hierarchy.schema.clone(), &logical_tables());
    let block_transport: Arc<dyn BlockTransport> = transport.clone();
    let fs = CryptFs::new(
        conn,
        schema,
        opened.hierarchy.meta.clone(),
        opened.hierarchy.data.clone(),
        unsafe { libc::getuid() },
        unsafe { libc::getgid() },
    )
    .with_sdo(opened.config.volume_id, author_device_id)
    .with_sdo_signing_key(teagarden_core::sdo::device_signing_key(&device_private.0))
    .with_sdo_object_envelope(credential_header_wire, opened.hierarchy.clone())
    .with_block_keys(
        opened.hierarchy.block_id.clone(),
        opened.hierarchy.filename.clone(),
    )
    .with_manifest_key(opened.hierarchy.manifest.clone())
    .with_transport(block_transport)
    .with_runtime(tokio::runtime::Handle::current());
    let backfilled = tokio::task::spawn_blocking(move || fs.backfill_sdo_versions())
        .await
        .context("owner upgrade backfill worker failed")?
        .map_err(errno_to_anyhow)
        .context("backfill explicit directories and portable file history before TGHD2")?;

    let mut config = opened.config.clone();
    config.sdo_author_device_id = Some(author_device_id);
    config.sdo_owner_public_key = Some(hex::encode(signing_key.verifying_key().to_bytes()));
    let vault_path = config
        .key_protection
        .as_ref()
        .map(|_| opened.paths.base_dir.join("slot_vault.json"));
    manager::save_config_resealed_in_transaction(
        &mut config,
        &opened.hierarchy,
        &opened.paths.config_path,
        &admin,
    )?;
    publish_initial_header_in_transaction(
        transport.as_ref(),
        &config,
        &opened.hierarchy,
        &opened.paths.config_path,
        vault_path.as_deref(),
        &admin,
    )
    .await?;
    println!(
        "Published owner-signed TGHD2 revision for {}.",
        config.display_name
    );
    println!("  Explicit objects backfilled: {backfilled}");
    println!(
        "  Owner public key: {}",
        config.sdo_owner_public_key.as_deref().unwrap_or_default()
    );
    println!(
        "  Signing capability: {}",
        owner_capability_path(&opened.paths.config_path)?.display()
    );
    Ok(())
}

/// Core volume creation logic, separated for testability.
///
/// `channel_id` / `channel_access_hash` must be the values from a Telegram channel
/// that was already created before calling this. Pass `(0, 0)` for offline volumes.
pub async fn create_with_password(
    name: Option<&str>,
    password: &str,
    volumes_dir: &std::path::Path,
    group_id: i64,
    group_access_hash: i64,
    topic_id: i64,
    block_size: Option<u64>,
) -> Result<teagarden_api::types::CreateVolumeResponse> {
    let svc = VolumeService::new(volumes_dir.to_path_buf());
    svc.create(
        name,
        password,
        group_id,
        group_access_hash,
        topic_id,
        block_size,
    )
    .await
    .map_err(utils::api_err)
}

pub async fn create(
    name: Option<String>,
    password_file: Option<&str>,
    key_protection: bool,
    group_name: Option<String>,
) -> Result<()> {
    let volumes_dir = manager::default_volumes_dir();

    let password = if password_file.is_some() {
        utils::read_password_input(password_file)?
    } else {
        let password = utils::prompt_password("Enter volume password: ")?;
        let confirm = utils::prompt_password("Confirm password: ")?;
        if password.as_str() != confirm.as_str() {
            anyhow::bail!("Passwords do not match");
        }
        password
    };

    let display_name: String = name
        .clone()
        .unwrap_or_else(volume_names::generate_group_name);

    // All local input is checked before Telegram is contacted at all.
    validate_create_input(&password, None)?;

    // Forum-only: every volume is a topic in the ONE shared storage supergroup,
    // so Telegram is required.
    let client = connect_user_session().await.map_err(|e| {
        anyhow::anyhow!(
            "Telegram is required to create a volume (forum storage): {e}. \
             Run `teagarden auth login` first."
        )
    })?;
    create_command(
        &client,
        &super::group::group_config_path()?,
        &volumes_dir,
        &display_name,
        &password,
        None,
        key_protection,
        group_name.as_deref(),
    )
    .await
    .map(|_| ())
}

/// What `volume create` prints about recovery for a password-rooted volume
/// (the default type).
const PASSWORD_ROOTED_CREATE_NOTE: &str = "This volume is password-rooted: it has no separate \
     recovery file, so the password is the only way in. `teagarden key export` prints a \
     recovery sentence for its key-hierarchy root; `teagarden volume create --key-protection` \
     creates a volume with a recovery slot instead.";

/// Smallest and largest `--block-size` accepted. The largest is the cloud-bot
/// ceiling `BlockConfig::fuse_chunk_size` caps to, so an accepted value is used
/// as given (rounded down to a multiple of 512 bytes, the upload part unit).
const MIN_BLOCK_SIZE: u64 = 512 * 1024;
const MAX_BLOCK_SIZE: u64 = 48_000_000;

fn validate_block_size(block_size: Option<u64>) -> Result<()> {
    if let Some(bs) = block_size {
        if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&bs) {
            anyhow::bail!(
                "--block-size must be between {MIN_BLOCK_SIZE} (512 KiB) and {MAX_BLOCK_SIZE} \
                 bytes; got {bs}"
            );
        }
    }
    Ok(())
}

/// Every check on `volume create`'s local input, run before any Telegram call so
/// a refused volume never leaves a storage group or forum topic behind.
fn validate_create_input(password: &str, block_size: Option<u64>) -> Result<()> {
    validate_block_size(block_size)?;
    if password.len() < 8 {
        anyhow::bail!("password must be at least 8 characters");
    }
    Ok(())
}

/// [`create`] once the password is known and a forum admin (the user's
/// Telegram session, or the test transport) is at hand. Returns
/// `(volume id, topic id)`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_command(
    forum: &dyn ForumAdmin,
    group_path: &std::path::Path,
    volumes_dir: &std::path::Path,
    display_name: &str,
    password: &str,
    block_size: Option<u64>,
    key_protection: bool,
    group_name: Option<&str>,
) -> Result<(String, i64)> {
    validate_create_input(password, block_size)?;

    // Provision the topic so its id can be baked into the KDF.
    let (group_id, group_access_hash, topic_id) =
        ensure_group_and_topic(forum, group_path, group_name)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Telegram is required to create a volume (forum storage): {e}. \
                 Run `teagarden auth login` first."
                )
            })?;
    forum
        .select_topic(group_id, group_access_hash, topic_id)
        .context("select the new Telegram topic for portable-object uploads")?;

    if key_protection {
        // MK-rooted multi-factor volume (K0b): the passphrase becomes one slot and
        // a recovery co-slot is auto-enrolled. Real protection — a bare password
        // cannot open it. This path does NOT go through VolumeService (the api
        // crate has no mfa dependency) and deliberately does NOT emit a root-key
        // "sentence reference" (that would bypass the vault).
        if password.len() < 8 {
            anyhow::bail!("password must be at least 8 characters");
        }
        let pc = teagarden_mfa::unlock::create_protected_volume(
            Some(display_name),
            password.as_bytes(),
            volumes_dir,
            group_id,
            group_access_hash,
            topic_id,
            block_size,
        )
        .map_err(|e| anyhow::anyhow!("create protected volume: {e}"))?;

        let vault_path = pc.created.paths.base_dir.join("slot_vault.json");
        publish_initial_header(
            forum,
            &pc.created.config,
            &pc.created.hierarchy,
            &pc.created.paths.config_path,
            Some(&vault_path),
        )
        .await?;

        println!(
            "  Owner public key: {}",
            hex::encode(
                load_owner_capability(&pc.created.paths.config_path)?
                    .verifying_key()
                    .to_bytes()
            )
        );
        println!("Volume created successfully (key-protected).");
        println!("  Name:       {}", pc.created.config.display_name);
        println!("  Volume ID:  {}", pc.created.config.volume_id);
        println!("  Group ID:   {group_id}");
        println!("  Topic ID:   {topic_id}  (group + topic baked into key derivation)");
        println!();
        println!("Key slots — any one enrolled slot opens the volume (like LUKS). It has two:");
        println!("the passphrase you just set, and the recovery sentence below; either one");
        println!("ALONE opens it. `keyslot enroll` adds a device slot (TPM2, Tang, PKCS#11,");
        println!("FIDO2): another way in, never a requirement. `keyslot remove-slot` can remove");
        println!("the passphrase slot, but at least one passphrase or recovery slot always");
        println!("remains, so this recovery sentence keeps opening the volume without any device.");
        println!();
        println!("RECOVERY SENTENCE (write it down OFFLINE now — shown only once):");
        println!("  {}", pc.recovery_sentence.as_str());
        println!();
        println!(
            "Mount later with:  teagarden volume mount {} <mountpoint>",
            pc.created.config.volume_id
        );
        println!("  (enter the passphrase, or pass the sentence via --recovery-file)");
        println!();
        println!("IMPORTANT: lose BOTH the passphrase AND this sentence and the data is gone.");
        return Ok((pc.created.config.volume_id.to_string(), topic_id));
    }

    let resp = create_with_password(
        Some(display_name),
        password,
        volumes_dir,
        group_id,
        group_access_hash,
        topic_id,
        block_size,
    )
    .await?;

    let opened = manager::open_volume(&resp.volume_id, password.as_bytes(), volumes_dir)
        .context("reopen newly created volume to publish its portable header")?;
    publish_initial_header(
        forum,
        &opened.config,
        &opened.hierarchy,
        &opened.paths.config_path,
        None,
    )
    .await?;

    println!(
        "  Owner public key: {}",
        hex::encode(
            load_owner_capability(&opened.paths.config_path)?
                .verifying_key()
                .to_bytes()
        )
    );
    println!("Volume created successfully.");
    println!("  Name:       {}", resp.display_name);
    println!("  Volume ID:  {}", resp.volume_id);
    println!("  Group ID:   {group_id}");
    println!("  Topic ID:   {topic_id}  (group + topic baked into key derivation)");
    println!();
    println!("IMPORTANT: Store your password and volume directory securely.");
    println!("{PASSWORD_ROOTED_CREATE_NOTE}");

    Ok((resp.volume_id.to_string(), topic_id))
}

/// Reserve and publish the first authenticated TGHD before volume creation reports success.
/// The config records a pending revision before the network call, so a timeout or lost
/// Telegram acknowledgement cannot be mistaken for a portable volume.
pub(super) async fn publish_initial_header(
    transport: &dyn ForumAdmin,
    config: &VolumeConfig,
    hierarchy: &KeyHierarchy,
    config_path: &std::path::Path,
    vault_path: Option<&std::path::Path>,
) -> Result<()> {
    let admin = manager::OwnerAdminLock::acquire(
        config_path
            .parent()
            .context("volume config has no parent")?,
    )?;
    publish_initial_header_in_transaction(
        transport,
        config,
        hierarchy,
        config_path,
        vault_path,
        &admin,
    )
    .await
}

async fn publish_initial_header_in_transaction(
    transport: &dyn BlockTransport,
    _config: &VolumeConfig,
    hierarchy: &KeyHierarchy,
    config_path: &std::path::Path,
    vault_path: Option<&std::path::Path>,
    admin: &manager::OwnerAdminLock,
) -> Result<()> {
    admin.require_config(config_path)?;
    let mut config: VolumeConfig = serde_json::from_slice(&std::fs::read(config_path)?)?;
    manager::verify_config_anchors(&config, hierarchy)?;
    if config.sdo_owner_public_key.is_none() && config.sdo_header_revision_published == 0 {
        let owner = ensure_owner_capability(config_path)?;
        config.sdo_owner_public_key = Some(hex::encode(owner.verifying_key().to_bytes()));
    }
    let revision = if config.sdo_header_pending
        && config.sdo_header_revision_reserved > config.sdo_header_revision_published
    {
        config.sdo_header_revision_reserved
    } else {
        config
            .sdo_header_revision_reserved
            .max(config.sdo_header_revision_published)
            .checked_add(1)
            .context("portable header revision overflow")?
    };
    let root_kind = if config.key_protection.is_some() {
        RootKind::MasterKey
    } else {
        RootKind::Password
    };
    let slot_vault = match (&root_kind, vault_path) {
        (RootKind::MasterKey, Some(path)) => {
            let bytes =
                std::fs::read(path).context("read encrypted slot vault for portable header")?;
            Some(serde_json::from_slice(&bytes).context("parse slot vault for portable header")?)
        }
        (RootKind::Password, None) => None,
        _ => anyhow::bail!("portable header root kind and slot vault disagree"),
    };
    let owner_signing_key = config
        .sdo_owner_public_key
        .as_ref()
        .map(|expected| {
            let signing_key = load_owner_capability(config_path)?;
            let actual = hex::encode(signing_key.verifying_key().to_bytes());
            if actual != *expected {
                anyhow::bail!("owner capability does not match the pinned TGHD2 public key");
            }
            Ok::<_, anyhow::Error>(signing_key)
        })
        .transpose()?;
    let header = HeaderDocument {
        format: if owner_signing_key.is_some() { 2 } else { 1 },
        volume_id: config.volume_id,
        revision,
        volume_version: config.volume_version.to_string(),
        root_kind,
        salt: hex::encode(config.salt),
        kdf_params: config
            .key_protection
            .is_none()
            .then(|| config.kdf_params.clone()),
        group_id: config.telegram_group_id,
        topic_id: config.telegram_topic_id,
        current_epoch: config.current_epoch,
        block_v2_from_epoch: config.block_v2_from_epoch,
        require_block_integrity: config.require_block_integrity,
        block_size: config.block_config.target_block_size,
        key_protection: config
            .key_protection
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .context("serialize key-protection anchor")?,
        slot_vault,
        owner_public_key: config.sdo_owner_public_key.clone(),
        key_generation: owner_signing_key.as_ref().map(|_| 0),
        revoked_device_ids: Vec::new(),
        revoked_account_bindings: Vec::new(),
        retained_key_bridges: Vec::new(),
        device_authorities: std::collections::BTreeMap::new(),
        rotation_state: None,
        generation_boundary_message_id: None,
        generation_cutoffs: Default::default(),
        revocation_cutoffs: Default::default(),
    };
    let bytes = match owner_signing_key.as_ref() {
        Some(signing_key) => header
            .encode_v2(&hierarchy.integrity, signing_key)
            .context("encode owner-signed TGHD2 header")?,
        None => header
            .encode(&hierarchy.integrity)
            .context("encode portable TGHD1 header")?,
    };
    let header_hash = hex::encode(teagarden_core::block::srb2::sha256(&bytes));
    if config.sdo_header_pending {
        match config.sdo_header_pending_sha256.as_deref() {
            Some(expected) if expected == header_hash => {}
            Some(_) => anyhow::bail!(
                "pending portable header bytes changed; reserve a new revision before publishing"
            ),
            None => anyhow::bail!(
                "pending portable header has no byte digest; refusing to reuse its revision"
            ),
        }
    }
    config.sdo_header_revision_reserved = revision;
    config.sdo_header_pending = true;
    config.sdo_header_pending_sha256 = Some(header_hash);
    config.sdo_header_pending_bytes = Some(hex::encode(&bytes));
    manager::save_config_resealed_in_transaction(&mut config, hierarchy, config_path, admin)
        .context("persist pending portable-header revision")?;

    let upload = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        transport.upload_block(&bytes, "teagarden-header-v1.tgh"),
    )
    .await
    .map_err(|e| anyhow::anyhow!("local volume was created; header revision {revision} remains pending publication after timeout: {e}"))?
    .map_err(|e| anyhow::anyhow!("local volume was created; header revision {revision} remains pending publication because upload was not acknowledged: {e}"))?;
    tracing::info!(
        message_id = upload.message_id,
        revision,
        "published portable volume header"
    );

    acknowledge_owner_header(config_path, hierarchy, revision, &bytes, admin)?;
    Ok(())
}

/// Authenticate the current owner header before any local global-slot mutation.
pub(super) async fn prepare_slot_header_update(
    transport: &dyn ForumAdmin,
    opened: &manager::OpenVolumeResult,
    admin: &manager::OwnerAdminLock,
) -> Result<()> {
    admin.require_config(&opened.paths.config_path)?;
    let pin = opened
        .config
        .sdo_owner_public_key
        .as_deref()
        .context("slot publication requires an owner-signed TGHD2 volume")?;
    let owner = load_owner_capability(&opened.paths.config_path)
        .context("global slot changes require the owner capability")?;
    anyhow::ensure!(
        hex::encode(owner.verifying_key().to_bytes()) == pin,
        "owner capability differs from the pinned owner"
    );
    anyhow::ensure!(
        !opened.config.sdo_header_pending,
        "portable header publication is pending; mount to repair it before changing slots"
    );
    bind_opened_topic(transport, &opened.config).await?;
    let (_, header, wire) = discover_latest_header(
        transport,
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &opened.hierarchy.integrity,
        Some(pin),
    )
    .await?
    .context("volume has no authenticated current header")?;
    policy::observe(&opened.paths.config_path, &header)?;
    anyhow::ensure!(header.format==2 && header.root_kind==RootKind::MasterKey && header.revision==opened.config.sdo_header_revision_published && header.key_protection==opened.config.key_protection.as_ref().map(serde_json::to_value).transpose()?,"current owner header and local published vault anchors disagree; refresh owner state before changing slots");
    teagarden_core::fsutil::write_file_atomic(
        &opened.paths.base_dir.join(manager::OWNER_HEADER_FILENAME),
        &wire,
        "authenticated owner header for slot change",
    )?;
    Ok(())
}

/// Shared production path for publishing a changed local credential vault.
#[cfg(test)]
pub(super) async fn publish_slot_header_update(
    transport: &dyn ForumAdmin,
    opened: &manager::OpenVolumeResult,
) -> Result<()> {
    let admin = manager::OwnerAdminLock::acquire(&opened.paths.base_dir)?;
    publish_slot_header_update_in_transaction(transport, opened, &admin).await
}

pub(super) async fn publish_slot_header_update_in_transaction(
    transport: &dyn ForumAdmin,
    opened: &manager::OpenVolumeResult,
    admin: &manager::OwnerAdminLock,
) -> Result<()> {
    admin.require_config(&opened.paths.config_path)?;
    bind_opened_topic(transport, &opened.config).await?;
    load_owner_capability(&opened.paths.config_path)
        .context("global slot changes require the owner capability")?;
    let (_, mut header, _) = discover_latest_header(
        transport,
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &opened.hierarchy.integrity,
        opened.config.sdo_owner_public_key.as_deref(),
    )
    .await?
    .context("volume has no authenticated current header")?;
    policy::observe(&opened.paths.config_path, &header)?;
    anyhow::ensure!(
        header.format == 2 && header.root_kind == RootKind::MasterKey,
        "slot publication requires an owner-signed master-key header"
    );
    let vault_path = opened
        .paths
        .base_dir
        .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
    let vault_bytes = std::fs::read(vault_path).context("read changed credential vault")?;
    let vault = teagarden_mfa::kslot::vault::SlotVault::from_bytes(&vault_bytes)?;
    let anchor = opened
        .config
        .key_protection
        .as_ref()
        .context("changed config has no vault anchor")?;
    anyhow::ensure!(
        anchor.vault_generation == vault.generation()
            && anchor.vault_digest == hex::encode(vault.state_digest()),
        "changed vault does not match the local authenticated anchor"
    );
    // Mutate only these two fields of the current owner-authenticated header.
    header.slot_vault = Some(serde_json::from_slice(&vault_bytes)?);
    header.key_protection = Some(serde_json::to_value(anchor)?);
    let revision = header.revision;
    publish_signed_header_update_in_transaction(
        transport,
        &opened.config,
        &opened.hierarchy,
        &opened.paths.config_path,
        revision,
        header,
        admin,
    )
    .await?;
    Ok(())
}

/// Print the authenticated installation registry and Telegram authorizations.
pub async fn device_list(
    volume: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    let volumes_dir = manager::default_volumes_dir();
    let id = resolve_volume_id(volume, &volumes_dir)?;
    let opened = utils::open_volume_any(&id, password_file, recovery_file, &volumes_dir)?;
    #[cfg(test)]
    if let Ok(client) = super::key::TEST_PORTABLE_TRANSPORT.try_with(Arc::clone) {
        println!("{}", device_list_command(client.as_ref(), &opened).await?);
        return Ok(());
    }
    let client = connect_user_session().await?;
    println!("{}", device_list_command(&client, &opened).await?);
    Ok(())
}

async fn device_list_command(
    transport: &dyn ForumAdmin,
    opened: &manager::OpenVolumeResult,
) -> Result<String> {
    use std::fmt::Write as _;
    bind_opened_topic(transport, &opened.config).await?;
    let (_, header, _) = discover_latest_header(
        transport,
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &opened.hierarchy.integrity,
        opened.config.sdo_owner_public_key.as_deref(),
    )
    .await?
    .context("volume has no authenticated current header")?;
    policy::observe(&opened.paths.config_path, &header)?;
    let scan = scan_topic_sdo_objects(
        transport,
        header.group_id,
        header.topic_id,
        &header,
        &opened.hierarchy,
    )
    .await?;
    let mut output = String::new();
    writeln!(
        output,
        "This computer: {}",
        opened
            .config
            .sdo_author_device_id
            .map_or_else(|| "legacy/unregistered".into(), |id| id.to_string())
    )?;
    writeln!(output, "Installations:")?;
    for (id, installation) in scan.all_registry.iter() {
        let revoked = header.revoked_device_ids.contains(id)
            || installation
                .authorization_session_hash
                .as_ref()
                .is_some_and(|binding| header.revoked_account_bindings.contains(binding));
        writeln!(
            output,
            "  id={} name={:?} last_seen_ms={} revoked={} telegram_user={} binding={}",
            id,
            installation.label,
            installation.clock_ms,
            revoked,
            installation.telegram_user_id,
            installation
                .authorization_session_hash
                .as_deref()
                .filter(|value| parse_authorization_hash(value).is_some())
                .unwrap_or("unknown")
        )?;
    }
    writeln!(output, "Telegram authorizations:")?;
    for authorization in transport.authorizations().await? {
        writeln!(
            output,
            "  hash={} device_model={:?} app={:?} last_active={} current={}",
            authorization.hash,
            authorization.device_model,
            authorization.app_name,
            authorization.date_active,
            authorization.current
        )?;
    }
    Ok(output)
}

/// Publish the next owner-signed revision while retaining exact retry bytes in the
/// authenticated local config until Telegram acknowledges the upload.
#[cfg(test)]
async fn publish_signed_header_update(
    transport: &dyn ForumAdmin,
    config: &VolumeConfig,
    hierarchy: &KeyHierarchy,
    config_path: &std::path::Path,
    expected_revision: u64,
    header: HeaderDocument,
) -> Result<i64> {
    let admin = manager::OwnerAdminLock::acquire(
        config_path
            .parent()
            .context("volume config has no parent")?,
    )?;
    publish_signed_header_update_in_transaction(
        transport,
        config,
        hierarchy,
        config_path,
        expected_revision,
        header,
        &admin,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn publish_signed_header_update_in_transaction(
    transport: &dyn BlockTransport,
    _config: &VolumeConfig,
    hierarchy: &KeyHierarchy,
    config_path: &std::path::Path,
    expected_revision: u64,
    mut header: HeaderDocument,
    admin: &manager::OwnerAdminLock,
) -> Result<i64> {
    admin.require_config(config_path)?;
    let mut config: VolumeConfig = serde_json::from_slice(
        &std::fs::read(config_path).context("read local config for signed header update")?,
    )
    .context("parse local config for signed header update")?;
    manager::verify_config_anchors(&config, hierarchy)?;
    let pinned = config
        .sdo_owner_public_key
        .as_deref()
        .context("owner capability is not pinned for this volume")?;
    let signing_key = load_owner_capability(config_path)?;
    anyhow::ensure!(
        hex::encode(signing_key.verifying_key().to_bytes()) == pinned,
        "owner capability does not match the pinned TGHD2 public key"
    );
    anyhow::ensure!(header.format == 2, "owner header update requires TGHD2");
    anyhow::ensure!(
        header.volume_id == config.volume_id,
        "header volume ID mismatch"
    );
    anyhow::ensure!(
        header.owner_public_key.as_deref() == Some(pinned),
        "header owner key mismatch"
    );
    if config.sdo_header_pending {
        let bytes = hex::decode(
            config
                .sdo_header_pending_bytes
                .as_deref()
                .context("pending owner header has no durable retry bytes")?,
        )
        .context("decode durable pending owner header bytes")?;
        let digest = hex::encode(teagarden_core::block::srb2::sha256(&bytes));
        anyhow::ensure!(
            config.sdo_header_pending_sha256.as_deref() == Some(digest.as_str()),
            "pending owner header digest does not match its durable bytes"
        );
        let pending = HeaderDocument::decode(&bytes, &hierarchy.integrity)
            .context("authenticate durable pending owner header")?;
        anyhow::ensure!(
            pending.revision == config.sdo_header_revision_reserved
                && pending.volume_id == config.volume_id
                && pending.owner_public_key.as_deref() == Some(pinned),
            "pending owner header does not match its reserved volume revision"
        );
        pending.require_policy_successor(&header).context(
            "pending owner header is older than or inconsistent with current Telegram policy",
        )?;
        let upload = transport
            .upload_block(&bytes, "teagarden-header-v1.tgh")
            .await
            .context("owner-signed header upload failed; exact bytes remain pending")?;
        acknowledge_owner_header(config_path, hierarchy, pending.revision, &bytes, admin)?;
        return Ok(upload.message_id);
    }
    anyhow::ensure!(
        !config.sdo_header_pending,
        "a signed header revision is already pending; repair it before starting another update"
    );
    anyhow::ensure!(
        config.sdo_header_revision_published == expected_revision,
        "Telegram header revision changed; refresh owner state before retrying"
    );
    let revision = expected_revision
        .checked_add(1)
        .context("portable header revision overflow")?;
    header.revision = revision;
    let bytes = header
        .encode_v2(&hierarchy.integrity, &signing_key)
        .context("encode owner-signed TGHD2 update")?;
    let digest = hex::encode(teagarden_core::block::srb2::sha256(&bytes));
    config.sdo_header_revision_reserved = revision;
    config.sdo_header_pending = true;
    config.sdo_header_pending_sha256 = Some(digest);
    config.sdo_header_pending_bytes = Some(hex::encode(&bytes));
    manager::save_config_resealed_in_transaction(&mut config, hierarchy, config_path, admin)
        .context("persist pending owner-signed header bytes")?;
    let upload = transport
        .upload_block(&bytes, "teagarden-header-v1.tgh")
        .await
        .context("owner-signed header upload failed; exact bytes remain pending")?;
    acknowledge_owner_header(config_path, hierarchy, revision, &bytes, admin)?;
    Ok(upload.message_id)
}

fn acknowledge_owner_header(
    config_path: &std::path::Path,
    hierarchy: &KeyHierarchy,
    revision: u64,
    bytes: &[u8],
    admin: &manager::OwnerAdminLock,
) -> Result<()> {
    admin.require_config(config_path)?;
    let mut current: VolumeConfig = serde_json::from_slice(
        &std::fs::read(config_path).context("reload current owner state after upload")?,
    )?;
    manager::verify_config_anchors(&current, hierarchy)?;
    let digest = hex::encode(teagarden_core::block::srb2::sha256(bytes));
    anyhow::ensure!(
        current.sdo_header_pending
            && current.sdo_header_revision_reserved == revision
            && current.sdo_header_pending_sha256.as_deref() == Some(digest.as_str())
            && current.sdo_header_pending_bytes.as_deref() == Some(hex::encode(bytes).as_str()),
        "pending owner state changed during upload; refusing stale acknowledgement"
    );
    let authenticated = HeaderDocument::decode_pinned(
        bytes,
        &hierarchy.integrity,
        current.sdo_owner_public_key.as_deref(),
    )?;
    anyhow::ensure!(
        authenticated.volume_id == current.volume_id && authenticated.revision == revision,
        "acknowledged header differs from current volume revision"
    );
    teagarden_core::fsutil::write_file_atomic(
        &config_path
            .parent()
            .unwrap()
            .join(manager::OWNER_HEADER_FILENAME),
        bytes,
        "acknowledged owner header",
    )?;
    current.sdo_header_revision_published = revision;
    current.sdo_header_pending = false;
    current.sdo_header_pending_sha256 = None;
    current.sdo_header_pending_bytes = None;
    manager::save_config_resealed_in_transaction(&mut current, hierarchy, config_path, admin)?;
    Ok(())
}

/// Attach a fresh local volume identity to an existing Telegram forum topic.
pub async fn attach(
    group_topic: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    owner_public_key: Option<&str>,
) -> Result<()> {
    if password_file.is_some() && recovery_file.is_some() {
        anyhow::bail!("choose only one of --password-file and --recovery-file");
    }
    let (group, topic) = group_topic
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("expected GROUP_ID:TOPIC_ID"))?;
    let group_id: i64 = group
        .parse()
        .context("GROUP_ID must be a Telegram integer")?;
    let topic_id: i64 = topic
        .parse()
        .context("TOPIC_ID must be a Telegram integer")?;
    if topic_id <= 0 {
        anyhow::bail!("TOPIC_ID must be positive");
    }

    let (credential, recovery) =
        if let Some(sentence) = utils::read_recovery_sentence(recovery_file)? {
            (sentence, true)
        } else {
            (utils::read_password_input(password_file)?, false)
        };
    let client = connect_user_session().await?;
    let attached = attach_command(
        &client,
        group_id,
        topic_id,
        credential.as_bytes(),
        recovery,
        &manager::default_volumes_dir(),
        owner_public_key,
    )
    .await?;
    println!(
        "Attached volume {} to Telegram topic {}:{}.",
        attached.config.volume_id, group_id, topic_id
    );
    println!(
        "Mount it with `teagarden volume mount {}`.",
        attached.config.volume_id
    );
    Ok(())
}

pub(crate) fn observe_header_revision(
    config_path: &std::path::Path,
    header: &HeaderDocument,
) -> Result<()> {
    policy::observe(config_path, header)
}

/// Page through one topic and return its newest authenticated TGHD document.
pub async fn discover_latest_header(
    transport: &dyn BlockTransport,
    group_id: i64,
    topic_id: i64,
    integrity_key: &teagarden_core::crypto::keys::SymmetricKey,
    owner_public_key: Option<&str>,
) -> Result<
    Option<(
        teagarden_telegram::types::DocumentInfo,
        HeaderDocument,
        Vec<u8>,
    )>,
> {
    let Some((document, candidate, bytes)) =
        scan_header_topic(transport, group_id, topic_id).await?
    else {
        return Ok(None);
    };
    anyhow::ensure!(
        candidate.group_id == group_id && candidate.topic_id == topic_id,
        "newest header candidate is bound to a different Telegram topic"
    );
    // The selected revision must authenticate with the current credential. Older
    // revisions can have a previous generation's MAC key after root rotation, so
    // they cannot be authenticated with this key. Selection happens first and an
    // authentication failure here never falls back to an older candidate.
    let authenticated = HeaderDocument::decode_pinned(&bytes, integrity_key, owner_public_key)
        .with_context(|| {
            format!(
                "authenticate newest header document {}",
                document.message_id
            )
        })?;
    anyhow::ensure!(
        authenticated.revision == candidate.revision,
        "authenticated newest header revision changed during selection"
    );
    Ok(Some((document, authenticated, bytes)))
}

/// Create a new local volume identity from the newest authenticated header in a
/// forum topic. The caller supplies the current credential; no old config or DB
/// is required.
pub async fn attach_command(
    transport: &dyn BlockTransport,
    group_id: i64,
    topic_id: i64,
    credential: &[u8],
    recovery: bool,
    volumes_dir: &std::path::Path,
    owner_public_key: Option<&str>,
) -> Result<manager::OpenVolumeResult> {
    let selected = scan_header_topic(transport, group_id, topic_id).await?;
    let (document, untrusted, bytes) =
        selected.ok_or_else(|| anyhow::anyhow!("no TGHD header found in Telegram topic"))?;
    anyhow::ensure!(
        untrusted.format == 2,
        "TGHD1 is unsupported by 1.0 attach; an owner-signed TGHD2 header is required"
    );
    let hierarchy = super::decrypt::derive_header_hierarchy(&untrusted, credential, recovery)
        .context("unlock the newest Telegram header; older revisions are not used as fallback")?;
    anyhow::ensure!(untrusted.format != 2 || owner_public_key.is_some(),
        "fresh TGHD2 attach requires --owner-public-key copied from the creating computer; the password alone cannot identify the owner");
    let header = HeaderDocument::decode_pinned(&bytes, &hierarchy.integrity, owner_public_key)
        .context("authenticate newest Telegram header")?;
    if header.group_id != group_id || header.topic_id != topic_id {
        anyhow::bail!("authenticated TGHD header belongs to another Telegram topic");
    }

    let scan = scan_topic_sdo_objects(transport, group_id, topic_id, &header, &hierarchy).await?;

    let base_dir = volumes_dir.join(header.volume_id.to_string());
    let paths = manager::VolumePaths::new(base_dir.clone());
    if paths.base_dir.exists() {
        anyhow::bail!(
            "local data directory for volume {} already exists",
            header.volume_id
        );
    }
    let mut config = VolumeConfig::new(
        format!("Attached {}", &header.volume_id.to_string()[..8]),
        volume_names::generate_group_name(),
    );
    config.volume_id = header.volume_id;
    config.telegram_group_id = group_id;
    config.telegram_topic_id = topic_id;
    config.telegram_channel_access_hash = transport
        .channel_ref()
        .filter(|(id, _, topic)| *id == group_id && *topic == topic_id)
        .map_or(0, |(_, access_hash, _)| access_hash);
    config.salt = hex::decode(&header.salt)
        .context("decode authenticated TGHD salt")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("authenticated TGHD salt is not 32 bytes"))?;
    if let Some(params) = &header.kdf_params {
        config.kdf_params = params.clone();
    }
    config.current_epoch = header.current_epoch;
    config.block_config.target_block_size = header.block_size;
    config.require_block_integrity = header.require_block_integrity;
    config.block_v2_from_epoch = header.block_v2_from_epoch;
    config.key_protection = header
        .key_protection
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .context("parse authenticated key-protection anchor")?;
    config.sdo_header_revision_reserved = header.revision;
    config.sdo_header_revision_published = header.revision;
    config.sdo_author_device_id = Some(uuid::Uuid::new_v4());
    config.sdo_owner_public_key = header.owner_public_key.clone();
    config.sdo_initial_clock_ms = scan.max_clock.0;
    config.sdo_initial_clock_counter = scan.max_clock.1;
    manager::restore_config_anchors(&mut config, &hierarchy);

    std::fs::create_dir_all(volumes_dir).context("create volumes directory")?;
    let staging_dir = volumes_dir.join(format!(".attach-{}", uuid::Uuid::new_v4()));
    let staging_paths = manager::VolumePaths::new(staging_dir.clone());
    staging_paths
        .ensure_dirs()
        .context("create attach staging directory")?;

    let result = (|| -> Result<()> {
        if let Some(vault) = &header.slot_vault {
            let vault_path = staging_paths
                .base_dir
                .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
            let vault_bytes = serde_json::to_vec_pretty(vault)?;
            std::fs::write(&vault_path, vault_bytes).context("write attached slot vault")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&vault_path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        manager::save_config_resealed(&mut config, &hierarchy, &staging_paths.config_path)
            .context("write authenticated local volume config")?;
        build_attached_index(&staging_paths.db_path, &scan, &hierarchy)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&staging_dir);
        return Err(error);
    }
    let rechecked = match scan_header_topic(transport, group_id, topic_id).await {
        Ok(rechecked) => rechecked,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging_dir);
            return Err(error);
        }
    };
    if rechecked
        .as_ref()
        .is_none_or(|(_, _, latest)| latest != &bytes)
    {
        let _ = std::fs::remove_dir_all(&staging_dir);
        anyhow::bail!("Telegram topic header changed during attach; retry attach");
    }
    if let Err(error) = std::fs::rename(&staging_dir, &base_dir) {
        let _ = std::fs::remove_dir_all(&staging_dir);
        return Err(error).context("publish attached volume directory");
    }
    let paths = manager::VolumePaths::new(base_dir);
    if let Some(owner) = &header.owner_public_key {
        let fingerprint = hex::encode(teagarden_core::block::srb2::sha256(&hex::decode(owner)?));
        println!("Authenticated owner fingerprint: SHA256:{fingerprint}");
        println!("Owner public key: {owner}");
    }

    tracing::info!(
        message_id = document.message_id,
        revision = header.revision,
        volume_id = %header.volume_id,
        file_records = scan.file_record_count,
        devices = scan.device_count,
        "attached portable volume header"
    );
    Ok(manager::OpenVolumeResult {
        config,
        paths,
        hierarchy,
    })
}

struct SdoScanSummary {
    high_water_message_id: i64,
    max_clock: (u64, u64),
    file_record_count: usize,
    device_count: usize,
    registry: teagarden_core::sdo::DeviceRegistry,
    all_registry: teagarden_core::sdo::DeviceRegistry,
    device_authorities: std::collections::BTreeMap<uuid::Uuid, String>,
    records: Vec<ScannedSdoVersion>,
    view: teagarden_core::sdo::SdoView,
}

struct ScannedSdoVersion {
    record: teagarden_core::sdo::SdoRecord,
    wire: Vec<u8>,
    message_id: i64,
    physical_message_ids: Vec<i64>,
    key_generation: u64,
    file_id: uuid::Uuid,
    origin_message_id: Option<i64>,
    local_version: u64,
    size: u64,
    mtime_ns: i64,
    mode: u32,
}

fn build_attached_index(
    db_path: &std::path::Path,
    scan: &SdoScanSummary,
    hierarchy: &KeyHierarchy,
) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    use teagarden_core::crypto::blake3::keyed_hash;
    use teagarden_core::metadata::{inode::Inode, types::Timestamps};
    use teagarden_core::sdo::SdoKind;
    use teagarden_store::{
        inode_store::InodeStore,
        migrations::initialize_database,
        sdo_cursor_store::SdoCursorStore,
        sdo_identity_store::{SdoFileIdentity, SdoIdentityStore},
        sdo_version_store::{SdoVersionStore, StoredSdoVersion},
    };

    let conn = rusqlite::Connection::open(db_path)?;
    let schema = OpaqueSchema::new(hierarchy.schema.clone(), &logical_tables());
    initialize_database(&conn, &schema)?;
    let inodes = InodeStore::new(&conn, &schema, &hierarchy.meta);
    let root = Inode::root();
    inodes.insert(&root)?;
    let mut paths = BTreeSet::new();
    for version in &scan.records {
        if matches!(version.record.kind, SdoKind::File | SdoKind::Directory) {
            let mut prefix = String::new();
            let components: Vec<_> = version.record.path.split('/').collect();
            for component in components.iter().take(components.len().saturating_sub(1)) {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                paths.insert(prefix.clone());
            }
            paths.insert(version.record.path.clone());
        }
    }
    let winners: BTreeMap<_, _> = paths
        .iter()
        .filter_map(|path| {
            scan.view
                .winner(path)
                .filter(|_| scan.view.is_visible(path))
                .map(|record| (path.clone(), record.clone()))
        })
        .collect();
    let mut path_inos = BTreeMap::<String, u64>::new();
    for (path, winner) in &winners {
        let (parent_path, name) = path
            .rsplit_once('/')
            .map_or(("", path.as_str()), |(p, n)| (p, n));
        let parent = if parent_path.is_empty() {
            1
        } else {
            *path_inos
                .get(parent_path)
                .context("missing visible parent while importing SDO history")?
        };
        let source = scan
            .records
            .iter()
            .find(|v| v.record.version_id == winner.version_id);
        let is_dir = winner.kind == SdoKind::Directory;
        let mode = source.map_or(if is_dir { 0o755 } else { 0o644 }, |v| v.mode);
        let ino = inodes.next_ino()?;
        let mut inode = if is_dir {
            Inode::new_dir(ino, parent, name.to_owned(), mode, 0, 0)
        } else {
            Inode::new_file(ino, parent, name.to_owned(), mode, 0, 0)
        };
        if let Some(version) = source {
            inode.size = version.size;
            let ns = version.mtime_ns as i128;
            inode.timestamps = Timestamps {
                atime_ns: ns,
                mtime_ns: ns,
                ctime_ns: ns,
                crtime_ns: ns,
            };
        }
        inodes.insert(&inode)?;
        if let Some(mut p) = inodes.get(parent)? {
            p.children.push(ino);
            if is_dir {
                p.nlink += 1;
            }
            inodes.update(&p)?;
        }
        path_inos.insert(path.clone(), ino);
    }
    let versions = SdoVersionStore::new(&conn, &schema);
    let identities = SdoIdentityStore::new(&conn, &schema, &hierarchy.meta);
    SdoCursorStore::new(&conn, &schema)
        .set(scan.high_water_message_id, scan.high_water_message_id)?;
    for version in &scan.records {
        let ino = path_inos.get(&version.record.path).copied().unwrap_or(0);
        let path_id = keyed_hash(
            &hierarchy.manifest,
            &[
                b"teagarden.sdo.path.v1".as_slice(),
                version.record.path.as_bytes(),
            ]
            .concat(),
        );
        versions.insert(
            version.record.version_id.as_bytes(),
            &StoredSdoVersion {
                path_id,
                ino,
                message_id: version.message_id,
                wire: version.wire.clone(),
            },
        )?;
    }
    for (path, winner) in &winners {
        if winner.kind != SdoKind::File {
            continue;
        }
        if let (Some(ino), Some(version)) = (
            path_inos.get(path),
            scan.records
                .iter()
                .find(|v| v.record.version_id == winner.version_id),
        ) {
            identities.set(
                *ino,
                &SdoFileIdentity {
                    file_id: version.file_id,
                    origin_message_id: version.origin_message_id,
                    latest_version_id: Some(winner.version_id),
                    local_version: version.local_version,
                },
            )?;
        }
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(conn);
    Ok(())
}

#[cfg(feature = "key-rotation")]
fn set_generation_boundary(
    header: &mut HeaderDocument,
    message_id: i64,
    installation_id: uuid::Uuid,
) -> Result<()> {
    let generation = header
        .key_generation
        .context("generation boundary requires a generation")?;
    if let Some(existing) = header.generation_cutoffs.get(&generation) {
        anyhow::ensure!(*existing == message_id, "generation cutoff is immutable");
    }
    header
        .generation_cutoffs
        .entry(generation)
        .or_insert(message_id);
    if !installation_id.is_nil() {
        header.revocation_cutoffs.entry(installation_id).or_insert(
            teagarden_core::sdo::RevocationCutoff {
                key_generation: generation,
                boundary_message_id: message_id,
            },
        );
    }
    header.generation_boundary_message_id = Some(message_id);
    Ok(())
}

#[cfg(feature = "key-rotation")]
fn make_rotated_header(
    current: &HeaderDocument,
    old_hierarchy: &KeyHierarchy,
    new_hierarchy: &KeyHierarchy,
    new_salt: &[u8; 32],
    key_protection: serde_json::Value,
    slot_vault: serde_json::Value,
) -> Result<HeaderDocument> {
    use teagarden_core::sdo::KeyGenerationBridge;

    anyhow::ensure!(current.format == 2, "credential rotation requires TGHD2");
    let old_generation = current
        .key_generation
        .context("TGHD2 key generation is missing")?;
    let new_generation = old_generation
        .checked_add(1)
        .context("TGHD2 key generation overflow")?;
    let old_salt: [u8; 32] = hex::decode(&current.salt)
        .context("decode current TGHD2 salt")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("TGHD2 salt is not 32 bytes"))?;
    let mut bridges: Vec<KeyGenerationBridge> = if let Some(rotation) = &current.rotation_state {
        rotation
            .get("key_bridges")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .context("parse current TGHD2 bridges")?
            .unwrap_or_default()
    } else {
        current.retained_key_bridges.clone()
    };
    anyhow::ensure!(bridges.len() < 64, "TGHD2 key bridge limit reached");
    for bridge in &mut bridges {
        anyhow::ensure!(
            bridge.key_generation < old_generation,
            "current TGHD2 contains a bridge that is not from an earlier generation"
        );
        let (root, salt) = bridge
            .unwrap(&old_hierarchy.wrapping)
            .context("unwrap an existing historical key bridge")?;
        *bridge =
            KeyGenerationBridge::wrap(bridge.key_generation, &salt, &root, &new_hierarchy.wrapping)
                .context("rewrap an existing historical key bridge")?;
    }
    bridges.push(
        KeyGenerationBridge::wrap(
            old_generation,
            &old_salt,
            &old_hierarchy.root,
            &new_hierarchy.wrapping,
        )
        .context("wrap the current key generation for retained history")?,
    );

    let mut rotated = current.clone();
    rotated.revision = current
        .revision
        .checked_add(1)
        .context("TGHD revision overflow")?;
    rotated.root_kind = RootKind::MasterKey;
    rotated.salt = hex::encode(new_salt);
    rotated.kdf_params = None;
    rotated.key_protection = Some(key_protection);
    rotated.slot_vault = Some(slot_vault);
    rotated.key_generation = Some(new_generation);
    rotated.retained_key_bridges.clear();
    rotated.rotation_state = Some(serde_json::json!({
        "phase": "migrating",
        "key_bridges": bridges,
        "device_key_handoff_version": 1,
    }));
    // Telegram assigns the message ID after the bytes are signed. The first
    // header's returned ID becomes this field in a following signed revision.
    rotated.generation_boundary_message_id = None;
    Ok(rotated)
}

#[cfg(not(feature = "key-rotation"))]
pub(crate) fn generation_meta_keys(
    header: &HeaderDocument,
    hierarchy: &KeyHierarchy,
) -> Result<std::collections::BTreeMap<u64, teagarden_core::crypto::keys::SymmetricKey>> {
    anyhow::ensure!(header.key_generation.unwrap_or(0) == 0 && header.retained_key_bridges.is_empty()
        && header.rotation_state.is_none(), "TGFV key rotation is not available in 1.0; this header requires the experimental key-rotation build");
    Ok(std::collections::BTreeMap::from([(
        0,
        hierarchy.meta.clone(),
    )]))
}

#[cfg(feature = "key-rotation")]
pub(crate) fn generation_meta_keys(
    header: &HeaderDocument,
    active_hierarchy: &KeyHierarchy,
) -> Result<std::collections::BTreeMap<u64, teagarden_core::crypto::keys::SymmetricKey>> {
    use teagarden_core::crypto::kdf::derive_hierarchy_v1;
    use teagarden_core::sdo::KeyGenerationBridge;

    let active_generation = header.key_generation.unwrap_or(0);
    let mut keys = std::collections::BTreeMap::new();
    keys.insert(active_generation, active_hierarchy.meta.clone());
    let mut bridges = header.retained_key_bridges.clone();
    let rotation_bridges: Vec<KeyGenerationBridge> = header
        .rotation_state
        .as_ref()
        .and_then(|rotation| rotation.get("key_bridges"))
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .context("parse TGHD2 key generation bridges")?
        .unwrap_or_default();
    bridges.extend(rotation_bridges);
    anyhow::ensure!(
        bridges.len() <= 64,
        "TGHD2 contains more than 64 key generation bridges"
    );
    for bridge in bridges {
        anyhow::ensure!(
            bridge.key_generation < active_generation,
            "TGHD2 key bridge does not name an earlier generation"
        );
        anyhow::ensure!(
            !keys.contains_key(&bridge.key_generation),
            "TGHD2 contains a duplicate key generation bridge"
        );
        let (root, salt) = bridge
            .unwrap(&active_hierarchy.wrapping)
            .context("unwrap prior-generation key bridge")?;
        let old_hierarchy = derive_hierarchy_v1(root, &salt, header.group_id, header.topic_id)
            .context("derive prior-generation key hierarchy")?;
        keys.insert(bridge.key_generation, old_hierarchy.meta.clone());
    }
    Ok(keys)
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "key-rotation")]
async fn publish_missing_device_key_updates<T: BlockTransport + ?Sized>(
    transport: &T,
    scan: &SdoScanSummary,
    header: &HeaderDocument,
    active_hierarchy: &KeyHierarchy,
    root: &[u8; 32],
    salt: &[u8; 32],
    revoked_installation: uuid::Uuid,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<usize> {
    use teagarden_core::sdo::SdoFileObjectV3;

    let new_generation = header
        .key_generation
        .context("replacement TGHD2 key generation is missing")?;
    let keys = generation_meta_keys(header, active_hierarchy)?;
    let mut clock = scan.max_clock;
    let mut published = 0usize;
    for (installation_id, announcement) in scan.registry.iter() {
        if *installation_id == revoked_installation {
            continue;
        }
        let public_key_hex = announcement.public_key.as_deref().with_context(|| {
            format!(
                "remaining installation {installation_id} has no key-handoff public key; mount it once with the updated client before rotating"
            )
        })?;
        if announcement
            .key_update
            .as_ref()
            .is_some_and(|update| update.key_generation == new_generation && update.salt == *salt)
        {
            continue;
        }
        let recipient_public = teagarden_core::crypto::mlkem::MlKemEncapsulationKey(
            hex::decode(public_key_hex).context("decode installation ML-KEM public key")?,
        );
        let scanned = scan
            .records
            .iter()
            .find(|version| version.record.version_id == announcement.version_id)
            .with_context(|| {
                format!("latest encrypted record for installation {installation_id} is missing")
            })?;
        let source_key = keys.get(&scanned.key_generation).with_context(|| {
            format!("missing metadata key generation {}", scanned.key_generation)
        })?;
        let mut metadata = SdoFileObjectV3::decode_header(
            &scanned.wire,
            header.volume_id,
            scanned.key_generation,
            source_key,
        )?
        .metadata;
        metadata.device_key_update = Some(create_device_key_update(
            header.volume_id,
            *installation_id,
            new_generation,
            salt,
            root,
            &recipient_public,
        )?);
        let public_update = create_device_key_update(
            header.volume_id,
            *installation_id,
            new_generation,
            salt,
            active_hierarchy.root.as_bytes(),
            &recipient_public,
        )?;
        let handoff_wire = encode_device_handoff(header.volume_id, &public_update, signing_key)?;
        transport
            .upload_file_object(&handoff_wire, "teagarden-device-handoff-v1.tgk")
            .await
            .context("publish durable independently readable device handoff")?;
        metadata.previous_version_id = Some(announcement.version_id);
        metadata.version_id = uuid::Uuid::new_v4();
        metadata.local_version = metadata.local_version.saturating_add(1);
        if clock.1 == u64::MAX {
            clock.0 = clock
                .0
                .checked_add(1)
                .context("device registry HLC overflow")?;
            clock.1 = 0;
        } else {
            clock.1 += 1;
        }
        metadata.clock_ms = clock.0;
        metadata.clock_counter = clock.1;
        metadata.author_device_id = uuid::Uuid::nil();
        metadata.sign_authority(header.volume_id, signing_key, &[])?;
        let wire = SdoFileObjectV3::encode(
            header.volume_id,
            scanned.key_generation,
            source_key,
            metadata,
            &[],
        )
        .context("encode encrypted per-installation key update")?;
        let filename = format!("{}.tgv", uuid::Uuid::new_v4());
        transport
            .upload_block(&wire, &filename)
            .await
            .with_context(|| {
                format!("publish key update for remaining installation {installation_id}")
            })?;
        published += 1;
    }
    Ok(published)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "key-rotation")]
struct DeviceHandoffDocument {
    volume_id: uuid::Uuid,
    update: teagarden_core::sdo::SdoDeviceKeyUpdate,
}

#[cfg(feature = "key-rotation")]
fn encode_device_handoff(
    volume_id: uuid::Uuid,
    update: &teagarden_core::sdo::SdoDeviceKeyUpdate,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer;
    let json = serde_json::to_vec(&DeviceHandoffDocument {
        volume_id,
        update: update.clone(),
    })?;
    anyhow::ensure!(json.len() <= 64 * 1024, "device handoff exceeds size limit");
    let mut wire = b"TGKU".to_vec();
    wire.extend_from_slice(&(json.len() as u32).to_le_bytes());
    wire.extend_from_slice(&json);
    let mut signed = b"teagarden.device-handoff.v1".to_vec();
    signed.extend_from_slice(&wire);
    wire.extend_from_slice(&signing_key.sign(&signed).to_bytes());
    Ok(wire)
}

#[cfg(feature = "key-rotation")]
fn decode_device_handoff(
    wire: &[u8],
    volume_id: uuid::Uuid,
    owner: &str,
) -> Result<teagarden_core::sdo::SdoDeviceKeyUpdate> {
    use ed25519_dalek::Verifier;
    anyhow::ensure!(
        wire.len() >= 72 && wire.len() <= 64 * 1024 + 72 && wire.starts_with(b"TGKU"),
        "invalid device handoff framing"
    );
    let size = u32::from_le_bytes(wire[4..8].try_into()?) as usize;
    anyhow::ensure!(
        size.checked_add(72) == Some(wire.len()),
        "device handoff length mismatch"
    );
    let owner: [u8; 32] = hex::decode(owner)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid owner public key"))?;
    let public = ed25519_dalek::VerifyingKey::from_bytes(&owner)?;
    let signature = ed25519_dalek::Signature::from_slice(&wire[8 + size..])?;
    let mut signed = b"teagarden.device-handoff.v1".to_vec();
    signed.extend_from_slice(&wire[..8 + size]);
    public
        .verify(&signed, &signature)
        .context("authenticate owner-signed device handoff")?;
    let package: DeviceHandoffDocument = serde_json::from_slice(&wire[8..8 + size])?;
    anyhow::ensure!(
        package.volume_id == volume_id,
        "device handoff belongs to another volume"
    );
    Ok(package.update)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "key-rotation")]
struct LocalDeviceTransition {
    handoff_wire: Vec<u8>,
    header_wire: Vec<u8>,
}

#[cfg(feature = "key-rotation")]
fn persist_device_transition(
    base_dir: &std::path::Path,
    handoff_wire: &[u8],
    header_wire: &[u8],
) -> Result<()> {
    let package = LocalDeviceTransition {
        handoff_wire: handoff_wire.to_vec(),
        header_wire: header_wire.to_vec(),
    };
    let path = base_dir.join("device-transition.json");
    teagarden_core::fsutil::write_file_atomic(
        &path,
        &serde_json::to_vec(&package)?,
        "durable device credential transition",
    )?;
    Ok(())
}

/// Reuse this installation's existing local unlock policy. The transition file
/// stores only owner-signed ciphertext addressed to its persistent device key;
/// the original password/MFA config and vault remain the local unlock anchor.
#[cfg(feature = "key-rotation")]
pub(super) fn apply_local_device_transition(opened: &mut manager::OpenVolumeResult) -> Result<()> {
    let path = opened.paths.base_dir.join("device-transition.json");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.len() <= 32 * 1024 * 1024,
        "invalid durable credential transition file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "durable credential transition must be private to this installation"
        );
    }
    let package: LocalDeviceTransition = serde_json::from_slice(&std::fs::read(path)?)?;
    let owner = opened
        .config
        .sdo_owner_public_key
        .as_deref()
        .context("device transition requires an established owner pin")?;
    let update = decode_device_handoff(&package.handoff_wire, opened.config.volume_id, owner)?;
    anyhow::ensure!(
        Some(update.installation_id) == opened.config.sdo_author_device_id,
        "durable credential transition targets another installation"
    );
    let candidate = super::decrypt::parse_header_json(&package.header_wire)?;
    if candidate.revision < opened.config.sdo_header_revision_published {
        return Ok(());
    }
    anyhow::ensure!(
        opened.paths.base_dir.join("device-keypair.json").is_file(),
        "device transition is present but this installation's receiving key is missing"
    );
    let (private, public) =
        load_or_create_device_keypair(&opened.paths.base_dir, &opened.hierarchy.wrapping)?;
    let root = unwrap_device_key_update(opened.config.volume_id, &update, &private)?;
    let hierarchy = teagarden_core::crypto::kdf::derive_hierarchy_v1(
        teagarden_core::crypto::keys::SymmetricKey::from_bytes(root),
        &update.salt,
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
    )?;
    let header =
        HeaderDocument::decode_pinned(&package.header_wire, &hierarchy.integrity, Some(owner))?;
    anyhow::ensure!(
        header.volume_id == opened.config.volume_id
            && header.group_id == opened.config.telegram_group_id
            && header.topic_id == opened.config.telegram_topic_id
            && header.key_generation == Some(update.key_generation)
            && !header.revoked_device_ids.contains(&update.installation_id),
        "durable credential transition does not match the current installation and header"
    );
    store_device_key_wrap(
        &opened.paths.base_dir,
        &hierarchy.wrapping,
        &private,
        &public,
    )?;
    opened.config.salt = update.salt;
    opened.config.kdf_params = header
        .kdf_params
        .clone()
        .unwrap_or_else(|| opened.config.kdf_params.clone());
    opened.config.key_protection = header
        .key_protection
        .clone()
        .map(serde_json::from_value)
        .transpose()?;
    opened.config.sdo_header_revision_published = header.revision;
    opened.config.sdo_header_revision_reserved = header.revision;
    opened.config.current_epoch = header.current_epoch;
    opened.hierarchy = hierarchy;
    // This is an in-memory authenticated remote configuration. Never reseal the
    // base config with this root: doing so would discard C's old local unlock.
    manager::restore_config_anchors(&mut opened.config, &opened.hierarchy);
    Ok(())
}

fn open_mount_credentials(
    volume_id: &str,
    inputs: &teagarden_mfa::unlock::UnlockInputs<'_>,
    volumes_dir: &std::path::Path,
) -> Result<manager::OpenVolumeResult> {
    let opened = teagarden_mfa::unlock::open_volume(volume_id, inputs, volumes_dir)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    #[cfg(feature = "key-rotation")]
    let opened = {
        let mut opened = opened;
        apply_local_device_transition(&mut opened)?;
        opened
    };
    Ok(opened)
}

/// Find retained owner-signed handoffs from the entire topic, including packages
/// posted while this computer was offline. This runs before mount authentication.
#[cfg(feature = "key-rotation")]
async fn refresh_device_transition(
    transport: &dyn BlockTransport,
    opened: &mut manager::OpenVolumeResult,
) -> Result<()> {
    let Some(owner) = opened.config.sdo_owner_public_key.clone() else {
        return Ok(());
    };
    let Some(installation) = opened.config.sdo_author_device_id else {
        return Ok(());
    };
    if !opened.paths.base_dir.join("device-keypair.json").exists() {
        return Ok(());
    }
    let (private, _) =
        load_or_create_device_keypair(&opened.paths.base_dir, &opened.hierarchy.wrapping)?;
    let mut before = None;
    let mut candidates = Vec::new();
    loop {
        let page = transport
            .list_topic_page(
                opened.config.telegram_group_id,
                opened.config.telegram_topic_id,
                None,
                None,
                before,
                100,
            )
            .await?;
        if page.raw_message_ids.is_empty() {
            break;
        }
        before = page.raw_message_ids.last().copied();
        for document in page.documents {
            if document.filename != "teagarden-device-handoff-v1.tgk" {
                continue;
            }
            let wire = transport
                .download_range(document.message_id, 0, 64 * 1024 + 72)
                .await?;
            let update = decode_device_handoff(&wire, opened.config.volume_id, &owner)?;
            if update.installation_id == installation {
                candidates.push((update.key_generation, update, wire));
            }
        }
        if page.exhausted {
            break;
        }
    }
    candidates.sort_by_key(|(generation, _, _)| *generation);
    let Some((_, update, wire)) = candidates.pop() else {
        return Ok(());
    };
    let root = unwrap_device_key_update(opened.config.volume_id, &update, &private)?;
    let hierarchy = teagarden_core::crypto::kdf::derive_hierarchy_v1(
        teagarden_core::crypto::keys::SymmetricKey::from_bytes(root),
        &update.salt,
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
    )?;
    let (_, header, header_wire) = discover_latest_header(
        transport,
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &hierarchy.integrity,
        Some(&owner),
    )
    .await?
    .context("no current owner header for this device handoff")?;
    anyhow::ensure!(
        header.key_generation == Some(update.key_generation),
        "latest device handoff is stale"
    );
    persist_device_transition(&opened.paths.base_dir, &wire, &header_wire)?;
    apply_local_device_transition(opened)
}

#[cfg(feature = "key-rotation")]
fn device_key_update_aad(
    volume_id: uuid::Uuid,
    installation_id: uuid::Uuid,
    key_generation: u64,
    salt: &[u8; 32],
) -> Vec<u8> {
    let mut aad = b"teagarden.sdo.device-key.v1".to_vec();
    aad.extend_from_slice(volume_id.as_bytes());
    aad.extend_from_slice(installation_id.as_bytes());
    aad.extend_from_slice(&key_generation.to_le_bytes());
    aad.extend_from_slice(salt);
    aad
}

#[cfg(feature = "key-rotation")]
fn create_device_key_update(
    volume_id: uuid::Uuid,
    installation_id: uuid::Uuid,
    key_generation: u64,
    salt: &[u8; 32],
    root: &[u8; 32],
    recipient: &teagarden_core::crypto::mlkem::MlKemEncapsulationKey,
) -> Result<teagarden_core::sdo::SdoDeviceKeyUpdate> {
    let aad = device_key_update_aad(volume_id, installation_id, key_generation, salt);
    let root = teagarden_core::crypto::keys::SymmetricKey::from_bytes(*root);
    let wrapped = teagarden_sharing::key_exchange::wrap_key_for_user(&root, recipient, &aad)
        .context("wrap replacement root for retained installation")?;
    Ok(teagarden_core::sdo::SdoDeviceKeyUpdate {
        installation_id,
        key_generation,
        salt: *salt,
        wrapped_root: wrapped
            .to_bytes()
            .context("serialize retained installation key package")?,
    })
}

#[cfg(feature = "key-rotation")]
fn unwrap_device_key_update(
    volume_id: uuid::Uuid,
    update: &teagarden_core::sdo::SdoDeviceKeyUpdate,
    recipient: &teagarden_core::crypto::mlkem::MlKemDecapsulationKey,
) -> Result<[u8; 32]> {
    let wrapped = teagarden_sharing::key_exchange::WrappedKey::from_bytes(&update.wrapped_root)
        .context("decode retained installation key package")?;
    let aad = device_key_update_aad(
        volume_id,
        update.installation_id,
        update.key_generation,
        &update.salt,
    );
    let root = teagarden_sharing::key_exchange::unwrap_key(&wrapped, recipient, &aad)
        .context("unwrap retained installation key package")?;
    Ok(*root.as_bytes())
}

fn legacy_v2_logical_metadata(
    metadata: &teagarden_core::sdo::SdoObjectMetadata,
) -> teagarden_core::sdo::SdoObjectMetadataV3 {
    teagarden_core::sdo::SdoObjectMetadataV3 {
        authority: None,
        migration_receipt: None,
        file_id: metadata.file_id,
        origin_message_id: metadata.origin_message_id,
        path: Some(metadata.path.clone()),
        size: metadata.size,
        mtime_ns: metadata.mtime_ns,
        mode: metadata.mode,
        version_id: metadata.version_id,
        author_device_id: metadata.author_device_id,
        previous_version_id: metadata.previous_version_id,
        kind: teagarden_core::sdo::SdoKind::File,
        key_generation: 0,
        clock_ms: u64::try_from(metadata.saved_at_ns.max(0) / 1_000_000).unwrap_or_default(),
        clock_counter: 0,
        saved_at_ns: metadata.saved_at_ns,
        local_version: metadata.local_version,
        deleted: metadata.deleted,
        installation_id: None,
        label: None,
        telegram_user_id: None,
        authorization_session_hash: None,
        created_at_ms: None,
        device_public_key: None,
        device_key_update: None,
        segment_size: metadata.segment_size,
        segment_count: metadata.segment_count,
        content_sha256: metadata.content_sha256.clone(),
    }
}

async fn scan_topic_sdo_objects(
    transport: &dyn BlockTransport,
    group_id: i64,
    topic_id: i64,
    header: &HeaderDocument,
    hierarchy: &KeyHierarchy,
) -> Result<SdoScanSummary> {
    use std::collections::HashMap;
    use teagarden_core::sdo::{
        reduce_records, DeviceAnnouncement, DeviceRegistry, SdoFileObject, SdoFileObjectV3,
        SdoKind, SdoRecord,
    };

    header.require_complete_revocation_cutoffs()?;
    let generation_meta_keys = generation_meta_keys(header, hierarchy)?;
    let active_generation = header.key_generation.unwrap_or(0);
    anyhow::ensure!(
        active_generation == 0 || header.generation_boundary_message_id.is_some(),
        "rotated TGHD2 header has no generation boundary"
    );

    let mut cursor = None;
    let mut records = Vec::new();
    let mut scanned_versions: Vec<ScannedSdoVersion> = Vec::new();
    let mut announcements = Vec::new();
    let mut revoked_inventory = Vec::new();
    let mut device_bindings = std::collections::BTreeMap::<uuid::Uuid, (i64, String)>::new();
    let mut announcement_signers = std::collections::BTreeMap::<uuid::Uuid, String>::new();
    let mut version_plaintexts = HashMap::<uuid::Uuid, Vec<u8>>::new();
    let mut version_positions = HashMap::<uuid::Uuid, usize>::new();
    let mut max_clock = (0u64, 0u64);
    let mut high_water_message_id = 0i64;
    loop {
        let page = transport
            .list_topic_page(group_id, topic_id, None, None, cursor, 100)
            .await
            .context("enumerate TGFV history in Telegram topic")?;
        if page.raw_message_ids.is_empty() {
            break;
        }
        if high_water_message_id == 0 {
            high_water_message_id = page.raw_message_ids[0];
        }
        cursor = page.raw_message_ids.last().copied();
        for document in page.documents {
            let prefix = transport
                .download_range(document.message_id, 0, 34)
                .await
                .with_context(|| format!("read object prefix {}", document.message_id))?;
            if prefix.get(..4) != Some(b"TGFV") {
                continue;
            }
            if prefix.len() < 6 {
                anyhow::bail!(
                    "truncated TGFV format field at message {}",
                    document.message_id
                );
            }
            let format = u16::from_le_bytes([prefix[4], prefix[5]]);
            let (
                record,
                plaintext,
                wire,
                file_id,
                origin_message_id,
                local_version,
                size,
                mtime_ns,
                mode,
                object_generation,
            ) = match format {
                2 => {
                    if prefix.len() < 26 {
                        anyhow::bail!("truncated TGFV2 prefix at message {}", document.message_id);
                    }
                    let header_len =
                        u32::from_le_bytes(prefix[22..26].try_into().unwrap()) as usize;
                    let total = 26usize
                        .checked_add(header_len)
                        .context("TGFV2 header length overflow")?;
                    if total > teagarden_core::sdo::MAX_MANIFEST_SIZE {
                        anyhow::bail!(
                            "TGFV2 header at message {} exceeds the size limit",
                            document.message_id
                        );
                    }
                    let wire = transport
                        .download_range(document.message_id, 0, total as u32)
                        .await
                        .with_context(|| format!("read TGFV2 header {}", document.message_id))?;
                    let meta_key = generation_meta_keys
                        .get(&0)
                        .context("TGHD2 has no bridge for the legacy TGFV2 generation")?;
                    let object = SdoFileObject::decode_header(&wire, header.volume_id, meta_key)
                        .with_context(|| {
                            format!("authenticate TGFV2 header {}", document.message_id)
                        })?;
                    let metadata = object.metadata;
                    if !teagarden_core::sdo::object_transition_is_acceptable(
                        header,
                        &legacy_v2_logical_metadata(&metadata),
                        document.message_id,
                    ) {
                        continue;
                    }
                    let record = teagarden_core::sdo::legacy_object_record(&metadata);
                    let plaintext = serde_json::to_vec(&legacy_v2_logical_metadata(&metadata))?;
                    (
                        record,
                        plaintext,
                        wire,
                        metadata.file_id,
                        metadata.origin_message_id,
                        metadata.local_version,
                        metadata.size,
                        metadata.mtime_ns,
                        metadata.mode,
                        0,
                    )
                }
                3 => {
                    if prefix.len() < 34 {
                        anyhow::bail!("truncated TGFV3 prefix at message {}", document.message_id);
                    }
                    let header_len =
                        u32::from_le_bytes(prefix[30..34].try_into().unwrap()) as usize;
                    let total = 34usize
                        .checked_add(header_len)
                        .context("TGFV3 header length overflow")?;
                    if total > teagarden_core::sdo::MAX_MANIFEST_SIZE {
                        anyhow::bail!(
                            "TGFV3 header at message {} exceeds the size limit",
                            document.message_id
                        );
                    }
                    let wire = transport
                        .download_range(document.message_id, 0, total as u32)
                        .await
                        .with_context(|| format!("read TGFV3 header {}", document.message_id))?;
                    let object_generation = u64::from_le_bytes(prefix[22..30].try_into().unwrap());
                    let meta_key =
                        generation_meta_keys
                            .get(&object_generation)
                            .with_context(|| {
                                format!(
                                    "TGHD2 has no bridge for key generation {object_generation}"
                                )
                            })?;
                    let object = SdoFileObjectV3::decode_header(
                        &wire,
                        header.volume_id,
                        object_generation,
                        meta_key,
                    )
                    .with_context(|| {
                        format!("authenticate TGFV3 header {}", document.message_id)
                    })?;
                    let metadata = object.metadata;
                    let accepted = teagarden_core::sdo::object_transition_is_acceptable(
                        header,
                        &metadata,
                        document.message_id,
                    );
                    // Read-only discovery must retain revoked installations even
                    // when their records are excluded from the writable state.
                    if metadata.kind == SdoKind::Device
                        && (accepted
                            || (metadata.installation_id == Some(metadata.author_device_id)
                                && header
                                    .revoked_device_ids
                                    .contains(&metadata.author_device_id)
                                && header
                                    .device_authorities
                                    .get(&metadata.author_device_id)
                                    .is_none_or(|expected| {
                                        metadata
                                            .authority
                                            .as_ref()
                                            .is_some_and(|proof| &proof.public_key == expected)
                                    })))
                    {
                        let announcement = DeviceAnnouncement {
                            installation_id: metadata
                                .installation_id
                                .context("device record missing installation id")?,
                            label: metadata
                                .label
                                .clone()
                                .context("device record missing label")?,
                            telegram_user_id: metadata
                                .telegram_user_id
                                .context("device record missing Telegram user id")?,
                            authorization_session_hash: metadata.authorization_session_hash.clone(),
                            public_key: metadata.device_public_key.clone(),
                            key_update: metadata.device_key_update.clone(),
                            created_at_ms: metadata
                                .created_at_ms
                                .context("device record missing creation time")?,
                            clock_ms: metadata.clock_ms,
                            clock_counter: metadata.clock_counter,
                            author_device_id: metadata.author_device_id,
                            version_id: metadata.version_id,
                        };
                        if accepted {
                            announcements.push(announcement);
                        } else {
                            revoked_inventory.push(announcement);
                        }
                    }
                    if !accepted {
                        continue;
                    }
                    if metadata.kind == SdoKind::Device {
                        if let Some(proof) = &metadata.authority {
                            announcement_signers
                                .insert(metadata.version_id, proof.public_key.clone());
                            if Some(proof.public_key.as_str()) != header.owner_public_key.as_deref()
                            {
                                let id = metadata
                                    .installation_id
                                    .context("signed device is missing its installation id")?;
                                #[cfg(not(feature = "key-rotation"))]
                                let original_id = document.message_id;
                                #[cfg(feature = "key-rotation")]
                                let original_id = metadata
                                    .migration_receipt
                                    .as_ref()
                                    .map_or(document.message_id, |receipt| {
                                        receipt.source_message_id
                                    });
                                if device_bindings
                                    .get(&id)
                                    .is_none_or(|(old_id, _)| original_id < *old_id)
                                {
                                    device_bindings
                                        .insert(id, (original_id, proof.public_key.clone()));
                                }
                            }
                        }
                    }
                    let path = match metadata.kind {
                        SdoKind::Device => metadata
                            .installation_id
                            .context("device record is missing its installation UUID")?
                            .to_string(),
                        _ => metadata
                            .path
                            .clone()
                            .context("filesystem object is missing its path")?,
                    };
                    let record = SdoRecord {
                        path,
                        kind: metadata.kind,
                        clock_ms: metadata.clock_ms,
                        clock_counter: metadata.clock_counter,
                        author_device_id: metadata.author_device_id,
                        version_id: metadata.version_id,
                        deleted: metadata.deleted,
                        legacy: false,
                        implicit: false,
                    };
                    let mut logical_metadata = metadata.clone();
                    logical_metadata.key_generation = 0;
                    logical_metadata.authority = None;
                    logical_metadata.migration_receipt = None;
                    let plaintext = serde_json::to_vec(&logical_metadata)?;
                    (
                        record,
                        plaintext,
                        wire,
                        metadata.file_id,
                        metadata.origin_message_id,
                        metadata.local_version,
                        metadata.size,
                        metadata.mtime_ns,
                        metadata.mode,
                        object_generation,
                    )
                }
                _ => anyhow::bail!(
                    "unsupported TGFV format {format} at message {}",
                    document.message_id
                ),
            };
            if let Some(previous) = version_plaintexts.get(&record.version_id) {
                if previous != &plaintext {
                    anyhow::bail!(
                        "conflicting authenticated plaintext for version UUID {}",
                        record.version_id
                    );
                }
                let position = version_positions[&record.version_id];
                scanned_versions[position]
                    .physical_message_ids
                    .push(document.message_id);
                if object_generation > scanned_versions[position].key_generation {
                    scanned_versions[position] = ScannedSdoVersion {
                        record: record.clone(),
                        wire,
                        message_id: document.message_id,
                        physical_message_ids: scanned_versions[position]
                            .physical_message_ids
                            .clone(),
                        key_generation: object_generation,
                        file_id,
                        origin_message_id,
                        local_version,
                        size,
                        mtime_ns,
                        mode,
                    };
                }
            } else {
                version_plaintexts.insert(record.version_id, plaintext);
                max_clock = max_clock.max((record.clock_ms, record.clock_counter));
                records.push(record.clone());
                version_positions.insert(record.version_id, scanned_versions.len());
                scanned_versions.push(ScannedSdoVersion {
                    record,
                    wire,
                    message_id: document.message_id,
                    physical_message_ids: vec![document.message_id],
                    key_generation: object_generation,
                    file_id,
                    origin_message_id,
                    local_version,
                    size,
                    mtime_ns,
                    mode,
                });
            }
        }
        if page.exhausted {
            break;
        }
    }
    let file_record_count = records
        .iter()
        .filter(|record| matches!(record.kind, SdoKind::File | SdoKind::Directory))
        .count();
    let view = reduce_records(records).context("reduce authenticated TGFV history")?;
    announcements.retain(|device| {
        device_bindings
            .get(&device.installation_id)
            .is_none_or(|(_, expected)| {
                announcement_signers
                    .get(&device.version_id)
                    .is_some_and(|signer| {
                        signer == expected
                            || Some(signer.as_str()) == header.owner_public_key.as_deref()
                    })
            })
    });
    let device_authorities = device_bindings
        .into_iter()
        .map(|(id, (_, key))| (id, key))
        .collect();
    let all_registry =
        DeviceRegistry::from_announcements(announcements.iter().cloned().chain(revoked_inventory))
            .context("reconstruct observed device inventory")?;
    let mut registry = DeviceRegistry::from_announcements(announcements)
        .context("reconstruct encrypted device registry")?;
    registry.apply_revocations(&header.revoked_device_ids, &header.revoked_account_bindings);
    Ok(SdoScanSummary {
        max_clock,
        file_record_count,
        device_count: registry.len(),
        registry,
        all_registry,
        device_authorities,
        records: scanned_versions,
        view,
        high_water_message_id,
    })
}

/// History and restore use the same authenticated, generation-aware scan as
/// attach and mount. The local manifest table is only a disposable cache.
type SdoHistoryScan = (
    Vec<serde_json::Value>,
    Option<(teagarden_core::sdo::SdoObjectMetadataV3, Vec<u8>)>,
    (u64, u64),
);

pub(crate) async fn scan_sdo_history(
    transport: &dyn BlockTransport,
    group_id: i64,
    topic_id: i64,
    header: &HeaderDocument,
    hierarchy: &KeyHierarchy,
    restore_id: Option<uuid::Uuid>,
) -> Result<SdoHistoryScan> {
    use teagarden_core::sdo::{SdoFileObject, SdoFileObjectV3, SdoKind};

    let scan = scan_topic_sdo_objects(transport, group_id, topic_id, header, hierarchy).await?;
    let keys = generation_meta_keys(header, hierarchy)?;
    let mut restored = None;
    let mut rows = Vec::new();
    for version in scan
        .records
        .iter()
        .filter(|v| v.record.kind == SdoKind::File)
    {
        let key = keys
            .get(&version.key_generation)
            .context("missing TGFV generation key")?;
        let is_v3 = version.wire.get(4..6) == Some(3u16.to_le_bytes().as_slice());
        let selected = restore_id == Some(version.record.version_id);
        // V3 hashes are authenticated in its ranged header. Restoring bytes
        // (or hashing a legacy V2 object) also authenticates the full payload.
        let full = if selected || !is_v3 {
            let wire = transport.download_block(version.message_id).await?.data;
            anyhow::ensure!(
                wire.starts_with(&version.wire),
                "downloaded TGFV header changed since the authenticated topic scan"
            );
            let (metadata, content) = if is_v3 {
                let object =
                    SdoFileObjectV3::decode(&wire, header.volume_id, version.key_generation, key)?;
                (object.metadata, object.content)
            } else {
                let object = SdoFileObject::decode(&wire, header.volume_id, key)?;
                (legacy_v2_logical_metadata(&object.metadata), object.content)
            };
            anyhow::ensure!(
                teagarden_core::sdo::object_transition_is_acceptable(
                    header,
                    &metadata,
                    version.message_id
                ),
                "downloaded TGFV is not authorized by the current volume policy"
            );
            Some((metadata, content))
        } else {
            None
        };
        let sha = if is_v3 {
            SdoFileObjectV3::decode_header(
                &version.wire,
                header.volume_id,
                version.key_generation,
                key,
            )?
            .metadata
            .content_sha256
        } else {
            hex::encode(teagarden_core::block::srb2::sha256(
                &full.as_ref().unwrap().1,
            ))
        };
        if selected {
            restored = full;
        }
        rows.push(serde_json::to_value((
            version.file_id,
            &version.record.path,
            version.record.version_id,
            version.record.author_device_id,
            version.record.clock_ms,
            version.record.clock_counter,
            version.size,
            version.record.deleted,
            Some(sha),
        ))?);
    }
    anyhow::ensure!(
        restore_id.is_none() || restored.is_some(),
        "TGFV version UUID not found in authenticated topic scan"
    );
    Ok((rows, restored, scan.max_clock))
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "key-rotation")]
async fn migrate_v3_history(
    transport: &dyn BlockTransport,
    header: &HeaderDocument,
    active_hierarchy: &KeyHierarchy,
    credential_header_wire: &[u8],
    versions: &[ScannedSdoVersion],
    operation_path: &std::path::Path,
    operation: &mut serde_json::Value,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<usize> {
    use teagarden_core::sdo::{SdoFileObject, SdoFileObjectV3};

    let active_generation = header.key_generation.unwrap_or(0);
    let generation_keys = generation_meta_keys(header, active_hierarchy)?;
    let mut delete_ids = Vec::<i64>::new();
    let mut migrated = 0usize;
    if operation.get("migrated_versions").is_none() {
        operation["migrated_versions"] = serde_json::json!({});
    }
    for version in versions {
        let latest_wire = transport
            .download_block(version.message_id)
            .await
            .with_context(|| {
                format!(
                    "download version {} for history migration",
                    version.record.version_id
                )
            })?
            .data;
        let current_meta_key = generation_keys
            .get(&version.key_generation)
            .with_context(|| format!("missing source key generation {}", version.key_generation))?;
        let is_v3 = latest_wire.get(4..6) == Some(3u16.to_le_bytes().as_slice());
        let (source_metadata, source_content) = if is_v3 {
            let source = SdoFileObjectV3::decode(
                &latest_wire,
                header.volume_id,
                version.key_generation,
                current_meta_key,
            )
            .with_context(|| {
                format!("authenticate source version {}", version.record.version_id)
            })?;
            (source.metadata, source.content)
        } else if latest_wire.get(4..6) == Some(2u16.to_le_bytes().as_slice()) {
            anyhow::ensure!(
                version.key_generation == 0,
                "TGFV2 can only belong to generation zero"
            );
            let source = SdoFileObject::decode(&latest_wire, header.volume_id, current_meta_key)
                .with_context(|| {
                    format!(
                        "authenticate legacy source version {}",
                        version.record.version_id
                    )
                })?;
            (legacy_v2_logical_metadata(&source.metadata), source.content)
        } else {
            anyhow::bail!(
                "unsupported source format for version {}",
                version.record.version_id
            );
        };
        if !teagarden_core::sdo::object_transition_is_acceptable(
            header,
            &source_metadata,
            version.message_id,
        ) {
            continue;
        }
        anyhow::ensure!(
            source_metadata.version_id == version.record.version_id,
            "source message {} no longer contains expected version {}",
            version.message_id,
            version.record.version_id
        );

        let replacement_id = if version.key_generation == active_generation {
            anyhow::ensure!(is_v3, "legacy TGFV2 cannot be current-generation data");
            let mut source_ids = version.physical_message_ids.clone();
            source_ids.retain(|id| *id != version.message_id);
            delete_ids.extend(source_ids);
            version.message_id
        } else {
            let mut migrated_metadata = source_metadata.clone();
            migrated_metadata.key_generation = active_generation;
            if !migrated_metadata.has_authorized_migration_receipt(header) {
                migrated_metadata.attest_migration(
                    header.volume_id,
                    version.message_id,
                    signing_key,
                )?;
            }
            let rewritten = SdoFileObjectV3::encode(
                header.volume_id,
                active_generation,
                &active_hierarchy.meta,
                migrated_metadata.clone(),
                &source_content,
            )?;
            let rewritten = teagarden_core::sdo::ObjectEnvelope::seal(
                &rewritten,
                credential_header_wire,
                active_hierarchy,
            )
            .context("seal migrated history with standalone credentials")?;
            let upload = transport
                .upload_file_object(&rewritten, "teagarden-file-v3.tgf")
                .await
                .with_context(|| {
                    format!("upload replacement version {}", version.record.version_id)
                })?;
            let verification_wire = transport
                .download_block(upload.message_id)
                .await
                .with_context(|| {
                    format!("download replacement version {}", version.record.version_id)
                })?
                .data;
            let verified = SdoFileObjectV3::decode(
                &verification_wire,
                header.volume_id,
                active_generation,
                &active_hierarchy.meta,
            )
            .with_context(|| format!("verify replacement version {}", version.record.version_id))?;
            let expected_metadata = migrated_metadata;
            anyhow::ensure!(
                verified.metadata.has_authorized_migration_receipt(header),
                "replacement migration receipt failed: author={} pinned={} signature={} source={} boundary={:?}",
                verified.metadata.author_device_id,
                verified.metadata.authority.as_ref().is_some_and(|proof| header.device_authorities.get(&verified.metadata.author_device_id) == Some(&proof.public_key)),
                verified.metadata.has_valid_migration_receipt(header.volume_id, header.owner_public_key.as_deref().unwrap_or(""), i64::MAX),
                version.message_id, header.generation_boundary_message_id
            );
            anyhow::ensure!(
                verified.metadata == expected_metadata && verified.content == source_content,
                "replacement version {} differs from its authenticated source",
                version.record.version_id
            );
            delete_ids.extend(version.physical_message_ids.iter().copied());
            migrated += 1;
            upload.message_id
        };
        operation["migrated_versions"][version.record.version_id.to_string()] =
            serde_json::json!(replacement_id);
        teagarden_core::fsutil::write_file_atomic(
            operation_path,
            &serde_json::to_vec_pretty(operation)?,
            "owner revocation migration state",
        )?;
    }

    delete_ids.sort_unstable();
    delete_ids.dedup();
    for batch in delete_ids.chunks(100) {
        delete_message_batch_retry(transport, batch)
            .await
            .context("delete replaced history messages")?;
    }
    operation["phase"] = serde_json::Value::String("history_migration_complete".into());
    teagarden_core::fsutil::write_file_atomic(
        operation_path,
        &serde_json::to_vec_pretty(operation)?,
        "owner revocation migration state",
    )?;
    Ok(migrated)
}

#[cfg(feature = "key-rotation")]
async fn delete_message_batch_retry(
    transport: &dyn BlockTransport,
    message_ids: &[i64],
) -> Result<()> {
    loop {
        match transport.delete_messages(message_ids).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                let detail = error.to_string();
                if let Some(seconds) = detail
                    .strip_prefix("rate limited, retry after ")
                    .and_then(|value| value.strip_suffix('s'))
                    .and_then(|value| value.parse::<u64>().ok())
                {
                    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                    continue;
                }
                return Err(error).context("delete Telegram messages");
            }
        }
    }
}

#[cfg(feature = "key-rotation")]
#[allow(clippy::too_many_arguments)]
async fn finish_history_migration(
    transport: &dyn ForumAdmin,
    config: &VolumeConfig,
    hierarchy: &KeyHierarchy,
    config_path: &std::path::Path,
    operation_path: &std::path::Path,
    operation: &mut serde_json::Value,
    admin: &manager::OwnerAdminLock,
) -> Result<usize> {
    let group_id = config.telegram_group_id;
    let topic_id = config.telegram_topic_id;
    let (_, mut header, mut credential_header_wire) = discover_latest_header(
        transport,
        group_id,
        topic_id,
        &hierarchy.integrity,
        config.sdo_owner_public_key.as_deref(),
    )
    .await?
    .context("discover active rotated header before migration")?;
    let mut scan = scan_topic_sdo_objects(
        transport as &dyn BlockTransport,
        group_id,
        topic_id,
        &header,
        hierarchy,
    )
    .await?;
    // Registration committed before the immutable boundary is eligible even if
    // it raced the orchestrator's first scan. Old-key post-boundary enrollment
    // without an existing pinned authority is excluded by this same scanner.
    let mut added = false;
    for (installation, key) in &scan.device_authorities {
        if !header.device_authorities.contains_key(installation) {
            header.device_authorities.insert(*installation, key.clone());
            added = true;
        }
    }
    let signing = load_owner_capability(config_path)?;
    if added {
        publish_signed_header_update_in_transaction(
            transport,
            config,
            hierarchy,
            config_path,
            header.revision,
            header.clone(),
            admin,
        )
        .await?;
        let (_, updated, wire) = discover_latest_header(
            transport,
            group_id,
            topic_id,
            &hierarchy.integrity,
            config.sdo_owner_public_key.as_deref(),
        )
        .await?
        .context("authenticate newly enrolled migration authorities")?;
        header = updated;
        credential_header_wire = wire;
    }
    let salt: [u8; 32] = hex::decode(&header.salt)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid migration salt"))?;
    publish_missing_device_key_updates(
        transport,
        &scan,
        &header,
        hierarchy,
        hierarchy.root.as_bytes(),
        &salt,
        uuid::Uuid::nil(),
        &signing,
    )
    .await?;
    if added {
        scan = scan_topic_sdo_objects(transport, group_id, topic_id, &header, hierarchy).await?;
    }
    let migrated = migrate_v3_history(
        transport as &dyn BlockTransport,
        &header,
        hierarchy,
        &credential_header_wire,
        &scan.records,
        operation_path,
        operation,
        &load_owner_capability(config_path)?,
    )
    .await?;

    header.retained_key_bridges = header
        .rotation_state
        .as_ref()
        .and_then(|state| state.get("key_bridges"))
        .cloned()
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    header.rotation_state = None;
    let expected_revision = header.revision;
    let final_header_id = publish_signed_header_update_in_transaction(
        transport,
        config,
        hierarchy,
        config_path,
        expected_revision,
        header,
        admin,
    )
    .await?;

    let mut cursor = None;
    let mut obsolete_headers = Vec::new();
    loop {
        let page = transport
            .list_topic_page(group_id, topic_id, None, None, cursor, 100)
            .await
            .context("enumerate obsolete TGHD revisions")?;
        if page.raw_message_ids.is_empty() {
            break;
        }
        cursor = page.raw_message_ids.last().copied();
        for document in page.documents {
            if document.message_id == final_header_id {
                continue;
            }
            let magic = transport.download_range(document.message_id, 0, 4).await?;
            if document.filename == "teagarden-header-v1.tgh" || magic.as_slice() == b"TGHD" {
                obsolete_headers.push(document.message_id);
            }
        }
        if page.exhausted {
            break;
        }
    }
    obsolete_headers.sort_unstable();
    obsolete_headers.dedup();
    for batch in obsolete_headers.chunks(100) {
        delete_message_batch_retry(transport as &dyn BlockTransport, batch)
            .await
            .context("delete obsolete TGHD revisions after verified migration")?;
    }
    operation["phase"] = serde_json::Value::String("complete".into());
    operation["final_header_message_id"] = serde_json::json!(final_header_id);
    teagarden_core::fsutil::write_file_atomic(
        operation_path,
        &serde_json::to_vec_pretty(operation)?,
        "completed owner revocation state",
    )?;
    Ok(migrated)
}

async fn scan_header_topic(
    transport: &dyn BlockTransport,
    group_id: i64,
    topic_id: i64,
) -> Result<
    Option<(
        teagarden_telegram::types::DocumentInfo,
        HeaderDocument,
        Vec<u8>,
    )>,
> {
    let mut cursor = None;
    let mut candidates = Vec::new();
    loop {
        let page = transport
            .list_topic_page(group_id, topic_id, None, None, cursor, 100)
            .await
            .context("enumerate raw Telegram topic messages")?;
        if page.raw_message_ids.is_empty() {
            break;
        }
        cursor = page.raw_message_ids.last().copied();
        for document in page.documents {
            let prefix = transport
                .download_range(document.message_id, 0, 4)
                .await
                .with_context(|| format!("inspect topic document {}", document.message_id))?;
            if prefix.as_slice() != b"TGHD" {
                continue;
            }
            let bytes = transport
                .download_block(document.message_id)
                .await
                .with_context(|| format!("download TGHD candidate {}", document.message_id))?
                .data;
            let header = super::decrypt::parse_header_json(&bytes)
                .with_context(|| format!("parse TGHD candidate {}", document.message_id))?;
            if header.group_id != group_id || header.topic_id != topic_id {
                continue;
            }
            candidates.push((document, header, bytes));
        }
        if page.exhausted {
            break;
        }
    }
    let owner_format_seen = candidates.iter().any(|(_, header, _)| header.format == 2);
    let Some(highest_revision) = candidates.iter().map(|(_, h, _)| h.revision).max() else {
        return Ok(None);
    };
    let mut highest: Vec<_> = candidates
        .into_iter()
        .filter(|(_, header, _)| header.revision == highest_revision)
        .collect();
    if highest
        .iter()
        .skip(1)
        .any(|candidate| candidate.2 != highest[0].2)
    {
        anyhow::bail!("conflicting TGHD headers have revision {highest_revision}");
    }
    anyhow::ensure!(!owner_format_seen || highest.iter().all(|(_, header, _)| header.format == 2),
        "refusing TGHD1 downgrade: this topic contains TGHD2; attach requires the trusted owner public key");
    highest.sort_by_key(|(document, _, _)| document.message_id);
    Ok(highest.pop())
}

/// Connect the user's own Telegram session (no storage location bound).
pub(crate) async fn connect_user_session() -> Result<TelegramClient> {
    use teagarden_telegram::types::AuthState;

    let (api_id, api_hash) = utils::load_telegram_credentials()?;
    let client = TelegramClient::new(TelegramConfig {
        api_id,
        api_hash,
        session_path: session_file_path().to_string_lossy().to_string(),
        channel_ref: None,
        ..Default::default()
    });
    let state = client.connect().await.map_err(utils::telegram_err)?;
    if state != AuthState::Authenticated {
        anyhow::bail!("not authenticated with Telegram; run `teagarden auth login` first");
    }
    Ok(client)
}

/// Upgrade legitimate acknowledged in-flight saves without asking the writer to
/// repeat its operation. Verify the replacement before retiring the old document.
#[cfg(feature = "key-rotation")]
async fn upgrade_survivor_batch(
    transport: &dyn BlockTransport,
    objects: &mut [(i64, Vec<u8>)],
    header_wire: &[u8],
    hierarchy: &KeyHierarchy,
) -> Result<()> {
    use teagarden_core::sdo::SdoFileObjectV3;
    let policy = HeaderDocument::decode(header_wire, &hierarchy.integrity)?;
    // Owner migration owns replacement/deletion until it publishes its completed
    // header. Handoff delivery must not wait on a temporary deletion outage.
    if policy.rotation_state.is_some() {
        return Ok(());
    }
    let active = policy.key_generation.unwrap_or(0);
    let keys = generation_meta_keys(&policy, hierarchy)?;
    for (message_id, wire) in objects {
        if wire.get(4..6) != Some(&[3, 0]) || wire.len() < 34 {
            continue;
        }
        let generation = u64::from_le_bytes(
            wire.get(22..30)
                .context("truncated TGFV generation prefix")?
                .try_into()?,
        );
        if generation >= active {
            continue;
        }
        let source_key = keys
            .get(&generation)
            .context("missing source key for surviving concurrent save")?;
        let source_header =
            SdoFileObjectV3::decode_header(wire, policy.volume_id, generation, source_key)?;
        if policy
            .revoked_device_ids
            .contains(&source_header.metadata.author_device_id)
            || !teagarden_core::sdo::object_transition_is_acceptable(
                &policy,
                &source_header.metadata,
                *message_id,
            )
        {
            continue;
        }
        let source = transport.download_block(*message_id).await?.data;
        let mut object =
            SdoFileObjectV3::decode(&source, policy.volume_id, generation, source_key)?;
        object.metadata.key_generation = active;
        let replacement = SdoFileObjectV3::encode(
            policy.volume_id,
            active,
            &hierarchy.meta,
            object.metadata.clone(),
            &object.content,
        )?;
        let replacement =
            teagarden_core::sdo::ObjectEnvelope::seal(&replacement, header_wire, hierarchy)?;
        let uploaded = transport
            .upload_file_object(&replacement, "teagarden-file-v3.tgf")
            .await?;
        let verified_wire = transport.download_block(uploaded.message_id).await?.data;
        let verified =
            SdoFileObjectV3::decode(&verified_wire, policy.volume_id, active, &hierarchy.meta)?;
        anyhow::ensure!(
            verified.metadata == object.metadata && verified.content == object.content,
            "surviving concurrent-save replacement differs from its acknowledged source"
        );
        transport.delete_message(*message_id).await?;
        let size = u32::from_le_bytes(
            verified_wire
                .get(30..34)
                .context("truncated replacement TGFV prefix")?
                .try_into()?,
        ) as usize;
        let header_end = 34usize
            .checked_add(size)
            .context("replacement TGFV header length overflow")?;
        let replacement_header = verified_wire
            .get(..header_end)
            .context("truncated replacement TGFV header")?
            .to_vec();
        *message_id = uploaded.message_id;
        *wire = replacement_header;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn start_sdo_topic_poller(
    transport: Arc<dyn BlockTransport>,
    group_id: i64,
    topic_id: i64,
    volume_id: uuid::Uuid,
    installation_id: uuid::Uuid,
    decapsulation_key: Option<teagarden_core::crypto::mlkem::MlKemDecapsulationKey>,
    initial_generation: u64,
    initial_boundary: Option<i64>,
    initial_integrity_key: teagarden_core::crypto::keys::SymmetricKey,
    generation_meta_keys: std::collections::BTreeMap<
        u64,
        teagarden_core::crypto::keys::SymmetricKey,
    >,
    cursor: Arc<std::sync::atomic::AtomicI64>,
    last_activity: Arc<std::sync::atomic::AtomicU64>,
    activity_notify: Arc<tokio::sync::Notify>,
    notifier_slot: Arc<Mutex<Option<fuser::Notifier>>>,
    sender: tokio::sync::mpsc::Sender<teagarden_fuse::fs::SdoPollBatch>,
    owner_public_key: Option<String>,
    initial_object_envelope: Option<(Vec<u8>, KeyHierarchy)>,
    transition_base_dir: Option<PathBuf>,
) -> tokio::task::JoinHandle<()> {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[cfg(not(feature = "key-rotation"))]
    let _ = (volume_id, installation_id, decapsulation_key);
    tokio::spawn(async move {
        let mut backoff_secs = 3u64;
        let mut active_generation = initial_generation;
        let mut generation_boundary = initial_boundary;
        let mut integrity_key = initial_integrity_key;
        let mut current_generation_meta_keys = generation_meta_keys;
        let mut current_object_envelope = initial_object_envelope;
        loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let active = now.saturating_sub(last_activity.load(Ordering::Relaxed)) < 60;
            tokio::select! {
                _ = tokio::time::sleep(teagarden_telegram::topic_poller::poll_interval(active)) => {},
                _ = activity_notify.notified() => {},
            }

            let after = cursor.load(Ordering::Relaxed);
            let batch = match teagarden_telegram::topic_poller::collect_topic_batch(
                transport.as_ref(),
                group_id,
                topic_id,
                after,
                100,
            )
            .await
            {
                Ok(batch) => batch,
                Err(error) => {
                    tracing::warn!(%error, "portable topic poll failed; retaining cursor");
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }
            };
            if batch.raw_message_ids.is_empty() {
                backoff_secs = 3;
                continue;
            }

            let mut objects = Vec::new();
            let mut generation_update: Option<teagarden_fuse::fs::SdoGenerationUpdate> = None;
            #[cfg(feature = "key-rotation")]
            let mut handoff_integrity_key: Option<
                teagarden_core::crypto::keys::SymmetricKey,
            > = None;
            #[cfg(not(feature = "key-rotation"))]
            let handoff_integrity_key: Option<
                teagarden_core::crypto::keys::SymmetricKey,
            > = None;
            #[cfg(feature = "key-rotation")]
            let mut failed_handoffs = Vec::<(u64, i64)>::new();
            let mut fetch_failed = false;
            for document in batch.documents {
                let prefix = match transport.download_range(document.message_id, 0, 34).await {
                    Ok(prefix) => prefix,
                    Err(error) => {
                        tracing::warn!(message_id = document.message_id, %error, "read polled object prefix failed");
                        fetch_failed = true;
                        break;
                    }
                };
                if prefix.get(..4) == Some(b"TGKU") {
                    #[cfg(feature = "key-rotation")]
                    if let (Some(owner), Some(private)) =
                        (owner_public_key.as_deref(), decapsulation_key.as_ref())
                    {
                        let selected_generation = generation_update.as_ref().map_or(
                            active_generation,
                            |update: &teagarden_fuse::fs::SdoGenerationUpdate| {
                                update.active_generation
                            },
                        );
                        let mut attempted_generation = None;
                        let mut retry_handoff_download = false;
                        let handoff = async {
                            let length = u32::from_le_bytes(
                                prefix
                                    .get(4..8)
                                    .context("truncated TGKU length prefix")?
                                    .try_into()?,
                            );
                            anyhow::ensure!(length <= 64 * 1024, "device handoff is overlong");
                            let wire = match transport
                                .download_range(document.message_id, 0, length + 72)
                                .await
                            {
                                Ok(wire) => wire,
                                Err(error) => {
                                    retry_handoff_download = true;
                                    return Err(error.into());
                                }
                            };
                            if wire.len() != (length + 72) as usize {
                                retry_handoff_download = true;
                                anyhow::bail!(
                                    "incomplete TGKU body download; retaining package for retry"
                                );
                            }
                            let update = decode_device_handoff(&wire, volume_id, owner)?;
                            if update.installation_id != installation_id
                                || update.key_generation <= selected_generation
                            {
                                return Ok(None);
                            }
                            attempted_generation = Some(update.key_generation);
                            let root = unwrap_device_key_update(volume_id, &update, private)?;
                            let hierarchy = teagarden_core::crypto::kdf::derive_hierarchy_v1(
                                teagarden_core::crypto::keys::SymmetricKey::from_bytes(root),
                                &update.salt,
                                group_id,
                                topic_id,
                            )?;
                            let (_, header, header_wire) = discover_latest_header(
                                transport.as_ref(),
                                group_id,
                                topic_id,
                                &hierarchy.integrity,
                                Some(owner),
                            )
                            .await?
                            .context("new owner header is not published yet")?;
                            anyhow::ensure!(
                                header.key_generation == Some(update.key_generation),
                                "handoff generation does not match the current owner header"
                            );
                            header.require_complete_revocation_cutoffs()?;
                            let keys = self::generation_meta_keys(&header, &hierarchy)?;
                            if let Some(directory) = &transition_base_dir {
                                persist_device_transition(directory, &wire, &header_wire)?;
                            }
                            Ok::<_, anyhow::Error>(Some((hierarchy, header, header_wire, keys)))
                        }
                        .await;
                        match handoff {
                            Ok(Some((hierarchy, header, wire, keys))) => {
                                handoff_integrity_key = Some(hierarchy.integrity.clone());
                                generation_update = Some(teagarden_fuse::fs::SdoGenerationUpdate {
                                    active_generation: header.key_generation.unwrap(),
                                    boundary_message_id: header.generation_boundary_message_id,
                                    generation_meta_keys: keys,
                                    object_envelope: Some((wire, hierarchy)),
                                });
                            }
                            Ok(None) => {}
                            Err(error) => {
                                if retry_handoff_download {
                                    tracing::warn!(%error, "handoff download is incomplete; retaining poll cursor");
                                    fetch_failed = true;
                                    break;
                                }
                                if let Some(generation) = attempted_generation {
                                    // An older retained package may no longer authenticate
                                    // the newest header. Examine later packages in this batch.
                                    failed_handoffs.push((generation, document.message_id));
                                    tracing::debug!(%error, generation, "examining further handoffs for a usable current generation");
                                } else {
                                    // No authenticated package was obtained. A malformed
                                    // public control document must not kill or stall polling.
                                    tracing::warn!(%error, "ignoring malformed or unauthenticated device handoff");
                                }
                            }
                        }
                    }
                    continue;
                }
                if prefix.get(..4) != Some(b"TGFV") {
                    continue;
                }
                let format = prefix
                    .get(4..6)
                    .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                    .map(u16::from_le_bytes)
                    .unwrap_or(0);
                let (fixed, length_range) = match format {
                    2 if prefix.len() >= 26 => (26usize, 22..26),
                    3 if prefix.len() >= 34 => (34usize, 30..34),
                    _ => {
                        tracing::error!(
                            message_id = document.message_id,
                            format,
                            "recognized polled TGFV has invalid framing"
                        );
                        fetch_failed = true;
                        break;
                    }
                };
                let header_len = u32::from_le_bytes(
                    prefix[length_range]
                        .try_into()
                        .expect("fixed framing range"),
                ) as usize;
                let total = match fixed.checked_add(header_len) {
                    Some(total) if total <= teagarden_core::sdo::MAX_MANIFEST_SIZE => total,
                    _ => {
                        tracing::error!(
                            message_id = document.message_id,
                            "polled TGFV header exceeds size limit"
                        );
                        fetch_failed = true;
                        break;
                    }
                };
                let wire = match transport
                    .download_range(document.message_id, 0, total as u32)
                    .await
                {
                    Ok(wire) => wire,
                    Err(error) => {
                        tracing::warn!(message_id = document.message_id, %error, "fetch polled TGFV header failed");
                        fetch_failed = true;
                        break;
                    }
                };
                #[cfg(feature = "key-rotation")]
                if format == 3 {
                    let object_generation = u64::from_le_bytes(prefix[22..30].try_into().unwrap());
                    if let Some(meta_key) = current_generation_meta_keys.get(&object_generation) {
                        if let Ok(device_record) =
                            teagarden_core::sdo::SdoFileObjectV3::decode_header(
                                &wire,
                                volume_id,
                                object_generation,
                                meta_key,
                            )
                        {
                            if device_record.metadata.kind == teagarden_core::sdo::SdoKind::Device
                                && device_record.metadata.installation_id == Some(installation_id)
                            {
                                if let (Some(update), Some(private_key)) = (
                                    device_record.metadata.device_key_update.as_ref().filter(
                                        |update| {
                                            owner_public_key.is_none()
                                                && update.key_generation > active_generation
                                        },
                                    ),
                                    decapsulation_key.as_ref(),
                                ) {
                                    let new_root = match unwrap_device_key_update(
                                        volume_id,
                                        update,
                                        private_key,
                                    ) {
                                        Ok(root) => root,
                                        Err(error) => {
                                            tracing::error!(%error, "device key handoff authentication failed");
                                            fetch_failed = true;
                                            break;
                                        }
                                    };
                                    let hierarchy = match teagarden_core::crypto::kdf::derive_hierarchy_from_master_key(
                                        &new_root,
                                        &update.salt,
                                        group_id,
                                        topic_id,
                                    ) {
                                        Ok(hierarchy) => hierarchy,
                                        Err(error) => {
                                            tracing::error!(%error, "derive handed-off generation keys failed");
                                            fetch_failed = true;
                                            break;
                                        }
                                    };
                                    handoff_integrity_key = Some(hierarchy.integrity.clone());
                                    match discover_latest_header(
                                        transport.as_ref(),
                                        group_id,
                                        topic_id,
                                        &hierarchy.integrity,
                                        owner_public_key.as_deref(),
                                    )
                                    .await
                                    {
                                        Ok(Some((_, header, header_wire)))
                                            if header.key_generation
                                                == Some(update.key_generation) =>
                                        {
                                            if let Err(error) =
                                                header.require_complete_revocation_cutoffs()
                                            {
                                                tracing::error!(%error, "refusing incomplete handed-off policy");
                                                fetch_failed = true;
                                                break;
                                            }
                                            match self::generation_meta_keys(&header, &hierarchy) {
                                                Ok(keys) => {
                                                    generation_update = Some(
                                                        teagarden_fuse::fs::SdoGenerationUpdate {
                                                            active_generation: update
                                                                .key_generation,
                                                            boundary_message_id: header
                                                                .generation_boundary_message_id,
                                                            generation_meta_keys: keys,
                                                            object_envelope: Some((
                                                                header_wire,
                                                                hierarchy.clone(),
                                                            )),
                                                        },
                                                    );
                                                }
                                                Err(error) => {
                                                    tracing::error!(%error, "resolve handed-off key generations failed");
                                                    fetch_failed = true;
                                                    break;
                                                }
                                            }
                                        }
                                        Ok(_) => {
                                            tracing::debug!("device key handoff arrived before its signed TGHD2 header; retaining cursor");
                                            fetch_failed = true;
                                            break;
                                        }
                                        Err(error) => {
                                            tracing::debug!(%error, "new TGHD2 header not available for device key handoff yet");
                                            fetch_failed = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                objects.push((document.message_id, wire));
            }
            if fetch_failed {
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
                continue;
            }

            #[cfg(feature = "key-rotation")]
            let mut authenticated_current = false;
            let candidate_integrity = handoff_integrity_key.as_ref().unwrap_or(&integrity_key);
            let refreshed = match discover_latest_header(
                transport.as_ref(),
                group_id,
                topic_id,
                candidate_integrity,
                owner_public_key.as_deref(),
            )
            .await
            {
                Ok(Some(header)) => Some(header),
                Ok(None) if owner_public_key.is_none() => None,
                result => {
                    tracing::warn!(error = ?result.err(), "current owner header unavailable or invalid; retaining poll cursor");
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    continue;
                }
            };
            if let Some((_, refreshed_header, refreshed_wire)) = refreshed {
                if let Some(base_dir) = transition_base_dir.as_ref() {
                    if let Err(error) =
                        policy::observe(&base_dir.join("volume.json"), &refreshed_header)
                    {
                        tracing::error!(%error, "refusing owner header below persisted revision floor; retaining poll cursor");
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        continue;
                    }
                }
                if let Err(error) = refreshed_header.require_complete_revocation_cutoffs() {
                    tracing::error!(%error, "refusing incomplete current policy; retaining poll cursor");
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    continue;
                }
                if let Some((previous_wire, previous_hierarchy)) = current_object_envelope.as_ref()
                {
                    let successor = HeaderDocument::decode_pinned(
                        previous_wire,
                        &previous_hierarchy.integrity,
                        owner_public_key.as_deref(),
                    )
                    .and_then(|previous| refreshed_header.require_policy_successor(&previous));
                    if let Err(error) = successor {
                        tracing::warn!(%error, "refusing replayed owner policy; retaining poll cursor");
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        continue;
                    }
                }
                let expected_generation = generation_update
                    .as_ref()
                    .map_or(active_generation, |update| update.active_generation);
                #[cfg(feature = "key-rotation")]
                {
                    authenticated_current =
                        refreshed_header.key_generation == Some(expected_generation);
                }
                if refreshed_header.key_generation == Some(expected_generation)
                    && (generation_update.is_some()
                        || refreshed_header.generation_boundary_message_id != generation_boundary
                        || current_object_envelope
                            .as_ref()
                            .is_some_and(|(wire, _)| *wire != refreshed_wire))
                {
                    let keys = generation_update.as_ref().map_or_else(
                        || current_generation_meta_keys.clone(),
                        |update| update.generation_meta_keys.clone(),
                    );
                    generation_update = Some(teagarden_fuse::fs::SdoGenerationUpdate {
                        active_generation: expected_generation,
                        boundary_message_id: refreshed_header.generation_boundary_message_id,
                        generation_meta_keys: keys,
                        object_envelope: generation_update
                            .as_ref()
                            .and_then(|update| update.object_envelope.as_ref())
                            .or(current_object_envelope.as_ref())
                            .map(|(_, hierarchy)| (refreshed_wire, hierarchy.clone())),
                    });
                }
            }

            #[cfg(feature = "key-rotation")]
            let selected_generation = generation_update
                .as_ref()
                .map_or(active_generation, |update| update.active_generation);
            let high_water_id = batch.high_water_id;
            #[cfg(feature = "key-rotation")]
            let mut high_water_id = high_water_id;
            #[cfg(feature = "key-rotation")]
            if let Some(pending_id) = failed_handoffs
                .iter()
                .filter(|(generation, _)| *generation > selected_generation)
                .map(|(_, id)| *id)
                .min()
            {
                if !authenticated_current {
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }
                // Keep unpublished future packages reachable, while installing
                // the highest handoff that authenticates the current header now.
                high_water_id = high_water_id.min(pending_id.saturating_sub(1));
            }

            #[cfg(feature = "key-rotation")]
            if let Some((header_wire, hierarchy)) = generation_update
                .as_ref()
                .and_then(|update| update.object_envelope.as_ref())
                .or(current_object_envelope.as_ref())
            {
                if let Err(error) =
                    upgrade_survivor_batch(transport.as_ref(), &mut objects, header_wire, hierarchy)
                        .await
                {
                    tracing::warn!(%error, "surviving concurrent saves remain queued for upgrade");
                    continue;
                }
            }
            let (ack, wait) = tokio::sync::oneshot::channel();
            if sender
                .send(teagarden_fuse::fs::SdoPollBatch {
                    high_water_id,
                    objects,
                    generation_update: generation_update.clone(),
                    ack,
                })
                .await
                .is_err()
            {
                break;
            }
            if let Some(notifier) = notifier_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                if let Err(error) = notifier.inval_inode(1, 0, -1) {
                    tracing::debug!(%error, "wake FUSE request loop for remote topic batch failed");
                }
            }
            match wait.await {
                Ok(Ok(())) => {
                    cursor.store(high_water_id, Ordering::Relaxed);
                    if let Some(update) = generation_update {
                        active_generation = update.active_generation;
                        generation_boundary = update.boundary_message_id;
                        current_generation_meta_keys = update.generation_meta_keys;
                        if let Some(envelope) = update.object_envelope {
                            current_object_envelope = Some(envelope);
                        }
                        if let Some(integrity) = handoff_integrity_key {
                            integrity_key = integrity;
                        }
                        tracing::info!(generation = active_generation, boundary = ?generation_boundary, "installed current volume key generation and boundary");
                    }
                    backoff_secs = 3;
                }
                Ok(Err(errno)) => {
                    tracing::warn!(
                        errno,
                        high_water_id,
                        "remote SDO batch apply failed; retaining poll cursor"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                }
                Err(_) => {
                    tracing::warn!(
                        high_water_id,
                        "FUSE dropped remote SDO batch; retaining poll cursor"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                }
            }
        }
    })
}

/// Ensure the shared storage group exists (creating it on the first volume and
/// persisting it to `group.json`), then create this volume's forum topic with a
/// random title (see [`super::group::allocate_topic`]: the display name is
/// never sent). Returns `(group_id, group_access_hash, topic_id)`.
async fn ensure_group_and_topic(
    forum: &dyn ForumAdmin,
    group_path: &std::path::Path,
    group_name: Option<&str>,
) -> Result<(i64, i64, i64)> {
    let a = super::group::allocate_topic(forum, group_path, group_name).await?;
    Ok((a.group_id, a.group_access_hash, a.topic_id))
}

/// Return the session file path.
pub(crate) fn session_file_path() -> PathBuf {
    utils::session_file_path()
}

/// Read a volume password from a file (or stdin via `-`), or prompt interactively.
fn read_volume_password(password_file: Option<&str>) -> Result<utils::SecretString> {
    utils::read_password_input(password_file)
}

/// Resolve a display name or UUID prefix to the canonical UUID string.
pub(crate) fn resolve_volume_id(volume: &str, volumes_dir: &std::path::Path) -> Result<String> {
    // Fast path: if a directory with this exact name exists it's already a UUID.
    if volumes_dir.join(volume).join("volume.json").exists() {
        return Ok(volume.to_string());
    }

    // Search by display name or UUID prefix.
    let all = manager::list_volumes(volumes_dir).map_err(utils::core_err)?;
    let needle = volume.to_lowercase();
    let matches: Vec<_> = all
        .iter()
        .filter(|c| {
            c.display_name.to_lowercase() == needle || c.volume_id.to_string().starts_with(volume)
        })
        .collect();

    match matches.len() {
        0 => anyhow::bail!(
            "volume not found: '{}'\nUse `teagarden volume list` to see available volumes.",
            volume
        ),
        1 => Ok(matches[0].volume_id.to_string()),
        _ => {
            let names: Vec<_> = matches.iter().map(|c| &c.display_name).collect();
            anyhow::bail!(
                "ambiguous volume name '{}' — matches: {:?}\nUse the volume UUID instead.",
                volume,
                names
            )
        }
    }
}

/// Download the raw portable header and file objects through the user's MTProto session.
pub async fn export_objects(
    volume: &str,
    out_dir: &std::path::Path,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    if out_dir.exists() {
        anyhow::bail!("output directory already exists: {}", out_dir.display());
    }
    let volumes_dir = manager::default_volumes_dir();
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;
    let _volume_lock = manager::VolumeLock::acquire_exclusive(&volumes_dir.join(&volume_id))
        .context("lock volume for owner administration")?;
    let opened = utils::open_volume_any(&volume_id, password_file, recovery_file, &volumes_dir)?;
    #[cfg(test)]
    if let Ok(client) = super::key::TEST_PORTABLE_TRANSPORT.try_with(Arc::clone) {
        return export_objects_command(client.as_ref(), &opened, out_dir).await;
    }
    let client = connect_user_session().await?;
    export_objects_command(&client, &opened, out_dir).await
}

async fn export_objects_command(
    client: &dyn ForumAdmin,
    opened: &manager::OpenVolumeResult,
    out_dir: &std::path::Path,
) -> Result<()> {
    bind_opened_topic(client, &opened.config).await?;
    let (newest_document, newest_header, _) = discover_latest_header(
        client,
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &opened.hierarchy.integrity,
        opened.config.sdo_owner_public_key.as_deref(),
    )
    .await?
    .context("volume has no authenticated portable header")?;
    policy::observe(&opened.paths.config_path, &newest_header)?;
    newest_header.require_complete_revocation_cutoffs()?;
    let generation_keys = generation_meta_keys(&newest_header, &opened.hierarchy)?;
    let source_owner = if owner_capability_path(&opened.paths.config_path)?.exists() {
        let owner = load_owner_capability(&opened.paths.config_path)?;
        anyhow::ensure!(
            newest_header.owner_public_key.as_deref()
                == Some(hex::encode(owner.verifying_key().to_bytes()).as_str()),
            "export source capability does not match the authenticated owner"
        );
        Some(owner)
    } else {
        None
    };

    std::fs::create_dir(out_dir)
        .with_context(|| format!("create export directory {}", out_dir.display()))?;
    let result = async {
        let mut before = None;
        let mut written = 0usize;
        let mut provenance = serde_json::Map::new();
        loop {
            let page = client
                .list_topic_page(
                    opened.config.telegram_group_id,
                    opened.config.telegram_topic_id,
                    None,
                    None,
                    before,
                    100,
                )
                .await
                .map_err(utils::telegram_err)?;
            if page.raw_message_ids.is_empty() {
                break;
            }
            let next_before = page.raw_message_ids.last().copied();
            for document in page.documents {
                if document.group_id != opened.config.telegram_group_id
                    || document.topic_id != opened.config.telegram_topic_id
                {
                    anyhow::bail!(
                        "Telegram returned a document outside the authenticated volume topic"
                    );
                }
                let magic = client.download_range(document.message_id, 0, 4).await
                    .with_context(|| format!("inspect export document {}", document.message_id))?;
                if magic.as_slice() != b"TGHD" && magic.as_slice() != b"TGFV" {
                    continue;
                }
                if magic.as_slice() == b"TGHD" && document.message_id != newest_document.message_id {
                    continue;
                }
                let downloaded = client
                    .download_block(document.message_id)
                    .await
                    .map_err(utils::telegram_err)?;
                anyhow::ensure!(downloaded.data.starts_with(&magic), "export document framing changed during download");
                let filename = if downloaded.data.starts_with(b"TGHD") {
                    let header = HeaderDocument::decode_pinned(&downloaded.data,
                        &opened.hierarchy.integrity, opened.config.sdo_owner_public_key.as_deref())
                        .context("authenticate downloaded TGHD header")?;
                    anyhow::ensure!(header == newest_header, "export header changed during download");
                    format!("header-{}.tgh", document.message_id)
                } else if downloaded.data.starts_with(b"TGFV") {
                    let metadata = match downloaded.data.get(4..6) {
                        Some([2, 0]) => {
                            let object = teagarden_core::sdo::SdoFileObject::decode_header(
                                &downloaded.data,
                                opened.config.volume_id,
                                generation_keys
                                    .get(&0)
                                    .context("missing legacy generation key during export")?,
                            )
                            .context("authenticate downloaded TGFV v2 header")?;
                            teagarden_core::sdo::legacy_metadata_v3(&object.metadata)
                        }
                        Some([3, 0]) if downloaded.data.len() >= 30 => {
                            let generation =
                                u64::from_le_bytes(downloaded.data[22..30].try_into().unwrap());
                            teagarden_core::sdo::SdoFileObjectV3::decode_header(
                                &downloaded.data,
                                opened.config.volume_id,
                                generation,
                                generation_keys.get(&generation).with_context(|| {
                                    format!("missing generation {generation} during export")
                                })?,
                            )
                            .context("authenticate downloaded TGFV v3 header")?.metadata
                        }
                        _ => anyhow::bail!("unsupported downloaded TGFV format"),
                    };
                    if !teagarden_core::sdo::object_transition_is_acceptable(&newest_header, &metadata, document.message_id) {
                        tracing::warn!(message_id = document.message_id, "excluded unauthorized object from current-state export");
                        continue;
                    }
                    let filename = format!("file-{}.tgf", document.message_id);
                    provenance.insert(filename.clone(), serde_json::json!({
                        "message_id": document.message_id,
                        "sha256": hex::encode(teagarden_core::block::srb2::sha256(&downloaded.data)),
                    }));
                    filename
                } else {
                    continue;
                };
                let path = out_dir.join(filename);
                use std::io::Write as _;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                file.write_all(&downloaded.data)?;
                file.sync_all()?;
                written += 1;
            }
            before = next_before;
            if page.exhausted {
                break;
            }
        }
        if written == 0 {
            anyhow::bail!("no authenticated TGHD or TGFV objects were found in this volume topic");
        }
        let payload = serde_json::json!({
            "format": 1,
            "volume_id": newest_header.volume_id,
            "header_revision": newest_header.revision,
            "header_sha256": hex::encode(teagarden_core::block::srb2::sha256(&serde_json::to_vec(&newest_header)?)),
            "objects": provenance,
        });
        super::decrypt::write_export_provenance(out_dir, payload, &opened.hierarchy.integrity, source_owner.as_ref())?;
        Ok::<usize, anyhow::Error>(written)
    }
    .await;
    match result {
        Ok(count) => {
            println!(
                "Downloaded {count} raw TGHD/TGFV object(s) to {}",
                out_dir.display()
            );
            Ok(())
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(out_dir);
            Err(error)
        }
    }
}

async fn repair_pending_header_before_mount(
    transport: &dyn BlockTransport,
    opened: &mut manager::OpenVolumeResult,
) -> Result<()> {
    let admin = manager::OwnerAdminLock::acquire(&opened.paths.base_dir)?;
    let mut current: VolumeConfig =
        serde_json::from_slice(&std::fs::read(&opened.paths.config_path)?)?;
    manager::verify_config_anchors(&current, &opened.hierarchy)?;
    if !current.sdo_header_pending {
        opened.config = current;
        return Ok(());
    }
    let bytes =
        hex::decode(current.sdo_header_pending_bytes.as_deref().context(
            "pending portable header has no durable retry bytes; refusing reconstruction",
        )?)?;
    let digest = hex::encode(teagarden_core::block::srb2::sha256(&bytes));
    anyhow::ensure!(
        current.sdo_header_pending_sha256.as_deref() == Some(digest.as_str()),
        "pending portable header digest differs from its retry bytes"
    );
    let header = HeaderDocument::decode_pinned(
        &bytes,
        &opened.hierarchy.integrity,
        current.sdo_owner_public_key.as_deref(),
    )?;
    anyhow::ensure!(
        header.volume_id == current.volume_id
            && header.group_id == current.telegram_group_id
            && header.topic_id == current.telegram_topic_id
            && header.revision == current.sdo_header_revision_reserved
            && header.salt == hex::encode(current.salt),
        "pending header differs from the reserved volume identity"
    );
    if header.root_kind == RootKind::MasterKey {
        let intended: teagarden_core::volume::config::KeyProtection = serde_json::from_value(
            header
                .key_protection
                .clone()
                .context("pending slot header has no vault anchor")?,
        )?;
        let mut vault = teagarden_mfa::kslot::SlotVault::from_bytes(&serde_json::to_vec(
            header
                .slot_vault
                .as_ref()
                .context("pending slot header has no vault")?,
        )?)?;
        anyhow::ensure!(
            vault.generation() == intended.vault_generation
                && hex::encode(vault.state_digest()) == intended.vault_digest,
            "pending slot header vault differs from its signed anchor"
        );
        let path = opened
            .paths
            .base_dir
            .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
        let live = teagarden_mfa::kslot::SlotVault::load(&path)?;
        let live_anchor = teagarden_core::volume::config::KeyProtection {
            vault_generation: live.generation(),
            vault_digest: hex::encode(live.state_digest()),
        };
        anyhow::ensure!(
            current.key_protection.as_ref() == Some(&live_anchor),
            "live vault differs from the authenticated local anchor"
        );
        if live_anchor != intended {
            anyhow::ensure!(
                intended.vault_generation > live_anchor.vault_generation,
                "pending slot vault would roll back the live vault"
            );
            vault.save(&path)?;
            current.key_protection = Some(intended);
            manager::save_config_resealed_in_transaction(
                &mut current,
                &opened.hierarchy,
                &opened.paths.config_path,
                &admin,
            )?;
        }
    }
    let remote = discover_latest_header(
        transport,
        current.telegram_group_id,
        current.telegram_topic_id,
        &opened.hierarchy.integrity,
        current.sdo_owner_public_key.as_deref(),
    )
    .await?;
    if let Some((_, stored, wire)) = &remote {
        policy::observe(&opened.paths.config_path, stored)?;
        anyhow::ensure!(
            stored.revision <= header.revision,
            "newer owner policy exists; refusing to publish an older pending header"
        );
        if stored.revision == header.revision {
            anyhow::ensure!(
                *wire == bytes,
                "Telegram contains different bytes at the pending revision"
            );
        } else {
            header.require_policy_successor(stored)?;
        }
    }
    if remote.as_ref().is_none_or(|(_, _, wire)| *wire != bytes) {
        transport.upload_block(&bytes,"teagarden-header-v1.tgh").await.context("repair pending portable-header publication before mount; exact signed bytes remain pending")?;
    }
    acknowledge_owner_header(
        &opened.paths.config_path,
        &opened.hierarchy,
        header.revision,
        &bytes,
        &admin,
    )?;
    opened.config = serde_json::from_slice(&std::fs::read(&opened.paths.config_path)?)?;
    manager::verify_config_anchors(&opened.config, &opened.hierarchy)?;
    Ok(())
}

/// Shared preparation path used before the real mount creates a FUSE session.
async fn prepare_sdo_mount(
    transport: Arc<dyn BlockTransport>,
    opened: &manager::OpenVolumeResult,
    mut fs: CryptFs,
    authorization_hash: Option<i64>,
) -> Result<(CryptFs, i64)> {
    if opened.config.sdo_header_pending {
        let mut pending = manager::OpenVolumeResult {
            config: opened.config.clone(),
            paths: manager::VolumePaths::new(opened.paths.base_dir.clone()),
            hierarchy: opened.hierarchy.clone(),
        };
        repair_pending_header_before_mount(transport.as_ref(), &mut pending).await?;
    }
    let (_, header, header_wire) = discover_latest_header(
        transport.as_ref(),
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &opened.hierarchy.integrity,
        opened.config.sdo_owner_public_key.as_deref(),
    )
    .await?
    .context("portable mount requires an authenticated initial TGHD header")?;
    policy::observe(&opened.paths.config_path, &header)?;
    let installation = opened
        .config
        .sdo_author_device_id
        .context("portable mount has no installation id")?;
    anyhow::ensure!(
        !header.revoked_device_ids.contains(&installation),
        "this installation is revoked"
    );
    anyhow::ensure!(
        authorization_hash
            .is_none_or(|hash| !header.revoked_account_bindings.contains(&hash.to_string())),
        "this Telegram session is revoked"
    );
    let keys = generation_meta_keys(&header, &opened.hierarchy)?;
    fs = fs
        .with_sdo_generation_keys(
            header.key_generation.unwrap_or(0),
            header.generation_boundary_message_id,
            keys,
        )
        .with_sdo_object_envelope(header_wire, opened.hierarchy.clone())
        .with_transport(transport.clone());
    let (private, public) =
        load_or_create_device_keypair(&opened.paths.base_dir, &opened.hierarchy.wrapping)?;
    let signer = teagarden_core::sdo::device_signing_key(&private.0);
    if let Some(expected) = header.device_authorities.get(&installation) {
        anyhow::ensure!(
            *expected == hex::encode(signer.verifying_key().to_bytes()),
            "installation signing key differs from its established authority"
        );
    }
    fs = fs
        .with_sdo_signing_key(signer)
        .with_sdo_device_public_key(hex::encode(&public.0));
    let (conn, schema, key) = open_sdo_outbox(opened)?;
    fs = fs.with_sdo_outbox(conn, schema, key);
    let scan = scan_topic_sdo_objects(
        transport.as_ref(),
        header.group_id,
        header.topic_id,
        &header,
        &opened.hierarchy,
    )
    .await
    .context("authenticate the complete initial topic before mount readiness")?;
    fs.observe_sdo_clock(scan.max_clock.0, scan.max_clock.1)
        .map_err(errno_to_anyhow)
        .context("seed the HLC before local announcements, retries or writes")?;
    let cursor = scan.high_water_message_id;
    let mut objects: Vec<_> = scan
        .records
        .into_iter()
        .map(|version| (version.message_id, version.wire))
        .collect();
    objects.sort_by_key(|(message_id, _)| *message_id);
    fs.apply_remote_sdo_batch(objects, cursor)
        .map_err(errno_to_anyhow)
        .context("apply the authenticated initial topic before FUSE mount readiness")?;
    let user_id = transport
        .telegram_user_id()
        .await?
        .context("authenticated Telegram user id is unavailable")?;
    let mut label = std::env::var("HOSTNAME").unwrap_or_else(|_| "TeaGarden device".into());
    while label.len() > 128 {
        label.pop();
    }
    let fs = tokio::task::spawn_blocking(move || -> Result<CryptFs> {
        let recovered = fs
            .retry_pending_sdo_writes()
            .map_err(errno_to_anyhow)
            .context("recover the stable portable outbox before mount")?;
        if recovered > 0 {
            tracing::info!(
                recovered,
                "recovered stable portable writes before readiness"
            );
        }
        fs.publish_sdo_device_announcement(&label, user_id, authorization_hash)
            .map_err(errno_to_anyhow)?;
        fs.backfill_sdo_versions().map_err(errno_to_anyhow)?;
        Ok(fs)
    })
    .await
    .context("portable mount preparation worker failed")??;
    Ok((fs, cursor))
}

fn sdo_outbox_path(opened: &manager::OpenVolumeResult) -> PathBuf {
    opened
        .paths
        .base_dir
        .join("outbox")
        .join(
            opened
                .config
                .sdo_author_device_id
                .map_or_else(|| "legacy".into(), |id| id.to_string()),
        )
        .join("pending.db")
}

fn open_sdo_outbox(
    opened: &manager::OpenVolumeResult,
) -> Result<(
    Connection,
    OpaqueSchema,
    teagarden_core::crypto::keys::SymmetricKey,
)> {
    let (private, _) =
        load_or_create_device_keypair(&opened.paths.base_dir, &opened.hierarchy.wrapping)?;
    let key = teagarden_core::crypto::keys::SymmetricKey::from_bytes(
        teagarden_core::sdo::device_signing_key(&private.0).to_bytes(),
    );
    let key = teagarden_core::crypto::kdf::hkdf_derive(
        &key,
        &[
            b"teagarden.outbox.v1".as_slice(),
            opened.config.volume_id.as_bytes(),
        ]
        .concat(),
    )?;
    let schema = OpaqueSchema::new(key.clone(), &logical_tables());
    let path = sdo_outbox_path(opened);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    initialize_database(&conn, &schema)?;
    Ok((conn, schema, key))
}

/// Wire the live receiver and start the prepared mount's poller as one path.
async fn start_prepared_sdo_mount_poller(
    fs: CryptFs,
    transport: Arc<dyn BlockTransport>,
    opened: &manager::OpenVolumeResult,
    initial_cursor: i64,
    notifier_slot: Arc<Mutex<Option<fuser::Notifier>>>,
) -> Result<(CryptFs, Arc<tokio::sync::Notify>)> {
    let (_, header, wire) = discover_latest_header(
        transport.as_ref(),
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &opened.hierarchy.integrity,
        opened.config.sdo_owner_public_key.as_deref(),
    )
    .await?
    .context("prepared mount has no current header")?;
    let (private, _) =
        load_or_create_device_keypair(&opened.paths.base_dir, &opened.hierarchy.wrapping)?;
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let cursor = Arc::new(std::sync::atomic::AtomicI64::new(initial_cursor));
    let activity = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let notify = Arc::new(tokio::sync::Notify::new());
    let fs = fs.with_sdo_poll_inbox(
        receiver,
        notifier_slot.clone(),
        activity.clone(),
        notify.clone(),
    );
    let _poller = start_sdo_topic_poller(
        transport,
        header.group_id,
        header.topic_id,
        header.volume_id,
        opened
            .config
            .sdo_author_device_id
            .context("mount installation is missing")?,
        Some(private),
        header.key_generation.unwrap_or(0),
        header.generation_boundary_message_id,
        opened.hierarchy.integrity.clone(),
        generation_meta_keys(&header, &opened.hierarchy)?,
        cursor,
        activity,
        notify.clone(),
        notifier_slot,
        sender,
        opened.config.sdo_owner_public_key.clone(),
        Some((wire, opened.hierarchy.clone())),
        Some(opened.paths.base_dir.clone()),
    );
    Ok((fs, notify))
}

pub async fn mount(
    volume: &str,
    mountpoint: &str,
    allow_other: bool,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    factor: &FactorSelect,
) -> Result<()> {
    mount_in(
        &manager::default_volumes_dir(),
        volume,
        mountpoint,
        allow_other,
        password_file,
        recovery_file,
        factor,
    )
    .await
}

/// [`mount`] against an explicit volumes directory, so the pre-FUSE refusal paths
/// are testable against a tempdir volume (mirrors `revert_in`).
pub(crate) async fn mount_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    mountpoint: &str,
    allow_other: bool,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    factor: &FactorSelect,
) -> Result<()> {
    let volumes_dir = volumes_dir.to_path_buf();

    // Verify mountpoint exists
    let mp = std::path::Path::new(mountpoint);
    match std::fs::metadata(mp) {
        Ok(_) => {}
        // A mount whose process was killed (SIGKILL) stays attached but dead:
        // plain mounts do not use auto_unmount (see `mount_options`).
        Err(e) if e.raw_os_error() == Some(libc::ENOTCONN) => anyhow::bail!(
            "'{mountpoint}' is a stale mount left by a TeaGarden process that was killed; \
             clear it with `teagarden volume unmount {mountpoint}`, then mount again"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(mp)?;
            println!("Created mountpoint directory: {mountpoint}");
        }
        Err(e) => {
            return Err(e).with_context(|| format!("cannot use mountpoint '{mountpoint}'"));
        }
    }

    // Resolve display name / UUID prefix → canonical UUID directory name
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;

    // This lock is local to this machine: acquire it before reading config so a
    // second local mount cannot race volume administration. Separate computers
    // have separate local lock files and continue to write concurrently.
    let _volume_lock = manager::VolumeLock::acquire_exclusive(&volumes_dir.join(&volume_id))
        .map_err(utils::core_err)?;

    // A read-only shared volume mounts read-only: the recipient holds the volume
    // key (so this is client-enforced, not a cryptographic barrier — it stops
    // accidental writes), and `unlock::open_volume` already routes a shared
    // volume down the shared path via its sidecar.
    let read_only = read_only_share(&volumes_dir.join(&volume_id))?;

    // C3: a WRITABLE mount needs the Telegram transport. Blocks are stored only
    // on Telegram, so without it every file write would be accepted by the
    // kernel and then discarded at close. Refuse up front — before the password
    // prompt, key derivation, or anything is mounted. A read-only share may
    // still mount offline (reads are served from the local block cache).
    if !read_only {
        if let Err(e) = utils::load_telegram_credentials() {
            anyhow::bail!(
                "refusing to mount volume '{volume}' read-write without a Telegram transport \
                 ({e:#}). File contents are stored only on Telegram, so writes made through \
                 this mount could not be saved. Configure credentials with \
                 `teagarden configure` and `teagarden auth login`, then mount again."
            );
        }
    }

    // A device factor (TPM2/Tang/PKCS#11/FIDO2) is a targeted, exclusive
    // alternative to a passphrase/recovery-sentence unlock — it opens the K5
    // slot enrolled via `mfa enroll`, not the passphrase slot. Building BOTH
    // an UnlockInputs::password and a device-factor field would be ambiguous
    // about which slot the caller actually wants, so a factor takes over the
    // whole unlock and password/recovery-file are not read at all.
    //
    // `password`/`recovery_sentence` are declared here (not inside the branch
    // below) so the borrows in `inputs` outlive this whole function body.
    let mut password: Option<utils::SecretString> = None;
    let mut recovery_sentence: Option<utils::SecretString> = None;
    let mut factor_inputs = None;
    let mut factor_msg = None;

    if factor.chosen() > 0 {
        factor.require_exactly_one()?;
        if password_file.is_some() || recovery_file.is_some() {
            anyhow::bail!(
                "a device factor (--tpm2/--tang/--pkcs11-module/--fido2) and \
                 --password-file/--recovery-file are mutually exclusive — pick one \
                 slot to unlock with"
            );
        }
        factor_inputs = Some(build_unlock_inputs(factor)?);
        factor_msg = Some(factor_label(factor));
    } else {
        // A key-protected volume may be unlocked with its recovery sentence instead
        // of the passphrase; when --recovery-file is given we do not prompt for a
        // password.
        recovery_sentence = read_recovery_sentence(recovery_file)?;

        password = if password_file.is_some() {
            Some(utils::read_password_input(password_file)?)
        } else if recovery_sentence.is_some() {
            // Recovery-only unlock — no passphrase needed.
            None
        } else {
            Some(utils::prompt_password("Enter volume password: ")?)
        };
    }

    let inputs = match factor_inputs {
        Some(inputs) => inputs,
        None => teagarden_mfa::unlock::UnlockInputs {
            password: password.as_deref().map(String::as_bytes),
            recovery_sentence: recovery_sentence.as_ref().map(|secret| secret.as_str()),
            ..Default::default()
        },
    };

    // Open volume and derive keys. Routed through the K0b unlock bridge so
    // password, recovery-sentence, and device-factor slots ALL open through one
    // path; a bare password against a protected volume fails closed inside core.
    let mut result = open_mount_credentials(&volume_id, &inputs, &volumes_dir)?;
    let author_device_id =
        if result.config.telegram_group_id != 0 && result.config.telegram_topic_id != 0 {
            Some(ensure_sdo_author_device_id(&mut result)?)
        } else {
            None
        };

    // Lock key pages in RAM and disable core dumps so key material cannot
    // reach swap or be extracted via /proc/<pid>/mem or crash dumps.
    harden_process();

    match factor_msg {
        Some(label) => println!("Volume '{volume}' authenticated successfully via {label}."),
        None => println!("Volume '{volume}' authenticated successfully."),
    }
    if let Err(e) = snapshot_publish_status(&result.paths.base_dir) {
        eprintln!("WARNING: {e:#}\nA fresh snapshot is published again when this mount ends.");
    }

    // --- Telegram transport setup ---

    // Load credentials (fall back gracefully if not configured)
    let mut telegram_authorization_hash = None;
    let telegram_client = match utils::load_telegram_credentials() {
        Ok((api_id, api_hash)) => {
            // Forum storage: bind the shared group + this volume's topic.
            let channel_ref = Some(ChannelRef {
                id: result.config.telegram_group_id,
                access_hash: result.config.telegram_channel_access_hash,
                topic_id: result.config.telegram_topic_id,
            });

            let tg_config = TelegramConfig {
                api_id,
                api_hash,
                session_path: session_file_path().to_string_lossy().to_string(),
                channel_ref,
                ..Default::default()
            };

            let client = TelegramClient::new(tg_config);
            let state = client.connect().await.map_err(utils::telegram_err)?;

            use teagarden_telegram::types::AuthState;
            if state != AuthState::Authenticated {
                anyhow::bail!("Not authenticated with Telegram. Run `teagarden auth login` first.");
            }

            #[cfg(feature = "key-rotation")]
            refresh_device_transition(&client, &mut result)
                .await
                .context("recover this installation's durable owner key handoff before mount")?;

            telegram_authorization_hash = match client.current_authorization_hash().await {
                Ok(hash) => hash,
                Err(error) => {
                    tracing::warn!(%error, "Telegram session binding is unavailable; device revocation may require an explicit authorization hash");
                    None
                }
            };

            if result.config.telegram_group_id == 0 || result.config.telegram_topic_id == 0 {
                anyhow::bail!(
                    "Volume '{}' has no forum group/topic — it should have been created during \
                     `volume create` with Telegram configured. Delete and recreate it.",
                    result.config.display_name
                );
            }

            if result.config.sdo_header_pending {
                repair_pending_header_before_mount(&client, &mut result).await?;
            }

            Some(client)
        }
        Err(e) => {
            // Only reachable for a read-only mount: a writable one was refused
            // above when credentials were missing.
            tracing::warn!(error = %e, "Telegram credentials not found; mounting read-only without transport");
            None
        }
    };

    // Journal recovery (phase 1, BEFORE opening the DB), the DB open and the
    // session's starting state: see `prepare_session`. Returns the loaded HEAD
    // for an already-journaled volume; `None` for a fresh / pre-journal one,
    // which is initialized in phase 2 once the transport is wired.
    let sdo_mount = author_device_id.is_some();
    if telegram_client.is_none() {
        // Portable mounts normally build an isolated disposable index. Offline
        // mounts cannot do that: without Telegram it would silently create an
        // empty root instead of proving that a usable local DB exists.
        offline_mount_check(&result, volume, read_only)?;
    }
    let (conn, loaded_journal_head, mut session_db) = if sdo_mount {
        let conn = open_sdo_mount_db(&mut result)?;
        (conn, None, None)
    } else if let Some(ref client) = telegram_client {
        let s = prepare_session(&mut result, client).await?;
        (s.conn, s.head, Some(s.db))
    } else {
        // Offline mount (read-only; see `offline_mount_check`): a journaled
        // volume cannot be mounted safely without the transport — writes would
        // not be logged to the channel, and uncached blocks cannot be read —
        // except a read-only share, which writes nothing.
        let conn = open_volume_db(&result)?;
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        (conn, None, None)
    };
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let mut initial_poll_cursor =
        teagarden_store::sdo_cursor_store::SdoCursorStore::new(&conn, &schema)
            .get()
            .context("read portable topic poll cursor")?
            .map_or(0, |(cursor, _)| cursor);

    // Set up block cache
    let cache_config = CacheConfig {
        cache_dir: result.paths.cache_dir.clone(),
        max_size: 512 * 1024 * 1024, // 512MB
        encrypt_at_rest: true,
    };
    let cache = BlockCache::new(cache_config, result.hierarchy.data.clone())
        .map_err(|e| anyhow::anyhow!("cache init: {e}"))?;

    let device_keypair = if author_device_id.is_some() {
        Some(load_or_create_device_keypair(
            &result.paths.base_dir,
            &result.hierarchy.wrapping,
        )?)
    } else {
        None
    };

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // Build CryptFs
    let mut fs_builder = CryptFs::new(
        conn,
        schema,
        result.hierarchy.meta.clone(),
        result.hierarchy.data.clone(),
        uid,
        gid,
    )
    .with_epoch(result.config.current_epoch);
    if let Some(author_device_id) = author_device_id {
        fs_builder = fs_builder.with_sdo(result.config.volume_id, author_device_id);
        if let Some((private_key, public_key)) = &device_keypair {
            fs_builder = fs_builder
                .with_sdo_signing_key(teagarden_core::sdo::device_signing_key(&private_key.0));
            fs_builder = fs_builder.with_sdo_device_public_key(hex::encode(&public_key.0));
        }
        if result.config.sdo_initial_clock_ms != 0 || result.config.sdo_initial_clock_counter != 0 {
            fs_builder
                .observe_sdo_clock(
                    result.config.sdo_initial_clock_ms,
                    result.config.sdo_initial_clock_counter,
                )
                .map_err(errno_to_anyhow)
                .context("persist the greatest authenticated remote HLC before mounting")?;
        }
    }
    fs_builder = fs_builder
        .with_block_keys(
            result.hierarchy.block_id.clone(),
            result.hierarchy.filename.clone(),
        )
        .with_manifest_key(result.hierarchy.manifest.clone())
        .with_block_integrity(result.config.require_block_integrity)
        .with_block_v2_from_epoch(result.config.block_v2_from_epoch)
        .with_fuse_block_size(result.config.block_config.fuse_chunk_size())
        .with_cache(Arc::new(cache))
        .with_runtime(tokio::runtime::Handle::current())
        .with_read_only(read_only);
    // Only the session checkpoints its DB (see `local_db::SessionCheckpoints`).
    if let Some(db) = &session_db {
        fs_builder = fs_builder
            .with_session_checkpoints(db.checkpoints.clone())
            .context("take over the metadata database's checkpoints")?;
    }

    // Wire transport — single session or multi-session bot pool
    let transport_arc: Option<Arc<dyn teagarden_telegram::client::BlockTransport>> =
        match telegram_client {
            None => None,
            Some(primary) => {
                // Optional extra upload sessions: TELEGRAM_BOT_TOKEN_1, _2, ... from the
                // environment or the config .env, read up to the first gap. `volume
                // add-bot` records them and makes each bot an admin of the group.
                let bot_tokens: Vec<String> = {
                    let mut tokens = Vec::new();
                    let mut i = 1usize;
                    loop {
                        match std::env::var(format!("TELEGRAM_BOT_TOKEN_{i}")) {
                            Ok(t) if !t.is_empty() => {
                                tokens.push(t);
                                i += 1;
                            }
                            _ => break,
                        }
                    }
                    tokens
                };

                if bot_tokens.is_empty() {
                    Some(Arc::new(primary) as Arc<dyn teagarden_telegram::client::BlockTransport>)
                } else {
                    use teagarden_telegram::multi::MultiTransport;

                    // All bot sessions share the same forum group + topic.
                    let (ch_id, ch_hash, ch_topic) = primary.channel_ref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "forum storage must be initialised before adding bot sessions"
                        )
                    })?;
                    let channel_ref = ChannelRef {
                        id: ch_id,
                        access_hash: ch_hash,
                        topic_id: ch_topic,
                    };

                    let mut sessions: Vec<Arc<dyn teagarden_telegram::client::BlockTransport>> =
                        vec![Arc::new(primary)];

                    // Bots upload via the Bot HTTP API (sendDocument with
                    // message_thread_id), not MTProto. This is the approach that actually
                    // parallelizes: the Bot API resolves the group server-side from its
                    // numeric chat_id, so there is no per-session access_hash to resolve
                    // (which hangs over MTProto). Construction is just an HTTP client — no
                    // handshake — so it's instant and cannot wedge the mount. Downloads by
                    // message_id are served by the MTProto session via MultiTransport
                    // fallthrough.
                    use teagarden_telegram::bot_api::BotApiTransport;
                    for token in &bot_tokens {
                        sessions.push(Arc::new(BotApiTransport::new(
                            token.clone(),
                            channel_ref.id,
                            channel_ref.topic_id,
                        )));
                    }

                    let n = sessions.len();
                    if n > 1 {
                        println!(
                            "Multi-session transport: {} sessions active ({} bots)",
                            n,
                            n - 1
                        );
                    }
                    Some(Arc::new(MultiTransport::new(sessions)))
                }
            }
        };

    if author_device_id.is_some() {
        if let Some(t) = &transport_arc {
            let premium = t.is_premium_user().await.unwrap_or(false);
            let file_limit = if premium {
                teagarden_core::sdo::MAX_SDO_FILE_BYTES_PREMIUM
            } else {
                teagarden_core::sdo::MAX_SDO_FILE_BYTES
            };
            fs_builder = fs_builder.with_sdo_file_limit(file_limit);
        }
    }

    if let Some(ref t) = transport_arc {
        fs_builder = fs_builder.with_transport(t.clone()).with_upload_queue();
    }

    if sdo_mount {
        if let Some(transport) = &transport_arc {
            let (prepared, cursor) = prepare_sdo_mount(
                transport.clone(),
                &result,
                fs_builder,
                telegram_authorization_hash,
            )
            .await?;
            fs_builder = prepared;
            initial_poll_cursor = cursor;
        }
    }

    let session_notifier_slot = Arc::new(Mutex::new(None));
    if sdo_mount {
        if let Some(transport) = &transport_arc {
            fs_builder = start_prepared_sdo_mount_poller(
                fs_builder,
                transport.clone(),
                &result,
                initial_poll_cursor,
                session_notifier_slot.clone(),
            )
            .await?
            .0;
        }
    }

    // Journal activation (phase 2): with the DB open and the transport wired, turn
    // on the metadata journal so every FS mutation is durably logged to the channel
    // before it commits locally. A fresh / pre-journal volume publishes its base
    // snapshot here; an already-journaled volume reuses its loaded HEAD. Only when
    // a transport exists — an offline mount runs un-journaled (plain transactions).
    // A read-only share gets no journal (it writes nothing into the owner's
    // topic; see `activate_journal`).
    if !sdo_mount {
        if let (Some(t), Some(db)) = (&transport_arc, &mut session_db) {
            if let Some(head) =
                activate_journal(&mut result, t.as_ref(), loaded_journal_head, db).await?
            {
                fs_builder = fs_builder.with_journal(
                    result.hierarchy.integrity.clone(),
                    journal_head_path(&result),
                    head,
                );
            }
        }
    }
    println!("Mounting at '{mountpoint}'...");
    println!("Press Ctrl+C to unmount.");

    // Stall watchdog: every 120 s log mount health and this process's CPU ticks.
    // If the mountpoint becomes inaccessible (ESTALE, EIO, etc.) while CPU is
    // burning — the classic symptom after a SIGKILL mid-write — a WARN is emitted
    // so operators can see it in journald / log aggregators without tailing tracing.
    {
        let watchdog_mountpoint = mountpoint.to_string();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(120));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                match tokio::fs::metadata(&watchdog_mountpoint).await {
                    Ok(_) => {
                        tracing::info!(
                            mountpoint = %watchdog_mountpoint,
                            "mount health: ok"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            mountpoint = %watchdog_mountpoint,
                            error = %e,
                            "mount health: mountpoint inaccessible — possible upload stall or transport hang"
                        );
                    }
                }
                // Surface CPU ticks for the process so log aggregators can detect
                // a tight retry loop (>50 % CPU with no successful flushes).
                if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
                    let fields: Vec<&str> = stat.split_whitespace().collect();
                    if fields.len() > 15 {
                        let utime: u64 = fields[13].parse().unwrap_or(0);
                        let stime: u64 = fields[14].parse().unwrap_or(0);
                        tracing::debug!(utime, stime, "mount process cpu ticks");
                    }
                }
            }
        });
    }

    // Convert Ctrl+C / SIGTERM into a GRACEFUL unmount. Detaching the mount makes
    // `mount2` below return, after which we drain queued block uploads and publish
    // the anti-rollback snapshot. Without this, the default signal disposition would
    // kill the process mid-upload — losing not-yet-uploaded blocks and skipping the
    // snapshot. The watchdog comment above ("the classic symptom after a SIGKILL
    // mid-write") is exactly the failure this prevents for the common Ctrl+C path.
    #[cfg(unix)]
    {
        let mp = mountpoint.to_string();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, Signal, SignalKind};
            // SIGHUP (terminal close / SSH disconnect) is handled here too — it is
            // masked on the FUSE thread (to avoid EINTR), so without a handler it
            // would default-terminate the process mid-`release` and lose blocks.
            let mk = |k: SignalKind, name: &str| match signal(k) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(signal = name, error = %e,
                        "could not install shutdown handler; this signal won't flush gracefully — \
                         use `teagarden volume unmount` to flush safely");
                    None
                }
            };
            let mut sigint = mk(SignalKind::interrupt(), "SIGINT");
            let mut sigterm = mk(SignalKind::terminate(), "SIGTERM");
            let mut sighup = mk(SignalKind::hangup(), "SIGHUP");
            if sigint.is_none() && sigterm.is_none() && sighup.is_none() {
                return; // nothing to wait on
            }
            // Re-arm in a loop: a very early signal (before mount2 attaches) detaches
            // a not-yet-existent mount harmlessly; the next signal then unmounts the
            // live mount. After a real unmount, mount2 returns and the process exits.
            async fn next(s: &mut Option<Signal>) {
                match s {
                    Some(sig) => {
                        sig.recv().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            }
            loop {
                tokio::select! {
                    _ = next(&mut sigint) => {},
                    _ = next(&mut sigterm) => {},
                    _ = next(&mut sighup) => {},
                }
                println!("\nUnmounting (flushing queued uploads — do not power off)…");
                #[cfg(target_os = "linux")]
                if let Err(e) = detach_linux_mount(&mp) {
                    tracing::warn!(mountpoint = %mp, error = %e,
                        "signal-triggered unmount failed; filesystem remains mounted");
                }
                #[cfg(target_os = "macos")]
                match std::process::Command::new("umount").arg(&mp).status() {
                    Ok(status) if status.success() => {}
                    Ok(status) => tracing::warn!(mountpoint = %mp, %status,
                        "signal-triggered unmount failed; filesystem remains mounted"),
                    Err(error) => tracing::warn!(mountpoint = %mp, %error,
                        "could not execute umount; filesystem remains mounted"),
                }
            }
        });
    }

    // Mount FUSE filesystem (blocks until unmounted)
    //
    let options = mount_options(&volume_id, read_only, allow_other);

    // Run FUSE mount in a blocking task since it blocks the thread
    let mp_owned = mountpoint.to_string();
    let notifier_slot = session_notifier_slot.clone();
    tokio::task::spawn_blocking(move || {
        // Block SIGINT/SIGTERM/SIGHUP on THIS (FUSE session) thread. The session
        // loop processes one request at a time and an in-flight `release` may be
        // uploading a large file for minutes. If a signal interrupted this thread's
        // syscalls (EINTR), the loop would abort mid-`release` and lose the
        // not-yet-uploaded blocks — observed as a 64 MiB write truncating to the
        // ~22 MiB uploaded before Ctrl+C. The signal is instead handled only by the
        // dedicated task above, which triggers a graceful detach that lets the
        // in-flight release finish first.
        #[cfg(unix)]
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            libc::sigaddset(&mut set, libc::SIGTERM);
            libc::sigaddset(&mut set, libc::SIGHUP);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
        let mut session = fuser::Session::new(fs_builder, &mp_owned, &options)
            .map_err(|e| anyhow::anyhow!("FUSE mount failed: {e}"))?;
        let notifier = session.notifier();
        *notifier_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(notifier.clone());
        if let Err(error) = notifier.inval_inode(1, 0, -1) {
            tracing::debug!(%error, "initial FUSE poll inbox wake failed");
        }
        session
            .run()
            .map_err(|e| anyhow::anyhow!("FUSE session failed: {e}"))
    })
    .await??;

    // --- Post-unmount: publish an anti-rollback metadata snapshot + compact ---
    // A failure here is an ERROR (non-zero exit), never a log line: the volume's
    // cloud metadata is then stale. It is also recorded in the volume directory,
    // so `volume unmount` (a different process) reports it too.
    println!("Filesystem unmounted.");
    if let (Some(transport), Some(db)) = (&transport_arc, &session_db) {
        end_session(&mut result, transport.as_ref(), db).await?;
    }
    Ok(())
}

/// Load the per-device UUID used only inside encrypted TGFV manifests. New
/// volumes create it with their config; old volumes receive one authenticated
/// local value on first writable mount/revert.
fn ensure_sdo_author_device_id(result: &mut manager::OpenVolumeResult) -> Result<uuid::Uuid> {
    if let Some(id) = result.config.sdo_author_device_id {
        return Ok(id);
    }
    let id = uuid::Uuid::new_v4();
    result.config.sdo_author_device_id = Some(id);
    manager::save_config_resealed(
        &mut result.config,
        &result.hierarchy,
        &result.paths.config_path,
    )
    .context("persist local SDO author-device id")?;
    Ok(id)
}

/// FUSE mount options for `volume mount`.
///
/// No `allow_other` / `allow_root` unless the user asks with `--allow-other`:
/// `fusermount3` refuses either one for a non-root user unless `/etc/fuse.conf`
/// has `user_allow_other`, which stock Linux leaves commented out. Without them
/// the kernel lets only the mounting user into the mount.
///
/// `auto_unmount` is tied to `--allow-other` for the same reason: fuser 0.16
/// silently ADDS `allow_other` whenever `AutoUnmount` is given without an
/// `Allow*` option (`Session::new`), which put the fuse.conf requirement back.
/// The cost: a mount process killed with SIGKILL leaves a stale mount
/// ("Transport endpoint is not connected") until `teagarden volume unmount`
/// (or `fusermount3 -u`) clears it. SIGINT/SIGTERM/SIGHUP still unmount
/// cleanly through the signal handler in `mount_in`.
fn mount_options(volume_id: &str, read_only: bool, allow_other: bool) -> Vec<fuser::MountOption> {
    let mut options = vec![
        fuser::MountOption::FSName(format!("teagarden:{volume_id}")),
        // Subtype → fstype shows as `fuse.teagarden` in /proc/mounts and `mount`,
        // so the mount is identifiable as ours and `umount` can dispatch to a
        // `umount.fuse.teagarden` helper. `active_fuse_mounts` matches `fuse.*`.
        fuser::MountOption::Subtype("teagarden".to_string()),
        fuser::MountOption::DefaultPermissions,
    ];
    if read_only {
        // Kernel-level RO as the outer layer; the FUSE handlers refuse mutating
        // ops as the inner one (a mount is not MS_RDONLY-forced, so both matter).
        options.push(fuser::MountOption::RO);
    }
    if allow_other {
        options.push(fuser::MountOption::AllowOther);
        options.push(fuser::MountOption::AutoUnmount);
    }
    options
}

/// Publish a fresh anti-rollback metadata snapshot of the current DB, persist the
/// bumped version + snapshot id (resealed HMAC), then reset the journal HEAD to
/// `{seq:0, base:this snapshot}` — compacting the delta chain. Shared by the
/// post-unmount path (`mount`) and the offline journaled-mutation substrate
/// (`volume revert`), so the load-bearing ordering lives in exactly one place.
///
/// The snapshot embeds a monotonic version (`VolumeConfig::next_snapshot_version`).
/// Ordering is deliberate: reserve the version in volume.json, publish to the
/// channel, then persist the version (the restore floor) + snapshot id + snapshot
/// hash with a recomputed `config_integrity` HMAC, then reset HEAD. If we crash
/// between publish and persist, the floor merely LAGS the published snapshot,
/// which `volume restore` still accepts (snapshot_version >= local_version). Raising
/// the floor before publishing would brick restore — a persisted-but-unpublished
/// version would reject the only available (older) snapshot — which is why only
/// the separate reservation is written first: a publish Telegram stored without
/// acknowledging it still uses its version up, so the retry never publishes a
/// second, different snapshot under the same version.
///
/// A failure is returned, never swallowed: the mutation that preceded this call
/// is durable locally (and journaled), but until a snapshot is published the
/// volume's cloud metadata snapshot is stale. The failure is also recorded in
/// the volume directory ([`SNAPSHOT_FAILED_MARKER`]) for `volume unmount`, which
/// runs in another process, and cleared by the next successful publish.
///
/// The lineage stamp (see `local_db::DbStamp`): after reserving version N and
/// BEFORE the DB file is read for the snapshot, the DB is stamped with this
/// volume's id, N and a fresh random nonce, so the snapshot carries the stamp;
/// the HEAD reset then records the same lineage. Deciding whether the DB is the
/// volume's needs no fetch: it was checked against the HEAD's lineage when the
/// session opened it (`local_db_state`). If the publish fails after the stamp,
/// the stamp it replaced is put back (the DB is then the volume's current one
/// again); if that fails too, or the process dies in between, the DB no longer
/// matches the HEAD and the next mount rebuilds it from the snapshot and
/// journal the HEAD names, which hold everything acknowledged (every session
/// change is journaled before it commits locally).
///
/// What is published must be the database the caller opened (`of`): the file
/// at `metadata.db` must be the same file (device and inode) the session, or
/// `volume republish`, opened, and for a session of a volume with a published
/// snapshot and a journal HEAD, its stamp must be the lineage the HEAD
/// records. Both are checked before anything is written (the reservation in
/// volume.json included); a mismatch is recorded as a failed publish and
/// leaves the stamp, volume.json and the HEAD as they are, so a HEAD with
/// entries past its base is replayed by the next mount. The identity is
/// checked again on the file the snapshot's bytes are read from. A read-only
/// share never publishes (into the owner's topic).
pub(crate) async fn publish_snapshot_and_compact(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
    of: PublishOf,
) -> Result<()> {
    if read_only_share(&result.paths.base_dir)? {
        anyhow::bail!(
            "volume '{}' is a read-only share of someone else's volume: it never publishes \
             metadata into the owner's Telegram topic. Nothing was changed.",
            result.config.display_name
        );
    }
    if let Err(e) = ensure_config_unchanged(result) {
        let failure = record_snapshot_failure(result, format!("{e:#}"));
        anyhow::bail!(stale_message(&result.config.display_name, &failure));
    }
    if let Err(why) = check_publish_source(result, &of) {
        let failure = record_db_not_current(result, why);
        anyhow::bail!(stale_message(&result.config.display_name, &failure));
    }
    let opened = of.db();
    let next_version = match reserve_snapshot_version(result) {
        Ok(v) => v,
        Err(e) => {
            let failure = record_snapshot_failure(
                result,
                format!("reserving the next snapshot version in volume.json failed: {e:#}"),
            );
            anyhow::bail!(stale_message(&result.config.display_name, &failure));
        }
    };
    // The DB becomes snapshot version `next_version`: stamp it with a new
    // lineage before its bytes are read.
    let lineage = Lineage::new(next_version);
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let stamp = local_db::DbStamp {
        volume_id: result.config.volume_id.to_string(),
        lineage,
    };
    #[cfg(test)]
    BEFORE_RESTAMP.with(|h| {
        if let Some(f) = h.borrow_mut().take() {
            f()
        }
    });
    // The DB becomes the HEAD's base at journal position 0, in the same
    // transaction as the stamp.
    let restamp =
        || local_db::restamp_db_file(&result.paths.db_path, &schema, Some(&stamp), Some(0));
    let restamped = match of.checkpoints() {
        Some(ck) => ck.own_write(restamp),
        None => restamp().map_err(local_db::CheckpointRefused::Failed),
    };
    let replaced = match restamped {
        Ok(prev) => prev,
        Err(local_db::CheckpointRefused::Foreign(why)) => {
            let failure = record_db_not_current(result, why);
            anyhow::bail!(stale_message(&result.config.display_name, &failure));
        }
        Err(local_db::CheckpointRefused::Failed(e)) => {
            let failure = record_snapshot_failure(
                result,
                format!("stamping the metadata database for the snapshot failed: {e}"),
            );
            anyhow::bail!(stale_message(&result.config.display_name, &failure));
        }
    };
    // Every failure below puts the replaced stamp back first.
    let unstamp = |result: &manager::OpenVolumeResult| {
        let put_back = || {
            local_db::restamp_db_file(
                &result.paths.db_path,
                &schema,
                replaced.0.as_ref(),
                replaced.1,
            )
        };
        let put = match of.checkpoints() {
            Some(ck) => ck.own_write(put_back),
            None => put_back().map_err(local_db::CheckpointRefused::Failed),
        };
        match put {
            Ok(_) => false,
            Err(local_db::CheckpointRefused::Foreign(why)) => {
                // Not ours to unstamp: never write the HEAD's stamp and
                // position into another program's file. Mark it to be rebuilt.
                eprintln!("WARNING: {why}; the previous lineage stamp was not put back.");
                let _ = record_db_not_current(result, why);
                true
            }
            Err(local_db::CheckpointRefused::Failed(e)) => {
                eprintln!(
                    "WARNING: could not put back the metadata database's previous lineage stamp \
                     ({e}); the next mount rebuilds the database from Telegram."
                );
                false
            }
        }
    };
    // The failure record after an `unstamp`: a file found to be another
    // program's keeps the "not current" verdict (and its rebuild marker), so
    // the report never calls that file intact.
    let fail_after_unstamp = |result: &manager::OpenVolumeResult, foreign: bool, reason: String| {
        record_snapshot_failure_full(result, reason, None, foreign)
    };
    // The snapshot's bytes, read from the file the session opened; a file put
    // at the path since the check above is not ours to unstamp.
    #[cfg(test)]
    BEFORE_SNAPSHOT_READ.with(|h| {
        if let Some(f) = h.borrow_mut().take() {
            f()
        }
    });
    // Read ONCE: these bytes are checked below and exactly these are uploaded.
    let db_bytes = match read_db_file_of(&result.paths.db_path, &opened) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(why)) => {
            let failure = record_db_not_current(result, why);
            anyhow::bail!(stale_message(&result.config.display_name, &failure));
        }
        Err(e) => {
            let foreign = unstamp(result);
            let failure = fail_after_unstamp(
                result,
                foreign,
                format!("reading the metadata database for the snapshot failed: {e:#}"),
            );
            anyhow::bail!(stale_message(&result.config.display_name, &failure));
        }
    };
    // The file must still be as the restamp left it, and the bytes read must
    // be the database the restamp stamped. A file another program wrote
    // since is not ours to unstamp.
    let read_back = match of.checkpoints().map(|ck| ck.verify()) {
        Some(Err(why)) => Err(format!(
            "{why}, after the publish stamped it and before its bytes were read. It was not \
             published (volume.json and the journal HEAD were left as they are). The next mount \
             rebuilds the database from the volume's snapshot and journal on Telegram"
        )),
        _ => match check_snapshot_bytes(result, &of, &db_bytes, &stamp, &schema) {
            Ok(checked) => checked,
            Err(e) => {
                let foreign = unstamp(result);
                let failure = fail_after_unstamp(
                    result,
                    foreign,
                    format!(
                        "checking the metadata database's bytes for the snapshot failed: {e:#}"
                    ),
                );
                anyhow::bail!(stale_message(&result.config.display_name, &failure));
            }
        },
    };
    if let Err(why) = read_back {
        let failure = record_db_not_current(result, why);
        anyhow::bail!(stale_message(&result.config.display_name, &failure));
    }
    #[cfg(test)]
    AFTER_SNAPSHOT_CHECK.with(|h| {
        if let Some(f) = h.borrow_mut().take() {
            f()
        }
    });
    let (snapshot_id, snapshot_hash) =
        match sync_metadata_snapshot(result, next_version, &db_bytes, transport).await {
            Ok(published) => published,
            Err(e) => {
                tracing::warn!(error = %e, "metadata snapshot publish failed");
                let foreign = unstamp(result);
                let failure = fail_after_unstamp(
                    result,
                    foreign,
                    format!("publishing the metadata snapshot failed: {e:#}"),
                );
                anyhow::bail!(stale_message(&result.config.display_name, &failure));
            }
        };
    result.config.metadata_snapshot_id = Some(snapshot_id);
    result.config.metadata_snapshot_hash = Some(hex::encode(snapshot_hash));
    result.config.metadata_version = next_version;
    // metadata_version is HMAC-covered, so a plain write would brick the config on
    // next open — reseal recomputes config_integrity.
    if let Err(e) = manager::save_config_resealed(
        &mut result.config,
        &result.hierarchy,
        &result.paths.config_path,
    ) {
        // The snapshot is durable in the channel but volume.json still names the
        // previous one (and the bumped floor never reached disk), so `restore`
        // and a share grant would still use the OLD snapshot.
        tracing::warn!(error = %e, message_id = snapshot_id, "config persist failed after snapshot publish");
        let foreign = unstamp(result);
        let failure = fail_after_unstamp(
            result,
            foreign,
            format!(
                "the metadata snapshot was published (message_id={snapshot_id}, \
                 version={next_version}) but saving volume.json failed: {e}"
            ),
        );
        anyhow::bail!(stale_message(&result.config.display_name, &failure));
    }
    // Journal compaction: the fresh snapshot subsumes every delta, so reset the
    // chain to {seq:0, base:this snapshot, lineage: the DB's new stamp}. Written
    // AFTER the snapshot+config; a crash here just leaves the old HEAD, and
    // recovery rebuilds the prior consistent state from it (the new snapshot is
    // then unused by recovery), as the DB's stamp no longer matches that HEAD.
    //
    // A FAILED reset is an error, not a warning: the HEAD on disk still names the
    // older base, so the next session journals onto it and a crash recovery
    // rebuilds from it. That is consistent for journaled changes, but not for a
    // caller that changed the DB without journaling it (`key rotate` re-points
    // block rows) and would go on to act on the new snapshot being the base.
    let head_path = journal_head_path(result);
    let head = JournalHead::at_snapshot(snapshot_id, next_version, snapshot_hash, lineage);
    if let Err(e) = head.store_atomic(&head_path, &result.hierarchy.integrity) {
        tracing::warn!(error = %e, message_id = snapshot_id, "journal HEAD reset failed after snapshot publish");
        let foreign = unstamp(result);
        let still = JournalHead::load(&head_path, &result.hierarchy.integrity);
        let not_reset = HeadNotReset {
            published_snapshot_message_id: snapshot_id,
            published_snapshot_version: next_version,
            head_base_snapshot_message_id: still
                .as_ref()
                .ok()
                .and_then(|h| h.map(|h| h.base_snapshot_msg_id)),
            head_seq: still.as_ref().ok().and_then(|h| h.map(|h| h.seq)),
        };
        let failure = record_snapshot_failure_full(
            result,
            format!(
                "resetting the journal HEAD ({}) onto the published snapshot failed: {e}",
                head_path.display()
            ),
            Some(not_reset),
            foreign,
        );
        anyhow::bail!(stale_message(&result.config.display_name, &failure));
    }
    clear_snapshot_failure(&result.paths.base_dir);
    println!("Metadata snapshot synced (message_id={snapshot_id}, version={next_version}).");
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Test seam: run once between a publish's checks (and its stamp) and its
    /// read of the snapshot's bytes, on the publishing thread.
    pub(crate) static BEFORE_SNAPSHOT_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    /// Test seam: run once after the publish's checks and version reservation,
    /// right before its restamp.
    pub(crate) static BEFORE_RESTAMP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    /// Test seam: run once after the content checks of the bytes read, before
    /// they are uploaded, on the publishing thread.
    pub(crate) static AFTER_SNAPSHOT_CHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

/// The content checks of a snapshot's bytes, on a scratch copy of exactly
/// those bytes (the file at `metadata.db` may change after they were read):
/// a SQLite file, `PRAGMA quick_check` ok, stamped with `stamp` (the one the
/// publish just wrote) at journal position 0 and, for a session, carrying
/// its nonce. `Ok(Err(why))` when they are not the database the publish
/// stamped; `Err` when the scratch copy cannot be written or read.
fn check_snapshot_bytes(
    result: &manager::OpenVolumeResult,
    of: &PublishOf,
    bytes: &[u8],
    stamp: &local_db::DbStamp,
    schema: &OpaqueSchema,
) -> Result<std::result::Result<(), String>> {
    use teagarden_core::volume::metadata_snapshot;
    let not_ours = |what: String| {
        Ok(Err(format!(
            "the bytes read for the snapshot are not the database the publish stamped ({what}): \
             another program wrote metadata.db after the publish stamped it, so it was not \
             published (volume.json and the journal HEAD were left as they are). The next mount \
             rebuilds the database from the volume's snapshot and journal on Telegram"
        )))
    };
    if let Err(e) = metadata_snapshot::ensure_sqlite_db(bytes) {
        return not_ours(format!("not a SQLite database: {e}"));
    }
    let scratch = result.paths.base_dir.join("metadata.db.publishing");
    metadata_snapshot::remove_db_files(&scratch).map_err(utils::core_err)?;
    let checked = (|| -> Result<std::result::Result<(), String>> {
        std::fs::write(&scratch, bytes).with_context(|| format!("write {}", scratch.display()))?;
        let conn = match local_db::open_existing(&scratch) {
            Ok(c) => c,
            Err(e) if local_db::is_damage(&e) => return Ok(Err(format!("damaged: {e}"))),
            Err(e) => return Err(anyhow::anyhow!("open {}: {e}", scratch.display())),
        };
        let read = (|| {
            Ok::<_, rusqlite::Error>((
                local_db::quick_check(&conn)?,
                local_db::read_stamp(&conn, schema)?,
                local_db::read_session(&conn, schema)?,
            ))
        })();
        let (problems, got_stamp, session) = match read {
            Ok(r) => r,
            Err(e) if local_db::is_damage(&e) => return Ok(Err(format!("damaged: {e}"))),
            Err(e) => return Err(anyhow::anyhow!("read {}: {e}", scratch.display())),
        };
        if let Some(problems) = problems {
            return Ok(Err(format!("PRAGMA quick_check reports: {problems}")));
        }
        if got_stamp.as_ref() != Some(stamp) {
            return Ok(Err("it does not carry the stamp the publish wrote".into()));
        }
        if session.map(|r| r.seq) != Some(0) {
            return Ok(Err(
                "it is not at the journal position the publish wrote".into()
            ));
        }
        if let PublishOf::Session(s) = of {
            if session.and_then(|r| r.nonce) != Some(s.nonce) {
                return Ok(Err("it does not carry this session's nonce".into()));
            }
        }
        Ok(Ok(()))
    })();
    let removed = metadata_snapshot::remove_db_files(&scratch);
    let checked = checked?;
    removed.map_err(utils::core_err)?;
    Ok(checked)
}

/// The database a session (a mount, `revert`, `key rotate`) opened, and
/// what proves that a file is still it ([`begin_db_session`]).
#[derive(Debug, Clone)]
pub(crate) struct SessionDb {
    /// The file the session opened (device and inode).
    pub(crate) file: local_db::DbFileId,
    /// The session's ownership of the main file: only the session
    /// checkpoints it, and the fingerprint it left there is compared before
    /// each of its checkpoints and first of all by its publishes.
    pub(crate) checkpoints: Arc<local_db::SessionCheckpoints>,
    /// The random nonce the session wrote into the DB's session record.
    pub(crate) nonce: [u8; 16],
    /// Whether the volume had a journal HEAD when the session started (or
    /// got one from its base snapshot publish): its publish then refuses if
    /// the HEAD is gone.
    pub(crate) had_head: bool,
}

/// Which database a snapshot publish may read: the one its caller opened.
#[derive(Debug, Clone)]
pub(crate) enum PublishOf {
    /// A session's: the file it opened, still holding its nonce, at the
    /// journal position the HEAD records, and (with a HEAD) stamped with the
    /// lineage the HEAD records.
    Session(SessionDb),
    /// `volume republish --from-local-db`: the file it checked. Its stamp is
    /// replaced whatever it is (republish checked it against the HEAD).
    Republish(local_db::DbFileId),
}

impl PublishOf {
    fn db(&self) -> local_db::DbFileId {
        match self {
            PublishOf::Session(s) => s.file,
            PublishOf::Republish(id) => *id,
        }
    }

    /// The session's checkpoint ownership (none for a republish).
    fn checkpoints(&self) -> Option<&local_db::SessionCheckpoints> {
        match self {
            PublishOf::Session(s) => Some(&s.checkpoints),
            PublishOf::Republish(_) => None,
        }
    }
}

/// Start a session on the DB `conn` (the file at `metadata.db`): write a new
/// random session nonce and the journal position `head` records (0 without
/// a HEAD) into its session record, take over the DB's checkpoints
/// ([`local_db::SessionCheckpoints::start`]: `conn` stops checkpointing on
/// its own, the WAL is checkpointed into the main file and its fingerprint
/// recorded), and record the file's identity. The session's publishes may
/// read only a file that is still this one, by fingerprint, identity and
/// content.
pub(crate) fn begin_db_session(
    result: &manager::OpenVolumeResult,
    conn: &Connection,
    head: Option<&JournalHead>,
) -> Result<SessionDb> {
    use rand::RngCore as _;
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    local_db::begin_session(conn, &schema, nonce, head.map_or(0, |h| h.seq))
        .context("record the session in the metadata database")?;
    let checkpoints = local_db::SessionCheckpoints::start(conn, &result.paths.db_path)
        .map_err(utils::core_err)
        .context("take over the metadata database's checkpoints")?;
    // While `conn` is open its file cannot be freed, so any other file put at
    // the path later has another identity.
    let file = local_db::DbFileId::of(&result.paths.db_path).map_err(utils::core_err)?;
    Ok(SessionDb {
        file,
        checkpoints,
        nonce,
        had_head: head.is_some(),
    })
}

/// Whether the database at `metadata.db` may be published for `of`: see
/// [`publish_snapshot_and_compact`]. `Err` says why not.
fn check_publish_source(
    result: &manager::OpenVolumeResult,
    of: &PublishOf,
) -> std::result::Result<(), String> {
    let db_path = &result.paths.db_path;
    // First: the main file must be as the session last left it. Under WAL
    // the rows checked below can sit in the WAL while another program put
    // a different main file under them (`cp backup metadata.db`).
    if let Some(ck) = of.checkpoints() {
        ck.verify().map_err(|why| {
            format!(
                "{why}. So it is not the session's current database, and it was not published \
                 (its stamp, volume.json and the journal HEAD were left as they are). The next \
                 mount rebuilds the database from the volume's snapshot and journal on Telegram"
            )
        })?;
    }
    let opened = of.db();
    let now = local_db::DbFileId::of(db_path).map_err(|e| {
        format!("the metadata database cannot be checked before the snapshot publish: {e}")
    })?;
    if !local_db::same_db_file(&opened, &now) {
        return Err(replaced_db_reason(db_path, &opened, &now));
    }
    // By content: the file must be internally consistent and, for a session,
    // still this session's database at the HEAD's journal position.
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let not_published = "so it was not published (its stamp, volume.json and the journal HEAD \
                         were left as they are). The next mount rebuilds the database from the \
                         volume's snapshot and journal on Telegram";
    let conn = local_db::open_read_only(db_path).map_err(|e| {
        format!("the metadata database cannot be opened to check it ({e}), {not_published}")
    })?;
    match local_db::quick_check(&conn) {
        Ok(None) => {}
        Ok(Some(problems)) => {
            return Err(format!(
                "the metadata database is damaged (PRAGMA quick_check reports: {problems}): a \
                 copy of it was put over it in place, or its disk failed, {not_published}"
            ))
        }
        Err(e) => {
            return Err(format!(
                "the metadata database is damaged (PRAGMA quick_check fails: {e}), \
                 {not_published}"
            ))
        }
    }
    let session = match of {
        PublishOf::Republish(_) => return Ok(()),
        PublishOf::Session(s) => s,
    };
    let record = local_db::read_session(&conn, &schema).map_err(|e| {
        format!("the metadata database's session record cannot be read ({e}), {not_published}")
    })?;
    drop(conn);
    if record.and_then(|r| r.nonce) != Some(session.nonce) {
        return Err(format!(
            "the metadata database is not the one this session opened: it does not carry this \
             session's nonce (another copy of the database was put over it in place while the \
             volume was in use, for example with `cp`), {not_published}"
        ));
    }
    let db_seq = record.map_or(0, |r| r.seq);
    let head = match JournalHead::load(&journal_head_path(result), &result.hierarchy.integrity) {
        Ok(Some(h)) => h,
        // The session started without a HEAD (a new volume, or one whose
        // snapshot volume.json names was just installed): its base snapshot
        // publish writes the first one. Nothing was journaled meanwhile.
        Ok(None) if !session.had_head && db_seq == 0 => return Ok(()),
        Ok(None) => {
            return Err(
                "the journal HEAD (journal.head) was removed while the volume was in use, so \
                 nothing shows the metadata database is the volume's current one; it was not \
                 published (its stamp and volume.json were left as they are). Without \
                 journal.head the next mount refuses and names `volume restore` and `volume \
                 republish --from-local-db`"
                    .to_string(),
            )
        }
        Err(e) => {
            return Err(format!(
                "the journal HEAD cannot be read ({}), so nothing shows the metadata database \
                 is the volume's current one; it was not published. The next mount rebuilds \
                 the database once journal.head can be read, or refuses and names the ways out",
                utils::core_err(e)
            ))
        }
    };
    if db_seq != head.seq {
        return Err(format!(
            "the metadata database holds journal position {db_seq}, but the journal HEAD \
             records {}: it is not the database this session wrote (an older copy of it was put \
             over it in place, or a local commit did not happen), {not_published}",
            head.seq
        ));
    }
    if !has_published_snapshot(result) {
        return Ok(());
    }
    let stamp = local_db::open_read_only(db_path)
        .and_then(|c| local_db::read_stamp(&c, &schema))
        .map_err(|e| format!("the metadata database's lineage stamp cannot be read: {e}"))?;
    let volume_id = result.config.volume_id.to_string();
    match (&stamp, head.lineage) {
        (Some(s), Some(l)) if s.volume_id == volume_id && s.lineage == l => Ok(()),
        _ => Err(format!(
            "the metadata database's lineage stamp ({}) is not the one the journal HEAD records \
             ({}), so it is not the volume's current database and was not published (its stamp, \
             volume.json and the HEAD were left as they are). The next mount rebuilds the \
             database from the volume's snapshot and journal on Telegram",
            match &stamp {
                Some(s) if s.volume_id != volume_id => format!("another volume's, {}", s.volume_id),
                Some(s) => s.lineage.to_string(),
                None => "none".into(),
            },
            head.lineage
                .map(|l| l.to_string())
                .unwrap_or_else(|| "no lineage".into())
        )),
    }
}

/// Why a file at `db_path` that is not the one the session opened is not
/// published.
fn replaced_db_reason(
    db_path: &std::path::Path,
    opened: &local_db::DbFileId,
    now: &local_db::DbFileId,
) -> String {
    format!(
        "the file at {} is not the metadata database this session opened ({opened}; the file \
         there now is {now}): it was replaced while the volume was in use, so it was not \
         published, and the journal HEAD was left as it is. The next mount rebuilds the \
         database from the volume's snapshot and journal on Telegram",
        db_path.display()
    )
}

/// The bytes of the DB file at `db_path`, read through one open handle whose
/// identity is checked first: `Ok(Err(why))` when it is not `opened`.
fn read_db_file_of(
    db_path: &std::path::Path,
    opened: &local_db::DbFileId,
) -> Result<std::result::Result<Vec<u8>, String>> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(db_path)
        .with_context(|| format!("open {} for the snapshot", db_path.display()))?;
    let now = local_db::DbFileId::of_metadata(&f.metadata().context("stat metadata db")?);
    if !local_db::same_db_file(opened, &now) {
        return Ok(Err(replaced_db_reason(db_path, opened, &now)));
    }
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .context("read metadata db for snapshot")?;
    Ok(Ok(bytes))
}

/// A publish with no session around it: the state the tests' "clean unmount"
/// and fixtures publish (the file at the path is the session's).
#[cfg(test)]
pub(crate) async fn publish_as_new_session(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
) -> Result<()> {
    let conn = local_db::open_existing(&result.paths.db_path)
        .with_context(|| format!("open {}", result.paths.db_path.display()))?;
    let head = JournalHead::load(&journal_head_path(result), &result.hierarchy.integrity)
        .map_err(utils::core_err)?;
    let db = begin_db_session(result, &conn, head.as_ref())?;
    drop(conn);
    publish_snapshot_and_compact(result, transport, PublishOf::Session(db)).await
}

/// Refuse to go on from `result.config` if volume.json on disk no longer says
/// what it said when this process read it: some other writer (a `key rotate`
/// that finished in the window before this command took the volume lock, or a
/// writer that does not take it) changed the volume underneath this command.
/// Writing from the stale copy would roll back the epoch or the snapshot
/// version, or publish a snapshot of a DB that copy does not describe.
///
/// Compares the fields those writers change (the epoch, the snapshot version,
/// reservation, id and hash, and the key-slot anchor); the opener's in-memory
/// adjustments to other fields do not count as a change.
pub(crate) fn ensure_config_unchanged(result: &manager::OpenVolumeResult) -> Result<()> {
    let bytes = std::fs::read(&result.paths.config_path).context("re-read volume.json")?;
    let disk: VolumeConfig = serde_json::from_slice(&bytes).context("parse volume.json")?;
    let fields = |c: &VolumeConfig| {
        serde_json::json!([
            c.current_epoch,
            c.metadata_version,
            c.metadata_version_reserved,
            c.metadata_snapshot_id,
            c.metadata_snapshot_hash,
            c.key_protection,
        ])
    };
    if fields(&disk) == fields(&result.config) {
        return Ok(());
    }
    anyhow::bail!(
        "volume.json changed on disk since this command read it (epoch {} -> {}, snapshot \
         version {} -> {}, snapshot message_id {:?} -> {:?}): another TeaGarden command, such \
         as `key rotate`, changed the volume meanwhile. Refusing to write from the stale copy; \
         nothing was written by this step. Run the command again.",
        result.config.current_epoch,
        disk.current_epoch,
        result.config.metadata_version,
        disk.metadata_version,
        result.config.metadata_snapshot_id,
        disk.metadata_snapshot_id,
    )
}

/// Pick the next snapshot version and save it as reserved (resealed) BEFORE it is
/// uploaded, so no later attempt can reuse it. See [`publish_snapshot_and_compact`].
fn reserve_snapshot_version(result: &mut manager::OpenVolumeResult) -> Result<u64> {
    let next_version = result.config.next_snapshot_version();
    result.config.metadata_version_reserved = next_version;
    manager::save_config_resealed(
        &mut result.config,
        &result.hierarchy,
        &result.paths.config_path,
    )
    .map_err(utils::core_err)?;
    Ok(next_version)
}

/// Recorded in a volume's directory while its cloud metadata snapshot is stale
/// (the last publish failed); removed by the next successful publish. Local
/// status only: it holds an error description and the ids of the snapshot that
/// Telegram does have, never key material.
pub(crate) const SNAPSHOT_FAILED_MARKER: &str = "snapshot_publish_failed.json";

/// Contents of [`SNAPSHOT_FAILED_MARKER`].
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct SnapshotPublishFailure {
    /// Unix time of the failed attempt.
    pub failed_at_unix: u64,
    /// What failed.
    pub reason: String,
    /// The snapshot volume.json still names (what `restore` would use).
    pub stale_snapshot_message_id: Option<i64>,
    /// Its version.
    pub stale_snapshot_version: u64,
    /// Set when the snapshot WAS published and volume.json names it, but the
    /// journal HEAD could not be reset onto it. Absent in a record written before
    /// this field existed, and for every other failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_not_reset: Option<HeadNotReset>,
    /// Set when the publish refused because the file at metadata.db is not
    /// the session's current database (identity, nonce, journal position,
    /// stamp, quick_check, journal.head): the local DB must not be relied
    /// on, the next mount rebuilds it. Absent (false) in a record written
    /// before this field existed, and for every other failure.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub db_not_current: bool,
}

/// What [`SnapshotPublishFailure::head_not_reset`] records.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct HeadNotReset {
    /// The snapshot that was published (volume.json names it).
    pub published_snapshot_message_id: i64,
    /// Its version.
    pub published_snapshot_version: u64,
    /// The base snapshot the journal HEAD on disk still names (`None` when the
    /// HEAD is missing or unreadable).
    pub head_base_snapshot_message_id: Option<i64>,
    /// That HEAD's entry count past its base.
    pub head_seq: Option<u64>,
}

fn record_snapshot_failure(
    result: &manager::OpenVolumeResult,
    reason: String,
) -> SnapshotPublishFailure {
    record_snapshot_failure_with(result, reason, None)
}

/// [`record_snapshot_failure`] for a refusal of the DB itself (see
/// [`SnapshotPublishFailure::db_not_current`]). With a journal HEAD, the DB
/// is also marked to be rebuilt ([`rebuild_marker`]): a refused file can
/// still carry the HEAD's stamp and journal position (another session's copy
/// at the same position, a file renamed into place), and must not be served
/// as it is by the next mount, which rebuilds it from what the HEAD names
/// (keeping it unless it is reproducible). Without a HEAD (removed during
/// the session, or unreadable) no marker is written: the next mount then
/// refuses and names the ways out instead of restoring the snapshot.
fn record_db_not_current(
    result: &manager::OpenVolumeResult,
    reason: String,
) -> SnapshotPublishFailure {
    if let Ok(Some(_)) = JournalHead::load(&journal_head_path(result), &result.hierarchy.integrity)
    {
        if let Err(e) = rebuild_marker::mark(
            &result.paths.base_dir,
            "a snapshot publish refused the local metadata database: it is not the session's \
             current database",
        ) {
            eprintln!(
                "WARNING: could not mark the refused local metadata database to be rebuilt \
                 ({e}); do not use it until a mount has rebuilt it."
            );
        }
    }
    record_snapshot_failure_full(result, reason, None, true)
}

fn record_snapshot_failure_with(
    result: &manager::OpenVolumeResult,
    reason: String,
    head_not_reset: Option<HeadNotReset>,
) -> SnapshotPublishFailure {
    record_snapshot_failure_full(result, reason, head_not_reset, false)
}

fn record_snapshot_failure_full(
    result: &manager::OpenVolumeResult,
    reason: String,
    head_not_reset: Option<HeadNotReset>,
    db_not_current: bool,
) -> SnapshotPublishFailure {
    // Describe what volume.json on disk names (the in-memory config may already
    // carry the unsaved new values when the persist step failed).
    let on_disk: Option<VolumeConfig> = std::fs::read(&result.paths.config_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let failure = SnapshotPublishFailure {
        failed_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        reason,
        stale_snapshot_message_id: on_disk.as_ref().and_then(|c| c.metadata_snapshot_id),
        stale_snapshot_version: on_disk.map(|c| c.metadata_version).unwrap_or(0),
        head_not_reset,
        db_not_current,
    };
    let path = result.paths.base_dir.join(SNAPSHOT_FAILED_MARKER);
    let written = serde_json::to_vec_pretty(&failure)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| {
            teagarden_core::fsutil::write_file_atomic(&path, &bytes, "snapshot status")
                .map_err(anyhow::Error::from)
        });
    if let Err(e) = written {
        eprintln!(
            "WARNING: could not record the failed snapshot publish in {}: {e:#}",
            path.display()
        );
    }
    failure
}

fn clear_snapshot_failure(base_dir: &std::path::Path) {
    match std::fs::remove_file(base_dir.join(SNAPSHOT_FAILED_MARKER)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, "could not clear the snapshot-failure record"),
    }
}

/// The report of a failed publish `f` of volume `volume` (its name or id, for
/// the commands it names).
fn stale_message(volume: &str, f: &SnapshotPublishFailure) -> String {
    if let Some(h) = &f.head_not_reset {
        let head = match (h.head_base_snapshot_message_id, h.head_seq) {
            (Some(base), Some(seq)) => format!(
                "still names the older base snapshot message_id={base} with {seq} journal \
                 entr{} past it",
                if seq == 1 { "y" } else { "ies" }
            ),
            _ => "is missing or unreadable".to_string(),
        };
        return format!(
            "{}.\nThe metadata snapshot version {} (message_id={}) IS published on Telegram and \
             volume.json names it, so `volume restore` and a share grant use it. But the local \
             journal HEAD (journal.head) {head}: until it is reset, the next mount journals onto \
             that base, and recovery after a crash rebuilds from it rather than from the \
             published snapshot. {} Fix the cause (for example free disk space), then mount and \
             unmount the volume again to reset the HEAD.",
            f.reason.trim_end_matches('.'),
            h.published_snapshot_version,
            h.published_snapshot_message_id,
            if f.db_not_current {
                "The local metadata database was NOT published because it is not this \
                 session's current database: do not rely on it; the next mount rebuilds it."
            } else {
                "Your files and the local metadata database are intact."
            }
        );
    }
    let cloud = match f.stale_snapshot_message_id {
        Some(id) => format!(
            "the newest snapshot this volume names on Telegram is still version {} \
             (message_id={id})",
            f.stale_snapshot_version
        ),
        None if f.stale_snapshot_version > 0 && f.db_not_current => format!(
            "volume.json records snapshot version {} but names no snapshot message",
            f.stale_snapshot_version
        ),
        None if f.stale_snapshot_version > 0 => {
            // volume.json records a published version but its (un-MACed)
            // snapshot id is gone: nothing names a snapshot to restore or
            // share. With journal.head present the next publish names one
            // again; without it a mount cannot rebuild either.
            return format!(
                "{}.\nThe volume's cloud metadata is STALE: volume.json records snapshot version \
                 {} but names no snapshot message (its message id is missing), so `volume \
                 restore` and a share grant cannot use any snapshot. Your files and the local \
                 metadata database are intact. Fix the cause, then mount and unmount the volume \
                 again to publish a fresh snapshot. If the mount cannot rebuild the local \
                 database because no snapshot is named to rebuild it from, run `teagarden volume \
                 republish {volume} --from-local-db` instead.",
                f.reason.trim_end_matches('.'),
                f.stale_snapshot_version
            );
        }
        None => "this volume has no metadata snapshot on Telegram at all".to_string(),
    };
    if f.db_not_current {
        return format!(
            "{}.\nThe volume's cloud metadata is STALE: {cloud}. The local metadata database \
             was NOT published because it is not this session's current database: do not rely \
             on it. The next mount rebuilds it from the volume's snapshot and journal on \
             Telegram, which hold every change this session made (if journal.head is missing, \
             the mount refuses instead and names `volume restore` and `volume republish \
             --from-local-db`). Leave metadata.db alone until then.",
            f.reason.trim_end_matches('.')
        );
    }
    format!(
        "{}.\nThe volume's cloud metadata is STALE: {cloud}, so `volume restore` (or a share \
         grant made now) would bring back that older state, not your latest changes. Your \
         files and the local metadata database are intact. Fix the cause, then mount and \
         unmount the volume again to publish a fresh snapshot.",
        f.reason.trim_end_matches('.')
    )
}

/// `Err` (with the full stale-metadata explanation) while the volume's last
/// snapshot publish is recorded as failed, and while the local metadata DB is
/// marked to be rebuilt from Telegram (a `volume restore` that did not
/// finish). `volume unmount` reports either as an error.
pub(crate) fn snapshot_publish_status(base_dir: &std::path::Path) -> Result<()> {
    let volume = base_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<volume>".into());
    let path = base_dir.join(SNAPSHOT_FAILED_MARKER);
    if let Some(reason) = rebuild_marker::load(base_dir).map_err(utils::core_err)? {
        // A refused publish writes both: say both.
        let stale = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<SnapshotPublishFailure>(&b).ok())
            .map(|f| format!("\n{}", stale_message(&volume, &f)))
            .unwrap_or_default();
        anyhow::bail!(
            "the volume's local metadata database is marked to be rebuilt from Telegram \
             ({reason}). The next mount rebuilds the database before using it.{stale}"
        );
    }
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<SnapshotPublishFailure>(&bytes) {
            Ok(f) => anyhow::bail!(stale_message(&volume, &f)),
            Err(_) => anyhow::bail!(
                "the volume's last metadata snapshot publish failed ({} is present but \
                 unreadable); its cloud metadata is STALE until a mount and unmount publish a \
                 fresh snapshot",
                path.display()
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Encrypt the SQLite DB's bytes with the versioned metadata-snapshot codec
/// (anti-rollback: `version` is bound into the AEAD plaintext under the
/// `metadata-snapshot-v2` AAD), and upload it. Returns the snapshot message ID.
async fn sync_metadata_snapshot(
    result: &manager::OpenVolumeResult,
    version: u64,
    db_bytes: &[u8],
    transport: &dyn teagarden_telegram::client::BlockTransport,
) -> Result<(i64, [u8; 32])> {
    use teagarden_core::volume::metadata_snapshot;

    let encrypted = metadata_snapshot::encrypt_snapshot(&result.hierarchy.data, version, db_bytes)
        .map_err(|e| anyhow::anyhow!("encrypt metadata snapshot: {e}"))?;

    // Hash the exact ciphertext blob so the journal HEAD can bind the base
    // snapshot's identity (not just its version) against transport substitution.
    let blob_hash = *blake3::hash(&encrypted).as_bytes();

    let message_id = transport
        .sync_metadata(&encrypted)
        .await
        .map_err(utils::telegram_err)?;

    Ok((message_id, blob_hash))
}

/// Restore a volume's local metadata DB from its Telegram snapshot.
///
/// Disaster recovery + anti-rollback. Fetches the encrypted metadata snapshot
/// from the channel, decrypts it, refuses any snapshot whose embedded monotonic
/// version is older than the volume's HMAC-protected `metadata_version`, then
/// atomically swaps the SQLite DB into place. The volume must NOT be mounted or
/// otherwise in use — the DB file is replaced underneath any open handle.
pub async fn restore(
    volume: &str,
    snapshot_id: Option<i64>,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    force: bool,
    discard_journal: bool,
) -> Result<()> {
    restore_in(
        &manager::default_volumes_dir(),
        volume,
        snapshot_id,
        password_file,
        recovery_file,
        force,
        discard_journal,
        Box::new(|channel_ref| Box::pin(connect_restore_transport(channel_ref))),
    )
    .await
}

/// Opens the Telegram transport `restore` fetches the snapshot through (the
/// user's session, or a test transport).
pub(crate) type ConnectRestore<'a> = Box<
    dyn FnOnce(
            ChannelRef,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Arc<dyn BlockTransport>>> + 'a>,
        > + 'a,
>;

/// The user's Telegram session bound to a volume's channel, for `restore`.
async fn connect_restore_transport(channel_ref: ChannelRef) -> Result<Arc<dyn BlockTransport>> {
    use teagarden_telegram::types::AuthState;
    // A Telegram transport is required — the snapshot lives in the channel.
    let (api_id, api_hash) = utils::load_telegram_credentials()
        .context("Telegram credentials are required to restore a snapshot from the channel")?;
    let tg_config = TelegramConfig {
        api_id,
        api_hash,
        session_path: session_file_path().to_string_lossy().to_string(),
        channel_ref: Some(channel_ref),
        ..Default::default()
    };
    let client = TelegramClient::new(tg_config);
    let state = client.connect().await.map_err(utils::telegram_err)?;
    if state != AuthState::Authenticated {
        anyhow::bail!("Not authenticated with Telegram. Run `teagarden auth login` first.");
    }
    Ok(Arc::new(client))
}

/// [`restore`] against an explicit volumes directory and Telegram connector.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn restore_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    snapshot_id: Option<i64>,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    force: bool,
    discard_journal: bool,
    connect: ConnectRestore<'_>,
) -> Result<()> {
    let volume_id = resolve_volume_id(volume, volumes_dir)?;

    // No one to ask means no restore: refuse (non-zero), rather than read the
    // missing answer as "no" and exit 0. Checked first, before the slow key
    // derivation and any Telegram contact.
    if !force && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "refusing to restore volume '{volume}' without confirmation: stdin is not a \
             terminal, so there is no one to ask. Pass --force to restore without asking. \
             Nothing was changed."
        );
    }

    // Refuse if mounted: swapping the DB file under a live SQLite handle corrupts
    // it. This guards FUSE mounts only; the volume must also not be served by the
    // API/portal during a restore.
    if active_fuse_mounts().contains_key(&volume_id) {
        anyhow::bail!(
            "volume '{volume}' is currently mounted; unmount it before restoring \
             (the metadata DB is replaced in place)"
        );
    }

    // Single-writer backstop (held for the whole restore): serialize against a
    // concurrent FUSE mount AND another offline mutator. Crucial here because
    // `restore_with_floor` renames `metadata.db` and unlinks the `-wal`/`-shm`/
    // `-journal` sidecars — doing that under a concurrent `revert`'s open SQLite
    // handle would strand its committed-but-uncheckpointed delta (audit #3).
    // Taken BEFORE volume.json is read, so the floor, snapshot id and hash used
    // below are ones no other writer can change underneath this restore.
    let _volume_lock = manager::VolumeLock::acquire_exclusive(&volumes_dir.join(&volume_id))
        .map_err(utils::core_err)?;

    // Key-protection aware: restore must work on a `--key-protection` volume, not
    // just a legacy password one (see utils::open_volume_any).
    let result = utils::open_volume_any(&volume_id, password_file, recovery_file, volumes_dir)?;
    harden_process();
    println!("Volume '{volume}' authenticated successfully.");

    if snapshot_id.or(result.config.metadata_snapshot_id).is_none() {
        anyhow::bail!(
            "no metadata snapshot recorded for volume '{volume}'. Snapshots are published on \
             unmount once Telegram is configured; there is nothing to restore."
        );
    }
    if result.config.telegram_group_id == 0 {
        anyhow::bail!("volume '{volume}' has no Telegram channel recorded; cannot restore");
    }
    let transport = connect(ChannelRef {
        id: result.config.telegram_group_id,
        access_hash: result.config.telegram_channel_access_hash,
        topic_id: result.config.telegram_topic_id,
    })
    .await?;
    restore_core(
        result,
        transport.as_ref(),
        volume,
        snapshot_id,
        force,
        discard_journal,
    )
    .await?;
    Ok(())
}

/// A boundary between two durable steps of `volume restore` (after the floor is
/// persisted). The crash tests stop the restore there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreStep {
    /// The rebuild-required marker is durable; the DB and HEAD are the old ones.
    MarkerWritten,
    /// The local metadata DB (and its sidecars) is removed; the HEAD is the old one.
    LocalDbRemoved,
    /// The HEAD names the restored snapshot at seq 0; the DB is still absent.
    HeadReset,
    /// The restored DB is in place; the marker is not removed yet.
    DbInstalled,
}

/// Core of `volume restore` on an opened volume (the caller holds the volume
/// lock) and an injected transport. Returns the restored snapshot version; a
/// declined confirmation is an error ("Restore cancelled").
pub(crate) async fn restore_core(
    result: manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
    volume: &str,
    snapshot_id: Option<i64>,
    force: bool,
    discard_journal: bool,
) -> Result<Option<u64>> {
    restore_core_at(
        result,
        transport,
        volume,
        snapshot_id,
        force,
        discard_journal,
        &|_| {},
    )
    .await
}

/// [`restore_core`], reporting each [`RestoreStep`] to `at`.
///
/// It refuses while the journal HEAD has entries past its base snapshot (the
/// last session did not end cleanly): restoring would discard those changes,
/// which are on Telegram and which the next mount would replay. Only
/// `discard_journal` lets it go on, and it says how many entries it drops.
///
/// The restored DB's bytes are stamped first, with a new lineage at journal
/// position 0, in a scratch file, before anything is persisted or removed.
/// After the floor is persisted, the order is: write the rebuild-required
/// marker ([`rebuild_marker`], durable), remove the local DB (kept unless it
/// is reproducible, see [`local_db::keep_replaced`]: only when the HEAD is at
/// seq 0 on this very snapshot and the DB carries its lineage there), write a
/// fresh journal HEAD (seq 0, base = the snapshot being restored, that
/// lineage), install the stamped DB, remove the marker. While the marker exists no command uses the
/// local DB, and the next mount rebuilds it from Telegram before anything else:
/// - marker, old DB, old HEAD: rebuilt from the old HEAD's base snapshot and
///   journal, i.e. the volume as it was before the restore;
/// - marker, DB removed, old HEAD: the same;
/// - marker, DB removed, new HEAD: rebuilt from the restored snapshot;
/// - marker, DB installed, new HEAD: rebuilt from the restored snapshot, which
///   is the DB just installed (it carries the new HEAD's lineage at seq 0, so
///   that rebuild does not keep a copy of it);
/// - no marker, DB installed, new HEAD: the restore is complete.
///
/// Never a restored DB under the old HEAD (the next mount would replay the old
/// journal over it, or chain new entries onto a base the DB is not), never the
/// old DB under the new HEAD, and never a state some command could take for an
/// empty volume.
pub(crate) async fn restore_core_at(
    mut result: manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
    volume: &str,
    snapshot_id: Option<i64>,
    force: bool,
    discard_journal: bool,
    at: &dyn Fn(RestoreStep),
) -> Result<Option<u64>> {
    use teagarden_core::volume::metadata_snapshot;

    // Choose the snapshot message id: explicit override, else the one recorded in
    // the config. The anti-rollback gate applies to either, so an explicit older
    // snapshot is still refused.
    let msg_id = match snapshot_id.or(result.config.metadata_snapshot_id) {
        Some(id) => id,
        None => anyhow::bail!(
            "no metadata snapshot recorded for volume '{volume}'. Snapshots are published on \
             unmount once Telegram is configured; there is nothing to restore."
        ),
    };

    // Journal entries past the base snapshot are changes the user made (each one
    // was published to Telegram before it was committed locally); restoring
    // replaces them with the snapshot, so it needs an explicit go-ahead.
    let head_path = journal_head_path(&result);
    let loaded_head = JournalHead::load(&head_path, &result.hierarchy.integrity);
    // The DB is what this restore installs again (and not kept) only when the
    // HEAD has no entries past the very snapshot being restored and the DB
    // carries the HEAD's lineage at that position (a second `volume restore`
    // of the same snapshot, or one after a restore whose marker was left).
    let reproduces = match &loaded_head {
        Ok(Some(h)) if h.seq == 0 && h.base_snapshot_msg_id == msg_id => reproduced_by(&result, h),
        _ => None,
    };
    let discarded = match loaded_head {
        Ok(Some(h)) if h.seq > 0 => Some(format!(
            "{} entr{} past snapshot version {} (message_id={})",
            h.seq,
            if h.seq == 1 { "y" } else { "ies" },
            h.base_snapshot_version,
            h.base_snapshot_msg_id
        )),
        Ok(_) => None,
        Err(e) => Some(format!(
            "an unknown number of entries (journal.head is unreadable: {e})"
        )),
    };
    if let Some(what) = &discarded {
        if !discard_journal {
            anyhow::bail!(
                "refusing to restore volume '{volume}': its metadata journal has {what}, in no \
                 snapshot yet. They are changes from the last session, which did not \
                 end with a clean unmount; they are stored on Telegram and the next mount \
                 replays them. Restoring now would DISCARD them. To keep them, mount the volume \
                 and unmount it cleanly instead (that publishes a snapshot holding them). To \
                 restore anyway and lose them, run `teagarden volume restore {volume} \
                 --discard-journal`. Nothing was changed."
            );
        }
    }

    println!("Fetching metadata snapshot (message_id={msg_id})...");
    let blob = transport
        .fetch_metadata(msg_id)
        .await
        .map_err(utils::telegram_err)?;

    // Peek the version (decrypt-only) so we can show it and confirm BEFORE the
    // destructive swap. `restore_with_floor` re-decrypts and is the single source
    // of truth for the gated write (it persists the floor before swapping).
    let (snapshot_version, _peek) =
        metadata_snapshot::decrypt_snapshot(&result.hierarchy.data, &blob)
            .map_err(utils::core_err)?;
    metadata_snapshot::check_not_rolled_back(snapshot_version, result.config.metadata_version)
        .map_err(utils::core_err)?;
    // The floor and recorded hash checked below must be the ones on disk now.
    ensure_config_unchanged(&result)?;

    if let Some(what) = &discarded {
        println!(
            "--discard-journal: the metadata journal's {what} (changes from a session that did \
             not end cleanly) will be DISCARDED by this restore."
        );
    }
    if !force {
        println!(
            "About to overwrite the local metadata DB for '{}' with snapshot version {} \
             (local version {}). This is destructive and cannot be undone.",
            result.config.display_name, snapshot_version, result.config.metadata_version
        );
        if let Some(what) = &discarded {
            println!("The journal's {what} will be lost.");
        }
        print!("Continue? [y/N] ");
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("read confirmation")?;
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            anyhow::bail!("Restore cancelled. Nothing was changed.");
        }
    }

    // Clone the borrows the call needs so the persist closure can take the rest of
    // `result` mutably without overlapping borrows.
    let data_key = result.hierarchy.data.clone();
    let db_path = result.paths.db_path.clone();
    let floor = result.config.metadata_version;
    let recorded_hash = result.config.recorded_snapshot_hash();
    let blob_hash_bytes = *blake3::hash(&blob).as_bytes();
    let blob_hash = hex::encode(blob_hash_bytes);
    let integrity = result.hierarchy.integrity.clone();
    let base_dir = result.paths.base_dir.clone();
    // The restored DB becomes the volume's current database under a new
    // lineage at journal position 0: its bytes are stamped with them BEFORE
    // anything is persisted or removed, and the HEAD records the same lineage
    // before the DB is installed. So the installed DB always carries the
    // HEAD's lineage and position: a restore killed after the install leaves
    // a DB the next mount's rebuild reproduces exactly (and does not keep).
    let lineage = std::cell::Cell::new(None::<Lineage>);
    let keep_schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let volume_id = result.config.volume_id.to_string();
    let scratch = base_dir.join("metadata.db.restoring");
    let restored_version = metadata_snapshot::restore_prepared_with_floor_then(
        &data_key,
        &blob,
        &db_path,
        floor,
        recorded_hash,
        |v, bytes| {
            let l = Lineage::new(v);
            lineage.set(Some(l));
            let stamp = local_db::DbStamp {
                volume_id: volume_id.clone(),
                lineage: l,
            };
            local_db::stamp_db_bytes(&bytes, &scratch, &keep_schema, &stamp, 0)
        },
        |v| {
            // Raise the HMAC-covered anti-rollback floor BEFORE the swap (fail-closed),
            // and record the snapshot it now names.
            result.config.metadata_version = v;
            result.config.metadata_snapshot_id = Some(msg_id);
            result.config.metadata_snapshot_hash = Some(blob_hash);
            manager::save_config_resealed(
                &mut result.config,
                &result.hierarchy,
                &result.paths.config_path,
            )
        },
        |v| {
            // See the ordering in the doc comment above.
            rebuild_marker::mark(
                &base_dir,
                &format!(
                    "`volume restore` of snapshot version {v} (message_id={msg_id}) has not \
                     finished"
                ),
            )?;
            at(RestoreStep::MarkerWritten);
            keep_replaced_db(&db_path, &keep_schema, volume, reproduces.as_ref())?;
            metadata_snapshot::remove_db_files(&db_path)?;
            at(RestoreStep::LocalDbRemoved);
            let l = lineage.get().ok_or_else(|| {
                teagarden_core::error::CoreError::Volume(
                    "the restored database was not stamped before the HEAD reset".into(),
                )
            })?;
            JournalHead::at_snapshot(msg_id, v, blob_hash_bytes, l)
                .store_atomic(&head_path, &integrity)?;
            at(RestoreStep::HeadReset);
            Ok(())
        },
    )
    .map_err(utils::core_err)
    .with_context(|| {
        if rebuild_marker::path(&base_dir).exists() {
            "the restore did not finish. The local metadata database is marked to be rebuilt \
             from Telegram: no command uses it until a mount rebuilds it (or `volume restore` \
             is run again)"
        } else {
            "the local metadata database was not touched"
        }
    })?;
    at(RestoreStep::DbInstalled);
    if let Err(e) = rebuild_marker::clear(&base_dir) {
        // Harmless: the next mount rebuilds the DB just installed from the
        // snapshot it came from, then removes the marker.
        eprintln!(
            "WARNING: could not remove {}: {e}. The next mount rebuilds the metadata database \
             from Telegram once.",
            rebuild_marker::path(&base_dir).display()
        );
    }

    println!(
        "Restored volume '{}' from snapshot version {} (message_id={}).",
        result.config.display_name, restored_version, msg_id
    );
    println!("The local metadata DB has been replaced. Mount the volume to use it.");
    Ok(Some(restored_version))
}

/// `teagarden volume republish <volume> --from-local-db`: the explicit "local
/// database wins" recovery. For a volume whose metadata cannot be rebuilt from
/// Telegram (its base snapshot or a journal entry is gone, or it names no
/// snapshot) while the local metadata database is intact: publish that
/// database as the volume's metadata at the next reserved snapshot version,
/// stamp it, and reset the journal HEAD onto it. `replace_newer`
/// (`--replace-newer-metadata`) is needed for a database whose stamp is not
/// the HEAD's lineage; see [`republish_core`].
pub async fn republish(
    volume: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    force: bool,
    replace_newer: bool,
) -> Result<()> {
    match republish_in(
        &manager::default_volumes_dir(),
        volume,
        password_file,
        recovery_file,
        force,
        replace_newer,
        Box::new(|channel_ref| Box::pin(connect_restore_transport(channel_ref))),
    )
    .await
    {
        Ok(true) => Ok(()),
        // A declined (or unanswerable) confirmation is an error, like
        // `volume restore` and `volume delete`: a script must not read it as done.
        Ok(false) => anyhow::bail!("Republish cancelled. Nothing was changed."),
        Err(e) => Err(e),
    }
}

/// [`republish`] against an explicit volumes directory and Telegram connector.
/// `Ok(true)` once published, `Ok(false)` when the confirmation was declined.
pub(crate) async fn republish_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    force: bool,
    replace_newer: bool,
    connect: ConnectRestore<'_>,
) -> Result<bool> {
    let volume_id = resolve_volume_id(volume, volumes_dir)?;
    if active_fuse_mounts().contains_key(&volume_id) {
        anyhow::bail!(
            "volume '{volume}' is currently mounted; unmount it before republishing its local \
             metadata database. Nothing was changed."
        );
    }
    // The exclusive lock, held to the end and taken before volume.json is read:
    // no mount, `revert`, `restore`, `key rotate` (exclusive) and no `history`
    // or `diff` (shared) runs meanwhile.
    let _volume_lock = manager::VolumeLock::acquire_exclusive(&volumes_dir.join(&volume_id))
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot republish volume '{volume}' now: {e:#}. Nothing was changed.",
                e = utils::core_err(e)
            )
        })?;
    let result = utils::open_volume_any(&volume_id, password_file, recovery_file, volumes_dir)?;
    harden_process();
    println!("Volume '{volume}' authenticated successfully.");
    if result.config.telegram_group_id == 0 {
        anyhow::bail!("volume '{volume}' has no Telegram channel recorded; cannot republish");
    }
    let transport = connect(ChannelRef {
        id: result.config.telegram_group_id,
        access_hash: result.config.telegram_channel_access_hash,
        topic_id: result.config.telegram_topic_id,
    })
    .await?;
    republish_core(
        result,
        transport.as_ref(),
        volume,
        force,
        replace_newer,
        &mut |prompt: &str| {
            print!("{prompt}");
            std::io::stdout().flush().ok();
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .context("read confirmation")?;
            Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
        },
    )
    .await
}

/// Core of `volume republish --from-local-db` on an opened volume whose
/// exclusive lock the caller holds, and an injected transport. `confirm` asks
/// the user, with the whole summary as its prompt (skipped with `force`, which
/// prints the summary instead).
///
/// The summary gives the verdict of the database's lineage stamp against the
/// lineage journal.head records, and the snapshot the republish supersedes
/// (which `volume restore` refuses afterwards: the floor moves). It refuses,
/// before asking, a database stamped as another volume's, and, unless
/// `replace_newer` (`--replace-newer-metadata`; `force` does not imply it),
/// one that is not the database the HEAD's lineage was stamped on: its stamp
/// differs from that lineage, or it carries no stamp while the HEAD records
/// one (an older copy). No HEAD, an unreadable one, or one without a lineage
/// leave nothing to compare, and republish goes on: those are the cases the
/// mount's refusals send the user here for. The publish itself refuses a
/// database that fails `PRAGMA quick_check`.
pub(crate) async fn republish_core(
    mut result: manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
    volume: &str,
    force: bool,
    replace_newer: bool,
    confirm: &mut dyn FnMut(&str) -> Result<bool>,
) -> Result<bool> {
    refuse_read_only_share(&result, "volume republish")?;
    let db_path = result.paths.db_path.clone();
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    // A usable state other than the stamp: present, readable, with a root.
    if local_db::db_file_absent(&db_path)
        .with_context(|| format!("check the metadata database {}", db_path.display()))?
    {
        anyhow::bail!(
            "volume '{volume}' has no local metadata database ({} is missing), so there is \
             nothing to republish. Nothing was changed.",
            db_path.display()
        );
    }
    let tree = local_db::tree_summary_of(&db_path, &schema).map_err(|e| {
        anyhow::anyhow!(
            "the local metadata database of volume '{volume}' cannot be read ({e}), so it \
             cannot be republished. Nothing was changed."
        )
    })?;
    if !tree.has_root {
        anyhow::bail!(
            "the local metadata database of volume '{volume}' has no root directory, so it is \
             not a usable volume database and cannot be republished. Nothing was changed."
        );
    }
    // The file checked here is the only one the publish below may read.
    let db = local_db::DbFileId::of(&db_path).map_err(utils::core_err)?;

    let head = JournalHead::load(&journal_head_path(&result), &result.hierarchy.integrity);
    let marker = rebuild_marker::load(&result.paths.base_dir).map_err(utils::core_err)?;

    // The verdict of the database's lineage stamp against the HEAD's lineage.
    let stamp = local_db::open_read_only(&db_path)
        .and_then(|c| local_db::read_stamp(&c, &schema))
        .map_err(|e| {
            anyhow::anyhow!(
                "the lineage stamp of the local metadata database of volume '{volume}' cannot \
                 be read ({e}). Nothing was changed."
            )
        })?;
    let head_lineage = match &head {
        Ok(Some(h)) => h.lineage,
        _ => None,
    };
    let volume_id = result.config.volume_id.to_string();
    let (verdict, older) = match (&stamp, head_lineage) {
        (Some(s), _) if s.volume_id != volume_id => anyhow::bail!(
            "refusing to republish: the local metadata database of volume '{volume}' is stamped \
             as the database of another volume ({}), not of this one, so its rows do not \
             describe this volume's files. Nothing was changed. `teagarden volume restore \
             {volume}` puts back the snapshot volume.json names.",
            s.volume_id
        ),
        (Some(s), Some(l)) if s.lineage == l => (
            format!(
                "its lineage stamp ({l}) is the one journal.head records: it is the volume's \
                 current database"
            ),
            false,
        ),
        (Some(s), Some(l)) => (
            format!(
                "its lineage stamp ({}) is NOT the one journal.head records ({l}): it is an \
                 older copy of the volume's database, or one a snapshot publish did not finish, \
                 and the volume's metadata on Telegram may hold newer changes",
                s.lineage
            ),
            true,
        ),
        // journal.head records a lineage, and this database carries none: it
        // is not the database that lineage was stamped on (an older copy, or
        // one from an earlier build), so the metadata on Telegram may be newer.
        (None, Some(l)) => (
            format!(
                "it carries no lineage stamp (written by an earlier version of teagarden, or \
                 created by something else), but journal.head records one ({l}): it is not \
                 the database that lineage was stamped on (an older copy of the volume's \
                 database, perhaps from a backup), and the volume's metadata on Telegram may \
                 hold newer changes"
            ),
            true,
        ),
        (None, None) => (
            "it carries no lineage stamp (written by an earlier version of teagarden, or \
             created by something else), and journal.head records none either, so nothing \
             shows which state of the volume it holds"
                .to_string(),
            false,
        ),
        (Some(s), None) => (
            format!(
                "it is stamped as {}; journal.head records no lineage (it is missing, \
                 unreadable, or written by an earlier version of teagarden), so there is \
                 nothing to compare the stamp with",
                s.lineage
            ),
            false,
        ),
    };
    let superseded = match result.config.metadata_snapshot_id {
        Some(id) => format!(
            "the snapshot volume.json names, version {} (message_id={id})",
            result.config.metadata_version
        ),
        None => format!(
            "volume.json's snapshot record (version {}, no snapshot message named)",
            result.config.metadata_version
        ),
    };
    if older && !replace_newer {
        anyhow::bail!(
            "refusing to republish the local metadata database of volume '{volume}': {verdict}. \
             Republishing it would supersede {superseded}, and afterwards `teagarden volume \
             restore` refuses that snapshot and every older one (the anti-rollback floor moves \
             to the republished version), so its newer changes could not be brought back. \
             Nothing was changed. If Telegram can be reached, mount the volume instead: the \
             mount rebuilds the database from the volume's snapshot and journal. Only if you \
             are sure this database is the one to keep, run `teagarden volume republish \
             {volume} --from-local-db --replace-newer-metadata` (`--force` alone does not)."
        );
    }

    let mut summary = format!(
        "Republish the local metadata database of volume '{volume}' as the volume's metadata:\n"
    );
    summary += &format!(
        "  local database: {} entr{} below the root directory (files, directories, symlinks)\n",
        tree.entries,
        if tree.entries == 1 { "y" } else { "ies" }
    );
    summary += &format!("  lineage: {verdict}\n");
    let journal = match &head {
        Ok(Some(h)) => format!(
            "journal HEAD: seq {} past base snapshot version {} (message_id={})",
            h.seq, h.base_snapshot_version, h.base_snapshot_msg_id
        ),
        Ok(None) => "journal HEAD: none".to_string(),
        Err(e) => format!("journal HEAD: unreadable ({e})"),
    };
    summary += &format!("  {journal}\n");
    summary += "This overwrites:\n";
    summary += &format!(
        "  - the volume's latest metadata snapshot: this supersedes {superseded}; from now on \
         `volume restore` and a share grant use the new one, and `volume restore` refuses the \
         superseded snapshot and every older one (the anti-rollback floor moves to the new \
         version)\n"
    );
    match &head {
        Ok(Some(h)) if h.seq > 0 => {
            summary += &format!(
                "  - the metadata journal: its {} entr{} past the base snapshot are no longer \
                 replayed by any mount (the local database holds what this machine committed \
                 of them)\n",
                h.seq,
                if h.seq == 1 { "y" } else { "ies" }
            )
        }
        _ => summary += "  - the journal HEAD (reset onto the new snapshot)\n",
    }
    if let Some(reason) = &marker {
        summary += &format!("  - the rebuild marker ({reason}), which is removed\n");
    }
    summary += "Nothing on Telegram is deleted.\n";
    if older {
        summary += "--replace-newer-metadata: the newer metadata on Telegram is replaced.\n";
    }
    if force {
        print!("{summary}");
    } else if !confirm(&format!("{summary}Continue? [y/N] "))? {
        return Ok(false);
    }
    ensure_config_unchanged(&result)?;

    // Bring the schema up to date and fold the WAL into the file the snapshot
    // reads.
    {
        let conn = local_db::open_existing(&db_path)
            .with_context(|| format!("open the metadata database {}", db_path.display()))?;
        initialize_database(&conn, &schema)?;
        local_db::checkpoint_fully(&conn, &db_path).map_err(utils::core_err)?;
    }
    publish_snapshot_and_compact(&mut result, transport, PublishOf::Republish(db)).await?;
    if marker.is_some() {
        finish_rebuild(&result);
    }
    println!(
        "Republished the local metadata database of volume '{volume}' as snapshot version {}; \
         the journal HEAD is reset onto it. Mount the volume to use it.",
        result.config.metadata_version
    );
    Ok(true)
}

/// Restore a file to a prior manifest version, in place, preserving history.
///
/// This is the **offline journaled-mutation substrate** (v0.4.8). It does NOT mount
/// the volume; it opens it transiently, appends a NEW manifest version whose content
/// is `target_version`'s (git-revert style — the superseded versions remain in
/// history), and journals the change to the channel. Non-destructive: nothing is
/// overwritten, so there is no confirmation prompt.
///
/// Single-writer is a **correctness** constraint, not hygiene: a second journaled
/// writer would interleave changeset before-images and ABORT crash recovery. Hence
/// two refusals — while the volume is FUSE-mounted (another process owns the journal
/// HEAD), and while offline (the mutation MUST be journaled; an un-journaled write to
/// a journaled table poisons recovery, and manifest history only exists for journaled
/// volumes, so an offline revert is never valid).
pub async fn revert(
    volume: &str,
    path: &str,
    target_version: u64,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    revert_in(
        &manager::default_volumes_dir(),
        volume,
        path,
        target_version,
        password_file,
        recovery_file,
    )
    .await
}

/// Body of [`revert`], parameterized on `volumes_dir` so the wrapper (guards +
/// offline refusal) is testable against a tempdir volume without touching the real
/// default volumes directory.
async fn revert_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    path: &str,
    target_version: u64,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    use teagarden_telegram::types::AuthState;

    let volume_id = resolve_volume_id(volume, volumes_dir)?;

    // Refuse-if-mounted (single writer): a live mount owns the journal HEAD;
    // a concurrent journaled mutation corrupts the changeset chain.
    if active_fuse_mounts().contains_key(&volume_id) {
        anyhow::bail!(
            "volume '{volume}' is currently mounted; unmount it before reverting \
             (revert is a single-writer offline operation)"
        );
    }

    // Single-writer backstop: hold an exclusive advisory lock for the whole
    // operation. This closes the TOCTOU window the refuse-if-mounted check leaves
    // open (a mount, or another offline `revert`/`restore`, starting during the
    // seconds-long Telegram connect below) and serializes offline-vs-offline
    // mutators, which `/proc/mounts` cannot see. Held until `revert` returns — across
    // the connect, the recover→mutate→publish sequence, and the WAL checkpoint at
    // `drop(fs)` inside `revert_core` (so a concurrent `restore` cannot rename the DB
    // / unlink the `-wal` mid-revert). Taken BEFORE volume.json is read (by the
    // unlock below), so a `key rotate` cannot replace it underneath this revert.
    let _volume_lock = manager::VolumeLock::acquire_exclusive(&volumes_dir.join(&volume_id))
        .map_err(utils::core_err)?;

    // Key-protection aware (see utils::open_volume_any).
    let result = utils::open_volume_any(&volume_id, password_file, recovery_file, volumes_dir)?;
    harden_process();
    println!("Volume '{volume}' authenticated successfully.");

    // Refuse-if-offline: the revert is a journaled mutation; without the channel it
    // cannot be logged, and an un-journaled mutation of a journaled table poisons
    // recovery (the changeset before-image chain). A Telegram transport is required.
    let (api_id, api_hash) = utils::load_telegram_credentials().context(
        "Telegram credentials are required to revert (the change is journaled to the channel)",
    )?;
    let channel_ref = if result.config.telegram_group_id != 0 {
        Some(ChannelRef {
            id: result.config.telegram_group_id,
            access_hash: result.config.telegram_channel_access_hash,
            topic_id: result.config.telegram_topic_id,
        })
    } else {
        anyhow::bail!("volume '{volume}' has no Telegram channel recorded; cannot revert");
    };
    let tg_config = TelegramConfig {
        api_id,
        api_hash,
        session_path: session_file_path().to_string_lossy().to_string(),
        channel_ref,
        ..Default::default()
    };
    let client = TelegramClient::new(tg_config);
    let state = client.connect().await.map_err(utils::telegram_err)?;
    if state != AuthState::Authenticated {
        anyhow::bail!("Not authenticated with Telegram. Run `teagarden auth login` first.");
    }

    let transport: Arc<dyn BlockTransport> = Arc::new(client);
    let (new_version, size) = revert_core(result, transport, path, target_version).await?;
    println!(
        "Reverted '{path}' to version {target_version} (new version {new_version}, {size} bytes). \
         History is preserved — run `teagarden volume history {volume}` to see all versions."
    );
    Ok(())
}

/// Core of `volume revert`, with the Telegram transport **injected** so the whole
/// substrate is testable end-to-end against an in-memory channel (no live Telegram).
///
/// Drives the transient journaled mount: recover the metadata DB from the channel
/// (same precondition a real mount establishes), build a journaled — but un-mounted —
/// `CryptFs`, append the reverting manifest version via [`CryptFs::revert_impl`] in
/// ONE `journaled_txn` (delta published before local commit → crash-safe + replayable
/// exactly like a FUSE write), then publish a fresh snapshot and compact the journal.
///
/// `path` is an absolute in-volume path (`/dir/file`). Returns `(new_version,
/// total_size)` for the caller's success message. `result` is consumed.
pub(crate) async fn revert_core(
    mut result: manager::OpenVolumeResult,
    transport: Arc<dyn BlockTransport>,
    path: &str,
    target_version: u64,
) -> Result<(u64, u64)> {
    // Phase 1 — journal recovery: rebuild the DB from the channel if it was lost or
    // left with uncompacted deltas, BEFORE we open it for mutation. Returns the
    // loaded HEAD (None for a pre-journal volume, initialised below).
    // Then open the (now-consistent) DB and checkpoint the WAL into the main file,
    // so the base-snapshot read in `journal_init_phase` (and the post-revert
    // snapshot) sees a complete DB file. Nothing writes between here and those reads.
    refuse_read_only_share(&result, "volume revert")?;
    let author_device_id =
        if result.config.telegram_group_id != 0 && result.config.telegram_topic_id != 0 {
            Some(ensure_sdo_author_device_id(&mut result)?)
        } else {
            None
        };
    let PreparedSession {
        conn,
        head: loaded_head,
        mut db,
        ..
    } = prepare_session(&mut result, transport.as_ref()).await?;
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // Build the journaled CryptFs — NO FUSE mount, NO cache, NO upload pool. The
    // revert publishes one complete TGFV object plus the journal/snapshot via the
    // transport directly.
    let mut fs_builder = CryptFs::new(
        conn,
        schema,
        result.hierarchy.meta.clone(),
        result.hierarchy.data.clone(),
        uid,
        gid,
    )
    .with_epoch(result.config.current_epoch);
    if let Some(author_device_id) = author_device_id {
        fs_builder = fs_builder.with_sdo(result.config.volume_id, author_device_id);
        if result.config.sdo_initial_clock_ms != 0 || result.config.sdo_initial_clock_counter != 0 {
            fs_builder
                .observe_sdo_clock(
                    result.config.sdo_initial_clock_ms,
                    result.config.sdo_initial_clock_counter,
                )
                .map_err(errno_to_anyhow)
                .context("persist the greatest authenticated remote HLC before reverting")?;
        }
        let (_, header, header_wire) = discover_latest_header(
            transport.as_ref(),
            result.config.telegram_group_id,
            result.config.telegram_topic_id,
            &result.hierarchy.integrity,
            result.config.sdo_owner_public_key.as_deref(),
        )
        .await?
        .context("portable volume has no authenticated header")?;
        fs_builder = fs_builder
            .with_sdo_generation_keys(
                header.key_generation.unwrap_or(0),
                header.generation_boundary_message_id,
                generation_meta_keys(&header, &result.hierarchy)?,
            )
            .with_sdo_object_envelope(header_wire, result.hierarchy.clone());
        let (private, _) =
            load_or_create_device_keypair(&result.paths.base_dir, &result.hierarchy.wrapping)?;
        fs_builder =
            fs_builder.with_sdo_signing_key(teagarden_core::sdo::device_signing_key(&private.0));
        let premium = transport.is_premium_user().await.unwrap_or(false);
        fs_builder = fs_builder.with_sdo_file_limit(if premium {
            teagarden_core::sdo::MAX_SDO_FILE_BYTES_PREMIUM
        } else {
            teagarden_core::sdo::MAX_SDO_FILE_BYTES
        });
    }
    let fs = fs_builder
        .with_block_keys(
            result.hierarchy.block_id.clone(),
            result.hierarchy.filename.clone(),
        )
        .with_manifest_key(result.hierarchy.manifest.clone())
        .with_block_integrity(result.config.require_block_integrity)
        .with_block_v2_from_epoch(result.config.block_v2_from_epoch)
        .with_transport(transport.clone())
        .with_runtime(tokio::runtime::Handle::current())
        .with_session_checkpoints(db.checkpoints.clone())
        .context("take over the metadata database's checkpoints")?;

    // Resolve the path to an inode BEFORE activating the journal, so a bad path fails
    // fast without publishing a base snapshot for a pre-journal volume.
    let ino = {
        let store = fs.store();
        resolve_path_to_ino(&store, path)?
    };

    // Phase 2 — journal activation: reuse the loaded HEAD, or initialise one for a
    // pre-journal volume so revert_impl's journaled_txn has a live HEAD to advance.
    let head = match loaded_head {
        Some(h) => h,
        None => journal_init_phase(&mut result, transport.as_ref(), &mut db).await?,
    };
    let fs = fs.with_journal(
        result.hierarchy.integrity.clone(),
        journal_head_path(&result),
        head,
    );

    // Run the revert on a BLOCKING thread: revert_impl is a synchronous FUSE-style
    // callback that performs Telegram I/O via the runtime handle, so it must not run
    // on an async worker. Drop the FS inside the closure so the SQLite connection
    // closes and CHECKPOINTS the WAL into the main DB file BEFORE the snapshot below
    // reads that file (mirrors how `mount2` consumes the FS and checkpoints on close
    // before the unmount snapshot is read).
    let outcome = tokio::task::spawn_blocking(move || {
        let r = fs
            .revert_impl(ino, target_version)
            .and_then(|inode| fs.backfill_sdo_versions().map(|_| inode));
        drop(fs);
        r
    })
    .await
    .context("revert task panicked")?;
    let inode = outcome.map_err(errno_to_anyhow)?;

    // Publish a fresh snapshot + compact the journal. A failure here is returned
    // (non-zero exit) with the exact cloud/HEAD state; the revert itself is
    // already durable via its journaled delta (published before the local commit).
    publish_snapshot_and_compact(&mut result, transport.as_ref(), PublishOf::Session(db))
        .await
        .context("the revert itself is applied and journaled")?;

    Ok((inode.manifest.as_ref().map_or(0, |m| m.version), inode.size))
}

/// Resolve an absolute in-volume path (`/a/b/file`) to its inode number by walking
/// components from the root (ino 1). Errors if a component is missing, the path is
/// the root itself, or the target is not a regular file.
fn resolve_path_to_ino(store: &InodeStore<'_>, path: &str) -> Result<u64> {
    let mut ino = 1u64; // root inode
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        let children = store
            .list_children(ino)
            .map_err(|e| anyhow::anyhow!("read directory entries: {e}"))?;
        let next = children
            .into_iter()
            .find(|c| c.name == comp)
            .ok_or_else(|| anyhow::anyhow!("no such path component '{comp}' in '{path}'"))?;
        ino = next.ino;
    }
    if ino == 1 {
        anyhow::bail!("'{path}' resolves to the root directory, not a file");
    }
    let inode = store
        .get(ino)
        .map_err(|e| anyhow::anyhow!("read inode: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("inode {ino} for '{path}' not found"))?;
    if !inode.is_file() {
        anyhow::bail!("'{path}' is not a regular file");
    }
    Ok(ino)
}

/// Map a `revert_impl` errno to a human-facing error for the CLI.
fn errno_to_anyhow(errno: libc::c_int) -> anyhow::Error {
    let detail = match errno {
        libc::ENOENT => "file or target version not found",
        libc::EISDIR => "path is a directory, not a regular file",
        libc::EINVAL => "path is not a regular file (e.g. a symlink)",
        libc::EIO => "I/O error during revert (see logs for the failing step)",
        _ => "revert failed",
    };
    anyhow::anyhow!("{detail} (errno {errno})")
}

/// Before a rebuild, restore, auto-restore or share adoption replaces the DB
/// at `db_path` of volume `volume`: keep it unless it is reproducible from
/// Telegram (`reproduces`; see [`local_db::keep_replaced`]), and say where
/// and how to bring it back.
fn keep_replaced_db(
    db_path: &std::path::Path,
    schema: &OpaqueSchema,
    volume: &str,
    reproduces: Option<&local_db::Reproduces>,
) -> std::result::Result<(), teagarden_core::error::CoreError> {
    let say_removed = |removed: &[PathBuf]| {
        for old in removed {
            println!(
                "Removed the oldest kept copy {} (at most {} of each kind are kept).",
                old.display(),
                local_db::KEPT_COPIES
            );
        }
    };
    match local_db::keep_replaced(db_path, schema, reproduces)? {
        local_db::Kept::Nothing | local_db::Kept::Reproducible => {}
        local_db::Kept::Replaced { path, removed } => {
            println!(
                "The local metadata database being replaced is kept at {}. To bring it back: \
                 copy it over {} (remove {}-wal and {}-shm first), then run `teagarden volume \
                 republish {volume} --from-local-db --replace-newer-metadata`.",
                path.display(),
                db_path.display(),
                db_path.display(),
                db_path.display()
            );
            say_removed(&removed);
        }
        local_db::Kept::Unreadable { path, why, removed } => {
            println!(
                "The local metadata database being replaced could not be read as a volume \
                 database ({why}); it was renamed, unread, to {} (with its -wal and -shm, if \
                 any).",
                path.display()
            );
            say_removed(&removed);
        }
    }
    Ok(())
}

/// What a rebuild onto `head` reproduces: the HEAD's lineage at its journal
/// position. `None` for a HEAD without a lineage (nothing proves a DB
/// reproducible then).
fn reproduced_by(
    result: &manager::OpenVolumeResult,
    head: &JournalHead,
) -> Option<local_db::Reproduces> {
    head.lineage.map(|lineage| local_db::Reproduces {
        stamp: local_db::DbStamp {
            volume_id: result.config.volume_id.to_string(),
            lineage,
        },
        seq: head.seq,
    })
}

/// Auto-reconcile the local metadata DB on mount (disaster recovery).
///
/// If the local SQLite DB is missing or empty (the lost/corrupt-DB case) and the
/// volume has a published snapshot, fetch and restore it before mounting — so a
/// user who lost their local state recovers automatically instead of mounting an
/// empty filesystem over durable-but-orphaned blocks. The anti-rollback floor
/// lives in `volume.json` (which survives a lost DB), so it still gates the
/// restore. An intact, non-empty local DB is NEVER touched here — "the channel is
/// newer than an existing local DB" is the multi-device milestone, not this.
/// True only when the local metadata DB is absent (missing or zero-length) — the
/// disaster-recovery trigger for auto-reconcile. An existing, non-empty DB returns
/// `false` so it is NEVER clobbered by an automatic restore (newer-channel-wins is
/// the multi-device milestone, not this).
#[cfg(test)]
fn local_db_absent(db_path: &std::path::Path) -> bool {
    local_db::db_file_absent(db_path).unwrap()
}

/// Whether the volume has a successfully published snapshot to rebuild its
/// local DB from ([`manager::has_published_snapshot`]). Its local DB is then
/// never created, only rebuilt.
pub(crate) fn has_published_snapshot(result: &manager::OpenVolumeResult) -> bool {
    manager::has_published_snapshot(&result.config, &result.paths.base_dir)
}

/// What the volume's records (volume.json, the journal HEAD's lineage) say
/// its local DB must be.
pub(crate) fn expected_db(result: &manager::OpenVolumeResult) -> Result<local_db::Expected> {
    local_db::Expected::of_volume(
        &result.config,
        &result.paths.base_dir,
        &result.hierarchy.integrity,
    )
    .map_err(utils::core_err)
}

/// [`local_db::local_db_state`] for an opened volume.
pub(crate) fn local_db_state(result: &manager::OpenVolumeResult) -> Result<LocalDb> {
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    local_db::local_db_state(
        &result.paths.base_dir,
        &result.paths.db_path,
        &schema,
        &expected_db(result)?,
    )
    .map_err(utils::core_err)
}

/// The refusal of a command (`teagarden {command}`) that needs the local DB
/// while it must be rebuilt.
pub(crate) fn needs_rebuild_error(volume: &str, command: &str, why: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "the local metadata database of volume '{volume}' must be rebuilt from Telegram \
         before `teagarden {command}` can use it: {why}. Nothing was changed. Mount the volume \
         with Telegram configured (`teagarden volume mount {volume} <mountpoint>`): the mount \
         rebuilds the database from the volume's snapshot and journal on Telegram. Unmount it, \
         then run the command again."
    )
}

/// The refusal of a command (`teagarden {command}`) that needs the local DB
/// of a volume without a published snapshot while that DB is unusable.
pub(crate) fn unusable_db_error(volume: &str, command: &str, why: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "the local metadata database of volume '{volume}' cannot be used by `teagarden \
         {command}`: {why}. The volume has published no metadata snapshot yet, so it holds no \
         files. Mount the volume with Telegram configured (`teagarden volume mount {volume} \
         <mountpoint>`): the mount sets that database aside and creates the volume's. Nothing \
         was changed."
    )
}

/// The explicit recovery for a volume whose snapshot or journal cannot be
/// fetched, named by every such error.
fn republish_hint(volume: &str) -> String {
    format!(
        "If the local metadata database is intact (it holds the volume's files as of its last \
         session), `teagarden volume republish {volume} --from-local-db` publishes it as the \
         volume's metadata and resets the journal onto it (it says what that overwrites and \
         asks first)"
    )
}

/// The refusal of a mount (online or offline) whose journal HEAD cannot be
/// read. A read-only share has no journal of its own (its HEAD is always at
/// seq 0): `volume restore --discard-journal` installs the owner's snapshot
/// again, and republish (which refuses on a share) is not named.
fn unreadable_head_error(
    result: &manager::OpenVolumeResult,
    head_path: &std::path::Path,
    e: teagarden_core::error::CoreError,
) -> anyhow::Error {
    let volume = &result.config.display_name;
    let why = format!(
        "the journal HEAD of volume '{volume}' ({}) cannot be read ({}), so no mount can tell \
         which snapshot and journal entries hold the volume's metadata. Nothing was changed.",
        head_path.display(),
        utils::core_err(e)
    );
    if read_only_share(&result.paths.base_dir).unwrap_or(true) {
        anyhow::anyhow!(
            "{why} This is a read-only share: `teagarden volume restore {volume} \
             --discard-journal` (with a Telegram connection) installs the owner's snapshot \
             again and writes a new journal.head; a share has no journal entries of its own, \
             so nothing is lost. If that snapshot is gone, {}.",
            share_reimport_hint(volume)
        )
    } else {
        anyhow::anyhow!(
            "{why} `teagarden volume restore {volume} --discard-journal` puts back the snapshot \
             volume.json names (journal entries past it are lost). {}.",
            republish_hint(volume)
        )
    }
}

/// The way out for a share whose owner's snapshot is gone (or that must
/// follow the owner's newer metadata): a new grant, re-imported. `share
/// import` refuses a volume that exists, so the local copy goes first.
pub(crate) fn share_reimport_hint(volume: &str) -> String {
    format!(
        "ask the owner for a new grant and re-import it: `teagarden volume delete {volume} \
         --local-only` removes your local copy (nothing on Telegram is touched), then \
         `teagarden share import <grant> --expected-fingerprint <b3:...>` imports the new \
         grant. A share never follows the owner's newer snapshots on its own: it shows the \
         snapshot its grant named until it is re-imported"
    )
}

/// A failed fetch of `what` (message `msg_id`) during a rebuild.
fn recovery_fetch_error(
    result: &manager::OpenVolumeResult,
    what: &str,
    msg_id: i64,
    e: teagarden_telegram::error::TelegramError,
) -> anyhow::Error {
    let volume = &result.config.display_name;
    let gone = matches!(
        e,
        teagarden_telegram::error::TelegramError::MessageNotFound(_)
    );
    let e = utils::telegram_err(e);
    // Only a message that is gone for good makes the local database the only
    // copy left: republish is named for that alone. After any other failure
    // the volume's metadata on Telegram is intact (and may be newer than the
    // local database), so the advice is to mount again.
    let share = read_only_share(&result.paths.base_dir).unwrap_or(true);
    let next = if gone && share {
        format!(
            "That message is gone from the owner's Telegram topic, so this read-only share \
             cannot rebuild its database from it; {}.",
            share_reimport_hint(volume)
        )
    } else if gone {
        format!(
            "That message is gone from the volume's Telegram group, so no mount can rebuild the \
             database from it. {}.",
            republish_hint(volume)
        )
    } else {
        "Check the connection to Telegram and mount again.".to_string()
    };
    anyhow::anyhow!(
        "could not fetch {what} (message_id={msg_id}) needed to rebuild the local metadata \
         database of volume '{volume}': {e:#}. Nothing was changed. {next}"
    )
}

/// Open the volume's metadata DB for a mount or `revert`, after journal
/// recovery. Only the first mount of a volume that has no published snapshot
/// creates the file (the last step of creating a volume, or, for a volume
/// whose first mount failed to publish its base snapshot, again); for any
/// other volume a missing DB is an error here, never an empty new one.
///
/// It creates the DB atomically ([`local_db::create_db_atomically`]): with the
/// root directory already in it (owned by the mounting user, as FUSE `init`
/// would create it) and a lineage stamp at version 0, so the base snapshot the
/// first mount publishes has the root, and a first mount that stops at any
/// point leaves either no DB or a whole one.
fn open_volume_db(result: &manager::OpenVolumeResult) -> Result<Connection> {
    let db_path = &result.paths.db_path;
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let absent = local_db::db_file_absent(db_path)
        .with_context(|| format!("check the metadata database {}", db_path.display()))?;
    if absent {
        if has_published_snapshot(result)
            || rebuild_marker::load(&result.paths.base_dir)
                .map_err(utils::core_err)?
                .is_some()
        {
            anyhow::bail!(
                "the local metadata database {} is missing although the volume has published \
                 metadata to Telegram; refusing to create an empty one",
                db_path.display()
            );
        }
        let mut root = Inode::root();
        root.uid = unsafe { libc::getuid() };
        root.gid = unsafe { libc::getgid() };
        let stamp = local_db::DbStamp {
            volume_id: result.config.volume_id.to_string(),
            lineage: Lineage::new(0),
        };
        local_db::create_db_atomically(db_path, &schema, &result.hierarchy.meta, &root, &stamp)
            .map_err(utils::core_err)
            .context("create the volume's metadata database")?;
    }
    let conn = local_db::open_existing(db_path)
        .with_context(|| format!("open the metadata database {}", db_path.display()))?;
    initialize_database(&conn, &schema)?;
    Ok(conn)
}

/// Open an independent disposable index for one writable portable mount.
/// `VACUUM INTO` takes a consistent snapshot of the base index, including WAL
/// state, while every live mount writes only to its own SQLite file.
fn open_sdo_mount_db(result: &mut manager::OpenVolumeResult) -> Result<Connection> {
    let instance_dir = result
        .paths
        .base_dir
        .join("mount-instances")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&instance_dir).context("create private SDO mount index directory")?;
    let db_path = instance_dir.join("metadata.db");
    if result.paths.db_path.exists() {
        let source = Connection::open(&result.paths.db_path)
            .context("open source metadata DB for private SDO mount index")?;
        source
            .execute("VACUUM INTO ?1", [db_path.to_string_lossy().as_ref()])
            .context("copy source metadata into private SDO mount index")?;
    }
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let conn = Connection::open(&db_path).context("open private SDO mount index")?;
    initialize_database(&conn, &schema)?;
    let inodes = InodeStore::new(&conn, &schema, &result.hierarchy.meta);
    if inodes.get(1)?.is_none() {
        let mut root = Inode::root();
        root.uid = unsafe { libc::getuid() };
        root.gid = unsafe { libc::getgid() };
        inodes.insert(&root)?;
    }
    for mut inode in inodes.list_all()? {
        inode.uid = unsafe { libc::getuid() };
        inode.gid = unsafe { libc::getgid() };
        inodes.update(&inode)?;
    }
    // A fresh disposable copy catches up from Telegram even if the base index
    // predates the most recent mount. Existing rows deduplicate by version UUID.
    teagarden_store::sdo_cursor_store::SdoCursorStore::new(&conn, &schema).set(0, 0)?;
    result.paths.db_path = db_path;
    result.paths.cache_dir = instance_dir.join("cache");
    std::fs::create_dir_all(&result.paths.cache_dir)
        .context("create private SDO mount cache directory")?;
    Ok(conn)
}

async fn maybe_auto_restore_db(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
) -> Result<()> {
    use teagarden_core::volume::metadata_snapshot;

    if !matches!(local_db_state(result)?, LocalDb::NeedsRebuild(_)) {
        return Ok(());
    }

    let Some(msg_id) = result.config.metadata_snapshot_id else {
        // No snapshot named: nothing to restore from.
        return Ok(());
    };

    println!(
        "Local metadata DB must be rebuilt — auto-restoring from channel snapshot \
         (message_id={msg_id})..."
    );
    // Fail the mount rather than silently mount an empty filesystem over orphaned
    // blocks if the snapshot cannot be fetched.
    let blob = transport
        .fetch_metadata(msg_id)
        .await
        .map_err(|e| recovery_fetch_error(result, "the metadata snapshot", msg_id, e))?;

    let data_key = result.hierarchy.data.clone();
    let db_path = result.paths.db_path.clone();
    let floor = result.config.metadata_version;
    let recorded_hash = result.config.recorded_snapshot_hash();
    let blob_hash = hex::encode(blake3::hash(&blob).as_bytes());
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let volume = result.config.display_name.clone();
    let restored = metadata_snapshot::restore_with_floor_then(
        &data_key,
        &blob,
        &db_path,
        floor,
        recorded_hash,
        |v| {
            result.config.metadata_version = v;
            result.config.metadata_snapshot_hash = Some(blob_hash);
            manager::save_config_resealed(
                &mut result.config,
                &result.hierarchy,
                &result.paths.config_path,
            )
        },
        |_| keep_replaced_db(&db_path, &schema, &volume, None),
    )
    .map_err(utils::core_err)?;

    println!("Auto-restored metadata DB from snapshot version {restored}.");
    Ok(())
}

/// What a session (a mount, or `revert`) starts from: the opened metadata DB
/// and the journal HEAD phase 1 loaded.
pub(crate) struct PreparedSession {
    pub(crate) conn: Connection,
    /// The HEAD to journal onto; `None` when the volume has none yet (a new
    /// volume, a reserved-only one, or one rebuilt from the snapshot
    /// volume.json names): phase 2 publishes a base snapshot and writes it.
    pub(crate) head: Option<JournalHead>,
    /// Whether phase 1 rebuilt the DB from the volume's snapshot (and journal).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) rebuilt: bool,
    /// Which file `conn` is, and the nonce the session wrote into it: the
    /// only database the session's publishes may read.
    pub(crate) db: SessionDb,
}

/// Everything a mount (with a Telegram transport) and `revert` do before the
/// session can change the DB, in one place so the tests drive exactly it:
/// journal recovery (phase 1, which rebuilds the DB from the channel when it
/// is not the volume's current database), and opening the DB (created only by
/// the first mount of a volume without a published snapshot; see
/// `open_volume_db`).
///
/// It then checkpoints the WAL into the main DB file, before the connection is
/// handed to the filesystem: the DB is in WAL mode (migrations.rs), and
/// `journal_init_phase` reads the file directly (std::fs::read) to build the
/// base snapshot — without this checkpoint a fresh volume's tables live only in
/// the -wal sidecar, so the base snapshot would be empty and recovery would
/// yield an empty DB. Nothing writes the DB between here and that read. (The
/// unmount snapshot is safe without an explicit checkpoint because `mount2`
/// consumes the filesystem, dropping the connection and checkpointing on close
/// before that snapshot is read.)
pub(crate) async fn prepare_session(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
) -> Result<PreparedSession> {
    let recovered = journal_recover(result, transport).await?;
    let conn = open_volume_db(result)?;
    let db = begin_db_session(result, &conn, recovered.head.as_ref())?;
    Ok(PreparedSession {
        conn,
        head: recovered.head,
        rebuilt: recovered.rebuilt,
        db,
    })
}

/// Whether the volume in `base_dir` is a share accepted with `share import`.
/// Every share is read-only in 1.0 (there is no multi-writer design), whatever
/// access level its grant or its `shared_origin.json` names: so this keys on
/// the share existing, never on its access level. Such a volume's Telegram
/// topic is its OWNER's: it never publishes a snapshot, writes no journal
/// entry, never reverts, rotates, republishes or deletes anything there, and
/// its mount is read-only (see `journal_recover`). A `shared_origin.json`
/// that cannot be parsed still makes the volume a share.
pub(crate) fn read_only_share(base_dir: &std::path::Path) -> Result<bool> {
    Ok(teagarden_core::volume::shared::SharedOrigin::exists(
        base_dir,
    ))
}

/// The refusal of `teagarden {command}` on a read-only share.
fn refuse_read_only_share(result: &manager::OpenVolumeResult, command: &str) -> Result<()> {
    if read_only_share(&result.paths.base_dir)? {
        anyhow::bail!(
            "volume '{}' is a read-only share of someone else's volume; `teagarden {command}` \
             would write into the owner's Telegram topic, so it refuses. Nothing was changed.",
            result.config.display_name
        );
    }
    Ok(())
}

/// Mount phase 2, with the DB open and the transport wired: the HEAD the
/// session journals onto (`loaded`, or, for a volume without one, the HEAD of
/// the base snapshot published now). `None` for a read-only share: its mount
/// is read-only, journals nothing and publishes nothing.
pub(crate) async fn activate_journal(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
    loaded: Option<JournalHead>,
    db: &mut SessionDb,
) -> Result<Option<JournalHead>> {
    if read_only_share(&result.paths.base_dir)? {
        return Ok(None);
    }
    Ok(Some(match loaded {
        Some(h) => h,
        None => journal_init_phase(result, transport, db).await?,
    }))
}

/// The end of a session with a transport (after the FUSE unmount): publish
/// the session's DB (`db`) and reset the HEAD onto it. A read-only share
/// publishes nothing.
pub(crate) async fn end_session(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
    db: &SessionDb,
) -> Result<()> {
    if read_only_share(&result.paths.base_dir)? {
        println!("Read-only share: nothing is published to the owner's volume.");
        return Ok(());
    }
    publish_snapshot_and_compact(result, transport, PublishOf::Session(db.clone())).await
}

/// Whether a mount WITHOUT a Telegram connection may serve the volume: never
/// creating or rebuilding anything, and only where nothing it would write
/// could be lost. A volume with a journal HEAD may not (writes would not be
/// journaled), except a read-only share (`read_only`) whose HEAD has no
/// entries past its base and whose DB is the one the HEAD names: it writes
/// nothing, so it serves its DB and cached blocks.
pub(crate) fn offline_mount_check(
    result: &manager::OpenVolumeResult,
    volume: &str,
    read_only: bool,
) -> Result<()> {
    let head_path = journal_head_path(result);
    let head = JournalHead::load(&head_path, &result.hierarchy.integrity)
        .map_err(|e| unreadable_head_error(result, &head_path, e))?;
    let shared_ok = read_only && head.is_some_and(|h| h.seq == 0);
    if head.is_some() && !shared_ok {
        anyhow::bail!(
            "volume '{volume}' is journaled and needs a Telegram connection to mount \
             safely — run `teagarden auth login` and configure credentials. Mounting it \
             offline would lose writes and cannot read uncached blocks."
        );
    }
    // Offline, nothing can be rebuilt and no DB is ever created: an empty one
    // would serve an empty filesystem in place of the volume's files. (An
    // offline mount is read-only: a writable one was refused before.)
    match local_db_state(result)? {
        LocalDb::Usable => Ok(()),
        LocalDb::Unusable(why) => anyhow::bail!(
            "the local metadata database of volume '{volume}' cannot be used: {why}. A \
             mount with a Telegram connection sets it aside and creates the volume's \
             database (the volume has published nothing yet); a mount without one cannot. \
             Nothing was changed."
        ),
        LocalDb::NeedsRebuild(why) => anyhow::bail!(
            "the local metadata database of volume '{volume}' must be rebuilt from \
             Telegram before it can be mounted: {why}. A mount without a Telegram \
             connection cannot do that. Configure Telegram (`teagarden configure`, \
             `teagarden auth login`) and mount again; nothing was changed."
        ),
        LocalDb::Fresh => anyhow::bail!(
            "volume '{volume}' has no local metadata database yet, and a mount without a \
             Telegram connection cannot create one. Configure Telegram (`teagarden \
             configure`, `teagarden auth login`) and mount again; nothing was changed."
        ),
    }
}

/// Path of the HMAC'd journal HEAD file (sibling of the metadata DB).
pub(crate) fn journal_head_path(result: &manager::OpenVolumeResult) -> PathBuf {
    result.paths.base_dir.join(manager::JOURNAL_HEAD_FILE)
}

/// What journal recovery (mount phase 1) did.
pub(crate) struct Recovered {
    /// The loaded HEAD (`Some` for an already-journaled volume; `None` for a
    /// fresh / pre-journal one).
    pub(crate) head: Option<JournalHead>,
    /// Whether the local DB was rebuilt in this process from the volume's
    /// snapshot (and journal) on Telegram.
    pub(crate) rebuilt: bool,
}

/// [`journal_recover`], for the tests that only need the HEAD.
#[cfg(test)]
pub(crate) async fn journal_recover_phase(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
) -> Result<Option<JournalHead>> {
    Ok(journal_recover(result, transport).await?.head)
}

/// Journal recovery (mount phase 1): rebuild the local DB from the channel when it
/// is not the volume's current database (see `local_db_state`) or the volume
/// crashed mid-session, and stamp the rebuilt DB with the lineage the HEAD
/// records.
pub(crate) async fn journal_recover(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
) -> Result<Recovered> {
    let head_path = journal_head_path(result);
    let integrity = result.hierarchy.integrity.clone();
    let head = JournalHead::load(&head_path, &integrity)
        .map_err(|e| unreadable_head_error(result, &head_path, e))?;

    // A read-only share without a HEAD (its first mount, as `share import`
    // left it): adopt the owner's snapshot locally, the way `volume restore`
    // installs one, publishing nothing into the owner's topic.
    if head.is_none() && read_only_share(&result.paths.base_dir)? {
        let head = adopt_shared_snapshot(result, transport).await?;
        return Ok(Recovered {
            head: Some(head),
            rebuilt: true,
        });
    }

    // A volume without a published snapshot (never published, or its first
    // mount reserved a version and failed to publish its base snapshot) has
    // nothing on Telegram to rebuild from, and holds no user data (that first
    // mount stopped before serving the filesystem). A rebuild marker on it is
    // not one this build wrote (`volume restore` needs a published snapshot):
    // remove it. A DB that cannot be used is set aside, and `open_volume_db`
    // creates the volume's. The mount holds the volume's exclusive lock.
    if !has_published_snapshot(result) {
        if let Some(reason) =
            rebuild_marker::load(&result.paths.base_dir).map_err(utils::core_err)?
        {
            eprintln!(
                "Removing {} ({reason}): the volume has published no metadata snapshot, so \
                 there is nothing to rebuild its database from.",
                rebuild_marker::path(&result.paths.base_dir).display()
            );
            rebuild_marker::clear(&result.paths.base_dir).map_err(utils::core_err)?;
        }
        if let LocalDb::Unusable(why) = local_db_state(result)? {
            let aside = local_db::set_aside(&result.paths.db_path).map_err(utils::core_err)?;
            eprintln!(
                "The local metadata database cannot be used ({why}). The volume has published \
                 no metadata snapshot, so it holds no files and there is nothing to rebuild \
                 from: the database was renamed to {} and this mount creates a new one.",
                aside.display()
            );
        }
    }

    // The local DB is rebuilt from Telegram, never used or created empty, when it
    // is not the volume's current database: a `volume restore` that did not
    // finish (its marker), missing, unreadable, without a root, or not carrying
    // the lineage stamp the HEAD records.
    let rebuild_why = match local_db_state(result)? {
        LocalDb::NeedsRebuild(why) => Some(why),
        LocalDb::Usable | LocalDb::Fresh | LocalDb::Unusable(_) => None,
    };
    let rebuild = rebuild_why.is_some();

    let Some(head) = head else {
        // No journal HEAD. If the DB must be rebuilt, restore the snapshot
        // volume.json names (the pre-journal disaster-recovery path); phase 2
        // then publishes a base snapshot, which stamps the DB and writes the
        // HEAD with its lineage.
        if let Some(why) = rebuild_why {
            let volume = &result.config.display_name;
            if result.config.metadata_snapshot_id.is_none() {
                anyhow::bail!(
                    "the local metadata database of volume '{volume}' must be rebuilt, but the \
                     volume names no metadata snapshot to rebuild it from (volume.json records \
                     snapshot version {} but no snapshot message, and there is no journal \
                     HEAD). Nothing was changed. {}.",
                    result.config.metadata_version,
                    republish_hint(volume)
                );
            }
            // Without a HEAD nothing says whether a database that can be read
            // and has a root, or the snapshot volume.json names, is newer: a
            // session after that snapshot may have committed files to it (its
            // journal entries are named only by the lost HEAD), and a
            // pre-journal build wrote only the local database between
            // snapshots. Only the user can choose; replacing it could lose
            // files. A `volume restore` that did not finish (its marker) has
            // already chosen the snapshot.
            let marked = rebuild_marker::load(&result.paths.base_dir)
                .map_err(utils::core_err)?
                .is_some();
            if !marked {
                // Auto-restore only over a DB that is absent, damaged (SQLite
                // reports NOTADB or CORRUPT, or quick_check fails) or rootless.
                // One that cannot be opened right now is an error here (it
                // names the cause), never "worthless".
                let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
                if let local_db::DbProbe::Readable(c) =
                    local_db::probe_db(&result.paths.db_path, &schema).map_err(utils::core_err)?
                {
                    let tree = c.tree;
                    if tree.has_root {
                        anyhow::bail!(
                            "the journal HEAD of volume '{volume}' ({}) is missing, but its local \
                             metadata database can be read and holds {} entr{} below the root \
                             directory. Nothing shows whether that database or the snapshot \
                             volume.json names (version {}, message_id={}) holds the volume's \
                             newest metadata: a session after that snapshot may have committed \
                             files to the database, so replacing it could lose them. Nothing \
                             was changed. Choose one: `teagarden volume restore {volume}` puts \
                             that snapshot back (the snapshot wins; the local database is kept \
                             as {}<time>), or `teagarden volume republish {volume} \
                             --from-local-db` publishes the local database as the volume's \
                             metadata (the local database wins).",
                            head_path.display(),
                            tree.entries,
                            if tree.entries == 1 { "y" } else { "ies" },
                            result.config.metadata_version,
                            result.config.metadata_snapshot_id.unwrap_or_default(),
                            result
                                .paths
                                .base_dir
                                .join(local_db::REPLACED_PREFIX)
                                .display()
                        );
                    }
                }
            }
            println!("Rebuilding the local metadata database from Telegram: {why}.");
            maybe_auto_restore_db(result, transport).await?;
            finish_rebuild(result);
        }
        return Ok(Recovered {
            head: None,
            rebuilt: rebuild,
        });
    };

    // A clean unmount resets seq to 0, so seq > 0 means an unclean shutdown with
    // uncompacted deltas. Rebuild then, too.
    let mut head = head;
    let rebuilt = rebuild || head.seq > 0;
    if let Some(why) = &rebuild_why {
        println!("Rebuilding the local metadata database from Telegram: {why}.");
    }
    if rebuilt {
        println!(
            "Recovering metadata from journal (HEAD seq {})...",
            head.seq
        );
        let newest = recover_via_transport(result, transport, head).await?;
        if head.seq > 0 {
            println!(
                "Replayed {} journaled operation(s) from the channel.",
                head.seq
            );
        }
        // The rebuilt DB is the volume's current database: stamp it with the
        // lineage the HEAD records, or, for a HEAD written before HEADs recorded
        // one, with a new lineage at its base version, written into the DB
        // FIRST and then into the HEAD (a crash in between leaves a DB the next
        // mount rebuilds once more). A HEAD written before HEADs recorded the
        // newest delta's hash also gets the hash of the delta the DB was just
        // rebuilt from, so the deltas appended from now on bind to exactly it.
        let lineage = head
            .lineage
            .unwrap_or_else(|| Lineage::new(head.base_snapshot_version));
        let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
        let stamp = local_db::DbStamp {
            volume_id: result.config.volume_id.to_string(),
            lineage,
        };
        local_db::restamp_db_file(&result.paths.db_path, &schema, Some(&stamp), Some(head.seq))
            .map_err(utils::core_err)
            .context("stamp the rebuilt metadata database")?;
        if head.last_hash.is_none() || head.lineage.is_none() {
            head.last_hash = Some(head.last_hash.unwrap_or(newest));
            head.lineage = Some(lineage);
            head.store_atomic(&head_path, &integrity)
                .map_err(utils::core_err)?;
        }
        if rebuild {
            finish_rebuild(result);
        }
    }
    Ok(Recovered {
        head: Some(head),
        rebuilt,
    })
}

/// A read-only share's mount when it has no journal HEAD (its first, as
/// `share import` left it): install the owner's snapshot that volume.json
/// names as the local DB, the way `volume restore` does. Fetch it, check it
/// against the anti-rollback floor and the recorded hash, keep the DB it
/// replaces (`local_db::keep_replaced`: a share has no HEAD here, so nothing
/// is provably reproducible), install it, stamp it with a new local lineage
/// at journal position 0, and only then write a HEAD at seq 0 on that snapshot
/// recording the lineage. A crash before the HEAD leaves a share without one,
/// and its next mount adopts again. Nothing is uploaded: the topic is the
/// owner's. Returns the HEAD.
async fn adopt_shared_snapshot(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
) -> Result<JournalHead> {
    use teagarden_core::volume::metadata_snapshot;

    let volume = result.config.display_name.clone();
    let Some(msg_id) = result.config.metadata_snapshot_id else {
        anyhow::bail!(
            "volume '{volume}' is a read-only share whose configuration names no metadata \
             snapshot, so there is nothing to mount. Ask the owner for a new grant. Nothing \
             was changed."
        );
    };
    println!(
        "Read-only share: installing the owner's metadata snapshot (message_id={msg_id}); \
         nothing is published to the owner's volume."
    );
    let blob = transport.fetch_metadata(msg_id).await.map_err(|e| {
        anyhow::anyhow!(
            "could not fetch the owner's metadata snapshot (message_id={msg_id}) of the \
             read-only share '{volume}': {:#}. Nothing was changed. Check the connection to \
             Telegram and mount again; if the snapshot is gone, {}.",
            utils::telegram_err(e),
            share_reimport_hint(&volume)
        )
    })?;
    let data_key = result.hierarchy.data.clone();
    let db_path = result.paths.db_path.clone();
    let floor = result.config.metadata_version;
    let recorded_hash = result.config.recorded_snapshot_hash();
    let blob_hash = *blake3::hash(&blob).as_bytes();
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let version = metadata_snapshot::restore_with_floor_then(
        &data_key,
        &blob,
        &db_path,
        floor,
        recorded_hash,
        |v| {
            result.config.metadata_version = v;
            result.config.metadata_snapshot_hash = Some(hex::encode(blob_hash));
            manager::save_config_resealed(
                &mut result.config,
                &result.hierarchy,
                &result.paths.config_path,
            )
        },
        |_| keep_replaced_db(&db_path, &schema, &volume, None),
    )
    .map_err(utils::core_err)?;
    let lineage = Lineage::new(version);
    let stamp = local_db::DbStamp {
        volume_id: result.config.volume_id.to_string(),
        lineage,
    };
    local_db::restamp_db_file(&db_path, &schema, Some(&stamp), Some(0))
        .map_err(utils::core_err)
        .context("stamp the owner's snapshot installed as the share's database")?;
    let head = JournalHead::at_snapshot(msg_id, version, blob_hash, lineage);
    head.store_atomic(&journal_head_path(result), &result.hierarchy.integrity)
        .map_err(utils::core_err)?;
    println!("Installed the owner's metadata snapshot version {version}.");
    Ok(head)
}

/// After a rebuild from Telegram is installed: remove the rebuild-required
/// marker. A marker left behind only costs one more rebuild.
fn finish_rebuild(result: &manager::OpenVolumeResult) {
    if let Err(e) = rebuild_marker::clear(&result.paths.base_dir) {
        eprintln!(
            "WARNING: could not remove {}: {e}. The next mount rebuilds the metadata database \
             from Telegram once more.",
            rebuild_marker::path(&result.paths.base_dir).display()
        );
    }
}

/// Fetch the base snapshot + back-linked delta chain for `head` from the channel,
/// then rebuild the local DB at `db_path` (fail-closed against truncation and
/// substitution). Returns the hash of the blob at `head.parent_msg_id` that the
/// rebuild used (the newest delta, or the base snapshot at seq 0). A fetch that
/// fails names `volume republish --from-local-db` only when the message is gone
/// for good (MessageNotFound) and the volume is not a share (a share names the
/// re-import procedure instead); any other failure says to check the
/// connection and mount again ([`recovery_fetch_error`]).
async fn recover_via_transport(
    result: &manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
    head: JournalHead,
) -> Result<[u8; 32]> {
    use std::collections::HashMap;
    use teagarden_core::error::CoreError;

    let data_key = result.hierarchy.data.clone();
    let mut channel: HashMap<i64, Vec<u8>> = HashMap::new();

    // Base snapshot (id carried in the HEAD itself — never cross-referenced from
    // the config, so the compaction crash window cannot brick recovery).
    let snap = transport
        .fetch_metadata(head.base_snapshot_msg_id)
        .await
        .map_err(|e| {
            recovery_fetch_error(
                result,
                "the base snapshot the journal HEAD names",
                head.base_snapshot_msg_id,
                e,
            )
        })?;
    channel.insert(head.base_snapshot_msg_id, snap);

    // Walk the back-linked delta chain, bounded by head.seq.
    let mut cursor = head.parent_msg_id;
    let mut remaining = head.seq;
    while remaining > 0 && cursor != 0 {
        let blob = transport
            .fetch_metadata(cursor)
            .await
            .map_err(|e| recovery_fetch_error(result, "a metadata journal entry", cursor, e))?;
        let (hdr, _) = teagarden_core::volume::metadata_journal::decrypt_delta(&data_key, &blob)
            .map_err(utils::core_err)?;
        channel.insert(cursor, blob);
        cursor = hdr.parent_msg_id;
        remaining -= 1;
    }

    let db_path = result.paths.db_path.clone();
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let volume = result.config.display_name.clone();
    // A DB carrying the HEAD's lineage at its journal position is what this
    // rebuild reproduces: it is not kept.
    let reproduces = reproduced_by(result, &head);
    teagarden_store::journal_recovery::recover_from_head_then(
        &data_key,
        head,
        &db_path,
        |id| {
            channel.get(&id).cloned().ok_or_else(|| {
                CoreError::Snapshot(format!("journal message {id} missing from channel"))
            })
        },
        || keep_replaced_db(&db_path, &schema, &volume, reproduces.as_ref()),
    )
    .map_err(|e| match e {
        // Authentic, correctly chained entries that do not apply to their base
        // snapshot were written against another database. The lineage stamp
        // keeps a mount from serving a database that is not the volume's, so
        // this needs a database that was made to look like the volume's current
        // one. Only dropping them helps. A fetch, MAC or hash failure is never
        // this, and never gets this advice.
        CoreError::JournalApply { seq, detail } => {
            let volume = &result.config.display_name;
            anyhow::anyhow!(
                "the metadata journal of volume '{volume}' cannot be replayed: its entry seq \
                 {seq} (of {}) does not apply to its base snapshot (version {}, message_id={}): \
                 {detail}. Its entries were written against another database than that \
                 snapshot, so no mount can rebuild the volume from them. Run \
                 `teagarden volume restore {volume} --discard-journal` to put that snapshot \
                 back; it drops those {} journal entr{}, then mount again. Nothing was changed.",
                head.seq,
                head.base_snapshot_version,
                head.base_snapshot_msg_id,
                head.seq,
                if head.seq == 1 { "y" } else { "ies" }
            )
        }
        e => utils::core_err(e),
    })?;
    let newest_id = if head.seq == 0 {
        head.base_snapshot_msg_id
    } else {
        head.parent_msg_id
    };
    let newest = channel
        .get(&newest_id)
        .map(|b| teagarden_core::volume::metadata_journal::blob_hash(b))
        .ok_or_else(|| anyhow::anyhow!("journal message {newest_id} missing from channel"))?;
    Ok(newest)
}

/// Journal initialization (mount phase 2): publish a base snapshot of the current
/// DB and write a fresh HEAD so the delta chain has a recoverable base. Run once
/// per volume (when no HEAD exists yet — a fresh or upgrading-from-v0.4.2 volume).
///
/// This is a snapshot publish like any other, so it goes through
/// [`publish_snapshot_and_compact`]: the same order (reserve, publish, save
/// volume.json, write the HEAD), every failure recorded as stale cloud
/// metadata, and that record cleared only once all of it succeeded.
pub(crate) async fn journal_init_phase(
    result: &mut manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
    db: &mut SessionDb,
) -> Result<JournalHead> {
    publish_snapshot_and_compact(result, transport, PublishOf::Session(db.clone())).await?;
    // From now on the session has a HEAD, and its publishes require one.
    db.had_head = true;
    JournalHead::load(&journal_head_path(result), &result.hierarchy.integrity)
        .map_err(utils::core_err)?
        .ok_or_else(|| anyhow::anyhow!("journal HEAD missing right after it was written"))
}

pub async fn unmount(target: &str) -> Result<()> {
    println!("Unmounting '{target}'...");

    // Correlate the mountpoint back to its volume BEFORE detaching: once the mount is
    // gone from the OS mount table we can no longer find which volume's writer to
    // wait for (the lock-scan fallback inside still works, but this is the cheap path).
    let writer_base_dir = writer_base_dir_for_mountpoint(target);

    // Detach the FUSE mount. This makes the writer process's `mount2` return; it then
    // drains any in-flight block uploads, publishes the anti-rollback snapshot,
    // releases the single-writer lock, and exits.
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("umount").arg(target).status() {
            Ok(status) if status.success() => {}
            Ok(status) => anyhow::bail!("failed to detach '{target}': umount exited with {status}"),
            Err(error) => anyhow::bail!("failed to execute umount for '{target}': {error}"),
        }
    }
    #[cfg(target_os = "linux")]
    detach_linux_mount(target)?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    anyhow::bail!("unmount is unsupported on this platform");

    // Block until the writer has fully drained queued uploads and released the
    // single-writer lock. Only then is it safe to remount or power off without losing
    // not-yet-uploaded blocks. (A naive unmount returns the instant the mount detaches
    // while the writer keeps uploading in the background.)
    match writer_base_dir {
        Some(base_dir) => {
            println!("Detached; waiting for the writer to finish flushing…");
            if let Some(flushed_visibly) = wait_for_writer_drain(&base_dir).await {
                // The writer has exited; if its snapshot publish failed it left a
                // record. Report it as an error: the cloud metadata is stale. The
                // success line is printed only after that check, so a stale
                // snapshot never follows an "Unmounted." that reads as success.
                if let Err(stale) = snapshot_publish_status(&base_dir) {
                    anyhow::bail!(
                        "The filesystem was unmounted, but the volume's last metadata snapshot \
                         was not published. {stale}"
                    );
                }
                if flushed_visibly {
                    println!("Flush complete — safe to remount or power off.");
                } else {
                    println!("Unmounted.");
                }
            }
        }
        None => {
            // Couldn't map the mountpoint to a volume (e.g. nothing was actually
            // mounted there, or — on a platform without mount enumeration — multiple
            // volumes are mounted). The writer still drains in the background; we just
            // can't block on it. Be honest rather than imply a barrier we don't have.
            println!(
                "Detached. NOTE: could not correlate this mountpoint to a single live \
                 volume, so this command did not wait for the flush to finish. Wait \
                 until `teagarden volume list` shows it unmounted before remounting or \
                 powering off."
            );
        }
    }

    Ok(())
}

/// Detach a Linux FUSE mount using the FUSE 3 command name first, while retaining
/// compatibility with distributions that expose only the legacy name. A missing
/// helper or non-zero status is an error: callers must never report a successful
/// unmount while the filesystem remains attached.
#[cfg(target_os = "linux")]
fn detach_linux_mount(target: &str) -> Result<()> {
    let mut failures = Vec::new();
    for program in ["fusermount3", "fusermount"] {
        match std::process::Command::new(program)
            .args(["-u", target])
            .output()
        {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                failures.push(format!(
                    "{program} exited with {}{}",
                    output.status,
                    if stderr.trim().is_empty() {
                        String::new()
                    } else {
                        format!(": {}", stderr.trim())
                    }
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                failures.push(format!("{program} is not installed"));
            }
            Err(error) => failures.push(format!("could not execute {program}: {error}")),
        }
    }
    anyhow::bail!("failed to detach '{target}': {}", failures.join("; "))
}

/// Map a FUSE `mountpoint` back to its volume's base directory (where the
/// single-writer `volume.lock` lives). Primary path: read the OS mount table
/// (Linux `/proc/mounts`) while the mount is still attached. Fallback (macOS, or an
/// already-detached mount): if exactly one volume's writer lock is currently held,
/// that is the writer to wait for. Returns `None` if it can't be determined.
fn writer_base_dir_for_mountpoint(target: &str) -> Option<PathBuf> {
    let volumes_dir = manager::default_volumes_dir();

    // Primary: correlate via the OS mount table.
    let target_canon = std::fs::canonicalize(target).ok();
    for (vid, mp) in active_fuse_mounts() {
        let same = match (&target_canon, std::fs::canonicalize(&mp).ok()) {
            (Some(a), Some(b)) => *a == b,
            _ => mp == target,
        };
        if same {
            return Some(volumes_dir.join(vid));
        }
    }

    // Fallback: probe every volume's lock. If exactly one is held, it's the live
    // writer (platform-agnostic — works on macOS, and after a detach race). Ambiguous
    // when several mounts are live, so only act on a unique held lock.
    let mut held: Vec<PathBuf> = Vec::new();
    if let Ok(volumes) = manager::list_volumes(&volumes_dir) {
        for v in volumes {
            let base = volumes_dir.join(v.volume_id.to_string());
            if matches!(manager::VolumeLock::is_held(&base), Ok(true)) {
                held.push(base);
            }
        }
    }
    if held.len() == 1 {
        return held.into_iter().next();
    }
    None
}

/// Block until the volume's writer process releases the single-writer lock — i.e.
/// until it has drained every queued block upload and published the unmount
/// snapshot. The lock is held for the writer's whole lifetime (acquired at mount,
/// released on exit), so a free lock means the writer is gone and the volume is safe
/// to remount or power off.
///
/// `Some(flushed_visibly)` once the lock is free (`true` if the wait was long
/// enough that the user was told about the flush); `None` if the wait could not
/// confirm the writer finished. It prints progress and problems only: the caller
/// prints the final result, after it has checked for a stale snapshot.
async fn wait_for_writer_drain(base_dir: &std::path::Path) -> Option<bool> {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let mut announced = false;
    let mut last_progress = Duration::ZERO;
    loop {
        match manager::VolumeLock::is_held(base_dir) {
            // Lock free → writer exited cleanly and released it.
            Ok(false) => return Some(announced),
            Ok(true) => { /* writer still draining — keep waiting */ }
            Err(e) => {
                // Couldn't probe the lock (e.g. permissions) — don't busy-wait 2h on a
                // fault. Report honestly and stop.
                println!(
                    "Note: could not confirm the writer finished flushing ({e}). Wait \
                     until `teagarden volume list` shows it unmounted before remounting \
                     or powering off."
                );
                return None;
            }
        }
        let el = start.elapsed();
        if !announced && el >= Duration::from_secs(1) {
            println!(
                "Flushing queued uploads to Telegram before it is safe to remount or power off…"
            );
            announced = true;
            last_progress = el;
        } else if announced && el.saturating_sub(last_progress) >= Duration::from_secs(15) {
            println!("  …still flushing ({}s elapsed)", el.as_secs());
            last_progress = el;
        }
        if el >= Duration::from_secs(7200) {
            println!(
                "WARNING: the writer is still active after 2h. Do NOT power off — run \
                 `teagarden volume list` until it shows the volume unmounted."
            );
            return None;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Read active TeaGarden mountpoints from the OS, keyed by volume ID.
///
/// Parses `/proc/mounts`. The device column is `teagarden:<uuid>` (written via
/// `FSName` at mount time) and the fstype is `fuse.teagarden` (the `Subtype` mount
/// option) — though we accept plain `fuse` too for older mounts — so we match the
/// device prefix — our unique marker — to correlate each mountpoint back to the
/// volume that owns it.
/// Read a recovery sentence from `--recovery-file` (`-` means stdin), trimmed.
///
/// Shared by every command that can unlock a key-protected volume, so they all
/// accept the same input forms rather than each re-implementing the match.
fn read_recovery_sentence(recovery_file: Option<&str>) -> Result<Option<utils::SecretString>> {
    match recovery_file {
        Some("-") => {
            let mut s = String::new();
            std::io::stdin()
                .read_line(&mut s)
                .context("read recovery sentence from stdin")?;
            Ok(Some(utils::trimmed_secret(s)))
        }
        Some(path) => std::fs::read_to_string(path)
            .map(utils::trimmed_secret)
            .map(Some)
            .with_context(|| format!("read recovery file: {path}")),
        None => Ok(None),
    }
}

pub(crate) fn active_fuse_mounts() -> std::collections::HashMap<String, String> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        parse_active_fuse_mounts(&content)
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("mount")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| parse_active_macos_mounts(&String::from_utf8_lossy(&output.stdout)))
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        std::collections::HashMap::new()
    }
}

/// Parse macOS `mount` output. A TeaGarden FSName is the authority; the fstype
/// label differs between macFUSE releases (`macfuse`, `osxfuse`, or a FUSE
/// subtype), so it is intentionally not used as the identity boundary.
#[cfg(any(test, target_os = "macos"))]
fn parse_active_macos_mounts(content: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in content.lines() {
        let Some((mounted, _options)) = line.rsplit_once(" (") else {
            continue;
        };
        let Some((device, mountpoint)) = mounted.split_once(" on ") else {
            continue;
        };
        if let Some(volume_id) = device.strip_prefix("teagarden:") {
            map.insert(volume_id.to_string(), mountpoint.to_string());
        }
    }
    map
}

#[cfg(any(test, target_os = "linux"))]
fn parse_active_fuse_mounts(content: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in content.lines() {
        let mut parts = line.splitn(4, ' ');
        let device = parts.next().unwrap_or("");
        let mountpoint = parts.next().unwrap_or("").replace("\\040", " ");
        let fstype = parts.next().unwrap_or("");
        // Plain `fuse` (our mounts set FSName, not a subtype) or a `fuse.<subtype>`
        // — but NOT arbitrary other types — and the device must be ours.
        let is_fuse = fstype == "fuse" || fstype.starts_with("fuse.");
        if is_fuse {
            if let Some(vid) = device.strip_prefix("teagarden:") {
                map.insert(vid.to_string(), mountpoint);
            }
        }
    }
    map
}

pub async fn list() -> Result<()> {
    let volumes_dir = manager::default_volumes_dir();
    let volumes = manager::list_volumes(&volumes_dir).map_err(utils::core_err)?;

    if volumes.is_empty() {
        println!("No volumes found.");
        println!("Use `teagarden volume create` to create a new volume.");
        return Ok(());
    }

    let mounts = active_fuse_mounts();

    println!("{:<38}  {:<24}  STATUS", "VOLUME ID", "NAME");
    println!("{}", "-".repeat(76));
    for v in &volumes {
        // A volume is "mounted" if any active FUSE mount path exists under the
        // volumes dir or, more generally, if any TeaGarden mount is live and we
        // can cross-reference via /proc/mounts device name (which is the FSName).
        // We can't easily correlate mountpoint→volume without a state file, so
        // we report "mounted" if there is at least one live TeaGarden mount and
        // offer the mountpoints separately.
        let vid = v.volume_id.to_string();
        let status = match mounts.get(&vid) {
            Some(mp) => format!("mounted at {mp}"),
            None => "unmounted".into(),
        };
        println!("{:<38}  {:<24}  {}", v.volume_id, v.display_name, status);
    }
    println!();
    println!("{} volume(s) total.", volumes.len());

    if !mounts.is_empty() {
        println!();
        println!("Active teagarden mounts:");
        for mp in mounts.values() {
            println!("  {mp}");
        }
    }

    Ok(())
}

/// Permanently delete a volume: its Telegram topic first, then the local state.
///
/// This command previously deleted ONLY the local directory while advertising
/// "and all its Telegram blocks", leaving every encrypted block in the cloud
/// forever. It also accepted `--force` with no credential at all, which deleted
/// `slot_vault.json` — the sole wrapping of a key-protected volume's master key —
/// while the ciphertext survived remotely, and it guarded against live mounts with
/// an in-process map that is always empty in a fresh CLI invocation. A later
/// version deleted only the blocks the local DB lists, leaving the metadata
/// snapshots, journal entries and the topic itself on Telegram.
///
/// All of these are fixed here:
///   1. the volume's whole forum topic is deleted (every message in it: blocks,
///      metadata snapshots, journal); a topic-less volume has its blocks deleted
///      by message id;
///   2. a credential is REQUIRED (key-protected volumes open via a factor);
///   3. the live-mount guard is the real `/proc/mounts` scan used by restore/revert,
///      backed by the exclusive single-writer `VolumeLock` (a mount, `revert`,
///      `restore` or `key rotate` in progress makes delete refuse before anything
///      is deleted).
///
/// `--local-only` is the explicit escape hatch for "the cloud data is already gone
/// / unreachable and I accept orphaning it"; it is never the silent default.
pub async fn delete(
    volume: &str,
    force: bool,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    local_only: bool,
) -> Result<()> {
    delete_in(
        &manager::default_volumes_dir(),
        volume,
        force,
        password_file,
        recovery_file,
        local_only,
        Box::new(|channel_ref| Box::pin(connect_volume_remote(channel_ref))),
    )
    .await
}

/// What `volume delete` needs from Telegram: topic deletion (user session) and,
/// for a volume without a topic, per-message deletion.
pub(crate) trait VolumeRemote: ForumAdmin + BlockTransport {}
impl<T: ForumAdmin + BlockTransport + ?Sized> VolumeRemote for T {}

/// Opens the Telegram side of a volume on demand (the real session, or the test
/// transport). Called at most once, and only when something remote must go.
pub(crate) type ConnectRemote<'a> = Box<
    dyn FnOnce(
            ChannelRef,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Arc<dyn VolumeRemote>>> + 'a>,
        > + 'a,
>;

/// The user's Telegram session bound to a volume's storage location.
async fn connect_volume_remote(channel_ref: ChannelRef) -> Result<Arc<dyn VolumeRemote>> {
    let (api_id, api_hash) = utils::load_telegram_credentials()?;
    let client = TelegramClient::new(TelegramConfig {
        api_id,
        api_hash,
        session_path: session_file_path().to_string_lossy().to_string(),
        channel_ref: Some(channel_ref),
        ..Default::default()
    });
    let state = client.connect().await.map_err(utils::telegram_err)?;
    if state != teagarden_telegram::types::AuthState::Authenticated {
        anyhow::bail!("not authenticated with Telegram — run `teagarden auth login`");
    }
    Ok(Arc::new(client))
}

/// [`delete`] against an explicit volumes directory and Telegram connector.
pub(crate) async fn delete_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    force: bool,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    local_only: bool,
    connect: ConnectRemote<'_>,
) -> Result<()> {
    let volumes_dir = volumes_dir.to_path_buf();
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;

    // No one to ask means no deletion: refuse (non-zero), rather than read the
    // missing answer as "no" and exit 0. Checked first, before the lock, the
    // slow key derivation and any Telegram contact.
    if !force && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "refusing to delete volume '{volume}' without confirmation: stdin is not a \
             terminal, so there is no one to ask. Pass --force to delete without asking; \
             nothing was deleted."
        );
    }

    // (3) Real live-mount guard. `VolumeService`'s `self.mounted` map is per-process
    // and always empty here, so it never protected anything from the CLI.
    if let Some(mp) = active_fuse_mounts().get(&volume_id) {
        anyhow::bail!(
            "volume '{volume}' is currently mounted at {mp}; unmount it before deleting \
             (deleting under a live mount corrupts the mount and can lose queued uploads)"
        );
    }

    // Single-writer backstop: the SAME exclusive lock a mount, `revert`, `restore`
    // and `key rotate` take, held until the volume is gone. `/proc/mounts` cannot
    // see an offline writer, and deleting a volume under one loses its writes.
    // Taken before any credential prompt, Telegram call or local deletion.
    let _volume_lock = manager::VolumeLock::acquire_exclusive(&volumes_dir.join(&volume_id))
        .map_err(|e| {
            anyhow::anyhow!(
                "refusing to delete volume '{volume}': {e}. Stop the other command and retry; \
                 nothing was deleted."
            )
        })?;

    let _admin = manager::OwnerAdminLock::acquire(&volumes_dir.join(&volume_id))?;

    // A shared copy (accepted with `share import`) is bound to the OWNER's forum
    // topic. Deleting that topic would destroy the owner's data for every holder,
    // so a shared copy can only be removed locally. (The marker is a local
    // sidecar; forging it can only make this command refuse, never delete more.)
    if !local_only
        && teagarden_core::volume::shared::SharedOrigin::exists(&volumes_dir.join(&volume_id))
    {
        anyhow::bail!(
            "volume '{volume}' is a shared copy of someone else's volume (imported with \
             `share import`); its Telegram topic belongs to the owner, and deleting it would \
             destroy their data. Remove only your local copy with --local-only."
        );
    }

    // (2) Require a credential. Opening also gives us the config + key hierarchy we
    // need to reach the block store, so proving ownership and doing the work share
    // one step. A bare password against a key-protected volume fails closed in core.
    let password = match password_file {
        Some(p) => Some(read_volume_password(Some(p))?),
        None if recovery_file.is_none() => Some(read_volume_password(None)?),
        None => None,
    };
    let recovery_sentence = read_recovery_sentence(recovery_file)?;
    let inputs = teagarden_mfa::unlock::UnlockInputs {
        password: password.as_deref().map(String::as_bytes),
        recovery_sentence: recovery_sentence.as_ref().map(|secret| secret.as_str()),
        ..Default::default()
    };
    let result = teagarden_mfa::unlock::open_volume(&volume_id, &inputs, &volumes_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    harden_process();
    println!("Volume '{volume}' authenticated.");

    // ── Enumerate every block this volume owns, across ALL epochs ──────────────
    // The DB is opened read-only and never created: a DB created here would list
    // no blocks, and for a volume without a topic that would orphan all of them.
    let has_topic = result.config.telegram_group_id != 0 && result.config.telegram_topic_id > 1;
    let mut message_ids: Vec<i64> = Vec::new();
    match local_db_state(&result)? {
        LocalDb::Usable => {
            let conn = local_db::open_read_only(&result.paths.db_path)
                .map_err(|e| anyhow::anyhow!("Failed to open database: {e}"))?;
            let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
            let block_store = teagarden_store::block_store::BlockStore::new(&conn, &schema);
            for epoch in 0..=result.config.current_epoch {
                for b in block_store
                    .list_by_epoch(epoch)
                    .map_err(|e| anyhow::anyhow!("Failed to list blocks at epoch {epoch}: {e}"))?
                {
                    message_ids.push(b.message_id);
                }
            }
        }
        // No published snapshot: the volume holds no files, so no blocks.
        LocalDb::Fresh => {}
        LocalDb::Unusable(why) => println!(
            "Note: the local metadata database {}: {why}. The volume has published no \
             metadata snapshot, so it holds no files.",
            result.paths.db_path.display()
        ),
        LocalDb::NeedsRebuild(why) => {
            if !local_only && !has_topic {
                return Err(needs_rebuild_error(volume, "volume delete", &why)).context(
                    "this volume has no forum topic, so its blocks are deleted one by one from \
                     the list in the local database",
                );
            }
            println!(
                "Note: the local metadata database {}: {why}. Its block count is not known; \
                 deleting the volume's topic removes every block regardless.",
                result.paths.db_path.display()
            );
        }
    }
    message_ids.sort_unstable();
    message_ids.dedup();

    // A 1.0 volume stores file versions, volume headers and device records as
    // objects in its forum topic; it has no block list to count.
    let is_tgfv_volume = result.config.sdo_author_device_id.is_some()
        && result.config.telegram_group_id != 0
        && result.config.telegram_topic_id != 0;
    if !is_tgfv_volume {
        println!(
            "Found {} encrypted block(s) on Telegram across epochs 0..={}.",
            message_ids.len(),
            result.config.current_epoch
        );
    }

    // What exists on Telegram: one forum topic per volume holding every block,
    // metadata snapshot and journal entry the volume ever posted. Deleting the
    // topic removes all of them at once, including those the local DB does not
    // list (snapshots, journal deltas, superseded blocks).
    let cfg = &result.config;
    if !local_only && !has_topic && !message_ids.is_empty() && cfg.telegram_group_id == 0 {
        anyhow::bail!(
            "volume '{volume}' lists {} block(s) but records no Telegram location, so they \
             cannot be found to delete; pass --local-only to remove only the local state",
            message_ids.len()
        );
    }
    let remote_work = !local_only && (has_topic || !message_ids.is_empty());

    // ── Confirmation, now that we can state the REAL scope ─────────────────────
    if !force {
        if local_only {
            print!(
                "WARNING: --local-only will destroy local volume '{volume}' and ABANDON \
                 everything it stored on Telegram ({} encrypted block(s) plus its metadata \
                 snapshots and journal); they stay there, undeletable without this volume's \
                 local state. Continue? [y/N] ",
                message_ids.len()
            );
        } else if has_topic {
            print!(
                "WARNING: This will permanently delete the volume's Telegram topic, with \
                 every message in it ({} encrypted block(s) plus its metadata snapshots and \
                 journal), AND destroy local volume '{volume}'. This cannot be undone. \
                 Continue? [y/N] ",
                message_ids.len()
            );
        } else {
            print!(
                "WARNING: This will permanently delete {} Telegram block(s) AND destroy \
                 local volume '{volume}'. This cannot be undone. Continue? [y/N] ",
                message_ids.len()
            );
        }
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            anyhow::bail!("Cancelled. Nothing was deleted.");
        }
    }

    // ── (1) Delete the remote state BEFORE destroying the local metadata ───────
    // Order matters: the local state is the only record of where this volume
    // lives on Telegram. Deleting it first would make the remote data
    // unreachable and therefore permanently undeletable.
    if remote_work {
        let channel_ref = ChannelRef {
            id: cfg.telegram_group_id,
            access_hash: cfg.telegram_channel_access_hash,
            topic_id: cfg.telegram_topic_id,
        };
        let client = connect(channel_ref).await.map_err(|e| {
            anyhow::anyhow!(
                "{e}\n\
                 Deleting a volume removes its data from Telegram, which needs a Telegram \
                 login.\n\
                 Run `teagarden auth login`, or pass --local-only to destroy ONLY local \
                 state and knowingly leave the volume's data on Telegram."
            )
        })?;

        if has_topic {
            if let Err(e) = client
                .delete_topic(
                    cfg.telegram_group_id,
                    cfg.telegram_channel_access_hash,
                    cfg.telegram_topic_id,
                )
                .await
            {
                anyhow::bail!(
                    "the volume's Telegram topic could not be deleted ({e}). The local volume \
                     has been left INTACT so the deletion can be retried — rerun this command \
                     once the problem is fixed. (Use --local-only only if you accept leaving \
                     the volume's data on Telegram.)"
                );
            }
            if is_tgfv_volume {
                println!(
                    "Deleted the volume's Telegram topic and everything in it (every file \
                     version, volume header and device record)."
                );
            } else {
                println!(
                    "Deleted the volume's Telegram topic and everything in it ({} block(s), \
                     metadata snapshots and journal).",
                    message_ids.len()
                );
            }
        } else {
            // A volume without a topic (pre-forum layout): delete its blocks by id.
            const BATCH: usize = 100;
            let mut deleted = 0usize;
            let mut failed: Vec<i64> = Vec::new();
            for chunk in message_ids.chunks(BATCH) {
                match client.delete_messages(chunk).await {
                    Ok(()) => {
                        deleted += chunk.len();
                        println!("  deleted {deleted}/{} block(s)...", message_ids.len());
                    }
                    Err(e) => {
                        eprintln!("  WARNING: batch deletion failed: {e}");
                        failed.extend_from_slice(chunk);
                    }
                }
            }
            if !failed.is_empty() {
                // Do NOT delete the local metadata: it is the only remaining map from
                // this volume to those message IDs.
                anyhow::bail!(
                    "{} of {} block(s) could not be deleted from Telegram. The local volume \
                     has been left INTACT so the deletion can be retried — rerun this command \
                     once connectivity is restored. (Use --local-only only if you accept \
                     abandoning those blocks.)",
                    failed.len(),
                    message_ids.len()
                );
            }
            println!("All {deleted} Telegram block(s) deleted.");
        }
    } else if local_only && (has_topic || !message_ids.is_empty()) {
        if is_tgfv_volume {
            println!(
                "--local-only: leaving the volume's Telegram topic and every file version \
                 in it on Telegram, abandoned."
            );
        } else {
            println!(
                "--local-only: leaving the volume's data on Telegram ({} block(s) plus any \
                 metadata snapshots and journal), abandoned.",
                message_ids.len()
            );
        }
    }

    // ── Now destroy the local state ───────────────────────────────────────────
    // Directly, under the lock this command holds (`VolumeService::delete` takes
    // the volume lock itself, which this process already holds).
    manager::delete_volume(&volume_id, &volumes_dir).map_err(utils::core_err)?;

    println!("Volume '{volume}' deleted.");
    Ok(())
}

pub async fn info(volume: &str) -> Result<()> {
    let volumes_dir = manager::default_volumes_dir();
    let volumes = manager::list_volumes(&volumes_dir).map_err(utils::core_err)?;

    let needle = volume.to_lowercase();
    let config = volumes.into_iter().find(|v| {
        v.volume_id.to_string() == volume
            || v.volume_id.to_string().starts_with(volume)
            || v.display_name.to_lowercase() == needle
    });

    match config {
        Some(c) => {
            println!("Volume Information");
            println!("==================");
            println!("  Volume ID:    {}", c.volume_id);
            println!("  Name:         {}", c.display_name);
            println!(
                "  Installation ID: {}",
                c.sdo_author_device_id
                    .map_or_else(|| "legacy/unregistered".into(), |id| id.to_string())
            );
            if let Some(owner) = &c.sdo_owner_public_key {
                println!("  Owner public key: {owner}");
            }
            println!("  Block size:   {}", c.block_config.target_block_size);
            println!("  Compression:  {:?}", c.block_config.compression);
            println!("  KDF memory:   {} KiB", c.kdf_params.memory_kib);
            println!("  KDF iter:     {}", c.kdf_params.iterations);
        }
        None => {
            println!("Volume '{volume}' not found.");
            println!("Use `teagarden volume list` to see available volumes.");
        }
    }

    Ok(())
}

/// Load a volume's config and require that it has a Telegram storage group.
fn volume_with_group(volume: &str) -> Result<VolumeConfig> {
    let volumes_dir = manager::default_volumes_dir();
    let volume_id = resolve_volume_id(volume, &volumes_dir)?;
    let json = std::fs::read_to_string(volumes_dir.join(&volume_id).join("volume.json"))
        .context("read volume.json")?;
    let config: VolumeConfig = serde_json::from_str(&json).context("parse volume.json")?;
    if config.telegram_group_id == 0 {
        anyhow::bail!(
            "volume '{volume}' has no Telegram storage group (it was created offline), \
             so it has no group to add a bot to"
        );
    }
    Ok(config)
}

/// Read a bot token from `--token-file` (`-` = stdin), trimmed. The token is
/// never accepted on the command line, where the process list and shell
/// history would show it.
fn read_bot_token(token_file: &str) -> Result<utils::SecretString> {
    use std::io::Read as _;
    let raw = if token_file == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("read the bot token from stdin")?;
        s
    } else {
        std::fs::read_to_string(token_file)
            .with_context(|| format!("read the bot token file {token_file}"))?
    };
    Ok(utils::trimmed_secret(raw))
}

/// `volume add-bot`: register a bot the user created by hand (in @BotFather)
/// as an extra upload session for the volume's storage group.
///
/// Order: validate the token's shape, check the volume and the Telegram login,
/// validate the token with `getMe`, make the bot an administrator of the group
/// through the user's own session, and only then record the token in the
/// config `.env` (atomically, mode 0600, see `bot_env`). The token is never
/// printed.
pub async fn add_bot(volume: &str, token_file: &str) -> Result<()> {
    use teagarden_telegram::types::AuthState;

    let token = read_bot_token(token_file)?;
    super::bot_env::validate_token(&token)?;
    let config = volume_with_group(volume)?;
    let env_path = utils::config_dir()?.join(".env");
    let (api_id, api_hash) = utils::load_telegram_credentials()?;

    let me = teagarden_telegram::bot_api::get_me(&token)
        .await
        .map_err(utils::telegram_err)?;
    if me.id.to_string() != super::bot_env::bot_id(&token) {
        anyhow::bail!(
            "getMe reported bot id {}, which does not match the token's id; refusing it",
            me.id
        );
    }
    println!("Token belongs to bot @{} (id {}).", me.username, me.id);

    let client = TelegramClient::new(TelegramConfig {
        api_id,
        api_hash,
        session_path: session_file_path().to_string_lossy().to_string(),
        channel_ref: None,
        ..Default::default()
    });
    let state = client.connect().await.map_err(utils::telegram_err)?;
    if state != AuthState::Authenticated {
        anyhow::bail!("not authenticated with Telegram; run `teagarden auth login` first");
    }
    client
        .add_bot_to_group(
            config.telegram_group_id,
            config.telegram_channel_access_hash,
            &me.username,
        )
        .await
        .map_err(utils::telegram_err)?;
    println!(
        "@{} is now an administrator of the storage group (post rights only).",
        me.username
    );

    use super::bot_env::Added;
    match super::bot_env::add_token(&env_path, &token)? {
        Added::New { index } => println!(
            "Recorded it as {}{index} in {}.",
            super::bot_env::PREFIX,
            env_path.display()
        ),
        Added::AlreadyPresent { index } => println!(
            "It was already recorded as {}{index} in {}; nothing changed there.",
            super::bot_env::PREFIX,
            env_path.display()
        ),
        Added::Replaced { index } => println!(
            "Updated its token in {}{index} in {}.",
            super::bot_env::PREFIX,
            env_path.display()
        ),
    }
    println!(
        "The bot serves every volume in the storage group. Remount a volume to start using it."
    );
    Ok(())
}

/// `volume remove-bot`: the bot leaves the storage group (Bot API `leaveChat`,
/// with its own token), then its `.env` entry is removed and the remaining
/// entries renumbered so the mount path still finds all of them.
pub async fn remove_bot(volume: &str, bot_id: &str) -> Result<()> {
    if bot_id.is_empty() || !bot_id.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!("--bot-id must be the bot's numeric id (the part of its token before ':')");
    }
    let config = volume_with_group(volume)?;
    let env_path = utils::config_dir()?.join(".env");
    let Some(token) = super::bot_env::find_token(&env_path, bot_id)? else {
        let ids: Vec<String> = super::bot_env::list_bots(&env_path)?
            .into_iter()
            .map(|(_, id)| id)
            .collect();
        anyhow::bail!(
            "no bot with id {bot_id} is recorded in {} (recorded bot ids: {})",
            env_path.display(),
            if ids.is_empty() {
                "none".to_string()
            } else {
                ids.join(", ")
            }
        );
    };

    match teagarden_telegram::bot_api::leave_chat(&token, config.telegram_group_id).await {
        Ok(()) => println!("Bot {bot_id} left the storage group."),
        Err(e) => eprintln!(
            "warning: bot {bot_id} could not leave the storage group itself ({e}). If its token \
             was already revoked this is expected; remove the bot from the group in the \
             Telegram app."
        ),
    }
    drop(token);

    let index = super::bot_env::remove_bot(&env_path, bot_id)?.ok_or_else(|| {
        anyhow::anyhow!(
            "bot {bot_id} was removed from {} concurrently",
            env_path.display()
        )
    })?;
    println!(
        "Removed {}{index} from {}; later entries were renumbered.",
        super::bot_env::PREFIX,
        env_path.display()
    );
    println!("To make the token itself useless, revoke it in @BotFather (/revoke).");
    Ok(())
}

// ── Process hardening ──────────────────────────────────────────────────────

/// Lock key pages in RAM and disable crash dumps.
///
/// Called immediately after the key hierarchy is derived, so that key
/// material cannot reach swap files or be extracted from core dumps.
/// Failures are logged as warnings rather than aborting — the mount
/// succeeds even if the OS denies mlockall (e.g. no CAP_IPC_LOCK).
fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0i64, 0i64, 0i64, 0i64) != 0 {
                tracing::warn!("PR_SET_DUMPABLE=0 failed; core dumps may expose key material");
            }
        }
    }
    #[cfg(unix)]
    {
        unsafe {
            if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!(
                    error = %err,
                    "mlockall failed; key pages may be swappable \
                     (raise RLIMIT_MEMLOCK or run as root to fix)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "key-rotation")]
    fn rotation_key_package_is_decryptable_only_by_the_intended_device() {
        use teagarden_core::crypto::keys::SymmetricKey;
        use teagarden_sharing::key_exchange::UserKeyPair;

        let device_b = UserKeyPair::generate().unwrap();
        let revoked_c = UserKeyPair::generate().unwrap();
        let installation_b = uuid::Uuid::new_v4();
        let root = SymmetricKey::from_bytes([0x9a; 32]);
        let salt = [0x4c; 32];
        let update = create_device_key_update(
            uuid::Uuid::from_u128(1),
            installation_b,
            7,
            &salt,
            root.as_bytes(),
            &device_b.encapsulation_key,
        )
        .unwrap();
        assert_eq!(
            unwrap_device_key_update(
                uuid::Uuid::from_u128(1),
                &update,
                &device_b.decapsulation_key
            )
            .unwrap(),
            *root.as_bytes()
        );
        assert!(unwrap_device_key_update(
            uuid::Uuid::from_u128(1),
            &update,
            &revoked_c.decapsulation_key
        )
        .is_err());
    }

    struct A2TruncationFixture {
        f: Round2Fixture,
        opened: Arc<manager::OpenVolumeResult>,
        header: HeaderDocument,
        templates: Vec<(&'static str, Vec<u8>)>,
        private: teagarden_core::crypto::mlkem::MlKemDecapsulationKey,
    }

    impl A2TruncationFixture {
        async fn new() -> Self {
            use teagarden_core::sdo::{SdoFileObject, SdoFileObjectV3, SdoObjectMetadata};
            let f = Round2Fixture::new().await;
            let opened = Arc::new(f.open(b"original-password"));
            let (_, header, header_wire) = discover_latest_header(
                f.mock.as_ref(),
                opened.config.telegram_group_id,
                opened.config.telegram_topic_id,
                &opened.hierarchy.integrity,
                opened.config.sdo_owner_public_key.as_deref(),
            )
            .await
            .unwrap()
            .unwrap();
            let (private, _public) =
                load_or_create_device_keypair(&opened.paths.base_dir, &opened.hierarchy.wrapping)
                    .unwrap();
            #[cfg(feature = "key-rotation")]
            let handoff = {
                let update = create_device_key_update(
                    header.volume_id,
                    opened.config.sdo_author_device_id.unwrap(),
                    1,
                    &[0x66; 32],
                    &[0x67; 32],
                    &_public,
                )
                .unwrap();
                encode_device_handoff(
                    header.volume_id,
                    &update,
                    &load_owner_capability(&opened.paths.config_path).unwrap(),
                )
                .unwrap()
            };
            #[cfg(not(feature = "key-rotation"))]
            let handoff = {
                let mut wire = b"TGKU".to_vec();
                wire.extend_from_slice(&128u32.to_le_bytes());
                wire.resize(200, 0);
                wire
            };
            let v2 = SdoFileObject::encode(
                header.volume_id,
                &opened.hierarchy.meta,
                SdoObjectMetadata::test_fixture(),
                b"",
            )
            .unwrap();
            let v3 = SdoFileObjectV3::encode(
                header.volume_id,
                0,
                &opened.hierarchy.meta,
                legacy_v2_logical_metadata(&SdoObjectMetadata::test_fixture()),
                b"",
            )
            .unwrap();
            let mut templates = vec![
                ("TGKU", handoff),
                ("TGHD", header_wire),
                ("TGFV2", v2),
                ("TGFV3", v3),
            ];
            for (label, index, range) in [
                ("TGKU-overlong", 0, 4..8),
                ("TGHD-overlong", 1, 6..10),
                ("TGFV2-overlong", 2, 22..26),
                ("TGFV3-overlong", 3, 30..34),
            ] {
                let mut wire = templates[index].1.clone();
                wire[range].copy_from_slice(&u32::MAX.to_le_bytes());
                templates.push((label, wire));
            }
            Self {
                f,
                opened,
                header,
                templates,
                private,
            }
        }
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn a2_n3_transient_handoff_read_retains_the_package_cursor() {
        let f = A2TruncationFixture::new().await;
        assert_eq!(f.f.mock.message_count(), 1);
        f.f.mock.put_document(
            500,
            f.header.group_id,
            f.header.topic_id,
            "handoff.tgku",
            f.templates[0].1.clone(),
        );
        f.f.mock.clear_channel_binding();
        f.f.mock.reset_counters();
        // The header prefix and handoff prefix succeed. Its full body fails
        // once; subsequent current-header discovery succeeds normally.
        f.f.mock.fail_one_read_after(2);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let notify = Arc::new(tokio::sync::Notify::new());
        let cursor = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let handle = start_sdo_topic_poller(
            f.f.mock.clone(),
            f.header.group_id,
            f.header.topic_id,
            f.header.volume_id,
            f.opened.config.sdo_author_device_id.unwrap(),
            Some(teagarden_core::crypto::mlkem::MlKemDecapsulationKey(
                f.private.0.clone(),
            )),
            0,
            None,
            f.opened.hierarchy.integrity.clone(),
            generation_meta_keys(&f.header, &f.opened.hierarchy).unwrap(),
            cursor.clone(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            notify.clone(),
            Arc::new(Mutex::new(None)),
            sender,
            f.header.owner_public_key.clone(),
            Some((f.templates[1].1.clone(), f.opened.hierarchy.clone())),
            None,
        );
        notify.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while f.f.mock.read_count() < 3 && !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;
        if let Ok(batch) = receiver.try_recv() {
            assert!(
                batch.high_water_id < 500,
                "transient download failure must not consume the unread handoff"
            );
            batch.ack.send(Ok(())).unwrap();
        }
        assert!(cursor.load(std::sync::atomic::Ordering::Relaxed) < 500);
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn a2_n3_truncated_documents_do_not_panic_scanners() {
        let f = A2TruncationFixture::new().await;
        let output = tempfile::tempdir().unwrap();
        for (kind, template) in &f.templates {
            for length in 0..=64 {
                let bytes = template[..length].to_vec();
                f.f.mock.put_document(
                    500,
                    f.header.group_id,
                    f.header.topic_id,
                    "teagarden-file-v3.tgf",
                    bytes.clone(),
                );
                f.f.mock.clear_channel_binding();
                let mock = f.f.mock.clone();
                let opened = f.opened.clone();
                let header = f.header.clone();
                let export = output.path().join(format!("{kind}-{length}"));
                tokio::spawn(async move {
                    // Each parser and scanner sees the exact truncated document.
                    let _ = super::super::decrypt::parse_header_json(&bytes);
                    let _ = HeaderDocument::decode(&bytes, &opened.hierarchy.integrity);
                    #[cfg(feature = "key-rotation")]
                    let _ = decode_device_handoff(
                        &bytes,
                        header.volume_id,
                        header.owner_public_key.as_deref().unwrap(),
                    );
                    let _ = teagarden_core::sdo::SdoFileObject::decode(
                        &bytes,
                        header.volume_id,
                        &opened.hierarchy.meta,
                    );
                    let _ = teagarden_core::sdo::SdoFileObjectV3::decode(
                        &bytes,
                        header.volume_id,
                        0,
                        &opened.hierarchy.meta,
                    );
                    let _ = teagarden_core::sdo::ObjectEnvelope::parse(&bytes);
                    let _ =
                        scan_header_topic(mock.as_ref(), header.group_id, header.topic_id).await;
                    let _ = scan_topic_sdo_objects(
                        mock.as_ref(),
                        header.group_id,
                        header.topic_id,
                        &header,
                        &opened.hierarchy,
                    )
                    .await;
                    let _ = export_objects_command(mock.as_ref(), opened.as_ref(), &export).await;
                })
                .await
                .unwrap_or_else(|error| {
                    panic!("scanner panic for {kind} length {length}: {error}")
                });
            }
        }
    }

    #[tokio::test]
    async fn a2_n3_truncated_documents_do_not_panic_the_production_poller() {
        let f = A2TruncationFixture::new().await;
        for (kind, template) in &f.templates {
            for length in 0..=64 {
                f.f.mock.put_document(
                    500,
                    f.header.group_id,
                    f.header.topic_id,
                    "teagarden-file-v3.tgf",
                    template[..length].to_vec(),
                );
                f.f.mock.clear_channel_binding();
                f.f.mock.reset_counters();
                let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
                let notify = Arc::new(tokio::sync::Notify::new());
                let handle = start_sdo_topic_poller(
                    f.f.mock.clone(),
                    f.header.group_id,
                    f.header.topic_id,
                    f.header.volume_id,
                    f.opened.config.sdo_author_device_id.unwrap(),
                    Some(teagarden_core::crypto::mlkem::MlKemDecapsulationKey(
                        f.private.0.clone(),
                    )),
                    0,
                    None,
                    f.opened.hierarchy.integrity.clone(),
                    generation_meta_keys(&f.header, &f.opened.hierarchy).unwrap(),
                    Arc::new(std::sync::atomic::AtomicI64::new(0)),
                    Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    notify.clone(),
                    Arc::new(Mutex::new(None)),
                    sender,
                    f.header.owner_public_key.clone(),
                    Some((f.templates[1].1.clone(), f.opened.hierarchy.clone())),
                    None,
                );
                notify.notify_one();
                tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    while f.f.mock.read_count() == 0 && !handle.is_finished() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("the actual poller must inspect the document");
                tokio::task::yield_now().await;
                if *kind == "TGKU" && length == 4 {
                    let batch =
                        tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                            .await
                            .expect(
                                "a malformed unauthenticated handoff must not stall the next batch",
                            )
                            .expect("the poller must remain connected");
                    assert_eq!(batch.high_water_id, 500);
                    batch.ack.send(Ok(())).unwrap();
                    tokio::task::yield_now().await;
                }
                handle.abort();
                let error = handle
                    .await
                    .expect_err("a live poller should be cancelled only by the test");
                assert!(
                    error.is_cancelled(),
                    "poller panic for {kind} length {length}: {error}"
                );
                drop(receiver);
            }
        }
    }

    #[tokio::test]
    async fn local_filesystem_activity_interrupts_idle_sdo_poll_delay() {
        let transport = Arc::new(MockTransport::new());
        let group_id = -100;
        let topic_id = 42;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(now - 61));
        let activity_notify = Arc::new(tokio::sync::Notify::new());
        let _poller = start_sdo_topic_poller(
            transport.clone(),
            group_id,
            topic_id,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            None,
            0,
            None,
            teagarden_core::crypto::keys::SymmetricKey::from_bytes([0x45; 32]),
            std::collections::BTreeMap::from([(
                0,
                teagarden_core::crypto::keys::SymmetricKey::from_bytes([0x46; 32]),
            )]),
            Arc::new(std::sync::atomic::AtomicI64::new(0)),
            last_activity.clone(),
            activity_notify.clone(),
            Arc::new(Mutex::new(None)),
            sender,
            None,
            None,
            None,
        );

        transport.put_text_message(1, group_id, topic_id);
        last_activity.store(now, std::sync::atomic::Ordering::Relaxed);
        activity_notify.notify_one();

        let batch = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
            .await
            .expect("local file activity should interrupt the idle poll delay")
            .expect("poller should send the discovered high-water batch");
        assert_eq!(batch.high_water_id, 1);
        batch.ack.send(Ok(())).unwrap();
    }

    use teagarden_core::block::pointer::{BlockPointer, FileManifest};
    use teagarden_core::metadata::inode::Inode;
    use teagarden_core::volume::metadata_snapshot;
    use teagarden_store::block_store::{BlockRecord, BlockStore};
    use teagarden_store::manifest_store::ManifestStore;
    use teagarden_telegram::mock::MockTransport;

    #[test]
    #[cfg(feature = "key-rotation")]
    fn rotated_header_recovers_bridged_generation_hierarchies() {
        let root_old = teagarden_core::crypto::keys::SymmetricKey::from_bytes([0x31; 32]);
        let salt_old = [0x32; 32];
        let old =
            teagarden_core::crypto::kdf::derive_hierarchy_v1(root_old.clone(), &salt_old, -100, 42)
                .unwrap();
        let root_new = teagarden_core::crypto::keys::SymmetricKey::from_bytes([0x33; 32]);
        let salt_new = [0x34; 32];
        let current =
            teagarden_core::crypto::kdf::derive_hierarchy_v1(root_new, &salt_new, -100, 42)
                .unwrap();
        let bridge = teagarden_core::sdo::KeyGenerationBridge::wrap(
            0,
            &salt_old,
            &old.root,
            &current.wrapping,
        )
        .unwrap();
        let header = HeaderDocument {
            format: 2,
            volume_id: uuid::Uuid::new_v4(),
            revision: 3,
            volume_version: "1.0.0".into(),
            root_kind: RootKind::MasterKey,
            salt: hex::encode(salt_new),
            kdf_params: None,
            group_id: -100,
            topic_id: 42,
            current_epoch: 0,
            block_v2_from_epoch: None,
            require_block_integrity: true,
            block_size: 1024,
            key_protection: None,
            slot_vault: None,
            owner_public_key: None,
            key_generation: Some(1),
            revoked_device_ids: Vec::new(),
            revoked_account_bindings: Vec::new(),
            retained_key_bridges: Vec::new(),
            device_authorities: std::collections::BTreeMap::new(),
            rotation_state: Some(serde_json::json!({"key_bridges": [bridge]})),
            generation_boundary_message_id: Some(100),
            generation_cutoffs: Default::default(),
            revocation_cutoffs: Default::default(),
        };
        let generations = generation_meta_keys(&header, &current).unwrap();
        assert_eq!(generations.len(), 2);
        assert_eq!(generations[&0].as_bytes(), old.meta.as_bytes());
        assert_eq!(generations[&1].as_bytes(), current.meta.as_bytes());
    }

    #[test]
    #[cfg(feature = "key-rotation")]
    fn rotated_header_rejects_old_generation_objects_at_or_after_boundary() {
        assert!(teagarden_core::sdo::generation_is_acceptable(0, 1, 99, 100));
        assert!(!teagarden_core::sdo::generation_is_acceptable(
            0, 1, 100, 100
        ));
    }

    #[test]
    #[cfg(feature = "key-rotation")]
    fn rotation_header_rewraps_all_prior_roots_and_bumps_generation() {
        let old_salt = [0x41; 32];
        let old_root = teagarden_core::crypto::keys::SymmetricKey::from_bytes([0x42; 32]);
        let old =
            teagarden_core::crypto::kdf::derive_hierarchy_v1(old_root.clone(), &old_salt, -100, 42)
                .unwrap();
        let next_salt = [0x43; 32];
        let next_root = teagarden_core::crypto::keys::SymmetricKey::from_bytes([0x44; 32]);
        let next =
            teagarden_core::crypto::kdf::derive_hierarchy_v1(next_root, &next_salt, -100, 42)
                .unwrap();
        let header = HeaderDocument {
            format: 2,
            volume_id: uuid::Uuid::new_v4(),
            revision: 8,
            volume_version: "1.0.0".into(),
            root_kind: RootKind::MasterKey,
            salt: hex::encode(old_salt),
            kdf_params: None,
            group_id: -100,
            topic_id: 42,
            current_epoch: 0,
            block_v2_from_epoch: None,
            require_block_integrity: true,
            block_size: 1024,
            key_protection: Some(serde_json::json!({"vault_generation": 1})),
            slot_vault: Some(serde_json::json!({"version": 2})),
            owner_public_key: Some(hex::encode([0x45; 32])),
            key_generation: Some(0),
            revoked_device_ids: Vec::new(),
            revoked_account_bindings: Vec::new(),
            retained_key_bridges: Vec::new(),
            device_authorities: std::collections::BTreeMap::new(),
            rotation_state: None,
            generation_boundary_message_id: None,
            generation_cutoffs: Default::default(),
            revocation_cutoffs: Default::default(),
        };
        let rotated = make_rotated_header(
            &header,
            &old,
            &next,
            &next_salt,
            serde_json::json!({"vault_generation": 2}),
            serde_json::json!({"version": 2}),
        )
        .unwrap();
        assert_eq!(rotated.revision, 9);
        assert_eq!(rotated.key_generation, Some(1));
        assert_eq!(rotated.salt, hex::encode(next_salt));
        assert_eq!(rotated.generation_boundary_message_id, None);
        let keys = generation_meta_keys(&rotated, &next).unwrap();
        assert_eq!(keys[&0].as_bytes(), old.meta.as_bytes());
        assert_eq!(keys[&1].as_bytes(), next.meta.as_bytes());
    }

    #[test]
    fn device_receiving_key_obeys_existing_local_unlock_policy() {
        let directory = tempfile::tempdir().unwrap();
        let old = teagarden_core::crypto::keys::SymmetricKey::from_bytes([41; 32]);
        let next = teagarden_core::crypto::keys::SymmetricKey::from_bytes([42; 32]);
        let wrong = teagarden_core::crypto::keys::SymmetricKey::from_bytes([43; 32]);
        let (private, public) = load_or_create_device_keypair(directory.path(), &old).unwrap();
        store_device_key_wrap(directory.path(), &next, &private, &public).unwrap();
        for key in [&old, &next] {
            let (loaded, loaded_public) =
                load_or_create_device_keypair(directory.path(), key).unwrap();
            assert!(loaded.0 == private.0);
            assert_eq!(loaded_public.0, public.0);
        }
        assert!(load_or_create_device_keypair(directory.path(), &wrong).is_err());
        let value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("device-keypair.json")).unwrap(),
        )
        .unwrap();
        assert!(value.get("private").is_none(), "durable handoff must not introduce an unwrapped receiving-key bypass of the local unlock policy");
        assert!(value["private_wraps"].is_object());
    }

    #[test]
    fn owner_signing_capability_is_separate_and_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("volume.json");
        std::fs::write(&config_path, b"{}").unwrap();
        let created = ensure_owner_capability(&config_path).unwrap();
        let path = owner_capability_path(&config_path).unwrap();
        assert_ne!(path, config_path);
        let loaded = load_owner_capability(&config_path).unwrap();
        assert_eq!(loaded.to_bytes(), created.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    /// A plain mount must not need `user_allow_other`: neither allow option,
    /// and no `AutoUnmount` (which makes fuser add `allow_other` itself).
    /// The note `volume create` prints for a (default) password-rooted
    /// volume: the password is the only way in, and it names the two real
    /// ways to get a recovery credential, both of which exist as spelled.
    #[test]
    fn the_password_rooted_create_note_names_real_recovery_commands() {
        use clap::CommandFactory as _;
        let note = PASSWORD_ROOTED_CREATE_NOTE;
        assert!(!note.contains("Legacy"), "{note}");
        assert!(note.contains("no separate recovery file"), "{note}");
        assert!(note.contains("the password is the only way in"), "{note}");
        assert!(note.contains("`teagarden key export`"), "{note}");
        assert!(
            note.contains("`teagarden volume create --key-protection`"),
            "{note}"
        );
        let cli = crate::Cli::command();
        let sub = |c: &clap::Command, n: &str| c.find_subcommand(n).cloned().unwrap();
        let key = sub(&cli, "key");
        sub(&key, "export");
        let create = sub(&sub(&cli, "volume"), "create");
        assert!(
            create
                .get_arguments()
                .any(|a| a.get_long() == Some("key-protection")),
            "volume create has no --key-protection"
        );
        assert!(
            !create
                .get_arguments()
                .any(|a| a.get_long() == Some("block-size")),
            "volume create must not advertise legacy multi-block file sizing"
        );
    }

    #[test]
    fn plain_mount_options_never_need_user_allow_other() {
        use fuser::MountOption as M;
        for read_only in [false, true] {
            let o = mount_options("v", read_only, false);
            for forbidden in [M::AllowOther, M::AllowRoot, M::AutoUnmount] {
                assert!(!o.contains(&forbidden), "{forbidden:?} in {o:?}");
            }
            assert_eq!(o.contains(&M::RO), read_only);
        }
        let o = mount_options("v", false, true);
        assert!(o.contains(&M::AllowOther) && o.contains(&M::AutoUnmount));
        assert!(!o.contains(&M::AllowRoot));
    }

    #[test]
    fn gateway_mount_parser_accepts_only_teagarden_fuse_identity() {
        let mounts = parse_active_fuse_mounts(
            "teagarden:vol-1 /home/user/secure fuse.teagarden rw 0 0\n\
             /dev/sda1 /home/user/plain ext4 rw 0 0\n\
             attacker:vol-2 /home/user/fake fuse rw 0 0\n\
             teagarden:vol-3 /home/user/space\\040name fuse rw 0 0\n",
        );

        assert_eq!(
            mounts.get("vol-1").map(String::as_str),
            Some("/home/user/secure")
        );
        assert_eq!(
            mounts.get("vol-3").map(String::as_str),
            Some("/home/user/space name")
        );
        assert!(!mounts.contains_key("vol-2"));
        assert_eq!(mounts.len(), 2);
    }

    #[test]
    fn macos_mount_parser_accepts_only_teagarden_fsname() {
        let mounts = parse_active_macos_mounts(
            "teagarden:vol-1 on /Users/test/vault (macfuse, nodev, nosuid)\n\
             /dev/disk3s1 on /Volumes/plain (apfs, local)\n\
             attacker:vol-2 on /Users/test/fake (macfuse, nodev)\n\
             teagarden:vol-3 on /Users/test/path on disk (osxfuse, nodev)\n",
        );

        assert_eq!(
            mounts.get("vol-1").map(String::as_str),
            Some("/Users/test/vault")
        );
        assert_eq!(
            mounts.get("vol-3").map(String::as_str),
            Some("/Users/test/path on disk")
        );
        assert!(!mounts.contains_key("vol-2"));
        assert_eq!(mounts.len(), 2);
    }

    // ── metadata snapshot publish: a failure must not be silent ───────────────

    /// An offline volume with an initialized metadata DB, opened.
    fn opened_volume_with_db(dir: &std::path::Path) -> manager::OpenVolumeResult {
        let created =
            manager::create_volume(Some("snap"), b"snap-pass-1", dir, 0, 0, 0, None).unwrap();
        let id = created.config.volume_id.to_string();
        let result = manager::open_volume(&id, b"snap-pass-1", dir).unwrap();
        let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
        let conn = Connection::open(&result.paths.db_path).unwrap();
        initialize_database(&conn, &schema).unwrap();
        InodeStore::new(&conn, &schema, &result.hierarchy.meta)
            .insert(&Inode::root())
            .unwrap();
        drop(conn);
        result
    }

    /// Mount phase 1 on a journal a pre-round-6 build left unclean: a v1 HEAD
    /// (no `last_hash`) at seq 1 over a `metadata-delta-v1` delta. Recovery
    /// rebuilds from it and records the hash of the delta it used in the HEAD, so
    /// the deltas this build appends bind to exactly that one; a later recovery
    /// served a different delta for that id is refused.
    #[tokio::test]
    async fn mount_recovery_of_a_v1_journal_pins_the_delta_it_used() {
        let dir = tempfile::tempdir().unwrap();
        let mut result = opened_volume_with_db(dir.path());
        let mock = MockTransport::new();
        publish_as_new_session(&mut result, &mock).await.unwrap();
        let head_path = journal_head_path(&result);
        let base = JournalHead::load(&head_path, &result.hierarchy.integrity)
            .unwrap()
            .unwrap();

        // One committed change, journaled the way debb93b did it (v1 delta).
        let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
        let cs = {
            let conn = Connection::open(&result.paths.db_path).unwrap();
            let mut session = rusqlite::session::Session::new(&conn).unwrap();
            session.attach(None::<&str>).unwrap();
            InodeStore::new(&conn, &schema, &result.hierarchy.meta)
                .insert(&Inode::new_file(7, 1, "late.txt".into(), 0o644, 1000, 1000))
                .unwrap();
            let mut cs = Vec::new();
            session.changeset_strm(&mut cs).unwrap();
            cs
        };
        let data_key = result.hierarchy.data.clone();
        let v1_delta = |cs: &[u8]| {
            let mut pt = vec![];
            pt.extend_from_slice(&1u64.to_le_bytes());
            pt.extend_from_slice(&base.base_snapshot_version.to_le_bytes());
            pt.extend_from_slice(&base.base_snapshot_msg_id.to_le_bytes());
            pt.extend_from_slice(cs);
            teagarden_core::crypto::aead::encrypt(&data_key, &pt, b"metadata-delta-v1").unwrap()
        };
        let delta = v1_delta(&cs);
        let delta_id = mock.sync_metadata(&delta).await.unwrap();
        JournalHead {
            seq: 1,
            parent_msg_id: delta_id,
            last_hash: None,
            lineage: None,
            ..base
        }
        .store_atomic(&head_path, &result.hierarchy.integrity)
        .unwrap();

        let head = journal_recover_phase(&mut result, &mock)
            .await
            .unwrap()
            .unwrap();
        let pinned = Some(*blake3::hash(&delta).as_bytes());
        assert_eq!(head.last_hash, pinned, "returned HEAD names the delta used");
        assert!(
            head.lineage.is_some(),
            "the v1 HEAD's recovery records a lineage"
        );
        let on_disk = JournalHead::load(&head_path, &result.hierarchy.integrity)
            .unwrap()
            .unwrap();
        assert_eq!(on_disk.last_hash, pinned, "and it is persisted");

        // Same header, same changeset, different bytes: refused now.
        mock.put_raw(delta_id, v1_delta(&cs));
        let err = journal_recover_phase(&mut result, &mock).await.unwrap_err();
        assert!(format!("{err:#}").contains("hash"), "{err:#}");
    }

    /// F3: a snapshot publish whose acknowledgement is withheld leaves an orphan
    /// on Telegram. The retry must not reuse its version, and a restore answered
    /// with that orphan in place of the recorded snapshot must be refused rather
    /// than silently installing the older state.
    #[tokio::test]
    async fn orphan_snapshot_from_a_withheld_ack_is_never_restored() {
        let dir = tempfile::tempdir().unwrap();
        let mut result = opened_volume_with_db(dir.path());
        let mock = MockTransport::new();

        // State A, published; Telegram keeps it but the ack never arrives.
        mock.withhold_metadata_acks(1);
        publish_as_new_session(&mut result, &mock)
            .await
            .expect_err("the client sees the publish fail");
        let orphan_id = 1;
        let orphan = mock
            .get_raw(orphan_id)
            .expect("the orphan is on the server");

        // State B (one more file), published and recorded.
        {
            let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
            let conn = Connection::open(&result.paths.db_path).unwrap();
            InodeStore::new(&conn, &schema, &result.hierarchy.meta)
                .insert(&Inode::new_file(9, 1, "b.txt".into(), 0o644, 1000, 1000))
                .unwrap();
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }
        publish_as_new_session(&mut result, &mock).await.unwrap();
        let recorded_id = result.config.metadata_snapshot_id.unwrap();
        let recorded = mock.get_raw(recorded_id).unwrap();
        let data_key = result.hierarchy.data.clone();
        let (orphan_v, _) = metadata_snapshot::decrypt_snapshot(&data_key, &orphan).unwrap();
        let (recorded_v, _) = metadata_snapshot::decrypt_snapshot(&data_key, &recorded).unwrap();
        assert_ne!(
            orphan_v, recorded_v,
            "two different snapshots were published with the same version"
        );

        // The local DB is lost; Telegram answers the recorded id with the orphan.
        std::fs::remove_file(&result.paths.db_path).unwrap();
        mock.put_raw(recorded_id, orphan);
        let err = maybe_auto_restore_db(&mut result, &mock)
            .await
            .expect_err("the older state must not be restored");
        assert!(!result.paths.db_path.exists(), "nothing installed: {err:#}");

        // The genuine recorded snapshot still restores.
        mock.put_raw(recorded_id, recorded);
        maybe_auto_restore_db(&mut result, &mock).await.unwrap();
        let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
        let conn = Connection::open(&result.paths.db_path).unwrap();
        assert!(InodeStore::new(&conn, &schema, &result.hierarchy.meta)
            .get(9)
            .unwrap()
            .is_some());
    }

    /// At the recorded version itself, the HMAC-covered hash decides: another
    /// snapshot carrying that version is refused.
    #[tokio::test]
    async fn same_version_snapshot_that_is_not_the_recorded_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut result = opened_volume_with_db(dir.path());
        let mock = MockTransport::new();
        publish_as_new_session(&mut result, &mock).await.unwrap();
        let id = result.config.metadata_snapshot_id.unwrap();
        let v = result.config.metadata_version;
        let db = std::fs::read(&result.paths.db_path).unwrap();
        let mut other = db.clone();
        let n = other.len();
        other[n - 1] ^= 0xFF; // same version, different contents
        let impostor =
            metadata_snapshot::encrypt_snapshot(&result.hierarchy.data, v, &other).unwrap();
        mock.put_raw(id, impostor);
        std::fs::remove_file(&result.paths.db_path).unwrap();
        let err = maybe_auto_restore_db(&mut result, &mock).await.unwrap_err();
        assert!(format!("{err:#}").contains("hash"), "{err:#}");
        assert!(!result.paths.db_path.exists());
    }

    /// A snapshot publish that fails (here: the transport is down) must leave a
    /// durable record that the volume's cloud metadata is stale, which the
    /// separate `volume unmount` process can read after the writer exits; a later
    /// successful publish clears it.
    #[tokio::test]
    async fn failed_snapshot_publish_is_recorded_as_stale_cloud_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let mut result = opened_volume_with_db(dir.path());
        let marker = result.paths.base_dir.join("snapshot_publish_failed.json");
        let mock = MockTransport::new();
        mock.set_connected(false);
        let err = publish_as_new_session(&mut result, &mock)
            .await
            .expect_err("a failed publish is an error, not a warning");
        assert!(format!("{err:#}").contains("STALE"), "{err:#}");
        assert!(
            marker.exists(),
            "a failed publish must be recorded for `volume unmount`"
        );
        assert_eq!(result.config.metadata_snapshot_id, None);
        // What `volume unmount` reports after the writer exits.
        let status = snapshot_publish_status(&result.paths.base_dir).unwrap_err();
        assert!(
            format!("{status:#}").contains("no metadata snapshot on Telegram at all"),
            "{status:#}"
        );

        mock.set_connected(true);
        publish_as_new_session(&mut result, &mock).await.unwrap();
        assert!(!marker.exists(), "a successful publish clears the record");
        assert!(result.config.metadata_snapshot_id.is_some());
        snapshot_publish_status(&result.paths.base_dir).unwrap();

        // A second failure now names the snapshot Telegram does hold. It is
        // version 2: the failed first attempt used up version 1 (reserved before
        // the upload, so a stored-but-unacknowledged attempt is never reused).
        mock.set_connected(false);
        let err = publish_as_new_session(&mut result, &mock)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("still version 2"), "{err:#}");
    }

    /// R1: a snapshot that is published, and named by volume.json, while the
    /// journal HEAD cannot be reset onto it is an ERROR, recorded for `volume
    /// unmount`, and the report says exactly what is published and what the HEAD
    /// still names (the cloud snapshot is not stale; the local HEAD is).
    #[tokio::test]
    async fn head_reset_failure_after_publish_is_an_error_that_names_both_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let mut result = opened_volume_with_db(dir.path());
        let mock = MockTransport::new();
        publish_as_new_session(&mut result, &mock).await.unwrap();
        let first_id = result.config.metadata_snapshot_id.unwrap();
        let hp = journal_head_path(&result);
        let saved = std::fs::read(&hp).unwrap();
        // The HEAD becomes unwritable once the snapshot is uploaded.
        let block = hp.clone();
        mock.after_next_metadata_sync(move || {
            std::fs::remove_file(&block).unwrap();
            std::fs::create_dir(&block).unwrap();
            std::fs::write(block.join("block-rename"), b"x").unwrap();
        });

        let err = publish_as_new_session(&mut result, &mock)
            .await
            .expect_err("a HEAD reset failure is an error");
        let msg = format!("{err:#}");
        eprintln!("R1 publish error: {msg}");
        let second_id = result.config.metadata_snapshot_id.unwrap();
        assert_ne!(first_id, second_id);
        assert!(msg.contains("journal HEAD"), "{msg}");
        assert!(msg.contains(&format!("message_id={second_id}")), "{msg}");
        assert!(
            !msg.contains("STALE"),
            "the cloud snapshot is not stale: {msg}"
        );

        // `volume unmount` (another process) reads the same account.
        std::fs::remove_dir_all(&hp).unwrap();
        std::fs::write(&hp, &saved).unwrap();
        let status = format!(
            "{:#}",
            snapshot_publish_status(&result.paths.base_dir).unwrap_err()
        );
        assert!(
            status.contains(&format!("message_id={second_id}")),
            "{status}"
        );
        assert!(status.contains("journal HEAD"), "{status}");

        // The next successful publish resets the HEAD and clears the record.
        publish_as_new_session(&mut result, &mock).await.unwrap();
        snapshot_publish_status(&result.paths.base_dir).unwrap();
        let head = JournalHead::load(&hp, &result.hierarchy.integrity)
            .unwrap()
            .unwrap();
        assert_eq!(
            Some(head.base_snapshot_msg_id),
            result.config.metadata_snapshot_id
        );
    }

    /// A `snapshot_publish_failed.json` written before `head_not_reset` existed
    /// still parses and reads as a stale cloud snapshot; a record without the
    /// field is written without it.
    #[test]
    fn snapshot_failure_record_without_head_field_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SNAPSHOT_FAILED_MARKER),
            r#"{"failed_at_unix":1,"reason":"publishing the metadata snapshot failed: x","stale_snapshot_message_id":5,"stale_snapshot_version":3}"#,
        )
        .unwrap();
        let msg = format!("{:#}", snapshot_publish_status(dir.path()).unwrap_err());
        assert!(
            msg.contains("STALE") && msg.contains("still version 3"),
            "{msg}"
        );
        let f: SnapshotPublishFailure = serde_json::from_slice(
            &std::fs::read(dir.path().join(SNAPSHOT_FAILED_MARKER)).unwrap(),
        )
        .unwrap();
        assert!(f.head_not_reset.is_none());
        assert!(!serde_json::to_string(&f)
            .unwrap()
            .contains("head_not_reset"));
        // Round 12's field reads as false from a record written before it,
        // and is not written while false.
        assert!(!f.db_not_current);
        assert!(!serde_json::to_string(&f)
            .unwrap()
            .contains("db_not_current"));
        assert!(
            msg.contains("intact"),
            "an older record keeps its text: {msg}"
        );
    }

    // ── R3: every writer takes the volume lock before it reads volume.json ────

    /// A password volume with a forum topic and its pass file, then: the volume
    /// lock taken (as by a running `key rotate`) and volume.json rewritten so it
    /// still parses but fails its MAC. A command that reads the config before
    /// the lock reports the config; one that locks first reports the lock.
    fn locked_volume_with_unverifiable_config(
        dir: &std::path::Path,
    ) -> (String, std::path::PathBuf, manager::VolumeLock) {
        let (id, pass) = topic_volume(dir);
        let held = manager::VolumeLock::acquire_exclusive(&dir.join(&id)).unwrap();
        let path = dir.join(&id).join("volume.json");
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let bumped = v["metadata_version"].as_u64().unwrap_or(0) + 1000;
        v["metadata_version"] = serde_json::json!(bumped);
        std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        (id, pass, held)
    }

    fn assert_lock_refusal(cmd: &str, r: Result<()>) {
        let msg = format!("{:#}", r.expect_err("must refuse while the lock is held"));
        eprintln!("{cmd} under a held lock: {msg}");
        assert!(
            msg.contains("in use by another process"),
            "{cmd} must take the volume lock before reading volume.json, got: {msg}"
        );
    }

    #[test]
    fn mount_takes_the_volume_lock_before_reading_its_config() {
        let dir = tempfile::tempdir().unwrap();
        let (id, pass, _held) = locked_volume_with_unverifiable_config(dir.path());
        let mp = dir.path().join("mnt");
        std::fs::create_dir_all(&mp).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let r = rt.block_on(mount_in(
            dir.path(),
            &id,
            mp.to_str().unwrap(),
            false,
            Some(pass.to_str().unwrap()),
            None,
            &FactorSelect::default(),
        ));
        assert_lock_refusal("mount", r);
    }

    #[tokio::test]
    async fn restore_takes_the_volume_lock_before_reading_its_config() {
        let dir = tempfile::tempdir().unwrap();
        let (id, pass, _held) = locked_volume_with_unverifiable_config(dir.path());
        let r = restore_in(
            dir.path(),
            &id,
            None,
            Some(pass.to_str().unwrap()),
            None,
            true,
            false,
            Box::new(|_| Box::pin(async { panic!("Telegram must not be contacted") })),
        )
        .await;
        assert_lock_refusal("restore", r);
    }

    #[tokio::test]
    async fn revert_takes_the_volume_lock_before_reading_its_config() {
        let dir = tempfile::tempdir().unwrap();
        let (id, pass, _held) = locked_volume_with_unverifiable_config(dir.path());
        let r = revert_in(dir.path(), &id, "/f", 1, Some(pass.to_str().unwrap()), None).await;
        assert_lock_refusal("revert", r);
    }

    #[tokio::test]
    async fn delete_takes_the_volume_lock_before_reading_its_config() {
        let dir = tempfile::tempdir().unwrap();
        let (id, pass, _held) = locked_volume_with_unverifiable_config(dir.path());
        let r = delete_in(
            dir.path(),
            &id,
            true,
            Some(pass.to_str().unwrap()),
            None,
            false,
            connect_never(),
        )
        .await;
        assert_lock_refusal("delete", r);
    }

    // ── volume delete: what it removes from Telegram ─────────────────────────

    const DEL_GROUP: i64 = 999_000_000;
    const DEL_HASH: i64 = 1_234_567_890;
    const DEL_TOPIC: i64 = 77;
    const DEL_PASS: &str = "delete-me-password";

    /// A password volume bound to a forum topic, with no blocks yet (so before
    /// this fix nothing on Telegram was touched at all) and a pass file.
    fn topic_volume(dir: &std::path::Path) -> (String, std::path::PathBuf) {
        let created = manager::create_volume(
            Some("to-delete"),
            DEL_PASS.as_bytes(),
            dir,
            DEL_GROUP,
            DEL_HASH,
            DEL_TOPIC,
            None,
        )
        .unwrap();
        let pass = dir.join("pass.txt");
        std::fs::write(&pass, DEL_PASS).unwrap();
        (created.config.volume_id.to_string(), pass)
    }

    fn connect_mock(m: Arc<MockTransport>) -> ConnectRemote<'static> {
        Box::new(move |_channel| Box::pin(async move { Ok(m as Arc<dyn VolumeRemote>) }))
    }

    fn connect_never() -> ConnectRemote<'static> {
        Box::new(|_channel| Box::pin(async { panic!("Telegram must not be contacted") }))
    }

    /// `volume delete` removes everything the volume put on Telegram — blocks,
    /// metadata snapshots, journal entries — by deleting its whole forum topic,
    /// even when the local DB lists no blocks, and only then the local state.
    #[tokio::test]
    async fn delete_removes_the_volume_forum_topic() {
        use teagarden_telegram::mock::ForumCall;
        let dir = tempfile::tempdir().unwrap();
        let (id, pass) = topic_volume(dir.path());
        let mock = Arc::new(MockTransport::new());
        delete_in(
            dir.path(),
            &id,
            true,
            Some(pass.to_str().unwrap()),
            None,
            false,
            connect_mock(mock.clone()),
        )
        .await
        .unwrap();
        assert_eq!(
            mock.forum_calls(),
            vec![ForumCall::DeleteTopic {
                group_id: DEL_GROUP,
                access_hash: DEL_HASH,
                topic_id: DEL_TOPIC,
            }]
        );
        assert!(!dir.path().join(&id).exists(), "local state must be gone");
    }

    /// If the topic cannot be deleted, the local volume (the only record of what
    /// is on Telegram) is left intact so the deletion can be retried.
    #[tokio::test]
    async fn delete_keeps_local_state_when_the_topic_cannot_be_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let (id, pass) = topic_volume(dir.path());
        let mock = Arc::new(MockTransport::new());
        mock.set_fail_forum(true);
        let err = delete_in(
            dir.path(),
            &id,
            true,
            Some(pass.to_str().unwrap()),
            None,
            false,
            connect_mock(mock.clone()),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("INTACT"), "{err:#}");
        assert!(dir.path().join(&id).join("volume.json").exists());
    }

    /// Keep a real fork child before exec, so CLOEXEC cannot close its copies of
    /// the parent's open lock descriptions. The socket handshake has no sleeps.
    #[cfg(target_os = "linux")]
    pub(super) struct ForkLockChild {
        pid: libc::pid_t,
        control: std::os::unix::net::UnixStream,
        _parent_lock: Option<manager::VolumeLock>,
    }

    #[cfg(target_os = "linux")]
    impl ForkLockChild {
        pub(super) fn retain(parent_lock: Option<manager::VolumeLock>) -> Self {
            use std::io::Read;
            use std::os::fd::AsRawFd;
            let (control, child_control) = std::os::unix::net::UnixStream::pair().unwrap();
            control
                .set_read_timeout(Some(std::time::Duration::from_secs(20)))
                .unwrap();
            let parent_fd = control.as_raw_fd();
            let child_fd = child_control.as_raw_fd();
            // SAFETY: the child performs only descriptor close, the File-only
            // VolumeLock destructor, getpid/flock, socket I/O and _exit. It never
            // allocates, locks Rust state, invokes libtest or returns into Tokio.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
            if pid == 0 {
                // A Some guard is dropped ONLY in this child copy. The parent
                // still owns its copy, testing that a child cannot unlock it.
                drop(parent_lock);
                let mut byte = 1u8;
                // SAFETY: these descriptors are open in this child and the
                // one-byte stack buffers are valid for exactly one byte.
                unsafe {
                    libc::close(parent_fd);
                    if libc::write(child_fd, (&byte as *const u8).cast(), 1) != 1 {
                        libc::_exit(70);
                    }
                    loop {
                        let read = libc::read(child_fd, (&mut byte as *mut u8).cast(), 1);
                        if read >= 0 {
                            libc::_exit(0);
                        }
                        if *libc::__errno_location() != libc::EINTR {
                            libc::_exit(71);
                        }
                    }
                }
            }
            drop(child_control);
            let mut child = Self {
                pid,
                control,
                _parent_lock: parent_lock,
            };
            let mut ready = [0u8; 1];
            child.control.read_exact(&mut ready).unwrap();
            assert_eq!(ready, [1]);
            child
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ForkLockChild {
        fn drop(&mut self) {
            // shutdown wakes the child even if another concurrent fork copied
            // this socket; cleanup never depends on the last copied fd closing.
            let _ = self.control.shutdown(std::net::Shutdown::Both);
            let mut status = 0;
            loop {
                // SAFETY: wait for this owned child, with a valid status pointer.
                let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if result >= 0
                    || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    break;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forked_descriptor_does_not_delay_owner_admin_guard_release() {
        let dir = tempfile::tempdir().unwrap();
        let held = manager::OwnerAdminLock::acquire(dir.path()).unwrap();
        let child = ForkLockChild::retain(None);
        assert!(manager::OwnerAdminLock::acquire(dir.path()).is_err());
        drop(held);
        let acquired = manager::OwnerAdminLock::acquire(dir.path())
            .expect("owner administration must release before the inherited descriptor closes");
        drop(acquired);
        drop(child);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forked_shared_descriptors_release_only_when_the_last_parent_guard_drops() {
        let dir = tempfile::tempdir().unwrap();
        let first = manager::VolumeLock::acquire_shared(dir.path()).unwrap();
        let second = manager::VolumeLock::acquire_shared(dir.path()).unwrap();
        let child = ForkLockChild::retain(None);
        drop(first);
        assert!(
            manager::VolumeLock::acquire_exclusive(dir.path()).is_err(),
            "a remaining parent reader must exclude writers"
        );
        drop(second);
        let acquired = manager::VolumeLock::acquire_exclusive(dir.path())
            .expect("inherited shared descriptors must not extend the readers' lifetimes");
        drop(acquired);
        drop(child);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forked_child_dropping_an_inherited_guard_cannot_unlock_the_parent() {
        let dir = tempfile::tempdir().unwrap();
        let held = manager::VolumeLock::acquire_exclusive(dir.path()).unwrap();
        let child = ForkLockChild::retain(Some(held));
        assert!(
            manager::VolumeLock::acquire_exclusive(dir.path()).is_err(),
            "the parent still owns its guard after the child drops its inherited copy"
        );
        drop(child);
        manager::VolumeLock::acquire_exclusive(dir.path())
            .expect("free when the parent guard drops");
    }

    /// `volume delete` takes the same exclusive single-writer lock a mount and
    /// `key rotate` take. While another holder owns it, delete refuses before any
    /// Telegram call or local deletion (`/proc/mounts` cannot see an offline writer).
    #[tokio::test]
    async fn delete_refuses_while_another_process_holds_the_volume_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (id, pass) = topic_volume(dir.path());
        let mock = Arc::new(MockTransport::new());
        let held = manager::VolumeLock::acquire_exclusive(&dir.path().join(&id)).unwrap();
        // A real child retains the open file description until this test ends.
        // Owner drop must release it before the child reaches exec or exit.
        #[cfg(target_os = "linux")]
        let child = ForkLockChild::retain(None);
        for local_only in [false, true] {
            let err = delete_in(
                dir.path(),
                &id,
                true,
                Some(pass.to_str().unwrap()),
                None,
                local_only,
                connect_mock(mock.clone()),
            )
            .await
            .unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("in use by another process"), "{msg}");
            assert!(msg.contains("nothing was deleted"), "{msg}");
        }
        assert!(
            mock.forum_calls().is_empty(),
            "no topic delete may be issued while the lock is held"
        );
        assert!(dir.path().join(&id).join("volume.json").exists());
        drop(held);
        delete_in(
            dir.path(),
            &id,
            true,
            Some(pass.to_str().unwrap()),
            None,
            false,
            connect_mock(mock.clone()),
        )
        .await
        .expect("delete proceeds once the lock is released");
        assert!(!dir.path().join(&id).exists());
        #[cfg(target_os = "linux")]
        drop(child);
    }

    /// `--local-only` keeps its meaning: nothing on Telegram is touched.
    #[tokio::test]
    async fn delete_local_only_never_contacts_telegram() {
        let dir = tempfile::tempdir().unwrap();
        let (id, pass) = topic_volume(dir.path());
        delete_in(
            dir.path(),
            &id,
            true,
            Some(pass.to_str().unwrap()),
            None,
            true,
            connect_never(),
        )
        .await
        .unwrap();
        assert!(!dir.path().join(&id).exists());
    }

    /// A shared copy (from `share import`) points at the OWNER's topic: deleting
    /// it remotely would destroy the owner's data, so only `--local-only` works.
    #[tokio::test]
    async fn delete_refuses_to_delete_a_shared_copy_remotely() {
        use teagarden_core::volume::shared::{SharedDerivation, SharedOrigin};
        let dir = tempfile::tempdir().unwrap();
        let (id, pass) = topic_volume(dir.path());
        SharedOrigin {
            derivation: SharedDerivation::HierarchyRootV1,
            access_level: "read-write".into(),
            granted_by: "owner".into(),
            volume_id: id.clone(),
        }
        .save(&dir.path().join(&id))
        .unwrap();
        let err = delete_in(
            dir.path(),
            &id,
            true,
            Some(pass.to_str().unwrap()),
            None,
            false,
            connect_never(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("--local-only"), "{err:#}");
        assert!(dir.path().join(&id).join("volume.json").exists());
    }

    /// A5: bad local input is refused before anything reaches Telegram — no
    /// storage group and no forum topic is created for a volume that is never made.
    #[tokio::test]
    async fn create_rejects_bad_input_before_any_telegram_call() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let group_path = cfg.path().join("group.json");
        let mock = MockTransport::new();
        let cases: [(&str, Option<u64>); 4] = [
            ("short", None),
            ("a-long-enough-pass", Some(512 * 1024 - 1)),
            ("a-long-enough-pass", Some(48_000_001)),
            ("a-long-enough-pass", Some(50 * 1024 * 1024)),
        ];
        for protected in [false, true] {
            for (password, block_size) in cases {
                let err = create_command(
                    &mock,
                    &group_path,
                    volumes.path(),
                    "v",
                    password,
                    block_size,
                    protected,
                    None,
                )
                .await
                .expect_err("bad input must be refused");
                assert!(
                    mock.forum_calls().is_empty(),
                    "{password:?}/{block_size:?}/{protected}: Telegram was contacted \
                     before refusing ({err:#}): {:?}",
                    mock.forum_calls()
                );
            }
        }
        assert!(!group_path.exists(), "no storage group recorded");
        assert_eq!(std::fs::read_dir(volumes.path()).unwrap().count(), 0);
    }

    /// A4: the accepted --block-size range is the range actually used: the
    /// largest accepted value is the cloud-bot ceiling, used as given.
    #[tokio::test]
    async fn create_accepts_exactly_the_block_sizes_it_uses() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let group_path = cfg.path().join("group.json");
        let mock = MockTransport::new();
        for (asked, used) in [
            (48_000_000u64, 48_000_000usize),
            (512 * 1024, 512 * 1024),
            (1_000_000, 1_000_000 & !511),
        ] {
            let (id, _) = create_command(
                &mock,
                &group_path,
                volumes.path(),
                "v",
                "a-long-enough-pass",
                Some(asked),
                false,
                None,
            )
            .await
            .unwrap();
            let config: VolumeConfig = serde_json::from_slice(
                &std::fs::read(volumes.path().join(&id).join("volume.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(config.block_config.fuse_chunk_size(), used, "asked {asked}");
        }
    }

    /// Telegram sees a new volume's forum topic title, so it must never carry
    /// the user's name for the volume; that name stays in the local config only.
    #[tokio::test]
    async fn created_topic_title_does_not_carry_the_volume_name() {
        use teagarden_telegram::mock::ForumCall;
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let group_path = cfg.path().join("group.json");
        let mock = MockTransport::new();
        for (name, protected) in [("tax-records-2026", false), ("medical scans", true)] {
            let (id, topic) = create_command(
                &mock,
                &group_path,
                volumes.path(),
                name,
                "a-long-enough-pass",
                None,
                protected,
                None,
            )
            .await
            .unwrap();
            let titles: Vec<String> = mock
                .forum_calls()
                .into_iter()
                .filter_map(|c| match c {
                    ForumCall::CreateTopic { title, .. } => Some(title),
                    _ => None,
                })
                .collect();
            let title = titles.last().expect("a topic was created");
            for part in name
                .split(|c: char| !c.is_alphanumeric())
                .filter(|p| !p.is_empty())
            {
                assert!(
                    !title.to_lowercase().contains(&part.to_lowercase()),
                    "topic title {title:?} carries part of the volume name {name:?}"
                );
            }
            let config: VolumeConfig = serde_json::from_slice(
                &std::fs::read(volumes.path().join(&id).join("volume.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                config.display_name, name,
                "the name stays in the local config"
            );
            assert_eq!(
                config.telegram_topic_id, topic,
                "the topic is referenced by id"
            );
            assert!(
                config.sdo_author_device_id.is_some(),
                "new volumes carry the SDO author identity"
            );
            let headers = mock
                .list_topic_documents(config.telegram_group_id, topic, None, 100)
                .await
                .unwrap();
            let header_doc = headers
                .iter()
                .find(|doc| doc.filename == "teagarden-header-v1.tgh")
                .expect("volume creation uploads a named portable header");
            let raw_header = mock.get_raw(header_doc.message_id).unwrap();
            assert_eq!(&raw_header[..4], b"TGHD");
            let opened = if protected {
                teagarden_mfa::unlock::open_volume(
                    &id,
                    &teagarden_mfa::unlock::UnlockInputs {
                        password: Some(b"a-long-enough-pass"),
                        ..Default::default()
                    },
                    volumes.path(),
                )
                .unwrap()
            } else {
                manager::open_volume(&id, b"a-long-enough-pass", volumes.path()).unwrap()
            };
            let decoded = HeaderDocument::decode(&raw_header, &opened.hierarchy.integrity).unwrap();
            assert_eq!(decoded.volume_id.to_string(), id);
            assert_eq!(decoded.topic_id, topic);
            assert_eq!(decoded.revision, 1);
        }
    }

    #[tokio::test]
    async fn lost_header_ack_is_pending_and_repair_reuses_the_reserved_revision() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let group_path = cfg.path().join("group.json");
        let mock = MockTransport::new();
        mock.withhold_upload_acks(1);
        let error = create_command(
            &mock,
            &group_path,
            volumes.path(),
            "pending-header",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("remains pending publication"));
        let volume_entry = std::fs::read_dir(volumes.path())
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.path().is_dir())
            .unwrap()
            .path();
        let config_path = volume_entry.join("volume.json");
        let pending: VolumeConfig =
            serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        assert!(pending.sdo_header_pending);
        assert_eq!(pending.sdo_header_revision_reserved, 1);
        assert_eq!(pending.sdo_header_revision_published, 0);
        assert!(pending.sdo_header_pending_sha256.is_some());

        let opened = manager::open_volume(
            &pending.volume_id.to_string(),
            b"a-long-enough-pass",
            volumes.path(),
        )
        .unwrap();
        publish_initial_header(
            &mock,
            &opened.config,
            &opened.hierarchy,
            &opened.paths.config_path,
            None,
        )
        .await
        .unwrap();
        let repaired: VolumeConfig =
            serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
        assert!(!repaired.sdo_header_pending);
        assert_eq!(repaired.sdo_header_revision_reserved, 1);
        assert_eq!(repaired.sdo_header_revision_published, 1);
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_legacy_command_fixture(
        mock: &MockTransport,
        group_path: &std::path::Path,
        volumes: &std::path::Path,
        name: &str,
        password: &str,
        block_size: Option<u64>,
        protected: bool,
        group_name: Option<&str>,
    ) -> Result<(String, i64)> {
        let (id, topic) = create_command(
            mock, group_path, volumes, name, password, block_size, protected, group_name,
        )
        .await?;
        let mut opened = manager::open_volume(&id, password.as_bytes(), volumes)?;
        let (document, mut header, _) = discover_latest_header(
            mock,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &opened.hierarchy.integrity,
            None,
        )
        .await?
        .unwrap();
        header.format = 1;
        header.owner_public_key = None;
        header.key_generation = None;
        mock.put_document(
            document.message_id,
            header.group_id,
            topic,
            "teagarden-header-v1.tgh",
            header.encode(&opened.hierarchy.integrity)?,
        );
        // Construct a historical on-disk fixture; production policy saves now
        // correctly refuse removing an established owner pin.
        let admin = manager::OwnerAdminLock::acquire(&opened.paths.base_dir)?;
        std::fs::remove_file(&opened.paths.config_path)?;
        opened.config.sdo_owner_public_key = None;
        manager::save_config_resealed_in_transaction(
            &mut opened.config,
            &opened.hierarchy,
            &opened.paths.config_path,
            &admin,
        )?;
        std::fs::remove_file(owner_capability_path(&opened.paths.config_path)?)?;
        Ok((id, topic))
    }

    #[tokio::test]
    async fn a2_n4_attach_refuses_tghd1_when_no_owner_evidence_is_visible() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = MockTransport::new_unbound();
        let (id, topic) = create_legacy_command_fixture(
            &mock,
            &cfg.path().join("group.json"),
            volumes.path(),
            "legacy-only",
            "original-password",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"original-password", volumes.path()).unwrap();
        let destination = tempfile::tempdir().unwrap();
        mock.clear_channel_binding();
        let error = attach_command(
            &mock,
            opened.config.telegram_group_id,
            topic,
            b"original-password",
            false,
            destination.path(),
            None,
        )
        .await
        .expect_err("1.0 attach must reject TGHD1 even when all TGHD2 evidence is absent");
        assert!(
            format!("{error:#}").contains("TGHD1 is unsupported"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
    }

    #[test]
    fn round3_int_n4_export_uses_wire_magic_for_renamed_documents() {
        const CHILD: &str = "TEAGARDEN_R3_EXPORT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::volume::tests::round3_int_n4_export_uses_wire_magic_for_renamed_documents", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| !line.starts_with("New volume recovery sentence"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(output.status.success(), "{diagnostic}");
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let f = Round2Fixture::new().await;
            let opened = f.open(b"original-password");
            let (document, header, bytes) = discover_latest_header(
                f.mock.as_ref(),
                opened.config.telegram_group_id,
                opened.config.telegram_topic_id,
                &opened.hierarchy.integrity,
                opened.config.sdo_owner_public_key.as_deref(),
            )
            .await
            .unwrap()
            .unwrap();
            f.mock.put_document(
                document.message_id,
                header.group_id,
                header.topic_id,
                "renamed-header.bin",
                bytes.clone(),
            );
            for (id, path, name) in [
                (500, "renamed.txt", "arbitrary.dat"),
                (501, "ordinary.txt", "teagarden-file-v3.tgf"),
            ] {
                let mut m = legacy_v2_logical_metadata(
                    &teagarden_core::sdo::SdoObjectMetadata::test_fixture(),
                );
                m.file_id = uuid::Uuid::new_v4();
                m.version_id = uuid::Uuid::new_v4();
                m.path = Some(path.into());
                m.clock_ms = id as u64;
                m.size = 4;
                let wire = teagarden_core::sdo::SdoFileObjectV3::encode(
                    header.volume_id,
                    0,
                    &opened.hierarchy.meta,
                    m,
                    b"kept",
                )
                .unwrap();
                f.mock
                    .put_document(id, header.group_id, header.topic_id, name, wire);
            }
            f.mock.put_document(
                502,
                header.group_id,
                header.topic_id,
                "teagarden-file-v3.tgf",
                b"unrelated document".to_vec(),
            );
            let scan = scan_topic_sdo_objects(
                f.mock.as_ref(),
                header.group_id,
                header.topic_id,
                &header,
                &opened.hierarchy,
            )
            .await
            .unwrap();
            assert!(scan.view.is_visible("renamed.txt"));
            unsafe {
                std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
            }
            let password = f.cfg.path().join("password");
            std::fs::write(&password, "original-password").unwrap();
            let out = f.cfg.path().join("export");
            super::super::key::TEST_PORTABLE_TRANSPORT
                .scope(
                    f.mock.clone(),
                    export_objects(&f.id, &out, Some(password.to_str().unwrap()), None),
                )
                .await
                .unwrap();
            assert_eq!(
                std::fs::read(out.join(format!("header-{}.tgh", document.message_id)))
                    .expect("renamed authenticated header must be exported"),
                bytes
            );
            assert!(
                out.join("file-500.tgf").exists(),
                "accepted renamed object must not disappear from export"
            );
            assert!(!out.join("file-502.tgf").exists());
            let recovered = f.cfg.path().join("recovered");
            super::super::decrypt::run(
                &out,
                Some(&recovered),
                Some(password.to_str().unwrap()),
                None,
                None,
                header.owner_public_key.as_deref(),
                false,
            )
            .unwrap();
            for path in ["renamed.txt", "ordinary.txt"] {
                assert_eq!(std::fs::read(recovered.join(path)).unwrap(), b"kept");
            }
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round3_int_n1_no_file_noninteractive_refuses_clearly() {
        round3_revoke_credential_child(false);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round3_int_n1_no_file_tty_prompts_and_revokes() {
        round3_revoke_credential_child(true);
    }

    #[cfg(target_os = "linux")]
    fn round3_revoke_credential_child(terminal: bool) {
        const CHILD: &str = "TEAGARDEN_R3_CREDENTIAL_CHILD";
        if std::env::var_os(CHILD).is_none() {
            use std::os::fd::{AsRawFd, FromRawFd};
            use std::os::unix::process::CommandExt;
            use std::process::{Command, Stdio};
            let name = if terminal {
                "commands::volume::tests::round3_int_n1_no_file_tty_prompts_and_revokes"
            } else {
                "commands::volume::tests::round3_int_n1_no_file_noninteractive_refuses_clearly"
            };
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut tty_reader = None;
            if terminal {
                // Open atomically with CLOEXEC: unrelated concurrent test
                // subprocesses must not inherit this terminal and delay EOF.
                // SAFETY: flags only, returns an owned descriptor or -1.
                let master =
                    unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
                assert!(
                    master >= 0,
                    "open test terminal: {}",
                    std::io::Error::last_os_error()
                );
                // SAFETY: master is an owned open PTY descriptor.
                let mut master = unsafe { std::fs::File::from_raw_fd(master) };
                // SAFETY: owned valid PTY master, no pointers passed.
                assert_eq!(unsafe { libc::grantpt(master.as_raw_fd()) }, 0);
                // SAFETY: owned valid PTY master, no pointers passed.
                assert_eq!(unsafe { libc::unlockpt(master.as_raw_fd()) }, 0);
                let mut name = [0 as libc::c_char; 128];
                // SAFETY: valid output buffer of exactly the supplied size.
                assert_eq!(
                    unsafe { libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) },
                    0
                );
                // SAFETY: ptsname_r returned a terminated path in name.
                let slave = unsafe {
                    libc::open(
                        name.as_ptr(),
                        libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
                    )
                };
                assert!(slave >= 0, "open test terminal slave");
                // SAFETY: slave is an owned open descriptor.
                let slave = unsafe { std::fs::File::from_raw_fd(slave) };
                command.stdin(Stdio::from(slave.try_clone().unwrap()));
                let slave_fd = slave.as_raw_fd();
                // SAFETY: only async-signal-safe calls in the child before exec.
                unsafe {
                    command.pre_exec(move || {
                        if libc::setsid() == -1
                            || libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) == -1
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let child = command.spawn().unwrap();
                drop(command);
                drop(slave);
                tty_reader = Some(std::thread::spawn(move || {
                    use std::io::Read;
                    let mut seen = String::new();
                    let mut answered = false;
                    let mut buf = [0; 1024];
                    while let Ok(n) = master.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if !answered && seen.contains("Enter volume password: ") {
                            master.write_all(b"original-password\n").unwrap();
                            answered = true;
                        }
                    }
                    seen
                }));
                round3_finish_credential_child(child, tty_reader);
            } else {
                command.stdin(Stdio::null());
                // SAFETY: detach any inherited controlling terminal so this is truly noninteractive.
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                round3_finish_credential_child(command.spawn().unwrap(), tty_reader);
            }
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let f = Round2Fixture::new().await;
            let target = cut_only_target(&f, Some("88")).await;
            unsafe {
                std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
            }
            let confirmed = if terminal {
                Some(confirmed_fixture_session_map(&f, target, 88).await)
            } else {
                None
            };
            let result = super::super::key::TEST_PORTABLE_TRANSPORT
                .scope(
                    f.mock.clone(),
                    revoke_device(
                        &f.id,
                        target,
                        None,
                        None,
                        Some(88),
                        false,
                        confirmed.as_deref(),
                    ),
                )
                .await;
            if terminal {
                result.expect(
                    "bare public revoke must prompt once for the existing credential on a terminal",
                );
                assert!(f.mock.forum_calls().contains(
                    &teagarden_telegram::mock::ForumCall::ResetAuthorization { hash: 88 }
                ));
            } else {
                let error = result.expect_err(
                    "bare noninteractive revoke must refuse before transport administration",
                );
                let message = format!("{error:#}");
                assert!(
                    message.contains("terminal") && message.contains("--password-file"),
                    "clear noninteractive credential guidance required: {message}"
                );
                assert!(!f.mock.forum_calls().iter().any(|call| matches!(
                    call,
                    teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
                        | teagarden_telegram::mock::ForumCall::BanMember { .. }
                )));
            }
        });
    }

    #[cfg(target_os = "linux")]
    fn round3_finish_credential_child(
        mut child: std::process::Child,
        terminal: Option<std::thread::JoinHandle<String>>,
    ) {
        use std::io::Read;
        let mut stderr = child.stderr.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let err = std::thread::spawn(move || {
            let mut s = String::new();
            stderr.read_to_string(&mut s).unwrap();
            s
        });
        let out = std::thread::spawn(move || {
            let mut s = String::new();
            stdout.read_to_string(&mut s).unwrap();
            s
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() > deadline {
                child.kill().unwrap();
                panic!("credential command did not finish within 60 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let diagnostic = err
            .join()
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("New volume recovery sentence"))
            .collect::<Vec<_>>()
            .join("\n");
        let stdout = out.join().unwrap();
        assert!(status.success(), "{diagnostic}");
        if let Some(terminal) = terminal {
            let screen = terminal.join().unwrap();
            assert_eq!(
                screen.matches("Enter volume password: ").count(),
                1,
                "exactly one existing-credential prompt"
            );
            assert!(!screen.contains("NEW volume password"));
            assert!(stdout.contains("Revocation complete"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round3_411_public_revoke_runs_beside_owner_mount_and_serializes_admin() {
        const CHILD: &str = "TEAGARDEN_R3_OWNER_MOUNT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::volume::tests::round3_411_public_revoke_runs_beside_owner_mount_and_serializes_admin", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| !line.starts_with("New volume recovery sentence"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(output.status.success(), "{diagnostic}");
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let f = Round2Fixture::new().await;
            let target = cut_only_target(&f, Some("88")).await;
            unsafe {
                std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
            }
            let password = f.cfg.path().join("password");
            std::fs::write(&password, "original-password").unwrap();
            // This is the exact lock retained by mount_in for the kernel session.
            let _mount_lock =
                manager::VolumeLock::acquire_exclusive(&f.volumes.path().join(&f.id)).unwrap();
            let mut owner = f.open(b"original-password");
            let conn = open_sdo_mount_db(&mut owner).unwrap();
            let builder = portable_mount_builder(&owner, conn);
            let (fs, cursor) = prepare_sdo_mount(f.mock.clone(), &owner, builder, Some(77))
                .await
                .unwrap();
            let (fs, notify) = start_prepared_sdo_mount_poller(
                fs,
                f.mock.clone(),
                &owner,
                cursor,
                Arc::new(Mutex::new(None)),
            )
            .await
            .unwrap();
            let mountpoint = tempfile::tempdir().unwrap();
            let session = fuser::spawn_mount2(
                fs,
                mountpoint.path(),
                &[fuser::MountOption::FSName("teagarden-owner-admin".into())],
            )
            .unwrap();
            let confirmed = confirmed_fixture_session_map(&f, target, 88).await;
            super::super::key::TEST_PORTABLE_TRANSPORT
                .scope(
                    f.mock.clone(),
                    revoke_device(
                        &f.id,
                        target,
                        Some(password.to_str().unwrap()),
                        None,
                        Some(88),
                        false,
                        Some(&confirmed),
                    ),
                )
                .await
                .expect("default revoke must work while this owner's real mount holds volume.lock");
            notify.notify_one();
            let mut file =
                std::fs::File::create(mountpoint.path().join("owner-still-writes.txt")).unwrap();
            file.write_all(b"owner continues").unwrap();
            file.sync_all().unwrap();
            drop(file);
            assert_eq!(
                std::fs::read(mountpoint.path().join("owner-still-writes.txt")).unwrap(),
                b"owner continues"
            );

            let next = cut_only_target(&f, Some("89")).await;
            f.mock.extra_authorizations.lock().unwrap().push(
                teagarden_telegram::client::TelegramAuthorizationInfo {
                    hash: 89,
                    current: false,
                    device_model: "second target".into(),
                    app_name: "test".into(),
                    date_active: 1,
                },
            );
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            f.mock
                .gate_next_upload("teagarden-header-v1.tgh", entered.clone(), release.clone());
            let id = f.id.clone();
            let next_confirmed = confirmed_fixture_session_map(&f, next, 89).await;
            let first_confirmed = next_confirmed.clone();
            let password_path = password.to_str().unwrap().to_owned();
            let transport = f.mock.clone();
            let first = tokio::spawn(async move {
                super::super::key::TEST_PORTABLE_TRANSPORT
                    .scope(
                        transport,
                        revoke_device(
                            &id,
                            next,
                            Some(&password_path),
                            None,
                            Some(89),
                            false,
                            Some(&first_confirmed),
                        ),
                    )
                    .await
            });
            tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
                .await
                .expect("first owner administration reaches publication");
            let error = super::super::key::TEST_PORTABLE_TRANSPORT
                .scope(
                    f.mock.clone(),
                    revoke_device(
                        &f.id,
                        next,
                        Some(password.to_str().unwrap()),
                        None,
                        Some(89),
                        false,
                        Some(&next_confirmed),
                    ),
                )
                .await
                .expect_err("a concurrent revoke must not enter owner administration");
            assert!(
                format!("{error:#}").contains("owner administration"),
                "{error:#}"
            );
            release.notify_one();
            first.await.unwrap().unwrap();
            let resets: Vec<_> = f
                .mock
                .forum_calls()
                .into_iter()
                .filter(|call| {
                    matches!(
                        call,
                        teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
                    )
                })
                .collect();
            assert_eq!(
                resets,
                vec![
                    teagarden_telegram::mock::ForumCall::ResetAuthorization { hash: 88 },
                    teagarden_telegram::mock::ForumCall::ResetAuthorization { hash: 89 }
                ]
            );
            drop(session);
        });
    }

    async fn round3_run_reader(
        kind: &str,
        volumes: &std::path::Path,
        id: &str,
        transport: Arc<MockTransport>,
        versions: [uuid::Uuid; 2],
        export: &std::path::Path,
    ) -> Result<()> {
        let password = volumes.join("password");
        std::fs::write(&password, "original-password")?;
        let password = Some(password.to_str().unwrap());
        super::super::history::TEST_VOLUMES_DIR
            .with(|path| *path.borrow_mut() = Some(volumes.to_path_buf()));
        super::super::history::TEST_TRANSPORT
            .with(|mock| *mock.borrow_mut() = Some(transport.clone()));
        let result = match kind {
            "history" => super::super::history::run(id, None, password, None).await,
            "diff" => {
                super::super::history::diff(
                    id,
                    &versions[0].to_string(),
                    &versions[1].to_string(),
                    password,
                    None,
                )
                .await
            }
            "restore-version" => {
                super::super::history::restore_version(
                    id,
                    "restored.txt",
                    &versions[0].to_string(),
                    password,
                    None,
                )
                .await
            }
            "export" => {
                super::super::key::TEST_PORTABLE_TRANSPORT
                    .scope(
                        transport.clone(),
                        export_objects(id, export, password, None),
                    )
                    .await
            }
            "device-list" => {
                super::super::key::TEST_PORTABLE_TRANSPORT
                    .scope(transport.clone(), device_list(id, password, None))
                    .await
            }
            "mount-prepare" => {
                let mut opened = teagarden_mfa::unlock::open_volume(
                    id,
                    &teagarden_mfa::unlock::UnlockInputs {
                        password: Some(b"original-password"),
                        ..Default::default()
                    },
                    volumes,
                )?;
                let conn = open_sdo_mount_db(&mut opened)?;
                let builder = portable_mount_builder(&opened, conn);
                prepare_sdo_mount(transport, &opened, builder, Some(77))
                    .await
                    .map(|_| ())
            }
            _ => panic!("unknown volume reader case: {kind}"),
        };
        super::super::history::TEST_VOLUMES_DIR.with(|path| *path.borrow_mut() = None);
        super::super::history::TEST_TRANSPORT.with(|mock| *mock.borrow_mut() = None);
        result
    }

    #[test]
    fn round3_int_n2_persisted_floor_across_command_readers() {
        const CHILD: &str = "TEAGARDEN_R3_FLOOR_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::volume::tests::round3_int_n2_persisted_floor_across_command_readers",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| !line.starts_with("New volume recovery sentence"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(output.status.success(), "{diagnostic}");
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let f = Round2Fixture::new().await;
            let owner = f.open(b"original-password");
            let target = cut_only_target(&f, Some("88")).await;
            let (private, _) =
                load_or_create_device_keypair(&owner.paths.base_dir, &owner.hierarchy.wrapping)
                    .unwrap();
            let signer = teagarden_core::sdo::device_signing_key(&private.0);
            let file_id = uuid::Uuid::new_v4();
            let versions = [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
            for (i, content) in [b"one", b"two"].into_iter().enumerate() {
                let mut m = legacy_v2_logical_metadata(
                    &teagarden_core::sdo::SdoObjectMetadata::test_fixture(),
                );
                m.file_id = file_id;
                m.version_id = versions[i];
                m.author_device_id = owner.config.sdo_author_device_id.unwrap();
                m.path = Some("history.txt".into());
                m.clock_ms = 10 + i as u64;
                m.local_version = 1 + i as u64;
                m.size = 3;
                let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
                    owner.config.volume_id,
                    0,
                    &owner.hierarchy.meta,
                    m,
                    content,
                    Some(&signer),
                )
                .unwrap();
                f.mock
                    .upload_file_object(&wire, "teagarden-file-v3.tgf")
                    .await
                    .unwrap();
            }
            let readers = [
                "history",
                "diff",
                "restore-version",
                "export",
                "device-list",
                "mount-prepare",
            ];
            let mut installations = Vec::new();
            for _ in readers {
                let volumes = tempfile::tempdir().unwrap();
                let attached = attach_command(
                    f.mock.as_ref(),
                    owner.config.telegram_group_id,
                    owner.config.telegram_topic_id,
                    b"original-password",
                    false,
                    volumes.path(),
                    owner.config.sdo_owner_public_key.as_deref(),
                )
                .await
                .unwrap();
                assert_eq!(attached.config.sdo_header_revision_published, 1);
                installations.push(volumes);
            }
            revoke_fixture_target(&f, &owner, target, 88).await.unwrap();
            let (document, current, wire) = discover_latest_header(
                f.mock.as_ref(),
                owner.config.telegram_group_id,
                owner.config.telegram_topic_id,
                &owner.hierarchy.integrity,
                owner.config.sdo_owner_public_key.as_deref(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(current.revision, 2);
            for (producer, volumes) in readers.into_iter().zip(installations) {
                unsafe {
                    std::env::set_var("TEAGARDEN_VOLUMES_DIR", volumes.path());
                }
                f.mock.put_document(
                    document.message_id,
                    current.group_id,
                    current.topic_id,
                    "policy.bin",
                    wire.clone(),
                );
                round3_run_reader(
                    producer,
                    volumes.path(),
                    &f.id,
                    f.mock.clone(),
                    versions,
                    &volumes.path().join("observed-export"),
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("{producer} must first observe revision 2: {error:#}")
                });
                // No owner publication or attach has advanced this installation's
                // bootstrap: it must remember the revision learned by a reader.
                let local = teagarden_mfa::unlock::open_volume(
                    &f.id,
                    &teagarden_mfa::unlock::UnlockInputs {
                        password: Some(b"original-password"),
                        ..Default::default()
                    },
                    volumes.path(),
                )
                .unwrap();
                assert_eq!(local.config.sdo_header_revision_published, 1);
                f.mock.delete_message(document.message_id).await.unwrap();
                let mut violations = Vec::new();
                for consumer in readers {
                    let out = volumes.path().join(format!("replayed-{consumer}"));
                    match round3_run_reader(
                        consumer,
                        volumes.path(),
                        &f.id,
                        f.mock.clone(),
                        versions,
                        &out,
                    )
                    .await
                    {
                        Ok(()) => violations.push(format!(
                            "{consumer} accepted revision 1 after {producer} observed 2"
                        )),
                        Err(error) if format!("{error:#}").contains("revision floor") => {}
                        Err(error) => {
                            violations.push(format!("{consumer} gave unrelated refusal: {error:#}"))
                        }
                    }
                    if consumer == "export" && out.exists() {
                        violations.push("replayed export wrote output".into());
                    }
                }
                assert!(violations.is_empty(), "{}", violations.join("; "));
            }
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round3_int_n3_revoked_root_cannot_impersonate_a_frozen_installation() {
        const CHILD: &str = "TEAGARDEN_R3_WRITER_BINDING_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::volume::tests::round3_int_n3_revoked_root_cannot_impersonate_a_frozen_installation", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| !line.starts_with("New volume recovery sentence"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(output.status.success(), "{diagnostic}");
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let f = Round2Fixture::new().await;
            let mut owner = f.open(b"original-password");
            let conn = open_sdo_mount_db(&mut owner).unwrap();
            let builder = portable_mount_builder(&owner, conn);
            let prepared_owner = prepare_sdo_mount(f.mock.clone(), &owner, builder, Some(77))
                .await
                .unwrap();
            drop(prepared_owner);
            let target = cut_only_target(&f, Some("88")).await;
            let c_volumes = tempfile::tempdir().unwrap();
            let c_transport = Arc::new(f.mock.fork_session());
            let mut c = attach_command(
                c_transport.as_ref(),
                owner.config.telegram_group_id,
                owner.config.telegram_topic_id,
                b"original-password",
                false,
                c_volumes.path(),
                owner.config.sdo_owner_public_key.as_deref(),
            )
            .await
            .unwrap();
            let conn = open_sdo_mount_db(&mut c).unwrap();
            let builder = portable_mount_builder(&c, conn);
            let (fs, cursor) = prepare_sdo_mount(c_transport.clone(), &c, builder, Some(99))
                .await
                .unwrap();
            let (fs, notify) = start_prepared_sdo_mount_poller(
                fs,
                c_transport,
                &c,
                cursor,
                Arc::new(Mutex::new(None)),
            )
            .await
            .unwrap();
            let mountpoint = tempfile::tempdir().unwrap();
            let session = fuser::spawn_mount2(
                fs,
                mountpoint.path(),
                &[fuser::MountOption::FSName("teagarden-frozen-writer".into())],
            )
            .unwrap();
            let mut file =
                std::fs::File::create(mountpoint.path().join("legitimate-c.txt")).unwrap();
            file.write_all(b"safe").unwrap();
            file.sync_all().unwrap();
            drop(file);
            let (private, _) =
                load_or_create_device_keypair(&c.paths.base_dir, &c.hierarchy.wrapping).unwrap();
            let c_signer = teagarden_core::sdo::device_signing_key(&private.0);
            unsafe {
                std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
            }
            let password = f.cfg.path().join("password");
            std::fs::write(&password, "original-password").unwrap();
            let confirmed = confirmed_fixture_session_map(&f, target, 88).await;
            super::super::key::TEST_PORTABLE_TRANSPORT
                .scope(
                    f.mock.clone(),
                    revoke_device(
                        &f.id,
                        target,
                        Some(password.to_str().unwrap()),
                        None,
                        Some(88),
                        false,
                        Some(&confirmed),
                    ),
                )
                .await
                .unwrap();
            let (_, policy, policy_wire) = discover_latest_header(
                f.mock.as_ref(),
                owner.config.telegram_group_id,
                owner.config.telegram_topic_id,
                &owner.hierarchy.integrity,
                owner.config.sdo_owner_public_key.as_deref(),
            )
            .await
            .unwrap()
            .unwrap();
            let mut bad_versions = Vec::new();
            let mut bad_wires = Vec::new();
            for (path, signer) in [
                ("claimed-c-unsigned.txt", None),
                (
                    "claimed-c-wrong-key.txt",
                    Some(teagarden_core::sdo::SigningKey::from_bytes(&[99; 32])),
                ),
            ] {
                let mut m = legacy_v2_logical_metadata(
                    &teagarden_core::sdo::SdoObjectMetadata::test_fixture(),
                );
                m.file_id = uuid::Uuid::new_v4();
                m.version_id = uuid::Uuid::new_v4();
                bad_versions.push(m.version_id);
                m.author_device_id = c.config.sdo_author_device_id.unwrap();
                m.path = Some(path.into());
                m.size = 4;
                m.clock_ms = u64::MAX / 2;
                // The attacker has the unchanged root, but never C's signing key.
                let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
                    owner.config.volume_id,
                    0,
                    &owner.hierarchy.meta,
                    m,
                    b"evil",
                    signer.as_ref(),
                )
                .unwrap();
                bad_wires.push(wire.clone());
                f.mock
                    .upload_file_object(&wire, "renamed-injection.bin")
                    .await
                    .unwrap();
            }
            let mut newcomer =
                legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
            newcomer.file_id = uuid::Uuid::new_v4();
            newcomer.version_id = uuid::Uuid::new_v4();
            newcomer.author_device_id = uuid::Uuid::new_v4();
            newcomer.path = Some("new-unfrozen-author.txt".into());
            newcomer.size = 4;
            newcomer.clock_ms = 20;
            let wire = teagarden_core::sdo::SdoFileObjectV3::encode(
                owner.config.volume_id,
                0,
                &owner.hierarchy.meta,
                newcomer,
                b"new!",
            )
            .unwrap();
            f.mock
                .upload_file_object(&wire, "newcomer.bin")
                .await
                .unwrap();
            notify.notify_one();
            for _ in 0..100 {
                if mountpoint.path().join("new-unfrozen-author.txt").exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert_eq!(
                std::fs::read(mountpoint.path().join("new-unfrozen-author.txt")).unwrap(),
                b"new!"
            );
            for path in ["claimed-c-unsigned.txt", "claimed-c-wrong-key.txt"] {
                assert!(
                    !mountpoint.path().join(path).exists(),
                    "live reducer accepted a revoked-root writer impersonating frozen C: {path}"
                );
            }
            assert_eq!(
                std::fs::read(mountpoint.path().join("legitimate-c.txt")).unwrap(),
                b"safe"
            );
            assert_eq!(
                policy
                    .device_authorities
                    .get(&c.config.sdo_author_device_id.unwrap()),
                Some(&hex::encode(c_signer.verifying_key().to_bytes()))
            );
            assert!(policy
                .device_authorities
                .contains_key(&owner.config.sdo_author_device_id.unwrap()));
            drop(session);

            let fresh = tempfile::tempdir().unwrap();
            let attached = attach_command(
                f.mock.as_ref(),
                policy.group_id,
                policy.topic_id,
                b"original-password",
                false,
                fresh.path(),
                policy.owner_public_key.as_deref(),
            )
            .await
            .unwrap();
            let scan = scan_topic_sdo_objects(
                f.mock.as_ref(),
                policy.group_id,
                policy.topic_id,
                &policy,
                &attached.hierarchy,
            )
            .await
            .unwrap();
            assert!(
                scan.view.is_visible("legitimate-c.txt")
                    && scan.view.is_visible("new-unfrozen-author.txt")
            );
            assert!(
                !scan.view.is_visible("claimed-c-unsigned.txt")
                    && !scan.view.is_visible("claimed-c-wrong-key.txt")
            );
            super::super::history::TEST_VOLUMES_DIR
                .with(|path| *path.borrow_mut() = Some(fresh.path().to_path_buf()));
            super::super::history::TEST_TRANSPORT
                .with(|mock| *mock.borrow_mut() = Some(f.mock.clone()));
            super::super::history::run(&f.id, None, Some(password.to_str().unwrap()), None)
                .await
                .unwrap();
            for id in &bad_versions {
                assert!(super::super::history::restore_version(
                    &f.id,
                    "forged-restore.txt",
                    &id.to_string(),
                    Some(password.to_str().unwrap()),
                    None
                )
                .await
                .is_err());
            }
            assert!(super::super::history::diff(
                &f.id,
                &bad_versions[0].to_string(),
                &bad_versions[1].to_string(),
                Some(password.to_str().unwrap()),
                None
            )
            .await
            .is_err());
            super::super::history::TEST_VOLUMES_DIR.with(|path| *path.borrow_mut() = None);
            super::super::history::TEST_TRANSPORT.with(|mock| *mock.borrow_mut() = None);
            unsafe {
                std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
            }
            let export = fresh.path().join("export");
            super::super::key::TEST_PORTABLE_TRANSPORT
                .scope(
                    f.mock.clone(),
                    export_objects(&f.id, &export, Some(password.to_str().unwrap()), None),
                )
                .await
                .unwrap();
            let recovered = fresh.path().join("recovered");
            super::super::decrypt::run(
                &export,
                Some(&recovered),
                Some(password.to_str().unwrap()),
                None,
                None,
                policy.owner_public_key.as_deref(),
                false,
            )
            .unwrap();
            assert_eq!(
                std::fs::read(recovered.join("legitimate-c.txt")).unwrap(),
                b"safe"
            );
            assert_eq!(
                std::fs::read(recovered.join("new-unfrozen-author.txt")).unwrap(),
                b"new!"
            );
            assert!(
                !recovered.join("claimed-c-unsigned.txt").exists()
                    && !recovered.join("claimed-c-wrong-key.txt").exists()
            );
            let raw = fresh.path().join("raw-forgeries");
            std::fs::create_dir(&raw).unwrap();
            std::fs::write(raw.join("policy.tgh"), policy_wire).unwrap();
            for (i, wire) in bad_wires.iter().enumerate() {
                std::fs::write(raw.join(format!("forged-{i}.tgf")), wire).unwrap();
            }
            for include in [true, false] {
                let out = fresh.path().join(format!("refused-forgeries-{include}"));
                let error = super::super::decrypt::run(
                    &raw,
                    Some(&out),
                    Some(password.to_str().unwrap()),
                    None,
                    None,
                    policy.owner_public_key.as_deref(),
                    include,
                )
                .expect_err(
                    "unverified recovery must never bypass a frozen installation's signing key",
                );
                let message = format!("{error:#}");
                assert!(
                    message.contains("2 object(s)") && message.contains("installation signing"),
                    "{message}"
                );
                assert!(!out.exists());
            }
        });
    }

    #[tokio::test]
    async fn round3_int_n3_unsigned_registry_refuses_before_access_cut() {
        let f = Round2Fixture::new().await;
        let target = cut_only_target(&f, Some("88")).await;
        let opened = f.open(b"original-password");
        let unsigned = uuid::Uuid::new_v4();
        let mut m =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        m.version_id = uuid::Uuid::new_v4();
        m.author_device_id = unsigned;
        m.installation_id = Some(unsigned);
        m.path = None;
        m.kind = teagarden_core::sdo::SdoKind::Device;
        m.label = Some("unsigned registry evidence".into());
        m.telegram_user_id = Some(12345);
        m.authorization_session_hash = Some("99".into());
        m.created_at_ms = Some(1);
        m.size = 0;
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode(
            opened.config.volume_id,
            0,
            &opened.hierarchy.meta,
            m,
            &[],
        )
        .unwrap();
        f.mock
            .upload_file_object(&wire, "unsigned-registry.bin")
            .await
            .unwrap();
        let error = revoke_fixture_target(&f, &opened, target, 88)
            .await
            .expect_err(
                "revoke must never silently omit a registered survivor from the signer freeze",
            );
        assert!(
            format!("{error:#}").contains("no authenticated installation signing key"),
            "{error:#}"
        );
        assert!(!f.mock.forum_calls().iter().any(|call| matches!(
            call,
            teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
                | teagarden_telegram::mock::ForumCall::BanMember { .. }
        )));
        assert_eq!(
            f.open(b"original-password")
                .config
                .sdo_header_revision_published,
            1
        );
    }

    #[test]
    fn round4_final_n2_exported_master_root_opens_decrypt_and_attach() {
        const EXPORT: &str = "TEAGARDEN_R4_ROOT_EXPORT_CHILD";
        if let Ok(id) = std::env::var(EXPORT) {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(super::super::key::export(
                    &id,
                    Some(std::env::var("TEAGARDEN_R4_PASSWORD").unwrap().as_str()),
                    None,
                ))
                .unwrap();
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let volumes = tempfile::tempdir().unwrap();
            let cfg = tempfile::tempdir().unwrap();
            let mock = Arc::new(MockTransport::new_unbound());
            let (id, _) = create_command(mock.as_ref(), &cfg.path().join("group.json"), volumes.path(), "exported-master-root", "original-password", None, true, None).await.unwrap();
            let password = cfg.path().join("password");
            std::fs::write(&password, "original-password").unwrap();
            let opened = teagarden_mfa::unlock::open_volume(&id, &teagarden_mfa::unlock::UnlockInputs { password: Some(b"original-password"), ..Default::default() }, volumes.path()).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::volume::tests::round4_final_n2_exported_master_root_opens_decrypt_and_attach", "--nocapture"])
                .env(EXPORT, &id).env("TEAGARDEN_VOLUMES_DIR", volumes.path()).env("TEAGARDEN_CONFIG_DIR", cfg.path())
                .env("TEAGARDEN_R4_PASSWORD", &password).output().unwrap();
            assert!(output.status.success(), "real key export failed: {}", String::from_utf8_lossy(&output.stderr));
            let stdout = String::from_utf8(output.stdout).unwrap();
            let sentence = stdout.lines().find(|line| line.starts_with("  ") && line.split_whitespace().count() == 22).expect("key export must print its actual root sentence").trim();
            let recovery = cfg.path().join("exported-root");
            std::fs::write(&recovery, sentence).unwrap();
            let local = teagarden_mfa::unlock::open_volume(&id, &teagarden_mfa::unlock::UnlockInputs { recovery_sentence: Some(sentence), ..Default::default() }, volumes.path()).unwrap();
            assert_eq!(local.hierarchy.root.as_bytes(), opened.hierarchy.root.as_bytes());
            let (_, header, header_wire) = discover_latest_header(mock.as_ref(), opened.config.telegram_group_id, opened.config.telegram_topic_id, &opened.hierarchy.integrity, opened.config.sdo_owner_public_key.as_deref()).await.unwrap().unwrap();
            assert_eq!(header.root_kind, RootKind::MasterKey);
            let mut metadata = legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
            metadata.path = Some("protected.txt".into());
            metadata.size = 4;
            let wire = teagarden_core::sdo::SdoFileObjectV3::encode(header.volume_id, 0, &opened.hierarchy.meta, metadata, b"root").unwrap();
            let wire = teagarden_core::sdo::ObjectEnvelope::seal(&wire, &header_wire, &opened.hierarchy).unwrap();
            let objects = cfg.path().join("objects");
            std::fs::create_dir(&objects).unwrap();
            std::fs::write(objects.join("header.tgh"), &header_wire).unwrap();
            std::fs::write(objects.join("protected.tgf"), &wire).unwrap();
            mock.upload_file_object(&wire, "teagarden-file-v3.tgf").await.unwrap();
            let mut errors = Vec::new();
            for (name, input) in [("standalone", objects.join("protected.tgf")), ("directory", objects.clone())] {
                let out = cfg.path().join(name);
                match super::super::decrypt::run(&input, Some(&out), None, Some(recovery.to_str().unwrap()), None, header.owner_public_key.as_deref(), false) {
                    Ok(()) => assert_eq!(std::fs::read(out.join("protected.txt")).unwrap(), b"root"),
                    Err(error) => errors.push(format!("{name} rejected key export root: {error:#}")),
                }
            }
            let fresh = tempfile::tempdir().unwrap();
            match attach_command(mock.as_ref(), header.group_id, header.topic_id, sentence.as_bytes(), true, fresh.path(), header.owner_public_key.as_deref()).await {
                Ok(mut attached) => {
                    assert_eq!(attached.hierarchy.root.as_bytes(), opened.hierarchy.root.as_bytes());
                    let conn = open_sdo_mount_db(&mut attached).unwrap();
                    let builder = portable_mount_builder(&attached, conn);
                    prepare_sdo_mount(mock.clone(), &attached, builder, Some(77)).await.unwrap();
                }
                Err(error) => errors.push(format!("attach rejected key export root: {error:#}")),
            }
            assert!(errors.is_empty(), "{}", errors.join("; "));
            let wrong = teagarden_core::sentence::encode::encode_ref_string(&[9; 32], &teagarden_core::sentence::wordlists::production_wordlists()).unwrap();
            let wrong_file = cfg.path().join("wrong-root");
            std::fs::write(&wrong_file, &wrong).unwrap();
            let out = cfg.path().join("wrong-output");
            assert!(super::super::decrypt::run(&objects.join("protected.tgf"), Some(&out), None, Some(wrong_file.to_str().unwrap()), None, header.owner_public_key.as_deref(), false).is_err());
            assert!(!out.exists());
            let rejected = tempfile::tempdir().unwrap();
            assert!(attach_command(mock.as_ref(), header.group_id, header.topic_id, wrong.as_bytes(), true, rejected.path(), header.owner_public_key.as_deref()).await.is_err());
            assert_eq!(std::fs::read_dir(rejected.path()).unwrap().count(), 0);
        });
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn round4_final_n3_plaintext_boundary_fits_real_transport_cap() {
        let f = Round2Fixture::new().await;
        let mut errors = Vec::new();
        for (premium, limit) in [
            (false, teagarden_core::sdo::MAX_SDO_FILE_BYTES),
            (true, teagarden_core::sdo::MAX_SDO_FILE_BYTES_PREMIUM),
        ] {
            let mut opened = f.open(b"original-password");
            let conn = open_sdo_mount_db(&mut opened).unwrap();
            let builder = portable_mount_builder(&opened, conn).with_sdo_file_limit(limit);
            let (fs, _) = prepare_sdo_mount(f.mock.clone(), &opened, builder, Some(77))
                .await
                .unwrap();
            let mountpoint = tempfile::tempdir().unwrap();
            let session = fuser::spawn_mount2(
                fs,
                mountpoint.path(),
                &[fuser::MountOption::FSName("teagarden-size-boundary".into())],
            )
            .unwrap();
            let file = std::fs::File::create(mountpoint.path().join("boundary.txt")).unwrap();
            assert_eq!(
                file.set_len(limit + 1).unwrap_err().raw_os_error(),
                Some(libc::EFBIG)
            );
            drop(file);
            drop(session);
            // Production bounds: complete v3 encrypted header, maximum TGFE
            // JSON and trailer, and one authentication tag per content segment.
            let maximum_wire = teagarden_core::sdo::sdo_v3_upload_bound(limit).unwrap();
            let next = teagarden_core::sdo::sdo_v3_upload_bound(limit + 1).unwrap();
            assert!(
                teagarden_telegram::client::check_file_object_size(next as usize, premium).is_err(),
                "the documented maximum must be the exact boundary for the reserved format budget"
            );
            if let Err(error) =
                teagarden_telegram::client::check_file_object_size(maximum_wire as usize, premium)
            {
                errors.push(format!("premium={premium}, accepted plaintext={limit}, maximum wire={maximum_wire}: {error}"));
            }
            let cap = teagarden_telegram::client::file_object_upload_limit(premium);
            assert!(teagarden_telegram::client::check_file_object_size(cap + 1, premium).is_err());
        }
        assert!(
            errors.is_empty(),
            "accepted plaintext must reserve the full TGFV3 and TGFE overhead: {}",
            errors.join("; ")
        );
    }

    #[cfg(target_os = "linux")]
    fn round4_software_factor() -> teagarden_mfa::unlock::EnrollFactor {
        teagarden_mfa::unlock::EnrollFactor::Test(Box::new(
            teagarden_mfa::kslot::protectors::PassphraseProtector::new(
                b"independent software slot".to_vec(),
                teagarden_mfa::kslot::protectors::Argon2Cost {
                    m_kib: 1024,
                    t: 1,
                    p: 1,
                },
            ),
        ))
    }

    #[cfg(target_os = "linux")]
    fn round4_assert_slot_policy(mut actual: HeaderDocument, baseline: &HeaderDocument) {
        actual.revision = baseline.revision;
        actual.slot_vault = baseline.slot_vault.clone();
        actual.key_protection = baseline.key_protection.clone();
        assert_eq!(
            &actual, baseline,
            "slot publication must preserve all other owner-signed policy fields"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round4_final_n1_enroll_publishes_and_mount_retries_exact_tghd2() {
        round4_slot_command_lifecycle(false);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round4_final_n1_remove_publishes_and_mount_retries_exact_tghd2() {
        round4_slot_command_lifecycle(true);
    }

    #[cfg(target_os = "linux")]
    fn round4_slot_command_lifecycle(remove: bool) {
        const CHILD: &str = "TEAGARDEN_R4_SLOT_LIFECYCLE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let name = if remove {
                "commands::volume::tests::round4_final_n1_remove_publishes_and_mount_retries_exact_tghd2"
            } else {
                "commands::volume::tests::round4_final_n1_enroll_publishes_and_mount_retries_exact_tghd2"
            };
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let f = round4_protected_fixture().await;
            unsafe { std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path()); }
            let password = f.cfg.path().join("password"); std::fs::write(&password,"original-password").unwrap();
            let mut owner = f.open(b"original-password");
            let conn = open_sdo_mount_db(&mut owner).unwrap(); let builder = portable_mount_builder(&owner,conn);
            drop(prepare_sdo_mount(f.mock.clone(),&owner,builder,Some(77)).await.unwrap());
            let c_dir = tempfile::tempdir().unwrap();
            let mut c = attach_command(f.mock.as_ref(), owner.config.telegram_group_id, owner.config.telegram_topic_id, b"original-password", false, c_dir.path(), owner.config.sdo_owner_public_key.as_deref()).await.unwrap();
            let conn = open_sdo_mount_db(&mut c).unwrap(); let builder = portable_mount_builder(&c,conn);
            drop(prepare_sdo_mount(f.mock.clone(),&c,builder,Some(99)).await.unwrap());
            let target = cut_only_target(&f,Some("88")).await;
            let confirmed = confirmed_fixture_session_map(&f, target, 88).await;
            super::super::key::TEST_PORTABLE_TRANSPORT.scope(f.mock.clone(),revoke_device(&f.id,target,Some(password.to_str().unwrap()),None,Some(88),false,Some(&confirmed))).await.unwrap();
            let (_,baseline,_) = discover_latest_header(f.mock.as_ref(),owner.config.telegram_group_id,owner.config.telegram_topic_id,&owner.hierarchy.integrity,owner.config.sdo_owner_public_key.as_deref()).await.unwrap().unwrap();
            assert!(baseline.revoked_device_ids.contains(&target)); assert_eq!(baseline.device_authorities.len(),2);
            let vault_path = owner.paths.base_dir.join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
            if remove {
                let slot = teagarden_mfa::kslot::SlotVault::load(&vault_path).unwrap().slots().into_iter().find(|slot| slot.slot_type == teagarden_mfa::kslot::SlotType::Recovery).unwrap().slot_id;
                super::super::key::TEST_PORTABLE_TRANSPORT.scope(f.mock.clone(),super::super::mfa::remove_slot(&f.id,slot,FactorSelect::default(),Some(password.to_str().unwrap()),None,true)).await.expect("real remove-slot must publish the complete TGHD2 slot update");
            } else {
                super::super::mfa::TEST_ENROLL_FACTOR.with(|factor| *factor.borrow_mut()=Some(round4_software_factor()));
                super::super::key::TEST_PORTABLE_TRANSPORT.scope(f.mock.clone(),super::super::mfa::enroll(&f.id,FactorSelect{tang:Some("test://software-slot-provider".into()),..Default::default()},Some(password.to_str().unwrap()),None)).await.expect("real enroll must publish the complete TGHD2 slot update");
            }
            let (_,normal,_) = discover_latest_header(f.mock.as_ref(),baseline.group_id,baseline.topic_id,&owner.hierarchy.integrity,baseline.owner_public_key.as_deref()).await.unwrap().unwrap();
            assert_eq!(normal.revision,baseline.revision+1); round4_assert_slot_policy(normal.clone(),&baseline);
            assert!(!f.open(b"original-password").config.sdo_header_pending);
            // For each command, create a second mutation whose upload is refused
            // before storage, so mount must use the durable exact retry bytes.
            if remove {
                super::super::mfa::TEST_ENROLL_FACTOR.with(|factor| *factor.borrow_mut()=Some(round4_software_factor()));
                super::super::key::TEST_PORTABLE_TRANSPORT.scope(f.mock.clone(),super::super::mfa::enroll(&f.id,FactorSelect{tang:Some("test://software-slot-provider".into()),..Default::default()},Some(password.to_str().unwrap()),None)).await.unwrap();
            }
            *f.mock.fail_uploads.lock().unwrap()=Some("test publication outage".into());
            let failure = if remove {
                let slot=teagarden_mfa::kslot::SlotVault::load(&vault_path).unwrap().slots().into_iter().map(|s|s.slot_id).max().unwrap();
                super::super::key::TEST_PORTABLE_TRANSPORT.scope(f.mock.clone(),super::super::mfa::remove_slot(&f.id,slot,FactorSelect::default(),Some(password.to_str().unwrap()),None,true)).await
            } else {
                super::super::mfa::TEST_ENROLL_FACTOR.with(|factor| *factor.borrow_mut()=Some(round4_software_factor()));
                super::super::key::TEST_PORTABLE_TRANSPORT.scope(f.mock.clone(),super::super::mfa::enroll(&f.id,FactorSelect{tang:Some("test://software-slot-provider".into()),..Default::default()},Some(password.to_str().unwrap()),None)).await
            };
            assert!(failure.is_err()); *f.mock.fail_uploads.lock().unwrap()=None;
            let mut pending=f.open(b"original-password"); assert!(pending.config.sdo_header_pending);
            let retry=hex::decode(pending.config.sdo_header_pending_bytes.as_ref().expect("slot producer must persist the exact signed retry bytes")).unwrap();
            let intended=HeaderDocument::decode_pinned(&retry,&pending.hierarchy.integrity,baseline.owner_public_key.as_deref()).unwrap();
            assert_eq!(intended.format,2); round4_assert_slot_policy(intended.clone(),&baseline);
            assert_eq!(pending.config.sdo_header_pending_sha256,Some(hex::encode(teagarden_core::block::srb2::sha256(&retry))));
            let _mount_lock=manager::VolumeLock::acquire_exclusive(&pending.paths.base_dir).unwrap();
            let conn=open_sdo_mount_db(&mut pending).unwrap(); let builder=portable_mount_builder(&pending,conn);
            let (fs,_)=prepare_sdo_mount(f.mock.clone(),&pending,builder,Some(77)).await.expect("mount preparation must consume pending slot bytes before readiness");
            let mountpoint=tempfile::tempdir().unwrap(); let session=fuser::spawn_mount2(fs,mountpoint.path(),&[fuser::MountOption::FSName("teagarden-slot-repair".into())]).unwrap();
            assert!(!f.open(b"original-password").config.sdo_header_pending);
            let (_,repaired,repaired_wire)=discover_latest_header(f.mock.as_ref(),baseline.group_id,baseline.topic_id,&owner.hierarchy.integrity,baseline.owner_public_key.as_deref()).await.unwrap().unwrap();
            assert_eq!(repaired_wire,retry,"mount must upload the reserved exact TGHD2, never reconstruct a TGHD1 or reset owner policy"); round4_assert_slot_policy(repaired,&baseline);
            let mut file=std::fs::File::create(mountpoint.path().join("after-slot-repair.txt")).unwrap(); file.write_all(b"mounted slot repair").unwrap(); file.sync_all().unwrap(); drop(file);
            assert_eq!(std::fs::read(mountpoint.path().join("after-slot-repair.txt")).unwrap(),b"mounted slot repair");
            drop(session); drop(_mount_lock);
            let fresh=tempfile::tempdir().unwrap();
            let attached=attach_command(f.mock.as_ref(),baseline.group_id,baseline.topic_id,b"original-password",false,fresh.path(),baseline.owner_public_key.as_deref()).await.unwrap();
            let scan=scan_topic_sdo_objects(f.mock.as_ref(),baseline.group_id,baseline.topic_id,&intended,&attached.hierarchy).await.unwrap(); assert!(scan.view.is_visible("after-slot-repair.txt"));
            // Attached installations do not inherit the owner capability. Refuse
            // global slot mutation before either local vault or policy changes.
            unsafe { std::env::set_var("TEAGARDEN_VOLUMES_DIR",fresh.path()); }
            let before_config=std::fs::read(&attached.paths.config_path).unwrap(); let before_vault=std::fs::read(attached.paths.base_dir.join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME)).unwrap();
            super::super::mfa::TEST_ENROLL_FACTOR.with(|factor| *factor.borrow_mut()=Some(round4_software_factor()));
            let denied=super::super::key::TEST_PORTABLE_TRANSPORT.scope(f.mock.clone(),super::super::mfa::enroll(&f.id,FactorSelect{tang:Some("test://software-slot-provider".into()),..Default::default()},Some(password.to_str().unwrap()),None)).await.expect_err("non-owner slot changes must refuse before mutation");
            assert!(format!("{denied:#}").contains("owner")); assert_eq!(std::fs::read(&attached.paths.config_path).unwrap(),before_config); assert_eq!(std::fs::read(attached.paths.base_dir.join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME)).unwrap(),before_vault);
        });
    }

    async fn round4_protected_fixture() -> Round2Fixture {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockTransport::new_unbound());
        let (id, _) = create_command(
            mock.as_ref(),
            &cfg.path().join("group.json"),
            volumes.path(),
            "round-four",
            "original-password",
            None,
            true,
            None,
        )
        .await
        .unwrap();
        Round2Fixture {
            volumes,
            cfg,
            mock,
            id,
        }
    }

    struct Round4SlotGate {
        inner: teagarden_mfa::kslot::protectors::PassphraseProtector,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }
    impl teagarden_mfa::kslot::protector::SlotProtector for Round4SlotGate {
        fn slot_type(&self) -> teagarden_mfa::kslot::SlotType {
            teagarden_mfa::kslot::protector::SlotProtector::slot_type(&self.inner)
        }
        fn enroll(
            &mut self,
        ) -> teagarden_mfa::error::Result<teagarden_mfa::kslot::protector::Enrollment> {
            self.entered.notify_one();
            let (lock, ready) = &*self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = ready.wait(released).unwrap();
            }
            teagarden_mfa::kslot::protector::SlotProtector::enroll(&mut self.inner)
        }
        fn recover_kek(
            &self,
            params: &serde_json::Value,
            transport: &teagarden_mfa::kslot::protector::KekTransport,
        ) -> teagarden_mfa::error::Result<teagarden_mfa::kslot::types::Kek> {
            teagarden_mfa::kslot::protector::SlotProtector::recover_kek(
                &self.inner,
                params,
                transport,
            )
        }
    }

    #[test]
    fn round4_final_n4_slot_read_cannot_race_owner_policy_writers() {
        const CHILD: &str = "TEAGARDEN_R4_SLOT_RACE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", "commands::volume::tests::round4_final_n4_slot_read_cannot_race_owner_policy_writers", "--nocapture"]).env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let f = round4_protected_fixture().await;
                let target = cut_only_target(&f, Some("88")).await;
                let mut old = f.open(b"original-password");
                unsafe {
                    std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
                }
                let password = f.cfg.path().join("password");
                std::fs::write(&password, "original-password").unwrap();
                let entered = Arc::new(tokio::sync::Notify::new());
                let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
                let provider = Round4SlotGate {
                    inner: teagarden_mfa::kslot::protectors::PassphraseProtector::new(
                        b"independent software factor".to_vec(),
                        teagarden_mfa::kslot::protectors::Argon2Cost {
                            m_kib: 1024,
                            t: 1,
                            p: 1,
                        },
                    ),
                    entered: entered.clone(),
                    release: release.clone(),
                };
                let transport = f.mock.clone();
                let id = f.id.clone();
                let pw = password.to_str().unwrap().to_owned();
                let slot = tokio::spawn(async move {
                    super::super::mfa::TEST_ENROLL_FACTOR.with(|factor| {
                        *factor.borrow_mut() = Some(teagarden_mfa::unlock::EnrollFactor::Test(
                            Box::new(provider),
                        ))
                    });
                    super::super::key::TEST_PORTABLE_TRANSPORT
                        .scope(
                            transport,
                            super::super::mfa::enroll(
                                &id,
                                FactorSelect {
                                    tang: Some("test://injected-software-protector".into()),
                                    ..Default::default()
                                },
                                Some(&pw),
                                None,
                            ),
                        )
                        .await
                });
                tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
                    .await
                    .expect(
                        "slot producer reads and authenticates old config before the interleaving",
                    );
                let confirmed = confirmed_fixture_session_map(&f, target, 88).await;
                let revoke = super::super::key::TEST_PORTABLE_TRANSPORT
                    .scope(
                        f.mock.clone(),
                        revoke_device(
                            &f.id,
                            target,
                            Some(password.to_str().unwrap()),
                            None,
                            Some(88),
                            false,
                            Some(&confirmed),
                        ),
                    )
                    .await;
                let publication = publish_slot_header_update(f.mock.as_ref(), &old).await;
                old.config.display_name = "stale config must never overwrite policy".into();
                let write = manager::save_config_resealed(
                    &mut old.config,
                    &old.hierarchy,
                    &old.paths.config_path,
                );
                {
                    let (lock, ready) = &*release;
                    *lock.lock().unwrap() = true;
                    ready.notify_all();
                }
                let slot_result = slot.await.unwrap();
                for (name, result) in [
                    ("revoke", revoke),
                    ("publication", publication),
                    ("config writer", write.map_err(anyhow::Error::from)),
                ] {
                    let error = result.expect_err(&format!(
                        "{name} must refuse while the slot transaction owns administration"
                    ));
                    assert!(
                        format!("{error:#}").contains("owner administration"),
                        "{name}: {error:#}"
                    );
                }
                if let Err(error) = slot_result {
                    // FINAL-N1 is a separate pending-state producer fix; this test
                    // checks serialization even if that publication still refuses.
                    assert!(
                        format!("{error:#}")
                            .contains("pending owner header has no durable retry bytes"),
                        "{error:#}"
                    );
                }
                assert!(!f.mock.forum_calls().iter().any(|call| matches!(
                    call,
                    teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
                )));
                let latest = f.open(b"original-password");
                let vault = teagarden_mfa::kslot::SlotVault::load(
                    latest
                        .paths
                        .base_dir
                        .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME),
                )
                .unwrap();
                assert_eq!(
                    latest.config.key_protection.unwrap().vault_digest,
                    hex::encode(vault.state_digest())
                );
                assert_ne!(
                    latest.config.display_name,
                    "stale config must never overwrite policy"
                );
            });
    }

    #[test]
    fn round4_final_n4_delete_cannot_cross_pending_publication() {
        const CHILD: &str = "TEAGARDEN_R4_DELETE_RACE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", "commands::volume::tests::round4_final_n4_delete_cannot_cross_pending_publication", "--nocapture"]).env(CHILD, "1").output().unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| !line.starts_with("New volume recovery sentence"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(output.status.success(), "{diagnostic}");
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let f = Round2Fixture::new().await;
            let target = cut_only_target(&f, Some("88")).await;
            unsafe {
                std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
            }
            let password = f.cfg.path().join("password");
            std::fs::write(&password, "original-password").unwrap();
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            f.mock
                .gate_next_upload("teagarden-header-v1.tgh", entered.clone(), release.clone());
            let id = f.id.clone();
            let pw = password.to_str().unwrap().to_owned();
            let transport = f.mock.clone();
            let confirmed = confirmed_fixture_session_map(&f, target, 88).await;
            let revoke = tokio::spawn(async move {
                super::super::key::TEST_PORTABLE_TRANSPORT
                    .scope(
                        transport,
                        revoke_device(
                            &id,
                            target,
                            Some(&pw),
                            None,
                            Some(88),
                            false,
                            Some(&confirmed),
                        ),
                    )
                    .await
            });
            tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
                .await
                .unwrap();
            let deletion = delete_in(
                f.volumes.path(),
                &f.id,
                true,
                Some(password.to_str().unwrap()),
                None,
                true,
                Box::new(|_| Box::pin(async { panic!("local deletion must never connect") })),
            )
            .await;
            release.notify_one();
            let publication = revoke.await.unwrap();
            let error = deletion.expect_err(
                "delete must not unlink config or its lock while an owner publication is pending",
            );
            assert!(
                format!("{error:#}").contains("owner administration"),
                "{error:#}"
            );
            publication.unwrap();
            assert!(!f.open(b"original-password").config.sdo_header_pending);
        });
    }

    async fn cut_only_target(f: &Round2Fixture, binding: Option<&str>) -> uuid::Uuid {
        let opened = f.open(b"original-password");
        let target = uuid::Uuid::new_v4();
        let mut metadata =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        metadata.version_id = uuid::Uuid::new_v4();
        metadata.kind = teagarden_core::sdo::SdoKind::Device;
        metadata.path = None;
        metadata.author_device_id = target;
        metadata.installation_id = Some(target);
        metadata.label = Some("Cut target".into());
        metadata.telegram_user_id = Some(12345);
        metadata.authorization_session_hash = binding.map(str::to_owned);
        metadata.created_at_ms = Some(1);
        let signer = teagarden_core::sdo::SigningKey::from_bytes(&[96; 32]);
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
            opened.config.volume_id,
            0,
            &opened.hierarchy.meta,
            metadata,
            &[],
            Some(&signer),
        )
        .unwrap();
        f.mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        target
    }

    async fn confirmed_fixture_session_map(
        f: &Round2Fixture,
        target: uuid::Uuid,
        target_hash: i64,
    ) -> PathBuf {
        let opened = f.open(b"original-password");
        bind_opened_topic(f.mock.as_ref(), &opened.config)
            .await
            .unwrap();
        let (_, header, _) = discover_latest_header(
            f.mock.as_ref(),
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &opened.hierarchy.integrity,
            opened.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        let scan = scan_topic_sdo_objects(
            f.mock.as_ref(),
            header.group_id,
            header.topic_id,
            &header,
            &opened.hierarchy,
        )
        .await
        .unwrap();
        let mut bindings = vec![(target, target_hash)];
        for (id, entry) in scan.registry.iter() {
            if *id == target
                || Some(*id) == opened.config.sdo_author_device_id
                || entry.telegram_user_id != 12345
            {
                continue;
            }
            let hash = entry
                .authorization_session_hash
                .as_deref()
                .and_then(parse_authorization_hash)
                .expect("fixture peers have an independently verified nonzero authorization");
            bindings.push((*id, hash));
        }
        let rows: Vec<_> = bindings
            .into_iter()
            .map(|(id, hash)| {
                if hash != 88 {
                    let mut extras = f.mock.extra_authorizations.lock().unwrap();
                    if !extras.iter().any(|entry| entry.hash == hash) {
                        extras.push(teagarden_telegram::client::TelegramAuthorizationInfo {
                            hash,
                            current: false,
                            device_model: "Synthetic fixture installation".into(),
                            app_name: "test".into(),
                            date_active: 1,
                        });
                    }
                }
                serde_json::json!({
                    "installation_id": id,
                    "authorization_hash": hash.to_string(),
                })
            })
            .collect();
        let path = f.cfg.path().join(format!("confirmed-{target}.json"));
        std::fs::write(&path, serde_json::to_vec(&rows).unwrap()).unwrap();
        path
    }

    async fn revoke_fixture_target(
        f: &Round2Fixture,
        opened: &manager::OpenVolumeResult,
        target: uuid::Uuid,
        target_hash: i64,
    ) -> Result<()> {
        let path = confirmed_fixture_session_map(f, target, target_hash).await;
        let admin = manager::OwnerAdminLock::acquire(&opened.paths.base_dir)?;
        revocation::command_in_transaction(
            f.mock.clone(),
            opened,
            target,
            Some(target_hash),
            false,
            &revocation::load_confirmed_session_map(&path)?,
            &admin,
        )
        .await
    }

    #[test]
    fn release_1_0_reset_all_requires_explicit_yes() {
        const CHILD: &str = "TEAGARDEN_CUT_ALL_CHILD";
        if std::env::var_os(CHILD).is_none() {
            use std::process::{Command, Stdio};
            for answer in ["NO", "YES"] {
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "commands::volume::tests::release_1_0_reset_all_requires_explicit_yes",
                        "--nocapture",
                    ])
                    .env(CHILD, answer)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                writeln!(child.stdin.take().unwrap(), "{answer}").unwrap();
                let output = child.wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let f = Round2Fixture::new().await;
            let target = cut_only_target(&f, Some("88")).await;
            unsafe {
                std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
            }
            let password = f.cfg.path().join("password");
            std::fs::write(&password, "original-password").unwrap();
            let result = super::super::key::TEST_PORTABLE_TRANSPORT
                .scope(
                    f.mock.clone(),
                    revoke_device(
                        &f.id,
                        target,
                        Some(password.to_str().unwrap()),
                        None,
                        None,
                        true,
                        None,
                    ),
                )
                .await;
            let accepted = std::env::var(CHILD).unwrap() == "YES";
            if accepted {
                result.unwrap();
            } else {
                assert!(format!("{:#}", result.unwrap_err()).contains("confirmation declined"));
            }
            assert_eq!(
                f.mock
                    .forum_calls()
                    .iter()
                    .filter(|call| matches!(
                        call,
                        teagarden_telegram::mock::ForumCall::ResetOtherAuthorizations
                    ))
                    .count(),
                usize::from(accepted)
            );
        });
    }

    #[tokio::test]
    async fn release_1_0_reset_all_cannot_cut_an_unbound_or_shared_authorization() {
        for (binding, diagnostic) in [
            (None, "cannot safely identify"),
            (Some("77"), "cannot revoke the owner's current"),
        ] {
            let f = Round2Fixture::new().await;
            let target = cut_only_target(&f, binding).await;
            let opened = f.open(b"original-password");
            let before = f.mock.message_count();
            let error = revocation::command(f.mock.clone(), &opened, target, None, true)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains(diagnostic));
            assert_eq!(f.mock.message_count(), before);
            assert!(!f.mock.forum_calls().iter().any(|call| matches!(
                call,
                teagarden_telegram::mock::ForumCall::ResetOtherAuthorizations
            )));
        }
    }

    #[tokio::test]
    async fn release_1_0_revoke_keeps_active_installations_with_a_shared_target_authorization() {
        let f = Round2Fixture::new().await;
        let target = cut_only_target(&f, Some("88")).await;
        let peer = cut_only_target(&f, Some("88")).await;
        assert_ne!(target, peer);
        let opened = f.open(b"original-password");
        let before = f.mock.message_count();

        let error = revocation::command(f.mock.clone(), &opened, target, None, false)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("shares its Telegram authorization"));
        assert_eq!(f.mock.message_count(), before);
        assert!(!f.mock.forum_calls().iter().any(|call| matches!(
            call,
            teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
                | teagarden_telegram::mock::ForumCall::ResetOtherAuthorizations
        )));
        assert!(!opened
            .paths
            .base_dir
            .join(format!("owner-access-cut-{target}.json"))
            .exists());
    }

    #[tokio::test]
    async fn release_1_0_revoke_refuses_to_reset_an_unconfirmed_legacy_binding() {
        use teagarden_telegram::mock::ForumCall;

        let f = Round2Fixture::new().await;
        let target = cut_only_target(&f, Some("88")).await;
        let opened = f.open(b"original-password");
        let before = f.mock.message_count();
        let error = revocation::command(f.mock.clone(), &opened, target, Some(88), false)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("fresh owner-confirmed session map"));
        assert_eq!(f.mock.message_count(), before);
        assert!(!f.mock.forum_calls().iter().any(|call| matches!(
            call,
            ForumCall::ResetAuthorization { .. } | ForumCall::ResetOtherAuthorizations
        )));
        assert!(!opened
            .paths
            .base_dir
            .join(format!("owner-access-cut-{target}.json"))
            .exists());
    }

    #[tokio::test]
    async fn release_1_0_revoke_uses_owner_confirmed_bindings_for_masked_authorizations() {
        use teagarden_telegram::mock::ForumCall;

        let f = Round2Fixture::new().await;
        let target = cut_only_target(&f, Some("0")).await;
        let survivor = cut_only_target(&f, Some("111")).await;
        f.mock.extra_authorizations.lock().unwrap().push(
            teagarden_telegram::client::TelegramAuthorizationInfo {
                hash: 99,
                current: false,
                device_model: "surviving installation".into(),
                app_name: "test".into(),
                date_active: 1,
            },
        );
        let opened = f.open(b"original-password");
        let admin = manager::OwnerAdminLock::acquire(&opened.paths.base_dir).unwrap();
        let map = f.cfg.path().join("confirmed-sessions.json");
        let write_bindings = |bindings: &[(uuid::Uuid, &str)]| {
            let bindings: Vec<_> = bindings
                .iter()
                .map(|(id, hash)| {
                    serde_json::json!({
                        "installation_id": id,
                        "authorization_hash": hash,
                    })
                })
                .collect();
            std::fs::write(&map, serde_json::to_vec(&bindings).unwrap()).unwrap();
        };
        for invalid in [&[(target, "0")][..], &[(target, "88"), (survivor, "88")]] {
            write_bindings(invalid);
            assert!(revocation::load_confirmed_session_map(&map).is_err());
        }
        for invalid_previous in ["0", "88"] {
            let ambiguous = serde_json::json!([
                {"installation_id": target, "authorization_hash": "88"},
                {"installation_id": survivor, "authorization_hash": "99", "previous_authorization_hash": invalid_previous}
            ]);
            std::fs::write(&map, serde_json::to_vec(&ambiguous).unwrap()).unwrap();
            assert!(revocation::load_confirmed_session_map(&map).is_err());
        }
        write_bindings(&[(target, "88")]);
        let before = f.mock.message_count();
        let error = revocation::command_in_transaction(
            f.mock.clone(),
            &opened,
            target,
            Some(88),
            false,
            &revocation::load_confirmed_session_map(&map).unwrap(),
            &admin,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("another active installation"));
        assert_eq!(f.mock.message_count(), before);
        assert!(!f.mock.forum_calls().iter().any(|call| matches!(
            call,
            ForumCall::ResetAuthorization { .. } | ForumCall::ResetOtherAuthorizations
        )));

        write_bindings(&[(target, "88"), (survivor, "99")]);
        let error = revocation::command_in_transaction(
            f.mock.clone(),
            &opened,
            target,
            Some(88),
            false,
            &revocation::load_confirmed_session_map(&map).unwrap(),
            &admin,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("conflicts with the installation"));
        let renewed = serde_json::json!([
            {"installation_id": target, "authorization_hash": "88"},
            {"installation_id": survivor, "authorization_hash": "99", "previous_authorization_hash": "111"}
        ]);
        std::fs::write(&map, serde_json::to_vec(&renewed).unwrap()).unwrap();
        f.mock.extra_authorizations.lock().unwrap().push(
            teagarden_telegram::client::TelegramAuthorizationInfo {
                hash: 111,
                current: false,
                device_model: "previous installation login".into(),
                app_name: "test".into(),
                date_active: 1,
            },
        );
        let error = revocation::command_in_transaction(
            f.mock.clone(),
            &opened,
            target,
            Some(88),
            false,
            &revocation::load_confirmed_session_map(&map).unwrap(),
            &admin,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}")
            .contains("previous authorization in the renewed session map is still live"));
        assert_eq!(f.mock.message_count(), before);
        assert!(!f.mock.forum_calls().iter().any(|call| matches!(
            call,
            ForumCall::ResetAuthorization { .. } | ForumCall::ResetOtherAuthorizations
        )));
        f.mock
            .extra_authorizations
            .lock()
            .unwrap()
            .retain(|entry| entry.hash != 111);
        revocation::command_in_transaction(
            f.mock.clone(),
            &opened,
            target,
            Some(88),
            false,
            &revocation::load_confirmed_session_map(&map).unwrap(),
            &admin,
        )
        .await
        .unwrap();
        let resets: Vec<_> = f
            .mock
            .forum_calls()
            .into_iter()
            .filter(|call| {
                matches!(
                    call,
                    ForumCall::ResetAuthorization { .. } | ForumCall::ResetOtherAuthorizations
                )
            })
            .collect();
        assert_eq!(resets, [ForumCall::ResetAuthorization { hash: 88 }]);
        let remaining = f.mock.authorizations().await.unwrap();
        assert!(remaining.iter().any(|entry| entry.current));
        assert!(remaining.iter().any(|entry| entry.hash == 99));
    }

    #[tokio::test]
    async fn release_1_0_cut_resumes_after_a_verified_target_disappears() {
        let f = Round2Fixture::new().await;
        let target = cut_only_target(&f, Some("99")).await;
        let opened = f.open(b"original-password");
        let path = seed_legacy_cut_for_fixture(&f, &opened, target);
        let error = revocation::command(f.mock.clone(), &opened, target, None, false)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("target Telegram authorization was not found"));

        // Model the durable verification written before an interrupted reset.
        // This authorisation is now absent, so a retry may publish the same cut.
        let mut journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(journal["phase"], "prepared");
        assert_eq!(journal["target_authorization_verified"], false);
        journal["target_authorization_verified"] = serde_json::json!(true);
        std::fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();

        revocation::command(f.mock.clone(), &opened, target, None, false)
            .await
            .unwrap();
        let journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(journal["phase"], "complete");
        assert!(!f.mock.forum_calls().iter().any(|call| matches!(
            call,
            teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
        )));
    }

    #[tokio::test]
    async fn release_1_0_old_completed_cut_can_finish_policy_without_resetting_again() {
        let f = Round2Fixture::new().await;
        let target = cut_only_target(&f, Some("99")).await;
        let opened = f.open(b"original-password");
        let path = seed_legacy_cut_for_fixture(&f, &opened, target);
        let mut older_journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        older_journal["phase"] = serde_json::json!("access_cut");
        older_journal["authorization_session_hash"] = serde_json::Value::Null;
        older_journal
            .as_object_mut()
            .unwrap()
            .remove("target_authorization_verified");
        std::fs::write(&path, serde_json::to_vec(&older_journal).unwrap()).unwrap();

        revocation::command(f.mock.clone(), &opened, target, None, false)
            .await
            .unwrap();
        let journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(journal["phase"], "complete");
        assert!(!f.mock.forum_calls().iter().any(|call| matches!(
            call,
            teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
                | teagarden_telegram::mock::ForumCall::ResetOtherAuthorizations
        )));
    }

    fn seed_legacy_cut_for_fixture(
        f: &Round2Fixture,
        opened: &manager::OpenVolumeResult,
        target: uuid::Uuid,
    ) -> PathBuf {
        let path = opened
            .paths
            .base_dir
            .join(format!("owner-access-cut-{target}.json"));
        let journal = serde_json::json!({
            "volume_id": opened.config.volume_id,
            "installation_id": target,
            "owner_public_key": opened.config.sdo_owner_public_key,
            "cutoff": {
                "key_generation": 0,
                "boundary_message_id": f.mock.message_count() + 1,
            },
            "device_authorities": {},
            "phase": "prepared",
            "telegram_user_id": 12345,
            "owner_telegram_user_id": 12345,
            "authorization_session_hash": "99",
            "target_authorization_verified": false,
        });
        std::fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
        path
    }

    #[tokio::test]
    async fn release_1_0_cut_retries_publication_without_repeating_access_removal() {
        let f = Round2Fixture::new().await;
        let target = cut_only_target(&f, Some("88")).await;
        let opened = f.open(b"original-password");
        f.mock.withhold_upload_acks(1);
        f.mock.clear_channel_binding();
        let error = revoke_fixture_target(&f, &opened, target, 88)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("publication remains resumable"));
        let pending = f.open(b"original-password");
        assert!(pending.config.sdo_header_pending);
        let pending_bytes = pending.config.sdo_header_pending_bytes.clone();
        let (_, cut, _) = discover_latest_header(
            f.mock.as_ref(),
            pending.config.telegram_group_id,
            pending.config.telegram_topic_id,
            &pending.hierarchy.integrity,
            pending.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        revocation::command(f.mock.clone(), &pending, target, None, false)
            .await
            .unwrap();
        let complete = f.open(b"original-password");
        assert!(
            !complete.config.sdo_header_pending,
            "an acknowledged retry must clear its pending publication anchor"
        );
        let (_, after, bytes) = discover_latest_header(
            f.mock.as_ref(),
            cut.group_id,
            cut.topic_id,
            &complete.hierarchy.integrity,
            complete.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(hex::encode(bytes), pending_bytes.unwrap());
        assert_eq!(after.revocation_cutoffs, cut.revocation_cutoffs);
        assert_eq!(
            f.mock
                .forum_calls()
                .iter()
                .filter(|call| matches!(
                    call,
                    teagarden_telegram::mock::ForumCall::ResetAuthorization { hash: 88 }
                ))
                .count(),
            1
        );
    }

    #[cfg(not(feature = "key-rotation"))]
    #[tokio::test]
    async fn release_1_0_portable_rotate_is_unavailable_without_the_feature() {
        let f = Round2Fixture::new().await;
        let password = f.cfg.path().join("password");
        std::fs::write(&password, "original-password").unwrap();
        let before = f.mock.message_count();
        let error = super::super::key::TEST_PORTABLE_TRANSPORT
            .scope(
                f.mock.clone(),
                super::super::key::rotate_in(
                    f.volumes.path(),
                    &f.id,
                    Some(password.to_str().unwrap()),
                    None,
                    None,
                ),
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("planned for a later release"));
        assert_eq!(before, f.mock.message_count());
        assert!(f.open(b"original-password").config.key_protection.is_none());
    }

    #[tokio::test]
    async fn release_1_0_revoke_refuses_missing_owner_and_unrelated_session_override() {
        let f = Round2Fixture::new().await;
        let target = cut_only_target(&f, Some("88")).await;
        let opened = f.open(b"original-password");
        let owner_path = owner_capability_path(&opened.paths.config_path).unwrap();
        let owner_bytes = std::fs::read(&owner_path).unwrap();
        std::fs::remove_file(&owner_path).unwrap();
        assert!(
            revocation::command(f.mock.clone(), &opened, target, None, false)
                .await
                .is_err()
        );
        std::fs::write(&owner_path, owner_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&owner_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = revocation::command(f.mock.clone(), &opened, target, Some(99), false)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("does not match the authenticated target binding"));
        assert!(!f.mock.forum_calls().iter().any(|c| matches!(
            c,
            teagarden_telegram::mock::ForumCall::BanMember { .. }
                | teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
                | teagarden_telegram::mock::ForumCall::ResetOtherAuthorizations
        )));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn release_1_0_mounted_survivor_applies_same_generation_revocation() {
        let f = Round2Fixture::new().await;
        let target = cut_only_target(&f, Some("88")).await;
        let owner = f.open(b"original-password");
        let mut metadata =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        metadata.author_device_id = target;
        metadata.path = Some("retained.txt".into());
        metadata.size = 4;
        metadata.clock_ms = 10;
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode(
            owner.config.volume_id,
            0,
            &owner.hierarchy.meta,
            metadata.clone(),
            b"safe",
        )
        .unwrap();
        f.mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        let c_volumes = tempfile::tempdir().unwrap();
        let c_transport = Arc::new(f.mock.fork_session());
        c_transport.clear_channel_binding();
        let mut c = attach_command(
            c_transport.as_ref(),
            owner.config.telegram_group_id,
            owner.config.telegram_topic_id,
            b"original-password",
            false,
            c_volumes.path(),
            owner.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap();
        let conn = open_sdo_mount_db(&mut c).unwrap();
        let builder = portable_mount_builder(&c, conn);
        let (fs, cursor) = prepare_sdo_mount(c_transport.clone(), &c, builder, Some(99))
            .await
            .unwrap();
        let (fs, notify) = start_prepared_sdo_mount_poller(
            fs,
            c_transport,
            &c,
            cursor,
            Arc::new(Mutex::new(None)),
        )
        .await
        .unwrap();
        let mountpoint = tempfile::tempdir().unwrap();
        let session = fuser::spawn_mount2(
            fs,
            mountpoint.path(),
            &[fuser::MountOption::FSName("teagarden-cut-only".into())],
        )
        .unwrap();
        revoke_fixture_target(&f, &owner, target, 88).await.unwrap();
        metadata.version_id = uuid::Uuid::new_v4();
        metadata.clock_ms = u64::MAX / 2;
        let late = teagarden_core::sdo::SdoFileObjectV3::encode(
            owner.config.volume_id,
            0,
            &owner.hierarchy.meta,
            metadata.clone(),
            b"evil",
        )
        .unwrap();
        f.mock
            .upload_file_object(&late, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        metadata.file_id = uuid::Uuid::new_v4();
        metadata.version_id = uuid::Uuid::new_v4();
        metadata.author_device_id = c.config.sdo_author_device_id.unwrap();
        metadata.path = Some("survivor.txt".into());
        let (private, _) =
            load_or_create_device_keypair(&c.paths.base_dir, &c.hierarchy.wrapping).unwrap();
        let signer = teagarden_core::sdo::device_signing_key(&private.0);
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
            owner.config.volume_id,
            0,
            &owner.hierarchy.meta,
            metadata.clone(),
            b"live",
            Some(&signer),
        )
        .unwrap();
        f.mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        notify.notify_one();
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if mountpoint.path().join("survivor.txt").exists() {
                break;
            }
        }
        assert_eq!(
            std::fs::read(mountpoint.path().join("survivor.txt")).unwrap(),
            b"live"
        );
        assert_eq!(
            std::fs::read(mountpoint.path().join("retained.txt")).unwrap(),
            b"safe",
            "a late revoked-author write must not become current on an already mounted survivor"
        );
        assert_eq!(c.hierarchy.root.as_bytes(), owner.hierarchy.root.as_bytes());
        // Replaying an older correctly signed header must not undo an observed cut.
        let (cut_document, _, _) = discover_latest_header(
            f.mock.as_ref(),
            owner.config.telegram_group_id,
            owner.config.telegram_topic_id,
            &owner.hierarchy.integrity,
            owner.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        f.mock
            .delete_message(cut_document.message_id)
            .await
            .unwrap();
        metadata.file_id = uuid::Uuid::new_v4();
        metadata.version_id = uuid::Uuid::new_v4();
        metadata.author_device_id = target;
        metadata.path = Some("intruder-after-rollback.txt".into());
        let bad = teagarden_core::sdo::SdoFileObjectV3::encode(
            owner.config.volume_id,
            0,
            &owner.hierarchy.meta,
            metadata.clone(),
            b"evil",
        )
        .unwrap();
        f.mock
            .upload_file_object(&bad, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        metadata.file_id = uuid::Uuid::new_v4();
        metadata.version_id = uuid::Uuid::new_v4();
        metadata.author_device_id = c.config.sdo_author_device_id.unwrap();
        metadata.path = Some("rollback-proof.txt".into());
        let proof = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
            owner.config.volume_id,
            0,
            &owner.hierarchy.meta,
            metadata,
            b"live",
            Some(&signer),
        )
        .unwrap();
        f.mock
            .upload_file_object(&proof, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        notify.notify_one();
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if mountpoint.path().join("rollback-proof.txt").exists() {
                break;
            }
        }
        assert!(
            !mountpoint
                .path()
                .join("intruder-after-rollback.txt")
                .exists(),
            "an older signed header must not undo an observed revocation"
        );
        assert!(
            !mountpoint.path().join("rollback-proof.txt").exists(),
            "the stale-policy batch must retain its cursor"
        );
        drop(session);
        let mut reopened = teagarden_mfa::unlock::open_volume(
            &owner.config.volume_id.to_string(),
            &teagarden_mfa::unlock::UnlockInputs {
                password: Some(b"original-password"),
                ..Default::default()
            },
            c_volumes.path(),
        )
        .unwrap();
        let conn = open_sdo_mount_db(&mut reopened).unwrap();
        let builder = portable_mount_builder(&reopened, conn);
        let error = match prepare_sdo_mount(f.mock.clone(), &reopened, builder, Some(99)).await {
            Ok(_) => {
                panic!("a cold mount must retain the revision observed by its previous live poller")
            }
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("revision floor"), "{error:#}");
    }

    #[test]
    fn release_1_0_revoke_cuts_access_without_replacement_credentials() {
        const CHILD: &str = "TEAGARDEN_CUT_ONLY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::volume::tests::release_1_0_revoke_cuts_access_without_replacement_credentials", "--nocapture"])
                .env(CHILD, "1").stdin(std::process::Stdio::null()).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(!stdout.contains("NEW volume password"));
            assert!(stdout.contains(
                "Telegram confirmed the group ban for the installation's registered account"
            ));
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for different_account in [false, true] {
                let f = Round2Fixture::new().await;
                unsafe {
                    std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
                    std::env::set_var("TEAGARDEN_CONFIG_DIR", f.cfg.path());
                }
                let opened = f.open(b"original-password");
                let (header_doc, before, header_wire) = discover_latest_header(f.mock.as_ref(), opened.config.telegram_group_id,
                    opened.config.telegram_topic_id, &opened.hierarchy.integrity, opened.config.sdo_owner_public_key.as_deref()).await.unwrap().unwrap();
                let target = uuid::Uuid::new_v4();
                let mut metadata = legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
                metadata.kind = teagarden_core::sdo::SdoKind::Device;
                metadata.path = None;
                metadata.installation_id = Some(target);
                metadata.author_device_id = target;
                metadata.telegram_user_id = Some(if different_account { 99999 } else { 12345 });
                metadata.authorization_session_hash = Some("88".into());
                metadata.label = Some("Target".into());
                metadata.created_at_ms = Some(1);
                metadata.clock_ms = 1;
                let pair = teagarden_sharing::key_exchange::UserKeyPair::generate().unwrap();
                let signer = teagarden_core::sdo::device_signing_key(&pair.decapsulation_key.0);
                let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(before.volume_id, 0, &opened.hierarchy.meta,
                    metadata.clone(), &[], Some(&signer)).unwrap();
                f.mock.upload_file_object(&wire, "teagarden-file-v3.tgf").await.unwrap();
                let _survivor_without_handoff_key = cut_only_target(&f, Some("99")).await;
                metadata.kind = teagarden_core::sdo::SdoKind::File;
                metadata.path = Some("retained.txt".into());
                metadata.installation_id = None;
                metadata.label = None;
                metadata.telegram_user_id = None;
                metadata.authorization_session_hash = None;
                metadata.created_at_ms = None;
                metadata.version_id = uuid::Uuid::new_v4();
                metadata.size = 4;
                let retained_id = metadata.version_id;
                let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(before.volume_id, 0, &opened.hierarchy.meta, metadata.clone(), b"safe", Some(&signer)).unwrap();
                let wire = teagarden_core::sdo::ObjectEnvelope::seal(&wire, &header_wire, &opened.hierarchy).unwrap();
                let original = f.mock.upload_file_object(&wire, "teagarden-file-v3.tgf").await.unwrap().message_id;
                let password = f.cfg.path().join("password");
                std::fs::write(&password, "original-password").unwrap();
                let config_before = std::fs::read(&opened.paths.config_path).unwrap();
                let (session, confirmed) = if different_account {
                    (None, None)
                } else {
                    (Some(88), Some(confirmed_fixture_session_map(&f, target, 88).await))
                };
                f.mock.clear_channel_binding();
                super::super::key::TEST_PORTABLE_TRANSPORT.scope(f.mock.clone(), revoke_device(&f.id, target,
                    Some(password.to_str().unwrap()), None, session, false, confirmed.as_deref())).await
                    .expect("1.0 revoke must cut access and publish policy without asking for replacement credentials");
                let reopened = f.open(b"original-password");
                assert_eq!(reopened.hierarchy.root.as_bytes(), opened.hierarchy.root.as_bytes());
                assert!(!reopened.paths.base_dir.join("slot_vault.json").exists());
                let (_, after, _) = discover_latest_header(f.mock.as_ref(), before.group_id, before.topic_id,
                    &reopened.hierarchy.integrity, reopened.config.sdo_owner_public_key.as_deref()).await.unwrap().unwrap();
                assert!(after.revoked_device_ids.contains(&target));
                assert_eq!(after.key_generation, before.key_generation);
                assert_eq!(after.salt, before.salt);
                assert_eq!(after.key_protection, before.key_protection);
                assert!(after.rotation_state.is_none() && after.retained_key_bridges.is_empty());
                let cutoff = &after.revocation_cutoffs[&target];
                assert_eq!(cutoff.key_generation, 0);
                assert!(cutoff.boundary_message_id > original);
                assert_eq!(f.mock.download_block(original).await.unwrap().data, wire, "revocation must not rewrite retained ciphertext");
                assert_eq!(f.mock.download_block(header_doc.message_id).await.unwrap().data, header_wire);
                metadata.version_id = uuid::Uuid::new_v4();
                metadata.clock_ms = u64::MAX / 2;
                let late_id = metadata.version_id;
                let late = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(before.volume_id, 0, &opened.hierarchy.meta, metadata, b"late", Some(&signer)).unwrap();
                f.mock.upload_file_object(&late, "teagarden-file-v3.tgf").await.unwrap();
                let scan = scan_topic_sdo_objects(f.mock.as_ref(), before.group_id, before.topic_id, &after, &reopened.hierarchy).await.unwrap();
                assert!(scan.records.iter().any(|v| v.record.version_id == retained_id));
                assert!(!scan.records.iter().any(|v| v.record.version_id == late_id));
                let calls = f.mock.forum_calls();
                if different_account { assert!(calls.iter().any(|c| matches!(c, teagarden_telegram::mock::ForumCall::BanMember { user_id: 99999, .. }))); }
                else { assert!(calls.contains(&teagarden_telegram::mock::ForumCall::ResetAuthorization { hash: 88 })); }
                assert!(!calls.iter().any(|c| matches!(c, teagarden_telegram::mock::ForumCall::ResetOtherAuthorizations)));
                assert_ne!(std::fs::read(&reopened.paths.config_path).unwrap(), config_before, "only signed-header publication anchors change locally");
                let artifact = f.cfg.path().join("retained.tgf");
                std::fs::write(&artifact, &wire).unwrap();
                let recovered = f.cfg.path().join("forensic");
                super::super::decrypt::run(&artifact, Some(&recovered), Some(password.to_str().unwrap()), None, None,
                    reopened.config.sdo_owner_public_key.as_deref(), false).unwrap();
                assert_eq!(std::fs::read(recovered.join("retained.txt")).unwrap(), b"safe");
            }
        });
    }

    #[test]
    fn a2_n4_attach_always_prints_the_authenticated_owner_fingerprint() {
        const CHILD: &str = "TEAGARDEN_A2_N4_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::volume::tests::a2_n4_attach_always_prints_the_authenticated_owner_fingerprint", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            let owner = stdout
                .lines()
                .find_map(|line| line.strip_prefix("Owner public key: "))
                .expect("attach did not print its owner");
            let expected = hex::encode(teagarden_core::block::srb2::sha256(
                &hex::decode(owner).unwrap(),
            ));
            assert!(
                stdout.contains(&format!(
                    "Authenticated owner fingerprint: SHA256:{expected}"
                )),
                "{stdout}"
            );
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let f = Round2Fixture::new().await;
            let opened = f.open(b"original-password");
            let destination = tempfile::tempdir().unwrap();
            f.mock.clear_channel_binding();
            let attached = attach_command(
                f.mock.as_ref(),
                opened.config.telegram_group_id,
                opened.config.telegram_topic_id,
                b"original-password",
                false,
                destination.path(),
                opened.config.sdo_owner_public_key.as_deref(),
            )
            .await
            .unwrap();
            assert_eq!(
                attached.config.sdo_owner_public_key,
                opened.config.sdo_owner_public_key
            );
        });
    }

    #[tokio::test]
    async fn create_command_defaults_to_owner_signed_tghd2() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = MockTransport::new_unbound();
        assert!(mock.channel_ref().is_none());
        let (id, _) = create_command(
            &mock,
            &cfg.path().join("group.json"),
            volumes.path(),
            "default-owner",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"a-long-enough-pass", volumes.path()).unwrap();
        let (_, header, _) = discover_latest_header(
            &mock,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &opened.hierarchy.integrity,
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(header.format, 2);
        assert_eq!(header.owner_public_key, opened.config.sdo_owner_public_key);
        assert_eq!(
            header.owner_public_key.unwrap(),
            hex::encode(
                load_owner_capability(&opened.paths.config_path)
                    .unwrap()
                    .verifying_key()
                    .to_bytes()
            )
        );
    }

    #[tokio::test]
    async fn upgrade_owner_command_resolves_initially_unbound_session() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockTransport::new());
        let (id, _) = create_legacy_command_fixture(
            mock.as_ref(),
            &cfg.path().join("group.json"),
            volumes.path(),
            "legacy-owner",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"a-long-enough-pass", volumes.path()).unwrap();
        mock.clear_channel_binding();
        assert!(mock.channel_ref().is_none());
        upgrade_owner_command(mock.clone(), &opened).await.unwrap();
        assert_eq!(
            mock.channel_ref().unwrap().0,
            opened.config.telegram_group_id
        );
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn revoke_device_command_resolves_initially_unbound_session() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockTransport::new());
        let (id, _) = create_legacy_command_fixture(
            mock.as_ref(),
            &cfg.path().join("group.json"),
            volumes.path(),
            "owner-revoke-command",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"a-long-enough-pass", volumes.path()).unwrap();
        upgrade_owner_with_transport(mock.clone(), mock.channel_ref().unwrap().1, &opened)
            .await
            .unwrap();
        let opened = manager::open_volume(&id, b"a-long-enough-pass", volumes.path()).unwrap();
        mock.clear_channel_binding();
        assert!(mock.channel_ref().is_none());
        let error = revoke_and_rotate_command(
            mock,
            &opened,
            uuid::Uuid::new_v4(),
            b"replacement-password",
            None,
            false,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("is not in the active registry"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn upgrade_owner_command_refuses_reownership() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockTransport::new_unbound());
        let (id, _) = create_command(
            mock.as_ref(),
            &cfg.path().join("group.json"),
            volumes.path(),
            "owner",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"a-long-enough-pass", volumes.path()).unwrap();
        std::fs::remove_file(owner_capability_path(&opened.paths.config_path).unwrap()).unwrap();
        let result = upgrade_owner_command(mock, &opened).await;
        assert!(result.is_err(), "TGHD2 must never be upgraded or re-owned");
        assert!(!owner_capability_path(&opened.paths.config_path)
            .unwrap()
            .exists());
    }

    #[tokio::test]
    async fn attach_command_rejects_owner_downgrade_and_reownership() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = MockTransport::new_unbound();
        let (id, _) = create_command(
            &mock,
            &cfg.path().join("group.json"),
            volumes.path(),
            "owner",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"a-long-enough-pass", volumes.path()).unwrap();
        let (_, header, _) = discover_latest_header(
            &mock,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &opened.hierarchy.integrity,
            None,
        )
        .await
        .unwrap()
        .unwrap();
        let pin = header.owner_public_key.clone().unwrap();
        for downgrade in [true, false] {
            let mut forged = header.clone();
            forged.revision += 1;
            let bytes = if downgrade {
                forged.format = 1;
                forged.owner_public_key = None;
                forged.key_generation = None;
                forged.encode(&opened.hierarchy.integrity).unwrap()
            } else {
                let impostor = ed25519_dalek::SigningKey::from_bytes(&[0xab; 32]);
                forged.owner_public_key = Some(hex::encode(impostor.verifying_key().to_bytes()));
                forged
                    .encode_v2(&opened.hierarchy.integrity, &impostor)
                    .unwrap()
            };
            mock.put_document(
                500,
                header.group_id,
                header.topic_id,
                "teagarden-header-v1.tgh",
                bytes,
            );
            let destination = tempfile::tempdir().unwrap();
            let result = attach_command(
                &mock,
                header.group_id,
                header.topic_id,
                b"a-long-enough-pass",
                false,
                destination.path(),
                Some(&pin),
            )
            .await;
            assert!(
                result.is_err(),
                "owner pin must reject downgrade={downgrade}"
            );
            assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn round2_n4_pinless_attach_refuses_topic_with_owner_header() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = MockTransport::new_unbound();
        let (id, _) = create_command(
            &mock,
            &cfg.path().join("group.json"),
            volumes.path(),
            "owner",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"a-long-enough-pass", volumes.path()).unwrap();
        let (_, header, _) = discover_latest_header(
            &mock,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &opened.hierarchy.integrity,
            None,
        )
        .await
        .unwrap()
        .unwrap();

        for downgrade in [true, false] {
            let mut forged = header.clone();
            forged.revision += 1;
            let bytes = if downgrade {
                forged.format = 1;
                forged.owner_public_key = None;
                forged.key_generation = None;
                forged.encode(&opened.hierarchy.integrity).unwrap()
            } else {
                let impostor = ed25519_dalek::SigningKey::from_bytes(&[0xab; 32]);
                forged.owner_public_key = Some(hex::encode(impostor.verifying_key().to_bytes()));
                forged
                    .encode_v2(&opened.hierarchy.integrity, &impostor)
                    .unwrap()
            };
            mock.put_document(
                500,
                header.group_id,
                header.topic_id,
                "teagarden-header-v1.tgh",
                bytes,
            );
            let destination = tempfile::tempdir().unwrap();
            let result = attach_command(
                &mock,
                header.group_id,
                header.topic_id,
                b"a-long-enough-pass",
                false,
                destination.path(),
                None,
            )
            .await;
            assert!(
                result.is_err(),
                "owner pin must reject downgrade={downgrade}"
            );
            assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn slot_command_preserves_rotated_header_state() {
        use teagarden_mfa::kslot::protector::SlotProtector;
        use teagarden_mfa::kslot::protectors::{Argon2Cost, PassphraseProtector};
        use teagarden_mfa::kslot::vault::SlotVault;
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = MockTransport::new_unbound();
        let (id, _) = create_command(
            &mock,
            &cfg.path().join("group.json"),
            volumes.path(),
            "protected-owner",
            "a-long-enough-pass",
            None,
            true,
            None,
        )
        .await
        .unwrap();
        let inputs = teagarden_mfa::unlock::UnlockInputs {
            password: Some(b"a-long-enough-pass"),
            ..Default::default()
        };
        let mut opened = teagarden_mfa::unlock::open_volume(&id, &inputs, volumes.path()).unwrap();
        let (_, mut header, _) = discover_latest_header(
            &mock,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &opened.hierarchy.integrity,
            opened.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        header.key_generation = Some(7);
        header.generation_boundary_message_id = Some(100);
        header.revoked_device_ids.push(uuid::Uuid::new_v4());
        header.revocation_cutoffs.insert(
            header.revoked_device_ids[0],
            teagarden_core::sdo::RevocationCutoff {
                key_generation: header.key_generation.unwrap(),
                boundary_message_id: 100,
            },
        );
        header.revoked_account_bindings.push("88".into());
        header.rotation_state = Some(serde_json::json!({"phase":"migrating", "key_bridges":[]}));
        publish_signed_header_update(
            &mock,
            &opened.config,
            &opened.hierarchy,
            &opened.paths.config_path,
            header.revision,
            header.clone(),
        )
        .await
        .unwrap();
        opened = teagarden_mfa::unlock::open_volume(&id, &inputs, volumes.path()).unwrap();
        let path = opened
            .paths
            .base_dir
            .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
        let mut vault = SlotVault::load(&path).unwrap();
        let password =
            PassphraseProtector::new(b"a-long-enough-pass".to_vec(), Argon2Cost::default());
        let master = vault.unlock(&[&password as &dyn SlotProtector]).unwrap();
        let mut extra = PassphraseProtector::new(
            b"another-password".to_vec(),
            Argon2Cost {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        );
        vault
            .add_independent_slot(&master, &mut extra, "new password slot")
            .unwrap();
        vault.save(&path).unwrap();
        opened.config.key_protection = Some(teagarden_core::volume::config::KeyProtection {
            vault_generation: vault.generation(),
            vault_digest: hex::encode(vault.state_digest()),
        });
        manager::save_config_resealed(
            &mut opened.config,
            &opened.hierarchy,
            &opened.paths.config_path,
        )
        .unwrap();
        publish_slot_header_update(&mock, &opened).await.unwrap();
        let (_, updated, _) = discover_latest_header(
            &mock,
            header.group_id,
            header.topic_id,
            &opened.hierarchy.integrity,
            opened.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(updated.key_generation, header.key_generation);
        assert_eq!(
            updated.generation_boundary_message_id,
            header.generation_boundary_message_id
        );
        assert_eq!(updated.revoked_device_ids, header.revoked_device_ids);
        assert_eq!(
            updated.revoked_account_bindings,
            header.revoked_account_bindings
        );
        assert_eq!(updated.rotation_state, header.rotation_state);
        assert_eq!(
            updated.slot_vault,
            Some(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
        );
        let destination = tempfile::tempdir().unwrap();
        let attached = attach_command(
            &mock,
            header.group_id,
            header.topic_id,
            b"another-password",
            false,
            destination.path(),
            opened.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap();
        assert_eq!(
            attached.config.sdo_owner_public_key,
            opened.config.sdo_owner_public_key
        );
    }

    #[tokio::test]
    async fn device_list_command_discovers_installations_and_authorizations() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = MockTransport::new_unbound();
        let (id, _) = create_command(
            &mock,
            &cfg.path().join("group.json"),
            volumes.path(),
            "owner",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"a-long-enough-pass", volumes.path()).unwrap();
        let own = opened.config.sdo_author_device_id.unwrap();
        let revoked = uuid::Uuid::new_v4();
        for (index, installation, label) in
            [(0, own, "Owner desktop"), (1, revoked, "Revoked laptop")]
        {
            let mut metadata =
                legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
            metadata.kind = teagarden_core::sdo::SdoKind::Device;
            metadata.path = None;
            metadata.installation_id = Some(installation);
            metadata.author_device_id = installation;
            metadata.label = Some(label.into());
            metadata.telegram_user_id = Some(12345);
            metadata.authorization_session_hash = Some((77 + index * 11).to_string());
            metadata.created_at_ms = Some(1);
            metadata.clock_ms = 123;
            metadata.version_id = uuid::Uuid::new_v4();
            let wire = teagarden_core::sdo::SdoFileObjectV3::encode(
                opened.config.volume_id,
                0,
                &opened.hierarchy.meta,
                metadata,
                &[],
            )
            .unwrap();
            mock.put_document(
                10 + index,
                opened.config.telegram_group_id,
                opened.config.telegram_topic_id,
                "teagarden-file-v3.tgf",
                wire,
            );
        }
        let (_, mut header, _) = discover_latest_header(
            &mock,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &opened.hierarchy.integrity,
            opened.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        header.revoked_device_ids.push(revoked);
        header.revocation_cutoffs.insert(
            revoked,
            teagarden_core::sdo::RevocationCutoff {
                key_generation: header.key_generation.unwrap(),
                boundary_message_id: 9,
            },
        );
        publish_signed_header_update(
            &mock,
            &opened.config,
            &opened.hierarchy,
            &opened.paths.config_path,
            header.revision,
            header,
        )
        .await
        .unwrap();
        mock.clear_channel_binding();
        let listing = device_list_command(&mock, &opened).await.unwrap();
        let (_, current_header, _) = discover_latest_header(
            &mock,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &opened.hierarchy.integrity,
            opened.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        let scan = scan_topic_sdo_objects(
            &mock,
            current_header.group_id,
            current_header.topic_id,
            &current_header,
            &opened.hierarchy,
        )
        .await
        .unwrap();
        assert!(scan.registry.get(&revoked).is_none());
        assert!(scan
            .records
            .iter()
            .all(|version| version.record.author_device_id != revoked));
        for expected in [
            own.to_string(),
            revoked.to_string(),
            "Owner desktop".into(),
            "Revoked laptop".into(),
            "last_seen_ms=123".into(),
            "revoked=true".into(),
            "binding=88".into(),
            "Mock laptop".into(),
            "Telegram Desktop".into(),
            "1700000123".into(),
            format!("This computer: {own}"),
        ] {
            assert!(
                listing.contains(&expected),
                "missing {expected:?} in {listing}"
            );
        }
    }

    #[tokio::test]
    async fn owner_pinned_header_publication_writes_verified_tghd2() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let group_path = cfg.path().join("group.json");
        let mock = Arc::new(MockTransport::new());
        let (volume_id, _) = create_legacy_command_fixture(
            mock.as_ref(),
            &group_path,
            volumes.path(),
            "owner-upgrade",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened =
            manager::open_volume(&volume_id, b"a-long-enough-pass", volumes.path()).unwrap();
        let group_access_hash = mock.channel_ref().unwrap().1;
        upgrade_owner_with_transport(mock.clone(), group_access_hash, &opened)
            .await
            .unwrap();
        let config: VolumeConfig =
            serde_json::from_slice(&std::fs::read(&opened.paths.config_path).unwrap()).unwrap();
        let pages = mock
            .list_topic_documents(
                config.telegram_group_id,
                config.telegram_topic_id,
                None,
                100,
            )
            .await
            .unwrap();
        let newest = pages
            .iter()
            .filter(|document| document.filename == "teagarden-header-v1.tgh")
            .max_by_key(|document| document.message_id)
            .unwrap();
        let bytes = mock.get_raw(newest.message_id).unwrap();
        let header = HeaderDocument::decode(&bytes, &opened.hierarchy.integrity).unwrap();
        assert_eq!(header.format, 2);
        assert_eq!(header.revision, 2);
        assert_eq!(header.owner_public_key, config.sdo_owner_public_key);
    }

    #[tokio::test]
    async fn owner_header_update_publishes_signed_revocation_revision() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let group_path = cfg.path().join("group.json");
        let mock = Arc::new(MockTransport::new());
        let (volume_id, _) = create_legacy_command_fixture(
            mock.as_ref(),
            &group_path,
            volumes.path(),
            "owner-revoke",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened =
            manager::open_volume(&volume_id, b"a-long-enough-pass", volumes.path()).unwrap();
        upgrade_owner_with_transport(mock.clone(), mock.channel_ref().unwrap().1, &opened)
            .await
            .unwrap();
        let mut header = discover_latest_header(
            mock.as_ref(),
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &opened.hierarchy.integrity,
            None,
        )
        .await
        .unwrap()
        .unwrap()
        .1;
        let revoked = uuid::Uuid::new_v4();
        header.revoked_device_ids.push(revoked);
        mock.withhold_upload_acks(1);
        assert!(publish_signed_header_update(
            mock.as_ref(),
            &opened.config,
            &opened.hierarchy,
            &opened.paths.config_path,
            header.revision,
            header.clone(),
        )
        .await
        .is_err());
        let pending_config: VolumeConfig =
            serde_json::from_slice(&std::fs::read(&opened.paths.config_path).unwrap()).unwrap();
        let exact_pending_bytes =
            hex::decode(pending_config.sdo_header_pending_bytes.as_deref().unwrap()).unwrap();
        let message_id = publish_signed_header_update(
            mock.as_ref(),
            &opened.config,
            &opened.hierarchy,
            &opened.paths.config_path,
            header.revision,
            header,
        )
        .await
        .unwrap();
        let bytes = mock.get_raw(message_id).unwrap();
        assert_eq!(bytes, exact_pending_bytes);
        let published = HeaderDocument::decode(&bytes, &opened.hierarchy.integrity).unwrap();
        assert_eq!(published.format, 2);
        assert_eq!(published.revision, 3);
        assert!(published.revoked_device_ids.contains(&revoked));
    }

    fn portable_mount_builder(opened: &manager::OpenVolumeResult, conn: Connection) -> CryptFs {
        let schema = OpaqueSchema::new(opened.hierarchy.schema.clone(), &logical_tables());
        CryptFs::new(
            conn,
            schema,
            opened.hierarchy.meta.clone(),
            opened.hierarchy.data.clone(),
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        )
        .with_sdo(
            opened.config.volume_id,
            opened.config.sdo_author_device_id.unwrap(),
        )
        .with_manifest_key(opened.hierarchy.manifest.clone())
        .with_runtime(tokio::runtime::Handle::current())
    }

    #[tokio::test]
    async fn mount_preparation_authenticates_applies_and_seeds_before_ready() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockTransport::new_unbound());
        let (id, _) = create_command(
            mock.as_ref(),
            &cfg.path().join("group.json"),
            volumes.path(),
            "mount",
            "original-password",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let mut opened = manager::open_volume(&id, b"original-password", volumes.path()).unwrap();
        let remote_clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 1000;
        let mut metadata =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        metadata.path = Some("from-other-computer.txt".into());
        metadata.size = 4;
        metadata.clock_ms = remote_clock;
        metadata.clock_counter = 7;
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode(
            opened.config.volume_id,
            0,
            &opened.hierarchy.meta,
            metadata,
            b"data",
        )
        .unwrap();
        let uploaded = mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap()
            .message_id;
        let conn = open_sdo_mount_db(&mut opened).unwrap();
        let fs = portable_mount_builder(&opened, conn);
        mock.clear_channel_binding();
        assert!(mock.channel_ref().is_none());
        let (fs, cursor) = prepare_sdo_mount(mock.clone(), &opened, fs, None)
            .await
            .unwrap();
        let file = fs
            .store()
            .lookup(1, "from-other-computer.txt")
            .unwrap()
            .expect("ready mount must contain the authenticated initial remote tree");
        assert_eq!(file.size, 4);
        assert_eq!(file.uid, unsafe { libc::getuid() });
        assert!(cursor >= uploaded);
        let mut announcement_clock = None;
        for id in 1..=100 {
            if let Some(wire) = mock.get_raw(id) {
                if wire.get(..4) == Some(b"TGFV") && wire.get(4..6) == Some(&[3, 0]) {
                    let object = teagarden_core::sdo::SdoFileObjectV3::decode(
                        &wire,
                        opened.config.volume_id,
                        0,
                        &opened.hierarchy.meta,
                    )
                    .unwrap();
                    if object.metadata.kind == teagarden_core::sdo::SdoKind::Device {
                        announcement_clock =
                            Some((object.metadata.clock_ms, object.metadata.clock_counter));
                    }
                }
            }
        }
        assert!(
            announcement_clock.unwrap() > (remote_clock, 7),
            "HLC must be seeded before announcing or writing"
        );
        drop(fs);
        mock.put_document(
            1000,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            "broken.tgf",
            b"TGFV\x03\x00truncated".to_vec(),
        );
        let mut reopened = manager::open_volume(&id, b"original-password", volumes.path()).unwrap();
        let conn = open_sdo_mount_db(&mut reopened).unwrap();
        let fs = portable_mount_builder(&reopened, conn);
        assert!(
            prepare_sdo_mount(mock, &reopened, fs, None).await.is_err(),
            "recognized unauthenticated input must prevent readiness"
        );
    }

    #[tokio::test]
    async fn mount_outbox_path_survives_new_instance_and_recovers_without_old_inode() {
        use teagarden_store::sdo_pending_store::{SdoPendingWrite, SdoPendingWriteStore};
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockTransport::new_unbound());
        let (id, _) = create_command(
            mock.as_ref(),
            &cfg.path().join("group.json"),
            volumes.path(),
            "outbox",
            "original-password",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let mut first = manager::open_volume(&id, b"original-password", volumes.path()).unwrap();
        drop(open_sdo_mount_db(&mut first).unwrap());
        let first_path = sdo_outbox_path(&first);
        let (_, header, header_wire) = discover_latest_header(
            mock.as_ref(),
            first.config.telegram_group_id,
            first.config.telegram_topic_id,
            &first.hierarchy.integrity,
            first.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        let (private, _) =
            load_or_create_device_keypair(&first.paths.base_dir, &first.hierarchy.wrapping)
                .unwrap();
        let mut metadata =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        metadata.author_device_id = first.config.sdo_author_device_id.unwrap();
        metadata.path = Some("pending.txt".into());
        metadata.size = 4;
        metadata.version_id = uuid::Uuid::new_v4();
        let version = metadata.version_id;
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
            header.volume_id,
            0,
            &first.hierarchy.meta,
            metadata,
            b"data",
            Some(&teagarden_core::sdo::device_signing_key(&private.0)),
        )
        .unwrap();
        let wire = teagarden_core::sdo::ObjectEnvelope::seal(&wire, &header_wire, &first.hierarchy)
            .unwrap();
        {
            let (conn, schema, key) = open_sdo_outbox(&first).unwrap();
            SdoPendingWriteStore::new(&conn, &schema, &key)
                .put(&SdoPendingWrite {
                    metadata_snapshot: None,
                    version_id: version,
                    inode: 999,
                    handle_id: 99,
                    predecessor: None,
                    clock_ms: 1,
                    clock_counter: 0,
                    bytes: b"data".to_vec(),
                    wire: Some(wire),
                })
                .unwrap();
        }
        let mut second = manager::open_volume(&id, b"original-password", volumes.path()).unwrap();
        let conn = open_sdo_mount_db(&mut second).unwrap();
        assert_ne!(first.paths.db_path, second.paths.db_path);
        assert_eq!(
            first_path,
            sdo_outbox_path(&second),
            "outbox must live outside disposable mount-instance paths"
        );
        let fs = portable_mount_builder(&second, conn);
        let (fs, _) = prepare_sdo_mount(mock, &second, fs, None).await.unwrap();
        assert!(
            fs.store().lookup(1, "pending.txt").unwrap().is_some(),
            "pending wire must recover even when its old inode is absent"
        );
        let (conn, schema, key) = open_sdo_outbox(&second).unwrap();
        assert!(SdoPendingWriteStore::new(&conn, &schema, &key)
            .list()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn round2_410_revoke_override_must_match_authenticated_target_binding() {
        let f = Round2Fixture::new().await;
        let original = f.open(b"original-password");
        let revoked = uuid::Uuid::new_v4();
        let pair = teagarden_sharing::key_exchange::UserKeyPair::generate().unwrap();
        let mut ann =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        ann.kind = teagarden_core::sdo::SdoKind::Device;
        ann.path = None;
        ann.installation_id = Some(revoked);
        ann.author_device_id = revoked;
        ann.version_id = uuid::Uuid::new_v4();
        ann.label = Some("target B".into());
        ann.telegram_user_id = Some(12345);
        ann.authorization_session_hash = Some("88".into());
        ann.created_at_ms = Some(1);
        ann.device_public_key = Some(hex::encode(&pair.encapsulation_key.0));
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
            original.config.volume_id,
            0,
            &original.hierarchy.meta,
            ann,
            &[],
            Some(&teagarden_core::sdo::device_signing_key(
                &pair.decapsulation_key.0,
            )),
        )
        .unwrap();
        f.mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        f.mock.extra_authorizations.lock().unwrap().push(
            teagarden_telegram::client::TelegramAuthorizationInfo {
                hash: 99,
                current: false,
                device_model: "unrelated phone".into(),
                app_name: "Telegram".into(),
                date_active: 1700000000,
            },
        );
        f.mock.clear_channel_binding();
        let result = revoke_and_rotate_command(
            f.mock.clone(),
            &original,
            revoked,
            b"replacement-one",
            Some(99),
            false,
        )
        .await;
        assert!(
            result.is_err(),
            "a live unrelated authorization must not be used for the target's access cut"
        );
        assert!(format!("{:#}", result.unwrap_err()).contains("target binding"));
        assert!(!f.mock.forum_calls().iter().any(|call| matches!(
            call,
            teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
        )));
        f.mock.clear_channel_binding();
        revoke_and_rotate_command(
            f.mock.clone(),
            &original,
            revoked,
            b"replacement-one",
            Some(88),
            false,
        )
        .await
        .unwrap();
        assert!(f
            .mock
            .forum_calls()
            .contains(&teagarden_telegram::mock::ForumCall::ResetAuthorization { hash: 88 }));
        assert!(!f
            .mock
            .forum_calls()
            .contains(&teagarden_telegram::mock::ForumCall::ResetAuthorization { hash: 99 }));
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn round2_n7_revoke_refuses_reused_replacement_before_access_cut() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockTransport::new_unbound());
        let (id, _) = create_command(
            mock.as_ref(),
            &cfg.path().join("group.json"),
            volumes.path(),
            "reuse",
            "original-password",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"original-password", volumes.path()).unwrap();
        mock.clear_channel_binding();
        let error = revoke_and_rotate_command(
            mock.clone(),
            &opened,
            uuid::Uuid::new_v4(),
            b"original-password",
            None,
            false,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("replacement password must differ"),
            "{error:#}"
        );
        assert!(!mock.forum_calls().iter().any(|call| matches!(
            call,
            teagarden_telegram::mock::ForumCall::BanMember { .. }
                | teagarden_telegram::mock::ForumCall::ResetAuthorization { .. }
        )));
    }

    #[test]
    #[cfg(feature = "key-rotation")]
    fn round2_n7_real_rotate_reads_stdin_once_and_refuses_reused_passwords() {
        const CHILD: &str = "TEAGARDEN_R2_N7_CHILD";
        if std::env::var_os(CHILD).is_none() {
            use std::process::{Command, Stdio};
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::volume::tests::round2_n7_real_rotate_reads_stdin_once_and_refuses_reused_passwords", "--nocapture"])
                .env(CHILD, "1").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"original-password\n")
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let volumes = tempfile::tempdir().unwrap();
            let cfg = tempfile::tempdir().unwrap();
            let mock = Arc::new(MockTransport::new_unbound());
            let (id, _) = create_command(mock.as_ref(), &cfg.path().join("group.json"),
                volumes.path(), "stdin-rotate", "original-password", None, false, None).await.unwrap();
            let replacement = cfg.path().join("replacement");
            std::fs::write(&replacement, b"replacement-password").unwrap();
            let old_file = cfg.path().join("old");
            std::fs::write(&old_file, b"original-password").unwrap();
            let error = super::super::key::TEST_PORTABLE_TRANSPORT.scope(mock.clone(),
                super::super::key::rotate_in(volumes.path(), &id, Some(old_file.to_str().unwrap()), None, Some(old_file.to_str().unwrap()))).await.unwrap_err();
            assert!(format!("{error:#}").contains("replacement password must differ"));
            mock.clear_channel_binding();
            super::super::key::TEST_PORTABLE_TRANSPORT.scope(mock.clone(),
                super::super::key::rotate_in(volumes.path(), &id, Some("-"), None, Some(replacement.to_str().unwrap()))).await
                .expect("real key::rotate_in must consume the old stdin credential once and rotate with a distinct replacement");
            let current = utils::open_volume_any(&id, Some(replacement.to_str().unwrap()), None, volumes.path()).unwrap();
            assert_eq!(current.config.sdo_header_revision_published, 4);
        });
    }

    struct Round2Fixture {
        volumes: tempfile::TempDir,
        cfg: tempfile::TempDir,
        mock: Arc<MockTransport>,
        id: String,
    }
    impl Round2Fixture {
        async fn new() -> Self {
            let volumes = tempfile::tempdir().unwrap();
            let cfg = tempfile::tempdir().unwrap();
            let mock = Arc::new(MockTransport::new_unbound());
            let (id, _) = create_command(
                mock.as_ref(),
                &cfg.path().join("group.json"),
                volumes.path(),
                "round-two",
                "original-password",
                None,
                false,
                None,
            )
            .await
            .unwrap();
            Self {
                volumes,
                cfg,
                mock,
                id,
            }
        }
        fn open(&self, password: &[u8]) -> manager::OpenVolumeResult {
            teagarden_mfa::unlock::open_volume(
                &self.id,
                &teagarden_mfa::unlock::UnlockInputs {
                    password: Some(password),
                    ..Default::default()
                },
                self.volumes.path(),
            )
            .unwrap()
        }
        #[cfg(feature = "key-rotation")]
        async fn rotate(&self, old: &[u8], next: &[u8]) -> Result<()> {
            let old_path = self.cfg.path().join("old");
            let next_path = self.cfg.path().join("next");
            std::fs::write(&old_path, old)?;
            std::fs::write(&next_path, next)?;
            self.mock.clear_channel_binding();
            super::super::key::TEST_PORTABLE_TRANSPORT
                .scope(
                    self.mock.clone(),
                    super::super::key::rotate_in(
                        self.volumes.path(),
                        &self.id,
                        Some(old_path.to_str().unwrap()),
                        None,
                        Some(next_path.to_str().unwrap()),
                    ),
                )
                .await
        }
    }

    #[test]
    #[cfg(feature = "key-rotation")]
    fn round2_n6_export_and_directory_restore_follow_current_authority() {
        const CHILD: &str = "TEAGARDEN_R2_N6_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::volume::tests::round2_n6_export_and_directory_restore_follow_current_authority", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            let diagnostic = stderr
                .lines()
                .filter(|line| !line.starts_with("New volume recovery sentence"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(output.status.success(), "{diagnostic}");
            assert!(
                stderr.contains("Forensic single-object recovery"),
                "single-object recovery must explicitly identify its forensic scope"
            );
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {

        use teagarden_core::sdo::{SdoFileObjectV3, SdoKind};
        let f = Round2Fixture::new().await;
        let original = f.open(b"original-password");
        let (_, _, old_header_wire) = discover_latest_header(f.mock.as_ref(), original.config.telegram_group_id, original.config.telegram_topic_id,
            &original.hierarchy.integrity, original.config.sdo_owner_public_key.as_deref()).await.unwrap().unwrap();
        let revoked = uuid::Uuid::new_v4();
        let pair = teagarden_sharing::key_exchange::UserKeyPair::generate().unwrap();
        let signer = teagarden_core::sdo::device_signing_key(&pair.decapsulation_key.0);
        let mut ann =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        ann.kind = SdoKind::Device;
        ann.path = None;
        ann.installation_id = Some(revoked);
        ann.author_device_id = revoked;
        ann.label = Some("B".into());
        ann.telegram_user_id = Some(12345);
        ann.authorization_session_hash = Some("88".into());
        ann.created_at_ms = Some(1);
        ann.device_public_key = Some(hex::encode(&pair.encapsulation_key.0));
        let wire = SdoFileObjectV3::encode_with_signer(
            original.config.volume_id,
            0,
            &original.hierarchy.meta,
            ann,
            &[],
            Some(&signer),
        )
        .unwrap();
        f.mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        let mut safe =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        safe.author_device_id = revoked;
        safe.path = Some("safe.txt".into());
        safe.size = 4;
        safe.version_id = uuid::Uuid::new_v4();

        let wire = SdoFileObjectV3::encode_with_signer(
            original.config.volume_id,
            0,
            &original.hierarchy.meta,
            safe.clone(),
            b"safe",
            Some(&signer),
        )
        .unwrap();
        f.mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        f.mock.clear_channel_binding();
        revoke_and_rotate_command(
            f.mock.clone(),
            &original,
            revoked,
            b"replacement-one",
            None,
            false,
        )
        .await
        .unwrap();
        let first = f.open(b"replacement-one");
        let (_, h1, _) = discover_latest_header(
            f.mock.as_ref(),
            first.config.telegram_group_id,
            first.config.telegram_topic_id,
            &first.hierarchy.integrity,
            first.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        let cutoff = h1.generation_boundary_message_id.unwrap();
        let mut evil = safe;
        evil.version_id = uuid::Uuid::new_v4();
        evil.path = Some("intruder.txt".into());
        evil.clock_ms = u64::MAX / 2;

        let wire = SdoFileObjectV3::encode_with_signer(
            original.config.volume_id,
            0,
            &original.hierarchy.meta,
            evil,
            b"evil",
            Some(&signer),
        )
        .unwrap();
        let wire = teagarden_core::sdo::ObjectEnvelope::seal(&wire, &old_header_wire, &original.hierarchy).unwrap();
        let evil_wire = wire.clone();
        let late = f
            .mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap()
            .message_id;
        assert!(late > cutoff);
        let current = f.open(b"replacement-one");
        let current_password = f.cfg.path().join("current-password");
        let old_password = f.cfg.path().join("old-password");
        std::fs::write(&current_password, b"replacement-one").unwrap();
        std::fs::write(&old_password, b"original-password").unwrap();
        std::env::set_var("TEAGARDEN_VOLUMES_DIR", f.volumes.path());
        std::env::set_var("TEAGARDEN_CONFIG_DIR", f.cfg.path());
        let exported = f.cfg.path().join("exported");
        f.mock.clear_channel_binding();
        super::super::key::TEST_PORTABLE_TRANSPORT.scope(f.mock.clone(), export_objects(&f.id, &exported,
            Some(current_password.to_str().unwrap()), None)).await.unwrap();
        let rejected_path = exported.join(format!("file-{late}.tgf"));
        let was_exported = rejected_path.exists();
        std::fs::write(exported.join("file-1.tgf"), &evil_wire).unwrap();
        let restored = f.cfg.path().join("restored");
        super::super::decrypt::run(&exported, Some(&restored), Some(current_password.to_str().unwrap()), None, None,
            current.config.sdo_owner_public_key.as_deref(), false).expect_err("directory restore must refuse an injected object instead of silently omitting it");
        assert!(!restored.exists(), "a refused restore must not write a partial tree");
        let injected_wire = std::fs::read(exported.join("file-1.tgf")).unwrap();
        std::fs::remove_file(exported.join("file-1.tgf")).unwrap();
        super::super::decrypt::run(&exported, Some(&restored), Some(current_password.to_str().unwrap()), None, None,
            current.config.sdo_owner_public_key.as_deref(), false).unwrap();
        std::fs::write(exported.join("file-1.tgf"), injected_wire).unwrap();
        let restored_bad = restored.join("intruder.txt").exists();
        assert_eq!(std::fs::read(restored.join("safe.txt")).unwrap(), b"safe");
        let forensic = f.cfg.path().join("forensic");
        std::fs::create_dir(&forensic).unwrap();
        let single = forensic.join("object.tgf");
        std::fs::write(&single, evil_wire).unwrap();
        let forensic_output = f.cfg.path().join("forensic-output");
        super::super::decrypt::run(&single, Some(&forensic_output), Some(old_password.to_str().unwrap()), None, None,
            current.config.sdo_owner_public_key.as_deref(), false).unwrap();
        assert_eq!(std::fs::read(forensic_output.join("intruder.txt")).unwrap(), b"evil");
        assert!(!was_exported && !restored_bad, "current-state policy bypass: export included revoked={was_exported}; directory restored revoked={restored_bad}");
            let manifest = exported.join("export-provenance.json");
            let mut forged: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
            forged["payload"]["objects"]["file-1.tgf"] = serde_json::json!({"message_id": 1, "sha256": "00"});
            std::fs::write(&manifest, serde_json::to_vec(&forged).unwrap()).unwrap();
            let tampered_output = f.cfg.path().join("tampered-output");
            let error = super::super::decrypt::run(&exported, Some(&tampered_output), Some(current_password.to_str().unwrap()),
                None, None, current.config.sdo_owner_public_key.as_deref(), false).unwrap_err();
            assert!(format!("{error:#}").contains("export provenance authentication failed"));
            assert!(!tampered_output.exists());
            // A current writer knows the shared integrity key. That key must
            // not turn a made-up old source position into owner authorization.
            let injected = std::fs::read(exported.join("file-1.tgf")).unwrap();
            forged["payload"]["objects"]["file-1.tgf"] = serde_json::json!({
                "message_id": 1, "sha256": hex::encode(teagarden_core::block::srb2::sha256(&injected)),
            });
            let mut mac_input = b"teagarden.export-provenance.v1".to_vec();
            mac_input.extend_from_slice(&serde_json::to_vec(&forged["payload"]).unwrap());
            forged["mac"] = serde_json::json!(blake3::keyed_hash(current.hierarchy.integrity.as_bytes(), &mac_input).to_hex().to_string());
            std::fs::write(&manifest, serde_json::to_vec(&forged).unwrap()).unwrap();
            let forgery_output = f.cfg.path().join("shared-key-forgery-output");
            let result = super::super::decrypt::run(&exported, Some(&forgery_output), Some(current_password.to_str().unwrap()),
                None, None, current.config.sdo_owner_public_key.as_deref(), false);
            assert!(result.is_err() || !forgery_output.join("intruder.txt").exists(),
                "a shared-key provenance MAC must not authorize a forged pre-revocation source position");
            forged.as_object_mut().unwrap().remove("owner_signature");
            std::fs::write(&manifest, serde_json::to_vec(&forged).unwrap()).unwrap();
            let unsigned_output = f.cfg.path().join("unsigned-source-output");
            let result = super::super::decrypt::run(&exported, Some(&unsigned_output), Some(current_password.to_str().unwrap()),
                None, None, current.config.sdo_owner_public_key.as_deref(), false);
            result.expect_err("missing provenance must refuse the injected object, never silently omit it");
            assert!(!unsigned_output.exists());
            std::fs::remove_file(exported.join("file-1.tgf")).unwrap();
            forged["payload"]["objects"].as_object_mut().unwrap().remove("file-1.tgf");
            super::super::decrypt::write_export_provenance(&exported, forged["payload"].clone(),
                &current.hierarchy.integrity, None).unwrap();
            super::super::decrypt::run(&exported, Some(&unsigned_output), Some(current_password.to_str().unwrap()),
                None, None, current.config.sdo_owner_public_key.as_deref(), false)
                .expect("owner-receipted legitimate history remains recoverable without source-position authority");
            assert!(!unsigned_output.join("intruder.txt").exists(),
                "stripping source owner authorization must not fall back to shared-key authority");
            assert_eq!(std::fs::read(unsigned_output.join("safe.txt")).unwrap(), b"safe");


        });
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn round2_n3_mounted_survivor_catches_two_missed_rotations() {
        let f = Round2Fixture::new().await;
        let original = f.open(b"original-password");
        let c_transport = Arc::new(f.mock.fork_session());
        let c_volumes = tempfile::tempdir().unwrap();
        let mut c = attach_command(
            c_transport.as_ref(),
            original.config.telegram_group_id,
            original.config.telegram_topic_id,
            b"original-password",
            false,
            c_volumes.path(),
            original.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap();
        let conn = open_sdo_mount_db(&mut c).unwrap();
        let builder = portable_mount_builder(&c, conn);
        let (fs, cursor) = prepare_sdo_mount(c_transport.clone(), &c, builder, None)
            .await
            .unwrap();
        let (fs, notify) = start_prepared_sdo_mount_poller(
            fs,
            c_transport.clone(),
            &c,
            cursor,
            Arc::new(Mutex::new(None)),
        )
        .await
        .unwrap();
        *c_transport.fail_downloads.lock().unwrap() = Some("C is offline".into());
        let mountpoint = tempfile::tempdir().unwrap();
        let session = fuser::spawn_mount2(
            fs,
            mountpoint.path(),
            &[fuser::MountOption::FSName("teagarden-r2-N3".into())],
        )
        .expect("required real Linux FUSE mount must start");
        f.rotate(b"original-password", b"replacement-one")
            .await
            .unwrap();
        f.rotate(b"replacement-one", b"replacement-two")
            .await
            .unwrap();
        let current = f.open(b"replacement-two");
        let (_, header, header_wire) = discover_latest_header(
            f.mock.as_ref(),
            current.config.telegram_group_id,
            current.config.telegram_topic_id,
            &current.hierarchy.integrity,
            current.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(header.key_generation, Some(2));
        let mut metadata =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        metadata.key_generation = 2;
        metadata.path = Some("generation-two.txt".into());
        metadata.version_id = uuid::Uuid::new_v4();
        metadata.size = 4;
        let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
            header.volume_id,
            2,
            &current.hierarchy.meta,
            metadata,
            b"live",
            Some(&ed25519_dalek::SigningKey::from_bytes(&[0x77; 32])),
        )
        .unwrap();
        let wire =
            teagarden_core::sdo::ObjectEnvelope::seal(&wire, &header_wire, &current.hierarchy)
                .unwrap();
        f.mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        *c_transport.fail_downloads.lock().unwrap() = None;
        notify.notify_one();
        let path = mountpoint.path().join("generation-two.txt");
        let bytes = tokio::time::timeout(std::time::Duration::from_secs(45), async {
            loop {
                let attempt = path.clone();
                if let Ok(bytes) = tokio::task::spawn_blocking(move || std::fs::read(attempt))
                    .await
                    .unwrap()
                {
                    break bytes;
                }
                notify.notify_one();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .expect(
            "the same mounted C must choose its highest usable retained handoff without restart",
        );
        assert_eq!(bytes, b"live");
        drop(session);
        let old = f.cfg.path().join("c-old-password");
        std::fs::write(&old, b"original-password").unwrap();
        let reopened =
            utils::open_volume_any(&f.id, Some(old.to_str().unwrap()), None, c_volumes.path())
                .unwrap();
        assert!(reopened.hierarchy.root.as_bytes() == current.hierarchy.root.as_bytes());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(feature = "key-rotation")]
    async fn round2_n1_real_rotation_keeps_racing_saves_and_concurrent_attach() {
        use teagarden_core::sdo::{ObjectEnvelope, SdoFileObjectV3};
        tokio::task::LocalSet::new().run_until(async {
        let f = Arc::new(Round2Fixture::new().await);
        let mut owner = f.open(b"original-password");
        let conn = open_sdo_mount_db(&mut owner).unwrap();
        let fs = portable_mount_builder(&owner, conn);
        drop(prepare_sdo_mount(f.mock.clone(), &owner, fs, None).await.unwrap());
        let (_, _, old_header) = discover_latest_header(f.mock.as_ref(), owner.config.telegram_group_id, owner.config.telegram_topic_id,
            &owner.hierarchy.integrity, owner.config.sdo_owner_public_key.as_deref()).await.unwrap().unwrap();
        let (owner_private, _) = load_or_create_device_keypair(&owner.paths.base_dir, &owner.hierarchy.wrapping).unwrap();
        let package_entered = Arc::new(tokio::sync::Notify::new());
        let package_release = Arc::new(tokio::sync::Notify::new());
        let boundary_entered = Arc::new(tokio::sync::Notify::new());
        let boundary_release = Arc::new(tokio::sync::Notify::new());
        f.mock.gate_next_upload("teagarden-device-handoff-v1.tgk", package_entered.clone(), package_release.clone());
        f.mock.gate_next_upload("teagarden-header-v1.tgh", boundary_entered.clone(), boundary_release.clone());
        let rotating = f.clone();
        let task = tokio::task::spawn_local(async move { rotating.rotate(b"original-password", b"replacement-one").await });
        tokio::time::timeout(std::time::Duration::from_secs(30), package_entered.notified()).await.unwrap();
        let joining_transport = Arc::new(f.mock.fork_session());
        let joining_dir = tempfile::tempdir().unwrap();
        let mut joined = attach_command(joining_transport.as_ref(), owner.config.telegram_group_id, owner.config.telegram_topic_id,
            b"original-password", false, joining_dir.path(), owner.config.sdo_owner_public_key.as_deref()).await.unwrap();
        let conn = open_sdo_mount_db(&mut joined).unwrap();
        let fs = portable_mount_builder(&joined, conn);
        drop(prepare_sdo_mount(joining_transport.clone(), &joined, fs, None).await.unwrap());
        let (join_private, _) = load_or_create_device_keypair(&joined.paths.base_dir, &joined.hierarchy.wrapping).unwrap();
        package_release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(30), boundary_entered.notified()).await.unwrap();
        let mut saves = Vec::new();
        for (author, key, path) in [
            (owner.config.sdo_author_device_id.unwrap(), &owner_private, "racing-owner.txt"),
            (joined.config.sdo_author_device_id.unwrap(), &join_private, "racing-join.txt"),
        ] {
            let mut metadata = legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
            metadata.author_device_id = author; metadata.version_id = uuid::Uuid::new_v4(); metadata.file_id = uuid::Uuid::new_v4();
            metadata.path = Some(path.into()); metadata.clock_ms = 10000000000000; metadata.size = 4;
            let id = metadata.version_id;
            let wire = SdoFileObjectV3::encode_with_signer(owner.config.volume_id, 0, &owner.hierarchy.meta, metadata, b"save",
                Some(&teagarden_core::sdo::device_signing_key(&key.0))).unwrap();
            let wire = ObjectEnvelope::seal(&wire, &old_header, &owner.hierarchy).unwrap();
            let source = joining_transport.upload_file_object(&wire, "teagarden-file-v3.tgf").await.unwrap().message_id;
            saves.push((id, source, path));
        }
        boundary_release.notify_one();
        task.await.unwrap().expect("legitimate acknowledged saves during owner migration must not fail receipt verification");
        let current = f.open(b"replacement-one");
        let (_, header, _) = discover_latest_header(f.mock.as_ref(), current.config.telegram_group_id, current.config.telegram_topic_id,
            &current.hierarchy.integrity, current.config.sdo_owner_public_key.as_deref()).await.unwrap().unwrap();
        let scan = scan_topic_sdo_objects(f.mock.as_ref(), header.group_id, header.topic_id, &header, &current.hierarchy).await.unwrap();
        for (id, source, _) in &saves {
            let record = scan.records.iter().find(|v| v.record.version_id == *id).expect("both racing saves must remain in history");
            assert_eq!(record.key_generation, 1);
            let object = SdoFileObjectV3::decode(&f.mock.get_raw(record.message_id).unwrap(), header.volume_id, 1, &current.hierarchy.meta).unwrap();
            assert_eq!(object.metadata.migration_receipt.as_ref().unwrap().source_message_id, *source);
            assert!(*source > header.generation_boundary_message_id.unwrap());
            assert!(object.metadata.has_valid_migration_receipt(header.volume_id, header.owner_public_key.as_deref().unwrap(), i64::MAX));
            assert!(teagarden_core::sdo::object_transition_is_acceptable(&header, &object.metadata, record.message_id));
            assert!(f.mock.get_raw(*source).is_none());
        }
        assert!(header.device_authorities.contains_key(&joined.config.sdo_author_device_id.unwrap()));
        let documents = f.mock.list_topic_documents(header.group_id, header.topic_id, None, 100).await.unwrap();
        let join_update = documents.iter().filter(|doc| doc.filename == "teagarden-device-handoff-v1.tgk")
            .filter_map(|doc| decode_device_handoff(&f.mock.get_raw(doc.message_id).unwrap(), header.volume_id, header.owner_public_key.as_deref().unwrap()).ok())
            .find(|update| update.installation_id == joined.config.sdo_author_device_id.unwrap()).unwrap();
        let root = unwrap_device_key_update(header.volume_id, &join_update, &join_private).unwrap();
        assert!(root == *current.hierarchy.root.as_bytes());
        }).await;
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn round2_n2_two_rotations_never_resurrect_revoked_authority() {
        use teagarden_core::sdo::{SdoFileObjectV3, SdoKind};
        let f = Round2Fixture::new().await;
        let original = f.open(b"original-password");
        let revoked = uuid::Uuid::new_v4();
        let pair = teagarden_sharing::key_exchange::UserKeyPair::generate().unwrap();
        let signer = teagarden_core::sdo::device_signing_key(&pair.decapsulation_key.0);
        let mut ann =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        ann.kind = SdoKind::Device;
        ann.path = None;
        ann.installation_id = Some(revoked);
        ann.author_device_id = revoked;
        ann.label = Some("B".into());
        ann.telegram_user_id = Some(12345);
        ann.authorization_session_hash = Some("88".into());
        ann.created_at_ms = Some(1);
        ann.device_public_key = Some(hex::encode(&pair.encapsulation_key.0));
        let wire = SdoFileObjectV3::encode_with_signer(
            original.config.volume_id,
            0,
            &original.hierarchy.meta,
            ann,
            &[],
            Some(&signer),
        )
        .unwrap();
        f.mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        let mut safe =
            legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
        safe.author_device_id = revoked;
        safe.path = Some("safe.txt".into());
        safe.size = 4;
        safe.version_id = uuid::Uuid::new_v4();
        let safe_id = safe.version_id;
        let wire = SdoFileObjectV3::encode_with_signer(
            original.config.volume_id,
            0,
            &original.hierarchy.meta,
            safe.clone(),
            b"safe",
            Some(&signer),
        )
        .unwrap();
        f.mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap();
        f.mock.clear_channel_binding();
        revoke_and_rotate_command(
            f.mock.clone(),
            &original,
            revoked,
            b"replacement-one",
            None,
            false,
        )
        .await
        .unwrap();
        let first = f.open(b"replacement-one");
        let (_, h1, _) = discover_latest_header(
            f.mock.as_ref(),
            first.config.telegram_group_id,
            first.config.telegram_topic_id,
            &first.hierarchy.integrity,
            first.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        let cutoff = h1.generation_boundary_message_id.unwrap();
        let mut evil = safe;
        evil.version_id = uuid::Uuid::new_v4();
        evil.path = Some("intruder.txt".into());
        evil.clock_ms = u64::MAX / 2;
        let evil_id = evil.version_id;
        let wire = SdoFileObjectV3::encode_with_signer(
            original.config.volume_id,
            0,
            &original.hierarchy.meta,
            evil,
            b"evil",
            Some(&signer),
        )
        .unwrap();
        let late = f
            .mock
            .upload_file_object(&wire, "teagarden-file-v3.tgf")
            .await
            .unwrap()
            .message_id;
        assert!(late > cutoff);
        f.rotate(b"replacement-one", b"replacement-two")
            .await
            .unwrap();
        let current = f.open(b"replacement-two");
        let attached_dir = tempfile::tempdir().unwrap();
        f.mock.clear_channel_binding();
        let attached = attach_command(
            f.mock.as_ref(),
            current.config.telegram_group_id,
            current.config.telegram_topic_id,
            b"replacement-two",
            false,
            attached_dir.path(),
            current.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap();
        let conn = Connection::open(&attached.paths.db_path).unwrap();
        let schema = OpaqueSchema::new(attached.hierarchy.schema.clone(), &logical_tables());
        let store = InodeStore::new(&conn, &schema, &attached.hierarchy.meta);
        assert!(
            store.lookup(1, "intruder.txt").unwrap().is_none(),
            "second rotation must not turn a rejected revoked save into current content"
        );
        let (_, h2, _) = discover_latest_header(
            f.mock.as_ref(),
            current.config.telegram_group_id,
            current.config.telegram_topic_id,
            &current.hierarchy.integrity,
            current.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        let scan = scan_topic_sdo_objects(
            f.mock.as_ref(),
            h2.group_id,
            h2.topic_id,
            &h2,
            &current.hierarchy,
        )
        .await
        .unwrap();
        assert!(scan.records.iter().any(|v| v.record.version_id == safe_id));
        assert!(!scan.records.iter().any(|v| v.record.version_id == evil_id));
        let json = serde_json::to_value(&h2).unwrap();
        assert_eq!(
            json["revocation_cutoffs"][revoked.to_string()]["boundary_message_id"],
            cutoff
        );
        assert_eq!(json["generation_cutoffs"]["1"], cutoff);
        assert_eq!(h2.key_generation, Some(2));
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn round2_n5_real_rotate_resumes_interrupted_portable_migration() {
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockTransport::new_unbound());
        let (id, _) = create_command(
            mock.as_ref(),
            &cfg.path().join("group.json"),
            volumes.path(),
            "resume",
            "original-password",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"original-password", volumes.path()).unwrap();
        let mut metadata = teagarden_core::sdo::SdoObjectMetadata::test_fixture();
        metadata.size = 4;
        let wire = teagarden_core::sdo::SdoFileObject::encode(
            opened.config.volume_id,
            &opened.hierarchy.meta,
            metadata,
            b"data",
        )
        .unwrap();
        let original = mock
            .upload_file_object(&wire, "teagarden-file-v2.tgf")
            .await
            .unwrap()
            .message_id;
        let old = cfg.path().join("old");
        let next = cfg.path().join("next");
        std::fs::write(&old, b"original-password").unwrap();
        std::fs::write(&next, b"replacement-password").unwrap();
        mock.clear_channel_binding();
        mock.set_fail_deletes(true);
        let error = super::super::key::TEST_PORTABLE_TRANSPORT
            .scope(
                mock.clone(),
                super::super::key::rotate_in(
                    volumes.path(),
                    &id,
                    Some(old.to_str().unwrap()),
                    None,
                    Some(next.to_str().unwrap()),
                ),
            )
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("history migration remains resumable"),
            "{error:#}"
        );
        mock.set_fail_deletes(false);
        mock.clear_channel_binding();
        super::super::key::TEST_PORTABLE_TRANSPORT.scope(mock.clone(),
            super::super::key::rotate_in(volumes.path(), &id, Some(next.to_str().unwrap()), None, None)).await
            .expect("actual key::rotate_in must resume rotation-only state without revoking the nil sentinel");
        let current =
            utils::open_volume_any(&id, Some(next.to_str().unwrap()), None, volumes.path())
                .unwrap();
        let (_, header, _) = discover_latest_header(
            mock.as_ref(),
            current.config.telegram_group_id,
            current.config.telegram_topic_id,
            &current.hierarchy.integrity,
            current.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(header.key_generation, Some(1));
        assert!(header.rotation_state.is_none());
        assert!(header.revoked_device_ids.is_empty());
        assert!(mock.get_raw(original).is_none());
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn key_rotate_command_rotates_root_and_migrates_without_cutting_devices() {
        use teagarden_telegram::mock::ForumCall;
        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockTransport::new_unbound());
        let (id, _) = create_command(
            mock.as_ref(),
            &cfg.path().join("group.json"),
            volumes.path(),
            "rotate",
            "original-password",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let opened = manager::open_volume(&id, b"original-password", volumes.path()).unwrap();
        let mut devices = Vec::new();
        for installation in [
            opened.config.sdo_author_device_id.unwrap(),
            uuid::Uuid::new_v4(),
        ] {
            let pair = teagarden_sharing::key_exchange::UserKeyPair::generate().unwrap();
            let mut metadata =
                legacy_v2_logical_metadata(&teagarden_core::sdo::SdoObjectMetadata::test_fixture());
            metadata.kind = teagarden_core::sdo::SdoKind::Device;
            metadata.path = None;
            metadata.installation_id = Some(installation);
            metadata.author_device_id = installation;
            metadata.version_id = uuid::Uuid::new_v4();
            metadata.label = Some("writer".into());
            metadata.telegram_user_id = Some(12345);
            metadata.created_at_ms = Some(1);
            metadata.device_public_key = Some(hex::encode(&pair.encapsulation_key.0));
            let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
                opened.config.volume_id,
                0,
                &opened.hierarchy.meta,
                metadata,
                &[],
                Some(&teagarden_core::sdo::device_signing_key(
                    &pair.decapsulation_key.0,
                )),
            )
            .unwrap();
            mock.upload_file_object(&wire, "teagarden-file-v3.tgf")
                .await
                .unwrap();
            devices.push((installation, pair));
        }
        let mut metadata = teagarden_core::sdo::SdoObjectMetadata::test_fixture();
        metadata.size = 4;
        let wire = teagarden_core::sdo::SdoFileObject::encode(
            opened.config.volume_id,
            &opened.hierarchy.meta,
            metadata,
            b"data",
        )
        .unwrap();
        let original = mock
            .upload_file_object(&wire, "teagarden-file-v2.tgf")
            .await
            .unwrap()
            .message_id;
        mock.clear_channel_binding();
        super::super::key::rotate_portable_command(mock.clone(), &opened, b"replacement-password")
            .await
            .unwrap();
        let current = teagarden_mfa::unlock::open_volume(
            &id,
            &teagarden_mfa::unlock::UnlockInputs {
                password: Some(b"replacement-password"),
                ..Default::default()
            },
            volumes.path(),
        )
        .unwrap();
        assert!(current.hierarchy.root.as_bytes() != opened.hierarchy.root.as_bytes());
        let (_, header, _) = discover_latest_header(
            mock.as_ref(),
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            &current.hierarchy.integrity,
            current.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(header.key_generation, Some(1));
        assert!(header.revoked_device_ids.is_empty());
        assert!(header.revoked_account_bindings.is_empty());
        assert!(!mock.forum_calls().iter().any(|call| matches!(
            call,
            ForumCall::BanMember { .. }
                | ForumCall::ResetAuthorization { .. }
                | ForumCall::ResetOtherAuthorizations
        )));
        let documents = mock
            .list_topic_documents(header.group_id, header.topic_id, None, 100)
            .await
            .unwrap();
        let handoffs: Vec<_> = documents
            .iter()
            .filter(|document| document.filename == "teagarden-device-handoff-v1.tgk")
            .collect();
        assert_eq!(handoffs.len(), devices.len());
        for (installation, pair) in devices {
            let update = handoffs
                .iter()
                .map(|document| {
                    decode_device_handoff(
                        &mock.get_raw(document.message_id).unwrap(),
                        header.volume_id,
                        header.owner_public_key.as_deref().unwrap(),
                    )
                    .unwrap()
                })
                .find(|update| update.installation_id == installation)
                .unwrap();
            let root = unwrap_device_key_update(header.volume_id, &update, &pair.decapsulation_key)
                .unwrap();
            let keys = teagarden_core::crypto::kdf::derive_hierarchy_v1(
                teagarden_core::crypto::keys::SymmetricKey::from_bytes(root),
                &update.salt,
                header.group_id,
                header.topic_id,
            )
            .unwrap();
            assert!(keys.meta.as_bytes() == current.hierarchy.meta.as_bytes());
        }
        assert!(mock.get_raw(original).is_none());
        let scan = scan_topic_sdo_objects(
            mock.as_ref(),
            header.group_id,
            header.topic_id,
            &header,
            &current.hierarchy,
        )
        .await
        .unwrap();
        assert_eq!(scan.registry.len(), 2);
        assert!(scan.records.iter().all(|record| record.key_generation == 1));
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn round4_final_n4_declined_experimental_reset_never_enters_administration() {
        let f = Round2Fixture::new().await;
        let opened = f.open(b"original-password");
        let before = std::fs::read(&opened.paths.config_path).unwrap();
        let calls = f.mock.forum_calls();
        let _admin = manager::OwnerAdminLock::acquire(&opened.paths.base_dir).unwrap();
        let refused = revoke_device_with_transport(
            f.mock.clone(),
            f.mock.channel_ref().unwrap().1,
            &opened,
            uuid::Uuid::new_v4(),
            b"replacement-password",
            None,
            true,
            false,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{refused:#}").contains("confirmation declined"),
            "{refused:#}"
        );
        assert_eq!(std::fs::read(&opened.paths.config_path).unwrap(), before);
        assert_eq!(f.mock.forum_calls(), calls);
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn revoke_cuts_access_rotates_credentials_and_migrates_history() {
        revoke_command_scenario(false, false, false).await;
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn revoke_command_delayed_survivor_recovers_after_completed_migration() {
        revoke_command_scenario(true, false, false).await;
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn revoke_command_survivor_persists_transition_for_remount() {
        revoke_command_scenario(true, true, false).await;
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn revoke_command_preserves_acknowledged_survivor_save_across_generation_boundary() {
        revoke_command_scenario(true, true, true).await;
    }

    #[cfg(feature = "key-rotation")]
    async fn revoke_command_scenario(
        delayed_survivor: bool,
        durable_transition: bool,
        concurrent_save: bool,
    ) {
        use teagarden_telegram::mock::ForumCall;

        let volumes = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let group_path = cfg.path().join("group.json");
        let mock = Arc::new(MockTransport::new());
        let (volume_id, _) = create_legacy_command_fixture(
            mock.as_ref(),
            &group_path,
            volumes.path(),
            "owner-revoke-flow",
            "a-long-enough-pass",
            None,
            false,
            None,
        )
        .await
        .unwrap();
        let before =
            manager::open_volume(&volume_id, b"a-long-enough-pass", volumes.path()).unwrap();
        let access_hash = mock.channel_ref().unwrap().1;
        upgrade_owner_with_transport(mock.clone(), access_hash, &before)
            .await
            .unwrap();
        let opened =
            manager::open_volume(&volume_id, b"a-long-enough-pass", volumes.path()).unwrap();
        let installation_id = uuid::Uuid::new_v4();
        let revoked_device_c_keys =
            teagarden_sharing::key_exchange::UserKeyPair::generate().unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let device_wire = teagarden_core::sdo::SdoFileObjectV3::encode(
            opened.config.volume_id,
            0,
            &opened.hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: uuid::Uuid::new_v4(),
                origin_message_id: None,
                path: None,
                size: 0,
                mtime_ns: 0,
                mode: 0,
                version_id: uuid::Uuid::new_v4(),
                author_device_id: uuid::Uuid::new_v4(),
                previous_version_id: None,
                kind: teagarden_core::sdo::SdoKind::Device,
                key_generation: 0,
                clock_ms: now_ms,
                clock_counter: 0,
                saved_at_ns: 0,
                local_version: 1,
                deleted: false,
                installation_id: Some(installation_id),
                label: Some("shared-login-device".into()),
                telegram_user_id: Some(12345),
                authorization_session_hash: None,
                created_at_ms: Some(now_ms),
                device_public_key: Some(hex::encode(&revoked_device_c_keys.encapsulation_key.0)),
                device_key_update: None,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 0,
                content_sha256: hex::encode(teagarden_core::block::srb2::sha256(&[])),
            },
            &[],
        )
        .unwrap();
        let c_volumes = tempfile::tempdir().unwrap();
        let c_opened = attach_command(
            mock.as_ref(),
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            b"a-long-enough-pass",
            false,
            c_volumes.path(),
            opened.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap();
        let (private, public) =
            load_or_create_device_keypair(&c_opened.paths.base_dir, &c_opened.hierarchy.wrapping)
                .unwrap();
        let device_b_keys = teagarden_sharing::key_exchange::UserKeyPair {
            decapsulation_key: private,
            encapsulation_key: public,
        };
        let installation_b = c_opened.config.sdo_author_device_id.unwrap();
        let device_b_wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
            opened.config.volume_id,
            0,
            &opened.hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: uuid::Uuid::new_v4(),
                origin_message_id: None,
                path: None,
                size: 0,
                mtime_ns: 0,
                mode: 0,
                version_id: uuid::Uuid::new_v4(),
                author_device_id: installation_b,
                previous_version_id: None,
                kind: teagarden_core::sdo::SdoKind::Device,
                key_generation: 0,
                clock_ms: now_ms + 1,
                clock_counter: 0,
                saved_at_ns: 0,
                local_version: 1,
                deleted: false,
                installation_id: Some(installation_b),
                label: Some("remaining-device-b".into()),
                telegram_user_id: Some(12345),
                authorization_session_hash: None,
                created_at_ms: Some(now_ms + 1),
                device_public_key: Some(hex::encode(&device_b_keys.encapsulation_key.0)),
                device_key_update: None,
                segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                segment_count: 0,
                content_sha256: hex::encode(teagarden_core::block::srb2::sha256(&[])),
            },
            &[],
            Some(&teagarden_core::sdo::device_signing_key(
                &device_b_keys.decapsulation_key.0,
            )),
        )
        .unwrap();
        let mut legacy_metadata = teagarden_core::sdo::SdoObjectMetadata::test_fixture();
        legacy_metadata.file_id = uuid::Uuid::new_v4();
        legacy_metadata.path = "legacy-history.txt".into();
        legacy_metadata.size = 3;
        legacy_metadata.version_id = uuid::Uuid::new_v4();
        legacy_metadata.saved_at_ns = 1_700_000_000_000_000_000;
        let legacy_version_id = legacy_metadata.version_id;
        let legacy_wire = teagarden_core::sdo::SdoFileObject::encode(
            opened.config.volume_id,
            &opened.hierarchy.meta,
            legacy_metadata,
            b"old",
        )
        .unwrap();
        mock.put_document(
            498,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            "device-b.tgf",
            device_b_wire,
        );
        mock.put_document(
            499,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            "legacy.tgf",
            legacy_wire,
        );
        mock.put_document(
            500,
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            "device.tgf",
            device_wire,
        );
        mock.set_next_id(501);

        let refusal = revoke_device_with_transport(
            mock.clone(),
            access_hash,
            &opened,
            installation_id,
            b"replacement-password",
            None,
            false,
            false,
        )
        .await
        .unwrap_err();
        let refusal = format!("{refusal:#}");
        assert!(refusal.contains("Telegram binding is unknown"));
        assert!(refusal.contains("hash=88"));
        assert!(refusal.contains("device model=Mock laptop"));
        assert!(refusal.contains("app name=Telegram Desktop"));
        assert!(refusal.contains("last active Unix=1700000123"));
        assert!(refusal.contains("--telegram-session <hash>"));
        assert!(!mock
            .forum_calls()
            .contains(&ForumCall::ResetOtherAuthorizations));
        let declined = revoke_device_with_transport(
            mock.clone(),
            access_hash,
            &opened,
            installation_id,
            b"replacement-password",
            None,
            true,
            false,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{declined:#}").contains("confirmation declined"),
            "{declined:#}"
        );
        assert!(!mock
            .forum_calls()
            .contains(&ForumCall::ResetOtherAuthorizations));

        mock.set_fail_deletes(!delayed_survivor);
        mock.clear_channel_binding();
        assert!(mock.channel_ref().is_none());
        let result = revoke_and_rotate_command(
            mock.clone(),
            &opened,
            installation_id,
            b"replacement-password",
            None,
            true,
        )
        .await;
        if delayed_survivor {
            result.unwrap();
        } else {
            let migration_error = result.unwrap_err();
            assert!(format!("{migration_error:#}").contains("history migration remains resumable"));
        }

        let mut concurrent_versions = None;
        if concurrent_save {
            let mut ids = Vec::new();
            for (author, path) in [
                (installation_b, "late-survivor.txt"),
                (installation_id, "late-revoked.txt"),
            ] {
                let mut metadata = legacy_v2_logical_metadata(
                    &teagarden_core::sdo::SdoObjectMetadata::test_fixture(),
                );
                metadata.author_device_id = author;
                metadata.path = Some(path.into());
                metadata.version_id = uuid::Uuid::new_v4();
                metadata.clock_ms = now_ms + 10;
                metadata.size = 4;
                let id = metadata.version_id;
                let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
                    opened.config.volume_id,
                    0,
                    &opened.hierarchy.meta,
                    metadata,
                    b"late",
                    Some(&teagarden_core::sdo::device_signing_key(
                        if author == installation_b {
                            &device_b_keys.decapsulation_key.0
                        } else {
                            &revoked_device_c_keys.decapsulation_key.0
                        },
                    )),
                )
                .unwrap();
                let uploaded = mock
                    .upload_file_object(&wire, "teagarden-file-v3.tgf")
                    .await
                    .unwrap();
                ids.push((id, uploaded.message_id));
            }
            concurrent_versions = Some(ids);
        }
        let (poll_sender, mut poll_receiver) = tokio::sync::mpsc::channel(1);
        let poll_cursor = Arc::new(std::sync::atomic::AtomicI64::new(500));
        let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ));
        let _poller = start_sdo_topic_poller(
            mock.clone(),
            opened.config.telegram_group_id,
            opened.config.telegram_topic_id,
            opened.config.volume_id,
            installation_b,
            Some(teagarden_core::crypto::mlkem::MlKemDecapsulationKey(
                device_b_keys.decapsulation_key.0.clone(),
            )),
            0,
            None,
            opened.hierarchy.integrity.clone(),
            std::collections::BTreeMap::from([(0, opened.hierarchy.meta.clone())]),
            poll_cursor,
            last_activity,
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(Mutex::new(None)),
            poll_sender,
            opened.config.sdo_owner_public_key.clone(),
            None,
            durable_transition.then(|| c_opened.paths.base_dir.clone()),
        );
        let handoff_batch =
            tokio::time::timeout(std::time::Duration::from_secs(12), poll_receiver.recv())
                .await
                .expect("mounted poller should observe the per-device key update")
                .expect("poller should deliver a batch");
        let update = handoff_batch.generation_update.as_ref().unwrap();
        assert_eq!(update.active_generation, 1);
        assert!(update.generation_meta_keys.contains_key(&0));
        assert!(update.generation_meta_keys.contains_key(&1));
        let expected_current_meta = update.generation_meta_keys[&1].clone();
        handoff_batch.ack.send(Ok(())).unwrap();
        if durable_transition {
            let password_file = cfg.path().join("original-password");
            std::fs::write(&password_file, b"a-long-enough-pass").unwrap();
            let reopened = utils::open_volume_any(
                &volume_id,
                Some(password_file.to_str().unwrap()),
                None,
                c_volumes.path(),
            )
            .unwrap();
            assert!(reopened.hierarchy.meta.as_bytes() == expected_current_meta.as_bytes(),
                "C remount must install its persisted credential transition without the new password");
            let inputs = teagarden_mfa::unlock::UnlockInputs {
                password: Some(b"a-long-enough-pass"),
                ..Default::default()
            };
            let mounted = open_mount_credentials(&volume_id, &inputs, c_volumes.path()).unwrap();
            assert!(
                mounted.hierarchy.meta.as_bytes() == expected_current_meta.as_bytes(),
                "actual mount unlock must apply C's saved transition"
            );
        }

        mock.set_fail_deletes(false);
        assert!(mock
            .forum_calls()
            .contains(&ForumCall::ResetOtherAuthorizations));
        let old_unlock = teagarden_mfa::unlock::UnlockInputs {
            password: Some(b"a-long-enough-pass"),
            ..Default::default()
        };
        assert!(
            teagarden_mfa::unlock::open_volume(&volume_id, &old_unlock, volumes.path(),).is_err()
        );
        let new_unlock = teagarden_mfa::unlock::UnlockInputs {
            password: Some(b"replacement-password"),
            ..Default::default()
        };
        let rotated =
            teagarden_mfa::unlock::open_volume(&volume_id, &new_unlock, volumes.path()).unwrap();
        if !delayed_survivor {
            mock.clear_channel_binding();
            revoke_and_rotate_command(mock.clone(), &rotated, installation_id, b"", None, true)
                .await
                .unwrap();
        }
        let latest = discover_latest_header(
            mock.as_ref(),
            rotated.config.telegram_group_id,
            rotated.config.telegram_topic_id,
            &rotated.hierarchy.integrity,
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(latest.1.revoked_device_ids.contains(&installation_id));
        assert!(latest.1.rotation_state.is_none());
        assert_eq!(latest.1.key_generation, Some(1));
        let registry = scan_topic_sdo_objects(
            mock.as_ref(),
            rotated.config.telegram_group_id,
            rotated.config.telegram_topic_id,
            &latest.1,
            &rotated.hierarchy,
        )
        .await
        .unwrap()
        .registry;
        if let Some(ids) = &concurrent_versions {
            let scan = scan_topic_sdo_objects(
                mock.as_ref(),
                latest.1.group_id,
                latest.1.topic_id,
                &latest.1,
                &rotated.hierarchy,
            )
            .await
            .unwrap();
            assert!(scan
                .records
                .iter()
                .any(|version| version.record.version_id == ids[0].0));
            assert!(!scan
                .records
                .iter()
                .any(|version| version.record.version_id == ids[1].0));
            let retained = scan
                .records
                .iter()
                .find(|version| version.record.version_id == ids[0].0)
                .unwrap();
            assert_eq!(
                retained.key_generation, 1,
                "acknowledged survivor save must be upgraded"
            );
            assert!(
                mock.get_raw(ids[0].1).is_none(),
                "verified survivor replacement retires old wire"
            );
        }
        let device_b = registry.get(&installation_b).unwrap();
        let update = device_b.key_update.as_ref().unwrap();
        let handed_root = unwrap_device_key_update(
            rotated.config.volume_id,
            update,
            &device_b_keys.decapsulation_key,
        )
        .unwrap();
        assert_eq!(
            teagarden_core::crypto::kdf::derive_hierarchy_from_master_key(
                &handed_root,
                &update.salt,
                rotated.config.telegram_group_id,
                rotated.config.telegram_topic_id,
            )
            .unwrap()
            .meta
            .as_bytes(),
            rotated.hierarchy.meta.as_bytes()
        );
        assert!(unwrap_device_key_update(
            rotated.config.volume_id,
            update,
            &revoked_device_c_keys.decapsulation_key,
        )
        .is_err());
        let handed_hierarchy = teagarden_core::crypto::kdf::derive_hierarchy_from_master_key(
            &handed_root,
            &update.salt,
            rotated.config.telegram_group_id,
            rotated.config.telegram_topic_id,
        )
        .unwrap();
        let new_file_wire = teagarden_core::sdo::SdoFileObjectV3::encode(
            rotated.config.volume_id,
            1,
            &handed_hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: uuid::Uuid::new_v4(),
                origin_message_id: None,
                path: Some("after-revoke.txt".into()),
                size: 6,
                mtime_ns: 1,
                mode: 0o600,
                version_id: uuid::Uuid::new_v4(),
                author_device_id: installation_b,
                previous_version_id: None,
                kind: teagarden_core::sdo::SdoKind::File,
                key_generation: 1,
                clock_ms: 100,
                clock_counter: 0,
                saved_at_ns: 1,
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
                content_sha256: hex::encode(teagarden_core::block::srb2::sha256(b"newkey")),
            },
            b"newkey",
        )
        .unwrap();
        assert_eq!(
            teagarden_core::sdo::SdoFileObjectV3::decode(
                &new_file_wire,
                rotated.config.volume_id,
                1,
                &handed_hierarchy.meta,
            )
            .unwrap()
            .content,
            b"newkey"
        );
        assert!(teagarden_core::sdo::SdoFileObjectV3::decode(
            &new_file_wire,
            opened.config.volume_id,
            1,
            &opened.hierarchy.meta,
        )
        .is_err());
        assert!(mock.download_block(499).await.is_err());
        let migration_state: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                opened
                    .paths
                    .base_dir
                    .join(format!("owner-revoke-{installation_id}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        let legacy_replacement = migration_state["migrated_versions"]
            [legacy_version_id.to_string()]
        .as_i64()
        .unwrap();
        let legacy_download = mock.download_block(legacy_replacement).await.unwrap();
        let legacy_restored = teagarden_core::sdo::SdoFileObjectV3::decode(
            &legacy_download.data,
            volume_id.parse().unwrap(),
            1,
            &rotated.hierarchy.meta,
        )
        .unwrap();
        assert_eq!(legacy_restored.content, b"old");
        // A real revoke followed by a local slot change must retain its header
        // generation/revocations and still support fresh attach and offline decrypt.
        {
            use teagarden_mfa::kslot::protector::SlotProtector;
            use teagarden_mfa::kslot::protectors::{Argon2Cost, PassphraseProtector};
            use teagarden_mfa::kslot::vault::SlotVault;
            let mut slot_opened =
                teagarden_mfa::unlock::open_volume(&volume_id, &new_unlock, volumes.path())
                    .unwrap();
            let path = slot_opened
                .paths
                .base_dir
                .join(teagarden_mfa::unlock::SLOT_VAULT_FILENAME);
            let mut vault = SlotVault::load(&path).unwrap();
            let password =
                PassphraseProtector::new(b"replacement-password".to_vec(), Argon2Cost::default());
            let master = vault.unlock(&[&password as &dyn SlotProtector]).unwrap();
            let mut extra = PassphraseProtector::new(
                b"additional-password".to_vec(),
                Argon2Cost {
                    m_kib: 1024,
                    t: 1,
                    p: 1,
                },
            );
            vault
                .add_independent_slot(&master, &mut extra, "additional password after revoke")
                .unwrap();
            vault.save(&path).unwrap();
            slot_opened.config.key_protection =
                Some(teagarden_core::volume::config::KeyProtection {
                    vault_generation: vault.generation(),
                    vault_digest: hex::encode(vault.state_digest()),
                });
            manager::save_config_resealed(
                &mut slot_opened.config,
                &slot_opened.hierarchy,
                &slot_opened.paths.config_path,
            )
            .unwrap();
            publish_slot_header_update(mock.as_ref(), &slot_opened)
                .await
                .unwrap();
            let (_, changed, _) = discover_latest_header(
                mock.as_ref(),
                latest.1.group_id,
                latest.1.topic_id,
                &rotated.hierarchy.integrity,
                rotated.config.sdo_owner_public_key.as_deref(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(changed.key_generation, latest.1.key_generation);
            assert_eq!(changed.revoked_device_ids, latest.1.revoked_device_ids);
            assert_eq!(changed.device_authorities, latest.1.device_authorities);
            assert_eq!(changed.retained_key_bridges, latest.1.retained_key_bridges);
            assert_eq!(
                changed.generation_boundary_message_id,
                latest.1.generation_boundary_message_id
            );
        }
        let attached_dir = tempfile::tempdir().unwrap();
        let fresh_attach = attach_command(
            mock.as_ref(),
            rotated.config.telegram_group_id,
            rotated.config.telegram_topic_id,
            b"replacement-password",
            false,
            attached_dir.path(),
            rotated.config.sdo_owner_public_key.as_deref(),
        )
        .await
        .unwrap();
        assert_eq!(fresh_attach.config.volume_id, rotated.config.volume_id);
        let operation = opened
            .paths
            .base_dir
            .join(format!("owner-revoke-{installation_id}.json"));
        let operation: serde_json::Value =
            serde_json::from_slice(&std::fs::read(operation).unwrap()).unwrap();
        assert_eq!(operation["phase"], "complete");
        // Exercise offline recovery through the shipped command on each retained
        // replacement, with no TGHD or local volume state beside the document.
        let offline = tempfile::tempdir().unwrap();
        let downloads = offline.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let password_file = offline.path().join("password");
        std::fs::write(&password_file, b"replacement-password").unwrap();
        for (version_id, message_id) in operation["migrated_versions"].as_object().unwrap() {
            let wire = mock
                .download_block(message_id.as_i64().unwrap())
                .await
                .unwrap()
                .data;
            assert!(teagarden_core::sdo::ObjectEnvelope::parse(&wire)
                .unwrap()
                .is_some());
            let object = teagarden_core::sdo::SdoFileObjectV3::decode(
                &wire,
                rotated.config.volume_id,
                1,
                &rotated.hierarchy.meta,
            )
            .unwrap();
            let input = downloads.join("one.tgf");
            std::fs::write(&input, &wire).unwrap();
            let output = offline.path().join(version_id);
            let result = super::super::decrypt::run(
                &input,
                Some(&output),
                Some(password_file.to_str().unwrap()),
                None,
                None,
                rotated.config.sdo_owner_public_key.as_deref(),
                false,
            );
            if object.metadata.kind == teagarden_core::sdo::SdoKind::File
                && !object.metadata.deleted
            {
                result.unwrap();
                assert_eq!(
                    std::fs::read(output.join(object.metadata.path.unwrap())).unwrap(),
                    object.content
                );
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn header_discovery_pages_and_selects_highest_authenticated_revision() {
        use teagarden_core::crypto::keys::SymmetricKey;
        let mock = MockTransport::new();
        for id in 1..=101 {
            mock.put_document(id, -100, 42, "unrelated.bin", vec![0; 8]);
        }
        let integrity = SymmetricKey::from_bytes([0x61; 32]);
        let mut older = HeaderDocument::test_fixture();
        older.group_id = -100;
        older.topic_id = 42;
        older.revision = 2;
        let mut newer = older.clone();
        newer.revision = 7;
        mock.put_document(
            102,
            -100,
            42,
            "teagarden-header-v1.tgh",
            older.encode(&integrity).unwrap(),
        );
        mock.put_document(
            103,
            -100,
            42,
            "teagarden-header-v1.tgh",
            newer.encode(&integrity).unwrap(),
        );
        mock.put_document(
            104,
            -100,
            43,
            "teagarden-header-v1.tgh",
            newer.encode(&integrity).unwrap(),
        );

        let (info, header, _) = discover_latest_header(&mock, -100, 42, &integrity, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.message_id, 103);
        assert_eq!(header.revision, 7);
    }

    #[tokio::test]
    async fn header_discovery_ignores_old_generation_mac_and_authenticates_newest_only() {
        use ed25519_dalek::SigningKey;
        use teagarden_core::crypto::keys::SymmetricKey;

        let mock = MockTransport::new();
        let old_integrity = SymmetricKey::from_bytes([0x81; 32]);
        let new_integrity = SymmetricKey::from_bytes([0x82; 32]);
        let signing = SigningKey::from_bytes(&[0x83; 32]);
        let mut old = HeaderDocument::test_fixture();
        old.format = 2;
        old.owner_public_key = Some(hex::encode(signing.verifying_key().to_bytes()));
        old.key_generation = Some(0);
        old.group_id = -100;
        old.topic_id = 42;
        old.revision = 7;
        let mut newest = old.clone();
        newest.revision = 8;
        newest.key_generation = Some(1);
        newest.generation_boundary_message_id = Some(20);
        mock.put_document(
            19,
            -100,
            42,
            "teagarden-header-v1.tgh",
            old.encode_v2(&old_integrity, &signing).unwrap(),
        );
        mock.put_document(
            20,
            -100,
            42,
            "teagarden-header-v1.tgh",
            newest.encode_v2(&new_integrity, &signing).unwrap(),
        );

        let (info, selected, _) = discover_latest_header(&mock, -100, 42, &new_integrity, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.message_id, 20);
        assert_eq!(selected.revision, 8);
        assert_eq!(selected.key_generation, Some(1));
    }

    #[tokio::test]
    #[cfg(feature = "key-rotation")]
    async fn history_migration_verifies_replacement_before_deleting_old_version() {
        use ed25519_dalek::SigningKey;
        use teagarden_core::crypto::keys::SymmetricKey;

        let mock = MockTransport::new();
        let volume_id = uuid::Uuid::new_v4();
        let old_salt = [0x91; 32];
        let old_root = SymmetricKey::from_bytes([0x92; 32]);
        let old = teagarden_core::crypto::kdf::derive_hierarchy_v1(old_root, &old_salt, -100, 42)
            .unwrap();
        let new_salt = [0x93; 32];
        let new_root = SymmetricKey::from_bytes([0x94; 32]);
        let new = teagarden_core::crypto::kdf::derive_hierarchy_v1(new_root, &new_salt, -100, 42)
            .unwrap();
        let bridge =
            teagarden_core::sdo::KeyGenerationBridge::wrap(0, &old_salt, &old.root, &new.wrapping)
                .unwrap();
        let signing = SigningKey::from_bytes(&[0x95; 32]);
        let mut header = HeaderDocument::test_fixture();
        header.format = 2;
        header.volume_id = volume_id;
        header.owner_public_key = Some(hex::encode(signing.verifying_key().to_bytes()));
        header.key_generation = Some(1);
        header.salt = hex::encode(new_salt);
        header.group_id = -100;
        header.topic_id = 42;
        header.rotation_state =
            Some(serde_json::json!({"phase":"migrating","key_bridges":[bridge]}));
        header.generation_boundary_message_id = Some(20);

        let version_id = uuid::Uuid::new_v4();
        let old_wire = teagarden_core::sdo::SdoFileObjectV3::encode(
            volume_id,
            0,
            &old.meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: uuid::Uuid::new_v4(),
                origin_message_id: Some(7),
                path: Some("history.txt".into()),
                size: 3,
                mtime_ns: 11,
                mode: 0o600,
                version_id,
                author_device_id: uuid::Uuid::new_v4(),
                previous_version_id: None,
                kind: teagarden_core::sdo::SdoKind::File,
                key_generation: 0,
                clock_ms: 17,
                clock_counter: 2,
                saved_at_ns: 0,
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
                content_sha256: hex::encode(teagarden_core::block::srb2::sha256(b"abc")),
            },
            b"abc",
        )
        .unwrap();
        mock.put_document(10, -100, 42, "old.tgf", old_wire);
        let scan = scan_topic_sdo_objects(&mock, -100, 42, &header, &new)
            .await
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut operation = serde_json::json!({"phase":"migration_pending"});
        let migrated = migrate_v3_history(
            &mock,
            &header,
            &new,
            &header.encode_v2(&new.integrity, &signing).unwrap(),
            &scan.records,
            directory.path().join("owner-revoke.json").as_path(),
            &mut operation,
            &signing,
        )
        .await
        .unwrap();
        assert_eq!(migrated, 1);
        assert!(!operation["migrated_versions"][version_id.to_string()].is_null());
        assert!(mock.download_block(10).await.is_err());
        let replacement_id = operation["migrated_versions"][version_id.to_string()]
            .as_i64()
            .unwrap();
        let replacement = mock.download_block(replacement_id).await.unwrap();
        let decoded = teagarden_core::sdo::SdoFileObjectV3::decode(
            &replacement.data,
            volume_id,
            1,
            &new.meta,
        )
        .unwrap();
        assert_eq!(decoded.metadata.version_id, version_id);
        assert_eq!(decoded.content, b"abc");
    }

    #[tokio::test]
    async fn attach_bootstraps_a_new_local_identity_from_the_authenticated_header() {
        let source_dir = tempfile::tempdir().unwrap();
        let local_dir = tempfile::tempdir().unwrap();
        let source = manager::create_volume(
            Some("source"),
            b"portable-password",
            source_dir.path(),
            -100,
            123,
            42,
            None,
        )
        .unwrap();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
        let pin = hex::encode(owner.verifying_key().to_bytes());
        let header = HeaderDocument {
            format: 2,
            volume_id: source.config.volume_id,
            revision: 3,
            volume_version: "1.0.0".into(),
            root_kind: RootKind::Password,
            salt: hex::encode(source.config.salt),
            kdf_params: Some(source.config.kdf_params.clone()),
            group_id: -100,
            topic_id: 42,
            current_epoch: source.config.current_epoch,
            block_v2_from_epoch: source.config.block_v2_from_epoch,
            require_block_integrity: source.config.require_block_integrity,
            block_size: source.config.block_config.target_block_size,
            key_protection: None,
            slot_vault: None,
            owner_public_key: Some(pin.clone()),
            key_generation: Some(0),
            revoked_device_ids: Vec::new(),
            revoked_account_bindings: Vec::new(),
            retained_key_bridges: Vec::new(),
            device_authorities: std::collections::BTreeMap::new(),
            rotation_state: None,
            generation_boundary_message_id: None,
            generation_cutoffs: Default::default(),
            revocation_cutoffs: Default::default(),
        };
        let wire = header
            .encode_v2(&source.hierarchy.integrity, &owner)
            .unwrap();
        let transport = MockTransport::new();
        transport.put_document(9, -100, 42, "opaque.tgh", wire);
        let version_id = uuid::Uuid::from_bytes([0x73; 16]);
        let object = teagarden_core::sdo::SdoFileObjectV3::encode(
            source.config.volume_id,
            0,
            &source.hierarchy.meta,
            teagarden_core::sdo::SdoObjectMetadataV3 {
                authority: None,
                migration_receipt: None,
                file_id: uuid::Uuid::from_bytes([0x72; 16]),
                origin_message_id: None,
                path: Some("notes.txt".into()),
                size: 1,
                mtime_ns: 1,
                mode: 0o600,
                version_id,
                author_device_id: uuid::Uuid::from_bytes([0x74; 16]),
                previous_version_id: None,
                kind: teagarden_core::sdo::SdoKind::File,
                key_generation: 0,
                clock_ms: 77,
                clock_counter: 4,
                saved_at_ns: 0,
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
                segment_count: 0,
                content_sha256: hex::encode(teagarden_core::block::srb2::sha256(b"x")),
            },
            b"x",
        )
        .unwrap();
        transport.put_document(8, -100, 42, "random.tgf", object);

        let attached = attach_command(
            &transport,
            -100,
            42,
            b"portable-password",
            false,
            local_dir.path(),
            Some(&pin),
        )
        .await
        .unwrap();

        assert_eq!(attached.config.volume_id, source.config.volume_id);
        assert_eq!(attached.config.telegram_group_id, -100);
        assert_eq!(attached.config.telegram_topic_id, 42);
        assert_ne!(
            attached.config.sdo_author_device_id,
            source.config.sdo_author_device_id
        );
        assert_eq!(attached.config.sdo_header_revision_published, 3);
        assert_eq!(attached.config.sdo_initial_clock_ms, 77);
        assert_eq!(attached.config.sdo_initial_clock_counter, 4);
        assert!(attached.paths.config_path.exists());
        assert!(attached.paths.db_path.exists());
        let conn = rusqlite::Connection::open(&attached.paths.db_path).unwrap();
        let schema = OpaqueSchema::new(attached.hierarchy.schema.clone(), &logical_tables());
        let inode_store = InodeStore::new(&conn, &schema, &attached.hierarchy.meta);
        let root = inode_store.get(1).unwrap().expect("staged root inode");
        assert!(root.is_dir());
        let file = inode_store
            .lookup(1, "notes.txt")
            .unwrap()
            .expect("imported TGFV file");
        assert!(file.is_file());
        assert_eq!(file.size, 1);
        let sdo_versions = teagarden_store::sdo_version_store::SdoVersionStore::new(&conn, &schema);
        assert_eq!(sdo_versions.list_all().unwrap().len(), 1);
        assert_eq!(
            teagarden_store::sdo_cursor_store::SdoCursorStore::new(&conn, &schema)
                .get()
                .unwrap(),
            Some((9, 9)),
            "attach records the fixed scan high-water for subsequent polling"
        );
        let reopened = manager::open_volume(
            &source.config.volume_id.to_string(),
            b"portable-password",
            local_dir.path(),
        )
        .unwrap();
        assert_eq!(reopened.config.volume_id, source.config.volume_id);
    }

    #[test]
    fn concurrent_sdo_mounts_get_independent_unjournaled_indexes() {
        let local_dir = tempfile::tempdir().unwrap();
        let created = manager::create_volume(
            Some("sdo-private-index"),
            b"portable-password",
            local_dir.path(),
            -100,
            123,
            42,
            None,
        )
        .unwrap();
        let schema = OpaqueSchema::new(created.hierarchy.schema.clone(), &logical_tables());
        let conn = Connection::open(&created.paths.db_path).unwrap();
        initialize_database(&conn, &schema).unwrap();
        let store = InodeStore::new(&conn, &schema, &created.hierarchy.meta);
        store.insert(&Inode::root()).unwrap();
        store
            .insert(&Inode::new_file(2, 1, "shared.txt".into(), 0o600, 0, 0))
            .unwrap();
        drop(conn);

        let mut first = manager::open_volume(
            &created.config.volume_id.to_string(),
            b"portable-password",
            local_dir.path(),
        )
        .unwrap();
        let mut second = manager::open_volume(
            &created.config.volume_id.to_string(),
            b"portable-password",
            local_dir.path(),
        )
        .unwrap();
        let first_conn = open_sdo_mount_db(&mut first).unwrap();
        let second_conn = open_sdo_mount_db(&mut second).unwrap();
        assert_ne!(first.paths.db_path, second.paths.db_path);
        assert_ne!(first.paths.base_dir, first.paths.db_path.parent().unwrap());

        let first_schema = OpaqueSchema::new(first.hierarchy.schema.clone(), &logical_tables());
        let first_store = InodeStore::new(&first_conn, &first_schema, &first.hierarchy.meta);
        let mut file = first_store.get(2).unwrap().unwrap();
        file.size = 27;
        first_store.update(&file).unwrap();

        let second_schema = OpaqueSchema::new(second.hierarchy.schema.clone(), &logical_tables());
        let second_store = InodeStore::new(&second_conn, &second_schema, &second.hierarchy.meta);
        assert_eq!(second_store.get(2).unwrap().unwrap().size, 0);
        assert_eq!(
            teagarden_store::sdo_cursor_store::SdoCursorStore::new(&second_conn, &second_schema)
                .get()
                .unwrap(),
            Some((0, 0))
        );
    }

    #[tokio::test]
    async fn attach_does_not_fall_back_when_the_newest_header_cannot_authenticate() {
        let source_dir = tempfile::tempdir().unwrap();
        let local_dir = tempfile::tempdir().unwrap();
        let source = manager::create_volume(
            Some("source"),
            b"portable-password",
            source_dir.path(),
            -100,
            123,
            42,
            None,
        )
        .unwrap();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
        let pin = hex::encode(owner.verifying_key().to_bytes());
        let header = HeaderDocument {
            format: 2,
            volume_id: source.config.volume_id,
            revision: 3,
            volume_version: "1.0.0".into(),
            root_kind: RootKind::Password,
            salt: hex::encode(source.config.salt),
            kdf_params: Some(source.config.kdf_params.clone()),
            group_id: -100,
            topic_id: 42,
            current_epoch: source.config.current_epoch,
            block_v2_from_epoch: source.config.block_v2_from_epoch,
            require_block_integrity: source.config.require_block_integrity,
            block_size: source.config.block_config.target_block_size,
            key_protection: None,
            slot_vault: None,
            owner_public_key: Some(pin.clone()),
            key_generation: Some(0),
            revoked_device_ids: Vec::new(),
            revoked_account_bindings: Vec::new(),
            retained_key_bridges: Vec::new(),
            device_authorities: std::collections::BTreeMap::new(),
            rotation_state: None,
            generation_boundary_message_id: None,
            generation_cutoffs: Default::default(),
            revocation_cutoffs: Default::default(),
        };
        let older = header
            .encode_v2(&source.hierarchy.integrity, &owner)
            .unwrap();
        let mut newest_header = header;
        newest_header.revision = 4;
        let newest = newest_header
            .encode_v2(
                &teagarden_core::crypto::keys::SymmetricKey::from_bytes([0xa7; 32]),
                &owner,
            )
            .unwrap();
        let transport = MockTransport::new();
        transport.put_document(9, -100, 42, "old.tgh", older);
        transport.put_document(10, -100, 42, "new.tgh", newest);

        let error = attach_command(
            &transport,
            -100,
            42,
            b"portable-password",
            false,
            local_dir.path(),
            Some(&pin),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("authenticate newest Telegram header"));
        assert!(!local_dir
            .path()
            .join(source.config.volume_id.to_string())
            .exists());
    }

    #[test]
    fn auto_reconcile_never_clobbers_an_intact_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");

        // Missing → absent (auto-restore would trigger).
        assert!(local_db_absent(&db), "missing DB is absent");

        // Zero-length → absent (e.g. created-then-crashed before init).
        std::fs::write(&db, b"").unwrap();
        assert!(local_db_absent(&db), "empty DB is absent");

        // Non-empty → present: an intact local DB must NEVER be auto-clobbered.
        std::fs::write(&db, b"SQLite format 3\x00...").unwrap();
        assert!(
            !local_db_absent(&db),
            "an existing non-empty DB must be treated as present"
        );
    }

    /// End-to-end gate for the v0.4.8 revert substrate. Drive a real revert through
    /// `revert_core` against an in-memory channel, then read the result back ONLY
    /// through the published snapshot (never the live connection). This proves the
    /// journaled mutation reached the snapshot — i.e. the revert's WAL was
    /// checkpointed into the main DB file before `publish_snapshot_and_compact` read
    /// it (the `spawn_blocking` + `drop(fs)` ordering). A stale snapshot would
    /// recover the pre-revert head (v2) and fail every version/size assertion below.
    #[test]
    fn revert_substrate_e2e_snapshot_captures_reverted_version() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let volumes_dir = dir.path().to_path_buf();
        let password = "correct horse battery staple";

        // Create an OFFLINE volume (channel 0,0 — no Telegram). revert_core takes an
        // injected MockTransport, so no real network is ever involved.
        let created = rt
            .block_on(create_with_password(
                Some("revert-test"),
                password,
                &volumes_dir,
                0,
                0,
                0,
                None,
            ))
            .expect("create offline volume");
        let volume_id = created.volume_id.clone();

        let result = manager::open_volume(&volume_id, password.as_bytes(), &volumes_dir)
            .expect("open volume");
        let meta_key = result.hierarchy.meta.clone();
        let manifest_key = result.hierarchy.manifest.clone();
        let data_key = result.hierarchy.data.clone();
        let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());

        const V1_SIZE: u64 = 11; // the version we revert TO (smaller)
        const V2_SIZE: u64 = 21; // the head we revert AWAY from (larger)

        // Seed a file with two manifest versions on the fresh, PRE-JOURNAL DB via the
        // public stores. Journaling is inactive here (no HEAD yet), so these writes
        // are NOT captured by any changeset — they land in the base snapshot rather
        // than poisoning the journal chain (the round-2 critical).
        {
            let conn = Connection::open(&result.paths.db_path).unwrap();
            initialize_database(&conn, &schema).unwrap();
            let istore = InodeStore::new(&conn, &schema, &meta_key);
            let mstore = ManifestStore::new(&conn, &schema, &meta_key);
            let bstore = BlockStore::new(&conn, &schema);

            if istore.get(1).unwrap().is_none() {
                istore.insert(&Inode::root()).unwrap();
            }

            let v1_block_id = [0x11u8; 32];
            bstore
                .insert(&BlockRecord {
                    block_id: v1_block_id,
                    filename: "v1-block".into(),
                    message_id: 5_000,
                    plaintext_size: V1_SIZE as i64,
                    encrypted_size: V1_SIZE as i64 + 32,
                    epoch: 0,
                    ref_count: 1,
                    compressed: false,
                    plaintext_sha256: [0u8; 32],
                    ciphertext_sha256: [0u8; 32],
                })
                .unwrap();

            let v1 = FileManifest {
                inode: 2,
                version: 1,
                total_size: V1_SIZE,
                file_hash: [0xA1; 32],
                blocks: vec![BlockPointer {
                    block_id: v1_block_id,
                    message_id: 5_000,
                    file_offset: 0,
                    length: V1_SIZE,
                    block_data_offset: 0,
                    encrypted_size: V1_SIZE + 32,
                    compressed: false,
                    epoch: 0,
                }],
                parent_ids: vec![],
            };
            let v1_id = v1.compute_id(&manifest_key);
            let v2 = FileManifest {
                inode: 2,
                version: 2,
                total_size: V2_SIZE,
                file_hash: [0xA2; 32],
                blocks: vec![BlockPointer {
                    block_id: [0x22u8; 32],
                    message_id: 6_000,
                    file_offset: 0,
                    length: V2_SIZE,
                    block_data_offset: 0,
                    encrypted_size: V2_SIZE + 32,
                    compressed: false,
                    epoch: 0,
                }],
                parent_ids: vec![v1_id],
            };
            mstore.insert(&v1).unwrap();
            mstore.insert(&v2).unwrap();

            // Current head = v2.
            let mut file = Inode::new_file(2, 1, "file".into(), 0o644, 1000, 1000);
            file.manifest = Some(v2);
            file.size = V2_SIZE;
            istore.insert(&file).unwrap();

            // Drop the seeding connection so its WAL is checkpointed into the main DB
            // file before revert_core reads it for the base snapshot.
            drop(conn);
        }

        // Drive the revert through the REAL substrate with an in-memory channel.
        let transport = Arc::new(MockTransport::new());
        let (new_version, size) = rt
            .block_on(revert_core(result, transport.clone(), "/file", 1))
            .expect("revert_core succeeds");
        assert_eq!(
            new_version, 3,
            "revert appends a new version above the head"
        );
        assert_eq!(size, V1_SIZE, "reverted live size matches v1");

        // Re-open (config was resealed by compaction) and read back ONLY through the
        // published snapshot — never the live conn.
        let result2 = manager::open_volume(&volume_id, password.as_bytes(), &volumes_dir)
            .expect("re-open volume");
        let head = JournalHead::load(&journal_head_path(&result2), &result2.hierarchy.integrity)
            .expect("load head")
            .expect("head present after revert");
        assert_eq!(head.seq, 0, "journal compacted to seq 0 after revert");

        let snap_blob = transport
            .get_raw(head.base_snapshot_msg_id)
            .expect("post-revert snapshot present in channel");
        let (_v, db_bytes) =
            metadata_snapshot::decrypt_snapshot(&data_key, &snap_blob).expect("decrypt snapshot");

        let recovered_db = dir.path().join("recovered.db");
        std::fs::write(&recovered_db, &db_bytes).unwrap();
        let rconn = Connection::open(&recovered_db).unwrap();
        let rstore = InodeStore::new(&rconn, &schema, &meta_key);
        let recovered = rstore
            .get(2)
            .unwrap()
            .expect("file inode recovered from snapshot");
        let rmanifest = recovered.manifest.expect("recovered manifest present");

        assert_eq!(
            rmanifest.version, 3,
            "the snapshot must capture the reverted head (v3), not the stale pre-revert v2"
        );
        assert_eq!(
            recovered.size, V1_SIZE,
            "recovered inode size must be v1's — proves the revert reached the snapshot"
        );
        assert_eq!(
            rmanifest.total_size, V1_SIZE,
            "recovered manifest content size is v1's"
        );
        assert_eq!(
            rmanifest.parent_ids.len(),
            2,
            "reverting version descends from BOTH the prior head and the target — history preserved"
        );

        // The full version history survives the revert (nothing overwritten).
        let mstore2 = ManifestStore::new(&rconn, &schema, &meta_key);
        assert_eq!(
            mstore2.list_versions(2).unwrap(),
            vec![1, 2, 3],
            "all versions preserved in history after revert"
        );
    }

    /// Wrapper-level coverage (audit v0.4.8 #8): the delivered `volume revert`
    /// command must REFUSE on an offline volume — the mutation is journaled, and an
    /// un-journaled write to a journaled table poisons recovery. An offline volume
    /// (`telegram_group_id == 0`) makes `revert_in` return `Err` on BOTH arms
    /// (credentials-missing → bail, or credentials-present → "no Telegram channel
    /// recorded" → bail), so the assertion is hermetic regardless of the test host's
    /// Telegram config, and it never reaches a real network connect.
    #[test]
    fn revert_refuses_on_offline_volume() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let volumes_dir = dir.path().to_path_buf();
        let password = "correct horse battery staple";

        // Offline volume — channel (0, 0), telegram_group_id == 0.
        let created = rt
            .block_on(create_with_password(
                Some("offline-vol"),
                password,
                &volumes_dir,
                0,
                0,
                0,
                None,
            ))
            .expect("create offline volume");

        let pwfile = dir.path().join("pw");
        std::fs::write(&pwfile, password).unwrap();

        let err = rt
            .block_on(revert_in(
                &volumes_dir,
                &created.volume_id,
                "/whatever",
                1,
                Some(pwfile.to_str().unwrap()),
                None,
            ))
            .expect_err("revert must refuse an offline (un-journaled) volume");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Telegram") || msg.contains("no Telegram channel"),
            "offline refusal should cite the missing channel/credentials, got: {msg}"
        );
    }

    /// C3: a WRITABLE mount with no Telegram transport must be refused with a clear
    /// message before anything is mounted — offline, every file write would be
    /// accepted and then silently discarded. Hermetic like the revert test above:
    /// an offline volume (`telegram_group_id == 0`) is refused on BOTH arms
    /// (no credentials → the new refusal; credentials present → the existing
    /// "no forum group/topic" bail), and neither arm reaches `fuser::mount2`.
    /// A watchdog unmounts and fails the test if the mount actually happens.
    #[test]
    fn mount_refuses_writable_mount_without_transport() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let volumes_dir = dir.path().join("volumes");
        std::fs::create_dir_all(&volumes_dir).unwrap();
        let password = "correct horse battery staple";
        let created = rt
            .block_on(create_with_password(
                Some("offline-mount"),
                password,
                &volumes_dir,
                0,
                0,
                0,
                None,
            ))
            .expect("create offline volume");
        drop(rt);
        let pwfile = dir.path().join("pw");
        std::fs::write(&pwfile, password).unwrap();
        let mp = dir.path().join("mnt");
        std::fs::create_dir_all(&mp).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        {
            let volumes_dir = volumes_dir.clone();
            let volume_id = created.volume_id.clone();
            let mp = mp.to_string_lossy().into_owned();
            let pwfile = pwfile.to_string_lossy().into_owned();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let r = rt.block_on(mount_in(
                    &volumes_dir,
                    &volume_id,
                    &mp,
                    false,
                    Some(&pwfile),
                    None,
                    &FactorSelect::default(),
                ));
                let _ = tx.send(r.map_err(|e| format!("{e:#}")));
            });
        }

        let mp_str = mp.to_string_lossy().into_owned();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let result = loop {
            if let Ok(r) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
                break r;
            }
            let mounted = std::fs::read_to_string("/proc/self/mounts")
                .map(|m| {
                    m.lines()
                        .any(|l| l.split(' ').nth(1) == Some(mp_str.as_str()))
                })
                .unwrap_or(false);
            if mounted || std::time::Instant::now() > deadline {
                let _ = std::process::Command::new("fusermount3")
                    .arg("-u")
                    .arg(&mp)
                    .status();
                panic!("writable mount without a transport was NOT refused (mounted: {mounted})");
            }
        };
        let msg = result.expect_err("a writable offline mount must be refused");
        eprintln!("refusal: {msg}");
        assert!(
            msg.contains("without a Telegram transport")
                || msg.contains("no forum group/topic")
                || msg.contains("Not authenticated with Telegram"),
            "refusal should explain the missing transport, got: {msg}"
        );
        assert!(
            !msg.contains("FUSE mount failed"),
            "must be refused before reaching the FUSE mount, got: {msg}"
        );
    }

    // ── round 8 ──────────────────────────────────────────────────────────────

    /// A failed `journal_init_phase` (here the HEAD cannot be written) must not
    /// clear the record that the volume's cloud metadata is stale: it may only
    /// go once the snapshot, volume.json and the HEAD are all written.
    #[tokio::test]
    async fn a_failed_journal_init_never_clears_the_stale_cloud_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut result = opened_volume_with_db(dir.path());
        let mock = MockTransport::new();
        mock.set_connected(false);
        publish_as_new_session(&mut result, &mock)
            .await
            .unwrap_err();
        mock.set_connected(true);
        let record = result.paths.base_dir.join(SNAPSHOT_FAILED_MARKER);
        assert!(record.exists());
        // The HEAD becomes unwritable once the base snapshot is uploaded.
        let hp = journal_head_path(&result);
        let block = hp.clone();
        mock.after_next_metadata_sync(move || {
            std::fs::create_dir(&block).unwrap();
            std::fs::write(block.join("block-rename"), b"x").unwrap();
        });
        let conn = local_db::open_existing(&result.paths.db_path).unwrap();
        let mut db = begin_db_session(&result, &conn, None).unwrap();
        drop(conn);
        let err = journal_init_phase(&mut result, &mock, &mut db)
            .await
            .expect_err("the HEAD cannot be written");
        eprintln!("journal init with an unwritable HEAD: {err:#}");
        assert!(
            record.exists(),
            "a failed journal init cleared the stale-cloud record"
        );
        assert!(snapshot_publish_status(&result.paths.base_dir).is_err());
    }

    /// A volume that published a snapshot but lost its local DB: `volume delete`
    /// never creates a DB to count blocks in. Without a topic (blocks deleted
    /// by id) it refuses, since an empty DB would list none and orphan them;
    /// with a topic, a failed topic delete leaves the volume as it was.
    #[tokio::test]
    async fn delete_never_creates_a_metadata_db() {
        for topic in [0, DEL_TOPIC] {
            let dir = tempfile::tempdir().unwrap();
            let created = manager::create_volume(
                Some("to-delete"),
                DEL_PASS.as_bytes(),
                dir.path(),
                DEL_GROUP,
                DEL_HASH,
                topic,
                None,
            )
            .unwrap();
            let id = created.config.volume_id.to_string();
            let pass = dir.path().join("pass.txt");
            std::fs::write(&pass, DEL_PASS).unwrap();
            // The snapshot id is outside the config MAC.
            let mut v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&created.paths.config_path).unwrap())
                    .unwrap();
            v["metadata_snapshot_id"] = serde_json::json!(4242);
            std::fs::write(
                &created.paths.config_path,
                serde_json::to_vec_pretty(&v).unwrap(),
            )
            .unwrap();
            let mock = Arc::new(MockTransport::new());
            mock.set_fail_forum(true);
            let err = delete_in(
                dir.path(),
                &id,
                true,
                Some(pass.to_str().unwrap()),
                None,
                false,
                connect_mock(mock.clone()),
            )
            .await
            .expect_err("must not delete");
            eprintln!("delete (topic {topic}) with a lost DB: {err:#}");
            assert!(
                !created.paths.db_path.exists(),
                "topic {topic}: delete created a metadata DB"
            );
            assert!(created.paths.config_path.exists());
            if topic == 0 {
                assert!(format!("{err:#}").contains("rebuilt"), "{err:#}");
                assert!(mock.forum_calls().is_empty());
            }
        }
    }
}
