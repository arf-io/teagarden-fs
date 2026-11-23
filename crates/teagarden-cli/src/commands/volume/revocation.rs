//! The 1.0 access cut. No credential change, handoff, migration or ciphertext rewrite.
use super::*;
use teagarden_core::sdo::RevocationCutoff;
use teagarden_telegram::client::TelegramAuthorizationInfo;

type ConfirmedSessions = std::collections::BTreeMap<uuid::Uuid, ConfirmedSession>;

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub(super) enum ConfirmedSession {
    Current(i64),
    Rebound { hash: i64, previous_hash: i64 },
}

impl ConfirmedSession {
    fn hash(&self) -> i64 {
        match self {
            Self::Current(hash) | Self::Rebound { hash, .. } => *hash,
        }
    }

    fn matches(&self, announced: i64) -> bool {
        self.hash() == announced
            || matches!(self, Self::Rebound { previous_hash, .. } if *previous_hash == announced)
    }

    fn previous_hash(&self) -> Option<i64> {
        match self {
            Self::Current(_) => None,
            Self::Rebound { previous_hash, .. } => Some(*previous_hash),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionBinding {
    installation_id: uuid::Uuid,
    authorization_hash: String,
    previous_authorization_hash: Option<String>,
}

pub(super) fn load_confirmed_session_map(path: &std::path::Path) -> Result<ConfirmedSessions> {
    let entries: Vec<SessionBinding> = serde_json::from_slice(&std::fs::read(path)?)
        .context("the confirmed Telegram session map must be a JSON array of bindings")?;
    anyhow::ensure!(
        !entries.is_empty(),
        "the confirmed Telegram session map is empty"
    );
    let mut confirmed = ConfirmedSessions::new();
    let mut hashes = std::collections::BTreeSet::new();
    for entry in entries {
        let hash = entry.authorization_hash.parse::<i64>().ok().filter(|hash| *hash != 0)
            .context("the confirmed Telegram session map contains an invalid or masked authorization hash")?;
        let binding = if let Some(previous) = entry.previous_authorization_hash {
            let previous_hash = parse_authorization_hash(&previous)
                .filter(|previous| *previous != hash)
                .context("the previous Telegram authorization hash is invalid or unchanged")?;
            ConfirmedSession::Rebound {
                hash,
                previous_hash,
            }
        } else {
            ConfirmedSession::Current(hash)
        };
        anyhow::ensure!(
            hashes.insert(hash)
                && binding.previous_hash().is_none_or(|previous| hashes.insert(previous))
                && confirmed.insert(entry.installation_id, binding).is_none(),
            "the confirmed Telegram session map contains duplicate installation IDs or authorizations"
        );
    }
    Ok(confirmed)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessCut {
    volume_id: uuid::Uuid,
    installation_id: uuid::Uuid,
    owner_public_key: String,
    cutoff: RevocationCutoff,
    device_authorities: std::collections::BTreeMap<uuid::Uuid, String>,
    phase: Phase,
    telegram_user_id: i64,
    owner_telegram_user_id: i64,
    authorization_session_hash: Option<String>,
    #[serde(default)]
    target_authorization_verified: bool,
    #[serde(default)]
    confirmed_sessions: ConfirmedSessions,
    #[serde(default)]
    reset_other_sessions: Option<bool>,
}

impl AccessCut {
    fn telegram_cut_verified(&self) -> bool {
        self.telegram_user_id != self.owner_telegram_user_id || self.target_authorization_verified
    }

    fn print_completion(&self) {
        if self.telegram_user_id != self.owner_telegram_user_id {
            println!("Revocation policy recorded. Telegram confirmed the group ban for the installation's registered account; the original volume credential is unchanged.");
        } else if self.telegram_cut_verified() {
            println!("Revocation complete. Telegram access is removed; the original volume credential is unchanged.");
        } else {
            println!("Revocation policy recorded. The previous operation did not verify a distinct target Telegram authorization.");
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    AccessCut,
    Complete,
}

fn save(path: &std::path::Path, operation: &AccessCut) -> Result<()> {
    teagarden_core::fsutil::write_file_atomic(
        path,
        &serde_json::to_vec_pretty(operation)?,
        "owner access-cut state",
    )?;
    Ok(())
}

fn target_authorization(binding: Option<i64>) -> Result<i64> {
    binding.context(
        "cannot safely identify the target's Telegram authorization. Use an independently approved login and an owner-confirmed session map when Telegram masks the current session hash",
    )
}

fn session_binding(
    installation_id: &uuid::Uuid,
    entry: &teagarden_core::sdo::DeviceAnnouncement,
    confirmed: &ConfirmedSessions,
) -> Result<Option<i64>> {
    let announced = entry
        .authorization_session_hash
        .as_deref()
        .and_then(parse_authorization_hash);
    let Some(mapped) = confirmed.get(installation_id) else {
        return Ok(announced);
    };
    anyhow::ensure!(
        announced.is_none_or(|hash| mapped.matches(hash)),
        "the confirmed map conflicts with the installation's authenticated Telegram binding; provide the exact previous authorization when renewing a verified owner-approved login"
    );
    Ok(Some(mapped.hash()))
}

fn require_live_confirmed_sessions(
    authorizations: &[TelegramAuthorizationInfo],
    confirmed: &ConfirmedSessions,
) -> Result<()> {
    for binding in confirmed.values() {
        let mut matches = authorizations
            .iter()
            .filter(|entry| entry.hash == binding.hash());
        anyhow::ensure!(
            matches.next().is_some_and(|entry| !entry.current) && matches.next().is_none(),
            "a confirmed binding is absent, ambiguous, or is the owner's current authorization; no sessions were reset"
        );
        anyhow::ensure!(
            binding.previous_hash().is_none_or(|previous| {
                !authorizations.iter().any(|entry| entry.hash == previous)
            }),
            "a previous authorization in the renewed session map is still live; no sessions were reset"
        );
    }
    Ok(())
}

fn require_distinct_authorization(
    registry: &teagarden_core::sdo::DeviceRegistry,
    header: &HeaderDocument,
    installation_id: uuid::Uuid,
    telegram_user_id: i64,
    authorization_hash: i64,
    confirmed: &ConfirmedSessions,
    owner_installation: Option<uuid::Uuid>,
) -> Result<()> {
    let active = |id: &uuid::Uuid, entry: &teagarden_core::sdo::DeviceAnnouncement| {
        entry.telegram_user_id == telegram_user_id && !header.revoked_device_ids.contains(id)
    };
    let target = registry
        .get(&installation_id)
        .filter(|entry| active(&installation_id, entry));
    anyhow::ensure!(
        target
            .map(|entry| session_binding(&installation_id, entry, confirmed))
            .transpose()?
            .flatten()
            == Some(authorization_hash),
        "the target Telegram authorization changed; no sessions were reset"
    );
    for id in confirmed.keys() {
        anyhow::ensure!(
            Some(*id) != owner_installation && registry.get(id).is_some_and(|entry| active(id, entry)),
            "the confirmed map contains the owner installation or an installation outside the active account registry"
        );
    }
    for (id, entry) in registry.iter().filter(|(id, entry)| active(id, entry)) {
        if *id == installation_id {
            continue;
        }
        let peer = session_binding(id, entry, confirmed)?;
        anyhow::ensure!(
            peer != Some(authorization_hash),
            "the target shares its Telegram authorization with another active installation; revoking it would also sign out that installation. Give the installations distinct logins before revoking one"
        );
        anyhow::ensure!(
            confirmed.is_empty() || Some(*id) == owner_installation || confirmed.contains_key(id),
            "another active installation has no confirmed Telegram binding; no sessions were reset"
        );
    }
    Ok(())
}

/// Access-only administration never opens the mount's disposable index. Its
/// independent lock serializes revoke journals and signed policy publication.
pub(super) fn lock_owner_administration(
    base_dir: &std::path::Path,
) -> Result<manager::OwnerAdminLock> {
    Ok(manager::OwnerAdminLock::acquire(base_dir)?)
}

#[cfg(test)]
pub(super) async fn command<T: ForumAdmin + 'static>(
    client: Arc<T>,
    opened: &manager::OpenVolumeResult,
    installation_id: uuid::Uuid,
    telegram_session: Option<i64>,
    all_sessions_confirmed: bool,
) -> Result<()> {
    let admin = lock_owner_administration(&opened.paths.base_dir)?;
    command_in_transaction(
        client,
        opened,
        installation_id,
        telegram_session,
        all_sessions_confirmed,
        &ConfirmedSessions::new(),
        &admin,
    )
    .await
}

pub(super) async fn command_in_transaction<T: ForumAdmin + 'static>(
    client: Arc<T>,
    opened: &manager::OpenVolumeResult,
    installation_id: uuid::Uuid,
    telegram_session: Option<i64>,
    all_sessions_confirmed: bool,
    confirmed_sessions: &ConfirmedSessions,
    admin: &manager::OwnerAdminLock,
) -> Result<()> {
    anyhow::ensure!(
        confirmed_sessions.is_empty() || (telegram_session.is_some() && !all_sessions_confirmed),
        "a confirmed session map requires one explicit --telegram-session and cannot reset all logins"
    );
    admin.require_config(&opened.paths.config_path)?;
    let signer = load_owner_capability(&opened.paths.config_path)
        .context("owner signing capability is required before revocation")?;
    let pinned = opened
        .config
        .sdo_owner_public_key
        .as_deref()
        .context("revocation requires a pinned TGHD2 owner")?;
    anyhow::ensure!(
        hex::encode(signer.verifying_key().to_bytes()) == pinned,
        "owner capability does not match the pinned TGHD2 public key"
    );
    anyhow::ensure!(
        Some(installation_id) != opened.config.sdo_author_device_id,
        "cannot revoke this owner installation from itself; use another owner installation"
    );
    let access_hash = bind_opened_topic(client.as_ref(), &opened.config).await?;
    let (_, mut header, _) = discover_latest_header(
        client.as_ref(),
        opened.config.telegram_group_id,
        opened.config.telegram_topic_id,
        &opened.hierarchy.integrity,
        Some(pinned),
    )
    .await?
    .context("no authenticated portable header exists")?;
    policy::observe(&opened.paths.config_path, &header)?;
    anyhow::ensure!(
        header.volume_id == opened.config.volume_id,
        "authenticated owner header belongs to another volume"
    );
    header.require_complete_revocation_cutoffs()?;
    anyhow::ensure!(
        header.revision >= opened.config.sdo_header_revision_published,
        "latest owner header is missing; refusing a revocation against rolled-back policy"
    );
    let path = opened
        .paths
        .base_dir
        .join(format!("owner-access-cut-{installation_id}.json"));
    let mut operation: Option<AccessCut> = if path.exists() {
        Some(
            serde_json::from_slice(&std::fs::read(&path)?)
                .context("read resumable access-cut state")?,
        )
    } else {
        None
    };
    if let Some(operation) = &operation {
        anyhow::ensure!(
            operation.volume_id == header.volume_id
                && operation.installation_id == installation_id
                && operation.owner_public_key == pinned
                && operation.cutoff.boundary_message_id > 0,
            "access-cut state does not match this volume, installation and owner"
        );
        anyhow::ensure!(
            confirmed_sessions.is_empty() || &operation.confirmed_sessions == confirmed_sessions,
            "the supplied session map differs from the original access-cut record"
        );
        anyhow::ensure!(
            telegram_session.is_none()
                || operation
                    .authorization_session_hash
                    .as_deref()
                    .and_then(parse_authorization_hash)
                    == telegram_session,
            "the supplied authorization differs from the original access-cut record"
        );
        anyhow::ensure!(
            !all_sessions_confirmed || operation.confirmed_sessions.is_empty(),
            "the original access cut names one confirmed authorization and cannot reset all logins"
        );
    }
    if opened.config.sdo_header_pending {
        let operation = operation
            .as_mut()
            .context("another owner header update is pending; repair it before revoking")?;
        anyhow::ensure!(
            operation.phase == Phase::AccessCut,
            "pending header does not belong to a completed Telegram access cut"
        );
        let bytes = hex::decode(
            opened
                .config
                .sdo_header_pending_bytes
                .as_deref()
                .context("pending owner header bytes missing")?,
        )?;
        let pending =
            HeaderDocument::decode_pinned(&bytes, &opened.hierarchy.integrity, Some(pinned))?;
        anyhow::ensure!(
            pending.revoked_device_ids.contains(&installation_id)
                && pending.revocation_cutoffs.get(&installation_id) == Some(&operation.cutoff)
                && operation
                    .device_authorities
                    .iter()
                    .all(|(id, key)| pending.device_authorities.get(id) == Some(key)),
            "pending owner header does not match this immutable access cutoff"
        );
        publish_signed_header_update_in_transaction(
            client.as_ref(),
            &opened.config,
            &opened.hierarchy,
            &opened.paths.config_path,
            opened.config.sdo_header_revision_published,
            pending,
            admin,
        )
        .await?;
        operation.phase = Phase::Complete;
        save(&path, operation)?;
        operation.print_completion();
        return Ok(());
    }
    if header.revoked_device_ids.contains(&installation_id) {
        if let Some(operation) = operation.as_mut() {
            anyhow::ensure!(
                header.revocation_cutoffs.get(&installation_id) == Some(&operation.cutoff)
                    && operation
                        .device_authorities
                        .iter()
                        .all(|(id, key)| header.device_authorities.get(id) == Some(key)),
                "recorded device cutoff differs from this access-cut operation"
            );
            operation.phase = Phase::Complete;
            save(&path, operation)?;
        }
        println!(
            "Installation {installation_id} is already revoked; its original cutoff is unchanged."
        );
        return Ok(());
    }
    let continuing = operation.is_some();
    if operation.is_none() {
        let scan = scan_topic_sdo_objects(
            client.as_ref(),
            header.group_id,
            header.topic_id,
            &header,
            &opened.hierarchy,
        )
        .await?;
        let target = scan
            .registry
            .get(&installation_id)
            .context("installation is not in the active registry")?;
        let owner_telegram_user_id = client
            .telegram_user_id()
            .await?
            .context("authenticated Telegram user id is unavailable")?;
        anyhow::ensure!(
            confirmed_sessions.is_empty() || target.telegram_user_id == owner_telegram_user_id,
            "a confirmed session map applies only to installations on the owner's Telegram account"
        );
        let binding = session_binding(&installation_id, target, confirmed_sessions)?;
        if let Some(explicit) = telegram_session {
            let bound = binding.context(
                "authenticated target binding is missing; cannot correlate a session override without a confirmed map",
            )?;
            anyhow::ensure!(
                bound == explicit,
                "Telegram session override does not match the authenticated target binding"
            );
        }
        if target.telegram_user_id == owner_telegram_user_id {
            let hash = target_authorization(binding)?;
            if !all_sessions_confirmed {
                require_distinct_authorization(
                    &scan.registry,
                    &header,
                    installation_id,
                    target.telegram_user_id,
                    hash,
                    confirmed_sessions,
                    opened.config.sdo_author_device_id,
                )?;
                anyhow::ensure!(
                    confirmed_sessions.contains_key(&installation_id),
                    "targeted same-account revocation requires a fresh owner-confirmed session map; no sessions were reset"
                );
            }
        }
        if !confirmed_sessions.is_empty() {
            require_live_confirmed_sessions(&client.authorizations().await?, confirmed_sessions)?;
        }
        let mut device_authorities = header.device_authorities.clone();
        for (id, _) in scan.registry.iter() {
            if *id == installation_id {
                continue;
            }
            let key = scan.device_authorities.get(id).or_else(|| header.device_authorities.get(id))
                .with_context(|| format!("remaining installation {id} has no authenticated installation signing key; obtain its signed registry announcement before revoking; no Telegram access was cut"))?;
            if let Some(existing) = device_authorities.get(id) {
                anyhow::ensure!(
                    existing == key,
                    "registered installation {id} differs from its frozen signing key"
                );
            }
            device_authorities.insert(*id, key.clone());
        }
        operation = Some(AccessCut {
            volume_id: header.volume_id,
            installation_id,
            owner_public_key: pinned.to_owned(),
            // Freeze the first excluded position before the cut. A retry never
            // advances this boundary and therefore cannot re-admit later writes.
            cutoff: RevocationCutoff {
                key_generation: header.key_generation.unwrap_or(0),
                boundary_message_id: scan
                    .high_water_message_id
                    .checked_add(1)
                    .context("device cutoff overflow")?,
            },
            device_authorities,
            phase: Phase::Prepared,
            telegram_user_id: target.telegram_user_id,
            owner_telegram_user_id,
            authorization_session_hash: if confirmed_sessions.contains_key(&installation_id) {
                binding.map(|hash| hash.to_string())
            } else {
                target.authorization_session_hash.clone()
            },
            target_authorization_verified: false,
            confirmed_sessions: confirmed_sessions.clone(),
            reset_other_sessions: Some(all_sessions_confirmed),
        });
        save(&path, operation.as_ref().unwrap())?;
    }
    let operation = operation.as_mut().unwrap();
    if operation.phase == Phase::Prepared {
        let current_user = client
            .telegram_user_id()
            .await?
            .context("authenticated Telegram user id is unavailable")?;
        anyhow::ensure!(
            current_user == operation.owner_telegram_user_id,
            "resume the access cut from the original owner Telegram account"
        );
        if current_user != operation.telegram_user_id {
            if continuing {
                let scan = scan_topic_sdo_objects(
                    client.as_ref(),
                    header.group_id,
                    header.topic_id,
                    &header,
                    &opened.hierarchy,
                )
                .await?;
                anyhow::ensure!(
                    scan.registry.get(&installation_id).is_some_and(|entry|
                        entry.telegram_user_id == operation.telegram_user_id
                    ),
                    "the registered Telegram account changed since this cut was prepared; no group ban was sent"
                );
            }
            client
                .ban_group_member(header.group_id, access_hash, operation.telegram_user_id)
                .await
                .context("access cut FAILED: Telegram refused channels.editBanned")?;
        } else {
            let target_hash = target_authorization(
                operation
                    .authorization_session_hash
                    .as_deref()
                    .and_then(parse_authorization_hash),
            )?;
            let authorizations = client.authorizations().await?;
            if let Some(target) = authorizations.iter().find(|a| a.hash == target_hash) {
                anyhow::ensure!(
                    !target.current,
                    "cannot revoke the owner's current Telegram authorization; use another owner session"
                );
                anyhow::ensure!(
                    operation.reset_other_sessions == Some(all_sessions_confirmed),
                    "the pending access cut lacks the original scope or its confirmation; no sessions were reset"
                );
                anyhow::ensure!(
                    all_sessions_confirmed || operation.confirmed_sessions.contains_key(&installation_id),
                    "the pending access cut lacks current owner confirmation; no sessions were reset"
                );
                if !all_sessions_confirmed {
                    let scan = scan_topic_sdo_objects(
                        client.as_ref(),
                        header.group_id,
                        header.topic_id,
                        &header,
                        &opened.hierarchy,
                    )
                    .await?;
                    require_distinct_authorization(
                        &scan.registry,
                        &header,
                        installation_id,
                        operation.telegram_user_id,
                        target_hash,
                        &operation.confirmed_sessions,
                        opened.config.sdo_author_device_id,
                    )?;
                }
                require_live_confirmed_sessions(&authorizations, &operation.confirmed_sessions)?;
                if !operation.target_authorization_verified {
                    operation.target_authorization_verified = true;
                    save(&path, operation)?;
                }
                if all_sessions_confirmed {
                    client
                        .reset_other_authorizations()
                        .await
                        .context("access cut FAILED: Telegram refused auth.resetAuthorizations")?;
                } else {
                    client.reset_authorization(target_hash).await.context(
                        "access cut FAILED: Telegram refused account.resetAuthorization",
                    )?;
                }
            } else {
                // The reset may have succeeded before the response or next
                // local journal update. Only a previously verified target can
                // establish the desired state by being absent on retry.
                anyhow::ensure!(
                    operation.target_authorization_verified,
                    "the target Telegram authorization was not found"
                );
            }
        }
        operation.phase = Phase::AccessCut;
        save(&path, operation)?;
    }
    anyhow::ensure!(
        operation.phase == Phase::AccessCut,
        "access-cut journal is complete but the owner policy is missing"
    );
    for (id, key) in &operation.device_authorities {
        anyhow::ensure!(
            header
                .device_authorities
                .get(id)
                .is_none_or(|current| current == key),
            "owner policy changed a frozen installation signing key during the access cut"
        );
        header.device_authorities.insert(*id, key.clone());
    }
    header.revoked_device_ids.push(installation_id);
    header
        .revocation_cutoffs
        .entry(installation_id)
        .or_insert_with(|| operation.cutoff.clone());
    if operation.telegram_user_id == operation.owner_telegram_user_id {
        if let Some(binding) = &operation.authorization_session_hash {
            if !header.revoked_account_bindings.contains(binding) {
                header.revoked_account_bindings.push(binding.clone());
            }
        }
    }
    publish_signed_header_update_in_transaction(
        client.as_ref(),
        &opened.config,
        &opened.hierarchy,
        &opened.paths.config_path,
        header.revision,
        header,
        admin,
    )
    .await
    .context(if operation.telegram_user_id != operation.owner_telegram_user_id {
        "Telegram confirmed the group ban for the registered account; signed revocation publication remains resumable"
    } else if operation.telegram_cut_verified() {
        "Telegram access is removed; signed revocation publication remains resumable"
    } else {
        "signed revocation publication remains resumable; the previous Telegram cut was not verified"
    })?;
    operation.phase = Phase::Complete;
    save(&path, operation)?;
    operation.print_completion();
    Ok(())
}
