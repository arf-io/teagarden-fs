use anyhow::{Context, Result};
use std::collections::VecDeque;

use teagarden_core::block::pointer::FileManifest;
use teagarden_core::volume::manager;
use teagarden_store::dag_store::DagStore;
use teagarden_store::inode_store::InodeStore;
use teagarden_store::local_db::{self, LocalDb};
use teagarden_store::manifest_store::ManifestStore;
use teagarden_store::migrations::initialize_database;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::schema::logical_tables;

use super::utils;

type SdoHistoryRecord = (
    String,
    String,
    String,
    String,
    u64,
    u64,
    u64,
    bool,
    Option<String>,
);

type SdoTopicScan = (
    teagarden_core::sdo::HeaderDocument,
    Vec<SdoHistoryRecord>,
    Option<(teagarden_core::sdo::SdoObjectMetadataV3, Vec<u8>)>,
    (u64, u64),
    std::sync::Arc<dyn teagarden_telegram::client::BlockTransport>,
);

async fn scan_tgfvs(v: &OpenedVolume, restore_id: Option<uuid::Uuid>) -> Result<SdoTopicScan> {
    anyhow::ensure!(
        v.group_id != 0 && v.topic_id != 0,
        "TGFV volume is missing its Telegram topic"
    );
    let transport = history_transport().await?;
    let (_, header, _) = super::volume::discover_latest_header(
        transport.as_ref(),
        v.group_id,
        v.topic_id,
        &v.hierarchy.integrity,
        v.owner_public_key.as_deref(),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("no authenticated TGHD header found in Telegram topic"))?;
    super::volume::observe_header_revision(&v.base_dir.join("volume.json"), &header)?;
    scan_tgfvs_with_source(v, transport, header, restore_id).await
}

async fn history_transport(
) -> Result<std::sync::Arc<dyn teagarden_telegram::client::BlockTransport>> {
    #[cfg(test)]
    if let Some(transport) = TEST_TRANSPORT.with(|transport| transport.borrow().clone()) {
        return Ok(transport);
    }
    let (api_id, api_hash) = utils::load_telegram_credentials()
        .context("Telegram credentials are required for TGFV history")?;
    let client = teagarden_telegram::client::TelegramClient::new(
        teagarden_telegram::types::TelegramConfig {
            api_id,
            api_hash,
            session_path: utils::session_file_path().to_string_lossy().to_string(),
            channel_ref: None,
            ..Default::default()
        },
    );
    anyhow::ensure!(
        client.connect().await.map_err(utils::telegram_err)?
            == teagarden_telegram::types::AuthState::Authenticated,
        "Not authenticated with Telegram. Run `teagarden auth login` first."
    );
    Ok(std::sync::Arc::new(client))
}

fn history_volumes_dir() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(dir) = TEST_VOLUMES_DIR.with(|dir| dir.borrow().clone()) {
        return dir;
    }
    manager::default_volumes_dir()
}

pub(crate) fn ensure_legacy_revert_only(volume: &str) -> Result<()> {
    ensure_legacy_revert_only_in(&manager::default_volumes_dir(), volume)
}

fn ensure_legacy_revert_only_in(volumes_dir: &std::path::Path, volume: &str) -> Result<()> {
    let listed = manager::list_volumes(volumes_dir).map_err(utils::core_err)?;
    let info = listed
        .into_iter()
        .find(|entry| entry.volume_id.to_string() == volume || entry.display_name == volume)
        .ok_or_else(|| anyhow::anyhow!("Volume '{volume}' not found"))?;
    let config_path = volumes_dir
        .join(info.volume_id.to_string())
        .join("volume.json");
    let bytes = std::fs::read(&config_path)
        .with_context(|| format!("read volume configuration {}", config_path.display()))?;
    let config: teagarden_core::volume::config::VolumeConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse volume configuration {}", config_path.display()))?;
    anyhow::ensure!(
        !(config.sdo_author_device_id.is_some()
            && config.telegram_group_id != 0
            && config.telegram_topic_id != 0),
        "volume revert supports legacy block volumes only; use `volume restore-version <volume> <PATH> <VERSION-UUID-prefix>` for TGFV history"
    );
    Ok(())
}

fn emit_history_output(output: &str) {
    #[cfg(test)]
    COMMAND_OUTPUT.with(|captured| *captured.borrow_mut() = Some(output.to_owned()));
    print!("{output}");
}

async fn scan_tgfvs_with_source(
    v: &OpenedVolume,
    transport: std::sync::Arc<dyn teagarden_telegram::client::BlockTransport>,
    header: teagarden_core::sdo::HeaderDocument,
    restore_id: Option<uuid::Uuid>,
) -> Result<SdoTopicScan> {
    let (raw, restored, max_clock) = super::volume::scan_sdo_history(
        transport.as_ref(),
        v.group_id,
        v.topic_id,
        &header,
        &v.hierarchy,
        restore_id,
    )
    .await?;
    let records: Vec<SdoHistoryRecord> = raw
        .into_iter()
        .map(serde_json::from_value)
        .collect::<std::result::Result<_, _>>()?;
    Ok((header, records, restored, max_clock, transport))
}

fn history_command_with_scanned_versions(
    v: &OpenedVolume,
    path: Option<&str>,
    mut versions: Vec<SdoHistoryRecord>,
) -> Result<String> {
    render_tgfvs_history(v, path, &mut versions)
}

fn render_tgfvs_history(
    v: &OpenedVolume,
    path: Option<&str>,
    versions: &mut Vec<SdoHistoryRecord>,
) -> Result<String> {
    if let Some(path) = path {
        let normalized = path.trim_start_matches('/');
        let identities: std::collections::HashSet<String> = versions
            .iter()
            .filter(|(_, version_path, ..)| version_path.trim_start_matches('/') == normalized)
            .map(|(identity, ..)| identity.clone())
            .collect();
        versions.retain(|(identity, ..)| identities.contains(identity));
    }
    versions
        .sort_by_key(|(identity, _, _, _, ms, counter, _, _, _)| (identity.clone(), *ms, *counter));
    let mut out = format!(
        "Volume: {}\nStorage: authenticated TGFV topic history\n\n",
        v.display_name
    );
    out.push_str("FILE ID    VERSION UUID                         AUTHOR INSTALLATION                    TIME (UTC)               SIZE    STATE  PATH\n");
    for (file_id, version_path, version_id, author, ms, counter, size, deleted, _) in
        versions.iter()
    {
        out.push_str(&format!(
            "{}  {}  {}  {:<24} {:>10}  {:>6}  {}\n",
            file_id,
            version_id,
            author,
            format!("{ms}.{counter} ms since Unix epoch"),
            size,
            if *deleted { "DELETE" } else { "FILE" },
            version_path
        ));
    }
    out.push_str(&format!("\nTotal: {} TGFV version(s)\n", versions.len()));
    Ok(out)
}

/// Walk the directory tree and collect `(ino, path)` for every file inode.
fn collect_file_paths(
    store: &InodeStore<'_>,
    root_ino: u64,
) -> rusqlite::Result<Vec<(u64, String)>> {
    let mut results = Vec::new();
    let mut queue: VecDeque<(u64, String)> = VecDeque::new();
    queue.push_back((root_ino, String::new()));

    while let Some((ino, path)) = queue.pop_front() {
        let Some(inode) = store.get(ino)? else {
            continue;
        };
        if inode.is_file() {
            results.push((ino, path.clone()));
        }
        for child in store.list_children(ino)? {
            let child_path = if path.is_empty() {
                format!("/{}", child.name)
            } else {
                format!("{}/{}", path, child.name)
            };
            queue.push_back((child.ino, child_path));
        }
    }
    Ok(results)
}

/// Gather the FULL persisted version history for every file: each entry is
/// `(path, manifest)` for one archived version. This is the single source of
/// truth shared by `history` and `diff` — the `manifests` table written by the
/// metadata journal (v0.4.5). For volumes created before history persistence
/// existed (empty `manifests` table), fall back to the inode's current manifest so
/// the commands still show something useful.
fn gather_version_history(
    store: &InodeStore<'_>,
    ms: &ManifestStore<'_>,
) -> Result<Vec<(String, FileManifest)>> {
    let paths = collect_file_paths(store, 1)
        .map_err(|e| anyhow::anyhow!("Failed to walk filesystem: {e}"))?;
    let mut out = Vec::new();
    for (ino, path) in &paths {
        let versions = ms
            .list_versions(*ino)
            .map_err(|e| anyhow::anyhow!("Failed to read manifest history: {e}"))?;
        if versions.is_empty() {
            // Pre-v0.4.5 volume (or a never-written file): show the current manifest
            // if it carries any content. The genesis empty manifest (version 0, no
            // blocks) is skipped as uninteresting.
            if let Some(inode) = store
                .get(*ino)
                .map_err(|e| anyhow::anyhow!("Failed to read inode: {e}"))?
            {
                if let Some(m) = inode.manifest {
                    if m.version > 0 || !m.blocks.is_empty() {
                        out.push((path.clone(), m));
                    }
                }
            }
        } else {
            for ver in versions {
                if let Some(m) = ms
                    .get(*ino, ver)
                    .map_err(|e| anyhow::anyhow!("Failed to read manifest version: {e}"))?
                {
                    out.push((path.clone(), m));
                }
            }
        }
    }
    Ok(out)
}

/// Shared boilerplate: prompt for the password, open the volume read-only, and
/// return an opened connection + schema + key material.
///
/// `history`/`diff` only read, and never create or change the metadata DB:
/// after the unlock (which may prompt for the password, and so holds no lock)
/// they take the volume lock SHARED (so no mount, `restore` or `key rotate` is
/// changing or replacing the DB meanwhile; two readers may run together),
/// refuse if volume.json changed since the unlock read it, open
/// the DB read-only without `SQLITE_OPEN_CREATE`, and refuse while it must be
/// rebuilt from Telegram (a `volume restore` that did not finish, a lost DB).
/// A DB created here would be an empty filesystem that the next mount would
/// serve and publish over the volume's real one.
pub(crate) struct OpenedVolume {
    pub(crate) conn: rusqlite::Connection,
    schema: OpaqueSchema,
    meta: teagarden_core::crypto::keys::SymmetricKey,
    manifest_key: teagarden_core::crypto::keys::SymmetricKey,
    pub(crate) hierarchy: teagarden_core::crypto::keys::KeyHierarchy,
    display_name: String,
    current_epoch: u32,
    group_id: i64,
    topic_id: i64,
    base_dir: std::path::PathBuf,
    owner_public_key: Option<String>,
    is_tgfv: bool,
    author_device_id: Option<uuid::Uuid>,
    _lock: manager::VolumeLock,
}

#[cfg(test)]
thread_local! {
    /// Test seam: run once between `open_for_read`'s unlock and its lock (the
    /// window in which another writer can change volume.json).
    pub(crate) static AFTER_UNLOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    pub(crate) static TEST_TRANSPORT: std::cell::RefCell<Option<std::sync::Arc<dyn teagarden_telegram::client::BlockTransport>>> =
        const { std::cell::RefCell::new(None) };
    pub(crate) static TEST_VOLUMES_DIR: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
    pub(crate) static COMMAND_OUTPUT: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

pub(crate) fn open_for_read(
    volumes_dir: &std::path::Path,
    volume: &str,
    command: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<OpenedVolume> {
    let volume_id = manager::list_volumes(volumes_dir)
        .map_err(utils::core_err)?
        .into_iter()
        .find(|v| v.volume_id.to_string() == volume || v.display_name == volume)
        .map(|v| v.volume_id.to_string())
        .ok_or_else(|| anyhow::anyhow!("Volume '{volume}' not found"))?;

    // Unlock first. Key-protection aware: a `--key-protection` volume opens with
    // a factor, not a bare password. Routing through open_volume_any keeps
    // history/diff usable on protected volumes instead of failing closed with
    // un-actionable advice. This may prompt for the password, so it runs
    // BEFORE the lock: an idle prompt holding the lock would block a mount and
    // stall `volume unmount`'s wait for the writer.
    let config_path = volumes_dir.join(&volume_id).join("volume.json");
    let base_config =
        std::fs::read(&config_path).context("read volume configuration before unlock")?;
    let result = utils::open_volume_any(&volume_id, password_file, recovery_file, volumes_dir)?;
    #[cfg(test)]
    if let Some(f) = AFTER_UNLOCK.with(|h| h.borrow_mut().take()) {
        f();
    }
    let lock = manager::VolumeLock::acquire_shared(&volumes_dir.join(&volume_id))
        .map_err(|e| anyhow::anyhow!("cannot read volume '{volume}' now: {e}"))?;
    // volume.json was read before the lock: refuse if a writer (a `key rotate`,
    // a `restore`, a mount's publish) changed it in between.
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let is_tgfv = result.config.sdo_author_device_id.is_some()
        && result.config.telegram_group_id != 0
        && result.config.telegram_topic_id != 0;

    if is_tgfv {
        // A durable remote transition overlays the opened credential anchor.
        // Compare the actual disk snapshot, not that intentional overlay.
        anyhow::ensure!(
            std::fs::read(&config_path).context("recheck volume configuration under lock")?
                == base_config,
            "volume.json changed on disk since this command read it; retry the command"
        );
    } else {
        super::volume::ensure_config_unchanged(&result)?;
    }

    let conn = if is_tgfv {
        // TGFV history lives in the authenticated topic. Its local metadata DB
        // is only a cache and may be absent, stale, or damaged.
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| anyhow::anyhow!("open an in-memory TGFV history database: {e}"))?;
        initialize_database(&conn, &schema)
            .map_err(|e| anyhow::anyhow!("initialize an in-memory TGFV history database: {e}"))?;
        conn
    } else {
        match super::volume::local_db_state(&result)? {
            LocalDb::Usable => local_db::open_read_only(&result.paths.db_path)
                .map_err(|e| anyhow::anyhow!("Failed to open database: {e}"))?,
            // Never mounted, nothing published: there is no history. An in-memory
            // DB with the schema reads as exactly that, and nothing is written.
            LocalDb::Fresh => {
                let conn = rusqlite::Connection::open_in_memory()
                    .map_err(|e| anyhow::anyhow!("open an empty in-memory database: {e}"))?;
                initialize_database(&conn, &schema)
                    .map_err(|e| anyhow::anyhow!("Database init failed: {e}"))?;
                conn
            }
            LocalDb::NeedsRebuild(why) => {
                return Err(super::volume::needs_rebuild_error(volume, command, &why));
            }
            LocalDb::Unusable(why) => {
                return Err(super::volume::unusable_db_error(volume, command, &why));
            }
        }
    };

    Ok(OpenedVolume {
        conn,
        schema,
        meta: result.hierarchy.meta.clone(),
        manifest_key: result.hierarchy.manifest.clone(),
        hierarchy: result.hierarchy,
        display_name: result.config.display_name.clone(),
        current_epoch: result.config.current_epoch,
        group_id: result.config.telegram_group_id,
        topic_id: result.config.telegram_topic_id,
        base_dir: result.paths.base_dir,
        owner_public_key: result.config.sdo_owner_public_key.clone(),
        is_tgfv,
        author_device_id: result.config.sdo_author_device_id,
        _lock: lock,
    })
}

pub async fn run(
    volume: &str,
    path: Option<&str>,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    run_path_in(
        &history_volumes_dir(),
        volume,
        path,
        password_file,
        recovery_file,
    )
    .await
}

/// [`run`] against an explicit volumes directory.
#[cfg(test)]
pub(crate) async fn run_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    run_path_in(volumes_dir, volume, None, password_file, recovery_file).await
}

async fn run_path_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    path: Option<&str>,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    let v = open_for_read(
        volumes_dir,
        volume,
        "volume history",
        password_file,
        recovery_file,
    )?;
    if v.is_tgfv {
        let (_, versions, _, _, _) = scan_tgfvs(&v, None).await?;
        emit_history_output(&history_command_with_scanned_versions(&v, path, versions)?);
        return Ok(());
    }
    let store = InodeStore::new(&v.conn, &v.schema, &v.meta);
    let ms = ManifestStore::new(&v.conn, &v.schema, &v.meta);
    let dag = DagStore::new(&v.conn, &v.schema);

    let mut history = gather_version_history(&store, &ms)?;
    if let Some(path) = path {
        let normalized = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        history.retain(|(file_path, _)| file_path == &normalized);
    }
    if history.is_empty() {
        println!("No file manifest history in volume '{}'.", v.display_name);
        return Ok(());
    }

    println!("Volume: {}", v.display_name);
    println!("Storage: legacy manifest history (block volume)");
    println!("Epoch:  {}", v.current_epoch);
    println!();
    println!(
        "{:<40}  {:>4}  {:>12}  {:>6}  PATH",
        "MANIFEST ID", "VER", "SIZE", "BLOCKS"
    );
    println!("{}", "-".repeat(80));

    for (path, manifest) in &history {
        let mid = manifest.compute_id(&v.manifest_key);
        let mid_hex = hex::encode(&mid[..20]); // first 20 bytes = 40 hex chars
        println!(
            "{}  {:>4}  {:>12}  {:>6}  {}",
            mid_hex,
            manifest.version,
            manifest.total_size,
            manifest.blocks.len(),
            path
        );
        // Show parents from the DAG edges table, falling back to the stored field.
        let parents = dag.get_parents(&mid).unwrap_or_default();
        let parent_sources: Vec<[u8; 32]> = if parents.is_empty() {
            manifest.parent_ids.clone()
        } else {
            parents
        };
        for pid in &parent_sources {
            let pid_hex = hex::encode(&pid[..20]);
            println!("  ↑ {pid_hex}...");
        }
    }

    println!();
    println!("Total: {} manifest version(s)", history.len());
    Ok(())
}

fn short_uuid(id: &str) -> &str {
    &id[..8]
}

fn resolve_sdo_version(history: &[SdoHistoryRecord], prefix: &str) -> Result<SdoHistoryRecord> {
    let matches: Vec<_> = history
        .iter()
        .filter(|record| record.2.starts_with(prefix))
        .collect();
    match matches.as_slice() {
        [] => anyhow::bail!("No TGFV version found with UUID prefix '{prefix}'"),
        [one] => Ok((*one).clone()),
        many => anyhow::bail!(
            "Ambiguous TGFV version UUID prefix '{prefix}' matches {} versions",
            many.len()
        ),
    }
}

fn tgfvdiff_summary(a: &SdoHistoryRecord, b: &SdoHistoryRecord) -> String {
    let same = a.6 == b.6 && a.8.is_some() && a.8 == b.8;
    format!(
        "  Content: {}\n  SHA-256: {} → {}\n  Size: {} → {} ({:+} bytes)",
        if same { "identical" } else { "different" },
        a.8.as_deref().unwrap_or("unavailable"),
        b.8.as_deref().unwrap_or("unavailable"),
        a.6,
        b.6,
        b.6 as i64 - a.6 as i64
    )
}

fn diff_command_with_scanned_versions(
    _v: &OpenedVolume,
    id_a: &str,
    id_b: &str,
    versions: &[SdoHistoryRecord],
) -> Result<String> {
    let a = resolve_sdo_version(versions, id_a)?;
    let b = resolve_sdo_version(versions, id_b)?;
    Ok(format!(
        "TGFV content diff: {}@{} vs {}@{}\n{}\n",
        a.1,
        short_uuid(&a.2),
        b.1,
        short_uuid(&b.2),
        tgfvdiff_summary(&a, &b)
    ))
}

async fn restore_tgfvs_with_source(
    v: &OpenedVolume,
    path: &str,
    version_prefix: &str,
    transport: std::sync::Arc<dyn teagarden_telegram::client::BlockTransport>,
    header: teagarden_core::sdo::HeaderDocument,
    versions: &[SdoHistoryRecord],
    now_ms: u64,
) -> Result<String> {
    let target = resolve_sdo_version(versions, version_prefix)?;
    // Query and cache the real account capability before content allocation or
    // publication, then apply the same plaintext admission as a mounted save.
    let premium = transport.is_premium_user().await.unwrap_or(false);
    let limit = teagarden_core::sdo::SDO_PLAINTEXT_MAX_BYTES[usize::from(premium)];
    anyhow::ensure!(
        // Field 6 is the plaintext size; field 4 is the HLC wall-clock millis.
        target.6 <= limit,
        "selected version exceeds this account's supported plaintext maximum of {limit} bytes"
    );
    // Authenticate the current bootstrap again immediately before selecting
    // the bytes to restore; an old listing is not a publication capability.
    let (_, current, header_wire) = super::volume::discover_latest_header(
        transport.as_ref(),
        v.group_id,
        v.topic_id,
        &v.hierarchy.integrity,
        v.owner_public_key.as_deref(),
    )
    .await?
    .context("no authenticated TGHD header found before restore")?;
    super::volume::observe_header_revision(&v.base_dir.join("volume.json"), &current)?;
    anyhow::ensure!(
        current.volume_id == header.volume_id,
        "restore topic changed volume identity"
    );
    let header = current;
    let target_id = uuid::Uuid::parse_str(&target.2)?;
    let (header, _, restored, max_clock, _) =
        scan_tgfvs_with_source(v, transport.clone(), header, Some(target_id)).await?;
    let (source_metadata, content) =
        restored.context("selected TGFV content was not downloaded")?;
    let author = v
        .author_device_id
        .context("TGFV volume has no author installation identity")?;
    anyhow::ensure!(
        !header.revoked_device_ids.contains(&author),
        "this installation is revoked"
    );
    let (private, _) =
        super::volume::load_or_create_device_keypair(&v.base_dir, &v.hierarchy.wrapping)?;
    let signer = teagarden_core::sdo::device_signing_key(&private.0);
    if let Some(expected) = header.device_authorities.get(&author) {
        anyhow::ensure!(
            *expected == hex::encode(signer.verifying_key().to_bytes()),
            "installation signing key differs from its established authority"
        );
    }
    let generation = header.key_generation.unwrap_or(0);
    let metadata =
        build_restored_metadata(source_metadata, path, author, generation, max_clock, now_ms)?;
    let wire = teagarden_core::sdo::SdoFileObjectV3::encode_with_signer(
        header.volume_id,
        generation,
        &v.hierarchy.meta,
        metadata.clone(),
        &content,
        Some(&signer),
    )
    .context("encode restored TGFV version")?;
    let signed = teagarden_core::sdo::SdoFileObjectV3::decode_header(
        &wire,
        header.volume_id,
        generation,
        &v.hierarchy.meta,
    )?;
    anyhow::ensure!(
        teagarden_core::sdo::object_transition_is_acceptable(&header, &signed.metadata, i64::MAX),
        "restored save is not authorized by the current volume policy"
    );
    let wire = teagarden_core::sdo::ObjectEnvelope::seal(&wire, &header_wire, &v.hierarchy)
        .context("seal restored TGFV with the current credential envelope")?;
    transport
        .upload_file_object(&wire, "teagarden-file-v3.tgf")
        .await
        .context("publish restored bytes as a new TGFV version")?;
    Ok(format!(
        "Restored {version_prefix} to '{path}' as new TGFV version {} ({} bytes).",
        metadata.version_id,
        content.len()
    ))
}

fn build_restored_metadata(
    mut metadata: teagarden_core::sdo::SdoObjectMetadataV3,
    path: &str,
    author: uuid::Uuid,
    generation: u64,
    max_clock: (u64, u64),
    now_ms: u64,
) -> Result<teagarden_core::sdo::SdoObjectMetadataV3> {
    use teagarden_core::sdo::SdoKind;
    anyhow::ensure!(
        metadata.kind == SdoKind::File,
        "only file versions can be restored"
    );
    let previous = metadata.version_id;
    metadata.path = Some(path.trim_start_matches('/').to_owned());
    metadata.version_id = uuid::Uuid::new_v4();
    metadata.previous_version_id = Some(previous);
    metadata.author_device_id = author;
    metadata.key_generation = generation;
    metadata.local_version = metadata
        .local_version
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("file version counter overflow"))?;
    metadata.clock_ms = now_ms.max(max_clock.0);
    metadata.clock_counter = if now_ms > max_clock.0 {
        0
    } else {
        max_clock
            .1
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("hybrid clock counter overflow"))?
    };
    metadata.saved_at_ns = (now_ms as i64).saturating_mul(1_000_000);
    metadata.deleted = false;
    // This is a new author, UUID, path and clock, not an owner migration of
    // the selected logical version. Its old proofs cannot describe this save.
    metadata.authority = None;
    metadata.migration_receipt = None;
    Ok(metadata)
}

pub async fn restore_version(
    volume: &str,
    path: &str,
    version_prefix: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    restore_version_in(
        &history_volumes_dir(),
        volume,
        path,
        version_prefix,
        password_file,
        recovery_file,
    )
    .await
}

async fn restore_version_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    path: &str,
    version_prefix: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    let v = open_for_read(
        volumes_dir,
        volume,
        "volume restore-version",
        password_file,
        recovery_file,
    )?;
    anyhow::ensure!(v.is_tgfv, "volume restore-version requires a TGFV volume");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let (header, versions, _, _, transport) = scan_tgfvs(&v, None).await?;
    let output = restore_tgfvs_with_source(
        &v,
        path,
        version_prefix,
        transport,
        header,
        &versions,
        now_ms,
    )
    .await?;
    emit_history_output(&format!("{output}\n"));
    Ok(())
}

/// Resolve a manifest by hex ID prefix against the gathered history. Like
/// `git rev-parse`, a prefix that matches MORE than one manifest is an error
/// (listing the candidates) rather than a silent first-wins pick.
fn resolve_manifest_prefix(
    history: &[(String, FileManifest)],
    manifest_key: &teagarden_core::crypto::keys::SymmetricKey,
    prefix: &str,
) -> Result<(String, FileManifest)> {
    let matches: Vec<&(String, FileManifest)> = history
        .iter()
        .filter(|(_, m)| hex::encode(m.compute_id(manifest_key)).starts_with(prefix))
        .collect();
    match matches.as_slice() {
        [] => Err(anyhow::anyhow!(
            "No manifest found with ID prefix '{prefix}'"
        )),
        [one] => Ok((one.0.clone(), one.1.clone())),
        many => {
            let mut msg = format!(
                "Ambiguous ID prefix '{prefix}' matches {} manifests:",
                many.len()
            );
            for (p, m) in many {
                msg.push_str(&format!(
                    "\n  {} v{} {}",
                    hex::encode(&m.compute_id(manifest_key)[..20]),
                    m.version,
                    p
                ));
            }
            Err(anyhow::anyhow!(msg))
        }
    }
}

pub async fn diff(
    volume: &str,
    id_a: &str,
    id_b: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    diff_in(
        &history_volumes_dir(),
        volume,
        id_a,
        id_b,
        password_file,
        recovery_file,
    )
    .await
}

/// [`diff`] against an explicit volumes directory.
pub(crate) async fn diff_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    id_a: &str,
    id_b: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    let v = open_for_read(
        volumes_dir,
        volume,
        "volume diff",
        password_file,
        recovery_file,
    )?;
    if v.is_tgfv {
        let (_, versions, _, _, _) = scan_tgfvs(&v, None).await?;
        emit_history_output(&diff_command_with_scanned_versions(
            &v, id_a, id_b, &versions,
        )?);
        return Ok(());
    }
    let store = InodeStore::new(&v.conn, &v.schema, &v.meta);
    let ms = ManifestStore::new(&v.conn, &v.schema, &v.meta);

    // Same source as `history`: every persisted version, not just current ones.
    let history = gather_version_history(&store, &ms)?;

    let (path_a, man_a) = resolve_manifest_prefix(&history, &v.manifest_key, id_a)?;
    let (path_b, man_b) = resolve_manifest_prefix(&history, &v.manifest_key, id_b)?;

    println!(
        "Diff: {} (v{}) vs {} (v{}) [legacy block IDs]",
        path_a, man_a.version, path_b, man_b.version
    );
    println!();

    use std::collections::HashSet;
    let blocks_a: HashSet<[u8; 32]> = man_a.blocks.iter().map(|b| b.block_id).collect();
    let blocks_b: HashSet<[u8; 32]> = man_b.blocks.iter().map(|b| b.block_id).collect();

    let added: Vec<_> = blocks_b.difference(&blocks_a).collect();
    let removed: Vec<_> = blocks_a.difference(&blocks_b).collect();
    let unchanged = blocks_a.intersection(&blocks_b).count();

    println!("  Unchanged blocks: {unchanged}");
    println!("  Added blocks:     {}", added.len());
    for bid in &added {
        println!("    + {}", hex::encode(&bid[..8]));
    }
    println!("  Removed blocks:   {}", removed.len());
    for bid in &removed {
        println!("    - {}", hex::encode(&bid[..8]));
    }

    let size_delta = man_b.total_size as i64 - man_a.total_size as i64;
    println!();
    println!(
        "  Size: {} → {} ({:+} bytes)",
        man_a.total_size, man_b.total_size, size_delta
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepare_real_entry(
        dir: &std::path::Path,
        transport: std::sync::Arc<dyn teagarden_telegram::client::BlockTransport>,
        volume_id: uuid::Uuid,
    ) {
        std::fs::write(
            dir.join(volume_id.to_string()).join("metadata.db"),
            b"damaged local cache",
        )
        .unwrap();
        TEST_VOLUMES_DIR.with(|path| *path.borrow_mut() = Some(dir.to_path_buf()));
        TEST_TRANSPORT.with(|mock| *mock.borrow_mut() = Some(transport));
        COMMAND_OUTPUT.with(|output| *output.borrow_mut() = None);
    }

    fn clear_real_entry() -> Option<String> {
        TEST_VOLUMES_DIR.with(|path| *path.borrow_mut() = None);
        TEST_TRANSPORT.with(|mock| *mock.borrow_mut() = None);
        COMMAND_OUTPUT.with(|output| output.borrow_mut().take())
    }

    async fn mock_tgfvs() -> (
        tempfile::TempDir,
        OpenedVolume,
        std::sync::Arc<teagarden_telegram::mock::MockTransport>,
        teagarden_core::sdo::HeaderDocument,
        [uuid::Uuid; 3],
    ) {
        use teagarden_core::sdo::{HeaderDocument, SdoFileObjectV3, SdoKind, SdoObjectMetadataV3};
        let dir = tempfile::tempdir().unwrap();
        let created = manager::create_volume(
            Some("history-fixture"),
            b"pw",
            dir.path(),
            999_000_000,
            7,
            42,
            None,
        )
        .unwrap();
        let mut config = created.config.clone();
        config.sdo_author_device_id = Some(uuid::Uuid::from_bytes([0xc1; 16]));
        manager::save_config_resealed(&mut config, &created.hierarchy, &created.paths.config_path)
            .unwrap();
        let pass = dir.path().join("pw");
        std::fs::write(&pass, "pw").unwrap();
        let opened = open_for_read(
            dir.path(),
            "history-fixture",
            "volume history",
            Some(pass.to_str().unwrap()),
            None,
        )
        .unwrap();
        let ids = [
            uuid::Uuid::from_bytes([0xa1; 16]),
            uuid::Uuid::from_bytes([0xa2; 16]),
            uuid::Uuid::from_bytes([0xa3; 16]),
        ];
        let file_id = uuid::Uuid::from_u128(77);
        let author_a = uuid::Uuid::from_bytes([0xb1; 16]);
        let author_b = uuid::Uuid::from_bytes([0xb2; 16]);
        let contents: [&[u8]; 3] = [b"one", b"two", b""];
        let paths = ["docs/old.txt", "docs/new.txt", "docs/new.txt"];
        let authors = [author_a, author_b, author_b];
        let transport = std::sync::Arc::new(teagarden_telegram::mock::MockTransport::new_unbound());
        let mut header = HeaderDocument::test_fixture();
        header.volume_id = created.config.volume_id;
        header.group_id = 999_000_000;
        header.topic_id = 42;
        header.salt = hex::encode(created.config.salt);
        header.kdf_params = Some(created.config.kdf_params.clone());
        transport.put_document(
            99,
            999_000_000,
            42,
            "teagarden-header-v1.tgh",
            header.encode(&opened.hierarchy.integrity).unwrap(),
        );
        for i in 0..3 {
            let wire = SdoFileObjectV3::encode(
                created.config.volume_id,
                0,
                &opened.hierarchy.meta,
                SdoObjectMetadataV3 {
                    authority: None,
                    migration_receipt: None,
                    file_id,
                    origin_message_id: None,
                    path: Some(paths[i].into()),
                    size: contents[i].len() as u64,
                    mtime_ns: i as i64,
                    mode: 0o600,
                    version_id: ids[i],
                    author_device_id: authors[i],
                    previous_version_id: i.checked_sub(1).map(|n| ids[n]),
                    kind: SdoKind::File,
                    key_generation: 0,
                    // Realistic wall-clock milliseconds (late 2026): a field
                    // mix-up between clock and size must not hide behind tiny
                    // fixture clocks.
                    clock_ms: 1_795_000_000_000 + i as u64,
                    clock_counter: 0,
                    saved_at_ns: i as i64 + 1,
                    local_version: i as u64 + 1,
                    deleted: i == 2,
                    installation_id: None,
                    label: None,
                    telegram_user_id: None,
                    authorization_session_hash: None,
                    created_at_ms: None,
                    device_public_key: None,
                    device_key_update: None,
                    segment_size: teagarden_core::sdo::SDO_SEGMENT_SIZE,
                    segment_count: 0,
                    content_sha256: hex::encode(teagarden_core::block::srb2::sha256(contents[i])),
                },
                contents[i],
            )
            .unwrap();
            transport.put_document(100 + i as i64, 999_000_000, 42, "history.tgf", wire);
        }
        (dir, opened, transport, header, ids)
    }

    // A current root plus a genuinely distinct retained generation, a revoked
    // author with owner-preserved history, and a survivor's delayed old-key save.
    async fn owner_pinned_history() -> (
        tempfile::TempDir,
        OpenedVolume,
        std::sync::Arc<teagarden_telegram::mock::MockTransport>,
        teagarden_core::sdo::HeaderDocument,
        [uuid::Uuid; 5],
    ) {
        use teagarden_core::sdo::*;
        use teagarden_telegram::client::BlockTransport;
        let (dir, opened, transport, mut header, ids) = mock_tgfvs().await;
        let owner = SigningKey::from_bytes(&[91; 32]);
        let pin = hex::encode(owner.verifying_key().to_bytes());
        let author = opened.author_device_id.unwrap();
        // Same installation key location and wrapping as a mounted save.
        let base = dir.path().join(header.volume_id.to_string());
        let (private, _) =
            super::super::volume::load_or_create_device_keypair(&base, &opened.hierarchy.wrapping)
                .unwrap();
        let signer = device_signing_key(&private.0);
        let revoked = uuid::Uuid::from_bytes([0xb2; 16]);
        header.format = 2;
        header.revision = 2;
        header.owner_public_key = Some(pin.clone());
        let generation = u64::from(cfg!(feature = "key-rotation"));
        header.key_generation = Some(generation);
        header.generation_boundary_message_id = (generation > 0).then_some(110);
        if generation > 0 {
            header.generation_cutoffs.insert(1, 110);
        }
        header.revoked_device_ids.push(revoked);
        header.revocation_cutoffs.insert(
            revoked,
            RevocationCutoff {
                key_generation: generation,
                boundary_message_id: 110,
            },
        );
        header
            .device_authorities
            .insert(author, hex::encode(signer.verifying_key().to_bytes()));
        #[cfg(feature = "key-rotation")]
        let old_salt = [78; 32];
        #[cfg(feature = "key-rotation")]
        let old = teagarden_core::crypto::kdf::derive_hierarchy_v1(
            teagarden_core::crypto::keys::SymmetricKey::from_bytes([79; 32]),
            &old_salt,
            header.group_id,
            header.topic_id,
        )
        .unwrap();
        #[cfg(not(feature = "key-rotation"))]
        let old = opened.hierarchy.clone();
        #[cfg(feature = "key-rotation")]
        {
            header.retained_key_bridges.push(
                KeyGenerationBridge::wrap(0, &old_salt, &old.root, &opened.hierarchy.wrapping)
                    .unwrap(),
            );
            for i in 0..3 {
                let wire = transport.download_block(100 + i).await.unwrap().data;
                let mut object =
                    SdoFileObjectV3::decode(&wire, header.volume_id, 0, &opened.hierarchy.meta)
                        .unwrap();
                object
                    .metadata
                    .attest_migration(header.volume_id, 100 + i, &owner)
                    .unwrap();
                object.metadata.key_generation = 1;
                let wire = SdoFileObjectV3::encode(
                    header.volume_id,
                    1,
                    &opened.hierarchy.meta,
                    object.metadata,
                    &object.content,
                )
                .unwrap();
                transport.put_document(
                    100 + i,
                    header.group_id,
                    header.topic_id,
                    "history.tgf",
                    wire,
                );
            }
        }
        let mut late = legacy_metadata_v3(&SdoObjectMetadata::test_fixture());
        late.file_id = uuid::Uuid::new_v4();
        late.version_id = uuid::Uuid::new_v4();
        late.author_device_id = author;
        late.path = Some("late.txt".into());
        late.size = 4;
        late.clock_ms = 10;
        late.content_sha256 = hex::encode(teagarden_core::block::srb2::sha256(b"late"));
        let late_id = late.version_id;
        let late_wire = SdoFileObjectV3::encode_with_signer(
            header.volume_id,
            0,
            &old.meta,
            late.clone(),
            b"late",
            Some(&signer),
        )
        .unwrap();
        transport.put_document(130, header.group_id, header.topic_id, "late.tgf", late_wire);
        late.version_id = uuid::Uuid::new_v4();
        late.author_device_id = revoked;
        late.path = Some("docs/new.txt".into());
        late.clock_ms = u64::MAX - 1;
        let evil_id = late.version_id;
        let evil_wire = SdoFileObjectV3::encode_with_signer(
            header.volume_id,
            0,
            &old.meta,
            late,
            b"late",
            Some(&SigningKey::from_bytes(&[92; 32])),
        )
        .unwrap();
        transport.put_document(
            131,
            header.group_id,
            header.topic_id,
            "revoked.tgf",
            evil_wire,
        );
        transport.put_document(
            120,
            header.group_id,
            header.topic_id,
            "teagarden-header-v2.tgh",
            header
                .encode_v2(&opened.hierarchy.integrity, &owner)
                .unwrap(),
        );
        drop(opened);
        let mut local =
            manager::open_volume(&header.volume_id.to_string(), b"pw", dir.path()).unwrap();
        local.config.sdo_owner_public_key = Some(pin);
        manager::save_config_resealed(
            &mut local.config,
            &local.hierarchy,
            &local.paths.config_path,
        )
        .unwrap();
        let opened = open_for_read(
            dir.path(),
            "history-fixture",
            "volume history",
            Some(dir.path().join("pw").to_str().unwrap()),
            None,
        )
        .unwrap();
        transport.set_next_id(132);
        transport.clear_channel_binding();
        assert!(transport.channel_ref().is_none());
        (
            dir,
            opened,
            transport,
            header,
            [ids[0], ids[1], ids[2], late_id, evil_id],
        )
    }

    #[tokio::test]
    async fn a2_n1_missing_revocation_cutoff_refuses_history_attach_and_live_apply() {
        let (dir, opened, transport, mut header, _) = owner_pinned_history().await;
        let hierarchy = opened.hierarchy.clone();
        let author = opened.author_device_id.unwrap();
        header.revocation_cutoffs.clear();
        header.revision += 1;
        let wire = header
            .encode_v2(
                &hierarchy.integrity,
                &teagarden_core::sdo::SigningKey::from_bytes(&[91; 32]),
            )
            .unwrap();
        transport.put_document(
            140,
            header.group_id,
            header.topic_id,
            "incomplete-policy.tgh",
            wire.clone(),
        );
        drop(opened);
        prepare_real_entry(dir.path(), transport.clone(), header.volume_id);
        let error = run(
            "history-fixture",
            None,
            Some(dir.path().join("pw").to_str().unwrap()),
            None,
        )
        .await
        .expect_err(
            "history must refuse missing cutoff evidence, not silently omit legitimate versions",
        );
        let message = format!("{error:#}");
        assert!(message.contains("missing recorded cutoff"), "{message}");
        assert!(
            message.contains(&header.revoked_device_ids[0].to_string()),
            "{message}"
        );
        assert!(COMMAND_OUTPUT.with(|out| out.borrow().is_none()));
        clear_real_entry();
        let fresh = tempfile::tempdir().unwrap();
        transport.clear_channel_binding();
        let error = super::super::volume::attach_command(
            transport.as_ref(),
            header.group_id,
            header.topic_id,
            b"pw",
            false,
            fresh.path(),
            header.owner_public_key.as_deref(),
        )
        .await
        .expect_err("attach must refuse an incomplete revocation policy");
        assert!(format!("{error:#}").contains("missing recorded cutoff"));
        assert_eq!(std::fs::read_dir(fresh.path()).unwrap().count(), 0);
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let schema = OpaqueSchema::new(hierarchy.schema.clone(), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        InodeStore::new(&conn, &schema, &hierarchy.meta)
            .insert(&teagarden_core::metadata::inode::Inode::root())
            .unwrap();
        let mut live = teagarden_fuse::fs::CryptFs::new(
            conn,
            schema,
            hierarchy.meta.clone(),
            hierarchy.data.clone(),
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        )
        .with_sdo(header.volume_id, author)
        .with_manifest_key(hierarchy.manifest.clone())
        .with_sdo_generation_keys(
            header.key_generation.unwrap_or(0),
            header.generation_boundary_message_id,
            super::super::volume::generation_meta_keys(&header, &hierarchy).unwrap(),
        )
        .with_sdo_object_envelope(wire, hierarchy);
        assert!(
            live.apply_remote_sdo_batch(Vec::new(), 140).is_err(),
            "live apply must not interpret invalid policy as absent policy"
        );
        assert!(live.store().get(1).unwrap().is_some());
    }

    #[test]
    fn a2_n2_nonowner_interrupted_export_requires_explicit_unverified_restore() {
        const CHILD: &str = "TEAGARDEN_A2_N2_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::history::tests::a2_n2_nonowner_interrupted_export_requires_explicit_unverified_restore", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("UNVERIFIED object included by --include-unverified"),
                "{stderr}"
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout
                    .lines()
                    .any(|line| line.contains("safe-unmigrated.txt")
                        && line.contains("[UNVERIFIED:")),
                "{stdout}"
            );
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            use teagarden_telegram::client::BlockTransport;
            use teagarden_core::sdo::{legacy_metadata_v3, SdoObjectMetadata, SdoFileObjectV3};
            let (dir, opened, transport, header, _) = owner_pinned_history().await;
            let hierarchy = opened.hierarchy.clone();
            assert!(!dir.path().join(header.volume_id.to_string()).join("owner-signing.key").exists());
            for id in [100, 101, 102, 130, 131] {
                let wire = transport.download_block(id).await.unwrap().data;
                transport.put_document(id, header.group_id, header.topic_id, "teagarden-file-v3.tgf", wire);
            }
            #[cfg(not(feature = "key-rotation"))]
            for id in [101, 102] { transport.delete_message(id).await.unwrap(); }
            let wire = transport.download_block(120).await.unwrap().data;
            transport.put_document(120, header.group_id, header.topic_id, "teagarden-header-v1.tgh", wire);
            let mut metadata = legacy_metadata_v3(&SdoObjectMetadata::test_fixture());
            metadata.file_id = uuid::Uuid::new_v4();
            metadata.version_id = uuid::Uuid::new_v4();
            metadata.author_device_id = header.revoked_device_ids[0];
            metadata.path = Some("safe-unmigrated.txt".into());
            metadata.clock_ms = 11;
            metadata.size = 4;
            let keys = super::super::volume::generation_meta_keys(&header, &hierarchy).unwrap();
            let original = SdoFileObjectV3::encode(header.volume_id, 0, &keys[&0], metadata, b"safe").unwrap();
            transport.put_document(90, header.group_id, header.topic_id, "teagarden-file-v3.tgf", original.clone());
            drop(opened);
            unsafe { std::env::set_var("TEAGARDEN_VOLUMES_DIR", dir.path()); }
            let export = dir.path().join("export");
            let password = dir.path().join("pw");
            transport.clear_channel_binding();
            super::super::key::TEST_PORTABLE_TRANSPORT.scope(transport.clone(),
                super::super::volume::export_objects(&header.volume_id.to_string(), &export, Some(password.to_str().unwrap()), None)).await.unwrap();
            assert_eq!(std::fs::read(export.join("file-90.tgf")).unwrap(), original);
            let provenance: serde_json::Value = serde_json::from_slice(&std::fs::read(export.join("export-provenance.json")).unwrap()).unwrap();
            assert!(provenance["owner_signature"].is_null(), "non-owner cannot attest source positions");
            let output = dir.path().join("refused-output");
            let error = super::super::decrypt::run(&export, Some(&output), Some(password.to_str().unwrap()), None, None, header.owner_public_key.as_deref(), false)
                .expect_err("directory recovery must refuse, not succeed while silently omitting the valid unmigrated original");
            let message = format!("{error:#}");
            assert!(message.contains("1 object(s)"), "{message}");
            assert!(message.contains("owner provenance"), "{message}");
            assert!(!output.exists(), "refusal must not write a partial tree");
            let included = dir.path().join("included-output");
            super::super::decrypt::run(&export, Some(&included), Some(password.to_str().unwrap()), None, None, header.owner_public_key.as_deref(), true).unwrap();
            assert_eq!(std::fs::read(included.join("safe-unmigrated.txt")).unwrap(), b"safe");
            // Explicit recovery cannot override an owner-proven post-cutoff rejection.
            let mut payload = provenance["payload"].clone();
            payload["objects"]["file-90.tgf"]["message_id"] = serde_json::json!(131);
            super::super::decrypt::write_export_provenance(&export, payload, &hierarchy.integrity,
                Some(&teagarden_core::sdo::SigningKey::from_bytes(&[91; 32]))).unwrap();
            let rejected = dir.path().join("known-rejected-output");
            let error = super::super::decrypt::run(&export, Some(&rejected), Some(password.to_str().unwrap()), None, None, header.owner_public_key.as_deref(), true).unwrap_err();
            assert!(format!("{error:#}").contains("authenticated source message 131"));
            assert!(!rejected.exists());
        });
    }

    #[tokio::test]
    async fn integration_restore_version_is_signed_sealed_and_accepted_by_attach_and_live_apply() {
        use teagarden_core::sdo::{ObjectEnvelope, SdoFileObjectV3};
        use teagarden_telegram::client::BlockTransport;
        let (dir, opened, transport, header, ids) = owner_pinned_history().await;
        let hierarchy = opened.hierarchy.clone();
        let author = opened.author_device_id.unwrap();
        let live_path = dir.path().join("live.db");
        let schema = OpaqueSchema::new(hierarchy.schema.clone(), &logical_tables());
        let conn = rusqlite::Connection::open(&live_path).unwrap();
        initialize_database(&conn, &schema).unwrap();
        InodeStore::new(&conn, &schema, &hierarchy.meta)
            .insert(&teagarden_core::metadata::inode::Inode::root())
            .unwrap();
        let header_wire = transport.download_block(120).await.unwrap().data;
        let mut live = teagarden_fuse::fs::CryptFs::new(
            conn,
            schema,
            hierarchy.meta.clone(),
            hierarchy.data.clone(),
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        )
        .with_sdo(header.volume_id, author)
        .with_manifest_key(hierarchy.manifest.clone())
        .with_sdo_generation_keys(
            header.key_generation.unwrap_or(0),
            header.generation_boundary_message_id,
            super::super::volume::generation_meta_keys(&header, &hierarchy).unwrap(),
        )
        .with_sdo_object_envelope(header_wire, hierarchy.clone());
        let mut initial = Vec::new();
        for id in [100, 101, 102, 130, 131] {
            initial.push((id, transport.download_block(id).await.unwrap().data));
        }
        assert_eq!(live.apply_remote_sdo_batch(initial, 131).unwrap(), 4);
        assert_eq!(live.store().lookup(1, "late.txt").unwrap().unwrap().size, 4);
        drop(opened);
        prepare_real_entry(dir.path(), transport.clone(), header.volume_id);
        restore_version(
            "history-fixture",
            "restored.txt",
            &ids[0].to_string(),
            Some(dir.path().join("pw").to_str().unwrap()),
            None,
        )
        .await
        .unwrap();
        clear_real_entry();
        let documents = transport
            .list_topic_documents(header.group_id, header.topic_id, None, 100)
            .await
            .unwrap();
        let new_id = documents.iter().map(|d| d.message_id).max().unwrap();
        assert!(new_id > 131);
        let wire = transport.download_block(new_id).await.unwrap().data;
        let restored = SdoFileObjectV3::decode(
            &wire,
            header.volume_id,
            header.key_generation.unwrap_or(0),
            &hierarchy.meta,
        )
        .expect("restore must create a valid new signed version, without the source receipt");
        assert_eq!(restored.content, b"one");
        assert_eq!(restored.metadata.author_device_id, author);
        assert_eq!(restored.metadata.previous_version_id, Some(ids[0]));
        assert_ne!(restored.metadata.version_id, ids[0]);
        assert!(
            restored.metadata.authority.is_some(),
            "restore lacks installation authority"
        );
        assert!(
            restored.metadata.migration_receipt.is_none(),
            "new save reused historical provenance"
        );
        assert_eq!(
            restored.metadata.authority.as_ref().unwrap().public_key,
            header.device_authorities[&author]
        );
        assert!(
            ObjectEnvelope::parse(&wire).unwrap().is_some(),
            "restore lacks credential envelope"
        );
        // The object alone, outside the topic and without any sidecar or index,
        // must open through the real forensic decrypt command.
        let download = tempfile::tempdir().unwrap();
        let object = download.path().join("restored.tgf");
        std::fs::write(&object, &wire).unwrap();
        let output = download.path().join("output");
        super::super::decrypt::run(
            &object,
            Some(&output),
            Some(dir.path().join("pw").to_str().unwrap()),
            None,
            None,
            header.owner_public_key.as_deref(),
            false,
        )
        .unwrap();
        assert_eq!(std::fs::read(output.join("restored.txt")).unwrap(), b"one");
        let fresh = tempfile::tempdir().unwrap();
        transport.clear_channel_binding();
        let attached = super::super::volume::attach_command(
            transport.as_ref(),
            header.group_id,
            header.topic_id,
            b"pw",
            false,
            fresh.path(),
            header.owner_public_key.as_deref(),
        )
        .await
        .unwrap();
        let conn = rusqlite::Connection::open(&attached.paths.db_path).unwrap();
        let schema = OpaqueSchema::new(attached.hierarchy.schema.clone(), &logical_tables());
        let versions = teagarden_store::sdo_version_store::SdoVersionStore::new(&conn, &schema);
        assert!(
            versions
                .get(restored.metadata.version_id.as_bytes())
                .unwrap()
                .is_some(),
            "fresh attach lost the restored save"
        );
        assert_eq!(
            InodeStore::new(&conn, &schema, &hierarchy.meta)
                .lookup(1, "restored.txt")
                .unwrap()
                .unwrap()
                .size,
            3
        );
        assert_eq!(
            live.apply_remote_sdo_batch(vec![(new_id, wire)], new_id)
                .unwrap(),
            1
        );
        assert_eq!(
            live.store()
                .lookup(1, "restored.txt")
                .unwrap()
                .unwrap()
                .size,
            3
        );
    }

    #[tokio::test]
    async fn integration_history_keeps_legitimate_versions_excludes_revoked_and_enforces_owner_pin()
    {
        use teagarden_core::sdo::SigningKey;
        let (dir, opened, transport, header, ids) = owner_pinned_history().await;
        let hierarchy = opened.hierarchy.clone();
        drop(opened);
        let password = dir.path().join("pw");
        prepare_real_entry(dir.path(), transport.clone(), header.volume_id);
        run(
            "history-fixture",
            None,
            Some(password.to_str().unwrap()),
            None,
        )
        .await
        .unwrap();
        let output = COMMAND_OUTPUT.with(|out| out.borrow_mut().take()).unwrap();
        for id in &ids[..4] {
            assert!(
                output.contains(&id.to_string()),
                "legitimate history missing: {output}"
            );
        }
        assert!(
            output.contains("DELETE"),
            "legitimate deletion missing: {output}"
        );
        assert!(
            !output.contains(&ids[4].to_string()),
            "revoked version leaked: {output}"
        );
        diff(
            "history-fixture",
            &ids[0].to_string(),
            &ids[3].to_string(),
            Some(password.to_str().unwrap()),
            None,
        )
        .await
        .unwrap();
        assert!(diff(
            "history-fixture",
            &ids[0].to_string(),
            &ids[4].to_string(),
            Some(password.to_str().unwrap()),
            None
        )
        .await
        .is_err());
        let count = transport.message_count();
        assert!(restore_version(
            "history-fixture",
            "bad.txt",
            &ids[4].to_string(),
            Some(password.to_str().unwrap()),
            None
        )
        .await
        .is_err());
        assert_eq!(transport.message_count(), count);
        // A password holder can MAC a second owner's header; the local pin must
        // stop every history consumer before it reads or publishes under it.
        let impostor = SigningKey::from_bytes(&[93; 32]);
        let mut changed = header.clone();
        changed.owner_public_key = Some(hex::encode(impostor.verifying_key().to_bytes()));
        changed.revision += 1;
        transport.put_document(
            140,
            header.group_id,
            header.topic_id,
            "teagarden-header-v2.tgh",
            changed.encode_v2(&hierarchy.integrity, &impostor).unwrap(),
        );
        let err = run(
            "history-fixture",
            None,
            Some(password.to_str().unwrap()),
            None,
        )
        .await
        .expect_err("history accepted another owner");
        assert!(format!("{err:#}").contains("owner"));
        assert!(diff(
            "history-fixture",
            &ids[0].to_string(),
            &ids[1].to_string(),
            Some(password.to_str().unwrap()),
            None
        )
        .await
        .is_err());
        assert!(restore_version(
            "history-fixture",
            "bad.txt",
            &ids[0].to_string(),
            Some(password.to_str().unwrap()),
            None
        )
        .await
        .is_err());
        assert_eq!(transport.message_count(), count + 1);
        let mut downgrade = header.clone();
        downgrade.format = 1;
        downgrade.revision += 2;
        downgrade.owner_public_key = None;
        downgrade.key_generation = None;
        downgrade.revoked_device_ids.clear();
        downgrade.revocation_cutoffs.clear();
        downgrade.generation_cutoffs.clear();
        downgrade.device_authorities.clear();
        downgrade.generation_boundary_message_id = None;
        downgrade.retained_key_bridges.clear();
        transport.put_document(
            141,
            header.group_id,
            header.topic_id,
            "teagarden-header-v1.tgh",
            downgrade.encode(&hierarchy.integrity).unwrap(),
        );
        assert!(run(
            "history-fixture",
            None,
            Some(password.to_str().unwrap()),
            None
        )
        .await
        .is_err());
        assert!(diff(
            "history-fixture",
            &ids[0].to_string(),
            &ids[1].to_string(),
            Some(password.to_str().unwrap()),
            None
        )
        .await
        .is_err());
        assert!(restore_version(
            "history-fixture",
            "bad.txt",
            &ids[0].to_string(),
            Some(password.to_str().unwrap()),
            None
        )
        .await
        .is_err());
        assert_eq!(transport.message_count(), count + 2);
        clear_real_entry();
    }

    #[tokio::test]
    async fn history_command_lists_remote_installations_renames_and_deletions() {
        let (_dir, opened, transport, header, ids) = mock_tgfvs().await;
        let (_, versions, _, _, _) = scan_tgfvs_with_source(&opened, transport, header, None)
            .await
            .unwrap();
        let output = history_command_with_scanned_versions(&opened, None, versions).unwrap();
        assert!(output.contains("docs/old.txt"), "{output}");
        assert!(output.contains("docs/new.txt"), "{output}");
        assert!(output.contains("DELETE"), "{output}");
        assert!(output.contains(short_uuid(&ids[0].to_string())), "{output}");
        assert!(
            output.contains(&ids[0].to_string()),
            "full version UUID missing: {output}"
        );
        assert!(
            output.contains("b1b1b1b1"),
            "installation A missing: {output}"
        );
        assert!(
            output.contains("b2b2b2b2"),
            "installation B missing: {output}"
        );
    }

    #[tokio::test]
    async fn history_path_matches_relative_paths_and_follows_renames_by_file_identity() {
        let (_dir, opened, transport, header, _) = mock_tgfvs().await;
        let (_, versions, _, _, _) = scan_tgfvs_with_source(&opened, transport, header, None)
            .await
            .unwrap();
        let output =
            history_command_with_scanned_versions(&opened, Some("docs/old.txt"), versions).unwrap();
        assert!(output.contains("docs/old.txt"), "{output}");
        assert!(
            output.contains("docs/new.txt"),
            "renamed history missing: {output}"
        );
        assert!(
            output.contains("DELETE"),
            "deletion history missing: {output}"
        );
        assert!(output.contains("Total: 3 TGFV version(s)"), "{output}");
    }

    #[tokio::test]
    async fn history_run_discovers_header_filters_relative_path_and_ignores_local_db() {
        let (dir, opened, transport, _, ids) = mock_tgfvs().await;
        let volume_id = ids[0];
        let actual_volume_id = manager::list_volumes(dir.path()).unwrap()[0].volume_id;
        drop(opened);
        let password = dir.path().join("pw");
        prepare_real_entry(dir.path(), transport, actual_volume_id);
        run(
            "history-fixture",
            Some("docs/old.txt"),
            Some(password.to_str().unwrap()),
            None,
        )
        .await
        .unwrap();
        let output = clear_real_entry().unwrap();
        assert!(output.contains(&volume_id.to_string()), "{output}");
        assert!(
            output.contains("docs/new.txt"),
            "rename history missing: {output}"
        );
        assert!(
            output.contains("DELETE"),
            "delete history missing: {output}"
        );
        assert!(output.contains("Total: 3 TGFV version(s)"), "{output}");
    }

    #[tokio::test]
    async fn diff_entrypoint_discovers_header_without_local_metadata_db() {
        let (dir, opened, transport, _, ids) = mock_tgfvs().await;
        let volume_id = manager::list_volumes(dir.path()).unwrap()[0].volume_id;
        drop(opened);
        let password = dir.path().join("pw");
        prepare_real_entry(dir.path(), transport, volume_id);
        diff(
            "history-fixture",
            &ids[0].to_string(),
            &ids[1].to_string(),
            Some(password.to_str().unwrap()),
            None,
        )
        .await
        .unwrap();
        let output = clear_real_entry().unwrap();
        assert!(output.contains("Content: different"), "{output}");
        assert!(output.contains("SHA-256:"), "{output}");
    }

    #[tokio::test]
    async fn round3_b2_n2_restore_queries_transport_capability() {
        let (dir, opened, transport, _, ids) = mock_tgfvs().await;
        let volume_id = manager::list_volumes(dir.path()).unwrap()[0].volume_id;
        drop(opened);
        let password = dir.path().join("pw");
        prepare_real_entry(dir.path(), transport.clone(), volume_id);
        restore_version(
            "history-fixture",
            "docs/restored.txt",
            &ids[0].to_string(),
            Some(password.to_str().unwrap()),
            None,
        )
        .await
        .unwrap();
        let output = clear_real_entry().unwrap();
        assert!(
            transport
                .forum_calls()
                .contains(&teagarden_telegram::mock::ForumCall::IsPremiumUser),
            "restore must query the recording transport capability"
        );
        assert!(output.contains("Restored"), "{output}");
        assert_eq!(transport.message_count(), 5);
    }

    #[tokio::test]
    async fn tgfvs_refuse_legacy_revert_and_direct_to_restore_version() {
        let (dir, opened, _, _, _) = mock_tgfvs().await;
        drop(opened);
        let error = ensure_legacy_revert_only_in(dir.path(), "history-fixture").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("legacy block volumes only"), "{message}");
        assert!(message.contains("volume restore-version"), "{message}");
    }

    #[tokio::test]
    async fn diff_command_compares_remote_tgfv_content_hashes() {
        let (_dir, opened, transport, header, ids) = mock_tgfvs().await;
        let (_, versions, _, _, _) = scan_tgfvs_with_source(&opened, transport, header, None)
            .await
            .unwrap();
        let output = diff_command_with_scanned_versions(
            &opened,
            &ids[0].to_string(),
            &ids[1].to_string(),
            &versions,
        )
        .unwrap();
        assert!(output.contains("Content: different"), "{output}");
        assert!(output.contains("Size: 3 → 3 (+0 bytes)"), "{output}");
    }

    #[tokio::test]
    async fn restore_command_publishes_new_remote_version_linked_to_selected_version() {
        let (_dir, opened, transport, header, ids) = mock_tgfvs().await;
        let (_, versions, _, _, _) =
            scan_tgfvs_with_source(&opened, transport.clone(), header.clone(), None)
                .await
                .unwrap();
        let output = restore_tgfvs_with_source(
            &opened,
            "/restored.txt",
            &ids[0].to_string(),
            transport.clone(),
            header.clone(),
            &versions,
            100,
        )
        .await
        .unwrap();
        assert!(
            transport
                .forum_calls()
                .contains(&teagarden_telegram::mock::ForumCall::IsPremiumUser),
            "restore must initialize Premium capability before uploading"
        );
        assert!(output.contains("Restored"), "{output}");
        assert!(transport
            .uploaded_filenames()
            .contains(&"teagarden-file-v3.tgf".to_string()));
        assert_eq!(transport.message_count(), 5);
        use teagarden_telegram::client::BlockTransport;
        let docs = transport
            .list_topic_documents(999_000_000, 42, None, 100)
            .await
            .unwrap();
        let restored_doc = docs
            .iter()
            .find(|doc| doc.filename == "teagarden-file-v3.tgf")
            .unwrap();
        let restored_wire = transport
            .download_block(restored_doc.message_id)
            .await
            .unwrap()
            .data;
        let restored = teagarden_core::sdo::SdoFileObjectV3::decode(
            &restored_wire,
            header.volume_id,
            0,
            &opened.hierarchy.meta,
        )
        .unwrap();
        assert_ne!(restored.metadata.version_id, ids[0]);
        assert_eq!(restored.metadata.previous_version_id, Some(ids[0]));
        assert_eq!(restored.metadata.path.as_deref(), Some("restored.txt"));
        assert_eq!(restored.metadata.file_id, uuid::Uuid::from_u128(77));
        assert_eq!(restored.content, b"one");
        assert!(restored.metadata.clock_ms > 3);
    }
    use teagarden_core::block::pointer::BlockPointer;
    use teagarden_core::crypto::keys::SymmetricKey;
    use teagarden_core::metadata::inode::Inode;

    fn man(ino: u64, version: u64, size: u64, block: u8) -> FileManifest {
        FileManifest {
            inode: ino,
            version,
            total_size: size,
            file_hash: [block; 32],
            blocks: vec![BlockPointer {
                block_id: [block; 32],
                message_id: block as i64,
                file_offset: 0,
                length: size,
                block_data_offset: 0,
                encrypted_size: size + 16,
                compressed: false,
                epoch: 0,
            }],
            parent_ids: vec![],
        }
    }

    // gather_version_history is the single source both `history` and `diff` read —
    // verify it returns every archived version, and that a pre-v0.4.5 file (no
    // archived versions) falls back to its current inode manifest.
    #[test]
    fn gather_returns_all_archived_versions_and_falls_back_to_current() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let meta = SymmetricKey::from_bytes([0x99; 32]);
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x42; 32]), &logical_tables());
        initialize_database(&conn, &schema).unwrap();

        let store = InodeStore::new(&conn, &schema, &meta);
        let ms = ManifestStore::new(&conn, &schema, &meta);
        store.insert(&Inode::root()).unwrap();

        // File "f" (ino 2) with two ARCHIVED versions (the v0.4.5 path).
        store
            .insert(&Inode::new_file(2, 1, "f".into(), 0o644, 1000, 1000))
            .unwrap();
        ms.insert(&man(2, 1, 10, 0xA1)).unwrap();
        ms.insert(&man(2, 2, 20, 0xA2)).unwrap();

        // File "g" (ino 3) with NO archived versions but a non-genesis current
        // manifest on the inode (simulates a pre-history-persistence volume).
        let mut g = Inode::new_file(3, 1, "g".into(), 0o644, 1000, 1000);
        g.manifest = Some(man(3, 7, 30, 0xB7));
        store.insert(&g).unwrap();

        let hist = gather_version_history(&store, &ms).unwrap();

        // Two versions of /f + one fallback for /g.
        let f_versions: Vec<u64> = hist
            .iter()
            .filter(|(p, _)| p == "/f")
            .map(|(_, m)| m.version)
            .collect();
        assert_eq!(
            f_versions,
            vec![1, 2],
            "all archived versions of /f surface"
        );

        let g_entry: Vec<_> = hist.iter().filter(|(p, _)| p == "/g").collect();
        assert_eq!(
            g_entry.len(),
            1,
            "pre-v0.4.5 /g falls back to current manifest"
        );
        assert_eq!(g_entry[0].1.version, 7);

        // The genesis empty manifest (version 0, no blocks) of a freshly-created,
        // never-written file is NOT surfaced.
        store
            .insert(&Inode::new_file(4, 1, "empty".into(), 0o644, 1000, 1000))
            .unwrap();
        let hist2 = gather_version_history(&store, &ms).unwrap();
        assert!(
            !hist2.iter().any(|(p, _)| p == "/empty"),
            "a never-written file shows no history"
        );
    }

    #[test]
    fn resolve_prefix_unique_match_ambiguous_and_missing() {
        let mk = SymmetricKey::from_bytes([0x47; 32]);
        let m1 = man(2, 1, 10, 0xA1);
        let m2 = man(2, 2, 20, 0xA2);
        let hist = vec![
            ("/f".to_string(), m1.clone()),
            ("/f".to_string(), m2.clone()),
        ];

        // A full manifest id resolves to exactly that version.
        let id1 = hex::encode(m1.compute_id(&mk));
        let (_, got) = resolve_manifest_prefix(&hist, &mk, &id1).unwrap();
        assert_eq!(got.version, 1);

        // The empty prefix matches BOTH manifests -> ambiguous error (not first-wins).
        let err = resolve_manifest_prefix(&hist, &mk, "").unwrap_err();
        assert!(err.to_string().contains("Ambiguous"), "{err}");

        // A prefix that matches nothing -> clear not-found error.
        let absent = "ee".repeat(32); // 64 hex chars; cannot collide with a real id prefix
        let err = resolve_manifest_prefix(&hist, &mk, &absent).unwrap_err();
        assert!(err.to_string().contains("No manifest found"), "{err}");
    }

    #[test]
    fn tgfvdiff_detects_equal_size_content_changes_from_sha256() {
        let a = (
            "id1".into(),
            "/f".into(),
            "11111111-0000-0000-0000-000000000000".into(),
            "author".into(),
            1,
            0,
            7,
            false,
            Some("aa".into()),
        );
        let b = (
            "id1".into(),
            "/f".into(),
            "22222222-0000-0000-0000-000000000000".into(),
            "author".into(),
            2,
            0,
            7,
            false,
            Some("bb".into()),
        );
        let output = tgfvdiff_summary(&a, &b);
        assert!(output.contains("Content: different"), "{output}");
        assert!(output.contains("SHA-256: aa → bb"), "{output}");
        assert!(output.contains("Size: 7 → 7 (+0 bytes)"), "{output}");
    }

    #[test]
    fn restore_version_builds_a_new_linked_version_with_a_fresh_hlc() {
        let metadata = teagarden_core::sdo::SdoObjectMetadataV3 {
            authority: None,
            migration_receipt: None,
            file_id: uuid::Uuid::from_u128(6),
            origin_message_id: None,
            path: Some("old.txt".into()),
            size: 0,
            mtime_ns: 0,
            mode: 0o600,
            version_id: uuid::Uuid::from_u128(4),
            author_device_id: uuid::Uuid::from_u128(5),
            previous_version_id: None,
            kind: teagarden_core::sdo::SdoKind::File,
            key_generation: 0,
            clock_ms: 10,
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
            segment_count: 0,
            content_sha256: hex::encode(teagarden_core::block::srb2::sha256(b"")),
        };
        let previous = metadata.version_id;
        let restored = build_restored_metadata(
            metadata.clone(),
            "/renamed/path.txt",
            uuid::Uuid::new_v4(),
            4,
            (100, 7),
            90,
        )
        .unwrap();
        assert_ne!(restored.version_id, previous);
        assert_eq!(restored.previous_version_id, Some(previous));
        assert_eq!(restored.path.as_deref(), Some("renamed/path.txt"));
        assert_eq!(restored.key_generation, 4);
        assert_eq!((restored.clock_ms, restored.clock_counter), (100, 8));
        assert_eq!(restored.file_id, metadata.file_id);
    }
}
