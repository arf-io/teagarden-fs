use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use teagarden_core::block::aad::block_aad;
use teagarden_core::block::srb2;
use teagarden_core::crypto::{aead, kdf};
use teagarden_core::sentence;
use teagarden_core::volume::manager;

use teagarden_store::block_store::BlockStore;
use teagarden_store::local_db::{self, LocalDb};
use teagarden_store::migrations::initialize_database;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::schema::logical_tables;
use teagarden_telegram::client::{BlockTransport, TelegramClient};
use teagarden_telegram::types::{ChannelRef, TelegramConfig};
use zeroize::Zeroizing;

use super::utils;

// ---------------------------------------------------------------------------
// Rotation marker — two-phase commit state (Fix CRITICAL-1)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct RotationBlock {
    block_id_hex: String,
    old_message_id: i64,
    new_message_id: Option<i64>, // None = not yet re-encrypted
    /// SHA-256 (hex) of the re-encrypted ciphertext, checkpointed so a resumed
    /// rotation can refresh the block's `ciphertext_sha256` without re-encrypting.
    #[serde(default)]
    new_ciphertext_sha256: Option<String>,
    db_updated: bool,
    old_deleted: bool,
    /// Further old-epoch messages this block's row named in an earlier run (a
    /// row can come back on a different message between two runs). Each is
    /// deleted like `old_message_id`. Absent in a marker written before it existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    also_old_message_ids: Vec<i64>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct RotationMarker {
    volume_id: String,
    old_epoch: u32,
    new_epoch: u32,
    blocks: HashMap<String, RotationBlock>, // keyed by block_id_hex
}

/// `path` as one shell word (single-quoted unless it is plainly safe), so a
/// printed recovery command can be pasted as is.
fn shell_word(path: &std::path::Path) -> String {
    let s = path.display().to_string();
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+@:,%=~".contains(c))
    {
        s
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

impl RotationMarker {
    fn path(volume_dir: &std::path::Path) -> std::path::PathBuf {
        volume_dir.join("rotation_pending.json")
    }

    /// `Ok(None)` only when there is no marker file. A marker that exists but
    /// cannot be read or parsed is an error with recovery instructions: it is
    /// the record of which old-epoch messages must still be deleted, so it is
    /// never mistaken for "no rotation in progress".
    fn load(volume_dir: &std::path::Path, volume: &str) -> anyhow::Result<Option<Self>> {
        let path = Self::path(volume_dir);
        let why = match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => e.to_string(),
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => format!("{} bytes, {e}", bytes.len()),
            },
        };
        let mut aside = path.clone().into_os_string();
        aside.push(".unreadable");
        anyhow::bail!(
            "the key-rotation marker {} exists but cannot be read ({why}). It records which \
             old-epoch messages an interrupted `key rotate` still has to delete, so it is not \
             treated as absent. Nothing was changed.\n  \
             If you have an intact copy of that file, put it back and run `teagarden key rotate \
             {volume}` again.\n  \
             Otherwise move it aside:\n    \
             mv {} {}\n  \
             and run `teagarden key rotate {volume}` again. That run finishes the rotation, \
             deletes the old messages it can still identify (from the block rows and the \
             volume's metadata snapshot on Telegram) and reports every one it cannot; it says \
             \"complete\" only if none is left.",
            path.display(),
            shell_word(&path),
            shell_word(std::path::Path::new(&aside)),
        )
    }

    /// Atomic (unique temp file, fsync, rename, directory fsync): a crash leaves
    /// the previous marker or this one, never a torn file.
    fn save(&self, volume_dir: &std::path::Path) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        teagarden_core::fsutil::write_file_atomic(&Self::path(volume_dir), &json, "rotation marker")
            .map_err(anyhow::Error::from)
    }

    fn remove(volume_dir: &std::path::Path) {
        let _ = std::fs::remove_file(Self::path(volume_dir));
    }
}

// ---------------------------------------------------------------------------
// Deletion failure tracking — persisted cleanup list (Fix LOW-2)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct DeletionFailures {
    pending: Vec<i64>, // message IDs that failed to delete
}

impl DeletionFailures {
    fn path(volume_dir: &std::path::Path) -> std::path::PathBuf {
        volume_dir.join("deletion_failures.json")
    }

    /// Empty when the file does not exist; an unreadable file is an error (it
    /// would otherwise read as "nothing left on Telegram").
    fn load(volume_dir: &std::path::Path) -> anyhow::Result<Self> {
        let path = Self::path(volume_dir);
        match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
            Ok(b) => {
                serde_json::from_slice(&b).with_context(|| format!("parse {}", path.display()))
            }
        }
    }

    /// Atomic, like [`RotationMarker::save`].
    fn save(&self, volume_dir: &std::path::Path) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        teagarden_core::fsutil::write_file_atomic(
            &Self::path(volume_dir),
            &json,
            "deletion failure list",
        )
        .map_err(anyhow::Error::from)
    }

    /// Add `ids` to the persisted list.
    fn record(volume_dir: &std::path::Path, ids: &[i64]) -> anyhow::Result<()> {
        let mut f = Self::load(volume_dir)?;
        for id in ids {
            if !f.pending.contains(id) {
                f.pending.push(*id);
            }
        }
        f.save(volume_dir)
    }
}

// ---------------------------------------------------------------------------
// Plaintext copy of the base snapshot (looked up when a marker was lost)
// ---------------------------------------------------------------------------

/// Where [`old_rows_in_base_snapshot`] puts the decrypted snapshot it reads. A
/// fixed name: only the holder of the volume lock (the rotation) uses it.
fn base_snapshot_copy_path(volume_dir: &std::path::Path) -> PathBuf {
    volume_dir.join(".rotation-base-snapshot.db")
}

/// Remove every plaintext base-snapshot copy in `volume_dir`: the fixed one,
/// its SQLite sidecars, and the pid-named copies an earlier build used.
fn remove_base_snapshot_copies(volume_dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(volume_dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".rotation-base-snapshot.")
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Removes the base-snapshot copies when the rotation returns or unwinds, by
/// any path. (A SIGKILL skips it; the next rotation removes them at its start.)
struct BaseSnapshotCopies(PathBuf);

impl Drop for BaseSnapshotCopies {
    fn drop(&mut self) {
        remove_base_snapshot_copies(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Credential helpers
// ---------------------------------------------------------------------------

/// Decode a hex-encoded SHA-256 string back to a 32-byte array.
fn decode_sha256(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok()?.try_into().ok()
}

fn session_file_path() -> PathBuf {
    utils::session_file_path()
}

// ---------------------------------------------------------------------------
// rotate()
// ---------------------------------------------------------------------------

/// Key rotation entry point: advance the block-encryption epoch, re-encrypting
/// every block under the new epoch key and re-pointing the metadata store at the
/// fresh Telegram messages.
///
/// Correctness — the two bugs the old guard flagged are both fixed. First,
/// manifests are NOT rewritten and do not need to be: `update_block_epoch` records
/// each block's new `(message_id, epoch)` in the block store, and the read path
/// (`CryptFs::download_block`) resolves a block's current location from the store,
/// treating the manifest's embedded values as a fallback — so a file whose manifest
/// still carries the pre-rotation pointers reads back correctly after rotation.
/// Second, `config_integrity` IS re-signed: the epoch advance is persisted via
/// `manager::save_config_resealed`, which recomputes the HMAC so the volume opens.
///
/// The work is resumable (see the `RotationMarker` below and [`rotate_core`] for
/// the step order): an interrupted rotation never advances the epoch and can be
/// re-run to completion. Before any old message is deleted, a metadata snapshot
/// naming the new messages is published and the journal HEAD is reset onto it, so
/// a later journal recovery or `volume restore` never rebuilds block rows that
/// point at deleted messages.
pub async fn rotate(
    volume: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    new_password_file: Option<&str>,
) -> Result<()> {
    rotate_impl(volume, password_file, recovery_file, new_password_file).await
}

async fn rotate_impl(
    volume: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    new_password_file: Option<&str>,
) -> Result<()> {
    rotate_in(
        &manager::default_volumes_dir(),
        volume,
        password_file,
        recovery_file,
        new_password_file,
    )
    .await
}

/// [`rotate`] against an explicit volumes directory.
pub(crate) async fn rotate_in(
    volumes_dir: &std::path::Path,
    volume: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    new_password_file: Option<&str>,
) -> Result<()> {
    #[cfg(not(feature = "key-rotation"))]
    let _ = new_password_file;
    println!("Key rotation for volume '{volume}'...");
    println!();
    let volumes_dir = volumes_dir.to_path_buf();

    // Find the volume. Only its id is taken from this listing (read before the
    // lock); everything else comes from the config re-read after the lock.
    let volume_id_str = manager::list_volumes(&volumes_dir)
        .map_err(utils::core_err)?
        .into_iter()
        .find(|v| v.volume_id.to_string() == volume || v.display_name == volume)
        .map(|v| v.volume_id.to_string())
        .ok_or_else(|| anyhow::anyhow!("Volume '{volume}' not found"))?;

    // Single writer: rotation re-points every block and re-seals volume.json, so
    // it must not run under a live mount (whose FUSE writer and unmount snapshot
    // would race it) or beside `restore` / `revert`. Take the SAME exclusive lock
    // a mount holds for its whole lifetime, before the (slow) key derivation, and
    // hold it until rotation returns.
    if let Some(mp) = super::volume::active_fuse_mounts().get(&volume_id_str) {
        anyhow::bail!(
            "refusing to rotate keys for volume '{volume}': it is mounted at {mp}. Unmount it \
             first (`teagarden volume unmount {mp}`), then run `teagarden key rotate` again."
        );
    }
    let _volume_lock = manager::VolumeLock::acquire_exclusive(&volumes_dir.join(&volume_id_str))
        .map_err(|e| {
            anyhow::anyhow!(
                "refusing to rotate keys for volume '{volume}': {e}. Unmount it or wait for the \
                 other command to finish; nothing was changed."
            )
        })?;

    // Key-protection aware: rotation on a `--key-protection` volume needs a factor.
    let (result, _unlock_password) = utils::open_volume_any_retaining_password(
        &volume_id_str,
        password_file,
        recovery_file,
        &volumes_dir,
    )?;

    if result.config.telegram_group_id != 0
        && result.config.telegram_topic_id != 0
        && result.config.sdo_author_device_id.is_some()
    {
        #[cfg(not(feature = "key-rotation"))]
        anyhow::bail!("TGFV key rotation is planned for a later release; 1.0 device revoke removes Telegram access without changing the volume credential");
        #[cfg(feature = "key-rotation")]
        {
            let pending_path = result
                .paths
                .base_dir
                .join(format!("owner-revoke-{}.json", uuid::Uuid::nil()));
            let pending = result.config.sdo_header_pending
                || std::fs::read(&pending_path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .is_some_and(|state| {
                        matches!(
                            state["phase"].as_str(),
                            Some(
                                "generation_header_published"
                                    | "migration_pending"
                                    | "history_migration_complete"
                            )
                        )
                    });
            anyhow::ensure!(new_password_file != Some("-") || (password_file != Some("-") && recovery_file != Some("-")),
            "unlock and replacement credentials cannot both consume stdin; use a separate --new-password-file");
            let password = if pending {
                utils::SecretString::new(String::new())
            } else if let Some(path) = new_password_file {
                utils::read_password_input(Some(path))?
            } else {
                utils::prompt_password("Enter NEW volume password: ")?
            };
            if !pending {
                super::volume::validate_replacement_password(&result, password.as_bytes())?;
            }
            #[cfg(test)]
            if let Ok(client) = TEST_PORTABLE_TRANSPORT.try_with(Arc::clone) {
                return rotate_portable_command(client, &result, password.as_bytes()).await;
            }
            let client = Arc::new(super::volume::connect_user_session().await?);
            return rotate_portable_command(client, &result, password.as_bytes()).await;
        }
    }
    println!("Legacy block volume: rotating block epochs.");
    let channel_ref = (result.config.telegram_group_id != 0).then_some(ChannelRef {
        id: result.config.telegram_group_id,
        access_hash: result.config.telegram_channel_access_hash,
        topic_id: result.config.telegram_topic_id,
    });
    let connect: ConnectTransport<'_> = Box::new(move || Box::pin(connect_telegram(channel_ref)));
    rotate_core(volume, result, connect, &|_| {})
        .await
        .map(|_| ())
}

#[cfg(feature = "key-rotation")]
pub(crate) async fn rotate_portable_command<T: teagarden_telegram::client::ForumAdmin + 'static>(
    transport: Arc<T>,
    opened: &manager::OpenVolumeResult,
    password: &[u8],
) -> Result<()> {
    super::volume::rotate_root_command(transport, opened, password).await
}

/// Connect the user's Telegram session for a rotation, or explain why not and
/// return `None` (the caller refuses to rotate without a transport).
async fn connect_telegram(channel_ref: Option<ChannelRef>) -> Option<Arc<dyn BlockTransport>> {
    match utils::load_telegram_credentials() {
        Ok((api_id, api_hash)) => {
            let tg_config = TelegramConfig {
                api_id,
                api_hash,
                session_path: session_file_path().to_string_lossy().to_string(),
                channel_ref,
                ..Default::default()
            };
            let client = TelegramClient::new(tg_config);
            match client.connect().await.map_err(utils::telegram_err) {
                Ok(teagarden_telegram::types::AuthState::Authenticated) => Some(Arc::new(client)),
                _ => {
                    println!("WARNING: Not authenticated with Telegram.");
                    println!("  Key rotation CANNOT safely proceed without Telegram.");
                    println!(
                        "  Run `teagarden auth login` and retry for a full cryptographic rotation."
                    );
                    println!();
                    None
                }
            }
        }
        Err(e) => {
            println!("WARNING: Telegram credentials not found ({e}).");
            println!("  Key rotation CANNOT safely proceed without Telegram.");
            println!();
            None
        }
    }
}

/// Lazily connects the transport a rotation uses (only when it has blocks to move).
type ConnectTransport<'a> = Box<
    dyn FnOnce() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<Arc<dyn BlockTransport>>> + 'a>,
        > + 'a,
>;

/// A boundary between two durable steps of a rotation. `rotate_core` reports each
/// one to its `at` callback; production passes a no-op, the crash tests stop the
/// rotation there (a panic unwinds out without running any later step).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RotateStep {
    /// Block `i`'s re-encrypted copy is uploaded and checkpointed in the marker.
    Uploaded(usize),
    /// Block `i`'s row now names the new message and epoch.
    RowUpdated(usize),
    /// Block `i`'s old message is deleted.
    OldDeleted(usize),
    /// Every row is re-pointed (and the DB checkpointed); nothing published yet.
    AllBlocksDone,
    /// The snapshot naming the new messages is published and the HEAD reset onto
    /// it; no old message is deleted yet.
    SnapshotPublished,
    /// The advanced epoch is saved in volume.json; the marker still exists.
    EpochAdvanced,
}

/// What a finished rotation run reports (and prints): `complete` only when every
/// old-epoch message the volume knows of was deleted; otherwise `reported` old
/// messages were named as left on Telegram (by id, or counted as unidentifiable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RotationOutcome {
    complete: bool,
    reported: usize,
}

/// The rotation itself, on an opened volume and a transport supplied by
/// `connect`. The caller holds the volume lock and has checked it is not mounted.
///
/// Order, chosen so that at every instant a copy of the metadata that can be
/// recovered from Telegram names messages that still exist:
/// 1. refuse while the local DB must be rebuilt from Telegram (a `volume
///    restore` that did not finish, a lost DB, a DB without a root; it is never
///    created here), and while the journal HEAD has entries (`seq > 0`): the
///    local DB may then differ from what recovery would rebuild, so it must not
///    be snapshotted. Both come before anything else, "nothing to do" and
///    "an interrupted run had already advanced the epoch" included;
/// 2. record every old-epoch message in the marker (written atomically, before
///    any row changes), then upload every block below the new epoch (rows left
///    at an epoch older than the current one included) re-encrypted under the
///    new epoch and point its row at the new message (the old one is untouched);
/// 3. publish a metadata snapshot of the re-pointed DB and reset the HEAD onto it
///    (`publish_snapshot_and_compact`, as a clean unmount does), then re-read the
///    HEAD and volume.json and require that they name that snapshot;
/// 4. only now delete the old messages, each one only if no row still names it,
///    and record every one that was not deleted (if that record cannot be
///    written, stop here with the marker kept: it is then the only record);
/// 5. advance the epoch in volume.json, then remove the marker.
///
/// A rotation killed anywhere can be re-run. What is done is read from the block
/// rows, not trusted from the marker: a journal recovery between the two runs
/// can put rows back on their old messages, and those are then re-pointed again.
/// Until step 3 the recoverable copy is the pre-rotation snapshot, whose
/// messages all still exist. Rows already at the new epoch that the marker does
/// not cover (its file was lost) have their old messages looked up in the HEAD's
/// base snapshot; any that cannot be found there are reported, never forgotten.
async fn rotate_core(
    volume: &str,
    mut result: manager::OpenVolumeResult,
    connect: ConnectTransport<'_>,
    at: &dyn Fn(RotateStep),
) -> Result<RotationOutcome> {
    let volume_id_str = result.config.volume_id.to_string();
    let volume_dir = result.paths.base_dir.clone();

    let old_epoch = result.config.current_epoch;
    let new_epoch = old_epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("epoch counter is at its maximum; cannot rotate"))?;
    // Block AAD format threshold (unchanged by a routine rotation): re-encryption
    // preserves each block's existing format. A v0.4.1+ volume (Some(0)) re-seals
    // under block-v2; a legacy block-v1 volume (None) stays block-v1.
    let block_v2_from_epoch = result.config.block_v2_from_epoch;

    // A plaintext copy of a snapshot left by a run that was killed (or by an
    // earlier build) goes now; whatever this run creates goes when it returns.
    remove_base_snapshot_copies(&volume_dir);
    let _copies = BaseSnapshotCopies(volume_dir.clone());

    let loaded_marker = RotationMarker::load(&volume_dir, volume)?;

    // Step 1: refusals, before anything is read for the rotation itself.
    // A read-only share's topic is its owner's: nothing is uploaded there.
    // The local DB is never created here, and one that must be rebuilt from
    // Telegram is not rotated: rows read from it would not be the volume's.
    if super::volume::read_only_share(&volume_dir)? {
        anyhow::bail!(
            "volume '{volume}' is a read-only share of someone else's volume; `teagarden key \
             rotate` would write into the owner's Telegram topic, so it refuses. Nothing was \
             changed."
        );
    }
    let db_state = super::volume::local_db_state(&result)?;
    match &db_state {
        LocalDb::NeedsRebuild(why) => {
            return Err(super::volume::needs_rebuild_error(
                volume,
                "key rotate",
                why,
            ))
        }
        LocalDb::Unusable(why) => {
            return Err(super::volume::unusable_db_error(volume, "key rotate", why))
        }
        LocalDb::Usable | LocalDb::Fresh => {}
    }
    // The journal must be compacted. With entries past the base snapshot the
    // local DB may not be what recovery would rebuild (a delta can be published
    // and the local commit lost), so snapshotting it could drop a write.
    let head_path = super::volume::journal_head_path(&result);
    let loaded_head = teagarden_core::volume::journal_head::JournalHead::load(
        &head_path,
        &result.hierarchy.integrity,
    )
    .map_err(utils::core_err)?;
    if let Some(head) = &loaded_head {
        if head.seq > 0 {
            anyhow::bail!(
                "refusing to rotate keys for volume '{volume}': its metadata journal has {} \
                 entr{} that are not in a published snapshot yet (the last session did not \
                 end with a clean unmount). Mount the volume and unmount it cleanly, then run \
                 `teagarden key rotate {volume}` again. Nothing was changed.",
                head.seq,
                if head.seq == 1 { "y" } else { "ies" }
            );
        }
    }

    // A previous run that got as far as advancing the epoch (step 5) and died
    // before removing its marker has only its marker to account for (after the
    // refusals above, like any other run: with a DB to rebuild or journal
    // entries it never reports "complete"): the old
    // messages it names as not deleted are recorded (and reported) before the
    // marker goes, so they are never forgotten.
    if let Some(m) = &loaded_marker {
        if m.volume_id == volume_id_str
            && m.new_epoch == old_epoch
            && m.old_epoch + 1 == m.new_epoch
        {
            let mut left: Vec<i64> = Vec::new();
            for b in m.blocks.values() {
                if !b.old_deleted {
                    left.push(b.old_message_id);
                }
                left.extend(&b.also_old_message_ids);
            }
            left.sort_unstable();
            left.dedup();
            if !left.is_empty() {
                DeletionFailures::record(&volume_dir, &left).with_context(|| {
                    format!(
                        "the interrupted rotation from epoch {} to {} had advanced the epoch, but \
                         its marker names {} old message(s) that were not deleted, and this run \
                         could not record the list of them in {}. The marker ({}) is kept; fix the \
                         cause and run `teagarden key rotate {volume}` again",
                        m.old_epoch,
                        m.new_epoch,
                        left.len(),
                        DeletionFailures::path(&volume_dir).display(),
                        RotationMarker::path(&volume_dir).display()
                    )
                })?;
            }
            RotationMarker::remove(&volume_dir);
            println!(
                "The interrupted rotation from epoch {} to {} had already advanced the epoch; \
                 removed its marker. Run `teagarden key rotate {volume}` again to rotate further.",
                m.old_epoch, m.new_epoch
            );
            return Ok(report_outcome(
                &volume_dir,
                m.old_epoch,
                m.new_epoch,
                &left,
                0,
            ));
        }
    }

    // The new epoch key; each block is decrypted under the key of the epoch its
    // row names (normally the current one, older for a row left behind).
    let new_epoch_key =
        kdf::derive_epoch_key(&result.hierarchy.data, new_epoch).map_err(utils::core_err)?;
    let mut epoch_keys: HashMap<u32, teagarden_core::crypto::keys::EpochKey> = HashMap::new();

    let db_path = result.paths.db_path.clone();
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let open_db = || -> Result<rusqlite::Connection> {
        let conn = local_db::open_existing(&db_path)
            .map_err(|e| anyhow::anyhow!("Failed to open database: {e}"))?;
        initialize_database(&conn, &schema)
            .map_err(|e| anyhow::anyhow!("Failed to initialize database: {e}"))?;
        Ok(conn)
    };

    // Rows at every epoch below the new one, and rows an earlier run already
    // moved to the new one. A volume that never published anything and has no
    // DB yet has no rows; nothing creates its DB here.
    // The file first opened here is the only one the snapshot publish below
    // may read (a file put at the path meanwhile is not the rotated DB).
    let mut session_db = None;
    let (blocks, moved) = if db_state == LocalDb::Fresh {
        (Vec::new(), Vec::new())
    } else {
        let conn = open_db()?;
        session_db = Some(super::volume::begin_db_session(
            &result,
            &conn,
            loaded_head.as_ref(),
        )?);
        let bs = BlockStore::new(&conn, &schema);
        let list = |e| {
            bs.list_by_epoch(e)
                .map_err(|err| anyhow::anyhow!("Failed to list blocks at epoch {e}: {err}"))
        };
        let mut below = Vec::new();
        for e in 0..new_epoch {
            below.extend(list(e)?);
        }
        (below, list(new_epoch)?)
    };

    // Resume a matching marker, refuse a foreign one, discard a stale one.
    let resumed = match loaded_marker {
        Some(existing)
            if existing.old_epoch == old_epoch
                && existing.new_epoch == new_epoch
                && existing.volume_id == volume_id_str =>
        {
            Some(existing)
        }
        Some(existing) if existing.old_epoch == old_epoch && existing.new_epoch == new_epoch => {
            anyhow::bail!(
                "rotation marker volume_id '{}' does not match current volume '{}'; \
                 remove {} manually if this is intentional",
                existing.volume_id,
                volume_id_str,
                RotationMarker::path(&volume_dir).display()
            );
        }
        Some(_stale) => {
            println!("Discarding stale rotation marker (different epoch range).");
            RotationMarker::remove(&volume_dir);
            None
        }
        None => None,
    };

    // Nothing to re-encrypt and no trace of an interrupted rotation (no marker,
    // no row already at the new epoch): only the epoch counter moves.
    if blocks.is_empty() && moved.is_empty() && resumed.is_none() {
        println!("No blocks below epoch {new_epoch}. Nothing to re-encrypt.");
        println!("Incrementing epoch counter {old_epoch} -> {new_epoch}.");
        result.config.increment_epoch().map_err(utils::core_err)?;
        manager::save_config_resealed(
            &mut result.config,
            &result.hierarchy,
            &result.paths.config_path,
        )
        .map_err(utils::core_err)?;
        return Ok(report_outcome(&volume_dir, old_epoch, new_epoch, &[], 0));
    }

    println!("Found {} block(s) below epoch {new_epoch}.", blocks.len());

    // No Telegram — refuse to advance epoch (Fix CRITICAL-1). Exit non-zero: a
    // caller that scripts rotation must be able to tell "rotated" from "did
    // nothing", and only the exit code carries that.
    let Some(transport) = connect().await else {
        anyhow::bail!(
            "Key rotation requires Telegram connectivity to re-encrypt blocks.\n  \
             Run `teagarden auth login` and retry with: teagarden key rotate {volume}\n  \
             The epoch has NOT been advanced. No data has been modified."
        );
    };

    let fresh_entry = |b: &teagarden_store::block_store::BlockRecord| RotationBlock {
        block_id_hex: hex::encode(b.block_id),
        old_message_id: b.message_id,
        new_message_id: None,
        new_ciphertext_sha256: None,
        db_updated: false,
        old_deleted: false,
        also_old_message_ids: vec![],
    };
    let mut marker = match resumed {
        Some(m) => {
            println!(
                "Resuming interrupted rotation (marker found for epoch {old_epoch} -> {new_epoch})."
            );
            m
        }
        None => RotationMarker {
            volume_id: volume_id_str.clone(),
            old_epoch,
            new_epoch,
            blocks: HashMap::new(),
        },
    };

    // Every old-epoch message the volume knows of goes into the marker, and the
    // marker is durable, BEFORE any row changes. A row listed at the old epoch
    // names its current message as an old one; a different one recorded by an
    // earlier run is kept too.
    for block in &blocks {
        let hex = hex::encode(block.block_id);
        match marker.blocks.get_mut(&hex) {
            None => {
                marker.blocks.insert(hex, fresh_entry(block));
            }
            Some(entry) if entry.old_message_id != block.message_id => {
                if !entry.also_old_message_ids.contains(&entry.old_message_id) {
                    entry.also_old_message_ids.push(entry.old_message_id);
                }
                entry.old_message_id = block.message_id;
                entry.old_deleted = false;
            }
            Some(_) => {}
        }
    }
    // Rows already at the new epoch that the marker does not cover: an earlier
    // run moved them, and its marker is gone. Their old messages are what the
    // HEAD's base snapshot names for them while it is still the pre-rotation one.
    let uncovered: Vec<_> = moved
        .iter()
        .filter(|b| !marker.blocks.contains_key(&hex::encode(b.block_id)))
        .collect();
    let mut unidentified = 0usize;
    if !uncovered.is_empty() {
        let known = old_rows_in_base_snapshot(&result, transport.as_ref(), new_epoch, &schema)
            .await
            .with_context(|| {
                format!(
                    "{} block(s) are already at epoch {new_epoch} but no rotation marker \
                     records their old messages; looking them up in the volume's metadata \
                     snapshot failed. Nothing was changed. Re-run `teagarden key rotate \
                     {volume}` once Telegram is reachable",
                    uncovered.len()
                )
            })?;
        for b in uncovered {
            match known.get(&b.block_id) {
                Some(&old) if old != b.message_id => {
                    marker.blocks.insert(
                        hex::encode(b.block_id),
                        RotationBlock {
                            new_message_id: Some(b.message_id),
                            new_ciphertext_sha256: Some(hex::encode(b.ciphertext_sha256)),
                            db_updated: true,
                            old_message_id: old,
                            ..fresh_entry(b)
                        },
                    );
                }
                _ => unidentified += 1,
            }
        }
        if unidentified > 0 {
            eprintln!(
                "  WARNING: {unidentified} block(s) were re-encrypted by an earlier run whose \
                 rotation marker was lost, and the volume's snapshot no longer names their \
                 old-epoch messages; those messages cannot be identified, so they cannot be \
                 deleted and may remain on Telegram under the old epoch key."
            );
        }
    }
    marker
        .save(&volume_dir)
        .context("Failed to write rotation marker; nothing was changed")?;

    println!(
        "Re-encrypting {} block(s) to epoch {new_epoch}...",
        blocks.len()
    );
    println!();

    // Step 2: re-encrypt, upload, re-point the row. Nothing is deleted here.
    let mut errors = 0usize;
    {
        let conn = open_db()?;
        // Only the session checkpoints its DB (`local_db::SessionCheckpoints`).
        if session_db.is_some() {
            local_db::own_checkpoints(&conn)
                .map_err(|e| anyhow::anyhow!("take over the metadata DB's checkpoints: {e}"))?;
        }
        let block_store = BlockStore::new(&conn, &schema);
        for (i, block) in blocks.iter().enumerate() {
            let block_hex = hex::encode(block.block_id);
            let prefix = format!("  [{}/{}] Block {}", i + 1, blocks.len(), &block_hex[..16]);

            let entry = &marker.blocks[&block_hex];
            let checkpointed = entry.new_message_id.zip(
                entry
                    .new_ciphertext_sha256
                    .as_deref()
                    .map(|h| decode_sha256(h).ok_or(())),
            );
            let old_msg_id = block.message_id;

            // Reuse a re-encrypted copy uploaded by an earlier run only if it is
            // still on the channel, matches the checkpointed hash when there is
            // one, AND decrypts as this block under the new epoch key and AAD
            // (block id + epoch). An older marker has no hash, so the AEAD check
            // is what proves the copy is ours; anything else is re-uploaded.
            let reuse = match (entry.new_message_id, checkpointed) {
                (Some(id), _) => match transport.download_block(id).await {
                    Ok(r) => {
                        let sha = srb2::sha256(&r.data);
                        let hash_ok = !matches!(checkpointed, Some((_, Ok(want))) if want != sha);
                        let new_aad = block_aad(new_epoch, &block.block_id, block_v2_from_epoch);
                        let decrypts = hash_ok
                            && aead::decrypt(&new_epoch_key.key, &r.data, &new_aad)
                                .map(Zeroizing::new)
                                .is_ok();
                        if decrypts {
                            Some((id, sha))
                        } else {
                            eprintln!(
                                "{prefix}: the copy an earlier run uploaded (msg {id}) is not this \
                                 block under the new epoch key; uploading a fresh one"
                            );
                            None
                        }
                    }
                    Err(teagarden_telegram::error::TelegramError::MessageNotFound(_)) => None,
                    Err(e) => {
                        eprintln!("{prefix}: checking the earlier re-encrypted copy failed: {e}");
                        errors += 1;
                        continue;
                    }
                },
                (None, _) => None,
            };

            let (new_msg_id, new_ct_sha) = match reuse {
                Some(found) => found,
                None => {
                    let ciphertext = match transport.download_block(old_msg_id).await {
                        Ok(r) => r.data,
                        Err(e) => {
                            eprintln!("{prefix}: download failed: {e}");
                            errors += 1;
                            continue;
                        }
                    };
                    let old_key = match epoch_keys.entry(block.epoch) {
                        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                        std::collections::hash_map::Entry::Vacant(e) => e.insert(
                            kdf::derive_epoch_key(&result.hierarchy.data, block.epoch)
                                .map_err(utils::core_err)?,
                        ),
                    };
                    let old_aad = block_aad(block.epoch, &block.block_id, block_v2_from_epoch);
                    let plaintext = match aead::decrypt(&old_key.key, &ciphertext, &old_aad) {
                        Ok(p) => Zeroizing::new(p),
                        Err(e) => {
                            eprintln!("{prefix}: decrypt failed: {e}");
                            errors += 1;
                            continue;
                        }
                    };
                    let new_aad = block_aad(new_epoch, &block.block_id, block_v2_from_epoch);
                    let new_ciphertext = aead::encrypt(&new_epoch_key.key, &plaintext, &new_aad)
                        .map_err(|e| anyhow::anyhow!("re-encrypt block {i}: {e}"))?;
                    let new_ct_sha = srb2::sha256(&new_ciphertext);
                    let id = match transport
                        .upload_block(&new_ciphertext, &block.filename)
                        .await
                    {
                        Ok(r) => r.message_id,
                        Err(e) => {
                            eprintln!("{prefix}: upload failed: {e}");
                            errors += 1;
                            continue;
                        }
                    };
                    // Checkpoint: new message uploaded (+ its ciphertext hash).
                    if let Some(s) = marker.blocks.get_mut(&block_hex) {
                        s.new_message_id = Some(id);
                        s.new_ciphertext_sha256 = Some(hex::encode(new_ct_sha));
                    }
                    if let Err(e) = marker.save(&volume_dir) {
                        eprintln!(
                            "{prefix}: WARNING — failed to checkpoint marker after upload: {e}"
                        );
                    }
                    at(RotateStep::Uploaded(i));
                    (id, new_ct_sha)
                }
            };

            // Re-point the row. Use the existing encrypted_size — AEAD tag length is
            // the same across epochs.
            if let Err(e) = block_store.update_block_epoch(
                &block.block_id,
                new_epoch,
                new_msg_id,
                block.encrypted_size,
                &new_ct_sha,
            ) {
                eprintln!("{prefix}: DB update failed: {e}");
                errors += 1;
                continue;
            }
            if let Some(s) = marker.blocks.get_mut(&block_hex) {
                s.new_message_id = Some(new_msg_id);
                s.new_ciphertext_sha256 = Some(hex::encode(new_ct_sha));
                s.db_updated = true;
            }
            // A failed checkpoint here loses nothing: the old id is already durable.
            if let Err(e) = marker.save(&volume_dir) {
                eprintln!("{prefix}: WARNING — failed to checkpoint marker after DB update: {e}");
            }
            at(RotateStep::RowUpdated(i));
            println!("{prefix}: re-encrypted (msg {old_msg_id} -> {new_msg_id})");
        }

        // A rotation that did not complete must exit non-zero, and must not
        // publish or delete anything: the old messages are what the recoverable
        // (pre-rotation) snapshot names.
        if errors > 0 {
            println!();
            anyhow::bail!(
                "Key rotation is incomplete: {errors} block(s) could not be re-encrypted.\n  \
                 The rotation marker is preserved, the epoch has NOT been advanced and no old \
                 message has been deleted; every file is still readable.\n  \
                 Re-run `teagarden key rotate {volume}` after fixing connectivity to resume."
            );
        }

        // The snapshot below reads the DB file, so fold the WAL into it first:
        // the session's own checkpoint. A main file another program wrote is
        // not checkpointed over; the publish below then refuses it.
        match &session_db {
            Some(db) => match db.checkpoints.checkpoint(&conn) {
                Ok(()) | Err(local_db::CheckpointRefused::Foreign(_)) => {}
                Err(local_db::CheckpointRefused::Failed(e)) => {
                    anyhow::bail!("checkpoint metadata DB before snapshot: {e}")
                }
            },
            None => conn
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|e| anyhow::anyhow!("checkpoint metadata DB before snapshot: {e}"))?,
        }
    }
    at(RotateStep::AllBlocksDone);

    // Step 3: make the re-pointed rows recoverable before anything is deleted.
    let session_db = session_db.ok_or_else(|| {
        anyhow::anyhow!(
            "volume '{volume}' has no local metadata database to publish; the epoch has NOT \
             been advanced and nothing was deleted"
        )
    })?;
    super::volume::publish_snapshot_and_compact(
        &mut result,
        transport.as_ref(),
        super::volume::PublishOf::Session(session_db),
    )
    .await
    .with_context(|| {
        format!(
            "key rotation stopped before deleting anything: the blocks are re-encrypted and \
                 re-pointed locally, but publishing the snapshot that names them and resetting \
                 the journal HEAD onto it did not both complete (details below). Every file is \
                 still readable and the epoch has NOT been advanced. Re-run `teagarden key \
                 rotate {volume}` to finish"
        )
    })?;
    at(RotateStep::SnapshotPublished);

    // The deletes below are safe only if a crash recovery would rebuild from the
    // snapshot just published. Re-read both files rather than trust the publish.
    ensure_head_names_published_snapshot(volume, &result)?;

    // Step 4: delete the old messages nothing names any more. Every one that is
    // not deleted is collected and reported; none is skipped silently.
    let mut not_deleted: Vec<i64> = Vec::new();
    {
        let conn = open_db()?;
        let block_store = BlockStore::new(&conn, &schema);
        let mut keys: Vec<String> = marker.blocks.keys().cloned().collect();
        keys.sort();
        let mut targets: Vec<(String, i64)> = Vec::new();
        for key in &keys {
            let s = &marker.blocks[key];
            if !s.old_deleted {
                targets.push((key.clone(), s.old_message_id));
            }
            for id in &s.also_old_message_ids {
                targets.push((key.clone(), *id));
            }
        }
        for (i, (key, old_msg_id)) in targets.iter().enumerate() {
            let old_msg_id = *old_msg_id;
            let still_named = decode_sha256(key)
                .map(|id| block_store.get(&id))
                .transpose()
                .map_err(|e| anyhow::anyhow!("read block row: {e}"))?
                .flatten()
                .is_some_and(|row| row.message_id == old_msg_id);
            if still_named {
                eprintln!(
                    "  WARNING: block {} still names message {old_msg_id}; not deleting it",
                    &key[..16.min(key.len())]
                );
                not_deleted.push(old_msg_id);
                continue;
            }
            match transport.delete_message(old_msg_id).await {
                Err(e) => {
                    eprintln!("  old message {old_msg_id} deletion failed: {e}");
                    not_deleted.push(old_msg_id);
                }
                Ok(()) => {
                    if let Some(s) = marker.blocks.get_mut(key) {
                        if s.old_message_id == old_msg_id {
                            s.old_deleted = true;
                        }
                        s.also_old_message_ids.retain(|id| *id != old_msg_id);
                    }
                    if let Err(e) = marker.save(&volume_dir) {
                        eprintln!("  WARNING — failed to checkpoint marker after deletion: {e}");
                    }
                    at(RotateStep::OldDeleted(i));
                }
            }
        }
    }
    // Track the failures for later cleanup (Fix LOW-2). If that record cannot be
    // written, the marker is the only record of them: stop before the epoch
    // advances (which is what lets the marker go), so the re-run retries them.
    if !not_deleted.is_empty() {
        DeletionFailures::record(&volume_dir, &not_deleted).with_context(|| {
            format!(
                "key rotation stopped before advancing the epoch: {} old message(s) could not be \
                 deleted ({not_deleted:?}) and this run could not record the list of them in {}. \
                 The rotation marker, which names them, is kept and every file is readable. Fix \
                 the cause and run `teagarden key rotate {volume}` again: it retries the deletions",
                not_deleted.len(),
                DeletionFailures::path(&volume_dir).display()
            )
        })?;
    }

    // Step 5: advance the epoch on the SAME config the snapshot publish just
    // updated (it raised the HMAC-covered metadata_version; a stale copy would
    // roll that back). save_config_resealed re-signs config_integrity; a plain
    // write would brick the volume on next open.
    result.config.increment_epoch().map_err(utils::core_err)?;
    manager::save_config_resealed(
        &mut result.config,
        &result.hierarchy,
        &result.paths.config_path,
    )
    .map_err(utils::core_err)?;
    at(RotateStep::EpochAdvanced);

    RotationMarker::remove(&volume_dir);

    Ok(report_outcome(
        &volume_dir,
        old_epoch,
        new_epoch,
        &not_deleted,
        unidentified,
    ))
}

/// Print the end of a rotation and say what it achieved. "complete" is printed
/// only when no old-epoch message is known to be left: none failed or was
/// skipped in this run (`not_deleted`), none is unidentifiable, and the
/// persisted list from earlier runs is readable and empty.
fn report_outcome(
    volume_dir: &std::path::Path,
    old_epoch: u32,
    new_epoch: u32,
    not_deleted: &[i64],
    unidentified: usize,
) -> RotationOutcome {
    let mut left: Vec<i64> = not_deleted.to_vec();
    let recorded = DeletionFailures::load(volume_dir);
    match &recorded {
        Ok(f) => left.extend(&f.pending),
        Err(e) => eprintln!("WARNING: {e:#}"),
    }
    left.sort_unstable();
    left.dedup();
    let complete = left.is_empty() && unidentified == 0 && recorded.is_ok();
    println!();
    if complete {
        println!("Key rotation complete, including old-message deletion.");
    } else {
        if !left.is_empty() {
            println!(
                "WARNING: {} old Telegram message(s) could not be deleted: {left:?}.",
                left.len()
            );
            println!("  These blocks remain on Telegram under the old epoch key.");
            println!(
                "  No automatic cleanup command exists. Pending message IDs are recorded in {}.",
                DeletionFailures::path(volume_dir).display()
            );
        }
        if recorded.is_err() {
            println!(
                "WARNING: the list of old messages earlier rotations could not delete ({}) is \
                 unreadable, so it is not known whether any is left.",
                DeletionFailures::path(volume_dir).display()
            );
        }
        if unidentified > 0 {
            println!(
                "WARNING: {unidentified} old-epoch message(s) could not be identified (an \
                 earlier run's rotation marker was lost) and may remain on Telegram under the \
                 old epoch key."
            );
        }
        println!();
        println!(
            "Key re-encryption and epoch advance complete; old-message deletion is INCOMPLETE."
        );
    }
    println!("  Old epoch: {old_epoch}");
    println!("  New epoch: {new_epoch}");
    RotationOutcome {
        complete,
        reported: left.len() + unidentified,
    }
}

/// Block id -> message id of every row below `below_epoch` in the snapshot the
/// journal HEAD has as its base (volume.json's snapshot for a volume without a
/// HEAD), fetched from Telegram. Empty when the volume has no snapshot.
///
/// The snapshot is used only if it is provably that one: its hash must equal
/// the hash the HEAD (or volume.json) records for it, so there must be one, and
/// the version inside it must equal the HEAD's base version (or volume.json's
/// `metadata_version`). The decrypted copy is read from a fixed file under the
/// volume lock and removed again (see [`BaseSnapshotCopies`]).
async fn old_rows_in_base_snapshot(
    result: &manager::OpenVolumeResult,
    transport: &dyn BlockTransport,
    below_epoch: u32,
    schema: &OpaqueSchema,
) -> Result<HashMap<[u8; 32], i64>> {
    use teagarden_core::volume::journal_head::JournalHead;
    use teagarden_core::volume::metadata_snapshot;
    let head = JournalHead::load(
        &super::volume::journal_head_path(result),
        &result.hierarchy.integrity,
    )
    .map_err(utils::core_err)?;
    let base = match head {
        Some(h) => Some((
            h.base_snapshot_msg_id,
            Some(h.base_snapshot_hash),
            h.base_snapshot_version,
            "the journal HEAD",
        )),
        None => result.config.metadata_snapshot_id.map(|id| {
            (
                id,
                result.config.recorded_snapshot_hash(),
                result.config.metadata_version,
                "volume.json",
            )
        }),
    };
    let Some((msg_id, want, want_version, named_by)) = base else {
        return Ok(HashMap::new());
    };
    let Some(want) = want else {
        anyhow::bail!(
            "{named_by} records no hash for its metadata snapshot (message_id={msg_id}), so a \
             snapshot served under that id cannot be told from a different one"
        );
    };
    let blob = transport
        .fetch_metadata(msg_id)
        .await
        .map_err(utils::telegram_err)
        .with_context(|| format!("fetch metadata snapshot message_id={msg_id}"))?;
    if *blake3::hash(&blob).as_bytes() != want {
        anyhow::bail!(
            "the metadata snapshot served for message_id={msg_id} is not the one {named_by} \
             records for it (hash mismatch)"
        );
    }
    let (version, db) = metadata_snapshot::decrypt_snapshot(&result.hierarchy.data, &blob)
        .map_err(utils::core_err)?;
    if version != want_version {
        anyhow::bail!(
            "the metadata snapshot message_id={msg_id} holds version {version}, but {named_by} \
             names version {want_version} for it"
        );
    }
    let tmp = base_snapshot_copy_path(&result.paths.base_dir);
    remove_base_snapshot_copies(&result.paths.base_dir);
    teagarden_core::fsutil::write_file_atomic(&tmp, &db, "snapshot copy")
        .map_err(utils::core_err)?;
    let rows = local_db::open_read_only(&tmp)
        .map_err(anyhow::Error::from)
        .and_then(|conn| {
            let bs = BlockStore::new(&conn, schema);
            let mut rows = Vec::new();
            for e in 0..below_epoch {
                rows.extend(bs.list_by_epoch(e)?);
            }
            Ok(rows)
        });
    remove_base_snapshot_copies(&result.paths.base_dir);
    Ok(rows
        .context("read the block rows of the metadata snapshot")?
        .into_iter()
        .map(|b| (b.block_id, b.message_id))
        .collect())
}

/// Refuse (before anything is deleted) unless, ON DISK, volume.json names the
/// snapshot this rotation published and the journal HEAD has that snapshot, with
/// its hash, as its base and no entries past it. Otherwise a crash recovery would
/// rebuild block rows from an older snapshot whose rows name the old messages.
fn ensure_head_names_published_snapshot(
    volume: &str,
    result: &manager::OpenVolumeResult,
) -> Result<()> {
    let head_path = super::volume::journal_head_path(result);
    let on_disk: teagarden_core::volume::config::VolumeConfig = serde_json::from_slice(
        &std::fs::read(&result.paths.config_path).context("re-read volume.json")?,
    )
    .context("parse volume.json")?;
    let head = teagarden_core::volume::journal_head::JournalHead::load(
        &head_path,
        &result.hierarchy.integrity,
    );
    let published = (
        result.config.metadata_snapshot_id,
        result.config.recorded_snapshot_hash(),
    );
    let named = (
        on_disk.metadata_snapshot_id,
        on_disk.recorded_snapshot_hash(),
    );
    let head_ok = matches!(&head, Ok(Some(h)) if h.seq == 0
        && Some(h.base_snapshot_msg_id) == published.0
        && Some(h.base_snapshot_hash) == published.1);
    if published.0.is_some() && published.1.is_some() && named == published && head_ok {
        return Ok(());
    }
    let head_state = match &head {
        Ok(Some(h)) => format!(
            "names base snapshot message_id={} with {} entr{} past it",
            h.base_snapshot_msg_id,
            h.seq,
            if h.seq == 1 { "y" } else { "ies" }
        ),
        Ok(None) => "is missing".to_string(),
        Err(e) => format!("is unreadable ({e})"),
    };
    anyhow::bail!(
        "key rotation stopped before deleting any old message: the journal HEAD ({}) {head_state}, \
         but the snapshot this rotation published is message_id={} (volume.json names \
         message_id={}). A crash recovery would rebuild from the HEAD's base, whose block rows \
         name the old messages, so none of them was deleted. Every file is still readable, the \
         epoch has NOT been advanced and the rotation marker is kept. Re-run `teagarden key \
         rotate {volume}` to finish: it publishes the snapshot and resets the HEAD again.",
        head_path.display(),
        published.0.map_or("none".to_string(), |id| id.to_string()),
        named.0.map_or("none".to_string(), |id| id.to_string()),
    );
}

pub async fn export(
    volume: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
) -> Result<()> {
    let volumes_dir = manager::default_volumes_dir();

    // Find the volume
    let volumes = manager::list_volumes(&volumes_dir).map_err(utils::core_err)?;

    let config = volumes
        .into_iter()
        .find(|v| v.volume_id.to_string() == volume || v.display_name == volume)
        .ok_or_else(|| anyhow::anyhow!("Volume '{volume}' not found"))?;

    // Key-protection aware: key export on a `--key-protection` volume needs a factor.
    let result = utils::open_volume_any(
        &config.volume_id.to_string(),
        password_file,
        recovery_file,
        &volumes_dir,
    )?;

    // Encode root key as sentence reference
    let wordlists = sentence::wordlists::production_wordlists();
    let sentence_ref =
        sentence::encode::encode_ref_string(result.hierarchy.root.as_bytes(), &wordlists)
            .map_err(utils::core_err)?;

    println!();
    println!("Sentence Reference for volume '{}':", config.display_name);
    println!();
    println!("  {sentence_ref}");
    println!();
    println!("Store this reference securely. It allows full key recovery");
    println!("without your password. Do NOT share it.");
    println!();
    // mfa-H2(c): printed for EVERY volume — the exported value is the hierarchy
    // root, which opens the volume no matter how it is otherwise protected.
    println!("WARNING: this sentence opens the volume by itself, without any slot or factor —");
    println!("no passphrase, recovery slot, TPM2, FIDO2, PKCS#11 or Tang is consulted. It");
    println!("cannot be revoked: changing or removing key slots, re-enrolling factors, and");
    println!("`key rotate` all leave it working. The only cut-off is moving the data to a new");
    println!("volume. Anyone who ever sees it keeps full access.");
    if config.key_protection.is_some() {
        println!();
        println!("WARNING: this volume is key-protected, and this sentence BYPASSES that.");
        println!("It encodes the volume's hierarchy root (not the vault master key, but the");
        println!("value derived from it that all the volume's keys hang off), so whoever holds");
        println!("it can open the volume without any enrolled factor — no TPM2, no FIDO2, no");
        println!("PKCS#11, no Tang — via `teagarden key import --recovery-file` or a volume");
        println!("command's --recovery-file option. It also keeps");
        println!("working after you remove a slot or re-seal the vault. Treat this sentence as");
        println!("equivalent to every factor at once, and destroy it when it is no longer needed.");
    }

    Ok(())
}

pub async fn import(sentence_str: &str) -> Result<()> {
    let words: Vec<&str> = sentence_str.split_whitespace().collect();
    if words.len() != 22 {
        anyhow::bail!(
            "Invalid sentence reference: expected 22 words, got {}",
            words.len()
        );
    }

    // Decode sentence back to root key
    let wordlists: [Vec<String>; 4] = sentence::wordlists::production_wordlists();
    let reverse_lookups: [std::collections::HashMap<String, u16>; 4] =
        core::array::from_fn(|i| sentence::wordlists::build_reverse_lookup(&wordlists[i]));
    let key_bytes = Zeroizing::new(
        sentence::decode::decode_ref_string(sentence_str, &wordlists, &reverse_lookups)
            .map_err(utils::core_err)?,
    );
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "decoded root is {} bytes, expected 32 — this is not a valid recovery sentence",
            key_bytes.len()
        );
    }
    let mut root = Zeroizing::new([0u8; 32]);
    root.copy_from_slice(&key_bytes[..]);

    // Verify the root against the LOCAL volumes: a recovery sentence is only a
    // real credential if it actually opens a volume. open_volume_shared derives
    // the hierarchy from the root and checks it against each volume's own
    // verification hash + config-integrity anchors, so exactly the volume this
    // root belongs to (if its config is present locally) will verify.
    use teagarden_core::volume::manager;
    use teagarden_core::volume::shared::SharedDerivation;
    let volumes_dir = manager::default_volumes_dir();
    let volumes = manager::list_volumes(&volumes_dir).map_err(utils::core_err)?;

    let mut opened = None;
    for v in &volumes {
        let id = v.volume_id.to_string();
        if manager::open_volume_shared(&id, &root, SharedDerivation::HierarchyRootV1, &volumes_dir)
            .is_ok()
        {
            opened = Some((id, v.display_name.clone()));
            break;
        }
    }

    match opened {
        Some((id, name)) => {
            println!("Recovery sentence verified — it opens volume '{name}' ({id}).");
            println!();
            println!("This root is a valid recovery credential for that volume: mount it with");
            println!("  teagarden volume mount {id} <mountpoint>");
            println!("using the sentence via --recovery-file, or re-protect it with a new");
            println!("passphrase.");
            Ok(())
        }
        None => {
            // Do NOT claim success. A root alone cannot reconstruct a volume whose
            // config is absent — that needs the volume's config too.
            anyhow::bail!(
                "The sentence decoded to a 32-byte root, but it does not open any volume whose \
                 config is present on this machine.\n  \
                 A recovery sentence alone cannot rebuild a volume without its config \
                 (salt, Telegram group/topic, KDF params). If you still have the volume's \
                 directory, mount it with --recovery-file; to move a whole volume to a new \
                 machine, use a share grant (`teagarden share grant` / `share import`), which \
                 carries the config too."
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_marker_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut blocks = std::collections::HashMap::new();
        blocks.insert(
            "aabbcc".to_string(),
            RotationBlock {
                block_id_hex: "aabbcc".to_string(),
                old_message_id: 100,
                new_message_id: None,
                new_ciphertext_sha256: None,
                db_updated: false,
                old_deleted: false,
                also_old_message_ids: vec![],
            },
        );
        let marker = RotationMarker {
            volume_id: "test-vol".to_string(),
            old_epoch: 0,
            new_epoch: 1,
            blocks,
        };
        marker.save(dir.path()).unwrap();
        let loaded = RotationMarker::load(dir.path(), "v").unwrap().unwrap();
        assert_eq!(loaded.old_epoch, 0);
        assert_eq!(loaded.new_epoch, 1);
        assert!(loaded.blocks.contains_key("aabbcc"));
    }

    #[test]
    fn rotate_unknown_volume_fails_safe() {
        // Rotation is enabled (the manifests-unreadable and unsealed-integrity
        // bugs are fixed: reads resolve a block's location from the store, and the
        // epoch advance is persisted via save_config_resealed). An unknown volume
        // must still fail cleanly — return an error, never panic or touch data.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(rotate("definitely-not-a-real-volume-xyz", None, None, None))
            .unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "rotate of an unknown volume must fail cleanly with 'not found', got: {err}"
        );
    }

    #[test]
    fn rotation_marker_carries_ciphertext_hash() {
        // The checkpointed new ciphertext hash must round-trip so a resumed
        // rotation can refresh ciphertext_sha256 without re-encrypting.
        let dir = tempfile::TempDir::new().unwrap();
        let sha_hex = hex::encode([0xAB; 32]);
        let mut blocks = std::collections::HashMap::new();
        blocks.insert(
            "k".to_string(),
            RotationBlock {
                block_id_hex: "k".to_string(),
                old_message_id: 1,
                new_message_id: Some(2),
                new_ciphertext_sha256: Some(sha_hex.clone()),
                db_updated: false,
                old_deleted: false,
                also_old_message_ids: vec![],
            },
        );
        RotationMarker {
            volume_id: "v".to_string(),
            old_epoch: 0,
            new_epoch: 1,
            blocks,
        }
        .save(dir.path())
        .unwrap();
        let loaded = RotationMarker::load(dir.path(), "v").unwrap().unwrap();
        assert_eq!(
            loaded.blocks["k"].new_ciphertext_sha256.as_deref(),
            Some(sha_hex.as_str())
        );
    }

    #[test]
    fn decode_sha256_roundtrips_and_rejects_bad_input() {
        let bytes = [0x9Au8; 32];
        assert_eq!(decode_sha256(&hex::encode(bytes)), Some(bytes));
        assert_eq!(decode_sha256("not-hex"), None);
        assert_eq!(decode_sha256("aabb"), None); // wrong length
    }

    #[test]
    fn rotation_marker_remove() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = RotationMarker {
            volume_id: "v".to_string(),
            old_epoch: 0,
            new_epoch: 1,
            blocks: Default::default(),
        };
        marker.save(dir.path()).unwrap();
        assert!(RotationMarker::path(dir.path()).exists());
        RotationMarker::remove(dir.path());
        assert!(!RotationMarker::path(dir.path()).exists());
    }

    #[test]
    fn deletion_failures_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = DeletionFailures::default();
        f.pending.push(42);
        f.pending.push(99);
        f.save(dir.path()).unwrap();
        let loaded = DeletionFailures::load(dir.path()).unwrap();
        assert_eq!(loaded.pending, vec![42, 99]);
    }

    #[test]
    fn deletion_failures_no_duplicates() {
        let dir = tempfile::TempDir::new().unwrap();
        DeletionFailures::record(dir.path(), &[7]).unwrap();
        DeletionFailures::record(dir.path(), &[7, 8]).unwrap();
        let f = DeletionFailures::load(dir.path()).unwrap();
        assert_eq!(f.pending, vec![7, 8]);
    }

    /// R2: a torn deletion-failure list is an error, never "nothing left".
    #[test]
    fn unreadable_deletion_failures_is_an_error() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(DeletionFailures::path(dir.path()), b"{\"pend").unwrap();
        assert!(DeletionFailures::load(dir.path()).is_err());
        assert!(DeletionFailures::record(dir.path(), &[1]).is_err());
        let o = report_outcome(dir.path(), 0, 1, &[], 0);
        assert!(!o.complete, "an unreadable list must not read as complete");
    }

    /// R2: an unreadable marker is an error that names the file and how to
    /// recover, never "no marker"; a missing one is `None`.
    #[test]
    fn unreadable_rotation_marker_is_an_error_with_instructions() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(RotationMarker::load(dir.path(), "v").unwrap().is_none());
        for bytes in [&b""[..], &b"{\"volume_id\": \"v\", \"old_ep"[..]] {
            std::fs::write(RotationMarker::path(dir.path()), bytes).unwrap();
            let msg = format!("{:#}", RotationMarker::load(dir.path(), "v").unwrap_err());
            assert!(
                msg.contains("cannot be read") && msg.contains("mv "),
                "{msg}"
            );
        }
    }

    // ── F1: rotation must never leave the only recoverable metadata pointing at
    //    deleted messages ────────────────────────────────────────────────────

    use std::collections::BTreeMap;
    use teagarden_core::block::pointer::{BlockPointer, FileManifest};
    use teagarden_core::metadata::inode::Inode;
    use teagarden_core::volume::journal_head::JournalHead;
    use teagarden_core::volume::metadata_snapshot;
    use teagarden_fuse::fs::CryptFs;
    use teagarden_store::block_store::BlockRecord;
    use teagarden_store::inode_store::InodeStore;
    use teagarden_store::manifest_store::ManifestStore;
    use teagarden_telegram::mock::MockTransport;

    const ROT_PASS: &[u8] = b"rotation-test-pass";

    /// A volume with three files on a mock channel, after one clean unmount
    /// (snapshot published, HEAD at seq 0). `/h` has two versions so a later
    /// session can make a journaled change with `revert_core`.
    struct RotVol {
        dir: tempfile::TempDir,
        id: String,
        mock: Arc<MockTransport>,
        /// ino -> expected bytes.
        expect: BTreeMap<u64, Vec<u8>>,
        /// Every block message the volume had before rotation.
        pre_rotation_msgs: Vec<i64>,
        /// Bytes of `/h` version 1 and version 2.
        h_versions: [Vec<u8>; 2],
    }

    impl RotVol {
        fn open(&self) -> manager::OpenVolumeResult {
            manager::open_volume(&self.id, ROT_PASS, self.dir.path()).unwrap()
        }
        fn transport(&self) -> Arc<dyn BlockTransport> {
            self.mock.clone()
        }
    }

    fn block_bytes(tag: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| tag ^ (i as u8).wrapping_mul(31)).collect()
    }

    /// Encrypt `pt` as an epoch-0 block, upload it, insert its row, and return its pointer.
    fn put_block(
        rt: &tokio::runtime::Runtime,
        mock: &MockTransport,
        result: &manager::OpenVolumeResult,
        bs: &BlockStore<'_>,
        pt: &[u8],
        file_offset: u64,
    ) -> BlockPointer {
        let block_id = *blake3::hash(pt).as_bytes();
        let key = kdf::derive_epoch_key(&result.hierarchy.data, 0).unwrap();
        let aad = block_aad(0, &block_id, result.config.block_v2_from_epoch);
        let ct = aead::encrypt(&key.key, pt, &aad).unwrap();
        let name = hex::encode(rand::random::<[u8; 16]>());
        let msg = rt
            .block_on(mock.upload_block(&ct, &name))
            .unwrap()
            .message_id;
        bs.insert(&BlockRecord {
            block_id,
            filename: name,
            message_id: msg,
            plaintext_size: pt.len() as i64,
            encrypted_size: ct.len() as i64,
            epoch: 0,
            ref_count: 1,
            compressed: false,
            plaintext_sha256: srb2::sha256(pt),
            ciphertext_sha256: srb2::sha256(&ct),
        })
        .unwrap();
        BlockPointer {
            block_id,
            message_id: msg,
            file_offset,
            length: pt.len() as u64,
            block_data_offset: 0,
            encrypted_size: ct.len() as u64,
            compressed: false,
            epoch: 0,
        }
    }

    fn manifest(
        ino: u64,
        version: u64,
        blocks: Vec<BlockPointer>,
        parents: Vec<[u8; 32]>,
    ) -> FileManifest {
        FileManifest {
            inode: ino,
            version,
            total_size: blocks.iter().map(|b| b.length).sum(),
            file_hash: [version as u8; 32],
            blocks,
            parent_ids: parents,
        }
    }

    fn rot_volume(rt: &tokio::runtime::Runtime) -> RotVol {
        let dir = tempfile::tempdir().unwrap();
        let created =
            manager::create_volume(Some("rot"), ROT_PASS, dir.path(), 0, 0, 0, None).unwrap();
        let id = created.config.volume_id.to_string();
        let mut result = manager::open_volume(&id, ROT_PASS, dir.path()).unwrap();
        let mock = Arc::new(MockTransport::new());
        let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
        let mut expect = BTreeMap::new();
        let h_versions = [block_bytes(0x61, 1500), block_bytes(0x62, 2500)];
        {
            let conn = rusqlite::Connection::open(&result.paths.db_path).unwrap();
            initialize_database(&conn, &schema).unwrap();
            let meta = result.hierarchy.meta.clone();
            let is = InodeStore::new(&conn, &schema, &meta);
            let ms = ManifestStore::new(&conn, &schema, &meta);
            let bs = BlockStore::new(&conn, &schema);
            is.insert(&Inode::root()).unwrap();

            // /a: three blocks; /b: one block.
            for (ino, name, parts) in [
                (
                    2u64,
                    "a",
                    vec![
                        block_bytes(0x11, 3000),
                        block_bytes(0x12, 3000),
                        block_bytes(0x13, 1234),
                    ],
                ),
                (3u64, "b", vec![block_bytes(0x21, 999)]),
            ] {
                let mut off = 0;
                let mut ptrs = vec![];
                for p in &parts {
                    ptrs.push(put_block(rt, &mock, &result, &bs, p, off));
                    off += p.len() as u64;
                }
                let m = manifest(ino, 1, ptrs, vec![]);
                ms.insert(&m).unwrap();
                let mut f = Inode::new_file(ino, 1, name.into(), 0o644, 1000, 1000);
                f.size = m.total_size;
                f.manifest = Some(m);
                is.insert(&f).unwrap();
                expect.insert(ino, parts.concat());
            }
            // /h: version 1 and version 2 (current).
            let v1 = manifest(
                4,
                1,
                vec![put_block(rt, &mock, &result, &bs, &h_versions[0], 0)],
                vec![],
            );
            let v1_id = v1.compute_id(&result.hierarchy.manifest);
            let v2 = manifest(
                4,
                2,
                vec![put_block(rt, &mock, &result, &bs, &h_versions[1], 0)],
                vec![v1_id],
            );
            ms.insert(&v1).unwrap();
            ms.insert(&v2).unwrap();
            let mut h = Inode::new_file(4, 1, "h".into(), 0o644, 1000, 1000);
            h.size = v2.total_size;
            h.manifest = Some(v2);
            is.insert(&h).unwrap();
            expect.insert(4, h_versions[1].clone());
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }
        let pre_rotation_msgs = {
            let conn = rusqlite::Connection::open(&result.paths.db_path).unwrap();
            let bs = BlockStore::new(&conn, &schema);
            bs.list_by_epoch(0)
                .unwrap()
                .iter()
                .map(|b| b.message_id)
                .collect()
        };
        // Session 1 ends with a clean unmount: snapshot published, HEAD at seq 0.
        rt.block_on(super::super::volume::publish_as_new_session(
            &mut result,
            mock.as_ref(),
        ))
        .unwrap();
        RotVol {
            dir,
            id,
            mock,
            expect,
            pre_rotation_msgs,
            h_versions,
        }
    }

    /// Read every expected file through `CryptFs::download_block` (which resolves
    /// each block's current location from the block store). `None` = unreadable.
    fn read_files(rt: &tokio::runtime::Runtime, v: &RotVol) -> BTreeMap<u64, Option<Vec<u8>>> {
        let result = v.open();
        let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
        let conn = rusqlite::Connection::open(&result.paths.db_path).unwrap();
        initialize_database(&conn, &schema).unwrap();
        let fs = CryptFs::new(
            conn,
            schema,
            result.hierarchy.meta.clone(),
            result.hierarchy.data.clone(),
            1000,
            1000,
        )
        .with_epoch(result.config.current_epoch)
        .with_block_keys(
            result.hierarchy.block_id.clone(),
            result.hierarchy.filename.clone(),
        )
        .with_manifest_key(result.hierarchy.manifest.clone())
        .with_block_integrity(result.config.require_block_integrity)
        .with_block_v2_from_epoch(result.config.block_v2_from_epoch)
        .with_transport(v.transport())
        .with_runtime(rt.handle().clone());
        v.expect
            .keys()
            .map(|&ino| {
                let got = fs.store().get(ino).unwrap().and_then(|i| {
                    let mut out = vec![];
                    for bp in &i.manifest?.blocks {
                        out.extend(fs.download_block(bp.message_id, &bp.block_id, bp.epoch)?);
                    }
                    Some(out)
                });
                (ino, got)
            })
            .collect()
    }

    fn assert_files_exact(rt: &tokio::runtime::Runtime, v: &RotVol, when: &str) {
        let got = read_files(rt, v);
        for (ino, want) in &v.expect {
            match &got[ino] {
                Some(bytes) => {
                    assert!(bytes == want, "{when}: ino {ino} read back different bytes")
                }
                None => {
                    panic!("{when}: ino {ino} is UNREADABLE (its blocks point at missing messages)")
                }
            }
        }
    }

    fn rotate_with(
        rt: &tokio::runtime::Runtime,
        v: &RotVol,
        at: &dyn Fn(RotateStep),
    ) -> Result<()> {
        let t = v.transport();
        let connect: ConnectTransport<'_> = Box::new(move || Box::pin(async move { Some(t) }));
        rt.block_on(rotate_core("rot", v.open(), connect, at))
            .map(|_| ())
    }

    /// The next session: a mount that makes one journaled change (`/h` reverted to
    /// version `to`) and then dies before its unmount snapshot is published. The
    /// HEAD is left at seq > 0, so the mount after it runs journal recovery.
    fn session_crashes_before_snapshot(rt: &tokio::runtime::Runtime, v: &mut RotVol, to: u64) {
        v.mock.set_metadata_budget(Some(1)); // the delta publishes; the snapshot does not
        let r = rt.block_on(super::super::volume::revert_core(
            v.open(),
            v.transport(),
            "/h",
            to,
        ));
        v.mock.set_metadata_budget(None);
        assert!(r.is_err(), "the unmount snapshot must have failed");
        let result = v.open();
        let head = JournalHead::load(
            &super::super::volume::journal_head_path(&result),
            &result.hierarchy.integrity,
        )
        .unwrap()
        .unwrap();
        assert!(
            head.seq > 0,
            "an unclean session leaves journal entries to replay"
        );
        v.expect.insert(4, v.h_versions[(to - 1) as usize].clone());
    }

    /// The mount after a crash: journal recovery rebuilds the DB from the HEAD's
    /// base snapshot + deltas. Then every file must read back byte-exact.
    fn recover_and_check(rt: &tokio::runtime::Runtime, v: &RotVol, when: &str) {
        let mut result = v.open();
        rt.block_on(super::super::volume::journal_recover_phase(
            &mut result,
            v.mock.as_ref(),
        ))
        .unwrap_or_else(|e| panic!("{when}: journal recovery failed: {e:#}"));
        assert_files_exact(rt, v, when);
    }

    /// ...and that mount ends cleanly (snapshot + HEAD reset).
    fn clean_unmount(rt: &tokio::runtime::Runtime, v: &RotVol) {
        let mut result = v.open();
        rt.block_on(super::super::volume::publish_as_new_session(
            &mut result,
            v.mock.as_ref(),
        ))
        .unwrap();
    }

    fn assert_rotation_complete(v: &RotVol, when: &str) {
        let result = v.open();
        assert_eq!(
            result.config.current_epoch, 1,
            "{when}: epoch advanced exactly once"
        );
        assert!(
            !RotationMarker::path(&result.paths.base_dir).exists(),
            "{when}: marker removed"
        );
        for id in &v.pre_rotation_msgs {
            assert!(
                v.mock.get_raw(*id).is_none(),
                "{when}: old message {id} still on the channel"
            );
        }
        let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
        let conn = rusqlite::Connection::open(&result.paths.db_path).unwrap();
        let bs = BlockStore::new(&conn, &schema);
        assert!(
            bs.list_by_epoch(0).unwrap().is_empty(),
            "{when}: no block left at epoch 0"
        );
        for b in bs.list_by_epoch(1).unwrap() {
            assert!(
                v.mock.get_raw(b.message_id).is_some(),
                "{when}: row names a missing message"
            );
        }
    }

    /// The review reproduction, through the real code: rotate, mount, change, crash before
    /// the unmount snapshot, recover. Every file must still read back byte-exact,
    /// and the snapshot the recovery used must already hold the rotated rows.
    #[test]
    fn rotate_then_crash_in_next_session_keeps_every_file() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut v = rot_volume(&rt);
        assert_files_exact(&rt, &v, "before rotation");
        rotate_with(&rt, &v, &|_| {}).unwrap();
        assert_files_exact(&rt, &v, "after rotation");
        assert_rotation_complete(&v, "after rotation");

        // The recoverable copy on the channel names the new messages.
        let result = v.open();
        let head = JournalHead::load(
            &super::super::volume::journal_head_path(&result),
            &result.hierarchy.integrity,
        )
        .unwrap()
        .unwrap();
        assert_eq!(head.seq, 0);
        let blob = v.mock.get_raw(head.base_snapshot_msg_id).unwrap();
        let (_, db) = metadata_snapshot::decrypt_snapshot(&result.hierarchy.data, &blob).unwrap();
        let snap_path = v.dir.path().join("snap.db");
        std::fs::write(&snap_path, db).unwrap();
        let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
        let conn = rusqlite::Connection::open(&snap_path).unwrap();
        let bs = BlockStore::new(&conn, &schema);
        assert_eq!(
            bs.list_by_epoch(0).unwrap().len(),
            0,
            "snapshot still has epoch-0 rows"
        );
        assert_eq!(
            bs.list_by_epoch(1).unwrap().len(),
            v.pre_rotation_msgs.len()
        );
        drop(conn);

        session_crashes_before_snapshot(&rt, &mut v, 1);
        recover_and_check(&rt, &v, "recovery after the post-rotation session");
    }

    /// The step boundaries the crash matrix stops a rotation at.
    fn crash_points() -> Vec<RotateStep> {
        let mut v = vec![];
        for i in [0, 2, 5] {
            v.push(RotateStep::Uploaded(i));
            v.push(RotateStep::RowUpdated(i));
        }
        v.push(RotateStep::AllBlocksDone);
        v.push(RotateStep::SnapshotPublished);
        for i in [0, 3, 5] {
            v.push(RotateStep::OldDeleted(i));
        }
        v.push(RotateStep::EpochAdvanced);
        v
    }

    /// A rotation killed at every step boundary. Each time: the volume is still
    /// fully readable after a crashed-and-recovered session; the re-run rotation
    /// completes (epoch advanced exactly once, every old message deleted); and a
    /// session that crashes after that also recovers every byte.
    #[test]
    fn rotate_killed_at_every_step_then_resumed_never_loses_data() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        for step in crash_points() {
            let when = format!("killed at {step:?}");
            let mut v = rot_volume(&rt);
            let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rotate_with(&rt, &v, &|s| {
                    if s == step {
                        panic!("simulated kill at {s:?}");
                    }
                })
            }));
            assert!(
                killed.is_err(),
                "{when}: the rotation never reached that step"
            );

            // Without resuming: a session that crashes, then recovery.
            session_crashes_before_snapshot(&rt, &mut v, 1);
            recover_and_check(&rt, &v, &format!("{when}, then a crashed session"));
            clean_unmount(&rt, &v);

            // Resume the rotation to completion.
            let claimed =
                rotate_claims(&rt, &v).unwrap_or_else(|e| panic!("{when}: resume failed: {e:#}"));
            assert!(claimed.complete, "{when}: resume did not report completion");
            assert_files_exact(&rt, &v, &format!("{when}, after resume"));
            assert_rotation_complete(&v, &format!("{when}, after resume"));

            // And a crashed session after the resumed rotation still recovers.
            session_crashes_before_snapshot(&rt, &mut v, 2);
            recover_and_check(&rt, &v, &format!("{when}, resumed, then a crashed session"));
        }
    }

    fn old_messages_left(v: &RotVol) -> usize {
        v.pre_rotation_msgs
            .iter()
            .filter(|id| v.mock.get_raw(**id).is_some())
            .count()
    }

    /// R1 (review reproduction 1): the HEAD reset inside the snapshot publish fails (the
    /// rename target is a directory here; ENOSPC/EIO/EDQUOT in the field). That
    /// failure must stop the rotation BEFORE any old message is deleted, since
    /// the HEAD still names the pre-rotation snapshot that a crash recovery would
    /// rebuild from. After the cause is fixed, the volume survives a crashed
    /// session and the re-run rotation completes for real.
    #[test]
    fn head_reset_failure_stops_rotation_before_any_delete() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut v = rot_volume(&rt);
        let hp = super::super::volume::journal_head_path(&v.open());
        let saved = std::cell::RefCell::new(None::<Vec<u8>>);
        let err = rotate_with(&rt, &v, &|s| {
            if s == RotateStep::AllBlocksDone {
                *saved.borrow_mut() = Some(std::fs::read(&hp).unwrap());
                std::fs::remove_file(&hp).unwrap();
                std::fs::create_dir(&hp).unwrap();
                std::fs::write(hp.join("block-rename"), b"x").unwrap();
            }
            if matches!(s, RotateStep::OldDeleted(_) | RotateStep::EpochAdvanced) {
                panic!("rotation went on to {s:?} after the HEAD reset failed");
            }
        })
        .expect_err("a failed HEAD reset must stop the rotation");
        let msg = format!("{err:#}");
        eprintln!("R1 rotation error: {msg}");
        assert!(msg.contains("journal HEAD"), "{msg}");
        assert_eq!(old_messages_left(&v), v.pre_rotation_msgs.len());
        assert_eq!(v.open().config.current_epoch, 0);
        assert!(RotationMarker::path(&v.open().paths.base_dir).exists());

        // The cause is fixed (the failed atomic write left the old HEAD in place).
        std::fs::remove_dir_all(&hp).unwrap();
        std::fs::write(&hp, saved.borrow().as_ref().unwrap()).unwrap();
        assert_files_exact(&rt, &v, "R1 after the stopped rotation");
        session_crashes_before_snapshot(&rt, &mut v, 1);
        recover_and_check(&rt, &v, "R1 crashed session after the stopped rotation");
        clean_unmount(&rt, &v);

        rotate_with(&rt, &v, &|_| {}).expect("the re-run rotation completes");
        assert_rotation_complete(&v, "R1 after the re-run");
        assert_files_exact(&rt, &v, "R1 after the re-run");
        session_crashes_before_snapshot(&rt, &mut v, 2);
        recover_and_check(&rt, &v, "R1 crashed session after the re-run");
    }

    /// R1, the reload check on its own: the publish reports success, but the
    /// journal HEAD on disk does not name the snapshot it published (here: the
    /// pre-rotation HEAD, with a valid MAC, is put back). Rotation must re-read
    /// the HEAD and refuse to delete anything.
    #[test]
    fn rotation_rereads_head_and_refuses_to_delete_when_it_names_another_snapshot() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut v = rot_volume(&rt);
        let hp = super::super::volume::journal_head_path(&v.open());
        let pre = std::fs::read(&hp).unwrap();
        let err = rotate_with(&rt, &v, &|s| {
            if s == RotateStep::SnapshotPublished {
                std::fs::write(&hp, &pre).unwrap();
            }
        })
        .expect_err("rotation must refuse when the HEAD names another snapshot");
        let msg = format!("{err:#}");
        eprintln!("R1 reload-check error: {msg}");
        assert!(msg.contains("journal HEAD"), "{msg}");
        assert_eq!(old_messages_left(&v), v.pre_rotation_msgs.len());
        assert_eq!(v.open().config.current_epoch, 0);
        session_crashes_before_snapshot(&rt, &mut v, 1);
        recover_and_check(&rt, &v, "R1 crashed session after the refusal");
        clean_unmount(&rt, &v);
        rotate_with(&rt, &v, &|_| {}).expect("the re-run rotation completes");
        assert_rotation_complete(&v, "R1 reload check, after the re-run");
        assert_files_exact(&rt, &v, "R1 reload check, after the re-run");
    }

    /// What a finished `rotate_core` run claimed: `complete` = it reported every
    /// old-epoch message deleted; `reported` = old messages it reported as left.
    struct Claimed {
        complete: bool,
        reported: usize,
    }

    fn rotate_claims(rt: &tokio::runtime::Runtime, v: &RotVol) -> Result<Claimed> {
        let t = v.transport();
        let connect: ConnectTransport<'_> = Box::new(move || Box::pin(async move { Some(t) }));
        rt.block_on(rotate_core("rot", v.open(), connect, &|_| {}))
            .map(|o| Claimed {
                complete: o.complete,
                reported: o.reported,
            })
    }

    #[derive(Debug, Clone, Copy)]
    enum Tear {
        /// 0 bytes: SIGKILL between O_TRUNC and the write.
        Empty,
        /// The first half of the JSON: a write cut short.
        Truncated,
        /// An intact marker with a stray temp file of the atomic writer beside it.
        StrayTmp,
    }

    fn tear_marker(dir: &std::path::Path, tear: Tear) {
        let mp = RotationMarker::path(dir);
        let intact = std::fs::read(&mp).expect("the killed rotation left its marker");
        match tear {
            Tear::Empty => std::fs::write(&mp, b"").unwrap(),
            Tear::Truncated => std::fs::write(&mp, &intact[..intact.len() / 2]).unwrap(),
            Tear::StrayTmp => std::fs::write(
                dir.join(".rotation_pending.json.4242.00000000deadbeef.tmp"),
                &intact[..intact.len() / 3],
            )
            .unwrap(),
        }
    }

    /// R2 (review reproduction 2): a rotation killed at every step, its marker torn.
    /// The re-run either completes for real (every old-epoch message gone from
    /// the channel, verified against the mock) or fails loudly; when it fails,
    /// following its recovery instruction literally leads to a run that either
    /// completes for real or reports every old message it left. Never a false
    /// "complete", and every file stays readable throughout.
    #[test]
    fn torn_rotation_marker_never_yields_a_false_complete() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut cases = vec![];
        for step in crash_points() {
            cases.push((step, Tear::Empty));
            cases.push((step, Tear::Truncated));
        }
        for step in [
            RotateStep::RowUpdated(2),
            RotateStep::SnapshotPublished,
            RotateStep::OldDeleted(3),
        ] {
            cases.push((step, Tear::StrayTmp));
        }
        for (step, tear) in cases {
            let when = format!("killed at {step:?}, marker {tear:?}");
            let mut v = rot_volume(&rt);
            let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rotate_with(&rt, &v, &|s| {
                    if s == step {
                        panic!("simulated kill at {s:?}");
                    }
                })
            }));
            assert!(
                killed.is_err(),
                "{when}: the rotation never reached that step"
            );
            let base = v.open().paths.base_dir.clone();
            tear_marker(&base, tear);

            let claimed = match rotate_claims(&rt, &v) {
                Ok(c) => c,
                Err(e) => {
                    let msg = format!("{e:#}");
                    eprintln!("{when}: refused: {msg}");
                    assert_files_exact(&rt, &v, &format!("{when}, after the refusal"));
                    // Follow the printed recovery instruction literally.
                    let mp = RotationMarker::path(&base);
                    let aside = format!("{}.unreadable", mp.display());
                    assert!(
                        msg.contains(&format!("mv {} {aside}", mp.display())),
                        "{when}: no recovery instruction in: {msg}"
                    );
                    std::fs::rename(&mp, &aside).unwrap();
                    rotate_claims(&rt, &v).unwrap_or_else(|e| {
                        panic!("{when}: the run after the recovery step failed: {e:#}")
                    })
                }
            };
            let left = old_messages_left(&v);
            eprintln!(
                "{when}: claimed complete={} reported={}, old messages left {left} of {}",
                claimed.complete,
                claimed.reported,
                v.pre_rotation_msgs.len()
            );
            if claimed.complete {
                assert_eq!(left, 0, "{when}: FALSE 'complete' with old messages left");
            } else {
                // Over-reporting is honest ("may remain"); under-reporting is not.
                assert!(
                    claimed.reported >= left,
                    "{when}: {left} old messages left but {} reported",
                    claimed.reported
                );
            }
            let r = v.open();
            assert!(r.config.current_epoch >= 1, "{when}: epoch not advanced");
            assert!(!RotationMarker::path(&base).exists(), "{when}: marker left");
            let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
            let conn = rusqlite::Connection::open(&r.paths.db_path).unwrap();
            let bs = BlockStore::new(&conn, &schema);
            for e in 0..r.config.current_epoch {
                assert!(
                    bs.list_by_epoch(e).unwrap().is_empty(),
                    "{when}: rows at {e}"
                );
            }
            drop(conn);
            assert_files_exact(&rt, &v, &format!("{when}, after the final run"));
            session_crashes_before_snapshot(&rt, &mut v, 1);
            recover_and_check(&rt, &v, &format!("{when}, then a crashed session"));
        }
    }

    /// P1: a resumed rotation whose marker names an earlier upload but no hash
    /// for it (a marker from an older build, or one whose hash was dropped)
    /// must not trust whatever Telegram serves at that id: it re-points the row
    /// only to a copy that decrypts as THIS block under the new epoch key and
    /// AAD, and re-uploads otherwise. Served here: garbage, and a genuine
    /// new-epoch copy of a DIFFERENT block (passes the key, fails the AAD).
    #[test]
    fn resumed_rotation_verifies_an_unhashed_earlier_copy_before_reusing_it() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        for donor_copy in [false, true] {
            let when = if donor_copy {
                "another block's copy"
            } else {
                "garbage"
            };
            let v = rot_volume(&rt);
            let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rotate_with(&rt, &v, &|s| {
                    if s == RotateStep::Uploaded(2) {
                        panic!("simulated kill at {s:?}");
                    }
                })
            }));
            assert!(killed.is_err());
            let base = v.open().paths.base_dir.clone();
            let mut m = RotationMarker::load(&base, "rot").unwrap().unwrap();
            let pending = m
                .blocks
                .values()
                .find(|b| b.new_message_id.is_some() && !b.db_updated)
                .unwrap()
                .clone();
            let donor = m.blocks.values().find(|b| b.db_updated).unwrap().clone();
            let bad_id = pending.new_message_id.unwrap();
            let served = if donor_copy {
                v.mock.get_raw(donor.new_message_id.unwrap()).unwrap()
            } else {
                vec![0x5A; 1234]
            };
            v.mock.put_raw(bad_id, served);
            for b in m.blocks.values_mut() {
                b.new_ciphertext_sha256 = None;
            }
            m.save(&base).unwrap();

            let claimed =
                rotate_claims(&rt, &v).unwrap_or_else(|e| panic!("{when}: resume failed: {e:#}"));
            assert!(claimed.complete, "{when}: resume did not complete");
            assert_files_exact(&rt, &v, &format!("P1 {when}, after resume"));
            let r = v.open();
            let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
            let conn = rusqlite::Connection::open(&r.paths.db_path).unwrap();
            let row = BlockStore::new(&conn, &schema)
                .get(&decode_sha256(&pending.block_id_hex).unwrap())
                .unwrap()
                .unwrap();
            assert_ne!(
                row.message_id, bad_id,
                "{when}: the row was re-pointed at the unverified copy"
            );
            assert_eq!(row.epoch, 1);
        }
    }

    // ── P2: `volume restore` resets the journal HEAD onto what it installed ──

    fn restore(rt: &tokio::runtime::Runtime, v: &RotVol) -> Result<Option<u64>> {
        rt.block_on(super::super::volume::restore_core(
            v.open(),
            v.mock.as_ref(),
            "rot",
            None,
            true,
            true,
        ))
    }

    /// P2: after an unclean session (HEAD at seq 1 over the snapshot) the user
    /// restores that snapshot. The HEAD must then name it at seq 0, so the next
    /// mount does not replay the old journal over the restored DB, and the next
    /// session's entries chain onto the restored snapshot.
    #[test]
    fn restore_resets_the_journal_head_onto_the_restored_snapshot() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut v = rot_volume(&rt);
        session_crashes_before_snapshot(&rt, &mut v, 1);
        let snap = v.open().config.metadata_snapshot_id.unwrap();
        restore(&rt, &v).unwrap();
        v.expect.insert(4, v.h_versions[1].clone()); // the snapshot's `/h`
        let r = v.open();
        let head = JournalHead::load(
            &super::super::volume::journal_head_path(&r),
            &r.hierarchy.integrity,
        )
        .unwrap()
        .unwrap();
        eprintln!(
            "P2: HEAD after restore: seq {} base {}",
            head.seq, head.base_snapshot_msg_id
        );
        assert_eq!((head.seq, head.base_snapshot_msg_id), (0, snap));
        assert!(
            teagarden_core::volume::rebuild_marker::load(&r.paths.base_dir)
                .unwrap()
                .is_none(),
            "a finished restore leaves no rebuild marker"
        );
        assert_eq!(
            Some(head.base_snapshot_hash),
            r.config.recorded_snapshot_hash()
        );
        recover_and_check(&rt, &v, "P2 the mount after the restore");
        session_crashes_before_snapshot(&rt, &mut v, 1);
        recover_and_check(&rt, &v, "P2 a crashed session after the restore");
    }

    /// P2: a restore killed at every step after the floor is persisted. The next
    /// mount (journal recovery) must produce either the pre-restore state (the
    /// old HEAD's base + journal) or the restored one, every file byte-exact,
    /// and a crashed session after that must recover as well.
    #[test]
    fn restore_killed_at_every_step_leaves_a_state_the_next_mount_recovers() {
        use super::super::volume::{restore_core_at, RestoreStep};
        let rt = tokio::runtime::Runtime::new().unwrap();
        for (step, restored) in [
            (RestoreStep::MarkerWritten, false),
            (RestoreStep::LocalDbRemoved, false),
            (RestoreStep::HeadReset, true),
            (RestoreStep::DbInstalled, true),
        ] {
            let when = format!("restore killed at {step:?}");
            let mut v = rot_volume(&rt);
            session_crashes_before_snapshot(&rt, &mut v, 1);
            let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rt.block_on(restore_core_at(
                    v.open(),
                    v.mock.as_ref(),
                    "rot",
                    None,
                    true,
                    true,
                    &|s| {
                        if s == step {
                            panic!("simulated kill at {s:?}");
                        }
                    },
                ))
            }));
            assert!(killed.is_err(), "{when}: never reached");
            if restored {
                v.expect.insert(4, v.h_versions[1].clone());
            }
            let r = v.open();
            let head = JournalHead::load(
                &super::super::volume::journal_head_path(&r),
                &r.hierarchy.integrity,
            )
            .unwrap()
            .unwrap();
            let marker = teagarden_core::volume::rebuild_marker::load(&r.paths.base_dir)
                .unwrap()
                .is_some();
            eprintln!(
                "{when}: db present {}, rebuild marker {marker}, HEAD seq {} -> next mount yields \
                 the {} state",
                r.paths.db_path.exists(),
                head.seq,
                if restored { "restored" } else { "pre-restore" }
            );
            assert!(
                marker,
                "{when}: the interrupted restore left no rebuild marker"
            );
            recover_and_check(&rt, &v, &format!("{when}, the next mount"));
            assert!(
                teagarden_core::volume::rebuild_marker::load(&v.open().paths.base_dir)
                    .unwrap()
                    .is_none(),
                "{when}: the rebuild left its marker"
            );
            clean_unmount(&rt, &v);
            session_crashes_before_snapshot(&rt, &mut v, 2);
            recover_and_check(&rt, &v, &format!("{when}, then a crashed session"));
        }
    }

    // ── R3: a config read before a rotation finished must never be written back ──

    /// `key rotate` takes the volume lock before it reads volume.json (the list
    /// it resolves the name from is used for the id only): while another command
    /// holds the lock it refuses with the lock error, not with the error of the
    /// config below, which still parses but fails its MAC.
    #[test]
    fn rotate_takes_the_volume_lock_before_reading_its_config() {
        let dir = tempfile::tempdir().unwrap();
        let created =
            manager::create_volume(Some("rot"), ROT_PASS, dir.path(), 0, 0, 0, None).unwrap();
        let id = created.config.volume_id.to_string();
        let pass = dir.path().join("pass");
        std::fs::write(&pass, ROT_PASS).unwrap();
        let _held = manager::VolumeLock::acquire_exclusive(&dir.path().join(&id)).unwrap();
        let path = dir.path().join(&id).join("volume.json");
        let mut cfg: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        cfg["metadata_version"] = serde_json::json!(1000);
        std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(rotate_in(
                dir.path(),
                &id,
                Some(pass.to_str().unwrap()),
                None,
                None,
            ))
            .unwrap_err();
        let msg = format!("{err:#}");
        eprintln!("rotate under a held lock: {msg}");
        assert!(msg.contains("in use by another process"), "{msg}");
    }

    /// Review reproduction 3, inverted: a mount that read volume.json before a rotation
    /// finished (the window the lock order now closes) must not publish its
    /// snapshot over the rotation's: that would reuse the rotation's snapshot
    /// version for a different blob and write the rotated-away epoch back.
    #[test]
    fn a_config_read_before_a_rotation_cannot_publish_over_it() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let v = rot_volume(&rt);
        let mut stale = v.open();
        rotate_with(&rt, &v, &|_| {}).unwrap();
        let after = v.open();
        let messages = v.mock.message_count();
        let err = rt
            .block_on(super::super::volume::publish_as_new_session(
                &mut stale,
                v.mock.as_ref(),
            ))
            .expect_err("a stale config must not be published");
        let msg = format!("{err:#}");
        eprintln!("PoC-3 stale publish: {msg}");
        assert!(msg.contains("changed on disk"), "{msg}");
        let now = v.open();
        assert_eq!(now.config.current_epoch, 1, "epoch rolled back");
        assert_eq!(now.config.metadata_version, after.config.metadata_version);
        assert_eq!(
            now.config.metadata_snapshot_id,
            after.config.metadata_snapshot_id
        );
        assert_eq!(
            now.config.metadata_snapshot_hash,
            after.config.metadata_snapshot_hash
        );
        assert_eq!(v.mock.message_count(), messages, "nothing was published");
        assert_files_exact(&rt, &v, "PoC-3 after the refused publish");
    }

    /// Review reproduction 3b, inverted, through the restore path itself: a restore
    /// that read volume.json before a rotation finished must not install the
    /// pre-rotation snapshot (its rows name the messages the rotation deleted).
    #[test]
    fn a_config_read_before_a_rotation_cannot_restore_over_it() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let v = rot_volume(&rt);
        let stale = v.open();
        rotate_with(&rt, &v, &|_| {}).unwrap();
        let err = rt
            .block_on(super::super::volume::restore_core(
                stale,
                v.mock.as_ref(),
                "rot",
                None,
                true,
                true,
            ))
            .expect_err("a stale config must not drive a restore");
        let msg = format!("{err:#}");
        eprintln!("PoC-3b stale restore: {msg}");
        assert!(msg.contains("changed on disk"), "{msg}");
        assert_eq!(v.open().config.current_epoch, 1);
        assert_files_exact(&rt, &v, "PoC-3b after the refused restore");
    }

    /// With journal entries past the base snapshot the local DB may not be what
    /// recovery would rebuild, so rotation must refuse before touching anything.
    #[test]
    fn rotate_refuses_while_the_journal_has_entries() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut v = rot_volume(&rt);
        session_crashes_before_snapshot(&rt, &mut v, 1);
        let before = v.mock.message_count();
        let err = rotate_with(&rt, &v, &|s| panic!("no step may run, reached {s:?}")).unwrap_err();
        assert!(format!("{err:#}").contains("unmount it cleanly"), "{err:#}");
        let result = v.open();
        assert_eq!(result.config.current_epoch, 0);
        assert!(!RotationMarker::path(&result.paths.base_dir).exists());
        assert_eq!(
            v.mock.message_count(),
            before,
            "nothing uploaded or deleted"
        );
    }

    /// `rotation_pending.json` as written by the code at debb93b (fixture
    /// sha256 e83246ba30ce8ec1e6c3173e5057b3ba81c64274c19f689203180d58dc04f268)
    /// still loads, so a rotation interrupted by that build can be resumed.
    #[test]
    fn rotation_marker_written_by_debb93b_still_loads() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rotation-marker-debb93b");
        let m = RotationMarker::load(&dir, "v")
            .unwrap()
            .expect("old marker parses");
        assert_eq!((m.old_epoch, m.new_epoch), (0, 1));
        let b = &m.blocks[&"11".repeat(32)];
        assert_eq!((b.old_message_id, b.new_message_id), (7, Some(9)));
        assert!(b.db_updated && !b.old_deleted);
        assert_eq!(
            b.new_ciphertext_sha256.as_deref(),
            Some(hex::encode([0xAB; 32]).as_str())
        );
    }

    // ── Round 8: no command but a create/recovery path ever creates a metadata
    //    DB; a volume that published metadata is rebuilt, never served empty ──
    mod r8 {
        use super::*;
        use crate::commands::volume::{journal_recover_phase, restore_core_at, RestoreStep};
        use teagarden_store::local_db;

        fn db_len(v: &RotVol) -> u64 {
            std::fs::metadata(&v.open().paths.db_path)
                .map(|m| m.len())
                .unwrap_or(0)
        }

        fn pass_file(v: &RotVol) -> String {
            let p = v.dir.path().join("pass");
            std::fs::write(&p, ROT_PASS).unwrap();
            p.to_string_lossy().into_owned()
        }

        fn history(rt: &tokio::runtime::Runtime, v: &RotVol) -> Result<()> {
            let pass = pass_file(v);
            rt.block_on(crate::commands::history::run_in(
                v.dir.path(),
                &v.id,
                Some(&pass),
                None,
            ))
        }

        fn diff(rt: &tokio::runtime::Runtime, v: &RotVol) -> Result<()> {
            let pass = pass_file(v);
            rt.block_on(crate::commands::history::diff_in(
                v.dir.path(),
                &v.id,
                "00",
                "01",
                Some(&pass),
                None,
            ))
        }

        /// Kill `volume restore` at `step` (always after the floor is persisted).
        fn kill_restore_at(rt: &tokio::runtime::Runtime, v: &RotVol, step: RestoreStep) {
            let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rt.block_on(restore_core_at(
                    v.open(),
                    v.mock.as_ref(),
                    "rot",
                    None,
                    true,
                    true,
                    &|s| {
                        if s == step {
                            panic!("simulated kill at {s:?}");
                        }
                    },
                ))
            }));
            assert!(killed.is_err(), "restore never reached {step:?}");
        }

        /// The next mount: phase-1 journal recovery exactly as `mount_in` runs it.
        fn mount_recover(rt: &tokio::runtime::Runtime, v: &RotVol) {
            let mut r = v.open();
            rt.block_on(journal_recover_phase(&mut r, v.mock.as_ref()))
                .unwrap_or_else(|e| panic!("the next mount failed: {e:#}"));
        }

        /// Inodes below the root in the snapshot volume.json names.
        fn latest_snapshot_entries(v: &RotVol) -> u64 {
            let r = v.open();
            let id = r
                .config
                .metadata_snapshot_id
                .expect("a snapshot is recorded");
            let blob = v
                .mock
                .get_raw(id)
                .expect("the recorded snapshot is on the channel");
            let (_, db) = metadata_snapshot::decrypt_snapshot(&r.hierarchy.data, &blob).unwrap();
            let p = v.dir.path().join(format!("check-{id}.db"));
            std::fs::write(&p, db).unwrap();
            let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
            let n = local_db::tree_summary_of(&p, &schema).unwrap().entries;
            metadata_snapshot::remove_db_files(&p).unwrap();
            n
        }

        /// Every file reads back byte-exact after the next mount, its clean
        /// unmount publishes a snapshot that still holds every file, and a
        /// crashed session after that recovers too.
        fn assert_whole_after_next_mount(rt: &tokio::runtime::Runtime, v: &mut RotVol, when: &str) {
            mount_recover(rt, v);
            assert_files_exact(rt, v, &format!("{when}: after the next mount"));
            let before = v.open().config.metadata_version;
            clean_unmount(rt, v);
            let after = v.open().config;
            assert!(after.metadata_version > before, "{when}: nothing published");
            let n = latest_snapshot_entries(v);
            eprintln!(
                "{when}: the next unmount published snapshot v{} with {n} entries",
                after.metadata_version
            );
            assert_eq!(
                n,
                v.expect.len() as u64,
                "{when}: an EMPTY snapshot was published"
            );
            session_crashes_before_snapshot(rt, v, 1);
            recover_and_check(rt, v, &format!("{when}: then a crashed session"));
        }

        fn assert_refused_as_needing_rebuild(what: &str, r: Result<()>) -> String {
            let msg = format!("{:#}", r.expect_err(what));
            eprintln!("{what}: {msg}");
            assert!(
                msg.contains("rebuilt from Telegram") && msg.contains("Mount the volume"),
                "{what}: no rebuild instruction in: {msg}"
            );
            msg
        }

        /// F1a (PoC r8_history_in_restore_window_empties_the_volume, inverted):
        /// `volume history` / `volume diff` run in every window an interrupted
        /// `volume restore` leaves. They refuse and create nothing; the next
        /// mount rebuilds; its unmount publishes the files, not an empty volume.
        #[test]
        fn history_and_diff_in_the_restore_window_refuse_and_create_nothing() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            for step in [
                RestoreStep::LocalDbRemoved,
                RestoreStep::HeadReset,
                RestoreStep::DbInstalled,
            ] {
                let when = format!("restore killed at {step:?}");
                let mut v = rot_volume(&rt);
                kill_restore_at(&rt, &v, step);
                let len = db_len(&v);
                assert_refused_as_needing_rebuild(&format!("{when}: history"), history(&rt, &v));
                assert_refused_as_needing_rebuild(&format!("{when}: diff"), diff(&rt, &v));
                assert_eq!(db_len(&v), len, "{when}: history/diff changed the DB file");
                assert_whole_after_next_mount(&rt, &mut v, &when);
            }
        }

        /// F1b (PoC r8_rotate_on_absent_db_reports_complete_and_empties_the_volume,
        /// inverted), plus the DB an older build's `history` left (schema only):
        /// `key rotate` refuses, creates nothing and changes nothing; the next
        /// mount rebuilds every file; a rotation after that completes.
        #[test]
        fn rotate_without_a_usable_db_refuses_and_creates_nothing() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            for how in [
                "restore killed at HeadReset",
                "metadata.db lost",
                "schema-only metadata.db",
            ] {
                let mut v = rot_volume(&rt);
                let db_path = v.open().paths.db_path.clone();
                match how {
                    "restore killed at HeadReset" => {
                        kill_restore_at(&rt, &v, RestoreStep::HeadReset)
                    }
                    "metadata.db lost" => metadata_snapshot::remove_db_files(&db_path).unwrap(),
                    _ => {
                        metadata_snapshot::remove_db_files(&db_path).unwrap();
                        let r = v.open();
                        let schema =
                            OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
                        let c = rusqlite::Connection::open(&db_path).unwrap();
                        initialize_database(&c, &schema).unwrap();
                    }
                }
                let len = db_len(&v);
                let messages = v.mock.message_count();
                let r = rotate_claims(&rt, &v).map(|_| ());
                assert_refused_as_needing_rebuild(&format!("F1b [{how}]: rotate"), r);
                assert_eq!(db_len(&v), len, "F1b [{how}]: rotate changed the DB file");
                assert_eq!(v.open().config.current_epoch, 0, "F1b [{how}]: epoch moved");
                assert_eq!(
                    v.mock.message_count(),
                    messages,
                    "F1b [{how}]: Telegram touched"
                );
                assert!(!RotationMarker::path(&v.open().paths.base_dir).exists());
                assert_whole_after_next_mount(&rt, &mut v, &format!("F1b [{how}]"));
                clean_unmount(&rt, &v);
                let c = rotate_claims(&rt, &v).expect("the rotation after the rebuild");
                assert!(
                    c.complete,
                    "F1b [{how}]: the real rotation did not complete"
                );
                assert_files_exact(&rt, &v, &format!("F1b [{how}]: after the rotation"));
            }
        }

        /// F1c: a restore whose journal HEAD write fails (the rename target is
        /// a directory; ENOSPC/EIO in the field) after the local DB is removed.
        /// It is an error; no command uses or creates a DB meanwhile; once the
        /// cause is fixed the next mount rebuilds the pre-restore state.
        #[test]
        fn restore_with_a_failing_head_write_leaves_a_state_the_next_mount_rebuilds() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut v = rot_volume(&rt);
            let hp = super::super::super::volume::journal_head_path(&v.open());
            let saved = std::fs::read(&hp).unwrap();
            std::fs::remove_file(&hp).unwrap();
            std::fs::create_dir(&hp).unwrap();
            std::fs::write(hp.join("block-rename"), b"x").unwrap();
            let err = restore(&rt, &v).expect_err("a failed HEAD write fails the restore");
            eprintln!("F1c restore: {err:#}");
            assert!(!v.open().paths.db_path.exists(), "the DB was removed first");
            std::fs::remove_dir_all(&hp).unwrap();
            std::fs::write(&hp, &saved).unwrap();

            assert_refused_as_needing_rebuild("F1c history", history(&rt, &v));
            assert_refused_as_needing_rebuild("F1c rotate", rotate_claims(&rt, &v).map(|_| ()));
            assert!(
                !v.open().paths.db_path.exists(),
                "F1c: a command created the DB"
            );
            assert_whole_after_next_mount(&rt, &mut v, "F1c");
        }

        /// The next mount rebuilds a schema-only DB (what an older build's
        /// `history` or `key rotate` created) instead of mounting it.
        #[test]
        fn the_next_mount_rebuilds_a_schema_only_db() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut v = rot_volume(&rt);
            let r = v.open();
            metadata_snapshot::remove_db_files(&r.paths.db_path).unwrap();
            let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
            let c = rusqlite::Connection::open(&r.paths.db_path).unwrap();
            initialize_database(&c, &schema).unwrap();
            drop(c);
            assert_whole_after_next_mount(&rt, &mut v, "schema-only DB");
        }

        /// F4 (PoC r8_restore_discards_acknowledged_journal_entries, inverted):
        /// after an unclean session, `volume restore` refuses to drop the
        /// journaled change unless told to, says how many entries it would
        /// drop, and changes nothing; with the option it restores the snapshot.
        #[test]
        fn restore_refuses_to_discard_journal_entries_unless_told() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut v = rot_volume(&rt);
            session_crashes_before_snapshot(&rt, &mut v, 1);
            let cfg_before = std::fs::read(&v.open().paths.config_path).unwrap();
            let hp = super::super::super::volume::journal_head_path(&v.open());
            let head_before = std::fs::read(&hp).unwrap();
            let db_before = std::fs::read(&v.open().paths.db_path).unwrap();
            let err = rt
                .block_on(super::super::super::volume::restore_core(
                    v.open(),
                    v.mock.as_ref(),
                    "rot",
                    None,
                    true,
                    false,
                ))
                .expect_err("restore must refuse to discard journal entries");
            let msg = format!("{err:#}");
            eprintln!("F4 restore without --discard-journal: {msg}");
            assert!(
                msg.contains("1 entry") && msg.contains("--discard-journal"),
                "{msg}"
            );
            assert_eq!(
                std::fs::read(&v.open().paths.config_path).unwrap(),
                cfg_before
            );
            assert_eq!(std::fs::read(&hp).unwrap(), head_before);
            assert_eq!(std::fs::read(&v.open().paths.db_path).unwrap(), db_before);
            recover_and_check(&rt, &v, "F4: the journaled change is kept");

            // Told to: the snapshot's `/h` (version 2) comes back.
            session_crashes_before_snapshot(&rt, &mut v, 1);
            restore(&rt, &v).expect("restore --discard-journal");
            v.expect.insert(4, v.h_versions[1].clone());
            recover_and_check(&rt, &v, "F4: restored with --discard-journal");
        }

        /// F2 (PoC r8_early_exit_skips_seq_check_and_strands_old_epoch_rows):
        /// rows stranded below the current epoch (the epoch was advanced over
        /// them, as the old "nothing to re-encrypt" exit did) are re-encrypted
        /// by the next rotation, and their old messages deleted.
        #[test]
        fn rotation_moves_rows_stranded_below_the_current_epoch() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let v = rot_volume(&rt);
            let mut r = v.open();
            r.config.increment_epoch().unwrap();
            manager::save_config_resealed(&mut r.config, &r.hierarchy, &r.paths.config_path)
                .unwrap();
            assert_files_exact(&rt, &v, "F2: rows at epoch 0 under current epoch 1");
            let c = rotate_claims(&rt, &v).expect("rotation 1 -> 2");
            let r = v.open();
            let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
            let conn = rusqlite::Connection::open(&r.paths.db_path).unwrap();
            let bs = BlockStore::new(&conn, &schema);
            let (at0, at1, at2) = (
                bs.list_by_epoch(0).unwrap().len(),
                bs.list_by_epoch(1).unwrap().len(),
                bs.list_by_epoch(2).unwrap().len(),
            );
            drop(conn);
            eprintln!(
                "F2: complete={} epoch={} rows at 0/1/2: {at0}/{at1}/{at2}; old messages left {}",
                c.complete,
                r.config.current_epoch,
                old_messages_left(&v)
            );
            assert_eq!(r.config.current_epoch, 2);
            assert_eq!(
                (at0, at1),
                (0, 0),
                "F2: rows stranded below the current epoch"
            );
            assert_eq!(at2, v.pre_rotation_msgs.len());
            assert_eq!(old_messages_left(&v), 0, "F2: stranded rows' messages left");
            assert!(c.complete);
            assert_files_exact(&rt, &v, "F2: after the rotation");
        }

        /// F2, the PoC's own sequence: an unclean session, then the DB is lost,
        /// then `key rotate`. It refuses (the DB must be rebuilt) instead of
        /// advancing the epoch; after the next mount rebuilds (keeping the
        /// journaled change) and a clean unmount, the rotation leaves no row
        /// below the new epoch and no pre-rotation message.
        #[test]
        fn rotate_after_a_crash_and_a_lost_db_refuses_then_rotates_everything() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut v = rot_volume(&rt);
            session_crashes_before_snapshot(&rt, &mut v, 1);
            metadata_snapshot::remove_db_files(&v.open().paths.db_path).unwrap();
            let r = rotate_claims(&rt, &v).map(|_| ());
            assert_refused_as_needing_rebuild("F2 PoC: rotate", r);
            assert_eq!(v.open().config.current_epoch, 0);
            recover_and_check(&rt, &v, "F2 PoC: the next mount");
            clean_unmount(&rt, &v);
            let c = rotate_claims(&rt, &v).expect("rotation after the rebuild");
            let r = v.open();
            let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
            let conn = rusqlite::Connection::open(&r.paths.db_path).unwrap();
            let below = BlockStore::new(&conn, &schema)
                .list_by_epoch(0)
                .unwrap()
                .len();
            drop(conn);
            eprintln!(
                "F2 PoC: rotate complete={} epoch={} rows at epoch 0: {below}; pre-rotation \
                 messages left {}",
                c.complete,
                r.config.current_epoch,
                old_messages_left(&v)
            );
            assert!(c.complete && below == 0 && old_messages_left(&v) == 0);
            assert_files_exact(&rt, &v, "F2 PoC: after the rotation");
        }

        /// A volume whose DB holds only the root (no block rows), published.
        fn empty_volume(rt: &tokio::runtime::Runtime) -> RotVol {
            let dir = tempfile::tempdir().unwrap();
            let created =
                manager::create_volume(Some("rot"), ROT_PASS, dir.path(), 0, 0, 0, None).unwrap();
            let id = created.config.volume_id.to_string();
            let mut result = manager::open_volume(&id, ROT_PASS, dir.path()).unwrap();
            let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
            {
                let conn = rusqlite::Connection::open(&result.paths.db_path).unwrap();
                initialize_database(&conn, &schema).unwrap();
                InodeStore::new(&conn, &schema, &result.hierarchy.meta)
                    .insert(&Inode::root())
                    .unwrap();
            }
            let mock = Arc::new(MockTransport::new());
            rt.block_on(super::super::super::volume::publish_as_new_session(
                &mut result,
                mock.as_ref(),
            ))
            .unwrap();
            RotVol {
                dir,
                id,
                mock,
                expect: BTreeMap::new(),
                pre_rotation_msgs: vec![],
                h_versions: [vec![], vec![]],
            }
        }

        /// F2: the journal-entries refusal comes before the "nothing to
        /// re-encrypt" exit: with entries past the snapshot and no block row,
        /// rotation still refuses and the epoch does not move.
        #[test]
        fn rotate_refuses_journal_entries_even_with_nothing_to_re_encrypt() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let v = empty_volume(&rt);
            let r = v.open();
            let hp = super::super::super::volume::journal_head_path(&r);
            let mut head = JournalHead::load(&hp, &r.hierarchy.integrity)
                .unwrap()
                .unwrap();
            head.seq = 1;
            head.store_atomic(&hp, &r.hierarchy.integrity).unwrap();
            // The DB holds that journal position (as after a journaled change).
            {
                let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
                let c = local_db::open_existing(&r.paths.db_path).unwrap();
                local_db::set_session_seq(&c, &schema, 1).unwrap();
            }
            let err = rotate_claims(&rt, &v).map(|_| ()).expect_err("must refuse");
            eprintln!("F2 seq>0 with no blocks: {err:#}");
            assert!(format!("{err:#}").contains("unmount it cleanly"), "{err:#}");
            assert_eq!(v.open().config.current_epoch, 0);
        }

        fn deletion_failures(v: &RotVol) -> std::path::PathBuf {
            v.open().paths.base_dir.join("deletion_failures.json")
        }

        /// F3 (PoC r8_already_completed_branch_false_complete), first half: the
        /// old messages cannot be deleted AND the list of them cannot be
        /// recorded. That is an error that keeps the marker (the only record
        /// left) and does not advance the epoch; the re-run deletes them.
        #[test]
        fn an_unrecordable_deletion_failure_keeps_the_marker_and_is_an_error() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let v = rot_volume(&rt);
            let df = deletion_failures(&v);
            std::fs::create_dir(&df).unwrap(); // stands in for EIO/ENOSPC
            v.mock.set_fail_deletes(true);
            let r = rotate_claims(&rt, &v).map(|c| (c.complete, c.reported));
            eprintln!("F3a first run: {r:?}");
            let err = r.expect_err("an unrecorded deletion failure is an error");
            assert!(format!("{err:#}").contains("could not record"), "{err:#}");
            assert!(
                RotationMarker::path(&v.open().paths.base_dir).exists(),
                "marker kept"
            );
            assert_eq!(v.open().config.current_epoch, 0, "epoch not advanced");
            assert_files_exact(&rt, &v, "F3a after the failed run");
            std::fs::remove_dir(&df).unwrap();
            v.mock.set_fail_deletes(false);
            let c = rotate_claims(&rt, &v).expect("the re-run");
            let left = old_messages_left(&v);
            eprintln!(
                "F3a re-run: complete={} reported={} left={left}",
                c.complete, c.reported
            );
            assert!(
                c.complete && left == 0,
                "F3a: re-run left {left} old messages"
            );
            assert_rotation_complete(&v, "F3a after the re-run");
            assert_files_exact(&rt, &v, "F3a after the re-run");
        }

        /// F3, second half: the marker of a run that advanced the epoch names
        /// old messages that were not deleted, and nothing else records them
        /// (an earlier build lost the list). The re-run records them and
        /// reports them; if it cannot record them it keeps the marker and fails.
        #[test]
        fn already_completed_rotation_reports_and_records_its_leftovers() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            for record_fails in [false, true] {
                let when = format!("F3b (recording fails: {record_fails})");
                let v = rot_volume(&rt);
                v.mock.set_fail_deletes(true);
                let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rotate_with(&rt, &v, &|s| {
                        if s == RotateStep::EpochAdvanced {
                            panic!("simulated kill at {s:?}");
                        }
                    })
                }));
                assert!(killed.is_err(), "{when}: never reached EpochAdvanced");
                v.mock.set_fail_deletes(false);
                let df = deletion_failures(&v);
                std::fs::remove_file(&df).unwrap(); // the older build's lost list
                let marker = RotationMarker::path(&v.open().paths.base_dir);
                assert!(marker.exists());
                if record_fails {
                    std::fs::create_dir(&df).unwrap();
                    let err = rotate_claims(&rt, &v).map(|_| ()).expect_err("must fail");
                    eprintln!("{when}: {err:#}");
                    assert!(marker.exists(), "{when}: marker dropped");
                    std::fs::remove_dir(&df).unwrap();
                }
                let c = rotate_claims(&rt, &v).expect("the re-run");
                let left = old_messages_left(&v);
                eprintln!(
                    "{when}: re-run complete={} reported={} left={left}",
                    c.complete, c.reported
                );
                assert!(
                    !c.complete,
                    "{when}: FALSE complete with {left} old messages left"
                );
                assert!(c.reported >= left, "{when}: under-reported");
                let recorded: DeletionFailures =
                    serde_json::from_slice(&std::fs::read(&df).unwrap()).unwrap();
                for id in &v.pre_rotation_msgs {
                    assert!(recorded.pending.contains(id), "{when}: {id} not recorded");
                }
                assert!(!marker.exists(), "{when}: marker left after recording");
            }
        }

        /// The fallback that looks old messages up in the base snapshot accepts
        /// only the snapshot the HEAD (or volume.json) names, at its version,
        /// with a recorded hash.
        #[test]
        fn base_snapshot_lookup_refuses_an_unbound_snapshot() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let v = rot_volume(&rt);
            let r = v.open();
            let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
            let hp = super::super::super::volume::journal_head_path(&r);
            let lookup = |r: &manager::OpenVolumeResult| {
                rt.block_on(old_rows_in_base_snapshot(r, v.mock.as_ref(), 1, &schema))
            };
            assert_eq!(lookup(&r).unwrap().len(), v.pre_rotation_msgs.len());

            // The HEAD names the right blob but another version.
            let good = std::fs::read(&hp).unwrap();
            let mut head = JournalHead::load(&hp, &r.hierarchy.integrity)
                .unwrap()
                .unwrap();
            head.base_snapshot_version += 1;
            head.store_atomic(&hp, &r.hierarchy.integrity).unwrap();
            let e = lookup(&r).expect_err("HEAD version mismatch");
            eprintln!("fallback, HEAD version mismatch: {e:#}");
            std::fs::write(&hp, &good).unwrap();

            // No HEAD, and volume.json records no hash for its snapshot.
            std::fs::remove_file(&hp).unwrap();
            let mut nohash = v.open();
            nohash.config.metadata_snapshot_hash = None;
            let e = lookup(&nohash).expect_err("no recorded hash");
            eprintln!("fallback, no recorded hash: {e:#}");

            // No HEAD, hash recorded, but volume.json is at another version.
            let mut other = v.open();
            other.config.metadata_version += 1;
            let e = lookup(&other).expect_err("config version mismatch");
            eprintln!("fallback, config version mismatch: {e:#}");
        }

        fn base_snapshot_copies(v: &RotVol) -> Vec<String> {
            std::fs::read_dir(v.open().paths.base_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(".rotation-base-snapshot"))
                .collect()
        }

        fn plant_base_snapshot_copies(v: &RotVol) {
            let base = v.open().paths.base_dir;
            for n in [
                ".rotation-base-snapshot.db",
                ".rotation-base-snapshot.db-wal",
                ".rotation-base-snapshot.4242.db",
                ".rotation-base-snapshot.4242.db-journal",
            ] {
                std::fs::write(base.join(n), b"stale").unwrap();
            }
        }

        /// The plaintext copy of the base snapshot the fallback reads is never
        /// left in the volume directory: not by a successful rotation, not by a
        /// failed one, and stale copies (also an older build's pid-named ones)
        /// are removed at the start.
        #[test]
        fn base_snapshot_copy_is_never_left_behind() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            // Success without the fallback.
            let v = rot_volume(&rt);
            plant_base_snapshot_copies(&v);
            rotate_claims(&rt, &v).unwrap();
            assert_eq!(base_snapshot_copies(&v), Vec::<String>::new(), "plain run");

            // With the fallback: a lost marker after rows were moved.
            for fail in [false, true] {
                let v = rot_volume(&rt);
                let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rotate_with(&rt, &v, &|s| {
                        if s == RotateStep::RowUpdated(2) {
                            panic!("simulated kill at {s:?}");
                        }
                    })
                }));
                assert!(killed.is_err());
                std::fs::remove_file(RotationMarker::path(&v.open().paths.base_dir)).unwrap();
                plant_base_snapshot_copies(&v);
                if fail {
                    let r = v.open();
                    let head = JournalHead::load(
                        &super::super::super::volume::journal_head_path(&r),
                        &r.hierarchy.integrity,
                    )
                    .unwrap()
                    .unwrap();
                    v.mock.put_raw(head.base_snapshot_msg_id, vec![0x5A; 100]);
                    let e = rotate_claims(&rt, &v)
                        .map(|_| ())
                        .expect_err("bad snapshot");
                    eprintln!("fallback with a substituted snapshot: {e:#}");
                } else {
                    rotate_claims(&rt, &v).unwrap();
                }
                assert_eq!(
                    base_snapshot_copies(&v),
                    Vec::<String>::new(),
                    "fallback run (failing: {fail})"
                );
            }
        }

        // ── (d) a DB that is not the volume's current one is never published:
        //    it carries no lineage stamp (or another), so the mount rebuilds ───

        use crate::commands::volume::{publish_snapshot_and_compact, PublishOf};

        /// Replace the volume's DB with what an older build's `history` or `key
        /// rotate` created after the real one was lost (schema only), optionally
        /// with a root directory (what a FUSE mount's `init` adds).
        fn replace_with_empty_db(v: &RotVol, with_root: bool) {
            let r = v.open();
            metadata_snapshot::remove_db_files(&r.paths.db_path).unwrap();
            let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
            let c = rusqlite::Connection::open(&r.paths.db_path).unwrap();
            initialize_database(&c, &schema).unwrap();
            if with_root {
                InodeStore::new(&c, &schema, &r.hierarchy.meta)
                    .insert(&Inode::root())
                    .unwrap();
            }
        }

        struct Published {
            config: Vec<u8>,
            head: Vec<u8>,
            messages: usize,
        }

        fn published_state(v: &RotVol) -> Published {
            let r = v.open();
            Published {
                config: std::fs::read(&r.paths.config_path).unwrap(),
                head: std::fs::read(super::super::super::volume::journal_head_path(&r)).unwrap(),
                messages: v.mock.message_count(),
            }
        }

        fn assert_nothing_published(v: &RotVol, before: &Published, when: &str) {
            let now = published_state(v);
            assert_eq!(
                now.messages, before.messages,
                "{when}: something was uploaded"
            );
            assert!(now.config == before.config, "{when}: volume.json changed");
            assert!(now.head == before.head, "{when}: journal.head changed");
        }

        /// An empty DB (schema only, or root only) put in place of the
        /// volume's carries no lineage stamp, so it is not the volume's current
        /// database: `history` refuses it, the mount rebuilds every file from
        /// the snapshot, and the unmount publishes them. It is never published.
        #[test]
        fn an_empty_db_in_place_of_the_volumes_is_rebuilt_never_published() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            for with_root in [false, true] {
                let when = format!("(d) empty DB, root: {with_root}");
                let mut v = rot_volume(&rt);
                replace_with_empty_db(&v, with_root);
                let state = super::super::super::volume::local_db_state(&v.open()).unwrap();
                eprintln!("{when}: {state:?}");
                assert!(
                    matches!(&state, teagarden_store::local_db::LocalDb::NeedsRebuild(_)),
                    "{when}: {state:?}"
                );
                let before = published_state(&v);
                assert_refused_as_needing_rebuild(&format!("{when}: history"), history(&rt, &v));
                assert_nothing_published(&v, &before, &when);
                assert_whole_after_next_mount(&rt, &mut v, &when);
            }
        }

        /// An empty volume (published empty, root only) mounts through the
        /// real path (`prepare_session`) without a rebuild, and its unmount
        /// publishes it again, every time. (Deleting every file through a real
        /// mount: `real_fuse::a_session_that_deletes_every_file_publishes_the_\
        /// empty_volume`, and across a crash `real_fuse::deleting_everything_\
        /// then_crashing_is_published_by_the_next_mount`.)
        #[test]
        fn an_empty_volume_is_published_over_its_empty_snapshot() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let v = empty_volume(&rt);
            for session in 1..=3 {
                let (mut r, s) = r9::prep(&rt, &v);
                let s = s.unwrap_or_else(|e| panic!("mount {session}: {e:#}"));
                assert!(!s.rebuilt, "mount {session} rebuilt the volume's own DB");
                drop(s.conn);
                rt.block_on(publish_snapshot_and_compact(
                    &mut r,
                    v.mock.as_ref(),
                    PublishOf::Session(s.db),
                ))
                .unwrap_or_else(|e| panic!("unmount {session}: {e:#}"));
                assert_eq!(latest_snapshot_entries(&v), 0);
            }
        }

        // ── round 9: the regression tests of the round-8 review (RV1..RV10) ─────
        mod r9 {
            use super::*;

            thread_local! {
                /// The checkpoints of the session a test's mount preparation
                /// ([`prep`]) started on this thread: the real-FUSE tests'
                /// `with_mount` hands them to its filesystem, as `volume
                /// mount` hands those of `prepare_session` to its own.
                pub(super) static SESSION_CHECKPOINTS: std::cell::RefCell<
                    Option<Arc<local_db::SessionCheckpoints>>,
                > = const { std::cell::RefCell::new(None) };
            }
            use crate::commands::volume::{
                journal_init_phase, local_db_state, prepare_session, PreparedSession,
            };
            use teagarden_store::local_db::LocalDb;

            /// A volume just created: no DB, nothing published.
            pub(super) fn new_volume() -> RotVol {
                let dir = tempfile::tempdir().unwrap();
                let created =
                    manager::create_volume(Some("rot"), ROT_PASS, dir.path(), 0, 0, 0, None)
                        .unwrap();
                RotVol {
                    id: created.config.volume_id.to_string(),
                    dir,
                    mock: Arc::new(MockTransport::new()),
                    expect: BTreeMap::new(),
                    pre_rotation_msgs: vec![],
                    h_versions: [vec![], vec![]],
                }
            }

            /// What a mount does before FUSE starts (`prepare_session`), on a
            /// freshly opened volume.
            pub(super) fn prep(
                rt: &tokio::runtime::Runtime,
                v: &RotVol,
            ) -> (manager::OpenVolumeResult, Result<PreparedSession>) {
                let mut r = v.open();
                let s = rt.block_on(prepare_session(&mut r, v.mock.as_ref()));
                // A test mount (`real_fuse::with_mount`) of this session hands
                // the session's checkpoints to its filesystem, as `volume
                // mount` does.
                if let Ok(s) = &s {
                    SESSION_CHECKPOINTS.with(|c| *c.borrow_mut() = Some(s.db.checkpoints.clone()));
                }
                (r, s)
            }

            /// The tree in the snapshot volume.json names.
            pub(super) fn latest_snapshot_summary(v: &RotVol) -> local_db::TreeSummary {
                let r = v.open();
                let id = r
                    .config
                    .metadata_snapshot_id
                    .expect("a snapshot is recorded");
                let blob = v
                    .mock
                    .get_raw(id)
                    .expect("the recorded snapshot is on the channel");
                let (_, db) =
                    metadata_snapshot::decrypt_snapshot(&r.hierarchy.data, &blob).unwrap();
                let p = v.dir.path().join(format!("check-{id}.db"));
                std::fs::write(&p, db).unwrap();
                let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
                let t = local_db::tree_summary_of(&p, &schema).unwrap();
                metadata_snapshot::remove_db_files(&p).unwrap();
                t
            }

            /// RV7 (N3): a volume's first mount publishes its base snapshot and
            /// then stops before FUSE starts (a bad mountpoint, a kill). The DB
            /// and that snapshot already hold the root directory, so the volume
            /// is usable as it is: `history` works, and every later mount uses
            /// the DB without a rebuild.
            #[test]
            fn a_first_mount_that_stops_after_its_base_snapshot_leaves_a_usable_volume() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = new_volume();
                {
                    let (mut r, s) = prep(&rt, &v);
                    let mut s = s.expect("the first mount's preparation");
                    drop(s.conn);
                    rt.block_on(journal_init_phase(&mut r, v.mock.as_ref(), &mut s.db))
                        .expect("the base snapshot publish");
                } // the mount process dies here, before FUSE `init`
                let state = local_db_state(&v.open()).unwrap();
                eprintln!("RV7: state after the failed first mount = {state:?}");
                assert_eq!(state, LocalDb::Usable);
                assert!(
                    latest_snapshot_summary(&v).has_root,
                    "RV7: the base snapshot has no root directory"
                );
                history(&rt, &v).expect("RV7: history on the volume");
                for attempt in 1..=2 {
                    let (mut r, s) = prep(&rt, &v);
                    let s = s.unwrap_or_else(|e| panic!("RV7: mount {attempt}: {e:#}"));
                    drop(s.conn);
                    rt.block_on(publish_snapshot_and_compact(
                        &mut r,
                        v.mock.as_ref(),
                        PublishOf::Session(s.db),
                    ))
                    .unwrap_or_else(|e| panic!("RV7: unmount {attempt}: {e:#}"));
                    assert_eq!(local_db_state(&v.open()).unwrap(), LocalDb::Usable);
                }
            }

            /// The first mount's base snapshot publish fails (killed, Telegram
            /// down) after it reserved a snapshot version. The volume has then
            /// reserved a version but published nothing; the next mount resumes
            /// it: it publishes the base snapshot, and its unmount publishes.
            #[test]
            fn a_first_mount_whose_base_snapshot_publish_fails_mounts_again() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = new_volume();
                v.mock.set_metadata_budget(Some(0));
                {
                    let (mut r, s) = prep(&rt, &v);
                    let mut s = s.expect("the first mount's preparation");
                    drop(s.conn);
                    let e = rt
                        .block_on(journal_init_phase(&mut r, v.mock.as_ref(), &mut s.db))
                        .expect_err("the base snapshot publish must fail");
                    eprintln!("first mount, failed base snapshot: {e:#}");
                }
                let cfg = v.open().config;
                assert!(cfg.metadata_version_reserved > 0, "a version was reserved");
                assert_eq!(cfg.metadata_version, 0);
                assert!(cfg.metadata_snapshot_id.is_none());
                v.mock.set_metadata_budget(None);
                let (mut r, s) = prep(&rt, &v);
                let mut s = s.unwrap_or_else(|e| panic!("the next mount: {e:#}"));
                drop(s.conn);
                rt.block_on(journal_init_phase(&mut r, v.mock.as_ref(), &mut s.db))
                    .expect("the next mount's base snapshot");
                rt.block_on(publish_snapshot_and_compact(
                    &mut r,
                    v.mock.as_ref(),
                    PublishOf::Session(s.db),
                ))
                .expect("its unmount");
                assert!(latest_snapshot_summary(&v).has_root);
                history(&rt, &v).expect("history");
            }

            /// RV5 (B4): whether a volume has published metadata rests on
            /// fields the configuration MAC covers. With `metadata_snapshot_id`
            /// (outside the MAC) removed from volume.json, journal.head deleted
            /// and the DB gone, the volume is still published: a mount fails
            /// closed and creates no DB, and `history` refuses.
            #[test]
            fn published_state_rests_on_the_mac_covered_snapshot_version() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = rot_volume(&rt);
                let r = v.open();
                assert!(r.config.metadata_version > 0);
                let mut j: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&r.paths.config_path).unwrap()).unwrap();
                j["metadata_snapshot_id"] = serde_json::Value::Null;
                std::fs::write(&r.paths.config_path, serde_json::to_vec_pretty(&j).unwrap())
                    .unwrap();
                std::fs::remove_file(super::super::super::super::volume::journal_head_path(&r))
                    .unwrap();
                metadata_snapshot::remove_db_files(&r.paths.db_path).unwrap();
                let r = v.open(); // still opens: the MAC does not cover the id
                assert!(r.config.metadata_snapshot_id.is_none());
                let state = local_db_state(&r).unwrap();
                eprintln!("RV5: local_db_state = {state:?}");
                assert!(
                    matches!(&state, LocalDb::NeedsRebuild(w) if w.contains("missing")),
                    "RV5: {state:?}"
                );
                let (_, s) = prep(&rt, &v);
                let e = s.err().expect("RV5: the mount must fail closed");
                eprintln!("RV5: mount: {e:#}");
                assert!(!r.paths.db_path.exists(), "RV5: the mount created a DB");
                assert_refused_as_needing_rebuild("RV5 history", history(&rt, &v));
                assert!(!r.paths.db_path.exists(), "RV5: history created a DB");
            }

            fn head_seq(v: &RotVol) -> u64 {
                let r = v.open();
                JournalHead::load(
                    &super::super::super::super::volume::journal_head_path(&r),
                    &r.hierarchy.integrity,
                )
                .unwrap()
                .map(|h| h.seq)
                .expect("a journal HEAD")
            }

            /// RV10 (B1): the local DB is damaged (overwritten with garbage, or
            /// cut short to two pages: what a crash or a full disk can leave),
            /// after an unclean session (HEAD seq > 0) and after a clean one
            /// (seq 0). `history`, `key rotate` and `volume delete` (no topic)
            /// refuse with the rebuild instruction and leave the file as it is;
            /// the next mount rebuilds it from Telegram (no `--discard-journal`,
            /// the journaled change kept): every file byte-exact, and its
            /// unmount publishes every file.
            #[test]
            fn a_damaged_db_is_rebuilt_by_the_next_mount() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                for crashed in [true, false] {
                    for how in ["not a database", "truncated to 2 pages"] {
                        let when = format!("RV10 [{how}, unclean session: {crashed}]");
                        let mut v = rot_volume(&rt);
                        if crashed {
                            session_crashes_before_snapshot(&rt, &mut v, 1);
                        }
                        let db = v.open().paths.db_path.clone();
                        if how == "not a database" {
                            metadata_snapshot::remove_db_files(&db).unwrap();
                            std::fs::write(&db, vec![0x5Au8; 8192]).unwrap();
                        } else {
                            if crashed {
                                // A whole, checkpointed file holding the change.
                                mount_recover(&rt, &v);
                            }
                            let whole = std::fs::read(&db).unwrap();
                            assert!(whole.len() > 8192, "{when}: the DB is only {}", whole.len());
                            metadata_snapshot::remove_db_files(&db).unwrap();
                            std::fs::write(&db, &whole[..8192]).unwrap();
                        }
                        let damaged = std::fs::read(&db).unwrap();
                        let seq = head_seq(&v);
                        assert_eq!(seq > 0, crashed, "{when}: HEAD seq {seq}");
                        let state = local_db_state(&v.open());
                        eprintln!("{when}: HEAD seq {seq}; local_db_state = {state:?}");
                        assert!(
                            matches!(&state, Ok(LocalDb::NeedsRebuild(w)) if w.contains("unreadable")),
                            "{when}: {state:?}"
                        );
                        assert_refused_as_needing_rebuild(
                            &format!("{when}: history"),
                            history(&rt, &v),
                        );
                        assert_refused_as_needing_rebuild(
                            &format!("{when}: rotate"),
                            rotate_claims(&rt, &v).map(|_| ()),
                        );
                        let pass = pass_file(&v);
                        let del = rt.block_on(crate::commands::volume::delete_in(
                            v.dir.path(),
                            &v.id,
                            true,
                            Some(&pass),
                            None,
                            false,
                            Box::new(|_| {
                                Box::pin(async { anyhow::bail!("Telegram must not be contacted") })
                            }),
                        ));
                        let del = format!("{:#}", del.expect_err("delete must refuse"));
                        eprintln!("{when}: delete: {del}");
                        assert!(del.contains("rebuilt from Telegram"), "{when}: {del}");
                        assert!(
                            std::fs::read(&db).unwrap() == damaged,
                            "{when}: a refusing command changed the DB file"
                        );
                        assert_whole_after_next_mount(&rt, &mut v, &when);
                    }
                }
            }

            /// RV2 (B3): a DB holding no files that is not the volume's (root
            /// only, as an older build's mount left it after the real one was
            /// lost), to which the session then adds ONE file. The session never
            /// starts from it: it carries no lineage stamp, so the mount's
            /// preparation rebuilds the volume's DB first, and what is published
            /// is every file plus the new one.
            #[test]
            fn one_new_file_on_a_db_that_is_not_the_volumes_is_never_published() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = rot_volume(&rt);
                replace_with_empty_db(&v, true);
                let (mut r, s) = prep(&rt, &v);
                let s = s.expect("RV2: the mount's preparation");
                assert!(
                    s.rebuilt,
                    "RV2: the mount used the DB that is not the volume's"
                );
                let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
                assert_eq!(
                    local_db::tree_summary(&s.conn, &schema).unwrap().entries,
                    v.expect.len() as u64
                );
                InodeStore::new(&s.conn, &schema, &r.hierarchy.meta)
                    .insert(&Inode::new_file(9, 1, "new".into(), 0o644, 1000, 1000))
                    .unwrap();
                // The session's own checkpoint.
                s.db.checkpoints.checkpoint(&s.conn).unwrap();
                drop(s.conn);
                rt.block_on(publish_snapshot_and_compact(
                    &mut r,
                    v.mock.as_ref(),
                    PublishOf::Session(s.db),
                ))
                .expect("RV2: unmount");
                assert_eq!(latest_snapshot_entries(&v), v.expect.len() as u64 + 1);
                mount_recover(&rt, &v);
                assert_files_exact(&rt, &v, "RV2: after the next mount");
            }

            /// B5 (claim 7): `history`/`diff` read the DB under the volume's
            /// OWN lock, held shared for as long as they read, through a
            /// connection that cannot write. While it is open no writer can take
            /// the volume (another reader can); its connection rejects a write;
            /// once it is dropped the volume is free. And with a writer holding
            /// the volume, `history` and `diff` refuse.
            #[test]
            fn history_reads_under_the_volumes_shared_lock_through_a_read_only_connection() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = rot_volume(&rt);
                let base = v.open().paths.base_dir.clone();
                let db_before = std::fs::read(v.open().paths.db_path).unwrap();
                let pass = pass_file(&v);
                let opened = crate::commands::history::open_for_read(
                    v.dir.path(),
                    &v.id,
                    "volume history",
                    Some(&pass),
                    None,
                )
                .expect("open for read");
                assert!(
                    manager::VolumeLock::acquire_exclusive(&base).is_err(),
                    "B5: a writer could take the volume while history reads it"
                );
                drop(manager::VolumeLock::acquire_shared(&base).expect("B5: a second reader"));
                let w = opened
                    .conn
                    .execute_batch("CREATE TABLE b5_probe(x INTEGER)");
                eprintln!("B5: a write through the history connection -> {w:?}");
                assert!(w.is_err(), "B5: the history connection accepted a write");
                drop(opened);
                drop(
                    manager::VolumeLock::acquire_exclusive(&base)
                        .expect("B5: the volume is free once history is done"),
                );
                let w = manager::VolumeLock::acquire_exclusive(&base).unwrap();
                for (what, r) in [("history", history(&rt, &v)), ("diff", diff(&rt, &v))] {
                    let msg = format!("{:#}", r.expect_err("must refuse beside a writer"));
                    eprintln!("B5: {what} beside a writer: {msg}");
                    assert!(msg.contains("in use"), "B5 {what}: {msg}");
                }
                drop(w);
                assert!(
                    std::fs::read(v.open().paths.db_path).unwrap() == db_before,
                    "B5: history changed the DB file"
                );
            }

            /// N4: `history` unlocks the volume (the password prompt) BEFORE it
            /// takes the lock, so an idle prompt holds no lock (it would block a
            /// mount and stall `volume unmount`'s wait). Here a mount holds the
            /// volume and the password is wrong: the answer is about the
            /// password, not "in use".
            #[test]
            fn history_unlocks_before_it_takes_the_volume_lock() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = rot_volume(&rt);
                let base = v.open().paths.base_dir.clone();
                let w = manager::VolumeLock::acquire_exclusive(&base).unwrap();
                let bad = v.dir.path().join("wrong-pass");
                std::fs::write(&bad, b"not-the-volume-pass").unwrap();
                let e = rt
                    .block_on(crate::commands::history::run_in(
                        v.dir.path(),
                        &v.id,
                        Some(bad.to_str().unwrap()),
                        None,
                    ))
                    .expect_err("a wrong password");
                let msg = format!("{e:#}");
                eprintln!("N4: history with a wrong password while mounted: {msg}");
                assert!(
                    !msg.contains("in use"),
                    "N4: locked before unlocking: {msg}"
                );
                drop(w);
            }

            /// RV3 (N1): a rotation killed after it advanced the epoch, and then
            /// the DB must be rebuilt (a rebuild marker, a lost DB) or the
            /// journal has entries. The re-run refuses like any rotation would,
            /// keeps its marker and the epoch, and never reports "complete".
            /// Once the cause is gone (a mount rebuilt the DB), the re-run
            /// finishes.
            #[test]
            fn a_rerun_after_the_epoch_advanced_refuses_before_its_early_exit() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                for how in ["rebuild marker", "db lost", "journal entries"] {
                    let when = format!("RV3 [{how}]");
                    let v = rot_volume(&rt);
                    let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rotate_with(&rt, &v, &|s| {
                            if s == RotateStep::EpochAdvanced {
                                panic!("simulated kill at {s:?}");
                            }
                        })
                    }));
                    assert!(killed.is_err());
                    let base = v.open().paths.base_dir.clone();
                    let epoch = v.open().config.current_epoch;
                    let hp = super::super::super::super::volume::journal_head_path(&v.open());
                    let saved_head = std::fs::read(&hp).unwrap();
                    match how {
                        "rebuild marker" => {
                            teagarden_core::volume::rebuild_marker::mark(&base, "review").unwrap()
                        }
                        "db lost" => {
                            metadata_snapshot::remove_db_files(&v.open().paths.db_path).unwrap()
                        }
                        _ => {
                            let r = v.open();
                            let mut head = JournalHead::load(&hp, &r.hierarchy.integrity)
                                .unwrap()
                                .unwrap();
                            head.seq = 1;
                            head.store_atomic(&hp, &r.hierarchy.integrity).unwrap();
                        }
                    }
                    let r = rotate_claims(&rt, &v);
                    eprintln!(
                        "{when}: rotate -> {:?}",
                        r.as_ref().map(|c| c.complete).map_err(|e| format!("{e:#}"))
                    );
                    let msg = format!("{:#}", r.err().expect("RV3: the re-run must refuse"));
                    assert!(msg.contains("Nothing was changed"), "{when}: {msg}");
                    assert!(
                        RotationMarker::path(&base).exists(),
                        "{when}: marker dropped"
                    );
                    assert_eq!(v.open().config.current_epoch, epoch, "{when}: epoch moved");
                    if how == "journal entries" {
                        std::fs::write(&hp, &saved_head).unwrap();
                    } else {
                        mount_recover(&rt, &v);
                        clean_unmount(&rt, &v);
                    }
                    rotate_claims(&rt, &v).unwrap_or_else(|e| panic!("{when}: re-run: {e:#}"));
                    assert!(!RotationMarker::path(&base).exists(), "{when}: marker left");
                    assert_files_exact(&rt, &v, &format!("{when}: after the re-run"));
                }
            }

            /// RV4 (N8): what `history` (a read-only opener of the WAL-mode DB)
            /// leaves in the volume directory. SQLite creates the `-wal` and
            /// `-shm` sidecars for a read-only connection (every read-only
            /// opener does: the fixture's own start-of-session summary left
            /// them); they are harmless: besides them only the lock file
            /// appears, the main file is byte-identical, and the `-wal` holds no
            /// frames (a read-only connection cannot write any).
            #[test]
            fn history_leaves_only_empty_wal_sidecars() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = rot_volume(&rt);
                let r = v.open();
                let ls = || -> Vec<String> {
                    let mut n: Vec<String> = std::fs::read_dir(&r.paths.base_dir)
                        .unwrap()
                        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                        .collect();
                    n.sort();
                    n
                };
                let wal = r.paths.base_dir.join("metadata.db-wal");
                let shm = r.paths.base_dir.join("metadata.db-shm");
                if wal.exists() {
                    // Left by the fixture's read-only summary: empty, so
                    // removing it loses nothing.
                    assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
                    std::fs::remove_file(&wal).unwrap();
                }
                let _ = std::fs::remove_file(&shm);
                let _ = std::fs::remove_file(r.paths.base_dir.join("volume.lock"));
                let before = ls();
                let db_before = std::fs::read(&r.paths.db_path).unwrap();
                history(&rt, &v).expect("history");
                diff(&rt, &v).ok(); // ids "00"/"01" may not resolve; it still opens the DB
                let after = ls();
                eprintln!("RV4: before {before:?}");
                eprintln!("RV4: after  {after:?}");
                let added: Vec<&String> = after.iter().filter(|n| !before.contains(n)).collect();
                for n in &added {
                    assert!(
                        *n == "metadata.db-wal" || *n == "metadata.db-shm" || *n == "volume.lock",
                        "RV4: history left {n}"
                    );
                }
                assert!(
                    before.iter().all(|n| after.contains(n)),
                    "RV4: a file went away"
                );
                assert!(
                    std::fs::read(&r.paths.db_path).unwrap() == db_before,
                    "RV4: the main DB file changed"
                );
                if wal.exists() {
                    assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0, "RV4: WAL frames");
                }
            }

            /// RV6 (N2): a rebuild marker on a volume that never published
            /// anything (nothing to rebuild from; a real marker is only ever
            /// written for a published volume) does not brick it: `history`
            /// ignores it and leaves it, the next mount removes it and mounts.
            #[test]
            fn a_rebuild_marker_on_a_never_published_volume_is_removed_by_the_next_mount() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = new_volume();
                let base = v.open().paths.base_dir.clone();
                teagarden_core::volume::rebuild_marker::mark(&base, "forged").unwrap();
                history(&rt, &v).expect("RV6: history on a never-published volume");
                assert!(teagarden_core::volume::rebuild_marker::path(&base).exists());
                let (mut r, s) = prep(&rt, &v);
                let mut s = s.unwrap_or_else(|e| panic!("RV6: mount: {e:#}"));
                assert!(
                    !teagarden_core::volume::rebuild_marker::path(&base).exists(),
                    "RV6: the mount left the marker"
                );
                drop(s.conn);
                rt.block_on(journal_init_phase(&mut r, v.mock.as_ref(), &mut s.db))
                    .expect("RV6: base snapshot");
                rt.block_on(publish_snapshot_and_compact(
                    &mut r,
                    v.mock.as_ref(),
                    PublishOf::Session(s.db),
                ))
                .expect("RV6: unmount");
                let (_, s) = prep(&rt, &v);
                s.unwrap_or_else(|e| panic!("RV6: the mount after: {e:#}"));
            }
        }

        #[cfg(target_os = "linux")]
        mod real_fuse {
            use super::r9::{latest_snapshot_summary, prep};
            use super::*;
            use std::path::Path;

            fn fuse_available() -> bool {
                let which = |bin: &str| {
                    std::env::var_os("PATH")
                        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
                        .unwrap_or(false)
                };
                Path::new("/dev/fuse").exists() && (which("fusermount3") || which("fusermount"))
            }

            use super::r9::SESSION_CHECKPOINTS;

            fn force_unmount(mp: &Path) {
                for bin in ["fusermount3", "fusermount"] {
                    let _ = std::process::Command::new(bin).arg("-u").arg(mp).output();
                }
            }

            /// Mount the volume's DB through a real FUSE session, journaled
            /// against the mock channel exactly as `volume mount` wires it, run
            /// `body` on the mountpoint, unmount. `None` when FUSE is missing
            /// and not required.
            fn with_mount(
                rt: &tokio::runtime::Runtime,
                v: &RotVol,
                body: impl FnOnce(&Path),
            ) -> Option<()> {
                with_mount_opts(
                    rt,
                    v,
                    &[fuser::MountOption::FSName("teagarden-r8-test".into())],
                    body,
                )
            }

            /// [`with_mount`] with these mount options (`teagarden:<id>` as the
            /// FSName makes it a mount of the volume to `volume` commands).
            fn with_mount_opts(
                rt: &tokio::runtime::Runtime,
                v: &RotVol,
                opts: &[fuser::MountOption],
                body: impl FnOnce(&Path),
            ) -> Option<()> {
                if !fuse_available() {
                    assert!(
                        std::env::var_os("TEAGARDEN_REQUIRE_FUSE").is_none(),
                        "TEAGARDEN_REQUIRE_FUSE set but /dev/fuse or fusermount is missing"
                    );
                    eprintln!("SKIP: FUSE not available");
                    return None;
                }
                let r = v.open();
                let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
                let conn = local_db::open_existing(&r.paths.db_path).unwrap();
                initialize_database(&conn, &schema).unwrap();
                let hp = super::super::super::super::volume::journal_head_path(&r);
                let head = JournalHead::load(&hp, &r.hierarchy.integrity)
                    .unwrap()
                    .unwrap();
                let fs = CryptFs::new(
                    conn,
                    schema,
                    r.hierarchy.meta.clone(),
                    r.hierarchy.data.clone(),
                    unsafe { libc::getuid() },
                    unsafe { libc::getgid() },
                )
                .with_epoch(r.config.current_epoch)
                .with_block_keys(r.hierarchy.block_id.clone(), r.hierarchy.filename.clone())
                .with_manifest_key(r.hierarchy.manifest.clone())
                .with_block_integrity(r.config.require_block_integrity)
                .with_block_v2_from_epoch(r.config.block_v2_from_epoch)
                .with_transport(v.transport())
                .with_runtime(rt.handle().clone())
                .with_upload_queue()
                .with_journal(r.hierarchy.integrity.clone(), hp, head);
                let fs = match SESSION_CHECKPOINTS.with(|c| c.borrow().clone()) {
                    Some(ck) if ck.db_path() == r.paths.db_path => {
                        fs.with_session_checkpoints(ck).unwrap()
                    }
                    _ => fs,
                };
                let mp_dir = tempfile::tempdir().unwrap();
                let mp = mp_dir.path().to_path_buf();
                let session = match fuser::spawn_mount2(fs, &mp, opts) {
                    Ok(s) => s,
                    Err(e) => {
                        assert!(
                            std::env::var_os("TEAGARDEN_REQUIRE_FUSE").is_none(),
                            "TEAGARDEN_REQUIRE_FUSE set but the mount failed: {e}"
                        );
                        eprintln!("SKIP: spawn_mount2 failed: {e}");
                        return None;
                    }
                };
                std::thread::sleep(std::time::Duration::from_millis(300));
                let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&mp)));
                drop(session);
                force_unmount(&mp);
                if let Err(p) = ran {
                    std::panic::resume_unwind(p);
                }
                Some(())
            }

            /// The fixture's root directory belongs to uid 0 (`Inode::root()`);
            /// a real volume's root belongs to the user whose mount created it.
            fn own_root(v: &RotVol) {
                let r = v.open();
                let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
                let c = local_db::open_existing(&r.paths.db_path).unwrap();
                // Like the session's own writes, this one stays in the WAL
                // until the session checkpoints it.
                local_db::own_checkpoints(&c).unwrap();
                let s = InodeStore::new(&c, &schema, &r.hierarchy.meta);
                let mut root = s.get(1).unwrap().unwrap();
                root.uid = unsafe { libc::getuid() };
                root.gid = unsafe { libc::getgid() };
                s.update(&root).unwrap();
            }

            fn names(mp: &Path) -> Vec<String> {
                let mut n: Vec<String> = std::fs::read_dir(mp)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                n.sort();
                n
            }

            /// Through a real mount the user deletes every file; the unmount
            /// publish must carry that empty volume (the session started with
            /// files), and the next mount recovers it empty.
            #[test]
            fn a_session_that_deletes_every_file_publishes_the_empty_volume() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = rot_volume(&rt);
                own_root(&v);
                clean_unmount(&rt, &v);
                let mounted = with_mount(&rt, &v, |mp| {
                    assert_eq!(names(mp), ["a", "b", "h"]);
                    for f in ["a", "b", "h"] {
                        std::fs::remove_file(mp.join(f)).unwrap();
                    }
                    assert!(names(mp).is_empty());
                });
                if mounted.is_none() {
                    return;
                }
                let mut r = v.open();
                rt.block_on(crate::commands::volume::publish_as_new_session(
                    &mut r,
                    v.mock.as_ref(),
                ))
                .expect("the user's emptying is published");
                let n = latest_snapshot_entries(&v);
                eprintln!("(d) real mount, every file deleted: published snapshot entries {n}");
                assert_eq!(n, 0);
            }

            /// An empty DB that is not the volume's, mounted through the real
            /// path: schema only (what an older build's `history` or `key
            /// rotate` left) or root only (what an older build's mount left).
            /// Neither carries the lineage stamp, so the mount's preparation
            /// rebuilds the volume's DB: the mount shows every file, and its
            /// unmount publishes every file.
            #[test]
            fn an_empty_db_mounted_by_mistake_is_never_published() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                for with_root in [false, true] {
                    let when = format!("(d) empty DB, root: {with_root}");
                    let mut v = rot_volume(&rt);
                    replace_with_empty_db(&v, with_root);
                    own_root_if_any(&v);
                    let (mut r, s) = prep(&rt, &v);
                    let s = s.unwrap_or_else(|e| panic!("{when}: mount: {e:#}"));
                    assert!(s.rebuilt, "{when}: the mount used the empty DB");
                    drop(s.conn);
                    own_root(&v);
                    let mut seen = vec![];
                    let mounted = with_mount(&rt, &v, |mp| seen = names(mp));
                    if mounted.is_none() {
                        return;
                    }
                    eprintln!("{when}: the mount shows {seen:?}");
                    assert_eq!(seen, ["a", "b", "h"], "{when}");
                    rt.block_on(publish_snapshot_and_compact(
                        &mut r,
                        v.mock.as_ref(),
                        PublishOf::Session(s.db),
                    ))
                    .unwrap_or_else(|e| panic!("{when}: publish: {e:#}"));
                    assert_eq!(latest_snapshot_entries(&v), v.expect.len() as u64);
                    assert_whole_after_next_mount(&rt, &mut v, &when);
                }
            }

            // ── round 10: the lineage stamp (nv scenarios) ──
            mod r10 {
                use super::super::r9::latest_snapshot_summary;
                use super::*;
                include!("key_tests_lineage.rs");
                include!("key_tests_r11.rs");
                include!("key_tests_r12.rs");
                include!("key_tests_r13.rs");
                include!("key_tests_final.rs");
            }

            /// [`own_root`] when the DB has a root.
            fn own_root_if_any(v: &RotVol) {
                let r = v.open();
                let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
                let c = local_db::open_existing(&r.paths.db_path).unwrap();
                if InodeStore::new(&c, &schema, &r.hierarchy.meta)
                    .get(1)
                    .unwrap()
                    .is_some()
                {
                    drop(c);
                    own_root(v);
                }
            }

            // ── round 9 (needs FUSE) ────────────────────────────────────────

            fn head_seq_of(v: &RotVol) -> u64 {
                let r = v.open();
                JournalHead::load(
                    &super::super::super::super::volume::journal_head_path(&r),
                    &r.hierarchy.integrity,
                )
                .unwrap()
                .map(|h| h.seq)
                .expect("a journal HEAD")
            }

            /// RV1 (B2): through a real mount the user deletes every file, and
            /// the session dies before its unmount publish (kill, power loss,
            /// Telegram down). The next mount replays the deletions from the
            /// journal, so it STARTS empty, from a DB rebuilt from the volume's
            /// snapshot and journal. Its unmount publishes the empty volume
            /// (HEAD back to seq 0), and so does every mount after it.
            #[test]
            fn deleting_everything_then_crashing_is_published_by_the_next_mount() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let v = rot_volume(&rt);
                own_root(&v);
                clean_unmount(&rt, &v);
                let mounted = with_mount(&rt, &v, |mp| {
                    for f in ["a", "b", "h"] {
                        std::fs::remove_file(mp.join(f)).unwrap();
                    }
                    assert!(names(mp).is_empty());
                });
                if mounted.is_none() {
                    return;
                }
                let seq = head_seq_of(&v);
                eprintln!("RV1: session 1 ended without its publish; HEAD seq {seq}");
                assert!(seq >= 3, "RV1: the deletions were journaled");
                for session in 2..=3 {
                    let (mut r, s) = prep(&rt, &v);
                    let s = s.unwrap_or_else(|e| panic!("RV1: mount {session}: {e:#}"));
                    drop(s.conn);
                    let res = rt.block_on(publish_snapshot_and_compact(
                        &mut r,
                        v.mock.as_ref(),
                        PublishOf::Session(s.db),
                    ));
                    eprintln!(
                        "RV1: session {session} unmount publish -> {:?}",
                        res.as_ref().map_err(|e| format!("{e:#}"))
                    );
                    res.unwrap_or_else(|e| panic!("RV1: unmount {session}: {e:#}"));
                    assert_eq!(
                        head_seq_of(&v),
                        0,
                        "RV1: session {session}: HEAD not compacted"
                    );
                    assert_eq!(latest_snapshot_entries(&v), 0);
                    assert!(latest_snapshot_summary(&v).has_root);
                    assert!(
                        teagarden_core::volume::rebuild_marker::load(&v.open().paths.base_dir)
                            .unwrap()
                            .is_none(),
                        "RV1: session {session} marked the DB"
                    );
                }
            }

            /// N7: journal entries that do not apply to their base snapshot.
            /// The lineage stamp keeps every mount from serving a DB that is not
            /// the volume's (see `an_empty_db_mounted_by_mistake_is_never_\
            /// published`), so this needs a DB made to look like the volume's
            /// current one: here a root-only DB into which the HEAD's lineage
            /// was copied (what a local writer can do; the stamp guards against
            /// accidents, not against that). A file written through a real
            /// mount is journaled against it, and the session dies before its
            /// publish. Those entries cannot be replayed onto the volume's
            /// snapshot, so the next mount fails, and says why and what to run:
            /// `volume restore <volume> --discard-journal`. It changes nothing;
            /// that restore brings every file back.
            #[test]
            fn a_journal_that_cannot_be_replayed_names_restore_discard_journal() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut v = rot_volume(&rt);
                let lineage = {
                    let r = v.open();
                    JournalHead::load(
                        &super::super::super::super::volume::journal_head_path(&r),
                        &r.hierarchy.integrity,
                    )
                    .unwrap()
                    .unwrap()
                    .lineage
                    .unwrap()
                };
                replace_with_empty_db(&v, true);
                own_root(&v);
                {
                    let r = v.open();
                    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
                    let stamp = local_db::DbStamp {
                        volume_id: v.id.clone(),
                        lineage,
                    };
                    local_db::stamp_db_file(&r.paths.db_path, &schema, Some(&stamp)).unwrap();
                }
                let (_, s) = prep(&rt, &v);
                let s = s.expect("the mount's preparation");
                assert!(
                    !s.rebuilt,
                    "N7: the forged stamp was not taken as the volume's"
                );
                drop(s.conn);
                let mounted = with_mount(&rt, &v, |mp| {
                    std::fs::write(mp.join("new"), b"written to the wrong database").unwrap();
                });
                if mounted.is_none() {
                    return;
                }
                assert!(head_seq_of(&v) > 0, "N7: the write was journaled");
                // The session dies here, before its unmount publish.
                let before = published_state(&v);
                let db_before = std::fs::read(v.open().paths.db_path).unwrap();
                let (_, next) = prep(&rt, &v);
                let msg = format!("{:#}", next.err().expect("N7: the next mount must fail"));
                eprintln!("N7: the next mount: {msg}");
                assert!(
                    msg.contains("teagarden volume restore rot --discard-journal"),
                    "N7: {msg}"
                );
                assert!(msg.contains("cannot be replayed"), "N7: {msg}");
                assert_nothing_published(&v, &before, "N7: the failed mount");
                assert!(std::fs::read(v.open().paths.db_path).unwrap() == db_before);
                restore(&rt, &v).expect("N7: restore --discard-journal");
                assert_whole_after_next_mount(&rt, &mut v, "N7: after the restore");
            }
        }
    }
}

#[cfg(test)]
tokio::task_local! {
    pub(crate) static TEST_PORTABLE_TRANSPORT: Arc<teagarden_telegram::mock::MockTransport>;
}
