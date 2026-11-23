use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::Connection;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::error::CoreError;
use teagarden_core::volume::{config::VolumeConfig, manager};
use teagarden_store::local_db::{self, LocalDb};
use teagarden_store::migrations::initialize_database;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::schema::logical_tables;

use crate::error::{ApiError, Result};

/// An open volume session with live database connection and derived keys.
///
/// It holds the volume's exclusive lock for as long as it exists, like a mount
/// does, so no mount, `restore`, `revert` or `key rotate` runs while its
/// connection is live.
///
/// Its writes (see `SharingService`) are plain SQLite transactions, not
/// metadata-journal entries.
///
/// Not auto-derived Debug because `Connection` and `JoinHandle` don't implement it.
pub struct VolumeSession {
    /// Identifier of the open volume.
    pub volume_id: String,
    /// Human-friendly name of the volume.
    pub display_name: String,
    /// Decrypted volume configuration.
    pub config: VolumeConfig,
    /// Live SQLite connection to the volume's metadata database.
    pub conn: Arc<std::sync::Mutex<Connection>>,
    /// Opaque (obfuscated) logical-table schema mapping for the database.
    pub schema: OpaqueSchema,
    /// Key for encrypting/decrypting metadata.
    pub meta_key: SymmetricKey,
    /// Key for encrypting/decrypting block data.
    pub data_key: SymmetricKey,
    /// Schema obfuscation key (for opening a fresh DB connection for FUSE).
    pub schema_key: SymmetricKey,
    /// Block content-addressing key (CABS spec §3).
    pub block_id_key: SymmetricKey,
    /// Block filename derivation key (CABS spec §4).
    pub filename_key: SymmetricKey,
    /// Manifest identity key (DAG history).
    pub manifest_key: SymmetricKey,
    /// Directory containing the volume's on-disk data (volume.json, metadata.db, cache/).
    pub volume_dir: PathBuf,
    /// Handle to the background FUSE mount task, present while mounted.
    pub mount_handle: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// Path the volume is currently mounted at, if any.
    pub mount_point: std::sync::Mutex<Option<PathBuf>>,
    /// The volume's exclusive lock, released when the session is dropped.
    _lock: manager::VolumeLock,
}

impl std::fmt::Debug for VolumeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeSession")
            .field("volume_id", &self.volume_id)
            .field("display_name", &self.display_name)
            .field("is_mounted", &self.is_mounted())
            .finish()
    }
}

impl VolumeSession {
    /// Check if this session's volume is currently mounted.
    pub fn is_mounted(&self) -> bool {
        self.mount_handle
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    }

    /// Get the current mount point, if mounted.
    pub fn mount_point(&self) -> Option<PathBuf> {
        self.mount_point.lock().unwrap().clone()
    }
}

/// Manages open volume sessions.
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<VolumeSession>>>>,
    base_dir: PathBuf,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            base_dir,
        }
    }

    /// Open a volume session by decrypting with the given password.
    ///
    /// Follows the rules of every opener of a volume's metadata DB: the volume
    /// lock is taken (exclusive, before volume.json is read, held by the
    /// session), and the DB is opened only if it exists and does not have to
    /// be rebuilt from Telegram (`teagarden_store::local_db`). A missing DB is
    /// never created: a session is not a create or recovery path, and for a
    /// volume that published metadata an empty DB would replace its files.
    pub async fn open(&self, volume_id: &str, password: &str) -> Result<Arc<VolumeSession>> {
        // Check if already open
        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(volume_id) {
                return Err(ApiError::SessionAlreadyOpen(volume_id.to_string()));
            }
        }

        // The lock first, before anything reads volume.json.
        let vol_dir = self.base_dir.join(volume_id);
        if !vol_dir.is_dir() {
            return Err(ApiError::VolumeNotFound(volume_id.to_string()));
        }
        let lock = manager::VolumeLock::acquire_exclusive(&vol_dir)
            .map_err(|e| ApiError::Storage(format!("open session: {e}")))?;

        // Open the volume (CPU-bound key derivation)
        let vid = volume_id.to_string();
        let pwd = password.to_string();
        let base = self.base_dir.clone();
        let vid_for_err = vid.clone();

        let result =
            tokio::task::spawn_blocking(move || manager::open_volume(&vid, pwd.as_bytes(), &base))
                .await
                .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))?
                .map_err(|e| match &e {
                    CoreError::Volume(msg) if msg.contains("volume not found") => {
                        ApiError::VolumeNotFound(vid_for_err.clone())
                    }
                    CoreError::Decryption(_) => ApiError::InvalidArgument("wrong password".into()),
                    CoreError::Locked { retry_after_secs } => ApiError::RateLimited {
                        retry_after_secs: *retry_after_secs,
                    },
                    _ => ApiError::Crypto(format!("open volume: {e}")),
                })?;

        // Open database and initialize schema
        let schema_key_for_store = result.hierarchy.schema.clone();
        let schema_key_for_session = result.hierarchy.schema.clone();
        let meta_key = result.hierarchy.meta.clone();
        let data_key = result.hierarchy.data.clone();
        let block_id_key = result.hierarchy.block_id.clone();
        let filename_key = result.hierarchy.filename.clone();
        let manifest_key = result.hierarchy.manifest.clone();
        let db_path = result.paths.db_path.clone();
        let volume_dir = result.paths.base_dir.clone();

        // The DB is used only when it is the volume's current database: the
        // lineage stamp the journal HEAD records (see `local_db_state`).
        let expected =
            local_db::Expected::of_volume(&result.config, &volume_dir, &result.hierarchy.integrity)
                .map_err(|e| ApiError::Storage(format!("check metadata database: {e}")))?;
        let base_for_state = volume_dir.clone();
        let conn = tokio::task::spawn_blocking(move || {
            let schema = OpaqueSchema::new(schema_key_for_store, &logical_tables());
            match local_db::local_db_state(&base_for_state, &db_path, &schema, &expected)
                .map_err(|e| ApiError::Storage(format!("check metadata database: {e}")))?
            {
                LocalDb::Usable => {}
                LocalDb::Unusable(why) => {
                    return Err(ApiError::Storage(format!(
                        "the local metadata database cannot be used (mount the volume once; \
                         it has published nothing, and the mount creates its database): {why}"
                    )))
                }
                LocalDb::Fresh => {
                    return Err(ApiError::Storage(
                        "the volume has no local metadata database yet; its first mount \
                         creates it"
                            .into(),
                    ))
                }
                LocalDb::NeedsRebuild(why) => {
                    return Err(ApiError::Storage(format!(
                        "the local metadata database must be rebuilt from Telegram first \
                         (mount the volume once): {why}"
                    )))
                }
            }
            let conn = local_db::open_existing(&db_path)
                .map_err(|e| ApiError::Storage(format!("open db: {e}")))?;
            initialize_database(&conn, &schema)
                .map_err(|e| ApiError::Storage(format!("init db: {e}")))?;
            Ok::<_, ApiError>((conn, schema))
        })
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))??;

        let session = Arc::new(VolumeSession {
            volume_id: volume_id.to_string(),
            display_name: result.config.display_name.clone(),
            config: result.config,
            conn: Arc::new(std::sync::Mutex::new(conn.0)),
            schema: conn.1,
            meta_key,
            data_key,
            schema_key: schema_key_for_session,
            block_id_key,
            filename_key,
            manifest_key,
            volume_dir,
            mount_handle: std::sync::Mutex::new(None),
            mount_point: std::sync::Mutex::new(None),
            _lock: lock,
        });

        self.sessions
            .write()
            .await
            .insert(volume_id.to_string(), Arc::clone(&session));

        tracing::info!(volume_id = %volume_id, "session opened");
        Ok(session)
    }

    /// Close a volume session, unmounting if needed.
    pub async fn close(&self, volume_id: &str) -> Result<()> {
        let session = self
            .sessions
            .write()
            .await
            .remove(volume_id)
            .ok_or_else(|| ApiError::SessionNotOpen(volume_id.to_string()))?;

        // If mounted, abort the mount handle
        let handle = session.mount_handle.lock().unwrap().take();
        if let Some(h) = handle {
            h.abort();
            tracing::info!(volume_id = %volume_id, "mount task aborted");
        }

        tracing::info!(volume_id = %volume_id, "session closed");
        Ok(())
    }

    /// Get an open session by volume ID.
    pub async fn get(&self, volume_id: &str) -> Result<Arc<VolumeSession>> {
        self.sessions
            .read()
            .await
            .get(volume_id)
            .cloned()
            .ok_or_else(|| ApiError::SessionNotOpen(volume_id.to_string()))
    }

    /// List all open session volume IDs.
    pub async fn list_open(&self) -> Vec<String> {
        self.sessions.read().await.keys().cloned().collect()
    }

    /// Check if a volume has an open session.
    pub async fn is_open(&self, volume_id: &str) -> bool {
        self.sessions.read().await.contains_key(volume_id)
    }

    /// Get the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_manager(dir: &TempDir) -> SessionManager {
        SessionManager::new(dir.path().to_path_buf())
    }

    fn create_test_volume(dir: &Path) -> (String, String) {
        let result =
            manager::create_volume(Some("test-vol"), b"password123", dir, 0, 0, 0, None).unwrap();
        (result.config.volume_id.to_string(), "password123".into())
    }

    /// Give the volume the metadata DB its first mount would create (schema
    /// and root directory).
    pub(crate) fn seed_db(dir: &Path, vid: &str, pwd: &str) {
        let r = manager::open_volume(vid, pwd.as_bytes(), dir).unwrap();
        let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
        let conn = Connection::open(&r.paths.db_path).unwrap();
        initialize_database(&conn, &schema).unwrap();
        teagarden_store::inode_store::InodeStore::new(&conn, &schema, &r.hierarchy.meta)
            .insert(&teagarden_core::metadata::inode::Inode::root())
            .unwrap();
    }

    /// [`create_test_volume`] with its metadata DB in place.
    fn create_seeded_volume(dir: &Path) -> (String, String) {
        let (vid, pwd) = create_test_volume(dir);
        seed_db(dir, &vid, &pwd);
        (vid, pwd)
    }

    #[tokio::test]
    async fn open_and_get_session() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let (vid, pwd) = create_seeded_volume(dir.path());

        let session = mgr.open(&vid, &pwd).await.unwrap();
        assert_eq!(session.volume_id, vid);
        assert_eq!(session.display_name, "test-vol");
        assert!(!session.is_mounted());

        let got = mgr.get(&vid).await.unwrap();
        assert_eq!(got.volume_id, vid);
    }

    #[tokio::test]
    async fn open_twice_errors() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let (vid, pwd) = create_seeded_volume(dir.path());

        mgr.open(&vid, &pwd).await.unwrap();
        let err = mgr.open(&vid, &pwd).await.unwrap_err();
        assert!(matches!(err, ApiError::SessionAlreadyOpen(_)));
    }

    /// Service-level replacement for the removed HTTP test
    /// `open_wrong_password_returns_error`: a wrong password must not open a
    /// session, and must surface as a caller error rather than a crypto fault.
    #[tokio::test]
    async fn open_wrong_password_rejected() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let (vid, _pwd) = create_seeded_volume(dir.path());

        let err = mgr
            .open(&vid, "definitely-wrong-password-12345")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiError::InvalidArgument(_)),
            "expected InvalidArgument for a wrong password, got: {err:?}"
        );
        assert!(mgr.list_open().await.is_empty());
    }

    #[tokio::test]
    async fn close_session() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let (vid, pwd) = create_seeded_volume(dir.path());

        mgr.open(&vid, &pwd).await.unwrap();
        assert!(mgr.is_open(&vid).await);

        mgr.close(&vid).await.unwrap();
        assert!(!mgr.is_open(&vid).await);
    }

    #[tokio::test]
    async fn close_nonexistent_errors() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);

        let err = mgr.close("nonexistent").await.unwrap_err();
        assert!(matches!(err, ApiError::SessionNotOpen(_)));
    }

    #[tokio::test]
    async fn get_nonexistent_errors() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);

        let err = mgr.get("nonexistent").await.unwrap_err();
        assert!(matches!(err, ApiError::SessionNotOpen(_)));
    }

    #[tokio::test]
    async fn list_open_sessions() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);

        assert!(mgr.list_open().await.is_empty());

        let (vid, pwd) = create_seeded_volume(dir.path());
        mgr.open(&vid, &pwd).await.unwrap();

        let open = mgr.list_open().await;
        assert_eq!(open.len(), 1);
        assert_eq!(open[0], vid);
    }

    #[tokio::test]
    async fn open_produces_session_with_keys() {
        // Note: open_volume derives keys from password without validation;
        // wrong password produces wrong keys, detected only at decrypt time.
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let (vid, pwd) = create_seeded_volume(dir.path());

        let session = mgr.open(&vid, &pwd).await.unwrap();
        // Verify the session has valid keys (non-zero)
        assert_ne!(session.meta_key.as_bytes(), &[0u8; 32]);
        assert_ne!(session.data_key.as_bytes(), &[0u8; 32]);
    }

    #[tokio::test]
    async fn open_nonexistent_volume() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);

        let err = mgr.open("nonexistent", "password").await.unwrap_err();
        assert!(matches!(err, ApiError::VolumeNotFound(_)));
    }

    #[tokio::test]
    async fn reopen_after_close() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let (vid, pwd) = create_seeded_volume(dir.path());

        mgr.open(&vid, &pwd).await.unwrap();
        mgr.close(&vid).await.unwrap();

        // Should be able to reopen
        let session = mgr.open(&vid, &pwd).await.unwrap();
        assert_eq!(session.volume_id, vid);
    }

    /// B4: a volume whose MAC-covered snapshot version says it published
    /// metadata is published even when `metadata_snapshot_id` (outside the
    /// MAC) and journal.head are gone: its missing DB must be rebuilt, never
    /// taken for the DB of a new volume.
    #[tokio::test]
    async fn a_published_volume_without_a_db_is_never_taken_for_a_new_one() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let (vid, pwd) = create_test_volume(dir.path());
        let mut r = manager::open_volume(&vid, pwd.as_bytes(), dir.path()).unwrap();
        r.config.metadata_version = 3;
        manager::save_config_resealed(&mut r.config, &r.hierarchy, &r.paths.config_path).unwrap();
        let err = mgr.open(&vid, &pwd).await.unwrap_err();
        assert!(err.to_string().contains("rebuilt"), "{err}");
        assert!(
            !r.paths.db_path.exists(),
            "opening a session created a metadata DB"
        );
    }

    /// A session uses a published volume's DB only when it carries the
    /// lineage stamp the journal HEAD records: an unstamped DB (an earlier
    /// build's, or a foreign one) and an older stamp are refused as needing
    /// the rebuild a mount does; the current stamp opens.
    #[tokio::test]
    async fn a_session_opens_only_the_db_the_heads_lineage_names() {
        use teagarden_core::volume::journal_head::{JournalHead, Lineage};
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let (vid, pwd) = create_seeded_volume(dir.path());
        let mut r = manager::open_volume(&vid, pwd.as_bytes(), dir.path()).unwrap();
        r.config.metadata_version = 3;
        r.config.metadata_snapshot_id = Some(70);
        manager::save_config_resealed(&mut r.config, &r.hierarchy, &r.paths.config_path).unwrap();
        let current = Lineage::new(3);
        JournalHead::at_snapshot(70, 3, [7; 32], current)
            .store_atomic(
                &r.paths.base_dir.join(manager::JOURNAL_HEAD_FILE),
                &r.hierarchy.integrity,
            )
            .unwrap();
        let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
        let stamp = |l: Lineage| local_db::DbStamp {
            volume_id: vid.clone(),
            lineage: l,
        };
        // Unstamped.
        let err = mgr.open(&vid, &pwd).await.unwrap_err();
        assert!(err.to_string().contains("no lineage stamp"), "{err}");
        // An older stamp.
        local_db::stamp_db_file(&r.paths.db_path, &schema, Some(&stamp(Lineage::new(2)))).unwrap();
        let err = mgr.open(&vid, &pwd).await.unwrap_err();
        assert!(
            err.to_string().contains("not the volume's current"),
            "{err}"
        );
        // The current stamp.
        local_db::stamp_db_file(&r.paths.db_path, &schema, Some(&stamp(current))).unwrap();
        mgr.open(&vid, &pwd)
            .await
            .expect("the volume's current DB opens");
    }

    /// A session opens the volume's metadata DB like every other opener: it
    /// holds the volume's exclusive lock for its whole life (so no mount,
    /// `restore` or `key rotate` runs under it), refuses while another holder
    /// has the lock, and never creates a missing DB.
    #[tokio::test]
    async fn session_holds_the_volume_lock_and_never_creates_a_db() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let (vid, pwd) = create_test_volume(dir.path());
        let vol_dir = dir.path().join(&vid);
        let db = vol_dir.join("metadata.db");

        // No DB yet: refused, and none is created.
        let err = mgr.open(&vid, &pwd).await.unwrap_err();
        assert!(err.to_string().contains("metadata database"), "{err}");
        assert!(!db.exists(), "opening a session created a metadata DB");

        seed_db(dir.path(), &vid, &pwd);
        // Another holder has the lock: refused.
        let held = manager::VolumeLock::acquire_exclusive(&vol_dir).unwrap();
        let err = mgr.open(&vid, &pwd).await.unwrap_err();
        assert!(err.to_string().contains("in use"), "{err}");
        drop(held);

        // Open: the session holds the lock until it is closed and dropped.
        let session = mgr.open(&vid, &pwd).await.unwrap();
        assert!(manager::VolumeLock::acquire_exclusive(&vol_dir).is_err());
        mgr.close(&vid).await.unwrap();
        drop(session);
        manager::VolumeLock::acquire_exclusive(&vol_dir).unwrap();
    }
}
