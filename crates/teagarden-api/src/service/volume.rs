use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;

use teagarden_core::error::CoreError;
use teagarden_core::volume::manager;

use crate::error::{ApiError, Result};
use crate::types::{CreateVolumeResponse, VolumeSummary};

/// Tracks a mounted volume's runtime state.
struct MountedVolume {
    _volume_id: String,
    _display_name: String,
    mount_point: PathBuf,
}

/// Volume management service.
pub struct VolumeService {
    base_dir: PathBuf,
    mounted: Arc<RwLock<HashMap<String, MountedVolume>>>,
}

impl VolumeService {
    /// Create a new volume service with the given base directory.
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            mounted: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new volume.
    ///
    /// `group_id` / `group_access_hash` identify the shared TeaGarden forum supergroup;
    /// `topic_id` is this volume's forum topic within it. All three are created before
    /// this call and are bound into the volume's key hierarchy (the group + topic are
    /// part of the cryptographic identity).
    pub async fn create(
        &self,
        name: Option<&str>,
        password: &str,
        group_id: i64,
        group_access_hash: i64,
        topic_id: i64,
        block_size: Option<u64>,
    ) -> Result<CreateVolumeResponse> {
        if password.len() < 8 {
            return Err(ApiError::InvalidArgument(
                "password must be at least 8 characters".into(),
            ));
        }

        let result = manager::create_volume(
            name,
            password.as_bytes(),
            &self.base_dir,
            group_id,
            group_access_hash,
            topic_id,
            block_size,
        )
        .map_err(|e| ApiError::Crypto(format!("create volume: {e}")))?;

        let volume_id = result.config.volume_id.to_string();
        let display_name = result.config.display_name.clone();

        tracing::info!(volume_id = %volume_id, name = %display_name, "volume created");

        Ok(CreateVolumeResponse {
            volume_id,
            display_name,
        })
    }

    /// Open an existing volume with password.
    pub async fn open(&self, volume_id: &str, password: &str) -> Result<()> {
        let _result = manager::open_volume(volume_id, password.as_bytes(), &self.base_dir)
            .map_err(|e| ApiError::Crypto(format!("open volume: {e}")))?;

        tracing::info!(volume_id = %volume_id, "volume opened");
        Ok(())
    }

    /// List all volumes.
    pub async fn list(&self) -> Result<Vec<VolumeSummary>> {
        let configs = manager::list_volumes(&self.base_dir)
            .map_err(|e| ApiError::Storage(format!("list volumes: {e}")))?;

        let mounted = self.mounted.read().await;
        let mut summaries = Vec::new();

        for config in configs {
            let vid = config.volume_id.to_string();
            let is_mounted = mounted.contains_key(&vid);
            let mount_point = mounted
                .get(&vid)
                .map(|m| m.mount_point.display().to_string());

            summaries.push(VolumeSummary {
                volume_id: vid,
                display_name: config.display_name,
                created_at: 0,
                mounted: is_mounted,
                mount_point,
                block_count: 0,
                total_size: 0,
            });
        }

        Ok(summaries)
    }

    /// Delete a volume's local state.
    ///
    /// Takes the volume's exclusive lock (the one a mount, `restore`, `revert`
    /// and `key rotate` hold) for the deletion, and refuses while another
    /// holder has it. A caller that already holds that lock must call
    /// `manager::delete_volume` itself: a second acquisition in the same
    /// process is refused like any other.
    pub async fn delete(&self, volume_id: &str) -> Result<()> {
        let mounted = self.mounted.read().await;
        if mounted.contains_key(volume_id) {
            return Err(ApiError::VolumeIsMounted(volume_id.into()));
        }
        drop(mounted);

        let vol_dir = self.base_dir.join(volume_id);
        let _lock = if vol_dir.is_dir() {
            Some(
                manager::VolumeLock::acquire_exclusive(&vol_dir)
                    .map_err(|e| ApiError::Storage(format!("delete volume: {e}")))?,
            )
        } else {
            None
        };
        manager::delete_volume(volume_id, &self.base_dir).map_err(|e| match &e {
            CoreError::Volume(msg) if msg.contains("volume not found") => {
                ApiError::VolumeNotFound(volume_id.into())
            }
            _ => ApiError::Storage(format!("delete volume: {e}")),
        })?;

        tracing::info!(volume_id = %volume_id, "volume deleted");
        Ok(())
    }

    /// Get the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Check if a volume is mounted.
    pub async fn is_mounted(&self, volume_id: &str) -> bool {
        self.mounted.read().await.contains_key(volume_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn service(dir: &TempDir) -> VolumeService {
        VolumeService::new(dir.path().to_path_buf())
    }

    #[tokio::test]
    async fn create_volume() {
        let dir = TempDir::new().unwrap();
        let svc = service(&dir);
        let resp = svc
            .create(Some("test-vol"), "password123", 0, 0, 0, None)
            .await
            .unwrap();
        assert_eq!(resp.display_name, "test-vol");
        assert!(!resp.volume_id.is_empty());
    }

    #[tokio::test]
    async fn create_short_password_rejected() {
        let dir = TempDir::new().unwrap();
        let svc = service(&dir);
        let result = svc.create(None, "short", 0, 0, 0, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_and_list() {
        let dir = TempDir::new().unwrap();
        let svc = service(&dir);

        let r1 = svc
            .create(Some("vol-a"), "password123", 0, 0, 0, None)
            .await
            .unwrap();
        let r2 = svc
            .create(Some("vol-b"), "password456", 0, 0, 0, None)
            .await
            .unwrap();

        let vols = svc.list().await.unwrap();
        assert_eq!(vols.len(), 2);
        let ids: Vec<&str> = vols.iter().map(|v| v.volume_id.as_str()).collect();
        assert!(ids.contains(&r1.volume_id.as_str()));
        assert!(ids.contains(&r2.volume_id.as_str()));
    }

    #[tokio::test]
    async fn create_and_open() {
        let dir = TempDir::new().unwrap();
        let svc = service(&dir);
        let resp = svc
            .create(Some("open-test"), "password123", 0, 0, 0, None)
            .await
            .unwrap();
        svc.open(&resp.volume_id, "password123").await.unwrap();
    }

    #[tokio::test]
    async fn delete_volume() {
        let dir = TempDir::new().unwrap();
        let svc = service(&dir);
        let resp = svc
            .create(Some("del-test"), "password123", 0, 0, 0, None)
            .await
            .unwrap();

        svc.delete(&resp.volume_id).await.unwrap();

        let vols = svc.list().await.unwrap();
        assert!(vols.is_empty());
    }

    #[tokio::test]
    async fn open_nonexistent() {
        let dir = TempDir::new().unwrap();
        let svc = service(&dir);
        let result = svc.open("nonexistent", "password").await;
        assert!(result.is_err());
    }

    /// `delete` takes the volume's exclusive lock: while a mount or another
    /// command holds it, nothing is deleted.
    #[tokio::test]
    async fn delete_refuses_while_the_volume_lock_is_held() {
        let dir = TempDir::new().unwrap();
        let svc = service(&dir);
        let resp = svc
            .create(Some("locked"), "password123", 0, 0, 0, None)
            .await
            .unwrap();
        let held =
            manager::VolumeLock::acquire_exclusive(&dir.path().join(&resp.volume_id)).unwrap();
        let err = svc.delete(&resp.volume_id).await.unwrap_err();
        assert!(err.to_string().contains("in use"), "{err}");
        assert_eq!(svc.list().await.unwrap().len(), 1, "deleted under the lock");
        drop(held);
        svc.delete(&resp.volume_id).await.unwrap();
        assert!(svc.list().await.unwrap().is_empty());
    }
}
