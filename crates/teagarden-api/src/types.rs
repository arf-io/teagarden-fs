use serde::{Deserialize, Serialize};

/// Summary of a volume for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSummary {
    /// Stable identifier of the volume.
    pub volume_id: String,
    /// Human-friendly volume name.
    pub display_name: String,
    /// Volume creation time as a Unix timestamp (seconds).
    ///
    /// Not yet populated: `VolumeService::list` currently emits `0`.
    pub created_at: i64,
    /// Whether the volume currently has a live mount.
    pub mounted: bool,
    /// Filesystem path the volume is mounted at, if mounted.
    pub mount_point: Option<String>,
    /// Number of stored blocks in the volume.
    ///
    /// Not yet populated: `VolumeService::list` currently emits `0`.
    pub block_count: u64,
    /// Total size of the volume's data in bytes.
    ///
    /// Not yet populated: `VolumeService::list` currently emits `0`.
    pub total_size: u64,
}

/// Volume creation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVolumeRequest {
    /// Optional human-friendly name; a default is assigned when omitted.
    pub name: Option<String>,
    /// Password from which the volume's key hierarchy is derived.
    pub password: String,
    /// Optional block size in bytes; the default is used when omitted.
    pub block_size: Option<usize>,
}

/// Volume creation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVolumeResponse {
    /// Identifier assigned to the newly created volume.
    pub volume_id: String,
    /// Human-friendly name of the new volume.
    pub display_name: String,
}

/// Mount request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountRequest {
    /// Volume to mount.
    pub volume_id: String,
    /// Password used to open the volume.
    pub password: String,
    /// Filesystem path to mount the volume at.
    pub mount_point: String,
    /// Whether to mount the volume read-only.
    pub read_only: bool,
}

/// System status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    /// Running server/crate version string.
    pub version: String,
    /// Whether an authenticated Telegram session is active.
    pub telegram_connected: bool,
    /// Number of live FUSE mount handles owned by this API process.
    pub volumes_mounted: usize,
    /// Number of volumes whose keys are held in an open API session.
    pub volumes_open: usize,
    /// Total number of volumes known to the server.
    pub total_volumes: usize,
    /// Aggregate number of cached entries across open sessions.
    ///
    /// Currently always `0` because per-session cache instrumentation is not
    /// yet wired in.
    pub cache_entries: usize,
    /// Aggregate cache size in bytes across open sessions.
    ///
    /// Currently always `0` because per-session cache instrumentation is not
    /// yet wired in.
    pub cache_size_bytes: u64,
    /// Server uptime in seconds.
    pub uptime_secs: u64,
}

/// Telegram transport statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportStatus {
    /// Whether the Telegram transport is currently connected.
    pub connected: bool,
    /// Count of blocks successfully uploaded.
    pub blocks_uploaded: u64,
    /// Count of blocks successfully downloaded.
    pub blocks_downloaded: u64,
    /// Total bytes uploaded.
    pub bytes_uploaded: u64,
    /// Total bytes downloaded.
    pub bytes_downloaded: u64,
    /// Number of upload failures encountered.
    pub upload_errors: u64,
    /// Number of download failures encountered.
    pub download_errors: u64,
}

/// Sharing invite response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteResponse {
    /// Shareable invite code the recipient redeems.
    pub invite_code: String,
    /// Server-side identifier of the invite record.
    pub invite_id: String,
    /// Invite expiry as a Unix timestamp (seconds).
    pub expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_summary_serialization() {
        let summary = VolumeSummary {
            volume_id: "vol-1".into(),
            display_name: "Test Volume".into(),
            created_at: 1000000,
            mounted: false,
            mount_point: None,
            block_count: 42,
            total_size: 1024 * 1024,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let deser: VolumeSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.volume_id, "vol-1");
        assert_eq!(deser.block_count, 42);
    }

    #[test]
    fn system_status_serialization() {
        let status = SystemStatus {
            version: "0.1.0".into(),
            telegram_connected: true,
            volumes_mounted: 2,
            volumes_open: 3,
            total_volumes: 5,
            cache_entries: 100,
            cache_size_bytes: 1024 * 1024 * 50,
            uptime_secs: 3600,
        };
        let json = serde_json::to_string(&status).unwrap();
        let deser: SystemStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.volumes_mounted, 2);
        assert_eq!(deser.volumes_open, 3);
        assert!(deser.telegram_connected);
    }

    #[test]
    fn create_volume_request_deser() {
        let json = r#"{"password":"secret","block_size":524288}"#;
        let req: CreateVolumeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.password, "secret");
        assert_eq!(req.block_size, Some(524288));
        assert!(req.name.is_none());
    }
}
