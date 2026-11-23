//! The "metadata DB must be rebuilt from Telegram" marker.
//!
//! `volume restore` removes the local metadata DB before it installs the
//! restored one. While that is in progress, and after a restore that was killed
//! or failed part way, the local DB is either missing or not yet the state the
//! journal HEAD describes. The marker records that, durably, before the DB is
//! removed, and is removed only after the restored DB is installed:
//!
//! - every command that would read the DB refuses while the marker exists;
//! - a mount (or `revert`) that finds it rebuilds the DB from the channel (the
//!   journal HEAD's base snapshot and journal, or the snapshot `volume.json`
//!   names) and then removes it.
//!
//! A marker that outlives the state it describes costs one more rebuild:
//! rebuilding from the channel produces the same database as the one installed.
//!
//! A snapshot publish that refuses the file at `metadata.db` as not the
//! session's current database (identity, session nonce, journal position,
//! stamp, `PRAGMA quick_check`) also writes it, when `journal.head` can be
//! read, so the next mount rebuilds the database instead of serving the
//! refused file.
//!
//! File: `metadata_rebuild_required.json` in the volume directory. Local status
//! only (a reason and a timestamp); not authenticated. Forged on a volume that
//! has published metadata, it makes the next mount (or `revert`) rebuild the
//! database from Telegram, and the commands that need the database refuse until
//! then (`history`, `diff`, `key rotate`, `delete` of a volume without a topic,
//! an offline mount). The rebuild yields the volume's state on Telegram: the
//! same database for a journaled volume, but for a volume without a journal
//! HEAD that was mounted offline since its last snapshot, the changes made
//! since that snapshot are lost. A journal whose entries do not apply to their
//! base snapshot makes that mount fail until `volume restore
//! --discard-journal`. On a volume without a published snapshot (never
//! published, or its first mount's base snapshot publish failed) the marker is
//! ignored ([`crate::volume::manager::has_published_snapshot`]) and the next
//! mount removes it: a real one is only written for a volume with a published
//! snapshot.

use std::path::{Path, PathBuf};

use crate::error::CoreError;

/// File name of the marker in the volume directory.
pub const REBUILD_MARKER: &str = "metadata_rebuild_required.json";

/// Contents of [`REBUILD_MARKER`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RebuildRequired {
    /// Unix time the marker was written.
    pub written_at_unix: u64,
    /// Why the local DB cannot be used as it is.
    pub reason: String,
}

/// Path of the marker in `base_dir`.
pub fn path(base_dir: &Path) -> PathBuf {
    base_dir.join(REBUILD_MARKER)
}

fn fsync_dir(base_dir: &Path) -> Result<(), CoreError> {
    let dir = std::fs::File::open(base_dir)
        .map_err(|e| CoreError::Volume(format!("open {}: {e}", base_dir.display())))?;
    dir.sync_all()
        .map_err(|e| CoreError::Volume(format!("fsync {}: {e}", base_dir.display())))
}

/// Write the marker (unique temp file, fsync, rename) and fsync the directory,
/// so it is durable before the caller removes or replaces the DB. An error
/// means the marker may not be durable, and the caller must not go on.
pub fn mark(base_dir: &Path, reason: &str) -> Result<(), CoreError> {
    let record = RebuildRequired {
        written_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        reason: reason.to_string(),
    };
    let bytes = serde_json::to_vec_pretty(&record)
        .map_err(|e| CoreError::Serialization(format!("rebuild marker: {e}")))?;
    crate::fsutil::write_file_atomic(&path(base_dir), &bytes, "rebuild marker")?;
    fsync_dir(base_dir)
}

/// `Ok(Some(reason))` while the marker exists. A marker that exists but cannot
/// be parsed still counts (its reason then says so); only a missing file is
/// `Ok(None)`.
pub fn load(base_dir: &Path) -> Result<Option<String>, CoreError> {
    let p = path(base_dir);
    match std::fs::read(&p) {
        Ok(bytes) => Ok(Some(
            match serde_json::from_slice::<RebuildRequired>(&bytes) {
                Ok(r) => r.reason,
                Err(_) => format!("{} is present but unreadable", p.display()),
            },
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CoreError::Volume(format!("read {}: {e}", p.display()))),
    }
}

/// Remove the marker and fsync the directory. A missing marker is not an error.
pub fn clear(base_dir: &Path) -> Result<(), CoreError> {
    match std::fs::remove_file(path(base_dir)) {
        Ok(()) => fsync_dir(base_dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CoreError::Volume(format!(
            "remove {}: {e}",
            path(base_dir).display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_load_clear_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()).unwrap(), None);
        mark(dir.path(), "restore in progress").unwrap();
        assert_eq!(
            load(dir.path()).unwrap().as_deref(),
            Some("restore in progress")
        );
        // No temp file of the atomic writer is left beside it.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec![REBUILD_MARKER.to_string()]);
        clear(dir.path()).unwrap();
        assert_eq!(load(dir.path()).unwrap(), None);
        clear(dir.path()).unwrap(); // idempotent
    }

    #[test]
    fn unreadable_marker_still_counts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(path(dir.path()), b"{ torn").unwrap();
        let reason = load(dir.path()).unwrap().expect("a torn marker is present");
        assert!(reason.contains("unreadable"), "{reason}");
    }

    #[test]
    fn a_failed_mark_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // The rename target is a non-empty directory: the write cannot land.
        std::fs::create_dir(path(dir.path())).unwrap();
        std::fs::write(path(dir.path()).join("x"), b"x").unwrap();
        assert!(mark(dir.path(), "r").is_err());
    }
}
