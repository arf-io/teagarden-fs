//! Monotonic owner-policy observations for one local installation.
use super::*;

/// Called only after owner/MAC authentication. This trusted local observation
/// survives one-shot commands and mount restarts independently of the cache DB.
/// Its own lock prevents concurrent readers from lowering the durable floor.
pub(super) fn observe(config_path: &std::path::Path, header: &HeaderDocument) -> Result<()> {
    let base = config_path
        .parent()
        .context("volume config has no parent directory")?;
    let directory = base.join("observed-owner-policy");
    std::fs::create_dir_all(&directory)
        .context("create persisted header revision floor directory")?;
    let _lock = lock(&directory.join("revision.lock"))?;
    let config: VolumeConfig = serde_json::from_slice(&std::fs::read(config_path)?)
        .context("read local anchors for persisted header revision floor")?;
    anyhow::ensure!(
        header.volume_id == config.volume_id
            && header.group_id == config.telegram_group_id
            && header.topic_id == config.telegram_topic_id
            && header.owner_public_key == config.sdo_owner_public_key,
        "authenticated header does not match this installation's pinned volume"
    );
    let path = directory.join("header.json");
    let previous: Option<HeaderDocument> = match std::fs::read(&path) {
        Ok(bytes) => {
            Some(serde_json::from_slice(&bytes).context("read persisted header revision floor")?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("read persisted header revision floor"),
    };
    let floor = previous
        .as_ref()
        .map_or(config.sdo_header_revision_published, |old| {
            old.revision.max(config.sdo_header_revision_published)
        });
    anyhow::ensure!(header.revision >= floor,
        "refusing replayed owner header revision {} below this installation's persisted header revision floor {}; restore delivery of the current owner header", header.revision, floor);
    if let Some(previous) = &previous {
        header.require_policy_successor(previous).context(
            "refusing owner policy inconsistent with the persisted header revision floor",
        )?;
        if previous == header {
            return Ok(());
        }
    }
    teagarden_core::fsutil::write_file_atomic(
        &path,
        &serde_json::to_vec(header)?,
        "persist authenticated header revision floor",
    )?;
    Ok(())
}

fn lock(path: &std::path::Path) -> Result<teagarden_core::fsutil::ScopedFileLock> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .context("open persisted header revision floor lock")?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        loop {
            // SAFETY: an owned, valid descriptor; no await or external operation
            // occurs while this short local read/replace lock is held.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error).context("lock persisted header revision floor");
            }
        }
    }
    Ok(teagarden_core::fsutil::ScopedFileLock::from_locked_file(
        file,
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod fork_regression {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn forked_descriptor_does_not_delay_policy_observation_guard_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revision.lock");
        let held = lock(&path).unwrap();
        let child = super::super::tests::ForkLockChild::retain(None);
        drop(held);
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        // SAFETY: a valid owned descriptor and no pointers. A single nonblocking
        // attempt must succeed while the child is still waiting before exec.
        let result = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(
            result,
            0,
            "the observation lock survived its owner guard: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: release this test's acquired lock before closing its descriptor.
        assert_eq!(unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_UN) }, 0);
        drop(child);
    }
}
