//! Single-writer guard for a device directory.
//!
//! The engine is single-writer by design, and `open()` is NOT read-only: it
//! trims a torn staging tail before appending (C1), and compaction (H4)
//! rewrites the log. A second process opening a LIVE device (say `dev status`
//! while `dev serve nbd` runs) would trim the log to the length it scanned,
//! truncating entries the live writer appended and acknowledged meanwhile,
//! and the writer would keep appending past the cut. So every
//! [`crate::device::TeaGardenDevice`] holds an exclusive, non-blocking `flock`
//! on its directory for its whole lifetime, and a second opener is refused.
//!
//! The lock is on the directory itself, not on `staging.log` (compaction
//! renames over that path, so a lock on it would stop covering it) and not on
//! an extra file (no new on-disk state). `flock` locks belong to the open
//! file description. Owner drop explicitly unlocks, so pre-exec children cannot
//! extend the guard's lifetime. After abrupt process death the kernel releases
//! it when the last inherited descriptor closes. Two opens in one process
//! conflict exactly as two processes do.
//!
//! Non-Unix platforms get no lock (documented limitation; the block-device
//! export is Linux-only).

use std::path::Path;

use crate::error::{DeviceError, Result};

/// Held for the lifetime of an open device. Dropping it releases the lock.
pub(crate) struct DirLock {
    #[cfg(unix)]
    _dir: teagarden_core::fsutil::ScopedFileLock,
}

impl DirLock {
    /// Take the exclusive lock on `dir`, or fail at once if another opener
    /// holds it.
    pub(crate) fn acquire(dir: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let f = std::fs::File::open(dir)?;
            // SAFETY: flock on a valid, owned directory descriptor. Acquisition
            // stays strictly nonblocking; owner drop explicitly ends the lock.
            let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            let locked = if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            };
            if let Err(e) = locked {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Err(DeviceError::Io(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        format!(
                            "device directory {} is in use by another opener \
                             (is `teagarden dev serve` running?)",
                            dir.display()
                        ),
                    )));
                }
                return Err(e.into());
            }
            Ok(Self {
                _dir: teagarden_core::fsutil::ScopedFileLock::from_locked_file(f),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = dir;
            Ok(Self {})
        }
    }
}

/// An exclusive hold on a device directory by something that is NOT an open
/// device: it takes the same lock a [`crate::device::TeaGardenDevice`] takes, so it
/// excludes every opener (and is refused while one is live), without opening the
/// device — no staging trim, no replay, no transport. `dev delete` uses it to
/// prove nobody is serving the device, and to check the keys against the
/// superblock, before anything is destroyed.
pub struct DeviceDirGuard {
    dir: std::path::PathBuf,
    _lock: DirLock,
}

impl DeviceDirGuard {
    /// Take the exclusive lock on `dir`, or fail at once if a device (or another
    /// guard) holds it.
    pub fn acquire(dir: &Path) -> Result<Self> {
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: DirLock::acquire(dir)?,
        })
    }

    /// Check `keys` against the sealed superblock in the guarded directory. Fails
    /// closed: wrong keys, a forged superblock and a torn one all error.
    pub fn verify_keys(&self, keys: &crate::device::DeviceKeys) -> Result<()> {
        let blob = std::fs::read(self.dir.join("superblock"))?;
        crate::superblock::Superblock::open(&blob, &keys.integrity_key)?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::device::{DeviceConfig, DeviceKeys, TeaGardenDevice};
    use std::sync::Arc;
    use teagarden_core::crypto::keys::SymmetricKey;
    use teagarden_telegram::mock::MockTransport;

    fn keys(seed: u8) -> DeviceKeys {
        DeviceKeys {
            data_key: SymmetricKey::from_bytes([seed; 32]),
            meta_key: SymmetricKey::from_bytes([seed + 1; 32]),
            integrity_key: SymmetricKey::from_bytes([seed + 2; 32]),
        }
    }

    fn new_device(dir: &Path) -> TeaGardenDevice<MockTransport> {
        TeaGardenDevice::create(
            Arc::new(MockTransport::new()),
            keys(1),
            [9u8; 16],
            256,
            dir,
            DeviceConfig::default(),
        )
        .unwrap()
    }

    /// The guard shares the engine's lock: it is refused while a device is open on
    /// the directory, and succeeds once the device is dropped.
    #[test]
    fn guard_is_refused_while_a_device_is_open() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dev = new_device(tmp.path());
        let err = DeviceDirGuard::acquire(tmp.path())
            .err()
            .expect("must be refused");
        assert!(
            err.to_string().contains("in use by another opener"),
            "{err}"
        );
        drop(dev);
        DeviceDirGuard::acquire(tmp.path()).expect("free once the device is dropped");
    }

    /// And the other way round: while a guard is held, no device can open.
    #[test]
    fn guard_excludes_openers() {
        let tmp = tempfile::TempDir::new().unwrap();
        drop(new_device(tmp.path()));
        let guard = DeviceDirGuard::acquire(tmp.path()).unwrap();
        let err = TeaGardenDevice::open(
            Arc::new(MockTransport::new()),
            keys(1),
            tmp.path(),
            DeviceConfig::default(),
        )
        .err()
        .expect("open must be refused");
        assert!(
            err.to_string().contains("in use by another opener"),
            "{err}"
        );
        drop(guard);
    }

    /// The right keys pass; keys derived from a different secret fail closed.
    #[test]
    fn guard_verifies_the_keys_against_the_superblock() {
        let tmp = tempfile::TempDir::new().unwrap();
        drop(new_device(tmp.path()));
        let guard = DeviceDirGuard::acquire(tmp.path()).unwrap();
        guard.verify_keys(&keys(1)).expect("right keys");
        let err = guard.verify_keys(&keys(50)).unwrap_err();
        assert!(err.to_string().contains("superblock MAC mismatch"), "{err}");
    }
}
