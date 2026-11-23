//! Crash-safe, race-safe file replacement, and private directory creation.

use std::path::{Path, PathBuf};

use crate::error::CoreError;

/// Own the lifetime of an already acquired advisory file lock.
///
/// On Unix, a fork child inherits the open file description even when the file
/// has CLOEXEC. Closing only the parent's descriptor therefore does not release
/// flock until that child execs or closes its copy. Explicitly unlock before
/// closing, and only in the process which acquired this guard: dropping an
/// inherited guard in a child must never unlock the parent's live transaction.
/// Kernel descriptor cleanup remains the fallback after abrupt process exit.
#[derive(Debug)]
pub struct ScopedFileLock {
    file: std::fs::File,
    owner_pid: u32,
}

impl ScopedFileLock {
    /// Take responsibility for releasing `file`'s advisory lock on owner drop.
    /// The caller must acquire the required shared/exclusive lock first. This
    /// does not acquire, wait for, retry, clone or transfer a lock.
    pub fn from_locked_file(file: std::fs::File) -> Self {
        Self {
            file,
            owner_pid: std::process::id(),
        }
    }
}

impl Drop for ScopedFileLock {
    fn drop(&mut self) {
        if self.owner_pid == std::process::id() {
            // Explicit qualification avoids std's newer File locking methods.
            let _ = fs2::FileExt::unlock(&self.file);
        }
    }
}

/// Create `dir` (and any missing parents) for TeaGarden's own state, mode 0700
/// whatever the umask, and tighten `dir` itself to 0700 if it already exists
/// with group or other permissions.
///
/// Only `dir` is tightened. A pre-existing parent (`~/.config`, `~/.local/share`)
/// is not TeaGarden's to change, so call this on the directory TeaGarden owns
/// (the config dir, the volumes dir), not on something above it. Parents this
/// call has to create are made 0700 as well. Not unix: plain `create_dir_all`.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

/// A sibling temp path for `path` that is unique to this call:
/// `.<name>.<pid>.<random>.tmp`. Two writers (threads or processes) never share
/// it, so neither can truncate the other's half-written file or rename it away.
fn unique_tmp_path(path: &Path) -> PathBuf {
    use rand::RngCore as _;
    let name = path
        .file_name()
        .map_or_else(|| "file".into(), |n| n.to_string_lossy().into_owned());
    path.with_file_name(format!(
        ".{name}.{}.{:016x}.tmp",
        std::process::id(),
        rand::rngs::OsRng.next_u64()
    ))
}

/// Atomically replace `path` with `bytes`.
///
/// Writes a uniquely named sibling temp file (created `create_new`, mode 0600),
/// fsyncs it, renames it over `path`, then fsyncs the directory. A reader sees
/// the old file or the new one, never a torn one; a crash leaves one of the two;
/// concurrent writers each rename a whole file, the last rename winning. On any
/// error the temp file is removed.
///
/// `what` names the file in error messages (e.g. `"journal head"`).
pub fn write_file_atomic(path: &Path, bytes: &[u8], what: &str) -> Result<(), CoreError> {
    let tmp = unique_tmp_path(path);
    let result = write_then_rename(path, &tmp, bytes, what);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn write_then_rename(path: &Path, tmp: &Path, bytes: &[u8], what: &str) -> Result<(), CoreError> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    {
        let mut opts = std::fs::OpenOptions::new();
        // create_new: a stale or attacker-planted temp of the same name is an
        // error, never something we write through.
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts
            .open(tmp)
            .map_err(|e| CoreError::Volume(format!("create {what} tmp: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| CoreError::Volume(format!("write {what}: {e}")))?;
        f.sync_all()
            .map_err(|e| CoreError::Volume(format!("fsync {what}: {e}")))?;
    }
    std::fs::rename(tmp, path).map_err(|e| CoreError::Volume(format!("rename {what}: {e}")))?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all(); // best effort: the rename itself already landed
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_missing_private_dir_is_created_0700() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("a").join("b");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn an_existing_dir_is_tightened_but_its_parent_is_not() {
        let t = tempfile::tempdir().unwrap();
        let parent = t.path().join("parent");
        let dir = parent.join("owned");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700, "the dir teagarden owns is tightened");
        assert_eq!(mode(&parent), 0o755, "a parent is not ours to change");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700, "idempotent");
    }
}
