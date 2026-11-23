//! Exponential-backoff lockout for failed volume-open attempts.
//!
//! State is persisted to `{volume_dir}/auth_lockout.json` so that lockouts
//! survive process restarts.  Both the CLI and the REST API service pick up
//! the lockout automatically through `manager::open_volume`.
//!
//! # Backoff schedule
//!
//! | Failure # | Lockout |
//! |-----------|---------|
//! | 1         | 1 s     |
//! | 2         | 2 s     |
//! | 3         | 4 s     |
//! | 4         | 8 s     |
//! | 5         | 16 s    |
//! | 10        | 512 s   |
//! | ≥ 12      | 3600 s (capped) |
//!
//! A successful open resets the counter to zero.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

/// Minimum lockout on first failure (seconds).
const BASE_LOCKOUT_SECS: u64 = 1;
/// Maximum lockout after many failures (1 hour).
const MAX_LOCKOUT_SECS: u64 = 3600;

/// Persisted on-disk lockout record for a volume.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct LockoutFile {
    /// Number of consecutive wrong-password attempts.
    pub failure_count: u32,
    /// Unix timestamp after which the next attempt is allowed.
    pub locked_until_unix: Option<u64>,
}

/// Per-volume exponential-backoff lockout state.
pub struct LockoutState {
    inner: LockoutFile,
}

impl LockoutState {
    /// Load lockout state from disk.
    ///
    /// A **missing** file is a fresh (never-failed) state. Any other failure —
    /// the file exists but cannot be read, or does not parse — is an `Err`: the
    /// state is unknown, so the open fails closed rather than treating it as
    /// "unlocked" (core-M6). Previously a truncated or unreadable file silently
    /// reset the backoff.
    ///
    /// This only slows guessing through `open_volume`; it does nothing against
    /// an attacker who reads `volume.json` and guesses offline.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    inner: LockoutFile::default(),
                })
            }
            Err(e) => {
                return Err(CoreError::Volume(format!(
                    "cannot read the auth lockout state {}: {e}; refusing to open (fail \
                     closed). If the file is damaged, inspect it and remove it to reset the \
                     backoff",
                    path.display()
                )))
            }
        };
        let inner = serde_json::from_str(&text).map_err(|e| {
            CoreError::Volume(format!(
                "the auth lockout state {} is corrupt ({e}); refusing to open (fail closed). \
                 Inspect it and remove it to reset the backoff",
                path.display()
            ))
        })?;
        Ok(Self { inner })
    }

    /// Returns `Some(remaining_secs)` if the volume is currently locked,
    /// `None` if a new attempt is allowed.
    pub fn check_locked(&self) -> Option<u64> {
        self.check_locked_at(unix_now())
    }

    /// [`check_locked`](Self::check_locked) at a given Unix time (seconds).
    fn check_locked_at(&self, now: u64) -> Option<u64> {
        match self.inner.locked_until_unix {
            Some(until) if until > now => Some(until - now),
            _ => None,
        }
    }

    /// Record a successful open. Resets the failure counter.
    ///
    /// Writes only when there is something to reset, so a clean open does not
    /// rewrite the file every time. A failed write is returned to the caller.
    pub fn record_success(&mut self, path: &Path) -> Result<()> {
        if self.inner.failure_count == 0 && self.inner.locked_until_unix.is_none() {
            return Ok(());
        }
        self.inner.failure_count = 0;
        self.inner.locked_until_unix = None;
        self.save(path)
    }

    /// Record a failed open. Returns the new lockout duration in seconds, or
    /// the error if the new state could not be persisted.
    pub fn record_failure(&mut self, path: &Path) -> Result<u64> {
        self.inner.failure_count = self.inner.failure_count.saturating_add(1);
        let lockout = lockout_duration(self.inner.failure_count);
        self.inner.locked_until_unix = Some(unix_now().saturating_add(lockout));
        self.save(path)?;
        Ok(lockout)
    }

    /// Number of consecutive failures recorded.
    pub fn failure_count(&self) -> u32 {
        self.inner.failure_count
    }

    /// Persist atomically: write a sibling temp file at 0600, fsync it, rename
    /// it over the target, then fsync the directory. A crash leaves either the
    /// old state or the new one, never a torn file (which `load` would now
    /// refuse).
    fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(&self.inner)
            .map_err(|e| CoreError::Serialization(format!("lockout state: {e}")))?;
        // A temp name unique to this save: concurrent savers (two failing opens
        // at once) must never share — and truncate — one temp inode, or a torn
        // file could be renamed into place and the loser's rename would fail.
        let tmp = {
            use rand::RngCore as _;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "auth_lockout.json".into());
            path.with_file_name(format!(
                ".{name}.{}.{:016x}.tmp",
                std::process::id(),
                rand::rngs::OsRng.next_u64()
            ))
        };
        let result = Self::write_then_rename(&json, &tmp, path);
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    fn write_then_rename(json: &[u8], tmp: &Path, path: &Path) -> Result<()> {
        use std::io::Write as _;
        let io = |what: &str, e: std::io::Error| {
            CoreError::Volume(format!("{what} {}: {e}", path.display()))
        };
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(tmp)
                .map_err(|e| io("write auth lockout state (temp)", e))?;
            f.write_all(json)
                .map_err(|e| io("write auth lockout state (temp)", e))?;
            f.sync_all()
                .map_err(|e| io("fsync auth lockout state (temp)", e))?;
        }
        std::fs::rename(tmp, path).map_err(|e| io("replace auth lockout state", e))?;
        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all(); // best effort: the rename itself already landed
            }
        }
        Ok(())
    }
}

/// Compute the lockout duration for the n-th failure: `min(MAX, BASE * 2^(n-1))`.
pub fn lockout_duration(failure_count: u32) -> u64 {
    if failure_count == 0 {
        return 0;
    }
    let shift = (failure_count - 1).min(30);
    BASE_LOCKOUT_SECS
        .checked_shl(shift)
        .unwrap_or(u64::MAX)
        .min(MAX_LOCKOUT_SECS)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn first_failure_gives_1s() {
        assert_eq!(lockout_duration(1), 1);
    }

    #[test]
    fn doubles_per_failure() {
        assert_eq!(lockout_duration(2), 2);
        assert_eq!(lockout_duration(3), 4);
        assert_eq!(lockout_duration(4), 8);
        assert_eq!(lockout_duration(10), 512);
    }

    #[test]
    fn caps_at_one_hour() {
        assert_eq!(lockout_duration(100), 3600);
    }

    #[test]
    fn zero_failures_no_lockout() {
        assert_eq!(lockout_duration(0), 0);
    }

    #[test]
    fn fresh_state_is_not_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("lockout.json");
        let state = LockoutState::load(&path).unwrap();
        assert!(state.check_locked().is_none());
    }

    #[test]
    fn failure_then_check_is_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("lockout.json");
        let mut state = LockoutState::load(&path).unwrap();
        let before = unix_now();
        let secs = state.record_failure(&path).unwrap();
        // The first failure locks for 1 s from the moment it was recorded. Check
        // at that moment rather than "now": with whole-second times a wall-clock
        // check can already fall past the lock (a failure at X.999 s locks until
        // X+1), which made this test fail at random on a loaded machine.
        assert_eq!(secs, 1);
        assert!(state.check_locked_at(before).is_some());
        assert!(state.check_locked_at(before + secs + 1).is_none());
        // And the persisted state says the same.
        let reloaded = LockoutState::load(&path).unwrap();
        assert!(reloaded.check_locked_at(before).is_some());
    }

    #[test]
    fn success_resets_lockout() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("lockout.json");
        let mut state = LockoutState::load(&path).unwrap();
        state.record_failure(&path).unwrap();
        state.record_success(&path).unwrap();
        assert!(state.check_locked().is_none());
        assert_eq!(state.failure_count(), 0);
    }

    /// Two opens failing at the same moment (two processes, or two threads of
    /// the API) both save. With one fixed temp name they truncate and write the
    /// SAME temp inode, can rename a torn file into place (which `load` now
    /// refuses — locking the owner out), and the loser's rename hits ENOENT.
    /// Every save must succeed and every observable file must parse.
    #[test]
    fn concurrent_saves_never_tear_or_fail() {
        let dir = TempDir::new().unwrap();
        let path = std::sync::Arc::new(dir.path().join("auth_lockout.json"));
        let errors = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (path, errors) = (path.clone(), errors.clone());
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        let ok = LockoutState::load(&path)
                            .and_then(|mut s| s.record_failure(&path).map(|_| ()));
                        if ok.is_err() {
                            errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            errors.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "concurrent load/save must never see a torn file or a failed rename"
        );
        LockoutState::load(&path).expect("final state parses");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "auth_lockout.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    /// The on-disk format is unchanged: a file written by the previous
    /// (non-atomic) saver loads, keeps its count, and is still honoured.
    #[test]
    fn previous_format_file_still_loads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("auth_lockout.json");
        let until = unix_now() + 600;
        std::fs::write(
            &path,
            format!("{{\n  \"failure_count\": 3,\n  \"locked_until_unix\": {until}\n}}"),
        )
        .unwrap();
        let state = LockoutState::load(&path).unwrap();
        assert_eq!(state.failure_count(), 3);
        assert!(state.check_locked().is_some());
        std::fs::write(
            &path,
            "{\n  \"failure_count\": 0,\n  \"locked_until_unix\": null\n}",
        )
        .unwrap();
        assert!(LockoutState::load(&path).unwrap().check_locked().is_none());
    }

    #[test]
    fn state_persists_across_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("lockout.json");
        {
            let mut state = LockoutState::load(&path).unwrap();
            state.record_failure(&path).unwrap();
            state.record_failure(&path).unwrap();
        }
        let state2 = LockoutState::load(&path).unwrap();
        assert_eq!(state2.failure_count(), 2);
    }
}
