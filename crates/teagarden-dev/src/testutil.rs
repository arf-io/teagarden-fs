//! Test-only helpers: run one test body in a CHILD process so it can lower
//! process-wide limits (`RLIMIT_FSIZE`) without affecting the other tests the
//! harness runs in parallel threads.
//!
//! The child is the same test binary, re-executed with `<test> --exact` and
//! [`CHILD_ENV`] set. The parent asserts that exactly one test ran and passed,
//! so a filter typo can never turn into a silent pass.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Set (to a scratch directory) only inside the child process.
pub(crate) const CHILD_ENV: &str = "TEAGARDEN_DEV_TEST_CHILD_DIR";

/// `Some(dir)` when running as the child of [`run_in_child`].
pub(crate) fn child_dir() -> Option<PathBuf> {
    std::env::var_os(CHILD_ENV).map(PathBuf::from)
}

/// Re-run the test at `test_path` (e.g. `staging::tests::foo`) in a child
/// process with [`CHILD_ENV`] = `dir`. Panics unless the child ran exactly that
/// one test and it passed.
pub(crate) fn run_in_child(test_path: &str, dir: &Path) {
    let mut cmd = Command::new(std::env::current_exe().expect("test binary path"));
    cmd.args([test_path, "--exact", "--nocapture", "--test-threads=1"]);
    cmd.env(CHILD_ENV, dir);
    let out = cmd.output().expect("spawn child test process");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("test result: ok. 1 passed"),
        "child test {test_path} failed ({}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status
    );
}

/// Start the test at `test_path` in a child process (see [`run_in_child`])
/// WITHOUT waiting — for tests that kill the child mid-flight.
pub(crate) fn spawn_child(test_path: &str, dir: &Path) -> std::process::Child {
    let mut cmd = Command::new(std::env::current_exe().expect("test binary path"));
    cmd.args([test_path, "--exact", "--nocapture", "--test-threads=1"]);
    cmd.env(CHILD_ENV, dir);
    cmd.stdout(std::process::Stdio::null());
    cmd.spawn().expect("spawn child test process")
}

fn set_fsize_soft(soft: libc::rlim_t) {
    assert!(
        child_dir().is_some(),
        "RLIMIT_FSIZE is process-wide: only a run_in_child child may change it"
    );
    // SAFETY: plain libc calls on a valid, fully-initialised rlimit struct.
    unsafe {
        // Ignore SIGXFSZ so an over-limit write() fails with EFBIG instead of
        // killing the process — the real short-write / no-space behaviour.
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut rl), 0);
        rl.rlim_cur = soft.min(rl.rlim_max);
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &rl), 0);
    }
}

/// Limit every file this (child) process writes to `bytes` bytes: a write that
/// crosses it is SHORT (the kernel writes up to the limit), the next fails
/// with EFBIG — exactly what a disk filling up mid-`write_all` looks like.
pub(crate) fn limit_file_size(bytes: u64) {
    set_fsize_soft(bytes as libc::rlim_t);
}

/// Lift the soft limit back to the hard limit ("space freed").
pub(crate) fn unlimit_file_size() {
    set_fsize_soft(libc::RLIM_INFINITY);
}
