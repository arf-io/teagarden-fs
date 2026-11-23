//! The storage-bot entries (`TELEGRAM_BOT_TOKEN_N=`) of the config `.env` file.
//!
//! The mount path reads `TELEGRAM_BOT_TOKEN_1`, `_2`, ... and stops at the first
//! missing index, so every writer here keeps the indices contiguous from 1.
//!
//! Every change is a read-modify-write of the whole file, made safe by:
//! - an exclusive `flock` on a sibling `.env.lock`, so two concurrent `add-bot`
//!   runs cannot both pick the same free index and lose one token;
//! - a uniquely named sibling temp file (mode 0600, `create_new`), fsynced, then
//!   renamed over the target, then the directory fsynced — so a reader (a mount
//!   starting up) sees the old file or the new one, never a torn one, and a crash
//!   leaves one of the two.
//!
//! Tokens are secrets: nothing in this module formats a token into an error or
//! a `Debug` string.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::utils::SecretString;

/// Key prefix the mount path reads (`TELEGRAM_BOT_TOKEN_<N>`).
pub const PREFIX: &str = "TELEGRAM_BOT_TOKEN_";

/// Check that `token` has the shape of a Telegram bot token
/// (`<numeric bot id>:<secret>`), without echoing it.
///
/// The strict character set is also what keeps the `.env` file well formed: a
/// "token" carrying a newline or `=` could otherwise inject arbitrary
/// `KEY=VALUE` lines (e.g. a different `TG_API_HASH`) into the config.
pub fn validate_token(token: &str) -> Result<()> {
    let Some((id, secret)) = token.split_once(':') else {
        anyhow::bail!("the token file does not contain a bot token (expected <bot id>:<secret>)");
    };
    if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!("the bot token's id part (before ':') must be digits only");
    }
    if secret.len() < 20
        || !secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        anyhow::bail!(
            "the bot token's secret part (after ':') must be at least 20 characters of \
             A-Z, a-z, 0-9, '_' or '-'"
        );
    }
    Ok(())
}

/// The public numeric bot id: the part of a token before `:`.
pub fn bot_id(token: &str) -> &str {
    token.split_once(':').map_or("", |(id, _)| id)
}

/// Outcome of [`add_token`].
#[derive(Debug, PartialEq, Eq)]
pub enum Added {
    /// A new `TELEGRAM_BOT_TOKEN_<index>` line was written.
    New { index: usize },
    /// This exact token was already recorded; the file is unchanged.
    AlreadyPresent { index: usize },
    /// The same bot was recorded with a different (e.g. revoked) token; the
    /// line was updated in place.
    Replaced { index: usize },
}

/// A bot-token line parsed out of the env file.
struct TokenLine {
    /// Position of the line in the file.
    line: usize,
    /// The `N` of `TELEGRAM_BOT_TOKEN_N`.
    index: usize,
    /// The recorded token (a secret: never formatted anywhere).
    value: SecretString,
}

fn parse_token_line(line: &str) -> Option<(usize, &str)> {
    let rest = line.trim_start().strip_prefix(PREFIX)?;
    let (n, value) = rest.split_once('=')?;
    let index = n.trim().parse::<usize>().ok()?;
    Some((index, value.trim()))
}

fn token_lines(lines: &[String]) -> Vec<TokenLine> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(line, l)| {
            parse_token_line(l).map(|(index, value)| TokenLine {
                line,
                index,
                value: SecretString::new(value.to_string()),
            })
        })
        .collect()
}

/// Record `token` in the env file at `env_path`, at the smallest unused index.
/// `token` must already have passed [`validate_token`].
pub fn add_token(env_path: &Path, token: &str) -> Result<Added> {
    validate_token(token)?;
    let target = resolve_target(env_path)?;
    let _lock = lock(&target)?;
    let mut lines = read_lines(&target)?;
    let id = bot_id(token);
    let existing = token_lines(&lines);

    if let Some(t) = existing.iter().find(|t| bot_id(&t.value) == id) {
        if t.value.as_str() == token {
            return Ok(Added::AlreadyPresent { index: t.index });
        }
        lines[t.line] = format!("{PREFIX}{}={token}", t.index);
        write_atomic(&target, &lines)?;
        return Ok(Added::Replaced { index: t.index });
    }

    let used: std::collections::BTreeSet<usize> = existing.iter().map(|t| t.index).collect();
    let index = (1..)
        .find(|n| !used.contains(n))
        .expect("an unused index exists");
    lines.push(format!("{PREFIX}{index}={token}"));
    write_atomic(&target, &lines)?;
    Ok(Added::New { index })
}

/// The recorded bots as `(index, numeric bot id)`, in index order. No tokens.
pub fn list_bots(env_path: &Path) -> Result<Vec<(usize, String)>> {
    let lines = read_lines(env_path)?;
    let mut v: Vec<(usize, String)> = token_lines(&lines)
        .into_iter()
        .map(|t| (t.index, bot_id(&t.value).to_string()))
        .collect();
    v.sort();
    Ok(v)
}

/// The recorded token for the bot whose numeric id is `id`, if any.
pub fn find_token(env_path: &Path, id: &str) -> Result<Option<SecretString>> {
    let lines = read_lines(env_path)?;
    Ok(token_lines(&lines)
        .into_iter()
        .find(|t| bot_id(&t.value) == id)
        .map(|t| t.value))
}

/// Remove the bot whose numeric id is `id` and renumber the remaining bot
/// lines `1..=k` in their existing index order (the mount path stops at the
/// first gap). Returns the removed index, or `None` if no such bot is recorded
/// (the file is then unchanged).
pub fn remove_bot(env_path: &Path, id: &str) -> Result<Option<usize>> {
    let target = resolve_target(env_path)?;
    let _lock = lock(&target)?;
    let mut lines = read_lines(&target)?;
    let mut existing = token_lines(&lines);
    let Some(pos) = existing.iter().position(|t| bot_id(&t.value) == id) else {
        return Ok(None);
    };
    let removed = existing.remove(pos);
    existing.sort_by_key(|t| t.index);
    for (n, t) in existing.iter().enumerate() {
        lines[t.line] = format!("{PREFIX}{}={}", n + 1, t.value.as_str());
    }
    lines.remove(removed.line);
    write_atomic(&target, &lines)?;
    Ok(Some(removed.index))
}

/// Rewrite the whole env file under the same lock and atomic write the bot
/// commands use. `update` receives the file's current bytes (empty if it does not
/// exist yet), read after the lock is held so a concurrent `add-bot` is never
/// lost, and returns the bytes to store. For callers (`configure`) that own some
/// keys of the file and must carry every other byte over untouched.
pub fn rewrite(env_path: &Path, update: impl FnOnce(&[u8]) -> Vec<u8>) -> Result<()> {
    let target = resolve_target(env_path)?;
    let _lock = lock(&target)?;
    let current = match std::fs::read(&target) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("read {}", target.display())),
    };
    write_atomic_bytes(&target, &update(&current))
}

/// Write to the file a symlinked `.env` points at, not over the link itself.
fn resolve_target(env_path: &Path) -> Result<PathBuf> {
    match std::fs::canonicalize(env_path) {
        Ok(p) => Ok(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = env_path
                .parent()
                .context("config .env path has no parent directory")?;
            create_private_dir(parent)?;
            Ok(env_path.to_path_buf())
        }
        Err(e) => Err(e).with_context(|| format!("resolve {}", env_path.display())),
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    teagarden_core::fsutil::ensure_private_dir(dir)
        .with_context(|| format!("create config directory {}", dir.display()))
}

fn read_lines(path: &Path) -> Result<Vec<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s.lines().map(str::to_string).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Exclusive advisory lock on `<target>.lock`, explicitly unlocked on owner drop.
fn lock(target: &Path) -> Result<teagarden_core::fsutil::ScopedFileLock> {
    let mut name = target
        .file_name()
        .context("config .env path has no file name")?
        .to_os_string();
    name.push(".lock");
    let lock_path = target.with_file_name(name);
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let f = opts
        .open(&lock_path)
        .with_context(|| format!("open {}", lock_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd as _;
        loop {
            // SAFETY: flock on a valid, owned fd.
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(err).with_context(|| format!("lock {}", lock_path.display()));
            }
        }
    }
    let guard = teagarden_core::fsutil::ScopedFileLock::from_locked_file(f);
    sweep_stale_temps(target);
    Ok(guard)
}

/// Remove temp files a killed writer left beside `target`. Every writer holds
/// the lock for the whole of `write_atomic`, so once we hold it, any
/// `.<name>.*.tmp` belongs to a writer that died between create and rename.
/// Such a file is a full copy of the env file (tokens and API hash included),
/// so it must not linger. Best effort.
fn sweep_stale_temps(target: &Path) {
    let (Some(dir), Some(name)) = (target.parent(), target.file_name()) else {
        return;
    };
    let prefix = format!(".{}.", name.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let n = entry.file_name();
        let n = n.to_string_lossy();
        if n.starts_with(&prefix) && n.ends_with(".tmp") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn write_atomic(target: &Path, lines: &[String]) -> Result<()> {
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    write_atomic_bytes(target, content.as_bytes())
}

fn write_atomic_bytes(target: &Path, content: &[u8]) -> Result<()> {
    let tmp = {
        use rand::RngCore as _;
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".env".into());
        target.with_file_name(format!(
            ".{name}.{}.{:016x}.tmp",
            std::process::id(),
            rand::rngs::OsRng.next_u64()
        ))
    };
    let result = (|| -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(content)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
        drop(f);
        std::fs::rename(&tmp, target).with_context(|| format!("replace {}", target.display()))?;
        if let Some(dir) = target.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all(); // best effort: the rename itself already landed
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    // Token-shaped test values (not real bot tokens).
    fn tok(id: u64, tag: &str) -> String {
        format!("{id}:AAtestsecret_{tag}_0123456789abcdefghij")
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn token_indices(p: &Path) -> Vec<(usize, String)> {
        list_bots(p).unwrap()
    }

    #[test]
    fn appends_at_the_next_free_index_preserving_other_lines_and_tightening_mode() {
        let d = tempfile::tempdir().unwrap();
        let env = d.path().join(".env");
        let original = "# TeaGarden Configuration\nTG_API_ID=12345\nTG_API_HASH=abcdef\n\n";
        std::fs::write(&env, original).unwrap();
        std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            add_token(&env, &tok(111, "a")).unwrap(),
            Added::New { index: 1 }
        );
        assert_eq!(
            add_token(&env, &tok(222, "b")).unwrap(),
            Added::New { index: 2 }
        );
        let after = std::fs::read_to_string(&env).unwrap();
        assert!(
            after.starts_with(original),
            "existing lines changed:\n{after}"
        );
        assert_eq!(
            after,
            format!(
                "{original}TELEGRAM_BOT_TOKEN_1={}\nTELEGRAM_BOT_TOKEN_2={}\n",
                tok(111, "a"),
                tok(222, "b")
            )
        );
        assert_eq!(mode(&env), 0o600, ".env must be 0600 after a write");

        // Same token again: a no-op. Same bot, new token (after /revoke): in place.
        assert_eq!(
            add_token(&env, &tok(111, "a")).unwrap(),
            Added::AlreadyPresent { index: 1 }
        );
        assert_eq!(after, std::fs::read_to_string(&env).unwrap());
        assert_eq!(
            add_token(&env, &tok(111, "new")).unwrap(),
            Added::Replaced { index: 1 }
        );
        assert!(std::fs::read_to_string(&env)
            .unwrap()
            .contains(&format!("TELEGRAM_BOT_TOKEN_1={}\n", tok(111, "new"))));
    }

    #[test]
    fn creates_a_missing_env_file_and_fills_gaps() {
        let d = tempfile::tempdir().unwrap();
        let env = d.path().join("cfg").join(".env");
        assert_eq!(
            add_token(&env, &tok(1, "x")).unwrap(),
            Added::New { index: 1 }
        );
        assert_eq!(mode(&env), 0o600);
        assert_eq!(mode(env.parent().unwrap()), 0o700);

        // The mount loader stops at the first missing index, so a gap is filled.
        let gappy = d.path().join("gappy.env");
        std::fs::write(
            &gappy,
            format!(
                "TELEGRAM_BOT_TOKEN_1={}\nTELEGRAM_BOT_TOKEN_3={}\n",
                tok(1, "a"),
                tok(3, "c")
            ),
        )
        .unwrap();
        assert_eq!(
            add_token(&gappy, &tok(2, "b")).unwrap(),
            Added::New { index: 2 }
        );
    }

    #[test]
    fn malformed_tokens_are_refused_without_echoing_them_or_touching_the_file() {
        let d = tempfile::tempdir().unwrap();
        let env = d.path().join(".env");
        std::fs::write(&env, "TG_API_ID=1\n").unwrap();
        for bad in [
            // A newline would inject a line into the config file.
            format!("{}\nTG_API_HASH=attacker", tok(9, "inj")),
            "no-colon-AAtestsecret_0123456789abcdefghij".to_string(),
            "12ab:AAtestsecret_0123456789abcdefghij".to_string(),
            "123:short".to_string(),
            "123:AAtestsecret with spaces 0123456789".to_string(),
            "123:AAtestsecret=equals_0123456789abcdefgh".to_string(),
        ] {
            let e = add_token(&env, &bad).expect_err(&format!("accepted {bad:?}"));
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("AAtestsecret"),
                "error echoed the token: {msg}"
            );
        }
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "TG_API_ID=1\n");
    }

    /// Two `add-bot` runs at once must not both take the same free index and
    /// lose a token. Eight threads append ten distinct tokens each.
    #[test]
    fn concurrent_appends_lose_nothing() {
        let d = tempfile::tempdir().unwrap();
        let env = std::sync::Arc::new(d.path().join(".env"));
        std::fs::write(&*env, "TG_API_ID=1\n").unwrap();
        // A reader racing the writers, like a mount starting mid-`add-bot`: it
        // must only ever see a complete old or new file.
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let (env, done) = (env.clone(), done.clone());
            std::thread::spawn(move || {
                let mut reads = 0u64;
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    let text = std::fs::read_to_string(&*env).expect("env file always present");
                    let mut lines = text.lines();
                    assert_eq!(lines.next(), Some("TG_API_ID=1"), "torn read:\n{text:?}");
                    for l in lines {
                        let (_, value) = parse_token_line(l)
                            .unwrap_or_else(|| panic!("torn line {l:?} in:\n{text:?}"));
                        validate_token(value).unwrap_or_else(|_| panic!("torn token in {l:?}"));
                    }
                    assert!(text.ends_with('\n'), "torn tail: {text:?}");
                    reads += 1;
                }
                reads
            })
        };
        let threads: Vec<_> = (0..8u64)
            .map(|t| {
                let env = env.clone();
                std::thread::spawn(move || {
                    for i in 0..10u64 {
                        add_token(&env, &tok(1000 + t * 100 + i, "c")).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        let reads = reader.join().expect("reader saw a torn file");
        assert!(reads > 0, "the reader never ran");
        let bots = token_indices(&env);
        let indices: Vec<usize> = bots.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, (1..=80).collect::<Vec<_>>(), "lost or duplicated");
        let mut ids: Vec<&str> = bots.iter().map(|(_, id)| id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 80, "every token must survive exactly once");
        assert!(std::fs::read_to_string(&*env)
            .unwrap()
            .starts_with("TG_API_ID=1\n"));
        assert_eq!(mode(&env), 0o600);
        let leftovers: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != ".env" && n != ".env.lock")
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
    }

    /// A writer killed between creating its temp file and renaming it leaves a
    /// full copy of the secrets behind. The next writer removes it.
    #[test]
    fn a_killed_writers_temp_file_is_swept_by_the_next_writer() {
        let d = tempfile::tempdir().unwrap();
        let env = d.path().join(".env");
        std::fs::write(&env, "TG_API_ID=1\n").unwrap();
        // The name write_atomic uses: ".<file name>.<pid>.<random>.tmp".
        let stale = d.path().join("..env.4242.00000000deadbeef.tmp");
        std::fs::write(&stale, "TG_API_ID=1\nTG_API_HASH=secret\n").unwrap();
        let unrelated = d.path().join(".envrc");
        std::fs::write(&unrelated, "keep").unwrap();
        add_token(&env, &tok(7, "s")).unwrap();
        assert!(!stale.exists(), "stale temp file survived");
        assert!(unrelated.exists(), "an unrelated file was removed");
    }

    #[test]
    fn remove_renumbers_the_survivors_contiguously() {
        let d = tempfile::tempdir().unwrap();
        let env = d.path().join(".env");
        std::fs::write(&env, "TG_API_ID=1\n").unwrap();
        for (id, tag) in [(11, "a"), (22, "b"), (33, "c")] {
            add_token(&env, &tok(id, tag)).unwrap();
        }
        assert_eq!(remove_bot(&env, "99").unwrap(), None);
        assert_eq!(remove_bot(&env, "22").unwrap(), Some(2));
        assert_eq!(
            std::fs::read_to_string(&env).unwrap(),
            format!(
                "TG_API_ID=1\nTELEGRAM_BOT_TOKEN_1={}\nTELEGRAM_BOT_TOKEN_2={}\n",
                tok(11, "a"),
                tok(33, "c")
            )
        );
        assert_eq!(mode(&env), 0o600);
    }

    #[test]
    fn a_symlinked_env_is_written_through_not_replaced() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("dotfiles-env");
        std::fs::write(&real, "TG_API_ID=1\n").unwrap();
        let link = d.path().join(".env");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        add_token(&link, &tok(5, "s")).unwrap();
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::read_to_string(&real)
            .unwrap()
            .contains("TELEGRAM_BOT_TOKEN_1="));
    }

    /// `configure` (via `rewrite`) and `add-bot` share one lock: a token added
    /// while the other runs is never lost, and every state read back is whole.
    #[test]
    fn rewrite_and_add_token_never_lose_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let env = std::sync::Arc::new(dir.path().join(".env"));
        std::fs::write(&*env, "TG_API_ID=1\n").unwrap();
        let adders: Vec<_> = (1..=6u64)
            .map(|n| {
                let env = env.clone();
                std::thread::spawn(move || {
                    add_token(&env, &tok(n, "r")).unwrap();
                })
            })
            .collect();
        let rewriters: Vec<_> = (0..6)
            .map(|_| {
                let env = env.clone();
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        rewrite(&env, |old| {
                            let mut v = old.to_vec();
                            v.extend_from_slice(b"# note\n");
                            v
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in adders.into_iter().chain(rewriters) {
            t.join().unwrap();
        }
        assert_eq!(token_indices(&env).len(), 6, "a token was lost");
        assert_eq!(mode(&env), 0o600);
    }
}
