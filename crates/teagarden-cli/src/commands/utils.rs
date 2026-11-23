use anyhow::{Context, Result};
use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Heap-backed secret text which overwrites its allocation on drop.
pub type SecretString = Zeroizing<String>;

fn credentials_from_env_text(content: &str) -> (Option<i32>, Option<String>) {
    let mut api_id = None;
    let mut api_hash = None;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("TG_API_ID=") {
            api_id = value.parse::<i32>().ok().filter(|id| *id > 0);
        } else if let Some(value) = line.strip_prefix("TG_API_HASH=") {
            api_hash = (!value.is_empty()).then(|| value.to_string());
        }
    }
    (api_id, api_hash)
}

/// Application credentials baked into a release build by its publisher.
///
/// A Telegram api_id/api_hash identifies the APPLICATION, not the user, so a
/// publisher may register one app and build release binaries with it:
///   TEAGARDEN_BUILD_API_ID=12345 TEAGARDEN_BUILD_API_HASH=<32 hex> cargo build --release
/// Users of such a binary only need their phone number and login code. The value
/// is extractable from the binary, so treat it as public. Builds without these
/// variables (the default) contain no credentials and ask the user instead.
pub(crate) const BUILD_API_ID: Option<&str> = option_env!("TEAGARDEN_BUILD_API_ID");
/// See [`BUILD_API_ID`].
pub(crate) const BUILD_API_HASH: Option<&str> = option_env!("TEAGARDEN_BUILD_API_HASH");

/// Every place a Telegram api_id / api_hash can come from, highest precedence
/// first. Gathered by [`gather_and_resolve_credentials`]; kept as plain data so
/// the precedence rule is unit-testable with injected inputs.
#[derive(Default)]
pub(crate) struct CredentialInputs<'a> {
    /// `--api-id` (only `auth login` has the flags).
    pub flag_id: Option<i32>,
    /// `--api-hash`.
    pub flag_hash: Option<&'a str>,
    /// `TG_API_ID` from the process environment, which also carries the config
    /// `.env` (imported at startup without overriding the real environment).
    pub env_id: Option<&'a str>,
    /// `TG_API_HASH` from the process environment.
    pub env_hash: Option<&'a str>,
    /// The text of the config `.env` file, if it exists.
    pub env_file: Option<&'a str>,
    /// Build-time application id ([`BUILD_API_ID`]).
    pub build_id: Option<&'a str>,
    /// Build-time application hash ([`BUILD_API_HASH`]).
    pub build_hash: Option<&'a str>,
}

/// Outcome of [`resolve_credentials`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Resolved {
    /// A usable pair.
    Complete(i32, String),
    /// The user configured one half only. The build-time pair is never mixed in:
    /// an id from one application with a hash from another cannot work.
    Partial(Option<i32>, Option<String>),
    /// Nothing configured anywhere, and no build-time pair.
    Missing,
}

/// The ONE precedence rule for Telegram application credentials.
///
/// Per field: flag, then environment, then the config `.env`; an empty value
/// counts as unset. Only when the user configured NEITHER field is the
/// build-time pair used, and then only as a pair. An invalid value is an error,
/// never a reason to fall through to a lower tier.
pub(crate) fn resolve_credentials(inputs: &CredentialInputs<'_>) -> Result<Resolved> {
    fn nonempty(v: Option<&str>) -> Option<&str> {
        v.filter(|s| !s.is_empty())
    }
    if let Some(id) = inputs.flag_id {
        anyhow::ensure!(id > 0, "--api-id must be a positive integer");
    }
    let env_id = match nonempty(inputs.env_id) {
        Some(raw) => Some(
            raw.parse::<i32>()
                .ok()
                .filter(|id| *id > 0)
                .context("TG_API_ID must be a positive integer")?,
        ),
        None => None,
    };
    let (file_id, file_hash) = inputs
        .env_file
        .map(credentials_from_env_text)
        .unwrap_or((None, None));
    let id = inputs.flag_id.or(env_id).or(file_id);
    let hash = nonempty(inputs.flag_hash)
        .or(nonempty(inputs.env_hash))
        .map(str::to_string)
        .or(file_hash);

    match (id, hash) {
        (Some(id), Some(hash)) => Ok(Resolved::Complete(id, hash)),
        (None, None) => match (nonempty(inputs.build_id), nonempty(inputs.build_hash)) {
            (Some(raw_id), Some(hash)) => {
                let id = raw_id.parse::<i32>().ok().filter(|id| *id > 0).context(
                    "this build carries an invalid TEAGARDEN_BUILD_API_ID (not a positive integer)",
                )?;
                Ok(Resolved::Complete(id, hash.to_string()))
            }
            (None, None) => Ok(Resolved::Missing),
            _ => anyhow::bail!(
                "this build carries only one of TEAGARDEN_BUILD_API_ID / TEAGARDEN_BUILD_API_HASH"
            ),
        },
        (id, hash) => Ok(Resolved::Partial(id, hash)),
    }
}

/// Gather the real inputs (environment, config `.env`, build-time pair) and
/// apply [`resolve_credentials`]. `flag_*` are `auth login`'s flags; every other
/// command passes `None`.
pub(crate) fn gather_and_resolve_credentials(
    flag_id: Option<i32>,
    flag_hash: Option<&str>,
) -> Result<Resolved> {
    let read_env = |name: &str| match std::env::var(name) {
        Ok(v) => Ok(Some(Zeroizing::new(v))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {name}")),
    };
    let env_id = read_env("TG_API_ID")?;
    let env_hash = read_env("TG_API_HASH")?;
    let env_file = config_dir()
        .ok()
        .and_then(|d| std::fs::read_to_string(d.join(".env")).ok())
        .map(Zeroizing::new);
    resolve_credentials(&CredentialInputs {
        flag_id,
        flag_hash,
        env_id: env_id.as_deref().map(String::as_str),
        env_hash: env_hash.as_deref().map(String::as_str),
        env_file: env_file.as_deref().map(String::as_str),
        build_id: BUILD_API_ID,
        build_hash: BUILD_API_HASH,
    })
}

/// Telegram API credentials for every command that connects to Telegram:
/// environment, then the `configure`-written `.env`, then the build-time pair
/// (see [`resolve_credentials`]).
pub fn load_telegram_credentials() -> Result<(i32, String)> {
    match gather_and_resolve_credentials(None, None)? {
        Resolved::Complete(id, hash) => Ok((id, hash)),
        Resolved::Partial(..) => anyhow::bail!(
            "Telegram credentials are incomplete: only one of TG_API_ID / TG_API_HASH is set; \
             set both, or run `teagarden configure`"
        ),
        Resolved::Missing => {
            let where_ = config_dir()
                .map(|d| d.join(".env").display().to_string())
                .unwrap_or_else(|_| "the config .env".into());
            anyhow::bail!(
                "Telegram credentials not found in the environment or {where_}, and this build \
                 carries none; run `teagarden configure`"
            )
        }
    }
}

/// Resolve the Telegram session path, honoring the documented environment
/// override before falling back to the platform configuration directory.
pub fn session_file_path() -> PathBuf {
    if let Some(path) = std::env::var_os("TEAGARDEN_SESSION_PATH").filter(|path| !path.is_empty()) {
        return PathBuf::from(path);
    }
    config_dir()
        .expect("unable to determine config directory; set TEAGARDEN_SESSION_PATH")
        .join("teagarden.session")
}

/// The TeaGarden configuration directory — the ONE place every config file
/// (`.env`, `teagarden.fstab`, `group.json`, `identity.keypair`, the default session)
/// is resolved from.
///
/// `TEAGARDEN_CONFIG_DIR`, when set and non-empty, names the directory itself
/// (not its parent). Otherwise it is `<platform config dir>/teagarden`:
/// `$XDG_CONFIG_HOME/teagarden` or `~/.config/teagarden` on Linux, and
/// `~/Library/Application Support/teagarden` on macOS — where `dirs` ignores
/// `XDG_CONFIG_HOME`, which is why tests must set `TEAGARDEN_CONFIG_DIR`.
pub fn config_dir() -> Result<PathBuf> {
    config_dir_from(std::env::var_os("TEAGARDEN_CONFIG_DIR"), dirs::config_dir())
}

fn config_dir_from(
    override_dir: Option<std::ffi::OsString>,
    platform_config_dir: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(dir) = override_dir.filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    platform_config_dir
        .map(|d| d.join("teagarden"))
        .context("unable to determine the config directory; set TEAGARDEN_CONFIG_DIR")
}

/// Move secret text into a zeroizing allocation, then remove only transport
/// line endings in place. Wrapping before trimming ensures the original input
/// allocation is also wiped on drop instead of leaving an unprotected copy.
pub fn secret_without_line_endings(value: String) -> SecretString {
    let mut secret = Zeroizing::new(value);
    while matches!(secret.as_bytes().last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    secret
}

/// Move secret text into a zeroizing allocation and trim surrounding Unicode
/// whitespace in place. `String::zeroize` wipes the full allocation capacity,
/// including bytes removed by `truncate`/`drain`.
pub fn trimmed_secret(value: String) -> SecretString {
    let mut secret = Zeroizing::new(value);
    let (start, end) = {
        let trimmed = secret.trim();
        let start = trimmed.as_ptr() as usize - secret.as_ptr() as usize;
        (start, start + trimmed.len())
    };
    secret.truncate(end);
    secret.drain(..start);
    secret
}

/// Prompt the user for text input.
pub fn prompt(question: &str) -> Result<String> {
    print!("{question} ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin()
        .lock()
        .read_line(&mut input)
        .context("failed to read input")?;
    Ok(input.trim().to_string())
}

/// Prompt for a password with echo suppression.
///
/// Uses rpassword to suppress terminal echo so the password is not
/// visible on screen. Falls back to plain stdin if terminal is not available.
pub fn prompt_password(msg: &str) -> Result<SecretString> {
    rpassword::prompt_password(msg)
        .map(Zeroizing::new)
        .context("failed to read password")
}

/// Check a Telegram API hash: exactly 32 hexadecimal characters. One rule for
/// every prompt that reads it (`auth login`, `configure`).
pub fn validate_api_hash(hash: &str) -> Result<()> {
    if hash.len() != 32 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("the API hash must be 32 hexadecimal characters");
    }
    Ok(())
}

/// Read a hidden line (a credential) without echoing it.
///
/// On a terminal this is [`prompt_password`] (terminal echo off). When standard
/// input is not a terminal (a script feeding answers through a pipe) there is
/// no echo to suppress and `/dev/tty` may not exist, so the line is read from
/// standard input instead.
pub fn prompt_hidden(msg: &str) -> Result<SecretString> {
    use std::io::IsTerminal as _;
    if io::stdin().is_terminal() {
        return prompt_password(msg);
    }
    print!("{msg}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read input")?;
    Ok(trimmed_secret(line))
}

/// Format an error with its suggestion for CLI display.
pub fn cli_error<E: fmt::Display>(error: E, suggestion: &str) -> anyhow::Error {
    anyhow::anyhow!("{error}\n  Suggestion: {suggestion}")
}

/// Convert a core error to an anyhow error with suggestion.
pub fn core_err(e: teagarden_core::error::CoreError) -> anyhow::Error {
    let suggestion = e.suggestion();
    cli_error(e, suggestion)
}

/// Convert a telegram error to an anyhow error with suggestion.
pub fn telegram_err(e: teagarden_telegram::error::TelegramError) -> anyhow::Error {
    let suggestion = e.suggestion();
    cli_error(e, suggestion)
}

/// Convert an API error to an anyhow error with suggestion.
pub fn api_err(e: teagarden_api::error::ApiError) -> anyhow::Error {
    let suggestion = e.suggestion();
    cli_error(e, suggestion)
}

/// Convert a sharing error to an anyhow error with suggestion.
/// Not yet called in CLI commands (sharing ops use store errors directly),
/// but kept for consistency with other error converters.
#[cfg_attr(not(test), allow(dead_code))]
pub fn sharing_err(e: teagarden_sharing::error::SharingError) -> anyhow::Error {
    let suggestion = e.suggestion();
    cli_error(e, suggestion)
}

/// Open a volume with whatever credential it actually needs — passphrase for a
/// legacy volume, or a factor for a key-protected (`--key-protection`) one.
///
/// **Why this exists.** Only `volume mount` and `mfa unlock` used to route through
/// `teagarden_mfa::unlock::open_volume`; every other command called
/// `manager::open_volume` with a bare password. On a key-protected volume that
/// path fails closed (correctly — it is not a bypass), but it meant enabling the
/// headline 1.0.0 security feature silently disabled backup, restore, revert,
/// history, diff, key rotation and sharing. Worse, the
/// error told the user to "open it with a factor unlock" while those commands had
/// no flag to do so.
///
/// Routing every open through here makes `--key-protection` compatible with the
/// whole CLI instead of a subset of it.
pub fn open_volume_any(
    volume_id: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    volumes_dir: &std::path::Path,
) -> anyhow::Result<teagarden_core::volume::manager::OpenVolumeResult> {
    Ok(open_volume_any_retaining_password(volume_id, password_file, recovery_file, volumes_dir)?.0)
}

/// Read each unlock input once, retaining the zeroizing password for administration.
pub fn open_volume_any_retaining_password(
    volume_id: &str,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    volumes_dir: &std::path::Path,
) -> anyhow::Result<(
    teagarden_core::volume::manager::OpenVolumeResult,
    Option<SecretString>,
)> {
    // A recovery sentence replaces the passphrase; don't prompt for both.
    let recovery = read_recovery_sentence(recovery_file)?;
    let password = if recovery.is_some() {
        None
    } else {
        Some(read_password_input(password_file)?)
    };

    let inputs = teagarden_mfa::unlock::UnlockInputs {
        password: password.as_deref().map(String::as_bytes),
        recovery_sentence: recovery.as_ref().map(|secret| secret.as_str()),
        ..Default::default()
    };
    let opened = teagarden_mfa::unlock::open_volume(volume_id, &inputs, volumes_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    #[cfg(feature = "key-rotation")]
    let opened = {
        let mut opened = opened;
        super::volume::apply_local_device_transition(&mut opened)?;
        opened
    };
    Ok((opened, password))
}

/// Read a volume passphrase from `--password-file` (`-` = stdin), else prompt.
pub fn read_password_input(password_file: Option<&str>) -> anyhow::Result<SecretString> {
    use std::io::Read as _;
    match password_file {
        Some("-") => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            Ok(secret_without_line_endings(s))
        }
        Some(path) => std::fs::read_to_string(path)
            .map(secret_without_line_endings)
            .map_err(|e| anyhow::anyhow!("read password file {path}: {e}")),
        None => Ok(prompt_password("Enter volume password: ")?),
    }
}

/// Read a recovery sentence from `--recovery-file` (`-` = stdin), trimmed.
pub fn read_recovery_sentence(recovery_file: Option<&str>) -> anyhow::Result<Option<SecretString>> {
    match recovery_file {
        Some("-") => {
            let mut s = String::new();
            std::io::stdin().read_line(&mut s)?;
            Ok(Some(trimmed_secret(s)))
        }
        Some(path) => std::fs::read_to_string(path)
            .map(trimmed_secret)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("read recovery file {path}: {e}")),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_hash_must_be_exactly_32_hex_digits() {
        assert!(validate_api_hash("0123456789abcdef0123456789ABCDEF").is_ok());
        for bad in [
            "",
            "0123456789abcdef",                  // 16 hex: too short
            "0123456789abcdef0123456789abcde",   // 31
            "0123456789abcdef0123456789abcdef0", // 33
            "0123456789abcdef0123456789abcdeg",  // 32 but not hex
            "0123456789abcdef0123456789abcde ",  // 32 with a space
        ] {
            assert!(validate_api_hash(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn config_dir_override_wins_and_names_the_directory_itself() {
        let platform = Some(PathBuf::from("/platform/config"));
        assert_eq!(
            config_dir_from(Some("/chosen".into()), platform.clone()).unwrap(),
            PathBuf::from("/chosen")
        );
        assert_eq!(
            config_dir_from(None, platform.clone()).unwrap(),
            PathBuf::from("/platform/config/teagarden")
        );
        // An empty override is ignored, not treated as the current directory.
        assert_eq!(
            config_dir_from(Some("".into()), platform).unwrap(),
            PathBuf::from("/platform/config/teagarden")
        );
        assert!(config_dir_from(None, None).is_err());
    }

    #[test]
    fn cli_error_includes_suggestion() {
        let err = cli_error("something failed", "try again");
        let msg = format!("{err}");
        assert!(msg.contains("something failed"));
        assert!(msg.contains("Suggestion: try again"));
    }

    #[test]
    fn secret_input_trimming_preserves_expected_value() {
        assert_eq!(
            secret_without_line_endings("pass \r\n".into()).as_str(),
            "pass "
        );
        assert_eq!(
            trimmed_secret(" \talpha beta\r\n".into()).as_str(),
            "alpha beta"
        );
        assert!(trimmed_secret(" \r\n\t".into()).is_empty());
    }

    fn resolve(i: CredentialInputs<'_>) -> Resolved {
        resolve_credentials(&i).unwrap()
    }

    #[test]
    fn credential_precedence_is_flag_then_env_then_file_then_build() {
        let file = "TG_API_ID=3\nTG_API_HASH=file\n";
        let all = CredentialInputs {
            flag_id: Some(1),
            flag_hash: Some("flag"),
            env_id: Some("2"),
            env_hash: Some("env"),
            env_file: Some(file),
            build_id: Some("4"),
            build_hash: Some("build"),
        };
        assert_eq!(resolve(all), Resolved::Complete(1, "flag".into()));
        let env_over_file = CredentialInputs {
            env_id: Some("2"),
            env_hash: Some("env"),
            env_file: Some(file),
            build_id: Some("4"),
            build_hash: Some("build"),
            ..Default::default()
        };
        assert_eq!(resolve(env_over_file), Resolved::Complete(2, "env".into()));
        let file_over_build = CredentialInputs {
            env_file: Some(file),
            build_id: Some("4"),
            build_hash: Some("build"),
            ..Default::default()
        };
        assert_eq!(
            resolve(file_over_build),
            Resolved::Complete(3, "file".into())
        );
        let build_only = CredentialInputs {
            build_id: Some("4"),
            build_hash: Some("build"),
            ..Default::default()
        };
        assert_eq!(resolve(build_only), Resolved::Complete(4, "build".into()));
        assert_eq!(resolve(CredentialInputs::default()), Resolved::Missing);
    }

    #[test]
    fn credential_fields_merge_across_user_tiers_but_never_with_the_build_pair() {
        // env id + file hash: both are user configuration, merged per field.
        let merged = CredentialInputs {
            env_id: Some("2"),
            env_file: Some("TG_API_HASH=file\n"),
            ..Default::default()
        };
        assert_eq!(resolve(merged), Resolved::Complete(2, "file".into()));
        // A user id with the build's hash would pair two different applications.
        let half = CredentialInputs {
            env_id: Some("2"),
            build_id: Some("4"),
            build_hash: Some("build"),
            ..Default::default()
        };
        assert_eq!(resolve(half), Resolved::Partial(Some(2), None));
        let half_hash = CredentialInputs {
            flag_hash: Some("flag"),
            build_id: Some("4"),
            build_hash: Some("build"),
            ..Default::default()
        };
        assert_eq!(
            resolve(half_hash),
            Resolved::Partial(None, Some("flag".into()))
        );
    }

    #[test]
    fn empty_values_are_unset_and_invalid_values_are_errors() {
        // The configure template writes `TG_API_ID=` / `TG_API_HASH=`, which the
        // startup .env import copies into the environment as empty strings.
        let empty = CredentialInputs {
            env_id: Some(""),
            env_hash: Some(""),
            env_file: Some("TG_API_ID=\nTG_API_HASH=\n"),
            build_id: Some("4"),
            build_hash: Some("build"),
            ..Default::default()
        };
        assert_eq!(resolve(empty), Resolved::Complete(4, "build".into()));
        let bad_env = CredentialInputs {
            env_id: Some("abc"),
            env_hash: Some("env"),
            build_id: Some("4"),
            build_hash: Some("build"),
            ..Default::default()
        };
        assert!(
            resolve_credentials(&bad_env).is_err(),
            "an invalid value must never fall through to a lower tier"
        );
        let bad_build = CredentialInputs {
            build_id: Some("x"),
            build_hash: Some("build"),
            ..Default::default()
        };
        assert!(resolve_credentials(&bad_build).is_err());
        let half_build = CredentialInputs {
            build_id: Some("4"),
            ..Default::default()
        };
        assert!(resolve_credentials(&half_build).is_err());
        let zero_flag = CredentialInputs {
            flag_id: Some(0),
            flag_hash: Some("flag"),
            ..Default::default()
        };
        assert!(resolve_credentials(&zero_flag).is_err());
    }

    #[test]
    fn config_credentials_parser_requires_a_positive_id_and_nonempty_hash() {
        assert_eq!(
            credentials_from_env_text("TG_API_ID=123\nTG_API_HASH=abc\n"),
            (Some(123), Some("abc".into()))
        );
        assert_eq!(
            credentials_from_env_text("TG_API_ID=0\nTG_API_HASH=\n"),
            (None, None)
        );
    }

    #[test]
    fn core_err_includes_suggestion() {
        let core_err_val = teagarden_core::error::CoreError::Encryption("bad key".into());
        let err = core_err(core_err_val);
        let msg = format!("{err}");
        assert!(msg.contains("bad key"));
        assert!(msg.contains("Suggestion:"));
    }

    #[test]
    fn api_err_includes_suggestion() {
        let api_err_val = teagarden_api::error::ApiError::VolumeNotFound("test".into());
        let err = api_err(api_err_val);
        let msg = format!("{err}");
        assert!(msg.contains("test"));
        assert!(msg.contains("Suggestion:"));
    }

    #[test]
    fn sharing_err_includes_suggestion() {
        let se = teagarden_sharing::error::SharingError::InvalidInvite("expired".into());
        let err = sharing_err(se);
        let msg = format!("{err}");
        assert!(msg.contains("expired"));
        assert!(msg.contains("Suggestion:"));
    }
}
