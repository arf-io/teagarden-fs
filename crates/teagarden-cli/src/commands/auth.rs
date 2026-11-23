use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use zeroize::Zeroizing;

use teagarden_telegram::client::TelegramClient;
use teagarden_telegram::types::{AuthState, TelegramConfig};

use super::utils;

/// What `auth login` prints after Telegram accepted the request for a login code.
///
/// The Telegram library TeaGarden uses (grammers 0.10) drops the `SentCode` the
/// server answers with, so the delivery type (app, SMS, call, Fragment, e-mail)
/// is not known here and cannot be printed; the text says where each one arrives.
/// The same library has no resend call (`auth.resendCode` needs the code hash,
/// which it keeps private), so the prompt does not offer one.
const LOGIN_CODE_NOTICE: &str = "\
Telegram has sent a login code for this phone number.\n\
Look for a message from \"Telegram\" in the Telegram app on a device where this account is already signed in.\n\
If no device is signed in, Telegram sends the code by SMS, a phone call or Fragment instead.\n\
TeaGarden cannot see which of these Telegram chose, and cannot ask it for another route.\n\
If no code arrives, check the phone number and run `teagarden auth login` again; Telegram limits the codes it sends per number per day.";

/// Store the API id and hash in `env_path`: mode 0600, written atomically, every
/// line this tool does not own kept. The config directory is created 0700 first.
fn save_api_settings(env_path: &Path, api_id: i32, api_hash: &str) -> Result<()> {
    if let Some(dir) = env_path.parent() {
        teagarden_core::fsutil::ensure_private_dir(dir)
            .with_context(|| format!("create config directory {}", dir.display()))?;
    }
    let id = api_id.to_string();
    let owned = [("TG_API_ID", id.as_str()), ("TG_API_HASH", api_hash)];
    super::bot_env::rewrite(env_path, |existing| {
        super::configure::merge_owned_keys(existing, &owned)
    })
    .with_context(|| format!("write {}", env_path.display()))
}

/// The API id and hash `auth login` will use, and whether storing them failed.
struct Credentials {
    api_id: i32,
    api_hash: zeroize::Zeroizing<String>,
    /// Why the `.env` could not be written, when it could not. The login goes on
    /// with the values in memory and reports this at the end.
    save_failure: Option<String>,
}

const MAX_CODE_ATTEMPTS: u32 = 3;
const MAX_PASSWORD_ATTEMPTS: u32 = 3;

fn login_uri(token: &[u8]) -> String {
    format!(
        "tg://login?token={}",
        Base64UrlUnpadded::encode_string(token)
    )
}

fn print_login_qr(uri: &str) -> Result<()> {
    let code = qrcode::QrCode::new(uri).context("encode Telegram login QR code")?;
    println!(
        "{}",
        code.render::<qrcode::render::unicode::Dense1x2>().build()
    );
    println!("{uri}");
    Ok(())
}

#[cfg(test)]
thread_local! {
    static LOGIN_TEST_SKIP_TELEGRAM: std::cell::RefCell<bool> = const { std::cell::RefCell::new(false) };
    static TEST_CONFIG_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static EXPORT_TEST_BACKUP: std::cell::RefCell<Option<(PathBuf, u32, u32)>> = const { std::cell::RefCell::new(None) };
}

fn auth_config_dir() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = TEST_CONFIG_DIR.with(|dir| dir.borrow().clone()) {
        return Ok(dir);
    }
    utils::config_dir()
}

fn auth_session_file_path() -> PathBuf {
    #[cfg(test)]
    if let Some(dir) = TEST_CONFIG_DIR.with(|dir| dir.borrow().clone()) {
        return dir.join(SESSION_FILE);
    }
    session_file_path()
}

fn persist_api_settings(id: i32, hash: &str) -> Option<String> {
    let env_path = match auth_config_dir() {
        Ok(dir) => dir.join(".env"),
        Err(e) => {
            eprintln!("Could not locate the config directory: {e:#}");
            return Some(format!("{e:#}"));
        }
    };
    match save_api_settings(&env_path, id, hash) {
        Ok(()) => {
            println!("Saved to {} (readable only by you).", env_path.display());
            None
        }
        Err(e) => {
            eprintln!(
                "Could not save the API settings to {}: {e:#}",
                env_path.display()
            );
            eprintln!("Continuing: this login uses the resolved values.");
            Some(format!("{e:#}"))
        }
    }
}

/// Resolve the Telegram API credentials for `auth login`.
///
/// Order: the shared rule every Telegram command uses
/// ([`utils::resolve_credentials`]: `--api-id`/`--api-hash`, then `TG_API_ID` /
/// `TG_API_HASH`, then the config `.env`, then the build-time pair), and only
/// then an interactive prompt for whatever is still missing, when stdin is a
/// terminal. The hash prompt does not echo. Credentials entered at the prompt
/// are always saved to the `.env` file ([`save_api_settings`]) so later commands
/// find them; there is no question about it.
fn resolve_credentials(api_id: Option<i32>, api_hash: Option<String>) -> Result<Credentials> {
    use std::io::IsTerminal;

    let (api_id, api_hash) =
        match utils::gather_and_resolve_credentials(api_id, api_hash.as_deref())? {
            utils::Resolved::Complete(id, hash) => {
                let save_failure = persist_api_settings(id, &hash);
                return Ok(Credentials {
                    api_id: id,
                    api_hash: zeroize::Zeroizing::new(hash),
                    save_failure,
                });
            }
            utils::Resolved::Partial(id, hash) => (id, hash),
            utils::Resolved::Missing => (None, None),
        };
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "Telegram API credentials are not configured.\n\
             Create an application at https://my.telegram.org (API development tools), then run\n\
             `teagarden configure`, or set TG_API_ID and TG_API_HASH, and run `teagarden auth login` again."
        );
    }

    println!("Telegram API credentials are needed once. Get them at https://my.telegram.org");
    println!("(\"API development tools\"). They are stored only on this computer.");
    let id = match api_id {
        Some(id) => id,
        None => {
            let raw = utils::prompt("API id:")?;
            raw.trim()
                .parse::<i32>()
                .map_err(|_| anyhow::anyhow!("the API id must be a number"))?
        }
    };
    let hash = match api_hash {
        Some(h) => zeroize::Zeroizing::new(h),
        None => {
            let h = utils::prompt_password("API hash (input hidden): ")?;
            let h = zeroize::Zeroizing::new(h.trim().to_string());
            utils::validate_api_hash(&h)?;
            h
        }
    };

    let save_failure = persist_api_settings(id, &hash);
    Ok(Credentials {
        api_id: id,
        api_hash: hash,
        save_failure,
    })
}

pub async fn login(api_id: Option<i32>, api_hash: Option<String>) -> Result<()> {
    let credentials = resolve_credentials(api_id, api_hash)?;
    #[cfg(test)]
    if LOGIN_TEST_SKIP_TELEGRAM.with(|skip| *skip.borrow()) {
        return Ok(());
    }
    let outcome = sign_in(credentials.api_id, &credentials.api_hash).await;
    match (outcome, credentials.save_failure) {
        // The session is usable, but the next command would not find the API
        // settings: that is an error, not something to bury in the output.
        (Ok(()), Some(failure)) => anyhow::bail!(
            "signed in, and the session is saved to {}, but the API settings were NOT saved: {failure}\n\
             Other commands cannot find them. Fix the problem above and run `teagarden configure`.",
            session_file_path().display()
        ),
        (outcome, _) => outcome,
    }
}

pub async fn login_qr(
    api_id: Option<i32>,
    api_hash: Option<String>,
    cloud_password_file: Option<PathBuf>,
) -> Result<()> {
    let credentials = resolve_credentials(api_id, api_hash)?;
    let flow = async {
        if let Some(dir) = session_file_path().parent() {
            teagarden_core::fsutil::ensure_private_dir(dir)?;
        }
        let config = TelegramConfig {
            api_id: credentials.api_id,
            api_hash: credentials.api_hash.to_string(),
            session_path: session_file_path().to_string_lossy().to_string(),
            ..Default::default()
        };
        let client = TelegramClient::new(config);
        match client.connect().await.map_err(utils::telegram_err)? {
            AuthState::NotAuthenticated => {}
            AuthState::Authenticated => {
                println!("Already authenticated.");
                return Ok(());
            }
            other => anyhow::bail!("unexpected auth state after connect: {other:?}"),
        }

        run_qr_login_transport(
            &client,
            cloud_password_file.as_deref(),
            std::time::Duration::from_secs(5),
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    };

    let result = tokio::select! {
        result = tokio::time::timeout(std::time::Duration::from_secs(300), flow) => {
            match result {
                Ok(result) => result,
                Err(_) => anyhow::bail!("QR login timed out after 5 minutes"),
            }
        }
        signal = tokio::signal::ctrl_c() => {
            signal.context("wait for Ctrl+C")?;
            println!("QR login cancelled.");
            Ok(())
        }
    };
    match (result, credentials.save_failure) {
        (Ok(()), Some(failure)) => anyhow::bail!(
            "signed in, and the session is saved to {}, but the API settings were NOT saved: {failure}\n\
             Other commands cannot find them. Fix the problem above and run `teagarden configure`.",
            session_file_path().display()
        ),
        (result, _) => result,
    }
}

#[async_trait::async_trait]
trait QrLoginTransport: Send + Sync {
    async fn export_token(&self) -> Result<teagarden_telegram::client::QrLoginToken>;
    async fn import_token(
        &self,
        dc_id: i32,
        token: &[u8],
    ) -> Result<teagarden_telegram::client::QrLoginToken>;
    async fn check_password(&self, password: &str) -> Result<()>;
    async fn save_session(&self) -> Result<()>;
}

#[async_trait::async_trait]
impl QrLoginTransport for TelegramClient {
    async fn export_token(&self) -> Result<teagarden_telegram::client::QrLoginToken> {
        self.export_qr_login_token()
            .await
            .map_err(utils::telegram_err)
    }

    async fn import_token(
        &self,
        dc_id: i32,
        token: &[u8],
    ) -> Result<teagarden_telegram::client::QrLoginToken> {
        self.import_qr_login_token(dc_id, token)
            .await
            .map_err(utils::telegram_err)
    }

    async fn check_password(&self, password: &str) -> Result<()> {
        self.check_qr_login_password(password)
            .await
            .map_err(utils::telegram_err)
    }

    async fn save_session(&self) -> Result<()> {
        TelegramClient::save_session(self)
            .await
            .map_err(utils::telegram_err)
    }
}

async fn run_qr_login_transport<T: QrLoginTransport>(
    transport: &T,
    password_file: Option<&Path>,
    poll_interval: std::time::Duration,
) -> Result<()> {
    use teagarden_telegram::client::QrLoginToken;
    let mut displayed_token = None::<Vec<u8>>;
    let mut current = None::<(i32, Vec<u8>)>;
    loop {
        let result = match current.take() {
            Some((dc_id, token)) => transport.import_token(dc_id, &token).await,
            None => transport.export_token().await,
        };
        let result = match result {
            Ok(result) => result,
            Err(error) if format!("{error:#}").contains("SESSION_PASSWORD_NEEDED") => {
                complete_qr_password(transport, password_file).await?;
                break;
            }
            Err(error) if format!("{error:#}").contains("AUTH_TOKEN_EXPIRED") => continue,
            Err(error) => return Err(error),
        };
        match result {
            QrLoginToken::Pending { token, expires: _ } => {
                if displayed_token.as_deref() != Some(token.as_slice()) {
                    let uri = login_uri(&token);
                    println!(
                        "Scan this QR code in Telegram: Settings → Devices → Link Desktop Device"
                    );
                    print_login_qr(&uri)?;
                    displayed_token = Some(token);
                }
                tokio::time::sleep(poll_interval).await;
                current = None;
            }
            QrLoginToken::Migrate { dc_id, token } => current = Some((dc_id, token)),
            QrLoginToken::Success => break,
        }
    }
    transport.save_session().await?;
    restrict_session_permissions(&session_file_path());
    println!("Authenticated successfully!");
    Ok(())
}

/// Longest secret accepted from a file or stdin. Telegram cloud passwords are
/// far shorter; the cap exists so the buffer never has to grow.
const MAX_SECRET_BYTES: usize = 4096;

/// Read a secret from `reader` straight into zeroizing storage and strip the
/// trailing line ending in place. The read is bounded and the buffer is
/// reserved beyond that bound up front, so it never reallocates: a
/// reallocation would free the earlier bytes without erasing them.
fn read_secret_trimmed(reader: impl std::io::Read) -> std::io::Result<Zeroizing<String>> {
    let mut value = Zeroizing::new(String::with_capacity(MAX_SECRET_BYTES + 64));
    let capacity = value.capacity();
    reader
        .take(MAX_SECRET_BYTES as u64 + 1)
        .read_to_string(&mut value)?;
    debug_assert_eq!(value.capacity(), capacity, "secret buffer reallocated");
    if value.len() > MAX_SECRET_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("secret input is longer than {MAX_SECRET_BYTES} bytes"),
        ));
    }
    let keep = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(keep);
    Ok(value)
}

async fn complete_qr_password<T: QrLoginTransport>(
    client: &T,
    password_file: Option<&Path>,
) -> Result<()> {
    use std::io::IsTerminal as _;
    for attempt in 1..=MAX_PASSWORD_ATTEMPTS {
        let password = match password_file {
            Some(path) if path == Path::new("-") => read_secret_trimmed(std::io::stdin())?,
            Some(path) => read_secret_trimmed(
                std::fs::File::open(path)
                    .with_context(|| format!("read cloud password file {}", path.display()))?,
            )
            .with_context(|| format!("read cloud password file {}", path.display()))?,
            None if std::io::stdin().is_terminal() => {
                println!("Telegram cloud password required.");
                utils::prompt_password("Enter your Telegram cloud password: ")?
            }
            None => anyhow::bail!(
                "Telegram cloud password required; rerun with --cloud-password-file PATH"
            ),
        };
        match client.check_password(&password).await {
            Ok(()) => return Ok(()),
            Err(error) if attempt < MAX_PASSWORD_ATTEMPTS => {
                println!(
                    "Cloud password check failed: {error}. {} attempt(s) remaining.",
                    MAX_PASSWORD_ATTEMPTS - attempt
                );
            }
            Err(error) => anyhow::bail!(
                "failed cloud password check after {MAX_PASSWORD_ATTEMPTS} attempts: {error}"
            ),
        }
    }
    anyhow::bail!("cloud password authentication failed")
}

pub async fn approve(uri: &str, yes: bool) -> Result<()> {
    use std::io::{IsTerminal as _, Write as _};
    println!("WARNING: approving this token gives the new computer full access to this Telegram account.");
    println!("Only approve a token when you started the login yourself.");
    anyhow::ensure!(
        uri != "-" || yes,
        "reading the approval URI from stdin requires --yes"
    );
    if !yes && !std::io::stdin().is_terminal() {
        anyhow::bail!("refusing to approve without a terminal; pass --yes in scripts");
    }
    if !yes {
        print!("Type YES to approve: ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !approval_confirmed(false, true, answer.trim()) {
            anyhow::bail!("approval refused");
        }
    }
    let stdin_uri;
    let uri = if uri == "-" {
        stdin_uri = read_approval_uri(std::io::stdin().lock())?;
        stdin_uri.trim()
    } else {
        uri
    };
    let token = decode_approval_token(uri)?;
    let credentials = resolve_credentials(None, None)?;
    let config = TelegramConfig {
        api_id: credentials.api_id,
        api_hash: credentials.api_hash.to_string(),
        session_path: session_file_path().to_string_lossy().to_string(),
        ..Default::default()
    };
    let client = TelegramClient::new(config);
    if client.connect().await.map_err(utils::telegram_err)? != AuthState::Authenticated {
        anyhow::bail!(
            "this computer is not logged in to Telegram; run `teagarden auth login` first"
        );
    }
    let authorization = client.accept_token(&token).await?;
    let output = approved_authorization_text(&authorization);
    println!("{output}");
    Ok(())
}

fn read_approval_uri(input: impl std::io::Read) -> Result<Zeroizing<String>> {
    const MAX_URI_BYTES: u64 = 4096;
    let mut uri = Zeroizing::new(String::new());
    input
        .take(MAX_URI_BYTES + 1)
        .read_to_string(&mut uri)
        .context("reading the login URI from stdin")?;
    anyhow::ensure!(
        uri.len() as u64 <= MAX_URI_BYTES,
        "login URI from stdin exceeds the size limit"
    );
    Ok(uri)
}

#[async_trait::async_trait]
trait QrApprovalTransport: Send + Sync {
    async fn accept_token(
        &self,
        token: &[u8],
    ) -> Result<teagarden_telegram::client::ApprovedAuthorization>;
}

#[async_trait::async_trait]
impl QrApprovalTransport for TelegramClient {
    async fn accept_token(
        &self,
        token: &[u8],
    ) -> Result<teagarden_telegram::client::ApprovedAuthorization> {
        self.accept_qr_login_token(token)
            .await
            .map_err(utils::telegram_err)
    }
}

#[cfg(test)]
async fn approve_with_transport<T: QrApprovalTransport>(
    uri: &str,
    confirmed: bool,
    transport: &T,
) -> Result<String> {
    anyhow::ensure!(confirmed, "approval refused");
    let token = decode_approval_token(uri)?;
    let authorization = transport.accept_token(&token).await?;
    Ok(approved_authorization_text(&authorization))
}

fn decode_approval_token(uri: &str) -> Result<Zeroizing<Vec<u8>>> {
    let encoded = uri
        .strip_prefix("tg://login?token=")
        .context("expected a tg://login?token=... URI")?;
    anyhow::ensure!(!encoded.is_empty(), "login token is empty");
    Ok(Zeroizing::new(
        Base64UrlUnpadded::decode_vec(encoded).context("login token is not valid base64url")?,
    ))
}

fn approval_confirmed(yes: bool, terminal: bool, answer: &str) -> bool {
    yes || (terminal && answer == "YES")
}

fn approved_authorization_text(
    authorization: &teagarden_telegram::client::ApprovedAuthorization,
) -> String {
    format!(
        "Approved authorization:\n  Hash: {}\n  Device model: {}\n  App: {}\n  IP: {}\n  Region: {}, {}",
        authorization.hash,
        authorization.device_model,
        authorization.app_name,
        authorization.ip,
        authorization.region,
        authorization.country
    )
}

async fn sign_in(api_id: i32, api_hash: &str) -> Result<()> {
    println!("Connecting to Telegram with API ID: {api_id}...");

    // The session file is written into the config directory; on a first login with
    // the API settings given as flags nothing else has created that directory yet.
    if let Some(dir) = session_file_path().parent() {
        teagarden_core::fsutil::ensure_private_dir(dir)?;
    }

    let config = TelegramConfig {
        api_id,
        api_hash: api_hash.to_string(),
        session_path: session_file_path().to_string_lossy().to_string(),
        ..Default::default()
    };

    let client = TelegramClient::new(config);
    let state = client.connect().await.map_err(utils::telegram_err)?;

    match state {
        AuthState::Authenticated => {
            println!("Already authenticated.");
            return Ok(());
        }
        AuthState::NotAuthenticated => {
            // Continue with interactive login below
        }
        _ => {
            anyhow::bail!("unexpected auth state after connect: {state:?}");
        }
    }

    // Step 1: Get phone number and request login code
    let phone = utils::prompt("Enter your phone number (with country code, e.g. +1234567890):")?;
    if phone.is_empty() {
        anyhow::bail!("phone number is required");
    }

    println!("Requesting login code...");
    let token = client
        .request_login_code(&phone)
        .await
        .map_err(utils::telegram_err)?;
    println!("{LOGIN_CODE_NOTICE}");

    // Step 2: Enter verification code (with retry)
    for attempt in 1..=MAX_CODE_ATTEMPTS {
        let code = utils::prompt("Enter the verification code:")?;
        if code.is_empty() {
            println!("Code cannot be empty.");
            continue;
        }

        match client.sign_in(&token, &code).await {
            Ok(AuthState::Authenticated) => {
                println!("Authenticated successfully!");
                return Ok(());
            }
            Ok(AuthState::AwaitingPassword) => {
                println!("2FA password required.");
                return handle_2fa(&client).await;
            }
            Err(e) => {
                let remaining = MAX_CODE_ATTEMPTS - attempt;
                if remaining > 0 {
                    println!("Invalid code: {e}. {remaining} attempt(s) remaining.");
                } else {
                    anyhow::bail!("failed to sign in after {MAX_CODE_ATTEMPTS} attempts: {e}");
                }
            }
            Ok(other) => {
                anyhow::bail!("unexpected auth state: {other:?}");
            }
        }
    }

    anyhow::bail!("authentication failed: max code attempts exceeded");
}

async fn handle_2fa(client: &TelegramClient) -> Result<()> {
    for attempt in 1..=MAX_PASSWORD_ATTEMPTS {
        let password = utils::prompt_password("Enter your 2FA password: ")?;
        if password.is_empty() {
            println!("Password cannot be empty.");
            continue;
        }

        match client.check_password(&password).await {
            Ok(AuthState::Authenticated) => {
                println!("Authenticated successfully!");
                return Ok(());
            }
            Err(e) => {
                let remaining = MAX_PASSWORD_ATTEMPTS - attempt;
                if remaining > 0 {
                    println!("Invalid password: {e}. {remaining} attempt(s) remaining.");
                } else {
                    anyhow::bail!("failed 2FA after {MAX_PASSWORD_ATTEMPTS} attempts: {e}");
                }
            }
            Ok(other) => {
                anyhow::bail!("unexpected auth state after 2FA: {other:?}");
            }
        }
    }

    anyhow::bail!("2FA authentication failed: max password attempts exceeded");
}

/// Returns the path to the Telegram session file in the config directory.
fn session_file_path() -> std::path::PathBuf {
    super::utils::session_file_path()
}

/// Set restrictive permissions (0600) on the session file (Unix only).
#[cfg(unix)]
fn restrict_session_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_session_permissions(_path: &std::path::Path) {}

pub async fn logout() -> Result<()> {
    println!("Removing Telegram session...");
    let session_path = session_file_path();
    if session_path.exists() {
        std::fs::remove_file(&session_path)?;
        println!("Session removed.");
    } else {
        // Also check legacy CWD location
        let legacy = std::path::Path::new("teagarden.session");
        if legacy.exists() {
            std::fs::remove_file(legacy)?;
            println!("Legacy session removed.");
        } else {
            println!("No session file found.");
        }
    }
    Ok(())
}

pub async fn status() -> Result<()> {
    print_status();
    Ok(())
}

fn print_status() {
    let session_path = session_file_path();
    if session_path.exists() {
        restrict_session_permissions(&session_path);
        println!("Session file exists: {}", session_path.display());
        println!("Status: session file present (connect to verify)");
    } else {
        println!("Not authenticated. Run `teagarden auth login` to connect.");
    }
}

// ---------------------------------------------------------------------------
// auth export / auth import: moving a Telegram login to another computer
// ---------------------------------------------------------------------------

const ENV_FILE: &str = ".env";
const GROUP_FILE: &str = "group.json";
const SESSION_FILE: &str = "teagarden.session";

/// `.env` keys that name a path on the computer that wrote them. They are left
/// out of an export and dropped on import: `main` loads the `.env` into the
/// environment on every run, so a foreign path here would send the next command
/// looking for the session in a place that does not exist on this computer.
const MACHINE_PATH_KEYS: &[&str] = &["TEAGARDEN_SESSION_PATH", "TEAGARDEN_VOLUMES_DIR"];

/// Largest file `auth import` reads. Real files are a few kilobytes.
const MAX_TRANSFER_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The schema version and tables of the session database
/// (`teagarden-telegram`'s `session.rs`, `SCHEMA_VERSION` and `create_schema`).
const SESSION_SCHEMA_VERSION: i64 = 1;
const SESSION_TABLES: [&str; 5] = [
    "dc_home",
    "dc_option",
    "peer_info",
    "update_state",
    "channel_state",
];

/// Where this computer keeps the files a login consists of.
struct LocalFiles {
    dir: PathBuf,
    env: PathBuf,
    group: PathBuf,
    session: PathBuf,
}

fn local_files() -> Result<LocalFiles> {
    let dir = auth_config_dir()?;
    Ok(LocalFiles {
        env: dir.join(ENV_FILE),
        group: dir.join(GROUP_FILE),
        session: auth_session_file_path(),
        dir,
    })
}

/// Check, by structure only, that `path` is a TeaGarden session database with a
/// completed sign-in: schema version, the five tables, and a non-empty
/// `peer_info` (sign-in stores the account there; a connected but signed-out
/// session has none). Opens read-only, so it never creates or changes anything,
/// and prints no value from the file.
fn check_session_db(path: &Path, label: &str) -> Result<()> {
    use rusqlite::{Connection, OpenFlags};
    let not_a_session = || anyhow::anyhow!("{label} is not a TeaGarden session file");
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| not_a_session())?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| not_a_session())?;
    anyhow::ensure!(
        version == SESSION_SCHEMA_VERSION,
        "{label} is not a session file this build reads: its schema version is {version}, \
         this build uses {SESSION_SCHEMA_VERSION}"
    );
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .and_then(|mut q| {
            q.query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|_| not_a_session())?;
    for table in SESSION_TABLES {
        anyhow::ensure!(
            tables.iter().any(|t| t == table),
            "{label} is not a TeaGarden session file: table `{table}` is missing"
        );
    }
    let signed_in: bool = db
        .query_row("SELECT EXISTS (SELECT 1 FROM peer_info)", [], |r| r.get(0))
        .map_err(|_| not_a_session())?;
    anyhow::ensure!(
        signed_in,
        "the session in {label} is not signed in (it holds no account); \
         run `teagarden auth login` on the computer it came from first"
    );
    Ok(())
}

/// Read one file of a transfer directory. A symbolic link, or anything that is
/// not a regular file, is refused; the open itself does not follow a link either,
/// so a link swapped in after the check is refused too. `None` when the file is
/// absent and not `required`.
fn read_transfer_file(
    dir: &Path,
    name: &str,
    required: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let path = dir.join(name);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::ensure!(
                !required,
                "{name} is missing from {}; `teagarden auth export` writes it",
                dir.display()
            );
            return Ok(None);
        }
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    anyhow::ensure!(
        !meta.file_type().is_symlink(),
        "{} is a symbolic link; a transfer directory holds regular files only",
        path.display()
    );
    anyhow::ensure!(meta.is_file(), "{} is not a regular file", path.display());
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        file.metadata()
            .with_context(|| format!("read {}", path.display()))?
            .is_file(),
        "{} is not a regular file",
        path.display()
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_TRANSFER_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_TRANSFER_FILE_BYTES,
        "{} is too large to be a TeaGarden file",
        path.display()
    );
    Ok(Some(bytes))
}

/// Create `path` (it must not exist) with mode 0600 whatever the umask, write
/// `bytes` and fsync. A failed write removes the file again.
fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    let result = (|| -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })()
    .with_context(|| format!("write {}", path.display()));
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// A new file next to `target`, ready to be renamed over it.
struct Staged {
    target: PathBuf,
    tmp: PathBuf,
}

/// Write `bytes` to a uniquely named sibling of `target` (mode 0600).
fn stage_file(target: &Path, bytes: &[u8]) -> Result<Staged> {
    use rand::RngCore as _;
    let name = target
        .file_name()
        .context("a config file path has no file name")?
        .to_string_lossy();
    let tmp = target.with_file_name(format!(
        ".{name}.import-{}-{:016x}",
        std::process::id(),
        rand::rngs::OsRng.next_u64()
    ));
    write_new_private(&tmp, bytes)?;
    Ok(Staged {
        target: target.to_path_buf(),
        tmp,
    })
}

/// Rename every staged file over its target, all or nothing.
///
/// A file that already exists is first hard-linked to a backup name, so the
/// rename that replaces it is atomic (a reader never sees the file missing). If
/// any step fails, the files already replaced are put back from their backups,
/// the ones that were new are removed, and every staged file and backup is
/// deleted. A rollback step that fails too is named in the error, with the path
/// that still holds the previous file.
fn install(staged: &[Staged]) -> Result<()> {
    let mut backups: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut placed: Vec<&Path> = Vec::new();
    match try_install(staged, &mut backups, &mut placed) {
        Ok(()) => {
            for (_, backup) in &backups {
                let _ = std::fs::remove_file(backup);
            }
            for dir in staged.iter().filter_map(|s| s.target.parent()) {
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all(); // best effort: the renames already landed
                }
            }
            Ok(())
        }
        Err(error) => {
            let mut stuck = Vec::new();
            for target in &placed {
                match backups.iter().find(|(t, _)| t == target) {
                    Some((t, backup)) => {
                        if let Err(e) = std::fs::rename(backup, t) {
                            stuck.push(format!(
                                "could not restore {}: {e}; the previous file is {}",
                                t.display(),
                                backup.display()
                            ));
                        }
                    }
                    None => {
                        let _ = std::fs::remove_file(target);
                    }
                }
            }
            for (target, backup) in &backups {
                if !placed.contains(&target.as_path()) {
                    let _ = std::fs::remove_file(backup);
                }
            }
            for s in staged {
                let _ = std::fs::remove_file(&s.tmp);
            }
            if stuck.is_empty() {
                Err(error)
            } else {
                Err(error.context(stuck.join("; ")))
            }
        }
    }
}

fn try_install<'a>(
    staged: &'a [Staged],
    backups: &mut Vec<(PathBuf, PathBuf)>,
    placed: &mut Vec<&'a Path>,
) -> Result<()> {
    use rand::RngCore as _;
    for s in staged {
        if std::fs::symlink_metadata(&s.target).is_ok() {
            let name = s
                .target
                .file_name()
                .context("a config file path has no file name")?
                .to_string_lossy();
            let backup = s.target.with_file_name(format!(
                ".{name}.previous-{}-{:016x}",
                std::process::id(),
                rand::rngs::OsRng.next_u64()
            ));
            std::fs::hard_link(&s.target, &backup)
                .with_context(|| format!("keep the previous {}", s.target.display()))?;
            backups.push((s.target.clone(), backup));
        }
    }
    for s in staged {
        std::fs::rename(&s.tmp, &s.target)
            .with_context(|| format!("install {}", s.target.display()))?;
        placed.push(&s.target);
    }
    Ok(())
}

/// `teagarden auth export <DIR>`: copy this computer's login into `dir`.
pub async fn export(dir: &Path) -> Result<()> {
    let local = local_files()?;
    export_login(&local, dir)
}

fn export_login(local: &LocalFiles, dir: &Path) -> Result<()> {
    // Everything is read and checked before DIR is touched.
    std::fs::metadata(&local.session).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "there is no Telegram session at {}; run `teagarden auth login` first",
                local.session.display()
            )
        } else {
            anyhow::Error::new(e).context(format!("read {}", local.session.display()))
        }
    })?;
    check_session_db(&local.session, "the session on this computer")?;
    let mut backup_builder = tempfile::Builder::new();
    backup_builder.prefix("teagarden-session-export-");
    #[cfg(unix)]
    backup_builder.permissions(std::fs::Permissions::from_mode(0o700));
    let backup_dir = backup_builder
        .tempdir()
        .context("create private temporary directory for session export")?;
    let backup_path = backup_dir.path().join("session.sqlite");
    let backup_result = (|| -> Result<Vec<u8>> {
        let source = rusqlite::Connection::open(&local.session)
            .with_context(|| format!("open session database {}", local.session.display()))?;
        source
            .execute("VACUUM INTO ?1", [backup_path.to_string_lossy().as_ref()])
            .context("create consistent SQLite session backup")?;
        #[cfg(unix)]
        std::fs::set_permissions(&backup_path, std::fs::Permissions::from_mode(0o600))
            .context("make temporary SQLite session backup private")?;
        #[cfg(test)]
        EXPORT_TEST_BACKUP.with(|backup| {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(&backup_path)
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0);
            let dir_mode = std::fs::metadata(backup_path.parent().unwrap())
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0);
            *backup.borrow_mut() = Some((backup_path.clone(), file_mode, dir_mode));
        });
        check_session_db(&backup_path, "the copied session")?;
        std::fs::read(&backup_path)
            .with_context(|| format!("read copied session {}", backup_path.display()))
    })();
    let session = backup_result?;
    let settings = match std::fs::read(&local.env) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
            "there are no API settings at {}; run `teagarden configure` first",
            local.env.display()
        ),
        Err(e) => return Err(e).with_context(|| format!("read {}", local.env.display())),
    };
    let settings = Zeroizing::new(super::configure::drop_keys(&settings, MACHINE_PATH_KEYS));
    let group = match std::fs::read(&local.group) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("read {}", local.group.display())),
    };

    let created = match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            anyhow::ensure!(
                !meta.file_type().is_symlink(),
                "{} is a symbolic link; name a real directory",
                dir.display()
            );
            anyhow::ensure!(meta.is_dir(), "{} is not a directory", dir.display());
            let mut entries = std::fs::read_dir(dir)
                .with_context(|| format!("read directory {}", dir.display()))?;
            anyhow::ensure!(
                entries.next().is_none(),
                "{} is not empty; name an empty or new directory",
                dir.display()
            );
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    };
    teagarden_core::fsutil::ensure_private_dir(dir)
        .with_context(|| format!("create {}", dir.display()))?;

    let mut files: Vec<(&str, &[u8])> = vec![(ENV_FILE, settings.as_slice())];
    if let Some(group) = &group {
        files.push((GROUP_FILE, group));
    }
    files.push((SESSION_FILE, &session));
    let mut written: Vec<PathBuf> = Vec::new();
    let result = files.iter().try_for_each(|(name, bytes)| {
        let path = dir.join(name);
        write_new_private(&path, bytes)?;
        written.push(path);
        Ok::<(), anyhow::Error>(())
    });
    if let Err(e) = result {
        for path in &written {
            let _ = std::fs::remove_file(path);
        }
        if created {
            let _ = std::fs::remove_dir(dir);
        }
        return Err(e);
    }

    println!("Exported the Telegram login to {}:", dir.display());
    for (name, _) in &files {
        println!("  {name}");
    }
    println!(
        "Left out of {ENV_FILE}: {} (paths on this computer).",
        MACHINE_PATH_KEYS.join(", ")
    );
    println!();
    println!(
        "WARNING: {} now holds the login to your Telegram account. Anyone who gets a copy can act as you on Telegram.",
        dir.display()
    );
    println!("The files are not encrypted. Move the directory to the other computer only over a");
    println!("channel you trust, run `teagarden auth import <DIR>` there, then delete it on both.");
    Ok(())
}

/// `teagarden auth import <DIR> [--force]`: install a login exported on another
/// computer, then show `auth status`.
pub async fn import(dir: &Path, force: bool) -> Result<()> {
    let local = local_files()?;
    import_login(dir, &local, force)?;
    println!("Imported the Telegram login from {}.", dir.display());
    println!(
        "Delete {} now: it holds the login to your Telegram account.",
        dir.display()
    );
    println!();
    print_status();
    Ok(())
}

fn import_login(dir: &Path, local: &LocalFiles, force: bool) -> Result<()> {
    let meta =
        std::fs::symlink_metadata(dir).with_context(|| format!("cannot read {}", dir.display()))?;
    anyhow::ensure!(
        !meta.file_type().is_symlink(),
        "{} is a symbolic link; name the real directory",
        dir.display()
    );
    anyhow::ensure!(meta.is_dir(), "{} is not a directory", dir.display());

    // Read and check everything before anything on this computer is touched.
    let settings =
        read_transfer_file(dir, ENV_FILE, true)?.context("the API settings are missing")?;
    let session =
        read_transfer_file(dir, SESSION_FILE, true)?.context("the session file is missing")?;
    let group = read_transfer_file(dir, GROUP_FILE, false)?;
    check_session_db(
        &dir.join(SESSION_FILE),
        "the session in the transfer directory",
    )?;

    let mut settings = Zeroizing::new(super::configure::drop_keys(&settings, MACHINE_PATH_KEYS));
    // The session goes where this computer looks for it. When that is not the
    // default place (TEAGARDEN_SESSION_PATH is set), the `.env` records it,
    // because later runs read the `.env` and not this shell's variables.
    if local.session != local.dir.join(SESSION_FILE) {
        let path = local
            .session
            .to_str()
            .context("the session path is not valid UTF-8")?;
        settings = Zeroizing::new(super::configure::merge_owned_keys(
            &settings,
            &[("TEAGARDEN_SESSION_PATH", path)],
        ));
    }

    // `--force` replaces this computer's `.env`; the volumes directory it names
    // belongs to this computer and is carried over, or its volumes would no
    // longer be found.
    if force {
        if let Ok(own) = std::fs::read(&local.env) {
            let own = Zeroizing::new(own);
            if let Some(volumes) = super::configure::env_value(&own, "TEAGARDEN_VOLUMES_DIR") {
                settings = Zeroizing::new(super::configure::merge_owned_keys(
                    &settings,
                    &[("TEAGARDEN_VOLUMES_DIR", volumes.as_str())],
                ));
            }
        }
    }

    let mut targets: Vec<(&Path, &[u8])> = vec![(&local.env, settings.as_slice())];
    if let Some(group) = &group {
        targets.push((&local.group, group));
    }
    targets.push((&local.session, &session));

    let mut existing = Vec::new();
    for (target, _) in &targets {
        match std::fs::symlink_metadata(target) {
            Ok(meta) if meta.file_type().is_file() => existing.push(target.display().to_string()),
            Ok(meta) => anyhow::bail!(
                "{} is not a regular file ({}); move it away first, nothing was changed",
                target.display(),
                if meta.file_type().is_symlink() {
                    "it is a symbolic link"
                } else {
                    "it is a directory or special file"
                }
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("read {}", target.display())),
        }
    }
    anyhow::ensure!(
        existing.is_empty() || force,
        "this computer already has:\n  {}\nNothing was changed. Run again with --force to replace them.",
        existing.join("\n  ")
    );

    let dir_created = !local.dir.exists();
    teagarden_core::fsutil::ensure_private_dir(&local.dir)
        .with_context(|| format!("create config directory {}", local.dir.display()))?;
    if let Some(parent) = local.session.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }

    let mut staged: Vec<Staged> = Vec::new();
    let result = (|| -> Result<()> {
        for (target, bytes) in &targets {
            staged.push(stage_file(target, bytes)?);
        }
        // The bytes about to be installed are the ones checked.
        let installed = staged.last().context("nothing was staged")?.tmp.as_path();
        check_session_db(installed, "the session in the transfer directory")?;
        install(&staged)
    })();
    if let Err(e) = result {
        for s in &staged {
            let _ = std::fs::remove_file(&s.tmp);
        }
        if dir_created {
            let _ = std::fs::remove_dir(&local.dir);
        }
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cloud password is read straight into zeroizing storage, trimmed in
    /// place (no copy), and keeps every byte except the line ending.
    #[test]
    fn secret_reader_trims_line_ending_in_place_without_reallocating() {
        let reserved = String::with_capacity(MAX_SECRET_BYTES + 64).capacity();
        let secret = read_secret_trimmed(&b"p\xc3\xa4ss word \r\n"[..]).unwrap();
        assert_eq!(secret.as_str(), "päss word ");
        assert_eq!(secret.capacity(), reserved, "buffer must not reallocate");
        let empty = read_secret_trimmed(&b"\n"[..]).unwrap();
        assert_eq!(empty.as_str(), "");
        // Exactly the limit is accepted without growing the buffer.
        let at_limit = vec![b'a'; MAX_SECRET_BYTES];
        let secret = read_secret_trimmed(&at_limit[..]).unwrap();
        assert_eq!(secret.len(), MAX_SECRET_BYTES);
        assert_eq!(secret.capacity(), reserved, "buffer must not reallocate");
        // Longer input is refused instead of growing the buffer.
        let too_long = vec![b'a'; MAX_SECRET_BYTES + 1];
        let err = read_secret_trimmed(&too_long[..]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// The notice must say where the code arrives. Telegram sends it as a message
    /// from "Telegram" inside the app on a device that is already signed in, and
    /// by SMS, call or Fragment otherwise; it is NOT "sent to your Telegram app"
    /// in every case, and `auth login` cannot see which one Telegram chose.
    #[test]
    fn login_code_notice_says_where_the_code_arrives() {
        assert!(
            LOGIN_CODE_NOTICE.contains("message from \"Telegram\""),
            "{LOGIN_CODE_NOTICE}"
        );
        assert!(LOGIN_CODE_NOTICE.contains("already signed in"));
        assert!(LOGIN_CODE_NOTICE.contains("SMS"));
        assert!(
            !LOGIN_CODE_NOTICE.contains("sent to your Telegram app"),
            "the old claim must be gone"
        );
    }

    #[tokio::test]
    async fn auth_login_persists_resolved_api_pair_and_keeps_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        TEST_CONFIG_DIR.with(|config| *config.borrow_mut() = Some(dir.path().to_path_buf()));
        std::fs::write(dir.path().join(ENV_FILE), "KEEP_ME=present\n").unwrap();
        LOGIN_TEST_SKIP_TELEGRAM.with(|skip| *skip.borrow_mut() = true);
        let result = login(
            Some(12345),
            Some("0123456789abcdef0123456789abcdef".to_owned()),
        )
        .await;
        LOGIN_TEST_SKIP_TELEGRAM.with(|skip| *skip.borrow_mut() = false);
        TEST_CONFIG_DIR.with(|config| *config.borrow_mut() = None);
        result.unwrap();
        let env = std::fs::read_to_string(dir.path().join(ENV_FILE)).unwrap();
        assert!(env.contains("TG_API_ID=12345\n"), "{env}");
        assert!(
            env.contains("TG_API_HASH=0123456789abcdef0123456789abcdef\n"),
            "{env}"
        );
        assert!(env.contains("KEEP_ME=present\n"), "{env}");
    }

    #[tokio::test]
    async fn auth_export_copies_a_consistent_sqlite_session_backup() {
        let dir = tempfile::tempdir().unwrap();
        TEST_CONFIG_DIR.with(|config| *config.borrow_mut() = Some(dir.path().to_path_buf()));
        std::fs::write(
            dir.path().join(ENV_FILE),
            "TG_API_ID=1\nTG_API_HASH=0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        let session_path = dir.path().join(SESSION_FILE);
        let db = rusqlite::Connection::open(&session_path).unwrap();
        db.pragma_update(None, "journal_mode", "WAL").unwrap();
        db.pragma_update(None, "user_version", SESSION_SCHEMA_VERSION)
            .unwrap();
        for table in SESSION_TABLES {
            db.execute_batch(&format!("CREATE TABLE {table}(value TEXT);"))
                .unwrap();
        }
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        db.execute("INSERT INTO peer_info(value) VALUES ('signed-in')", [])
            .unwrap();
        let out = dir.path().join("transfer");
        export(&out).await.unwrap();
        let exported = rusqlite::Connection::open(out.join(SESSION_FILE)).unwrap();
        let rows: i64 = exported
            .query_row("SELECT count(*) FROM peer_info", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "export must include committed WAL contents");
        drop(exported);
        drop(db);
        TEST_CONFIG_DIR.with(|config| *config.borrow_mut() = None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn auth_export_backup_is_private_under_umask_022_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        TEST_CONFIG_DIR.with(|config| *config.borrow_mut() = Some(dir.path().to_path_buf()));
        std::fs::write(
            dir.path().join(ENV_FILE),
            "TG_API_ID=1\nTG_API_HASH=0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        let session_path = dir.path().join(SESSION_FILE);
        let db = rusqlite::Connection::open(&session_path).unwrap();
        db.pragma_update(None, "user_version", SESSION_SCHEMA_VERSION)
            .unwrap();
        for table in SESSION_TABLES {
            db.execute_batch(&format!("CREATE TABLE {table}(value TEXT);"))
                .unwrap();
        }
        db.execute("INSERT INTO peer_info(value) VALUES ('signed-in')", [])
            .unwrap();
        EXPORT_TEST_BACKUP.with(|backup| *backup.borrow_mut() = None);

        let out = dir.path().join("transfer");
        export(&out).await.unwrap();
        let (backup, file_mode, directory_mode) = EXPORT_TEST_BACKUP
            .with(|backup| backup.borrow().clone())
            .unwrap();
        assert_eq!(file_mode, 0o600, "temporary SQLite backup must be private");
        assert_eq!(directory_mode, 0o700, "backup parent must be private");
        assert!(
            !backup.exists(),
            "temporary backup must be removed after export"
        );

        std::fs::remove_file(dir.path().join(ENV_FILE)).unwrap();
        EXPORT_TEST_BACKUP.with(|backup| *backup.borrow_mut() = None);
        assert!(export(&dir.path().join("failed-transfer")).await.is_err());
        let (failed_backup, _, _) = EXPORT_TEST_BACKUP
            .with(|backup| backup.borrow().clone())
            .unwrap();
        assert!(
            !failed_backup.exists(),
            "temporary backup must be removed after a later export failure"
        );

        drop(db);
        TEST_CONFIG_DIR.with(|config| *config.borrow_mut() = None);
        EXPORT_TEST_BACKUP.with(|backup| *backup.borrow_mut() = None);
    }

    #[cfg(unix)]
    #[test]
    fn saving_the_api_settings_writes_a_private_env_and_keeps_other_lines() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join("cfg").join(".env");
        save_api_settings(&env, 12345, "0123456789abcdef0123456789abcdef").unwrap();
        let text = std::fs::read_to_string(&env).unwrap();
        assert!(text.contains("TG_API_ID=12345\n"), "{text}");
        assert!(text.contains("TG_API_HASH=0123456789abcdef0123456789abcdef\n"));
        assert_eq!(
            std::fs::metadata(&env).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(env.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        // A second save replaces only our two lines.
        std::fs::write(
            &env,
            "# mine\nTELEGRAM_BOT_TOKEN_1=1:abcdefghijklmnopqrstuvwx\nTG_API_ID=1\nTG_API_HASH=x\n",
        )
        .unwrap();
        save_api_settings(&env, 777, "fedcba9876543210fedcba9876543210").unwrap();
        assert_eq!(
            std::fs::read_to_string(&env).unwrap(),
            "# mine\nTELEGRAM_BOT_TOKEN_1=1:abcdefghijklmnopqrstuvwx\nTG_API_ID=777\nTG_API_HASH=fedcba9876543210fedcba9876543210\n"
        );
    }

    #[test]
    fn saving_the_api_settings_reports_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join(".env");
        std::fs::create_dir(&env).unwrap(); // a directory where the file must go
        let err = save_api_settings(&env, 1, "0123456789abcdef0123456789abcdef").unwrap_err();
        assert!(format!("{err:#}").contains(".env"), "{err:#}");
        assert!(env.is_dir(), "the failed save must not disturb the path");
    }

    #[test]
    fn a_failed_install_puts_every_file_back() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        std::fs::write(p("a"), "old a").unwrap();
        std::fs::write(p("b"), "old b").unwrap();
        let a = stage_file(&p("a"), b"new a").unwrap();
        let b = stage_file(&p("b"), b"new b").unwrap();
        let c = stage_file(&p("c"), b"new c").unwrap();
        // The last file cannot be installed: its staged copy has vanished.
        std::fs::remove_file(&c.tmp).unwrap();

        let err = install(&[a, b, c]).unwrap_err();
        assert!(format!("{err:#}").contains("install"), "{err:#}");

        assert_eq!(std::fs::read_to_string(p("a")).unwrap(), "old a");
        assert_eq!(std::fs::read_to_string(p("b")).unwrap(), "old b");
        assert!(!p("c").exists());
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["a", "b"], "no temp or backup file may remain");
    }

    #[test]
    fn a_good_install_replaces_files_and_leaves_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        std::fs::write(p("a"), "old a").unwrap();
        let a = stage_file(&p("a"), b"new a").unwrap();
        let b = stage_file(&p("b"), b"new b").unwrap();
        install(&[a, b]).unwrap();
        assert_eq!(std::fs::read_to_string(p("a")).unwrap(), "new a");
        assert_eq!(std::fs::read_to_string(p("b")).unwrap(), "new b");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}

#[cfg(test)]
mod qr_login_spec_tests {
    use super::{
        approval_confirmed, approve_with_transport, approved_authorization_text,
        decode_approval_token, login_uri, read_approval_uri, run_qr_login_transport,
        QrApprovalTransport, QrLoginTransport,
    };
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;
    use teagarden_telegram::client::{ApprovedAuthorization, QrLoginToken};

    struct RecordingTransport {
        exports: Mutex<VecDeque<anyhow::Result<QrLoginToken>>>,
        imports: Mutex<VecDeque<anyhow::Result<QrLoginToken>>>,
        password_result: Mutex<Option<anyhow::Result<()>>>,
        calls: Mutex<Vec<String>>,
        export_delay: Duration,
        authorization: ApprovedAuthorization,
    }

    impl RecordingTransport {
        fn new(exports: Vec<anyhow::Result<QrLoginToken>>) -> Self {
            Self {
                exports: Mutex::new(exports.into()),
                imports: Mutex::new(VecDeque::new()),
                password_result: Mutex::new(None),
                calls: Mutex::new(Vec::new()),
                export_delay: Duration::ZERO,
                authorization: ApprovedAuthorization {
                    hash: 44,
                    device_model: "Linux PC".into(),
                    app_name: "TeaGarden".into(),
                    ip: "192.0.2.1".into(),
                    country: "US".into(),
                    region: "CA".into(),
                },
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl QrLoginTransport for RecordingTransport {
        async fn export_token(&self) -> anyhow::Result<QrLoginToken> {
            self.calls.lock().unwrap().push("export".into());
            if !self.export_delay.is_zero() {
                tokio::time::sleep(self.export_delay).await;
            }
            self.exports
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(anyhow::anyhow!("unexpected export")))
        }

        async fn import_token(&self, dc_id: i32, _token: &[u8]) -> anyhow::Result<QrLoginToken> {
            self.calls.lock().unwrap().push(format!("import:{dc_id}"));
            self.imports
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(anyhow::anyhow!("unexpected import")))
        }

        async fn check_password(&self, password: &str) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("password:{password}"));
            self.password_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow::anyhow!("unexpected password check")))
        }

        async fn save_session(&self) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push("save".into());
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl QrApprovalTransport for RecordingTransport {
        async fn accept_token(&self, token: &[u8]) -> anyhow::Result<ApprovedAuthorization> {
            assert_eq!(token, [0xfb, 0xff]);
            self.calls.lock().unwrap().push("accept".into());
            Ok(ApprovedAuthorization {
                hash: self.authorization.hash,
                device_model: self.authorization.device_model.clone(),
                app_name: self.authorization.app_name.clone(),
                ip: self.authorization.ip.clone(),
                country: self.authorization.country.clone(),
                region: self.authorization.region.clone(),
            })
        }
    }

    #[test]
    fn login_uri_uses_unpadded_base64url() {
        assert_eq!(login_uri(&[0xfb, 0xff]), "tg://login?token=-_8");
    }

    #[test]
    fn approval_requires_exact_yes_or_script_flag() {
        assert!(!approval_confirmed(false, false, "YES"));
        assert!(!approval_confirmed(false, true, "yes"));
        assert!(!approval_confirmed(false, true, "NO"));
        assert!(approval_confirmed(false, true, "YES"));
        assert!(approval_confirmed(true, false, ""));
    }

    #[test]
    fn approval_stdin_accepts_one_bounded_uri() {
        let uri = read_approval_uri(&b"tg://login?token=YWJj\n"[..]).unwrap();
        assert_eq!(&**decode_approval_token(uri.trim()).unwrap(), b"abc");
        let extra =
            read_approval_uri(&b"tg://login?token=YWJj\ntg://login?token=YWJj\n"[..]).unwrap();
        assert!(decode_approval_token(extra.trim()).is_err());
        let oversized = vec![b'a'; 4097];
        assert!(read_approval_uri(oversized.as_slice()).is_err());
    }

    #[test]
    fn approval_prints_authorization_details_without_a_token() {
        let text = approved_authorization_text(&ApprovedAuthorization {
            hash: 44,
            device_model: "Linux PC".into(),
            app_name: "TeaGarden".into(),
            ip: "192.0.2.1".into(),
            country: "US".into(),
            region: "CA".into(),
        });
        assert!(text.contains("Hash: 44"));
        assert!(text.contains("Device model: Linux PC"));
        assert!(text.contains("App: TeaGarden"));
        assert!(text.contains("IP: 192.0.2.1"));
        assert!(!text.contains("token"));
    }

    #[tokio::test]
    async fn login_qr_records_initial_token_pending_and_success() {
        let transport = RecordingTransport::new(vec![
            Ok(QrLoginToken::Pending {
                token: b"test-token".to_vec(),
                expires: i32::MAX,
            }),
            Ok(QrLoginToken::Pending {
                token: b"test-token".to_vec(),
                expires: i32::MAX,
            }),
            Ok(QrLoginToken::Success),
        ]);
        run_qr_login_transport(&transport, None, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(transport.calls(), ["export", "export", "export", "save"]);
    }

    #[tokio::test]
    async fn login_qr_imports_a_migrated_token_and_completes() {
        let transport = RecordingTransport::new(vec![Ok(QrLoginToken::Migrate {
            dc_id: 4,
            token: b"migrated".to_vec(),
        })]);
        transport
            .imports
            .lock()
            .unwrap()
            .push_back(Ok(QrLoginToken::Success));
        run_qr_login_transport(&transport, None, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(transport.calls(), ["export", "import:4", "save"]);
    }

    #[tokio::test]
    async fn login_qr_checks_the_cloud_password_after_password_needed() {
        let transport =
            RecordingTransport::new(vec![Err(anyhow::anyhow!("SESSION_PASSWORD_NEEDED"))]);
        *transport.password_result.lock().unwrap() = Some(Ok(()));
        let password_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(password_file.path(), "cloud-password\n").unwrap();
        run_qr_login_transport(&transport, Some(password_file.path()), Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            transport.calls(),
            ["export", "password:cloud-password", "save"]
        );
    }

    #[tokio::test]
    async fn login_qr_reexports_after_an_expired_token() {
        let transport = RecordingTransport::new(vec![
            Err(anyhow::anyhow!("AUTH_TOKEN_EXPIRED")),
            Ok(QrLoginToken::Pending {
                token: b"refreshed".to_vec(),
                expires: i32::MAX,
            }),
            Ok(QrLoginToken::Success),
        ]);
        run_qr_login_transport(&transport, None, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(transport.calls(), ["export", "export", "export", "save"]);
    }

    #[tokio::test]
    async fn login_qr_timeout_cancels_a_slow_transport() {
        let mut transport = RecordingTransport::new(vec![Ok(QrLoginToken::Pending {
            token: b"test-token".to_vec(),
            expires: i32::MAX,
        })]);
        transport.export_delay = Duration::from_millis(100);
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            run_qr_login_transport(&transport, None, Duration::ZERO)
        )
        .await
        .is_err());
        assert_eq!(transport.calls(), ["export"]);
    }

    #[tokio::test]
    async fn approval_without_confirmation_makes_no_rpc() {
        let transport = RecordingTransport::new(Vec::new());
        let error = approve_with_transport("tg://login?token=-_8", false, &transport)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("approval refused"));
        assert!(transport.calls().is_empty());
    }

    #[tokio::test]
    async fn approval_with_confirmation_calls_accept_and_returns_details() {
        let transport = RecordingTransport::new(Vec::new());
        let output = approve_with_transport("tg://login?token=-_8", true, &transport)
            .await
            .unwrap();
        assert_eq!(transport.calls(), ["accept"]);
        assert!(output.contains("Hash: 44"));
        assert!(output.contains("Device model: Linux PC"));
        assert!(output.contains("App: TeaGarden"));
        assert!(output.contains("IP: 192.0.2.1"));
        assert!(!output.contains("token"));
    }
}
