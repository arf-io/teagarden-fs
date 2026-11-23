use std::collections::VecDeque;
use std::io::Read;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use grammers_client::client::{
    ClientConfiguration, LoginToken as GrammersLoginToken, PasswordToken, RetryContext,
    RetryPolicy, UpdateStream, UpdatesConfiguration,
};
use grammers_client::peer::{Peer, User};
use grammers_client::{Client, SenderPool, SignInError};
use grammers_mtsender::InvocationError;
use grammers_session::types::{PeerAuth, PeerId, PeerInfo, PeerRef};
use grammers_session::Session as _;
use grammers_tl_types as tl;
use tokio::sync::{Mutex, Semaphore};

/// Capped retry policy for transient Telegram transport failures.
///
/// Prevents the tight reconnect loop (100% CPU, zero I/O) observed after an
/// interrupted write (e.g. SIGKILL during rsync).  Backs off 1s → 2s → 4s → …
/// capped at 60s, and gives up after 15 consecutive failures so the FUSE layer
/// can surface a hard error instead of spinning forever. Permanent RPC,
/// authentication, serialization, and session failures are never retried.
struct BackoffRetryPolicy;
// Parts handle their own idle deadlines, retries and server-directed waits.
struct PartRetryPolicy;
impl RetryPolicy for PartRetryPolicy {
    fn should_retry(&self, _: &RetryContext) -> ControlFlow<(), Duration> {
        ControlFlow::Break(())
    }
}

impl RetryPolicy for BackoffRetryPolicy {
    fn should_retry(&self, context: &RetryContext) -> ControlFlow<(), Duration> {
        let attempt = context.fail_count.get();
        match &context.error {
            InvocationError::Rpc(error) if error.code == 420 && attempt == 1 => error
                .value
                .filter(|value| *value <= 60)
                .map_or(ControlFlow::Break(()), |value| {
                    ControlFlow::Continue(Duration::from_secs(value.into()))
                }),
            InvocationError::Io(_) | InvocationError::Transport(_) if attempt < 15 => {
                // 1s, 2s, 4s, 8s, 16s, 32s, 60s cap.
                let secs = 1u64 << (attempt.saturating_sub(1).min(6));
                ControlFlow::Continue(Duration::from_secs(secs.min(60)))
            }
            _ => ControlFlow::Break(()),
        }
    }
}

use crate::error::{Result, TelegramError};
use crate::session::SqliteSession;
use crate::types::{
    AuthState, DocumentInfo, DownloadResult, TelegramConfig, TopicDocumentPage, TransportStats,
    UploadResult,
};

/// Trait abstracting Telegram transport operations.
/// This allows mocking in tests and potentially swapping backends.
#[async_trait::async_trait]
pub trait BlockTransport: Send + Sync {
    /// Upload encrypted block data, returns the message ID.
    async fn upload_block(&self, data: &[u8], filename: &str) -> Result<UploadResult>;

    /// Upload one complete TGFV file object through the primary user MTProto session.
    /// Multi-session implementations must not route large file objects through Bot API.
    async fn upload_file_object(&self, data: &[u8], filename: &str) -> Result<UploadResult> {
        self.upload_block(data, filename).await
    }

    /// Upload directly from the sole local spool, with a deadline on each part.
    /// A compatibility transport may handle a single-part source; large sources
    /// require the streaming implementation and must never be collected in RAM.
    async fn upload_file_source(
        &self,
        source: &mut (dyn crate::transfer::UploadSource + '_),
        filename: &str,
        part_timeout: Duration,
    ) -> Result<UploadResult> {
        let size = usize::try_from(source.size())
            .map_err(|_| TelegramError::Upload("source too large".into()))?;
        if size > crate::transfer::UPLOAD_PART_BYTES {
            return Err(TelegramError::Upload(
                "transport does not implement streamed file objects".into(),
            ));
        }
        let mut bytes = vec![0; size];
        std::io::Read::read_exact(source, &mut bytes)?;
        let mut extra = [0; 1];
        if std::io::Read::read(source, &mut extra)? != 0 {
            return Err(TelegramError::Upload("overlong source".into()));
        }
        let result = tokio::time::timeout(part_timeout, self.upload_file_object(&bytes, filename))
            .await
            .map_err(|_| TelegramError::Timeout)??;
        source.acknowledge(0)?;
        Ok(result)
    }

    /// Whether this transport represents a Premium Telegram user account.
    async fn is_premium_user(&self) -> Result<bool> {
        Ok(false)
    }

    /// Telegram account user id for this authenticated user session, if available.
    async fn telegram_user_id(&self) -> Result<Option<i64>> {
        Ok(None)
    }

    /// Download block data by message ID.
    async fn download_block(&self, message_id: i64) -> Result<DownloadResult>;

    /// List document messages in exactly one forum group and topic, newest first.
    /// `before_message_id` is an exclusive descending cursor; the page size is
    /// capped at 100 by every implementation.
    async fn list_topic_documents(
        &self,
        group_id: i64,
        topic_id: i64,
        before_message_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<DocumentInfo>>;

    /// List a bounded, descending raw-message page from one forum topic.
    /// `min_message_id` and `max_message_id` are exclusive bounds; `offset_id`
    /// is an exclusive descending cursor. Document metadata is included for
    /// object messages while raw IDs also include text and service messages.
    async fn list_topic_page(
        &self,
        group_id: i64,
        topic_id: i64,
        min_message_id: Option<i64>,
        max_message_id: Option<i64>,
        offset_id: Option<i64>,
        limit: usize,
    ) -> Result<TopicDocumentPage> {
        let mut documents = self
            .list_topic_documents(group_id, topic_id, offset_id, limit)
            .await?;
        documents.retain(|document| {
            min_message_id.is_none_or(|min| document.message_id > min)
                && max_message_id.is_none_or(|max| document.message_id < max)
        });
        let raw_message_ids = documents
            .iter()
            .map(|document| document.message_id)
            .collect();
        let exhausted = documents.len() < limit.min(100);
        Ok(TopicDocumentPage {
            documents,
            raw_message_ids,
            exhausted,
        })
    }

    /// Download a byte RANGE `[offset, offset+len)` of the document in
    /// `message_id` (returns fewer bytes only at end-of-file). Real transports
    /// stitch across Telegram's 1 MiB `upload.GetFile` boundary; the mock slices
    /// its stored blob; bot-API transports (upload-only) return an error. This is
    /// the primitive the `teagarden-dev` block device reads segments through.
    async fn download_range(&self, message_id: i64, offset: u64, len: u32) -> Result<Vec<u8>>;

    /// Download the LAST `min(len, document_size)` bytes of the document in
    /// `message_id`. The block-device ranged read path bootstraps a segment from
    /// its tail (…‖index‖trailer‖MAC — all parseable relative to the buffer
    /// end), so the caller never needs to know the document size. REQUIRED (no
    /// whole-download default): a silent full fetch here would defeat the read-
    /// amplification contract exactly like G17's `download_range` fallback.
    async fn download_tail(&self, message_id: i64, len: u32) -> Result<Vec<u8>>;

    /// Delete a message (block) by ID.
    async fn delete_message(&self, message_id: i64) -> Result<()>;

    /// Delete multiple messages in batch.
    async fn delete_messages(&self, message_ids: &[i64]) -> Result<()>;

    /// Check if connected and authenticated.
    fn is_connected(&self) -> bool;

    /// Upload metadata snapshot bytes, returns message ID.
    async fn sync_metadata(&self, data: &[u8]) -> Result<i64>;

    /// Download metadata snapshot by message ID.
    async fn fetch_metadata(&self, message_id: i64) -> Result<Vec<u8>>;

    /// Return (group_id, group_access_hash, topic_id) if forum storage is configured.
    fn channel_ref(&self) -> Option<(i64, i64, i64)>;
}

/// Forum administration on the user's own session: the shared storage group and
/// one topic per volume or device. Separate from [`BlockTransport`] because only
/// the user's MTProto session can do this (bot sessions only post documents), and
/// so the CLI's create/delete paths can be driven by the test transport.
#[async_trait::async_trait]
pub trait ForumAdmin: BlockTransport + Send + Sync {
    /// Select the `(group, topic)` used by subsequent document uploads on this session.
    fn select_topic(&self, group_id: i64, access_hash: i64, topic_id: i64) -> Result<()>;

    /// Create the shared forum supergroup; returns `(group_id, group_access_hash)`.
    async fn create_forum_group(&self, title: &str) -> Result<(i64, i64)>;

    /// Create a topic in the group; returns its topic id (root message id).
    async fn create_topic(&self, group_id: i64, group_access_hash: i64, title: &str)
        -> Result<i64>;

    /// Delete a topic and every message in it (all blocks, metadata snapshots,
    /// journal entries and checkpoints posted there). Refuses the group's
    /// General topic (id 1) and anything below it.
    async fn delete_topic(
        &self,
        group_id: i64,
        group_access_hash: i64,
        topic_id: i64,
    ) -> Result<()>;

    /// Ban a member from the shared supergroup using MTProto `channels.editBanned`.
    async fn ban_group_member(&self, group_id: i64, access_hash: i64, user_id: i64) -> Result<()>;

    /// Terminate one authorization using MTProto `account.resetAuthorization`.
    async fn reset_authorization(&self, authorization_hash: i64) -> Result<()>;

    /// Terminate every other authorization using MTProto `auth.resetAuthorizations`.
    async fn reset_other_authorizations(&self) -> Result<()>;

    /// Return the hash marked `current` by MTProto `account.getAuthorizations`.
    async fn current_authorization_hash(&self) -> Result<Option<i64>>;

    /// Return Telegram authorizations with non-secret display metadata.
    async fn authorizations(&self) -> Result<Vec<TelegramAuthorizationInfo>>;
}

/// Safe, display-only Telegram authorization information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramAuthorizationInfo {
    /// Session hash used by `account.resetAuthorization`.
    pub hash: i64,
    /// Whether this is the current authorization.
    pub current: bool,
    /// Telegram's device model label.
    pub device_model: String,
    /// Telegram application name.
    pub app_name: String,
    /// Unix timestamp of last activity.
    pub date_active: i32,
}

/// Largest metadata snapshot (encrypted bytes) this client will upload.
///
/// Snapshots always travel over the user's MTProto session: `MultiTransport`
/// routes `sync_metadata` to session 0, and bot sessions never carry them. An
/// MTProto document is at most `upload_max_fileparts_default` parts (4000 for an
/// account without Premium, Telegram appConfig) of at most 512 KiB, the part
/// size this uploader always uses: 4000 x 524288 = 2,097,152,000 bytes (2000
/// MiB). Premium raises the part count to 8000; this client does not read
/// appConfig, so it stays at the limit every account has.
pub const MAX_METADATA_UPLOAD_BYTES: usize = 4000 * UPLOAD_CHUNK_SIZE;

/// Refuse a metadata snapshot larger than [`MAX_METADATA_UPLOAD_BYTES`].
pub fn check_metadata_size(len: usize) -> Result<()> {
    if len > MAX_METADATA_UPLOAD_BYTES {
        return Err(TelegramError::BlockTooLarge {
            size: len,
            max: MAX_METADATA_UPLOAD_BYTES,
        });
    }
    Ok(())
}

/// Account document cap used by the actual portable-object uploader.
pub fn file_object_upload_limit(premium: bool) -> usize {
    if premium {
        2 * MAX_METADATA_UPLOAD_BYTES
    } else {
        MAX_METADATA_UPLOAD_BYTES
    }
}

/// Apply the production portable-object cap without allocating a payload.
pub fn check_file_object_size(len: usize, premium: bool) -> Result<()> {
    let max = file_object_upload_limit(premium);
    if len > max {
        return Err(TelegramError::BlockTooLarge { size: len, max });
    }
    Ok(())
}

/// Upper bound on `messages.deleteTopicHistory` round-trips for one topic. Each
/// call deletes a batch and reports a positive `offset` while more remain; the
/// bound only stops a server that never reaches zero from looping forever.
const DELETE_TOPIC_MAX_ROUNDS: usize = 100_000;

/// Production Telegram client using grammers.
pub struct TelegramClient {
    config: TelegramConfig,
    upload_semaphore: Arc<Semaphore>,
    download_semaphore: Arc<Semaphore>,
    stats: Arc<TransportStatsInner>,
    connected: std::sync::atomic::AtomicBool,
    /// Cached Premium status, refreshed from `users.getFullUser`.
    premium_cache: AtomicBool,
    /// The actual grammers client, set after connect().
    inner: Mutex<Option<Client>>,
    // A retry-policy view of the same SenderPool, never a second sender/connection.
    part_client: Mutex<Option<Client>>,
    /// Session storage retained so a QR login can set the account's home DC.
    session: Mutex<Option<Arc<SqliteSession>>>,
    /// The single ordered update stream attached to this client's sender pool.
    /// Nothing reads it any more (only the removed BotFather dialog did); it is
    /// held so the connection keeps the stream it was created with.
    _updates: Mutex<Option<UpdateStream>>,
    /// Cached password token from sign_in() for 2FA flow.
    password_token: Mutex<Option<PasswordToken>>,
    /// Cached authenticated user (avoids repeated get_me() calls).
    #[allow(dead_code)]
    me_cache: Mutex<Option<User>>,
    /// Cached forum storage location: (group_id, group_access_hash, topic_id).
    channel_cache: Mutex<Option<(i64, i64, i64)>>,
    /// Unix timestamp (seconds) of the last successful block upload.  Zero means never.
    last_upload_ok: AtomicU64,
    /// Rolling window of recent upload timestamps (Unix seconds) for per-session rate tracking.
    upload_timestamps: Mutex<VecDeque<u64>>,
}

/// The result of Telegram's QR login token exchange.
pub enum QrLoginToken {
    /// A token that must be shown to the user and polled until expiry.
    Pending {
        /// Opaque Telegram login token bytes.
        token: Vec<u8>,
        /// Unix timestamp at which Telegram expires this token.
        expires: i32,
    },
    /// Telegram requires the import request to be sent to another DC.
    Migrate {
        /// Telegram datacenter id for the import request.
        dc_id: i32,
        /// Opaque token bytes returned by Telegram.
        token: Vec<u8>,
    },
    /// The new session has been authorized.
    Success,
}

/// Public, non-secret details returned after a login token is approved.
pub struct ApprovedAuthorization {
    /// Authorization hash used by Telegram to identify this session.
    pub hash: i64,
    /// Device model reported by Telegram.
    pub device_model: String,
    /// Application name reported by Telegram.
    pub app_name: String,
    /// IP address reported by Telegram.
    pub ip: String,
    /// Country reported by Telegram.
    pub country: String,
    /// Region reported by Telegram.
    pub region: String,
}

struct TransportStatsInner {
    blocks_uploaded: AtomicU64,
    blocks_downloaded: AtomicU64,
    bytes_uploaded: AtomicU64,
    bytes_downloaded: AtomicU64,
    upload_errors: AtomicU64,
    download_errors: AtomicU64,
    messages_deleted: AtomicU64,
}

impl TransportStatsInner {
    fn new() -> Self {
        Self {
            blocks_uploaded: AtomicU64::new(0),
            blocks_downloaded: AtomicU64::new(0),
            bytes_uploaded: AtomicU64::new(0),
            bytes_downloaded: AtomicU64::new(0),
            upload_errors: AtomicU64::new(0),
            download_errors: AtomicU64::new(0),
            messages_deleted: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> TransportStats {
        TransportStats {
            blocks_uploaded: self.blocks_uploaded.load(Ordering::Relaxed),
            blocks_downloaded: self.blocks_downloaded.load(Ordering::Relaxed),
            bytes_uploaded: self.bytes_uploaded.load(Ordering::Relaxed),
            bytes_downloaded: self.bytes_downloaded.load(Ordering::Relaxed),
            upload_errors: self.upload_errors.load(Ordering::Relaxed),
            download_errors: self.download_errors.load(Ordering::Relaxed),
            messages_deleted: self.messages_deleted.load(Ordering::Relaxed),
        }
    }
}

impl TelegramClient {
    async fn cache_qr_authorization(
        &self,
        authorization: &tl::enums::auth::Authorization,
    ) -> Result<()> {
        let tl::enums::auth::Authorization::Authorization(value) = authorization else {
            return Err(TelegramError::Api(
                "Telegram requires sign-up to complete this QR login".into(),
            ));
        };
        let tl::enums::User::User(user) = &value.user else {
            return Err(TelegramError::Api(
                "Telegram omitted the account user from QR login authorization".into(),
            ));
        };
        let access_hash = user
            .access_hash
            .ok_or_else(|| TelegramError::Api("Telegram omitted the account access hash".into()))?;
        let session = self
            .session
            .lock()
            .await
            .clone()
            .ok_or(TelegramError::NotConnected)?;
        session
            .cache_peer(&PeerInfo::User {
                id: user.id,
                auth: Some(PeerAuth::from_hash(access_hash)),
                bot: Some(user.bot),
                is_self: Some(true),
            })
            .await
            .map_err(|e| TelegramError::Session(format!("cache QR login authorization: {e}")))?;
        Ok(())
    }

    /// Create a new Telegram client with the given config.
    /// Does NOT connect - call `connect()` separately.
    pub fn new(config: TelegramConfig) -> Self {
        let upload_semaphore = Arc::new(Semaphore::new(config.max_concurrent_uploads));
        let download_semaphore = Arc::new(Semaphore::new(config.max_concurrent_downloads));

        // Pre-populate forum storage cache from config if available.
        let initial_channel = config
            .channel_ref
            .as_ref()
            .map(|ch| (ch.id, ch.access_hash, ch.topic_id));

        Self {
            config,
            upload_semaphore,
            download_semaphore,
            stats: Arc::new(TransportStatsInner::new()),
            connected: std::sync::atomic::AtomicBool::new(false),
            premium_cache: AtomicBool::new(false),
            inner: Mutex::new(None),
            part_client: Mutex::new(None),
            session: Mutex::new(None),
            _updates: Mutex::new(None),
            password_token: Mutex::new(None),
            me_cache: Mutex::new(None),
            channel_cache: Mutex::new(initial_channel),
            last_upload_ok: AtomicU64::new(0),
            upload_timestamps: Mutex::new(VecDeque::new()),
        }
    }

    fn reject_legacy_session_file(&self) -> Result<()> {
        let path = std::path::Path::new(&self.config.session_path);
        let Ok(metadata) = path.metadata() else {
            return Ok(());
        };
        if metadata.len() == 0 {
            return Ok(());
        }

        let mut file = std::fs::File::open(path)
            .map_err(|e| TelegramError::Session(format!("inspect session: {e}")))?;
        let mut header = [0u8; 16];
        let count = file
            .read(&mut header)
            .map_err(|e| TelegramError::Session(format!("inspect session: {e}")))?;
        if count != header.len() || &header != b"SQLite format 3\0" {
            return Err(TelegramError::Session(format!(
                "{} is a pre-1.0 Grammers session; preserve or rename it, then authenticate once to create the 1.0 SQLite session",
                path.display()
            )));
        }
        Ok(())
    }

    async fn create_client(&self) -> Result<(Client, UpdateStream)> {
        self.reject_legacy_session_file()?;
        let session = Arc::new(
            SqliteSession::open(&self.config.session_path)
                .map_err(|e| TelegramError::Session(format!("open SQLite session: {e}")))?,
        );
        *self.session.lock().await = Some(Arc::clone(&session));
        let SenderPool {
            runner,
            updates,
            handle,
        } = SenderPool::new(session, self.config.api_id);
        let part_client = Client::with_configuration(
            handle.clone(),
            ClientConfiguration {
                retry_policy: Box::new(PartRetryPolicy),
                ..Default::default()
            },
        );
        *self.part_client.lock().await = Some(part_client);
        let client = Client::with_configuration(
            handle,
            ClientConfiguration {
                retry_policy: Box::new(BackoffRetryPolicy),
                ..Default::default()
            },
        );
        tokio::spawn(runner.run());
        let updates = client
            .stream_updates(updates, UpdatesConfiguration::default())
            .await
            .map_err(|e| TelegramError::Api(format!("initialize update stream: {e}")))?;
        Ok((client, updates))
    }

    /// Connect to Telegram and restore session if available.
    pub async fn connect(&self) -> Result<AuthState> {
        tracing::info!("Connecting to Telegram...");
        let (client, updates) = self.create_client().await?;

        let authorized = client
            .is_authorized()
            .await
            .map_err(|e| TelegramError::Api(format!("auth check: {e}")))?;

        if authorized {
            self.connected.store(true, Ordering::SeqCst);
            *self._updates.lock().await = Some(updates);
            *self.inner.lock().await = Some(client);
            tracing::info!("Telegram: already authenticated");
            Ok(AuthState::Authenticated)
        } else {
            *self._updates.lock().await = Some(updates);
            *self.inner.lock().await = Some(client);
            tracing::info!("Telegram: authentication required");
            Ok(AuthState::NotAuthenticated)
        }
    }

    /// Request a login code to be sent to the phone number.
    pub async fn request_login_code(&self, phone: &str) -> Result<LoginToken> {
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?;

        let token = client
            .request_login_code(phone, &self.config.api_hash)
            .await
            .map_err(|e| TelegramError::Api(format!("request code: {e}")))?;

        Ok(LoginToken { inner: token })
    }

    /// Export a Telegram QR login token using the pinned TL schema.
    pub async fn export_qr_login_token(&self) -> Result<QrLoginToken> {
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?;
        let result: tl::enums::auth::LoginToken = client
            .invoke(&tl::functions::auth::ExportLoginToken {
                api_id: self.config.api_id,
                api_hash: self.config.api_hash.clone(),
                except_ids: Vec::new(),
            })
            .await
            .map_err(|e| TelegramError::Api(format!("auth.exportLoginToken: {e}")))?;
        match result {
            tl::enums::auth::LoginToken::Token(value) => Ok(QrLoginToken::Pending {
                token: value.token,
                expires: value.expires,
            }),
            tl::enums::auth::LoginToken::MigrateTo(value) => Ok(QrLoginToken::Migrate {
                dc_id: value.dc_id,
                token: value.token,
            }),
            tl::enums::auth::LoginToken::Success(value) => {
                self.cache_qr_authorization(&value.authorization).await?;
                self.connected.store(true, Ordering::SeqCst);
                self.save_session_inner().await?;
                Ok(QrLoginToken::Success)
            }
        }
    }

    /// Import a QR login token in Telegram's requested datacenter.
    pub async fn import_qr_login_token(&self, dc_id: i32, token: &[u8]) -> Result<QrLoginToken> {
        if let Some(session) = self.session.lock().await.as_ref() {
            session
                .set_home_dc_id(dc_id)
                .await
                .map_err(|e| TelegramError::Session(format!("set QR login home DC: {e}")))?;
        }
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?;
        let result: tl::enums::auth::LoginToken = client
            .invoke_in_dc(
                dc_id,
                &tl::functions::auth::ImportLoginToken {
                    token: token.to_vec(),
                },
            )
            .await
            .map_err(|e| TelegramError::Api(format!("auth.importLoginToken: {e}")))?;
        match result {
            tl::enums::auth::LoginToken::Token(value) => Ok(QrLoginToken::Pending {
                token: value.token,
                expires: value.expires,
            }),
            tl::enums::auth::LoginToken::MigrateTo(value) => Ok(QrLoginToken::Migrate {
                dc_id: value.dc_id,
                token: value.token,
            }),
            tl::enums::auth::LoginToken::Success(value) => {
                self.cache_qr_authorization(&value.authorization).await?;
                self.connected.store(true, Ordering::SeqCst);
                self.save_session_inner().await?;
                Ok(QrLoginToken::Success)
            }
        }
    }

    /// Complete a QR login that Telegram says requires the account cloud password.
    pub async fn check_qr_login_password(&self, password: &str) -> Result<()> {
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?;
        let mut info: tl::types::account::Password = client
            .invoke(&tl::functions::account::GetPassword {})
            .await
            .map_err(|e| TelegramError::Api(format!("account.getPassword: {e}")))?
            .into();
        for attempt in 0..2 {
            let algo = info.current_algo.as_ref().ok_or_else(|| {
                TelegramError::Api("Telegram has no current cloud password algorithm".into())
            })?;
            let tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(
                algo,
            ) = algo
            else {
                return Err(TelegramError::Api(
                    "Telegram returned an unsupported cloud password algorithm".into(),
                ));
            };
            if !grammers_crypto::two_factor_auth::check_p_and_g(&algo.p, &algo.g) {
                if attempt == 0 {
                    info = client
                        .invoke(&tl::functions::account::GetPassword {})
                        .await
                        .map_err(|e| TelegramError::Api(format!("account.getPassword: {e}")))?
                        .into();
                    continue;
                }
                return Err(TelegramError::Api(
                    "Telegram returned invalid cloud password parameters twice".into(),
                ));
            }
            let g_b = info.srp_b.clone().ok_or_else(|| {
                TelegramError::Api("Telegram omitted the cloud password SRP value".into())
            })?;
            let a = info.secure_random.clone();
            let srp_id = info.srp_id.ok_or_else(|| {
                TelegramError::Api("Telegram omitted the cloud password SRP id".into())
            })?;
            let (m1, g_a) = grammers_crypto::two_factor_auth::calculate_2fa(
                &algo.salt1,
                &algo.salt2,
                &algo.p,
                &algo.g,
                g_b,
                a,
                password.as_bytes(),
            );
            let check = tl::functions::auth::CheckPassword {
                password: tl::enums::InputCheckPasswordSrp::Srp(tl::types::InputCheckPasswordSrp {
                    srp_id,
                    a: g_a.to_vec(),
                    m1: m1.to_vec(),
                }),
            };
            let result: tl::enums::auth::Authorization = client
                .invoke(&check)
                .await
                .map_err(|e| TelegramError::Api(format!("auth.checkPassword: {e}")))?;
            if matches!(&result, tl::enums::auth::Authorization::Authorization(_)) {
                self.cache_qr_authorization(&result).await?;
                self.connected.store(true, Ordering::SeqCst);
                self.save_session_inner().await?;
                return Ok(());
            }
            return Err(TelegramError::Api(
                "unexpected cloud password authorization result".into(),
            ));
        }
        Err(TelegramError::Api("cloud password check failed".into()))
    }

    /// Approve a QR login token from an already authenticated session.
    pub async fn accept_qr_login_token(&self, token: &[u8]) -> Result<ApprovedAuthorization> {
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?;
        let result: tl::enums::Authorization = client
            .invoke(&tl::functions::auth::AcceptLoginToken {
                token: token.to_vec(),
            })
            .await
            .map_err(|e| TelegramError::Api(format!("auth.acceptLoginToken: {e}")))?;
        match result {
            tl::enums::Authorization::Authorization(value) => Ok(ApprovedAuthorization {
                hash: value.hash,
                device_model: value.device_model,
                app_name: value.app_name,
                ip: value.ip,
                country: value.country,
                region: value.region,
            }),
        }
    }

    /// Sign in with the verification code.
    pub async fn sign_in(&self, token: &LoginToken, code: &str) -> Result<AuthState> {
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?;

        match client.sign_in(&token.inner, code).await {
            Ok(_user) => {
                self.connected.store(true, Ordering::SeqCst);
                self.save_session_inner().await?;
                Ok(AuthState::Authenticated)
            }
            Err(SignInError::PasswordRequired(pwd_token)) => {
                *self.password_token.lock().await = Some(pwd_token);
                Ok(AuthState::AwaitingPassword)
            }
            Err(SignInError::InvalidCode) => {
                Err(TelegramError::Api("invalid verification code".into()))
            }
            Err(e) => Err(TelegramError::Api(format!("sign in: {e}"))),
        }
    }

    /// Check 2FA password using the cached password token from sign_in().
    pub async fn check_password(&self, password: &str) -> Result<AuthState> {
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?;

        let token = self.password_token.lock().await.take().ok_or_else(|| {
            TelegramError::Api("no cached password token (call sign_in first)".into())
        })?;

        match client.check_password(token, password).await {
            Ok(_user) => {
                self.connected.store(true, Ordering::SeqCst);
                self.save_session_inner().await?;
                Ok(AuthState::Authenticated)
            }
            Err(e) => Err(TelegramError::Api(format!(
                "2FA password check failed: {e}"
            ))),
        }
    }

    /// Connect and authenticate as a Telegram bot using a bot token.
    /// Uses the session_path from config for persistence; if the session is already
    /// authorized the token sign-in is skipped (bot sessions persist like user sessions).
    pub async fn connect_as_bot(&self, token: &str) -> Result<()> {
        let (client, updates) = self.create_client().await?;

        let already_authorized = client
            .is_authorized()
            .await
            .map_err(|e| TelegramError::Api(format!("bot auth check: {e}")))?;

        if !already_authorized {
            client
                .bot_sign_in(token, &self.config.api_hash)
                .await
                .map_err(|e| TelegramError::Api(format!("bot sign in: {e}")))?;
        }

        self.connected.store(true, Ordering::SeqCst);
        *self._updates.lock().await = Some(updates);
        *self.inner.lock().await = Some(client);
        tracing::info!("bot session authenticated");

        // Resolve the GROUP's access_hash for THIS bot's session. MTProto access
        // hashes are session-scoped, so the bot cannot reuse the user's hash. Because
        // the bot is a MEMBER of the shared forum group (added via `add_bot_to_group`),
        // `channels.getChannels` resolves cleanly here — unlike a broadcast channel the
        // bot only admins, which used to hang. Bounded so a slow bot can't wedge the
        // mount; on failure the bot keeps the (wrong) shared hash and is skipped at
        // upload time, with the pool falling through to a working session.
        if let Some((group_id, _shared_hash, topic_id)) = *self.channel_cache.lock().await {
            // Bounded short: `channels.getChannels(access_hash=0)` does not reliably
            // return for a bot session even when the bot is a group member, so cap it
            // tightly. On timeout/failure the bot keeps the shared hash; uploads on it
            // fail fast and MultiTransport falls through to the user session.
            const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
            match tokio::time::timeout(RESOLVE_TIMEOUT, self.resolve_channel_as_bot(group_id)).await
            {
                Ok(Ok(bot_hash)) => {
                    *self.channel_cache.lock().await = Some((group_id, bot_hash, topic_id));
                    tracing::info!(group_id, "bot resolved its own group access_hash");
                }
                Ok(Err(e)) => {
                    tracing::warn!(group_id, error = %e, "bot could not resolve group access_hash");
                }
                Err(_) => {
                    tracing::debug!(group_id, "bot group access_hash resolution timed out");
                }
            }
        }
        Ok(())
    }

    /// Resolve the storage channel's access_hash *for the current (bot) session*.
    ///
    /// MTProto access hashes are session-scoped, so a bot cannot reuse the access
    /// hash the user session stored. A bot that is a participant/admin of the channel
    /// can call `channels.getChannels` with `access_hash = 0`; Telegram resolves the
    /// channel server-side and returns it with an access hash valid for this session.
    /// This resolves cleanly for the shared forum group the bot is a member of (it
    /// hangs against a broadcast channel the bot only admins — a motivation for the
    /// forum model).
    async fn resolve_channel_as_bot(&self, channel_id: i64) -> Result<i64> {
        let client = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or(TelegramError::NotConnected)?.clone()
        };
        let result = client
            .invoke(&tl::functions::channels::GetChannels {
                id: vec![tl::enums::InputChannel::Channel(tl::types::InputChannel {
                    channel_id,
                    access_hash: 0,
                })],
            })
            .await
            .map_err(|e| TelegramError::Api(format!("bot getChannels: {e}")))?;
        let chats = match result {
            tl::enums::messages::Chats::Chats(c) => c.chats,
            tl::enums::messages::Chats::Slice(c) => c.chats,
        };
        chats
            .into_iter()
            .find_map(|chat| match chat {
                tl::enums::Chat::Channel(ch) if ch.id == channel_id => ch.access_hash,
                _ => None,
            })
            .ok_or_else(|| {
                TelegramError::Api(format!(
                    "bot could not resolve access_hash for channel {channel_id} (is the bot an admin?)"
                ))
            })
    }

    /// The SQLite session persists mutations transactionally as they occur.
    async fn save_session_inner(&self) -> Result<()> {
        self.reject_legacy_session_file()?;
        Ok(())
    }

    /// Save the current session.
    pub async fn save_session(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        if guard.is_some() {
            self.save_session_inner().await
        } else {
            Ok(())
        }
    }

    /// Get current transport statistics.
    pub fn stats(&self) -> TransportStats {
        self.stats.snapshot()
    }

    /// Get the config.
    pub fn config(&self) -> &TelegramConfig {
        &self.config
    }

    fn ensure_connected(&self) -> Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }
        Ok(())
    }

    /// Get the forum storage location (group_id, group_access_hash, topic_id) from cache.
    async fn get_channel(&self) -> Result<(i64, i64, i64)> {
        self.channel_cache.lock().await.ok_or_else(|| {
            TelegramError::Api(
                "no forum storage configured for this volume; mount once to create it".into(),
            )
        })
    }

    /// Build a `PeerRef` for the shared forum supergroup (the peer for all
    /// upload/download/delete ops). The volume's topic is carried separately in the
    /// send's `reply_to.top_msg_id`.
    async fn channel_packed(&self) -> Result<PeerRef> {
        let (group_id, hash, _topic) = self.get_channel().await?;
        let id = PeerId::channel(group_id)
            .ok_or_else(|| TelegramError::Api(format!("invalid Telegram channel id {group_id}")))?;
        Ok(PeerRef {
            id,
            auth: PeerAuth::from_hash(hash),
        })
    }

    /// Create the shared TeaGarden supergroup **forum** (one per TeaGarden identity).
    /// Returns `(group_id, group_access_hash)`. The caller persists these app-wide
    /// (e.g. `~/.config/teagarden/group.json`) and reuses the group for every volume.
    pub async fn create_forum_group(&self, title: &str) -> Result<(i64, i64)> {
        // Pad an unusually short title so Telegram never sees a degenerate
        // 1-2 char group name — but never brand the padding with this tool's
        // name; a random suffix is just as effective and reveals nothing.
        let title: String = {
            let t = if title.chars().count() >= 5 {
                title.to_string()
            } else {
                format!("{title} {}", uuid::Uuid::new_v4().simple())
            };
            t.chars().take(255).collect()
        };

        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?.clone();
        drop(guard);

        // A megagroup with `forum: true` is a supergroup whose messages are organised
        // into topics. Unlike a broadcast channel, bots added as members can resolve
        // its access_hash normally (they receive it in their dialogs), which is what
        // makes the multi-bot pool work.
        let updates = client
            .invoke(&tl::functions::channels::CreateChannel {
                broadcast: false,
                megagroup: true,
                for_import: false,
                forum: true,
                title: title.clone(),
                about: String::new(),
                geo_point: None,
                address: None,
                ttl_period: None,
            })
            .await
            .map_err(|e| TelegramError::Api(format!("create forum group: {e}")))?;

        let chats = match updates {
            tl::enums::Updates::Updates(u) => u.chats,
            other => {
                return Err(TelegramError::Api(format!(
                    "unexpected updates type after group creation: {other:?}"
                )));
            }
        };
        let (group_id, access_hash) = chats
            .into_iter()
            .find_map(|chat| match chat {
                tl::enums::Chat::Channel(ch) => Some((ch.id, ch.access_hash.unwrap_or(0))),
                _ => None,
            })
            .ok_or_else(|| TelegramError::Api("no group found in creation response".into()))?;

        // Disable message auto-delete (period = 0).
        let _ = client
            .invoke(&tl::functions::messages::SetHistoryTtl {
                peer: tl::enums::InputPeer::Channel(tl::types::InputPeerChannel {
                    channel_id: group_id,
                    access_hash,
                }),
                period: 0,
            })
            .await;

        tracing::info!(group_id, title = %title, "Created shared TeaGarden forum supergroup");
        Ok((group_id, access_hash))
    }

    /// Create a forum **topic** in the shared group for a volume. Returns the topic id
    /// (its root service-message id), used both to route block uploads (`top_msg_id`)
    /// and as part of the volume's key-derivation binding.
    pub async fn create_topic(
        &self,
        group_id: i64,
        group_access_hash: i64,
        title: &str,
    ) -> Result<i64> {
        let title: String = title.chars().take(128).collect();
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?.clone();
        drop(guard);

        let updates = client
            .invoke(&tl::functions::messages::CreateForumTopic {
                title_missing: false,
                peer: tl::enums::InputPeer::Channel(tl::types::InputPeerChannel {
                    channel_id: group_id,
                    access_hash: group_access_hash,
                }),
                title,
                icon_color: None,
                icon_emoji_id: None,
                random_id: generate_random_i64(),
                send_as: None,
            })
            .await
            .map_err(|e| TelegramError::Api(format!("create forum topic: {e}")))?;

        // The topic id is the id of the service message that opens the topic.
        let topic_id = extract_new_message_id(&updates)
            .ok_or_else(|| TelegramError::Api("createForumTopic returned no topic id".into()))?;
        tracing::info!(group_id, topic_id, "Created forum topic for volume");
        Ok(i64::from(topic_id))
    }

    /// Delete a forum topic with all its messages (`messages.deleteTopicHistory`,
    /// repeated while Telegram reports a positive `offset`, i.e. more to delete).
    /// Deleting a topic's whole history removes the topic itself. Refuses topic
    /// ids `<= 1`: id 1 is the group's General topic, never a volume's.
    pub async fn delete_topic(
        &self,
        group_id: i64,
        group_access_hash: i64,
        topic_id: i64,
    ) -> Result<()> {
        if topic_id <= 1 {
            return Err(TelegramError::Delete(format!(
                "refusing to delete forum topic {topic_id}: not a volume or device topic"
            )));
        }
        let top_msg_id = i32::try_from(topic_id)
            .map_err(|_| TelegramError::Delete(format!("topic_id {topic_id} out of i32 range")))?;
        self.ensure_connected()?;
        let client = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or(TelegramError::NotConnected)?.clone()
        };
        for _ in 0..DELETE_TOPIC_MAX_ROUNDS {
            let affected = client
                .invoke(&tl::functions::messages::DeleteTopicHistory {
                    peer: tl::enums::InputPeer::Channel(tl::types::InputPeerChannel {
                        channel_id: group_id,
                        access_hash: group_access_hash,
                    }),
                    top_msg_id,
                })
                .await
                .map_err(|e| TelegramError::Delete(format!("delete forum topic: {e}")))?;
            let tl::enums::messages::AffectedHistory::History(h) = affected;
            if h.offset <= 0 {
                tracing::info!(group_id, topic_id, "Deleted forum topic and its messages");
                return Ok(());
            }
        }
        Err(TelegramError::Delete(format!(
            "deleting forum topic {topic_id} did not finish after {DELETE_TOPIC_MAX_ROUNDS} rounds"
        )))
    }

    /// Make a bot the USER created by hand (identified by its `@username`) an
    /// administrator of the shared forum group, so its Bot API session can post
    /// blocks into the volume topics. Runs on the authenticated USER session.
    ///
    /// The bot is invited (an existing membership is fine), then promoted with
    /// the least rights that still make it an administrator: `post_messages`
    /// and `other` ("an admin with none of the other rights"). Administrators
    /// see every message in the group and are exempt from member restrictions.
    /// Nothing else is granted, because no bot needs it: `MultiTransport` sends
    /// every download and delete through the user's own MTProto session
    /// (`transports[0]`), so bots only post. Any failure is returned, never
    /// skipped, because a bot that cannot post would fail every upload routed
    /// to it.
    pub async fn add_bot_to_group(
        &self,
        group_id: i64,
        group_access_hash: i64,
        bot_username: &str,
    ) -> Result<()> {
        self.ensure_connected()?;
        let client = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or(TelegramError::NotConnected)?.clone()
        };
        let uname = bot_username.trim_start_matches('@');
        let bot_chat = client
            .resolve_username(uname)
            .await
            .map_err(|e| TelegramError::Api(format!("resolve @{uname}: {e}")))?
            .ok_or_else(|| TelegramError::Api(format!("@{uname} does not resolve")))?;
        let Peer::User(bot_user) = bot_chat else {
            return Err(TelegramError::Api(format!(
                "@{uname} is not a user account"
            )));
        };
        let bot_ref = bot_user
            .to_ref()
            .await
            .map_err(|e| TelegramError::Api(format!("resolve @{uname} reference: {e}")))?
            .ok_or_else(|| {
                TelegramError::Api(format!("@{uname} resolved without a usable access hash"))
            })?;
        let input_channel = tl::enums::InputChannel::Channel(tl::types::InputChannel {
            channel_id: group_id,
            access_hash: group_access_hash,
        });

        // Invite the bot into the group ("already a participant" is fine).
        if let Err(e) = client
            .invoke(&tl::functions::channels::InviteToChannel {
                channel: input_channel.clone(),
                users: vec![tl::enums::InputUser::from(bot_ref)],
            })
            .await
        {
            let msg = e.to_string();
            if !msg.contains("USER_ALREADY_PARTICIPANT") {
                return Err(TelegramError::Api(format!(
                    "invite @{uname} to the storage group: {msg}"
                )));
            }
        }

        // Promote with the minimum rights (see above). Raw TL, because the
        // grammers builder has no setter for `other`.
        client
            .invoke(&tl::functions::channels::EditAdmin {
                channel: input_channel,
                user_id: tl::enums::InputUser::from(bot_ref),
                admin_rights: tl::enums::ChatAdminRights::Rights(tl::types::ChatAdminRights {
                    change_info: false,
                    post_messages: true,
                    edit_messages: false,
                    delete_messages: false,
                    ban_users: false,
                    invite_users: false,
                    pin_messages: false,
                    add_admins: false,
                    anonymous: false,
                    manage_call: false,
                    other: true,
                    manage_topics: false,
                    post_stories: false,
                    edit_stories: false,
                    delete_stories: false,
                    manage_direct_messages: false,
                    manage_ranks: false,
                }),
                rank: Some(String::new()),
            })
            .await
            .map_err(|e| {
                TelegramError::Api(format!("promote @{uname} in the storage group: {e}"))
            })?;
        tracing::info!(
            bot = uname,
            group_id,
            "bot is an administrator of the storage group"
        );
        Ok(())
    }

    /// Returns `None` if no upload has ever succeeded, or `Some(elapsed_seconds)` since
    /// the last successful upload.
    pub fn seconds_since_last_upload(&self) -> Option<u64> {
        let ts = self.last_upload_ok.load(Ordering::Relaxed);
        if ts == 0 {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Some(now.saturating_sub(ts))
    }
}

/// Extract the wait duration from a Telegram FLOOD_WAIT or SLOWMODE_WAIT error.
///
/// grammers surfaces these as `InvocationError` whose `Display` form includes
/// the error code string, e.g. "FLOOD_WAIT_30" or "SLOWMODE_WAIT_60".
/// Returns `Some(seconds)` when recognised, `None` otherwise.
pub(crate) fn extract_flood_wait(err: &TelegramError) -> Option<u64> {
    if let TelegramError::RateLimited { seconds } = err {
        return Some(u64::from(*seconds));
    }
    let msg = format!("{err}");
    for prefix in &["FLOOD_WAIT_", "FLOOD_PREMIUM_WAIT_", "SLOWMODE_WAIT_"] {
        if let Some(rest) = msg.find(prefix).map(|pos| &msg[pos + prefix.len()..]) {
            if let Some(secs) = rest.split(|c: char| !c.is_ascii_digit()).next() {
                if !secs.is_empty() {
                    return secs.parse().ok();
                }
            }
        }
    }
    None
}

/// Opaque login token wrapper.
pub struct LoginToken {
    inner: GrammersLoginToken,
}

#[async_trait::async_trait]
impl BlockTransport for TelegramClient {
    async fn telegram_user_id(&self) -> Result<Option<i64>> {
        self.ensure_connected()?;
        if let Some(user) = self.me_cache.lock().await.as_ref() {
            return Ok(user.id().bare_id());
        }
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?.clone();
        drop(guard);
        let user = client
            .get_me()
            .await
            .map_err(|e| TelegramError::Download(format!("getMe: {e}")))?;
        let id = user.id().bare_id();
        *self.me_cache.lock().await = Some(user);
        Ok(id)
    }

    async fn is_premium_user(&self) -> Result<bool> {
        self.ensure_connected()?;
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?;
        let response = client
            .invoke(&tl::functions::users::GetFullUser {
                id: tl::enums::InputUser::UserSelf,
            })
            .await
            .map_err(|e| TelegramError::Api(format!("query Telegram account tier: {e}")))?;
        match response {
            tl::enums::users::UserFull::Full(full) => {
                let premium = full
                    .users
                    .iter()
                    .any(|user| matches!(user, tl::enums::User::User(record) if record.premium));
                self.premium_cache.store(premium, Ordering::Relaxed);
                Ok(premium)
            }
        }
    }

    async fn upload_block(&self, data: &[u8], filename: &str) -> Result<UploadResult> {
        self.upload_document_limited(data, filename, self.config.max_upload_size)
            .await
    }

    async fn upload_file_object(&self, data: &[u8], filename: &str) -> Result<UploadResult> {
        let premium = self.premium_cache.load(Ordering::Relaxed);
        check_file_object_size(data.len(), premium)?;
        let max_size = file_object_upload_limit(premium);
        self.upload_document_limited(data, filename, max_size).await
    }

    async fn upload_file_source(
        &self,
        source: &mut (dyn crate::transfer::UploadSource + '_),
        filename: &str,
        part_timeout: Duration,
    ) -> Result<UploadResult> {
        self.upload_stream(source, filename, part_timeout).await
    }

    async fn download_block(&self, message_id: i64) -> Result<DownloadResult> {
        self.ensure_connected()?;

        let _permit = self
            .download_semaphore
            .acquire()
            .await
            .map_err(|_| TelegramError::Download("semaphore closed".into()))?;

        let mut last_err = None;
        for attempt in 0..self.config.max_retries {
            match self.do_download(message_id).await {
                Ok(result) => {
                    self.stats.blocks_downloaded.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_downloaded
                        .fetch_add(result.data.len() as u64, Ordering::Relaxed);
                    return Ok(result);
                }
                Err(e) => {
                    self.stats.download_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(attempt, error = %e, "download attempt failed");
                    last_err = Some(e);
                    if attempt + 1 < self.config.max_retries {
                        // SECURITY/CORRECTNESS: cap the shift to avoid overflow —
                        // 2u64.pow(attempt) wraps silently for attempt >= 64,
                        // producing near-zero delays instead of the intended backoff.
                        let shift = attempt.min(32);
                        let delay = self
                            .config
                            .retry_base_delay_ms
                            .saturating_mul(1u64 << shift)
                            .min(60_000);
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or(TelegramError::Download("all retries exhausted".into())))
    }

    async fn list_topic_documents(
        &self,
        group_id: i64,
        topic_id: i64,
        before_message_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<DocumentInfo>> {
        Ok(self
            .list_topic_page(group_id, topic_id, None, None, before_message_id, limit)
            .await?
            .documents)
    }

    async fn list_topic_page(
        &self,
        group_id: i64,
        topic_id: i64,
        min_message_id: Option<i64>,
        max_message_id: Option<i64>,
        offset_id: Option<i64>,
        limit: usize,
    ) -> Result<TopicDocumentPage> {
        self.ensure_connected()?;
        if limit == 0 {
            return Ok(TopicDocumentPage {
                documents: Vec::new(),
                raw_message_ids: Vec::new(),
                exhausted: true,
            });
        }
        let channel_id = group_id;
        let msg_id = i32::try_from(topic_id).map_err(|_| {
            TelegramError::Download("topic id is outside Telegram's id range".into())
        })?;
        let offset_id = offset_id
            .map(i32::try_from)
            .transpose()
            .map_err(|_| {
                TelegramError::Download("pagination id is outside Telegram's id range".into())
            })?
            .unwrap_or(0);
        let min_id = min_message_id
            .map(i32::try_from)
            .transpose()
            .map_err(|_| {
                TelegramError::Download(
                    "minimum pagination id is outside Telegram's id range".into(),
                )
            })?
            .unwrap_or(0);
        let max_id = max_message_id
            .map(i32::try_from)
            .transpose()
            .map_err(|_| {
                TelegramError::Download(
                    "maximum pagination id is outside Telegram's id range".into(),
                )
            })?
            .unwrap_or(0);
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?.clone();
        drop(guard);
        let cached = *self.channel_cache.lock().await;
        let input_peer = if let Some((_, access_hash, _)) =
            cached.filter(|(cached_group, _, _)| *cached_group == group_id)
        {
            tl::enums::InputPeer::Channel(tl::types::InputPeerChannel {
                channel_id,
                access_hash,
            })
        } else {
            let mut dialogs = client.iter_dialogs();
            let mut resolved = None;
            while let Some(dialog) = dialogs
                .next()
                .await
                .map_err(|e| TelegramError::Download(format!("resolve Telegram group: {e}")))?
            {
                let peer = dialog.peer();
                if peer.id().bare_id() != Some(group_id) {
                    continue;
                }
                let reference = peer.to_ref().await.map_err(|e| {
                    TelegramError::Download(format!("resolve Telegram group peer: {e}"))
                })?;
                let Some(reference) = reference else {
                    continue;
                };
                resolved = Some(tl::enums::InputPeer::from(reference));
                break;
            }
            resolved.ok_or_else(|| {
                TelegramError::Download(format!(
                    "Telegram group {group_id} is not accessible to this login"
                ))
            })?
        };
        if let tl::enums::InputPeer::Channel(peer) = &input_peer {
            *self.channel_cache.lock().await = Some((group_id, peer.access_hash, topic_id));
        } else {
            return Err(TelegramError::Download(
                "requested forum group did not resolve to a channel peer".into(),
            ));
        }
        let result = client
            .invoke(&tl::functions::messages::GetReplies {
                peer: input_peer,
                msg_id,
                offset_id,
                offset_date: 0,
                add_offset: 0,
                limit: limit.clamp(1, 100) as i32,
                max_id,
                min_id,
                hash: 0,
            })
            .await
            .map_err(|e| TelegramError::Download(format!("GetReplies: {e}")))?;
        let messages = match result {
            tl::enums::messages::Messages::ChannelMessages(m) => m.messages,
            tl::enums::messages::Messages::Messages(m) => m.messages,
            tl::enums::messages::Messages::Slice(m) => m.messages,
            tl::enums::messages::Messages::NotModified(_) => {
                return Ok(TopicDocumentPage {
                    documents: Vec::new(),
                    raw_message_ids: Vec::new(),
                    exhausted: true,
                })
            }
        };
        let mut documents = Vec::new();
        let mut raw_message_ids = Vec::new();
        for message in messages {
            let message = match message {
                tl::enums::Message::Message(message) => message,
                tl::enums::Message::Service(message) => {
                    raw_message_ids.push(i64::from(message.id));
                    continue;
                }
                tl::enums::Message::Empty(message) => {
                    raw_message_ids.push(i64::from(message.id));
                    continue;
                }
            };
            raw_message_ids.push(i64::from(message.id));
            let Some(tl::enums::MessageMedia::Document(media)) = message.media else {
                continue;
            };
            let Some(tl::enums::Document::Document(document)) = media.document else {
                continue;
            };
            let Some(filename) =
                document
                    .attributes
                    .into_iter()
                    .find_map(|attribute| match attribute {
                        tl::enums::DocumentAttribute::Filename(attr) => Some(attr.file_name),
                        _ => None,
                    })
            else {
                continue;
            };
            documents.push(DocumentInfo {
                message_id: i64::from(message.id),
                filename,
                group_id,
                topic_id,
            });
        }
        documents.sort_by_key(|document| std::cmp::Reverse(document.message_id));
        raw_message_ids.sort_by_key(|id| std::cmp::Reverse(*id));
        raw_message_ids.truncate(limit.min(100));
        Ok(TopicDocumentPage {
            documents,
            exhausted: raw_message_ids.len() < limit.min(100),
            raw_message_ids,
        })
    }

    async fn download_range(&self, message_id: i64, offset: u64, len: u32) -> Result<Vec<u8>> {
        self.ensure_connected()?;
        let _permit = self
            .download_semaphore
            .acquire()
            .await
            .map_err(|_| TelegramError::Download("semaphore closed".into()))?;
        // Resolve + fetch inside the retry loop: a retry after
        // FILE_REFERENCE_EXPIRED naturally re-resolves and gets a fresh
        // file_reference (the P3.1 refresh-retry contract; the location CACHE
        // with single-flight refresh is P3.1a). Hot paths in the block-device cache
        // the parsed index, not the location.
        self.retry_ranged("download_range", || async {
            let (loc, _dc, _size) = self.resolve_document(message_id).await?;
            self.get_file_range(&loc, offset, len).await
        })
        .await
    }

    async fn download_tail(&self, message_id: i64, len: u32) -> Result<Vec<u8>> {
        self.ensure_connected()?;
        let _permit = self
            .download_semaphore
            .acquire()
            .await
            .map_err(|_| TelegramError::Download("semaphore closed".into()))?;
        // resolve_document already returns the document size, so the tail costs
        // the same 2 RTTs as any ranged read (location cache = P3.1a).
        self.retry_ranged("download_tail", || async {
            let (loc, _dc, size) = self.resolve_document(message_id).await?;
            let take = u64::from(len).min(size);
            let offset = size - take; // take ≤ size, no underflow
            let take = u32::try_from(take).unwrap_or(len);
            self.get_file_range(&loc, offset, take).await
        })
        .await
    }

    async fn delete_message(&self, message_id: i64) -> Result<()> {
        self.ensure_connected()?;
        self.do_delete(&[message_id]).await?;
        self.stats.messages_deleted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn delete_messages(&self, message_ids: &[i64]) -> Result<()> {
        self.ensure_connected()?;
        self.do_delete(message_ids).await?;
        self.stats
            .messages_deleted
            .fetch_add(message_ids.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn sync_metadata(&self, data: &[u8]) -> Result<i64> {
        self.ensure_connected()?;
        // NOT `max_upload_size` (the ~50 MB block ceiling, which exists for the
        // Bot API sessions blocks may go through): a snapshot always goes over
        // this, the user's MTProto session, whose limit is far larger.
        check_metadata_size(data.len())?;

        // A metadata snapshot gets the exact same random-UUID, no-extension name as
        // a block upload — one filename pool, nothing to distinguish it as special.
        let meta_filename = uuid::Uuid::new_v4().to_string();

        let result = self
            .upload_document_limited(data, &meta_filename, MAX_METADATA_UPLOAD_BYTES)
            .await?;
        Ok(result.message_id)
    }

    async fn fetch_metadata(&self, message_id: i64) -> Result<Vec<u8>> {
        self.ensure_connected()?;
        let result = self.do_download(message_id).await?;
        Ok(result.data)
    }

    fn channel_ref(&self) -> Option<(i64, i64, i64)> {
        // Use try_lock since this is sync; return None if contended (rare)
        self.channel_cache.try_lock().ok().and_then(|g| *g)
    }
}

#[async_trait::async_trait]
impl ForumAdmin for TelegramClient {
    fn select_topic(&self, group_id: i64, access_hash: i64, topic_id: i64) -> Result<()> {
        *self
            .channel_cache
            .try_lock()
            .map_err(|_| TelegramError::Api("forum routing is busy".into()))? =
            Some((group_id, access_hash, topic_id));
        Ok(())
    }

    async fn create_forum_group(&self, title: &str) -> Result<(i64, i64)> {
        TelegramClient::create_forum_group(self, title).await
    }

    async fn create_topic(
        &self,
        group_id: i64,
        group_access_hash: i64,
        title: &str,
    ) -> Result<i64> {
        TelegramClient::create_topic(self, group_id, group_access_hash, title).await
    }

    async fn delete_topic(
        &self,
        group_id: i64,
        group_access_hash: i64,
        topic_id: i64,
    ) -> Result<()> {
        TelegramClient::delete_topic(self, group_id, group_access_hash, topic_id).await
    }

    async fn ban_group_member(&self, group_id: i64, access_hash: i64, user_id: i64) -> Result<()> {
        let client = self.connected_client().await?;
        let peer = client
            .resolve_peer(PeerRef {
                id: PeerId::user_unchecked(user_id),
                auth: PeerAuth::default(),
            })
            .await
            .map_err(|error| {
                TelegramError::Api(format!("resolve Telegram user {user_id}: {error}"))
            })?;
        let participant = peer
            .to_ref()
            .await
            .map_err(|error| {
                TelegramError::Api(format!("resolve Telegram user authority: {error}"))
            })?
            .ok_or_else(|| {
                TelegramError::Api(format!("Telegram user {user_id} has no access hash"))
            })?;
        client
            .invoke(&tl::functions::channels::EditBanned {
                channel: tl::enums::InputChannel::Channel(tl::types::InputChannel {
                    channel_id: group_id,
                    access_hash,
                }),
                participant: tl::enums::InputPeer::User(tl::types::InputPeerUser {
                    user_id,
                    access_hash: participant.auth.hash(),
                }),
                banned_rights: tl::enums::ChatBannedRights::Rights(tl::types::ChatBannedRights {
                    view_messages: true,
                    send_messages: false,
                    send_media: false,
                    send_stickers: false,
                    send_gifs: false,
                    send_games: false,
                    send_inline: false,
                    embed_links: false,
                    send_polls: false,
                    change_info: false,
                    invite_users: false,
                    pin_messages: false,
                    manage_topics: false,
                    send_photos: false,
                    send_videos: false,
                    send_roundvideos: false,
                    send_audios: false,
                    send_voices: false,
                    send_docs: false,
                    send_plain: false,
                    edit_rank: false,
                    send_reactions: false,
                    until_date: 0,
                }),
            })
            .await
            .map_err(|error| TelegramError::Api(format!("channels.editBanned: {error}")))?;
        Ok(())
    }

    async fn reset_authorization(&self, authorization_hash: i64) -> Result<()> {
        let client = self.connected_client().await?;
        let reset: bool = client
            .invoke(&tl::functions::account::ResetAuthorization {
                hash: authorization_hash,
            })
            .await
            .map_err(|error| TelegramError::Api(format!("account.resetAuthorization: {error}")))?;
        if !reset {
            return Err(TelegramError::Api(
                "account.resetAuthorization did not confirm an access cut".into(),
            ));
        }
        Ok(())
    }

    async fn reset_other_authorizations(&self) -> Result<()> {
        let client = self.connected_client().await?;
        let reset: bool = client
            .invoke(&tl::functions::auth::ResetAuthorizations {})
            .await
            .map_err(|error| TelegramError::Api(format!("auth.resetAuthorizations: {error}")))?;
        if !reset {
            return Err(TelegramError::Api(
                "auth.resetAuthorizations did not confirm an access cut".into(),
            ));
        }
        Ok(())
    }

    async fn current_authorization_hash(&self) -> Result<Option<i64>> {
        let client = self.connected_client().await?;
        let authorizations: tl::enums::account::Authorizations = client
            .invoke(&tl::functions::account::GetAuthorizations {})
            .await
            .map_err(|error| TelegramError::Api(format!("account.getAuthorizations: {error}")))?;
        let tl::enums::account::Authorizations::Authorizations(authorizations) = authorizations;
        Ok(authorizations.authorizations.into_iter().find_map(
            |authorization| match authorization {
                tl::enums::Authorization::Authorization(value)
                    if value.current && value.hash != 0 =>
                {
                    Some(value.hash)
                }
                _ => None,
            },
        ))
    }

    async fn authorizations(&self) -> Result<Vec<TelegramAuthorizationInfo>> {
        let client = self.connected_client().await?;
        let authorizations: tl::enums::account::Authorizations = client
            .invoke(&tl::functions::account::GetAuthorizations {})
            .await
            .map_err(|error| TelegramError::Api(format!("account.getAuthorizations: {error}")))?;
        let tl::enums::account::Authorizations::Authorizations(authorizations) = authorizations;
        Ok(authorizations
            .authorizations
            .into_iter()
            .map(|authorization| match authorization {
                tl::enums::Authorization::Authorization(value) => TelegramAuthorizationInfo {
                    hash: value.hash,
                    current: value.current,
                    device_model: value.device_model,
                    app_name: value.app_name,
                    date_active: value.date_active,
                },
            })
            .collect())
    }
}

impl TelegramClient {
    async fn connected_client(&self) -> Result<Client> {
        self.ensure_connected()?;
        self.inner
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or(TelegramError::NotConnected)
    }
}

impl TelegramClient {
    async fn upload_stream(
        &self,
        source: &mut (dyn crate::transfer::UploadSource + '_),
        filename: &str,
        timeout: Duration,
    ) -> Result<UploadResult> {
        self.ensure_connected()?;
        let premium = self.premium_cache.load(Ordering::Relaxed);
        let size = usize::try_from(source.size()).unwrap_or(usize::MAX);
        check_file_object_size(size, premium)?;
        let route = self.get_channel().await?;
        let client = self
            .part_client
            .lock()
            .await
            .clone()
            .ok_or(TelegramError::NotConnected)?;
        let publication = source.publication_id();
        let input = upload_source_to_input(
            &client,
            source,
            filename,
            part_window()?,
            timeout,
            self.config.max_retries,
        )
        .await?;
        let mut failures = 0;
        loop {
            match tokio::time::timeout(
                timeout,
                self.do_upload(input.clone(), filename, publication, size, route),
            )
            .await
            .unwrap_or(Err(TelegramError::Timeout))
            {
                Ok(result) => {
                    self.stats.blocks_uploaded.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_uploaded
                        .fetch_add(size as u64, Ordering::Relaxed);
                    return Ok(result);
                }
                Err(error) => {
                    if let Some(seconds) = extract_flood_wait(&error) {
                        tokio::time::sleep(Duration::from_secs(seconds)).await;
                    } else {
                        failures += 1;
                        if failures >= self.config.max_retries {
                            return Err(error);
                        }
                    }
                }
            }
        }
    }

    async fn upload_document_limited(
        &self,
        data: &[u8],
        filename: &str,
        max_size: usize,
    ) -> Result<UploadResult> {
        self.ensure_connected()?;
        if data.len() > max_size {
            return Err(TelegramError::BlockTooLarge {
                size: data.len(),
                max: max_size,
            });
        }

        let _permit = self
            .upload_semaphore
            .acquire()
            .await
            .map_err(|_| TelegramError::Upload("semaphore closed".into()))?;

        // Per-session rate check: Telegram enforces ~20 messages per 60 seconds
        // on channels. If we've sent >= 20 in the last 60s, pause briefly to
        // avoid tripping the server-side limiter before we even send.
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut ts = self.upload_timestamps.lock().await;
            // Drop timestamps older than 60 seconds
            while ts
                .front()
                .map(|&t| now.saturating_sub(t) >= 60)
                .unwrap_or(false)
            {
                ts.pop_front();
            }
            if ts.len() >= 20 {
                tracing::warn!(
                    recent_uploads = ts.len(),
                    "approaching Telegram channel rate limit — sleeping 2s before upload"
                );
                drop(ts);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }

        // Upload the payload once. Publication retries reuse both the InputFile
        // and random_id; a SendMedia FLOOD_WAIT must not upload every part again.
        let route = self.get_channel().await?;
        let client = self
            .part_client
            .lock()
            .await
            .clone()
            .ok_or(TelegramError::NotConnected)?;
        let input_file = upload_in_memory(&client, data, filename, self.config.max_retries)
            .await
            .inspect_err(|_| {
                self.stats.upload_errors.fetch_add(1, Ordering::Relaxed);
            })?;
        let random_id = generate_random_i64();
        let mut last_err = None;
        let mut backoff_exponent: u32 = 0;
        for attempt in 0..self.config.max_retries {
            match self
                .do_upload(input_file.clone(), filename, random_id, data.len(), route)
                .await
            {
                Ok(result) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    self.last_upload_ok.store(now, Ordering::Relaxed);
                    // Record this successful upload in the rate-tracking window
                    {
                        let mut ts = self.upload_timestamps.lock().await;
                        ts.push_back(now);
                    }
                    self.stats.blocks_uploaded.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_uploaded
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    return Ok(result);
                }
                Err(e) => {
                    self.stats.upload_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(attempt, error = %e, "upload attempt failed");

                    // Detect FLOOD_WAIT / SLOWMODE_WAIT and sleep for exactly
                    // the duration Telegram requests.  Do NOT advance backoff_exponent
                    // since this is an explicit server-side instruction.
                    if let Some(secs) = extract_flood_wait(&e) {
                        let wait = secs;
                        tracing::warn!(flood_wait_secs = wait, "Telegram FloodWait — backing off");
                        tokio::time::sleep(Duration::from_secs(wait)).await;
                        last_err = Some(e);
                        continue; // retry without incrementing backoff exponent
                    }

                    last_err = Some(e);
                    if attempt + 1 < self.config.max_retries {
                        // SECURITY/CORRECTNESS: cap the shift to avoid overflow —
                        // 2u64.pow(attempt) wraps silently for attempt >= 64,
                        // producing near-zero delays instead of the intended backoff.
                        let shift = backoff_exponent.min(32);
                        let delay = self
                            .config
                            .retry_base_delay_ms
                            .saturating_mul(1u64 << shift)
                            .min(60_000);
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        backoff_exponent = backoff_exponent.saturating_add(1);
                    }
                }
            }
        }

        Err(last_err.unwrap_or(TelegramError::Upload("all retries exhausted".into())))
    }

    async fn do_upload(
        &self,
        input_file: tl::enums::InputFile,
        filename: &str,
        random_id: i64,
        size: usize,
        route: (i64, i64, i64),
    ) -> Result<UploadResult> {
        // Forum storage: the peer is the shared supergroup; the block must land in THIS
        // volume's topic, which requires `top_msg_id` on the send. grammers' high-level
        // `send_message` hardcodes `top_msg_id: None`, and `Uploaded.input_file` is
        // `pub(crate)`, so we cannot use the high-level path. Instead we chunk-upload via
        // the public `upload.SaveFilePart` / `SaveBigFilePart` (building the `InputFile`
        // ourselves) and send via a raw `messages.SendMedia` with the topic id.
        let (group_id, group_hash, topic_id) = route;

        let guard = self.part_client.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?.clone();
        drop(guard);

        let topic_i32 = i32::try_from(topic_id)
            .map_err(|_| TelegramError::Upload(format!("topic_id {topic_id} out of i32 range")))?;

        let updates = client
            .invoke(&tl::functions::messages::SendMedia {
                silent: false,
                background: false,
                clear_draft: false,
                noforwards: false,
                update_stickersets_order: false,
                invert_media: false,
                allow_paid_floodskip: false,
                peer: tl::enums::InputPeer::Channel(tl::types::InputPeerChannel {
                    channel_id: group_id,
                    access_hash: group_hash,
                }),
                reply_to: Some(tl::enums::InputReplyTo::Message(
                    tl::types::InputReplyToMessage {
                        reply_to_msg_id: topic_i32,
                        top_msg_id: Some(topic_i32),
                        reply_to_peer_id: None,
                        quote_text: None,
                        quote_entities: None,
                        quote_offset: None,
                        monoforum_peer_id: None,
                        todo_item_id: None,
                        poll_option: None,
                    },
                )),
                media: tl::enums::InputMedia::UploadedDocument(
                    tl::types::InputMediaUploadedDocument {
                        nosound_video: false,
                        force_file: true,
                        spoiler: false,
                        file: input_file,
                        thumb: None,
                        // Empty, not "application/octet-stream": a constant non-empty
                        // MIME type on every upload was itself a fingerprint. Telegram
                        // accepts an empty mime_type; it just means the client shows no
                        // type-specific preview, matching an anonymous binary blob.
                        mime_type: String::new(),
                        attributes: vec![tl::enums::DocumentAttribute::Filename(
                            tl::types::DocumentAttributeFilename {
                                file_name: filename.to_string(),
                            },
                        )],
                        stickers: None,
                        video_cover: None,
                        video_timestamp: None,
                        ttl_seconds: None,
                    },
                ),
                message: String::new(),
                random_id,
                reply_markup: None,
                entities: None,
                schedule_date: None,
                schedule_repeat_period: None,
                send_as: None,
                quick_reply_shortcut: None,
                effect: None,
                allow_paid_stars: None,
                suggested_post: None,
            })
            .await
            .map_err(part_error)?;

        let message_id = extract_new_message_id(&updates)
            .ok_or_else(|| TelegramError::Upload("SendMedia returned no new message id".into()))?;

        let actual = uploaded_document_size(&updates, message_id)
            .ok_or_else(|| TelegramError::Upload("SendMedia returned no document size".into()))?;
        if actual != size {
            return Err(TelegramError::Upload(format!(
                "Telegram document size mismatch: expected {size}, got {actual}"
            )));
        }
        Ok(UploadResult {
            message_id: i64::from(message_id),
            size: actual,
        })
    }

    async fn do_download(&self, message_id: i64) -> Result<DownloadResult> {
        let channel = self.channel_packed().await?;
        // Reads are by global message id within the supergroup — topic-agnostic.
        let (ch_id, ch_hash, _topic) = self.get_channel().await?;

        // Clone client to avoid holding the lock across awaits
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?.clone();
        drop(guard);

        // Use channels::GetMessages for O(1) lookup by message ID to verify existence
        let msg_id_i32 = i32::try_from(message_id).map_err(|_| {
            TelegramError::Download(format!("message_id {message_id} out of i32 range"))
        })?;
        let result = client
            .invoke(&tl::functions::channels::GetMessages {
                channel: tl::enums::InputChannel::Channel(tl::types::InputChannel {
                    channel_id: ch_id,
                    access_hash: ch_hash,
                }),
                id: vec![tl::enums::InputMessage::Id(tl::types::InputMessageId {
                    id: msg_id_i32,
                })],
            })
            .await
            .map_err(|e| TelegramError::Download(format!("GetMessages: {e}")))?;

        // Verify the message was found (not empty)
        let found = match &result {
            tl::enums::messages::Messages::Messages(m) => !m.messages.is_empty(),
            tl::enums::messages::Messages::Slice(m) => !m.messages.is_empty(),
            tl::enums::messages::Messages::ChannelMessages(m) => !m.messages.is_empty(),
            tl::enums::messages::Messages::NotModified(_) => false,
        };
        if !found {
            return Err(TelegramError::MessageNotFound(message_id));
        }

        // Use iter_messages with offset_id to position just after our message
        // (offset_id exclusive upper bound means messages with id < offset_id are returned)
        let offset_id = msg_id_i32.checked_add(1).ok_or_else(|| {
            TelegramError::Download(format!("message_id {message_id} offset overflow"))
        })?;
        let mut messages = client.iter_messages(channel).offset_id(offset_id);

        let mut target_msg = None;
        while let Some(msg) = messages
            .next()
            .await
            .map_err(|e| TelegramError::Download(format!("iter messages: {e}")))?
        {
            if i64::from(msg.id()) == message_id {
                target_msg = Some(msg);
                break;
            }
            // Messages are in descending ID order; stop searching below target
            if i64::from(msg.id()) < message_id {
                break;
            }
        }

        let msg = target_msg.ok_or(TelegramError::MessageNotFound(message_id))?;

        // Download the media
        let media = msg
            .media()
            .ok_or(TelegramError::Download("message has no media".into()))?;

        // Smart, progress-based timeout. A download that keeps making progress is
        // never killed regardless of absolute speed — only one that (a) STALLS (no
        // bytes for the idle window) or (b) DEGRADES (recent rate collapses far below
        // its own lifetime average, i.e. the connection is going bad) is failed, so
        // MultiTransport can try a different session. This replaces a blunt total-time
        // cap, which wrongly truncated a large block downloading slowly but steadily.
        use std::time::Instant;
        const IDLE_TIMEOUT: Duration = Duration::from_secs(45); // no chunk → stalled
        const SAMPLE_WINDOW: Duration = Duration::from_secs(20); // recent-rate window
        const DEGRADE_FRACTION: f64 = 0.25; // recent < 25% of lifetime avg → degrading

        let mut data = Vec::new();
        let mut download = client.iter_download(&media);
        let start = Instant::now();
        let mut window_start = start;
        let mut window_bytes: u64 = 0;
        loop {
            match tokio::time::timeout(IDLE_TIMEOUT, download.next()).await {
                Ok(Ok(Some(chunk))) => {
                    window_bytes += chunk.len() as u64;
                    data.extend_from_slice(&chunk);
                }
                Ok(Ok(None)) => break, // complete
                Ok(Err(e)) => {
                    return Err(TelegramError::Download(format!("download chunk: {e}")));
                }
                Err(_) => {
                    return Err(TelegramError::Download(format!(
                        "download stalled: no data for {}s after {} bytes",
                        IDLE_TIMEOUT.as_secs(),
                        data.len()
                    )));
                }
            }
            // Degradation check: compare the recent window's rate to the lifetime
            // average. Steady-slow downloads (recent ≈ average) pass; a connection
            // collapsing to a fraction of its established rate is failed early.
            let we = window_start.elapsed();
            if we >= SAMPLE_WINDOW {
                if download_is_degrading(
                    window_bytes,
                    we,
                    data.len() as u64,
                    start.elapsed(),
                    DEGRADE_FRACTION,
                ) {
                    let recent_rate = window_bytes as f64 / we.as_secs_f64().max(0.001);
                    let lifetime_rate =
                        data.len() as f64 / start.elapsed().as_secs_f64().max(0.001);
                    return Err(TelegramError::Download(format!(
                        "download degrading: recent {recent_rate:.0} B/s vs lifetime {lifetime_rate:.0} B/s"
                    )));
                }
                window_start = Instant::now();
                window_bytes = 0;
            }
        }

        Ok(DownloadResult { data, message_id })
    }

    // ── Ranged reads (block-device P3.1 primitive) ────────────────────────────
    //
    // The block device needs to read a *slice* of a large (~45 MiB) document
    // without pulling the whole thing. `download_block`/`iter_download` fetch
    // the entire document; these resolve the raw file location once and issue
    // `upload.GetFile` for a byte range, stitching across Telegram's 1 MiB
    // request-boundary rule.

    /// Bounded retry with flood-aware backoff for the ranged read path —
    /// mirrors `download_block`'s policy (ranged reads are the DEFAULT cold
    /// path for block devices, so a transient error or FLOOD_WAIT must not become
    /// an immediate EIO at the filesystem). The closure re-runs from the
    /// resolve step, so a `FILE_REFERENCE_EXPIRED` retry gets a fresh
    /// file_reference. A `FILE_MIGRATE` (media homed on a foreign DC) is
    /// surfaced distinctly and NOT retried — cross-DC `GetFile` routing is a
    /// known unimplemented residual, not a transient.
    async fn retry_ranged<F, Fut>(&self, what: &str, attempt_fn: F) -> Result<Vec<u8>>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>>>,
    {
        let mut last_err: Option<TelegramError> = None;
        for attempt in 0..self.config.max_retries.max(1) {
            match attempt_fn().await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("FILE_MIGRATE") {
                        return Err(TelegramError::Download(format!(
                            "{what}: document lives on a foreign DC (FILE_MIGRATE) — \
                             cross-DC ranged reads are not implemented yet: {e}"
                        )));
                    }
                    self.stats.download_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(attempt, error = %e, "{what} attempt failed");
                    if attempt + 1 < self.config.max_retries {
                        if let Some(secs) = extract_flood_wait(&e) {
                            tokio::time::sleep(std::time::Duration::from_secs(secs.min(120))).await;
                        } else {
                            let shift = attempt.min(32);
                            let delay = self
                                .config
                                .retry_base_delay_ms
                                .saturating_mul(1u64 << shift)
                                .min(60_000);
                            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        }
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or(TelegramError::Download(format!(
            "{what}: retries exhausted"
        ))))
    }

    /// Resolve a message's document into a raw `InputFileLocation`, plus its
    /// DC id and byte size, via one `GetMessages` round-trip. This does NOT
    /// cache today: the ranged read path (`download_range`/`download_tail`)
    /// deliberately re-resolves on every call inside its retry closure, so a
    /// `FILE_REFERENCE_EXPIRED` retry always gets a fresh file_reference. A
    /// single-flight expiring location cache is P3.1a in the plan.
    pub async fn resolve_document(
        &self,
        message_id: i64,
    ) -> Result<(tl::enums::InputFileLocation, i32, u64)> {
        let (ch_id, ch_hash, _topic) = self.get_channel().await?;
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?.clone();
        drop(guard);
        let msg_id_i32 = i32::try_from(message_id).map_err(|_| {
            TelegramError::Download(format!("message_id {message_id} out of i32 range"))
        })?;
        let result = client
            .invoke(&tl::functions::channels::GetMessages {
                channel: tl::enums::InputChannel::Channel(tl::types::InputChannel {
                    channel_id: ch_id,
                    access_hash: ch_hash,
                }),
                id: vec![tl::enums::InputMessage::Id(tl::types::InputMessageId {
                    id: msg_id_i32,
                })],
            })
            .await
            .map_err(|e| TelegramError::Download(format!("GetMessages: {e}")))?;
        let messages = match result {
            tl::enums::messages::Messages::ChannelMessages(m) => m.messages,
            tl::enums::messages::Messages::Messages(m) => m.messages,
            tl::enums::messages::Messages::Slice(m) => m.messages,
            tl::enums::messages::Messages::NotModified(_) => {
                return Err(TelegramError::MessageNotFound(message_id))
            }
        };
        let doc = messages
            .into_iter()
            .find_map(|m| match m {
                tl::enums::Message::Message(msg) => match msg.media {
                    Some(tl::enums::MessageMedia::Document(d)) => match d.document {
                        Some(tl::enums::Document::Document(doc)) => Some(doc),
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            })
            .ok_or(TelegramError::MessageNotFound(message_id))?;
        let size = doc.size.max(0) as u64;
        let dc_id = doc.dc_id;
        let loc = tl::enums::InputFileLocation::InputDocumentFileLocation(
            tl::types::InputDocumentFileLocation {
                id: doc.id,
                access_hash: doc.access_hash,
                file_reference: doc.file_reference,
                thumb_size: String::new(),
            },
        );
        Ok((loc, dc_id, size))
    }

    /// Fetch a byte range `[offset, offset+len)` of a resolved document via raw
    /// `upload.GetFile`, stitching across Telegram's 1 MiB request-boundary rule
    /// (a single request must not cross a 1,048,576-byte boundary and must be
    /// ≤ 1 MiB). Returns fewer bytes than requested only at end-of-file.
    pub async fn get_file_range(
        &self,
        location: &tl::enums::InputFileLocation,
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>> {
        use futures::{stream, StreamExt, TryStreamExt};
        let end = validate_get_range(offset, len)?;
        let client = self
            .part_client
            .lock()
            .await
            .clone()
            .ok_or(TelegramError::NotConnected)?;
        let requests = plan_get_ranges(offset, end);
        let mut replies = stream::iter(requests.into_iter().map(|(req_off, limit)| {
            let client = &client;
            async move {
                let mut failures = 0;
                loop {
                    let response = tokio::time::timeout(
                        crate::transfer::DEFAULT_PART_TIMEOUT,
                        client.invoke(&tl::functions::upload::GetFile {
                            precise: true,
                            cdn_supported: false,
                            location: location.clone(),
                            offset: req_off as i64,
                            limit: limit as i32,
                        }),
                    )
                    .await
                    .map_err(|_| TelegramError::Timeout)
                    .and_then(|r| r.map_err(part_error));
                    match response {
                        Ok(tl::enums::upload::File::File(f)) => {
                            self.stats
                                .bytes_downloaded
                                .fetch_add(f.bytes.len() as u64, Ordering::Relaxed);
                            return Ok((req_off, limit, f.bytes));
                        }
                        Ok(_) => {
                            return Err(TelegramError::Download("unexpected CDN redirect".into()))
                        }
                        Err(e) => {
                            if let Some(seconds) = extract_flood_wait(&e) {
                                tokio::time::sleep(Duration::from_secs(seconds)).await;
                            } else {
                                failures += 1;
                                if failures >= self.config.max_retries {
                                    return Err(e);
                                }
                            }
                        }
                    }
                }
            }
        }))
        .buffered(part_window()?);
        let mut out = Vec::with_capacity(len as usize);
        while let Some((start, limit, bytes)) = replies.try_next().await? {
            let pos = offset + out.len() as u64;
            let available = start + bytes.len() as u64;
            if available <= pos {
                break;
            }
            out.extend_from_slice(
                &bytes[(pos - start) as usize..(end.min(available) - start) as usize],
            );
            if bytes.len() < limit as usize {
                break;
            }
        }
        Ok(out)
    }

    async fn do_delete(&self, message_ids: &[i64]) -> Result<()> {
        let channel = self.channel_packed().await?;

        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or(TelegramError::NotConnected)?.clone();
        drop(guard);

        let ids: Vec<i32> = message_ids
            .iter()
            .map(|&id| {
                i32::try_from(id)
                    .map_err(|_| TelegramError::Delete(format!("message_id {id} out of i32 range")))
            })
            .collect::<std::result::Result<Vec<i32>, TelegramError>>()?;
        client
            .delete_messages(channel, &ids)
            .await
            .map_err(|e| TelegramError::Delete(format!("delete: {e}")))?;

        Ok(())
    }
}

/// Maximum bytes per `upload.SaveFilePart` chunk (Telegram's documented limit).
const UPLOAD_CHUNK_SIZE: usize = 512 * 1024;
/// Files larger than this use the big-file upload path (no md5).
const BIG_FILE_THRESHOLD: usize = 10 * 1024 * 1024;

/// Upload an in-memory buffer to Telegram via the public `upload.SaveFilePart` /
/// `SaveBigFilePart` calls and return the resulting `InputFile` handle (which we own,
/// unlike grammers' `Uploaded` whose `input_file` is `pub(crate)`). Mirrors grammers'
/// own `upload_stream` logic, specialised for a `&[u8]` (no async part stream needed).
async fn upload_in_memory(
    client: &Client,
    data: &[u8],
    filename: &str,
    max_attempts: u32,
) -> Result<tl::enums::InputFile> {
    let mut source = crate::transfer::SliceSource::new(data);
    upload_source_to_input(
        client,
        &mut source,
        filename,
        part_window()?,
        crate::transfer::DEFAULT_PART_TIMEOUT,
        max_attempts,
    )
    .await
}

fn part_window() -> Result<usize> {
    match std::env::var("TEAGARDEN_UPLOAD_IN_FLIGHT_PARTS") {
        Ok(s)=>s.parse::<usize>().ok().filter(|n|*n>0 && *n<=i32::MAX as usize / crate::transfer::UPLOAD_PART_BYTES)
            .ok_or_else(||TelegramError::Upload("TEAGARDEN_UPLOAD_IN_FLIGHT_PARTS must be a positive resident-memory budget in parts".into())),
        Err(std::env::VarError::NotPresent)=>Ok(crate::transfer::DEFAULT_IN_FLIGHT_PARTS),
        Err(e)=>Err(TelegramError::Upload(e.to_string())),
    }
}

fn part_error(error: InvocationError) -> TelegramError {
    match error {
        InvocationError::Rpc(e) if e.code == 420 => e
            .value
            .map(|n| TelegramError::RateLimited { seconds: n })
            .unwrap_or_else(|| TelegramError::Upload(e.to_string())),
        InvocationError::Dropped => TelegramError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "MTProto part request dropped",
        )),
        InvocationError::Rpc(e) if e.code >= 500 => {
            TelegramError::Io(std::io::Error::other(e.to_string()))
        }
        InvocationError::Io(e) => TelegramError::Io(e),
        InvocationError::Transport(e) => TelegramError::Io(std::io::Error::other(e.to_string())),
        e => TelegramError::Upload(e.to_string()),
    }
}

async fn upload_source_to_input(
    client: &Client,
    source: &mut (dyn crate::transfer::UploadSource + '_),
    filename: &str,
    window: usize,
    timeout: Duration,
    attempts: u32,
) -> Result<tl::enums::InputFile> {
    let file_id = source.upload_id();
    let big = source.size() > BIG_FILE_THRESHOLD as u64;
    let total_parts = i32::try_from(source.size().div_ceil(UPLOAD_CHUNK_SIZE as u64).max(1))
        .map_err(|_| TelegramError::Upload("too many parts".into()))?;
    let done = crate::transfer::upload_source_parts(
        source,
        window,
        timeout,
        attempts,
        |part, bytes| async move {
            let accepted = if big {
                client
                    .invoke(&tl::functions::upload::SaveBigFilePart {
                        file_id,
                        file_part: part as i32,
                        file_total_parts: total_parts,
                        bytes: bytes.to_vec(),
                    })
                    .await
            } else {
                client
                    .invoke(&tl::functions::upload::SaveFilePart {
                        file_id,
                        file_part: part as i32,
                        bytes: bytes.to_vec(),
                    })
                    .await
            }
            .map_err(part_error)?;
            if accepted {
                Ok(())
            } else {
                Err(TelegramError::Upload("server rejected part".into()))
            }
        },
    )
    .await?;
    let name = if filename.is_empty() { "a" } else { filename }.to_owned();
    Ok(if big {
        tl::enums::InputFile::Big(tl::types::InputFileBig {
            id: file_id,
            parts: done.parts,
            name,
        })
    } else {
        tl::enums::InputFile::File(tl::types::InputFile {
            id: file_id,
            parts: done.parts,
            name,
            md5_checksum: done.md5,
        })
    })
}

// Shared by the MTProto sender and the opt-in recording mock. Each callback is
// exactly one RPC part; the mock does not reimplement the scheduling policy.
#[cfg(test)]
pub(crate) async fn upload_parts<'a, F, Fut>(
    data: &'a [u8],
    max_attempts: u32,
    send: F,
) -> Result<()>
where
    F: Fn(usize, &'a [u8]) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<()>> + Send,
{
    let mut source = crate::transfer::SliceSource::new(data);
    crate::transfer::upload_source_parts(
        &mut source,
        4,
        crate::transfer::DEFAULT_PART_TIMEOUT,
        max_attempts,
        |part, _| {
            let start = part * UPLOAD_CHUNK_SIZE;
            send(
                part,
                &data[start..(start + UPLOAD_CHUNK_SIZE).min(data.len())],
            )
        },
    )
    .await
    .map(|_| ())
}

#[cfg(test)]
mod upload_part_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test(start_paused = true)]
    async fn parallel_parts_retry_only_the_flooded_part_and_keep_exact_indices() {
        let payload = vec![0x42; 4 * UPLOAD_CHUNK_SIZE + 13];
        let counts: Vec<_> = (0..5).map(|_| AtomicUsize::new(0)).collect();
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        upload_parts(&payload, 3, |part, chunk| {
            let counts = &counts;
            let active = &active;
            let peak = &peak;
            async move {
                assert_eq!(chunk.len(), if part == 4 { 13 } else { UPLOAD_CHUNK_SIZE });
                let n = counts[part].fetch_add(1, Ordering::SeqCst);
                if part == 2 && n == 0 {
                    return Err(TelegramError::RateLimited { seconds: 2 });
                }
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .unwrap();
        assert_eq!(
            counts
                .iter()
                .map(|n| n.load(Ordering::SeqCst))
                .collect::<Vec<_>>(),
            vec![1, 1, 2, 1, 1]
        );
        assert!((2..=4).contains(&peak.load(Ordering::SeqCst)));
    }
}

/// A random i64 for `random_id` / `file_id`. Uses the OS RNG (already a dependency).
fn generate_random_i64() -> i64 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Extract the id of the newly-created message from a `messages.SendMedia` `Updates`
/// response (the `updateMessageID` / `updateNewChannelMessage` carrying our send).
// grammers-mtproto 0.10 manual_tl::Message requires body < 1_044_448.
// upload.File framing plus rpc_result is 28 bytes; precise limits are KiB aligned.
const GET_FILE_MAX_BYTES: u64 = ((1_044_448 - 28 - 1) / 1024) * 1024;
fn plan_get_ranges(offset: u64, end: u64) -> Vec<(u64, u32)> {
    const MB: u64 = 1024 * 1024;
    const ALIGN: u64 = 1024;
    let mut pos = offset;
    let mut ranges = Vec::new();
    while pos < end {
        let start = pos / ALIGN * ALIGN;
        let stop = (end.div_ceil(ALIGN) * ALIGN)
            .min(start + GET_FILE_MAX_BYTES)
            .min((start / MB + 1) * MB);
        ranges.push((start, (stop - start) as u32));
        pos = stop;
    }
    ranges
}

#[cfg(test)]
mod pipeline_read_tests {
    use super::*;
    #[test]
    fn largest_pinned_grammers_reply_is_safe_and_ranges_cover_without_crossing_boundaries() {
        assert_eq!(GET_FILE_MAX_BYTES, 1019 * 1024);
        const { assert!(GET_FILE_MAX_BYTES + 28 < 1_044_448) };
        const { assert!(GET_FILE_MAX_BYTES + 1024 + 28 >= 1_044_448) };
        for (offset, n) in [(0, 100 * 1024 * 1024), (17, 8191), (1048575, 1048578)] {
            let mut previous = offset;
            for (start, len) in plan_get_ranges(offset, offset + n) {
                assert!(start <= previous);
                assert_eq!(start % 1024, 0);
                assert_eq!(len % 1024, 0);
                assert!(u64::from(len) <= GET_FILE_MAX_BYTES);
                assert_eq!(
                    start / (1024 * 1024),
                    (start + u64::from(len) - 1) / (1024 * 1024)
                );
                previous = start + u64::from(len);
            }
            assert!(previous >= offset + n);
        }
    }
}

fn uploaded_document_size(updates: &tl::enums::Updates, message_id: i32) -> Option<usize> {
    use tl::enums::{Document, Message, MessageMedia, Update, Updates};
    let scan = |items: &[Update]| {
        items.iter().find_map(|item| {
            let message = match item {
                Update::NewMessage(m) => &m.message,
                Update::NewChannelMessage(m) => &m.message,
                _ => return None,
            };
            if let Message::Message(m) = message {
                if m.id != message_id {
                    return None;
                }
                if let Some(MessageMedia::Document(media)) = &m.media {
                    if let Some(Document::Document(doc)) = &media.document {
                        return usize::try_from(doc.size).ok();
                    }
                }
            }
            None
        })
    };
    match updates {
        Updates::Updates(u) => scan(&u.updates),
        Updates::Combined(u) => scan(&u.updates),
        Updates::UpdateShort(u) => scan(std::slice::from_ref(&u.update)),
        _ => None,
    }
}

fn extract_new_message_id(updates: &tl::enums::Updates) -> Option<i32> {
    use tl::enums::{Message as M, Update, Updates};
    let scan = |ups: &[tl::enums::Update]| -> Option<i32> {
        for u in ups {
            match u {
                Update::MessageId(m) => return Some(m.id),
                Update::NewChannelMessage(m) => {
                    if let M::Message(msg) = &m.message {
                        return Some(msg.id);
                    }
                }
                Update::NewMessage(m) => {
                    if let M::Message(msg) = &m.message {
                        return Some(msg.id);
                    }
                }
                _ => {}
            }
        }
        None
    };
    match updates {
        Updates::Updates(u) => scan(&u.updates),
        Updates::Combined(u) => scan(&u.updates),
        Updates::UpdateShort(u) => scan(std::slice::from_ref(&u.update)),
        _ => None,
    }
}

/// Decide whether an in-flight download has DEGRADED: its recent-window byte rate
/// has collapsed below `degrade_fraction` of its own lifetime average. A
/// slow-but-steady download (recent ≈ lifetime) survives; only a connection
/// falling to a small fraction of its established rate is failed early so
/// `MultiTransport` can try another session. Pure so the progress-timeout policy
/// is unit-tested and can't silently drift. Returns `false` until a lifetime rate
/// exists (no data yet → nothing to degrade from).
fn download_is_degrading(
    window_bytes: u64,
    window_elapsed: std::time::Duration,
    total_bytes: u64,
    total_elapsed: std::time::Duration,
    degrade_fraction: f64,
) -> bool {
    let recent_rate = window_bytes as f64 / window_elapsed.as_secs_f64().max(1e-3);
    let lifetime_rate = total_bytes as f64 / total_elapsed.as_secs_f64().max(1e-3);
    lifetime_rate > 0.0 && recent_rate < lifetime_rate * degrade_fraction
}

/// Validate a requested byte range for [`TelegramClient::get_file_range`] and
/// return the exclusive end offset. Fails closed — rather than panicking, wrapping,
/// or issuing a negative `upload.GetFile` offset — when `offset + len` overflows or
/// the range would exceed Telegram's `i64` offset space. Keeping `end <= i64::MAX`
/// also makes every downstream window computation (`req_off + CHUNK`, the 1 MiB
/// boundary math, the `as i64` cast) overflow-safe.
fn validate_get_range(offset: u64, len: u32) -> Result<u64> {
    offset
        .checked_add(u64::from(len))
        .filter(|&end| end <= i64::MAX as u64)
        .ok_or_else(|| {
            TelegramError::Download(format!(
                "invalid ranged read: offset {offset} + len {len} overflows or exceeds i64::MAX"
            ))
        })
}

#[cfg(test)]
mod range_tests {
    use super::validate_get_range;

    #[test]
    fn accepts_normal_ranges() {
        assert_eq!(validate_get_range(0, 4096).unwrap(), 4096);
        assert_eq!(
            validate_get_range(45 * 1024 * 1024, 512 * 1024).unwrap(),
            45 * 1024 * 1024 + 512 * 1024
        );
        // the i64::MAX boundary with zero len is the largest accepted offset
        assert_eq!(
            validate_get_range(i64::MAX as u64, 0).unwrap(),
            i64::MAX as u64
        );
    }

    #[test]
    fn rejects_overflow_and_out_of_i64_range() {
        assert!(validate_get_range(u64::MAX, 1).is_err()); // u64 overflow
        assert!(validate_get_range(u64::MAX - 10, 4096).is_err()); // u64 overflow
        assert!(validate_get_range(i64::MAX as u64 + 1, 0).is_err()); // offset > i64::MAX
        assert!(validate_get_range(i64::MAX as u64, 1).is_err()); // end > i64::MAX
    }
}

#[cfg(test)]
mod session_format_tests {
    use super::{TelegramClient, TelegramConfig};

    #[test]
    fn absent_and_sqlite_session_files_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let config = TelegramConfig {
            session_path: path.display().to_string(),
            ..TelegramConfig::default()
        };
        let client = TelegramClient::new(config);
        client.reject_legacy_session_file().unwrap();

        std::fs::write(&path, b"SQLite format 3\0test").unwrap();
        client.reject_legacy_session_file().unwrap();
    }

    #[test]
    fn legacy_session_is_rejected_without_modification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session");
        let legacy = b"legacy-grammers-session";
        std::fs::write(&path, legacy).unwrap();
        let config = TelegramConfig {
            session_path: path.display().to_string(),
            ..TelegramConfig::default()
        };
        let client = TelegramClient::new(config);

        let error = client.reject_legacy_session_file().unwrap_err();
        assert!(error.to_string().contains("pre-1.0 Grammers session"));
        assert_eq!(std::fs::read(path).unwrap(), legacy);
    }
}

#[cfg(test)]
mod download_timeout_tests {
    use super::download_is_degrading;
    use std::time::Duration;

    // The production DEGRADE_FRACTION (recent must stay ≥ 25% of lifetime average).
    const FRAC: f64 = 0.25;

    #[test]
    fn steady_slow_download_survives() {
        // Recent 20s window (20 KiB) matches the lifetime rate (100 KiB / 100s =
        // 1 KiB/s). A slow-but-steady download must NOT be killed.
        assert!(!download_is_degrading(
            20 * 1024,
            Duration::from_secs(20),
            100 * 1024,
            Duration::from_secs(100),
            FRAC
        ));
    }

    #[test]
    fn collapsed_recent_rate_is_degrading() {
        // Lifetime ~1 KiB/s but the recent 20s window delivered only ~51 B/s (5% of
        // lifetime, below the 25% floor) — the connection is going bad → fail early.
        assert!(download_is_degrading(
            1024,
            Duration::from_secs(20),
            100 * 1024,
            Duration::from_secs(100),
            FRAC
        ));
    }

    #[test]
    fn accelerating_download_survives() {
        // Recent (2.5 KiB/s) far above lifetime (1 KiB/s) — catching up, never degraded.
        assert!(!download_is_degrading(
            50 * 1024,
            Duration::from_secs(20),
            100 * 1024,
            Duration::from_secs(100),
            FRAC
        ));
    }

    #[test]
    fn boundary_just_above_and_below_the_floor() {
        // lifetime 1024 B/s; floor = 256 B/s over a 20s window.
        // 300 B/s (6000 B / 20s) is just above the floor → survive.
        assert!(!download_is_degrading(
            6000,
            Duration::from_secs(20),
            102_400,
            Duration::from_secs(100),
            FRAC
        ));
        // 200 B/s (4000 B / 20s) is just below the floor → degrading.
        assert!(download_is_degrading(
            4000,
            Duration::from_secs(20),
            102_400,
            Duration::from_secs(100),
            FRAC
        ));
    }

    #[test]
    fn no_lifetime_rate_is_not_degrading() {
        // No bytes received yet → no established rate to degrade from.
        assert!(!download_is_degrading(
            0,
            Duration::from_secs(20),
            0,
            Duration::from_secs(20),
            FRAC
        ));
    }
}

#[cfg(test)]
mod metadata_size_tests {
    use super::*;

    /// The metadata snapshot always travels over the user's MTProto session
    /// (`MultiTransport` routes `sync_metadata` to session 0), whose document
    /// limit is 4000 parts x 512 KiB, not the Bot API's 50 MB. A 60 MiB snapshot
    /// must not be refused for its size.
    #[tokio::test]
    async fn a_60_mib_metadata_snapshot_is_not_refused_for_its_size() {
        let client = TelegramClient::new(TelegramConfig::default());
        // Past the connection gate, so the size check is what decides.
        client.connected.store(true, Ordering::SeqCst);
        let blob = vec![0u8; 60 * 1024 * 1024];
        let err = client.sync_metadata(&blob).await.unwrap_err();
        assert!(
            !matches!(err, TelegramError::BlockTooLarge { .. }),
            "a 60 MiB snapshot was refused for its size: {err}"
        );
    }
}

#[cfg(test)]
mod metadata_limit_tests {
    use super::*;

    #[test]
    fn metadata_limit_is_4000_parts_of_512_kib() {
        assert_eq!(MAX_METADATA_UPLOAD_BYTES, 2_097_152_000);
        assert!(check_metadata_size(MAX_METADATA_UPLOAD_BYTES).is_ok());
        assert!(matches!(
            check_metadata_size(MAX_METADATA_UPLOAD_BYTES + 1),
            Err(TelegramError::BlockTooLarge { .. })
        ));
        // The part count the uploader computes for the largest accepted size is
        // exactly Telegram's 4000.
        assert_eq!(MAX_METADATA_UPLOAD_BYTES.div_ceil(UPLOAD_CHUNK_SIZE), 4000);
    }
}
