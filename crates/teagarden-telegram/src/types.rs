use serde::{Deserialize, Serialize};

/// Reference to a volume's storage location: the shared TeaGarden supergroup forum
/// plus this volume's topic within it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRef {
    /// Shared forum supergroup ID (the same for every volume).
    pub id: i64,
    /// Forum group access hash (session-scoped; re-resolved at mount).
    pub access_hash: i64,
    /// This volume's forum topic id (the topic's root message id) within the group.
    pub topic_id: i64,
}

/// Telegram API configuration.
#[derive(Debug, Clone)]
pub struct TelegramConfig {
    /// Telegram API ID (from my.telegram.org).
    pub api_id: i32,
    /// Telegram API hash.
    pub api_hash: String,
    /// Path to session file for persistent auth.
    pub session_path: String,
    /// Maximum BLOCK upload size in bytes. Blocks may also go through Bot API
    /// sessions, whose document limit is 50 MB, hence the default. Metadata
    /// snapshots are not bound by this: they always use the MTProto session and
    /// its own limit, `client::MAX_METADATA_UPLOAD_BYTES`.
    pub max_upload_size: usize,
    /// Maximum concurrent uploads.
    pub max_concurrent_uploads: usize,
    /// Maximum concurrent downloads.
    pub max_concurrent_downloads: usize,
    /// Retry count for failed operations.
    pub max_retries: u32,
    /// Base delay between retries in milliseconds.
    pub retry_base_delay_ms: u64,
    /// Pre-existing channel reference (if the channel was already created for this volume).
    pub channel_ref: Option<ChannelRef>,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            api_id: 0,
            api_hash: String::new(),
            session_path: "teagarden.session".into(),
            max_upload_size: 50 * 1024 * 1024, // 50MB conservative default
            max_concurrent_uploads: 3,
            max_concurrent_downloads: 5,
            max_retries: 3,
            retry_base_delay_ms: 1000,
            channel_ref: None,
        }
    }
}

/// Result of uploading a block to Telegram.
#[derive(Debug, Clone)]
pub struct UploadResult {
    /// Telegram message ID containing this block.
    pub message_id: i64,
    /// Size of the uploaded data.
    pub size: usize,
}

/// Result of downloading a block from Telegram.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    /// The raw block data.
    pub data: Vec<u8>,
    /// Telegram message ID it was downloaded from.
    pub message_id: i64,
}

/// Metadata needed to discover portable documents in a Telegram forum topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentInfo {
    /// Telegram message id containing the document.
    pub message_id: i64,
    /// Filename attached to the Telegram document.
    pub filename: String,
    /// Forum supergroup id.
    pub group_id: i64,
    /// Forum topic id (the root message id).
    pub topic_id: i64,
}

/// One descending page of raw Telegram messages from a single forum topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicDocumentPage {
    /// Document messages in this page, newest first.
    pub documents: Vec<DocumentInfo>,
    /// IDs of every raw message in the page, including text and service messages.
    pub raw_message_ids: Vec<i64>,
    /// Whether Telegram returned fewer than the requested number of raw messages.
    pub exhausted: bool,
}

/// Authentication state.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    /// Not authenticated at all.
    NotAuthenticated,
    /// Phone number submitted, waiting for code.
    AwaitingCode,
    /// Code submitted, waiting for 2FA password.
    AwaitingPassword,
    /// Fully authenticated.
    Authenticated,
}

/// Statistics for the Telegram transport.
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Total number of blocks successfully uploaded.
    pub blocks_uploaded: u64,
    /// Total number of blocks successfully downloaded.
    pub blocks_downloaded: u64,
    /// Total bytes uploaded across all blocks.
    pub bytes_uploaded: u64,
    /// Total bytes downloaded across all blocks.
    pub bytes_downloaded: u64,
    /// Number of upload operations that failed.
    pub upload_errors: u64,
    /// Number of download operations that failed.
    pub download_errors: u64,
    /// Number of Telegram messages (blocks) deleted.
    pub messages_deleted: u64,
}
