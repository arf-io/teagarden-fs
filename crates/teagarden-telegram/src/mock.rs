use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::client::{BlockTransport, ForumAdmin, TelegramAuthorizationInfo};
use crate::error::{Result, TelegramError};
use crate::types::{DocumentInfo, DownloadResult, TopicDocumentPage, UploadResult};

/// Fixed mock forum group ID for testing.
const MOCK_CHANNEL_ID: i64 = 999_000_000;
/// Fixed mock group access hash for testing.
const MOCK_ACCESS_HASH: i64 = 1234567890;
/// Fixed mock forum topic ID for testing.
const MOCK_TOPIC_ID: i64 = 42;

/// One [`ForumAdmin`] call the mock received, with every argument, so tests can
/// assert exactly what would have reached Telegram (e.g. a topic title).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForumCall {
    /// Account capability query before a restore upload.
    IsPremiumUser,
    /// `create_forum_group(title)`.
    CreateGroup {
        /// Group title sent.
        title: String,
    },
    /// `create_topic(group_id, access_hash, title)`.
    CreateTopic {
        /// Group the topic was created in.
        group_id: i64,
        /// Access hash sent with it.
        access_hash: i64,
        /// Topic title sent.
        title: String,
    },
    /// `delete_topic(group_id, access_hash, topic_id)`.
    DeleteTopic {
        /// Group the topic lives in.
        group_id: i64,
        /// Access hash sent with it.
        access_hash: i64,
        /// Topic deleted.
        topic_id: i64,
    },
    /// MTProto `channels.editBanned` with view_messages=true.
    BanMember {
        /// Supergroup id.
        group_id: i64,
        /// Session-scoped group access hash.
        access_hash: i64,
        /// Telegram account id to ban.
        user_id: i64,
    },
    /// MTProto `account.resetAuthorization` for one session hash.
    ResetAuthorization {
        /// Authorization hash from account.getAuthorizations.
        hash: i64,
    },
    /// MTProto `auth.resetAuthorizations` for every other session.
    ResetOtherAuthorizations,
    /// MTProto `account.getAuthorizations` used to identify the current session.
    GetCurrentAuthorization,
}

type ServerParts = Vec<Arc<Vec<u8>>>;
type IncompleteParts = Vec<Option<Arc<Vec<u8>>>>;

/// In-memory mock Telegram transport for testing.
pub struct MockTransport {
    messages: Arc<Mutex<HashMap<i64, Vec<u8>>>>,
    part_messages: Arc<Mutex<HashMap<i64, ServerParts>>>,
    documents: Arc<Mutex<HashMap<i64, DocumentInfo>>>,
    topic_messages: Arc<Mutex<HashMap<i64, (i64, i64)>>>,
    telegram_user_id: Mutex<Option<i64>>,
    /// Additional safe account authorization metadata for correlation tests.
    pub extra_authorizations: Mutex<Vec<TelegramAuthorizationInfo>>,
    channel_ref: Mutex<Option<(i64, i64, i64)>>,
    next_id: Arc<AtomicI64>,
    connected: AtomicBool,
    /// If set, all uploads will fail with this error message.
    pub fail_uploads: Mutex<Option<String>>,
    /// If set, all downloads will fail with this error message.
    pub fail_downloads: Mutex<Option<String>>,
    /// Total bytes served by `download_block` + `download_range` — lets tests
    /// assert read amplification (a 4 KiB record read fetches ≈4 KiB, not 45 MiB).
    bytes_served: AtomicU64,
    /// Number of read calls served (drives FLOOD_WAIT injection).
    read_count: AtomicUsize,
    /// Number of successful uploads so far.
    upload_count: AtomicUsize,
    file_part_delay: Mutex<Option<std::time::Duration>>,
    file_part_window: AtomicUsize,
    fail_file_part_once: AtomicUsize,
    local_write_bytes: Mutex<Option<Arc<crate::transfer::LocalWriteStats>>>,
    partial_files: Mutex<HashMap<i64, IncompleteParts>>,
    file_receipts: Mutex<HashMap<i64, UploadResult>>,
    file_upload_calls: AtomicUsize,
    file_upload_bytes: AtomicUsize,
    file_parts: AtomicUsize,
    active_parts: AtomicUsize,
    peak_parts: AtomicUsize,
    /// If `Some(n)`, the (n+1)-th read returns a simulated FLOOD_WAIT.
    flood_after: Mutex<Option<usize>>,
    read_failure_once: Mutex<Option<usize>>,
    /// If `Some(n)`, uploads after the n-th fail (crash / lost-upload injection).
    fail_uploads_after: Mutex<Option<usize>>,
    /// Filenames passed to `upload_block`, in order — lets tests assert wire
    /// opacity (uploaded names must not leak role/ids, e.g. no "seg-3.bin").
    uploaded_filenames: Mutex<Vec<String>>,
    /// Number of upcoming upload_block calls that store bytes but lose the ack.
    withhold_upload_acks: Mutex<usize>,
    /// If true, `delete_message` / `delete_messages` fail — a transient delete
    /// outage (GC must defer + retry, never roll back its repoints).
    fail_deletes: AtomicBool,
    /// If true, `upload_block` never completes (a wedged upload) — exercises the
    /// caller's bounded-wait / timeout path. Cleared with `set_hang_uploads(false)`.
    hang_uploads: AtomicBool,
    /// Every [`ForumAdmin`] call, in order.
    forum_calls: Mutex<Vec<ForumCall>>,
    /// Next topic id `create_topic` hands out.
    next_topic_id: AtomicI64,
    /// If true, every [`ForumAdmin`] call fails (after being recorded).
    fail_forum: AtomicBool,
    /// Number of upcoming `sync_metadata` calls that STORE the message but then
    /// report `Timeout` — what a client sees when Telegram keeps a message and the
    /// acknowledgement never arrives in time.
    withhold_metadata_acks: Mutex<usize>,
    /// If `Some(n)`, `sync_metadata` stores `n` more messages and then fails
    /// without storing (a snapshot publish refused, the process dying first).
    metadata_budget: Mutex<Option<usize>>,
    /// When set, `sync_metadata` never completes (and stores nothing).
    hang_metadata: AtomicBool,
    /// Run (once) right after the next `sync_metadata` stored its message and
    /// before it returns the id: what happens to the caller's machine while
    /// the upload is acknowledged (a full disk, another writer).
    after_metadata_sync: Mutex<Option<AfterMetadataSync>>,
    upload_gates: Mutex<HashMap<String, UploadGate>>,
}

/// See [`MockTransport::after_next_metadata_sync`].
type AfterMetadataSync = Box<dyn FnOnce() + Send>;
type UploadGate = (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);

impl MockTransport {
    /// An authenticated user session before selecting any storage group or topic.
    pub fn new_unbound() -> Self {
        let transport = Self::new();
        transport.clear_channel_binding();
        transport
    }

    /// A distinct authenticated session sharing the topic, with independent failures.
    pub fn fork_session(&self) -> Self {
        let mut session = Self::new_unbound();
        session.messages = Arc::clone(&self.messages);
        session.part_messages = Arc::clone(&self.part_messages);
        session.documents = Arc::clone(&self.documents);
        session.topic_messages = Arc::clone(&self.topic_messages);
        session.next_id = Arc::clone(&self.next_id);
        *session.telegram_user_id.lock().unwrap() = *self.telegram_user_id.lock().unwrap();
        session
    }

    /// Simulate expiry of Telegram's temporary uploaded parts, retaining receipts.
    pub fn forget_file_parts(&self) {
        self.partial_files.lock().unwrap().clear();
    }

    /// Pause one acknowledged upload after storage, allowing deterministic races.
    pub fn gate_next_upload(
        &self,
        filename: &str,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    ) {
        self.upload_gates
            .lock()
            .unwrap()
            .insert(filename.to_owned(), (entered, release));
    }

    /// Drop only the session's selected topic, retaining remote mock documents.
    pub fn clear_channel_binding(&self) {
        *self.channel_ref.lock().unwrap() = None;
    }

    /// Creates a new, connected mock transport with no stored messages.
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(HashMap::new())),
            part_messages: Arc::new(Mutex::new(HashMap::new())),
            documents: Arc::new(Mutex::new(HashMap::new())),
            topic_messages: Arc::new(Mutex::new(HashMap::new())),
            telegram_user_id: Mutex::new(Some(12345)),
            extra_authorizations: Mutex::new(Vec::new()),
            channel_ref: Mutex::new(Some((MOCK_CHANNEL_ID, MOCK_ACCESS_HASH, MOCK_TOPIC_ID))),
            next_id: Arc::new(AtomicI64::new(1)),
            connected: AtomicBool::new(true),
            fail_uploads: Mutex::new(None),
            fail_downloads: Mutex::new(None),
            bytes_served: AtomicU64::new(0),
            read_count: AtomicUsize::new(0),
            upload_count: AtomicUsize::new(0),
            file_part_delay: Mutex::new(None),
            file_part_window: AtomicUsize::new(crate::transfer::DEFAULT_IN_FLIGHT_PARTS),
            fail_file_part_once: AtomicUsize::new(usize::MAX),
            local_write_bytes: Mutex::new(None),
            partial_files: Mutex::new(HashMap::new()),
            file_receipts: Mutex::new(HashMap::new()),
            file_upload_calls: AtomicUsize::new(0),
            file_upload_bytes: AtomicUsize::new(0),
            file_parts: AtomicUsize::new(0),
            active_parts: AtomicUsize::new(0),
            peak_parts: AtomicUsize::new(0),
            flood_after: Mutex::new(None),
            read_failure_once: Mutex::new(None),
            fail_uploads_after: Mutex::new(None),
            uploaded_filenames: Mutex::new(Vec::new()),
            withhold_upload_acks: Mutex::new(0),
            fail_deletes: AtomicBool::new(false),
            hang_uploads: AtomicBool::new(false),
            forum_calls: Mutex::new(Vec::new()),
            next_topic_id: AtomicI64::new(100),
            fail_forum: AtomicBool::new(false),
            withhold_metadata_acks: Mutex::new(0),
            metadata_budget: Mutex::new(None),
            hang_metadata: AtomicBool::new(false),
            after_metadata_sync: Mutex::new(None),
            upload_gates: Mutex::new(HashMap::new()),
        }
    }

    /// Run `f` once, right after the next successful `sync_metadata` stored its
    /// message (before the id is returned to the caller).
    pub fn after_next_metadata_sync(&self, f: impl FnOnce() + Send + 'static) {
        *self.after_metadata_sync.lock().unwrap() = Some(Box::new(f));
    }

    /// The next `n` `sync_metadata` calls store their message (it gets an id and
    /// `fetch_metadata` serves it) but return `TelegramError::Timeout`.
    pub fn withhold_metadata_acks(&self, n: usize) {
        *self.withhold_metadata_acks.lock().unwrap() = n;
    }

    /// Allow `n` more successful `sync_metadata` calls, then fail every later one
    /// without storing anything. `None` removes the limit.
    pub fn set_metadata_budget(&self, n: Option<usize>) {
        *self.metadata_budget.lock().unwrap() = n;
    }

    /// Store `data` under `message_id`, replacing whatever was there — what a
    /// storage provider that answers one message id with other bytes looks like,
    /// and how tests load fixture messages at their recorded ids.
    pub fn put_raw(&self, message_id: i64, data: Vec<u8>) {
        self.part_messages.lock().unwrap().remove(&message_id);
        self.messages.lock().unwrap().insert(message_id, data);
    }

    /// Insert a named document with an explicit group and topic for enumeration tests.
    pub fn put_document(
        &self,
        message_id: i64,
        group_id: i64,
        topic_id: i64,
        filename: &str,
        data: Vec<u8>,
    ) {
        self.part_messages.lock().unwrap().remove(&message_id);
        self.messages.lock().unwrap().insert(message_id, data);
        self.topic_messages
            .lock()
            .unwrap()
            .insert(message_id, (group_id, topic_id));
        self.documents.lock().unwrap().insert(
            message_id,
            DocumentInfo {
                message_id,
                filename: filename.to_string(),
                group_id,
                topic_id,
            },
        );
    }

    /// Insert a text-only topic message for raw pagination tests.
    pub fn put_text_message(&self, message_id: i64, group_id: i64, topic_id: i64) {
        self.messages.lock().unwrap().insert(message_id, Vec::new());
        self.topic_messages
            .lock()
            .unwrap()
            .insert(message_id, (group_id, topic_id));
    }

    /// Configure the account id returned by [`BlockTransport::telegram_user_id`].
    pub fn set_telegram_user_id(&self, user_id: Option<i64>) {
        *self.telegram_user_id.lock().unwrap() = user_id;
    }

    /// Every [`ForumAdmin`] call received so far, in order.
    pub fn forum_calls(&self) -> Vec<ForumCall> {
        self.forum_calls.lock().unwrap().clone()
    }

    /// Make every [`ForumAdmin`] call fail (it is still recorded) until cleared.
    pub fn set_fail_forum(&self, fail: bool) {
        self.fail_forum.store(fail, Ordering::Relaxed);
    }

    fn forum_gate(&self, call: ForumCall) -> Result<()> {
        self.forum_calls.lock().unwrap().push(call);
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }
        if self.fail_forum.load(Ordering::Relaxed) {
            return Err(TelegramError::Api("simulated forum failure".into()));
        }
        Ok(())
    }

    /// Every filename passed to `upload_block`, in upload order. Used by wire-opacity
    /// tests to assert uploaded document names carry no role/id (no "seg-{id}.bin").
    pub fn uploaded_filenames(&self) -> Vec<String> {
        self.uploaded_filenames.lock().unwrap().clone()
    }

    /// Toggles the simulated connection state to exercise not-connected paths.
    pub fn set_connected(&self, connected: bool) {
        self.connected.store(connected, Ordering::Relaxed);
    }

    /// Total bytes served by reads so far — assert read amplification.
    pub fn bytes_served(&self) -> u64 {
        self.bytes_served.load(Ordering::Relaxed)
    }

    /// Number of read calls served so far.
    pub fn read_count(&self) -> usize {
        self.read_count.load(Ordering::Relaxed)
    }

    /// Inject one transient read failure after `successful_reads` more reads.
    pub fn fail_one_read_after(&self, successful_reads: usize) {
        *self.read_failure_once.lock().unwrap() = Some(
            self.read_count
                .load(Ordering::Relaxed)
                .saturating_add(successful_reads),
        );
    }

    /// Reset the byte / read / upload counters (leaves stored messages intact).
    pub fn reset_counters(&self) {
        self.bytes_served.store(0, Ordering::Relaxed);
        self.read_count.store(0, Ordering::Relaxed);
        self.upload_count.store(0, Ordering::Relaxed);
    }

    /// After `n` successful reads, the next read returns a simulated FLOOD_WAIT
    /// (`RateLimited`) — exercises the ranged-read failure/backoff paths (there
    /// is no shipped read-rate governor; P3.4 is the device-layer send governor).
    pub fn set_flood_after(&self, n: usize) {
        *self.flood_after.lock().unwrap() = Some(n);
    }

    /// After `n` successful uploads, subsequent uploads fail — simulates a crash
    /// or a lost upload for durability / recovery tests.
    pub fn set_fail_uploads_after(&self, n: usize) {
        *self.fail_uploads_after.lock().unwrap() = Some(n);
    }

    /// Cause the next `n` uploads to be stored but return a timeout without an id.
    pub fn withhold_upload_acks(&self, n: usize) {
        *self.withhold_upload_acks.lock().unwrap() = n;
    }

    /// Directly drop a stored message, bypassing the connected/auth checks —
    /// simulates a segment lost server-side (negative recovery tests).
    pub fn drop_message(&self, message_id: i64) -> bool {
        self.part_messages.lock().unwrap().remove(&message_id);
        self.messages.lock().unwrap().remove(&message_id).is_some()
    }

    /// Position the next message id (e.g. near `i32::MAX`) to exercise the
    /// message-id ceiling handling.
    pub fn set_next_id(&self, id: i64) {
        self.next_id.store(id, Ordering::Relaxed);
    }

    /// Make `delete_message` / `delete_messages` fail until cleared — simulates
    /// a transient delete outage for GC retry-path tests.
    pub fn set_fail_deletes(&self, fail: bool) {
        self.fail_deletes.store(fail, Ordering::Relaxed);
    }

    /// Make every subsequent `sync_metadata` hang forever (until cleared),
    /// storing nothing: with a timeout around the caller, what a process
    /// killed while its metadata upload was in flight leaves behind.
    pub fn set_hang_metadata(&self, hang: bool) {
        self.hang_metadata.store(hang, Ordering::Relaxed);
    }

    /// Make every subsequent `upload_block` hang forever (until cleared) — a
    /// transport that accepted the request and never answered.
    pub fn set_hang_uploads(&self, hang: bool) {
        self.hang_uploads.store(hang, Ordering::Relaxed);
    }

    /// Bump the read counter and inject a FLOOD_WAIT if armed. Shared by
    /// `download_block` and `download_range`.
    fn read_gate(&self) -> Result<()> {
        let n = self.read_count.fetch_add(1, Ordering::Relaxed);
        let mut once = self.read_failure_once.lock().unwrap();
        if *once == Some(n) {
            *once = None;
            return Err(TelegramError::RateLimited { seconds: 1 });
        }
        drop(once);
        if let Some(threshold) = *self.flood_after.lock().unwrap() {
            if n >= threshold {
                return Err(TelegramError::RateLimited { seconds: 30 });
            }
        }
        Ok(())
    }

    /// Exercise the production MTProto part scheduler with a fixed mock RPC latency.
    pub fn record_file_parts(&self, latency: std::time::Duration) {
        *self.file_part_delay.lock().unwrap() = Some(latency);
    }

    /// Observed local payload and intent/progress writes for the last source upload.
    pub fn local_write_bytes(&self) -> Option<(u64, u64)> {
        self.local_write_bytes
            .lock()
            .unwrap()
            .as_ref()
            .map(|stats| stats.snapshot())
    }

    /// Simulate one interrupted transfer at an individual part.
    pub fn fail_file_part_once(&self, part: usize) {
        self.fail_file_part_once.store(part, Ordering::Relaxed);
    }

    /// Set the resident part budget for a recording transport.
    pub fn set_file_part_window(&self, parts: usize) {
        self.file_part_window.store(parts, Ordering::Relaxed);
    }

    /// File-object upload attempts, bytes, RPC parts and peak in-flight parts.
    pub fn file_upload_metrics(&self) -> (usize, usize, usize, usize) {
        (
            self.file_upload_calls.load(Ordering::Relaxed),
            self.file_upload_bytes.load(Ordering::Relaxed),
            self.file_parts.load(Ordering::Relaxed),
            self.peak_parts.load(Ordering::Relaxed),
        )
    }

    /// Returns the number of messages (blocks) currently stored in the mock.
    pub fn message_count(&self) -> usize {
        self.messages.lock().unwrap().len()
    }

    /// Returns the raw stored bytes for a message ID, or `None` if absent.
    pub fn get_raw(&self, message_id: i64) -> Option<Vec<u8>> {
        if let Some(parts) = self.part_messages.lock().unwrap().get(&message_id) {
            return Some(parts.iter().flat_map(|p| p.iter().copied()).collect());
        }
        self.messages.lock().unwrap().get(&message_id).cloned()
    }
}

impl MockTransport {
    fn stored_part_range(&self, id: i64, offset: u64, len: u64) -> Option<Vec<u8>> {
        let messages = self.part_messages.lock().unwrap();
        let parts = messages.get(&id)?;
        let total = parts.iter().map(|p| p.len() as u64).sum::<u64>();
        let end = offset.saturating_add(len).min(total);
        if offset >= end {
            return Some(Vec::new());
        }
        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut at = 0;
        for part in parts {
            let next = at + part.len() as u64;
            if next > offset && at < end {
                out.extend_from_slice(
                    &part[(offset.saturating_sub(at)) as usize..(end.min(next) - at) as usize],
                );
            }
            at = next;
            if at >= end {
                break;
            }
        }
        Some(out)
    }
    async fn store_owned(&self, data: Vec<u8>, filename: &str) -> Result<UploadResult> {
        self.store_payload(data, None, filename).await
    }
    async fn store_payload(
        &self,
        data: Vec<u8>,
        parts: Option<ServerParts>,
        filename: &str,
    ) -> Result<UploadResult> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }

        if let Some(ref err) = *self.fail_uploads.lock().unwrap() {
            return Err(TelegramError::Upload(err.clone()));
        }
        if self.hang_uploads.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
        // Record the wire-visible filename (even on the paths that later fail is
        // fine — tests assert on successful uploads).
        self.uploaded_filenames
            .lock()
            .unwrap()
            .push(filename.to_string());
        let done = self.upload_count.fetch_add(1, Ordering::Relaxed);
        if let Some(threshold) = *self.fail_uploads_after.lock().unwrap() {
            if done >= threshold {
                return Err(TelegramError::Upload(format!(
                    "simulated upload failure after {threshold} uploads"
                )));
            }
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let size = parts
            .as_ref()
            .map_or(data.len(), |parts| parts.iter().map(|p| p.len()).sum());
        self.messages.lock().unwrap().insert(id, data);
        if let Some(parts) = parts {
            self.part_messages.lock().unwrap().insert(id, parts);
        }
        let (group_id, _, topic_id) = self.channel_ref.lock().unwrap().unwrap_or((
            MOCK_CHANNEL_ID,
            MOCK_ACCESS_HASH,
            MOCK_TOPIC_ID,
        ));
        self.documents.lock().unwrap().insert(
            id,
            DocumentInfo {
                message_id: id,
                filename: filename.to_string(),
                group_id,
                topic_id,
            },
        );
        self.topic_messages
            .lock()
            .unwrap()
            .insert(id, (group_id, topic_id));

        {
            let mut withhold = self.withhold_upload_acks.lock().unwrap();
            if *withhold > 0 {
                *withhold -= 1;
                return Err(TelegramError::Timeout);
            }
        }
        let gate = self.upload_gates.lock().unwrap().remove(filename);
        if let Some((entered, release)) = gate {
            entered.notify_one();
            release.notified().await;
        }

        Ok(UploadResult {
            message_id: id,
            size,
        })
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl BlockTransport for MockTransport {
    async fn upload_file_object(&self, data: &[u8], filename: &str) -> Result<UploadResult> {
        let mut source = crate::transfer::SliceSource::new(data);
        self.upload_file_source(&mut source, filename, crate::transfer::DEFAULT_PART_TIMEOUT)
            .await
    }

    async fn upload_file_source(
        &self,
        source: &mut (dyn crate::transfer::UploadSource + '_),
        filename: &str,
        timeout: std::time::Duration,
    ) -> Result<UploadResult> {
        *self.local_write_bytes.lock().unwrap() = source.local_write_meter();
        let publication = source.publication_id();
        if let Some(result) = self
            .file_receipts
            .lock()
            .unwrap()
            .get(&publication)
            .cloned()
        {
            return Ok(result);
        }
        self.file_upload_calls.fetch_add(1, Ordering::Relaxed);
        let file_id = source.upload_id();
        let size = source.size() as usize;
        let delay = self.file_part_delay.lock().unwrap().unwrap_or_default();
        let timing = crate::transfer::upload_source_parts(
            source,
            self.file_part_window.load(Ordering::Relaxed),
            timeout,
            3,
            |part, bytes| async move {
                if self
                    .fail_file_part_once
                    .compare_exchange(part, usize::MAX, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return Err(TelegramError::Upload("simulated interrupted part".into()));
                }
                if let Some(ref err) = *self.fail_uploads.lock().unwrap() {
                    return Err(TelegramError::Upload(err.clone()));
                }
                if self.hang_uploads.load(Ordering::Relaxed) {
                    std::future::pending::<()>().await;
                }
                self.file_parts.fetch_add(1, Ordering::Relaxed);
                self.file_upload_bytes
                    .fetch_add(bytes.len(), Ordering::Relaxed);
                let active = self.active_parts.fetch_add(1, Ordering::Relaxed) + 1;
                self.peak_parts.fetch_max(active, Ordering::Relaxed);
                if delay.is_zero() {
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::sleep(delay).await;
                }
                self.active_parts.fetch_sub(1, Ordering::Relaxed);
                let mut files = self.partial_files.lock().unwrap();
                let file = files.entry(file_id).or_insert_with(|| {
                    vec![None; size.div_ceil(crate::transfer::UPLOAD_PART_BYTES).max(1)]
                });
                file[part] = Some(bytes);
                Ok(())
            },
        )
        .await?;
        if size >= 100 * 1024 * 1024 {
            eprintln!(
                "MOCK_TRANSFER_STAGE source_read_s={:.6} acknowledgement_s={:.6}",
                timing.source_read_nanos as f64 / 1e9,
                timing.acknowledgement_nanos as f64 / 1e9
            );
        }
        let bytes = self
            .partial_files
            .lock()
            .unwrap()
            .remove(&file_id)
            .ok_or_else(|| TelegramError::Upload("FILE_PART_0_MISSING".into()))?;
        // Simulated Telegram storage owns this buffer. There is no local disk copy.
        let before = self.next_id.load(Ordering::Relaxed);
        let parts = bytes
            .into_iter()
            .collect::<Option<ServerParts>>()
            .ok_or_else(|| TelegramError::Upload("FILE_PART_0_MISSING".into()))?;
        let result = self.store_payload(Vec::new(), Some(parts), filename).await;
        match result {
            Ok(result) => {
                self.file_receipts
                    .lock()
                    .unwrap()
                    .insert(publication, result.clone());
                Ok(result)
            }
            Err(e) => {
                if self.messages.lock().unwrap().contains_key(&before) {
                    self.file_receipts.lock().unwrap().insert(
                        publication,
                        UploadResult {
                            message_id: before,
                            size,
                        },
                    );
                }
                Err(e)
            }
        }
    }

    async fn is_premium_user(&self) -> Result<bool> {
        self.forum_calls
            .lock()
            .unwrap()
            .push(ForumCall::IsPremiumUser);
        Ok(false)
    }

    async fn telegram_user_id(&self) -> Result<Option<i64>> {
        Ok(*self.telegram_user_id.lock().unwrap())
    }

    async fn upload_block(&self, data: &[u8], filename: &str) -> Result<UploadResult> {
        self.store_owned(data.to_vec(), filename).await
    }

    async fn download_block(&self, message_id: i64) -> Result<DownloadResult> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }

        if let Some(ref err) = *self.fail_downloads.lock().unwrap() {
            return Err(TelegramError::Download(err.clone()));
        }
        self.read_gate()?;

        let data = self
            .get_raw(message_id)
            .ok_or(TelegramError::MessageNotFound(message_id))?;
        self.bytes_served
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(DownloadResult { data, message_id })
    }

    async fn list_topic_documents(
        &self,
        group_id: i64,
        topic_id: i64,
        before_message_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<DocumentInfo>> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }
        let mut documents: Vec<_> = self
            .documents
            .lock()
            .unwrap()
            .values()
            .filter(|doc| {
                doc.group_id == group_id
                    && doc.topic_id == topic_id
                    && before_message_id.is_none_or(|before| doc.message_id < before)
            })
            .cloned()
            .collect();
        documents.sort_by_key(|document| std::cmp::Reverse(document.message_id));
        documents.truncate(limit.min(100));
        Ok(documents)
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
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }
        // Like the real user's dialog resolution, an explicit topic read binds
        // this session's peer cache even when it started unbound.
        *self.channel_ref.lock().unwrap() = Some((group_id, MOCK_ACCESS_HASH, topic_id));
        let page_limit = limit.min(100);
        if page_limit == 0 {
            return Ok(TopicDocumentPage {
                documents: Vec::new(),
                raw_message_ids: Vec::new(),
                exhausted: true,
            });
        }
        let mut raw_message_ids: Vec<_> = self
            .topic_messages
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(&id, &(group, topic))| {
                (group == group_id
                    && topic == topic_id
                    && min_message_id.is_none_or(|min| id > min)
                    && max_message_id.is_none_or(|max| id < max)
                    && offset_id.is_none_or(|offset| id < offset))
                .then_some(id)
            })
            .collect();
        raw_message_ids.sort_by_key(|id| std::cmp::Reverse(*id));
        raw_message_ids.truncate(page_limit);
        let mut documents: Vec<_> = self
            .documents
            .lock()
            .unwrap()
            .values()
            .filter(|document| raw_message_ids.contains(&document.message_id))
            .cloned()
            .collect();
        documents.sort_by_key(|document| std::cmp::Reverse(document.message_id));
        let exhausted = raw_message_ids.len() < page_limit;
        Ok(TopicDocumentPage {
            documents,
            raw_message_ids,
            exhausted,
        })
    }

    async fn download_range(&self, message_id: i64, offset: u64, len: u32) -> Result<Vec<u8>> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }
        if let Some(ref err) = *self.fail_downloads.lock().unwrap() {
            return Err(TelegramError::Download(err.clone()));
        }
        self.read_gate()?;
        if let Some(bytes) = self.stored_part_range(message_id, offset, u64::from(len)) {
            self.bytes_served
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            return Ok(bytes);
        }
        let messages = self.messages.lock().unwrap();
        let blob = messages
            .get(&message_id)
            .ok_or(TelegramError::MessageNotFound(message_id))?;
        // Slice [offset, offset+len), clamped at EOF — a read entirely past the
        // end returns empty, matching Telegram's `upload.GetFile` behaviour.
        let start = offset as usize;
        if start >= blob.len() {
            return Ok(Vec::new());
        }
        let end = start.saturating_add(len as usize).min(blob.len());
        let slice = blob[start..end].to_vec();
        self.bytes_served
            .fetch_add(slice.len() as u64, Ordering::Relaxed);
        Ok(slice)
    }

    async fn download_tail(&self, message_id: i64, len: u32) -> Result<Vec<u8>> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }
        if let Some(ref err) = *self.fail_downloads.lock().unwrap() {
            return Err(TelegramError::Download(err.clone()));
        }
        self.read_gate()?;
        let size = self
            .part_messages
            .lock()
            .unwrap()
            .get(&message_id)
            .map(|parts| parts.iter().map(|p| p.len() as u64).sum::<u64>());
        if let Some(size) = size {
            let bytes = self
                .stored_part_range(
                    message_id,
                    size.saturating_sub(u64::from(len)),
                    u64::from(len),
                )
                .unwrap();
            self.bytes_served
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            return Ok(bytes);
        }
        let messages = self.messages.lock().unwrap();
        let blob = messages
            .get(&message_id)
            .ok_or(TelegramError::MessageNotFound(message_id))?;
        // last min(len, size) bytes — same clamp semantics as the real client
        let take = (len as usize).min(blob.len());
        let slice = blob[blob.len() - take..].to_vec();
        self.bytes_served
            .fetch_add(slice.len() as u64, Ordering::Relaxed);
        Ok(slice)
    }

    async fn delete_message(&self, message_id: i64) -> Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }
        if self.fail_deletes.load(Ordering::Relaxed) {
            return Err(TelegramError::Delete("simulated delete failure".into()));
        }

        let mut messages = self.messages.lock().unwrap();
        if messages.remove(&message_id).is_some() {
            self.part_messages.lock().unwrap().remove(&message_id);
            self.documents.lock().unwrap().remove(&message_id);
            Ok(())
        } else {
            Err(TelegramError::MessageNotFound(message_id))
        }
    }

    async fn delete_messages(&self, message_ids: &[i64]) -> Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }
        if self.fail_deletes.load(Ordering::Relaxed) {
            return Err(TelegramError::Delete("simulated delete failure".into()));
        }

        let mut messages = self.messages.lock().unwrap();
        for id in message_ids {
            messages.remove(id);
            self.part_messages.lock().unwrap().remove(id);
            self.documents.lock().unwrap().remove(id);
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn sync_metadata(&self, data: &[u8]) -> Result<i64> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }
        if self.hang_metadata.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
        {
            let mut budget = self.metadata_budget.lock().unwrap();
            match *budget {
                Some(0) => {
                    return Err(TelegramError::Api(
                        "simulated metadata publish failure".into(),
                    ))
                }
                Some(n) => *budget = Some(n - 1),
                None => {}
            }
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.messages.lock().unwrap().insert(id, data.to_vec());
        {
            let mut withhold = self.withhold_metadata_acks.lock().unwrap();
            if *withhold > 0 {
                *withhold -= 1;
                return Err(TelegramError::Timeout);
            }
        }
        let after = self.after_metadata_sync.lock().unwrap().take();
        if let Some(f) = after {
            f();
        }
        Ok(id)
    }

    async fn fetch_metadata(&self, message_id: i64) -> Result<Vec<u8>> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TelegramError::NotConnected);
        }

        let messages = self.messages.lock().unwrap();
        match messages.get(&message_id) {
            Some(data) => Ok(data.clone()),
            None => Err(TelegramError::MessageNotFound(message_id)),
        }
    }

    fn channel_ref(&self) -> Option<(i64, i64, i64)> {
        *self.channel_ref.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl ForumAdmin for MockTransport {
    fn select_topic(&self, group_id: i64, access_hash: i64, topic_id: i64) -> Result<()> {
        *self.channel_ref.lock().unwrap() = Some((group_id, access_hash, topic_id));
        Ok(())
    }

    async fn create_forum_group(&self, title: &str) -> Result<(i64, i64)> {
        self.forum_gate(ForumCall::CreateGroup {
            title: title.to_string(),
        })?;
        Ok((MOCK_CHANNEL_ID, MOCK_ACCESS_HASH))
    }

    async fn create_topic(
        &self,
        group_id: i64,
        group_access_hash: i64,
        title: &str,
    ) -> Result<i64> {
        self.forum_gate(ForumCall::CreateTopic {
            group_id,
            access_hash: group_access_hash,
            title: title.to_string(),
        })?;
        Ok(self.next_topic_id.fetch_add(1, Ordering::Relaxed))
    }

    async fn delete_topic(
        &self,
        group_id: i64,
        group_access_hash: i64,
        topic_id: i64,
    ) -> Result<()> {
        self.forum_gate(ForumCall::DeleteTopic {
            group_id,
            access_hash: group_access_hash,
            topic_id,
        })?;
        if topic_id <= 1 {
            return Err(TelegramError::Delete(format!(
                "refusing to delete forum topic {topic_id}"
            )));
        }
        Ok(())
    }

    async fn ban_group_member(&self, group_id: i64, access_hash: i64, user_id: i64) -> Result<()> {
        self.forum_gate(ForumCall::BanMember {
            group_id,
            access_hash,
            user_id,
        })
    }

    async fn reset_authorization(&self, authorization_hash: i64) -> Result<()> {
        self.forum_gate(ForumCall::ResetAuthorization {
            hash: authorization_hash,
        })
    }

    async fn reset_other_authorizations(&self) -> Result<()> {
        self.forum_gate(ForumCall::ResetOtherAuthorizations)
    }

    async fn current_authorization_hash(&self) -> Result<Option<i64>> {
        self.forum_gate(ForumCall::GetCurrentAuthorization)?;
        Ok(Some(77))
    }

    async fn authorizations(&self) -> Result<Vec<TelegramAuthorizationInfo>> {
        self.forum_gate(ForumCall::GetCurrentAuthorization)?;
        let mut authorizations = vec![
            TelegramAuthorizationInfo {
                hash: 77,
                current: true,
                device_model: "Mock device".into(),
                app_name: "TeaGarden test".into(),
                date_active: 1_700_000_000,
            },
            TelegramAuthorizationInfo {
                hash: 88,
                current: false,
                device_model: "Mock laptop".into(),
                app_name: "Telegram Desktop".into(),
                date_active: 1_700_000_123,
            },
        ];
        authorizations.extend(self.extra_authorizations.lock().unwrap().iter().cloned());
        Ok(authorizations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn revocation_admin_calls_record_mtproto_targets_in_order() {
        let t = MockTransport::new();
        assert_eq!(t.current_authorization_hash().await.unwrap(), Some(77));
        t.ban_group_member(10, 20, 30).await.unwrap();
        t.reset_authorization(77).await.unwrap();
        t.reset_other_authorizations().await.unwrap();
        assert_eq!(
            t.forum_calls(),
            vec![
                ForumCall::GetCurrentAuthorization,
                ForumCall::BanMember {
                    group_id: 10,
                    access_hash: 20,
                    user_id: 30
                },
                ForumCall::ResetAuthorization { hash: 77 },
                ForumCall::ResetOtherAuthorizations,
            ]
        );
    }

    #[tokio::test]
    async fn withheld_metadata_ack_is_stored_but_reported_as_timeout() {
        let t = MockTransport::new();
        t.withhold_metadata_acks(1);
        let err = t.sync_metadata(b"first").await.unwrap_err();
        assert!(matches!(err, TelegramError::Timeout));
        assert_eq!(
            t.get_raw(1).as_deref(),
            Some(&b"first"[..]),
            "stored anyway"
        );
        assert_eq!(
            t.sync_metadata(b"second").await.unwrap(),
            2,
            "next call acks"
        );
    }

    #[tokio::test]
    async fn metadata_budget_fails_later_publishes_without_storing() {
        let t = MockTransport::new();
        t.set_metadata_budget(Some(1));
        assert_eq!(t.sync_metadata(b"a").await.unwrap(), 1);
        assert!(t.sync_metadata(b"b").await.is_err());
        assert_eq!(t.message_count(), 1);
        t.set_metadata_budget(None);
        t.sync_metadata(b"c").await.unwrap();
        t.put_raw(1, b"other".to_vec());
        assert_eq!(t.fetch_metadata(1).await.unwrap(), b"other");
    }

    #[tokio::test]
    async fn upload_and_download() {
        let transport = MockTransport::new();
        let data = vec![0x42; 1024];
        let result = transport.upload_block(&data, "block.srb1").await.unwrap();
        assert_eq!(result.size, 1024);

        let downloaded = transport.download_block(result.message_id).await.unwrap();
        assert_eq!(downloaded.data, data);
    }

    #[tokio::test]
    async fn download_nonexistent() {
        let transport = MockTransport::new();
        let err = transport.download_block(999).await.unwrap_err();
        assert!(matches!(err, TelegramError::MessageNotFound(999)));
    }

    #[tokio::test]
    async fn delete_message() {
        let transport = MockTransport::new();
        let result = transport.upload_block(&[1, 2, 3], "test").await.unwrap();
        assert_eq!(transport.message_count(), 1);

        transport.delete_message(result.message_id).await.unwrap();
        assert_eq!(transport.message_count(), 0);
    }

    #[tokio::test]
    async fn delete_batch() {
        let transport = MockTransport::new();
        let r1 = transport.upload_block(&[1], "a").await.unwrap();
        let r2 = transport.upload_block(&[2], "b").await.unwrap();
        let r3 = transport.upload_block(&[3], "c").await.unwrap();
        assert_eq!(transport.message_count(), 3);

        transport
            .delete_messages(&[r1.message_id, r3.message_id])
            .await
            .unwrap();
        assert_eq!(transport.message_count(), 1);
        assert!(transport.get_raw(r2.message_id).is_some());
    }

    #[tokio::test]
    async fn not_connected() {
        let transport = MockTransport::new();
        transport.set_connected(false);

        let err = transport.upload_block(&[1], "test").await.unwrap_err();
        assert!(matches!(err, TelegramError::NotConnected));

        let err = transport.download_block(1).await.unwrap_err();
        assert!(matches!(err, TelegramError::NotConnected));
    }

    #[tokio::test]
    async fn forced_upload_failure() {
        let transport = MockTransport::new();
        *transport.fail_uploads.lock().unwrap() = Some("disk full".into());

        let err = transport.upload_block(&[1], "test").await.unwrap_err();
        assert!(matches!(err, TelegramError::Upload(_)));
    }

    #[tokio::test]
    async fn multiple_uploads_unique_ids() {
        let transport = MockTransport::new();
        let r1 = transport.upload_block(&[1], "a").await.unwrap();
        let r2 = transport.upload_block(&[2], "b").await.unwrap();
        assert_ne!(r1.message_id, r2.message_id);
    }

    #[tokio::test]
    async fn download_range_slices_and_clamps() {
        let transport = MockTransport::new();
        let blob: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let up = transport.upload_block(&blob, "seg").await.unwrap();

        // a mid slice returns exactly the requested bytes
        let mid = transport
            .download_range(up.message_id, 100, 256)
            .await
            .unwrap();
        assert_eq!(mid, blob[100..356]);

        // a slice that overruns the end is clamped to EOF
        let tail = transport
            .download_range(up.message_id, 9_950, 1_000)
            .await
            .unwrap();
        assert_eq!(tail, blob[9_950..10_000]);

        // a read starting at/after EOF is empty (matches upload.GetFile)
        let past = transport
            .download_range(up.message_id, 10_000, 4096)
            .await
            .unwrap();
        assert!(past.is_empty());
    }

    // download_tail returns the LAST min(len, size) bytes (the TeaGarden block device
    // ranged-read bootstrap), counts toward the read/byte accounting, and
    // errors on a missing message.
    #[tokio::test]
    async fn download_tail_clamps_and_accounts() {
        let transport = MockTransport::new();
        let blob: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let up = transport.upload_block(&blob, "seg").await.unwrap();
        transport.reset_counters();

        let tail = transport.download_tail(up.message_id, 256).await.unwrap();
        assert_eq!(tail, blob[10_000 - 256..]);
        assert_eq!(transport.bytes_served(), 256);
        assert_eq!(transport.read_count(), 1);

        // len larger than the document → the whole document
        let all = transport
            .download_tail(up.message_id, 1_000_000)
            .await
            .unwrap();
        assert_eq!(all, blob);

        assert!(transport.download_tail(9999, 64).await.is_err());
    }

    #[tokio::test]
    async fn download_range_negatives() {
        let transport = MockTransport::new();
        // nonexistent message
        let err = transport.download_range(999, 0, 16).await.unwrap_err();
        assert!(matches!(err, TelegramError::MessageNotFound(999)));

        // forced-download failure surfaces
        let up = transport.upload_block(&[7u8; 64], "x").await.unwrap();
        *transport.fail_downloads.lock().unwrap() = Some("dc down".into());
        let err = transport
            .download_range(up.message_id, 0, 16)
            .await
            .unwrap_err();
        assert!(matches!(err, TelegramError::Download(_)));
        *transport.fail_downloads.lock().unwrap() = None;

        // not connected
        transport.set_connected(false);
        let err = transport
            .download_range(up.message_id, 0, 16)
            .await
            .unwrap_err();
        assert!(matches!(err, TelegramError::NotConnected));
    }

    #[tokio::test]
    async fn byte_accounting_tracks_read_amplification() {
        let transport = MockTransport::new();
        let blob = vec![0u8; 1_000_000]; // 1 MB "segment"
        let up = transport.upload_block(&blob, "seg").await.unwrap();
        transport.reset_counters();

        // a small ranged read serves only the slice — not the whole segment
        let _ = transport
            .download_range(up.message_id, 0, 4096)
            .await
            .unwrap();
        assert_eq!(transport.bytes_served(), 4096);
        assert_eq!(transport.read_count(), 1);

        // a whole-block download serves the whole blob
        let _ = transport.download_block(up.message_id).await.unwrap();
        assert_eq!(transport.bytes_served(), 4096 + 1_000_000);
        assert_eq!(transport.read_count(), 2);
    }

    #[tokio::test]
    async fn flood_wait_injection() {
        let transport = MockTransport::new();
        let up = transport.upload_block(&[1u8; 32], "x").await.unwrap();
        transport.set_flood_after(2); // reads 0 and 1 OK, read 2 floods

        assert!(transport.download_range(up.message_id, 0, 8).await.is_ok());
        assert!(transport.download_range(up.message_id, 0, 8).await.is_ok());
        let err = transport
            .download_range(up.message_id, 0, 8)
            .await
            .unwrap_err();
        assert!(matches!(err, TelegramError::RateLimited { seconds: 30 }));
    }

    #[tokio::test]
    async fn upload_failure_injection() {
        let transport = MockTransport::new();
        transport.set_fail_uploads_after(2); // uploads 0 and 1 OK, upload 2 fails

        assert!(transport.upload_block(&[1], "a").await.is_ok());
        assert!(transport.upload_block(&[2], "b").await.is_ok());
        let err = transport.upload_block(&[3], "c").await.unwrap_err();
        assert!(matches!(err, TelegramError::Upload(_)));
        // the failed upload left no message behind
        assert_eq!(transport.message_count(), 2);
    }

    #[tokio::test]
    async fn hang_uploads_never_completes_until_cleared() {
        let transport = MockTransport::new();
        transport.set_hang_uploads(true);
        let hung = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            transport.upload_block(&[1], "a"),
        )
        .await;
        assert!(hung.is_err(), "a hung upload must not complete");
        assert_eq!(transport.message_count(), 0);
        transport.set_hang_uploads(false);
        assert!(transport.upload_block(&[1], "a").await.is_ok());
    }

    #[tokio::test]
    async fn hang_metadata_never_completes_and_stores_nothing_until_cleared() {
        let transport = MockTransport::new();
        transport.set_hang_metadata(true);
        let hung = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            transport.sync_metadata(&[1]),
        )
        .await;
        assert!(hung.is_err(), "a hung metadata upload must not complete");
        assert_eq!(transport.message_count(), 0);
        transport.set_hang_metadata(false);
        assert!(transport.sync_metadata(&[1]).await.is_ok());
    }

    #[tokio::test]
    async fn drop_message_simulates_server_side_loss() {
        let transport = MockTransport::new();
        let up = transport.upload_block(&[9u8; 128], "seg").await.unwrap();
        assert!(transport.drop_message(up.message_id));

        // the lost segment now fails both whole and ranged reads (fail-closed)
        let err = transport.download_block(up.message_id).await.unwrap_err();
        assert!(matches!(err, TelegramError::MessageNotFound(_)));
        let err = transport
            .download_range(up.message_id, 0, 16)
            .await
            .unwrap_err();
        assert!(matches!(err, TelegramError::MessageNotFound(_)));
        // dropping a second time reports it was already gone
        assert!(!transport.drop_message(up.message_id));
    }
}
