use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::client::BlockTransport;
use crate::error::{Result, TelegramError};
use crate::types::{DocumentInfo, DownloadResult, TopicDocumentPage, UploadResult};

/// Distributes block operations across multiple Telegram sessions round-robin,
/// multiplying upload throughput by approximately N sessions.
///
/// All sessions must be admins of the same private channel. Because blocks are
/// identified by message_id in that shared channel, any session can read any
/// block regardless of which session uploaded it.
pub struct MultiTransport {
    transports: Vec<Arc<dyn BlockTransport>>,
    upload_counter: AtomicU64,
    download_counter: AtomicU64,
}

impl MultiTransport {
    /// Builds a multi-session transport over the given transports.
    ///
    /// Panics if `transports` is empty, since at least one session is required.
    pub fn new(transports: Vec<Arc<dyn BlockTransport>>) -> Self {
        assert!(
            !transports.is_empty(),
            "MultiTransport requires at least one transport"
        );
        Self {
            transports,
            upload_counter: AtomicU64::new(0),
            download_counter: AtomicU64::new(0),
        }
    }

    /// Returns the number of underlying sessions in the round-robin pool.
    pub fn session_count(&self) -> usize {
        self.transports.len()
    }
}

#[async_trait::async_trait]
impl BlockTransport for MultiTransport {
    async fn telegram_user_id(&self) -> Result<Option<i64>> {
        self.transports[0].telegram_user_id().await
    }

    async fn is_premium_user(&self) -> Result<bool> {
        self.transports[0].is_premium_user().await
    }

    async fn upload_file_object(&self, data: &[u8], filename: &str) -> Result<UploadResult> {
        // The primary transport is the user's MTProto session. TGFV objects may
        // exceed the Bot API's 50 MiB document upload limit.
        self.transports[0].upload_file_object(data, filename).await
    }

    async fn upload_file_source(
        &self,
        source: &mut (dyn crate::transfer::UploadSource + '_),
        filename: &str,
        timeout: std::time::Duration,
    ) -> Result<UploadResult> {
        self.transports[0]
            .upload_file_source(source, filename, timeout)
            .await
    }

    async fn upload_block(&self, data: &[u8], filename: &str) -> Result<UploadResult> {
        let n = self.transports.len();
        let start = self.upload_counter.fetch_add(1, Ordering::Relaxed) as usize;
        let mut last_err: Option<TelegramError> = None;
        for i in 0..n {
            let idx = (start + i) % n;
            match self.transports[idx].upload_block(data, filename).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    tracing::warn!(session = idx, error = %e, "upload failed on session, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    async fn download_block(&self, message_id: i64) -> Result<DownloadResult> {
        let n = self.transports.len();
        let start = self.download_counter.fetch_add(1, Ordering::Relaxed) as usize;
        let mut last_err: Option<TelegramError> = None;
        for i in 0..n {
            let idx = (start + i) % n;
            match self.transports[idx].download_block(message_id).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    tracing::warn!(session = idx, error = %e, "download failed on session, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
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
        let mut last_err = None;
        for transport in &self.transports {
            match transport
                .list_topic_page(
                    group_id,
                    topic_id,
                    min_message_id,
                    max_message_id,
                    offset_id,
                    limit,
                )
                .await
            {
                Ok(page) => return Ok(page),
                Err(error) => last_err = Some(error),
            }
        }
        Err(last_err.unwrap_or_else(|| TelegramError::Download("no transports configured".into())))
    }

    async fn download_range(&self, message_id: i64, offset: u64, len: u32) -> Result<Vec<u8>> {
        // Round-robin across sessions with failover, mirroring `download_block`.
        // Bot sessions error on reads, so the pool naturally routes to the
        // MTProto session(s) that can serve ranged `upload.GetFile`.
        let n = self.transports.len();
        let start = self.download_counter.fetch_add(1, Ordering::Relaxed) as usize;
        let mut last_err: Option<TelegramError> = None;
        for i in 0..n {
            let idx = (start + i) % n;
            match self.transports[idx]
                .download_range(message_id, offset, len)
                .await
            {
                Ok(r) => return Ok(r),
                Err(e) => {
                    tracing::warn!(session = idx, error = %e, "download_range failed on session, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    async fn download_tail(&self, message_id: i64, len: u32) -> Result<Vec<u8>> {
        // Same round-robin + failover as `download_range` (bot sessions error on
        // reads, so the pool routes to MTProto sessions).
        let n = self.transports.len();
        let start = self.download_counter.fetch_add(1, Ordering::Relaxed) as usize;
        let mut last_err: Option<TelegramError> = None;
        for i in 0..n {
            let idx = (start + i) % n;
            match self.transports[idx].download_tail(message_id, len).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    tracing::warn!(session = idx, error = %e, "download_tail failed on session, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    async fn delete_message(&self, message_id: i64) -> Result<()> {
        self.transports[0].delete_message(message_id).await
    }

    async fn delete_messages(&self, message_ids: &[i64]) -> Result<()> {
        self.transports[0].delete_messages(message_ids).await
    }

    fn is_connected(&self) -> bool {
        self.transports.iter().any(|t| t.is_connected())
    }

    async fn sync_metadata(&self, data: &[u8]) -> Result<i64> {
        self.transports[0].sync_metadata(data).await
    }

    async fn fetch_metadata(&self, message_id: i64) -> Result<Vec<u8>> {
        let n = self.transports.len();
        let start = self.download_counter.fetch_add(1, Ordering::Relaxed) as usize % n;
        let mut last_err: Option<TelegramError> = None;
        for i in 0..n {
            let idx = (start + i) % n;
            match self.transports[idx].fetch_metadata(message_id).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    fn channel_ref(&self) -> Option<(i64, i64, i64)> {
        self.transports[0].channel_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockTransport;

    /// Metadata snapshots go to session 0, the user's MTProto session, never a
    /// bot session (whose Bot API caps documents at 50 MB).
    #[tokio::test]
    async fn sync_metadata_always_uses_the_first_session() {
        let user = Arc::new(MockTransport::new());
        let bot = Arc::new(MockTransport::new());
        let multi = MultiTransport::new(vec![user.clone(), bot.clone()]);
        for _ in 0..4 {
            multi.sync_metadata(b"snapshot").await.unwrap();
        }
        assert_eq!(user.message_count(), 4);
        assert_eq!(bot.message_count(), 0);
    }

    #[tokio::test]
    async fn file_objects_always_use_the_primary_user_session() {
        let user = Arc::new(MockTransport::new());
        let bot = Arc::new(MockTransport::new());
        let multi = MultiTransport::new(vec![user.clone(), bot.clone()]);
        for _ in 0..3 {
            multi
                .upload_file_object(b"TGFV file", "file.tgf")
                .await
                .unwrap();
        }
        assert_eq!(user.message_count(), 3);
        assert_eq!(bot.message_count(), 0);
    }
}
