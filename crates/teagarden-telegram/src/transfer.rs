//! Memory-bounded part pipelines on a caller's existing MTProto connection.

use crate::error::{Result, TelegramError};
use futures::{stream::FuturesUnordered, StreamExt};
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

/// Telegram's maximum SaveFilePart payload.
pub const UPLOAD_PART_BYTES: usize = 512 * 1024;
/// Default resident upload payload budget: 32 requests, 16 MiB.
pub const DEFAULT_IN_FLIGHT_PARTS: usize = 32;
/// A request may wait this long without completing; there is no object deadline.
pub const DEFAULT_PART_TIMEOUT: Duration = Duration::from_secs(120);

/// Passive local-storage counters, retained through confirmation and intent cleanup.
#[derive(Default)]
pub struct LocalWriteStats {
    payload: std::sync::atomic::AtomicU64,
    intent: std::sync::atomic::AtomicU64,
}
impl LocalWriteStats {
    /// Count actual encrypted payload bytes written to the sole local spool.
    pub fn record_payload(&self, bytes: u64) {
        self.payload
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }
    /// Count small intent/progress record writes, including publication confirmation.
    pub fn record_intent(&self, bytes: u64) {
        self.intent
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }
    /// Snapshot payload and intent/progress writes.
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.payload.load(std::sync::atomic::Ordering::Relaxed),
            self.intent.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

/// Source of one immutable upload, backed by the existing local write spool.
pub trait UploadSource: Read + Send {
    /// Complete encoded wire size, including any credential trailer.
    fn size(&self) -> u64;
    /// Telegram temporary file id, retained after crashes.
    fn upload_id(&self) -> i64;
    /// SendMedia idempotency id, retained after crashes.
    fn publication_id(&self) -> i64;
    /// Whether Telegram already acknowledged this part in an earlier attempt.
    fn acknowledged(&self, part: usize) -> bool;
    /// Append the acknowledged offset to the small durable progress record.
    fn acknowledge(&mut self, part: usize) -> io::Result<()>;
    /// Optional passive storage meter; it remains live after the upload is confirmed.
    fn local_write_meter(&self) -> Option<Arc<LocalWriteStats>> {
        None
    }
}

/// Borrowed compatibility source; does not copy an existing wire buffer.
pub struct SliceSource<'a> {
    bytes: &'a [u8],
    position: usize,
    id: i64,
    publication: i64,
    acked: BTreeSet<usize>,
}
impl<'a> SliceSource<'a> {
    /// Borrow existing encoded bytes without a full-object copy.
    pub fn new(bytes: &'a [u8]) -> Self {
        use rand::Rng;
        Self {
            bytes,
            position: 0,
            id: rand::thread_rng().gen(),
            publication: rand::thread_rng().gen(),
            acked: BTreeSet::new(),
        }
    }
}
impl Read for SliceSource<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.bytes.len() - self.position);
        out[..n].copy_from_slice(&self.bytes[self.position..self.position + n]);
        self.position += n;
        Ok(n)
    }
}
impl UploadSource for SliceSource<'_> {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn upload_id(&self) -> i64 {
        self.id
    }
    fn publication_id(&self) -> i64 {
        self.publication
    }
    fn acknowledged(&self, part: usize) -> bool {
        self.acked.contains(&part)
    }
    fn acknowledge(&mut self, part: usize) -> io::Result<()> {
        self.acked.insert(part);
        Ok(())
    }
}

/// Completed part framing, including the small-file checksum.
pub struct UploadedParts {
    /// Exact number of parts advertised to Telegram.
    pub parts: i32,
    /// MD5 required by InputFile for objects at most 10 MiB.
    pub md5: String,
    /// Time spent reading and encrypting the local source.
    pub source_read_nanos: u128,
    /// Time spent recording durable part acknowledgements.
    pub acknowledgement_nanos: u128,
}

/// Pipeline parts continuously, with only resident-buffer backpressure.
/// Each callback uses the same existing sender. Retries retain the exact bytes
/// and affect only the failed part; FLOOD_WAIT sleeps outside the idle timer.
pub async fn upload_source_parts<F, Fut>(
    source: &mut (dyn UploadSource + '_),
    window: usize,
    timeout: Duration,
    attempts: u32,
    send: F,
) -> Result<UploadedParts>
where
    F: Fn(usize, Arc<Vec<u8>>) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<()>> + Send,
{
    if window == 0 || attempts == 0 || timeout.is_zero() {
        return Err(TelegramError::Upload("invalid part pipeline budget".into()));
    }
    let size = usize::try_from(source.size())
        .map_err(|_| TelegramError::Upload("object too large for this platform".into()))?;
    let parts = i32::try_from(size.div_ceil(UPLOAD_PART_BYTES).max(1))
        .map_err(|_| TelegramError::Upload("too many upload parts".into()))?;
    let flood_until = std::sync::Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now()));
    let mut active = FuturesUnordered::new();
    let mut md5 = md5::Context::new();
    let mut recycled: Vec<Vec<u8>> = Vec::new();
    let mut source_read_nanos = 0;
    let mut acknowledgement_nanos = 0;
    for part in 0..parts as usize {
        let n = UPLOAD_PART_BYTES.min(size.saturating_sub(part * UPLOAD_PART_BYTES));
        let mut bytes = recycled.pop().unwrap_or_default();
        bytes
            .try_reserve_exact(n.saturating_sub(bytes.len()))
            .map_err(|e| TelegramError::Upload(e.to_string()))?;
        bytes.resize(n, 0);
        let started = std::time::Instant::now();
        source.read_exact(&mut bytes)?;
        source_read_nanos += started.elapsed().as_nanos();
        if size <= 10 * 1024 * 1024 {
            md5.consume(&bytes);
        }
        if source.acknowledged(part) {
            continue;
        }
        let bytes = Arc::new(bytes);
        let send = &send;
        let flood_until = flood_until.clone();
        active.push(async move {
            let mut failures = 0;
            loop {
                loop {
                    let until = *flood_until.lock().await;
                    if until <= tokio::time::Instant::now() {
                        break;
                    }
                    tokio::time::sleep_until(until).await;
                }
                let result = tokio::time::timeout(timeout, send(part, bytes.clone()))
                    .await
                    .unwrap_or(Err(TelegramError::Timeout));
                match result {
                    Ok(()) => return Ok((part, bytes)),
                    Err(error) => {
                        if let Some(seconds) = crate::client::extract_flood_wait(&error) {
                            tracing::warn!(
                                part,
                                seconds,
                                "Telegram part FloodWait; retaining all completed parts"
                            );
                            let mut until = flood_until.lock().await;
                            *until = (*until)
                                .max(tokio::time::Instant::now() + Duration::from_secs(seconds));
                        } else if matches!(error, TelegramError::Timeout | TelegramError::Io(_)) {
                            failures += 1;
                            if failures >= attempts {
                                return Err(error);
                            }
                            tokio::task::yield_now().await;
                        } else {
                            return Err(error);
                        }
                    }
                }
            }
        });
        if active.len() == window {
            let (part, bytes) = active.next().await.expect("nonempty pipeline")?;
            recycled.push(Arc::try_unwrap(bytes).unwrap_or_default());
            let started = std::time::Instant::now();
            source.acknowledge(part)?;
            acknowledgement_nanos += started.elapsed().as_nanos();
        }
    }
    // Force stream finalization/hash verification before publication, even if
    // its encoded size ended exactly on a part boundary.
    let mut extra = [0; 1];
    if source.read(&mut extra)? != 0 {
        return Err(TelegramError::Upload(
            "upload source exceeded its declared size".into(),
        ));
    }
    while let Some(result) = active.next().await {
        let (part, _) = result?;
        let started = std::time::Instant::now();
        source.acknowledge(part)?;
        acknowledgement_nanos += started.elapsed().as_nanos();
    }
    Ok(UploadedParts {
        parts,
        md5: format!("{:x}", md5.compute()),
        source_read_nanos,
        acknowledgement_nanos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test(start_paused = true)]
    async fn pipeline_windows_are_memory_budgets_on_one_sender() {
        for window in [4, 8, 16, 32] {
            let payload = vec![0; 100 * 1024 * 1024];
            let mut source = SliceSource::new(&payload);
            let active = AtomicUsize::new(0);
            let peak = AtomicUsize::new(0);
            let sent = AtomicUsize::new(0);
            let started = tokio::time::Instant::now();
            upload_source_parts(
                &mut source,
                window,
                Duration::from_secs(1),
                3,
                |_, bytes| {
                    let active = &active;
                    let peak = &peak;
                    let sent = &sent;
                    async move {
                        assert!(bytes.len() <= UPLOAD_PART_BYTES);
                        let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(n, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        sent.fetch_add(bytes.len(), Ordering::SeqCst);
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(peak.load(Ordering::SeqCst), window);
            assert_eq!(sent.load(Ordering::SeqCst), payload.len());
            eprintln!("PIPELINE_WINDOW window={window} parts=200 peak={window} sender_count=1 resident_payload_bytes={} virtual_elapsed_ms={}",window*UPLOAD_PART_BYTES,started.elapsed().as_millis());
        }
    }
    #[tokio::test(start_paused = true)]
    async fn part_deadline_and_flood_wait_do_not_restart_completed_parts() {
        let payload = vec![0; 12 * UPLOAD_PART_BYTES];
        let mut source = SliceSource::new(&payload);
        let calls: Vec<_> = (0..12).map(|_| AtomicUsize::new(0)).collect();
        let start = tokio::time::Instant::now();
        upload_source_parts(&mut source, 4, Duration::from_millis(200), 3, |part, _| {
            let calls = &calls;
            async move {
                let n = calls[part].fetch_add(1, Ordering::SeqCst);
                if part == 3 && n < 4 {
                    return Err(TelegramError::RateLimited { seconds: 2 });
                }
                if part == 4 && n == 0 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(start.elapsed() > Duration::from_secs(2));
        for (part, n) in calls.iter().enumerate() {
            assert_eq!(
                n.load(Ordering::SeqCst),
                if part == 3 {
                    5
                } else if part == 4 {
                    2
                } else {
                    1
                }
            );
        }
    }
}
