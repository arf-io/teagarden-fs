//! Real-transport integration test for teagarden-telegram.
//!
//! Uploads random blobs of various sizes to a live Telegram channel, downloads
//! them back, and verifies SHA-256 hashes.  Results are written as JSONL for
//! post-analysis.
//!
//! Required environment (or ~/.config/teagarden/.env):
//!   TG_API_ID      — Telegram API id
//!   TG_API_HASH    — Telegram API hash
//!   TG_SESSION     — path to session file (default: ~/.config/teagarden/teagarden.session)
//!   TG_CHANNEL_ID  — channel id for the bench volume
//!   TG_ACCESS_HASH — channel access hash

#![deny(missing_docs)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tracing::{error, info};

use teagarden_telegram::client::{BlockTransport, TelegramClient};
use teagarden_telegram::types::{AuthState, ChannelRef, TelegramConfig};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const MAX_PARALLEL: usize = 4;

/// Blob sizes to test (bytes)
const SIZES: &[usize] = &[
    1024,             // 1 KB
    4 * 1024,         // 4 KB
    64 * 1024,        // 64 KB
    512 * 1024,       // 512 KB
    1024 * 1024,      // 1 MB
    4 * 1024 * 1024,  // 4 MB
    16 * 1024 * 1024, // 16 MB
];

// ---------------------------------------------------------------------------
// Result record
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct TestRecord {
    timestamp: String,
    size_bytes: usize,
    filename: String,
    message_id: i64,
    sha256_expected: String,
    sha256_actual: String,
    verified: bool,
    upload_ms: u128,
    download_ms: u128,
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "transport_test=info,teagarden_telegram=info".into()),
        )
        .init();

    // Load .env if present
    load_dotenv();

    let api_id: i32 = env_var("TG_API_ID")?
        .parse()
        .context("TG_API_ID must be an integer")?;
    let api_hash = env_var("TG_API_HASH")?;
    let session_path = std::env::var("TG_SESSION").unwrap_or_else(|_| {
        let mut p = dirs_home();
        p.push(".config/teagarden/teagarden.session");
        p.to_string_lossy().into_owned()
    });
    let channel_id: i64 = env_var("TG_CHANNEL_ID")?
        .parse()
        .context("TG_CHANNEL_ID must be an integer")?;
    let access_hash: i64 = env_var("TG_ACCESS_HASH")?
        .parse()
        .context("TG_ACCESS_HASH must be an integer")?;
    let topic_id: i64 = std::env::var("TG_TOPIC_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    info!("session: {session_path}");
    info!("group: id={channel_id} topic={topic_id}");

    let config = TelegramConfig {
        api_id,
        api_hash,
        session_path,
        max_upload_size: 2 * 1024 * 1024 * 1024, // 2 GiB (premium)
        max_concurrent_uploads: MAX_PARALLEL,
        max_concurrent_downloads: MAX_PARALLEL,
        max_retries: 3,
        retry_base_delay_ms: 1000,
        channel_ref: Some(ChannelRef {
            id: channel_id,
            access_hash,
            topic_id,
        }),
    };

    let client = Arc::new(TelegramClient::new(config));

    info!("connecting …");
    match client.connect().await.context("connect")? {
        AuthState::Authenticated => info!("authenticated"),
        other => bail!("not authenticated: {other:?}"),
    }

    // Prepare JSONL output file
    let now = jiff::Zoned::now();
    let out_path = format!("transport-test-{}.jsonl", now.strftime("%Y%m%d-%H%M%S"));
    info!("results → {out_path}");

    let sem = Arc::new(Semaphore::new(MAX_PARALLEL));
    let mut handles = Vec::new();

    for &size in SIZES {
        let client = Arc::clone(&client);
        let sem = Arc::clone(&sem);

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            test_one(client, size).await
        });
        handles.push(handle);
    }

    let mut records: Vec<TestRecord> = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(rec) => records.push(rec),
            Err(e) => error!("task panicked: {e}"),
        }
    }

    // Sort by size for readability
    records.sort_by_key(|r| r.size_bytes);

    // Write JSONL
    let mut out = String::new();
    for rec in &records {
        out.push_str(&serde_json::to_string(rec).unwrap());
        out.push('\n');
    }
    std::fs::write(&out_path, &out).context("write JSONL")?;

    // Summary
    let pass = records
        .iter()
        .filter(|r| r.verified && r.error.is_none())
        .count();
    let fail = records.len() - pass;
    println!("\n=== Transport test summary ===");
    println!("Total: {}  Pass: {}  Fail: {}", records.len(), pass, fail);
    for rec in &records {
        let status = if rec.verified && rec.error.is_none() {
            "PASS"
        } else {
            "FAIL"
        };
        println!(
            "  [{status}] {sz:>9} bytes  msg={mid}  up={up}ms  dn={dn}ms{err}",
            sz = rec.size_bytes,
            mid = rec.message_id,
            up = rec.upload_ms,
            dn = rec.download_ms,
            err = rec
                .error
                .as_deref()
                .map(|e| format!("  ERROR: {e}"))
                .unwrap_or_default(),
        );
    }
    println!("Results written to {out_path}");

    if fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Single blob test
// ---------------------------------------------------------------------------

async fn test_one(client: Arc<TelegramClient>, size: usize) -> TestRecord {
    let timestamp = jiff::Zoned::now().strftime("%FT%T%.f%:z").to_string();
    let filename = format!("bench-{size}-{}.bin", rand_hex(8));

    // Generate random blob
    let mut blob = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut blob);

    // SHA-256 before upload
    let expected_hash = hex::encode(Sha256::digest(&blob));

    info!("uploading {size} bytes as {filename}");
    let upload_start = Instant::now();
    let upload_res = client.upload_block(&blob, &filename).await;
    let upload_ms = upload_start.elapsed().as_millis();

    let message_id: i64 = match upload_res {
        Ok(r) => r.message_id,
        Err(e) => {
            let msg = format!("upload failed: {e}");
            error!("{msg}");
            return TestRecord {
                timestamp,
                size_bytes: size,
                filename,
                message_id: -1,
                sha256_expected: expected_hash,
                sha256_actual: String::new(),
                verified: false,
                upload_ms,
                download_ms: 0,
                error: Some(msg),
            };
        }
    };

    info!("uploaded {size} bytes → msg_id={message_id} in {upload_ms}ms");

    // Download and verify
    let download_start = Instant::now();
    let download_res = client.download_block(message_id).await;
    let download_ms = download_start.elapsed().as_millis();

    match download_res {
        Ok(dl) => {
            let actual_hash = hex::encode(Sha256::digest(&dl.data));
            let verified = actual_hash == expected_hash;
            if !verified {
                error!(
                    "hash mismatch for {size} bytes: expected={expected_hash} actual={actual_hash}"
                );
            } else {
                info!("verified {size} bytes in {download_ms}ms ✓");
            }
            TestRecord {
                timestamp,
                size_bytes: size,
                filename,
                message_id,
                sha256_expected: expected_hash,
                sha256_actual: actual_hash,
                verified,
                upload_ms,
                download_ms,
                error: if verified {
                    None
                } else {
                    Some("hash mismatch".into())
                },
            }
        }
        Err(e) => {
            let msg = format!("download failed: {e}");
            error!("{msg}");
            TestRecord {
                timestamp,
                size_bytes: size,
                filename,
                message_id,
                sha256_expected: expected_hash,
                sha256_actual: String::new(),
                verified: false,
                upload_ms,
                download_ms,
                error: Some(msg),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn env_var(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env var {key}"))
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

fn rand_hex(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(&buf[..len / 2])
}

/// Load key=value pairs from ~/.config/teagarden/.env into environment if not
/// already set.  Ignores lines starting with '#' and blank lines.
fn load_dotenv() {
    let mut path = dirs_home();
    path.push(".config/teagarden/.env");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim().trim_matches('"');
            if std::env::var(k).is_err() {
                std::env::set_var(k, v);
            }
        }
    }
}
