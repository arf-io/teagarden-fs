//! P-1 feasibility spike for TeaGarden block devices — the BLOCKING go/no-go.
//!
//! Proves (or kills) the premise before any crate re-layering. It uploads a
//! ~45 MiB document to a throwaway forum topic, then measures the numbers that
//! decide whether a metadata-heavy filesystem is usable over Telegram:
//!
//!   1. ranged-read CORRECTNESS via `upload.GetFile` — including a read that
//!      crosses the 1 MiB request boundary (gap G3) — verified byte-for-byte.
//!   2. cold single 4 KiB random-read latency over ONE session (the metadata
//!      -walk / e2fsck read pattern); p50/p95 + whether it trips a FLOOD_WAIT.
//!   3. whole-45 MiB-segment fetch time (the "warm the local cache" cost that
//!      amortizes the cold path in the P1.12–P1.14 design).
//!   4. local write-back fsync latency (confirms the write path is local-fast).
//!
//! It writes its report to the file named by `TEAGARDEN_DEV_P1_REPORT`, or to
//! `teagarden-dev-p1-go-nogo.md` in the system temp dir when that is unset (never
//! into the repository). Run:
//!   cargo run -p teagarden-transport-test --bin p1-feasibility --release
//!
//! Needs live creds: TG_API_ID / TG_API_HASH (from ~/.config/teagarden/.env),
//! the session at ~/.config/teagarden/teagarden.session, and the shared group
//! in ~/.config/teagarden/group.json.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use grammers_tl_types as tl;
use rand::RngCore;
use sha2::{Digest, Sha256};

use teagarden_telegram::client::{BlockTransport, TelegramClient};
use teagarden_telegram::types::{AuthState, ChannelRef, TelegramConfig};

const DOC_SIZE: usize = 45 * 1024 * 1024; // one ~45 MiB segment
const WALK_READS: usize = 200; // cold 4 KiB random reads (metadata-walk proxy)
const FSYNC_ITERS: usize = 200; // local write-back fsync samples
const MB: u64 = 1024 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "p1_feasibility=info,teagarden_telegram=warn".into()),
        )
        .init();
    load_dotenv();

    let api_id: i32 = env_var("TG_API_ID")?.parse().context("TG_API_ID int")?;
    let api_hash = env_var("TG_API_HASH")?;
    let session_path = {
        let mut p = dirs_home();
        p.push(".config/teagarden/teagarden.session");
        p.to_string_lossy().into_owned()
    };
    let (group_id, group_hash) = read_group_json()?;
    println!("== P-1 feasibility spike ==");
    println!("group_id={group_id}  session={session_path}");

    let mk_cfg = |topic_id: i64| TelegramConfig {
        api_id,
        api_hash: api_hash.clone(),
        session_path: session_path.clone(),
        max_upload_size: 2 * 1024 * 1024 * 1024,
        max_concurrent_uploads: 4,
        max_concurrent_downloads: 4,
        max_retries: 3,
        retry_base_delay_ms: 1000,
        channel_ref: Some(ChannelRef {
            id: group_id,
            access_hash: group_hash,
            topic_id,
        }),
    };

    // ── Phase 1: create a throwaway topic (config.channel_ref is immutable, so
    // we create the topic with a placeholder client, then rebind to it). ──────
    let c0 = TelegramClient::new(mk_cfg(0));
    match c0.connect().await.context("connect (topic-create)")? {
        AuthState::Authenticated => {}
        other => bail!("not authenticated: {other:?}"),
    }
    // Random words, like every real topic: a title is visible to Telegram and a
    // readable one would say what this probe is.
    let title = teagarden_core::volume::names::generate_group_name();
    let topic_id = c0
        .create_topic(group_id, group_hash, &title)
        .await
        .context("create_topic")?;
    c0.save_session().await.ok();
    drop(c0);
    println!("created throwaway topic '{title}' id={topic_id}");

    // ── Phase 2: bind to the topic and run the measurements. ──────────────────
    let client = Arc::new(TelegramClient::new(mk_cfg(topic_id)));
    match client.connect().await.context("connect (main)")? {
        AuthState::Authenticated => {}
        other => bail!("not authenticated: {other:?}"),
    }

    // Local write-back fsync latency (measured first; no network).
    let fsync = measure_local_fsync().context("local fsync bench")?;
    println!(
        "local write-back fsync (4 KiB): p50={:.3}ms p95={:.3}ms (n={FSYNC_ITERS})",
        fsync.p50, fsync.p95
    );

    // The ~45 MiB doc.
    let mut doc = vec![0u8; DOC_SIZE];
    rand::thread_rng().fill_bytes(&mut doc);
    let doc_sha = hex::encode(Sha256::digest(&doc));

    // Upload.
    let t = Instant::now();
    let up = client
        .upload_block(&doc, "p1-spike.bin")
        .await
        .context("upload_block")?;
    let upload_ms = t.elapsed().as_millis();
    let msg_id = up.message_id;
    let up_mbps = (DOC_SIZE as f64 / 1e6) / (upload_ms as f64 / 1e3);
    println!("uploaded {DOC_SIZE} B  msg_id={msg_id}  {upload_ms}ms  {up_mbps:.1} MB/s");

    // Resolve the document location ONCE (P3.1a cache in the real design).
    let t = Instant::now();
    let (loc, dc_id, size) = client
        .resolve_document(msg_id)
        .await
        .context("resolve_document")?;
    let resolve_ms = t.elapsed().as_millis();
    let size_ok = size == DOC_SIZE as u64;
    println!("resolve: dc_id={dc_id} size={size} size_ok={size_ok} ({resolve_ms}ms)");

    // ── Correctness cases (byte-for-byte verified). ───────────────────────────
    let mut correctness = Vec::new();
    let cases: &[(&str, u64, u32)] = &[
        ("first 4KiB @0", 0, 4096),
        ("mid unaligned 4KiB", 20 * MB + 1234, 4096),
        ("crosses 1MiB boundary", MB - 2048, 4096),
        ("record-sized 1MiB", 12 * MB, 1024 * 1024),
        ("last 4KiB @EOF", DOC_SIZE as u64 - 4096, 4096),
    ];
    for (name, off, len) in cases {
        let r = read_check(&client, &loc, &doc, *off, *len).await;
        println!(
            "  [{}] {name}: {} bytes in {}ms",
            if r.ok { "OK " } else { "BAD" },
            r.got_len,
            r.ms
        );
        correctness.push((name.to_string(), r));
    }

    // ── Cold 4 KiB random-read latency over ONE session (metadata-walk proxy).
    let max_off = (DOC_SIZE as u64 - 4096) & !4095;
    let mut walk_ms: Vec<u128> = Vec::with_capacity(WALK_READS);
    let mut walk_bad = 0usize;
    let mut flood_wait_hits = 0usize;
    let mut walk_err: Option<String> = None;
    let walk_start = Instant::now();
    for i in 0..WALK_READS {
        // deterministic pseudo-random 4 KiB-aligned offset (no Math.random needed)
        let off = ((i as u64).wrapping_mul(2_654_435_761) % (max_off / 4096)) * 4096;
        let t = Instant::now();
        match client.get_file_range(&loc, off, 4096).await {
            Ok(got) => {
                let ms = t.elapsed().as_millis();
                walk_ms.push(ms);
                let want = &doc[off as usize..off as usize + 4096];
                if got.as_slice() != want {
                    walk_bad += 1;
                }
            }
            Err(e) => {
                let s = e.to_string();
                if s.to_lowercase().contains("rate")
                    || s.to_lowercase().contains("flood")
                    || s.contains("420")
                {
                    flood_wait_hits += 1;
                }
                walk_err.get_or_insert(s);
                walk_bad += 1;
            }
        }
    }
    let walk_total_ms = walk_start.elapsed().as_millis();
    let (w_p50, w_p95, w_min, w_max, w_mean) = stats(&walk_ms);
    println!(
        "cold 4KiB walk (n={WALK_READS}): p50={w_p50}ms p95={w_p95}ms min={w_min} max={w_max} mean={w_mean:.0}ms total={walk_total_ms}ms bad={walk_bad} flood_hits={flood_wait_hits}"
    );

    // ── Whole-segment fetch (warm-the-cache cost) + full-doc correctness. ─────
    let t = Instant::now();
    let mut reassembled = Vec::with_capacity(DOC_SIZE);
    let mut seg_err: Option<String> = None;
    let n_chunks = DOC_SIZE as u64 / MB;
    for c in 0..n_chunks {
        match client.get_file_range(&loc, c * MB, MB as u32).await {
            Ok(mut b) => reassembled.append(&mut b),
            Err(e) => {
                seg_err = Some(e.to_string());
                break;
            }
        }
    }
    let seg_ms = t.elapsed().as_millis();
    let seg_sha = hex::encode(Sha256::digest(&reassembled));
    let seg_ok = seg_err.is_none() && seg_sha == doc_sha && reassembled.len() == DOC_SIZE;
    let seg_mbps = (reassembled.len() as f64 / 1e6) / (seg_ms as f64 / 1e3).max(0.001);
    println!(
        "whole-45MiB fetch: {}  {seg_ms}ms  {seg_mbps:.1} MB/s  (chunks={n_chunks})",
        if seg_ok { "OK" } else { "BAD" }
    );

    // ── Parallel reads on ONE session (pipelining hides RTT — the P10.4 lever). ─
    let par_n: usize = 32;
    let t = Instant::now();
    let mut tasks = Vec::with_capacity(par_n);
    for i in 0..par_n {
        let c = Arc::clone(&client);
        let l = loc.clone();
        let off = ((i as u64 + 7).wrapping_mul(2_654_435_761) % (max_off / 4096)) * 4096;
        tasks.push(tokio::spawn(async move {
            c.get_file_range(&l, off, 4096).await.map(|b| b.len())
        }));
    }
    let mut par_ok = 0usize;
    for h in tasks {
        if matches!(h.await, Ok(Ok(_))) {
            par_ok += 1;
        }
    }
    let par_ms = t.elapsed().as_millis();
    let par_rps = par_n as f64 / (par_ms as f64 / 1000.0).max(0.001);
    println!(
        "parallel 4KiB x{par_n} on one session: {par_ms}ms wall, ok={par_ok} => {par_rps:.1} reads/s (serial p50 was {w_p50}ms/read)"
    );

    // Parallel whole-segment fetch (bounded concurrency) — the realistic warm cost.
    let t = Instant::now();
    let n512 = (DOC_SIZE as u64).div_ceil(512 * 1024);
    let sem = Arc::new(tokio::sync::Semaphore::new(16));
    let mut tasks = Vec::new();
    for c in 0..n512 {
        let cl = Arc::clone(&client);
        let l = loc.clone();
        let sem = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            let _p = sem.acquire().await.unwrap();
            cl.get_file_range(&l, c * 512 * 1024, 512 * 1024)
                .await
                .map(|b| b.len())
        }));
    }
    let mut par_seg_bytes = 0usize;
    for h in tasks {
        if let Ok(Ok(n)) = h.await {
            par_seg_bytes += n;
        }
    }
    let par_seg_ms = t.elapsed().as_millis();
    let par_seg_mbps = (par_seg_bytes as f64 / 1e6) / (par_seg_ms as f64 / 1000.0).max(0.001);
    println!(
        "parallel whole-45MiB fetch (conc=16): {par_seg_ms}ms {par_seg_mbps:.1} MB/s (serial was {seg_mbps:.1} MB/s)"
    );

    // ── Cleanup: delete the spike doc (leave the throwaway topic; harmless). ──
    client.delete_message(msg_id).await.ok();

    // ── Verdict + report. ─────────────────────────────────────────────────────
    let all_correct = correctness.iter().all(|(_, r)| r.ok) && walk_bad == 0 && seg_ok && size_ok;
    // Projected first cold scan of a small ext4 (~2000 metadata 4 KiB reads):
    //  - WITHOUT the cache (serial single reads): 2000 * p50
    //  - WITH whole-segment warming (design P1.14): working_set/45MiB * seg_ms
    let proj_naive_s = (2000.0 * w_p50 as f64) / 1000.0;
    // Warm a ~256 MiB ext4 (~6 segments) using the PARALLEL fetch cost.
    let proj_warm_256mb_s = (256.0_f64 / 45.0).ceil() * (par_seg_ms as f64 / 1000.0);

    let verdict: String = if !all_correct {
        "NO-GO (correctness): ranged reads did not verify — the primitive is not sound yet".into()
    } else if flood_wait_hits > 0 {
        "CONDITIONAL: reads correct but a FLOOD_WAIT hit during the walk — the read-rate governor (P3.4) + multi-conn (P10.4) are load-bearing, not optional".to_string()
    } else if par_seg_mbps >= 5.0 {
        format!("GO: the ranged-read primitive is correct with ZERO rate-limiting. Serial reads are RTT-bound ({w_p50}ms p50, {seg_mbps:.1} MB/s) and unusable alone, but PARALLEL reads on ONE session reach {par_seg_mbps:.1} MB/s — so the cache tier (P1.12–P1.16) + multi-connection reads (P10.4) + locality packing (P1.15) are validated as load-bearing AND sufficient. Proceed to the carve-out.")
    } else {
        format!("CONDITIONAL: primitive correct but even parallel throughput ({par_seg_mbps:.1} MB/s) is marginal — multi-SESSION read fan-out may be required; usability hinges on cache hit-rate + locality packing (P1.15)")
    };
    println!("\n=== VERDICT: {verdict} ===");

    write_report(&Report {
        upload_ms,
        up_mbps,
        dc_id,
        size_ok,
        resolve_ms,
        correctness: &correctness,
        walk_reads: WALK_READS,
        w_p50,
        w_p95,
        w_min,
        w_max,
        w_mean,
        walk_total_ms,
        walk_bad,
        flood_wait_hits,
        walk_err: walk_err.clone(),
        seg_ok,
        seg_ms,
        seg_mbps,
        seg_err: seg_err.clone(),
        fsync_p50: fsync.p50,
        fsync_p95: fsync.p95,
        par_rps,
        par_seg_mbps,
        proj_naive_s,
        proj_warm_256mb_s,
        verdict: &verdict,
    })
    .context("write the go/no-go report")?;
    println!("wrote {}", report_path().display());
    Ok(())
}

// ───────────────────────────── helpers ──────────────────────────────────────

struct ReadResult {
    ok: bool,
    ms: u128,
    got_len: usize,
}

async fn read_check(
    client: &TelegramClient,
    loc: &tl::enums::InputFileLocation,
    doc: &[u8],
    off: u64,
    len: u32,
) -> ReadResult {
    let t = Instant::now();
    match client.get_file_range(loc, off, len).await {
        Ok(got) => {
            let ms = t.elapsed().as_millis();
            let want_end = (off as usize + len as usize).min(doc.len());
            let want = &doc[off as usize..want_end];
            ReadResult {
                ok: got.as_slice() == want,
                ms,
                got_len: got.len(),
            }
        }
        Err(e) => {
            eprintln!("read off={off} len={len} ERR: {e}");
            ReadResult {
                ok: false,
                ms: t.elapsed().as_millis(),
                got_len: 0,
            }
        }
    }
}

struct Fsync {
    p50: f64,
    p95: f64,
}

fn measure_local_fsync() -> Result<Fsync> {
    let mut path = std::env::temp_dir();
    path.push(format!("teagarden-dev-p1-fsync-{}.tmp", rand_hex(6)));
    let buf = [0u8; 4096];
    let mut samples = Vec::with_capacity(FSYNC_ITERS);
    for _ in 0..FSYNC_ITERS {
        let t = Instant::now();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        f.write_all(&buf)?;
        f.sync_all()?;
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    std::fs::remove_file(&path).ok();
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Ok(Fsync {
        p50: samples[samples.len() / 2],
        p95: samples[samples.len() * 95 / 100],
    })
}

fn stats(v: &[u128]) -> (u128, u128, u128, u128, f64) {
    if v.is_empty() {
        return (0, 0, 0, 0, 0.0);
    }
    let mut s = v.to_vec();
    s.sort_unstable();
    let mean = s.iter().sum::<u128>() as f64 / s.len() as f64;
    (
        s[s.len() / 2],
        s[s.len() * 95 / 100],
        s[0],
        s[s.len() - 1],
        mean,
    )
}

struct Report<'a> {
    upload_ms: u128,
    up_mbps: f64,
    dc_id: i32,
    size_ok: bool,
    resolve_ms: u128,
    correctness: &'a [(String, ReadResult)],
    walk_reads: usize,
    w_p50: u128,
    w_p95: u128,
    w_min: u128,
    w_max: u128,
    w_mean: f64,
    walk_total_ms: u128,
    walk_bad: usize,
    flood_wait_hits: usize,
    walk_err: Option<String>,
    seg_ok: bool,
    seg_ms: u128,
    seg_mbps: f64,
    seg_err: Option<String>,
    fsync_p50: f64,
    fsync_p95: f64,
    par_rps: f64,
    par_seg_mbps: f64,
    proj_naive_s: f64,
    proj_warm_256mb_s: f64,
    verdict: &'a str,
}

fn write_report(r: &Report) -> Result<()> {
    let mut s = String::new();
    s.push_str("# TeaGarden block devices — P-1 feasibility spike results (GO / NO-GO)\n\n");
    s.push_str("> Generated by `cargo run -p teagarden-transport-test --bin p1-feasibility`.\n");
    s.push_str("> Measures the real Telegram ranged-read primitive + the latencies that decide whether a metadata-heavy FS is usable on TeaGarden block devices.\n\n");
    s.push_str(&format!("## VERDICT\n\n**{}**\n\n", r.verdict));

    s.push_str("## Primitive correctness (ranged `upload.GetFile`, byte-verified)\n\n");
    s.push_str("| case | result | bytes | latency |\n|---|---|---|---|\n");
    for (name, rr) in r.correctness {
        s.push_str(&format!(
            "| {name} | {} | {} | {}ms |\n",
            if rr.ok { "✅ OK" } else { "❌ BAD" },
            rr.got_len,
            rr.ms
        ));
    }
    s.push_str(&format!(
        "\n- upload of the 45 MiB segment (single session): {}ms ({:.1} MB/s)\n- document DC id: `{}`  (uploaded via our own session — same-DC `GetFile` path)\n- reported size matches 45 MiB: {}\n- location resolve (`GetMessages`) cost: {}ms — cached per-segment in the real design (P3.1a)\n\n",
        r.upload_ms, r.up_mbps, r.dc_id, if r.size_ok { "✅" } else { "❌" }, r.resolve_ms
    ));

    s.push_str("## Read latency over ONE session (the existential measurement)\n\n");
    s.push_str(&format!(
        "Cold single 4 KiB random reads, serial, n={}:\n\n- p50 **{}ms**, p95 **{}ms**, min {}ms, max {}ms, mean {:.0}ms\n- total wall {}ms, mismatches {}, FLOOD_WAIT hits **{}**\n{}\n\n",
        r.walk_reads, r.w_p50, r.w_p95, r.w_min, r.w_max, r.w_mean, r.walk_total_ms, r.walk_bad, r.flood_wait_hits,
        r.walk_err.as_ref().map(|e| format!("- first error: `{e}`")).unwrap_or_default()
    ));
    s.push_str(&format!(
        "Whole-45 MiB segment fetch (the cache-warm cost): {} — {}ms, **{:.1} MB/s** SERIAL{}\n\n",
        if r.seg_ok {
            "✅ verified sha256"
        } else {
            "❌ FAILED"
        },
        r.seg_ms,
        r.seg_mbps,
        r.seg_err
            .as_ref()
            .map(|e| format!(" (error: `{e}`)"))
            .unwrap_or_default()
    ));
    s.push_str(&format!(
        "**Parallelism (the P10.4 lever, on ONE session):** 32 concurrent 4 KiB reads ⇒ **{:.1} reads/s** (vs {}ms/read serial); whole-45 MiB fetch at concurrency 16 ⇒ **{:.1} MB/s** (vs {:.1} MB/s serial). Pipelining hides the RTT — this is what makes the cache-warm + read paths viable.\n\n",
        r.par_rps, r.w_p50, r.par_seg_mbps, r.seg_mbps
    ));
    s.push_str(&format!(
        "Local write-back fsync (4 KiB): p50 **{:.3}ms**, p95 {:.3}ms — this is the *default* write/flush latency (D8 local-fast); Telegram is off the hot path.\n\n",
        r.fsync_p50, r.fsync_p95
    ));

    s.push_str("## Projected first cold scan (interpretation)\n\n");
    s.push_str(&format!(
        "- **Naïve** (no cache, ~2000 serial 4 KiB metadata reads): ≈ **{:.0}s** — this is what makes a naïve implementation unusable.\n",
        r.proj_naive_s
    ));
    s.push_str(&format!(
        "- **With whole-segment warming** (design P1.12–P1.14) for a ~256 MiB ext4 (~6 segments): ≈ **{:.0}s** first scan, then warm.\n",
        r.proj_warm_256mb_s
    ));
    s.push_str(&format!(
        "- Write path is **local-fast** ({:.3}ms fsync) regardless — writes never wait on Telegram (D8).\n\n",
        r.fsync_p50
    ));
    s.push_str("## What this gates\n\n");
    s.push_str("- ✅/❌ above decides whether the `download_range` primitive is real (P3.1) — the keystone every read depends on.\n");
    s.push_str("- The naïve-vs-warm gap is the whole argument for making the cache tier (P1.12–P1.16) P1-core rather than P10 polish.\n");
    s.push_str("- A FLOOD_WAIT during the walk means the read-rate governor (P3.4) and multi-connection reads (P10.4) are load-bearing, not optional.\n");
    s.push_str("- The real end-to-end proof (mkfs.ext4 → mount → e2fsck over NBD) is P9.4; this spike de-risks it before the crate re-layering.\n");

    let path = report_path();
    std::fs::write(&path, s).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Where the report goes: `$TEAGARDEN_DEV_P1_REPORT`, else a file in the system
/// temp dir. Never inside the repository.
fn report_path() -> PathBuf {
    report_path_from(std::env::var_os("TEAGARDEN_DEV_P1_REPORT"))
}

fn report_path_from(env: Option<std::ffi::OsString>) -> PathBuf {
    match env.filter(|p| !p.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => std::env::temp_dir().join("teagarden-dev-p1-go-nogo.md"),
    }
}

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

fn read_group_json() -> Result<(i64, i64)> {
    let mut p = dirs_home();
    p.push(".config/teagarden/group.json");
    let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    let v: serde_json::Value = serde_json::from_str(&s)?;
    let id = v["group_id"].as_i64().context("group_id")?;
    let hash = v["group_access_hash"]
        .as_i64()
        .context("group_access_hash")?;
    Ok((id, hash))
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The report goes where the environment says, else the system temp dir.
    #[test]
    fn report_goes_to_the_env_path_or_the_temp_dir() {
        assert_eq!(
            report_path_from(Some("/somewhere/else/report.md".into())),
            PathBuf::from("/somewhere/else/report.md")
        );
        let default = std::env::temp_dir().join("teagarden-dev-p1-go-nogo.md");
        assert_eq!(report_path_from(None), default);
        assert_eq!(report_path_from(Some("".into())), default);
    }
}
