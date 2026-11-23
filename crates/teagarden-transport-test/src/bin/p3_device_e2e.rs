//! P3 live-Telegram device end-to-end (the owed round-trip).
//!
//! Drives the REAL `teagarden-dev` engine over the REAL `TelegramClient` — no mock —
//! and proves the durability contract against live Telegram:
//!
//!   1. write a scattered, position-addressed pattern (multiple segments + a hole
//!      + an overwrite), `close()` → segments seal + upload to Telegram;
//!   2. read it back byte-exact from the warm cache;
//!   3. drop the device and `open()` the SAME dir with a COLD cache → reads now
//!      download the sealed segments from Telegram and decrypt → byte-exact
//!      (same-machine recovery, M2d-1);
//!   4. `checkpoint()` publishes a `DeviceHead`, then `recover_from_head()` on a
//!      FRESH dir (no local staging) rebuilds the device from the cloud alone →
//!      byte-exact (fresh-machine recovery, M2d-2).
//!
//! Uses a throwaway forum topic so it never touches real volume data. Run:
//!   cargo run -p teagarden-transport-test --bin p3-device-e2e --release
//! Needs live creds: TG_API_ID / TG_API_HASH (~/.config/teagarden/.env),
//! ~/.config/teagarden/teagarden.session, ~/.config/teagarden/group.json.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use rand::RngCore;

use teagarden_core::crypto::kdf;
use teagarden_core::crypto::keys::Argon2Params;
use teagarden_dev::cache::CacheConfig;
use teagarden_dev::device::{DeviceConfig, DeviceKeys, ReadConfig, TeaGardenDevice};
use teagarden_telegram::client::TelegramClient;
use teagarden_telegram::types::{AuthState, ChannelRef, TelegramConfig};

const BS: u64 = 4096;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "p3_device_e2e=info,teagarden_telegram=warn".into()),
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
    println!("== P3 live-Telegram device e2e ==  group_id={group_id}");

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

    // Throwaway topic (channel_ref is immutable, so create with a placeholder then
    // rebind), mirroring the P-1 spike.
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

    let transport = Arc::new(TelegramClient::new(mk_cfg(topic_id)));
    match transport.connect().await.context("connect (main)")? {
        AuthState::Authenticated => {}
        other => bail!("not authenticated: {other:?}"),
    }

    // A4 — REAL device keys derived from a credential via the audited KeyHierarchy
    // (credential -> Argon2id root -> hierarchy -> domain-separated device keys).
    // No hardcoded-key fallback: this drives REAL Telegram, so its keys are real too.
    let password = std::env::var("TEAGARDEN_DEV_PASSWORD").unwrap_or_else(|_| {
        // This e2e creates a throwaway device each run; a stable default keeps the
        // same-machine reopen + fresh-machine recover phases consistent. Override
        // with TEAGARDEN_DEV_PASSWORD.
        "p3-device-e2e-credential".to_string()
    });
    let salt = [0u8; 32];
    let root = kdf::derive_root_key(password.as_bytes(), &salt, &Argon2Params::default())
        .context("derive root key")?;
    let hierarchy = kdf::derive_hierarchy_v1(root, &salt, 0, 0).context("derive hierarchy")?;
    let keys = DeviceKeys::from_hierarchy(&hierarchy).context("derive device keys")?;
    // Small segments so the live round-trip is quick but still multi-segment.
    let cfg = || DeviceConfig {
        segment_target: 2 * 1024 * 1024, // 2 MiB
        record_max: 1024 * 1024,
        cache: CacheConfig {
            budget_bytes: 64 * 1024 * 1024,
            ..Default::default()
        },
        ..Default::default()
    };
    // Derived, not invented — available before any superblock exists, which the
    // fresh-machine recover_from_head phase below depends on (A4).
    let uuid = DeviceKeys::device_uuid_for(&hierarchy).context("derive device uuid")?;
    let capacity_blocks = 8192; // 32 MiB device

    // The reference pattern: 2 MiB at lba 0, 512 KiB at lba 2000, then overwrite
    // block 5 — spans several 2 MiB segments with a hole between, and a supersede.
    let mut a = vec![0u8; 512 * BS as usize]; // 2 MiB
    rand::thread_rng().fill_bytes(&mut a);
    let mut b = vec![0u8; 128 * BS as usize]; // 512 KiB
    rand::thread_rng().fill_bytes(&mut b);
    let mut ov = vec![0u8; BS as usize];
    rand::thread_rng().fill_bytes(&mut ov);
    // reference model of block 5 after the overwrite
    a[5 * BS as usize..6 * BS as usize].copy_from_slice(&ov);

    let dir = tempfile::tempdir().context("device dir")?;

    // ── Phase 1: write + close (seal + upload to Telegram) ────────────────────
    let t = Instant::now();
    let mut dev = TeaGardenDevice::create(
        Arc::clone(&transport),
        keys.clone(),
        uuid,
        capacity_blocks,
        dir.path(),
        cfg(),
    )
    .context("create")?;
    dev.write_at(0, &a).await.context("write a")?;
    dev.write_at(2000, &b).await.context("write b")?;
    dev.write_at(5, &ov).await.context("overwrite block 5")?;
    dev.close().await.context("close (seal+upload)")?;
    let confirmed = dev.confirmed_segments();
    println!(
        "phase1 write+close: {confirmed} segments uploaded to Telegram in {}ms",
        t.elapsed().as_millis()
    );
    if confirmed == 0 {
        bail!("no segments were confirmed to Telegram");
    }

    // warm-cache read-back
    verify(&mut dev, 0, &a, "phase1 warm read a").await?;
    verify(&mut dev, 2000, &b, "phase1 warm read b").await?;
    // hole between a (ends block 512) and b (block 2000) reads zeros
    let hole = dev.read_at(1000, 1).await.context("read hole")?;
    if hole != vec![0u8; BS as usize] {
        bail!("phase1: hole did not read zeros");
    }
    drop(dev);

    // ── Phase 2: same-machine recovery — open() with a COLD cache ─────────────
    let t = Instant::now();
    let mut dev = TeaGardenDevice::open(Arc::clone(&transport), keys.clone(), dir.path(), cfg())
        .context("open (same-machine recovery)")?;
    println!(
        "phase2 open() same-machine recovery in {}ms",
        t.elapsed().as_millis()
    );
    verify(
        &mut dev,
        0,
        &a,
        "phase2 cold read a (download from Telegram)",
    )
    .await?;
    verify(
        &mut dev,
        2000,
        &b,
        "phase2 cold read b (download from Telegram)",
    )
    .await?;

    // ── Phase 3: fresh-machine recovery — checkpoint → recover_from_head() ─────
    let head_msg_id = dev
        .checkpoint()
        .await
        .context("checkpoint (publish head)")?;
    println!("phase3 checkpoint published head msg_id={head_msg_id}");
    drop(dev);

    let fresh = tempfile::tempdir().context("fresh dir")?;
    let t = Instant::now();
    let mut fresh_dev = TeaGardenDevice::recover_from_head(
        Arc::clone(&transport),
        keys.clone(),
        uuid,
        fresh.path(),
        head_msg_id,
        cfg(),
    )
    .await
    .context("recover_from_head (fresh-machine recovery)")?;
    println!(
        "phase3 recover_from_head() fresh-machine recovery in {}ms",
        t.elapsed().as_millis()
    );
    verify(&mut fresh_dev, 0, &a, "phase3 fresh-machine read a").await?;
    verify(&mut fresh_dev, 2000, &b, "phase3 fresh-machine read b").await?;

    // ── Phase 4 (P3.1): ranged cold reads — MEASURED against live Telegram ────
    //
    // Scattered single-block records (the metadata-read shape), then cold
    // recoveries with ranged reads ON vs OFF, measuring the WIRE bytes
    // (TransportStats now counts GetFile payloads, not trimmed slices) and
    // latency for a single 4 KiB read. Also exercises a ranged read whose
    // record straddles the 1 MiB GetFile boundary (phase-1's 1 MiB records).
    println!("\n== phase4 (P3.1): ranged cold reads, measured ==");
    let mut scattered: Vec<(u64, Vec<u8>)> = Vec::new();
    for i in 0..16u64 {
        let lba = 3000 + i * 7;
        let mut d = vec![0u8; BS as usize];
        rand::thread_rng().fill_bytes(&mut d);
        fresh_dev
            .write_at(lba, &d)
            .await
            .context("phase4 scattered write")?;
        scattered.push((lba, d));
    }
    fresh_dev.close().await.context("phase4 close")?;
    let head2 = fresh_dev.checkpoint().await.context("phase4 checkpoint")?;
    drop(fresh_dev);

    // segments here are small (2 MiB) with few records — a small probe keeps
    // the bootstrap honest instead of tail-clamping half a megabyte
    let cfg_ranged = || DeviceConfig {
        read: ReadConfig {
            index_tail_probe: 8 * 1024,
            ..Default::default()
        },
        ..cfg()
    };
    let cfg_whole = || DeviceConfig {
        read: ReadConfig {
            ranged_reads: false,
            ..Default::default()
        },
        ..cfg()
    };

    // cold machine, RANGED (the new default path)
    let cold_r = tempfile::tempdir().context("cold ranged dir")?;
    let mut dev_r = TeaGardenDevice::recover_from_head(
        Arc::clone(&transport),
        keys.clone(),
        uuid,
        cold_r.path(),
        head2,
        cfg_ranged(),
    )
    .await
    .context("phase4 recover (ranged)")?;

    let (lba0, want0) = &scattered[0];
    let s0 = transport.stats();
    let t0 = Instant::now();
    verify(&mut dev_r, *lba0, want0, "phase4 RANGED cold 4 KiB read").await?;
    let ms_first = t0.elapsed().as_millis();
    let s1 = transport.stats();
    let ranged_first = s1.bytes_downloaded - s0.bytes_downloaded;

    let (lba1, want1) = &scattered[1];
    let t0 = Instant::now();
    verify(
        &mut dev_r,
        *lba1,
        want1,
        "phase4 RANGED read #2 (index cached)",
    )
    .await?;
    let ms_second = t0.elapsed().as_millis();
    let s2 = transport.stats();
    let ranged_second = s2.bytes_downloaded - s1.bytes_downloaded;

    // 1 MiB-boundary straddle: blocks ~300 live >1 MiB into a 1 MiB record of
    // phase-1's first segment — the sealed-record fetch must stitch GetFile
    // calls across the boundary and still decrypt byte-exact.
    verify(
        &mut dev_r,
        300,
        &a[300 * BS as usize..304 * BS as usize],
        "phase4 RANGED boundary-straddling read",
    )
    .await?;
    // the rest of the scattered set, byte-exact over the ranged path
    for (lba, want) in scattered.iter().skip(2) {
        let got = dev_r.read_at(*lba, 1).await.context("phase4 scattered")?;
        if &got != want {
            bail!("phase4: scattered block at lba {lba} mismatched over ranged path");
        }
    }
    println!("  ok: all scattered blocks byte-exact over the ranged path");
    drop(dev_r);

    // cold machine, WHOLE-SEGMENT (the old behavior, for the honest comparison)
    let cold_w = tempfile::tempdir().context("cold whole dir")?;
    let mut dev_w = TeaGardenDevice::recover_from_head(
        Arc::clone(&transport),
        keys.clone(),
        uuid,
        cold_w.path(),
        head2,
        cfg_whole(),
    )
    .await
    .context("phase4 recover (whole)")?;
    let (lba2, want2) = &scattered[2];
    let s3 = transport.stats();
    let t0 = Instant::now();
    verify(&mut dev_w, *lba2, want2, "phase4 WHOLE cold 4 KiB read").await?;
    let ms_whole = t0.elapsed().as_millis();
    let s4 = transport.stats();
    let whole_first = s4.bytes_downloaded - s3.bytes_downloaded;
    drop(dev_w);

    println!("\n== phase4 measurements (wire bytes for ONE cold 4 KiB read) ==");
    println!("  ranged, first touch (tail bootstrap + record): {ranged_first} B in {ms_first} ms");
    println!(
        "  ranged, second read (index cached):            {ranged_second} B in {ms_second} ms"
    );
    println!("  whole-segment (old behavior):                  {whole_first} B in {ms_whole} ms");
    if whole_first > 0 && ranged_first > 0 {
        println!(
            "  amplification reduction: {:.1}× (first touch), {:.1}× (warm index)",
            whole_first as f64 / ranged_first as f64,
            whole_first as f64 / ranged_second.max(1) as f64
        );
    }
    if ranged_first >= whole_first {
        bail!("phase4: ranged first-touch moved no fewer bytes than the whole-segment path");
    }

    println!("\n✅ P3 LIVE E2E PASSED — write→close→(same-machine open)→(fresh-machine recover_from_head)→(P3.1 ranged cold reads, measured), all byte-exact over real Telegram.");
    println!("(throwaway topic id={topic_id} left in place for inspection/GC)");
    Ok(())
}

/// Read `expect.len()/BS` blocks at `lba` and assert byte-exact.
async fn verify(
    dev: &mut TeaGardenDevice<TelegramClient>,
    lba: u64,
    expect: &[u8],
    what: &str,
) -> Result<()> {
    let count = expect.len() as u64 / BS;
    let got = dev
        .read_at(lba, count)
        .await
        .with_context(|| format!("{what}: read"))?;
    if got != expect {
        let first = got
            .iter()
            .zip(expect)
            .position(|(x, y)| x != y)
            .unwrap_or(0);
        bail!(
            "{what}: MISMATCH at byte {first} (block {})",
            first / BS as usize
        );
    }
    println!("  ok: {what} ({count} blocks byte-exact)");
    Ok(())
}

fn env_var(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env var {key}"))
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
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
