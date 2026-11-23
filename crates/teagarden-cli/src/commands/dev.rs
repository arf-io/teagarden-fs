//! `teagarden dev` — the TeaGarden encrypted block-device surface.
//!
//! A TeaGarden block device is a log-structured, position-addressed encrypted **block device**
//! whose segments are Telegram documents. You put a real kernel filesystem on top
//! of it (`mkfs.ext4 /dev/nbd0`), which is why the shape of this command set is
//! modelled on **cryptsetup**, not on `mkfs`:
//!
//! | cryptsetup | here | what it does |
//! |---|---|---|
//! | `luksFormat` | `dev create` | write the superblock + first head |
//! | `open` | `dev serve nbd` | expose the decrypted device (as /dev/nbdN) |
//! | `status` | `dev status` | report capacity, epoch, segments, head |
//! | `resize` | `dev resize` | change the logical capacity |
//! | — | `dev gc` | reclaim superseded segments |
//! | — | `dev delete` | delete the device's Telegram topic, then its local state |
//!
//! **There is deliberately no `mkfs.teagarden`.** The filesystem you make on a
//! TeaGarden block device is the *guest* filesystem, and you make it with the ordinary
//! `mkfs.ext4` / `mkfs.xfs` / `mkfs.btrfs` against the exported block device. A
//! `mkfs.teagarden` would imply this tool formats `/dev/nbd0`, which it must never
//! do — that is the guest's data.
//!
//! ## The device registry
//!
//! The engine persists only `superblock`, `catalog` and `staging.log`. Nothing in
//! it records WHICH Telegram group/topic holds the segments, what the capacity is,
//! or the last head message id — yet `recover_from_head` needs exactly that head id
//! as an argument. Without a registry, disaster recovery required the operator to
//! know a raw Telegram message ID by heart.
//!
//! `DeviceRegistry` closes that: one JSON file per device recording the Telegram
//! location, the key-derivation salt, the geometry, and the last known head. It is
//! metadata only — it holds no key material and no plaintext.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use teagarden_core::crypto::kdf;
use teagarden_core::crypto::keys::Argon2Params;
use teagarden_dev::adapter::BlockDeviceAdapter;
use teagarden_dev::cache::CacheConfig;
use teagarden_dev::device::{DeviceConfig, DeviceKeys, TeaGardenDevice};
use teagarden_dev::DeviceDirGuard;
use teagarden_telegram::client::{ForumAdmin, TelegramClient};
use teagarden_telegram::types::{AuthState, ChannelRef, TelegramConfig};

use super::utils;

/// 4 KiB logical blocks — the unit `capacity_blocks` counts in.
const BLOCK_SIZE: u64 = 4096;

/// On-disk record for one TeaGarden block device.
///
/// Metadata only: no key material, no plaintext. The salt is not secret (it is a
/// KDF salt, and the credential is what protects the device).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Operator-facing device name.
    pub name: String,
    /// Directory holding `superblock` / `catalog` / `staging.log`.
    pub dir: PathBuf,
    /// Logical capacity in 4 KiB blocks.
    pub capacity_blocks: u64,
    /// Target segment size in bytes (one segment = one Telegram document).
    pub segment_target: u64,
    /// Argon2id salt for credential -> root key.
    pub salt: [u8; 32],
    /// Telegram supergroup id holding this device's segments.
    pub telegram_group_id: i64,
    /// Access hash for that group.
    pub telegram_access_hash: i64,
    /// Forum topic id dedicated to this device.
    pub telegram_topic_id: i64,
    /// Last head message id we observed. THIS is what `recover_from_head` needs;
    /// without it, disaster recovery is impossible without the operator knowing a
    /// raw Telegram message id.
    #[serde(default)]
    pub last_head_msg_id: Option<i64>,
    /// Unix timestamp of creation.
    pub created_at: i64,
}

/// Where device records live: `<data>/teagarden/devices/<name>.json`.
fn registry_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("TEAGARDEN_DEV_REGISTRY_DIR") {
        return PathBuf::from(d);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("teagarden")
        .join("devices")
}

fn record_path(name: &str) -> PathBuf {
    registry_dir().join(format!("{name}.json"))
}

impl DeviceRecord {
    fn load(name: &str) -> Result<Self> {
        Self::load_in(&registry_dir(), name)
    }

    fn load_in(dir: &Path, name: &str) -> Result<Self> {
        let p = dir.join(format!("{name}.json"));
        let s = std::fs::read_to_string(&p).with_context(|| {
            format!(
                "no such device '{name}' (looked in {}). List them with `teagarden dev list`.",
                p.display()
            )
        })?;
        serde_json::from_str(&s).with_context(|| format!("parse device record {}", p.display()))
    }

    fn save(&self) -> Result<()> {
        self.save_in(&registry_dir())
    }

    fn save_in(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).context("create device registry dir")?;
        let p = dir.join(format!("{}.json", self.name));
        // Atomic replace (unique 0600 temp, fsync, rename) so a crash or a racing
        // writer cannot leave a truncated record (losing the head id would cost
        // the ability to recover the device).
        let bytes = serde_json::to_vec_pretty(self)?;
        teagarden_core::fsutil::write_file_atomic(&p, &bytes, "device record")
            .context("write device record")?;
        Ok(())
    }

    fn list_all() -> Result<Vec<Self>> {
        Self::list_in(&registry_dir())
    }

    fn list_in(dir: &Path) -> Result<Vec<Self>> {
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).context("read device registry")? {
            let p = e?.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if let Ok(s) = std::fs::read_to_string(&p) {
                if let Ok(r) = serde_json::from_str::<Self>(&s) {
                    out.push(r);
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

/// Read the device credential. Required — A4 closed the hardcoded-key gap and it
/// stays closed: there is no fallback key anywhere in this surface.
fn read_credential(password_file: Option<&str>) -> Result<utils::SecretString> {
    if let Some("-") = password_file {
        let mut s = String::new();
        std::io::stdin()
            .read_line(&mut s)
            .context("read credential from stdin")?;
        return Ok(utils::secret_without_line_endings(s));
    }
    if let Some(p) = password_file {
        return std::fs::read_to_string(p)
            .map(utils::secret_without_line_endings)
            .with_context(|| format!("read credential file: {p}"));
    }
    if let Ok(p) = std::env::var("TEAGARDEN_DEV_PASSWORD") {
        return Ok(utils::secret_without_line_endings(p));
    }
    utils::prompt_password("Device credential: ")
}

/// Derive the device keys from a credential + salt through the audited hierarchy.
///
/// **GOTCHA (documented because it looks like a hang):** `Argon2Params::default()`
/// is 256 MiB / t=4 / p=4. In a DEBUG build this takes minutes and looks like the
/// process has frozen. Use a `--release` binary for anything interactive.
fn derive_keys(credential: &str, salt: &[u8; 32]) -> Result<(DeviceKeys, [u8; 16])> {
    derive_keys_with(credential, salt, &Argon2Params::default())
}

/// [`derive_keys`] with explicit Argon2 cost, so tests need not spend 256 MiB per call.
fn derive_keys_with(
    credential: &str,
    salt: &[u8; 32],
    params: &Argon2Params,
) -> Result<(DeviceKeys, [u8; 16])> {
    let root =
        kdf::derive_root_key(credential.as_bytes(), salt, params).context("derive root key")?;
    let hierarchy = kdf::derive_hierarchy_v1(root, salt, 0, 0).context("derive hierarchy")?;
    let keys = DeviceKeys::from_hierarchy(&hierarchy).context("derive device keys")?;
    let uuid = DeviceKeys::device_uuid_for(&hierarchy).context("derive device uuid")?;
    Ok((keys, uuid))
}

/// Build a REAL Telegram transport bound to this device's topic.
///
/// This is the difference between the shipped `dev serve` and the old (now
/// removed) `teagarden-dev-nbd-serve` test binary, which used `MockTransport::new()`
/// and so could never serve real data.
async fn real_transport(rec: &DeviceRecord) -> Result<Arc<TelegramClient>> {
    real_transport_for(ChannelRef {
        id: rec.telegram_group_id,
        access_hash: rec.telegram_access_hash,
        topic_id: rec.telegram_topic_id,
    })
    .await
}

/// [`real_transport`] for an explicit storage location.
async fn real_transport_for(channel_ref: ChannelRef) -> Result<Arc<TelegramClient>> {
    let (api_id, api_hash) = utils::load_telegram_credentials()?;
    let cfg = TelegramConfig {
        api_id,
        api_hash,
        session_path: super::volume::session_file_path()
            .to_string_lossy()
            .to_string(),
        channel_ref: Some(channel_ref),
        ..Default::default()
    };
    let client = TelegramClient::new(cfg);
    match client.connect().await.map_err(utils::telegram_err)? {
        AuthState::Authenticated => {}
        other => anyhow::bail!(
            "not authenticated with Telegram ({other:?}) — run `teagarden auth login`"
        ),
    }
    Ok(Arc::new(client))
}

fn device_config(rec: &DeviceRecord) -> DeviceConfig {
    DeviceConfig {
        segment_target: rec.segment_target,
        record_max: 1024 * 1024,
        cache: CacheConfig::default(),
        ..Default::default()
    }
}

// ── verbs ───────────────────────────────────────────────────────────────────

/// `dev create` — the `luksFormat` step: write the superblock and first head.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    name: &str,
    size_gib: u64,
    segment_mib: u64,
    dir: Option<&str>,
    password_file: Option<&str>,
    group_name: Option<&str>,
) -> Result<()> {
    if record_path(name).exists() {
        anyhow::bail!(
            "device '{name}' already exists — `teagarden dev status {name}`, or pick another name"
        );
    }
    if size_gib == 0 {
        anyhow::bail!("--size-gib must be at least 1");
    }

    let device_dir = match dir {
        Some(d) => PathBuf::from(d),
        None => registry_dir().join(name).join("data"),
    };
    std::fs::create_dir_all(&device_dir).context("create device data dir")?;

    // Fresh random salt per device: two devices under the same credential must not
    // derive the same keys or the same device UUID.
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let credential = read_credential(password_file)?;
    println!("Deriving device keys (Argon2id 256 MiB — this takes a moment)...");
    let (keys, device_uuid) = derive_keys(&credential, &salt)?;

    // A dedicated forum topic per device, mirroring one-topic-per-volume.
    let (api_id, api_hash) = utils::load_telegram_credentials()?;
    let boot_cfg = TelegramConfig {
        api_id,
        api_hash,
        session_path: super::volume::session_file_path()
            .to_string_lossy()
            .to_string(),
        channel_ref: None,
        ..Default::default()
    };
    let boot = TelegramClient::new(boot_cfg);
    match boot.connect().await.map_err(utils::telegram_err)? {
        AuthState::Authenticated => {}
        other => anyhow::bail!(
            "not authenticated with Telegram ({other:?}) — run `teagarden auth login`"
        ),
    }
    // Reuse the shared forum supergroup, exactly as `volume create` does, so
    // devices and volumes live side by side under one group, and give the device
    // its own topic. The topic title is random words: the device name stays in
    // the local registry and is never sent to Telegram.
    let allocated =
        super::group::allocate_topic(&boot, &super::group::group_config_path()?, group_name)
            .await
            .context("create forum topic for device")?;
    let (group_id, group_hash, topic_id) = (
        allocated.group_id,
        allocated.group_access_hash,
        allocated.topic_id,
    );
    boot.save_session().await.ok();
    drop(boot);

    let capacity_blocks = size_gib * 1024 * 1024 * 1024 / BLOCK_SIZE;
    let mut rec = DeviceRecord {
        name: name.to_string(),
        dir: device_dir.clone(),
        capacity_blocks,
        segment_target: segment_mib * 1024 * 1024,
        salt,
        telegram_group_id: group_id,
        telegram_access_hash: group_hash,
        telegram_topic_id: topic_id,
        last_head_msg_id: None,
        created_at: chrono_now(),
    };

    let transport = real_transport(&rec).await?;
    let mut device = TeaGardenDevice::create(
        transport,
        keys,
        device_uuid,
        capacity_blocks,
        &device_dir,
        device_config(&rec),
    )
    .context("create device")?;

    // Flush so the superblock + first head exist in Telegram before we claim success,
    // and record the head id so this device can actually be recovered later.
    device.checkpoint().await.context("checkpoint new device")?;
    rec.last_head_msg_id = device.last_head_msg_id();
    device.close().await.context("close device")?;
    rec.save()?;

    println!("Created TeaGarden block device '{name}'.");
    println!("  capacity : {size_gib} GiB ({capacity_blocks} x 4 KiB blocks)");
    println!("  segments : {segment_mib} MiB (one Telegram document each)");
    println!("  topic    : {topic_id} in group {group_id}");
    println!("  state    : {}", device_dir.display());
    println!();
    println!("Next — expose it and put a real filesystem on it:");
    println!("  teagarden dev serve nbd {name} &");
    println!("  sudo nbd-client -b 4096 127.0.0.1 10809 /dev/nbd0");
    println!("  sudo mkfs.ext4 /dev/nbd0 && sudo mount /dev/nbd0 /mnt");
    Ok(())
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `dev list` — every registered device.
pub async fn list() -> Result<()> {
    let all = DeviceRecord::list_all()?;
    if all.is_empty() {
        println!("No TeaGarden block devices.");
        println!("Create one with: teagarden dev create --name mydev --size-gib 10");
        return Ok(());
    }
    println!("NAME                   CAPACITY    SEGMENT       HEAD MSG  TOPIC");
    for r in all {
        let gib = r.capacity_blocks * BLOCK_SIZE / (1024 * 1024 * 1024);
        println!(
            "{:<20} {:>9}G {:>9}M {:>14}  {}",
            r.name,
            gib,
            r.segment_target / (1024 * 1024),
            r.last_head_msg_id
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            r.telegram_topic_id
        );
    }
    Ok(())
}

/// `dev status` — open the device and report real engine state.
pub async fn status(name: &str, password_file: Option<&str>) -> Result<()> {
    let rec = DeviceRecord::load(name)?;
    let credential = read_credential(password_file)?;
    let (keys, _uuid) = derive_keys(&credential, &rec.salt)?;
    let transport = real_transport(&rec).await?;
    let device = TeaGardenDevice::open(transport, keys, &rec.dir, device_config(&rec))
        .context("open device (wrong credential, or in use by a running `dev serve`?)")?;

    println!("Device '{name}'");
    println!("  capacity blocks : {}", device.capacity_blocks());
    println!("  mapped blocks   : {}", device.mapped_blocks());
    println!("  current epoch   : {}", device.current_epoch());
    println!("  segments        : {}", device.confirmed_segments());
    println!("  cloud watermark : {}", device.cloud_watermark());
    println!(
        "  last head msg   : {}",
        device
            .last_head_msg_id()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "(none yet)".into())
    );
    println!(
        "  telegram topic  : {} (group {})",
        rec.telegram_topic_id, rec.telegram_group_id
    );
    println!("  state dir       : {}", rec.dir.display());
    Ok(())
}

/// `dev serve nbd` — the `cryptsetup open` step: expose the decrypted device.
///
/// Durability lifecycle (`teagarden_nbd::serve_durable`): while serving, a
/// checkpoint (`DeviceHead`) is published once 8 uploaded segments are not yet
/// covered by one, and at least every 60 s while any is (checked every 5 s).
/// On SIGINT / SIGTERM, or when the client disconnects cleanly
/// (`nbd-client -d`), it stops serving, seals and uploads the open segment,
/// drains pending uploads, publishes a final checkpoint and records it in the
/// device registry (where `dev recover` looks). Exit status 0 only if all of
/// that succeeded.
pub async fn serve_nbd(name: &str, bind: &str, password_file: Option<&str>) -> Result<()> {
    let mut rec = DeviceRecord::load(name)?;
    let credential = read_credential(password_file)?;
    println!("Deriving device keys (Argon2id 256 MiB — use a --release build)...");
    let (keys, _uuid) = derive_keys(&credential, &rec.salt)?;
    let transport = real_transport(&rec).await?;
    let device = TeaGardenDevice::open(transport, keys, &rec.dir, device_config(&rec))
        .context("open device (wrong credential, or in use by a running `dev serve`?)")?;

    let head = device.last_head_msg_id();
    let adapter = Arc::new(BlockDeviceAdapter::new(
        device,
        tokio::runtime::Handle::current(),
    ));
    let addr: std::net::SocketAddr = bind.parse().context("--bind must be host:port")?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("bind NBD port")?;

    // Persist the head we opened at, so recovery has a starting point even if the
    // process is killed before the first checkpoint of this session.
    if head.is_some() && head != rec.last_head_msg_id {
        rec.last_head_msg_id = head;
        let _ = rec.save();
    }

    println!("LISTENING {}", listener.local_addr()?);
    println!("Attach it, then put a real filesystem on top:");
    println!(
        "  sudo nbd-client -b 4096 {} {} /dev/nbd0",
        addr.ip(),
        addr.port()
    );
    println!("  sudo mkfs.ext4 /dev/nbd0     # the GUEST filesystem — not teagarden");
    println!(
        "Stop with Ctrl+C (or SIGTERM, or `sudo nbd-client -d /dev/nbd0`): the last segment is \
         uploaded and a final checkpoint published before exit."
    );

    // Every published checkpoint is recorded at once, so `dev recover` (which
    // reads the registry) always starts from the newest one.
    let interrupted = finalize_interrupted_message(name, &rec.dir);
    let record = std::sync::Mutex::new(rec);
    let report = teagarden_nbd::serve_durable(
        adapter,
        "",
        listener,
        shutdown_signal(interrupted),
        teagarden_nbd::CheckpointPolicy::default(),
        |head_msg_id| {
            let mut r = record.lock().unwrap_or_else(|p| p.into_inner());
            r.last_head_msg_id = Some(head_msg_id);
            r.save()
        },
    )
    .await
    .with_context(|| {
        format!(
            "`dev serve nbd {name}` did not shut down cleanly. Writes acknowledged by FLUSH are \
             in the local staging log; run `teagarden dev serve nbd {name}` again (it replays \
             them) and stop it once Telegram is reachable, so they are uploaded"
        )
    })?;
    let why = match report.end {
        teagarden_nbd::ServeEnd::Shutdown => "signal",
        teagarden_nbd::ServeEnd::ClientDisconnected => "client disconnected",
    };
    println!(
        "Stopped ({why}). Every segment is uploaded; final checkpoint {} recorded \
         ({} checkpoint(s) published while serving).",
        report.final_recovery_point, report.periodic_points
    );
    Ok(())
}

/// Resolves on the first SIGINT or SIGTERM, after which `serve_durable`
/// finalizes. A SECOND signal while it is still finalizing ends the process at
/// once with status 1 and `interrupted` on stderr
/// ([`teagarden_nbd::shutdown_signal`]). Installing the handlers also means
/// neither signal kills the process mid-write.
async fn shutdown_signal(interrupted: String) {
    teagarden_nbd::shutdown_signal(interrupted).await;
    println!("\nStopping: uploading the last segment and publishing a checkpoint…");
    println!("(A second Ctrl+C or SIGTERM abandons that upload and exits at once.)");
}

/// What a second signal during finalization prints. States what is true: the
/// staging log (`dir`) keeps every write acknowledged by FLUSH and the next
/// `dev serve nbd` replays it, but Telegram may lack the last segment and the
/// final checkpoint.
fn finalize_interrupted_message(name: &str, dir: &Path) -> String {
    let dir = dir.display();
    format!(
        "\n`dev serve nbd {name}` was stopped a second time while it was still finalizing, \
         and exited at once (status 1).\n\
         Finalization is INCOMPLETE: the last segment may not be uploaded and the final \
         checkpoint was not published, so Telegram does not yet hold everything this device \
         acknowledged.\n\
         Writes already acknowledged by FLUSH are safe in the local staging log under {dir}; \
         writes not yet flushed may be lost, as on any disk.\n\
         Run `teagarden dev serve nbd {name}` again: it replays the staging log. Stop it once \
         Telegram is reachable (press Ctrl+C once and wait) so the segments are uploaded and a \
         final checkpoint is published. Keep {dir} until then: `dev recover` from Telegram \
         alone returns only the device as of the newest published checkpoint."
    )
}

/// `dev gc` — reclaim segments superseded by newer writes.
pub async fn gc(name: &str, password_file: Option<&str>) -> Result<()> {
    let mut rec = DeviceRecord::load(name)?;
    let credential = read_credential(password_file)?;
    let (keys, _uuid) = derive_keys(&credential, &rec.salt)?;
    let transport = real_transport(&rec).await?;
    let mut device = TeaGardenDevice::open(transport, keys, &rec.dir, device_config(&rec))
        .context("open device (wrong credential, or in use by a running `dev serve`?)")?;

    println!("Running GC on '{name}'...");
    let report = device.gc().await.context("gc")?;
    println!("{report:?}");
    println!(
        "NOTE: after GC only the NEWEST head is a viable recovery point — older heads \
         reference segments that have been reclaimed."
    );
    rec.last_head_msg_id = device.last_head_msg_id();
    device.close().await.context("close device")?;
    rec.save()?;
    Ok(())
}

/// `dev resize` — change the logical capacity.
pub async fn resize(name: &str, size_gib: u64, password_file: Option<&str>) -> Result<()> {
    let mut rec = DeviceRecord::load(name)?;
    if size_gib == 0 {
        anyhow::bail!("--size-gib must be at least 1");
    }
    let new_blocks = size_gib * 1024 * 1024 * 1024 / BLOCK_SIZE;
    if new_blocks < rec.capacity_blocks {
        anyhow::bail!(
            "refusing to SHRINK '{name}' ({} -> {size_gib} GiB): the guest filesystem on this \
             device does not know it is being truncated, so shrinking would destroy its data. \
             Shrink the guest filesystem first, then recreate the device.",
            rec.capacity_blocks * BLOCK_SIZE / (1024 * 1024 * 1024)
        );
    }
    let credential = read_credential(password_file)?;
    let (keys, _uuid) = derive_keys(&credential, &rec.salt)?;
    let transport = real_transport(&rec).await?;
    let mut device = TeaGardenDevice::open(transport, keys, &rec.dir, device_config(&rec))
        .context("open device (wrong credential, or in use by a running `dev serve`?)")?;

    device.resize(new_blocks).context("resize")?;
    device
        .checkpoint()
        .await
        .context("checkpoint after resize")?;
    rec.capacity_blocks = new_blocks;
    rec.last_head_msg_id = device.last_head_msg_id();
    device.close().await.context("close device")?;
    rec.save()?;

    println!("Resized '{name}' to {size_gib} GiB ({new_blocks} x 4 KiB blocks).");
    println!("Grow the GUEST filesystem to use the new space, e.g. `sudo resize2fs /dev/nbd0`.");
    Ok(())
}

/// `dev recover` — rebuild local block state from Telegram using its local registry record.
///
/// This is why the registry records `last_head_msg_id`: without it the operator
/// would have to know a raw Telegram message id to recover.
///
/// The device's state directory must be missing or empty (L4): recovering over
/// live local state would destroy staged writes the head does not contain.
pub async fn recover(
    name: &str,
    head_msg_id: Option<i64>,
    password_file: Option<&str>,
) -> Result<()> {
    let mut rec = DeviceRecord::load(name)?;
    let head = head_msg_id.or(rec.last_head_msg_id).unwrap_or(0);
    if head == 0 {
        anyhow::bail!(
            "no head message id known for '{name}' and none supplied — pass --head-msg-id <ID>"
        );
    }
    // Recovery rebuilds superblock/catalog/staging.log from the head and would
    // DESTROY whatever local state the directory holds — including staged
    // writes that never reached Telegram. The engine refuses a non-empty
    // directory; check up front (before the slow key derivation and the
    // network) and say what to do. There is deliberately no in-place override.
    if let Some(entry) = std::fs::read_dir(&rec.dir)
        .ok()
        .and_then(|mut it| it.next())
        .and_then(|e| e.ok())
    {
        anyhow::bail!(
            "refusing to recover '{name}' into {}: the directory is not empty (it holds {:?}).\n\
             Recovery replaces the local device state with the Telegram head and would destroy \
             any staged writes that never uploaded. If the local state is really lost or \
             unwanted, move it aside first:\n  mv {} {}.bak\nthen rerun `teagarden dev recover {name}`.",
            rec.dir.display(),
            entry.file_name(),
            rec.dir.display(),
            rec.dir.display()
        );
    }
    let credential = read_credential(password_file)?;
    let (keys, uuid) = derive_keys(&credential, &rec.salt)?;
    let transport = real_transport(&rec).await?;

    std::fs::create_dir_all(&rec.dir).context("create device dir")?;
    println!("Recovering '{name}' from head message {head}...");
    let mut device = TeaGardenDevice::recover_from_head(
        transport,
        keys,
        uuid,
        &rec.dir,
        head,
        device_config(&rec),
    )
    .await
    .context("recover_from_head")?;

    println!(
        "Recovered: {} segments, epoch {}, {} mapped blocks.",
        device.confirmed_segments(),
        device.current_epoch(),
        device.mapped_blocks()
    );
    rec.last_head_msg_id = device.last_head_msg_id();
    device.close().await.context("close device")?;
    rec.save()?;
    Ok(())
}

/// What `dev delete` needs from Telegram: topic deletion. Opens the user's
/// session bound to the device's storage location on demand (the real client, or
/// a test transport); called at most once, and only when the topic must go.
pub(crate) type ConnectForum<'a> = Box<
    dyn FnOnce(
            ChannelRef,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Arc<dyn ForumAdmin>>> + 'a>,
        > + 'a,
>;

/// How `dev delete` gets its confirmation. There is deliberately no "assume yes"
/// and no "assume no": with nobody to ask, the command refuses.
pub(crate) enum Confirm<'a> {
    /// stdin is not a terminal, so there is no one to ask.
    NoTerminal,
    /// Show this prompt; `true` means the answer was yes.
    Ask(&'a mut dyn FnMut(&str) -> Result<bool>),
}

/// What a finished `dev delete` did, for the caller to report.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeleteOutcome {
    /// The device's forum topic (and everything in it) and its local state are gone.
    TopicDeleted,
    /// Only the local state is gone (`--local-only`); the topic remains.
    LocalOnly { topic_id: i64, group_id: i64 },
}

/// The flags of one `dev delete` run.
pub(crate) struct DeleteArgs<'a> {
    pub name: &'a str,
    pub password_file: Option<&'a str>,
    pub force: bool,
    pub local_only: bool,
}

/// `dev delete` — permanently delete a device: its Telegram topic first, then the
/// local state.
///
/// Modelled on `volume delete`, with the same safety properties:
///   1. the device must be closed: this takes the engine's own directory lock (the
///      one `dev serve`, `dev status`, `dev gc` and `dev resize` hold while the
///      device is open) and refuses while anything else holds it;
///   2. the device credential is REQUIRED and checked against the sealed
///      superblock, so a typo cannot delete someone else's device;
///   3. unless `--force`, the operator confirms, and with no terminal to ask on the
///      command refuses (a declined or unanswerable prompt is an error, never exit 0);
///   4. the forum topic — every segment, head and checkpoint the device posted — is
///      deleted BEFORE the local state, because the registry is the only record of
///      where the topic is. If that fails the local state is left intact and the
///      command can be run again;
///   5. only then the state directory is overwritten and removed (the helper
///      `volume delete` uses: it never follows symlinks or opens special files),
///      and the registry entry last.
///
/// `--local-only` removes only the local state, for when the topic is already gone
/// or unreachable and the operator accepts orphaning it; it never contacts Telegram.
pub async fn delete(
    name: &str,
    password_file: Option<&str>,
    force: bool,
    local_only: bool,
) -> Result<()> {
    use std::io::IsTerminal as _;
    let mut ask = |prompt: &str| -> Result<bool> {
        use std::io::Write as _;
        print!("{prompt}");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().eq_ignore_ascii_case("y"))
    };
    let confirm = if std::io::stdin().is_terminal() {
        Confirm::Ask(&mut ask)
    } else {
        Confirm::NoTerminal
    };
    let outcome = delete_in(
        &registry_dir(),
        &DeleteArgs {
            name,
            password_file,
            force,
            local_only,
        },
        &Argon2Params::default(),
        confirm,
        Box::new(|channel_ref| {
            Box::pin(async move {
                let client = real_transport_for(channel_ref).await?;
                Ok(client as Arc<dyn ForumAdmin>)
            })
        }),
    )
    .await?;
    match outcome {
        DeleteOutcome::TopicDeleted => println!("Device '{name}' deleted."),
        DeleteOutcome::LocalOnly { topic_id, group_id } => {
            println!("Device '{name}' deleted locally.");
            println!(
                "The Telegram topic was NOT deleted and remains: topic {topic_id} in group \
                 {group_id}, with every segment, head and checkpoint the device posted. \
                 TeaGarden can no longer delete it; remove it by hand in Telegram."
            );
        }
    }
    Ok(())
}

/// [`delete`] against an explicit registry directory, Argon2 cost and Telegram
/// connector.
pub(crate) async fn delete_in(
    registry: &Path,
    args: &DeleteArgs<'_>,
    kdf: &Argon2Params,
    confirm: Confirm<'_>,
    connect: ConnectForum<'_>,
) -> Result<DeleteOutcome> {
    let DeleteArgs {
        name,
        password_file,
        force,
        local_only,
    } = *args;
    // The name becomes a file name in the registry: never let it leave it.
    if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
        anyhow::bail!("'{name}' is not a device name. List them with `teagarden dev list`.");
    }
    let rec = DeviceRecord::load_in(registry, name)?;
    let (group_id, topic_id) = (rec.telegram_group_id, rec.telegram_topic_id);

    // No one to ask means no deletion: refuse, rather than read the missing
    // answer as "no" and exit 0. Checked first, before the slow key derivation.
    let asker = match confirm {
        _ if force => None,
        Confirm::Ask(ask) => Some(ask),
        Confirm::NoTerminal => anyhow::bail!(
            "refusing to delete device '{name}' without confirmation: stdin is not a terminal, \
             so there is no one to ask. Pass --force to delete without asking; nothing was \
             deleted."
        ),
    };

    // Single-writer backstop: the SAME exclusive lock the engine takes for the whole
    // life of an open device, held until the local state is gone. A running
    // `dev serve nbd` (or `dev status`, `gc`, `resize`) holds it, and deleting a
    // device under one loses its writes.
    // The removal helper never follows a symlink standing in for the directory, and
    // that refusal must come now, not after the topic is gone.
    if std::fs::symlink_metadata(&rec.dir).is_ok_and(|m| m.file_type().is_symlink()) {
        anyhow::bail!(
            "refusing to delete device '{name}': its state directory {} is a symlink, and \
             deleting follows no symlinks. Point the registry entry at the real directory and \
             retry; nothing was deleted.",
            rec.dir.display()
        );
    }
    if !rec.dir.is_dir() {
        anyhow::bail!(
            "device '{name}' has no state directory at {}, so its credential cannot be \
             checked and delete cannot prove you own it. Rebuild it from Telegram with \
             `teagarden dev recover {name}`, then delete; nothing was deleted.",
            rec.dir.display()
        );
    }
    let guard = DeviceDirGuard::acquire(&rec.dir).map_err(|e| {
        anyhow::anyhow!(
            "refusing to delete device '{name}': {e}. Stop the other command and retry; \
             nothing was deleted."
        )
    })?;

    // Require the credential, and check it against the sealed superblock, so a typo
    // cannot delete someone else's device. This opens nothing and contacts no one.
    let credential = read_credential(password_file)?;
    let (keys, _uuid) = derive_keys_with(&credential, &rec.salt, kdf)?;
    guard.verify_keys(&keys).map_err(|e| {
        anyhow::anyhow!(
            "wrong device credential for '{name}', or its state in {} is damaged ({e}); \
             nothing was deleted.",
            rec.dir.display()
        )
    })?;

    // The state directory is wiped wholesale, and `dev create --dir` may have named a
    // directory that already held other files: refuse before anything is deleted.
    if let Some(foreign) = foreign_entry(&rec.dir)? {
        anyhow::bail!(
            "refusing to delete device '{name}': its state directory {} holds {foreign:?}, which \
             the device engine did not write, and deleting the directory would destroy it. Move \
             it away and retry; nothing was deleted.",
            rec.dir.display()
        );
    }
    // A record with no dedicated topic has nothing to delete remotely, and General
    // (topic 1) is shared with everything else in the group: never target it.
    if !local_only && (group_id == 0 || topic_id <= 1) {
        anyhow::bail!(
            "device '{name}' records no dedicated Telegram topic (group {group_id}, topic \
             {topic_id}), so there is nothing to delete there; pass --local-only to remove only \
             the local state. Nothing was deleted."
        );
    }

    // ── Confirmation, now that we can state the REAL scope ─────────────────────
    if let Some(ask) = asker {
        let prompt = if local_only {
            format!(
                "WARNING: --local-only will destroy local device '{name}' and ABANDON \
                 everything it stored on Telegram (topic {topic_id} in group {group_id}, with \
                 every segment, head and checkpoint); it stays there, undeletable by teagarden \
                 without this device's local state. Continue? [y/N] "
            )
        } else {
            format!(
                "WARNING: This will permanently delete the device's Telegram topic {topic_id} \
                 in group {group_id}, with every segment, head and checkpoint in it, AND \
                 destroy local device '{name}'. This cannot be undone. Continue? [y/N] "
            )
        };
        if !ask(&prompt)? {
            anyhow::bail!("Cancelled. Nothing was deleted.");
        }
    }

    // ── (1) The topic BEFORE the local state ───────────────────────────────────
    // The registry is the only record of where this device's topic lives. Deleting
    // it first would make the topic unreachable and so permanently undeletable.
    if !local_only {
        let client = connect(ChannelRef {
            id: group_id,
            access_hash: rec.telegram_access_hash,
            topic_id,
        })
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "{e}\n\
                 Deleting a device removes its data from Telegram, which needs a Telegram \
                 login.\n\
                 Run `teagarden auth login`, or pass --local-only to destroy ONLY local \
                 state and knowingly leave the device's data on Telegram. The local device \
                 has been left INTACT."
            )
        })?;
        client
            .delete_topic(group_id, rec.telegram_access_hash, topic_id)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "the device's Telegram topic could not be deleted ({e}). The local device \
                     has been left INTACT so the deletion can be retried: rerun this command \
                     once the problem is fixed. (Use --local-only only if you accept leaving \
                     the device's data on Telegram.)"
                )
            })?;
        println!(
            "Deleted the device's Telegram topic {topic_id} and everything in it (segments, \
             heads and checkpoints)."
        );
    }

    // ── (2) Now the local state, under the lock this command holds ─────────────
    remove_local_state(registry, &rec).with_context(|| {
        if local_only {
            format!(
                "removing the local state of '{name}' failed part-way; remove {} and the \
                 registry entry by hand",
                rec.dir.display()
            )
        } else {
            format!(
                "the Telegram topic is deleted, but removing the local state of '{name}' \
                 failed part-way; remove {} and the registry entry by hand",
                rec.dir.display()
            )
        }
    })?;
    drop(guard);

    Ok(if local_only {
        DeleteOutcome::LocalOnly { topic_id, group_id }
    } else {
        DeleteOutcome::TopicDeleted
    })
}

/// Files the device engine writes into its state directory (or leaves there
/// mid-operation: `*.tmp` from an atomic write, the compaction scratch file, the
/// recovery marker). Matched as a name, or a name followed by `.`.
const ENGINE_FILES: [&str; 4] = [
    "superblock",
    "catalog",
    "staging.log",
    "recovery.incomplete",
];

/// The first entry of `dir` the engine did not write, if any.
fn foreign_entry(dir: &Path) -> Result<Option<std::ffi::OsString>> {
    for entry in std::fs::read_dir(dir).context("read the device state directory")? {
        let name = entry?.file_name();
        let ours = name.to_str().is_some_and(|n| {
            ENGINE_FILES
                .iter()
                .any(|f| n == *f || n.strip_prefix(f).is_some_and(|r| r.starts_with('.')))
        });
        if !ours {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// Remove a device's local state: the state directory (overwritten and removed the
/// way `volume delete` removes a volume), the registry subdirectory the default
/// layout puts it in, and the registry entry LAST — it is the record of where the
/// device is, so it outlives every other step.
fn remove_local_state(registry: &Path, rec: &DeviceRecord) -> Result<()> {
    teagarden_core::volume::manager::delete_dir_overwriting(&rec.dir).map_err(utils::core_err)?;
    if rec.dir == registry.join(&rec.name).join("data") {
        // `<registry>/<name>/` is ours only while it holds nothing else.
        let _ = std::fs::remove_dir(registry.join(&rec.name));
    }
    std::fs::remove_file(registry.join(format!("{}.json", rec.name)))
        .context("remove the device registry entry")
}

/// Exposed so `dev` can reuse the volume module's registry-path helper in tests.
#[allow(dead_code)]
pub(crate) fn registry_dir_for_test() -> PathBuf {
    registry_dir()
}

#[allow(dead_code)]
fn _assert_paths(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, pad: usize) -> DeviceRecord {
        DeviceRecord {
            // The name is the file stem, so keep it fixed and vary another field's size.
            name: name.into(),
            dir: PathBuf::from(format!("/dev-data/{}", "d".repeat(pad))),
            capacity_blocks: 1024,
            segment_target: 1 << 20,
            salt: [7; 32],
            telegram_group_id: 1,
            telegram_access_hash: 2,
            telegram_topic_id: 3,
            last_head_msg_id: Some(4),
            created_at: 5,
        }
    }

    /// Eight writers hammer `save_in` while reading back. With a fixed temp name
    /// they share one inode, so a torn record can be renamed into place (losing the
    /// head id that disaster recovery needs) and the loser's rename fails.
    #[test]
    fn concurrent_device_record_saves_never_tear_or_fail() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let tmp = tempfile::TempDir::new().unwrap();
        let reg = Arc::new(tmp.path().join("devices"));
        let errors = Arc::new(AtomicUsize::new(0));
        let first_error = Arc::new(Mutex::new(None::<String>));
        let threads: Vec<_> = (0..8usize)
            .map(|t| {
                let (reg, errors, first_error) = (reg.clone(), errors.clone(), first_error.clone());
                std::thread::spawn(move || {
                    let rec = record("dev0", t * 97);
                    for _ in 0..200 {
                        let r = rec
                            .save_in(&reg)
                            .map_err(|e| format!("{e:#}"))
                            .and_then(|()| {
                                let raw = std::fs::read(reg.join("dev0.json"))
                                    .map_err(|e| e.to_string())?;
                                serde_json::from_slice::<DeviceRecord>(&raw)
                                    .map(|_| ())
                                    .map_err(|e| format!("torn device record: {e}"))
                            });
                        if let Err(e) = r {
                            errors.fetch_add(1, Ordering::Relaxed);
                            first_error.lock().unwrap().get_or_insert(e);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            errors.load(Ordering::Relaxed),
            0,
            "concurrent saves must never fail or tear; first error: {:?}",
            first_error.lock().unwrap()
        );
        let names: Vec<_> = std::fs::read_dir(&*reg)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("dev0.json")]);
        let mode = std::fs::metadata(reg.join("dev0.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a device record must be written 0600");
    }

    /// The abort message tells the operator what is and is not safe, and what to
    /// run next; it must not point at `dev recover`, which refuses a non-empty
    /// state directory.
    #[test]
    fn a_second_signal_message_says_what_is_safe_and_what_to_run() {
        let m = finalize_interrupted_message("vault", Path::new("/var/lib/dev/vault"));
        for needle in [
            "INCOMPLETE",
            "/var/lib/dev/vault",
            "staging log",
            "acknowledged by FLUSH",
            "`teagarden dev serve nbd vault` again",
            "final checkpoint",
        ] {
            assert!(m.contains(needle), "missing {needle:?} in: {m}");
        }
        assert!(!m.contains("run `teagarden dev recover"), "{m}");
    }

    // ── dev delete ──────────────────────────────────────────────────────────

    use teagarden_telegram::mock::{ForumCall, MockTransport};

    const GROUP: i64 = 999_000_000;
    const HASH: i64 = 1_234_567_890;
    const TOPIC: i64 = 77;
    const CRED: &str = "dev-delete-test-credential";

    /// Argon2 cheap enough for a test; the product passes `Argon2Params::default()`.
    fn fast_kdf() -> Argon2Params {
        Argon2Params {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        }
    }

    /// A registered device in the default layout (`<registry>/<name>/data`), created
    /// by the real engine against a mock transport, with its credential file.
    struct Fixture {
        _tmp: tempfile::TempDir,
        registry: PathBuf,
        rec: DeviceRecord,
        cred_file: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::TempDir::new().unwrap();
            let registry = tmp.path().join("registry");
            let state = registry.join("vault").join("data");
            std::fs::create_dir_all(&state).unwrap();
            let salt = [3u8; 32];
            let (keys, uuid) = derive_keys_with(CRED, &salt, &fast_kdf()).unwrap();
            let rec = DeviceRecord {
                name: "vault".into(),
                dir: state.clone(),
                capacity_blocks: 256,
                segment_target: 1 << 20,
                salt,
                telegram_group_id: GROUP,
                telegram_access_hash: HASH,
                telegram_topic_id: TOPIC,
                last_head_msg_id: None,
                created_at: 1,
            };
            drop(
                TeaGardenDevice::create(
                    Arc::new(MockTransport::new()),
                    keys,
                    uuid,
                    256,
                    &state,
                    device_config(&rec),
                )
                .unwrap(),
            );
            rec.save_in(&registry).unwrap();
            let cred_file = tmp.path().join("cred.txt");
            std::fs::write(&cred_file, CRED).unwrap();
            Self {
                _tmp: tmp,
                registry,
                rec,
                cred_file,
            }
        }

        fn cred(&self) -> &str {
            self.cred_file.to_str().unwrap()
        }

        async fn run(
            &self,
            args: &DeleteArgs<'_>,
            confirm: Confirm<'_>,
            connect: ConnectForum<'_>,
        ) -> Result<DeleteOutcome> {
            delete_in(&self.registry, args, &fast_kdf(), confirm, connect).await
        }

        fn registered(&self) -> Vec<String> {
            DeviceRecord::list_in(&self.registry)
                .unwrap()
                .into_iter()
                .map(|r| r.name)
                .collect()
        }

        /// Everything is still there: the registry entry and the engine's files.
        fn assert_intact(&self) {
            assert_eq!(self.registered(), vec!["vault".to_string()]);
            for f in ["superblock", "staging.log"] {
                let p = self.rec.dir.join(f);
                assert!(p.exists(), "{} must still exist", p.display());
            }
        }
    }

    fn args<'a>(f: &'a Fixture, force: bool, local_only: bool) -> DeleteArgs<'a> {
        DeleteArgs {
            name: "vault",
            password_file: Some(f.cred()),
            force,
            local_only,
        }
    }

    fn connect_mock(m: Arc<MockTransport>) -> ConnectForum<'static> {
        Box::new(move |_channel| Box::pin(async move { Ok(m as Arc<dyn ForumAdmin>) }))
    }

    fn connect_never() -> ConnectForum<'static> {
        Box::new(|_channel| Box::pin(async { panic!("Telegram must not be contacted") }))
    }

    fn delete_call() -> ForumCall {
        ForumCall::DeleteTopic {
            group_id: GROUP,
            access_hash: HASH,
            topic_id: TOPIC,
        }
    }

    /// create -> delete: the topic is deleted on Telegram, then the registry entry
    /// and the whole state directory are gone.
    #[tokio::test]
    async fn delete_removes_the_topic_the_registry_entry_and_the_state_dir() {
        let f = Fixture::new();
        let mock = Arc::new(MockTransport::new());
        let outcome = f
            .run(
                &args(&f, true, false),
                Confirm::NoTerminal,
                connect_mock(mock.clone()),
            )
            .await
            .unwrap();
        assert_eq!(outcome, DeleteOutcome::TopicDeleted);
        assert_eq!(mock.forum_calls(), vec![delete_call()]);
        assert!(
            f.registered().is_empty(),
            "the registry must not list the device"
        );
        assert!(!f.rec.dir.exists(), "the state dir must be gone");
        assert!(
            !f.registry.join("vault").exists(),
            "the device's registry subdirectory must be gone"
        );
    }

    /// A device that has really been USED (written, checkpointed, garbage-collected,
    /// closed) is deleted too: the engine's own files must all be ones delete accepts,
    /// not just the ones `create` leaves behind.
    #[tokio::test]
    async fn delete_removes_a_device_that_has_been_used() {
        let f = Fixture::new();
        let (keys, _uuid) = derive_keys_with(CRED, &f.rec.salt, &fast_kdf()).unwrap();
        let mut dev = TeaGardenDevice::open(
            Arc::new(MockTransport::new()),
            keys,
            &f.rec.dir,
            device_config(&f.rec),
        )
        .unwrap();
        dev.write_at(0, &vec![0xA5u8; 4 * BLOCK_SIZE as usize])
            .await
            .unwrap();
        dev.checkpoint().await.unwrap();
        dev.gc().await.unwrap();
        dev.close().await.unwrap();
        drop(dev);
        assert!(f.rec.dir.join("catalog").exists(), "the device was used");

        let mock = Arc::new(MockTransport::new());
        f.run(
            &args(&f, true, false),
            Confirm::NoTerminal,
            connect_mock(mock.clone()),
        )
        .await
        .unwrap();
        assert_eq!(mock.forum_calls(), vec![delete_call()]);
        assert!(f.registered().is_empty());
        assert!(!f.rec.dir.exists());
    }

    /// A typo (wrong credential) cannot delete the device: nothing is touched, and
    /// Telegram is never contacted.
    #[tokio::test]
    async fn delete_with_the_wrong_credential_deletes_nothing() {
        let f = Fixture::new();
        let wrong = f._tmp.path().join("wrong.txt");
        std::fs::write(&wrong, "not-the-credential").unwrap();
        let err = f
            .run(
                &DeleteArgs {
                    password_file: Some(wrong.to_str().unwrap()),
                    ..args(&f, true, false)
                },
                Confirm::NoTerminal,
                connect_never(),
            )
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wrong device credential"), "{msg}");
        assert!(msg.contains("nothing was deleted"), "{msg}");
        f.assert_intact();
    }

    /// While the device is open (here: held by a live engine, as `dev serve nbd`
    /// holds it) delete refuses before any Telegram call or local deletion, and
    /// works once the holder lets go.
    #[tokio::test]
    async fn delete_refuses_while_the_device_is_open() {
        let f = Fixture::new();
        let (keys, _uuid) = derive_keys_with(CRED, &f.rec.salt, &fast_kdf()).unwrap();
        let open = TeaGardenDevice::open(
            Arc::new(MockTransport::new()),
            keys,
            &f.rec.dir,
            device_config(&f.rec),
        )
        .unwrap();
        for local_only in [false, true] {
            let err = f
                .run(
                    &args(&f, true, local_only),
                    Confirm::NoTerminal,
                    connect_never(),
                )
                .await
                .unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("in use by another opener"), "{msg}");
            assert!(msg.contains("nothing was deleted"), "{msg}");
            f.assert_intact();
        }
        drop(open);
        let mock = Arc::new(MockTransport::new());
        f.run(
            &args(&f, true, false),
            Confirm::NoTerminal,
            connect_mock(mock.clone()),
        )
        .await
        .expect("delete proceeds once the device is closed");
        assert_eq!(mock.forum_calls(), vec![delete_call()]);
        assert!(f.registered().is_empty());
    }

    /// If the topic cannot be deleted the local state (the only record of where the
    /// topic is) stays intact, the error says so, and a rerun succeeds.
    #[tokio::test]
    async fn delete_keeps_local_state_when_the_topic_cannot_be_deleted() {
        let f = Fixture::new();
        let mock = Arc::new(MockTransport::new());
        mock.set_fail_forum(true);
        let err = f
            .run(
                &args(&f, true, false),
                Confirm::NoTerminal,
                connect_mock(mock.clone()),
            )
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("could not be deleted"), "{msg}");
        assert!(msg.contains("INTACT"), "{msg}");
        assert!(msg.contains("rerun"), "{msg}");
        f.assert_intact();

        mock.set_fail_forum(false);
        f.run(
            &args(&f, true, false),
            Confirm::NoTerminal,
            connect_mock(mock.clone()),
        )
        .await
        .expect("the rerun must succeed");
        assert_eq!(mock.forum_calls(), vec![delete_call(), delete_call()]);
        assert!(f.registered().is_empty());
        assert!(!f.rec.dir.exists());
    }

    /// `--local-only` never contacts Telegram, removes the local state, and reports
    /// the topic that remains (its id and group).
    #[tokio::test]
    async fn delete_local_only_removes_local_state_and_reports_the_topic() {
        let f = Fixture::new();
        let outcome = f
            .run(&args(&f, true, true), Confirm::NoTerminal, connect_never())
            .await
            .unwrap();
        assert_eq!(
            outcome,
            DeleteOutcome::LocalOnly {
                topic_id: TOPIC,
                group_id: GROUP
            }
        );
        assert!(f.registered().is_empty());
        assert!(!f.rec.dir.exists());
    }

    /// No `--force` and no terminal: refused (an error, so a non-zero exit), nothing
    /// deleted, Telegram never contacted.
    #[tokio::test]
    async fn delete_without_force_and_without_a_terminal_refuses() {
        let f = Fixture::new();
        let err = f
            .run(
                &args(&f, false, false),
                Confirm::NoTerminal,
                connect_never(),
            )
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("--force"), "{msg}");
        assert!(msg.contains("terminal"), "{msg}");
        assert!(msg.contains("nothing was deleted"), "{msg}");
        f.assert_intact();
    }

    /// At a terminal the operator is asked, with the real scope; "no" is an error
    /// (non-zero exit) that deletes nothing, and "yes" deletes.
    #[tokio::test]
    async fn delete_asks_and_a_no_is_an_error_that_deletes_nothing() {
        let f = Fixture::new();
        let mut prompts = Vec::new();
        let mut no = |p: &str| -> Result<bool> {
            prompts.push(p.to_string());
            Ok(false)
        };
        let err = f
            .run(
                &args(&f, false, false),
                Confirm::Ask(&mut no),
                connect_never(),
            )
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("Nothing was deleted"),
            "{err:#}"
        );
        assert_eq!(prompts.len(), 1);
        assert!(prompts[0].contains("'vault'"), "{}", prompts[0]);
        assert!(
            prompts[0].contains(&format!("topic {TOPIC}")),
            "{}",
            prompts[0]
        );
        f.assert_intact();

        let mock = Arc::new(MockTransport::new());
        let mut yes = |_: &str| -> Result<bool> { Ok(true) };
        f.run(
            &args(&f, false, false),
            Confirm::Ask(&mut yes),
            connect_mock(mock.clone()),
        )
        .await
        .unwrap();
        assert_eq!(mock.forum_calls(), vec![delete_call()]);
        assert!(f.registered().is_empty());
    }

    /// `dev create --dir` may point at a directory that holds other things. Delete
    /// wipes the state directory, so it refuses one with files the engine did not
    /// write, and deletes nothing (not even the Telegram topic).
    #[tokio::test]
    async fn delete_refuses_a_state_dir_holding_foreign_files() {
        let f = Fixture::new();
        let foreign = f.rec.dir.join("holiday-photos.tar");
        std::fs::write(&foreign, b"not ours").unwrap();
        let err = f
            .run(&args(&f, true, false), Confirm::NoTerminal, connect_never())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("holiday-photos.tar"), "{msg}");
        assert!(msg.contains("nothing was deleted"), "{msg}");
        assert_eq!(std::fs::read(&foreign).unwrap(), b"not ours");
        f.assert_intact();
    }

    /// With the state directory gone there is nothing to check the credential
    /// against, so delete cannot prove ownership: it says so, and what to do, and
    /// deletes nothing (it must not blame a "running command").
    #[tokio::test]
    async fn delete_with_a_missing_state_dir_says_so_and_deletes_nothing() {
        let f = Fixture::new();
        std::fs::remove_dir_all(&f.rec.dir).unwrap();
        let err = f
            .run(&args(&f, true, false), Confirm::NoTerminal, connect_never())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("state directory"), "{msg}");
        assert!(msg.contains("dev recover vault"), "{msg}");
        assert!(msg.contains("nothing was deleted"), "{msg}");
        assert!(!msg.contains("Stop the other command"), "{msg}");
        assert_eq!(f.registered(), vec!["vault".to_string()]);
    }

    /// The removal helper refuses a symlink standing in for the state directory;
    /// that must be found BEFORE the Telegram topic is deleted, not after it.
    #[cfg(unix)]
    #[tokio::test]
    async fn delete_refuses_a_symlinked_state_dir_before_touching_telegram() {
        let f = Fixture::new();
        let real = f._tmp.path().join("real-state");
        std::fs::rename(&f.rec.dir, &real).unwrap();
        std::os::unix::fs::symlink(&real, &f.rec.dir).unwrap();
        let err = f
            .run(&args(&f, true, false), Confirm::NoTerminal, connect_never())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("symlink"), "{msg}");
        assert!(msg.contains("nothing was deleted"), "{msg}");
        assert!(real.join("superblock").exists());
        assert_eq!(f.registered(), vec!["vault".to_string()]);
    }

    /// A record without a dedicated topic (General is topic 1) must never reach the
    /// Telegram delete: refused unless `--local-only`.
    #[tokio::test]
    async fn delete_refuses_a_device_with_no_dedicated_topic() {
        let mut f = Fixture::new();
        f.rec.telegram_topic_id = 1;
        f.rec.save_in(&f.registry).unwrap();
        let err = f
            .run(&args(&f, true, false), Confirm::NoTerminal, connect_never())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("--local-only"), "{err:#}");
        f.assert_intact();
    }
}
