//! NBD (Network Block Device) server for TeaGarden.
//!
//! Serves a [`teagarden_blockdev::BlockDevice`] over the NBD "newstyle" fixed
//! protocol so a Linux host can `nbd-client` it into a `/dev/nbdX` and `mkfs` +
//! mount any filesystem on top. It is generic over the seam, so the same server
//! exports the in-memory test device, the `teagarden-dev` encrypted Telegram-backed
//! device (via its `BlockDeviceAdapter`), or any other back-end.
//!
//! Scope: the newstyle handshake with option haggling (`NBD_OPT_GO` / `NBD_OPT_INFO`
//! / `NBD_OPT_EXPORT_NAME` / `NBD_OPT_ABORT`), and the transmission phase with
//! simple replies for `READ` / `WRITE` / `FLUSH` / `TRIM` / `DISCONNECT`. Requests
//! must be block-aligned (the server advertises the logical block size via
//! `NBD_INFO_BLOCK_SIZE`); an unaligned or out-of-range request is rejected with
//! `EINVAL` rather than mishandled. Structured replies and TLS are not implemented.
//!
//! Every `BlockDevice` call runs on `spawn_blocking` so a slow back-end (a cold
//! Telegram fetch) never stalls the async runtime.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

mod durable;
mod shutdown;
pub use durable::{serve_durable, CheckpointPolicy, ServeEnd, ServeReport};
pub use shutdown::shutdown_signal;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use teagarden_blockdev::{BlockDevice, LOGICAL_BLOCK_SIZE};

// ── Handshake constants ─────────────────────────────────────────────────────
const NBDMAGIC: u64 = 0x4e42_444d_4147_4943; // "NBDMAGIC"
const IHAVEOPT: u64 = 0x4948_4156_454f_5054; // "IHAVEOPT"
const NBD_REP_MAGIC: u64 = 0x0003_e889_0455_65a9;

const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;
const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1 << 0;
const NBD_FLAG_C_NO_ZEROES: u32 = 1 << 1;

// Options (client → server)
const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_OPT_ABORT: u32 = 2;
const NBD_OPT_INFO: u32 = 6;
const NBD_OPT_GO: u32 = 7;

// Option replies (server → client)
const NBD_REP_ACK: u32 = 1;
const NBD_REP_INFO: u32 = 3;
const NBD_REP_FLAG_ERROR: u32 = 1 << 31;
const NBD_REP_ERR_UNSUP: u32 = NBD_REP_FLAG_ERROR | 1;
const NBD_REP_ERR_INVALID: u32 = NBD_REP_FLAG_ERROR | 3;

// Info types
const NBD_INFO_EXPORT: u16 = 0;
const NBD_INFO_BLOCK_SIZE: u16 = 3;

// ── Transmission constants ──────────────────────────────────────────────────
const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;

const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;
const NBD_CMD_TRIM: u16 = 4;

// Transmission flags (server → client, in the export info)
const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
const NBD_FLAG_SEND_TRIM: u16 = 1 << 5;

const EINVAL: u32 = 22;
const EIO: u32 = 5;

/// Maximum byte length of a single READ/WRITE/TRIM request. `length` is a
/// client-controlled `u32`; this bounds any per-request allocation AND is the
/// value advertised to the client as the maximum block size (`NBD_INFO_BLOCK_SIZE`),
/// so what the server accepts equals what it advertised.
const MAX_REQUEST_LEN: u64 = 32 * 1024 * 1024;

/// Maximum byte length of a handshake OPTION payload. Options carry only an export
/// name + a short info-request list, so this bounds a pre-auth allocation DoS.
const MAX_OPTION_LEN: usize = 4096;

/// An NBD server exporting a single [`BlockDevice`].
pub struct NbdServer<D: BlockDevice> {
    device: Arc<D>,
    export_name: String,
}

impl<D: BlockDevice> NbdServer<D> {
    /// Create a server exporting `device` under `export_name` (the name a client
    /// selects with `NBD_OPT_GO`/`EXPORT_NAME`; an empty client name matches the
    /// default export).
    pub fn new(device: Arc<D>, export_name: impl Into<String>) -> Self {
        Self {
            device,
            export_name: export_name.into(),
        }
    }

    /// Bind `addr` and accept connections indefinitely.
    pub async fn run(&self, addr: SocketAddr) -> anyhow::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!(%addr, export = %self.export_name, "NBD server listening");
        self.serve_with_listener(listener).await
    }

    /// Accept on a pre-bound listener (tests bind to an ephemeral port).
    pub async fn serve_with_listener(&self, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let dev = Arc::clone(&self.device);
            let export = self.export_name.clone();
            let sessions = Arc::new(AtomicUsize::new(0));
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, dev, export, sessions).await {
                    debug!(%peer, "NBD connection closed: {e:#}");
                }
            });
        }
    }
}

/// Server-visible export info, computed once per connection.
struct Export {
    size: u64,
    transmission_flags: u16,
}

fn export_info<D: BlockDevice>(dev: &D) -> Export {
    Export {
        size: dev.capacity(),
        transmission_flags: NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_TRIM,
    }
}

/// Serve one connection. Returns `Ok(true)` when it ended with a clean
/// `NBD_CMD_DISC`, `Ok(false)` for any other orderly end (EOF, `NBD_OPT_ABORT`).
/// `sessions` counts connections currently in the transmission phase (the ones
/// that can issue I/O).
async fn handle_connection<D: BlockDevice>(
    mut stream: TcpStream,
    device: Arc<D>,
    export_name: String,
    sessions: Arc<AtomicUsize>,
) -> anyhow::Result<bool> {
    stream.set_nodelay(true).ok();

    // ── Newstyle handshake ──────────────────────────────────────────────────
    stream.write_u64(NBDMAGIC).await?;
    stream.write_u64(IHAVEOPT).await?;
    let handshake_flags = NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES;
    stream.write_u16(handshake_flags).await?;
    stream.flush().await?;

    let client_flags = stream.read_u32().await?;
    if client_flags & NBD_FLAG_C_FIXED_NEWSTYLE == 0 {
        anyhow::bail!("client did not set fixed-newstyle flag");
    }
    let no_zeroes = client_flags & NBD_FLAG_C_NO_ZEROES != 0;

    let export = export_info(&*device);

    // ── Option haggling ───────────────────────────────────────────────────────
    // Loops until a GO/EXPORT_NAME transitions to transmission, or ABORT/EOF ends it.
    loop {
        let magic = stream.read_u64().await?;
        if magic != IHAVEOPT {
            anyhow::bail!("bad option magic {magic:#x}");
        }
        let option = stream.read_u32().await?;
        let len = stream.read_u32().await? as usize;
        // Cap the (client-controlled) option length BEFORE allocating — options are
        // small (export names + info-request lists). An oversized option is a
        // pre-auth memory-DoS attempt; drop the connection rather than allocate it.
        if len > MAX_OPTION_LEN {
            anyhow::bail!("oversized NBD option length {len}");
        }
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;

        match option {
            NBD_OPT_EXPORT_NAME => {
                // Legacy: reply is raw (no reply header): size + flags + optional zeros.
                let name = String::from_utf8_lossy(&data);
                if !name_matches(&name, &export_name) {
                    // No error channel in EXPORT_NAME — closing is the only signal.
                    anyhow::bail!("unknown export {name:?}");
                }
                stream.write_u64(export.size).await?;
                stream.write_u16(export.transmission_flags).await?;
                if !no_zeroes {
                    stream.write_all(&[0u8; 124]).await?;
                }
                stream.flush().await?;
                return serve_transmission(stream, device, &export, &sessions).await;
            }
            NBD_OPT_INFO | NBD_OPT_GO => {
                let Some(name) = parse_go_name(&data) else {
                    send_opt_reply(&mut stream, option, NBD_REP_ERR_INVALID, &[]).await?;
                    continue;
                };
                if !name_matches(&name, &export_name) {
                    send_opt_reply(&mut stream, option, NBD_REP_ERR_INVALID, &[]).await?;
                    continue;
                }
                // NBD_INFO_EXPORT: size + transmission flags.
                let mut info = Vec::with_capacity(12);
                info.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
                info.extend_from_slice(&export.size.to_be_bytes());
                info.extend_from_slice(&export.transmission_flags.to_be_bytes());
                send_opt_reply(&mut stream, option, NBD_REP_INFO, &info).await?;
                // NBD_INFO_BLOCK_SIZE: min / preferred / max — pins block alignment.
                let bs = LOGICAL_BLOCK_SIZE as u32;
                let mut bsz = Vec::with_capacity(14);
                bsz.extend_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
                bsz.extend_from_slice(&bs.to_be_bytes()); // minimum
                bsz.extend_from_slice(&bs.to_be_bytes()); // preferred
                bsz.extend_from_slice(&(MAX_REQUEST_LEN as u32).to_be_bytes()); // maximum (== enforced)
                send_opt_reply(&mut stream, option, NBD_REP_INFO, &bsz).await?;
                send_opt_reply(&mut stream, option, NBD_REP_ACK, &[]).await?;
                if option == NBD_OPT_GO {
                    return serve_transmission(stream, device, &export, &sessions).await;
                }
                // NBD_OPT_INFO stays in negotiation.
            }
            NBD_OPT_ABORT => {
                send_opt_reply(&mut stream, option, NBD_REP_ACK, &[]).await?;
                stream.flush().await?;
                return Ok(false);
            }
            _ => {
                send_opt_reply(&mut stream, option, NBD_REP_ERR_UNSUP, &[]).await?;
            }
        }
    }
}

fn name_matches(client: &str, export: &str) -> bool {
    // An empty client name selects the default export (NBD convention).
    client.is_empty() || client == export
}

/// `NBD_OPT_GO`/`INFO` data: `[u32 name_len][name][u16 n_info][info requests...]`.
fn parse_go_name(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    let name_len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let end = 4usize.checked_add(name_len)?;
    if end > data.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&data[4..end]).into_owned())
}

async fn send_opt_reply(
    stream: &mut TcpStream,
    option: u32,
    reply_type: u32,
    data: &[u8],
) -> io::Result<()> {
    stream.write_u64(NBD_REP_MAGIC).await?;
    stream.write_u32(option).await?;
    stream.write_u32(reply_type).await?;
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Run the transmission phase, then FLUSH on ANY connection end — clean `DISC`,
/// abrupt EOF, or a protocol error — so a detach never leaves acked-but-unsynced
/// writes only in the page cache (the flush is centralized here so no exit shape
/// can skip it). Finalizing OFFSITE durability (`BlockDevice::shutdown`) remains
/// the server owner's job on export teardown.
async fn serve_transmission<D: BlockDevice>(
    mut stream: TcpStream,
    device: Arc<D>,
    export: &Export,
    sessions: &AtomicUsize,
) -> anyhow::Result<bool> {
    sessions.fetch_add(1, Ordering::SeqCst);
    let res = transmission_loop(&mut stream, Arc::clone(&device), export).await;
    let _ = run_block(move || device.flush()).await;
    sessions.fetch_sub(1, Ordering::SeqCst);
    res
}

/// `Ok(true)` = clean `NBD_CMD_DISC`; `Ok(false)` = EOF or a disconnect forced
/// by an invalid request.
async fn transmission_loop<D: BlockDevice>(
    stream: &mut TcpStream,
    device: Arc<D>,
    export: &Export,
) -> anyhow::Result<bool> {
    // A reply that cannot be written usually means the client already left. The
    // Linux kernel's `nbd-client -d` sends NBD_CMD_DISC and shuts the socket down
    // at once, without waiting for replies to requests still in flight; the
    // failed reply must not hide the DISC queued behind it (observed: 3 of 8
    // real-kernel detaches were missed without this).
    macro_rules! reply {
        ($err:expr, $handle:expr, $data:expr) => {
            if let Err(e) = simple_reply(&mut *stream, $err, $handle, $data).await {
                return disconnect_or(&mut *stream, e).await;
            }
        };
    }
    loop {
        let magic = match stream.read_u32().await {
            Ok(m) => m,
            // Abrupt disconnect: end the loop; `serve_transmission` flushes.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if magic != NBD_REQUEST_MAGIC {
            anyhow::bail!("bad request magic {magic:#x}");
        }
        let cmd_flags = stream.read_u16().await?;
        let cmd_type = stream.read_u16().await?;
        let handle = stream.read_u64().await?;
        let offset = stream.read_u64().await?;
        let length = stream.read_u32().await?;

        // We negotiate no per-command flags (no FUA / structured replies), so any
        // nonzero flag is unnegotiated — reject it clearly rather than silently
        // process the request as if a durability-affecting flag were absent. WRITE
        // still has a payload on the wire, so drain it first to stay in sync.
        if cmd_flags != 0 {
            if cmd_type == NBD_CMD_WRITE {
                if length as u64 > MAX_REQUEST_LEN {
                    reply!(EINVAL, handle, &[]);
                    return Ok(false);
                }
                drain(&mut *stream, length).await?;
            }
            reply!(EINVAL, handle, &[]);
            continue;
        }

        match cmd_type {
            // Clean disconnect: end the loop; `serve_transmission` flushes for
            // local durability. Finalizing OFFSITE durability (seal+upload the open
            // segment) is `BlockDevice::shutdown`, called by the server owner on
            // export teardown — not per-connection, since connections may share
            // this single-writer device.
            NBD_CMD_DISC => return Ok(true),
            NBD_CMD_WRITE => {
                // Validate BEFORE allocating: an oversized length is disconnected;
                // an out-of-range/unaligned WRITE drains its (bounded) payload and
                // errors, so no buffer is allocated for a request that will fail.
                if length as u64 > MAX_REQUEST_LEN {
                    reply!(EINVAL, handle, &[]);
                    return Ok(false);
                }
                match block_range(offset, length, export.size) {
                    Ok((lba, count)) => {
                        let mut data = vec![0u8; length as usize];
                        stream.read_exact(&mut data).await?;
                        let dev = Arc::clone(&device);
                        let err = run_block(move || dev.write_blocks(lba, count, &data)).await;
                        reply!(err, handle, &[]);
                    }
                    Err(err) => {
                        drain(&mut *stream, length).await?;
                        reply!(err, handle, &[]);
                    }
                }
            }
            NBD_CMD_READ => match block_range(offset, length, export.size) {
                Ok((lba, count)) => {
                    let dev = Arc::clone(&device);
                    let res = tokio::task::spawn_blocking(move || {
                        let mut buf = vec![0u8; length as usize];
                        dev.read_blocks(lba, count, &mut buf).map(|()| buf)
                    })
                    .await
                    .unwrap_or_else(|_| Err(io::Error::other("read task panicked")));
                    match res {
                        Ok(buf) => reply!(0, handle, &buf),
                        Err(e) => reply!(errno(&e), handle, &[]),
                    }
                }
                Err(err) => reply!(err, handle, &[]),
            },
            NBD_CMD_FLUSH => {
                let dev = Arc::clone(&device);
                let err = run_block(move || dev.flush()).await;
                reply!(err, handle, &[]);
            }
            NBD_CMD_TRIM => {
                // TRIM carries no data payload, so it is NOT bounded by
                // MAX_REQUEST_LEN (which exists to cap READ/WRITE buffer
                // allocation). A client may legitimately discard the whole
                // device in one request — e.g. mkfs's initial full-device
                // DISCARD. Rejecting it as EINVAL surfaces as a block-layer I/O
                // error that can escalate ext4 to errors=remount-ro.
                let err = match discard_range(offset, length, export.size) {
                    Ok((lba, count)) => {
                        let dev = Arc::clone(&device);
                        run_block(move || dev.discard(lba, count)).await
                    }
                    Err(e) => e,
                };
                reply!(err, handle, &[]);
            }
            other => {
                warn!("unsupported NBD command {other}");
                reply!(EINVAL, handle, &[]);
            }
        }
    }
}

/// Validate + translate a byte range to (lba, block count), or an errno. Requires
/// block alignment and in-range access; the block size was advertised to the client.
fn block_range(offset: u64, length: u32, size: u64) -> Result<(u64, u32), u32> {
    let bs = LOGICAL_BLOCK_SIZE;
    if length == 0 || length as u64 > MAX_REQUEST_LEN {
        return Err(EINVAL);
    }
    if !offset.is_multiple_of(bs) || !(length as u64).is_multiple_of(bs) {
        return Err(EINVAL);
    }
    let end = offset.checked_add(length as u64).ok_or(EINVAL)?;
    if end > size {
        return Err(EINVAL);
    }
    let lba = offset / bs;
    let count = u32::try_from((length as u64) / bs).map_err(|_| EINVAL)?;
    Ok((lba, count))
}

/// Validate + translate a TRIM/DISCARD byte range to (lba, block count), or an
/// errno. Identical to [`block_range`] except it is NOT capped at
/// `MAX_REQUEST_LEN`: a discard carries no data payload (nothing to buffer), and
/// filesystems legitimately discard the entire device in a single request (mkfs
/// issues a full-device DISCARD before laying down structures). `discard` itself
/// is O(1) on the log-structured engine (one FTL-delta `Unmap` record), so a
/// whole-device range is cheap. Still requires block alignment and in-range access.
fn discard_range(offset: u64, length: u32, size: u64) -> Result<(u64, u32), u32> {
    let bs = LOGICAL_BLOCK_SIZE;
    if length == 0 {
        return Err(EINVAL);
    }
    if !offset.is_multiple_of(bs) || !(length as u64).is_multiple_of(bs) {
        return Err(EINVAL);
    }
    let end = offset.checked_add(length as u64).ok_or(EINVAL)?;
    if end > size {
        return Err(EINVAL);
    }
    let lba = offset / bs;
    let count = u32::try_from((length as u64) / bs).map_err(|_| EINVAL)?;
    Ok((lba, count))
}

/// Run a sync BlockDevice op on the blocking pool, returning an NBD errno (0 = ok).
async fn run_block<F>(f: F) -> u32
where
    F: FnOnce() -> io::Result<()> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => errno(&e),
        Err(_) => {
            error!("NBD block op task panicked");
            EIO
        }
    }
}

fn errno(e: &io::Error) -> u32 {
    match e.kind() {
        io::ErrorKind::InvalidInput => EINVAL,
        _ => EIO,
    }
}

/// After a reply could not be written: if the client sent NBD_CMD_DISC (it may
/// sit in the receive buffer behind requests that will never get a reply),
/// this was a clean disconnect; otherwise return the write error.
async fn disconnect_or(stream: &mut TcpStream, write_err: io::Error) -> anyhow::Result<bool> {
    if scan_for_disconnect(stream).await {
        debug!("client disconnected (NBD_CMD_DISC) while replies were pending");
        Ok(true)
    } else {
        Err(write_err.into())
    }
}

/// Read the requests still buffered on the socket, WITHOUT executing any (the
/// client no longer waits for them, so none can be acknowledged), looking for
/// NBD_CMD_DISC. Stops at EOF, an error, a malformed request, or when nothing
/// more arrives within a short timeout.
async fn scan_for_disconnect(stream: &mut TcpStream) -> bool {
    const MAX_SCANNED: usize = 4096;
    const QUIET: std::time::Duration = std::time::Duration::from_secs(2);
    for _ in 0..MAX_SCANNED {
        let mut hdr = [0u8; 28];
        match tokio::time::timeout(QUIET, stream.read_exact(&mut hdr)).await {
            Ok(Ok(_)) => {}
            _ => return false,
        }
        let magic = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
        let cmd_type = u16::from_be_bytes(hdr[6..8].try_into().unwrap());
        let length = u32::from_be_bytes(hdr[24..28].try_into().unwrap());
        if magic != NBD_REQUEST_MAGIC {
            return false;
        }
        match cmd_type {
            NBD_CMD_DISC => return true,
            NBD_CMD_WRITE => {
                if length as u64 > MAX_REQUEST_LEN {
                    return false;
                }
                match tokio::time::timeout(QUIET, drain(stream, length)).await {
                    Ok(Ok(())) => {}
                    _ => return false,
                }
            }
            _ => {}
        }
    }
    false
}

/// Read + discard `n` bytes in bounded chunks — keeps the stream in protocol sync
/// after an invalid WRITE without allocating the full (already length-capped)
/// payload up front.
async fn drain(stream: &mut TcpStream, n: u32) -> io::Result<()> {
    let mut remaining = n as usize;
    let mut buf = [0u8; 8192];
    while remaining > 0 {
        let take = remaining.min(buf.len());
        stream.read_exact(&mut buf[..take]).await?;
        remaining -= take;
    }
    Ok(())
}

async fn simple_reply(
    stream: &mut TcpStream,
    error: u32,
    handle: u64,
    data: &[u8],
) -> io::Result<()> {
    stream.write_u32(NBD_SIMPLE_REPLY_MAGIC).await?;
    stream.write_u32(error).await?;
    stream.write_u64(handle).await?;
    if !data.is_empty() {
        stream.write_all(data).await?;
    }
    stream.flush().await?;
    Ok(())
}
