//! Serving a cloud-backed device until it is told to stop, with recovery points.
//!
//! [`NbdServer::serve_with_listener`](crate::NbdServer::serve_with_listener)
//! accepts forever and never finalizes anything, so data written through it
//! stayed only in the device's local staging log. [`serve_durable`] is the
//! lifecycle the `dev serve nbd` command runs:
//!
//! - **while serving**, it publishes a recovery point whenever
//!   [`CheckpointPolicy::every_units`] new units are durable offsite, and at
//!   least every [`CheckpointPolicy::max_interval`] while any are (checked every
//!   [`CheckpointPolicy::tick`]);
//! - it **stops** when the `shutdown` future resolves (the CLI passes
//!   SIGINT/SIGTERM) or when a client ends its session with a clean
//!   `NBD_CMD_DISC` and no other session is in the transmission phase;
//! - on stopping, it stops accepting and drops every connection (no reply is
//!   sent after that, so nothing more is acknowledged), then **finalizes**:
//!   [`BlockDevice::shutdown`] (seal
//!   and upload whatever is open, drain pending uploads, fsync) followed by one
//!   last recovery point. It returns `Ok` only if all of that succeeded.

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use teagarden_blockdev::RecoveryPoints;

use crate::handle_connection;

/// When [`serve_durable`] publishes a recovery point while serving.
#[derive(Debug, Clone, Copy)]
pub struct CheckpointPolicy {
    /// Publish as soon as this many units (TeaGarden block device: uploaded segments) are
    /// durable offsite but not covered by the last recovery point.
    pub every_units: u64,
    /// Publish at least this often while any unit is uncovered.
    pub max_interval: Duration,
    /// How often the two conditions above are checked.
    pub tick: Duration,
}

impl Default for CheckpointPolicy {
    /// 8 segments (360 MiB at the default 45 MiB segment) or 60 s, checked every
    /// 5 s.
    fn default() -> Self {
        Self {
            every_units: 8,
            max_interval: Duration::from_secs(60),
            tick: Duration::from_secs(5),
        }
    }
}

/// Why [`serve_durable`] stopped serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeEnd {
    /// The `shutdown` future resolved (e.g. SIGINT / SIGTERM).
    Shutdown,
    /// A client sent `NBD_CMD_DISC` and no other session was transmitting.
    ClientDisconnected,
}

/// Outcome of a [`serve_durable`] run that finalized successfully.
#[derive(Debug, Clone, Copy)]
pub struct ServeReport {
    /// What ended the serving.
    pub end: ServeEnd,
    /// The recovery point published after finalizing (covers everything).
    pub final_recovery_point: i64,
    /// Recovery points published while serving.
    pub periodic_points: u64,
}

async fn blocking<T, F>(f: F) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| io::Error::other(format!("device task failed: {e}")))?
}

/// Serve `device` on `listener` until `shutdown` resolves or a client cleanly
/// disconnects, publishing recovery points per `policy`, then finalize.
///
/// `on_point` is called with every published recovery point's id, periodic and
/// final, so the caller can record it (the CLI writes it to the device
/// registry, which is where `dev recover` looks). A failing `on_point` is a
/// warning for a periodic point and an error for the final one.
///
/// Returns `Err` if finalizing failed (sealing, uploading, the final recovery
/// point, or recording it); the device's local state is intact in every such
/// case. Accept errors are logged and serving continues.
pub async fn serve_durable<D, S, P>(
    device: Arc<D>,
    export_name: &str,
    listener: TcpListener,
    shutdown: S,
    policy: CheckpointPolicy,
    on_point: P,
) -> anyhow::Result<ServeReport>
where
    D: RecoveryPoints,
    S: Future<Output = ()>,
    P: Fn(i64) -> anyhow::Result<()>,
{
    let sessions = Arc::new(AtomicUsize::new(0));
    let (disc_tx, mut disc_rx) = mpsc::unbounded_channel::<()>();
    let mut conns = JoinSet::new();
    let mut ticker = tokio::time::interval(policy.tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_point = Instant::now();
    let mut periodic_points = 0u64;
    tokio::pin!(shutdown);

    let end = loop {
        tokio::select! {
            () = &mut shutdown => break ServeEnd::Shutdown,
            Some(()) = disc_rx.recv() => {
                if sessions.load(Ordering::SeqCst) == 0 {
                    break ServeEnd::ClientDisconnected;
                }
                debug!("a client disconnected; others are still attached");
            }
            accepted = listener.accept() => {
                // An accept error (EMFILE, ECONNABORTED, ...) concerns one would-be
                // connection, never the device: keep serving. Leaving the loop
                // here would skip finalizing.
                let (stream, peer) = match accepted {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!(error = %e, "NBD accept failed; still serving");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let dev = Arc::clone(&device);
                let export = export_name.to_string();
                let sessions = Arc::clone(&sessions);
                let disc_tx = disc_tx.clone();
                conns.spawn(async move {
                    match handle_connection(stream, dev, export, sessions).await {
                        Ok(true) => {
                            info!(%peer, "NBD client disconnected (NBD_CMD_DISC)");
                            let _ = disc_tx.send(());
                        }
                        Ok(false) => debug!(%peer, "NBD connection closed"),
                        Err(e) => debug!(%peer, "NBD connection closed: {e:#}"),
                    }
                });
            }
            _ = ticker.tick() => {
                let dev = Arc::clone(&device);
                let pending = match blocking(move || dev.unpublished()).await {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(error = %e, "could not read the device's checkpoint state");
                        continue;
                    }
                };
                let due = pending >= policy.every_units
                    || (pending > 0 && last_point.elapsed() >= policy.max_interval);
                if !due {
                    continue;
                }
                let dev = Arc::clone(&device);
                match blocking(move || dev.publish_recovery_point()).await {
                    Ok(id) => {
                        periodic_points += 1;
                        last_point = Instant::now();
                        info!(recovery_point = id, segments = pending, "published a checkpoint");
                        if let Err(e) = on_point(id) {
                            warn!(error = %e, recovery_point = id, "could not record the checkpoint");
                        }
                    }
                    // Not fatal while serving: the data is durable locally and
                    // the next tick retries.
                    Err(e) => warn!(error = %e, "periodic checkpoint failed; will retry"),
                }
            }
        }
    };
    drop(listener);

    // Drop every connection: from here on no request is read and no reply is
    // sent, so nothing further is acknowledged to a client. A device call that
    // was already handed to a blocking thread still runs (the device mutex
    // serializes it with finalize, before or after it); if it lands after
    // finalize, it was never acknowledged and is only appended to the local
    // staging log (not fsynced), from which the next serve replays it.
    conns.abort_all();
    while conns.join_next().await.is_some() {}

    let dev = Arc::clone(&device);
    blocking(move || dev.shutdown()).await.map_err(|e| {
        anyhow::anyhow!(
            "finalizing the device failed (sealing / uploading the last segment): {e}; the \
             device's local state is intact"
        )
    })?;
    let dev = Arc::clone(&device);
    let final_recovery_point = blocking(move || dev.publish_recovery_point())
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "every segment is uploaded, but publishing the final checkpoint failed: {e}; the \
                 device's local state is intact"
            )
        })?;
    on_point(final_recovery_point).map_err(|e| {
        anyhow::anyhow!(
            "the final checkpoint {final_recovery_point} is published, but recording it failed: \
             {e:#}"
        )
    })?;
    Ok(ServeReport {
        end,
        final_recovery_point,
        periodic_points,
    })
}
