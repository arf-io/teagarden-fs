//! `serve_durable` over the full encrypted stack (TeaGarden block-device engine over the
//! test transport) with a real NBD client on loopback TCP: a clean
//! `NBD_CMD_DISC` finalizes, periodic checkpoints make uploaded segments
//! recoverable after a crash (no finalize at all), and a failed finalize is an
//! error. The SIGTERM path is `serve_sigterm.rs` (its own process).

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use teagarden_nbd::{serve_durable, CheckpointPolicy, ServeEnd};
use teagarden_telegram::mock::MockTransport;
use tokio::net::TcpListener;

async fn bind() -> (TcpListener, std::net::SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

/// A client that ends its session with NBD_CMD_DISC ends the serving: the
/// device is finalized and a final checkpoint published, which recovers every
/// byte into an empty directory. A second client that disconnects while the
/// first is still attached does NOT end it.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn clean_disconnect_finalizes_and_is_recoverable() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(MockTransport::new());
    let device = new_device(dir.path(), transport.clone());
    let (listener, addr) = bind().await;
    let server = tokio::spawn(async move {
        serve_durable(
            device,
            "",
            listener,
            std::future::pending::<()>(),
            CheckpointPolicy::default(),
            |_| Ok(()),
        )
        .await
    });

    let (mut a, _) = NbdClient::connect(addr).await;
    let (b, _) = NbdClient::connect(addr).await;
    let data = pattern(13, 0x42); // one full segment + 5 blocks left open
    assert_eq!(a.write(8 * BS as u64, &data).await, 0);
    b.disconnect().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !server.is_finished(),
        "a disconnect while another session is attached must not stop serving"
    );
    assert_eq!(a.write(500 * BS as u64, &pattern(1, 9)).await, 0);
    a.disconnect().await;

    let report = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("serving ends after the last clean disconnect")
        .unwrap()
        .expect("finalize succeeded");
    eprintln!("DISC: {report:?}");
    assert_eq!(report.end, ServeEnd::ClientDisconnected);
    assert_eq!(
        recover_and_read(transport.clone(), report.final_recovery_point, 8, 13).await,
        data
    );
    assert_eq!(
        recover_and_read(transport, report.final_recovery_point, 500, 1).await,
        pattern(1, 9)
    );
}

/// While serving, checkpoints are published on their own (here: after every 2
/// uploaded segments). The process then "crashes" (the serve task is aborted:
/// no finalize, no final checkpoint) and the machine is lost: recovering the
/// last PERIODIC checkpoint into an empty directory returns every uploaded
/// segment byte-exact. What was still in the open segment is the documented
/// loss (it reads back as zeros).
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn periodic_checkpoints_bound_the_loss_after_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(MockTransport::new());
    let device = new_device(dir.path(), transport.clone());
    let (listener, addr) = bind().await;
    let last = Arc::new(Mutex::new(None::<i64>));
    let count = Arc::new(AtomicU64::new(0));
    let (rec_last, rec_count) = (last.clone(), count.clone());
    let policy = CheckpointPolicy {
        every_units: 2,
        max_interval: Duration::from_secs(3600),
        tick: Duration::from_millis(20),
    };
    let server = tokio::spawn(async move {
        serve_durable(
            device,
            "",
            listener,
            std::future::pending::<()>(),
            policy,
            move |id| {
                *rec_last.lock().unwrap() = Some(id);
                rec_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
    });

    let wait_for = |n: u64| {
        let count = count.clone();
        async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while count.load(Ordering::SeqCst) < n && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                count.load(Ordering::SeqCst) >= n,
                "checkpoint {n} was not published while serving"
            );
        }
    };
    let (mut c, _) = NbdClient::connect(addr).await;
    let uploaded = pattern(32, 0x21); // four full segments, written 2 + 2
    assert_eq!(c.write(0, &uploaded[..16 * BS]).await, 0);
    wait_for(1).await;
    assert_eq!(c.write(16 * BS as u64, &uploaded[16 * BS..]).await, 0);
    wait_for(2).await;
    let open_tail = pattern(2, 0x99); // stays in the open segment
    assert_eq!(c.write(2000 * BS as u64, &open_tail).await, 0);
    assert_eq!(c.flush().await, 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "nothing new was uploaded, so no further checkpoint"
    );
    let head = last.lock().unwrap().unwrap();

    // Crash: no finalize, no final checkpoint.
    server.abort();
    let _ = server.await;
    drop(c);

    let got = recover_and_read(transport.clone(), head, 0, 32).await;
    assert_eq!(got, uploaded, "every uploaded segment is recoverable");
    let got = recover_and_read(transport, head, 2000, 2).await;
    assert_eq!(
        got,
        vec![0u8; 2 * BS],
        "the open segment was never in a checkpoint (the documented bound)"
    );
}

/// If the last segment cannot be uploaded at shutdown, `serve_durable` must
/// return an error (the CLI exits non-zero), never report success.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn failed_finalize_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(MockTransport::new());
    let device = new_device(dir.path(), transport.clone());
    let (listener, addr) = bind().await;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        serve_durable(
            device,
            "",
            listener,
            async move {
                let _ = stop_rx.await;
            },
            CheckpointPolicy::default(),
            |_| Ok(()),
        )
        .await
    });
    let (mut c, _) = NbdClient::connect(addr).await;
    assert_eq!(c.write(0, &pattern(3, 1)).await, 0);
    assert_eq!(c.flush().await, 0);
    *transport.fail_uploads.lock().unwrap() = Some("telegram is down".into());
    stop_tx.send(()).unwrap();
    let err = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .unwrap()
        .unwrap()
        .expect_err("a finalize that could not upload must fail");
    eprintln!("failed finalize: {err:#}");
    assert!(
        format!("{err:#}").contains("local state is intact"),
        "{err:#}"
    );
}

/// Killed and resumed: the serving process dies after a FLUSH (the serve task is
/// dropped: no finalize, no checkpoint; the device has no Drop logic, so this is
/// what a SIGKILL leaves, the directory lock included). The disk survives. A
/// restarted serve on the SAME directory replays the staging log, and stopping
/// it cleanly uploads everything: the final checkpoint recovers every flushed
/// byte into an empty directory, including the tail that was only staged.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn killed_then_restarted_serve_uploads_everything_flushed() {
    use teagarden_dev::adapter::BlockDeviceAdapter;
    use teagarden_dev::device::TeaGardenDevice;

    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(MockTransport::new());
    let device = new_device(dir.path(), transport.clone());
    let (listener, addr) = bind().await;
    let server = tokio::spawn(async move {
        serve_durable(
            device,
            "",
            listener,
            std::future::pending::<()>(),
            CheckpointPolicy::default(),
            |_| Ok(()),
        )
        .await
    });
    let (mut c, _) = NbdClient::connect(addr).await;
    let sealed = pattern(16, 0x31); // two full segments
    let tail = pattern(3, 0x77); // staged only
    assert_eq!(c.write(0, &sealed).await, 0);
    assert_eq!(c.write(700 * BS as u64, &tail).await, 0);
    assert_eq!(c.flush().await, 0);
    let before_kill = transport.message_count();

    // Kill: drop the whole serving future and the client.
    server.abort();
    let _ = server.await;
    drop(c);

    // Restart on the same directory. Wait for the dropped connection tasks to
    // release the device; a lock that never comes free would be a finding.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let reopened = loop {
        match TeaGardenDevice::open(transport.clone(), keys(), dir.path(), config()) {
            Ok(d) => break d,
            Err(e) if std::time::Instant::now() < deadline => {
                eprintln!("reopen not yet possible: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("the killed device could not be reopened: {e}"),
        }
    };
    let adapter = Arc::new(BlockDeviceAdapter::new(
        reopened,
        tokio::runtime::Handle::current(),
    ));
    let (listener, _addr) = bind().await;
    let report = serve_durable(
        adapter,
        "",
        listener,
        async {},
        CheckpointPolicy::default(),
        |_| Ok(()),
    )
    .await
    .expect("the restarted serve stops cleanly");
    eprintln!(
        "killed+resumed: documents before kill {before_kill}, after clean stop {}; {report:?}",
        transport.message_count()
    );
    assert_eq!(
        recover_and_read(transport.clone(), report.final_recovery_point, 0, 16).await,
        sealed
    );
    assert_eq!(
        recover_and_read(transport, report.final_recovery_point, 700, 3).await,
        tail,
        "the flushed tail survived the kill and was uploaded by the restarted serve"
    );
}

/// The Linux kernel's `nbd-client -d` sends NBD_CMD_DISC and shuts the socket
/// down at once, without waiting for replies to requests still in flight. Here:
/// eight 4 MiB READs are pipelined, then DISC, then the client closes without
/// reading a single reply (closing with unread data makes Linux send a RST, as
/// the kernel's shutdown does). The server's replies fail; the DISC behind them
/// must still end the session as a clean disconnect, not be lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn disconnect_with_replies_pending_still_ends_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(MockTransport::new());
    let device = new_device(dir.path(), transport.clone());
    let (listener, addr) = bind().await;
    let server = tokio::spawn(async move {
        serve_durable(
            device,
            "",
            listener,
            std::future::pending::<()>(),
            CheckpointPolicy::default(),
            |_| Ok(()),
        )
        .await
    });
    let (mut c, _) = NbdClient::connect(addr).await;
    let data = pattern(5, 0x5a);
    assert_eq!(c.write(0, &data).await, 0);
    for i in 0..8u64 {
        c.send_only(
            NBD_CMD_READ,
            i * 4 * 1024 * 1024 % (CAPACITY * BS as u64),
            4 * 1024 * 1024,
        )
        .await;
    }
    c.send_only(NBD_CMD_DISC, 0, 0).await;
    drop(c); // close with every reply unread

    let report = tokio::time::timeout(Duration::from_secs(20), server)
        .await
        .expect("the DISC behind the unanswered READs must end the serving")
        .unwrap()
        .expect("finalize succeeded");
    assert_eq!(report.end, ServeEnd::ClientDisconnected);
    assert_eq!(
        recover_and_read(transport, report.final_recovery_point, 0, 5).await,
        data
    );
}
