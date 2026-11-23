//! A REAL SIGTERM to a serving process, then disaster recovery from Telegram
//! alone. Its own test binary (= its own process) because the signal is
//! process-wide.
//!
//! The client writes through the NBD protocol over loopback TCP: three full
//! segments plus a tail that stays in the open (unsealed) segment, then
//! FLUSHes (local durability only) and stays attached. The process sends itself
//! SIGTERM; `serve_durable` must stop, seal and upload the tail, publish a
//! final checkpoint and return it. Recovering that checkpoint into an EMPTY
//! directory over the same test transport must read every byte back.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use teagarden_nbd::{serve_durable, CheckpointPolicy, ServeEnd};
use teagarden_telegram::mock::MockTransport;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn sigterm_finalizes_and_recover_from_head_reads_every_byte() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(MockTransport::new());
    let device = new_device(dir.path(), transport.clone());

    // Register the handler BEFORE the signal can arrive: from here on SIGTERM
    // no longer terminates this process, it resolves `shutdown`.
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let shutdown = async move {
        sigterm.recv().await;
    };
    let points = Arc::new(Mutex::new(Vec::new()));
    let recorded = points.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        serve_durable(
            device,
            "",
            listener,
            shutdown,
            CheckpointPolicy::default(),
            move |id| {
                recorded.lock().unwrap().push(id);
                Ok(())
            },
        )
        .await
    });

    let (mut c, size) = NbdClient::connect(addr).await;
    assert_eq!(size, CAPACITY * BS as u64);
    let sealed = pattern(24, 0x10); // 3 x 8 blocks: three full segments
    let tail = pattern(3, 0x80); // stays in the open segment
    assert_eq!(c.write(0, &sealed).await, 0);
    assert_eq!(c.write(1000 * BS as u64, &tail).await, 0);
    assert_eq!(c.flush().await, 0);
    let uploaded_before = transport.message_count();

    // SIGTERM while the client is still attached.
    assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGTERM) }, 0);
    let report = tokio::time::timeout(std::time::Duration::from_secs(30), server)
        .await
        .expect("serve_durable stopped after SIGTERM")
        .unwrap()
        .expect("finalizing succeeded");
    drop(c);
    eprintln!(
        "SIGTERM: end={:?} final checkpoint message={} periodic={} \
         (documents uploaded before SIGTERM {uploaded_before}, after {})",
        report.end,
        report.final_recovery_point,
        report.periodic_points,
        transport.message_count()
    );
    assert_eq!(report.end, ServeEnd::Shutdown);
    assert_eq!(
        points.lock().unwrap().last().copied(),
        Some(report.final_recovery_point),
        "the final checkpoint is reported to the caller (the CLI records it)"
    );
    assert!(
        transport.message_count() > uploaded_before,
        "shutdown must upload the open segment and a checkpoint"
    );

    // Disaster recovery: Telegram only, empty directory.
    let got = recover_and_read(transport.clone(), report.final_recovery_point, 0, 24).await;
    assert_eq!(got, sealed, "sealed segments read back byte-exact");
    let got = recover_and_read(transport, report.final_recovery_point, 1000, 3).await;
    assert_eq!(
        got, tail,
        "the tail that was only in the open segment survives"
    );
}
