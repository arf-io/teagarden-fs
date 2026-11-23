//! A SECOND SIGINT/SIGTERM while a signal-initiated shutdown is finalizing
//! must end the process at once with a non-zero status and the operator
//! message; the first one must not. Real signals to a real child process (the
//! signal disposition is process-wide, so the child is this same test binary
//! re-executed with `TGNBD_DOUBLE_SIGNAL_CHILD` set).

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use teagarden_nbd::shutdown_signal;

const MESSAGE: &str = "finalization is incomplete: the test says so";

/// Child body. A no-op unless re-executed by the parent test below.
#[test]
fn child_waits_for_a_signal_then_pretends_to_finalize() {
    if std::env::var_os("TGNBD_DOUBLE_SIGNAL_CHILD").is_none() {
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let fut = shutdown_signal(MESSAGE.to_string());
        tokio::pin!(fut);
        // Poll once so the handlers are installed before announcing readiness.
        tokio::select! {
            () = &mut fut => unreachable!("no signal has been sent yet"),
            () = tokio::task::yield_now() => {}
        }
        println!("READY");
        fut.await;
        println!("FIRST");
        // "Finalizing": a long blocking call, as `serve_durable` makes.
        tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(60)))
            .await
            .unwrap();
        println!("FINALIZED");
    });
}

fn wait_for_line(out: &mut impl BufRead, want: &str) {
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            out.read_line(&mut line).unwrap() > 0,
            "child ended before printing {want}"
        );
        // libtest prints "test <name> ... " without a newline before the body runs.
        if line.trim_end().ends_with(want) {
            return;
        }
    }
}

/// Kills the child if the test fails before it has exited on its own.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn send(pid: u32, sig: libc::c_int) {
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, sig) }, 0);
}

#[test]
fn second_signal_during_finalize_exits_nonzero_with_the_message() {
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_waits_for_a_signal_then_pretends_to_finalize",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("TGNBD_DOUBLE_SIGNAL_CHILD", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut child = KillOnDrop(child);
    let child = &mut child.0;
    let mut out = BufReader::new(child.stdout.take().unwrap());
    wait_for_line(&mut out, "READY");

    send(pid, libc::SIGINT);
    wait_for_line(&mut out, "FIRST");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().unwrap().is_none(),
        "the first signal starts finalizing; it must not end the process"
    );

    let started = Instant::now();
    send(pid, libc::SIGTERM);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the second signal was ignored: the child is still finalizing"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    eprintln!(
        "child exit: {status:?} after {:?}\nstderr: {err}",
        started.elapsed()
    );
    assert_eq!(
        status.code(),
        Some(1),
        "non-zero, and not killed by the signal"
    );
    assert!(err.contains(MESSAGE), "operator message missing: {err}");
}
