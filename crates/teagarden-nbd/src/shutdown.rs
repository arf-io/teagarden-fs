//! Operator shutdown signals for a long-running `serve_durable`.

use tokio::signal::unix::{signal, Signal, SignalKind};

/// Resolves on the first SIGINT or SIGTERM, which is when the caller starts
/// finalizing (sealing the open segment, uploading, publishing the final
/// checkpoint). From then on this keeps listening: a SECOND SIGINT or SIGTERM
/// while finalization is still running prints `second_signal_message` to stderr
/// and ends the process at once with exit status 1, instead of being swallowed.
///
/// Installing the handlers also means neither signal kills the process
/// mid-write. The watcher is a spawned task, so it works while the caller's
/// finalization blocks on a `spawn_blocking` thread; it is only started once the
/// first signal arrived, so a stop that begins any other way (a client's clean
/// NBD disconnect) is never aborted by it.
pub async fn shutdown_signal(second_signal_message: String) {
    match (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) {
        (Ok(mut int), Ok(mut term)) => {
            tokio::select! {
                _ = int.recv() => {},
                _ = term.recv() => {},
            }
            // Reuse the SAME streams: signals that arrive between the first and
            // a freshly installed pair would be lost.
            tokio::spawn(abort_on_next_signal(int, term, second_signal_message));
        }
        (int, term) => {
            eprintln!(
                "WARNING: could not install a SIGINT/SIGTERM handler ({}); stop the device with \
                 `nbd-client -d` so it can finalize",
                int.err()
                    .or(term.err())
                    .map(|e| e.to_string())
                    .unwrap_or_default()
            );
            std::future::pending::<()>().await
        }
    }
}

async fn abort_on_next_signal(mut int: Signal, mut term: Signal, message: String) {
    tokio::select! {
        _ = int.recv() => {},
        _ = term.recv() => {},
    }
    eprintln!("{message}");
    std::process::exit(1);
}
