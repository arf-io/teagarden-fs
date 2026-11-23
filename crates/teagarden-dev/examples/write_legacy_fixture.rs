//! Regenerate `tests/fixtures/legacy-v2-device/` (see `tests/common/legacy.rs`).
//!
//! `cargo run -p teagarden-dev --example write_legacy_fixture -- <out-dir>`
//!
//! The committed fixture must come from a PRE-fix build (it is the "existing
//! device" the compatibility test opens); regenerating it with current code
//! only proves current-code round-trips.

#[path = "../tests/common/legacy.rs"]
mod legacy;

use std::sync::Arc;
use teagarden_telegram::mock::MockTransport;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let out = std::path::PathBuf::from(std::env::args().nth(1).expect("usage: <out-dir>"));
    let dev_dir = out.join("dev");
    let msg_dir = out.join("messages");
    std::fs::create_dir_all(&dev_dir).unwrap();
    std::fs::create_dir_all(&msg_dir).unwrap();
    let t = Arc::new(MockTransport::new());
    let head = legacy::run_scenario(&dev_dir, &t).await;
    // dump every surviving cloud message under its message id
    let mut n = 0;
    for id in 1..10_000i64 {
        if let Some(raw) = t.get_raw(id) {
            std::fs::write(msg_dir.join(format!("{id}.bin")), raw).unwrap();
            n += 1;
        }
    }
    std::fs::write(out.join("head_msg_id"), head.to_string()).unwrap();
    println!("wrote {n} messages, head {head}, to {}", out.display());
}
