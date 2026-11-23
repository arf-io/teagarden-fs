//! Existing devices keep opening (HARD RULE: no on-disk format change).
//!
//! `tests/fixtures/legacy-v2-device/` is a device directory + its cloud
//! messages written by the pre-fix engine (see `tests/common/legacy.rs`).
//! These tests open it with the CURRENT engine.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::legacy::{self, BS};
use teagarden_dev::device::TeaGardenDevice;
use teagarden_telegram::mock::MockTransport;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-v2-device")
}

/// Copy the fixture's device dir into a scratch dir (open() may legitimately
/// rewrite local state, the committed fixture must stay pristine) and seed a
/// mock cloud with the recorded messages under their original ids.
async fn load() -> (tempfile::TempDir, Arc<MockTransport>, i64) {
    let scratch = tempfile::tempdir().unwrap();
    for name in ["superblock", "catalog", "staging.log"] {
        std::fs::copy(fixture().join("dev").join(name), scratch.path().join(name)).unwrap();
    }
    let t = Arc::new(MockTransport::new());
    let mut ids: Vec<i64> = std::fs::read_dir(fixture().join("messages"))
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            p.file_stem().unwrap().to_str().unwrap().parse().unwrap()
        })
        .collect();
    ids.sort_unstable();
    assert!(!ids.is_empty(), "fixture has no cloud messages");
    for id in ids {
        let raw = std::fs::read(fixture().join("messages").join(format!("{id}.bin"))).unwrap();
        t.set_next_id(id);
        let up = teagarden_telegram::client::BlockTransport::upload_block(&*t, &raw, "fixture.bin")
            .await
            .unwrap();
        assert_eq!(up.message_id, id);
    }
    let head: i64 = std::fs::read_to_string(fixture().join("head_msg_id"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    (scratch, t, head)
}

async fn assert_contents(
    d: &mut TeaGardenDevice<MockTransport>,
    want: impl Fn(u64) -> Option<u8>,
    what: &str,
) {
    for lba in 0..32u64 {
        let got = d.read_at(lba, 1).await.unwrap();
        let exp = match want(lba) {
            Some(g) => legacy::block(lba, g),
            None => vec![0u8; BS],
        };
        assert!(got == exp, "{what}: lba {lba} content mismatch");
    }
}

#[tokio::test]
async fn legacy_device_opens_and_reads_back() {
    let (dir, t, _head) = load().await;
    let mut d = TeaGardenDevice::open(Arc::clone(&t), legacy::keys(), dir.path(), legacy::config())
        .expect("a device written by the pre-fix engine must still open");
    assert_contents(&mut d, legacy::expected, "legacy open").await;

    // and it keeps working: write, flush, crash, reopen
    d.write_at(30, &legacy::blocks(30, 2, 0xD0)).await.unwrap();
    d.flush().await.unwrap();
    drop(d);
    let mut r = TeaGardenDevice::open(Arc::clone(&t), legacy::keys(), dir.path(), legacy::config())
        .unwrap();
    assert_contents(
        &mut r,
        |l| match l {
            30..=31 => Some(0xD0),
            _ => legacy::expected(l),
        },
        "legacy reopen after new write",
    )
    .await;
    r.close().await.unwrap();
}

#[tokio::test]
async fn legacy_head_still_recovers_on_a_fresh_machine() {
    let (_dir, t, head) = load().await;
    let fresh = tempfile::tempdir().unwrap();
    let mut r = TeaGardenDevice::recover_from_head(
        Arc::clone(&t),
        legacy::keys(),
        legacy::DEVICE_UUID,
        fresh.path(),
        head,
        legacy::config(),
    )
    .await
    .expect("a head published by the pre-fix engine must still recover");
    assert_contents(&mut r, legacy::expected_at_head, "legacy head recovery").await;
}
