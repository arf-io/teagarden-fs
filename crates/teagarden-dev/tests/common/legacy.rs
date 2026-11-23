//! The "legacy device" scenario shared by the fixture generator
//! (`examples/write_legacy_fixture.rs`) and the fixture test
//! (`tests/legacy_device_fixture.rs`).
//!
//! The committed fixture under `tests/fixtures/legacy-v2-device/` was written
//! by the generator at commit 55b5334, BEFORE the C1/H4/M5/L4 staging fixes, so
//! the fixture test proves that a device laid down by the old code still opens,
//! reads back byte-exact, and still recovers from its cloud head.
#![allow(dead_code)]

use std::sync::Arc;

use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_dev::cache::CacheConfig;
use teagarden_dev::device::{DeviceConfig, DeviceKeys, ReadConfig, TeaGardenDevice};
use teagarden_dev::gc::GcConfig;
use teagarden_telegram::mock::MockTransport;

pub const BS: usize = 4096;
pub const CAPACITY_BLOCKS: u64 = 256;
pub const DEVICE_UUID: [u8; 16] = [0x5au8; 16];

/// Fixed test keys (fixture only — never a product key).
pub fn keys() -> DeviceKeys {
    DeviceKeys {
        data_key: SymmetricKey::from_bytes([0x41u8; 32]),
        meta_key: SymmetricKey::from_bytes([0x42u8; 32]),
        integrity_key: SymmetricKey::from_bytes([0x43u8; 32]),
    }
}

pub fn config() -> DeviceConfig {
    DeviceConfig {
        segment_target: 32 * 1024,
        record_max: 8 * 1024,
        cache: CacheConfig {
            budget_bytes: 1 << 30,
            ..Default::default()
        },
        gc: GcConfig::default(),
        read: ReadConfig::default(),
    }
}

/// Block `lba` of generation `g`: distinct per (lba, generation).
pub fn block(lba: u64, g: u8) -> Vec<u8> {
    let mut b = vec![0u8; BS];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (lba as u8).wrapping_mul(31) ^ g ^ (i as u8);
    }
    b
}

pub fn blocks(lba: u64, count: u64, g: u8) -> Vec<u8> {
    (lba..lba + count).flat_map(|l| block(l, g)).collect()
}

/// The expected content of every LBA after the scenario (`None` = hole).
pub fn expected(lba: u64) -> Option<u8> {
    match lba {
        0..=5 => Some(0xB0),
        6..=9 => Some(0xA0),
        10..=11 => None, // discarded
        12..=15 => Some(0xA0),
        20..=23 => Some(0xC0), // staged, never uploaded
        _ => None,
    }
}

/// The expected content of every LBA as of the cloud head (the confirmed
/// prefix: the unuploaded C writes are not in it).
pub fn expected_at_head(lba: u64) -> Option<u8> {
    match lba {
        20..=23 => None,
        _ => expected(lba),
    }
}

/// Run the scenario: confirmed writes, an overwrite, a discard, a GC pass
/// (relocations + a published head), then an unconfirmed staged tail.
/// Returns the head message id GC published.
pub async fn run_scenario(dir: &std::path::Path, t: &Arc<MockTransport>) -> i64 {
    let mut d = TeaGardenDevice::create(
        Arc::clone(t),
        keys(),
        DEVICE_UUID,
        CAPACITY_BLOCKS,
        dir,
        config(),
    )
    .unwrap();
    d.write_at(0, &blocks(0, 16, 0xA0)).await.unwrap();
    d.close().await.unwrap();
    d.write_at(0, &blocks(0, 6, 0xB0)).await.unwrap();
    d.discard(10, 2).await.unwrap();
    d.close().await.unwrap();
    let report = d.gc().await.unwrap();
    assert!(
        report.extents_moved > 0,
        "scenario must exercise GC relocation: {report:?}"
    );
    let head = report.head_msg_id.expect("gc published a head");
    d.write_at(20, &blocks(20, 4, 0xC0)).await.unwrap();
    d.flush().await.unwrap();
    // drop WITHOUT close: the C writes stay staged-only (a crash)
    drop(d);
    head
}
