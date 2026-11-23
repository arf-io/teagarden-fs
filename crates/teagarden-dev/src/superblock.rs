//! Device superblock (P1.2) — the sealed, MAC'd device configuration.
//!
//! The superblock is the small, authenticated record that describes the device:
//! its capacity, its stable identity (`device_uuid`), the current key `epoch`,
//! and a monotonic `generation` counter. It is authenticated with a keyed BLAKE3
//! MAC under the volume's integrity key, so none of these fields can be
//! **forged** or edited: any modified byte fails the MAC.
//!
//! It is **not** protected against **rollback** (M4). The MAC proves a blob was
//! written by this device, not that it is the newest one, and nothing outside
//! the file anchors `generation`. Anyone who can write the device directory can
//! put back an OLDER authentic superblock — reverting a resize or an epoch
//! rotation — and `open()` accepts it
//! (`device::tests::superblock_and_head_rollback_are_accepted`). Detecting that
//! needs an externally anchored generation (TPM counter, pinned head); none
//! exists today.
//!
//! ```text
//! magic "TGDEVSB1" (8) │ ver u16 │ rsvd u16 │ device_uuid (16) │
//! capacity_blocks u64 │ current_epoch u32 │ generation u64 │ MAC (32)
//! ```
//!
//! `generation` bumps on every config change (epoch rotation, resize). It is a
//! monotonic counter that a future anti-rollback check could compare against an
//! external anchor; on its own it detects nothing. The moving per-barrier
//! durability floor lives in the [`crate::head`] `DeviceHead` (M2d).

use teagarden_core::crypto::keys::SymmetricKey;

use crate::error::{DeviceError, Result};

const MAGIC: &[u8; 8] = b"TGDEVSB1";
/// Bumped 1 → 2 with P4 (GC): the staging log gained the `Relocate` delta
/// (tag 3). A pre-P4 binary parsing a post-GC staging log would treat the first
/// `Relocate` as a torn tail and silently truncate recovery there — every
/// acknowledged write staged after it would vanish from the FTL. Version-gating
/// the (always-read-first) superblock converts that silent loss into a clean
/// fail-closed refusal on both sides of the skew.
const FORMAT_VERSION: u16 = 2;
/// Serialized length: magic(8)+ver(2)+rsvd(2)+uuid(16)+cap(8)+epoch(4)+gen(8)+mac(32).
const BODY_LEN: usize = 8 + 2 + 2 + 16 + 8 + 4 + 8; // = 48, MAC-covered
const MAC_LEN: usize = 32;
const TOTAL_LEN: usize = BODY_LEN + MAC_LEN; // = 80

/// The device configuration record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    /// Stable per-device identifier (bound into every record's AAD).
    pub device_uuid: [u8; 16],
    /// Device capacity in logical blocks.
    pub capacity_blocks: u64,
    /// Current key epoch (records seal under this; reads resolve per-record).
    pub current_epoch: u32,
    /// Monotonic config-change counter. Not anchored externally, so it does
    /// not by itself detect a rolled-back superblock (see the module docs).
    pub generation: u64,
}

impl Superblock {
    /// Create a fresh superblock (`epoch = 0`, `generation = 0`).
    pub fn create(device_uuid: [u8; 16], capacity_blocks: u64) -> Self {
        Self {
            device_uuid,
            capacity_blocks,
            current_epoch: 0,
            generation: 0,
        }
    }

    /// Capacity in bytes (`capacity_blocks * LOGICAL_BLOCK_SIZE`), saturating.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_blocks
            .saturating_mul(teagarden_blockdev::LOGICAL_BLOCK_SIZE)
    }

    /// Advance the key epoch and bump the generation (rotation). Fails closed if
    /// either counter would overflow — the counters must stay monotonic (a wrap
    /// would make any future generation comparison meaningless). Atomic: neither field changes unless both advance.
    pub fn rotate_epoch(&mut self) -> Result<()> {
        let epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or_else(|| DeviceError::Corruption("epoch counter exhausted".into()))?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| DeviceError::Corruption("generation counter exhausted".into()))?;
        self.current_epoch = epoch;
        self.generation = generation;
        Ok(())
    }

    /// Change the capacity and bump the generation (resize). Fails closed if the
    /// generation would overflow.
    pub fn set_capacity(&mut self, capacity_blocks: u64) -> Result<()> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| DeviceError::Corruption("generation counter exhausted".into()))?;
        self.capacity_blocks = capacity_blocks;
        self.generation = generation;
        Ok(())
    }

    fn body(&self) -> [u8; BODY_LEN] {
        let mut b = [0u8; BODY_LEN];
        b[0..8].copy_from_slice(MAGIC);
        b[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        // 10..12 reserved (zero)
        b[12..28].copy_from_slice(&self.device_uuid);
        b[28..36].copy_from_slice(&self.capacity_blocks.to_le_bytes());
        b[36..40].copy_from_slice(&self.current_epoch.to_le_bytes());
        b[40..48].copy_from_slice(&self.generation.to_le_bytes());
        b
    }

    /// Serialize + MAC the superblock under `integrity_key`. Returns 80 bytes.
    pub fn seal(&self, integrity_key: &SymmetricKey) -> Vec<u8> {
        let body = self.body();
        let mac = blake3::keyed_hash(integrity_key.as_bytes(), &body);
        let mut out = Vec::with_capacity(TOTAL_LEN);
        out.extend_from_slice(&body);
        out.extend_from_slice(mac.as_bytes());
        out
    }

    /// Verify the MAC and parse a sealed superblock. Fails closed on any
    /// structural or authentication error (a forged or short blob). An older,
    /// authentic superblock passes — rollback is not detected here.
    pub fn open(blob: &[u8], integrity_key: &SymmetricKey) -> Result<Self> {
        if blob.len() != TOTAL_LEN {
            return Err(DeviceError::Corruption(format!(
                "superblock length {} != {TOTAL_LEN}",
                blob.len()
            )));
        }
        let (body, mac) = blob.split_at(BODY_LEN);
        if &body[0..8] != MAGIC {
            return Err(DeviceError::Corruption("bad superblock magic".into()));
        }
        let stored = <[u8; 32]>::try_from(mac).unwrap();
        let computed = blake3::keyed_hash(integrity_key.as_bytes(), body);
        // blake3::Hash equality is constant-time.
        if computed != blake3::Hash::from(stored) {
            return Err(DeviceError::Corruption("superblock MAC mismatch".into()));
        }
        let version = u16::from_le_bytes([body[8], body[9]]);
        if version != FORMAT_VERSION {
            return Err(DeviceError::Corruption(format!(
                "unsupported superblock version {version}"
            )));
        }
        let mut device_uuid = [0u8; 16];
        device_uuid.copy_from_slice(&body[12..28]);
        Ok(Self {
            device_uuid,
            capacity_blocks: u64::from_le_bytes(body[28..36].try_into().unwrap()),
            current_epoch: u32::from_le_bytes(body[36..40].try_into().unwrap()),
            generation: u64::from_le_bytes(body[40..48].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ik() -> SymmetricKey {
        SymmetricKey::from_bytes([0x5a; 32])
    }

    #[test]
    fn seal_open_round_trip() {
        let sb = Superblock::create([3u8; 16], 1_000_000);
        let blob = sb.seal(&ik());
        assert_eq!(blob.len(), TOTAL_LEN);
        assert_eq!(Superblock::open(&blob, &ik()).unwrap(), sb);
    }

    #[test]
    fn rotate_and_resize_bump_generation() {
        let mut sb = Superblock::create([0u8; 16], 100);
        assert_eq!((sb.current_epoch, sb.generation), (0, 0));
        sb.rotate_epoch().unwrap();
        assert_eq!((sb.current_epoch, sb.generation), (1, 1));
        sb.set_capacity(200).unwrap();
        assert_eq!((sb.capacity_blocks, sb.generation), (200, 2));
        // survives a reseal/reopen
        let blob = sb.seal(&ik());
        assert_eq!(Superblock::open(&blob, &ik()).unwrap(), sb);
    }

    #[test]
    fn tamper_and_wrong_key_fail_closed() {
        let sb = Superblock::create([1u8; 16], 4096);
        let blob = sb.seal(&ik());

        // flip a capacity byte → MAC mismatch (cannot shrink capacity undetected)
        let mut bad = blob.clone();
        bad[28] ^= 0xFF;
        assert!(Superblock::open(&bad, &ik()).is_err());

        // wrong integrity key
        let wrong = SymmetricKey::from_bytes([0u8; 32]);
        assert!(Superblock::open(&blob, &wrong).is_err());

        // truncated / oversized blobs are rejected, not panicked
        assert!(Superblock::open(&blob[..TOTAL_LEN - 1], &ik()).is_err());
        assert!(Superblock::open(&[0u8; 8], &ik()).is_err());
    }

    #[test]
    fn capacity_bytes_saturates() {
        let sb = Superblock::create([0u8; 16], u64::MAX);
        // must not panic on overflow
        assert_eq!(sb.capacity_bytes(), u64::MAX);
    }

    #[test]
    fn counters_fail_closed_at_max_not_wrap() {
        // epoch at max → rotate fails; nothing changes (no wrap to 0, atomic)
        let mut sb = Superblock::create([0u8; 16], 10);
        sb.current_epoch = u32::MAX;
        let gen_before = sb.generation;
        assert!(sb.rotate_epoch().is_err());
        assert_eq!(sb.current_epoch, u32::MAX);
        assert_eq!(sb.generation, gen_before);

        // generation at max → both rotate and resize fail closed
        let mut sb2 = Superblock::create([0u8; 16], 10);
        sb2.generation = u64::MAX;
        assert!(sb2.rotate_epoch().is_err());
        assert!(sb2.set_capacity(20).is_err());
        assert_eq!(sb2.generation, u64::MAX);
        assert_eq!(sb2.capacity_blocks, 10); // resize did not apply
    }
}
