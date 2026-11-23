//! `DeviceHead` — the barrier-consistent cloud watermark (P1.8 / P1.16, M2d-2).
//!
//! The `DeviceHead` is the device's **cloud-recoverable point**. Uploads are
//! asynchronous and reordered, so the set of cloud-confirmed segments is an
//! arbitrary *subset*, not a prefix — and a fresh machine that recovered to an
//! arbitrary subset could see a committed filesystem journal sitting over data
//! that never uploaded (silent corruption). The head fixes this: it pins a
//! **barrier-consistent prefix** of the write history — the state as of the
//! highest **watermark** segment `W` for which segments `1..=W` are *all*
//! confirmed — and carries everything a fresh machine needs to reconstruct that
//! exact prefix state:
//!
//! - the device config (uuid, capacity, epoch, `next_segment_id`, generation),
//! - the **FTL checkpoint** for the prefix (the LBA → physical map, built by
//!   *replaying* the op-log up to the watermark, NOT by filtering the live FTL —
//!   see [`crate::device::TeaGardenDevice::checkpoint`]), and
//! - the **catalog subset** (`segment_id → message_id`) for the confirmed prefix
//!   segments, so the reader can fetch them.
//!
//! The whole body is AEAD-sealed under the meta key (the FTL checkpoint contains
//! LBAs, which the threat model keeps encrypted at rest); the tag also
//! authenticates the `generation` / `watermark` so they cannot be forged.
//!
//! **Replay is possible (M3).** The AAD binds only the context and the
//! `device_uuid` — not a message id, a generation the reader already knows, or
//! anything else fresh — so every head this device ever published stays a
//! valid input to `recover_from_head`. Whoever chooses the head id (the
//! operator, a stale registry entry, or a provider that controls the channel)
//! can recover an OLDER authentic prefix, silently losing everything after it
//! (`device::tests::superblock_and_head_rollback_are_accepted`). The
//! `head_generation` counter is **reserved** for local freshness comparison
//! (higher = fresher) but is not yet persisted across `open()`, so it is advisory
//! only — not load-bearing for any current decision. Consuming it, and defeating
//! an *active* provider that serves a stale-but-authentic head, is the opt-in
//! anti-rollback / pinned-head track (P2.6 / P3.2), out of scope here.
//!
//! The head is a **prefix ⊆ staging**: a fresh-machine recovery lands at the
//! watermark and loses the unsynced tail by design (the local-fast durability
//! contract). A same-machine restart still prefers the local staging log
//! ([`crate::device::TeaGardenDevice::open`]), which is exact.

use rand::rngs::OsRng;
use rand::RngCore;

use teagarden_core::crypto::aead;
use teagarden_core::crypto::keys::SymmetricKey;

use crate::error::{DeviceError, Result};
use crate::ftl::Phys;

const MAGIC: &[u8; 8] = b"TGDEVHD1";
const FORMAT_VERSION: u16 = 1;
const HEAD_AAD_CONTEXT: &[u8] = b"tgdev-head-v1";

/// One extent of the FTL checkpoint: `[lba, lba+lba_count)` maps to `phys`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadExtent {
    pub lba: u64,
    pub lba_count: u64,
    pub phys: Phys,
}

/// The barrier-consistent cloud watermark record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceHead {
    /// Stable device identity.
    pub device_uuid: [u8; 16],
    /// Device config generation (matches the superblock at checkpoint time).
    pub generation: u64,
    /// Head counter for local freshness comparison (higher = fresher). Advisory
    /// only until P2.6/P3.2 consume it — the device does not yet persist its
    /// counter across `open()`. The head is authenticated + a consistent prefix
    /// regardless of this field.
    pub head_generation: u64,
    /// Device capacity in logical blocks (as of the watermark).
    pub capacity_blocks: u64,
    /// Current key epoch (as of the watermark).
    pub current_epoch: u32,
    /// The next segment id to allocate (above every id ever used).
    pub next_segment_id: u64,
    /// Highest segment id `W` such that segments `1..=W` are ALL confirmed.
    pub watermark: u64,
    /// The FTL checkpoint for the prefix (LBA order, non-overlapping).
    pub extents: Vec<HeadExtent>,
    /// `segment_id → message_id` for confirmed segments in the prefix.
    pub catalog: Vec<(u64, i64)>,
}

impl DeviceHead {
    fn aad(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEAD_AAD_CONTEXT.len() + 16);
        v.extend_from_slice(HEAD_AAD_CONTEXT);
        v.extend_from_slice(&self.device_uuid);
        v
    }

    fn body(&self) -> Result<Vec<u8>> {
        let extent_count = u32::try_from(self.extents.len())
            .map_err(|_| DeviceError::Corruption("head extent count exceeds u32".into()))?;
        let catalog_count = u32::try_from(self.catalog.len())
            .map_err(|_| DeviceError::Corruption("head catalog count exceeds u32".into()))?;
        let mut b = Vec::with_capacity(84 + self.extents.len() * 44 + self.catalog.len() * 16);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // reserved
        b.extend_from_slice(&self.device_uuid);
        b.extend_from_slice(&self.generation.to_le_bytes());
        b.extend_from_slice(&self.head_generation.to_le_bytes());
        b.extend_from_slice(&self.capacity_blocks.to_le_bytes());
        b.extend_from_slice(&self.current_epoch.to_le_bytes());
        b.extend_from_slice(&self.next_segment_id.to_le_bytes());
        b.extend_from_slice(&self.watermark.to_le_bytes());
        b.extend_from_slice(&extent_count.to_le_bytes());
        for e in &self.extents {
            b.extend_from_slice(&e.lba.to_le_bytes());
            b.extend_from_slice(&e.lba_count.to_le_bytes());
            b.extend_from_slice(&e.phys.segment_id.to_le_bytes());
            b.extend_from_slice(&e.phys.record_off.to_le_bytes());
            b.extend_from_slice(&e.phys.data_off.to_le_bytes());
            b.extend_from_slice(&e.phys.epoch.to_le_bytes());
        }
        b.extend_from_slice(&catalog_count.to_le_bytes());
        for &(seg, mid) in &self.catalog {
            b.extend_from_slice(&seg.to_le_bytes());
            b.extend_from_slice(&mid.to_le_bytes());
        }
        Ok(b)
    }

    /// Serialize + AEAD-seal the head under `meta_key`. The ciphertext is the
    /// Telegram document uploaded as the head. The body is padded up to a coarse
    /// bucket before sealing so the on-wire ciphertext length reveals only a coarse
    /// size class, not the exact FTL-extent / catalog counts (M2e wire opacity);
    /// the trailing padding is inside the AEAD (authenticated) and ignored on parse.
    pub fn seal(&self, meta_key: &SymmetricKey) -> Result<Vec<u8>> {
        const HEAD_BUCKET: usize = 4096;
        let mut body = self.body()?;
        let target = body.len().div_ceil(HEAD_BUCKET) * HEAD_BUCKET;
        if target > body.len() {
            let mut pad = vec![0u8; target - body.len()];
            OsRng.fill_bytes(&mut pad);
            body.extend_from_slice(&pad);
        }
        aead::encrypt(meta_key, &body, &self.aad()).map_err(|e| DeviceError::Crypto(e.to_string()))
    }

    /// Decrypt + parse a sealed head. Fails closed (never partial state) on any
    /// authentication or structural error — a forged, truncated, or wrong-device
    /// head is rejected. The caller supplies the expected `device_uuid` (from its
    /// key material / handle); it is bound in the AAD and re-checked after parse.
    pub fn open(blob: &[u8], meta_key: &SymmetricKey, device_uuid: &[u8; 16]) -> Result<Self> {
        let mut aad = Vec::with_capacity(HEAD_AAD_CONTEXT.len() + 16);
        aad.extend_from_slice(HEAD_AAD_CONTEXT);
        aad.extend_from_slice(device_uuid);
        let body =
            aead::decrypt(meta_key, blob, &aad).map_err(|e| DeviceError::Crypto(e.to_string()))?;
        Self::parse(&body, device_uuid)
    }

    fn parse(b: &[u8], expect_uuid: &[u8; 16]) -> Result<Self> {
        let err = || DeviceError::Corruption("malformed device head".into());
        // fixed prefix through extent_count: magic(8)+ver(2)+rsvd(2)+uuid(16)
        //   +gen(8)+hgen(8)+cap(8)+epoch(4)+next(8)+watermark(8)+extent_count(4) = 76
        if b.len() < 76 || &b[0..8] != MAGIC {
            return Err(err());
        }
        let version = u16::from_le_bytes([b[8], b[9]]);
        if version != FORMAT_VERSION {
            return Err(DeviceError::Corruption(format!(
                "unsupported device head version {version}"
            )));
        }
        let mut device_uuid = [0u8; 16];
        device_uuid.copy_from_slice(&b[12..28]);
        if &device_uuid != expect_uuid {
            return Err(DeviceError::Corruption("device head uuid mismatch".into()));
        }
        let ru64 = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let generation = ru64(28);
        let head_generation = ru64(36);
        let capacity_blocks = ru64(44);
        let current_epoch = u32::from_le_bytes(b[52..56].try_into().unwrap());
        let next_segment_id = ru64(56);
        let watermark = ru64(64);
        let extent_count = u32::from_le_bytes(b[72..76].try_into().unwrap()) as usize;

        let mut pos = 76usize;
        let extents_bytes = extent_count.checked_mul(44).ok_or_else(err)?;
        let cat_count_at = pos.checked_add(extents_bytes).ok_or_else(err)?;
        if cat_count_at + 4 > b.len() {
            return Err(err());
        }
        let mut extents = Vec::with_capacity(extent_count);
        for _ in 0..extent_count {
            let g = |o: usize| u64::from_le_bytes(b[pos + o..pos + o + 8].try_into().unwrap());
            let epoch = u32::from_le_bytes(b[pos + 40..pos + 44].try_into().unwrap());
            extents.push(HeadExtent {
                lba: g(0),
                lba_count: g(8),
                phys: Phys {
                    segment_id: g(16),
                    record_off: g(24),
                    data_off: g(32),
                    epoch,
                },
            });
            pos += 44;
        }
        let catalog_count = u32::from_le_bytes(b[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let cat_bytes = catalog_count.checked_mul(16).ok_or_else(err)?;
        let end = pos.checked_add(cat_bytes).ok_or_else(err)?;
        // Trailing bytes beyond `end` are opacity padding (authenticated inside the
        // AEAD) — tolerate them, but the declared content must fit within the body.
        if end > b.len() {
            return Err(DeviceError::Corruption(format!(
                "device head content end {end} exceeds body length {} ({catalog_count} catalog entries)",
                b.len()
            )));
        }
        let mut catalog = Vec::with_capacity(catalog_count);
        for _ in 0..catalog_count {
            let seg = u64::from_le_bytes(b[pos..pos + 8].try_into().unwrap());
            let mid = i64::from_le_bytes(b[pos + 8..pos + 16].try_into().unwrap());
            catalog.push((seg, mid));
            pos += 16;
        }
        Ok(Self {
            device_uuid,
            generation,
            head_generation,
            capacity_blocks,
            current_epoch,
            next_segment_id,
            watermark,
            extents,
            catalog,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> SymmetricKey {
        SymmetricKey::from_bytes([0x2a; 32])
    }

    fn sample() -> DeviceHead {
        DeviceHead {
            device_uuid: [7u8; 16],
            generation: 3,
            head_generation: 5,
            capacity_blocks: 4096,
            current_epoch: 2,
            next_segment_id: 9,
            watermark: 4,
            extents: vec![
                HeadExtent {
                    lba: 0,
                    lba_count: 3,
                    phys: Phys {
                        segment_id: 1,
                        record_off: 40,
                        data_off: 0,
                        epoch: 0,
                    },
                },
                HeadExtent {
                    lba: 10,
                    lba_count: 2,
                    phys: Phys {
                        segment_id: 4,
                        record_off: 128,
                        data_off: 4096,
                        epoch: 2,
                    },
                },
            ],
            catalog: vec![(1, 1001), (2, 1002), (3, 1003), (4, 1004)],
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let h = sample();
        let blob = h.seal(&mk()).unwrap();
        let got = DeviceHead::open(&blob, &mk(), &[7u8; 16]).unwrap();
        assert_eq!(got, h);
    }

    #[test]
    fn empty_head_round_trips() {
        let mut h = sample();
        h.extents.clear();
        h.catalog.clear();
        h.watermark = 0;
        let blob = h.seal(&mk()).unwrap();
        assert_eq!(DeviceHead::open(&blob, &mk(), &[7u8; 16]).unwrap(), h);
    }

    // Opacity: the sealed head is padded to a coarse bucket, so two heads with
    // different extent/catalog counts (that fit the same bucket) seal to the SAME
    // ciphertext length — the size does not leak FTL fragmentation or segment count.
    #[test]
    fn head_length_is_bucketed_not_count_revealing() {
        let mut small = sample();
        small.extents.truncate(1);
        small.catalog.truncate(1);
        let big = sample(); // 2 extents, 4 catalog entries
        let a = small.seal(&mk()).unwrap();
        let b = big.seal(&mk()).unwrap();
        assert_eq!(a.len(), b.len()); // same bucket → same on-wire length
        assert_eq!(a.len() % 4096, aead::NONCE_SIZE + aead::TAG_SIZE); // bucketed body + AEAD overhead
                                                                       // and both still round-trip despite the padding
        assert_eq!(DeviceHead::open(&a, &mk(), &[7u8; 16]).unwrap(), small);
        assert_eq!(DeviceHead::open(&b, &mk(), &[7u8; 16]).unwrap(), big);
    }

    #[test]
    fn wrong_key_and_tamper_fail_closed() {
        let h = sample();
        let blob = h.seal(&mk()).unwrap();

        // wrong meta key
        let wrong = SymmetricKey::from_bytes([0u8; 32]);
        assert!(DeviceHead::open(&blob, &wrong, &[7u8; 16]).is_err());

        // wrong device uuid (AAD mismatch)
        assert!(DeviceHead::open(&blob, &mk(), &[9u8; 16]).is_err());

        // a flipped ciphertext byte fails the AEAD tag
        let mut bad = blob.clone();
        let i = bad.len() / 2;
        bad[i] ^= 0xFF;
        assert!(DeviceHead::open(&bad, &mk(), &[7u8; 16]).is_err());

        // truncated / too-short blobs rejected, not panicked
        assert!(DeviceHead::open(&blob[..blob.len() - 1], &mk(), &[7u8; 16]).is_err());
        assert!(DeviceHead::open(&[0u8; 4], &mk(), &[7u8; 16]).is_err());
    }
}
