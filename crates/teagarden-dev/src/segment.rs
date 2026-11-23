//! On-wire segment format **v2 — fully opaque** (P1.3 + M2e).
//!
//! A **segment** is one Telegram document. None of its metadata (device
//! identity, segment ordering, key epoch, record boundaries, record count) is
//! readable from the document: every byte of it is AEAD ciphertext, keyed-MAC
//! output or random padding, and the upload filename is 12 random hex
//! characters (see [`crate::device`]). What stays visible is that it exists, its
//! size (the segment target, see PADDING) and when it was uploaded.
//!
//! ```text
//! ┌ SEALED HEADER (fixed 80 B) ─────────────────────────────────────────────────┐
//! │ AEAD(meta_key, magic‖ver‖segment_id‖epoch‖device_uuid, aad="tgdev-seghdr-v2")│
//! ├ RECORDS ─────────────────────────────────────────────────────────────────────┤
//! │ sealed records concatenated back-to-back — NO plaintext length frames.        │
//! │ each = nonce‖ciphertext‖tag; its offset+length live in the encrypted index.   │
//! ├ PADDING ──────────────────────────────────────────────────────────────────────┤
//! │ random bytes so the document size rounds up to the segment target: every       │
//! │ segment has the same size, however full it was when sealed. MAC-covered.       │
//! ├ SEALED INDEX ──────────────────────────────────────────────────────────────────┤
//! │ AEAD(meta_key, Vec<RecordLoc>, aad="tgdev-idx-v2"‖segment_id‖epoch‖uuid)        │
//! ├ SEALED TRAILER (fixed 62 B) ────────────────────────────────────────────────────┤
//! │ AEAD(meta_key, magic‖ver‖index_off‖index_len, aad="tgdev-segtrl-v2")            │
//! ├ MAC (32 B) ──────────────────────────────────────────────────────────────────────┤
//! │ keyed-BLAKE3(integrity_key) over everything before it                            │
//! └───────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Read bootstrap (all fixed-position): verify the trailing MAC, decrypt the
//! fixed-size trailer just before it to learn where the index is, decrypt the
//! index for the record map, decrypt the fixed-size header for identity. A record
//! is read by slicing `[record_off, record_off + plain_len + RECORD_OVERHEAD)` —
//! the offset/length come from the (encrypted) index, so a **ranged** read of one
//! record needs no plaintext framing (this is what P3's `download_range` uses).
//!
//! The record AEAD ([`crate::sector_crypto`]) binds `device_uuid ‖ epoch ‖
//! segment_id ‖ record_off ‖ lba_start ‖ plain_len`; that binding — not the
//! header — is the anti-relocation / anti-substitution authority, and it holds on
//! the ranged read path where the header is never downloaded. There is **no v1
//! reader**: the plaintext-framed v1 format never reached real Telegram, so v2 is
//! a clean cutover.

use rand::rngs::OsRng;
use rand::RngCore;

use teagarden_blockdev::LOGICAL_BLOCK_SIZE;
use teagarden_core::crypto::aead;
use teagarden_core::crypto::keys::SymmetricKey;

use crate::error::{DeviceError, Result};
use crate::sector_crypto::{open_record, seal_record, RecordAad, RECORD_OVERHEAD};

const MAGIC: &[u8; 8] = b"TGDEVSG2";
const MAGIC_TRAILER: &[u8; 8] = b"TGDEVTR2";
const FORMAT_VERSION: u16 = 2;

/// Header plaintext: magic(8)+ver(2)+rsvd(2)+segment_id(8)+epoch(4)+uuid(16).
const HEADER_PLAIN_LEN: usize = 8 + 2 + 2 + 8 + 4 + 16; // 40
/// Sealed header length (fixed): nonce + header plaintext + tag.
pub const HEADER_LEN: usize = aead::NONCE_SIZE + HEADER_PLAIN_LEN + aead::TAG_SIZE; // 80
/// Trailer plaintext: magic(8)+ver(2)+index_off(8)+index_len(4).
const TRAILER_PLAIN_LEN: usize = 8 + 2 + 8 + 4; // 22
/// Sealed trailer length (fixed): nonce + trailer plaintext + tag.
pub const TRAILER_LEN: usize = aead::NONCE_SIZE + TRAILER_PLAIN_LEN + aead::TAG_SIZE; // 62
/// Trailing keyed-BLAKE3 MAC length.
pub const MAC_LEN: usize = 32;
/// Smallest possible v2 segment: sealed header + (empty index sealed) + trailer + MAC.
const MIN_SEGMENT_LEN: usize = HEADER_LEN + TRAILER_LEN + MAC_LEN;

const HEADER_AAD: &[u8] = b"tgdev-seghdr-v2";
const TRAILER_AAD: &[u8] = b"tgdev-segtrl-v2";
const INDEX_AAD_CONTEXT: &[u8] = b"tgdev-idx-v2";

fn crypto_err(e: impl std::fmt::Display) -> DeviceError {
    DeviceError::Crypto(e.to_string())
}

/// One record's entry in the segment index: where its frame lives and which
/// logical blocks it covers. 32 bytes serialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordLoc {
    /// Byte offset of the sealed record within the segment blob.
    pub record_off: u64,
    /// First logical block this record covers.
    pub lba_start: u64,
    /// Number of logical blocks this record covers.
    pub lba_count: u64,
    /// Plaintext length of the record in bytes.
    pub plain_len: u64,
}

/// The parsed (decrypted) segment header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentHeader {
    /// Segment id (Telegram-agnostic logical id).
    pub segment_id: u64,
    /// Key epoch every record in this segment is sealed under.
    pub epoch: u32,
    /// The owning device's uuid.
    pub device_uuid: [u8; 16],
}

fn header_plaintext(h: &SegmentHeader) -> [u8; HEADER_PLAIN_LEN] {
    let mut b = [0u8; HEADER_PLAIN_LEN];
    b[0..8].copy_from_slice(MAGIC);
    b[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    // 10..12 reserved (zero)
    b[12..20].copy_from_slice(&h.segment_id.to_le_bytes());
    b[20..24].copy_from_slice(&h.epoch.to_le_bytes());
    b[24..40].copy_from_slice(&h.device_uuid);
    b
}

fn parse_header_plaintext(b: &[u8]) -> Result<SegmentHeader> {
    if b.len() != HEADER_PLAIN_LEN || &b[0..8] != MAGIC {
        return Err(DeviceError::Corruption("bad segment header".into()));
    }
    let version = u16::from_le_bytes([b[8], b[9]]);
    if version != FORMAT_VERSION {
        return Err(DeviceError::Corruption(format!(
            "unsupported segment format version {version}"
        )));
    }
    let mut device_uuid = [0u8; 16];
    device_uuid.copy_from_slice(&b[24..40]);
    Ok(SegmentHeader {
        segment_id: u64::from_le_bytes(b[12..20].try_into().unwrap()),
        epoch: u32::from_le_bytes(b[20..24].try_into().unwrap()),
        device_uuid,
    })
}

fn index_aad(h: &SegmentHeader) -> Vec<u8> {
    let mut v = Vec::with_capacity(INDEX_AAD_CONTEXT.len() + 8 + 4 + 16);
    v.extend_from_slice(INDEX_AAD_CONTEXT);
    v.extend_from_slice(&h.segment_id.to_le_bytes());
    v.extend_from_slice(&h.epoch.to_le_bytes());
    v.extend_from_slice(&h.device_uuid);
    v
}

fn serialize_index(index: &[RecordLoc]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + index.len() * 32);
    v.extend_from_slice(&(index.len() as u32).to_le_bytes());
    for r in index {
        v.extend_from_slice(&r.record_off.to_le_bytes());
        v.extend_from_slice(&r.lba_start.to_le_bytes());
        v.extend_from_slice(&r.lba_count.to_le_bytes());
        v.extend_from_slice(&r.plain_len.to_le_bytes());
    }
    v
}

fn deserialize_index(b: &[u8]) -> Result<Vec<RecordLoc>> {
    if b.len() < 4 {
        return Err(DeviceError::Corruption("index too short".into()));
    }
    let count = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
    let need = 4 + count * 32;
    if b.len() != need {
        return Err(DeviceError::Corruption(format!(
            "index length {} != expected {} for {} records",
            b.len(),
            need,
            count
        )));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = 4;
    for _ in 0..count {
        let ru = |o: usize| u64::from_le_bytes(b[p + o..p + o + 8].try_into().unwrap());
        out.push(RecordLoc {
            record_off: ru(0),
            lba_start: ru(8),
            lba_count: ru(16),
            plain_len: ru(24),
        });
        p += 32;
    }
    Ok(out)
}

/// Builds a segment by appending sealed records, then finalizes it into the
/// opaque v2 layout.
pub struct SegmentBuilder {
    /// The growing blob. Starts with an 80-byte placeholder for the sealed header
    /// (filled in at `seal`) so record offsets are correct as records append.
    blob: Vec<u8>,
    index: Vec<RecordLoc>,
    header: SegmentHeader,
    data_key: SymmetricKey,
}

impl SegmentBuilder {
    /// Start a new segment. `data_key` seals the records; the header/index/trailer
    /// are sealed with the meta key at `seal`.
    pub fn new(segment_id: u64, device_uuid: [u8; 16], epoch: u32, data_key: SymmetricKey) -> Self {
        let header = SegmentHeader {
            segment_id,
            epoch,
            device_uuid,
        };
        Self {
            // Reserve the sealed-header region; records begin at HEADER_LEN.
            blob: vec![0u8; HEADER_LEN],
            index: Vec::new(),
            header,
            data_key,
        }
    }

    /// Append a record covering `[lba_start, lba_start+lba_count)`. Returns
    /// `(record_off, sealed_record_bytes)` — the byte offset of the sealed record
    /// within the segment, and the sealed bytes so the caller can also durably
    /// stage them ([`crate::staging`]) without re-sealing. No length frame is
    /// written; the offset+length are recorded in the (encrypted) index.
    pub fn append_record(
        &mut self,
        lba_start: u64,
        lba_count: u64,
        plaintext: &[u8],
    ) -> Result<(u64, Vec<u8>)> {
        if lba_count == 0
            || lba_count.checked_mul(LOGICAL_BLOCK_SIZE) != Some(plaintext.len() as u64)
        {
            return Err(DeviceError::Corruption(format!(
                "record must hold exactly lba_count * {LOGICAL_BLOCK_SIZE} bytes: \
                 got {} bytes for lba_count {}",
                plaintext.len(),
                lba_count
            )));
        }
        let record_off = self.blob.len() as u64;
        let aad = RecordAad {
            device_uuid: self.header.device_uuid,
            epoch: self.header.epoch,
            segment_id: self.header.segment_id,
            record_off,
            lba_start,
            plain_len: plaintext.len() as u64,
        };
        let sealed = seal_record(&self.data_key, plaintext, &aad)?;
        self.blob.extend_from_slice(&sealed);
        self.index.push(RecordLoc {
            record_off,
            lba_start,
            lba_count,
            plain_len: plaintext.len() as u64,
        });
        Ok((record_off, sealed))
    }

    /// Append a record whose bytes are ALREADY sealed — recovery re-framing.
    ///
    /// [`crate::device::TeaGardenDevice::open`] rebuilds an unconfirmed segment from
    /// the sealed record bytes kept in the staging log, without decrypting or
    /// re-sealing. Appending the same records in the same order reproduces the
    /// identical `record_off`s (the caller asserts the returned offset matches the
    /// mapping it is restoring). The sealed length is checked against `lba_count`.
    pub fn append_sealed_record(
        &mut self,
        lba_start: u64,
        lba_count: u64,
        sealed_record: &[u8],
    ) -> Result<u64> {
        let plain_len = lba_count
            .checked_mul(LOGICAL_BLOCK_SIZE)
            .ok_or_else(|| DeviceError::Corruption("record lba_count overflow".into()))?;
        let expect = usize::try_from(plain_len)
            .ok()
            .and_then(|p| p.checked_add(RECORD_OVERHEAD))
            .ok_or_else(|| DeviceError::Corruption("record length overflow".into()))?;
        if lba_count == 0 || sealed_record.len() != expect {
            return Err(DeviceError::Corruption(format!(
                "sealed record length {} != expected {expect} for lba_count {lba_count}",
                sealed_record.len()
            )));
        }
        let record_off = self.blob.len() as u64;
        self.blob.extend_from_slice(sealed_record);
        self.index.push(RecordLoc {
            record_off,
            lba_start,
            lba_count,
            plain_len,
        });
        Ok(record_off)
    }

    /// Undo the LAST [`Self::append_record`] / [`Self::append_sealed_record`],
    /// whose returned offset was `record_off` (M5). Used when the record could
    /// not be durably staged: leaving it in the builder would shift every later
    /// record's offset away from what the staging log recorded, and a crash
    /// before upload would then make recovery fail ("record_off != staged").
    pub fn rollback_record(&mut self, record_off: u64) -> Result<()> {
        match self.index.last() {
            Some(loc) if loc.record_off == record_off => {
                self.blob.truncate(record_off as usize);
                self.index.pop();
                Ok(())
            }
            _ => Err(DeviceError::Corruption(format!(
                "rollback_record({record_off}) is not the last record"
            ))),
        }
    }

    /// Current blob size in bytes (sealed header + records so far) — drives the
    /// seal threshold (`SEGMENT_TARGET` / `SEGMENT_HARD_CAP`).
    pub fn current_len(&self) -> u64 {
        self.blob.len() as u64
    }

    /// Number of records appended so far.
    pub fn record_count(&self) -> usize {
        self.index.len()
    }

    /// Finalize into the opaque v2 blob: seal the header into its reserved region,
    /// optionally pad the document up to `pad_to` bytes (random, MAC-covered), seal
    /// the index and the fixed trailer, then MAC the whole thing. Consumes the
    /// builder.
    pub fn seal(
        mut self,
        meta_key: &SymmetricKey,
        integrity_key: &SymmetricKey,
        pad_to: Option<u64>,
    ) -> Result<Vec<u8>> {
        // 1) Seal the header into the reserved 80-byte prefix.
        let header_ct = aead::encrypt(meta_key, &header_plaintext(&self.header), HEADER_AAD)
            .map_err(crypto_err)?;
        debug_assert_eq!(header_ct.len(), HEADER_LEN);
        if header_ct.len() != HEADER_LEN {
            return Err(DeviceError::Corruption("sealed header wrong length".into()));
        }
        self.blob[..HEADER_LEN].copy_from_slice(&header_ct);

        // 2) Seal the index (its length is not observable — it sits between random
        //    padding and the fixed trailer, and only the sealed trailer says where).
        let index_ct = aead::encrypt(
            meta_key,
            &serialize_index(&self.index),
            &index_aad(&self.header),
        )
        .map_err(crypto_err)?;
        let index_len = u32::try_from(index_ct.len())
            .map_err(|_| DeviceError::Corruption("index exceeds u32 length".into()))?;

        // 3) Pad the document up to the bucket so a segment sealed early has the
        //    same size as a full one. Padding goes between the records and the
        //    index; `index_off` accounts for it and the MAC covers it.
        let records_end = self.blob.len();
        let unpadded = records_end
            .checked_add(index_ct.len())
            .and_then(|x| x.checked_add(TRAILER_LEN))
            .and_then(|x| x.checked_add(MAC_LEN))
            .ok_or_else(|| DeviceError::Corruption("segment length overflow".into()))?;
        let pad = match pad_to {
            Some(target) => (target as usize).saturating_sub(unpadded),
            None => 0,
        };
        if pad > 0 {
            let mut filler = vec![0u8; pad];
            OsRng.fill_bytes(&mut filler);
            self.blob.extend_from_slice(&filler);
        }

        // 4) Append the sealed index.
        let index_off = self.blob.len() as u64;
        self.blob.extend_from_slice(&index_ct);

        // 5) Append the fixed-size sealed trailer (locates the index).
        let mut trailer_plain = [0u8; TRAILER_PLAIN_LEN];
        trailer_plain[0..8].copy_from_slice(MAGIC_TRAILER);
        trailer_plain[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        trailer_plain[10..18].copy_from_slice(&index_off.to_le_bytes());
        trailer_plain[18..22].copy_from_slice(&index_len.to_le_bytes());
        let trailer_ct =
            aead::encrypt(meta_key, &trailer_plain, TRAILER_AAD).map_err(crypto_err)?;
        if trailer_ct.len() != TRAILER_LEN {
            return Err(DeviceError::Corruption(
                "sealed trailer wrong length".into(),
            ));
        }
        self.blob.extend_from_slice(&trailer_ct);

        // 6) MAC over everything, appended last.
        let mac = blake3::keyed_hash(integrity_key.as_bytes(), &self.blob);
        self.blob.extend_from_slice(mac.as_bytes());
        Ok(self.blob)
    }
}

// ── Ranged-read helpers (P3.1) ────────────────────────────────────────────────
//
// A ranged reader never holds the whole blob, so it cannot verify the trailing
// MAC. The integrity chain on this path is: trailer (fixed tail position,
// sealed, identity-UNBOUND) → index (identity-bound AAD — wrong segment/epoch/
// device fails closed) → record (fully position-bound AAD — the sole
// anti-substitution authority, per the M2e design). A hostile transport can
// only cause denial (a decrypt error), never wrong plaintext.

/// Parse the fixed-size sealed trailer (the `TRAILER_LEN` bytes just before the
/// trailing MAC) → `(index_off, index_len)`. The offsets are ABSOLUTE within
/// the segment blob; a tail-relative caller typically only uses `index_len`
/// (the index always ends exactly where the trailer begins).
pub fn open_trailer_ranged(sealed_trailer: &[u8], meta_key: &SymmetricKey) -> Result<(u64, u32)> {
    if sealed_trailer.len() != TRAILER_LEN {
        return Err(DeviceError::Corruption(format!(
            "trailer slice is {} bytes, expected {TRAILER_LEN}",
            sealed_trailer.len()
        )));
    }
    let plain = aead::decrypt(meta_key, sealed_trailer, TRAILER_AAD).map_err(crypto_err)?;
    if plain.len() != TRAILER_PLAIN_LEN || &plain[0..8] != MAGIC_TRAILER {
        return Err(DeviceError::Corruption("bad segment trailer".into()));
    }
    let tver = u16::from_le_bytes([plain[8], plain[9]]);
    if tver != FORMAT_VERSION {
        return Err(DeviceError::Corruption(format!(
            "unsupported segment trailer version {tver}"
        )));
    }
    let index_off = u64::from_le_bytes(plain[10..18].try_into().unwrap());
    let index_len = u32::from_le_bytes(plain[18..22].try_into().unwrap());
    Ok((index_off, index_len))
}

/// Decrypt + deserialize a segment index fetched by a ranged read, under the
/// EXPECTED identity (from the FTL / device state — the header is never
/// downloaded on this path). A substituted index — another segment's, another
/// epoch's, another device's — fails the AAD and is rejected.
pub fn open_index_ranged(
    index_ct: &[u8],
    meta_key: &SymmetricKey,
    segment_id: u64,
    epoch: u32,
    device_uuid: [u8; 16],
) -> Result<Vec<RecordLoc>> {
    let expected = SegmentHeader {
        segment_id,
        epoch,
        device_uuid,
    };
    let plain = aead::decrypt(meta_key, index_ct, &index_aad(&expected)).map_err(crypto_err)?;
    deserialize_index(&plain)
}

/// Open one ranged-fetched sealed record under the expected position AAD.
/// `sealed` must be exactly the `[record_off, record_off+plain_len+OVERHEAD)`
/// slice; the same structural checks as [`SegmentReader::read_record`] apply
/// (block granularity, checked lengths), minus blob bounds — the fetch bounds it.
pub fn open_record_ranged(
    sealed: &[u8],
    data_key: &SymmetricKey,
    device_uuid: [u8; 16],
    epoch: u32,
    segment_id: u64,
    loc: &RecordLoc,
) -> Result<Vec<u8>> {
    if loc.lba_count.checked_mul(LOGICAL_BLOCK_SIZE) != Some(loc.plain_len) {
        return Err(DeviceError::Corruption(
            "record loc lba_count inconsistent with plain_len".into(),
        ));
    }
    let expect = usize::try_from(loc.plain_len)
        .ok()
        .and_then(|p| p.checked_add(RECORD_OVERHEAD))
        .ok_or_else(|| DeviceError::Corruption("record length overflow".into()))?;
    if sealed.len() != expect {
        return Err(DeviceError::Corruption(format!(
            "ranged record fetch returned {} bytes, expected {expect} (short read fails closed)",
            sealed.len()
        )));
    }
    let aad = RecordAad {
        device_uuid,
        epoch,
        segment_id,
        record_off: loc.record_off,
        lba_start: loc.lba_start,
        plain_len: loc.plain_len,
    };
    open_record(data_key, sealed, &aad)
}

/// Reads a finalized v2 segment: verifies the trailing MAC, decrypts the fixed
/// trailer + header, and exposes the index + record reads. Borrows the blob.
pub struct SegmentReader<'a> {
    blob: &'a [u8],
    header: SegmentHeader,
    index_off: usize,
    index_len: usize,
}

impl<'a> SegmentReader<'a> {
    /// Verify the trailing MAC, decrypt the fixed trailer (to locate the index) and
    /// the fixed header (identity). Fails closed on any structural or
    /// authentication error. `meta_key` decrypts the header/trailer; `integrity_key`
    /// keys the MAC.
    pub fn open(
        blob: &'a [u8],
        meta_key: &SymmetricKey,
        integrity_key: &SymmetricKey,
    ) -> Result<Self> {
        if blob.len() < MIN_SEGMENT_LEN {
            return Err(DeviceError::Corruption(
                "segment shorter than header+trailer+mac".into(),
            ));
        }
        // 1) MAC over everything before the trailing 32 bytes (constant-time).
        let mac_start = blob.len() - MAC_LEN;
        let stored = <[u8; 32]>::try_from(&blob[mac_start..]).unwrap();
        let computed = blake3::keyed_hash(integrity_key.as_bytes(), &blob[..mac_start]);
        if computed != blake3::Hash::from(stored) {
            return Err(DeviceError::Corruption("segment MAC mismatch".into()));
        }
        // 2) Decrypt the fixed-size trailer sitting just before the MAC.
        let trailer_start = mac_start - TRAILER_LEN;
        let trailer_plain = aead::decrypt(meta_key, &blob[trailer_start..mac_start], TRAILER_AAD)
            .map_err(crypto_err)?;
        if trailer_plain.len() != TRAILER_PLAIN_LEN || &trailer_plain[0..8] != MAGIC_TRAILER {
            return Err(DeviceError::Corruption("bad segment trailer".into()));
        }
        let tver = u16::from_le_bytes([trailer_plain[8], trailer_plain[9]]);
        if tver != FORMAT_VERSION {
            return Err(DeviceError::Corruption(format!(
                "unsupported segment trailer version {tver}"
            )));
        }
        let index_off = u64::from_le_bytes(trailer_plain[10..18].try_into().unwrap()) as usize;
        let index_len = u32::from_le_bytes(trailer_plain[18..22].try_into().unwrap()) as usize;
        // The index must sit within the records/padding region, before the trailer.
        if index_off < HEADER_LEN || index_off.saturating_add(index_len) > trailer_start {
            return Err(DeviceError::Corruption(
                "segment index out of bounds".into(),
            ));
        }
        // 3) Decrypt the fixed-size header (identity).
        let header_plain =
            aead::decrypt(meta_key, &blob[..HEADER_LEN], HEADER_AAD).map_err(crypto_err)?;
        let header = parse_header_plaintext(&header_plain)?;
        Ok(Self {
            blob,
            header,
            index_off,
            index_len,
        })
    }

    /// The verified (decrypted) header.
    pub fn header(&self) -> &SegmentHeader {
        &self.header
    }

    /// Decrypt + return the record index (for FTL rebuild from the sealed blob).
    pub fn index(&self, meta_key: &SymmetricKey) -> Result<Vec<RecordLoc>> {
        let index_blob = &self.blob[self.index_off..self.index_off + self.index_len];
        let plain =
            aead::decrypt(meta_key, index_blob, &index_aad(&self.header)).map_err(crypto_err)?;
        deserialize_index(&plain)
    }

    /// Read + decrypt one record's plaintext, verifying its position AAD. The
    /// sealed extent is `[record_off, record_off + plain_len + RECORD_OVERHEAD)` —
    /// no length frame is read, so the identical slice is what a ranged read
    /// fetches over the network.
    pub fn read_record(&self, loc: &RecordLoc, data_key: &SymmetricKey) -> Result<Vec<u8>> {
        let oob = || DeviceError::Corruption("record frame out of bounds".into());
        // The loc must describe a block-granular record consistent with its own
        // `plain_len` (authenticated in the AAD below) — rejects a hand-built loc.
        if loc.lba_count.checked_mul(LOGICAL_BLOCK_SIZE) != Some(loc.plain_len) {
            return Err(DeviceError::Corruption(
                "record loc lba_count inconsistent with plain_len".into(),
            ));
        }
        let off = usize::try_from(loc.record_off).map_err(|_| oob())?;
        let sealed_len = usize::try_from(loc.plain_len)
            .ok()
            .and_then(|p| p.checked_add(RECORD_OVERHEAD))
            .ok_or_else(oob)?;
        let end = off.checked_add(sealed_len).ok_or_else(oob)?;
        // Records live in `[HEADER_LEN, index_off)`; padding beyond the records is
        // random bytes that would fail the AEAD anyway, but bound to index_off.
        if off < HEADER_LEN || end > self.index_off {
            return Err(oob());
        }
        let sealed = &self.blob[off..end];
        let aad = RecordAad {
            device_uuid: self.header.device_uuid,
            epoch: self.header.epoch,
            segment_id: self.header.segment_id,
            record_off: loc.record_off,
            lba_start: loc.lba_start,
            plain_len: loc.plain_len,
        };
        open_record(data_key, sealed, &aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (SymmetricKey, SymmetricKey, SymmetricKey) {
        (
            SymmetricKey::from_bytes([1u8; 32]), // data
            SymmetricKey::from_bytes([2u8; 32]), // meta
            SymmetricKey::from_bytes([3u8; 32]), // integrity
        )
    }

    fn build_three() -> (Vec<u8>, [Vec<u8>; 3]) {
        let (dk, mk, ik) = keys();
        let mut b = SegmentBuilder::new(77, [9u8; 16], 4, dk);
        let r0 = vec![0xa0u8; 4096]; // 1 block
        let r1 = vec![0xb1u8; 8192]; // 2 blocks
        let r2 = vec![0xc2u8; 65536]; // 16 blocks
        b.append_record(0, 1, &r0).unwrap();
        b.append_record(1, 2, &r1).unwrap();
        b.append_record(3, 16, &r2).unwrap();
        assert_eq!(b.record_count(), 3);
        (b.seal(&mk, &ik, None).unwrap(), [r0, r1, r2])
    }

    // Seal → reopen → index round-trips, and every record reads back byte-exact
    // from the sealed blob alone. Records now begin at the 80-byte header base.
    #[test]
    fn seal_reopen_index_and_records() {
        let (_dk, mk, ik) = keys();
        let (blob, [r0, r1, r2]) = build_three();

        let reader = SegmentReader::open(&blob, &mk, &ik).unwrap();
        assert_eq!(reader.header().segment_id, 77);
        assert_eq!(reader.header().epoch, 4);
        assert_eq!(reader.header().device_uuid, [9u8; 16]);

        let idx = reader.index(&mk).unwrap();
        assert_eq!(idx.len(), 3);
        assert_eq!(idx[0].record_off, HEADER_LEN as u64); // first record at base 80
        assert_eq!(idx[0].lba_start, 0);
        assert_eq!(idx[2].lba_count, 16);

        let dk = SymmetricKey::from_bytes([1u8; 32]);
        assert_eq!(reader.read_record(&idx[0], &dk).unwrap(), r0);
        assert_eq!(reader.read_record(&idx[1], &dk).unwrap(), r1);
        assert_eq!(reader.read_record(&idx[2], &dk).unwrap(), r2);
    }

    // current_len grows monotonically from the 80-byte header base.
    #[test]
    fn current_len_tracks_appends() {
        let (dk, _mk, _ik) = keys();
        let mut b = SegmentBuilder::new(1, [0u8; 16], 0, dk);
        assert_eq!(b.current_len(), HEADER_LEN as u64);
        b.append_record(0, 1, &[0u8; 4096]).unwrap();
        assert!(b.current_len() > HEADER_LEN as u64 + 4096); // +AEAD overhead, no frame
    }

    // OPACITY (not just round-trip): the sealed blob carries no plaintext magics
    // and no plaintext segment id, and sealing twice gives different bytes
    // (fresh nonces).
    #[test]
    fn sealed_blob_is_opaque() {
        let (dk, mk, ik) = keys();
        let mut b = SegmentBuilder::new(0x1122334455667788, [7u8; 16], 9, dk.clone());
        b.append_record(0, 2, &[0x5au8; 8192]).unwrap();
        let blob = b.seal(&mk, &ik, None).unwrap();

        // no format magics appear anywhere in the on-wire bytes
        for magic in [b"TGDEVSG2", b"TGDEVTR2", b"TGDEVSG1", b"TGDEVEND"] {
            assert!(
                !blob.windows(8).any(|w| w == magic),
                "plaintext magic {:?} leaked into the segment blob",
                std::str::from_utf8(magic).unwrap()
            );
        }
        // the segment_id (0x1122334455667788) does not appear as a plaintext LE u64
        let id_le = 0x1122334455667788u64.to_le_bytes();
        assert!(
            !blob.windows(8).any(|w| w == id_le),
            "plaintext segment_id leaked into the segment blob"
        );
        // fresh nonces per seal → two seals of identical inputs differ everywhere
        let mut b2 = SegmentBuilder::new(0x1122334455667788, [7u8; 16], 9, dk);
        b2.append_record(0, 2, &[0x5au8; 8192]).unwrap();
        let blob2 = b2.seal(&mk, &ik, None).unwrap();
        assert_eq!(blob.len(), blob2.len());
        assert_ne!(blob, blob2); // header nonce, record nonce, index nonce all fresh
    }

    // Padding rounds a small segment up to the bucket (size-blending) while reads
    // still work; the pad is MAC-covered random bytes.
    #[test]
    fn padding_rounds_up_and_reads_still_work() {
        let (dk, mk, ik) = keys();
        let mut b = SegmentBuilder::new(5, [0u8; 16], 0, dk);
        let r = vec![0x11u8; 4096];
        b.append_record(0, 1, &r).unwrap();
        let bucket = 64 * 1024;
        let blob = b.seal(&mk, &ik, Some(bucket)).unwrap();
        assert_eq!(blob.len() as u64, bucket); // padded exactly to the bucket

        let reader = SegmentReader::open(&blob, &mk, &ik).unwrap();
        let idx = reader.index(&mk).unwrap();
        assert_eq!(idx.len(), 1);
        assert_eq!(reader.read_record(&idx[0], &dk_of()).unwrap(), r);
    }

    fn dk_of() -> SymmetricKey {
        SymmetricKey::from_bytes([1u8; 32])
    }

    // A segment already at/over the bucket is not shrunk by padding.
    #[test]
    fn padding_never_shrinks() {
        let (dk, mk, ik) = keys();
        let mut b = SegmentBuilder::new(1, [0u8; 16], 0, dk);
        b.append_record(0, 16, &vec![0u8; 65536]).unwrap();
        let unpadded_len = {
            let mut b2 = SegmentBuilder::new(1, [0u8; 16], 0, SymmetricKey::from_bytes([1u8; 32]));
            b2.append_record(0, 16, &vec![0u8; 65536]).unwrap();
            b2.seal(&mk, &ik, None).unwrap().len()
        };
        let blob = b.seal(&mk, &ik, Some(1024)).unwrap(); // bucket smaller than the segment
        assert_eq!(blob.len(), unpadded_len); // unchanged
    }

    // Recovery re-framing: rebuild a segment from its sealed record bytes alone
    // (no plaintext), and verify it reopens with the SAME record_offs (now based
    // at 80) and reads back byte-exact. Mismatched sealed lengths are rejected.
    #[test]
    fn append_sealed_record_reframes_segment() {
        let (dk, mk, ik) = keys();
        let mut orig = SegmentBuilder::new(42, [5u8; 16], 2, dk.clone());
        let p0 = vec![0x10u8; 4096];
        let p1 = vec![0x20u8; 8192];
        let (off0, sealed0) = orig.append_record(7, 1, &p0).unwrap();
        let (off1, sealed1) = orig.append_record(8, 2, &p1).unwrap();
        assert_eq!(off0, HEADER_LEN as u64);

        let mut rebuilt = SegmentBuilder::new(42, [5u8; 16], 2, dk);
        assert_eq!(rebuilt.append_sealed_record(7, 1, &sealed0).unwrap(), off0);
        assert_eq!(rebuilt.append_sealed_record(8, 2, &sealed1).unwrap(), off1);
        let blob = rebuilt.seal(&mk, &ik, None).unwrap();

        let reader = SegmentReader::open(&blob, &mk, &ik).unwrap();
        let idx = reader.index(&mk).unwrap();
        assert_eq!(idx[0].record_off, off0);
        assert_eq!(idx[1].record_off, off1);
        let rdk = SymmetricKey::from_bytes([1u8; 32]);
        assert_eq!(reader.read_record(&idx[0], &rdk).unwrap(), p0);
        assert_eq!(reader.read_record(&idx[1], &rdk).unwrap(), p1);

        let mut bad = SegmentBuilder::new(1, [0u8; 16], 0, SymmetricKey::from_bytes([1u8; 32]));
        assert!(bad
            .append_sealed_record(0, 1, &sealed0[..sealed0.len() - 1])
            .is_err());
        assert!(bad.append_sealed_record(0, 2, &sealed0).is_err());
        assert!(bad.append_sealed_record(0, 0, &sealed0).is_err());
    }

    // A flipped byte anywhere fails the trailing MAC (fail-closed).
    #[test]
    fn tampered_segment_fails_mac() {
        let (_dk, mk, ik) = keys();
        let (mut blob, _) = build_three();
        let mid = blob.len() / 2;
        blob[mid] ^= 0xFF;
        assert!(SegmentReader::open(&blob, &mk, &ik).is_err());
    }

    // Wrong integrity key (MAC), wrong meta key (header/trailer), wrong data key
    // (record) all fail closed.
    #[test]
    fn wrong_keys_fail_closed() {
        let (_dk, mk, ik) = keys();
        let (blob, _) = build_three();

        let wrong = SymmetricKey::from_bytes([0xEEu8; 32]);
        assert!(SegmentReader::open(&blob, &mk, &wrong).is_err()); // wrong MAC key
        assert!(SegmentReader::open(&blob, &wrong, &ik).is_err()); // wrong meta key (trailer decrypt)

        let reader = SegmentReader::open(&blob, &mk, &ik).unwrap();
        assert!(reader.index(&wrong).is_err()); // wrong meta key → index decrypt fails

        let idx = reader.index(&mk).unwrap();
        assert!(reader.read_record(&idx[0], &wrong).is_err()); // wrong data key
    }

    // A truncated segment (short of header+trailer+mac) is rejected, not panicked.
    #[test]
    fn short_blob_rejected() {
        let (_dk, mk, ik) = keys();
        assert!(SegmentReader::open(&[0u8; 10], &mk, &ik).is_err());
        assert!(SegmentReader::open(&[0u8; MIN_SEGMENT_LEN - 1], &mk, &ik).is_err());
    }

    // A hand-built RecordLoc with an out-of-range record_off fails closed via
    // checked arithmetic — no overflow/panic.
    #[test]
    fn read_record_rejects_bogus_loc() {
        let (_dk, mk, ik) = keys();
        let (blob, _) = build_three();
        let reader = SegmentReader::open(&blob, &mk, &ik).unwrap();
        let dk = SymmetricKey::from_bytes([1u8; 32]);

        let bogus = RecordLoc {
            record_off: u64::MAX,
            lba_start: 0,
            lba_count: 1,
            plain_len: 4096,
        };
        assert!(reader.read_record(&bogus, &dk).is_err());

        let in_header = RecordLoc {
            record_off: 8,
            lba_start: 0,
            lba_count: 1,
            plain_len: 4096,
        };
        assert!(reader.read_record(&in_header, &dk).is_err());

        let idx = reader.index(&mk).unwrap();
        assert!(reader.read_record(&idx[0], &dk).is_ok());
    }

    // Records must be block-granular; read_record rejects a loc whose lba_count
    // disagrees with the (authenticated) plain_len.
    #[test]
    fn record_block_granularity_enforced() {
        let (dk, mk, ik) = keys();
        let mut b = SegmentBuilder::new(1, [0u8; 16], 0, dk);
        assert!(b.append_record(0, 1, &[0u8; 1000]).is_err()); // 1000 ≠ 1 block
        assert!(b.append_record(0, 2, &[0u8; 4096]).is_err()); // 4096 ≠ 2 blocks
        assert!(b.append_record(0, 0, &[]).is_err()); // zero blocks
        b.append_record(0, 2, &[7u8; 8192]).unwrap();
        let blob = b.seal(&mk, &ik, None).unwrap();

        let reader = SegmentReader::open(&blob, &mk, &ik).unwrap();
        let idx = reader.index(&mk).unwrap();
        let dk = SymmetricKey::from_bytes([1u8; 32]);

        let mut bad = idx[0];
        bad.lba_count = 3;
        assert!(reader.read_record(&bad, &dk).is_err());
        assert_eq!(reader.read_record(&idx[0], &dk).unwrap().len(), 8192);
    }

    // ── P3.1 ranged-read helpers ─────────────────────────────────────────────

    /// Simulate the device's tail bootstrap on a sealed blob: take the last
    /// `probe` bytes, parse the trailer relative to the buffer END, slice the
    /// index (it ends exactly at the trailer start), open it with the expected
    /// identity. Returns the parsed index.
    fn bootstrap_from_tail(
        blob: &[u8],
        probe: usize,
        mk: &SymmetricKey,
        seg: u64,
        epoch: u32,
        uuid: [u8; 16],
    ) -> Result<Vec<RecordLoc>> {
        let tail = &blob[blob.len().saturating_sub(probe)..]; // download_tail(min(probe,size))
        if tail.len() < TRAILER_LEN + MAC_LEN {
            return Err(DeviceError::Corruption("tail probe too short".into()));
        }
        let trl_start = tail.len() - MAC_LEN - TRAILER_LEN;
        let (_, index_len) = open_trailer_ranged(&tail[trl_start..tail.len() - MAC_LEN], mk)?;
        let index_len = index_len as usize;
        if index_len > trl_start {
            return Err(DeviceError::Corruption("index larger than probe".into()));
        }
        open_index_ranged(
            &tail[trl_start - index_len..trl_start],
            mk,
            seg,
            epoch,
            uuid,
        )
    }

    // Ranged bootstrap + record read round-trips from tail slices alone — never
    // touching the header or verifying the MAC — including on a PADDED segment
    // and with a probe larger than the whole blob (download_tail clamps).
    #[test]
    fn ranged_bootstrap_and_record_read_round_trip() {
        let (dk, mk, ik) = keys();
        let uuid = [9u8; 16];
        let mut b = SegmentBuilder::new(77, uuid, 4, dk.clone());
        let r0 = vec![0xa0u8; 4096];
        let r1 = vec![0xb1u8; 8192];
        b.append_record(0, 1, &r0).unwrap();
        b.append_record(1, 2, &r1).unwrap();
        let blob = b.seal(&mk, &ik, Some(128 * 1024)).unwrap(); // padded bucket

        // probe smaller than the blob
        let idx = bootstrap_from_tail(&blob, 4096, &mk, 77, 4, uuid).unwrap();
        assert_eq!(idx.len(), 2);
        // probe larger than the blob (tail = whole blob; still parses tail-relative)
        let idx2 = bootstrap_from_tail(&blob, blob.len() + 999, &mk, 77, 4, uuid).unwrap();
        assert_eq!(idx, idx2);

        // ranged record fetch = exact sealed slice; opens under the expected AAD
        let loc = idx[1];
        let sealed = &blob[loc.record_off as usize
            ..loc.record_off as usize + loc.plain_len as usize + RECORD_OVERHEAD];
        let dk2 = SymmetricKey::from_bytes([1u8; 32]);
        assert_eq!(
            open_record_ranged(sealed, &dk2, uuid, 4, 77, &loc).unwrap(),
            r1
        );
    }

    // The identity binding: an index opened under the WRONG expected identity
    // (segment id, epoch, or device) fails closed — this is what defeats a
    // transport serving another segment's tail for our download_tail.
    #[test]
    fn ranged_index_rejects_wrong_identity() {
        let (dk, mk, ik) = keys();
        let uuid = [9u8; 16];
        let mut b = SegmentBuilder::new(77, uuid, 4, dk);
        b.append_record(0, 1, &[0u8; 4096]).unwrap();
        let blob = b.seal(&mk, &ik, None).unwrap();

        assert!(bootstrap_from_tail(&blob, 4096, &mk, 78, 4, uuid).is_err()); // wrong seg
        assert!(bootstrap_from_tail(&blob, 4096, &mk, 77, 5, uuid).is_err()); // wrong epoch
        assert!(bootstrap_from_tail(&blob, 4096, &mk, 77, 4, [1u8; 16]).is_err()); // wrong dev
        let wrong_mk = SymmetricKey::from_bytes([0xEEu8; 32]);
        assert!(bootstrap_from_tail(&blob, 4096, &wrong_mk, 77, 4, uuid).is_err());
        assert!(bootstrap_from_tail(&blob, 4096, &mk, 77, 4, uuid).is_ok());
    }

    // Ranged record opening fails closed on: short fetch (truncated sealed
    // bytes), tampered ciphertext, wrong epoch (wrong key AND wrong AAD), and a
    // hand-built loc with inconsistent granularity. Never wrong plaintext.
    #[test]
    fn ranged_record_fails_closed() {
        let (dk, mk, ik) = keys();
        let uuid = [9u8; 16];
        let mut b = SegmentBuilder::new(77, uuid, 4, dk.clone());
        let (off, sealed) = b.append_record(3, 1, &[0x77u8; 4096]).unwrap();
        let _ = b.seal(&mk, &ik, None).unwrap();
        let loc = RecordLoc {
            record_off: off,
            lba_start: 3,
            lba_count: 1,
            plain_len: 4096,
        };

        // short read → fail closed
        assert!(open_record_ranged(&sealed[..sealed.len() - 1], &dk, uuid, 4, 77, &loc).is_err());
        // tamper → AEAD reject
        let mut bad = sealed.clone();
        bad[100] ^= 0xFF;
        assert!(open_record_ranged(&bad, &dk, uuid, 4, 77, &loc).is_err());
        // wrong epoch in the expectation → reject
        assert!(open_record_ranged(&sealed, &dk, uuid, 5, 77, &loc).is_err());
        // inconsistent loc granularity → reject before any crypto
        let mut badloc = loc;
        badloc.lba_count = 2;
        assert!(open_record_ranged(&sealed, &dk, uuid, 4, 77, &badloc).is_err());
        // the honest expectation works
        assert_eq!(
            open_record_ranged(&sealed, &dk, uuid, 4, 77, &loc).unwrap(),
            vec![0x77u8; 4096]
        );
    }

    // A trailer slice of the wrong size, wrong key, or tampered bytes fails
    // closed; the honest one yields the same (index_off, index_len) the full
    // SegmentReader sees.
    #[test]
    fn ranged_trailer_parses_and_fails_closed() {
        let (dk, mk, ik) = keys();
        let mut b = SegmentBuilder::new(1, [0u8; 16], 0, dk);
        b.append_record(0, 1, &[0u8; 4096]).unwrap();
        let blob = b.seal(&mk, &ik, None).unwrap();
        let trl = &blob[blob.len() - MAC_LEN - TRAILER_LEN..blob.len() - MAC_LEN];

        let (index_off, index_len) = open_trailer_ranged(trl, &mk).unwrap();
        // the index really does end exactly at the trailer start
        assert_eq!(
            index_off as usize + index_len as usize,
            blob.len() - MAC_LEN - TRAILER_LEN
        );

        assert!(open_trailer_ranged(&trl[..TRAILER_LEN - 1], &mk).is_err()); // wrong size
        let wrong = SymmetricKey::from_bytes([0xEEu8; 32]);
        assert!(open_trailer_ranged(trl, &wrong).is_err()); // wrong key
        let mut tam = trl.to_vec();
        tam[5] ^= 1;
        assert!(open_trailer_ranged(&tam, &mk).is_err()); // tampered
    }

    // The record AEAD — NOT the header — is the anti-substitution authority on the
    // P3 ranged read path (where the header is never downloaded). The same sealed
    // record bytes relocated into a segment with a different segment_id must fail
    // to open, because the record's AAD binds segment_id.
    #[test]
    fn record_aead_binds_identity_without_header() {
        let (dk, mk, ik) = keys();
        let mut a = SegmentBuilder::new(100, [1u8; 16], 0, dk.clone());
        let (off, sealed) = a.append_record(0, 1, &[0x11u8; 4096]).unwrap();
        let _ = a.seal(&mk, &ik, None).unwrap();

        // relocate the identical sealed bytes into a DIFFERENT segment id (a
        // catalog-swap / wrong-segment substitution) at the same offset
        let mut b = SegmentBuilder::new(101, [1u8; 16], 0, dk.clone());
        assert_eq!(b.append_sealed_record(0, 1, &sealed).unwrap(), off);
        let blob_b = b.seal(&mk, &ik, None).unwrap();
        let reader = SegmentReader::open(&blob_b, &mk, &ik).unwrap();
        let idx = reader.index(&mk).unwrap();
        // read_record binds the reader header's segment_id (101) in the AAD →
        // decrypt fails even though the sealed bytes are byte-identical to seg 100's.
        assert!(reader.read_record(&idx[0], &dk).is_err());

        // sanity: in its own segment (id 100) the identical bytes read fine
        let mut a2 = SegmentBuilder::new(100, [1u8; 16], 0, dk.clone());
        a2.append_sealed_record(0, 1, &sealed).unwrap();
        let blob_a = a2.seal(&mk, &ik, None).unwrap();
        let ra = SegmentReader::open(&blob_a, &mk, &ik).unwrap();
        let ia = ra.index(&mk).unwrap();
        assert_eq!(ra.read_record(&ia[0], &dk).unwrap(), vec![0x11u8; 4096]);
    }
}
