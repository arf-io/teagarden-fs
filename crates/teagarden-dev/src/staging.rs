//! Local durable write-back staging log (P1.12).
//!
//! The staging log is the device's **default durability barrier** (decision D8:
//! local-fsync-fast). Every write appends an entry here and, on `flush()`, the
//! file is `fsync`'d — no Telegram round-trip on the hot path. An entry durably
//! captures both halves of a write:
//!
//! - the **FTL-delta** (the `LBA → physical` mapping), AEAD-sealed under the meta
//!   key so the mapping is never plaintext at rest, and
//! - the **sealed record** bytes (already ciphertext from
//!   [`crate::sector_crypto`]) for the open, not-yet-uploaded segment.
//!
//! On restart, [`StagingReader`] streams the entries back (one at a time — the
//! log is never read whole into RAM) so the device can rebuild the FTL and
//! finish uploading staged records. Replay is **torn-tail tolerant**: it applies
//! every complete, authentic entry and stops at the first partial or
//! undecryptable one (the crash point).
//!
//! Stopping is only half of tolerating a tear: the bytes past the valid prefix
//! must also be **removed before anything is appended**, or every later entry
//! would sit behind the tear and be dropped by the next replay (finding C1).
//! [`StagingLog::open_append`] therefore truncates the file to the valid prefix
//! and fsyncs it, and [`StagingLog::append`] rolls a failed (short) write back
//! to the previous length — a disk filling up mid-`write_all` must not tear a
//! log that no crash touched.
//!
//! Entry layout: `[u32 sealed_delta_len][sealed_delta][u32 record_len][sealed_record]`.
//! Integrity comes from the two AEAD tags; a torn or forged entry fails to
//! decrypt and stops replay. The layout is unchanged by the C1/H4 fixes.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, Write};
use std::path::Path;

use teagarden_core::crypto::aead;
use teagarden_core::crypto::keys::SymmetricKey;

use crate::error::{DeviceError, Result};
use crate::ftl::Ftl;
use crate::ftl_log::FtlDelta;

const STAGING_AAD_CONTEXT: &[u8] = b"tgdev-stg-v1";

/// Upper bound on a sealed delta. A real one is ~73 bytes (45-byte delta +
/// AEAD overhead); anything this large is corruption, and refusing it keeps a
/// garbage length field from driving a huge allocation.
const MAX_SEALED_DELTA: usize = 4096;

fn staging_aad(device_uuid: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(STAGING_AAD_CONTEXT.len() + 16);
    v.extend_from_slice(STAGING_AAD_CONTEXT);
    v.extend_from_slice(device_uuid);
    v
}

fn crypto_err(e: impl std::fmt::Display) -> DeviceError {
    DeviceError::Crypto(e.to_string())
}

/// One staged write: its FTL-delta and the sealed record bytes.
#[derive(Clone, Debug)]
pub struct StagedEntry {
    /// The mapping this write installed.
    pub delta: FtlDelta,
    /// The sealed (ciphertext) record for the open segment. Empty when the
    /// reader was asked to skip it (or for an `Unmap` / a compacted base entry).
    pub sealed_record: Vec<u8>,
}

/// How a staging file ended, as seen by [`StagingReader`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailState {
    /// The last entry ends exactly at end-of-file.
    Clean,
    /// The last entry runs past end-of-file — a crash mid-append (the classic
    /// torn tail). Nothing after it can be valid.
    Incomplete,
    /// A length-complete entry failed authentication or parsing. Usually a
    /// zero-filled tail after power loss, but it is also what a pre-C1 short
    /// write followed by later appends looks like — bytes past this point may
    /// hold acknowledged entries replay can no longer reach.
    Corrupt,
}

/// The result of replaying a staging file.
#[derive(Debug)]
pub struct StagingReplay {
    /// FTL reconstructed from the applied deltas.
    pub ftl: Ftl,
    /// The staged entries, in append order, up to the tear.
    pub entries: Vec<StagedEntry>,
    /// True if replay stopped at a partial/undecryptable entry (a torn tail).
    pub torn_tail: bool,
    /// Byte length of the valid prefix (end of the last good entry).
    pub valid_len: u64,
}

/// Streaming staging-log reader: yields one authenticated entry at a time,
/// holding at most one entry in memory.
pub struct StagingReader<'k> {
    r: BufReader<File>,
    file_len: u64,
    /// End of the last good entry (the valid prefix length).
    pos: u64,
    meta_key: &'k SymmetricKey,
    aad: Vec<u8>,
    tail: Option<TailState>,
}

impl<'k> StagingReader<'k> {
    /// Open `path` for streaming replay.
    pub fn open(
        path: impl AsRef<Path>,
        meta_key: &'k SymmetricKey,
        device_uuid: [u8; 16],
    ) -> Result<Self> {
        let f = File::open(path)?;
        let file_len = f.metadata()?.len();
        Ok(Self {
            r: BufReader::with_capacity(256 * 1024, f),
            file_len,
            pos: 0,
            meta_key,
            aad: staging_aad(&device_uuid),
            tail: None,
        })
    }

    /// The next entry, or `None` at the end of the valid prefix. `keep_record`
    /// decides (from the authenticated delta) whether the sealed record bytes
    /// are read into memory or skipped. I/O errors propagate; a torn or forged
    /// entry ends the stream (see [`Self::tail_state`]).
    pub fn next_entry(
        &mut self,
        keep_record: impl FnOnce(&FtlDelta) -> bool,
    ) -> Result<Option<StagedEntry>> {
        if self.tail.is_some() {
            return Ok(None);
        }
        let rem = self.file_len - self.pos;
        if rem == 0 {
            self.tail = Some(TailState::Clean);
            return Ok(None);
        }
        if rem < 4 {
            self.tail = Some(TailState::Incomplete);
            return Ok(None);
        }
        let mut u = [0u8; 4];
        self.r.read_exact(&mut u)?;
        let dlen = u32::from_le_bytes(u) as u64;
        if dlen > MAX_SEALED_DELTA as u64 {
            self.tail = Some(TailState::Corrupt);
            return Ok(None);
        }
        if 4 + dlen + 4 > rem {
            self.tail = Some(TailState::Incomplete);
            return Ok(None);
        }
        let mut sealed_delta = vec![0u8; dlen as usize];
        self.r.read_exact(&mut sealed_delta)?;
        self.r.read_exact(&mut u)?;
        let rlen = u32::from_le_bytes(u) as u64;
        if 4 + dlen + 4 + rlen > rem {
            self.tail = Some(TailState::Incomplete);
            return Ok(None);
        }
        let delta = match aead::decrypt(self.meta_key, &sealed_delta, &self.aad)
            .ok()
            .and_then(|b| FtlDelta::from_bytes(&b).ok())
        {
            Some(d) if d.is_representable() => d,
            _ => {
                self.tail = Some(TailState::Corrupt);
                return Ok(None);
            }
        };
        let sealed_record = if keep_record(&delta) {
            let mut rec = vec![0u8; rlen as usize];
            self.r.read_exact(&mut rec)?;
            rec
        } else {
            self.r.seek_relative(rlen as i64)?;
            Vec::new()
        };
        self.pos += 4 + dlen + 4 + rlen;
        Ok(Some(StagedEntry {
            delta,
            sealed_record,
        }))
    }

    /// Byte length of the valid prefix read so far.
    pub fn valid_len(&self) -> u64 {
        self.pos
    }

    /// Size of the file being read.
    pub fn file_len(&self) -> u64 {
        self.file_len
    }

    /// How the stream ended (`None` while entries remain).
    pub fn tail_state(&self) -> Option<TailState> {
        self.tail
    }
}

/// An append-only, fsync-durable local staging log.
pub struct StagingLog {
    file: File,
    meta_key: SymmetricKey,
    device_uuid: [u8; 16],
    /// Valid length of the log (== file length unless poisoned).
    bytes: u64,
    /// A failed append could not be rolled back (the file may hold torn bytes
    /// past `bytes`), or an fsync failed (earlier appends may not be on disk
    /// even if a later fsync succeeds): further appends/flushes are refused
    /// until the device is reopened (which trims to the valid prefix).
    poisoned: bool,
    /// Test-only fault hooks (empty unless `cfg(test)` / `fault-injection`).
    #[cfg_attr(not(any(test, feature = "fault-injection")), allow(dead_code))]
    faults: SyncFaults,
}

/// Injected fsync failures. Zero-sized in product builds.
#[derive(Default)]
struct SyncFaults {
    /// Fail this many upcoming `flush` fsyncs WITHOUT syncing — modelling
    /// Linux, where a failed fsync drops the dirty pages' error state so a
    /// later fsync can return success although the data never reached disk.
    #[cfg(any(test, feature = "fault-injection"))]
    fail_syncs: u32,
}

fn poisoned_err() -> DeviceError {
    DeviceError::Io(std::io::Error::other(
        "staging log failed earlier (un-rolled-back append or failed fsync); reopen the device",
    ))
}

impl StagingLog {
    /// Create (or truncate) a staging file at `path`.
    pub fn create(
        path: impl AsRef<Path>,
        meta_key: SymmetricKey,
        device_uuid: [u8; 16],
    ) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            file,
            meta_key,
            device_uuid,
            bytes: 0,
            poisoned: false,
            faults: SyncFaults::default(),
        })
    }

    /// Open an existing staging file for further appends. Scans it first and
    /// trims anything past the valid prefix (see [`Self::open_append_trimmed`]),
    /// so new entries can never land behind a torn tail.
    pub fn open_append(
        path: impl AsRef<Path>,
        meta_key: SymmetricKey,
        device_uuid: [u8; 16],
    ) -> Result<Self> {
        let (valid_len, tail) = {
            let mut rd = StagingReader::open(&path, &meta_key, device_uuid)?;
            while rd.next_entry(|_| false)?.is_some() {}
            (rd.valid_len(), rd.tail_state().unwrap_or(TailState::Clean))
        };
        Self::open_append_trimmed(path, meta_key, device_uuid, valid_len, tail)
    }

    /// Open for append after a replay that already found the valid prefix
    /// (`valid_len`, ending in `tail`). Bytes past `valid_len` are removed and
    /// the truncation is fsynced BEFORE any append. When the tail was
    /// [`TailState::Corrupt`] (not a plain crash tear) the discarded bytes are
    /// first preserved, still ciphertext, in `<path>.discarded-<valid_len>` —
    /// replay could not reach them, but truncating must not make that loss
    /// irreversible.
    pub fn open_append_trimmed(
        path: impl AsRef<Path>,
        meta_key: SymmetricKey,
        device_uuid: [u8; 16],
        valid_len: u64,
        tail: TailState,
    ) -> Result<Self> {
        let path = path.as_ref();
        let file = OpenOptions::new().read(true).append(true).open(path)?;
        let len = file.metadata()?.len();
        if len > valid_len {
            let discarded = len - valid_len;
            if tail == TailState::Corrupt {
                let side = path.with_file_name(format!(
                    "{}.discarded-{valid_len}",
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("staging.log")
                ));
                let mut src = &file;
                src.seek(std::io::SeekFrom::Start(valid_len))?;
                let mut out = File::create(&side)?;
                std::io::copy(&mut src.take(discarded), &mut out)?;
                out.sync_all()?;
                if let Some(parent) = path.parent() {
                    File::open(parent)?.sync_all()?;
                }
                tracing::warn!(
                    discarded,
                    valid_len,
                    sidecar = %side.display(),
                    "staging log: unauthenticated entry mid-log; trimmed to the valid prefix, \
                     discarded bytes preserved"
                );
            } else {
                tracing::warn!(
                    discarded,
                    valid_len,
                    "staging log: torn tail (crash mid-append) trimmed to the valid prefix"
                );
            }
            file.set_len(valid_len)?;
            file.sync_all()?;
        }
        Ok(Self {
            file,
            meta_key,
            device_uuid,
            bytes: valid_len,
            poisoned: false,
            faults: SyncFaults::default(),
        })
    }

    /// Append a write (its delta + sealed record). Not durable until `flush`.
    ///
    /// On a write error (e.g. ENOSPC part-way through) the file is truncated
    /// back to its previous length, so the failed entry leaves no torn bytes
    /// for a later successful append to hide behind. If even that truncation
    /// fails the log is poisoned: appends and flushes are refused until reopen.
    pub fn append(&mut self, delta: &FtlDelta, sealed_record: &[u8]) -> Result<()> {
        if self.poisoned {
            return Err(poisoned_err());
        }
        let aad = staging_aad(&self.device_uuid);
        let sealed_delta =
            aead::encrypt(&self.meta_key, &delta.to_bytes(), &aad).map_err(crypto_err)?;
        let dlen = u32::try_from(sealed_delta.len())
            .map_err(|_| DeviceError::Corruption("staging delta too large".into()))?;
        let rlen = u32::try_from(sealed_record.len())
            .map_err(|_| DeviceError::Corruption("staging record too large".into()))?;

        let mut buf = Vec::with_capacity(8 + sealed_delta.len() + sealed_record.len());
        buf.extend_from_slice(&dlen.to_le_bytes());
        buf.extend_from_slice(&sealed_delta);
        buf.extend_from_slice(&rlen.to_le_bytes());
        buf.extend_from_slice(sealed_record);
        if let Err(e) = self.file.write_all(&buf) {
            // Truncate the torn bytes AND move the cursor back: a log from
            // `create` is not O_APPEND, so without the seek the next write would
            // land past a zero-filled hole — a torn entry all the same.
            let rolled_back = self.file.set_len(self.bytes).is_ok()
                && self.file.seek(std::io::SeekFrom::Start(self.bytes)).is_ok();
            if !rolled_back {
                self.poisoned = true;
            }
            return Err(e.into());
        }
        self.bytes += buf.len() as u64;
        Ok(())
    }

    /// Flush + `fsync` the staging file — the durability barrier. After this
    /// returns, the appended writes survive a process crash / power-cycle.
    pub fn flush(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(poisoned_err());
        }
        self.file.flush()?;
        #[cfg(any(test, feature = "fault-injection"))]
        if self.faults.fail_syncs > 0 {
            self.faults.fail_syncs -= 1;
            self.poisoned = true;
            return Err(std::io::Error::other("injected fsync failure (staging)").into());
        }
        if let Err(e) = self.file.sync_all() {
            // After a failed fsync the kernel may clear the error and let a
            // later fsync "succeed" over lost pages: never flush again.
            self.poisoned = true;
            return Err(e.into());
        }
        Ok(())
    }

    /// TEST-ONLY: make the next `n` flushes fail their fsync (see
    /// [`SyncFaults`]).
    #[cfg(any(test, feature = "fault-injection"))]
    pub fn inject_sync_failures(&mut self, n: u32) {
        self.faults.fail_syncs = n;
    }

    /// Bytes written so far.
    pub fn len(&self) -> u64 {
        self.bytes
    }

    /// True if nothing has been appended.
    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    /// Replay a whole staging file into memory: rebuild the FTL from the
    /// decrypted deltas and return every staged entry (records included) in
    /// order. Stops fail-closed at the first torn or undecryptable entry.
    ///
    /// This holds every record in RAM; the device's own open/checkpoint paths
    /// stream with [`StagingReader`] instead and keep only what they need.
    pub fn replay(
        path: impl AsRef<Path>,
        meta_key: &SymmetricKey,
        device_uuid: [u8; 16],
    ) -> Result<StagingReplay> {
        let mut rd = StagingReader::open(path, meta_key, device_uuid)?;
        let mut ftl = Ftl::new();
        let mut entries = Vec::new();
        while let Some(e) = rd.next_entry(|_| true)? {
            e.delta.apply(&mut ftl);
            entries.push(e);
        }
        Ok(StagingReplay {
            ftl,
            entries,
            torn_tail: rd.tail_state() != Some(TailState::Clean),
            valid_len: rd.valid_len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ftl::Phys;

    fn keys() -> (SymmetricKey, [u8; 16]) {
        (SymmetricKey::from_bytes([0x11; 32]), [0xabu8; 16])
    }

    fn map(lba: u64, count: u64, seg: u64) -> FtlDelta {
        FtlDelta::Map {
            lba,
            count,
            phys: Phys {
                segment_id: seg,
                record_off: seg * 100,
                data_off: 0,
                epoch: 0,
            },
        }
    }

    // Append → flush → replay: the FTL and the staged records round-trip.
    #[test]
    fn append_flush_replay_round_trips() {
        let (mk, uuid) = keys();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staging.log");

        let r0 = vec![0xaau8; 40];
        let r1 = vec![0xbbu8; 80];
        {
            let mut log = StagingLog::create(&path, mk.clone(), uuid).unwrap();
            log.append(&map(0, 1, 1), &r0).unwrap();
            log.append(&map(1, 2, 2), &r1).unwrap();
            log.append(&FtlDelta::Unmap { lba: 0, count: 1 }, &[])
                .unwrap();
            log.flush().unwrap();
            assert!(!log.is_empty());
        }

        let rp = StagingLog::replay(&path, &mk, uuid).unwrap();
        assert!(!rp.torn_tail);
        assert_eq!(rp.entries.len(), 3);
        assert_eq!(rp.entries[0].sealed_record, r0);
        assert_eq!(rp.entries[1].sealed_record, r1);
        // FTL after replay: block 0 unmapped (last delta), blocks 1..3 mapped
        assert_eq!(rp.ftl.lookup(0), None);
        assert_eq!(rp.ftl.mapped_blocks(), 2);
    }

    // A torn tail (crash mid-append) recovers the good prefix and reports the tear.
    #[test]
    fn torn_tail_recovers_prefix() {
        let (mk, uuid) = keys();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staging.log");

        {
            let mut log = StagingLog::create(&path, mk.clone(), uuid).unwrap();
            log.append(&map(0, 1, 1), &[1u8; 32]).unwrap();
            log.append(&map(1, 1, 2), &[2u8; 32]).unwrap();
            let clean = log.len();
            log.append(&map(2, 1, 3), &[3u8; 32]).unwrap();
            log.flush().unwrap();
            // truncate mid-third-entry (simulate a crash mid-append)
            let f = OpenOptions::new().write(true).open(&path).unwrap();
            f.set_len(clean + 10).unwrap();
            f.sync_all().unwrap();
        }

        let rp = StagingLog::replay(&path, &mk, uuid).unwrap();
        assert!(rp.torn_tail);
        assert_eq!(rp.entries.len(), 2);
        assert_eq!(rp.ftl.mapped_blocks(), 2);
    }

    // Replay with the wrong meta key fails closed (delta decrypt fails → torn at
    // the first entry, nothing applied).
    #[test]
    fn wrong_key_fails_closed() {
        let (mk, uuid) = keys();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staging.log");
        {
            let mut log = StagingLog::create(&path, mk, uuid).unwrap();
            log.append(&map(0, 1, 1), &[7u8; 16]).unwrap();
            log.flush().unwrap();
        }
        let wrong = SymmetricKey::from_bytes([0u8; 32]);
        let rp = StagingLog::replay(&path, &wrong, uuid).unwrap();
        assert!(rp.torn_tail);
        assert_eq!(rp.entries.len(), 0);
        assert_eq!(rp.ftl.mapped_blocks(), 0);
    }

    // C1 (partial write): a disk that fills up MID-append makes `write_all`
    // write a prefix of the entry and then fail. Those torn bytes must not
    // stay in the log: an append that succeeds after space frees up would land
    // behind them, and replay — which stops at the first bad entry — would
    // silently drop that later, acknowledged write. Real kernel short write:
    // the child lowers RLIMIT_FSIZE so write() is truncated, then EFBIG.
    #[cfg(unix)]
    #[test]
    fn partial_append_is_rolled_back_so_later_appends_survive() {
        let (mk, uuid) = keys();
        if let Some(dir) = crate::testutil::child_dir() {
            let path = dir.join("staging.log");
            let mut log = StagingLog::create(&path, mk.clone(), uuid).unwrap();
            log.append(&map(0, 1, 1), &[1u8; 64]).unwrap();
            log.flush().unwrap();
            // only 10 more bytes fit: the next append is a real short write
            crate::testutil::limit_file_size(log.len() + 10);
            assert!(log.append(&map(1, 1, 2), &[2u8; 64]).is_err());
            crate::testutil::unlimit_file_size();
            log.append(&map(2, 1, 3), &[3u8; 64]).unwrap();
            log.flush().unwrap();
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        crate::testutil::run_in_child(
            "staging::tests::partial_append_is_rolled_back_so_later_appends_survive",
            dir.path(),
        );
        let rp = StagingLog::replay(dir.path().join("staging.log"), &mk, uuid).unwrap();
        assert!(
            !rp.torn_tail,
            "the failed append left torn bytes in the log"
        );
        let recs: Vec<u8> = rp.entries.iter().map(|e| e.sealed_record[0]).collect();
        assert_eq!(recs, vec![1, 3], "the append after the failure was lost");
    }

    // C1: open_append trims a crash tear (fsynced) before the first append, so
    // the new session's entries are reachable by the next replay.
    #[test]
    fn open_append_trims_torn_tail_before_appending() {
        let (mk, uuid) = keys();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staging.log");
        let clean = {
            let mut log = StagingLog::create(&path, mk.clone(), uuid).unwrap();
            log.append(&map(0, 1, 1), &[1u8; 16]).unwrap();
            log.flush().unwrap();
            log.len()
        };
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&[0x99; 3]).unwrap();
        }
        let mut log = StagingLog::open_append(&path, mk.clone(), uuid).unwrap();
        assert_eq!(log.len(), clean);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), clean);
        log.append(&map(1, 1, 2), &[2u8; 16]).unwrap();
        log.flush().unwrap();
        let rp = StagingLog::replay(&path, &mk, uuid).unwrap();
        assert!(!rp.torn_tail);
        assert_eq!(rp.entries.len(), 2);
        // a plain crash tear leaves no sidecar
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    // A length-complete entry that fails authentication mid-log (what a pre-C1
    // short write followed by later appends looks like) is classified Corrupt:
    // the log is still trimmed, but the unreachable bytes are preserved.
    #[test]
    fn corrupt_mid_log_entry_is_trimmed_and_preserved() {
        let (mk, uuid) = keys();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staging.log");
        let (clean, total) = {
            let mut log = StagingLog::create(&path, mk.clone(), uuid).unwrap();
            log.append(&map(0, 1, 1), &[1u8; 16]).unwrap();
            let clean = log.len();
            log.append(&map(1, 1, 2), &[2u8; 16]).unwrap();
            log.append(&map(2, 1, 3), &[3u8; 16]).unwrap();
            log.flush().unwrap();
            (clean, log.len())
        };
        // flip a byte inside the 2nd entry's sealed delta
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[clean as usize + 6] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        let mut rd = StagingReader::open(&path, &mk, uuid).unwrap();
        while rd.next_entry(|_| false).unwrap().is_some() {}
        assert_eq!(rd.tail_state(), Some(TailState::Corrupt));
        assert_eq!(rd.valid_len(), clean);
        drop(rd);
        let log = StagingLog::open_append(&path, mk.clone(), uuid).unwrap();
        assert_eq!(log.len(), clean);
        let side = dir.path().join(format!("staging.log.discarded-{clean}"));
        assert_eq!(
            std::fs::read(&side).unwrap(),
            bytes[clean as usize..total as usize]
        );
    }

    // A garbage length field never drives an allocation past the file: a
    // 4 GiB record length in a tiny file is a torn tail, not an OOM.
    #[test]
    fn huge_length_fields_are_torn_not_allocated() {
        let (mk, uuid) = keys();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staging.log");
        {
            let mut log = StagingLog::create(&path, mk.clone(), uuid).unwrap();
            log.append(&map(0, 1, 1), &[1u8; 16]).unwrap();
            log.flush().unwrap();
        }
        let good = std::fs::read(&path).unwrap();
        // valid-looking delta length, absurd record length
        let dlen = u32::from_le_bytes(good[..4].try_into().unwrap()) as usize;
        let mut bad = good.clone();
        bad.extend_from_slice(&good[..4 + dlen]);
        bad.extend_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &bad).unwrap();
        let rp = StagingLog::replay(&path, &mk, uuid).unwrap();
        assert!(rp.torn_tail);
        assert_eq!(rp.entries.len(), 1);
        assert_eq!(rp.valid_len, good.len() as u64);
        // absurd delta length
        let mut bad2 = good.clone();
        bad2.extend_from_slice(&u32::MAX.to_le_bytes());
        bad2.extend_from_slice(&[0u8; 64]);
        std::fs::write(&path, &bad2).unwrap();
        let mut rd = StagingReader::open(&path, &mk, uuid).unwrap();
        while rd.next_entry(|_| true).unwrap().is_some() {}
        assert_eq!(rd.tail_state(), Some(TailState::Corrupt));
    }

    // open_append continues an existing log; replay sees both sessions' entries.
    #[test]
    fn open_append_continues_the_log() {
        let (mk, uuid) = keys();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staging.log");
        {
            let mut log = StagingLog::create(&path, mk.clone(), uuid).unwrap();
            log.append(&map(0, 1, 1), &[1u8; 16]).unwrap();
            log.flush().unwrap();
        }
        {
            let mut log = StagingLog::open_append(&path, mk.clone(), uuid).unwrap();
            assert!(!log.is_empty());
            log.append(&map(1, 1, 2), &[2u8; 16]).unwrap();
            log.flush().unwrap();
        }
        let rp = StagingLog::replay(&path, &mk, uuid).unwrap();
        assert!(!rp.torn_tail);
        assert_eq!(rp.entries.len(), 2);
        assert_eq!(rp.ftl.mapped_blocks(), 2);
    }
}
