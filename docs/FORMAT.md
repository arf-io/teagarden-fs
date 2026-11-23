# Formats

Default volume TGHD and TGFV formats, credentials and recovery are described in
[OBJECT_FORMAT.md](OBJECT_FORMAT.md). The following sections describe the separate
block device, not the default volume format.

## 7. Device segment format v2 (on Telegram)

One segment is one Telegram document. Defined in `crates/teagarden-dev/src/segment.rs`.

```text
┌ SEALED HEADER (fixed 80 B) ──────────────────────────────────────────────────┐
│ AEAD(meta_key, magic "TGDEVSG2"(8) || ver(2) || rsvd(2) || segment_id(8)     │
│      || epoch(4) || device_uuid(16), aad = "tgdev-seghdr-v2")               │
├ RECORDS ─────────────────────────────────────────────────────────────────────┤
│ sealed records back to back, no plaintext length frames                       │
├ PADDING ─────────────────────────────────────────────────────────────────────┤
│ random bytes up to the segment target size; covered by the MAC               │
├ SEALED INDEX ────────────────────────────────────────────────────────────────┤
│ AEAD(meta_key, count(u32) || RecordLoc[count],                               │
│      aad = "tgdev-idx-v2" || segment_id || epoch || device_uuid)             │
│   RecordLoc = record_off(8) || lba_start(8) || lba_count(8) || plain_len(8)  │
├ SEALED TRAILER (fixed 62 B) ─────────────────────────────────────────────────┤
│ AEAD(meta_key, magic "TGDEVTR2"(8) || ver(2) || index_off(8) || index_len(4),│
│      aad = "tgdev-segtrl-v2")                                                │
├ MAC (32 B) ──────────────────────────────────────────────────────────────────┤
│ BLAKE3-keyed(integrity_key) over everything before it                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

Read order: verify the MAC, decrypt the fixed-size trailer before it to find the
index, decrypt the index, decrypt the header. A single record can be read by
fetching `[record_off, record_off + plain_len + 40)`, because its coordinates come
from the encrypted index.

Segments and checkpoints are uploaded with a name of 12 random lowercase hex
characters and no extension (`random_upload_name` in `device.rs`). Nothing reads
the name back: segments and checkpoints are fetched by message id. Earlier
builds added one of `jpg png mp4 pdf zip mov doc m4a`; such segments read the
same.

## 8. Device records

Defined in `crates/teagarden-dev/src/sector_crypto.rs`. A record is the plaintext of a
contiguous run of 4096-byte logical blocks, sealed as:

```
AEAD(epoch_key, plaintext,
     aad = "tgdev-rec-v1" || device_uuid (16) || epoch (u32) || segment_id (u64)
           || record_off (u64) || lba_start (u64) || plain_len (u64))

epoch_key = BLAKE3-keyed(device data key, "tgdev-epoch-v1\0\0" || epoch (u32))
```

A fresh random nonce is drawn for every physical write, so rewriting a block never
reuses a nonce; this is why the device is an append-only log. A record moved to a
different block address, segment, offset, epoch or device fails to decrypt. This
binding, not the segment header, is what prevents substitution, and it also holds
for ranged reads that never download the header.

Records are sealed under the epoch current at write time and read under their own
epoch, so old records stay readable after the epoch advances. The 1.0.0 CLI has no
command that advances a device's epoch.

## 9. Device checkpoint ("head")

Defined in `crates/teagarden-dev/src/head.rs`. The checkpoint records the block map
up to a point where every earlier segment is confirmed, so a device can be rebuilt
from Telegram. The body is sealed as `AEAD(meta_key, body, "tgdev-head-v1" ||
device_uuid)`.

```
fixed prefix (76 B)
  magic          8    "TGDEVHD1"
  ver            2    1
  rsvd           2    0
  device_uuid   16
  generation     8
  head_gen       8
  capacity       8    in 4096-byte blocks
  epoch          4
  next_segment   8
  watermark      8
  extent_count   4
extents[extent_count]   44 B each
  lba 8 | lba_count 8 | segment_id 8 | record_off 8 | data_off 8 | epoch 4
catalog_count    4
catalog[catalog_count]  16 B each
  segment_id 8 | message_id 8
```

Before sealing, the body is padded with random bytes to a multiple of 4096 bytes,
so the ciphertext length shows only a coarse size class. The padding is inside the
AEAD and ignored on parse.

The associated data binds only the context tag and the device UUID. Every
checkpoint a device ever published therefore remains a valid recovery input, and
recovering from an older one gives the older contents; nothing in this format
detects that (test `superblock_and_head_rollback_are_accepted` in `device.rs`).

## 10. Device superblock (local only)

Defined in `crates/teagarden-dev/src/superblock.rs`. 80 bytes:

```
magic "TGDEVSB1" (8) | ver u16 = 2 | rsvd u16 | device_uuid (16) |
capacity_blocks u64 | current_epoch u32 | generation u64 | MAC (32)
```

The MAC is BLAKE3-keyed under the device integrity key over the first 48 bytes.
The superblock is MACed but not encrypted, and it is never uploaded. The MAC stops
anyone without the key from editing capacity, epoch or generation, but an older
authentic superblock is accepted, which undoes a later resize. `generation` is
incremented on every configuration change; nothing outside the file anchors it.

Version 2 was introduced when the staging log gained the `Relocate` delta (tag 3).
An older binary would have treated a `Relocate` entry as a torn tail and silently
truncated replay there; the version check in the always-read-first superblock
turns that into a clean refusal.

## 11. Device local directory

| File | Format |
|---|---|
| `superblock` | Section 10. Replaced atomically (`superblock.tmp`, fsync, rename, directory fsync). |
| `catalog` | Confirmed uploads: 16-byte records `segment_id u64 || message_id i64`. A record is appended and fsynced only after the upload succeeded; a segment counts as confirmed only once its record is durable. `message_id` 0 marks a segment deleted by GC. A failed append is cut back. Open trims a torn trailing partial record. |
| `staging.log` | Write-back log. Entries `[u32 sealed_delta_len][sealed_delta][u32 record_len][sealed_record]`. The delta (FTL tags: Map 1, Unmap 2, Relocate 3) is AEAD-sealed under the device meta key with associated data `"tgdev-stg-v1" || device_uuid`; the record is already ciphertext (section 8). Replay stops at the first incomplete or unauthenticated entry, and open truncates to that valid prefix (fsynced) before appending. |
| `staging.log.compact` | Scratch file of staging compaction, renamed over `staging.log` once fsynced. A leftover from an interrupted compaction is deleted on open; the old log stays authoritative. |
| `staging.log.discarded-<len>` | Bytes cut from `staging.log` past the valid prefix `<len>`, kept (still ciphertext) when the first bad entry was length-complete but failed authentication, or had a sealed-delta length over 4 KiB. A plain torn tail is trimmed without this file. |
| `recovery.incomplete` | Present while `dev recover` runs: created and fsynced before any device file is written, removed once all are durable. Open and create refuse a directory that holds it. |

The single-writer lock is an exclusive `flock` on the directory itself, held while
the device is open and released on close or process exit. There is no lock file.

**Staging compaction** runs after a flush or close once the log is larger than
`max(8 × segment target, 2 × its size after the last compaction)`. It rewrites the
log so that confirmed segments are represented by `Map` entries with empty records
(their bytes are on Telegram), keeps every entry for unconfirmed segments verbatim,
and preserves each segment's historical block totals for GC. After compaction, a
confirmed segment's bytes exist only on Telegram, so losing `catalog` makes open
fail closed instead of re-uploading from the log.

## 12. Device GC

Policy is in `crates/teagarden-dev/src/gc.rs`, the mechanism in `TeaGardenDevice::gc`.
Because every segment is padded to the same size on Telegram, a segment's live
ratio is `live bytes / segment target`. Segments below `live_ratio_max` (0.30 by
default) are compacted into new segments, lowest live ratio first. The order is
compact, confirm, publish a checkpoint, then delete: a segment's message is
deleted only if the live block map and the just-published checkpoint both no
longer refer to it. Older checkpoints are not deleted by default.

**After a GC pass, only the newest checkpoint is a usable recovery point.** Older
checkpoints may refer to segments GC has deleted.

---

## What this document does not cover

- Size and timing of traffic, which are not hidden; see
  [SECURITY_MODEL.md](SECURITY_MODEL.md).
- The internal serialization of inodes and manifests (postcard over the structs in
  `crates/teagarden-core/src/metadata/`).
- The key-slot transport formats of individual factors beyond the
  [slot-vault summary](OBJECT_FORMAT.md#slot-vault-json-and-recovery-credentials).
- Nothing here has been reviewed by an independent third party.
