# Self-describing object formats

This document describes the portable TGHD header and TGFV file-version object.
All integer fields in the outer binary framing are unsigned little-endian unless
noted. UUIDs in JSON use canonical hyphenated text; UUIDs in a TGFV prefix are
the 16 raw UUID bytes in network byte order. JSON is UTF-8. Readers must reject
unknown versions, unknown JSON members, duplicate members, trailing bytes, and
lengths that do not exactly match the input.

## TGHD volume header

### TGHD format 1 (legacy)

The complete object is at most 4 MiB and has this exact framing:

| Offset | Length | Meaning |
| ---: | ---: | --- |
| 0 | 4 | ASCII `TGHD` |
| 4 | 2 | format version, `1` (`01 00`) |
| 6 | 4 | UTF-8 JSON payload length `N` |
| 10 | N | JSON document |
| 10 + N | 32 | keyed BLAKE3 MAC |

No bytes may follow the MAC. MAC input is the ASCII context
`teagarden.sdo.header.v1` followed immediately by bytes `[0, 10 + N)` exactly
as stored. The key is the hierarchy `integrity` key. Do not parse and reserialize
the JSON before checking the MAC. The JSON `format` member is also `1`.

The TGHD1 JSON document has these fields:

| Member | JSON type / encoding |
| --- | --- |
| `format` | integer 1 |
| `volume_id` | UUID string |
| `revision` | unsigned 64-bit integer |
| `volume_version` | string |
| `root_kind` | `password` or `master-key` |
| `salt` | exactly 32 bytes as 64 lowercase hexadecimal characters |
| `kdf_params` | null for master-key roots; otherwise object `{memory_kib, iterations, parallelism, output_len}` |
| `group_id`, `topic_id` | signed 64-bit integers |
| `current_epoch` | unsigned 32-bit integer |
| `block_v2_from_epoch` | unsigned 32-bit integer or null |
| `require_block_integrity` | boolean |
| `block_size` | unsigned 64-bit integer |
| `key_protection` | public anchor object or null |
| `slot_vault` | complete v2 slot-vault JSON object or null |

### TGHD format 2 (owner-signed)

TGHD2 uses detached Ed25519 signature bytes. Its JSON contains no signature
member. The exact framing is `TGHD || u16le(2) || u32le(N) || JSON(N) ||
u16le(S) || signature(S) || MAC(32)`, with no trailing bytes. The owner
signature covers exactly `TGHD || u16le(2) || u32le(N) || JSON(N)`, as stored.
The keyed BLAKE3 MAC uses context `teagarden.sdo.header.v2` followed by every
byte before the MAC, including signature length and signature. Readers bound
`N` and `S`, verify lengths and reject trailing data, check the MAC first, then
verify the detached signature with the owner public key in the JSON. The JSON
format member is `2`.

TGHD2 carries the common fields above with `format` set to `2`, plus the
owner and policy fields below. Empty optional fields can be omitted.

| Member | JSON type / encoding |
| --- | --- |
| `owner_public_key` | owner Ed25519 public key, 32 bytes in lowercase hexadecimal |
| `key_generation` | required unsigned 64-bit integer; `0` for the normal default volume |
| `revoked_device_ids` | array of installation UUID strings |
| `revoked_account_bindings` | array of Telegram account/session binding strings |
| `device_authorities` | map from installation UUID to frozen signing key |
| `revocation_cutoffs` | map from installation UUID to generation and boundary message ID |
| `generation_boundary_message_id`, `generation_cutoffs` | optional generation boundary and map of generation cutoffs |
| `rotation_state`, `retained_key_bridges` | optional rotation state and retained bridges; rotation operations require the `key-rotation` feature |

Password roots require `kdf_params` and no `slot_vault`. Master-key roots require
the slot vault and no password KDF parameters. The vault's public KDF parameters
and encrypted slot payloads are visible; the KEK-encrypted slot payloads remain
encrypted. A header does not contain a password, recovery sentence, root, master
key, access hash, or local path. TGHD2 can expose a session-binding string in
its unencrypted `revoked_account_bindings` after a same-account revocation.
Readers bound Argon2 costs before calling Argon2id and reject a vault above 32 slots or 4 MiB.

## TGFV file-version object (format 2)

Each file version is exactly one Telegram document. The object contains its
encrypted metadata header followed by all encrypted content segments. No content
block documents or separate manifest documents are required. TGFV v1 is
superseded by this format.

| Offset | Length | Meaning |
| ---: | ---: | --- |
| 0 | 4 | ASCII `TGFV` |
| 4 | 2 | Format number, u16 little-endian, value 2 |
| 6 | 16 | Volume UUID bytes |
| 22 | 4 | Encrypted metadata header length, u32 little-endian |
| 26 | variable | Encrypted metadata JSON (`nonce || ciphertext || tag`) |
| following | variable | Segment ciphertexts, in order, without per-segment nonce |

The metadata header uses the hierarchy `meta` key and XChaCha20-Poly1305. Its
AAD is ASCII `teagarden.sdo.file.v2` followed by the complete 26-byte prefix.
The plaintext is UTF-8 JSON with `file_id` (UUID), `origin_message_id` (i64 or
null), `path` (safe relative UTF-8 path), `size` (u64), `mtime_ns` (signed i64),
`mode` (u32), `version_id` (UUID), `author_device_id` (UUID),
`previous_version_id` (UUID or null), `saved_at_ns` (signed i64),
`local_version` (u64), `deleted` (boolean), `segment_size` (u32),
`segment_count` (u32), and `content_sha256` (32-byte lowercase hex). The JSON
has no `blocks` member. `origin_message_id` is null only for the first version;
later revisions link to its Telegram message id. Revisions are always new
messages and never edit an existing message or use reply threading. The encrypted
`file_id`, `origin_message_id`, and `previous_version_id` fields allow history
to be grouped across paths and renames.

Segments use a fixed 1 MiB plaintext size. This keeps the per-read overhead
small while matching Telegram's 1 MiB `upload.getFile` range granularity. The
first segment begins immediately after the encrypted metadata. Segment `i` has
plaintext length `min(segment_size, size - i*segment_size)` and ciphertext
length equal to that plus the 16-byte Poly1305 tag. Therefore its offset is
`26 + encrypted_header_length + i*(segment_size + 16)`. The final segment may be
shorter. Empty files and tombstones have zero segments.

The content key is HKDF-SHA256 from the hierarchy `meta` key with info
`teagarden.sdo.content.v2 || version_id_bytes`, no salt. The 24-byte nonce is
the first 24 bytes of keyed BLAKE3 under that content key over
`teagarden.sdo.segment.v2 || "nonce" || version_id_bytes || u32le(segment_index)`.
A fresh random `version_id` makes each saved version's nonce domain distinct;
segment indices are unique within that version. Segment AAD is ASCII
`teagarden.sdo.segment.v2 || version_id_bytes || u32le(segment_index) ||
u32le(segment_count) || final_flag`, where `final_flag` is one byte (1 for the
last segment, otherwise 0). This binds order, count, finality, and version.
`content_sha256` authenticates the complete reconstructed plaintext in addition
to each segment's AEAD tag.

The supported new-save plaintext maximum is 2,092,860,184 bytes for ordinary
accounts and 4,189,980,184 bytes for Premium accounts. The corresponding wire
caps are 2,097,152,000 and 4,194,304,000 bytes. The plaintext bound reserves
65,536 bytes for the complete TGFV3 header, 4,194,344 bytes for TGFE
JSON, framing and MAC, and a 16-byte tag per 1,048,576-byte segment. At each
maximum the reserved wire bound equals the transport cap; one additional
plaintext byte exceeds it. Premium status is checked before upload. Paths are at most 4096 bytes and 256
components; absolute, empty, dot, dot-dot, and NUL components are rejected.

A worked metadata example is:

```json
{"file_id":"66666666-6666-6666-6666-666666666666","origin_message_id":null,"path":"hello.txt","size":6,"mtime_ns":1700000000,"mode":384,"version_id":"22222222-2222-2222-2222-222222222222","author_device_id":"33333333-3333-3333-3333-333333333333","previous_version_id":null,"saved_at_ns":1700000001,"local_version":1,"deleted":false,"segment_size":1048576,"segment_count":1,"content_sha256":"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"}
```

The one segment decrypts to `hello\n`; its ciphertext follows the encrypted
metadata header directly. The version UUID participates in both content-key
and nonce derivation, so a version must never be edited in place.

Legacy TGFV2 and early TGFV3 documents require the matching TGHD beside them.
Newly written TGFV3 documents include the credential envelope described below.
`teagarden decrypt <object-file>` writes that authenticated file independently of
other directory records, creates its safe relative parent directories, and
rejects directory/device records and deletion tombstones with a clear error.
`teagarden decrypt <directory>` remains tree restore: it reduces the supplied
versions and selects the visible live file at each path. It prints the supplied
versions grouped by file identity. It restores files and explicit visible empty directories, including nested
empty directories, directory modes and modification times. Directory attributes
are applied after children; deleted directory records remain deleted. It does not
restore symlinks. `--file-id <UUID>` on a directory lists only
that identity's supplied history, which may be incomplete. Output defaults to
`decrypted` beside the input; `--out` selects another new directory. Existing
output is never replaced, and traversal and symbolic-link output paths are
rejected. Use `--password-file` or `--recovery-file` to supply the credential.

## TGFV file-version object (format 3)

TGFV3 retains the segmented TGFV2 layout. Its prefix is 34 bytes:
`TGFV || u16le(3) || volume_uuid(16) || key_generation(u64le) ||
encrypted_metadata_length(u32le)`. The complete 34-byte prefix is included in
metadata AAD with context `teagarden.sdo.file.v3`. The generation is clear for
key selection and is authenticated by that AAD and the encrypted metadata.

TGFV3 encrypted metadata keeps the file identity, origin message id, path,
size, mtime, mode, version id, author installation id, predecessor id, delete
flag, segment size/count, and plaintext SHA-256 from TGFV2. It adds `kind`
(`file`, `directory`, or `device`), `key_generation`, `clock_ms`, and
`clock_counter`. It retains `saved_at_ns` and `local_version` for compatibility;
neither is used for winner ordering. Directories, tombstones, and device
announcements carry zero content segments. Device records have no filesystem
path and carry `installation_id`, `label` (at most 128 UTF-8 bytes),
`telegram_user_id`, optional `authorization_session_hash`, and `created_at_ms`.
Device-record session hashes are encrypted in this metadata; a revoked session
binding can also appear in the public TGHD2 header as described above.

The default 1.0 revoke operation cuts Telegram access and publishes a signed
cutoff. It does not change the password, volume key or encrypted files.

The TGFV3 content key is HKDF-SHA256 from the hierarchy metadata key using info
`teagarden.sdo.content.v3 || version_id_bytes`. Segment nonces and AAD use the
domain `teagarden.sdo.segment.v3`; nonce input adds `nonce`, the version UUID,
and the u32le segment index. Segment AAD binds version UUID, segment index,
segment count, and the final-segment flag. Segment lengths and offsets follow
the TGFV2 rules, with the first segment immediately after the encrypted
metadata header.

Filesystem winners are ordered lexicographically by
`(clock_ms, clock_counter, author_device_id, version_id)` using unsigned raw
UUID bytes. A file or directory tombstone has `deleted: true` and the
corresponding `kind`. Histories retain losing versions; a tombstone hides only its exact path. Non-root paths
are visible only while every winning ancestor is a live directory. Missing
ancestors of legacy TGFV1/TGFV2 files synthesize clock-zero directories, which
any explicit record overrides.

Each installation stores its HLC pair locally. Before emitting a record,
`physical_ms` becomes `max(UTC_ms, previous_physical_ms)`; the counter advances
when physical time is unchanged and resets to zero when it advances. On receive,
the physical component becomes the maximum of UTC, local, and remote physical
times, and the counter advances from whichever local/remote components match.
Persist the pair before upload; retries reuse identical object bytes and UUID.

## Key derivation

Password roots use Argon2id, version `0x13`, with the parameters in the header;
the first 32 bytes of the configured output are the root. Validate costs before
allocation. Hierarchy subkeys use HKDF-SHA256 and 32-byte output. For v0, HKDF
salt is the 32-byte volume salt. For v1, HKDF salt is
`volume_salt || i64le(group_id) || i64le(topic_id)` (48 bytes). The exact
hierarchy labels are:

| Key | HKDF info bytes |
| --- | --- |
| data | `teagarden.v1:data` |
| meta | `teagarden.v1:meta` |
| schema | `teagarden.v1:schema` |
| integrity | `teagarden.v1:integrity` |
| wrapping | `teagarden.v1:wrapping` |
| block identity | `teagarden.v1:block-id` |
| filename | `teagarden.v1:filename` |
| manifest identity | `teagarden.v1:manifest-id` |

An MK-rooted hierarchy first derives a 32-byte root with HKDF-SHA256, absent
salt, and info `teagarden.v2:mk-hierarchy-root`; that root then uses the v1
group/topic-bound hierarchy. Epoch keys use the parent key, absent HKDF salt, and
ASCII info `epoch:<decimal epoch>`.

Known-answer check: root is 32 bytes of `42`, v0 salt is 32 bytes of `01`, and
HKDF info is `teagarden.v1:meta`. The output is
`dd6df5ae57f5ee71aecb91d6006b136f3342c451a88878e8b299ea98a917e263`.

## Slot vault JSON and recovery credentials

The `slot_vault` member is the existing v2 vault JSON object, unchanged. Its top
level contains `version`, `vault_uuid_hex`, `subject_id`, `mk_commitment_hex`,
`policy_mac_hex`, `next_slot_id`, `next_share_gen`, `vault_generation`, `policy`,
and `slots`. Each slot contains `slot_id`, `slot_type`, `label`, `enabled`,
non-secret `params`, `kek_transport`, `payload_is_share`, `share_gen`, and
`payload_ct_b64`. `payload_ct_b64` is standard padded Base64 of
`XChaCha20-Poly1305 nonce(24) || ciphertext || tag(16)`.

Passphrase slot params contain `argon2: {m_kib,t,p}` and a 16-byte random
`salt_b64`. Argon2id v0x13 produces 32 bytes, then BLAKE3 derive-key context
`teagarden.v2:kek:passphrase` derives the KEK. Recovery slots decode the
production 22-word sentence to 32 bytes, then use BLAKE3 derive-key context
`teagarden.v2:kek:recovery`. FIDO2 uses
`teagarden.v2:kek:fido2-hmac-secret`.

The slot AAD is the literal bytes
`teagarden.v2:slot-wrap || vault_uuid(16) || slot_id(u32le) || slot_type(u8) ||
share_gen(u32le) || payload_kind(u8)`. `PayloadKind::MasterKey` is `a0` and
`PayloadKind::Share` is `a1`. The BLAKE3 derive-key contexts are
`teagarden.v2:mk-commitment` and `teagarden.v2:policy-mac`; policy MAC input is
the canonical policy encoding: entry count u32le, then slot entries tagged `00`
plus slot id u32le, or group entries tagged `01`, threshold u32le, member count
u32le, sorted member ids u32le, and share generation u32le. This MAC and the MK
commitment are verified after recovering the MK.

Recovery sentences use four production wordlists interleaved by word position.
Each word encodes 12 bits, most-significant bit first, for 22 words (264 bits).
The final eight padding bits are zero; the format has no checksum. Reject a
sentence whose padding bits are nonzero.

## Synthetic test vectors

The following end-to-end vector uses password bytes `vector-password`, Argon2id
v0x13 with `m=1024 KiB,t=1,p=1,out=32`, salt `01` repeated 32 times, group
`-100123`, topic `456`, and the v1 channel-bound hierarchy. UUIDs are the byte
values repeated as shown. The 24-byte test-only block nonce is `33` repeated;
the test-only manifest nonce is `44` repeated. These fixed nonces exist only in
the test fixture and must never be used by a production writer.

Derived root:

```text
e4d500edabc1405696886d351bf2321c1e9410d224cd1f0b829e7d483d3115bc
```

Complete TGHD bytes (including framing and MAC):

```text
544748440100c20100007b22666f726d6174223a312c22766f6c756d655f6964223a2231313131313131312d313131312d313131312d313131312d313131313131313131313131222c227265766973696f6e223a312c22766f6c756d655f76657273696f6e223a22312e302e30222c22726f6f745f6b696e64223a2270617373776f7264222c2273616c74223a2230313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031222c226b64665f706172616d73223a7b226d656d6f72795f6b6962223a313032342c22697465726174696f6e73223a312c22706172616c6c656c69736d223a312c226f75747075745f6c656e223a33327d2c2267726f75705f6964223a2d3130303132332c22746f7069635f6964223a3435362c2263757272656e745f65706f6368223a302c22626c6f636b5f76325f66726f6d5f65706f6368223a6e756c6c2c22726571756972655f626c6f636b5f696e74656772697479223a66616c73652c22626c6f636b5f73697a65223a313034383537362c226b65795f70726f74656374696f6e223a6e756c6c2c22736c6f745f7661756c74223a6e756c6c7d3428ddfee0fd44121c6d0aeef262b132895c4541dc2bd46a40b8b56b3cb38979
```

The first 10 bytes are magic `TGHD`, version `1`, and JSON length `0x1c2`
(450). JSON occupies the next 450 bytes. The remaining 32 bytes are the keyed
BLAKE3 MAC over `teagarden.sdo.header.v1 || first 460 bytes`.

TGFV2 content is authenticated in independent 1 MiB segments using the nonce
and AAD rules above. The deterministic fixture described here covers TGHD1, a
block and a TGFV1 manifest; it is not a TGFV2 ciphertext fixture. Production
writers use derived per-version/per-segment nonces, not fixed fixture nonces.

## TGFV3 standalone credential envelope (TGFE v1)

New complete TGFV3 documents append this trailer after the final content segment:

```
envelope_json || framing_mac(32) || json_length(u32le) || TGFE
```

The JSON has exactly four members: `header_wire` (the exact TGHD document bytes),
`object_sha256` (lowercase SHA-256 of the preceding complete TGFV3 payload),
`password_wrapped_key`, and `recovery_wrapped_key`. Byte arrays are JSON arrays.
Its size is bounded at 4 MiB before parsing. The embedded TGHD carries the salt
and Argon2id parameters for a password-rooted volume, or the complete anchored
encrypted password/recovery slot vault for a master-key volume. No separate TGHD,
local database, Telegram session, or network is needed to unlock an enveloped
object. Existing TGFV3 segment offsets do not change.

Password unlock derives the root with those KDF parameters or unwraps the
master-key password slot. Recovery unlock uses the exported hierarchy-root
sentence or unwraps the master-key recovery slot. For key-protected volumes, both attach and
single-object or directory decrypt accept the exported root; normal MAC and
owner-pin checks still apply. The two KEKs are HKDF-SHA256 from the
unlocked hierarchy root with distinct info labels
`teagarden.sdo.envelope.password.v1` and `teagarden.sdo.envelope.recovery.v1`.
Each XChaCha20-Poly1305 wrap contains the 32-byte generation metadata key and
uses AAD `teagarden.sdo.credential-envelope.v1 || u64le(header_wire_length) ||
header_wire || object_sha256_ascii`. AEAD encodings include their random nonce.
The framing MAC is keyed BLAKE3 under that metadata key over
`teagarden.sdo.envelope.framing.v1 || envelope_json || u64le(payload_length)`.
The receiver authenticates embedded TGHD, key unwrap, framing MAC, payload hash,
metadata, and content before writing. Header selection happens before credential
unlock with no fallback to an older header. In a build with the off-by-default
`key-rotation` feature, a mixed-generation directory can use the newest
authenticated neighboring TGHD's key bridges for legacy objects, and export
uses the same bridges. In the default build, `generation_meta_keys` refuses
rotation state, retained bridges and nonzero generations when acquiring generation
keys for mount and export. Single-object forensic decrypt instead authenticates the
embedded header and opens the wrapped key through the object's envelope; it can
recover an authenticated object from any generation and does not assert current
namespace policy. Directory recovery applies its separate current-policy checks.

An object written before a password change opens with **the password that was
current when it was written, or its recovery sentence**. Changing the password
does not alter an already downloaded document. Revocation does not re-encrypt retained versions or change their credentials.

## Owner trust anchor on first attach

Default creation writes an owner capability and publishes TGHD2. Creation prints
its non-secret `Owner public key`. Copy this 64-character lowercase hexadecimal
Ed25519 public key from the creating computer through a trusted channel, then use
`teagarden volume attach GROUP_ID:TOPIC_ID --owner-public-key HEX` with the volume
password or recovery sentence. Fresh TGHD2 attach requires this independent pin:
the password authenticates shared encryption, but does not distinguish the owner
from another password holder who could sign with a replacement key. Attach saves
the verified pin in authenticated local configuration. Mount, polling and future
header updates require TGHD2 with that same pin; downgrade and re-ownership are
rejected. Version 1.0 attach refuses TGHD1 outright; there are no installed
TGHD1 volumes to migrate. An offline `decrypt` invocation can supply
`--owner-public-key HEX` to enforce its established owner independently of nearby
files; a standalone artifact without an external anchor proves credential-bound
content authentication, not independent knowledge of the original owner identity.

In default 1.0, revocation records the first excluded Telegram position and the
current key generation for the target installation. Earlier objects in that
same generation remain authorized; later objects do not. The cutoff is persisted
before the access-cut request and never advances on a retry. Missing cutoff
evidence refuses namespace reconstruction. No generation is created by revoke.

## Installation authority and generation transitions

New writers add `authority` to TGFV3 metadata: an Ed25519 public key and signature
in lowercase hexadecimal. Each installation derives this separate signing seed
as BLAKE3(`teagarden.installation-signing.v1 || private_ML_KEM_seed`); its public
receiving key cannot derive the signer. The signature covers
`teagarden.sdo.writer-authority.v1 || volume_uuid || normalized_metadata_json`.
Normalization sets generation to zero and omits authority and migration receipt;
all logical fields, including version UUID, HLC, path, author UUID, attributes and
content hash, remain bound. Generation itself remains bound by TGFV framing AEAD.
This lets a verified logical save be re-encrypted without its author's presence.

`volume history`, `volume diff`, and `volume restore-version` authenticate the
selected topic header against the installation's owner pin and use the same
transition-filtered scan as mount and attach. History retains legitimate older
versions, renames, deletions, and owner-preserved pre-revocation versions;
post-cutoff objects claiming the revoked ID are excluded under the current policy.
Revoke freezes the signing keys of non-revoked registered installations. An
object claiming a frozen UUID must carry a valid signature from its exact key;
missing or wrong-key signatures are refused, including with directory decrypt's
`--include-unverified`. A registered survivor without an authenticated signing
key causes revoke to refuse before the access cut. A new, never-seen UUID remains
accepted as a new author, including for writes to existing paths.

Existing installations persist the highest authenticated owner revision outside
the disposable index. Mount startup, live polling, history, diff, restore-version,
export and device list reject older revisions across restarts. Loss or rollback of
trusted local installation state is outside this protection. A new attach has no
prior observation: pinning the owner key does not prove that the latest revision
was delivered; establish freshness separately.
Restoring a version is a new save by the restoring installation: it gets a fresh
UUID and HLC, links to the selected version, and carries that installation's
signature and the current credential envelope. It does not inherit the source's
writer signature or migration receipt. Its one downloaded TGFV can be decrypted
with the credential current at restoration, independently of the source object
or a local history database.

## Mount readiness and local recovery

Portable mounts authenticate and apply the initial topic scan, seed the hybrid
logical clock from that history, recover pending writes, and publish their
installation announcement before creating the FUSE session. Daemon readiness
follows this preparation and successful kernel mount. A corrupt recognized object
or unrecovered outbox record fails preparation rather than advertising readiness.

Pending file writes live at `outbox/<installation_uuid>/pending.db` beneath the
local volume directory, outside disposable mount-instance indexes. The encrypted
outbox retains acknowledged bytes and a complete logical metadata snapshot even
before a TGFV wire exists. A later mount can reconstruct the write without the old
inode database. Recovery verifies the uploaded replacement before applying its
location and removing the pending record; generation upgrades retain the same
logical version, clock, predecessor and contents.

The persistent `device-keypair.json` receiving seed is AEAD-wrapped under the
already-unlocked local hierarchy wrapping key, with the public key in associated
data. Legacy plaintext seed files are migrated on successful local unlock.
Back up the local volume directory, including these installation files and the
outbox, to retain this installation's local state and pending writes.

Portable TGFV mounts refuse symlink creation with ENOTSUP and a diagnostic.
Directory mode and modification time are published as directory versions;
attributes absent from the portable model, including directory access time and
ownership changes, are refused rather than acknowledged as persistent.


Version 1.0 first-anchor rule: attach accepts only owner-signed TGHD2. It
refuses TGHD1 even if all TGHD2 evidence is absent from the topic. Supply the
independently obtained owner public key with `--owner-public-key`; attach
persists that pin and always prints its authenticated SHA-256 fingerprint and
public key. Absence of owner evidence in an untrusted store never enables a
legacy trust mode.


Export selects the authenticated TGHD and accepted TGFV objects by wire content,
not Telegram filenames. Renamed or imported valid documents are included, and
unrelated content is skipped even if its filename looks like a TeaGarden document.

Current-state export applies the same authority and transition predicate as
mount, using actual Telegram source message IDs. It writes
`export-provenance.json`, authenticated under the current integrity key and
bound to the exact normalized current header, object hashes and source IDs.
Source-position claims additionally require the separate owner's Ed25519
signature. A shared-key MAC proves bundle integrity; it cannot authorize a
pre-revocation position. Exports without the owner capability retain signed
writer/owner-receipt recovery, but unproved old source positions are treated as
unknown. Stripping the owner signature never falls back to shared-key authority.
Directory decrypt authenticates that current TGHD policy before decoding any
version, verifies export provenance when present, and applies the same predicate
before reducing the tree. It rejects altered provenance rather than silently
falling back. Bare filenames do not prove historical source positions: unlisted
objects use a conservative unknown position, so renaming a rejected old write
to a pre-boundary-looking filename cannot authorize it. Owner receipts and
pinned surviving signatures remain usable without a source listing.
Directory restore requires its authenticated current TGHD context; supply the
independently established `--owner-public-key` to identify the owner.

Single-object decrypt explicitly reports **Forensic single-object recovery**.
It can recover cryptographically authenticated historical bytes with the
credential that opens that artifact, including bytes excluded from current
volume state. It does not claim current revocation or namespace authorization.


The provenance wrapper carries `payload`, `mac`, and nullable `owner_signature`.
The MAC is keyed BLAKE3 under the current integrity key over
`teagarden.export-provenance.v1 || JSON(payload)`. The optional Ed25519 owner
signature covers `teagarden.export-source-authority.v1 || JSON(payload)` and is
verified against the authenticated owner anchor. The payload binds format one,
volume UUID, header revision, SHA-256 of the normalized header JSON, and each
filename's source message ID and full-object SHA-256. Both authenticators use
the parsed payload's JSON serialization. An invalid owner signature is an error;
an absent signature grants no source-position authority. An authorized current
writer cannot backdate a revoked object's source merely by recomputing the MAC.

A current namespace reader refuses an authenticated header if any revoked
installation lacks a recorded per-device cutoff. It reports the number and
installation UUIDs with missing evidence, rather than silently presenting a
partial filesystem or guessing from a later generation boundary. This applies
to topic scans, attach, mount/live apply, export and directory recovery. Header
codecs remain available to the owner's interrupted-publication resume logic;
explicit single-object forensic recovery does not assert current namespace
policy.


Directory recovery validates every supplied object before writing any files. If
an object cannot pass the current authority/transition rule, recovery refuses
with an object count and reasons. Missing owner source-position provenance is
not silently interpreted as proof that an original was unauthorized. This can
occur in a non-owner export, including during an interrupted owner migration in
a `key-rotation` build: its shared-key MAC authenticates the export bytes but
cannot attest Telegram source positions as the owner.

Use `teagarden decrypt OBJECTS --include-unverified` only for explicit recovery
of such objects. Each affected version and diagnostic is labelled `UNVERIFIED`,
and the summary states that current namespace authority is not asserted for
those objects. The flag does not bypass ciphertext authentication, the owner
pin, missing revocation cutoffs, or an owner-proven source position rejected by
the current policy. Historical version reduction still selects the latest
visible file version for each path; the printed version list includes the
unverified labels.

An export provenance listing also defines the expected object inventory.
Directory recovery refuses a listed object that is missing, non-regular, has an
unsafe name, or is no longer recognized as TGFV. The error counts those objects;
`--include-unverified` cannot recover absent or unrecognized ciphertext.
