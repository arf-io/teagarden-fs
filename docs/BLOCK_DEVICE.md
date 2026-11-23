# The encrypted block device (`teagarden dev`)

`teagarden dev` (the engine is called `teagarden-dev`) gives you an encrypted **disk**
whose contents are stored in your Telegram account. You expose it over NBD, attach
it as `/dev/nbdN`, and put an ordinary filesystem on it yourself.

The commands are modelled on `cryptsetup`:

| cryptsetup | TeaGarden | What it does |
|---|---|---|
| `luksFormat` | `dev create` | Create the device and its Telegram topic, write its superblock and first checkpoint |
| `open` | `dev serve nbd` | Serve the decrypted device over NBD |
| `status` | `dev status` | Report capacity, epoch, segments and the recovery checkpoint |
| `resize` | `dev resize` | Grow the device |
| | `dev gc` | Reclaim space held by overwritten data |
| | `dev recover` | Rebuild the local state from Telegram |
| | `dev list` | List registered devices |
| | `dev delete` | Delete the device's Telegram topic, then its local state |

There is no `mkfs.teagarden`. The filesystem on the device is a normal guest
filesystem (ext4, XFS, Btrfs, ...), made with the normal tools.

## A folder or a disk?

| | `volume` (FUSE folder) | `dev` (block device) |
|---|---|---|
| You get | a mounted directory | a raw device you format yourself |
| Platforms | Linux, macOS | tested on Linux; attaching with `nbd-client` needs Linux |
| Unlock | password or key slots | a device credential (password) only |
| Storage on Telegram | one TGFV document per file version | log-structured ~45 MiB segments |
| Durability barrier | `close`/`fsync` wait for Telegram | `fsync` waits for the local staging log (see below) |
| File version history | yes | no |

Use a volume by default. Use a device for real kernel filesystem semantics or a
specific filesystem.

## Quick start (Linux)

You need the `nbd` kernel module (`sudo modprobe nbd`) and `nbd-client`.

```bash
teagarden auth login                                  # once
teagarden dev create --name vault --size-gib 20       # asks for a device credential
teagarden dev serve nbd vault                         # foreground; listens on 127.0.0.1:10809
```

In a second terminal:

```bash
sudo nbd-client -b 4096 127.0.0.1 10809 /dev/nbd0     # 4096-byte blocks are required
sudo mkfs.ext4 /dev/nbd0                              # first time only
sudo mkdir -p /mnt/vault
sudo mount /dev/nbd0 /mnt/vault
```

Tear down in this order:

```bash
sudo umount /mnt/vault
sudo nbd-client -d /dev/nbd0      # dev serve nbd then finalizes and exits
```

`nbd-client -d` disconnects cleanly, and `dev serve nbd` then uploads the
partly filled segment, publishes a final checkpoint, records it in the registry
and exits. Ctrl+C (or SIGTERM) on `dev serve nbd` does the same; unmount the
guest filesystem first, because the device goes away when the server exits.
`dev serve nbd` exits with status 0 only if all of that succeeded.

NBD device numbers are assigned in attach order and are not stable across
reboots, so keep `/dev/nbdN` out of `/etc/fstab`. The repository includes
`scripts/teagarden-dev-attach` and `system/teagarden-dev@.service` for attaching a
device at boot; their header comments describe their use.

## Commands

All commands that open the device ask for the device credential. Use
`--password-file PATH` (or `-` for standard input) to supply it non-interactively;
if neither is given, `TEAGARDEN_DEV_PASSWORD` is used when set. There are no key
slots for devices in 1.0.0.

- **`dev create --name N --size-gib S`** creates the device. `--segment-mib`
  (default 45) sets the segment size; one segment is one Telegram document.
  `--dir` sets where local state is kept. The device's topic goes into the same
  private group as your volumes and gets a random title; the device name stays in
  the local registry. A fresh random salt is used per device.
- **`dev list`** shows registered devices.
- **`dev status N`** opens the device and prints capacity, mapped blocks, epoch,
  confirmed segments, the cloud watermark, the last checkpoint ("head") message id
  and the Telegram topic.
- **`dev serve nbd N [--bind HOST:PORT]`** serves the device. The default bind
  address is `127.0.0.1:10809`. It publishes checkpoints while serving and a
  final one when it stops (see [Durability](#durability-and-crash-safety)).
- **`dev gc N`** compacts segments that are mostly overwritten data (by default,
  segments less than 30% live) and deletes segments nothing refers to any more.
- **`dev resize N --size-gib S`** grows the device. Shrinking is refused. Grow the
  guest filesystem afterwards (for example `resize2fs`).
- **`dev recover N [--head-msg-id ID]`** rebuilds the local state from a
  checkpoint on Telegram (see below).
- **`dev delete N [--password-file F] [--force] [--local-only]`** permanently
  deletes the device: first its Telegram topic (every segment, head and
  checkpoint), then its local state directory and registry entry. It needs the
  device credential. It refuses, deleting nothing, if the credential is wrong or
  the device is open (for example while `dev serve nbd` runs). Without `--force` it
  asks for confirmation; with no terminal, or the answer no, it exits with an
  error and deletes nothing. If the topic cannot be deleted, the local state stays
  and the command can be run again. `--local-only` removes only local state and
  prints the topic id and group to remove by hand. It refuses a state directory
  holding files TeaGarden did not write. A device with no state directory needs
  `dev recover` first.

The registry record for each device is `~/.local/share/teagarden/devices/<name>.json`
on Linux (`TEAGARDEN_DEV_REGISTRY_DIR` overrides the directory). It holds the device's
salt, Telegram group and topic, geometry and last checkpoint id, but no key
material. By default the device's local state directory is
`<registry dir>/<name>/data`.

**Back up the registry record.** The salt in it derives the device keys, and
`dev recover` needs it.

## Security of the NBD socket

NBD has no authentication. While `dev serve nbd` runs, **any local user who can
connect to the bind address gets full read and write access to the decrypted
device.** On a single-user machine, the loopback default limits that to your own
processes. On a shared machine, isolate the socket in a network namespace or do
not serve. Bind a non-loopback address only on a network you fully control.

## Single writer

An open device holds an exclusive `flock` on its state directory. While
`dev serve nbd` is running, `dev status`, `dev gc`, `dev resize` and a second
`dev serve` for the same device are refused. The lock is released when the
process exits, including if it is killed.

## Durability and crash safety

The device is write-back:

1. A write is encrypted into the current open segment and appended to a local
   **staging log** (`staging.log`), with no Telegram round trip.
2. An NBD `FLUSH` (what the guest filesystem sends on `fsync`) makes the staging
   log durable on local disk. After that, the write survives a crash or power cut
   of this machine.
3. When a segment fills up (45 MiB by default) it is sealed and uploaded. Only
   after its entry in the local `catalog` file is durable is the segment counted
   as confirmed on Telegram.

An acknowledged `fsync` means "safe on this machine's disk", not "safe on
Telegram". If you lose the machine or its disk, writes that were not uploaded
are lost.

Local state stays consistent through these mechanisms:

- **Torn tails are trimmed.** On open, replay of the staging log stops at the
  first incomplete or unauthenticated entry, and the log is truncated (and
  fsynced) to that valid prefix before anything new is appended. If the first bad
  entry was complete but failed authentication, the cut bytes are kept in
  `staging.log.discarded-<len>` for inspection.
- **A failed fsync is sticky.** After a staging or catalog fsync fails, the kernel
  can report a later fsync as successful although the earlier data never reached
  disk. The device therefore enters a failed state: every later write, flush, GC and
  configuration change returns an error (an I/O error to the NBD client) until the
  device is reopened, which re-reads what is really on disk.
- **The staging log is compacted** once it grows past a threshold (at least eight
  segments' worth). Compaction writes a new log, fsyncs it, renames it over the
  old one and fsyncs the directory; a crash leaves either the old or the new log.
- **Unuploaded segments are re-uploaded.** On the next open, staged segments that
  were never confirmed are rebuilt from the staging log and uploaded when the
  device is next closed.

### Checkpoints while serving, and what a crash can lose

`dev recover` rebuilds the device from its newest **checkpoint** (below). A
checkpoint covers the longest run of segments, from the first, that are all
confirmed on Telegram. `dev serve nbd` publishes checkpoints itself and records
each one in the registry:

- **While serving**, every 5 seconds it checks how many uploaded segments the
  last checkpoint does not cover. It publishes a new checkpoint when that count
  reaches 8, or when it is at least 1 and 60 seconds have passed since the last
  checkpoint (or since the server started). A failed publish is retried at the
  next check.
- **When it stops** (Ctrl+C, SIGTERM, or a clean `nbd-client -d`), it seals and
  uploads the open segment, retries uploads that failed earlier, and publishes a
  final checkpoint. After a clean stop, the newest checkpoint covers every write
  the server acknowledged.
- **A second Ctrl+C or SIGTERM while it is still finalizing** ends it at once, with
  exit status 1 and a message saying finalization is incomplete. The last segment
  is then not uploaded and no final checkpoint is published, so the device is
  in the first situation below: everything acknowledged by FLUSH is in the local
  staging log. Run `dev serve nbd` again and stop it once with Ctrl+C.

The exact bound after an unclean end:

- **The process dies or the machine loses power, but its disk survives.** Nothing
  acknowledged by FLUSH is lost. Start `dev serve nbd` again: the staging log is
  replayed, segments that were never confirmed are uploaded, and the next clean
  stop publishes a checkpoint covering them. Writes not yet flushed can be lost,
  as on any disk.
- **The machine or its disk is lost** (only Telegram remains). `dev recover`
  returns the device as of the newest published checkpoint. Lost are:
  1. the writes in the **open segment**: everything written since the last
     segment filled up, at most one segment's worth of data (45 MiB at the
     default `--segment-mib`). A segment is sealed and uploaded only when it is
     full or when the server stops cleanly, so these writes can stay local for
     as long as the device is written slowly;
  2. segments that were **uploaded but not yet covered by a checkpoint**: fewer
     than 8 in steady state (a checkpoint follows within 5 seconds of the 8th),
     and only those uploaded in roughly the last 65 seconds (60 seconds plus one
     5-second check), while publishing works;
  3. segments whose **upload has not succeeded yet** (for example while Telegram
     is unreachable), and every segment after the first such gap, since a
     checkpoint only covers an unbroken run from the first segment.

A smaller `--segment-mib` at `dev create` shrinks the first item and produces more
Telegram documents. Telegram holds an off-machine copy as of the newest
checkpoint only; if it is your only copy, the bound above is what you can lose.

Of the other commands, `dev gc` and `dev resize` open and close the device,
which also uploads the open segment; `dev resize` publishes a checkpoint, and
`dev gc` does when it finds something to collect. `dev status` does neither.

## Recovery from Telegram

The device's recovery point on Telegram is its **checkpoint** (the "head"): an
encrypted record of which data lives in which segment, up to a point where every
earlier segment is confirmed. A checkpoint is published by `dev create`,
`dev serve nbd` (while serving and when it stops, see above), `dev resize`, and
by a `dev gc` pass that finds something to collect. The newest one's message id
is stored in the registry record.

To rebuild a device on a new machine, or after losing its local state:

```bash
teagarden dev recover vault                     # uses the recorded checkpoint
teagarden dev recover vault --head-msg-id 4242  # or a specific one
```

You need the registry record and the device credential. The state directory must
be missing or empty; move old state aside first. While recovery runs it keeps a
`recovery.incomplete` marker in the directory, created before any device file is
written and removed only once everything is durable. A device directory with that
marker is refused by open, so a half-finished recovery is never used. If recovery
is interrupted, move the directory aside and run it again.

The recovered device has the contents as of that checkpoint. Writes after it are
not included.

**After `dev gc`, only the newest checkpoint is usable.** GC deletes segments that
the newest checkpoint no longer refers to, which older checkpoints can still need.
`dev gc` records the newest checkpoint id in the registry. An older checkpoint id
is not a backup.

## Limits

- **Rollback is not detected.** The superblock and each checkpoint are
  authenticated, so they cannot be forged or edited. An older authentic copy
  is accepted: someone who can write the device directory can put back an
  older `superblock` (undoing a resize), and recovering from an older checkpoint
  gives you the older contents without a warning. Nothing outside the device
  anchors its generation counter.
- **No redundancy.** One lost or deleted segment on Telegram loses every block
  mapped into it. Keep an independent backup.
- **Discard and GC are not secure erase.** Discard (TRIM) drops the
  device's references to the data; `dev gc` later deletes segment messages that
  nothing refers to. Deleted messages can persist on Telegram's side. The
  bytes are ciphertext.
- **Upload pace is not managed.** Segment uploads wait only when Telegram asks the
  client to wait (up to 5 minutes per request). When staged-but-not-uploaded data
  reaches its local budget, further writes fail until uploads catch up.
- **Attaching is Linux-only.** The `dev` commands are part of the default build on
  macOS as well, but macOS has no NBD client, so the device attaches only from
  Linux. Serving from macOS is untested for 1.0.0.
- **Traffic shape is visible.** Telegram sees when and how much you write. Every
  segment is padded to the full segment size, and checkpoints are padded to a
  multiple of 4 KiB, so individual write sizes are not visible.
- **Upload names.** Segments and checkpoints are uploaded under 12 random hex
  characters with no extension. The name carries no segment id or role and is
  never read back (documents are fetched by message id).

For the exact formats, see [FORMAT.md](FORMAT.md). For the cryptography, see
[SECURITY_MODEL.md](SECURITY_MODEL.md).
