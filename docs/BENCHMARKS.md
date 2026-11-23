# Benchmarks

The figures below come from TeaGarden 1.0.0 running against real Telegram. Each one is from a single run, so treat them as indicative rather than averages.

## Test setup

| Item | Value |
|---|---|
| Binary | `teagarden 1.0.0`, release build of commit `06c6090`, sha256 `3bcf0aa77d26031625c3dd60cdb257060658022a5fe69a5e5062de008af95045` |
| Host | Linux 7.0.14 (Proxmox kernel), x86_64, Intel Xeon E5-2697 v2 @ 2.70 GHz, 24 threads, 62 GB RAM |
| Telegram account | One ordinary (non-Premium) account, logged in with a user session |
| Mount | FUSE 3 on Linux, one mount per installation |
| Network | The host's normal internet connection; nothing else was shaped or tuned |
| Upload settings | One MTProto connection, 512 KiB parts (Telegram's per-request maximum), 32 parts in flight |

Test commands:

- `scripts/test/live-e2e.sh` with `SIZES_MIB="1 10 100 1024"`
- `scripts/test/multicomputer-live.sh` with `SHARED_SESSION=1`
- two short experiments, described below

## File write and read (live-e2e, 2026-11-18)

Source: the machine-readable results file of the 1 GiB run (2026-11-18), kept with the release evidence.

The test file is random data. "Write" is the time for `cp` into the mount to finish, and includes the upload to Telegram. "First mount read" reads the file on a fresh mount. "Second mount read" reads it again after unmounting and mounting again. "Recovery read" reads it after a new installation attaches the volume from Telegram alone.

| Size | Write | First mount read | Second mount read | Recovery read |
|---|---|---|---|---|
| 1 MiB | 1.30 MiB/s | 1.47 MiB/s | 1.47 MiB/s | 1.45 MiB/s |
| 10 MiB | 7.72 MiB/s | 3.31 MiB/s | 3.70 MiB/s | 3.57 MiB/s |
| 100 MiB | 9.33 MiB/s | 3.48 MiB/s | 3.42 MiB/s | 3.54 MiB/s |
| 1 GiB | 9.96 MiB/s (102.8 s) | 3.47 MiB/s (295.5 s) | 3.67 MiB/s (279.3 s) | 3.48 MiB/s (294.4 s) |

Every read was byte-equal to the source.

## What limits throughput

| Experiment, 256 MiB | Write | Read |
|---|---|---|
| 32 parts in flight, one connection | 9.74 MiB/s | 3.37 MiB/s |
| 64 parts in flight, one connection | 9.56 MiB/s | 3.22 MiB/s |
| 128 parts in flight, one connection | 9.62 MiB/s | 3.27 MiB/s |
| Two uploads at once, two connections | 16.75 MiB/s combined | not measured |

What these results show:

- **Uploads look capped per connection.** On one connection, more parts in flight did not raise upload speed. Two connections at once came close to doubling it. These results fit a per-connection limit but do not isolate its cause. TeaGarden 1.0 uploads over one connection, and a single file uploaded at about 10 MiB/s on this host.
- **Downloads of 10 MiB and larger held at about 3.5 MiB/s** at every parallelism level tested. Small files are slower, because their time is mostly per-request latency. The test account is not Premium, and Telegram limits download speed for non-Premium accounts. That limit is a likely cause, but it was not isolated.
- **Each read after a remount is fetched from Telegram again.** A mount keeps up to 32 MiB of recently read, authenticated segments in memory. Unmounting discards them. The "second mount read" column therefore measures fetching again, not a warm cache. Rereading within one mount was not benchmarked.

## Local overhead, without network

This was measured with a mock transport through a real FUSE mount, on the same host. It shows TeaGarden's own processing cost, with no network involved. Source: the final measurement run of the upload rework (commit `a4dfe90`).

| Operation, 100 MiB `cp` | Result |
|---|---|
| Write | 109.4 MiB/s. Most of the time goes to the SHA-256 digests over the plaintext and over the encrypted object. |
| Read | 478.2 MiB/s |
| Extra local copies per write | none. The write spool is the only local copy. |
| Versions published per `cp` | 1 |

## Multi-computer timings (multicomputer-live, 2026-11-18)

Three installations ran on one host, sharing one Telegram login.

| Measurement | Result |
|---|---|
| Attach an existing volume from Telegram | 7.7 s |
| Change propagation between mounted computers, 6 samples | median 6.3 s, maximum 27.6 s |

The maximum is the first sample. A computer that has been idle polls Telegram less often, so its first change takes longer to arrive. Mounted computers poll every 4 s while active and every 30 s while idle.
