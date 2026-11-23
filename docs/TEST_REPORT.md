# Test report: TeaGarden 1.0.0

This report covers the tests that ran, what each one exercised, and what has not been verified yet. Every result below was observed directly. Nothing here was carried over from an earlier release candidate unless that is stated.

## November 23 release candidate

The November 23 checks used source commit `eb71fbfe961bcc75db356ae8c52c7558a684fd62`. The Linux x86-64 executable used for the live tests has SHA-256 `f51a5a2ca8d54ac543ad809fe6798e79effaa952345822d5d4f505ae8d8c18dd`.

| Check | Observed result |
|---|---|
| Clean Ubuntu 24.04 x86-64 installation | Built from the locked source, installed, reported `teagarden 1.0.0`, packaged with its license, and uninstalled successfully. The downloaded archive matched its SHA-256 checksum. |
| macOS Apple silicon build and non-mount tests | Clippy passed. The test harness reported 1,414 passed, 0 failed, and 0 ignored across 59 test binaries. This run did not exercise macFUSE mounting or physical security keys. |
| `scripts/test/live-e2e.sh` over Telegram | Passed on Linux x86-64, including byte-exact reads and fresh attach at 1 MiB, 10 MiB, and 100 MiB. |
| `scripts/test/durability-e2e.sh` over Telegram | The complete serial rerun passed. In an earlier attempt the graceful-unmount and SIGINT data checks passed, but the run failed overall when a read-only export call received a Telegram `RPC_CALL_FAIL` response. |
| `scripts/test/teagarden-dev-nbd-fs-e2e.sh` over Telegram | ext4, XFS, and Btrfs passed byte-exact verification after restarting the NBD server, including filesystem, persistence, and deletion checks. The test used Debian's packaged `nbd-client` 3.26.1 from a test directory. |

Physical FIDO2 testing and the full three-installation Telegram revoke test with distinct authorizations remain pending for this build. The November 18 shared-authorization test below does not exercise per-installation revocation.

## November 18 build and automated tests

These results are for commit `d33780f`. All tests ran on one Linux x86_64 test host (Proxmox kernel 7.0.14, Debian userland). `TEAGARDEN_REQUIRE_FUSE=1` was set, so tests that need a real FUSE mount fail instead of skipping.

| Check | Default build (1.0) | With `--features key-rotation` |
|---|---|---|
| `cargo fmt --all -- --check` | pass | pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | pass | pass |
| `cargo test --workspace --all-targets --locked --no-fail-fast` | **1,512 passed, 0 failed, 0 ignored** (59 test binaries) | **1,543 passed, 0 failed, 0 ignored** (59 test binaries) |
| `scripts/check-docs-help.sh` (documentation matches `--help`) | pass | n/a |

Most of these tests use a mock Telegram transport. The FUSE tests mount real kernel filesystems. The tests do not contact Telegram; the live tests below do.

## November 18 live tests against real Telegram

These runs used the same test host and one ordinary (non-Premium) Telegram account. Each run's binary is identified below.

The results in this section come from a release build of commit `d33780f`, sha256 `71bfc113ee93f8fc90b441779160592d6e4622a2554adeb4ce2f788b257ecf70`, run on 2026-11-18. That build includes every fix listed in this report.

The 1 GiB figures in [BENCHMARKS.md](BENCHMARKS.md) come from an earlier build, commit `06c6090`. That build predates the review fixes. On the final build, a 100 MiB write measured 9.38 MiB/s (9.33 MiB/s before) and a 100 MiB first-mount read measured 3.35 MiB/s (3.48 MiB/s before).

### Single computer: `scripts/test/live-e2e.sh`: PASS

This test uses one volume, a real FUSE mount and file sizes of 1 MiB, 10 MiB and 100 MiB.

- Create the volume. Write each file and read it back byte-equal, cold and warm.
- Unmount, then attach the volume as a new installation from Telegram alone, and read everything back byte-equal.
- Overwrite part of a saved file through the same open descriptor after fsync, overwrite part of it again after reopening, and truncate a file that has unsaved writes. After a remount, and again after the from-Telegram recovery mount, each result matches a reference file built the same way on local disk.
- Symlink creation is refused with `ENOTSUP`. 1.0 volumes do not store symlinks.
- `key rotate` is refused in the default build. Key rotation is not part of 1.0.
- Clean up: the volume and its Telegram topic are deleted.

Timings are in [BENCHMARKS.md](BENCHMARKS.md).

### Durability: `scripts/test/durability-e2e.sh`: ALL PASS

- Write a 16 MiB file, then unmount. Exactly one file version was published, and its content was byte-equal.
- Write a 16 MiB file, then stop the mount with Ctrl+C (SIGINT). The upload finished, exactly one version was published, and the content was byte-equal.

### Three installations on one Linux host: partial pass with `SHARED_SESSION=1`

The `scripts/test/multicomputer-live.sh` run gave each installation its own home, volumes directory and config directory. All three used copies of one Telegram login. Every exercised step passed. This mode skips revocation.

| Step | Result |
|---|---|
| A creates an owner-signed volume | pass |
| B and C attach with the password and pin A's owner key | pass, 7.7 s |
| A, B and C mount read-write at the same time | pass |
| Writes propagate between every pair of installations (6 samples) | pass. Median about 6 s, maximum 27.6 s |
| A and B edit the same file at once, from the same starting version | pass. All three mounts converge on one value, and both versions name the same predecessor |
| `volume history` on A, B and C shows both versions, with full UUIDs and both authors | pass |
| C runs `volume restore-version` on B's older version | pass. All mounts show the restored content as a new version authored by C |
| A file handle opened before a rewrite keeps the version it opened | pass |
| A, B and C end with identical trees (SHA-256 manifest) | pass |
| One file-version object is downloaded and decrypted offline with the password alone | pass. A nested path came back byte-equal |
| A whole directory is decrypted offline | pass. 9 files and 4 explicit directories match the source |
| `device revoke` | **NOT RUN**. Revoking a shared login would sign out every copy of it |

### Logging in a new computer from a logged-in one

- **`teagarden auth approve`: pass.** Run from a logged-in installation, it approved a login token. Telegram registered the new device.
- **`teagarden auth login --qr`: not completed.** The new installation could not finish the login, because the test account has a Telegram cloud password (two-step verification). On a terminal, the command prompts for that password. The run was unattended, so nobody could enter it. The command refused and said so.

## Defects found and fixed in this release

| Found by | Defect | Fix |
|---|---|---|
| live-e2e, 100 MiB file | A 100 MiB write took 1,304 s. Every write re-encoded the whole file into a local store (about 42 GB of local writes for one 100 MiB file), and parts were uploaded one at a time. | `a7bbabb`, `a4dfe90`: one local spool, 32 parts in flight on one connection, one version per write |
| live-e2e | Each `cp` published an empty version before the real one. | `a7bbabb` |
| multicomputer-live | A shell redirect (`printf x > f`) published an empty version first, because bash duplicates and closes the file descriptor. | `d7d4752` |
| multicomputer-live | `volume restore-version` compared the version's timestamp, not its size, with the size limit, so it refused every real version. | `06c6090` |
| full test suite under load | A forked mount daemon kept holding the volume lock after the parent released it. | `38b9e7a` |
| `volume delete` output | A 1.0 volume was described as "0 block(s), metadata snapshots and journal". | `a9b7b43` |
| independent review | Overwriting part of a saved file through the same descriptor, after fsync, could replace the earlier bytes with zeros. | `b730c97` |
| independent review | After a crash while preparing a write, recovery could publish an incomplete prefix as a new version. | `c3bc2be`; then `c65ea5e`: recovery publishes only writes that reached a durability point (flush, fsync or close) and sets aside anything else without blocking the mount |
| independent review | The local write spool held the file being written as plaintext. | `5728638`: the spool is encrypted at rest in authenticated blocks |
| independent review | Truncating a file with unsaved writes did not resize them. A clean truncate followed by another write could bring truncated bytes back. A shrinking file reported its old size. | `3a65cb1`, `201d448`, `52532fd` |
| independent review | An interrupted upload whose parts Telegram had dropped failed on every later mount. | `e670db6`: the upload restarts under a new upload id |
| independent review | The cloud password left unzeroized copies in memory. | `bcdd7d5`, `f090be9` |
| independent review | A read past the end of a file with unsaved writes returned an I/O error. | `81cc37e` |
| independent review | A daemon crash between closing a new empty file and publishing it lost the publication. | `e7d52a3` |
| independent review | A transient upload failure while recovering a prepared write blocked the mount. | `c2f8bd4`: the write stays pending and is retried at the next mount, and the mount proceeds |
| independent review of `c2f8bd4` | A create that failed could leave an intent that recovery published as an empty file. Uploads refused for permanent reasons stayed pending forever. | `cdc70e9`: the owed publication is recorded only after the create commits, and permanent refusals (EPERM, EACCES, ENOTSUP, EFBIG) are set aside |

## Not verified in this release

These items have not been tested. They are listed so that nobody assumes otherwise.

| Item | Status |
|---|---|
| Live `device revoke` against real Telegram | The full harness requires three distinct authorizations on its test account. The November 18 runs used a shared authorization. A November 23 live preflight confirmed that Telegram can mask the current hash as `0`. Full acceptance uses the two distinct hashes returned when the owner approves B's and C's exact login URIs. |
| Revoking a device that belongs to a different Telegram account (group ban) | Not run live. |
| FIDO2 key slots on hardware | Not verified on hardware. Mode selection and refusal of modes that cannot be enforced are covered by automated tests with a scripted plugin. |
| TPM2, PKCS#11 and Tang key slots on hardware | Not verified on hardware in this release. |
| macOS mounts (macFUSE, FUSE-T) | No physical mount test on the November 23 candidate. The hosted macOS checks covered the build and non-mount runtime tests. |
| Read speed | Measured at about 3.5 MiB/s. That is likely Telegram's download limit for non-Premium accounts, but this was not isolated. See [BENCHMARKS.md](BENCHMARKS.md). |

## Independent review

An independent reviewer (Codex, gpt-6-astra) audited the release candidate several times. Each audit read the code paths and ran selected tests on the test host. All findings were fixed and checked again. Two of those rounds came after the upload rework. They found the high-severity write-path defects in the table above, which every automated test and live run had missed.

The final re-check, of `c65ea5e` through `f090be9`, confirmed those fixes. It found two medium-severity edge cases: the empty-file and transient-upload rows in the table. They were fixed in `e7d52a3` and `c2f8bd4`. A separate reviewer (a Claude code-review agent) then reviewed those two commits and found two medium-severity problems, which were fixed in `cdc70e9`. That reviewer also found a retry limit that remains:

- A failed recovery upload is retried at the next mount, not during the current session. Until then, that pending write is not visible in the mounted filesystem.

A failure while recording a successful recovery upload no longer stops the mount (fixed in `d33780f`). The published version is applied by the topic poller, and the local record is repaired at the next mount.
