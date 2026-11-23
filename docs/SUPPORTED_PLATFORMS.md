# Supported platforms

TeaGarden 1.0.0 is built from source (see [GETTING_STARTED.md](GETTING_STARTED.md)).
It needs Rust 1.89 or newer.

| Platform | Status for 1.0.0 | What was run |
|---|---|---|
| Linux on aarch64 | Linux support; release verification pending | See the release test report when available. |
| Linux on x86-64 | Linux support; release verification pending | CI configuration includes x86-64 Ubuntu. |
| macOS on Apple silicon (arm64) | Mounting not verified | macFUSE mounting and hardware-specific behavior require verification. |
| Windows | Not supported | The CLI and mount code assume Unix and FUSE |

## Linux

- FUSE: the `fuse3` package (for `fusermount3`). Mounting does not need root.
  `--allow-other` additionally needs `user_allow_other` in `/etc/fuse.conf`.
- Block device: the `nbd` kernel module and `nbd-client`.
- Key slots: `tpm2-tools` for TPM2, `clevis` for Tang, the token's PKCS#11 module,
  and `age-plugin-fido2-hmac` v0.5.0+ for FIDO2.
- Process hardening (`PR_SET_DUMPABLE=0`) is Linux-only; `mlockall` is used on
  both Linux and macOS (see [SECURITY_MODEL.md](SECURITY_MODEL.md)).

## macOS

- FUSE: install macFUSE. Building needs `pkg-config` so that TeaGarden can link
  macFUSE's libfuse. Mounting needs macFUSE's kernel extension to be allowed: on
  Apple silicon that means starting in Recovery, choosing reduced security with
  kernel extensions from identified developers allowed, then approving macFUSE in
  System Settings > Privacy & Security and restarting. Until you do, a mount fails
  with `FUSE mount failed: Unspecified Error`.
- `volume unmount` uses the system `umount`.

## No built-in network server

TeaGarden 1.0.0 contains no network server for volumes. Use `volume attach` to open a volume on another computer; see the
[user guide](USER_GUIDE.md). The listening socket for the separate block device is the
NBD export of `dev serve nbd`, which is unauthenticated (see
[BLOCK_DEVICE.md](BLOCK_DEVICE.md)).
