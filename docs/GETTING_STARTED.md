# Getting started

This guide takes you from source code to a mounted, encrypted volume. The live
mount tests for 1.0.0 ran on Linux. The macOS instructions cover the Apple silicon
build. See the test report for the status of macOS mounting. For
what each step protects, see the
[security model](SECURITY_MODEL.md).

## 1. Build from source

TeaGarden needs Rust 1.89 or newer (install it with [rustup](https://rustup.rs)).

### Linux

Install a C compiler and the clang development files (both used to build the
bundled SQLite and its bindings) and FUSE 3. On Debian or Ubuntu:

```bash
sudo apt install build-essential libclang-dev fuse3
```

On other distributions the equivalent packages are, for example, Fedora
`gcc gcc-c++ make clang-devel fuse3`, Arch `base-devel clang fuse3`, openSUSE
`gcc gcc-c++ make clang-devel fuse3`. The [test report](TEST_REPORT.md) records a
clean install and uninstall on Ubuntu 24.04 x86-64.

The `fuse3` package provides `fusermount3`, which TeaGarden uses to mount and
unmount without root. FUSE development headers, `pkg-config` and OpenSSL are not
needed on Linux.

### macOS (Apple silicon)

Mounting on macOS is not verified for 1.0.0; see
[SUPPORTED_PLATFORMS.md](SUPPORTED_PLATFORMS.md).

1. Install [macFUSE](https://macfuse.github.io/). To mount, its kernel extension
   must be allowed: start in Recovery, choose reduced security with kernel
   extensions from identified developers allowed, approve macFUSE in System
   Settings > Privacy & Security, and restart.
2. Install the Xcode command line tools (`xcode-select --install`) and
   `pkg-config` (for example `brew install pkg-config`). On macOS TeaGarden links
   against macFUSE's libfuse, which it finds through `pkg-config`.

### Build and install

The install script checks the prerequisites, builds a release binary with
`cargo install --locked` and installs it to `~/.local/bin`:

```bash
git clone https://github.com/arf-io/teagarden-fs.git
cd teagarden-fs
./scripts/install.sh          # add --deps to install the packages above (asks first)
export PATH="$HOME/.local/bin:$PATH"
teagarden --version
```

Options: `--prefix DIR` installs to `DIR/bin` instead; `--no-dev` leaves out the
block device. `scripts/uninstall.sh` removes the binary and leaves your volumes,
session and settings alone. To build by hand: `cargo build --release`
and copy `target/release/teagarden` onto your `PATH`.

Use a release build. Key derivation uses Argon2id with 256 MiB of memory.

Tools for the features that use them:

| Feature | Needs |
|---|---|
| TPM2 key slot | `tpm2-tools` and a TPM |
| Tang key slot | `clevis` and a reachable Tang server |
| PKCS#11 key slot | the token's PKCS#11 module (for example SoftHSM's `libsofthsm2.so`) |
| FIDO2 key slot | `age-plugin-fido2-hmac` v0.5.0 or later on your `PATH` |
| Block device | Linux with the `nbd` kernel module and `nbd-client` |

## 2. Telegram API credentials

TeaGarden talks to Telegram as your own user account, so it needs an API ID and
API hash from [my.telegram.org](https://my.telegram.org). The steps are in
[TELEGRAM_SETUP.md](TELEGRAM_SETUP.md). Run `teagarden auth login` (next step):
when no credentials are configured it asks for the API ID and hash (the hash is
not echoed) and saves them without asking. Alternatively run the setup wizard,
`teagarden configure`, or set `TG_API_ID` and `TG_API_HASH` in your environment.
Saved credentials go to `.env` in the configuration directory with mode 0600.

The configuration directory is `~/.config/teagarden` on Linux and
`~/Library/Application Support/teagarden` on macOS, unless you set
`TEAGARDEN_CONFIG_DIR`.

## 3. Log in

```bash
teagarden auth login
```

Enter your phone number with its country code, then the login code, then your
Telegram two-step verification password if you use one. The code arrives as a
message from **Telegram** in the Telegram app on a device where the account is
already signed in; if no device is signed in, Telegram sends an SMS, calls, or
uses Fragment. The session is saved as `teagarden.session` in the configuration
directory with mode 0600. `teagarden auth status` shows whether a session file
exists (it does not contact Telegram). `teagarden auth logout` deletes the local session file.

The session file gives access to your Telegram account. It is not encrypted. Keep
it private.

To set up a second computer without a new login, run
`teagarden auth export <DIR>` on the first and `teagarden auth import <DIR>` on the
second (add `--force` to replace an existing configuration). The directory holds
the login to your Telegram account: move it only over a channel you trust and
delete it afterwards. See [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md#set-up-a-second-computer).

Both computers then share one Telegram authorization. For separate
per-installation revocation on that account, create independently logged-in
profiles and record the authorization from each direct owner QR approval.
See the [owner-confirmed session map](USER_GUIDE.md#device-revocation).

## 4. Create a volume

```bash
teagarden volume create --name personal
```

You are asked for a password twice. It must be at least 8 characters. Use a long,
unique passphrase: anyone who obtains the volume's local configuration file can
try passwords offline (each guess costs one Argon2id run). A password-rooted
volume prints that the password is the only way in, and names `teagarden key
export` and `volume create --key-protection`.

On your first volume, TeaGarden creates a private Telegram group to hold all your
volumes and devices. Its title is random unless you pass `--group-name`. Each
volume gets a topic in that group with a random title; the volume's name is kept
only on your computer.

For key slots (a recovery sentence, TPM2, PKCS#11, Tang or FIDO2), create the
volume with `--key-protection` instead. This prints a 22-word recovery sentence
once; write it down offline. See [USER_GUIDE.md](USER_GUIDE.md#key-slots).

```bash
teagarden volume create --name personal --key-protection
```

List your volumes with `teagarden volume list` and inspect one with
`teagarden volume info personal`.

## 5. Mount

```bash
mkdir -p ~/private
teagarden volume mount personal ~/private
```

By default the mount runs in the foreground. Leave the terminal open and use `~/private`
like any other directory. A read-write mount needs a working Telegram login and is
refused when Telegram credentials are not configured. Multiple computers may mount
read-write; each polls the topic, and the last write wins.

`teagarden personal ~/private` is a shorthand for the same mount.

## 6. Unmount

Press Ctrl+C in the mount's terminal, or from another terminal run:

```bash
teagarden volume unmount ~/private
```

`volume unmount` waits until the mount process has finished its queued uploads
before returning. Check for errors before powering off.

## 7. Mount without a prompt

For scripts and boot-time mounts, put the password in a file that only you can
read and pass it with `--password-file`:

```bash
umask 077
read -rs pw && printf '%s\n' "$pw" > ~/.config/teagarden/personal.pw; unset pw
teagarden volume mount personal ~/private --password-file ~/.config/teagarden/personal.pw --daemonize
```

(`read -rs` reads the password without echoing it, so it stays out of your
shell history. An editor also creates the file.)

Trailing newline characters are removed from a password file; everything else in
the file is part of the password. TeaGarden does not check the file's permissions;
set them yourself. `--password-file -` reads the password from standard input.

`--daemonize` returns once the mount is up and leaves it running in the
background. It needs a password file or a device factor that does not prompt
(`--tpm2`, `--tang`). A daemonized mount discards its output, so if it fails, run
the same command without `--daemonize` to see the error.

## 8. The mount table (`fstab`)

TeaGarden keeps its own mount table, `teagarden.fstab`, in the configuration directory
(mode 0600):

```bash
teagarden fstab add --volume personal --mountpoint ~/private --password-file ~/.config/teagarden/personal.pw
teagarden fstab list
teagarden fstab mount-all      # mounts auto=true entries that have a password file
teagarden fstab unmount-all
teagarden fstab remove --volume personal
```

With an entry in the table, `teagarden volume mount personal` finds the mount
point by itself. Entries without a password file are skipped by `mount-all`.

### `/etc/fstab` and `mount -t teagarden`

`scripts/mount.teagarden` is a `mount(8)` helper. Install it as
`/sbin/mount.teagarden` and a volume can be mounted with:

```bash
sudo mount -t teagarden personal /mnt/private -o password_file=/etc/teagarden/personal.pw
```

or from `/etc/fstab`:

```
personal  /mnt/private  teagarden  _netdev,password_file=/etc/teagarden/personal.pw  0 0
```

`password_file=` is required and `ro` is refused. `_netdev` makes the mount wait
for the network. TeaGarden finds its configuration and data directories through
`$HOME` (unless `TEAGARDEN_CONFIG_DIR` and friends are set; see
[ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md)). A boot-time mount runs as
root, so the volume, the Telegram session and the credentials must be where
root's TeaGarden will look for them. `scripts/umount.fuse.teagarden` is
the matching unmount helper; it calls `teagarden volume unmount`.

## Next steps

- [USER_GUIDE.md](USER_GUIDE.md): key slots, recovery, multiple computers, history and deletion.
- [BLOCK_DEVICE.md](BLOCK_DEVICE.md): the encrypted block device.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): error messages and what to do.
