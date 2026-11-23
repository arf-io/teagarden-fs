# Tea Garden FS

Tea Garden FS is a personal encrypted filesystem that stores its data in your own
Telegram account. It also provides a separate encrypted block device.

Version **1.0.0** uses Linux x86-64 for real filesystem mounts and the block
device. The Apple silicon build and non-mount tests have passed. The
[test report](docs/TEST_REPORT.md) identifies the builds tested and records the
status of native macOS mounts, physical FIDO2 and live Telegram revocation.

Each saved file version is one self-describing encrypted Telegram document (TGFV),
with a supported new-save plaintext maximum of 2,092,860,184 bytes on ordinary
accounts or 4,189,980,184 bytes with Telegram Premium. Segmented encryption allows
partial reads. A downloaded new-format document can be decrypted with
`teagarden decrypt` and its password or recovery sentence alone. The volume
header (TGHD2) is signed by the owner. See [the object format](docs/OBJECT_FORMAT.md).

On Linux, clone the repository and run the installer. The
[build and install guide](docs/GETTING_STARTED.md) covers prerequisites,
other installation options and the Apple silicon build.

```sh
git clone https://github.com/arf-io/teagarden-fs.git
cd teagarden-fs
./scripts/install.sh --deps
export PATH="$HOME/.local/bin:$PATH"
teagarden --version
```

Obtain your own Telegram API ID and hash using the
[Telegram setup guide](docs/TELEGRAM_SETUP.md). Then create and mount a volume:

```sh
teagarden auth login
teagarden volume create --name personal
mkdir -p ~/private
teagarden volume mount personal ~/private
```

To use the volume on another computer, transfer or establish a Telegram login and
run `volume attach GROUP_ID:TOPIC_ID --owner-public-key OWNER_HEX`. Copy the owner
public key from the creating computer over a trusted channel. Attach prints the
owner fingerprint and reconstructs the volume from Telegram. Computers can mount
read-write at the same time; each polls the topic. The last write wins, every
version is kept, and no conflict copies are made. See the [user guide](docs/USER_GUIDE.md).

`volume history` shows versions from all computers, with full UUIDs, including
history across renames. `volume diff` compares content; `volume restore-version`
publishes a selected old version as a new current version. `volume revert` is for
legacy block volumes only.

`device list` shows registered installations. `device revoke` asks for the
existing volume password to open the volume and does not change it. The separate
`owner-signing.key` file holds the owner signing key in mode 0600; the volume
password does not protect it. A same-account revoke requires a current
owner-confirmed Telegram session map, ends the selected authorization and
publishes a signed revocation record. Across accounts, the command requests a
group ban for the installation's registered Telegram account. The volume key
stays the same. See [device revocation](docs/USER_GUIDE.md#device-revocation)
for the map and its limits. A removed device that
obtains encrypted files another way can still decrypt them with the password it knows. Key rotation is planned for a
later release. If a removed device can still upload through another route,
readers reject its later writes under its revoked ID. Revoke freezes the signing
keys of non-revoked registered installations: a write claiming one of those IDs
must have a valid signature from its frozen key. A new, never-seen ID remains
accepted as a new author and can write to existing paths. Existing installations
persist and enforce their highest authenticated header revision; a fresh attach
has no earlier observation, so establish policy freshness separately.

Directory decrypt restores files and explicit visible empty directories, including
nested directories and their modes and modification times. Keep independent
backups: Telegram can remove account data, and losing all usable
credentials makes encrypted data inaccessible. Telegram can see account, network,
message timing and object sizes; TGHD has a public framing and TGFV has a public
prefix. See the [security model](docs/SECURITY_MODEL.md). Symbolic links are
refused with `ENOTSUP` on portable volumes.

Key-protected volumes support recovery sentences and hardware-factor slots.
FIDO2 enrollment supports `pin-up` and `up`; FIDO2 hardware testing remains pending.
See [key slots](docs/USER_GUIDE.md#key-slots) and [documentation](docs/README.md).
