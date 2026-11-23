# User guide

This guide covers everyday use of TeaGarden volumes. Installation and the first
mount are in [GETTING_STARTED.md](GETTING_STARTED.md); the block device is in
[BLOCK_DEVICE.md](BLOCK_DEVICE.md). Every command's exact options are in
[CLI_HELP.txt](CLI_HELP.txt).

Use the exact volume display name or full UUID when a command takes a volume.
Some commands also accept a unique UUID prefix; see their help for details.

## Volumes

A volume is an encrypted filesystem. Each saved file version lives on Telegram
as one encrypted TGFV object, with independently encrypted segments for ranged
reads. Filesystem metadata lives in a local SQLite database whose sensitive rows
are encrypted, and is also published to Telegram in encrypted form.

```bash
teagarden volume create --name personal          # password-rooted
teagarden volume create --name work --key-protection   # key slots
teagarden volume list
teagarden volume info personal
```

There are two kinds of volume:

| | Password-rooted (default) | Key-protected (`--key-protection`) |
|---|---|---|
| Keys come from | Argon2id of your password | a random 256-bit master key |
| Opens with | the password | any one enrolled key slot |
| Recovery sentence | none is printed at creation | one is enrolled and printed once at creation |
| Hardware factors (TPM2, PKCS#11, Tang, FIDO2) | not available | `keyslot enroll` |

The kind is fixed at creation. Choose `--key-protection` for a recovery
sentence or hardware factors.
`volume create` of a password-rooted volume prints that the password is the only
way in, and names `teagarden key export` and `volume create --key-protection`.

Each file version is one Telegram document. The supported new-save plaintext maximum is
2,092,860,184 bytes on ordinary accounts or 4,189,980,184 bytes with Premium. Each revision is a new object
linked in encrypted metadata; earlier messages remain unchanged.

### Local state

Each computer keeps local configuration and an index, including mount-instance
state. Back up the owner signing capability separately. An attached installation
can reconstruct the volume from its Telegram topic and credential; preserve the
owner public key independently for pinning.

## Moving to another computer

### Set up another computer without a code

On the new computer, run `teagarden auth login --qr`. Scan the displayed QR code
in Telegram mobile: **Settings → Devices → Link Desktop Device**. Keep the
terminal open until TeaGarden confirms the login. If Telegram asks for the cloud
password, enter it at the prompt or pass `--cloud-password-file PATH`.

On an already logged-in computer, run `teagarden auth approve
'tg://login?token=...'` with the URI printed by the new computer. Approval gives
that computer full access to this Telegram account. A token is safe to approve
only when you started that login yourself. TeaGarden asks you to type `YES`; use
`--yes` for a script.

`teagarden auth login --qr` creates a separate Telegram authorization for each
computer. You can revoke it from Telegram's **Settings → Devices**.

`teagarden auth export <DIR>` copies the API settings (`.env`), the storage-group
record (`group.json`) and the Telegram session into `DIR`; `teagarden auth import
<DIR>` installs them on the other computer (`--force` replaces an existing
configuration). `DIR` is created with mode 0700 and its files with mode 0600, and
it holds the login to your Telegram account unencrypted: move it only over a
channel you trust and delete it afterwards. The login code of `teagarden auth
login` arrives as a message from **Telegram** in an app that is already signed in,
or by SMS, call or Fragment if none is. Use separate Telegram authorizations for
simultaneous connections; the same copied session cannot be used concurrently. Details are in
[TELEGRAM_SETUP.md](TELEGRAM_SETUP.md#set-up-a-second-computer).

Attach a local copy of an existing volume with its forum group and topic IDs:

```bash
teagarden volume attach GROUP_ID:TOPIC_ID --owner-public-key OWNER_HEX --password-file ~/volume-password.txt
# or use --recovery-file ~/recovery-sentence.txt (recovery slot or exported root)
```

Copy `OWNER_HEX` from the creating computer's `Owner public key` output through a
trusted channel. The password alone cannot identify the owner of a fresh TGHD2
attach. Version 1.0 accepts only owner-signed TGHD2 headers and always prints
the authenticated owner fingerprint after attaching.


Attach reads the newest TGHD header from Telegram, verifies it with the current
credential, and creates a new local volume identity. The existing local volume
directory is left untouched if the header cannot be authenticated.

Back up `owner-signing.key` separately. This mode-0600 file holds the owner
signing key; the volume password does not protect it.

## Device revocation

Run `device revoke` from an owner administration installation. For a device on
the same Telegram account, use the owner-confirmed session map described below.

On a terminal, `device revoke` asks for the existing volume credential to open
the volume; it does not change the password. The owner signing key is loaded
separately from `owner-signing.key`. Without a terminal, supply
`--password-file PATH` (`-` reads stdin) or `--recovery-file PATH`. There is no
replacement-password prompt. Revoke works while the owner's volume is mounted on
the same computer; a separate administration lock serializes concurrent revokes.

Revoke resets the selected owner-confirmed authorization on the same Telegram
account and publishes an owner-signed record. For a different account, Telegram
confirms a storage-group ban for the installation's registered account. The
per-device cutoff is immutable. Publication can be retried after a transport
failure without repeating a completed access cut or moving its cutoff.

Revoke does not change the volume key, password, recovery credential or retained
encrypted files. A removed device that obtains encrypted files another way can
still decrypt them with the password it knows. Key rotation is planned for a
later release.

With the current signed policy, readers reject later writes claiming the revoked
installation ID. Revoke freezes the signing keys of non-revoked registered
installations. A write claiming a frozen ID must carry a valid signature from its
exact frozen key; a missing or different signature is rejected, including by
directory decrypt with `--include-unverified`. If a registered survivor lacks an
authenticated signing key, revoke refuses before cutting access.

If a removed device can upload through another route, it can claim a new,
never-seen installation ID. Readers accept that ID as a new author, which can
also write to existing paths. Frozen keys do not make new IDs owner-approved.

Each existing installation persists its highest authenticated owner-header
revision outside the disposable index. Mount startup, the live poller, history,
diff, restore-version, export and device list reject an older revision, including
after restart. Losing or rolling back trusted local installation state is outside
this protection. A fresh attach has no earlier revision observation: the owner key
pin authenticates the owner but cannot prove that the latest header was delivered.
Establish freshness separately when provisioning a new installation.

Run `teagarden device list personal` to inspect installations and their Telegram
bindings. Same-account revocation requires an explicit owner-confirmed map.
Use [direct owner QR approval](TELEGRAM_SETUP.md#set-up-another-computer-without-a-code)
to identify the login for each installation. Telegram can show `0` for an
installation's own login. With a separate owner-approved login for each
installation that needs a mapping, prepare a private JSON file
with their installation UUIDs and the signed decimal `Hash:` values from their
respective approvals. For example:

```json
[
  {"installation_id": "82fdda5e-e735-43b2-9887-2df8f6c722ea", "authorization_hash": "88"},
  {"installation_id": "4793830d-5659-4576-9384-d356b7e42ce9", "authorization_hash": "-99"}
]
```

From the owner profile, run `teagarden device revoke personal INSTALLATION_UUID
--telegram-session=HASH --confirmed-session-map PATH`. Include the target and
every other active installation on this account.
The owner's own installation is excluded. TeaGarden checks that the named
authorizations are distinct and currently visible from the owner's login.
If a fresh owner-approved login replaced a previously registered login, add
`"previous_authorization_hash": "OLD_HASH"` to that installation's row when the
owner's registry still shows the old value. Copy the new `authorization_hash`
from the owner's approval response for the replacement login. TeaGarden accepts
the renewal after the previous authorization has ended and its hash appears
only in that row.
Installations that share an imported login cannot be revoked individually
because ending that authorization would sign out every installation using it.
With a verified target authorization,
`--log-out-all-other-telegram-sessions` signs out every other authorization after
the exact response `YES`. Scripts may supply `YES` on stdin while using a separate
password file.

## Mounting and durability

```sh
teagarden volume mount personal ~/private
teagarden volume unmount ~/private
```

By default the mount runs in the foreground; `--daemonize` backgrounds it after
startup. A writable mount requires Telegram access. Multiple computers may mount
read-write simultaneously; each polls the topic. The last write wins, all
versions remain in history, and no conflict copies are created. Changes may take
time to appear on other computers.

`close` and `fsync` report an I/O error if the file version cannot be uploaded.
Ordinary writes use an encrypted on-disk spool. Renaming an open file saves any
pending changes before moving it, which can add a version to the file's history.
The supported new-save plaintext maximum is
2,092,860,184 bytes on ordinary accounts or 4,189,980,184 bytes with Premium. Hard links are unsupported and symbolic link creation is
refused with `ENOTSUP`. If a killed process leaves a stale mount, run `volume
unmount` on the mount point and mount again. `--allow-other` requires the FUSE
configuration described in [Supported platforms](SUPPORTED_PLATFORMS.md#linux).

## Key slots

A key-protected volume (`volume create --key-protection`) works like LUKS: a random
master key is wrapped separately by each key slot, and **any one enrolled slot
opens the volume on its own**. Adding a slot adds another way in and leaves every
existing slot sufficient. You can remove slots you no longer want. At
least one passphrase or recovery-sentence slot always remains, so a device (TPM2,
FIDO2, PKCS#11, Tang) is never mandatory: after you remove the passphrase
slot, the recovery sentence opens the volume without the device. Keep the
recovery sentence offline.

`mfa` is accepted as a hidden alias for `keyslot`.

| Slot type | How it is created | Notes |
|---|---|---|
| Passphrase | at `volume create --key-protection` | Argon2id (256 MiB, 4 passes, 4 lanes) |
| Recovery sentence | at `volume create --key-protection`, printed once | 22 words, see [RECOVERY_SENTENCE_FORMAT.md](RECOVERY_SENTENCE_FORMAT.md) |
| TPM2 | `keyslot enroll --tpm2 [--pcrs sha256:0,1,7]` | Uses `tpm2-tools`. Without `--pcrs`, any boot state of this TPM unseals it |
| Tang | `keyslot enroll --tang URL [--tang-thumbprint TP]` | Uses `clevis`. This slot opens only where that Tang server is reachable; other enrolled slots can open independently. Without a thumbprint the server key is trusted on first use |
| PKCS#11 | `keyslot enroll --pkcs11-module PATH [--pkcs11-token-label L] [--pkcs11-key-id HEX]` | Needs an existing RSA key pair on the token with that key id (default `01`); the PIN is prompted. `keyslot enroll` prints whether RSA-OAEP with SHA-256 or the SHA-1 fallback wrapped the key |
| FIDO2 | `keyslot enroll --fido2 [--fido2-mode pin-up\|up]` | Uses `age-plugin-fido2-hmac` v0.5.0+. Asks for the verification mode first (or takes `--fido2-mode`): `pin-up`, the key's PIN and a touch, or `up`, a touch. `pin`, `pin-uv` and `uv` are refused with the reason. The mode is recorded in the slot. Enrolling takes 2 touches and the PIN once (in mode `up` only if the key has a PIN); unlocking and mounting take 1 touch, after the PIN in mode `pin-up` |

FIDO2 hardware testing is pending. Checking or unlocking a slot can work offline.
Enrollment and removal publish the changed header to Telegram; a publication
failure can be reported after the local slot change has already occurred.

```bash
teagarden keyslot status work                   # lists slots and their ids
teagarden keyslot enroll work --tpm2            # asks for the passphrase to authorise
teagarden keyslot unlock work --tpm2            # proves the slot opens the volume; does not mount
teagarden volume mount work ~/work --tpm2       # mount with the TPM instead of the passphrase
teagarden keyslot remove-slot work 1 --tpm2     # remove slot 1, authorised by the TPM slot
```

- `keyslot enroll` is authorised with the passphrase, or with the recovery
  sentence via `--recovery-file`. Choose exactly one factor per call.
- `keyslot remove-slot` must be authorised by a **different** slot that will
  remain. It refuses to remove the last slot, and the last durable slot (a
  passphrase or recovery slot). Device-bound slots (TPM2, Tang, PKCS#11, FIDO2) do
  not count as durable, because losing the device would lose access.
- Removing a slot does not revoke a sentence already exported with `key export`.
- `--pkcs11-module` and `--fido2` need a terminal (PIN prompt, touch), so they
  cannot be combined with `--daemonize`. `--tpm2` and `--tang` can.
- FIDO2 enrollment first prints the exact sequence for the chosen mode, and an
  unlock or mount prints the mode the slot recorded. Every PIN entry is announced
  as `>>> Enter the PIN of your security key now <<<`, and every touch as `>>> Touch
  your security key now (touch N of M: ...) <<<`, confirmed with `✓ key confirmed`.
  Enrollment does not test-unlock the slot; run
  `teagarden keyslot unlock <volume> --fido2` to check it.
- In mode `up`, a key that always verifies its user (it lists `alwaysUv` in
  `fido2-token -I <device>`) also reads a fingerprint during each touch, and
  refuses if none is enrolled.
- On a password-rooted volume, `keyslot status` reports that key protection is not
  active. Key slots cannot be added to it; create a new volume with
  `--key-protection` and copy the files across.
- `keyslot remove` deletes a legacy vault file that was never enforced. It
  refuses to run on a key-protected volume.

### Failed-password delays

For password-rooted volumes, each wrong password makes the next attempt wait:
1 second after the first failure, doubling each time, up to one hour. The counter
is stored in `auth_lockout.json` in the volume directory and resets on success.
The delay slows guessing through TeaGarden itself. Someone with a copy of the
volume directory guesses offline at the cost of one Argon2id run per guess.
Key-protected volumes have no such counter; the Argon2id cost of the passphrase
slot is the only limit.

## Recovery sentence

A key-protected volume is created with a recovery slot whose 22-word sentence is
printed once. Write it down offline. Either the passphrase or the sentence opens
the volume; lose both (and every other slot) and the data is gone.

To use it, save the sentence in a file and pass `--recovery-file` (or `-` for
standard input) to any command that unlocks a volume, for example:

```bash
teagarden volume mount work ~/work --recovery-file ~/sentence.txt
teagarden keyslot enroll work --tpm2 --recovery-file ~/sentence.txt
```

`--recovery-file` also accepts the root sentence printed by `key export` (next
section). The sentence is tried first as the volume's recovery slot; if the
volume has no such slot, or the slot does not open, it is tried as the exported
root. This also works for key-protected volumes with
`volume attach` and with single-object or directory `decrypt`; authentication and
owner-pin checks still apply. The exception is `keyslot enroll` and
`keyslot remove-slot`: they change the key-slot vault, which only a key slot can unlock, so they need the recovery
slot's sentence (or another slot).

A sentence is accepted only from a file or standard input, never on the command
line. `--daemonize` does not accept `--recovery-file`.

## Exporting the root key

`teagarden key export personal` prints a root sentence. Treat it as a secret:
anyone holding it and the corresponding encrypted data can decrypt that data.
Removing a slot or revoking a device does not change the root. Keep recovery
credentials offline.

## History and recovery

```sh
teagarden volume history personal /notes/todo.txt
teagarden volume diff personal VERSION_UUID_A VERSION_UUID_B
teagarden volume restore-version personal /notes/todo.txt VERSION_UUID
```

History shows full file, version and installation UUIDs across computers and
follows file identity across renames. Diff compares content hashes and sizes.
Restore-version publishes the selected old content as a new current version.
`volume revert` uses legacy numeric versions and is limited to legacy block volumes.

To reconstruct a volume on a computer, use `volume attach` with the group and
topic, credential and owner public key, as shown above. For a downloaded
self-describing file, `teagarden decrypt FILE --password-file PASSWORD_FILE`
recovers it independently; `--recovery-file` accepts a recovery-slot sentence or
an exported hierarchy-root sentence, including for key-protected volumes.
Directory decrypt restores files and explicit visible empty directories, including
nested empty directories, directory modes and modification times. It applies
directory attributes after children; deleted directories remain deleted and
symlinks are not restored. Export selects authenticated documents by their wire
content, including those with changed filenames. Keep separate backups and see
[OBJECT_FORMAT.md](OBJECT_FORMAT.md).

Legacy block-volume `volume restore` downloads a remote metadata snapshot and
replaces local metadata; it does **not** publish local changes. Legacy `volume
republish --from-local-db` publishes local state. These are distinct operations,
not the reconstruction workflow for default TGFV volumes.

## Deleting a volume

`teagarden volume delete personal` deletes the Telegram topic and its TGHD and
TGFV history, then removes local state. `--local-only` removes local state while
leaving the topic and its documents in Telegram. Local deletion cannot guarantee
removal of copies on SSDs, copy-on-write filesystems, snapshots or backups.

## Logging

`-v` / `--verbose` turns on debug logging for any command. Without it, the level
comes from `RUST_LOG` (default `warn`).
