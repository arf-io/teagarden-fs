# Troubleshooting

- **No TGHD header or authentication fails:** check the group and topic, login,
  credential and owner public key. Attach requires an owner-signed TGHD2 header.
- **Telegram login fails:** run `teagarden auth status` and sign in again as needed.
  A copied session cannot be used simultaneously on two computers; use separate
  authorizations for concurrent mounts.
- **Stale mount after a killed process:** run `teagarden volume unmount <mountpoint>`
  and mount again.
- **Write fails with EIO:** check connectivity and Telegram access, then retry the
  write. The supported new-save plaintext maximum is 2,092,860,184 bytes on ordinary
  accounts or 4,189,980,184 bytes with Premium.
- **Volume not found on this computer:** attach it using the Telegram group and
  topic, the credential and the owner public key. See [USER_GUIDE.md](USER_GUIDE.md).
- **Owner capability does not match:** use the owner signing capability associated
  with the pinned owner key. Do not replace the pin based only on the password.
- **Revocation publication pending:** retry the same revoke command after restoring
  connectivity. The access cut and signed publication are distinct steps.
- **Directory recovery:** decrypt restores visible explicit empty directories,
  their modes and modification times as well as files. Export selects authenticated
  documents by content, including documents with changed filenames.
- **Revoked device still uploads:** later writes under the revoked ID are rejected;
  a frozen registered ID requires its exact signing key. A new, never-seen ID is
  accepted as a new author. Existing installations enforce a persisted header
  revision floor; a fresh attach needs a separate freshness check. See
  [SECURITY_MODEL.md](SECURITY_MODEL.md).
- **Revoke without a terminal:** supply `--password-file PATH` or
  `--recovery-file PATH`. For a broad session reset, supply the exact confirmation
  `YES` and use a separate credential file if stdin carries that confirmation.
- **Legacy snapshot recovery:** `volume restore` downloads a remote snapshot and
  replaces local metadata; `volume republish --from-local-db` publishes local
  metadata. Neither is the default TGFV attach workflow.

## Block device

### ``open device (wrong credential, or in use by a running `dev serve`?)``

The credential is wrong, or another process (usually `dev serve nbd`) has
the device open. Only one process opens a device at a time.

### `dev serve nbd … did not shut down cleanly`

On stopping (Ctrl+C, SIGTERM, or `nbd-client -d`), `dev serve nbd` uploads the open
segment and publishes a final checkpoint. If that fails (usually no connection),
it exits non-zero. Everything acknowledged by FLUSH is still in the local staging
log: start `dev serve nbd` again once Telegram is reachable (it replays the log),
then stop it cleanly. A second Ctrl+C (or SIGTERM) while it is finalizing has the
same effect: it exits at once with status 1 and says finalization is incomplete.

### `device is failed after an earlier durability error`

A local write or fsync failed (often a full disk). The device refuses further work
until it is reopened. Stop the server, fix the disk problem, and start it again.

### `refusing to recover '…': the directory is not empty`

`dev recover` never overwrites existing local state, which can hold writes that
were never uploaded. Move the directory aside as the message shows, then rerun it.

### `refusing to delete device '…'`

Another command holds the device, usually `dev serve nbd`. Stop it, then run
`dev delete` again. Nothing was deleted. A wrong credential refuses the same way
(`wrong device credential for '…'`), with nothing deleted. With no terminal to
ask, `dev delete` refuses until you pass `--force`; a state directory that is a
symlink or holds files TeaGarden did not write is refused too, and the message
says what to change.

### `the device's Telegram topic could not be deleted`

`dev delete` deletes the topic before the local state, and the topic delete
failed. The local state and registry entry are intact. Fix the connection and
rerun `dev delete`.

### `device '…' has no state directory at …`

`dev delete` checks the credential against the device's local state, which is
missing. Run `teagarden dev recover <name>` first, then `dev delete`. Nothing was
deleted.

### `the Telegram topic is deleted, but removing the local state of '…' failed part-way`

The topic and everything in it are gone from Telegram. Remove the state directory
named in the message and the device's registry entry
(`<name>.json` in the registry directory, see
[BLOCK_DEVICE.md](BLOCK_DEVICE.md#commands)) by hand.
