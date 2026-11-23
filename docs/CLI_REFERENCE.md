# TeaGarden command reference

This file is generated mechanically from [CLI_HELP.txt](CLI_HELP.txt), which is the
`--help` output of the real `teagarden` binary. Each section reproduces one help
screen verbatim. If the two ever differ, CLI_HELP.txt is authoritative.

### teagarden

```text
TeaGarden - Telegram Encrypted Filesystem

Usage: teagarden [OPTIONS] [VOLUME] [MOUNTPOINT] [COMMAND]

Commands:
  auth         Authenticate with Telegram
  volume       Volume management (create, mount, unmount, list, delete, info)
  device       Manage multi-computer installations in a portable volume
  configure    Interactive setup wizard
  status       Show system status
  key          Encryption key rotation and recovery-root export/verification
  fstab        Volume mount table — like /etc/fstab but for TeaGarden
  keyslot      Key slots: any ONE enrolled slot opens the volume (like LUKS key slots)
  dev          TeaGarden dev — encrypted BLOCK DEVICE (put a real filesystem on top)
  completions  Generate or install shell completions
  man          Print the TeaGarden man page in roff format
  decrypt      Decrypt downloaded TGFV file objects without local volume state or a Telegram login
  help         Print this message or the help of the given subcommand(s)

Arguments:
  [VOLUME]      Volume to mount (display name or UUID) — shorthand for `volume mount`
  [MOUNTPOINT]  Directory to mount at (defaults to the teagarden.fstab mountpoint for the volume)

Options:
  -v, --verbose               Enable verbose logging (sets RUST_LOG=debug)
      --allow-other           (shorthand mount) Allow other users to access the mount
      --password-file <PATH>  (shorthand mount) Read the password from this file instead of prompting
      --daemonize             (shorthand mount) Background the mount and return once it is up (for `mount.teagarden` / `/etc/fstab`). Requires --password-file
  -h, --help                  Print help
  -V, --version               Print version
```

### teagarden auth

```text
Authenticate with Telegram

Usage: teagarden auth [OPTIONS] <COMMAND>

Commands:
  login    Log in to Telegram (phone number + verification code)
  approve  Approve a QR login token on this already authenticated computer
  logout   Log out and delete the local session file
  status   Show authentication status
  export   Copy this computer's Telegram login (API settings, storage-group record, session) into DIR, to move it to another computer
  import   Install a login written by `auth export` into this computer's config directory, then show the authentication status
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden auth login

```text
Log in to Telegram (phone number + verification code)

Usage: teagarden auth login [OPTIONS]

Options:
      --api-id <API_ID>             Telegram API ID (or set TG_API_ID env var) [env: TG_API_ID]
  -v, --verbose                     Enable verbose logging (sets RUST_LOG=debug)
      --api-hash <API_HASH>         Telegram API hash (or set TG_API_HASH env var) [env: TG_API_HASH]
      --qr                          Use Telegram's QR based device login instead of a phone code
      --cloud-password-file <PATH>  Read the Telegram cloud password from this file if QR login requires it
  -h, --help                        Print help
```

### teagarden auth approve

```text
Approve a QR login token on this already authenticated computer

Usage: teagarden auth approve [OPTIONS] <TOKEN>

Arguments:
  <TOKEN>  The tg://login?token=... line shown on the new computer, or - to read it from stdin with --yes

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
      --yes      Approve without the interactive YES prompt
  -h, --help     Print help
```

### teagarden auth logout

```text
Log out and delete the local session file

Usage: teagarden auth logout [OPTIONS]

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden auth status

```text
Show authentication status

Usage: teagarden auth status [OPTIONS]

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden auth export

```text
Copy this computer's Telegram login (API settings, storage-group record, session) into DIR, to move it to another computer.

DIR must be empty or not exist; it is created with mode 0700 and each file in it with mode 0600. DIR then holds the login to your Telegram account, unencrypted: move it only over a channel you trust and delete it afterwards.

Usage: teagarden auth export [OPTIONS] <DIR>

Arguments:
  <DIR>
          Directory to write into

Options:
  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden auth import

```text
Install a login written by `auth export` into this computer's config directory, then show the authentication status.

Checks the files first (regular files, not symbolic links; a signed-in session) and refuses to replace an existing configuration unless --force is given. Nothing is left half-written.

Usage: teagarden auth import [OPTIONS] <DIR>

Arguments:
  <DIR>
          Directory written by `teagarden auth export`

Options:
      --force
          Replace the API settings, storage-group record and session already on this computer

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden volume

```text
Volume management (create, mount, unmount, list, delete, info)

Usage: teagarden volume [OPTIONS] <COMMAND>

Commands:
  create           Create a new encrypted volume, stored as its own topic in your private Telegram storage group
  attach           Attach this computer to an existing Telegram forum topic
  mount            Mount a volume at the given path, or at the teagarden.fstab mountpoint if omitted
  unmount          Unmount a mounted volume
  restore          Legacy-only: restore a block volume's metadata DB from its latest Telegram snapshot
  republish        Legacy-only: publish a block volume's local metadata DB as its metadata (explicit recovery)
  revert           Restore a file to a prior manifest version in a legacy block volume only
  export-objects   Download raw TGHD and TGFV documents from a volume for offline decryption
  list             List all configured volumes
  delete           Permanently delete a volume: first its Telegram forum topic, with every message in it (every file version, volume header and device record; on a legacy block volume also its blocks, metadata snapshots and journal), then the local state. Requires a credential (`--password-file`, `--recovery-file`, or the passphrase prompt). Refuses if the volume is mounted or in use by another TeaGarden command (mount, revert, restore, key rotate), and deletes nothing in that case
  info             Show detailed information about a volume
  history          Show the version history of a file in a volume
  restore-version  Restore a TGFV version by publishing its bytes as a new current version
  diff             Compare TGFV versions by content hash and size, or legacy manifests by block IDs
  add-bot          Add a storage bot created in @BotFather for parallel uploads in legacy and block transport
  remove-bot       Remove a storage bot added with `volume add-bot`
  help             Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden volume create

```text
Create a new encrypted volume, stored as its own topic in your private Telegram storage group

Usage: teagarden volume create [OPTIONS]

Options:
  -n, --name <NAME>           Human-readable name (auto-generated "noun verb adverb" if omitted)
  -v, --verbose               Enable verbose logging (sets RUST_LOG=debug)
      --password-file <PATH>  Read the password from this file instead of prompting (use `-` for stdin)
      --key-protection        Root the volume in a key-slot vault: its keys derive from a random master key that only an enrolled slot can unwrap. Key slots — any one enrolled slot opens the volume (like LUKS). The passphrase becomes one slot and a recovery co-slot is auto-enrolled (its sentence is printed once). Add device slots with `keyslot enroll`; remove slots (e.g. the passphrase) with `keyslot remove-slot`
      --group-name <NAME>     Name for the shared Telegram storage group, created once on your first volume and reused by every volume after (has no effect if the group already exists). If omitted, a random three-word name is used, so the title reveals nothing about your data
  -h, --help                  Print help
```

### teagarden volume attach

```text
Attach this computer to an existing Telegram forum topic

Usage: teagarden volume attach [OPTIONS] <GROUP_TOPIC>

Arguments:
  <GROUP_TOPIC>  Telegram group and topic in GROUP_ID:TOPIC_ID form

Options:
      --password-file <PATH>    Read the current volume password from a file instead of prompting
  -v, --verbose                 Enable verbose logging (sets RUST_LOG=debug)
      --recovery-file <PATH>    Unlock with the current recovery sentence from this file
      --owner-public-key <HEX>  Owner public key copied from the creating computer (required for TGHD2)
  -h, --help                    Print help
```

### teagarden volume mount

```text
Mount a volume at the given path, or at the teagarden.fstab mountpoint if omitted

Usage: teagarden volume mount [OPTIONS] <VOLUME> [MOUNTPOINT]

Arguments:
  <VOLUME>      Volume display name or UUID (prefix match accepted)
  [MOUNTPOINT]  Directory to mount at.  If omitted, the mountpoint from teagarden.fstab is used

Options:
      --allow-other                   Let other users (including root) into the mount. Off by default, so only you can access it and no /etc/fuse.conf change is needed. As a non-root user this needs `user_allow_other` in /etc/fuse.conf
  -v, --verbose                       Enable verbose logging (sets RUST_LOG=debug)
      --password-file <PATH>          Read the password from this file instead of prompting (for automation)
      --recovery-file <PATH>          Unlock with a 22-word recovery sentence read from this file (use `-` for stdin) instead of the passphrase: a key-protected volume's recovery-slot sentence, or the key-hierarchy root printed by `key export`
      --daemonize                     Background the mount and return once it is up (for `mount.teagarden` / `/etc/fstab` / boot). Requires --password-file or a device factor that doesn't need interaction (--tpm2, --tang) — a boot mount can't prompt
      --tpm2                          Unlock via the TPM2 slot instead of a password (mutually exclusive with --password-file/--recovery-file; the volume must have a TPM2 slot enrolled via `keyslot enroll --tpm2`)
      --tang <URL>                    Unlock via a Tang slot bound to this server URL
      --tang-thumbprint <THUMBPRINT>  Expected Tang advertised-key thumbprint
      --pkcs11-module <PATH>          Unlock via a PKCS#11 slot using this provider module. Foreground only — the PIN prompt needs a terminal, so this cannot combine with --daemonize
      --pkcs11-token-label <LABEL>    PKCS#11 token label
      --pkcs11-key-id <HEX>           PKCS#11 key id in hex (default: 01)
      --fido2                         Unlock via a FIDO2 hardware authenticator slot. Foreground only — needs a physical touch, so this cannot combine with --daemonize
  -h, --help                          Print help
```

### teagarden volume unmount

```text
Unmount a mounted volume

Usage: teagarden volume unmount [OPTIONS] <TARGET>

Arguments:
  <TARGET>  Mount point path or volume name

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden volume restore

```text
Legacy-only: restore a block volume's metadata DB from its latest Telegram snapshot.

Disaster recovery with anti-rollback: a snapshot older than the volume's known version is refused. The volume must be unmounted. Refuses while the metadata journal holds changes that are in no snapshot yet (the last session did not end with a clean unmount) unless --discard-journal is given. If the restore is interrupted, the next mount rebuilds the local metadata DB from Telegram.

Usage: teagarden volume restore [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>
          Volume display name or UUID (prefix match accepted)

Options:
      --snapshot-id <MESSAGE_ID>
          Restore a specific snapshot message ID instead of the recorded latest. Still subject to the anti-rollback checks: a snapshot older than the recorded version is refused, and at the recorded version only the recorded snapshot is accepted

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --password-file <PATH>
          Read the password from this file instead of prompting (use `-` for stdin)

      --force
          Skip the destructive-overwrite confirmation prompt. Without it the restore asks on the terminal, and exits non-zero when there is no terminal or the answer is not yes

      --recovery-file <PATH>
          Unlock with the recovery sentence in this file (use `-` for stdin) instead of the passphrase: a key-protected volume's recovery-slot sentence, or the key-hierarchy root printed by `key export`

      --discard-journal
          Restore even though the volume's metadata journal has entries that are not in any snapshot yet (the last session did not end with a clean unmount). Those changes are on Telegram and the next mount would replay them; restoring DISCARDS them. Without this option `restore` refuses and says how many entries would be lost

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden volume republish

```text
Legacy-only: publish a block volume's local metadata DB as its metadata (explicit recovery).

For a volume whose metadata cannot be rebuilt from Telegram (a mount fails because the base snapshot or a journal entry is gone from the group, the volume names no snapshot, or journal.head is missing or unreadable) while the local metadata DB is intact. Takes the volume's exclusive lock (refuses while the volume is mounted or another TeaGarden command uses it), requires a readable DB with a root directory, and refuses a DB stamped as another volume's, or one whose lineage stamp is not the one journal.head records (an older copy) unless --replace-newer-metadata is given. It prints how many entries the DB holds, whether its stamp is journal.head's, the journal HEAD, the snapshot it supersedes (which `volume restore` refuses afterwards) and what will be overwritten, and asks before going on. It then publishes the DB as a new snapshot (at the next reserved version), stamps it and resets the journal HEAD onto it. Journal entries past the old base are no longer replayed: the local DB holds what this machine committed of them. Nothing on Telegram is deleted.

Usage: teagarden volume republish [OPTIONS] --from-local-db <VOLUME>

Arguments:
  <VOLUME>
          Volume display name or UUID (prefix match accepted)

Options:
      --from-local-db
          Publish the local metadata database (the only source; required, so the choice is explicit)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --password-file <PATH>
          Read the password from this file instead of prompting (use `-` for stdin)

      --recovery-file <PATH>
          Unlock with the recovery sentence in this file (use `-` for stdin) instead of the passphrase: a key-protected volume's recovery-slot sentence, or the key-hierarchy root printed by `key export`

      --force
          Skip the confirmation prompt. Does not imply --replace-newer-metadata

      --replace-newer-metadata
          Republish even though the local DB's lineage stamp is not the one journal.head records (an older copy of the DB, or one a publish did not finish): the newer metadata on Telegram is replaced, and `volume restore` then refuses the snapshot it supersedes

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden volume revert

```text
Restore a file to a prior manifest version in a legacy block volume only.

For TGFV history, use `volume restore-version` with a version UUID prefix. Non-destructive git-revert: appends a new version whose content matches the target version (older versions stay in `history`). A journaled, single-writer operation — the volume must be unmounted and Telegram must be configured.

Usage: teagarden volume revert [OPTIONS] <VOLUME> <PATH> <VERSION>

Arguments:
  <VOLUME>
          Volume display name or UUID (prefix match accepted)

  <PATH>
          Absolute in-volume path of the file to revert (e.g. `/dir/file.txt`)

  <VERSION>
          Target manifest version to restore (see `volume history` for versions)

Options:
      --password-file <PATH>
          Read the password from this file instead of prompting (use `-` for stdin)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --recovery-file <PATH>
          Unlock with the recovery sentence in this file (use `-` for stdin) instead of the passphrase: a key-protected volume's recovery-slot sentence, or the key-hierarchy root printed by `key export`

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden volume export-objects

```text
Download raw TGHD and TGFV documents from a volume for offline decryption

Usage: teagarden volume export-objects [OPTIONS] --out <DIR> <VOLUME>

Arguments:
  <VOLUME>  Volume name or UUID

Options:
      --out <DIR>                      Directory to create for the downloaded raw objects
  -v, --verbose                        Enable verbose logging (sets RUST_LOG=debug)
      --password-file <PASSWORD_FILE>  Read the volume password from a file
      --recovery-file <RECOVERY_FILE>  Read a recovery sentence from a file
  -h, --help                           Print help
```

### teagarden volume list

```text
List all configured volumes

Usage: teagarden volume list [OPTIONS]

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden volume delete

```text
Permanently delete a volume: first its Telegram forum topic, with every message in it (every file version, volume header and device record; on a legacy block volume also its blocks, metadata snapshots and journal), then the local state. Requires a credential (`--password-file`, `--recovery-file`, or the passphrase prompt). Refuses if the volume is mounted or in use by another TeaGarden command (mount, revert, restore, key rotate), and deletes nothing in that case

Usage: teagarden volume delete [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>  Volume display name or UUID

Options:
      --force                 Skip the confirmation prompt (still requires a credential). Without it the delete asks on the terminal, and exits non-zero when there is no terminal or the answer is not yes
  -v, --verbose               Enable verbose logging (sets RUST_LOG=debug)
      --password-file <PATH>  Read the volume password from this file (use `-` for stdin)
      --recovery-file <PATH>  Unlock with the recovery sentence in this file: a key-protected volume's recovery-slot sentence, or the key-hierarchy root printed by `key export`
      --local-only            Destroy ONLY local state and knowingly abandon the volume's data on Telegram (its topic and every message in it stay there). Without this, deletion requires a Telegram login so the topic is removed
  -h, --help                  Print help
```

### teagarden volume info

```text
Show detailed information about a volume

Usage: teagarden volume info [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>  Volume display name or UUID

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden volume history

```text
Show the version history of a file in a volume.

Read-only: never creates or changes the local metadata DB. Refuses while the volume is mounted or another command is changing it. TGFV history reads Telegram directly and does not require a local metadata DB. Legacy block history requires a local metadata DB rebuilt by a mount.

Usage: teagarden volume history [OPTIONS] <VOLUME> [PATH]

Arguments:
  <VOLUME>
          Volume display name or UUID

  [PATH]
          File path inside the volume (omit to show every file)

Options:
      --password-file <PATH>
          Read the volume password / passphrase from this file instead of prompting (use `-` for stdin)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --recovery-file <PATH>
          Unlock with the recovery sentence in this file (use `-` for stdin) instead of the passphrase: a key-protected volume's recovery-slot sentence, or the key-hierarchy root printed by `key export`

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden volume restore-version

```text
Restore a TGFV version by publishing its bytes as a new current version

Usage: teagarden volume restore-version [OPTIONS] <VOLUME> <PATH> <VERSION_UUID>

Arguments:
  <VOLUME>        Volume display name or UUID
  <PATH>          Destination path inside the volume
  <VERSION_UUID>  Prefix of the historical TGFV version UUID

Options:
      --password-file <PATH>  Read the volume password / passphrase from this file instead of prompting
  -v, --verbose               Enable verbose logging (sets RUST_LOG=debug)
      --recovery-file <PATH>  Unlock with the recovery sentence in this file instead of the passphrase
  -h, --help                  Print help
```

### teagarden volume diff

```text
Compare TGFV versions by content hash and size, or legacy manifests by block IDs.

Read-only; refuses while the volume is mounted or another command is changing it. TGFV diff reads Telegram directly and does not require a local metadata DB. Legacy block diff requires a local metadata DB rebuilt by a mount.

Usage: teagarden volume diff [OPTIONS] <VOLUME> <VERSION_A> <VERSION_B>

Arguments:
  <VOLUME>
          Volume display name or UUID

  <VERSION_A>
          First version UUID prefix (TGFV) or manifest ID prefix (legacy)

  <VERSION_B>
          Second version UUID prefix (TGFV) or manifest ID prefix (legacy)

Options:
      --password-file <PATH>
          Read the volume password / passphrase from this file instead of prompting (use `-` for stdin)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --recovery-file <PATH>
          Unlock with the recovery sentence in this file (use `-` for stdin) instead of the passphrase: a key-protected volume's recovery-slot sentence, or the key-hierarchy root printed by `key export`

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden volume add-bot

```text
Add a storage bot created in @BotFather for parallel uploads in legacy and block transport.

Validates the token with the Bot API (getMe), makes the bot an administrator of the volume's storage group with post rights only (using your own Telegram login), and records the token as the next TELEGRAM_BOT_TOKEN_N in the config .env (mode 0600). The token is read from a file or stdin, never from the command line, and is never printed. A bot serves legacy and block transport volumes in the group. TGFV uploads use the user session. Optional: volumes work with your own login alone.

Usage: teagarden volume add-bot [OPTIONS] --token-file <PATH|-> <VOLUME>

Arguments:
  <VOLUME>
          Volume display name or UUID (locates the storage group)

Options:
      --token-file <PATH|->
          File containing the bot token (`-` for stdin)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden volume remove-bot

```text
Remove a storage bot added with `volume add-bot`.

The bot leaves the storage group, its TELEGRAM_BOT_TOKEN_N entry is deleted, and later entries are renumbered. Revoke the token in @BotFather (/revoke) to make it useless.

Usage: teagarden volume remove-bot [OPTIONS] --bot-id <ID> <VOLUME>

Arguments:
  <VOLUME>
          Volume display name or UUID (locates the storage group)

Options:
      --bot-id <ID>
          The bot's numeric id: the part of its token before ':' (printed by `volume add-bot`)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden device

```text
Manage multi-computer installations in a portable volume

Usage: teagarden device [OPTIONS] <COMMAND>

Commands:
  list    List every installation, this computer's id, and Telegram authorizations
  revoke  Revoke one installation from a volume. Requires the owner signing capability
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden device list

```text
List every installation, this computer's id, and Telegram authorizations

Usage: teagarden device list [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>  Volume display name or UUID

Options:
      --password-file <PASSWORD_FILE>  Read the volume password from this file (`-` reads stdin)
  -v, --verbose                        Enable verbose logging (sets RUST_LOG=debug)
      --recovery-file <RECOVERY_FILE>  Unlock with the recovery sentence from this file (`-` reads stdin)
  -h, --help                           Print help
```

### teagarden device revoke

```text
Revoke one installation from a volume. Requires the owner signing capability.

Immediately stops the target from reaching the volume through Telegram and publishes an owner-signed cutoff for its later writes. The password and root key stay unchanged: a removed device that obtains encrypted files another way can still decrypt them with the password it knows. Root-key rotation is planned for a later release.

Usage: teagarden device revoke [OPTIONS] <VOLUME> <INSTALLATION_ID>

Arguments:
  <VOLUME>
          Volume display name or UUID

  <INSTALLATION_ID>
          Full installation UUID shown by the device registry

Options:
      --password-file <PATH>
          Read the volume password from this file

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --recovery-file <PATH>
          Unlock with the recovery sentence from this file

      --telegram-session <HASH>
          End exactly this Telegram authorization when the device binding is known

      --confirmed-session-map <PATH>
          Owner-confirmed JSON bindings for sessions Telegram masks in their own view

      --log-out-all-other-telegram-sessions
          Explicitly sign out every other Telegram authorization on this account. Requires the exact response YES on stdin; there is no bypass flag

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden configure

```text
Interactive setup wizard

Usage: teagarden configure [OPTIONS]

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden status

```text
Show system status

Usage: teagarden status [OPTIONS]

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden key

```text
Encryption key rotation and recovery-root export/verification

Usage: teagarden key [OPTIONS] <COMMAND>

Commands:
  rotate  Rotate legacy block-volume encryption epochs. TGFV rotation is planned for a later release
  export  Export the volume's key-hierarchy root as a 22-word recovery sentence — a real recovery credential (verify with `key import --recovery-file`, or open the volume with a volume or key command's `--recovery-file`; `keyslot enroll`/`remove-slot` need a key slot instead). WARNING: the exported root opens the volume without a slot or factor. Device revocation removes Telegram access; it does not invalidate an exported root or change the password. TGFV root rotation is planned for a later release
  import  Verify a recovery sentence against the local volumes and report which volume it opens (a root alone cannot rebuild a volume whose config is absent)
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden key rotate

```text
Rotate legacy block-volume encryption epochs. TGFV rotation is planned for a later release.

Refuses while the legacy volume's last session did not end with a clean unmount (mount and unmount it once first). Old messages are deleted only after a metadata snapshot naming the re-encrypted ones is published. If a rotation is interrupted, run it again to finish it.

Usage: teagarden key rotate [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>
          Volume display name or UUID

Options:
      --password-file <PATH>
          Read the volume password / passphrase from this file instead of prompting (use `-` for stdin)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --recovery-file <PATH>
          Unlock with the recovery sentence in this file (use `-` for stdin) instead of the passphrase: a key-protected volume's recovery-slot sentence, or the key-hierarchy root printed by `key export`

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden key export

```text
Export the volume's key-hierarchy root as a 22-word recovery sentence — a real recovery credential (verify with `key import --recovery-file`, or open the volume with a volume or key command's `--recovery-file`; `keyslot enroll`/`remove-slot` need a key slot instead). WARNING: the exported root opens the volume without a slot or factor. Device revocation removes Telegram access; it does not invalidate an exported root or change the password. TGFV root rotation is planned for a later release

Usage: teagarden key export [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>  Volume display name or UUID

Options:
      --password-file <PATH>  Read the volume password / passphrase from this file instead of prompting (use `-` for stdin)
  -v, --verbose               Enable verbose logging (sets RUST_LOG=debug)
      --recovery-file <PATH>  Unlock with the recovery sentence in this file (use `-` for stdin) instead of the passphrase: a key-protected volume's recovery-slot sentence, or the key-hierarchy root printed by `key export`
  -h, --help                  Print help
```

### teagarden key import

```text
Verify a recovery sentence against the local volumes and report which volume it opens (a root alone cannot rebuild a volume whose config is absent)

Usage: teagarden key import [OPTIONS] --recovery-file <PATH>

Options:
      --recovery-file <PATH>  Read the mnemonic sentence from this file (use `-` for stdin). The sentence is intentionally never accepted in argv or shell history
  -v, --verbose               Enable verbose logging (sets RUST_LOG=debug)
  -h, --help                  Print help
```

### teagarden fstab

```text
Volume mount table — like /etc/fstab but for TeaGarden.

Stored as `teagarden.fstab` (TOML) in the config directory: ~/.config/teagarden on Linux, ~/Library/Application Support/teagarden on macOS, or $TEAGARDEN_CONFIG_DIR. Entries with auto=true are mounted by `fstab mount-all` and the systemd service installer.

Usage: teagarden fstab [OPTIONS] <COMMAND>

Commands:
  list         List all entries in teagarden.fstab
  add          Add a volume mount entry to teagarden.fstab
  remove       Remove a volume entry from teagarden.fstab
  mount-all    Mount all auto=true entries that have a password_file configured
  unmount-all  Unmount all teagarden.fstab volumes that are currently mounted
  help         Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden fstab list

```text
List all entries in teagarden.fstab

Usage: teagarden fstab list [OPTIONS]

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden fstab add

```text
Add a volume mount entry to teagarden.fstab

Usage: teagarden fstab add [OPTIONS] --volume <VOLUME> --mountpoint <MOUNTPOINT>

Options:
  -v, --verbose                  Enable verbose logging (sets RUST_LOG=debug)
      --volume <VOLUME>          Volume display name or UUID
      --mountpoint <MOUNTPOINT>  Mount point path (~ is expanded)
      --auto                     Mount automatically (default: true)
      --allow-other              Let other users (including root) into the mount (as a non-root user, needs `user_allow_other` in /etc/fuse.conf)
      --password-file <PATH>     Path to a file containing the volume password (enables non-interactive mounts)
  -h, --help                     Print help
```

### teagarden fstab remove

```text
Remove a volume entry from teagarden.fstab

Usage: teagarden fstab remove [OPTIONS] --volume <VOLUME>

Options:
  -v, --verbose          Enable verbose logging (sets RUST_LOG=debug)
      --volume <VOLUME>  Volume display name or UUID
  -h, --help             Print help
```

### teagarden fstab mount-all

```text
Mount all auto=true entries that have a password_file configured

Usage: teagarden fstab mount-all [OPTIONS]

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden fstab unmount-all

```text
Unmount all teagarden.fstab volumes that are currently mounted

Usage: teagarden fstab unmount-all [OPTIONS]

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden keyslot

```text
Key slots: any ONE enrolled slot opens the volume (like LUKS key slots).

A device slot (TPM2, Tang, PKCS#11/HSM, FIDO2) ADDS a way in; it never makes the passphrase or the recovery sentence insufficient. At least one passphrase or recovery-sentence slot always remains: `keyslot remove-slot` refuses to remove the last one, so a volume can never be opened only with a device. After you remove the passphrase slot, the recovery sentence still opens the volume without any device. Slot ids are listed by `teagarden keyslot status <VOLUME>`. Owner enrollment/removal commands publish slot changes to Telegram; status and unlock checks work offline.

`mfa` is accepted as a hidden alias, so existing scripts keep working.

Usage: teagarden keyslot [OPTIONS] <COMMAND>

Commands:
  status       Show a volume's key slots — any one enrolled slot opens the volume (like LUKS) — with the slot ids `keyslot remove-slot` takes. A legacy vault is reported as NOT enforced
  remove       Delete a LEGACY (non-enforcing) mfa vault. REFUSES on a key-protected volume — deleting its slot vault would destroy the volume permanently
  enroll       Enroll a hardware/device factor as a new key slot of a key-protected (`--key-protection`) volume. Key slots — any one enrolled slot opens the volume (like LUKS): the new factor is an ADDITIONAL way in, not a requirement; your passphrase still opens the volume until you remove its slot with `keyslot remove-slot`, and the recovery sentence keeps opening it either way. Unlock the existing vault with your passphrase (or `--recovery-file`). Publishes the changed slot vault to Telegram with the volume owner's signature. Choose exactly ONE factor per invocation; each enrolls its own independent slot. A failed publication remains pending and is retried by the next mount
  remove-slot  Remove one key slot from a key-protected volume. Key slots are any-one-of (like LUKS): every enrolled slot opens the volume on its own. Authorise with a DIFFERENT slot that will remain. Refuses to remove the last slot, and the last passphrase or recovery-sentence slot: removing the passphrase slot leaves the recovery sentence, which still opens the volume without any device. See `keyslot status` for slot ids. Publishes the changed slot vault to Telegram with the volume owner's signature. A failed publication remains pending and is retried by the next mount
  unlock       Verify a key-protected volume opens via a device factor (offline check — does NOT mount). Proves an enrolled factor works end-to-end
  help         Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden keyslot status

```text
Show a volume's key slots — any one enrolled slot opens the volume (like LUKS) — with the slot ids `keyslot remove-slot` takes. A legacy vault is reported as NOT enforced

Usage: teagarden keyslot status [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>  Volume display name or UUID

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden keyslot remove

```text
Delete a LEGACY (non-enforcing) mfa vault. REFUSES on a key-protected volume — deleting its slot vault would destroy the volume permanently

Usage: teagarden keyslot remove [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>  Volume display name or UUID

Options:
      --force    Skip confirmation prompt
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden keyslot enroll

```text
Enroll a hardware/device factor as a new key slot of a key-protected (`--key-protection`) volume. Key slots — any one enrolled slot opens the volume (like LUKS): the new factor is an ADDITIONAL way in, not a requirement; your passphrase still opens the volume until you remove its slot with `keyslot remove-slot`, and the recovery sentence keeps opening it either way. Unlock the existing vault with your passphrase (or `--recovery-file`). Publishes the changed slot vault to Telegram with the volume owner's signature. Choose exactly ONE factor per invocation; each enrolls its own independent slot. A failed publication remains pending and is retried by the next mount

Usage: teagarden keyslot enroll [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>
          Volume display name or UUID

Options:
      --tpm2
          Enroll a TPM2 sealing slot (requires tpm2-tools + a reachable TPM)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --pcrs <PCRS>
          Bind the TPM2 seal to a PCR selection (e.g. "sha256:0,1,7"); changed selected PCR values refuse unseal of this slot. Other slots remain independent. Omit for a TPM-only bind

      --tang <URL>
          Enroll a Tang (network-bound decryption) slot against this server URL. Only this Tang slot requires the server; other slots remain independent

      --tang-thumbprint <THUMBPRINT>
          Pin the Tang server's advertised-key thumbprint (trust-on-first-use if omitted)

      --pkcs11-module <PATH>
          Enroll a PKCS#11 / HSM slot using this provider module (e.g. /usr/lib/softhsm/libsofthsm2.so)

      --pkcs11-token-label <LABEL>
          PKCS#11 token label to select among multiple tokens

      --pkcs11-key-id <HEX>
          PKCS#11 key id in hex (default: 01)

      --fido2
          Enroll a FIDO2 hmac-secret slot on a hardware authenticator, with the verification mode from --fido2-mode (asked on the terminal if absent). Needs `age-plugin-fido2-hmac` v0.5.0 or later installed

      --fido2-mode <MODE>
          What the security key must check at every unlock of this slot. The mode is recorded in the slot; unlock and mount use it

          Possible values:
          - pin:    PIN only: NOT AVAILABLE (every FIDO2 unlock needs a touch); refused with the reason
          - pin-up: PIN + UP: the key's PIN and a touch
          - pin-uv: PIN + UV: NOT AVAILABLE (CTAP2 cannot require both); refused with the reason
          - up:     UP only: a touch
          - uv:     UV only: NOT AVAILABLE (the plugin never requests it); refused with the reason

      --fido2-post-quantum
          Wrap with the FIDO2 plugin's ML-KEM-768/X25519 hybrid stanza

      --password-file <PATH>
          Unlock the existing vault with the passphrase read from this file (use `-` for stdin) instead of prompting

      --recovery-file <PATH>
          Unlock the existing vault with the recovery sentence from this file (use `-` for stdin) instead of the passphrase

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden keyslot remove-slot

```text
Remove one key slot from a key-protected volume. Key slots are any-one-of (like LUKS): every enrolled slot opens the volume on its own. Authorise with a DIFFERENT slot that will remain. Refuses to remove the last slot, and the last passphrase or recovery-sentence slot: removing the passphrase slot leaves the recovery sentence, which still opens the volume without any device. See `keyslot status` for slot ids. Publishes the changed slot vault to Telegram with the volume owner's signature. A failed publication remains pending and is retried by the next mount

Usage: teagarden keyslot remove-slot [OPTIONS] <VOLUME> <SLOT>

Arguments:
  <VOLUME>  Volume display name or UUID
  <SLOT>    Id of the slot to remove (from `teagarden keyslot status`)

Options:
      --password-file <PATH>          Authorise with the passphrase read from this file (`-` = stdin)
  -v, --verbose                       Enable verbose logging (sets RUST_LOG=debug)
      --recovery-file <PATH>          Authorise with the recovery sentence read from this file (`-` = stdin)
      --tpm2                          Authorise with the TPM2 slot
      --tang <URL>                    Authorise with a Tang slot bound to this server URL
      --tang-thumbprint <THUMBPRINT>  Expected Tang advertised-key thumbprint
      --pkcs11-module <PATH>          Authorise with a PKCS#11 slot using this provider module
      --pkcs11-token-label <LABEL>    PKCS#11 token label
      --pkcs11-key-id <HEX>           PKCS#11 key id in hex (default: 01)
      --fido2                         Authorise with a FIDO2 hardware authenticator slot
      --yes                           Do not ask for confirmation
  -h, --help                          Print help
```

### teagarden keyslot unlock

```text
Verify a key-protected volume opens via a device factor (offline check — does NOT mount). Proves an enrolled factor works end-to-end

Usage: teagarden keyslot unlock [OPTIONS] <VOLUME>

Arguments:
  <VOLUME>  Volume display name or UUID

Options:
      --tpm2                          Open via the TPM2 slot
  -v, --verbose                       Enable verbose logging (sets RUST_LOG=debug)
      --tang <URL>                    Open via a Tang slot bound to this server URL
      --tang-thumbprint <THUMBPRINT>  Expected Tang advertised-key thumbprint
      --pkcs11-module <PATH>          Open via a PKCS#11 slot using this provider module
      --pkcs11-token-label <LABEL>    PKCS#11 token label
      --pkcs11-key-id <HEX>           PKCS#11 key id in hex (default: 01)
      --fido2                         Open via a FIDO2 hardware authenticator slot
  -h, --help                          Print help
```

### teagarden dev

```text
TeaGarden dev — encrypted BLOCK DEVICE (put a real filesystem on top).

Modelled on cryptsetup: `create` formats (like luksFormat), `serve nbd` exposes the decrypted device (like open), then you `mkfs.ext4 /dev/nbd0` yourself. There is deliberately no `mkfs.teagarden` — the filesystem you make on the device is the GUEST filesystem.

Usage: teagarden dev [OPTIONS] <COMMAND>

Commands:
  create   Format a new encrypted block device (the `luksFormat` step): allocate its Telegram topic, write the superblock, and register it locally
  list     List registered devices
  status   Show real engine state for a device (capacity, epoch, segments, head)
  serve    Expose a device over a network block protocol
  gc       Reclaim segments superseded by newer writes
  resize   Grow a device's logical capacity (shrinking is refused)
  recover  Rebuild a block device's local state from Telegram (disaster recovery). Requires this device's local registry record with its salt, geometry, topic and checkpoint ID, as well as the credential
  delete   Permanently delete a device: its Telegram topic (every segment, head and checkpoint in it), then its local state and registry entry
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden dev create

```text
Format a new encrypted block device (the `luksFormat` step): allocate its Telegram topic, write the superblock, and register it locally

Usage: teagarden dev create [OPTIONS] --name <NAME> --size-gib <SIZE_GIB>

Options:
      --name <NAME>                Device name
  -v, --verbose                    Enable verbose logging (sets RUST_LOG=debug)
      --size-gib <SIZE_GIB>        Logical capacity in GiB
      --segment-mib <SEGMENT_MIB>  Segment size in MiB — one segment is one Telegram document (default 45, matching the cloud Bot API document ceiling) [default: 45]
      --dir <PATH>                 Directory for local device state (default: under the registry)
      --password-file <PATH>       Read the device credential from this file (`-` for stdin)
      --group-name <NAME>          Name for the shared Telegram storage group (see `volume create --group-name`; same group, shared with volumes)
  -h, --help                       Print help
```

### teagarden dev list

```text
List registered devices

Usage: teagarden dev list [OPTIONS]

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden dev status

```text
Show real engine state for a device (capacity, epoch, segments, head)

Usage: teagarden dev status [OPTIONS] <NAME>

Arguments:
  <NAME>  Device name

Options:
      --password-file <PATH>  Read the device credential from this file (`-` for stdin)
  -v, --verbose               Enable verbose logging (sets RUST_LOG=debug)
  -h, --help                  Print help
```

### teagarden dev serve

```text
Expose a device over a network block protocol

Usage: teagarden dev serve [OPTIONS] <COMMAND>

Commands:
  nbd   Serve over NBD. Attach with `nbd-client -b 4096 <host> <port> /dev/nbd0`
  help  Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose  Enable verbose logging (sets RUST_LOG=debug)
  -h, --help     Print help
```

### teagarden dev serve nbd

```text
Serve over NBD. Attach with `nbd-client -b 4096 <host> <port> /dev/nbd0`.

Stop with Ctrl+C, SIGTERM, or `nbd-client -d /dev/nbd0`: the open segment is uploaded and a final checkpoint published and recorded before exit; the exit status is non-zero if any of that fails. While serving, a checkpoint is published after every 8 uploaded segments and at least every 60 s while uploaded segments are not yet covered by one.

SECURITY: NBD has no authentication — while serving, ANY local user who can reach the bind address has full read/write access to the DECRYPTED device. On shared machines, do not serve, or isolate the socket in a network namespace. See docs/BLOCK_DEVICE.md ("Security of the NBD socket").

Usage: teagarden dev serve nbd [OPTIONS] <NAME>

Arguments:
  <NAME>
          Device name

Options:
      --bind <BIND>
          Address to bind (host:port)
          
          [default: 127.0.0.1:10809]

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --password-file <PATH>
          Read the device credential from this file (`-` for stdin)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden dev gc

```text
Reclaim segments superseded by newer writes.

NOTE: after GC only the NEWEST head is a viable recovery point.

Usage: teagarden dev gc [OPTIONS] <NAME>

Arguments:
  <NAME>
          Device name

Options:
      --password-file <PATH>
          Read the device credential from this file (`-` for stdin)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden dev resize

```text
Grow a device's logical capacity (shrinking is refused)

Usage: teagarden dev resize [OPTIONS] --size-gib <SIZE_GIB> <NAME>

Arguments:
  <NAME>  Device name

Options:
      --size-gib <SIZE_GIB>   New capacity in GiB
  -v, --verbose               Enable verbose logging (sets RUST_LOG=debug)
      --password-file <PATH>  Read the device credential from this file (`-` for stdin)
  -h, --help                  Print help
```

### teagarden dev recover

```text
Rebuild a block device's local state from Telegram (disaster recovery). Requires this device's local registry record with its salt, geometry, topic and checkpoint ID, as well as the credential

Usage: teagarden dev recover [OPTIONS] <NAME>

Arguments:
  <NAME>  Device name

Options:
      --head-msg-id <HEAD_MSG_ID>  Head message id to recover from (defaults to the registry's record)
  -v, --verbose                    Enable verbose logging (sets RUST_LOG=debug)
      --password-file <PATH>       Read the device credential from this file (`-` for stdin)
  -h, --help                       Print help
```

### teagarden dev delete

```text
Permanently delete a device: its Telegram topic (every segment, head and checkpoint in it), then its local state and registry entry.

Refuses while the device is open (e.g. served by `dev serve nbd`) or the credential is wrong, and deletes nothing in that case. If the topic cannot be deleted the local state is kept so the command can be rerun. Without --force it asks for confirmation, and refuses when there is no terminal.

Usage: teagarden dev delete [OPTIONS] <NAME>

Arguments:
  <NAME>
          Device name

Options:
      --password-file <PATH>
          Read the device credential from this file (`-` for stdin)

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

      --force
          Do not ask for confirmation

      --local-only
          Remove only the local state and leave the Telegram topic (and everything in it) in place, abandoned

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden completions

```text
Generate or install shell completions.

Without --install, prints the completion script to stdout so you can redirect it manually.  With --install, writes to the user-local location for the given shell and prints the path.

Usage: teagarden completions [OPTIONS] <SHELL>

Arguments:
  <SHELL>
          Shell to generate completions for
          
          [possible values: bash, elvish, fish, powershell, zsh]

Options:
      --install
          Install to the user-local completions directory instead of printing

  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden man

```text
Print the TeaGarden man page in roff format.

Pipe to `man -l -` to read immediately, or install: teagarden man | gzip > /usr/local/share/man/man1/teagarden.1.gz

Usage: teagarden man [OPTIONS]

Options:
  -v, --verbose
          Enable verbose logging (sets RUST_LOG=debug)

  -h, --help
          Print help (see a summary with '-h')
```

### teagarden decrypt

```text
Decrypt downloaded TGFV file objects without local volume state or a Telegram login

Usage: teagarden decrypt [OPTIONS] <INPUT>

Arguments:
  <INPUT>  One downloaded file object or a directory of objects and its TGHD header

Options:
      --out <DIR>                      Write files here (defaults to `decrypted` beside the input)
  -v, --verbose                        Enable verbose logging (sets RUST_LOG=debug)
      --password-file <PASSWORD_FILE>  Read the volume passphrase from a file (`-` reads stdin); otherwise prompt
      --recovery-file <RECOVERY_FILE>  Read a recovery-slot or exported-root sentence from a file (`-` reads stdin)
      --file-id <UUID>                 Show only this file's version history by permanent UUID
      --owner-public-key <HEX>         Enforce a previously established owner public key during recovery
      --include-unverified             Recover objects with missing owner source provenance and label them UNVERIFIED
  -h, --help                           Print help
```
