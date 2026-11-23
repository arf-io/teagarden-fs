//! `teagarden` command-line interface.
//!
//! This binary is the user-facing entry point for TeaGarden, an encrypted FUSE
//! filesystem that stores data as opaque, individually encrypted blocks in a
//! private Telegram group (one forum topic per volume). It parses the `teagarden` command tree with clap
//! and dispatches each subcommand (authentication, volume lifecycle and
//! mounting, sharing, key slots, the fstab-style mount table, and the
//! TeaGarden block device) to the corresponding handler in the `commands`
//! module. It also handles startup concerns such as
//! loading the config `.env` file, initializing tracing, and generating shell
//! completions and the man page.

#![deny(missing_docs)]

use std::io::Write as _;

use anyhow::Context as _;
use clap::{CommandFactory, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
mod teagarden_fstab;

/// Load KEY=VALUE pairs from the TeaGarden config .env file into the process
/// environment. Only sets vars that aren't already set (shell env takes precedence).
fn load_config_env() {
    let Ok(dir) = commands::utils::config_dir() else {
        return;
    };
    let path = dir.join(".env");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return;
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            // TEAGARDEN_CONFIG_DIR decides where this very file lives; importing
            // it from the file would make later lookups resolve somewhere else.
            if key == "TEAGARDEN_CONFIG_DIR" {
                continue;
            }
            if std::env::var_os(key).is_none() {
                std::env::set_var(key, value);
            }
        }
    }
}

/// Keep `decrypt` fully offline: it must not discover or load local TeaGarden
/// configuration before parsing its downloaded objects and supplied credential.
fn is_offline_decrypt_invocation(args: &[std::ffi::OsString]) -> bool {
    args.iter()
        .skip(1)
        .find(|arg| arg.as_os_str() != "-v" && arg.as_os_str() != "--verbose")
        .is_some_and(|arg| arg == "decrypt")
}

/// TeaGarden — Telegram Encrypted Filesystem.
///
/// An encrypted FUSE filesystem that stores data as opaque blocks in private
/// Telegram channels. All blocks are encrypted with ChaCha20-Poly1305 before
/// upload; Telegram sees only binary documents with random filenames.
#[derive(Parser)]
#[command(
    name = "teagarden",
    version,
    about = "TeaGarden - Telegram Encrypted Filesystem",
    long_about = None,
    // Allow the mount-esque shorthand `teagarden [options] <volume> [mountpoint]`
    // (like `mount [options] device dir`) to coexist with the subcommands: a word
    // naming a subcommand ALWAYS dispatches that subcommand; only non-subcommand
    // words reach the VOLUME positional. (We deliberately do NOT use
    // `args_conflicts_with_subcommands`: it commits clap to args-mode as soon as a
    // leading global flag appears, so `teagarden --verbose status` swallowed
    // `status` as a volume name and died with a confusing teagarden.fstab error. The
    // no-mixing rule is enforced manually in `main` instead.)
    subcommand_precedence_over_arg = true,
)]
pub struct Cli {
    /// Enable verbose logging (sets RUST_LOG=debug).
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,

    // ---- mount-esque shorthand: `teagarden [options] <volume> [mountpoint]` ----
    // Used only when no subcommand is given. Equivalent to `volume mount`, so a
    // volume can be mounted just like a real filesystem (`mount device dir`).
    /// Volume to mount (display name or UUID) — shorthand for `volume mount`.
    #[arg(value_name = "VOLUME")]
    volume: Option<String>,
    /// Directory to mount at (defaults to the teagarden.fstab mountpoint for the volume).
    #[arg(value_name = "MOUNTPOINT")]
    mountpoint: Option<String>,
    /// (shorthand mount) Allow other users to access the mount.
    #[arg(long)]
    allow_other: bool,
    /// (shorthand mount) Read the password from this file instead of prompting.
    #[arg(long, value_name = "PATH")]
    password_file: Option<String>,
    /// (shorthand mount) Background the mount and return once it is up (for
    /// `mount.teagarden` / `/etc/fstab`). Requires --password-file.
    #[arg(long)]
    daemonize: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with Telegram.
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Volume management (create, mount, unmount, list, delete, info).
    Volume {
        #[command(subcommand)]
        action: VolumeAction,
    },
    /// Manage multi-computer installations in a portable volume.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Interactive setup wizard.
    Configure,
    /// Show system status.
    Status,
    /// Encryption key rotation and recovery-root export/verification.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Volume mount table — like /etc/fstab but for TeaGarden.
    ///
    /// Stored as `teagarden.fstab` (TOML) in the config directory: ~/.config/teagarden on
    /// Linux, ~/Library/Application Support/teagarden on macOS, or
    /// $TEAGARDEN_CONFIG_DIR.
    /// Entries with auto=true are mounted by `fstab mount-all` and the
    /// systemd service installer.
    Fstab {
        #[command(subcommand)]
        action: FstabAction,
    },
    /// Key slots: any ONE enrolled slot opens the volume (like LUKS key slots).
    ///
    /// A device slot (TPM2, Tang, PKCS#11/HSM, FIDO2) ADDS a way in; it never makes
    /// the passphrase or the recovery sentence insufficient. At least one
    /// passphrase or recovery-sentence slot always remains: `keyslot remove-slot`
    /// refuses to remove the last one, so a volume can never be opened only with a
    /// device. After you remove the passphrase slot, the recovery sentence still
    /// opens the volume without any device. Slot ids are listed by
    /// `teagarden keyslot status <VOLUME>`. Owner enrollment/removal commands
    /// publish slot changes to Telegram; status and unlock checks work offline.
    ///
    /// `mfa` is accepted as a hidden alias, so existing scripts keep working.
    #[command(alias = "mfa")]
    Keyslot {
        #[command(subcommand)]
        action: KeyslotAction,
    },
    /// TeaGarden dev — encrypted BLOCK DEVICE (put a real filesystem on top).
    ///
    /// Modelled on cryptsetup: `create` formats (like luksFormat), `serve nbd`
    /// exposes the decrypted device (like open), then you `mkfs.ext4 /dev/nbd0`
    /// yourself. There is deliberately no `mkfs.teagarden` — the filesystem you
    /// make on the device is the GUEST filesystem.
    #[cfg(feature = "dev")]
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },
    /// Generate or install shell completions.
    ///
    /// Without --install, prints the completion script to stdout so you can
    /// redirect it manually.  With --install, writes to the user-local
    /// location for the given shell and prints the path.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
        /// Install to the user-local completions directory instead of printing.
        #[arg(long)]
        install: bool,
    },
    /// Print the TeaGarden man page in roff format.
    ///
    /// Pipe to `man -l -` to read immediately, or install:
    ///   teagarden man | gzip > /usr/local/share/man/man1/teagarden.1.gz
    Man,
    /// Decrypt downloaded TGFV file objects without local volume state or a Telegram login.
    Decrypt {
        /// One downloaded file object or a directory of objects and its TGHD header.
        input: std::path::PathBuf,
        /// Write files here (defaults to `decrypted` beside the input).
        #[arg(long, value_name = "DIR")]
        out: Option<std::path::PathBuf>,
        /// Read the volume passphrase from a file (`-` reads stdin); otherwise prompt.
        #[arg(long, conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Read a recovery-slot or exported-root sentence from a file (`-` reads stdin).
        #[arg(long, conflicts_with = "password_file")]
        recovery_file: Option<String>,
        /// Show only this file's version history by permanent UUID.
        #[arg(long, value_name = "UUID")]
        file_id: Option<uuid::Uuid>,
        /// Enforce a previously established owner public key during recovery.
        #[arg(long, value_name = "HEX")]
        owner_public_key: Option<String>,
        /// Recover objects with missing owner source provenance and label them UNVERIFIED.
        #[arg(long)]
        include_unverified: bool,
    },
}

#[derive(Subcommand)]
enum AuthAction {
    /// Log in to Telegram (phone number + verification code).
    Login {
        /// Telegram API ID (or set TG_API_ID env var).
        #[arg(long, env = "TG_API_ID", hide_env_values = true)]
        api_id: Option<i32>,
        /// Telegram API hash (or set TG_API_HASH env var).
        #[arg(long, env = "TG_API_HASH", hide_env_values = true)]
        api_hash: Option<String>,
        /// Use Telegram's QR based device login instead of a phone code.
        #[arg(long)]
        qr: bool,
        /// Read the Telegram cloud password from this file if QR login requires it.
        #[arg(long, value_name = "PATH")]
        cloud_password_file: Option<std::path::PathBuf>,
    },
    /// Approve a QR login token on this already authenticated computer.
    Approve {
        /// The tg://login?token=... line shown on the new computer, or - to read it from stdin with --yes.
        token: String,
        /// Approve without the interactive YES prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Log out and delete the local session file.
    Logout,
    /// Show authentication status.
    Status,
    /// Copy this computer's Telegram login (API settings, storage-group record,
    /// session) into DIR, to move it to another computer.
    ///
    /// DIR must be empty or not exist; it is created with mode 0700 and each
    /// file in it with mode 0600. DIR then holds the login to your Telegram
    /// account, unencrypted: move it only over a channel you trust and delete it
    /// afterwards.
    Export {
        /// Directory to write into.
        dir: std::path::PathBuf,
    },
    /// Install a login written by `auth export` into this computer's config
    /// directory, then show the authentication status.
    ///
    /// Checks the files first (regular files, not symbolic links; a signed-in
    /// session) and refuses to replace an existing configuration unless --force
    /// is given. Nothing is left half-written.
    Import {
        /// Directory written by `teagarden auth export`.
        dir: std::path::PathBuf,
        /// Replace the API settings, storage-group record and session already on
        /// this computer.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum VolumeAction {
    /// Create a new encrypted volume, stored as its own topic in your private Telegram storage group.
    Create {
        /// Human-readable name (auto-generated "noun verb adverb" if omitted).
        #[arg(short, long)]
        name: Option<String>,
        /// Read the password from this file instead of prompting (use `-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Root the volume in a key-slot vault: its keys derive from a random
        /// master key that only an enrolled slot can unwrap. Key slots — any one
        /// enrolled slot opens the volume (like LUKS). The passphrase becomes one
        /// slot and a recovery co-slot is auto-enrolled (its sentence is printed
        /// once). Add device slots with `keyslot enroll`; remove slots (e.g. the
        /// passphrase) with `keyslot remove-slot`.
        #[arg(long)]
        key_protection: bool,
        /// Name for the shared Telegram storage group, created once on your first
        /// volume and reused by every volume after (has no effect if the group
        /// already exists). If omitted, a random three-word name is used, so the
        /// title reveals nothing about your data.
        #[arg(long, value_name = "NAME")]
        group_name: Option<String>,
    },
    /// Attach this computer to an existing Telegram forum topic.
    Attach {
        /// Telegram group and topic in GROUP_ID:TOPIC_ID form.
        group_topic: String,
        /// Read the current volume password from a file instead of prompting.
        #[arg(long, value_name = "PATH", conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Unlock with the current recovery sentence from this file.
        #[arg(long, value_name = "PATH", conflicts_with = "password_file")]
        recovery_file: Option<String>,
        /// Owner public key copied from the creating computer (required for TGHD2).
        #[arg(long, value_name = "HEX")]
        owner_public_key: Option<String>,
    },
    /// Mount a volume at the given path, or at the teagarden.fstab mountpoint if omitted.
    Mount {
        /// Volume display name or UUID (prefix match accepted).
        volume: String,
        /// Directory to mount at.  If omitted, the mountpoint from teagarden.fstab is used.
        mountpoint: Option<String>,
        /// Let other users (including root) into the mount. Off by default, so
        /// only you can access it and no /etc/fuse.conf change is needed. As a
        /// non-root user this needs `user_allow_other` in /etc/fuse.conf.
        #[arg(long)]
        allow_other: bool,
        /// Read the password from this file instead of prompting (for automation).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Unlock with a 22-word recovery sentence read from this file (use `-` for
        /// stdin) instead of the passphrase: a key-protected volume's recovery-slot
        /// sentence, or the key-hierarchy root printed by `key export`.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
        /// Background the mount and return once it is up (for `mount.teagarden` /
        /// `/etc/fstab` / boot). Requires --password-file or a device factor that
        /// doesn't need interaction (--tpm2, --tang) — a boot mount can't prompt.
        #[arg(long)]
        daemonize: bool,
        /// Unlock via the TPM2 slot instead of a password (mutually exclusive with
        /// --password-file/--recovery-file; the volume must have a TPM2 slot
        /// enrolled via `keyslot enroll --tpm2`).
        #[arg(long)]
        tpm2: bool,
        /// Unlock via a Tang slot bound to this server URL.
        #[arg(long, value_name = "URL")]
        tang: Option<String>,
        /// Expected Tang advertised-key thumbprint.
        #[arg(long, value_name = "THUMBPRINT")]
        tang_thumbprint: Option<String>,
        /// Unlock via a PKCS#11 slot using this provider module. Foreground only —
        /// the PIN prompt needs a terminal, so this cannot combine with --daemonize.
        #[arg(long, value_name = "PATH")]
        pkcs11_module: Option<String>,
        /// PKCS#11 token label.
        #[arg(long, value_name = "LABEL")]
        pkcs11_token_label: Option<String>,
        /// PKCS#11 key id in hex (default: 01).
        #[arg(long, value_name = "HEX")]
        pkcs11_key_id: Option<String>,
        /// Unlock via a FIDO2 hardware authenticator slot. Foreground only — needs
        /// a physical touch, so this cannot combine with --daemonize.
        #[arg(long)]
        fido2: bool,
    },
    /// Unmount a mounted volume.
    Unmount {
        /// Mount point path or volume name.
        target: String,
    },
    /// Legacy-only: restore a block volume's metadata DB from its latest Telegram snapshot.
    ///
    /// Disaster recovery with anti-rollback: a snapshot older than the volume's
    /// known version is refused. The volume must be unmounted. Refuses while the
    /// metadata journal holds changes that are in no snapshot yet (the last
    /// session did not end with a clean unmount) unless --discard-journal is
    /// given. If the restore is interrupted, the next mount rebuilds the local
    /// metadata DB from Telegram.
    Restore {
        /// Volume display name or UUID (prefix match accepted).
        volume: String,
        /// Restore a specific snapshot message ID instead of the recorded latest.
        /// Still subject to the anti-rollback checks: a snapshot older than the
        /// recorded version is refused, and at the recorded version only the
        /// recorded snapshot is accepted.
        #[arg(long, value_name = "MESSAGE_ID")]
        snapshot_id: Option<i64>,
        /// Read the password from this file instead of prompting (use `-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Skip the destructive-overwrite confirmation prompt. Without it the
        /// restore asks on the terminal, and exits non-zero when there is no
        /// terminal or the answer is not yes.
        #[arg(long)]
        force: bool,
        /// Unlock with the recovery sentence in this file (use `-` for stdin)
        /// instead of the passphrase: a key-protected volume's recovery-slot
        /// sentence, or the key-hierarchy root printed by `key export`.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
        /// Restore even though the volume's metadata journal has entries that
        /// are not in any snapshot yet (the last session did not end with a
        /// clean unmount). Those changes are on Telegram and the next mount
        /// would replay them; restoring DISCARDS them. Without this option
        /// `restore` refuses and says how many entries would be lost.
        #[arg(long)]
        discard_journal: bool,
    },
    /// Legacy-only: publish a block volume's local metadata DB as its metadata (explicit recovery).
    ///
    /// For a volume whose metadata cannot be rebuilt from Telegram (a mount
    /// fails because the base snapshot or a journal entry is gone from the
    /// group, the volume names no snapshot, or journal.head is missing or
    /// unreadable) while the local metadata DB is intact. Takes the volume's
    /// exclusive lock (refuses while the volume is mounted or another
    /// TeaGarden command uses it), requires a readable DB with a root
    /// directory, and refuses a DB stamped as another volume's, or one whose
    /// lineage stamp is not the one journal.head records (an older copy)
    /// unless --replace-newer-metadata is given. It prints how many entries
    /// the DB holds, whether its stamp is journal.head's, the journal HEAD, the
    /// snapshot it supersedes (which `volume restore` refuses afterwards) and
    /// what will be overwritten, and asks before going on. It then
    /// publishes the DB as a new snapshot (at the next reserved version),
    /// stamps it and resets the journal HEAD onto it. Journal entries past the
    /// old base are no longer replayed: the local DB holds what this machine
    /// committed of them. Nothing on Telegram is deleted.
    Republish {
        /// Volume display name or UUID (prefix match accepted).
        volume: String,
        /// Publish the local metadata database (the only source; required, so
        /// the choice is explicit).
        #[arg(long, required = true)]
        from_local_db: bool,
        /// Read the password from this file instead of prompting (use `-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence in this file (use `-` for stdin)
        /// instead of the passphrase: a key-protected volume's recovery-slot
        /// sentence, or the key-hierarchy root printed by `key export`.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
        /// Skip the confirmation prompt. Does not imply
        /// --replace-newer-metadata.
        #[arg(long)]
        force: bool,
        /// Republish even though the local DB's lineage stamp is not the one
        /// journal.head records (an older copy of the DB, or one a publish did
        /// not finish): the newer metadata on Telegram is replaced, and
        /// `volume restore` then refuses the snapshot it supersedes.
        #[arg(long)]
        replace_newer_metadata: bool,
    },
    /// Restore a file to a prior manifest version in a legacy block volume only.
    ///
    /// For TGFV history, use `volume restore-version` with a version UUID prefix.
    /// Non-destructive git-revert: appends a new version whose content matches the
    /// target version (older versions stay in `history`). A journaled, single-writer
    /// operation — the volume must be unmounted and Telegram must be configured.
    Revert {
        /// Volume display name or UUID (prefix match accepted).
        volume: String,
        /// Absolute in-volume path of the file to revert (e.g. `/dir/file.txt`).
        path: String,
        /// Target manifest version to restore (see `volume history` for versions).
        version: u64,
        /// Read the password from this file instead of prompting (use `-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence in this file (use `-` for stdin)
        /// instead of the passphrase: a key-protected volume's recovery-slot
        /// sentence, or the key-hierarchy root printed by `key export`.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
    },
    /// Download raw TGHD and TGFV documents from a volume for offline decryption.
    ExportObjects {
        /// Volume name or UUID.
        volume: String,
        /// Directory to create for the downloaded raw objects.
        #[arg(long, value_name = "DIR")]
        out: std::path::PathBuf,
        /// Read the volume password from a file.
        #[arg(long, conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Read a recovery sentence from a file.
        #[arg(long, conflicts_with = "password_file")]
        recovery_file: Option<String>,
    },
    /// List all configured volumes.
    List,
    /// Permanently delete a volume: first its Telegram forum topic, with every
    /// message in it (every file version, volume header and device record; on a
    /// legacy block volume also its blocks, metadata snapshots and journal), then
    /// the local state. Requires a credential (`--password-file`,
    /// `--recovery-file`, or the passphrase prompt). Refuses if the volume is
    /// mounted or in use by another TeaGarden command (mount, revert, restore,
    /// key rotate), and deletes nothing in that case.
    Delete {
        /// Volume display name or UUID.
        volume: String,
        /// Skip the confirmation prompt (still requires a credential). Without
        /// it the delete asks on the terminal, and exits non-zero when there is
        /// no terminal or the answer is not yes.
        #[arg(long)]
        force: bool,
        /// Read the volume password from this file (use `-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence in this file: a key-protected volume's
        /// recovery-slot sentence, or the key-hierarchy root printed by `key export`.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
        /// Destroy ONLY local state and knowingly abandon the volume's data on
        /// Telegram (its topic and every message in it stay there). Without
        /// this, deletion requires a Telegram login so the topic is removed.
        #[arg(long)]
        local_only: bool,
    },
    /// Show detailed information about a volume.
    Info {
        /// Volume display name or UUID.
        volume: String,
    },
    /// Show the version history of a file in a volume.
    ///
    /// Read-only: never creates or changes the local metadata DB. Refuses while
    /// the volume is mounted or another command is changing it. TGFV history reads
    /// Telegram directly and does not require a local metadata DB. Legacy block
    /// history requires a local metadata DB rebuilt by a mount.
    History {
        /// Volume display name or UUID.
        volume: String,
        /// File path inside the volume (omit to show every file).
        path: Option<String>,
        /// Read the volume password / passphrase from this file instead of
        /// prompting (use `-` for stdin).
        #[arg(long, value_name = "PATH", conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence in this file (use `-` for stdin)
        /// instead of the passphrase: a key-protected volume's recovery-slot
        /// sentence, or the key-hierarchy root printed by `key export`.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
    },
    /// Restore a TGFV version by publishing its bytes as a new current version.
    RestoreVersion {
        /// Volume display name or UUID.
        volume: String,
        /// Destination path inside the volume.
        path: String,
        /// Prefix of the historical TGFV version UUID.
        version_uuid: String,
        /// Read the volume password / passphrase from this file instead of prompting.
        #[arg(long, value_name = "PATH", conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence in this file instead of the passphrase.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
    },
    /// Compare TGFV versions by content hash and size, or legacy manifests by block IDs.
    ///
    /// Read-only; refuses while the volume is mounted or another command is changing it.
    /// TGFV diff reads Telegram directly and does not require a local metadata DB.
    /// Legacy block diff requires a local metadata DB rebuilt by a mount.
    Diff {
        /// Volume display name or UUID.
        volume: String,
        /// First version UUID prefix (TGFV) or manifest ID prefix (legacy).
        version_a: String,
        /// Second version UUID prefix (TGFV) or manifest ID prefix (legacy).
        version_b: String,
        /// Read the volume password / passphrase from this file instead of
        /// prompting (use `-` for stdin).
        #[arg(long, value_name = "PATH", conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence in this file (use `-` for stdin)
        /// instead of the passphrase: a key-protected volume's recovery-slot
        /// sentence, or the key-hierarchy root printed by `key export`.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
    },
    /// Add a storage bot created in @BotFather for parallel uploads in legacy and block transport.
    ///
    /// Validates the token with the Bot API (getMe), makes the bot an
    /// administrator of the volume's storage group with post rights only (using
    /// your own Telegram login), and records the token as the next
    /// TELEGRAM_BOT_TOKEN_N in the config .env (mode 0600). The token is read
    /// from a file or stdin, never from the command line, and is never printed.
    /// A bot serves legacy and block transport volumes in the group.
    /// TGFV uploads use the user session. Optional: volumes work with your
    /// own login alone.
    AddBot {
        /// Volume display name or UUID (locates the storage group).
        volume: String,
        /// File containing the bot token (`-` for stdin).
        #[arg(long, value_name = "PATH|-")]
        token_file: String,
    },
    /// Remove a storage bot added with `volume add-bot`.
    ///
    /// The bot leaves the storage group, its TELEGRAM_BOT_TOKEN_N entry is
    /// deleted, and later entries are renumbered. Revoke the token in
    /// @BotFather (/revoke) to make it useless.
    RemoveBot {
        /// Volume display name or UUID (locates the storage group).
        volume: String,
        /// The bot's numeric id: the part of its token before ':' (printed by
        /// `volume add-bot`).
        #[arg(long, value_name = "ID")]
        bot_id: String,
    },
}

#[derive(Subcommand)]
enum DeviceAction {
    /// List every installation, this computer's id, and Telegram authorizations.
    List {
        /// Volume display name or UUID.
        volume: String,
        /// Read the volume password from this file (`-` reads stdin).
        #[arg(long, conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence from this file (`-` reads stdin).
        #[arg(long, conflicts_with = "password_file")]
        recovery_file: Option<String>,
    },

    /// Revoke one installation from a volume. Requires the owner signing capability.
    ///
    /// Immediately stops the target from reaching the volume through Telegram
    /// and publishes an owner-signed cutoff for its later writes. The password
    /// and root key stay unchanged: a removed device that obtains encrypted files
    /// another way can still decrypt them with the password it knows. Root-key
    /// rotation is planned for a later release.
    Revoke {
        /// Volume display name or UUID.
        volume: String,
        /// Full installation UUID shown by the device registry.
        installation_id: uuid::Uuid,
        /// Read the volume password from this file.
        #[arg(long, value_name = "PATH", conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence from this file.
        #[arg(long, value_name = "PATH", conflicts_with = "password_file")]
        recovery_file: Option<String>,
        /// End exactly this Telegram authorization when the device binding is known.
        #[arg(
            long,
            value_name = "HASH",
            conflicts_with = "log_out_all_other_telegram_sessions"
        )]
        telegram_session: Option<i64>,
        /// Owner-confirmed JSON bindings for sessions Telegram masks in their own view.
        #[arg(long, value_name = "PATH", requires = "telegram_session")]
        confirmed_session_map: Option<std::path::PathBuf>,
        /// Explicitly sign out every other Telegram authorization on this account.
        /// Requires the exact response YES on stdin; there is no bypass flag.
        #[arg(long)]
        log_out_all_other_telegram_sessions: bool,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Rotate legacy block-volume encryption epochs. TGFV rotation is planned for a later release.
    ///
    /// Refuses while the legacy volume's last session did not end with a clean
    /// unmount (mount and unmount it once first). Old messages are deleted only
    /// after a metadata snapshot naming the re-encrypted ones is published.
    /// If a rotation is interrupted, run it again to finish it.
    #[cfg_attr(
        feature = "key-rotation",
        doc = "Experimental key-rotation builds also rotate TGFV roots and migrate history."
    )]
    Rotate {
        /// Volume display name or UUID.
        volume: String,
        /// Read the volume password / passphrase from this file instead of
        /// prompting (use `-` for stdin).
        #[arg(long, value_name = "PATH", conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence in this file (use `-` for stdin)
        /// instead of the passphrase: a key-protected volume's recovery-slot
        /// sentence, or the key-hierarchy root printed by `key export`.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
        /// Distinct replacement password for a TGFV root rotation (`-` reads stdin).
        #[cfg(feature = "key-rotation")]
        #[arg(long, value_name = "PATH")]
        new_password_file: Option<String>,
    },
    /// Export the volume's key-hierarchy root as a 22-word recovery sentence — a
    /// real recovery credential (verify with `key import --recovery-file`, or
    /// open the volume with a volume or key command's `--recovery-file`;
    /// `keyslot enroll`/`remove-slot` need a key slot instead). WARNING: the
    /// exported root opens the volume without a slot or factor. Device revocation
    /// removes Telegram access; it does not invalidate an exported root or change
    /// the password. TGFV root rotation is planned for a later release.
    Export {
        /// Volume display name or UUID.
        volume: String,
        /// Read the volume password / passphrase from this file instead of
        /// prompting (use `-` for stdin).
        #[arg(long, value_name = "PATH", conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Unlock with the recovery sentence in this file (use `-` for stdin)
        /// instead of the passphrase: a key-protected volume's recovery-slot
        /// sentence, or the key-hierarchy root printed by `key export`.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
    },
    /// Verify a recovery sentence against the local volumes and report which volume
    /// it opens (a root alone cannot rebuild a volume whose config is absent).
    Import {
        /// Read the mnemonic sentence from this file (use `-` for stdin). The
        /// sentence is intentionally never accepted in argv or shell history.
        #[arg(long, value_name = "PATH")]
        recovery_file: String,
    },
}

#[derive(Subcommand)]
enum KeyslotAction {
    /// REMOVED (was fake security): built a vault that volume open never consulted,
    /// so the password alone still opened the volume. Use `volume create
    /// --key-protection` + `keyslot enroll` for real, enforced protection.
    /// Hidden: kept only so old `mfa setup` scripts get this explanation.
    #[command(hide = true)]
    Setup {
        /// Volume display name or UUID.
        volume: String,
        /// Factor flag of the removed vault; `keyslot setup` refuses to run regardless.
        #[arg(long)]
        totp: bool,
        /// Factor flag of the removed vault; `keyslot setup` refuses to run regardless.
        #[arg(long)]
        hardware: bool,
        /// Factor flag of the removed vault — enroll a REAL TPM2 slot with `keyslot enroll --tpm2`.
        #[arg(long)]
        tpm2: bool,
        /// Factor flag of the removed vault; `keyslot setup` refuses to run regardless.
        #[arg(long)]
        sep: bool,
    },
    /// Show a volume's key slots — any one enrolled slot opens the volume (like
    /// LUKS) — with the slot ids `keyslot remove-slot` takes. A legacy vault is
    /// reported as NOT enforced.
    Status {
        /// Volume display name or UUID.
        volume: String,
    },
    /// Delete a LEGACY (non-enforcing) mfa vault. REFUSES on a key-protected volume —
    /// deleting its slot vault would destroy the volume permanently.
    Remove {
        /// Volume display name or UUID.
        volume: String,
        /// Skip confirmation prompt.
        #[arg(long)]
        force: bool,
    },
    /// REMOVED (was theatre): re-wrapped a vault that volume open never consulted, so
    /// it changed nothing about who could open the volume. Use `keyslot enroll` instead.
    /// Hidden: kept only so old `mfa rotate` scripts get this explanation.
    #[command(hide = true)]
    Rotate {
        /// Volume display name or UUID.
        volume: String,
    },
    /// Enroll a hardware/device factor as a new key slot of a key-protected
    /// (`--key-protection`) volume. Key slots — any one enrolled slot opens the
    /// volume (like LUKS): the new factor is an ADDITIONAL way in, not a
    /// requirement; your passphrase still opens the volume until you remove its
    /// slot with `keyslot remove-slot`, and the recovery sentence keeps opening it
    /// either way. Unlock the existing vault with your
    /// passphrase (or `--recovery-file`). Publishes the changed slot vault to Telegram
    /// with the volume owner's signature. Choose exactly ONE factor per invocation;
    /// each enrolls its own independent slot. A failed publication remains pending
    /// and is retried by the next mount.
    Enroll {
        /// Volume display name or UUID.
        volume: String,
        /// Enroll a TPM2 sealing slot (requires tpm2-tools + a reachable TPM).
        #[arg(long)]
        tpm2: bool,
        /// Bind the TPM2 seal to a PCR selection (e.g. "sha256:0,1,7");
        /// changed selected PCR values refuse unseal of this slot. Other slots
        /// remain independent. Omit for a TPM-only bind.
        #[arg(long, value_name = "PCRS")]
        pcrs: Option<String>,
        /// Enroll a Tang (network-bound decryption) slot against this server URL.
        /// Only this Tang slot requires the server; other slots remain independent.
        #[arg(long, value_name = "URL")]
        tang: Option<String>,
        /// Pin the Tang server's advertised-key thumbprint (trust-on-first-use if omitted).
        #[arg(long, value_name = "THUMBPRINT")]
        tang_thumbprint: Option<String>,
        /// Enroll a PKCS#11 / HSM slot using this provider module
        /// (e.g. /usr/lib/softhsm/libsofthsm2.so).
        #[arg(long, value_name = "PATH")]
        pkcs11_module: Option<String>,
        /// PKCS#11 token label to select among multiple tokens.
        #[arg(long, value_name = "LABEL")]
        pkcs11_token_label: Option<String>,
        /// PKCS#11 key id in hex (default: 01).
        #[arg(long, value_name = "HEX")]
        pkcs11_key_id: Option<String>,
        /// Enroll a FIDO2 hmac-secret slot on a hardware authenticator, with the
        /// verification mode from --fido2-mode (asked on the terminal if absent).
        /// Needs `age-plugin-fido2-hmac` v0.5.0 or later installed.
        #[arg(long)]
        fido2: bool,
        /// What the security key must check at every unlock of this slot. The
        /// mode is recorded in the slot; unlock and mount use it.
        #[arg(long, value_enum, value_name = "MODE", requires = "fido2")]
        fido2_mode: Option<commands::mfa::Fido2ModeChoice>,
        /// Wrap with the FIDO2 plugin's ML-KEM-768/X25519 hybrid stanza.
        #[arg(long, requires = "fido2")]
        fido2_post_quantum: bool,
        /// Unlock the existing vault with the passphrase read from this file
        /// (use `-` for stdin) instead of prompting.
        #[arg(long, value_name = "PATH", conflicts_with = "recovery_file")]
        password_file: Option<String>,
        /// Unlock the existing vault with the recovery sentence from this file
        /// (use `-` for stdin) instead of the passphrase.
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
    },
    /// Remove one key slot from a key-protected volume. Key slots are
    /// any-one-of (like LUKS): every enrolled slot opens the volume on its own.
    /// Authorise with a DIFFERENT slot that will remain. Refuses to remove the
    /// last slot, and the last passphrase or recovery-sentence slot: removing the
    /// passphrase slot leaves the recovery sentence, which still opens the volume
    /// without any device. See `keyslot status` for slot ids.
    /// Publishes the changed slot vault to Telegram with the volume owner's signature.
    /// A failed publication remains pending and is retried by the next mount.
    RemoveSlot {
        /// Volume display name or UUID.
        volume: String,
        /// Id of the slot to remove (from `teagarden keyslot status`).
        slot: u32,
        /// Authorise with the passphrase read from this file (`-` = stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Authorise with the recovery sentence read from this file (`-` = stdin).
        #[arg(long, value_name = "PATH")]
        recovery_file: Option<String>,
        /// Authorise with the TPM2 slot.
        #[arg(long)]
        tpm2: bool,
        /// Authorise with a Tang slot bound to this server URL.
        #[arg(long, value_name = "URL")]
        tang: Option<String>,
        /// Expected Tang advertised-key thumbprint.
        #[arg(long, value_name = "THUMBPRINT")]
        tang_thumbprint: Option<String>,
        /// Authorise with a PKCS#11 slot using this provider module.
        #[arg(long, value_name = "PATH")]
        pkcs11_module: Option<String>,
        /// PKCS#11 token label.
        #[arg(long, value_name = "LABEL")]
        pkcs11_token_label: Option<String>,
        /// PKCS#11 key id in hex (default: 01).
        #[arg(long, value_name = "HEX")]
        pkcs11_key_id: Option<String>,
        /// Authorise with a FIDO2 hardware authenticator slot.
        #[arg(long)]
        fido2: bool,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Verify a key-protected volume opens via a device factor (offline check —
    /// does NOT mount). Proves an enrolled factor works end-to-end.
    Unlock {
        /// Volume display name or UUID.
        volume: String,
        /// Open via the TPM2 slot.
        #[arg(long)]
        tpm2: bool,
        /// Open via a Tang slot bound to this server URL.
        #[arg(long, value_name = "URL")]
        tang: Option<String>,
        /// Expected Tang advertised-key thumbprint.
        #[arg(long, value_name = "THUMBPRINT")]
        tang_thumbprint: Option<String>,
        /// Open via a PKCS#11 slot using this provider module.
        #[arg(long, value_name = "PATH")]
        pkcs11_module: Option<String>,
        /// PKCS#11 token label.
        #[arg(long, value_name = "LABEL")]
        pkcs11_token_label: Option<String>,
        /// PKCS#11 key id in hex (default: 01).
        #[arg(long, value_name = "HEX")]
        pkcs11_key_id: Option<String>,
        /// Open via a FIDO2 hardware authenticator slot.
        #[arg(long)]
        fido2: bool,
    },
}

/// TeaGarden block-device verbs.
#[cfg(feature = "dev")]
#[derive(Subcommand)]
enum DevAction {
    /// Format a new encrypted block device (the `luksFormat` step): allocate its
    /// Telegram topic, write the superblock, and register it locally.
    Create {
        /// Device name.
        #[arg(long)]
        name: String,
        /// Logical capacity in GiB.
        #[arg(long)]
        size_gib: u64,
        /// Segment size in MiB — one segment is one Telegram document (default 45,
        /// matching the cloud Bot API document ceiling).
        #[arg(long, default_value = "45")]
        segment_mib: u64,
        /// Directory for local device state (default: under the registry).
        #[arg(long, value_name = "PATH")]
        dir: Option<String>,
        /// Read the device credential from this file (`-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Name for the shared Telegram storage group (see `volume create
        /// --group-name`; same group, shared with volumes).
        #[arg(long, value_name = "NAME")]
        group_name: Option<String>,
    },
    /// List registered devices.
    List,
    /// Show real engine state for a device (capacity, epoch, segments, head).
    Status {
        /// Device name.
        name: String,
        /// Read the device credential from this file (`-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
    },
    /// Expose a device over a network block protocol.
    Serve {
        #[command(subcommand)]
        action: DevServeAction,
    },
    /// Reclaim segments superseded by newer writes.
    ///
    /// NOTE: after GC only the NEWEST head is a viable recovery point.
    Gc {
        /// Device name.
        name: String,
        /// Read the device credential from this file (`-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
    },
    /// Grow a device's logical capacity (shrinking is refused).
    Resize {
        /// Device name.
        name: String,
        /// New capacity in GiB.
        #[arg(long)]
        size_gib: u64,
        /// Read the device credential from this file (`-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
    },
    /// Rebuild a block device's local state from Telegram (disaster recovery).
    /// Requires this device's local registry record with its salt, geometry, topic
    /// and checkpoint ID, as well as the credential.
    Recover {
        /// Device name.
        name: String,
        /// Head message id to recover from (defaults to the registry's record).
        #[arg(long)]
        head_msg_id: Option<i64>,
        /// Read the device credential from this file (`-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
    },
    /// Permanently delete a device: its Telegram topic (every segment, head and
    /// checkpoint in it), then its local state and registry entry.
    ///
    /// Refuses while the device is open (e.g. served by `dev serve nbd`) or the
    /// credential is wrong, and deletes nothing in that case. If the topic cannot
    /// be deleted the local state is kept so the command can be rerun. Without
    /// --force it asks for confirmation, and refuses when there is no terminal.
    Delete {
        /// Device name.
        name: String,
        /// Read the device credential from this file (`-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Do not ask for confirmation.
        #[arg(long)]
        force: bool,
        /// Remove only the local state and leave the Telegram topic (and
        /// everything in it) in place, abandoned.
        #[arg(long)]
        local_only: bool,
    },
}

/// How to expose a TeaGarden block device.
#[cfg(feature = "dev")]
#[derive(Subcommand)]
enum DevServeAction {
    /// Serve over NBD. Attach with `nbd-client -b 4096 <host> <port> /dev/nbd0`.
    ///
    /// Stop with Ctrl+C, SIGTERM, or `nbd-client -d /dev/nbd0`: the open segment
    /// is uploaded and a final checkpoint published and recorded before exit;
    /// the exit status is non-zero if any of that fails. While serving, a
    /// checkpoint is published after every 8 uploaded segments and at least
    /// every 60 s while uploaded segments are not yet covered by one.
    ///
    /// SECURITY: NBD has no authentication — while serving, ANY local user who
    /// can reach the bind address has full read/write access to the DECRYPTED
    /// device. On shared machines, do not serve, or isolate the socket in a
    /// network namespace. See docs/BLOCK_DEVICE.md ("Security of the NBD socket").
    Nbd {
        /// Device name.
        name: String,
        /// Address to bind (host:port).
        #[arg(long, default_value = "127.0.0.1:10809")]
        bind: String,
        /// Read the device credential from this file (`-` for stdin).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum FstabAction {
    /// List all entries in teagarden.fstab.
    List,
    /// Add a volume mount entry to teagarden.fstab.
    Add {
        /// Volume display name or UUID.
        #[arg(long)]
        volume: String,
        /// Mount point path (~ is expanded).
        #[arg(long)]
        mountpoint: String,
        /// Mount automatically (default: true).
        #[arg(long, default_value = "true")]
        auto: bool,
        /// Let other users (including root) into the mount (as a non-root user,
        /// needs `user_allow_other` in /etc/fuse.conf).
        #[arg(long)]
        allow_other: bool,
        /// Path to a file containing the volume password (enables non-interactive mounts).
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
    },
    /// Remove a volume entry from teagarden.fstab.
    Remove {
        /// Volume display name or UUID.
        #[arg(long)]
        volume: String,
    },
    /// Mount all auto=true entries that have a password_file configured.
    MountAll,
    /// Unmount all teagarden.fstab volumes that are currently mounted.
    UnmountAll,
}

/// Mount a volume, resolving the mountpoint from `teagarden.fstab` when omitted. Shared by
/// the `volume mount` subcommand and the mount-esque shorthand `teagarden <vol> [mp]`.
async fn do_mount(
    volume: String,
    mountpoint: Option<String>,
    allow_other: bool,
    password_file: Option<&str>,
    recovery_file: Option<&str>,
    daemonize: bool,
    factor: commands::mfa::FactorSelect,
) -> anyhow::Result<()> {
    let mp = match mountpoint {
        Some(m) => m,
        None => {
            let tab = teagarden_fstab::TeagardenFstab::load()?;
            match tab.find(&volume) {
                Some(entry) => entry.expanded_mountpoint().to_string_lossy().to_string(),
                None => anyhow::bail!(
                    "No mountpoint given and no entry for '{}' in teagarden.fstab.\n\
                     Provide a mountpoint: teagarden \"{}\" ~/vault\n\
                     Or add one: teagarden fstab add --volume \"{}\" --mountpoint ~/vault",
                    volume,
                    volume,
                    volume
                ),
            }
        }
    };
    if daemonize {
        if recovery_file.is_some() {
            // A backgrounded/boot mount can't hold a recovery sentence securely; a
            // key-protected volume's passphrase slot works with --password-file.
            anyhow::bail!(
                "--daemonize with --recovery-file is not supported; unlock a protected \
                 volume's passphrase slot via --password-file instead"
            );
        }
        if factor.pkcs11_module.is_some() || factor.fido2 {
            // Both need interactive input (a PIN prompt, a physical touch) that a
            // backgrounded/boot mount cannot provide.
            anyhow::bail!(
                "--daemonize does not support --pkcs11-module or --fido2 (both need \
                 interactive input); use --tpm2, --tang, or --password-file instead"
            );
        }
        return spawn_mount_daemon(&volume, &mp, allow_other, password_file, &factor);
    }
    commands::volume::mount(
        &volume,
        &mp,
        allow_other,
        password_file,
        recovery_file,
        &factor,
    )
    .await
}

/// `--daemonize`: re-exec ourselves as a detached foreground mount, then wait
/// (bounded) for the mount to appear and return — so `mount.teagarden` / `mount -a`
/// / boot get a real exit code without the FUSE process blocking them. We re-exec
/// (not fork) because the tokio runtime is already multi-threaded and forking it is
/// unsafe; a fresh child is clean. Requires `--password-file` because a backgrounded
/// mount cannot prompt.
fn spawn_mount_daemon(
    volume: &str,
    mp: &str,
    allow_other: bool,
    password_file: Option<&str>,
    factor: &commands::mfa::FactorSelect,
) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    if factor.chosen() == 0 && password_file.is_none() {
        anyhow::bail!(
            "--daemonize requires --password-file, --tpm2, or --tang: a backgrounded / \
             fstab / boot mount cannot prompt for a password"
        );
    }
    // Resolve the secret before spawning and pass it through an anonymous pipe.
    // The long-lived mount process therefore never exposes either the password or
    // its source path in argv, including for teagarden.fstab/boot mounts.
    let password = password_file
        .map(|source| commands::utils::read_password_input(Some(source)))
        .transpose()?;
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.args(["volume", "mount", volume, mp]);
    if password.is_some() {
        cmd.args(["--password-file", "-"]);
    }
    if allow_other {
        cmd.arg("--allow-other");
    }
    if factor.tpm2 {
        cmd.arg("--tpm2");
    }
    if let Some(url) = &factor.tang {
        cmd.args(["--tang", url]);
        if let Some(tp) = &factor.tang_thumbprint {
            cmd.args(["--tang-thumbprint", tp]);
        }
    }
    cmd.stdin(if password.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    // Detach into its own session so it outlives this process + the controlling
    // terminal (and isn't reaped by `mount`'s short-lived context).
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    if let Some(password) = password {
        let mut stdin = child
            .stdin
            .take()
            .context("mount daemon password pipe was not created")?;
        stdin
            .write_all(password.as_bytes())
            .context("write mount daemon password")?;
        // Closing the pipe is required because `--password-file -` reads to EOF.
        drop(stdin);
    }
    for _ in 0..120 {
        if is_mountpoint(mp) {
            println!("Mounted '{volume}' at {mp} (daemon pid {}).", child.id());
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!(
                "mount daemon exited ({status}) before the mount came up — \
                 check the volume name and the --password-file"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    anyhow::bail!("mount did not come up within 30s");
}

/// Whether `path` is a mount point (its device id differs from its parent's).
fn is_mountpoint(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let p = std::path::Path::new(path);
    match (
        std::fs::metadata(p),
        p.parent().and_then(|q| std::fs::metadata(q).ok()),
    ) {
        (Ok(m), Some(pm)) => m.dev() != pm.dev(),
        _ => false,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if !is_offline_decrypt_invocation(&args) {
        load_config_env();
    }
    let cli = Cli::parse();

    // The mount-shorthand arguments and a subcommand must not mix. Enforced
    // manually (not via `args_conflicts_with_subcommands` — see the Cli struct
    // note) so that a leading global flag like --verbose cannot derail subcommand
    // dispatch. E.g. `teagarden myvol status` is ambiguous and rejected here; a
    // volume literally named like a subcommand mounts via `volume mount <name>`.
    if cli.command.is_some()
        && (cli.volume.is_some()
            || cli.mountpoint.is_some()
            || cli.allow_other
            || cli.password_file.is_some()
            || cli.daemonize)
    {
        use clap::CommandFactory;
        Cli::command()
            .error(
                clap::error::ErrorKind::ArgumentConflict,
                "the mount-shorthand arguments (<VOLUME>, <MOUNTPOINT>, --allow-other, \
                 --password-file, --daemonize) cannot be combined with a subcommand",
            )
            .exit();
    }

    // Log level priority: --verbose > RUST_LOG > default (warn)
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .init();

    // No subcommand → mount-esque shorthand (`teagarden <volume> [mountpoint]`),
    // or print help if nothing was given.
    let command = match cli.command {
        Some(c) => c,
        None => {
            return match cli.volume {
                Some(volume) => {
                    do_mount(
                        volume,
                        cli.mountpoint,
                        cli.allow_other,
                        cli.password_file.as_deref(),
                        None, // shorthand mount has no --recovery-file; use `volume mount`
                        cli.daemonize,
                        // shorthand mount has no device-factor flags; use `volume mount`
                        commands::mfa::FactorSelect::default(),
                    )
                    .await
                }
                None => {
                    use clap::CommandFactory;
                    Cli::command().print_help()?;
                    println!();
                    Ok(())
                }
            };
        }
    };

    match command {
        Commands::Auth { action } => match action {
            AuthAction::Login {
                api_id,
                api_hash,
                qr,
                cloud_password_file,
            } => {
                if qr {
                    commands::auth::login_qr(api_id, api_hash, cloud_password_file).await?;
                } else {
                    if cloud_password_file.is_some() {
                        anyhow::bail!("--cloud-password-file requires --qr");
                    }
                    commands::auth::login(api_id, api_hash).await?;
                }
            }
            AuthAction::Approve { token, yes } => {
                commands::auth::approve(&token, yes).await?;
            }
            AuthAction::Logout => {
                commands::auth::logout().await?;
            }
            AuthAction::Status => {
                commands::auth::status().await?;
            }
            AuthAction::Export { dir } => {
                commands::auth::export(&dir).await?;
            }
            AuthAction::Import { dir, force } => {
                commands::auth::import(&dir, force).await?;
            }
        },

        Commands::Device { action } => match action {
            DeviceAction::List {
                volume,
                password_file,
                recovery_file,
            } => {
                commands::volume::device_list(
                    &volume,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                )
                .await?;
            }

            DeviceAction::Revoke {
                volume,
                installation_id,
                password_file,
                recovery_file,
                telegram_session,
                confirmed_session_map,
                log_out_all_other_telegram_sessions,
            } => {
                commands::volume::revoke_device(
                    &volume,
                    installation_id,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                    telegram_session,
                    log_out_all_other_telegram_sessions,
                    confirmed_session_map.as_deref(),
                )
                .await?;
            }
        },

        Commands::Volume { action } => match action {
            VolumeAction::Create {
                name,
                password_file,
                key_protection,
                group_name,
            } => {
                commands::volume::create(
                    name,
                    password_file.as_deref(),
                    key_protection,
                    group_name,
                )
                .await?;
            }
            VolumeAction::Attach {
                group_topic,
                password_file,
                recovery_file,
                owner_public_key,
            } => {
                commands::volume::attach(
                    &group_topic,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                    owner_public_key.as_deref(),
                )
                .await?;
            }
            VolumeAction::Mount {
                volume,
                mountpoint,
                allow_other,
                password_file,
                recovery_file,
                daemonize,
                tpm2,
                tang,
                tang_thumbprint,
                pkcs11_module,
                pkcs11_token_label,
                pkcs11_key_id,
                fido2,
            } => {
                let factor = commands::mfa::FactorSelect {
                    tpm2,
                    pcrs: None,
                    tang,
                    tang_thumbprint,
                    pkcs11_module,
                    pkcs11_token_label,
                    pkcs11_key_id,
                    fido2,
                    fido2_mode: None,
                    fido2_post_quantum: false,
                };
                do_mount(
                    volume,
                    mountpoint,
                    allow_other,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                    daemonize,
                    factor,
                )
                .await?;
            }
            VolumeAction::Unmount { target } => {
                commands::volume::unmount(&target).await?;
            }
            VolumeAction::Restore {
                volume,
                snapshot_id,
                password_file,
                recovery_file,
                force,
                discard_journal,
            } => {
                commands::volume::restore(
                    &volume,
                    snapshot_id,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                    force,
                    discard_journal,
                )
                .await?;
            }
            VolumeAction::Republish {
                volume,
                from_local_db: _,
                password_file,
                recovery_file,
                force,
                replace_newer_metadata,
            } => {
                commands::volume::republish(
                    &volume,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                    force,
                    replace_newer_metadata,
                )
                .await?;
            }
            VolumeAction::Revert {
                volume,
                path,
                version,
                password_file,
                recovery_file,
            } => {
                commands::history::ensure_legacy_revert_only(&volume)?;
                commands::volume::revert(
                    &volume,
                    &path,
                    version,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                )
                .await?;
            }
            VolumeAction::ExportObjects {
                volume,
                out,
                password_file,
                recovery_file,
            } => {
                commands::volume::export_objects(
                    &volume,
                    &out,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                )
                .await?;
            }
            VolumeAction::List => {
                commands::volume::list().await?;
            }
            VolumeAction::Delete {
                volume,
                force,
                password_file,
                recovery_file,
                local_only,
            } => {
                commands::volume::delete(
                    &volume,
                    force,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                    local_only,
                )
                .await?;
            }
            VolumeAction::Info { volume } => {
                commands::volume::info(&volume).await?;
            }
            VolumeAction::History {
                volume,
                path,
                password_file,
                recovery_file,
            } => {
                commands::history::run(
                    &volume,
                    path.as_deref(),
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                )
                .await?;
            }
            VolumeAction::RestoreVersion {
                volume,
                path,
                version_uuid,
                password_file,
                recovery_file,
            } => {
                commands::history::restore_version(
                    &volume,
                    &path,
                    &version_uuid,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                )
                .await?;
            }
            VolumeAction::Diff {
                volume,
                version_a,
                version_b,
                password_file,
                recovery_file,
            } => {
                commands::history::diff(
                    &volume,
                    &version_a,
                    &version_b,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                )
                .await?;
            }
            VolumeAction::AddBot { volume, token_file } => {
                commands::volume::add_bot(&volume, &token_file).await?;
            }
            VolumeAction::RemoveBot { volume, bot_id } => {
                commands::volume::remove_bot(&volume, &bot_id).await?;
            }
        },

        Commands::Configure => {
            commands::configure::run().await?;
        }

        Commands::Status => {
            commands::status::show().await?;
        }

        Commands::Fstab { action } => match action {
            FstabAction::List => {
                commands::fstab::list().await?;
            }
            FstabAction::Add {
                volume,
                mountpoint,
                auto,
                allow_other,
                password_file,
            } => {
                commands::fstab::add(
                    &volume,
                    &mountpoint,
                    auto,
                    allow_other,
                    password_file.as_deref(),
                )
                .await?;
            }
            FstabAction::Remove { volume } => {
                commands::fstab::remove(&volume).await?;
            }
            FstabAction::MountAll => {
                commands::fstab::mount_all().await?;
            }
            FstabAction::UnmountAll => {
                commands::fstab::unmount_all().await?;
            }
        },

        Commands::Keyslot { action } => match action {
            KeyslotAction::Setup {
                volume,
                totp,
                hardware,
                tpm2,
                sep,
            } => {
                commands::mfa::setup(&volume, totp, hardware, tpm2, sep).await?;
            }
            KeyslotAction::Status { volume } => {
                commands::mfa::status(&volume).await?;
            }
            KeyslotAction::Remove { volume, force } => {
                commands::mfa::remove(&volume, force).await?;
            }
            KeyslotAction::Rotate { volume } => {
                commands::mfa::rotate(&volume).await?;
            }
            KeyslotAction::Enroll {
                volume,
                tpm2,
                pcrs,
                tang,
                tang_thumbprint,
                pkcs11_module,
                pkcs11_token_label,
                pkcs11_key_id,
                fido2,
                fido2_mode,
                fido2_post_quantum,
                password_file,
                recovery_file,
            } => {
                let sel = commands::mfa::FactorSelect {
                    tpm2,
                    pcrs,
                    tang,
                    tang_thumbprint,
                    pkcs11_module,
                    pkcs11_token_label,
                    pkcs11_key_id,
                    fido2,
                    fido2_mode,
                    fido2_post_quantum,
                };
                commands::mfa::enroll(
                    &volume,
                    sel,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                )
                .await?;
            }
            KeyslotAction::Unlock {
                volume,
                tpm2,
                tang,
                tang_thumbprint,
                pkcs11_module,
                pkcs11_token_label,
                pkcs11_key_id,
                fido2,
            } => {
                let sel = commands::mfa::FactorSelect {
                    tpm2,
                    pcrs: None,
                    tang,
                    tang_thumbprint,
                    pkcs11_module,
                    pkcs11_token_label,
                    pkcs11_key_id,
                    fido2,
                    fido2_mode: None,
                    fido2_post_quantum: false,
                };
                commands::mfa::unlock(&volume, sel).await?;
            }
            KeyslotAction::RemoveSlot {
                volume,
                slot,
                password_file,
                recovery_file,
                tpm2,
                tang,
                tang_thumbprint,
                pkcs11_module,
                pkcs11_token_label,
                pkcs11_key_id,
                fido2,
                yes,
            } => {
                let sel = commands::mfa::FactorSelect {
                    tpm2,
                    pcrs: None,
                    tang,
                    tang_thumbprint,
                    pkcs11_module,
                    pkcs11_token_label,
                    pkcs11_key_id,
                    fido2,
                    fido2_mode: None,
                    fido2_post_quantum: false,
                };
                commands::mfa::remove_slot(
                    &volume,
                    slot,
                    sel,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                    yes,
                )
                .await?;
            }
        },

        #[cfg(feature = "dev")]
        Commands::Dev { action } => match action {
            DevAction::Create {
                name,
                size_gib,
                segment_mib,
                dir,
                password_file,
                group_name,
            } => {
                commands::dev::create(
                    &name,
                    size_gib,
                    segment_mib,
                    dir.as_deref(),
                    password_file.as_deref(),
                    group_name.as_deref(),
                )
                .await?;
            }
            DevAction::List => {
                commands::dev::list().await?;
            }
            DevAction::Status {
                name,
                password_file,
            } => {
                commands::dev::status(&name, password_file.as_deref()).await?;
            }
            DevAction::Serve { action } => match action {
                DevServeAction::Nbd {
                    name,
                    bind,
                    password_file,
                } => {
                    commands::dev::serve_nbd(&name, &bind, password_file.as_deref()).await?;
                }
            },
            DevAction::Gc {
                name,
                password_file,
            } => {
                commands::dev::gc(&name, password_file.as_deref()).await?;
            }
            DevAction::Resize {
                name,
                size_gib,
                password_file,
            } => {
                commands::dev::resize(&name, size_gib, password_file.as_deref()).await?;
            }
            DevAction::Recover {
                name,
                head_msg_id,
                password_file,
            } => {
                commands::dev::recover(&name, head_msg_id, password_file.as_deref()).await?;
            }
            DevAction::Delete {
                name,
                password_file,
                force,
                local_only,
            } => {
                commands::dev::delete(&name, password_file.as_deref(), force, local_only).await?;
            }
        },

        Commands::Completions { shell, install } => {
            if install {
                install_completions(shell)?;
            } else {
                clap_complete::generate(
                    shell,
                    &mut Cli::command(),
                    "teagarden",
                    &mut std::io::stdout(),
                );
            }
        }

        Commands::Decrypt {
            input,
            out,
            password_file,
            recovery_file,
            file_id,
            owner_public_key,
            include_unverified,
        } => {
            commands::decrypt::run(
                &input,
                out.as_deref(),
                password_file.as_deref(),
                recovery_file.as_deref(),
                file_id,
                owner_public_key.as_deref(),
                include_unverified,
            )?;
        }

        Commands::Man => {
            print_man()?;
        }

        Commands::Key { action } => match action {
            KeyAction::Rotate {
                volume,
                password_file,
                recovery_file,
                #[cfg(feature = "key-rotation")]
                new_password_file,
            } => {
                #[cfg(not(feature = "key-rotation"))]
                let new_password_file: Option<String> = None;
                commands::key::rotate(
                    &volume,
                    password_file.as_deref(),
                    recovery_file.as_deref(),
                    new_password_file.as_deref(),
                )
                .await?;
            }
            KeyAction::Export {
                volume,
                password_file,
                recovery_file,
            } => {
                commands::key::export(&volume, password_file.as_deref(), recovery_file.as_deref())
                    .await?;
            }
            KeyAction::Import { recovery_file } => {
                let sentence = commands::utils::read_recovery_sentence(Some(&recovery_file))?
                    .ok_or_else(|| anyhow::anyhow!("recovery sentence input is required"))?;
                commands::key::import(sentence.as_str()).await?;
            }
        },
    }

    Ok(())
}

/// Install shell completions to the user-local directory for the given shell.
fn install_completions(shell: clap_complete::Shell) -> anyhow::Result<()> {
    use clap_complete::Shell;

    let (dir, filename): (std::path::PathBuf, String) = match shell {
        Shell::Bash => (
            dirs::data_local_dir()
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".local/share"))
                .join("bash-completion")
                .join("completions"),
            "teagarden".to_string(),
        ),
        Shell::Zsh => (
            dirs::data_local_dir()
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".local/share"))
                .join("zsh")
                .join("site-functions"),
            "_teagarden".to_string(),
        ),
        Shell::Fish => (
            dirs::config_dir()
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"))
                .join("fish")
                .join("completions"),
            "teagarden.fish".to_string(),
        ),
        Shell::Elvish => (
            dirs::data_local_dir()
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".local/share"))
                .join("elvish")
                .join("lib"),
            "teagarden.elv".to_string(),
        ),
        Shell::PowerShell => (
            dirs::data_local_dir()
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".local/share"))
                .join("powershell")
                .join("completions"),
            "teagarden.ps1".to_string(),
        ),
        _ => anyhow::bail!("Unsupported shell for --install: {shell:?}"),
    };

    std::fs::create_dir_all(&dir)?;
    let dest = dir.join(&filename);

    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "teagarden", &mut buf);

    std::fs::write(&dest, &buf)?;
    println!("Installed {} completions → {}", shell, dest.display());

    match shell {
        Shell::Bash => {
            println!();
            println!("Reload with:  source {}", dest.display());
            println!("Or restart your shell.");
        }
        Shell::Zsh => {
            println!();
            println!(
                "If {} is not on your fpath, add to ~/.zshrc:",
                dir.display()
            );
            println!("  fpath=({} $fpath)", dir.display());
            println!("  autoload -Uz compinit && compinit");
        }
        Shell::Fish => {
            println!("Completions will be available in new fish sessions.");
        }
        _ => {}
    }

    Ok(())
}

/// Render the man page in roff format to stdout.
fn print_man() -> anyhow::Result<()> {
    let cmd = Cli::command().version(env!("CARGO_PKG_VERSION"));
    let mut buf = Vec::new();

    clap_mangen::Man::new(cmd)
        .title("TeaGarden")
        .section("1")
        .date("2026")
        .source(format!("teagarden {}", env!("CARGO_PKG_VERSION")))
        .manual("TeaGarden Manual")
        .render(&mut buf)?;

    // Append hand-written sections after the auto-generated OPTIONS block.
    buf.extend_from_slice(ROFF_EXTRA.as_bytes());

    std::io::stdout().write_all(&buf)?;
    Ok(())
}

/// Extra roff sections appended after the clap-generated content.
const ROFF_EXTRA: &str = r#"
.SH TEAGARDEN.FSTAB
The file
.I ~/.config/teagarden/teagarden.fstab
is a TOML table describing volume mount points, analogous to
.BR fstab (5).
Each entry is a
.B [[mount]]
table with the following keys:
.TP
.B volume
Volume display name or UUID (required).
.TP
.B mountpoint
Path to the mount directory.
.B ~
is expanded to the home directory (required).
.TP
.B auto
Boolean.  When true the entry is a candidate for
.B fstab mount-all
and the systemd service installer (default: true).
.TP
.B allow_other
Boolean.  Passes the FUSE
.B allow_other
option.  Requires
.I user_allow_other
in
.I /etc/fuse.conf
(default: false).
.TP
.B password_file
Path to a file containing the volume password.  Required for non-interactive
mounts via
.B fstab mount-all
or the systemd service.

.PP
Example:
.PP
.RS
.nf
[[mount]]
volume = "ember pulses swiftly"
mountpoint = "~/vault"
auto = true
allow_other = false
password_file = "~/.config/teagarden/passwords/vault"
.fi
.RE

.SH ENVIRONMENT
.TP
.B TG_API_ID
Telegram application API ID obtained from
.IR https://my.telegram.org .
Can be set in
.I ~/.config/teagarden/.env
instead of the shell environment.
.TP
.B TG_API_HASH
Telegram application API hash from
.IR https://my.telegram.org .
Same loading rules as
.BR TG_API_ID .
.TP
.B TEAGARDEN_VOLUMES_DIR
Override the default volume storage directory.
Default:
.IR ~/.local/share/teagarden/volumes/ .

.SH FILES
.TP
.I ~/.config/teagarden/.env
Telegram API credentials (
.B TG_API_ID
and
.BR TG_API_HASH ).
Mode 600.  Created by
.B teagarden configure
or
.BR setup.sh .
.TP
.I ~/.config/teagarden/teagarden.session
Telegram session file.  Keep secret — anyone with this file can authenticate
as you.  Mode 600.
.TP
.I ~/.config/teagarden/teagarden.fstab
Volume mount table (TOML).  See the
.B TEAGARDEN.FSTAB
section above.
.TP
.I ~/.local/share/teagarden/volumes/<uuid>/
Per-volume directory named by UUID.
.TP
.I ~/.local/share/teagarden/volumes/<uuid>/volume.json
Volume configuration: display name, Telegram channel reference, KDF parameters,
and metadata snapshot message ID.  Does not contain keys.
.TP
.I ~/.local/share/teagarden/volumes/<uuid>/meta.db
Encrypted SQLite database storing the directory tree, file manifests, and block
pointers.  Encrypted with the volume meta key derived from the password.
.TP
.I /etc/fuse.conf
System FUSE configuration.  Uncomment
.B user_allow_other
to allow the
.B --allow-other
mount option.

.SH EXAMPLES
.PP
Initial setup:
.PP
.RS
.nf
./setup.sh
.fi
.RE
.PP
Create a volume and mount it interactively:
.PP
.RS
.nf
teagarden volume create
teagarden volume mount "ember pulses swiftly" ~/vault
.fi
.RE
.PP
Add to teagarden.fstab and set up a systemd user service for automatic mounting:
.PP
.RS
.nf
teagarden fstab add --volume "ember pulses swiftly" \\
    --mountpoint ~/vault \\
    --password-file ~/.config/teagarden/passwords/vault
./scripts/service-install.sh "ember pulses swiftly" ~/vault
.fi
.RE
.PP
Mount using the teagarden.fstab default mountpoint:
.PP
.RS
.nf
teagarden volume mount "ember pulses swiftly"
.fi
.RE
.PP
Install shell completions:
.PP
.RS
.nf
teagarden completions bash --install
teagarden completions zsh --install
teagarden completions fish --install
.fi
.RE
.PP
Install the man page:
.PP
.RS
.nf
teagarden man | gzip | sudo tee /usr/local/share/man/man1/teagarden.1.gz >/dev/null
sudo mandb
.fi
.RE

.SH SECURITY
All file data is split into fixed-size blocks, each encrypted individually
with ChaCha20-Poly1305 using a block key derived from the volume root key via
BLAKE3-HKDF.  Block filenames uploaded to Telegram are random hex strings with
common file extensions; the channel is private and contains no metadata that
reveals the filesystem structure.

The volume root key is never stored to disk.  It is derived on every mount from
the user password using Argon2id with memory-hard parameters.  The password
cannot be recovered from the stored volume configuration.

Telegram channel access is controlled by the Telegram account session.
The session file (
.IR ~/.config/teagarden/teagarden.session )
must be protected against unauthorized access.

.SH SEE ALSO
.BR fuse (8),
.BR fusermount3 (1),
.BR systemctl (1),
.BR secret-tool (1),
.BR fstab (5)

.SH BUGS
Report issues at:
.I https://github.com/arf-io/teagarden-fs/issues
"#;

#[cfg(test)]
mod offline_dispatch_tests {
    use super::{is_offline_decrypt_invocation, Cli};

    #[test]
    fn only_top_level_decrypt_skips_config_discovery() {
        assert!(is_offline_decrypt_invocation(&[
            "teagarden".into(),
            "decrypt".into(),
            "objects".into(),
        ]));
        assert!(is_offline_decrypt_invocation(&[
            "teagarden".into(),
            "--verbose".into(),
            "decrypt".into(),
            "objects".into(),
        ]));
        assert!(!is_offline_decrypt_invocation(&[
            "teagarden".into(),
            "volume".into(),
            "mount".into(),
        ]));
    }

    #[test]
    fn release_1_0_revoke_has_no_replacement_or_force_flags() {
        use clap::Parser;
        for flag in ["--new-password-file", "--force"] {
            let mut args = vec![
                "teagarden",
                "device",
                "revoke",
                "vault",
                "11111111-1111-1111-1111-111111111111",
                "--log-out-all-other-telegram-sessions",
                flag,
            ];
            if flag == "--new-password-file" {
                args.push("replacement");
            }
            assert!(
                Cli::try_parse_from(args).is_err(),
                "1.0 revoke must not expose {flag}"
            );
        }
        #[cfg(not(feature = "key-rotation"))]
        assert!(Cli::try_parse_from([
            "teagarden",
            "key",
            "rotate",
            "vault",
            "--new-password-file",
            "replacement"
        ])
        .is_err());
    }

    #[test]
    fn a2_n2_decrypt_exposes_explicit_include_unverified_flag() {
        use crate::Commands;
        use clap::Parser;
        let cli = Cli::try_parse_from(["teagarden", "decrypt", "objects", "--include-unverified"])
            .unwrap();
        assert!(matches!(
            cli.command.unwrap(),
            Commands::Decrypt {
                include_unverified: true,
                ..
            }
        ));
        let cli = Cli::try_parse_from(["teagarden", "decrypt", "objects"]).unwrap();
        assert!(matches!(
            cli.command.unwrap(),
            Commands::Decrypt {
                include_unverified: false,
                ..
            }
        ));
    }

    #[test]
    fn a2_n4_upgrade_owner_command_is_removed() {
        use clap::{CommandFactory, Parser};
        assert!(Cli::try_parse_from(["teagarden", "volume", "upgrade-owner", "vault"]).is_err());
        let command = Cli::command();
        assert!(command
            .find_subcommand("volume")
            .unwrap()
            .find_subcommand("upgrade-owner")
            .is_none());
    }

    #[test]
    fn obsolete_share_commands_are_not_in_the_cli() {
        use clap::CommandFactory;

        assert!(Cli::command().find_subcommand("share").is_none());
    }

    #[test]
    fn volume_history_accepts_an_optional_file_path() {
        use clap::Parser;

        assert!(
            Cli::try_parse_from(["teagarden", "volume", "history", "vault", "/docs/a.txt"]).is_ok()
        );
    }

    #[test]
    fn volume_restore_version_accepts_a_path_and_uuid_prefix() {
        use clap::Parser;

        assert!(Cli::try_parse_from([
            "teagarden",
            "volume",
            "restore-version",
            "vault",
            "/docs/a.txt",
            "abcd1234"
        ])
        .is_ok());
    }
}
