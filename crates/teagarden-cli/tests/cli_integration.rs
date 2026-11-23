use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// An empty config directory shared by tests that do not set their own. Without
/// it, a test that forgets to isolate the config would read (and could write)
/// the developer's real one — on macOS `dirs::config_dir()` ignores
/// `XDG_CONFIG_HOME`, so setting that alone never isolated anything there.
fn default_config_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| TempDir::new().unwrap()).path()
}

/// Get a command for the TeaGarden binary, with an isolated config directory.
#[allow(deprecated)]
fn teagarden() -> Command {
    let mut cmd = Command::cargo_bin("teagarden").unwrap();
    cmd.env("TEAGARDEN_CONFIG_DIR", default_config_dir());
    cmd
}

/// Get a command with a custom TEAGARDEN_VOLUMES_DIR pointing to a temp dir.
fn teagarden_with_dir(dir: &TempDir) -> Command {
    let mut cmd = teagarden();
    cmd.env("TEAGARDEN_VOLUMES_DIR", dir.path().to_str().unwrap());
    cmd
}

#[test]
fn help_flag() {
    teagarden()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("TeaGarden"));
}

/// Top-level command names listed in the `Commands:` section of `--help`.
fn top_level_commands() -> Vec<String> {
    let out = teagarden().arg("--help").output().unwrap();
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    help.lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .collect()
}

/// The 1.0 top-level command list, exactly and in order. Anything added to or
/// removed from the CLI surface must change this list deliberately.
#[test]
fn top_level_commands_are_exactly_the_1_0_set() {
    let mut expected = vec![
        "auth",
        "volume",
        "device",
        "configure",
        "status",
        "key",
        "fstab",
        "keyslot",
    ];
    // `dev` exists exactly when its feature is enabled.
    if cfg!(feature = "dev") {
        expected.push("dev");
    }
    expected.extend(["completions", "man", "decrypt", "help"]);
    assert_eq!(top_level_commands(), expected);
}

/// `mfa` was renamed `keyslot`. `mfa` stays as a HIDDEN alias so existing
/// scripts keep working: it is not listed, but it dispatches to the same verbs.
#[test]
fn keyslot_is_listed_and_mfa_is_a_hidden_working_alias() {
    let commands = top_level_commands();
    assert!(commands.iter().any(|c| c == "keyslot"), "{commands:?}");
    assert!(
        !commands.iter().any(|c| c == "mfa"),
        "mfa must be hidden: {commands:?}"
    );
    let top = String::from_utf8(teagarden().arg("--help").output().unwrap().stdout).unwrap();
    assert!(!top.contains("mfa"), "top-level help mentions mfa:\n{top}");

    // The alias reaches the real verbs, with the same help as keyslot.
    let via_alias = teagarden()
        .args(["mfa", "status", "--help"])
        .output()
        .unwrap();
    let via_name = teagarden()
        .args(["keyslot", "status", "--help"])
        .output()
        .unwrap();
    assert!(via_alias.status.success() && via_name.status.success());
    assert_eq!(via_alias.stdout, via_name.stdout);

    // And it runs them: `mfa status` on a real key-protected volume.
    let dir = TempDir::new().unwrap();
    let pc = teagarden_mfa::unlock::create_protected_volume(
        Some("alias probe"),
        b"alias-passphrase-1",
        dir.path(),
        0,
        0,
        0,
        None,
    )
    .unwrap();
    let id = pc.created.config.volume_id.to_string();
    for group in ["mfa", "keyslot"] {
        teagarden_with_dir(&dir)
            .args([group, "status", &id])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "any one enrolled slot opens the volume",
            ))
            .stdout(predicate::str::contains("passphrase"))
            .stdout(predicate::str::contains("recovery"));
    }
}

/// The keyslot help must say plainly that slots are any-one-of, that a durable
/// slot always remains (no hardware-only access), and name the real removal verb.
#[test]
fn keyslot_help_states_any_one_slot_opens_the_volume() {
    let out = teagarden().args(["keyslot", "--help"]).output().unwrap();
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
    for required in [
        "Key slots: any ONE enrolled slot opens the volume (like LUKS key slots).",
        "A device slot (TPM2, Tang, PKCS#11/HSM, FIDO2) ADDS a way in; it never makes \
         the passphrase or the recovery sentence insufficient.",
        "At least one passphrase or recovery-sentence slot always remains:",
        "the recovery sentence still opens the volume without any device.",
        "`keyslot remove-slot`",
    ] {
        assert!(flat.contains(required), "missing {required:?} in:\n{help}");
    }
    let verbs: Vec<&str> = help
        .lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    for verb in ["enroll", "remove-slot", "status", "unlock"] {
        assert!(verbs.contains(&verb), "`keyslot {verb}` missing: {verbs:?}");
    }
    // The removed verbs are hidden but still explain themselves to old scripts.
    for (gone, why) in [
        ("setup", "fake security"),
        ("rotate", "re-wrapped the legacy vault"),
    ] {
        assert!(
            !verbs.contains(&gone),
            "`keyslot {gone}` should be hidden: {verbs:?}"
        );
        teagarden()
            .args(["mfa", gone, "some-volume"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("has been REMOVED"))
            .stderr(predicate::str::contains(why));
    }
}

/// `status` prints exactly the 1.0 sections, in order: a `Label:` followed by
/// two or more spaces of alignment. (Other lines — the title, the `↳` mount
/// lines, the closing hint — are not sections.)
#[test]
fn status_reports_exactly_the_1_0_sections() {
    let dir = TempDir::new().unwrap();
    let out = teagarden_with_dir(&dir).arg("status").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().next(), Some("TeaGarden Status"), "{text}");
    let sections: Vec<&str> = text
        .lines()
        .filter_map(|l| {
            let (label, rest) = l.split_once(':')?;
            let starts_section = !label.is_empty()
                && !label.starts_with(' ')
                && rest.starts_with("  ")
                && label.chars().all(|c| c.is_ascii_alphabetic() || c == ' ');
            starts_section.then_some(label)
        })
        .collect();
    assert_eq!(
        sections,
        ["Version", "Volumes", "Telegram", "Cache", "Data dir"],
        "{text}"
    );
}

#[test]
fn version_flag() {
    teagarden()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("teagarden"));
}

#[test]
fn volume_help() {
    teagarden()
        .args(["volume", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("delete"))
        .stdout(predicate::str::contains("restore"));
}

#[test]
fn volume_restore_help_lists_flags() {
    teagarden()
        .args(["volume", "restore", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--snapshot-id"))
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("anti-rollback"));
}

#[test]
fn volume_revert_help_is_limited_to_legacy_block_volumes() {
    Command::cargo_bin("teagarden")
        .unwrap()
        .args(["volume", "revert", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("legacy block volume only"))
        .stdout(predicate::str::contains("volume restore-version"));
}

/// `volume republish` exists, names its flags, and refuses to run without the
/// explicit `--from-local-db`.
#[test]
fn volume_republish_requires_from_local_db() {
    teagarden()
        .args(["volume", "republish", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--from-local-db"))
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("exclusive lock"));
    let dir = TempDir::new().unwrap();
    teagarden_with_dir(&dir)
        .args(["volume", "republish", "some-volume"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--from-local-db"));
    teagarden_with_dir(&dir)
        .args([
            "volume",
            "republish",
            "no-such-volume",
            "--from-local-db",
            "--password-file",
            "-",
        ])
        .write_stdin("irrelevant\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn volume_restore_unknown_volume_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    teagarden_with_dir(&dir)
        .args([
            "volume",
            "restore",
            "no-such-volume",
            "--password-file",
            "-",
        ])
        .write_stdin("irrelevant\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("volume not found"));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn volume_unmount_reports_detach_failure() {
    let dir = TempDir::new().unwrap();
    let mountpoint = dir.path().join("not-mounted");
    std::fs::create_dir(&mountpoint).unwrap();

    teagarden_with_dir(&dir)
        .args(["volume", "unmount", mountpoint.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to detach"));
}

#[test]
fn volume_list_empty() {
    let dir = TempDir::new().unwrap();
    // volume list reads from default_volumes_dir(), so we need to use a custom dir
    // The status command is a simpler test since it just counts volumes
    teagarden_with_dir(&dir)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Volumes:"));
}

#[test]
fn status_command() {
    teagarden()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("teagarden v"))
        .stdout(predicate::str::contains("Volumes:"));
}

#[test]
fn auth_status() {
    teagarden()
        .args(["auth", "status"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("authenticated")
                .or(predicate::str::contains("Not authenticated"))
                .or(predicate::str::contains("session file present")),
        );
}

/// The roster verbs granted and revoked nothing (a `revoke` that does not
/// revoke misleads), so they are gone. The real sharing verbs stay.
#[test]
fn key_help() {
    teagarden()
        .args(["key", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotate"))
        .stdout(predicate::str::contains("export"))
        .stdout(predicate::str::contains("import"));
}

#[test]
fn key_import_requires_a_file_and_rejects_recovery_text_in_argv() {
    teagarden()
        .args(["key", "import", "legacy-positional-recovery-text"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));

    teagarden()
        .args(["key", "import", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--recovery-file"))
        .stdout(predicate::str::contains("<SENTENCE>").not());
}

#[test]
fn unknown_subcommand() {
    // Since the mount-esque shorthand (`teagarden [options] <volume> [mountpoint]`),
    // a bare word that is NOT a subcommand is BY DESIGN a volume name — like
    // `mount device`. So an unknown word fails with the teagarden.fstab mount guidance,
    // not clap's "unrecognized subcommand". Hermetic: point XDG_CONFIG_HOME (and
    // HOME) at a temp dir so a real ~/.config/teagarden/teagarden.fstab can't interfere.
    let dir = TempDir::new().unwrap();
    teagarden()
        .env("XDG_CONFIG_HOME", dir.path())
        .env("TEAGARDEN_CONFIG_DIR", dir.path().join("teagarden"))
        .env("HOME", dir.path())
        .arg("nonexistent")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no entry for 'nonexistent' in teagarden.fstab",
        ));
}

/// `TEAGARDEN_CONFIG_DIR` wins over the platform config dir. This models the
/// macOS failure on Linux: there, `XDG_CONFIG_HOME` is the platform dir that
/// `dirs` would pick; the file must land in `TEAGARDEN_CONFIG_DIR` and nothing
/// may appear under XDG or HOME.
#[test]
fn config_dir_override_takes_precedence_over_xdg_and_home() {
    let chosen = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let cfg = chosen.path().join("cfg");
    std::fs::create_dir_all(&cfg).unwrap();
    let exported = chosen.path().join("exported");
    let source = cfg.join("teagarden.session");
    let db = rusqlite::Connection::open(&source).unwrap();
    db.execute_batch(
        "CREATE TABLE dc_home (dc_id INTEGER NOT NULL PRIMARY KEY);
         CREATE TABLE dc_option (dc_id INTEGER NOT NULL PRIMARY KEY, ipv4 TEXT NOT NULL, ipv6 TEXT NOT NULL, auth_key BLOB);
         CREATE TABLE peer_info (peer_id INTEGER NOT NULL PRIMARY KEY, hash INTEGER, subtype INTEGER);
         CREATE TABLE update_state (pts INTEGER NOT NULL, qts INTEGER NOT NULL, date INTEGER NOT NULL, seq INTEGER NOT NULL);
         CREATE TABLE channel_state (peer_id INTEGER NOT NULL PRIMARY KEY, pts INTEGER NOT NULL);
         INSERT INTO dc_home VALUES (2);
         INSERT INTO peer_info VALUES (1234567, 99, 1);
         PRAGMA user_version=1;",
    )
        .unwrap();
    drop(db);
    std::fs::write(
        cfg.join(".env"),
        "TG_API_ID=12345\nTG_API_HASH=0123456789abcdef0123456789abcdef\n",
    )
    .unwrap();
    std::fs::write(cfg.join("group.json"), "{}\n").unwrap();
    teagarden()
        .env("TEAGARDEN_CONFIG_DIR", &cfg)
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("HOME", home.path())
        .args(["auth", "export"])
        .arg(&exported)
        .assert()
        .success();
    assert!(
        exported.join("teagarden.session").is_file(),
        "auth export must read its session from TEAGARDEN_CONFIG_DIR"
    );
    for (what, dir) in [("XDG_CONFIG_HOME", xdg.path()), ("HOME", home.path())] {
        let entries: Vec<_> = std::fs::read_dir(dir).unwrap().collect();
        assert!(entries.is_empty(), "{what} was written to: {entries:?}");
    }
}

#[test]
fn subcommand_wins_over_volume_shorthand() {
    // A word naming a real subcommand must ALWAYS dispatch that subcommand, never
    // be swallowed as the VOLUME positional (subcommand_precedence_over_arg) —
    // with or without a preceding global flag.
    teagarden().arg("status").assert().success();
    teagarden()
        .args(["--verbose", "fstab", "list"])
        .assert()
        .success();
}

#[test]
fn fstab_mount_all_fails_when_a_configured_mount_cannot_start() {
    let config_home = TempDir::new().unwrap();
    let volumes_dir = TempDir::new().unwrap();
    let mount_root = TempDir::new().unwrap();
    let password_file = config_home.path().join("password");
    std::fs::write(&password_file, "not-a-real-volume-password\n").unwrap();
    let mountpoint = mount_root.path().join("mountpoint");

    teagarden_with_dir(&volumes_dir)
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("TEAGARDEN_CONFIG_DIR", config_home.path().join("teagarden"))
        .env("HOME", config_home.path())
        .args([
            "fstab",
            "add",
            "--volume",
            "volume-that-does-not-exist",
            "--mountpoint",
            mountpoint.to_str().unwrap(),
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    teagarden_with_dir(&volumes_dir)
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("TEAGARDEN_CONFIG_DIR", config_home.path().join("teagarden"))
        .env("HOME", config_home.path())
        .args(["fstab", "mount-all"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "configured teagarden.fstab mount(s) failed",
        ));
}

#[test]
fn verbose_flag_accepted() {
    teagarden().args(["--verbose", "status"]).assert().success();
}

#[test]
fn configure_help() {
    teagarden()
        .args(["configure", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("setup wizard"));
}

/// `configure` must update only the keys it owns. The `.env` also carries the
/// storage-bot tokens (`TELEGRAM_BOT_TOKEN_N`), comments and keys of other tools;
/// all of them survive byte for byte, including a CRLF line and a final line with
/// no newline. The write is atomic: mode 0600, no temp file left behind.
#[test]
fn configure_preserves_every_line_it_does_not_own() {
    use std::os::unix::fs::PermissionsExt as _;

    let cfg = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let env_path = cfg.path().join(".env");
    // Token-shaped test values, not real bot tokens.
    let tok1 = "111111111:AAtestsecret_one_0123456789abcdefghij";
    let tok2 = "222222222:AAtestsecret_two_0123456789abcdefghij";
    let seed = format!(
        "# my own notes\r\n\
         TELEGRAM_BOT_TOKEN_1={tok1}\n\
         SOME_OTHER_TOOL_KEY = keep me exactly   \n\
         TG_API_ID=1\n\
         # TG_API_HASH=commented-out-lines-are-not-ours\n\
         \n\
         TELEGRAM_BOT_TOKEN_2={tok2}\r\n\
         TEAGARDEN_SESSION_PATH=/old/session\r\n\
         LAST_KEY=no-final-newline"
    );
    std::fs::write(&env_path, &seed).unwrap();
    std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let volumes = data.path().join("volumes");
    let session = data.path().join("session");
    let hash = "0123456789abcdef0123456789abcdef";
    // overwrite? y / open browser? n / api id / api hash / volumes / session / rc? n
    let stdin = format!(
        "y\nn\n4242\n{hash}\n{}\n{}\nn\n",
        volumes.display(),
        session.display()
    );
    #[allow(deprecated)]
    Command::cargo_bin("teagarden")
        .unwrap()
        .env("TEAGARDEN_CONFIG_DIR", cfg.path())
        .env("HOME", home.path())
        .env("SHELL", "/bin/bash")
        .arg("configure")
        .write_stdin(stdin)
        .assert()
        .success();

    // Owned lines are replaced in place (keeping their own line ending); owned
    // keys that were absent are appended; every other byte is untouched.
    let expected = format!(
        "# my own notes\r\n\
         TELEGRAM_BOT_TOKEN_1={tok1}\n\
         SOME_OTHER_TOOL_KEY = keep me exactly   \n\
         TG_API_ID=4242\n\
         # TG_API_HASH=commented-out-lines-are-not-ours\n\
         \n\
         TELEGRAM_BOT_TOKEN_2={tok2}\r\n\
         TEAGARDEN_SESSION_PATH={}\r\n\
         LAST_KEY=no-final-newline\n\
         TG_API_HASH={hash}\n\
         TEAGARDEN_VOLUMES_DIR={}\n",
        session.display(),
        volumes.display()
    );
    let got = std::fs::read_to_string(&env_path).unwrap();
    assert_eq!(
        got, expected,
        "configure must keep every line it does not own"
    );

    let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the rewritten .env must be 0600");
    let leftovers: Vec<String> = std::fs::read_dir(cfg.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
}

/// The config directory and the volumes directory hold secrets; whatever the
/// umask, `configure` creates them 0700 (a missing one) or tightens them to 0700
/// (an existing one), and leaves their parent alone. Run under `umask 000`, where
/// a plain `create_dir_all` makes 0777 directories.
#[test]
fn configure_creates_its_directories_0700_under_a_permissive_umask() {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

    let root = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let hash = "0123456789abcdef0123456789abcdef";

    for existing in [false, true] {
        let tag = if existing { "existing" } else { "fresh" };
        let cfg = root.path().join(format!("cfg-{tag}"));
        let volumes = root.path().join(format!("vol-{tag}"));
        if existing {
            for d in [&cfg, &volumes] {
                std::fs::create_dir(d).unwrap();
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        // open browser? n / api id / api hash / volumes / session
        let stdin = format!(
            "n\n4242\n{hash}\n{}\n{}\n",
            volumes.display(),
            cfg.join("teagarden.session").display()
        );
        #[allow(deprecated)]
        let bin = assert_cmd::cargo::cargo_bin("teagarden");
        let out = std::process::Command::new("sh")
            .args([
                "-c",
                "umask 000; exec \"$0\" configure",
                bin.to_str().unwrap(),
            ])
            .env("TEAGARDEN_CONFIG_DIR", &cfg)
            .env("HOME", home.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                child.stdin.take().unwrap().write_all(stdin.as_bytes())?;
                child.wait_with_output()
            })
            .unwrap();
        assert!(
            out.status.success(),
            "{tag}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(mode(&cfg), 0o700, "{tag}: the config dir");
        assert_eq!(mode(&volumes), 0o700, "{tag}: the volumes dir");
        assert_eq!(mode(root.path()), 0o755, "{tag}: the parent is not ours");
    }
}

/// `configure` must never put the API hash (or anything else from the `.env`)
/// into a shell startup file, nor tell the user to `source` the `.env`: that
/// exports the hash and the bot tokens into every shell and every program it
/// starts. The CLI loads its `.env` itself. Every answer below is "yes", so an
/// offer to edit a startup file would be accepted if one were still made.
#[test]
fn configure_never_offers_to_put_secrets_in_a_shell_startup_file() {
    use std::os::unix::fs::PermissionsExt as _;

    for (shell, rc) in [
        ("/bin/bash", ".bashrc"),
        ("/usr/bin/zsh", ".zshrc"),
        ("/usr/bin/fish", ".config/fish/config.fish"),
    ] {
        let cfg = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let hash = "0123456789abcdef0123456789abcdef";
        // open browser? n / api id / api hash / volumes / session / then "y" to anything else
        let stdin = format!(
            "n\n4242\n{hash}\n{}\n{}\ny\ny\ny\n",
            data.path().join("volumes").display(),
            data.path().join("session").display()
        );
        #[allow(deprecated)]
        let out = Command::cargo_bin("teagarden")
            .unwrap()
            .env("TEAGARDEN_CONFIG_DIR", cfg.path())
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join(".config"))
            .env("SHELL", shell)
            .arg("configure")
            .write_stdin(stdin)
            .output()
            .unwrap();
        assert!(out.status.success(), "{shell}: configure failed");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !home.path().join(rc).exists(),
            "{shell}: configure created or edited ~/{rc}"
        );
        for leak in ["source ", "set -a", "set -gx", rc] {
            assert!(
                !stdout.contains(leak),
                "{shell}: configure still suggests loading the .env into the shell ({leak:?})"
            );
        }
        let env_path = cfg.path().join(".env");
        let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{shell}: the new .env must be 0600");
        let text = std::fs::read_to_string(&env_path).unwrap();
        assert!(
            text.lines().any(|l| l == format!("TG_API_HASH={hash}")),
            "{shell}: the hash must still be saved in the .env"
        );
    }
}

/// `volume add-bots` (automated @BotFather account creation) is gone; its
/// replacement `add-bot` takes a token the user created by hand, and only from a
/// file or stdin.
#[test]
fn add_bots_is_gone_and_add_bot_reads_the_token_only_from_a_file() {
    let out = teagarden().args(["volume", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    let verbs: Vec<&str> = help
        .lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert!(!verbs.contains(&"add-bots"), "{verbs:?}");
    assert!(
        verbs.contains(&"add-bot") && verbs.contains(&"remove-bot"),
        "{verbs:?}"
    );
    teagarden()
        .args(["volume", "add-bots", "v"])
        .assert()
        .failure();

    teagarden()
        .args(["volume", "add-bot", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--token-file"))
        .stdout(predicate::str::contains("--token ").not());
}

/// A token-shaped test value (not a real bot token).
const FAKE_BOT_TOKEN: &str = "123456789:AAfakeTokenForCliTests_0123456789abcdef";

fn assert_token_not_echoed(out: &std::process::Output) {
    for (name, stream) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        let text = String::from_utf8_lossy(stream);
        assert!(
            !text.contains("AAfakeTokenForCliTests"),
            "{name} echoed the bot token:\n{text}"
        );
    }
}

#[test]
fn add_bot_refuses_a_token_on_argv() {
    let dir = TempDir::new().unwrap();
    for args in [
        vec!["volume", "add-bot", "vol", "--token", FAKE_BOT_TOKEN],
        vec!["volume", "add-bot", "vol", FAKE_BOT_TOKEN],
        vec!["volume", "add-bot", "vol", "--token-file"],
    ] {
        let out = teagarden_with_dir(&dir).args(&args).output().unwrap();
        assert!(!out.status.success(), "{args:?} was accepted");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: expected a usage error"
        );
    }
}

#[test]
fn add_bot_fails_before_the_network_and_never_prints_the_token() {
    let dir = TempDir::new().unwrap();
    let cfg = TempDir::new().unwrap();
    let vol = make_volume(&dir, "correct horse battery staple"); // offline volume
    let good = cfg.path().join("token");
    std::fs::write(&good, format!("{FAKE_BOT_TOKEN}\n")).unwrap();
    let injected = cfg.path().join("injected");
    std::fs::write(
        &injected,
        format!("{FAKE_BOT_TOKEN}\nTG_API_HASH=attacker\n"),
    )
    .unwrap();

    let run = |vol: &str, file: &std::path::Path, stdin: Option<&str>| {
        let mut c = teagarden_with_dir(&dir);
        c.env("TEAGARDEN_CONFIG_DIR", cfg.path().join("teagarden"))
            .env_remove("TG_API_ID")
            .env_remove("TG_API_HASH")
            .args(["volume", "add-bot", vol, "--token-file"]);
        match stdin {
            Some(s) => {
                c.arg("-").write_stdin(s.to_string());
            }
            None => {
                c.arg(file);
            }
        }
        c.output().unwrap()
    };

    // A file that would inject a second .env line is refused by shape.
    let out = run(&vol, &injected, None);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("bot token"));
    assert_token_not_echoed(&out);

    // Unknown volume.
    let out = run("no-such-volume", &good, None);
    assert!(!out.status.success());
    assert_token_not_echoed(&out);

    // An offline volume has no storage group; via stdin too.
    for stdin in [None, Some(FAKE_BOT_TOKEN)] {
        let out = run(&vol, &good, stdin);
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("no Telegram storage group"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_token_not_echoed(&out);
    }
    assert!(
        !cfg.path().join("teagarden").join(".env").exists(),
        "a refused add-bot must not write the env file"
    );
}

#[test]
fn man_page_renders() {
    teagarden()
        .arg("man")
        .assert()
        .success()
        .stdout(predicate::str::contains("TeaGarden"))
        .stdout(predicate::str::contains("SYNOPSIS"));
}

#[test]
fn completions_bash_renders() {
    teagarden()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("teagarden"));
}

// ── `volume delete` safety regression tests ─────────────────────────────────
//
// `volume delete` shipped with three defects found by the 2026-07-27 release
// audit, all of which these tests pin:
//
//   1. it advertised "and all its Telegram blocks" but only deleted the LOCAL
//      directory, leaving every encrypted block in the cloud forever;
//   2. `--force` required NO credential, so it destroyed `slot_vault.json` (the
//      sole wrapping of a key-protected volume's master key) while the ciphertext
//      survived remotely — the exact hazard commit 4be1195 hardened `mfa remove`
//      against;
//   3. its "is it mounted?" guard read an in-process map that is always empty in
//      a fresh CLI invocation, so it would delete a live mount's directory.

/// Create a real volume offline (no Telegram needed) and return its id.
fn make_volume(dir: &TempDir, password: &str) -> String {
    let res = teagarden_core::volume::manager::create_volume(
        Some("audit probe"),
        password.as_bytes(),
        dir.path(),
        0,
        0,
        0,
        None,
    )
    .expect("create volume offline");
    res.config.volume_id.to_string()
}

/// Every command that unlocks a volume with its password takes
/// `--password-file <PATH|->`, so scripts can drive it, and rejects it together
/// with `--recovery-file`.
#[test]
fn password_file_is_accepted_by_every_password_unlocking_command() {
    let dir = TempDir::new().unwrap();
    let vol = make_volume(&dir, "correct horse battery staple");
    for cmd in [
        vec!["key", "rotate", &vol],
        vec!["key", "export", &vol],
        vec!["volume", "history", &vol],
        vec!["volume", "diff", &vol, "aa", "bb"],
        vec!["keyslot", "enroll", &vol, "--tpm2"],
    ] {
        let mut help = cmd[..2].to_vec();
        help.push("--help");
        teagarden()
            .args(&help)
            .assert()
            .success()
            .stdout(predicate::str::contains("--password-file <PATH>"));
        let out = teagarden_with_dir(&dir)
            .args(&cmd)
            .args([
                "--password-file",
                "/nonexistent",
                "--recovery-file",
                "/nonexistent",
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{cmd:?} must reject both at once"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("cannot be used with"),
            "{cmd:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// `key rotate --password-file` is really used to unlock: a wrong password
/// fails to open the volume; the right one, from a file or from stdin, opens
/// it and rotates. (An empty volume has no blocks to re-encrypt, so the epoch
/// advance completes offline; re-encrypting real blocks needs Telegram.)
#[test]
fn key_rotate_unlocks_with_password_file() {
    let dir = TempDir::new().unwrap();
    let vol = make_volume(&dir, "correct horse battery staple");
    let files = TempDir::new().unwrap();
    let wrong = files.path().join("wrong");
    std::fs::write(&wrong, "not the password\n").unwrap();
    let right = files.path().join("right");
    std::fs::write(&right, "correct horse battery staple\n").unwrap();
    let epoch = || -> u64 {
        let v: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join(&vol).join("volume.json")).unwrap(),
        )
        .unwrap();
        v["current_epoch"].as_u64().unwrap()
    };
    assert_eq!(epoch(), 0);

    let out = teagarden_with_dir(&dir)
        .args(["key", "rotate", &vol, "--password-file"])
        .arg(&wrong)
        .env_remove("TG_API_ID")
        .env_remove("TG_API_HASH")
        .output()
        .unwrap();
    assert!(!out.status.success(), "a wrong password must not rotate");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("wrong password"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(epoch(), 0);
    // That failure armed the 1 s failed-attempt lockout; let it lapse.
    std::thread::sleep(std::time::Duration::from_millis(2500));

    teagarden_with_dir(&dir)
        .args(["key", "rotate", &vol, "--password-file"])
        .arg(&right)
        .env_remove("TG_API_ID")
        .env_remove("TG_API_HASH")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Incrementing epoch counter 0 -> 1",
        ));
    assert_eq!(epoch(), 1);

    teagarden_with_dir(&dir)
        .args(["key", "rotate", &vol, "--password-file", "-"])
        .write_stdin("correct horse battery staple\n")
        .env_remove("TG_API_ID")
        .env_remove("TG_API_HASH")
        .assert()
        .success();
    assert_eq!(epoch(), 2);
}

#[test]
fn volume_delete_force_still_requires_a_credential() {
    let dir = TempDir::new().unwrap();
    let _id = make_volume(&dir, "correct horse battery staple");

    // --force may skip the y/N prompt, but it must NOT skip authentication.
    // Feed a WRONG password on stdin; deletion must fail and the volume survive.
    teagarden_with_dir(&dir)
        .args([
            "volume",
            "delete",
            "audit probe",
            "--force",
            "--password-file",
            "-",
        ])
        .write_stdin("definitely-the-wrong-password\n")
        .assert()
        .failure();

    // The volume directory must still be present — nothing was deleted.
    teagarden_with_dir(&dir)
        .args(["volume", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("audit probe"));
}

#[test]
fn volume_delete_help_no_longer_promises_telegram_deletion_unconditionally() {
    // The old help said "Permanently delete a volume and all its Telegram blocks."
    // with no way to actually do it. The help must now surface the credential
    // requirement and the --local-only escape hatch.
    teagarden()
        .args(["volume", "delete", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--local-only"))
        .stdout(predicate::str::contains("--recovery-file"))
        .stdout(predicate::str::contains("Requires a credential"));
}

// ── Device-factor CLI wiring (B4) ───────────────────────────────────────────
//
// K1-K4 protectors were proven against software tokens in teagarden-mfa's own
// tests long before 1.0.0 — but ONLY through the library. `mfa enroll` exposed
// `--tpm2` and nothing else, so FIDO2/PKCS#11/Tang were unreachable from the
// shipped binary. These tests drive the REAL binary end-to-end so "the factor
// works" and "a user can use the factor" are the same statement.
//
// Gated like the library factor tests: with TEAGARDEN_REQUIRE_TANG set, a skip
// becomes a hard failure.

fn require_tang() -> bool {
    std::env::var_os("TEAGARDEN_REQUIRE_TANG").is_some()
}

fn tangd_paths() -> Option<(String, String)> {
    for dir in ["/usr/lib", "/usr/libexec", "/usr/lib/x86_64-linux-gnu"] {
        let d = std::path::Path::new(dir);
        if d.join("tangd").exists() && d.join("tangd-keygen").exists() {
            return Some((
                d.join("tangd").to_string_lossy().into(),
                d.join("tangd-keygen").to_string_lossy().into(),
            ));
        }
    }
    None
}

/// Enroll a Tang slot through the CLI, then unlock through the CLI.
#[test]
fn mfa_enroll_and_unlock_tang_through_the_real_cli() {
    let Some((tangd, keygen)) = tangd_paths() else {
        assert!(
            !require_tang(),
            "TEAGARDEN_REQUIRE_TANG set but tangd/tangd-keygen missing"
        );
        eprintln!("SKIP: tangd not installed");
        return;
    };
    if which_ok("socat").is_none() {
        assert!(
            !require_tang(),
            "TEAGARDEN_REQUIRE_TANG set but socat missing"
        );
        eprintln!("SKIP: socat not installed");
        return;
    }

    // ── spawn a local tangd over socat ────────────────────────────────────
    let keys = TempDir::new().unwrap();
    let keydir = keys.path().to_string_lossy().to_string();
    let kg = std::process::Command::new(&keygen)
        .arg(&keydir)
        .output()
        .unwrap();
    assert!(
        kg.status.success(),
        "tangd-keygen failed: {}",
        String::from_utf8_lossy(&kg.stderr)
    );

    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let mut socat = std::process::Command::new("socat")
        .arg(format!("TCP-LISTEN:{port},fork,reuseaddr"))
        .arg(format!("SYSTEM:{tangd} {keydir}"))
        .spawn()
        .expect("spawn socat");

    // wait for /adv to answer
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut ready = false;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    assert!(ready, "tangd never became reachable on port {port}");
    let url = format!("http://127.0.0.1:{port}");

    // ── a real key-protected volume, created offline ──────────────────────
    let dir = TempDir::new().unwrap();
    let pc = teagarden_mfa::unlock::create_protected_volume(
        Some("tangvol"),
        b"correct-horse-battery-staple",
        dir.path(),
        0,
        0,
        0,
        None,
    )
    .expect("create protected volume");
    let id = pc.created.config.volume_id.to_string();

    // Unlock the existing vault non-interactively with the recovery sentence.
    let rec_path = dir.path().join("recovery.txt");
    std::fs::write(&rec_path, pc.recovery_sentence.as_str()).unwrap();

    // ── ENROLL through the shipped binary ─────────────────────────────────
    teagarden_with_dir(&dir)
        .args([
            "keyslot",
            "enroll",
            &id,
            "--tang",
            &url,
            "--recovery-file",
            rec_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "slot change is local but header publication is pending",
        ))
        .stdout(predicate::str::contains("Enrolled Tang slot"));

    // ── UNLOCK through the shipped binary ─────────────────────────────────
    teagarden_with_dir(&dir)
        .args(["keyslot", "unlock", &id, "--tang", &url])
        .assert()
        .success()
        .stdout(predicate::str::contains("unlocked via Tang"));

    let _ = socat.kill();
    let _ = socat.wait();
}

fn which_ok(bin: &str) -> Option<()> {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| ())
}

/// Selecting two factors at once must be refused: each factor gets its own slot.
#[test]
fn mfa_enroll_refuses_two_factors_at_once() {
    teagarden()
        .args([
            "keyslot",
            "enroll",
            "somevol",
            "--tpm2",
            "--tang",
            "http://127.0.0.1:1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("exactly ONE factor"));
}

#[test]
fn fido2_enrollment_help_offers_the_five_modes_and_no_separate_identity() {
    let out = teagarden()
        .args(["keyslot", "enroll", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8(out).unwrap();
    for want in [
        "--fido2-mode <MODE>",
        "--fido2-post-quantum",
        "pin-up",
        "pin-uv",
        "PIN + UP: the key's PIN and a touch",
        "UP only: a touch",
        "NOT AVAILABLE",
    ] {
        assert!(help.contains(want), "missing {want:?} in:\n{help}");
    }
    // The separate-identity path and the options only `--generate` could honour
    // are gone.
    for gone in [
        "--fido2-identity-file",
        "--fido2-symmetric",
        "--fido2-algorithm",
    ] {
        assert!(!help.contains(gone), "{gone} still offered:\n{help}");
    }
}

#[test]
fn fido2_modes_that_cannot_be_enforced_are_refused_with_the_reason() {
    for (mode, reason) in [
        ("pin", "CTAP2_ERR_UNSUPPORTED_OPTION"),
        ("pin-uv", "CTAP2 cannot require both"),
        ("uv", "never asks the key for built-in user verification"),
    ] {
        // Refused before the volume is even looked up: nothing is asked for and
        // nothing touches the key.
        teagarden()
            .args([
                "keyslot",
                "enroll",
                "no-such-volume",
                "--fido2",
                "--fido2-mode",
                mode,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!("FIDO2 mode {mode} (")))
            .stderr(predicate::str::contains("is not available"))
            .stderr(predicate::str::contains(reason))
            .stderr(predicate::str::contains("volume not found").not());
    }
}

#[test]
fn fido2_mode_needs_fido2() {
    teagarden()
        .args([
            "keyslot",
            "enroll",
            "somevol",
            "--tpm2",
            "--fido2-mode",
            "up",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "the following required arguments were not provided",
        ))
        .stderr(predicate::str::contains("--fido2"));
}

#[test]
fn fido2_enrollment_without_a_mode_or_a_terminal_names_the_flag() {
    use std::os::unix::process::CommandExt as _;
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_teagarden"));
    command
        .args(["keyslot", "enroll", "no-such-volume", "--fido2"])
        .env("TEAGARDEN_CONFIG_DIR", default_config_dir())
        .stdin(std::process::Stdio::null());
    // SAFETY: setsid is async-signal-safe and touches no memory.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let out = command.output().expect("run teagarden");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("no terminal to ask for the FIDO2 verification mode"),
        "{stderr}"
    );
    assert!(stderr.contains("--fido2-mode pin-up"), "{stderr}");
}

/// A stand-in for `age-plugin-fido2-hmac` v0.5.0 that needs no key. It speaks the
/// age plugin protocol the way the real plugin's data-less path does
/// (cmd/age-plugin-fido2-hmac/main.go `HandleIdentityEncodingAsRecipient`, and
/// pkg/plugin/cli.go `NewCredentials` with `askForIdentity=false`):
///
///   recipient-v1: post-quantum question; "insert your token"; the PIN request
///   when the key has a PIN; touch 1; the require-PIN question only when the key
///   has a PIN; touch 2; one `fido2-hmac` v2 stanza whose require-PIN flag is the
///   answer; done. An error is reported the way the real plugin reports it: an
///   `error` stanza, then exit 3 without `done`.
///   identity-v1: the PIN request when the stanza requires a PIN; one touch; the
///   file key.
///
/// It proves the TeaGarden side of the protocol (which questions are answered,
/// which prompts appear, what is recorded). It proves nothing about an
/// authenticator.
///
/// Environment: FAKE_FIDO2_STATE (a directory: `calls` logs every invocation,
/// `filekey` keeps the wrapped file key), FAKE_FIDO2_KEY_PIN (the key has this
/// PIN; unset = no PIN set), FAKE_FIDO2_ASK_SEPARATE_IDENTITY=1 (also ask the
/// separate-identity question the data-less path never asks).
const FAKE_FIDO2_PLUGIN: &str = r#"#!/usr/bin/env bash
set -u
state="${FAKE_FIDO2_STATE:?}"
echo "$*" >> "$state/calls"
MAGIC=AGE-PLUGIN-FIDO2-HMAC-1VE5KGMEJ945X6CTRM2TF76
B43=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
b64() { printf '%s' "$1" | base64 | tr -d '\n='; }
# One stanza: "-> <head>", then a base64 body wrapped at 64 columns.
send_b64() {
  local body="$2"
  printf -- '-> %s\n' "$1"
  while [ "${#body}" -ge 64 ]; do printf '%s\n' "${body:0:64}"; body="${body:64}"; done
  printf '%s\n' "$body"
}
send() { send_b64 "$1" "$(b64 "$2")"; }
# Read one stanza into HEAD and BODY (base64, unwrapped).
recv() {
  local line
  IFS= read -r line || exit 9
  HEAD="${line#-> }"; BODY=""
  while IFS= read -r line; do BODY="$BODY$line"; [ "${#line}" -lt 64 ] && break; done
}
# A command to the client, and its reply.
ask() { send "$1" "$2"; recv; }
die() { send "error identity 0" "$1"; recv; exit 3; }
phase1() {
  while recv; do
    case "$HEAD" in
      done) return ;;
      "add-identity "*) [ "${HEAD#add-identity }" = "$MAGIC" ] || die "unexpected identity" ;;
      wrap-file-key) FILEKEY="$BODY" ;;
      # age clients also send grease stanzas; like the real plugin, only its
      # own stanza type counts.
      "recipient-stanza 0 fido2-hmac "*) STANZA="$HEAD" ;;
    esac
  done
}
check_pin() {
  local prompt="$1"
  ask request-secret "$prompt"
  [ "$HEAD" = ok ] || die "client failed to request value"
  [ "$BODY" = "$(b64 "$FAKE_FIDO2_KEY_PIN")" ] || die "pin invalid"
}
case "${1:-}" in
  --help)
    echo 'Usage: age-plugin-fido2-hmac [-s] [-a ALG] [-pq] -g --post-quantum -y [FILE] --algorithm' ;;
  --age-plugin=recipient-v1)
    phase1
    ask "confirm $(b64 yes) $(b64 no)" "Use post-quantum encryption (MLKEM768X25519)?"
    [ "$HEAD" = "ok yes" ] && pq=1 || pq=0
    case "$HEAD" in "ok yes"|"ok no") ;; *) die "client failed to request confirmation" ;; esac
    ask msg $'Please insert your token now...\n'
    [ -n "${FAKE_FIDO2_KEY_PIN:-}" ] && check_pin "Please enter your PIN:"
    ask msg $'Please touch your token...\n'
    flag=AA
    if [ -n "${FAKE_FIDO2_KEY_PIN:-}" ]; then
      ask "confirm $(b64 yes) $(b64 no)" "Do you want to require a PIN for decryption?"
      echo "pin-question: $HEAD" >> "$state/calls"
      case "$HEAD" in "ok yes") flag=AQ ;; "ok no") ;; *) die "client failed to request confirmation" ;; esac
    fi
    if [ "${FAKE_FIDO2_ASK_SEPARATE_IDENTITY:-}" = 1 ]; then
      ask "confirm $(b64 yes) $(b64 no)" $'Are you fine with having a separate identity (better privacy)?\n'
      echo "separate-identity-question: $HEAD" >> "$state/calls"
      [ "$HEAD" = "ok no" ] || die "client failed to request confirmation"
    fi
    ask msg $'Please touch your token...\n'
    share="$B43"; [ "$pq" = 1 ] && share="$(printf 'A%.0s' $(seq 1 1500))"
    printf '%s' "$FILEKEY" > "$state/filekey"
    send_b64 "recipient-stanza 0 fido2-hmac AAI $share $flag $B43 Y3JlZGlk" "$B43"
    recv
    send_b64 done ""
    ;;
  --age-plugin=identity-v1)
    phase1
    set -- $STANZA
    [ "$6" = AQ ] && check_pin "Please enter you PIN:"
    ask msg "Please touch your token..."
    send_b64 "file-key 0" "$(cat "$state/filekey")"
    recv
    send_b64 done ""
    ;;
  *) echo "fake plugin: unexpected arguments: $*" >&2; exit 1 ;;
esac
"#;

/// A key-protected volume, its recovery file, and a directory holding the fake
/// plugin, for the device-free FIDO2 tests.
struct Fido2Bench {
    dir: TempDir,
    plugin: TempDir,
    state: TempDir,
    id: String,
    recovery: std::path::PathBuf,
}

impl Fido2Bench {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        let pc = teagarden_mfa::unlock::create_protected_volume(
            Some("fidovol"),
            b"correct-horse-battery-staple",
            dir.path(),
            0,
            0,
            0,
            None,
        )
        .expect("create protected volume");
        let id = pc.created.config.volume_id.to_string();
        let recovery = dir.path().join("recovery.txt");
        std::fs::write(&recovery, pc.recovery_sentence.as_str()).unwrap();
        let plugin = TempDir::new().unwrap();
        let path = plugin.path().join("age-plugin-fido2-hmac");
        std::fs::write(&path, FAKE_FIDO2_PLUGIN).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            dir,
            plugin,
            state: TempDir::new().unwrap(),
            id,
            recovery,
        }
    }

    /// `teagarden <args>` with the fake plugin first on PATH.
    fn command(&self, args: &[&str]) -> std::process::Command {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_teagarden"));
        command
            .args(args)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.plugin.path().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("TEAGARDEN_CONFIG_DIR", default_config_dir())
            .env("TEAGARDEN_VOLUMES_DIR", self.dir.path())
            .env("FAKE_FIDO2_STATE", self.state.path())
            .env_remove("FIDO2_HMAC_PQ")
            .env_remove("FAKE_FIDO2_KEY_PIN")
            .env_remove("FAKE_FIDO2_ASK_SEPARATE_IDENTITY")
            .stdin(std::process::Stdio::null());
        command
    }

    fn enroll(&self, extra: &[&str]) -> std::process::Command {
        let mut args = vec!["keyslot", "enroll", &self.id, "--fido2"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--recovery-file", self.recovery.to_str().unwrap()]);
        self.command(&args)
    }

    fn unlock(&self) -> std::process::Command {
        self.command(&["keyslot", "unlock", &self.id, "--fido2"])
    }

    fn vault_path(&self) -> std::path::PathBuf {
        self.dir.path().join(&self.id).join("slot_vault.json")
    }

    fn vault(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.vault_path()).unwrap()).unwrap()
    }

    /// The params of the one FIDO2 slot in the vault.
    fn fido2_params(&self) -> serde_json::Value {
        let vault = self.vault();
        let slots: Vec<_> = vault["slots"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|slot| slot["slot_type"] == "fido2-hmac")
            .cloned()
            .collect();
        assert_eq!(slots.len(), 1, "{vault:#}");
        slots[0]["params"].clone()
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(self.state.path().join("calls")).unwrap_or_default()
    }
}

/// What a command printed: on its controlling terminal, stdout and stderr.
struct PtyRun {
    status: std::process::ExitStatus,
    tty: String,
    stdout: String,
    stderr: String,
}

/// Run `command` with a fresh pseudo-terminal as its controlling terminal, so
/// everything it writes to `/dev/tty` is captured and the PIN can be typed. Each
/// `(wait_for, type)` pair types `type` once `wait_for` has appeared on the
/// terminal since the previous answer.
fn run_on_pty(mut command: std::process::Command, answers: &[(&str, &str)]) -> PtyRun {
    use std::io::{Read as _, Write as _};
    use std::os::fd::FromRawFd as _;
    use std::os::unix::process::CommandExt as _;

    let (mut master, mut slave) = (-1, -1);
    // SAFETY: openpty writes two descriptors into the provided integers.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // SAFETY: setsid and ioctl are async-signal-safe and touch no memory.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 || libc::ioctl(slave, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("spawn teagarden");
    // SAFETY: `slave` is open and owned here; the child has its own copy.
    unsafe { libc::close(slave) };
    // SAFETY: `master` is an open descriptor this function owns from here on.
    let mut tty = unsafe { std::fs::File::from_raw_fd(master) };
    let mut writer = tty.try_clone().unwrap();
    let answers: Vec<(String, String)> = answers
        .iter()
        .map(|(w, t)| (w.to_string(), t.to_string()))
        .collect();
    let screen = std::thread::spawn(move || {
        let mut seen = String::new();
        let mut from = 0;
        let mut next = 0;
        let mut buf = [0u8; 4096];
        // Ends with EIO once every copy of the terminal's other side is closed.
        while let Ok(n) = tty.read(&mut buf) {
            if n == 0 {
                break;
            }
            seen.push_str(&String::from_utf8_lossy(&buf[..n]).replace('\r', ""));
            while let Some((wait_for, typed)) = answers.get(next) {
                match seen[from..].find(wait_for.as_str()) {
                    Some(at) => {
                        writer.write_all(typed.as_bytes()).unwrap();
                        from += at + wait_for.len();
                        next += 1;
                    }
                    None => break,
                }
            }
        }
        seen
    });
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let err = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("teagarden did not finish within two minutes (waiting on the terminal?)");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    PtyRun {
        status,
        tty: screen.join().unwrap(),
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}

/// The positions of `items` in `text`, asserting each appears after the last.
fn assert_in_order(text: &str, items: &[&str]) {
    let mut from = 0;
    for item in items {
        match text[from..].find(item) {
            Some(at) => from += at + item.len(),
            None => panic!("{item:?} missing, or out of order, in:\n{text}"),
        }
    }
}

const PIN_BANNER: &str = ">>> Enter the PIN of your security key now <<<";
const TOUCH_1_OF_2: &str =
    ">>> Touch your security key now (touch 1 of 2: creating the credential) <<<";
const TOUCH_2_OF_2: &str = ">>> Touch your security key now (touch 2 of 2: deriving the key) <<<";
const UNLOCK_TOUCH: &str =
    ">>> Touch your security key now (touch 1 of 1: unlocking the volume) <<<";
/// Fixture PIN of the stand-in key; it protects nothing.
const FAKE_PIN: &str = "246810";

/// Offline slot changes are saved locally but must fail visibly while their
/// portable header cannot be published to Telegram.
fn assert_header_publish_pending(run: &PtyRun, action: &str) {
    assert!(
        !run.status.success(),
        "slot mutation without Telegram credentials must report pending publication"
    );
    assert!(run.stdout.contains(action), "{}", run.stdout);
    assert!(
        run.stderr
            .contains("slot change is local but header publication is pending"),
        "{}",
        run.stderr
    );
}

#[test]
fn fido2_pin_up_enrollment_and_unlock_follow_the_recorded_mode() {
    let bench = Fido2Bench::new();
    let mut enroll = bench.enroll(&["--fido2-mode", "pin-up"]);
    enroll.env("FAKE_FIDO2_KEY_PIN", FAKE_PIN);
    let pin = format!("{FAKE_PIN}\n");
    let run = run_on_pty(enroll, &[("  PIN: ", &pin)]);
    assert_header_publish_pending(&run, "Enrolled FIDO2 slot");
    assert_in_order(
        &run.tty,
        &[
            "FIDO2 enrollment, mode PIN + UP: unlocking this slot will need the key's PIN and a touch.",
            "  1. the key's PIN\n  2. touch 1 of 2 (creating the credential)\n  3. touch 2 of 2 (deriving the key)",
            "  token: Please insert your token now...",
            PIN_BANNER,
            TOUCH_1_OF_2,
            "  ✓ key confirmed",
            TOUCH_2_OF_2,
            "  ✓ key confirmed",
        ],
    );
    assert_eq!(run.tty.matches(PIN_BANNER).count(), 1, "{}", run.tty);
    assert!(run.stdout.contains("Enrolled FIDO2 slot"), "{}", run.stdout);
    assert!(
        run.stdout.contains(
            "Mode PIN + UP (pin-up), recorded in the slot: every unlock and mount asks for \
             the key's PIN, then a touch."
        ),
        "{}",
        run.stdout
    );
    // The slot records the mode, and the plugin was told to require the PIN.
    let params = bench.fido2_params();
    assert_eq!(params["mode"], "pin-up", "{params}");
    assert_eq!(params["version"], 4, "{params}");
    assert!(params.get("identity").is_none(), "{params}");
    let calls = bench.calls();
    assert!(calls.contains("pin-question: ok yes"), "{calls}");
    assert!(calls.contains("--age-plugin=recipient-v1"), "{calls}");
    assert!(!calls.contains("--generate"), "{calls}");

    let mut unlock = bench.unlock();
    unlock.env("FAKE_FIDO2_KEY_PIN", FAKE_PIN);
    let run = run_on_pty(unlock, &[("  PIN: ", &pin)]);
    assert!(
        run.status.success(),
        "tty:\n{}\nstderr:\n{}",
        run.tty,
        run.stderr
    );
    assert_in_order(
        &run.tty,
        &[
            "with FIDO2 (mode PIN + UP): enter the key's PIN, then touch the key.",
            PIN_BANNER,
            UNLOCK_TOUCH,
            "  ✓ key confirmed",
        ],
    );
    assert!(run.stdout.contains("unlocked via FIDO2"), "{}", run.stdout);
}

#[test]
fn fido2_up_enrollment_asks_the_pin_only_to_create_and_unlock_asks_only_a_touch() {
    let bench = Fido2Bench::new();
    let mut enroll = bench.enroll(&["--fido2-mode", "up"]);
    enroll.env("FAKE_FIDO2_KEY_PIN", FAKE_PIN);
    let pin = format!("{FAKE_PIN}\n");
    let run = run_on_pty(enroll, &[("  PIN: ", &pin)]);
    assert_header_publish_pending(&run, "Enrolled FIDO2 slot");
    assert_in_order(
        &run.tty,
        &[
            "FIDO2 enrollment, mode UP only: unlocking this slot will need a touch and no PIN.",
            "  1. the key's PIN, only if the key has one",
            PIN_BANNER,
            TOUCH_1_OF_2,
            TOUCH_2_OF_2,
        ],
    );
    assert_eq!(bench.fido2_params()["mode"], "up");
    assert!(
        bench.calls().contains("pin-question: ok no"),
        "{}",
        bench.calls()
    );

    let mut unlock = bench.unlock();
    unlock.env("FAKE_FIDO2_KEY_PIN", FAKE_PIN);
    let run = run_on_pty(unlock, &[]);
    assert!(
        run.status.success(),
        "tty:\n{}\nstderr:\n{}",
        run.tty,
        run.stderr
    );
    assert_in_order(
        &run.tty,
        &[
            "with FIDO2 (mode UP only): touch the key. No PIN is asked.",
            UNLOCK_TOUCH,
            "  ✓ key confirmed",
        ],
    );
    assert!(!run.tty.contains(PIN_BANNER), "{}", run.tty);
    assert!(run.stdout.contains("unlocked via FIDO2"), "{}", run.stdout);
}

#[test]
fn fido2_mode_is_asked_on_the_terminal_and_an_unavailable_choice_is_explained() {
    let bench = Fido2Bench::new();
    let mut enroll = bench.enroll(&[]);
    enroll.env("FAKE_FIDO2_KEY_PIN", FAKE_PIN);
    let pin = format!("{FAKE_PIN}\n");
    let run = run_on_pty(
        enroll,
        &[
            ("Mode (1-5", "3\n"),
            ("Mode (1-5", "2\n"),
            ("  PIN: ", &pin),
        ],
    );
    assert_header_publish_pending(&run, "Enrolled FIDO2 slot");
    assert_in_order(
        &run.tty,
        &[
            "Choose what your security key must check each time this slot unlocks the volume:",
            "  2) PIN + UP  the key's PIN and a touch\n",
            "  PIN + UV is not available: CTAP2 cannot require both.",
            "  Mode PIN + UP: the key's PIN and a touch.",
            "FIDO2 enrollment, mode PIN + UP",
            PIN_BANNER,
            TOUCH_1_OF_2,
        ],
    );
    // The mode was settled before the plugin ran at all.
    let calls = bench.calls();
    assert!(
        calls.starts_with("--help\n--age-plugin=recipient-v1"),
        "{calls}"
    );
    assert_eq!(bench.fido2_params()["mode"], "pin-up");
}

#[test]
fn fido2_pin_up_on_a_key_without_a_pin_is_refused_and_nothing_is_saved() {
    // With no PIN set the plugin never asks the require-PIN question and creates
    // a credential that does not require one (pkg/plugin/cli.go NewCredentials).
    let bench = Fido2Bench::new();
    let before = std::fs::read(bench.vault_path()).unwrap();
    let run = run_on_pty(bench.enroll(&["--fido2-mode", "pin-up"]), &[]);
    assert!(!run.status.success(), "stdout:\n{}", run.stdout);
    assert!(run.stderr.contains("NOT saved"), "{}", run.stderr);
    assert!(run.stderr.contains("fido2-token -S"), "{}", run.stderr);
    assert!(!run.tty.contains(PIN_BANNER), "{}", run.tty);
    assert_eq!(std::fs::read(bench.vault_path()).unwrap(), before);
}

#[test]
fn fido2_enrollment_never_answers_a_separate_identity_question() {
    let bench = Fido2Bench::new();
    let before = std::fs::read(bench.vault_path()).unwrap();
    let mut enroll = bench.enroll(&["--fido2-mode", "up"]);
    enroll.env("FAKE_FIDO2_ASK_SEPARATE_IDENTITY", "1");
    let run = run_on_pty(enroll, &[]);
    assert!(!run.status.success(), "stdout:\n{}", run.stdout);
    let calls = bench.calls();
    assert!(
        calls.contains("separate-identity-question: fail"),
        "{calls}"
    );
    assert!(run.stderr.contains("separate identity"), "{}", run.stderr);
    assert!(run.stderr.contains("NOT saved"), "{}", run.stderr);
    assert_eq!(std::fs::read(bench.vault_path()).unwrap(), before);
}

#[test]
fn fido2_wrong_pin_at_enrollment_is_reported_with_its_likely_cause() {
    // The real plugin reports the error and exits without `done`; age 0.11 then
    // returns "incomplete response" and drops the plugin's words.
    let bench = Fido2Bench::new();
    let before = std::fs::read(bench.vault_path()).unwrap();
    let mut enroll = bench.enroll(&["--fido2-mode", "pin-up"]);
    enroll.env("FAKE_FIDO2_KEY_PIN", FAKE_PIN);
    let run = run_on_pty(enroll, &[("  PIN: ", "000000\n")]);
    assert!(!run.status.success(), "stdout:\n{}", run.stdout);
    assert!(run.stderr.contains("wrong PIN"), "{}", run.stderr);
    assert!(run.stderr.contains("fido2-token -I"), "{}", run.stderr);
    assert!(run.stderr.contains("NOT saved"), "{}", run.stderr);
    assert_eq!(std::fs::read(bench.vault_path()).unwrap(), before);
}

#[test]
fn fido2_unlock_refuses_a_slot_whose_recorded_mode_was_altered() {
    let bench = Fido2Bench::new();
    let mut enroll = bench.enroll(&["--fido2-mode", "pin-up"]);
    enroll.env("FAKE_FIDO2_KEY_PIN", FAKE_PIN);
    let pin = format!("{FAKE_PIN}\n");
    let enrolled = run_on_pty(enroll, &[("  PIN: ", &pin)]);
    assert_header_publish_pending(&enrolled, "Enrolled FIDO2 slot");

    // Rewrite the recorded mode. The vault digest does not cover slot params, so
    // the file still loads; the mode must disagree with the credential instead.
    let text = std::fs::read_to_string(bench.vault_path()).unwrap();
    let altered = text.replace("\"mode\": \"pin-up\"", "\"mode\": \"up\"");
    assert_ne!(text, altered, "{text}");
    std::fs::write(bench.vault_path(), altered).unwrap();

    let calls_before = bench.calls();
    let run = run_on_pty(bench.unlock(), &[]);
    assert!(!run.status.success(), "stdout:\n{}", run.stdout);
    assert!(
        run.stderr
            .contains("records mode UP only but its credential requires"),
        "{}",
        run.stderr
    );
    // Refused before the plugin was started, so no prompt was shown.
    assert_eq!(bench.calls(), calls_before);
    assert!(!run.tty.contains(">>>"), "{}", run.tty);
}

/// With no controlling terminal the announcements still reach the operator, on
/// stderr; an UP-only enrollment on a key without a PIN needs no terminal input.
#[test]
fn fido2_up_enrollment_without_a_terminal_announces_on_stderr() {
    use std::os::unix::process::CommandExt as _;
    let bench = Fido2Bench::new();
    let mut command = bench.enroll(&["--fido2-mode", "up"]);
    // SAFETY: setsid is async-signal-safe and touches no memory.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let out = command.output().expect("run teagarden");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "offline enrollment must report pending publication; stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("Enrolled FIDO2 slot"), "{stdout}");
    assert!(
        stderr.contains("slot change is local but header publication is pending"),
        "{stderr}"
    );
    assert_in_order(
        &stderr,
        &["FIDO2 enrollment, mode UP only", TOUCH_1_OF_2, TOUCH_2_OF_2],
    );
    assert_eq!(stderr.matches("✓ key confirmed").count(), 2, "{stderr}");
    assert!(stdout.contains("Enrolled FIDO2 slot"), "{stdout}");
    assert!(
        stdout.contains(&format!("teagarden keyslot unlock {} --fido2", bench.id)),
        "{stdout}"
    );
    assert!(stdout.contains("did not test-unlock"), "{stdout}");
}

/// K1 FIDO2 through the SHIPPED binary, against a real hardware authenticator.
///
/// Gated on `TEAGARDEN_REQUIRE_FIDO2` because it needs a physical key AND a human
/// touch — with the flag set, a skip is a hard failure, so this can never quietly
/// pass on a machine with no authenticator. `TEAGARDEN_FIDO2_MODE` (pin-up or up)
/// selects the mode; the harness never supplies or guesses the PIN.
#[test]
fn mfa_enroll_and_unlock_fido2_through_the_real_cli() {
    let require = std::env::var_os("TEAGARDEN_REQUIRE_FIDO2").is_some();
    if !require {
        eprintln!("SKIP: set TEAGARDEN_REQUIRE_FIDO2=1 with a hardware key attached");
        return;
    }
    let mode = std::env::var("TEAGARDEN_FIDO2_MODE")
        .expect("set TEAGARDEN_FIDO2_MODE to pin-up or up for the attended test");

    let dir = TempDir::new().unwrap();
    let pc = teagarden_mfa::unlock::create_protected_volume(
        Some("fidovol"),
        b"correct-horse-battery-staple",
        dir.path(),
        0,
        0,
        0,
        None,
    )
    .expect("create protected volume");
    let id = pc.created.config.volume_id.to_string();

    let rec_path = dir.path().join("recovery.txt");
    std::fs::write(&rec_path, pc.recovery_sentence.as_str()).unwrap();

    // The binary announces every PIN entry and touch itself, on the terminal. Its
    // stderr is inherited, not captured: capturing it is what hid the plugin's
    // prompts and TeaGarden's own notices from the operator in the first
    // attended run.
    let enroll: Vec<String> = vec![
        "keyslot".into(),
        "enroll".into(),
        id.clone(),
        "--fido2".into(),
        "--fido2-mode".into(),
        mode.clone(),
        "--recovery-file".into(),
        rec_path.to_string_lossy().into_owned(),
    ];

    let enrolled = run_with_inherited_stderr(&dir, &enroll);
    assert!(
        enrolled.status.success(),
        "enroll exited with {}",
        enrolled.status
    );
    let stdout = String::from_utf8_lossy(&enrolled.stdout);
    assert!(stdout.contains("Enrolled FIDO2 slot"), "stdout: {stdout}");
    assert!(stdout.contains(&format!("({mode})")), "stdout: {stdout}");

    let unlocked = run_with_inherited_stderr(
        &dir,
        &[
            "keyslot".into(),
            "unlock".into(),
            id.clone(),
            "--fido2".into(),
        ],
    );
    assert!(
        unlocked.status.success(),
        "unlock exited with {}",
        unlocked.status
    );
    let stdout = String::from_utf8_lossy(&unlocked.stdout);
    assert!(stdout.contains("unlocked via FIDO2"), "stdout: {stdout}");
}

/// Run the `teagarden` binary with stdin and stderr INHERITED and stdout captured,
/// so prompts and banners reach the operator's terminal. Fails the test if the
/// binary does not finish within five minutes.
fn run_with_inherited_stderr(dir: &TempDir, args: &[String]) -> std::process::Output {
    use std::io::Read as _;
    use std::process::Stdio;

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_teagarden"))
        .args(args)
        .env("TEAGARDEN_CONFIG_DIR", default_config_dir())
        .env("TEAGARDEN_VOLUMES_DIR", dir.path())
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn teagarden");
    let mut pipe = child.stdout.take().expect("stdout is piped");
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = pipe.read_to_end(&mut out);
        out
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll teagarden") {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("teagarden did not finish within five minutes");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    std::process::Output {
        status,
        stdout: reader.join().expect("stdout reader"),
        stderr: Vec::new(),
    }
}

/// Helper: materialise a key-protected volume at a caller-chosen path so the
/// operator can drive `mfa enroll --fido2` by hand on a real TTY (needed when the
/// authenticator has a PIN, which must be typed rather than passed in an
/// environment variable or argv).
///
/// Run with: TEAGARDEN_FIDO2_FIXTURE=/path cargo test --release fido2_fixture -- --nocapture
#[test]
fn fido2_fixture() {
    let Some(dir) = std::env::var_os("TEAGARDEN_FIDO2_FIXTURE") else {
        eprintln!("SKIP: set TEAGARDEN_FIDO2_FIXTURE=<dir>");
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pc = teagarden_mfa::unlock::create_protected_volume(
        Some("fidovol"),
        b"correct-horse-battery-staple",
        &dir,
        0,
        0,
        0,
        None,
    )
    .expect("create protected volume");
    let id = pc.created.config.volume_id.to_string();
    let rec = dir.join("recovery.txt");
    std::fs::write(&rec, pc.recovery_sentence.as_str()).unwrap();
    println!("FIXTURE_VOLUMES_DIR={}", dir.display());
    println!("FIXTURE_VOLUME_ID={id}");
    println!("FIXTURE_RECOVERY_FILE={}", rec.display());
}

// ── K3 PKCS#11 through the SHIPPED binary ───────────────────────────────────
//
// The protector was proven against SoftHSM2 in teagarden-mfa's own tests, but
// only through the library. This drives the actual `teagarden` binary, so
// "the factor works" and "a user can use the factor" become the same statement.
//
// Gated on TEAGARDEN_REQUIRE_HSM: with the flag set, a skip is a hard failure.

fn softhsm_module() -> Option<String> {
    for p in [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/pkcs11/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
    ] {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

#[test]
fn mfa_enroll_and_unlock_pkcs11_through_the_real_cli() {
    const LABEL: &str = "teagarden-cli-test";
    const PIN: &str = "1234";
    let require = std::env::var_os("TEAGARDEN_REQUIRE_HSM").is_some();

    let Some(module) = softhsm_module() else {
        assert!(
            !require,
            "TEAGARDEN_REQUIRE_HSM set but libsofthsm2.so not found"
        );
        eprintln!("SKIP: libsofthsm2.so not found");
        return;
    };
    if which_ok("softhsm2-util").is_none() || which_ok("pkcs11-tool").is_none() {
        assert!(
            !require,
            "TEAGARDEN_REQUIRE_HSM set but softhsm2-util/pkcs11-tool missing"
        );
        eprintln!("SKIP: softhsm2-util / pkcs11-tool not available");
        return;
    }

    // ── provision a throwaway SoftHSM2 token ──────────────────────────────
    let work = TempDir::new().unwrap();
    let tokens = work.path().join("tokens");
    std::fs::create_dir_all(&tokens).unwrap();
    let conf = work.path().join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .unwrap();

    let init = std::process::Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", &conf)
        .args([
            "--init-token",
            "--free",
            "--label",
            LABEL,
            "--so-pin",
            PIN,
            "--pin",
            PIN,
        ])
        .output()
        .expect("run softhsm2-util");
    assert!(
        init.status.success(),
        "init-token failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let gen = std::process::Command::new("pkcs11-tool")
        .env("SOFTHSM2_CONF", &conf)
        .args([
            "--module",
            &module,
            "--login",
            "--pin",
            PIN,
            "--keypairgen",
            "--key-type",
            "rsa:2048",
            "--id",
            "01",
            "--label",
            "kek",
        ])
        .output()
        .expect("run pkcs11-tool");
    assert!(
        gen.status.success(),
        "keypairgen failed: {}",
        String::from_utf8_lossy(&gen.stderr)
    );

    // ── a real key-protected volume ───────────────────────────────────────
    let dir = TempDir::new().unwrap();
    let pc = teagarden_mfa::unlock::create_protected_volume(
        Some("hsmvol"),
        b"correct-horse-battery-staple",
        dir.path(),
        0,
        0,
        0,
        None,
    )
    .expect("create protected volume");
    let id = pc.created.config.volume_id.to_string();
    let rec_path = dir.path().join("recovery.txt");
    std::fs::write(&rec_path, pc.recovery_sentence.as_str()).unwrap();

    // ── ENROLL through the shipped binary ─────────────────────────────────
    // TEAGARDEN_FACTOR_PIN is the documented non-interactive PIN path; the PIN is
    // never passed as an argument, so it cannot leak into argv or shell history.
    let enrolled = teagarden_with_dir(&dir)
        .env("SOFTHSM2_CONF", &conf)
        .env("TEAGARDEN_FACTOR_PIN", PIN)
        .args([
            "keyslot",
            "enroll",
            &id,
            "--pkcs11-module",
            &module,
            "--pkcs11-token-label",
            LABEL,
            "--pkcs11-key-id",
            "01",
            "--recovery-file",
            rec_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "slot change is local but header publication is pending",
        ))
        .stdout(predicate::str::contains("Enrolled PKCS#11 slot"));

    // It says which RSA-OAEP hash wrapped the key, and that is what the vault
    // recorded (the slot record is plain JSON; no key material is involved).
    let out = String::from_utf8_lossy(&enrolled.get_output().stdout).to_string();
    let vault: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join(&id).join("slot_vault.json")).unwrap(),
    )
    .unwrap();
    let recorded = vault["slots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["label"] == "pkcs11")
        .expect("pkcs11 slot")["kek_transport"]["scheme"]
        .as_str()
        .expect("scheme recorded")
        .to_string();
    let printed = match recorded.as_str() {
        "pkcs11-rsa-oaep-sha256" => "Key wrap: RSA-OAEP with SHA-256 (pkcs11-rsa-oaep-sha256)",
        "pkcs11-rsa-oaep-sha1" => "Key wrap: RSA-OAEP with SHA-1 (pkcs11-rsa-oaep-sha1)",
        other => panic!("unexpected recorded scheme {other}"),
    };
    assert!(
        out.contains(printed),
        "enroll must print {printed:?}:\n{out}"
    );
    eprintln!("SoftHSM2 PKCS#11 enroll used scheme {recorded}");

    // ── UNLOCK through the shipped binary ─────────────────────────────────
    teagarden_with_dir(&dir)
        .env("SOFTHSM2_CONF", &conf)
        .env("TEAGARDEN_FACTOR_PIN", PIN)
        .args([
            "keyslot",
            "unlock",
            &id,
            "--pkcs11-module",
            &module,
            "--pkcs11-token-label",
            LABEL,
            "--pkcs11-key-id",
            "01",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("unlocked via PKCS#11"));
}

/// cli: `--help` must never print a value clap read from the environment (or
/// from the config `.env`, which the CLI loads into the environment). The
/// values here are fake; HOME / XDG_CONFIG_HOME point at an empty dir so no real
/// `.env` is loaded into the process under test.
#[test]
fn help_does_not_print_env_credentials() {
    let home = TempDir::new().unwrap();
    let fake_hash = "deadbeefcafebabe0123456789abcdef";
    let fake_id = "987654321";
    for args in [vec!["auth", "login", "--help"]] {
        let out = teagarden()
            .args(&args)
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join(".config"))
            .env(
                "TEAGARDEN_CONFIG_DIR",
                home.path().join(".config").join("teagarden"),
            )
            .env("TG_API_HASH", fake_hash)
            .env("TG_API_ID", fake_id)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?} failed");
        let text = String::from_utf8_lossy(&out.stdout);
        for value in [fake_hash, fake_id] {
            assert!(
                !text.contains(value),
                "{args:?} printed an env value ({value}):\n{text}"
            );
        }
    }
}

/// `auth login` with no API id/hash configured and no terminal must explain what
/// to do and exit non-zero instead of waiting for input.
#[test]
fn auth_login_without_api_settings_or_terminal_explains_and_fails() {
    let cfg = TempDir::new().unwrap();
    Command::cargo_bin("teagarden")
        .unwrap()
        .env_clear()
        .env("HOME", cfg.path())
        .env("TEAGARDEN_CONFIG_DIR", cfg.path())
        .args(["auth", "login"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("my.telegram.org"))
        .stderr(predicate::str::contains("teagarden configure"));
}

/// A first `auth login` with the API settings given as flags must create the
/// config directory (0700) for the session file before it connects, whether or
/// not the connection then succeeds. Before the fix nothing created it.
#[cfg(unix)]
#[test]
fn auth_login_with_flags_creates_the_private_config_dir_first() {
    use std::os::unix::fs::PermissionsExt;
    let home = TempDir::new().unwrap();
    let cfg = home.path().join("fresh").join("teagarden");
    // A directory is not a valid SQLite session file. This makes the client
    // fail locally before network setup while retaining the config-dir check.
    let invalid_session = home.path().join("session-is-a-directory");
    std::fs::create_dir(&invalid_session).unwrap();
    let output = Command::cargo_bin("teagarden")
        .unwrap()
        .env_clear()
        .env("HOME", home.path())
        .env("TEAGARDEN_CONFIG_DIR", &cfg)
        .env("TEAGARDEN_SESSION_PATH", &invalid_session)
        .args([
            "auth",
            "login",
            "--api-id",
            "1",
            "--api-hash",
            "0123456789abcdef0123456789abcdef",
        ])
        .write_stdin("")
        .timeout(std::time::Duration::from_secs(90))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("inspect session"),
        "the offline fixture should fail on its invalid local session path: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let meta = std::fs::metadata(&cfg).expect("auth login must create the config directory");
    assert!(meta.is_dir());
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
}

/// `dev delete` with no `--force` and no terminal must REFUSE with a non-zero exit
/// (a cancelled `volume restore` exiting 0 is how an unconfirmed run counted as a
/// pass), and must leave the device's registry entry alone.
#[cfg(feature = "dev")]
#[test]
fn dev_delete_without_force_and_without_a_terminal_exits_nonzero() {
    let reg = TempDir::new().unwrap();
    let record = reg.path().join("vault.json");
    std::fs::write(
        &record,
        serde_json::json!({
            "name": "vault",
            "dir": reg.path().join("vault-state"),
            "capacity_blocks": 256,
            "segment_target": 1048576,
            "salt": vec![7u8; 32],
            "telegram_group_id": 999000000i64,
            "telegram_access_hash": 1234567890i64,
            "telegram_topic_id": 77,
            "created_at": 1
        })
        .to_string(),
    )
    .unwrap();
    teagarden()
        .env("TEAGARDEN_DEV_REGISTRY_DIR", reg.path())
        .args(["dev", "delete", "vault"])
        .write_stdin("")
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"))
        .stderr(predicate::str::contains("nothing was deleted"));
    assert!(record.exists(), "the registry entry must be untouched");
}

/// Round 13 (A1): `volume restore` with no `--force` and no terminal to ask on
/// refuses with a non-zero exit before it unlocks or contacts anything, and
/// changes nothing (as `dev delete` does). A cancelled restore that exited 0
/// is how an unconfirmed scripted run once counted as a pass.
#[test]
fn volume_restore_without_force_and_without_a_terminal_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let vol = make_volume(&dir, "correct horse battery staple");
    let pass = dir.path().join("pass.txt");
    std::fs::write(&pass, "correct horse battery staple\n").unwrap();
    let before = std::fs::read(dir.path().join(&vol).join("volume.json")).unwrap();
    teagarden_with_dir(&dir)
        .args(["volume", "restore", &vol, "--password-file"])
        .arg(&pass)
        .write_stdin("y\n")
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a terminal"))
        .stderr(predicate::str::contains("--force"))
        .stderr(predicate::str::contains("Nothing was changed"));
    assert_eq!(
        std::fs::read(dir.path().join(&vol).join("volume.json")).unwrap(),
        before
    );
}

/// Round 13 (A1): `volume delete` with no `--force` and no terminal to ask on
/// refuses with a non-zero exit, and the volume survives.
#[test]
fn volume_delete_without_force_and_without_a_terminal_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let vol = make_volume(&dir, "correct horse battery staple");
    let pass = dir.path().join("pass.txt");
    std::fs::write(&pass, "correct horse battery staple\n").unwrap();
    teagarden_with_dir(&dir)
        .args(["volume", "delete", &vol, "--local-only", "--password-file"])
        .arg(&pass)
        .write_stdin("y\n")
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a terminal"))
        .stderr(predicate::str::contains("--force"))
        .stderr(predicate::str::contains("nothing was deleted"));
    assert!(dir.path().join(&vol).join("volume.json").exists());
}

/// Round 13 (A1): `volume delete` answered "n" on a terminal exits non-zero
/// with "Cancelled. Nothing was deleted.", and the volume survives. The
/// terminal is a pseudo-terminal from util-linux `script`.
#[cfg(target_os = "linux")]
#[test]
fn volume_delete_answered_no_on_a_terminal_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let vol = make_volume(&dir, "correct horse battery staple");
    let pass = dir.path().join("pass.txt");
    std::fs::write(&pass, "correct horse battery staple\n").unwrap();
    #[allow(deprecated)]
    let bin = assert_cmd::cargo::cargo_bin("teagarden");
    let cmd = format!(
        "{} volume delete {vol} --local-only --password-file {}",
        bin.display(),
        pass.display()
    );
    let out = Command::new("script")
        .args(["-qec", &cmd, "/dev/null"])
        .env("TEAGARDEN_CONFIG_DIR", default_config_dir())
        .env("TEAGARDEN_VOLUMES_DIR", dir.path())
        .write_stdin("n\n")
        .timeout(std::time::Duration::from_secs(60))
        .output()
        .expect("util-linux `script` provides the terminal");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("delete answered n: exit {:?}\n{text}", out.status.code());
    assert!(
        text.contains("Continue? [y/N]"),
        "no prompt was shown:\n{text}"
    );
    assert!(text.contains("Cancelled. Nothing was deleted."), "{text}");
    assert!(
        !out.status.success(),
        "a cancelled delete exited 0:\n{text}"
    );
    assert!(dir.path().join(&vol).join("volume.json").exists());
}

/// `auth export` / `auth import`: moving a Telegram login to another computer.
/// Every test uses temp directories and fake session databases; nothing here
/// reads a real configuration and nothing contacts Telegram.
#[cfg(unix)]
mod session_transfer {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};

    const FAKE_HASH: &str = "0123456789abcdef0123456789abcdef";
    const FAKE_BOT: &str = "424242:fakefakefakefakefakefake";

    /// A command whose config directory is `cfg`, with every variable that could
    /// point it at a real file removed.
    fn tg(cfg: &Path) -> Command {
        let mut cmd = Command::cargo_bin("teagarden").unwrap();
        cmd.env_clear()
            .env("HOME", cfg)
            .env("TEAGARDEN_CONFIG_DIR", cfg)
            .timeout(std::time::Duration::from_secs(60));
        cmd
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The tables and version of the session database TeaGarden's Telegram
    /// layer creates (`crates/teagarden-telegram/src/session.rs`), with a
    /// `peer_info` row only when `signed_in`.
    fn write_fake_session(path: &Path, signed_in: bool) {
        let _ = std::fs::remove_file(path);
        let db = rusqlite::Connection::open(path).unwrap();
        db.execute_batch(
            "CREATE TABLE dc_home (dc_id INTEGER NOT NULL PRIMARY KEY);
             CREATE TABLE dc_option (dc_id INTEGER NOT NULL PRIMARY KEY, ipv4 TEXT NOT NULL,
                 ipv6 TEXT NOT NULL, auth_key BLOB);
             CREATE TABLE peer_info (peer_id INTEGER NOT NULL PRIMARY KEY, hash INTEGER,
                 subtype INTEGER);
             CREATE TABLE update_state (pts INTEGER NOT NULL, qts INTEGER NOT NULL,
                 date INTEGER NOT NULL, seq INTEGER NOT NULL);
             CREATE TABLE channel_state (peer_id INTEGER NOT NULL PRIMARY KEY,
                 pts INTEGER NOT NULL);
             INSERT INTO dc_home (dc_id) VALUES (2);
             PRAGMA user_version = 1;",
        )
        .unwrap();
        if signed_in {
            db.execute(
                "INSERT INTO peer_info (peer_id, hash, subtype) VALUES (1234567, 99, 1)",
                [],
            )
            .unwrap();
        }
        drop(db);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// A computer that is set up: `.env` (API settings and a bot token), a
    /// storage-group record and a signed-in session, all in `cfg`.
    fn seed_config(cfg: &Path) {
        std::fs::create_dir_all(cfg).unwrap();
        std::fs::write(
            cfg.join(".env"),
            format!(
                "# TeaGarden Configuration\nTG_API_ID=12345\nTG_API_HASH={FAKE_HASH}\n\
                 TELEGRAM_BOT_TOKEN_1={FAKE_BOT}\nTEAGARDEN_VOLUMES_DIR=/old/computer/volumes\n"
            ),
        )
        .unwrap();
        std::fs::write(
            cfg.join("group.json"),
            "{\"group_id\":1,\"access_hash\":2}\n",
        )
        .unwrap();
        write_fake_session(&cfg.join("teagarden.session"), true);
    }

    /// A transfer directory as `auth export` writes it.
    fn seed_transfer_dir(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            dir.join(".env"),
            format!("TG_API_ID=12345\nTG_API_HASH={FAKE_HASH}\nTELEGRAM_BOT_TOKEN_1={FAKE_BOT}\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("group.json"),
            "{\"group_id\":1,\"access_hash\":2}\n",
        )
        .unwrap();
        write_fake_session(&dir.join("teagarden.session"), true);
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
        names(dir)
            .into_iter()
            .map(|n| {
                let b = std::fs::read(dir.join(&n)).unwrap_or_default();
                (n, b)
            })
            .collect()
    }

    fn stdout_stderr(out: &std::process::Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    #[test]
    fn auth_help_lists_export_and_import() {
        let cfg = TempDir::new().unwrap();
        tg(cfg.path())
            .args(["auth", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("export"))
            .stdout(predicate::str::contains("import"));
    }

    #[test]
    fn export_writes_a_private_dir_with_private_files_and_warns() {
        let cfg = TempDir::new().unwrap();
        seed_config(cfg.path());
        let out_root = TempDir::new().unwrap();
        let dir = out_root.path().join("to-move");

        let out = tg(cfg.path())
            .args(["auth", "export"])
            .arg(&dir)
            .output()
            .unwrap();
        let text = stdout_stderr(&out);
        assert!(out.status.success(), "{text}");

        assert_eq!(mode(&dir), 0o700);
        assert_eq!(names(&dir), [".env", "group.json", "teagarden.session"]);
        for n in names(&dir) {
            assert_eq!(mode(&dir.join(&n)), 0o600, "{n}");
        }
        let source_db = rusqlite::Connection::open(cfg.path().join("teagarden.session")).unwrap();
        let exported_db = rusqlite::Connection::open(dir.join("teagarden.session")).unwrap();
        for db in [&source_db, &exported_db] {
            let integrity: String = db
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .unwrap();
            assert_eq!(integrity, "ok");
        }
        for table in [
            "dc_home",
            "dc_option",
            "peer_info",
            "update_state",
            "channel_state",
        ] {
            let count = |db: &rusqlite::Connection| -> i64 {
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
            };
            assert_eq!(
                count(&source_db),
                count(&exported_db),
                "row count in {table}"
            );
        }
        assert_eq!(
            source_db
                .query_row("SELECT dc_id FROM dc_home", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            exported_db
                .query_row("SELECT dc_id FROM dc_home", [], |r| r.get::<_, i64>(0))
                .unwrap(),
        );
        assert_eq!(
            source_db
                .query_row("SELECT peer_id, hash, subtype FROM peer_info", [], |r| Ok(
                    (
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?
                    )
                ))
                .unwrap(),
            exported_db
                .query_row("SELECT peer_id, hash, subtype FROM peer_info", [], |r| Ok(
                    (
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?
                    )
                ))
                .unwrap(),
        );
        assert_eq!(
            std::fs::read(dir.join("group.json")).unwrap(),
            std::fs::read(cfg.path().join("group.json")).unwrap()
        );
        // The API settings and the bot token travel; a path on this computer
        // does not.
        let env = std::fs::read_to_string(dir.join(".env")).unwrap();
        assert!(env.contains("TG_API_ID=12345\n"), "{env}");
        assert!(env.contains(&format!("TG_API_HASH={FAKE_HASH}\n")));
        assert!(env.contains(&format!("TELEGRAM_BOT_TOKEN_1={FAKE_BOT}\n")));
        assert!(!env.contains("TEAGARDEN_VOLUMES_DIR"), "{env}");
        assert!(!env.contains("TEAGARDEN_SESSION_PATH"), "{env}");

        assert!(text.contains("login to your Telegram account"), "{text}");
        assert!(text.contains("channel you trust"), "{text}");
        assert!(text.contains("delete"), "{text}");
        assert!(
            !text.contains(FAKE_HASH) && !text.contains(FAKE_BOT),
            "{text}"
        );
    }

    #[test]
    fn export_without_a_group_record_omits_group_json() {
        let cfg = TempDir::new().unwrap();
        seed_config(cfg.path());
        std::fs::remove_file(cfg.path().join("group.json")).unwrap();
        let out_root = TempDir::new().unwrap();
        let dir = out_root.path().join("to-move");
        tg(cfg.path())
            .args(["auth", "export"])
            .arg(&dir)
            .assert()
            .success();
        assert_eq!(names(&dir), [".env", "teagarden.session"]);
    }

    #[test]
    fn export_accepts_an_existing_empty_dir_and_makes_it_0700() {
        let cfg = TempDir::new().unwrap();
        seed_config(cfg.path());
        let out_root = TempDir::new().unwrap();
        let dir = out_root.path().join("empty");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        tg(cfg.path())
            .args(["auth", "export"])
            .arg(&dir)
            .assert()
            .success();
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn export_refuses_a_directory_that_is_not_empty() {
        let cfg = TempDir::new().unwrap();
        seed_config(cfg.path());
        let out_root = TempDir::new().unwrap();
        let dir = out_root.path().join("busy");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("notes.txt"), "keep me").unwrap();
        let before = snapshot(&dir);
        tg(cfg.path())
            .args(["auth", "export"])
            .arg(&dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("not empty"));
        assert_eq!(snapshot(&dir), before, "the directory must be untouched");
    }

    #[test]
    fn export_refuses_a_symlinked_directory_and_a_plain_file() {
        let cfg = TempDir::new().unwrap();
        seed_config(cfg.path());
        let out_root = TempDir::new().unwrap();
        let real = out_root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = out_root.path().join("link");
        symlink(&real, &link).unwrap();
        tg(cfg.path())
            .args(["auth", "export"])
            .arg(&link)
            .assert()
            .failure()
            .stderr(predicate::str::contains("symbolic link"));
        assert!(names(&real).is_empty());

        let file = out_root.path().join("file");
        std::fs::write(&file, "x").unwrap();
        tg(cfg.path())
            .args(["auth", "export"])
            .arg(&file)
            .assert()
            .failure();
    }

    #[test]
    fn export_refuses_a_signed_out_session_and_writes_nothing() {
        let cfg = TempDir::new().unwrap();
        seed_config(cfg.path());
        write_fake_session(&cfg.path().join("teagarden.session"), false);
        let out_root = TempDir::new().unwrap();
        let dir = out_root.path().join("to-move");
        tg(cfg.path())
            .args(["auth", "export"])
            .arg(&dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("not signed in"));
        assert!(!dir.exists(), "no directory may be left behind");
    }

    #[test]
    fn export_without_a_session_or_settings_says_what_is_missing() {
        let cfg = TempDir::new().unwrap();
        let out_root = TempDir::new().unwrap();
        let dir = out_root.path().join("to-move");
        tg(cfg.path())
            .args(["auth", "export"])
            .arg(&dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("auth login"));
        assert!(!dir.exists());
    }

    #[test]
    fn import_installs_the_files_0600_prints_status_and_the_login_is_found() {
        let src = TempDir::new().unwrap();
        seed_config(src.path());
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("to-move");
        tg(src.path())
            .args(["auth", "export"])
            .arg(&dir)
            .assert()
            .success();

        let dst_root = TempDir::new().unwrap();
        let dst = dst_root.path().join("teagarden");
        let out = tg(&dst)
            .args(["auth", "import"])
            .arg(&dir)
            .output()
            .unwrap();
        let text = stdout_stderr(&out);
        assert!(out.status.success(), "{text}");

        assert_eq!(mode(&dst), 0o700);
        assert_eq!(names(&dst), [".env", "group.json", "teagarden.session"]);
        for n in names(&dst) {
            assert_eq!(mode(&dst.join(&n)), 0o600, "{n}");
        }
        assert_eq!(
            std::fs::read(dst.join("teagarden.session")).unwrap(),
            std::fs::read(dir.join("teagarden.session")).unwrap()
        );
        assert_eq!(
            std::fs::read(dst.join(".env")).unwrap(),
            std::fs::read(dir.join(".env")).unwrap()
        );
        assert!(text.contains("Session file exists"), "{text}");
        assert!(text.contains(&dst.join("teagarden.session").display().to_string()));
        assert!(
            !text.contains(FAKE_HASH) && !text.contains(FAKE_BOT),
            "{text}"
        );

        // `auth status` on the new computer now finds the session.
        tg(&dst)
            .args(["auth", "status"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Session file exists"));
        // The transfer directory is left alone for the user to delete.
        assert_eq!(names(&dir), [".env", "group.json", "teagarden.session"]);
    }

    #[test]
    fn import_without_a_group_record_works() {
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        std::fs::remove_file(dir.join("group.json")).unwrap();
        let dst = TempDir::new().unwrap();
        tg(dst.path())
            .args(["auth", "import"])
            .arg(&dir)
            .assert()
            .success();
        assert_eq!(names(dst.path()), [".env", "teagarden.session"]);
    }

    #[test]
    fn import_refuses_to_overwrite_without_force_and_changes_nothing() {
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        // Any one existing file is enough to refuse.
        for existing in [".env", "group.json", "teagarden.session"] {
            let dst = TempDir::new().unwrap();
            std::fs::write(dst.path().join(existing), b"mine").unwrap();
            let before = snapshot(dst.path());
            tg(dst.path())
                .args(["auth", "import"])
                .arg(&dir)
                .assert()
                .failure()
                .stderr(predicate::str::contains("--force"));
            assert_eq!(
                snapshot(dst.path()),
                before,
                "{existing}: nothing may change"
            );
        }
    }

    #[test]
    fn import_force_replaces_the_existing_files_and_leaves_no_temp_files() {
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        let dst = TempDir::new().unwrap();
        seed_config(dst.path());
        std::fs::write(dst.path().join(".env"), "TG_API_ID=1\nTG_API_HASH=old\n").unwrap();
        tg(dst.path())
            .args(["auth", "import", "--force"])
            .arg(&dir)
            .assert()
            .success();
        assert_eq!(
            std::fs::read(dst.path().join(".env")).unwrap(),
            std::fs::read(dir.join(".env")).unwrap()
        );
        assert_eq!(
            std::fs::read(dst.path().join("teagarden.session")).unwrap(),
            std::fs::read(dir.join("teagarden.session")).unwrap()
        );
        assert_eq!(
            names(dst.path()),
            [".env", "group.json", "teagarden.session"]
        );
        for n in names(dst.path()) {
            assert_eq!(mode(&dst.path().join(&n)), 0o600, "{n}");
        }
    }

    #[test]
    fn import_force_keeps_this_computers_volumes_dir() {
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        let dst = TempDir::new().unwrap();
        seed_config(dst.path());
        std::fs::write(
            dst.path().join(".env"),
            "TG_API_ID=1\nexport TEAGARDEN_VOLUMES_DIR=/mine/volumes\nTG_API_HASH=old\n",
        )
        .unwrap();
        tg(dst.path())
            .args(["auth", "import", "--force"])
            .arg(&dir)
            .assert()
            .success();
        let env = std::fs::read_to_string(dst.path().join(".env")).unwrap();
        assert_eq!(
            env,
            format!(
                "TG_API_ID=12345\nTG_API_HASH={FAKE_HASH}\nTELEGRAM_BOT_TOKEN_1={FAKE_BOT}\n\
                 TEAGARDEN_VOLUMES_DIR=/mine/volumes\n"
            )
        );
    }

    #[test]
    fn import_refuses_a_signed_out_session_and_writes_nothing() {
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        write_fake_session(&dir.join("teagarden.session"), false);
        let root = TempDir::new().unwrap();
        let dst = root.path().join("teagarden");
        tg(&dst)
            .args(["auth", "import"])
            .arg(&dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("not signed in"));
        assert!(!dst.exists(), "nothing may be left behind");

        // Also with --force over an existing config: it stays as it was.
        let existing = TempDir::new().unwrap();
        seed_config(existing.path());
        let before = snapshot(existing.path());
        tg(existing.path())
            .args(["auth", "import", "--force"])
            .arg(&dir)
            .assert()
            .failure();
        assert_eq!(snapshot(existing.path()), before);
    }

    #[test]
    fn import_refuses_files_that_are_not_a_session_database() {
        let moved = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        type Make = fn(&Path);
        let cases: [(&str, Make); 3] = [
            ("garbage", |p| {
                std::fs::write(p, b"not a database at all, just text\n").unwrap()
            }),
            ("empty", |p| std::fs::write(p, b"").unwrap()),
            ("other-tables", |p| {
                let db = rusqlite::Connection::open(p).unwrap();
                db.execute_batch(
                    "CREATE TABLE peer_info (peer_id INTEGER); \
                     INSERT INTO peer_info VALUES (1); PRAGMA user_version = 1;",
                )
                .unwrap();
            }),
        ];
        for (label, make) in cases {
            let dir = moved.path().join(label);
            seed_transfer_dir(&dir);
            std::fs::remove_file(dir.join("teagarden.session")).unwrap();
            make(&dir.join("teagarden.session"));
            let dst = root.path().join(label);
            tg(&dst)
                .args(["auth", "import"])
                .arg(&dir)
                .assert()
                .failure()
                .stderr(predicate::str::contains("session"));
            assert!(!dst.exists(), "{label}: nothing may be left behind");
        }
    }

    #[test]
    fn import_refuses_a_session_with_another_schema_version() {
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        let db = rusqlite::Connection::open(dir.join("teagarden.session")).unwrap();
        db.execute_batch("PRAGMA user_version = 9;").unwrap();
        drop(db);
        let root = TempDir::new().unwrap();
        let dst = root.path().join("t");
        tg(&dst)
            .args(["auth", "import"])
            .arg(&dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("version"));
        assert!(!dst.exists());
    }

    #[test]
    fn import_refuses_symbolic_links_and_missing_files() {
        let moved = TempDir::new().unwrap();
        let elsewhere = moved.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        seed_transfer_dir(&elsewhere.join("real"));
        let root = TempDir::new().unwrap();

        for file in [".env", "group.json", "teagarden.session"] {
            let tag = file.trim_start_matches('.');
            let dir = moved.path().join(format!("link-{tag}"));
            seed_transfer_dir(&dir);
            std::fs::remove_file(dir.join(file)).unwrap();
            symlink(elsewhere.join("real").join(file), dir.join(file)).unwrap();
            let dst = root.path().join(format!("dst-{tag}"));
            tg(&dst)
                .args(["auth", "import"])
                .arg(&dir)
                .assert()
                .failure()
                .stderr(predicate::str::contains("symbolic link"));
            assert!(!dst.exists(), "{file}: nothing may be left behind");
        }

        // The directory itself may not be a link either.
        let link_dir = moved.path().join("dirlink");
        symlink(elsewhere.join("real"), &link_dir).unwrap();
        let dst = root.path().join("dst-dirlink");
        tg(&dst)
            .args(["auth", "import"])
            .arg(&link_dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("symbolic link"));
        assert!(!dst.exists());

        // A required file that is missing is named.
        for file in [".env", "teagarden.session"] {
            let tag = file.trim_start_matches('.');
            let dir = moved.path().join(format!("missing-{tag}"));
            seed_transfer_dir(&dir);
            std::fs::remove_file(dir.join(file)).unwrap();
            let dst = root.path().join(format!("dst-missing-{tag}"));
            tg(&dst)
                .args(["auth", "import"])
                .arg(&dir)
                .assert()
                .failure()
                .stderr(predicate::str::contains(file));
            assert!(!dst.exists());
        }
    }

    #[test]
    fn import_refuses_an_existing_target_that_is_not_a_regular_file_even_with_force() {
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        let dst = TempDir::new().unwrap();
        seed_config(dst.path());
        std::fs::remove_file(dst.path().join("group.json")).unwrap();
        std::fs::create_dir(dst.path().join("group.json")).unwrap();
        std::fs::write(dst.path().join("group.json").join("keep"), "x").unwrap();
        let before_env = std::fs::read(dst.path().join(".env")).unwrap();
        let before_session = std::fs::read(dst.path().join("teagarden.session")).unwrap();
        tg(dst.path())
            .args(["auth", "import", "--force"])
            .arg(&dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("not a regular file"));
        assert_eq!(std::fs::read(dst.path().join(".env")).unwrap(), before_env);
        assert_eq!(
            std::fs::read(dst.path().join("teagarden.session")).unwrap(),
            before_session
        );
        assert!(dst.path().join("group.json").join("keep").exists());
        assert_eq!(
            names(dst.path()),
            [".env", "group.json", "teagarden.session"]
        );
    }

    #[test]
    fn import_that_fails_while_reading_leaves_the_config_exactly_as_it_was() {
        // Running as root ignores file modes, so the failure cannot be made.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        std::fs::set_permissions(
            dir.join("group.json"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let dst = TempDir::new().unwrap();
        seed_config(dst.path());
        let before = snapshot(dst.path());
        tg(dst.path())
            .args(["auth", "import", "--force"])
            .arg(&dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("group.json"));
        assert_eq!(snapshot(dst.path()), before);

        let root = TempDir::new().unwrap();
        let fresh = root.path().join("t");
        tg(&fresh)
            .args(["auth", "import"])
            .arg(&dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("group.json"));
        assert!(!fresh.exists(), "no directory may be left behind");
    }

    #[test]
    fn import_drops_paths_of_the_old_computer_from_the_settings() {
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        std::fs::write(
            dir.join(".env"),
            format!(
                "TG_API_ID=12345\nTG_API_HASH={FAKE_HASH}\n\
                 TEAGARDEN_SESSION_PATH=/old/computer/teagarden.session\n\
                 TEAGARDEN_VOLUMES_DIR=/old/computer/volumes\nTELEGRAM_BOT_TOKEN_1={FAKE_BOT}\n"
            ),
        )
        .unwrap();
        let dst = TempDir::new().unwrap();
        tg(dst.path())
            .args(["auth", "import"])
            .arg(&dir)
            .assert()
            .success();
        let env = std::fs::read_to_string(dst.path().join(".env")).unwrap();
        assert_eq!(
            env,
            format!("TG_API_ID=12345\nTG_API_HASH={FAKE_HASH}\nTELEGRAM_BOT_TOKEN_1={FAKE_BOT}\n")
        );
        assert!(dst.path().join("teagarden.session").exists());
    }

    #[test]
    fn import_writes_the_session_where_this_computer_looks_for_it() {
        let moved = TempDir::new().unwrap();
        let dir = moved.path().join("d");
        seed_transfer_dir(&dir);
        let dst = TempDir::new().unwrap();
        let custom: PathBuf = dst.path().join("elsewhere").join("my.session");
        std::fs::create_dir(dst.path().join("elsewhere")).unwrap();
        tg(dst.path())
            .env("TEAGARDEN_SESSION_PATH", &custom)
            .args(["auth", "import"])
            .arg(&dir)
            .assert()
            .success();
        assert!(custom.exists(), "the session goes to this computer's path");
        assert_eq!(mode(&custom), 0o600);
        assert!(!dst.path().join("teagarden.session").exists());
        // Later runs, which read the `.env` but not this shell variable, find it.
        let env = std::fs::read_to_string(dst.path().join(".env")).unwrap();
        assert!(
            env.contains(&format!("TEAGARDEN_SESSION_PATH={}\n", custom.display())),
            "{env}"
        );
    }
}

#[test]
fn round4_help_describes_current_command_boundaries() {
    let mut cases: Vec<(&[&str], &[&str])> = vec![
        (
            &["keyslot", "--help"],
            &["publish slot changes to Telegram"],
        ),
        (
            &["keyslot", "enroll", "--help"],
            &[
                "Publishes the changed slot vault to Telegram",
                "Only this Tang slot requires the server",
                "changed selected PCR values refuse unseal",
            ],
        ),
        (
            &["keyslot", "remove-slot", "--help"],
            &["Publishes the changed slot vault to Telegram"],
        ),
        (
            &["volume", "history", "--help"],
            &[
                "TGFV history reads Telegram directly",
                "does not require a local metadata DB",
            ],
        ),
        (
            &["volume", "diff", "--help"],
            &[
                "TGFV diff reads Telegram directly",
                "does not require a local metadata DB",
            ],
        ),
        (
            &["volume", "add-bot", "--help"],
            &[
                "legacy and block transport",
                "TGFV uploads use the user session",
            ],
        ),
        (&["volume", "restore", "--help"], &["Legacy-only"]),
        (&["volume", "republish", "--help"], &["Legacy-only"]),
        (&["man", "--help"], &["teagarden man | gzip"]),
    ];
    if cfg!(feature = "dev") {
        cases.push((
            &["dev", "recover", "--help"],
            &["Requires this device's local registry record"],
        ));
    }
    let mut missing = Vec::new();
    for (args, expected) in cases {
        let out = teagarden().args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        let help = String::from_utf8(out.stdout)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for phrase in expected {
            if !help.contains(phrase) {
                missing.push(format!("{args:?}: {phrase}"));
            }
        }
        assert!(!help.contains("anti-evil-maid"));
        assert!(!help.contains("TeaGarden man |"));
    }
    assert!(
        missing.is_empty(),
        "missing factual help text: {missing:#?}"
    );
}
