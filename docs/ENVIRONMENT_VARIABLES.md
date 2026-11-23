# Environment variables

Every variable below is read in the TeaGarden source or its helper
scripts; the source location is given for each. Values in the process environment
take precedence over the configuration `.env` file. When `teagarden` starts, it
loads every `KEY=VALUE` line of `.env` (in the configuration directory) into its
environment unless that key is already set, except `TEAGARDEN_CONFIG_DIR`.

## Telegram

| Variable | Used for | Read in |
|---|---|---|
| `TG_API_ID` | Telegram API ID (a positive integer). Also accepted as `auth login --api-id`. | `crates/teagarden-cli/src/main.rs` (clap `env`), `commands/utils.rs` |
| `TG_API_HASH` | Telegram API hash. Also accepted as `auth login --api-hash`. | same |

`--help` does not print the values of `TG_API_ID` or `TG_API_HASH` (clap
`hide_env_values`).

## Locations

| Variable | Default | Read in |
|---|---|---|
| `TEAGARDEN_CONFIG_DIR` | `~/.config/teagarden` (Linux, or `$XDG_CONFIG_HOME/teagarden`), `~/Library/Application Support/teagarden` (macOS). Names the directory itself. Ignored if set inside `.env`. | `commands/utils.rs`, `config_dir` |
| `TEAGARDEN_SESSION_PATH` | `teagarden.session` in the configuration directory | `commands/utils.rs`, `session_file_path` |
| `TEAGARDEN_VOLUMES_DIR` | `~/.local/share/teagarden/volumes` (Linux), `~/Library/Application Support/teagarden/volumes` (macOS) | `crates/teagarden-core/src/volume/manager.rs`, `default_volumes_dir` |
| `TEAGARDEN_DEV_REGISTRY_DIR` | `~/.local/share/teagarden/devices` (Linux), `~/Library/Application Support/teagarden/devices` (macOS) | `commands/dev.rs`, `registry_dir` |
| `HOME` | Used to find the cache directory when the platform cache directory is unknown, and by the platform directory lookups | `crates/teagarden-cache/src/block_cache.rs` |

`teagarden configure` writes `TEAGARDEN_VOLUMES_DIR` and `TEAGARDEN_SESSION_PATH`
into `.env` along with the API credentials.

## Secrets for non-interactive use

| Variable | Used for | Read in |
|---|---|---|
| `TEAGARDEN_DEV_PASSWORD` | Block-device credential, used by `dev` commands when `--password-file` is not given | `commands/dev.rs`, `read_credential` |
| `TEAGARDEN_FACTOR_PIN` | PKCS#11 user PIN for `keyslot enroll/unlock/remove-slot` and `volume mount` with `--pkcs11-module`, instead of a prompt | `commands/mfa.rs`, `prompt_pin` |

A variable holding a secret is visible to other processes of the same user (for
example through `/proc/<pid>/environ` on Linux). Use `--password-file` with a
mode-0600 file where a command offers it.

## Logging and other

| Variable | Used for | Read in |
|---|---|---|
| `RUST_LOG` | Log filter (default `warn`). `-v` / `--verbose` overrides it with `debug`. | `crates/teagarden-cli/src/main.rs` |
| `PATH` | Where `age-plugin-fido2-hmac`, `tpm2-tools` and `clevis` are looked up | `crates/teagarden-mfa/src/kslot/protectors/` |

## Helper scripts

| Variable | Used for | Read in |
|---|---|---|
| `TEAGARDEN_BIN` | The `teagarden` binary to run (default: `teagarden` on `PATH`) | `scripts/mount.teagarden`, `scripts/umount.fuse.teagarden`, `scripts/teagarden-dev-attach` |
| `TEAGARDEN_DEV_STOP_TIMEOUT` | Seconds `teagarden-dev-attach --detach` waits for `dev serve nbd` to finish its final upload and checkpoint (default 840; the systemd unit's `TimeoutStopSec` is 900) | `scripts/teagarden-dev-attach` |

## Build time

| Variable | Used for | Read in |
|---|---|---|
| `TEAGARDEN_BUILD_API_ID`, `TEAGARDEN_BUILD_API_HASH` | If both are set when compiling, the binary carries these application credentials and every command that connects to Telegram uses them when you configured neither an API ID nor a hash | `commands/utils.rs` (`option_env!`, `resolve_credentials`) |

Every command resolves the credentials the same way: for each of the two values,
the `--api-id` / `--api-hash` flag (only `auth login` has them), then the
environment, then the `.env` file; empty values count as unset. Only if neither
value is set anywhere is the built-in pair used, and only as a pair: an ID you
set is never combined with a built-in hash. An invalid value is an error, not a
reason to try the next source. Built-in credentials can be read out of the
binary and are public.

## Test suite

These make a missing prerequisite a test failure instead of a skip:
`TEAGARDEN_REQUIRE_FUSE`, `TEAGARDEN_REQUIRE_TPM`, `TEAGARDEN_REQUIRE_HSM`,
`TEAGARDEN_REQUIRE_TANG`, `TEAGARDEN_REQUIRE_FIDO2`. They are read only by the
tests, not by the `teagarden` binary.

`TEAGARDEN_DEV_P1_REPORT` names the file the unpublished live-Telegram probe
`p1-feasibility` (in `teagarden-transport-test`) writes its report to; without it
the report goes to `teagarden-dev-p1-go-nogo.md` in the system temp directory.
