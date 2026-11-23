# Contributing to TeaGarden

Thank you for your interest in contributing.

## The one rule

**Everything this project claims must be true, and observed.** No stubs that
present as features, no simulated success, no tests that pass because they
skipped. If something is not finished, say so in the code, the CLI help and the
docs. A pull request that adds a capability must show it working at the level a
user experiences it: through the `teagarden` command, a real mount, or a real
client.

## Getting started

### Prerequisites

- Rust 1.89+ (install via [rustup](https://rustup.rs))
- A C compiler and FUSE 3:
  - **Debian/Ubuntu**: `sudo apt install build-essential libclang-dev fuse3`
  - **macOS**: install [macFUSE](https://macfuse.github.io/), approve its system
    extension, reboot; install `pkg-config`

### Build and test

```bash
git clone https://github.com/arf-io/teagarden-fs.git teagarden
cd teagarden
cargo build
cargo test --workspace
```

Some suites need real FUSE, a software TPM, SoftHSM or a Tang server and skip
when those are missing. Set the `TEAGARDEN_REQUIRE_*` variables listed in
[`docs/ENVIRONMENT_VARIABLES.md`](docs/ENVIRONMENT_VARIABLES.md#test-suite) to make
a missing prerequisite a failure instead of a skip. Shell end-to-end scripts are in
`scripts/test/`.

### Project structure

```
crates/
  teagarden-core/       Crypto, key hierarchy, block format, volume config (no network I/O)
  teagarden-store/      SQLite metadata store with encrypted rows
  teagarden-telegram/   Telegram transport (MTProto user client and Bot API)
  teagarden-cache/      Local encrypted block cache
  teagarden-fuse/       FUSE filesystem
  teagarden-sharing/    ML-KEM-768 sharing grants
  teagarden-mfa/        Key slots: password, recovery sentence, TPM2, PKCS#11, Tang, FIDO2
  teagarden-api/        Service layer used by the CLI (no network server)
  teagarden-dev/           Encrypted, log-structured block device engine
  teagarden-blockdev/   Block-device trait shared by the device and its exports
  teagarden-nbd/        NBD export for block devices
  teagarden-cli/        Command-line interface (`teagarden`)
  teagarden-transport-test/  Live-Telegram test harnesses (not published)
```

## Submitting code

1. Fork the repository and branch from `main`.
2. Write the test first. For a bug fix, the test must fail before your change.
3. Make sure these pass:
   ```bash
   cargo fmt --all -- --check
   RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets
   cargo test --workspace
   ```
4. Open a pull request that explains what changed, why, and how you verified it.

## Security requirements

This is a cryptographic storage system. Contributions must:

- never log or print key material, passwords, tokens or session data;
- use constant-time comparison for secret data;
- zeroize sensitive data on drop;
- bind context into the AEAD associated data for every new encryption;
- validate all input at boundaries (CLI arguments, files on disk, data downloaded from Telegram);
- avoid `unsafe` unless it is justified, documented and reviewed;
- **not change an on-disk or wire format** without a version gate and a test
  proving that existing volumes still open.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Community

Be respectful and constructive, and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
