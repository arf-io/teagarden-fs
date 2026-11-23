# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities **privately**, using GitHub's
"Report a vulnerability" button on this repository's **Security** tab
(private vulnerability reporting). Keep exploits, secrets, volume material and
anything that identifies a user out of public issues.

Reports are acknowledged within 7 days. Fixes for confirmed issues are
released as patch versions and described in [`CHANGELOG.md`](CHANGELOG.md).

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |

## What TeaGarden protects, and what it does not

The security model, cryptographic design and limits are documented
in [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md). In short: Telegram stores
only ciphertext and never receives your keys. Telegram sees your account, how much
you store, the exact size of each stored object (a volume block is its plaintext
plus 40 bytes), and when you read or write.
