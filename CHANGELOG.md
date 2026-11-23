# Changelog

## 1.0.0

TeaGarden provides a personal encrypted filesystem backed by the user's own
Telegram account, and a separate encrypted block device.

- Each file version is a self-describing, segmented encrypted TGFV document,
  with supported new-save plaintext maxima of 2,092,860,184 bytes on ordinary
  accounts and 4,189,980,184 bytes with Premium. TGHD2 headers are owner-signed.
- `volume attach` reconstructs a volume from Telegram and supports owner-key
  pinning. Multiple computers can mount read-write and poll for changes; the last
  write wins, all versions are retained, and no conflict copies are made.
- `volume history` follows file identity across renames and shows full UUIDs;
  `volume diff` compares content and `volume restore-version` publishes a selected
  version as a new current version. Numeric `volume revert` is legacy-only.
- `device list` and `device revoke` manage installations. Revoke cuts Telegram
  access immediately and publishes a signed record. It asks for the existing
  volume password to open the volume; it does not change the password or key.
  The owner signing key is stored separately and is not protected by that password.
  A removed device obtaining encrypted files elsewhere can still decrypt them
  with the password it knows. Frozen registered writer IDs require their exact
  signing keys; new IDs remain accepted. Revoke can run while the owner's volume
  is mounted. Key rotation is planned for a later release.
- Existing installations persist and enforce the highest authenticated header
  revision. A fresh attach has no prior revision observation.
- Export selects authenticated documents by content. Directory decrypt restores
  files and explicit visible empty directories, including modes and mtimes.
- `auth export` and `auth import` transfer a login. Key-protected volumes support
  recovery and hardware-factor slots; FIDO2 `pin-up` and `up` hardware testing
  remains pending.
- Symbolic links are refused with `ENOTSUP` on portable volumes.
