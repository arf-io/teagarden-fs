# Frequently asked questions

## Can I use more than one computer?

Yes. Establish separate Telegram authorizations, then attach the volume using its
group and topic and pin the owner public key. Concurrent read-write mounts poll
the topic. The last write wins; all versions are retained without conflict copies.

## Can I recover a file without the volume directory?

A new self-describing TGFV document can be decrypted with `teagarden decrypt`
and its password or recovery sentence. Attach reconstructs a volume from its
Telegram topic. Preserve the owner public key for independent pinning.

## What happens when I revoke a device?

Revoke asks for the existing volume password to open the volume and does not
change it. The owner signing key is kept separately in `owner-signing.key` with
mode 0600; the volume password does not protect that file. Revoke immediately
stops the device reaching the volume through Telegram by banning its account from the group or ending its specific session,
and publishes a signed record. The volume key does not change.
A removed device that obtains encrypted files another way can still decrypt them
with the password it knows. Key rotation is planned for a later release. If it
can upload by another route, later writes under its revoked ID are rejected and
claims to frozen registered IDs need their exact signing keys. A new, never-seen
ID remains accepted as a new author. Existing installations enforce a persisted
header-revision floor; a fresh attach needs a separate freshness check. See the
[security model](SECURITY_MODEL.md).

## What is the file-size limit?

The supported new-save plaintext maximum is 2,092,860,184 bytes on ordinary
accounts, or 4,189,980,184 bytes with Premium. Each version is a single document.

## Are symbolic links supported?

No. Portable volumes refuse them with `ENOTSUP`. See the [user guide](USER_GUIDE.md).
