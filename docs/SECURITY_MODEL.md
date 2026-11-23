# Security model

TeaGarden encrypts file contents locally before storing them in your Telegram
account. Each new file version is a segmented, authenticated TGFV document with
its own credential envelope. The owner signs the TGHD2 volume header. See
[OBJECT_FORMAT.md](OBJECT_FORMAT.md) for the framing and cryptographic details.

While a file is being written, its local spool stores encrypted, authenticated blocks under a key derived from the volume hierarchy and intent ID; only bounded working buffers hold plaintext in memory.

Telegram can observe your account and network address, group and topic titles,
message timing, document sizes and counts. TGHD contains public framing and TGFV
has a public prefix; traffic is not padded. Local configuration, session files
and owner signing capability need filesystem protection. The owner public key
should be copied through a trusted channel and pinned on attach; a password alone
does not independently identify the owner.

Concurrent read-write mounts poll the topic. The last write wins, all versions
remain, and no conflict copies are made. Retain independent backups: Telegram may
remove data and credentials may be lost. Downloaded self-describing objects can
be decrypted with their password or recovery sentence. An object made before a
credential change retains its original credential.

Device revoke asks for the existing volume password to open the volume and does
not change it. The owner signing key is kept separately in `owner-signing.key`
with mode 0600; the volume password does not protect that file. Without a
terminal, use `--password-file PATH` or `--recovery-file PATH`. Revoke works while the owner volume is mounted on the
same computer. Revoke immediately stops the device reaching the volume
through Telegram by banning its account from the group or ending its specific
session, and publishes an owner-signed record. The volume key does not change.
A removed device that obtains encrypted files another way can still decrypt them with the password it knows. Key rotation is planned for a later
release. Revocation cannot recall plaintext or ciphertext already copied.

With the current signed policy, readers reject later writes claiming the revoked
installation ID. Revoke freezes the signing keys of non-revoked registered
installations. A write claiming a frozen ID must carry a valid signature from its
exact key; absent or wrong-key signatures are rejected, including in directory
decrypt with `--include-unverified`. A registered survivor without an authenticated
signing key makes revoke refuse before the access cut. If a removed device can
upload through another route, it can use a new, never-seen installation ID;
readers accept it as a new author, including for writes to existing paths.

Existing installations persist and enforce their highest authenticated owner
header revision across mount startup, live polling, history, diff, restore-version,
export and device list, including after restart. Losing or rolling back trusted
local installation state is outside that protection. A new attach has no prior
revision observation: the owner pin authenticates the owner but cannot establish
that the latest header was delivered. Establish freshness separately.

Directory decrypt restores files and explicit visible empty directories, including
nested empty directories, modes and modification times. Export selects the
authenticated header and accepted file objects by content, not Telegram filename.

A key-protected volume can use password, recovery and hardware-factor slots.
FIDO2 supports `pin-up` and `up` enrollment; its hardware test remains pending.
Software-backed factor tests do not establish hardware behavior. See
[USER_GUIDE.md](USER_GUIDE.md#key-slots). The separate block device has its own
[durability and recovery model](BLOCK_DEVICE.md).
