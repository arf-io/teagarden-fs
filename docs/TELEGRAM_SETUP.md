# Telegram setup

TeaGarden stores encrypted data in your own Telegram account. It connects as your
user account, so it needs an API ID and API hash that identify the
application to Telegram. The source tree contains no application credentials:
each user gets their own from Telegram, unless they use a binary that a publisher
built with `TEAGARDEN_BUILD_API_ID` and `TEAGARDEN_BUILD_API_HASH` set, which then
carries that publisher's pair (see below).

Telegram's Terms of Service and API Terms of Service apply to your use.
TeaGarden is an independent project, not affiliated with, endorsed by, or
sponsored by Telegram.

## 1. Get an API ID and API hash

1. Open [my.telegram.org](https://my.telegram.org) in a browser.
2. Log in with the phone number of your Telegram account and the confirmation
   code Telegram sends you.
3. Choose **API development tools**.
4. Fill in the application form. The title and short name are for your own
   reference; TeaGarden does not use them.
5. Submit. The page shows your **api_id** (a number) and **api_hash** (a
   32-character hexadecimal string).

Treat the API hash like a password. Do not paste it into chat, issue trackers,
screenshots, logs or shared shell history.

## 2. Give them to TeaGarden

Pick one of these.

**The setup wizard.**

```bash
teagarden configure
```

It asks for the API ID and hash, a volumes directory and a session file path. The
hash is typed hidden (nothing is shown as you type) and must be 32 hexadecimal
characters. It writes them to `.env` in the configuration directory with mode 0600
(owner read and write only). The file is written to a new temporary file created
with mode 0600 and then renamed over `.env`, so others can never read it. It first
offers to open my.telegram.org in your browser (pressing Enter answers yes). It
leaves your shell's startup files alone: `teagarden` reads its `.env` on every
start, and loading the file into your shell would hand the API hash to every program you start.

**Environment variables.**

```bash
export TG_API_ID=12345678
export TG_API_HASH=0123456789abcdef0123456789abcdef
teagarden auth login
```

Values already in the environment take precedence over `.env`.

`auth login` also accepts `--api-id` and `--api-hash`; a value on the command
line is visible to other users through the process list and is saved in shell
history. Use `.env` or the environment instead.

**A binary built with application credentials.** A publisher can build
`teagarden` with `TEAGARDEN_BUILD_API_ID` and `TEAGARDEN_BUILD_API_HASH` set; such
a binary needs no API ID or hash from you, only the phone login. Every command
uses the built-in pair when you have configured neither value, so anything you
set yourself (flag, environment, `.env`) still wins. See
[ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md#build-time).

`--help` never prints the current values of `TG_API_ID` and `TG_API_HASH`: these
options use clap's `hide_env_values`, so the help text names the variables without
showing what they contain.

## 3. Where the credentials live

The configuration directory is:

| Platform | Default |
|---|---|
| Linux | `$XDG_CONFIG_HOME/teagarden`, or `~/.config/teagarden` |
| macOS | `~/Library/Application Support/teagarden` |
| Any | `$TEAGARDEN_CONFIG_DIR`, if set and not empty |

Relevant files in it:

| File | Contents | Mode |
|---|---|---|
| `.env` | `TG_API_ID`, `TG_API_HASH`, optional paths | 0600 |
| `teagarden.session` | Your logged-in Telegram session (unless `TEAGARDEN_SESSION_PATH` points elsewhere) | 0600 |
| `group.json` | The id of the private storage group TeaGarden created | 0600 |

`.env` is a plain `KEY=VALUE` file. Every key in it is loaded into the process
environment when it is not already set, except `TEAGARDEN_CONFIG_DIR` (which
decides where `.env` itself is).

None of these files is encrypted. The session file gives access to
your Telegram account; anyone who can read it can act as you on Telegram. Keep
the configuration directory private and out of backups that other people can
read.

## 4. Log in

```bash
teagarden auth login
teagarden auth status
```

`auth login` asks for your phone number (with country code), the login code, and
your two-step verification password if you have one. You get three tries at the
code and three at the password. When no API ID and hash are configured it asks
for them first and always saves them to `.env` (mode 0600, other lines kept) and
prints where; if that write fails, the login still completes and the command then
exits non-zero and says the settings were not saved.

### Where the login code arrives

Telegram decides how to deliver the code. Normally it is a message from
**Telegram** in the Telegram app on a device where the account is already signed
in. If no device is signed in, Telegram sends an SMS, calls, or sends the code
through Fragment.
`auth login` prints this list after it requests the code. It cannot say which
route Telegram chose, because the Telegram library TeaGarden uses discards that
part of the reply, and it cannot request the code again by another route
(`auth.resendCode`) because that library keeps the needed code hash private. If no
code arrives, check the phone number and run `teagarden auth login` again.
Telegram limits how many codes it sends per number per day.

### Set up a second computer

#### Set up another computer without a code

On the new computer, use QR login:

```bash
teagarden auth login --qr
```

Scan the terminal QR in Telegram mobile under **Settings → Devices → Link
Desktop Device**. Leave TeaGarden running while it waits for Telegram to approve
the login. If Telegram requires a cloud password, enter it at the prompt or
provide `--cloud-password-file PATH`.

On a computer already logged in to the account, approve the URI printed by the
new computer:

```bash
teagarden auth approve 'tg://login?token=...'
```

Approval grants the new computer full access to this Telegram account. Approve a
token only when you started the login yourself. TeaGarden requires typing `YES`
in a terminal. A script can supply the URI on standard input with
`teagarden auth approve - --yes`, keeping the one-time URI out of the command's
arguments. Telegram Settings → Devices can revoke the computer's separate
authorization later.

For an installation you may want to revoke individually from a Tea Garden FS
volume, approve its QR login directly from the volume owner's TeaGarden profile.
Record the `Hash:` in that approval's response and the installation UUID once the
new computer mounts the volume. Telegram can display the current session's own
hash as `0`. The authorization returned to the approving owner identifies the
specific URI that owner just approved. Keep the pairing record private. If a
phone previously approved the login and you cannot identify it from an existing
owner approval record, leave that login in place and start a separate QR login
that the owner can approve directly. Device names, IP addresses and login times
can coincide.

Copy the login instead of signing in again:

```bash
# on the computer that is set up
teagarden auth export ~/to-move

# move ~/to-move to the new computer over a channel you trust, then there:
teagarden auth import ~/to-move
```

`auth export` writes `.env`, `group.json` (if present)
and `teagarden.session` into the directory. It creates the directory with mode 0700 (it must be empty or
not exist) and each file with mode 0600, and refuses a session that is not signed
in. The lines `TEAGARDEN_SESSION_PATH` and `TEAGARDEN_VOLUMES_DIR` are left out of
the exported `.env`: they name paths on the old computer.

`auth import` checks the files before it writes anything: they must be regular
files (not symbolic links) and the session must be a TeaGarden session database
with a completed sign-in. It refuses to replace an existing `.env`, `group.json`
or session unless you add `--force`; with `--force` the `TEAGARDEN_VOLUMES_DIR` line
of this computer's own `.env` is kept. It installs the files with mode 0600, writes
the session to the path this computer uses (recording it in `.env` when that is
not `teagarden.session` in the configuration directory), rolls back if any step fails, and
prints `auth status`.

The directory holds the login to your Telegram account, unencrypted. Move it only
over a channel you trust, and delete it on both computers once the import
succeeds. Use the login on one computer at a time: Telegram invalidates a session
that sends requests from two connections at once (`AUTH_KEY_DUPLICATED`,
[core.telegram.org/api/errors](https://core.telegram.org/api/errors)), and then
you sign in again with `teagarden auth login`. For concurrent mounts, sign in separately on each computer and attach the volume.
See [USER_GUIDE.md](USER_GUIDE.md#mounting).

Volume configuration (the per-volume files under the volumes directory) and
`identity.keypair` are not part of the export.

To log out on this machine, run `teagarden auth logout`, which deletes the local
session file. To end the session on Telegram's side as well, terminate it from
**Settings → Devices** in a Telegram app.

## 5. What TeaGarden creates in your account

- **One private group**, created on your first `volume create` or `dev create`
  and reused afterwards. It is a forum-style supergroup; when creating it,
  TeaGarden also asks Telegram to turn automatic message deletion off. Its title is random unless you set `--group-name`.
- **One topic per volume or device**, with a random title (random words, like
  the group title). Your names for volumes and devices stay on your computer.
- **Documents** in volume topics: owner-signed TGHD headers and encrypted TGFV
  file versions. The separate block device stores encrypted segments and checkpoints.

Leave the group's messages and settings alone and do not post in the group.
Deleting a document deletes the data in it.
