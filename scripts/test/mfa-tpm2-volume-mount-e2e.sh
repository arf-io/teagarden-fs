#!/usr/bin/env bash
# K5/PUB-005 e2e — prove a TPM2 device factor can MOUNT a volume through
# `volume mount`, not just pass the offline `mfa unlock` check.
#
# Before this fix, `mfa unlock --tpm2` could prove the factor decrypts the
# vault, but `volume mount` accepted only --password-file/--recovery-file —
# there was no way to reach the CLI's actual primary operation (mounting) with
# a device factor at all. This script drives the real binary through: create
# a real (Telegram-backed) key-protected volume -> enroll TPM2 -> `volume
# mount --tpm2` (no password, no recovery file) -> real FUSE write/read,
# genuinely round-tripping through Telegram -> `volume unmount` -> delete the
# test volume (including its real Telegram blocks).
#
# LIVE: unlike the sibling mfa-tpm2-cli-e2e.sh (which only proves enroll+
# unlock and can stay fully offline), this script's whole point is proving a
# real FUSE *mount* serves real I/O, which needs a real forum topic to upload
# to — an offline test volume has no group/topic and `volume mount` refuses
# to serve one. Requires Telegram credentials already configured
# (`teagarden auth login` / `~/.config/teagarden/.env`).
#
#   Requires: swtpm, swtpm_setup, tpm2-tools, FUSE (fusermount/fusermount3),
#             an authenticated Telegram session.
#   Usage:    scripts/test/mfa-tpm2-volume-mount-e2e.sh
#   Exit 0 = TPM2 alone authenticated AND mounted a real Telegram-backed
#            volume AND served real file I/O on it (the written block
#            genuinely uploads on unmount-drain — this script's cleanup then
#            deletes it via the real per-block Telegram deletion path, which
#            only finds something to delete if the upload really happened).
set -uo pipefail

BIN="${BIN:-target/debug/teagarden}"
PASSPHRASE="correct-horse-battery-staple-$$"
WORK="$(mktemp -d)"
MNT="$WORK/mnt"
VOL_NAME="tpm2-mount-e2e-$$"
SWTPM_PID=""
VOL_ID=""
mkdir -p "$MNT"

cleanup() {
  "$BIN" volume unmount "$MNT" >/dev/null 2>&1
  # Escalate straight to a lazy unmount + killing the mount process if a
  # plain unmount didn't clear it (e.g. a blocked FUSE read under a Telegram
  # flood-wait, which is uninterruptible and won't respond to a normal
  # unmount at all) — otherwise this cleanup can itself hang forever.
  if findmnt "$MNT" >/dev/null 2>&1; then
    fusermount3 -uz "$MNT" >/dev/null 2>&1 || fusermount -uz "$MNT" >/dev/null 2>&1
    pkill -9 -f "volume mount .* $MNT" >/dev/null 2>&1
  fi
  # Recovery fallback. The success path below requires and observes deletion;
  # this trap retries only when an earlier test step failed.
  if [ -n "$VOL_ID" ]; then
    echo "$PASSPHRASE" | timeout 120 "$BIN" volume delete "$VOL_ID" --force --password-file - >/dev/null 2>&1 || true
  fi
  [ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 && return
  if [ -n "${TEAGARDEN_REQUIRE_TPM:-}" ]; then
    echo "FAIL: TEAGARDEN_REQUIRE_TPM is set but $1 is not installed" >&2
    exit 1
  fi
  echo "SKIP: $1 not installed"
  exit 0
}
need swtpm; need swtpm_setup; need tpm2_createprimary; need tpm2_pcrread
need findmnt; need timeout
if ! command -v fusermount3 >/dev/null 2>&1 \
    && ! command -v fusermount >/dev/null 2>&1; then
  if [ -n "${TEAGARDEN_REQUIRE_FUSE:-}" ]; then
    echo "FAIL: TEAGARDEN_REQUIRE_FUSE is set but fusermount is not installed" >&2
    exit 1
  fi
  echo "SKIP: fusermount not installed"
  exit 0
fi

[ -x "$BIN" ] || { echo "build the CLI first: cargo build -p teagarden-cli"; exit 1; }

wait_mounted() { for _ in $(seq 1 "$1"); do findmnt "$MNT" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
wait_unmounted() { for _ in $(seq 1 30); do findmnt "$MNT" >/dev/null 2>&1 || return 0; sleep 1; done; return 1; }

# ── 1. software TPM ──────────────────────────────────────────────────────
SOCK="$WORK/swtpm.sock"
swtpm_setup --tpm2 --tpmstate "$WORK" --overwrite >/dev/null 2>&1
swtpm socket --tpm2 --tpmstate "dir=$WORK" \
  --server "type=unixio,path=$SOCK" --ctrl "type=unixio,path=$SOCK.ctrl" \
  --flags not-need-init,startup-clear >/dev/null 2>&1 &
SWTPM_PID=$!
export TPM2TOOLS_TCTI="swtpm:path=$SOCK"
for _ in $(seq 1 40); do tpm2_pcrread sha256:0 >/dev/null 2>&1 && break; sleep 0.15; done
tpm2_pcrread sha256:0 >/dev/null 2>&1 || { echo "FAIL: swtpm never became ready"; exit 1; }
echo "[1] software TPM up"

# ── 2. a REAL (Telegram-backed) key-protected volume ─────────────────────
# Not the offline mk_protected_volume test fixture: that volume has no forum
# group/topic, and `volume mount` correctly refuses to serve one (there is
# nowhere to fetch/upload real blocks), so it can't complete step 5 below.
OUT="$(echo "$PASSPHRASE" | "$BIN" volume create --name "$VOL_NAME" --key-protection --password-file - 2>&1)"
echo "$OUT" | tee "$WORK/create.log" >/dev/null
VOL_ID="$(echo "$OUT" | sed -n 's/^ *Volume ID: *//p')"
RECOVERY="$(echo "$OUT" | sed -n '/^RECOVERY SENTENCE/{n;s/^ *//;p}')"
[ -n "$VOL_ID" ] || { echo "FAIL: could not create the protected volume"; cat "$WORK/create.log"; exit 1; }
[ -n "$RECOVERY" ] || { echo "FAIL: could not parse the recovery sentence"; cat "$WORK/create.log"; exit 1; }
echo "$RECOVERY" > "$WORK/recovery.txt"
echo "[2] key-protected volume created: $VOL_ID"

# ── 3. enroll the TPM2 factor via the real CLI ───────────────────────────
"$BIN" mfa enroll "$VOL_ID" --tpm2 --recovery-file "$WORK/recovery.txt" | tee "$WORK/enroll.log"
grep -q "Enrolled TPM2 slot" "$WORK/enroll.log" || { echo "FAIL: enroll did not report success"; exit 1; }
echo "[3] TPM2 factor enrolled"

# ── 4. `volume mount --tpm2` — no password, no recovery file — must work ──
"$BIN" volume mount "$VOL_ID" "$MNT" --tpm2 > "$WORK/mount.log" 2>&1 &
MOUNT_PID=$!
wait_mounted 120 || { echo "FAIL: volume never mounted"; cat "$WORK/mount.log"; exit 1; }
grep -q "authenticated successfully via TPM2" "$WORK/mount.log" || {
  echo "FAIL: mount did not report TPM2 authentication"; cat "$WORK/mount.log"; exit 1
}
echo "[4] mounted via TPM2 alone — through the real CLI, at $MNT"

# ── 5. real FUSE I/O through the TPM2-authenticated mount ───────────────
echo "hello from tpm2 mount e2e $$" > "$MNT/probe.txt"
sync
READBACK="$(cat "$MNT/probe.txt")"
[ "$READBACK" = "hello from tpm2 mount e2e $$" ] || { echo "FAIL: readback mismatch: $READBACK"; exit 1; }
echo "[5] real file written and read back through the mount"

# ── 6. unmount cleanly ────────────────────────────────────────────────────
"$BIN" volume unmount "$MNT" >/dev/null 2>&1 || fusermount3 -u "$MNT" >/dev/null 2>&1 || fusermount -u "$MNT" >/dev/null 2>&1
wait_unmounted || { echo "FAIL: volume did not unmount"; exit 1; }
wait "$MOUNT_PID" 2>/dev/null || { echo "FAIL: mount process exited unsuccessfully"; exit 1; }
echo "[6] unmounted cleanly"

# ── 7. authenticated remote cleanup is part of the pass condition ─────────
DELETE_OUT="$(echo "$PASSPHRASE" | timeout 180 "$BIN" volume delete "$VOL_ID" \
  --force --password-file - 2>&1)" && DELETE_RC=0 || DELETE_RC=$?
if [ "$DELETE_RC" -ne 0 ] \
    || ! grep -Fq "Volume '$VOL_ID' deleted." <<<"$DELETE_OUT"; then
  echo "FAIL: authenticated Telegram/local cleanup failed (exit=$DELETE_RC)"
  tail -5 <<<"$DELETE_OUT"
  exit 1
fi
VOL_ID=""
echo "[7] Telegram blocks and local volume deleted"

echo
echo "== SUCCESS: TPM2 alone authenticated AND mounted a volume AND served real"
echo "   file I/O, driven entirely through the real teagarden CLI (PUB-005) =="
