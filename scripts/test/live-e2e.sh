#!/usr/bin/env bash
#
# live-e2e.sh — end-to-end test and benchmark of TeaGarden against REAL Telegram.
#
# This drives only the shipped `teagarden` binary, a real FUSE mount and a real
# Telegram account. Nothing is mocked. It uses a throwaway volume in a temporary
# volumes directory and deletes the volume (including its Telegram objects) at
# the end.
#
# Requirements:
#   - Linux with FUSE (fusermount3), sha256sum, findmnt, timeout
#   - `teagarden auth login` already done for this user
#   - TEAGARDEN_BIN (default: TeaGarden on PATH)
#
# Usage:
#   scripts/test/live-e2e.sh                  # default sizes
#   SIZES_MIB="1 16 128" scripts/test/live-e2e.sh
#   RESULTS=/path/results.jsonl scripts/test/live-e2e.sh
#
# Exit status is non-zero on ANY mismatch or failed step.

set -uo pipefail

BIN="${TEAGARDEN_BIN:-$(command -v teagarden || true)}"
SIZES_MIB="${SIZES_MIB:-1 10 100}"
RESULTS="${RESULTS:-$PWD/live-e2e-results.jsonl}"
CONFIG_DIR="${TEAGARDEN_CONFIG_DIR:-$HOME/.config/teagarden}"
WORK="$(mktemp -d)"
export TEAGARDEN_VOLUMES_DIR="$WORK/volumes"
MNT="$WORK/mnt"
RECOVERY_HOME="$WORK/recovery-home"
RECOVERY_CONFIG="$WORK/recovery-config"
RECOVERY_VOLUMES="$WORK/recovery-volumes"
RECOVERY_MNT="$WORK/recovery-mnt"
SRC="$WORK/src"
PASS="$WORK/pass"
VOL="e2e-$(date +%s)-$$"
FAIL=0
MOUNTED=0
RECOVERY_MOUNTED=0
CREATED=0

mkdir -p "$TEAGARDEN_VOLUMES_DIR" "$MNT" "$SRC" "$RECOVERY_HOME" "$RECOVERY_CONFIG" "$RECOVERY_VOLUMES" "$RECOVERY_MNT"
head -c 32 /dev/urandom | base64 > "$PASS"
chmod 600 "$PASS"

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '[%s] FAIL: %s\n' "$(date +%H:%M:%S)" "$*" >&2; FAIL=1; }
now()  { date +%s.%N; }
record() { # name bytes seconds [extra-json]
  local mibs
  mibs=$(awk -v b="$2" -v s="$3" 'BEGIN { if (s > 0) printf "%.2f", b/1048576/s; else print "null" }')
  printf '{"test":"%s","bytes":%s,"seconds":%.3f,"mib_per_s":%s%s}\n' \
    "$1" "$2" "$3" "$mibs" "${4:+,$4}" >> "$RESULTS"
  log "$1: $2 bytes in $(printf %.2f "$3") s ($mibs MiB/s)"
}

mount_vol() {
  "$BIN" volume mount "$VOL" "$MNT" --password-file "$PASS" --daemonize \
    || { fail "mount"; return 1; }
  findmnt -n "$MNT" >/dev/null || { fail "mountpoint not mounted after --daemonize"; return 1; }
  MOUNTED=1
}
unmount_vol() {
  local t0 t1
  t0=$(now)
  "$BIN" volume unmount "$MNT" || fail "unmount"
  t1=$(now)
  MOUNTED=0
  findmnt -n "$MNT" >/dev/null && fail "still mounted after unmount"
  log "unmount (drain) took $(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}') s"
}
cleanup() {
  set +e
  if [ "$MOUNTED" = 1 ]; then
    timeout 180 "$BIN" volume unmount "$MNT" >/dev/null 2>&1 || log "WARNING: primary mount unmount failed: $MNT"
    findmnt -n "$MNT" >/dev/null 2>&1 && { log "WARNING: primary mount remains mounted: $MNT"; return; }
    MOUNTED=0
  fi
  if [ "$RECOVERY_MOUNTED" = 1 ]; then
    timeout 180 env HOME="$RECOVERY_HOME" TEAGARDEN_CONFIG_DIR="$RECOVERY_CONFIG" \
      TEAGARDEN_VOLUMES_DIR="$RECOVERY_VOLUMES" "$BIN" volume unmount "$RECOVERY_MNT" >/dev/null 2>&1 \
      || log "WARNING: recovery mount unmount failed: $RECOVERY_MNT"
    findmnt -n "$RECOVERY_MNT" >/dev/null 2>&1 && { log "WARNING: recovery mount remains mounted: $RECOVERY_MNT"; return; }
    RECOVERY_MOUNTED=0
  fi
  if [ "$CREATED" = 1 ]; then
    log "deleting test volume and its Telegram objects"
    # A failed-password delay may still be running (step 2): retry briefly.
    local tries=0
    until "$BIN" volume delete "$VOL" --password-file "$PASS" --force; do
      tries=$((tries + 1))
      if [ "$tries" -ge 5 ]; then
        echo "WARNING: test volume '$VOL' could not be deleted. Its volume directory is" \
          "kept at $TEAGARDEN_VOLUMES_DIR (the password is in $PASS); delete it with:" \
          "TEAGARDEN_VOLUMES_DIR=$TEAGARDEN_VOLUMES_DIR $BIN volume delete $VOL --password-file $PASS" >&2
        return
      fi
      sleep 3
    done
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "teagarden binary not found (set TEAGARDEN_BIN)" >&2; exit 2; }
for c in sha256sum findmnt fusermount3 timeout python3; do
  command -v "$c" >/dev/null || { echo "missing: $c" >&2; exit 2; }
done
"$BIN" auth status | grep -qi "not authenticated" && {
  echo "LIVE TELEGRAM SESSION REQUIRED: run 'teagarden auth login' first" >&2; exit 2; }

log "binary: $("$BIN" --version)   results: $RESULTS"

# ── 1. create ───────────────────────────────────────────────────────────────
t0=$(now)
if ! CREATE_OUT=$(timeout 180 "$BIN" volume create --name "$VOL" --password-file "$PASS" 2>&1); then
  printf '%s\n' "$CREATE_OUT" >&2
  fail "volume create"
  exit 1
fi
printf '%s\n' "$CREATE_OUT"
GROUP_ID=$(sed -n 's/^  Group ID:[[:space:]]*//p' <<<"$CREATE_OUT" | head -1)
TOPIC_ID=$(sed -n 's/^  Topic ID:[[:space:]]*\([0-9][0-9]*\).*/\1/p' <<<"$CREATE_OUT" | head -1)
OWNER_KEY=$(sed -n 's/^  Owner public key:[[:space:]]*//p' <<<"$CREATE_OUT" | head -1)
[[ -n "$GROUP_ID" && -n "$TOPIC_ID" && -n "$OWNER_KEY" ]] || { fail "could not parse create group/topic/owner key output"; exit 1; }
CREATED=1
record create 0 "$(awk -v a="$t0" -v b="$(now)" 'BEGIN{print b-a}')"

# ── 2. wrong password must be refused ───────────────────────────────────────
echo "definitely-not-the-password" > "$WORK/wrong"
if "$BIN" volume mount "$VOL" "$MNT" --password-file "$WORK/wrong" --daemonize 2>/dev/null; then
  fail "mount with a WRONG password succeeded"
  "$BIN" volume unmount "$MNT" >/dev/null 2>&1
fi
# The wrong password starts the failed-attempt delay (1 s after the first
# failure); a correct password is refused until it has passed.
sleep 2

# ── 3. upload: cp returns only after the data is on Telegram ────────────────
mount_vol || exit 1
for m in $SIZES_MIB; do
  head -c "$((m * 1048576))" /dev/urandom > "$SRC/rand-$m.bin"
  t0=$(now)
  cp "$SRC/rand-$m.bin" "$MNT/rand-$m.bin" || fail "cp $m MiB returned non-zero"
  record "write_${m}MiB" "$((m * 1048576))" "$(awk -v a="$t0" -v b="$(now)" 'BEGIN{print b-a}')"
done

# ── 4. ordinary filesystem operations ───────────────────────────────────────
mkdir -p "$MNT/a/b/c" || fail mkdir
printf 'hello\n' > "$MNT/a/b/c/note.txt" || fail write-small
printf 'world\n' >> "$MNT/a/b/c/note.txt" || fail append
mv "$MNT/a/b/c/note.txt" "$MNT/a/renamed.txt" || fail rename
if timeout 10 python3 - "$MNT/a/link" <<'PY'
import errno
import os
import sys

try:
    os.symlink("renamed.txt", sys.argv[1])
except OSError as error:
    if error.errno == errno.ENOTSUP:
        print("REFUSED: symlink creation returned ENOTSUP")
        raise SystemExit(0)
    print(f"unexpected symlink errno: {error.errno} ({error})", file=sys.stderr)
    raise SystemExit(1)
else:
    print("symlink creation unexpectedly succeeded", file=sys.stderr)
    raise SystemExit(1)
PY
then
  log "symlink: REFUSED with ENOTSUP (expected for TGFV)"
else
  fail "symlink creation was not refused with ENOTSUP"
fi
if ! { printf '0123456789' > "$MNT/trunc.txt" && truncate -s 4 "$MNT/trunc.txt"; }; then fail truncate; fi
# Partial overwrites through ONE open descriptor after fsync, a reopen with a
# partial overwrite, and ftruncate of unsaved writes. The expected bytes are
# built the same way in a plain local file; the comparison happens after a
# remount and after the from-Telegram recovery mount (verify_all).
if timeout 120 python3 - "$MNT/overwrite.bin" "$SRC/overwrite.expected" "$MNT/dirty-trunc.txt" <<'PY'
import os, sys
target, expected, dirty = sys.argv[1:4]
base = os.urandom(3 * 1048576 + 777)
def apply(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
    os.write(fd, base); os.fsync(fd)
    os.pwrite(fd, b"Z" * 4096, 1048576 + 123); os.fsync(fd)   # same fd, after fsync
    os.pwrite(fd, b"Y", 5); os.close(fd)
    fd = os.open(path, os.O_RDWR)                              # reopen, partial overwrite
    os.pwrite(fd, b"X" * 10, len(base) - 10); os.close(fd)
apply(expected)
apply(target)
fd = os.open(dirty, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
os.write(fd, b"ABCDEF"); os.ftruncate(fd, 2); os.close(fd)     # truncate unsaved writes
with open(target, "rb") as a, open(expected, "rb") as b:
    if a.read() != b.read():
        print("overwrite.bin differs from expected immediately after writing", file=sys.stderr)
        raise SystemExit(1)
PY
then
  log "overwrite after fsync / reopen / ftruncate of unsaved writes: written"
else
  fail "overwrite after fsync / ftruncate of unsaved writes"
fi
[ "$(cat "$MNT/dirty-trunc.txt")" = "AB" ] || fail "ftruncate of unsaved writes content"
if ! { printf 'gone' > "$MNT/delete-me" && rm "$MNT/delete-me"; }; then fail unlink; fi
[ ! -e "$MNT/a/link" ] || fail "refused symlink exists"
[ "$(cat "$MNT/trunc.txt")" = "0123" ] || fail "truncate content"
[ -e "$MNT/delete-me" ] && fail "deleted file still present"
unmount_vol

verify_all() { # label [mountpoint]
  local root="${2:-$MNT}" m
  [ "$(cat "$root/a/renamed.txt")" = "$(printf 'hello\nworld')" ] || fail "$1: renamed.txt content"
  [ ! -e "$root/a/link" ] || fail "$1: refused symlink exists"
  [ "$(cat "$root/trunc.txt")" = "0123" ] || fail "$1: truncated file content"
  [ "$(cat "$root/dirty-trunc.txt")" = "AB" ] || fail "$1: ftruncate of unsaved writes content"
  cmp -s "$root/overwrite.bin" "$SRC/overwrite.expected" \
    || fail "$1: overwrite after fsync differs from expected bytes"
  [ -e "$root/delete-me" ] && fail "$1: deleted file came back"
  for m in $SIZES_MIB; do
    local t0 want got
    want=$(sha256sum < "$SRC/rand-$m.bin" | cut -d' ' -f1)
    t0=$(now)
    got=$(sha256sum < "$root/rand-$m.bin" | cut -d' ' -f1)
    record "${1}_read_${m}MiB" "$((m * 1048576))" "$(awk -v a="$t0" -v b="$(now)" 'BEGIN{print b-a}')"
    [ "$got" = "$want" ] || fail "$1: sha256 mismatch for $m MiB"
  done
}

# Verify each test file's path in the authenticated decrypt history and report
# the actual size of every exported TGFV version for that path.
verify_file_objects() { # file names...
  local raw="$WORK/objects-$RANDOM" file line object object_id object_size sizes count decrypt_out decrypt_rc
  "$BIN" volume export-objects "$VOL" --out "$raw" --password-file "$PASS" \
    || { fail "export-objects for object-count check"; return 1; }
  for file in "$@"; do
    count=0
    sizes=""
    while IFS= read -r -d '' object; do
      object_id="${object##*/file-}"
      object_id="${object_id%.tgf}"
      decrypt_out=$(timeout 180 "$BIN" decrypt "$object" --out "$WORK/decrypted-$RANDOM-$object_id" --password-file "$PASS" 2>&1) \
        && decrypt_rc=0 || decrypt_rc=$?
      line=$(grep -F " path=$file" <<<"$decrypt_out" | head -1 || true)
      [ -n "$line" ] || continue
      [ "$decrypt_rc" -eq 0 ] || { printf '%s\n' "$decrypt_out" >&2; fail "single-object decrypt failed for $file message $object_id"; continue; }
      object_size=$(stat -c %s "$object")
      sizes="${sizes}${sizes:+,}$object_size"
      count=$((count + 1))
    done < <(find "$raw" -maxdepth 1 -type f -name 'file-*.tgf' -print0)
    [ "$count" -ge 1 ] || { fail "no decrypt history or exported TGFV object for $file"; return 1; }
    log "objects $file: versions=$count sizes_bytes=$sizes"
  done
}

VDIR=$(find "$TEAGARDEN_VOLUMES_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
[ -n "$VDIR" ] || { fail "volume directory not found"; exit 1; }

# ── 5. cold read: empty the local cache so every block downloads ────────────
rm -rf "${VDIR:?}/cache" && mkdir -p "$VDIR/cache"
mount_vol || exit 1
verify_all cold
unmount_vol

# ── 6. warm read: second mount, cache populated ─────────────────────────────
mount_vol || exit 1
verify_all warm
unmount_vol

# ── 7. fresh attach: rebuild local state from Telegram alone ────────────────
# Keep only Telegram auth material in a second config directory. The volume
# state, HOME, and volumes directory are fresh and cannot supply the files.
for auth_file in .env group.json teagarden.session; do
  [ -f "$CONFIG_DIR/$auth_file" ] || { fail "missing Telegram auth file $CONFIG_DIR/$auth_file"; exit 1; }
  cp -p "$CONFIG_DIR/$auth_file" "$RECOVERY_CONFIG/$auth_file" || { fail "copy Telegram auth file $auth_file"; exit 1; }
done
chmod 700 "$RECOVERY_CONFIG"
ATTACH_OUT=$(timeout 300 env HOME="$RECOVERY_HOME" TEAGARDEN_CONFIG_DIR="$RECOVERY_CONFIG" \
  TEAGARDEN_VOLUMES_DIR="$RECOVERY_VOLUMES" \
  "$BIN" volume attach "$GROUP_ID:$TOPIC_ID" --password-file "$PASS" --owner-public-key "$OWNER_KEY" 2>&1) \
  || { printf '%s\n' "$ATTACH_OUT" >&2; fail "fresh volume attach from Telegram"; exit 1; }
printf '%s\n' "$ATTACH_OUT"
RECOVERY_VOLUME_ID=$(sed -n 's/^Attached volume \([^ ]*\) to Telegram topic.*/\1/p' <<<"$ATTACH_OUT" | head -1)
CREATE_VOLUME_ID=$(sed -n 's/^  Volume ID:[[:space:]]*//p' <<<"$CREATE_OUT" | head -1)
[ -n "$RECOVERY_VOLUME_ID" ] && [ "$RECOVERY_VOLUME_ID" = "$CREATE_VOLUME_ID" ] \
  || { fail "fresh attach output did not identify the created volume"; exit 1; }
grep -Fqx "Attached volume $RECOVERY_VOLUME_ID to Telegram topic $GROUP_ID:$TOPIC_ID." <<<"$ATTACH_OUT" \
  || { fail "fresh attach output did not identify the created volume and topic"; exit 1; }
if ! timeout 180 env HOME="$RECOVERY_HOME" TEAGARDEN_CONFIG_DIR="$RECOVERY_CONFIG" \
  TEAGARDEN_VOLUMES_DIR="$RECOVERY_VOLUMES" \
  "$BIN" volume mount "$RECOVERY_VOLUME_ID" "$RECOVERY_MNT" --password-file "$PASS" --daemonize; then
  fail "mount after fresh attach"
  exit 1
fi
findmnt -n "$RECOVERY_MNT" >/dev/null || { fail "freshly attached volume did not mount"; exit 1; }
RECOVERY_MOUNTED=1
t0=$(now)
verify_all recovery "$RECOVERY_MNT"
unmount_rec_out=$(timeout 180 env HOME="$RECOVERY_HOME" TEAGARDEN_CONFIG_DIR="$RECOVERY_CONFIG" \
  TEAGARDEN_VOLUMES_DIR="$RECOVERY_VOLUMES" "$BIN" volume unmount "$RECOVERY_MNT" 2>&1) \
  || { printf '%s\n' "$unmount_rec_out" >&2; fail "unmount recovered volume"; }
findmnt -n "$RECOVERY_MNT" >/dev/null && fail "freshly attached mount remained mounted"
RECOVERY_MOUNTED=0
log "fresh attach byte-equality recovery checks took $(awk -v a="$t0" -v b="$(now)" 'BEGIN{printf "%.2f", b-a}') s"

# ── 8. key rotation, then everything must still read back ───────────────────
t0=$(now)
ROTATE_OUT=$(timeout 180 "$BIN" key rotate "$VOL" --password-file "$PASS" 2>&1) && rotate_rc=0 || rotate_rc=$?
printf '%s\n' "$ROTATE_OUT"
EXPECTED_ROTATE_ERROR="Error: TGFV key rotation is planned for a later release; 1.0 device revoke removes Telegram access without changing the volume credential"
[ "$rotate_rc" -ne 0 ] && grep -Fqx "$EXPECTED_ROTATE_ERROR" <<<"$ROTATE_OUT" \
  || fail "key rotate did not return the exact default-build refusal"
record rotate 0 "$(awk -v a="$t0" -v b="$(now)" 'BEGIN{print b-a}')"
rm -rf "${VDIR:?}/cache" && mkdir -p "$VDIR/cache"
mount_vol || exit 1
verify_all rotated
unmount_vol
verify_file_objects "rand-1.bin"

if [ "$FAIL" -ne 0 ]; then log "LIVE E2E: FAILED"; exit 1; fi
log "LIVE E2E: PASSED"
