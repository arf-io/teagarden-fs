#!/usr/bin/env bash
#
# durability-e2e.sh — live end-to-end regression for the unmount/Ctrl+C drain.
#
# WHAT IT GUARDS
#   Uploads happen inside the FUSE `release` handler, which runs asynchronously
#   AFTER userspace close()/cp returns. The mount process holds the single-writer
#   lock for its whole life and only drains the in-flight uploads + publishes the
#   anti-rollback snapshot when it exits. The bug this guards (silent 64 MiB -> 0
#   byte data loss): `volume unmount` used to return the instant fusermount
#   detached, while the writer kept uploading; a kill/poweroff in that window lost
#   the not-yet-uploaded blocks. The fix makes unmount poll the writer lock until
#   the drain completes, and makes a foreground mount self-unmount on SIGINT so
#   Ctrl+C drains gracefully. The deterministic unit test for the lock primitive
#   is `is_held_tracks_writer_lock_for_unmount_drain` (teagarden-core); this script
#   proves the full path against a real Telegram backend.
#
# REQUIREMENTS (this is a LIVE test — it really uploads to Telegram)
#   - A built binary (default ./target/debug/teagarden; override with TEAGARDEN_BIN)
#   - Authenticated session + configured storage group (`teagarden auth login`)
#   - A password file (default ~/.config/teagarden/.bench_pw; override PASSFILE)
#
# USAGE
#   scripts/test/durability-e2e.sh [unmount|sigint|both]   # default: both
#   SIZE_MIB=64 scripts/test/durability-e2e.sh both         # bigger = more blocks
#
# Exit status is non-zero on any sha/size mismatch, missing drain message, or
# mount failure, so it can gate a release.

set -uo pipefail

BIN="${TEAGARDEN_BIN:-./target/debug/teagarden}"
PASSFILE="${PASSFILE:-$HOME/.config/teagarden/.bench_pw}"
SIZE_MIB="${SIZE_MIB:-16}"
MODE="${1:-both}"
WORK="$(mktemp -d)"
# A throwaway volumes directory: never the user's real volumes.
export TEAGARDEN_VOLUMES_DIR="$WORK/volumes"
mkdir -p "$TEAGARDEN_VOLUMES_DIR"
MNT="$WORK/mnt"
VOL="durtest-$$"
SRC="$WORK/src.bin"
DL="$WORK/dl.bin"
FAIL=0
VOL_CREATED=0

mkdir -p "$MNT"

for command in findmnt sha256sum stat timeout; do
  command -v "$command" >/dev/null 2>&1 \
    || { echo "FAIL: $command is required" >&2; exit 1; }
done
[ -x "$BIN" ] || { echo "FAIL: teagarden binary is not executable: $BIN" >&2; exit 1; }
[ -s "$PASSFILE" ] || { echo "FAIL: password file is missing or empty: $PASSFILE" >&2; exit 1; }
case "$SIZE_MIB" in
  ''|*[!0-9]*) echo "FAIL: SIZE_MIB must be a positive integer" >&2; exit 2 ;;
esac
[ "$SIZE_MIB" -gt 0 ] || { echo "FAIL: SIZE_MIB must be greater than zero" >&2; exit 2; }
case "$MODE" in
  unmount|sigint|both) ;;
  *) echo "FAIL: unknown mode '$MODE' (use: unmount|sigint|both)" >&2; exit 2 ;;
esac

# shellcheck disable=SC2329 # Invoked by the EXIT/INT/TERM trap below.
cleanup() {
  "$BIN" volume unmount "$MNT" >/dev/null 2>&1
  # Escalate to a lazy unmount + killing the mount process if a plain
  # unmount didn't clear it (e.g. a blocked FUSE read under a Telegram
  # flood-wait is uninterruptible and won't respond to a normal unmount) —
  # otherwise this cleanup can itself hang forever.
  if findmnt "$MNT" >/dev/null 2>&1; then
    fusermount3 -uz "$MNT" >/dev/null 2>&1 || fusermount -uz "$MNT" >/dev/null 2>&1
    pkill -9 -f "volume mount $VOL" >/dev/null 2>&1
  fi
  if [ "$VOL_CREATED" -eq 1 ]; then
    if ! timeout 180 "$BIN" volume delete "$VOL" --force \
      --password-file "$PASSFILE" >/dev/null 2>&1; then
      echo "WARNING: test volume '$VOL' could not be deleted; its volume directory is kept:" \
        "TEAGARDEN_VOLUMES_DIR=$TEAGARDEN_VOLUMES_DIR $BIN volume delete $VOL --force --password-file $PASSFILE" >&2
      return
    fi
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_mounted() {  # $1 = timeout seconds
  for _ in $(seq 1 "$1"); do findmnt "$MNT" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
wait_unmounted() {
  for _ in $(seq 1 120); do findmnt "$MNT" >/dev/null 2>&1 || return 0; sleep 1; done
  return 1
}

echo "== durability-e2e: ${SIZE_MIB} MiB, mode=${MODE}, vol=${VOL} =="
"$BIN" volume create --name "$VOL" --password-file "$PASSFILE" >/dev/null 2>&1 \
  || { echo "FAIL: create"; exit 1; }
VOL_CREATED=1
head -c "$((SIZE_MIB * 1024 * 1024))" /dev/urandom > "$SRC"
SRC_SHA="$(sha256sum "$SRC" | cut -d' ' -f1)"
SRC_SZ="$(stat -c%s "$SRC")"

# verify_readback <label>: remount, copy the file out, bitwise-compare to source.
verify_readback() {
  local label="$1"
  "$BIN" volume mount "$VOL" "$MNT" --password-file "$PASSFILE" >"$WORK/m.log" 2>&1 &
  local mpid=$!
  wait_mounted 200 || { echo "FAIL[$label]: remount"; FAIL=1; return; }
  cp "$MNT/f.bin" "$DL" 2>/dev/null \
    || { echo "FAIL[$label]: copy from mounted volume"; FAIL=1; }
  local dl_sha dl_sz; dl_sha="$(sha256sum "$DL" 2>/dev/null | cut -d' ' -f1)"; dl_sz="$(stat -c%s "$DL" 2>/dev/null || echo 0)"
  if [ "$dl_sha" = "$SRC_SHA" ] && [ "$dl_sz" = "$SRC_SZ" ]; then
    echo "PASS[$label]: sha=OK size=${dl_sz}/${SRC_SZ}"
  else
    echo "FAIL[$label]: sha=${dl_sha:-none} size=${dl_sz}/${SRC_SZ} (expected ${SRC_SHA})"; FAIL=1
  fi
  "$BIN" volume unmount "$MNT" >/dev/null 2>&1
  wait_unmounted || { echo "FAIL[$label]: did not unmount"; FAIL=1; }
  wait "$mpid" 2>/dev/null || { echo "FAIL[$label]: mount process exited unsuccessfully"; FAIL=1; }
  rm -f "$DL"
}

verify_object_layout() { # label [baseline-message-id]
  local label="$1" baseline="${2:-0}" raw="$WORK/objects-$1"
  local objects=0 object object_id object_size decrypt_out decrypt_rc line sizes="" versions=0 max_id="$baseline"
  "$BIN" volume export-objects "$VOL" --out "$raw" --password-file "$PASSFILE" \
    || { echo "FAIL[$1]: export-objects"; FAIL=1; return; }
  while IFS= read -r -d '' object; do
    objects=$((objects + 1))
    object_id="${object##*/file-}"
    object_id="${object_id%.tgf}"
    case "$object_id" in ''|*[!0-9]*) continue ;; esac
    [ "$object_id" -gt "$max_id" ] && max_id="$object_id"
  done < <(find "$raw" -maxdepth 1 -type f -name 'file-*.tgf' -print0)
  [ "$objects" -ge 1 ] || { echo "FAIL[$1]: export contained no TGFV file objects"; FAIL=1; return; }
  while IFS= read -r -d '' object; do
    object_id="${object##*/file-}"
    object_id="${object_id%.tgf}"
    case "$object_id" in ''|*[!0-9]*) continue ;; esac
    [ "$object_id" -gt "$baseline" ] || continue
    decrypt_out=$(timeout 180 "$BIN" decrypt "$object" --out "$WORK/decrypted-$label-$object_id" --password-file "$PASSFILE" 2>&1) \
      && decrypt_rc=0 || decrypt_rc=$?
    line=$(grep -F ' path=f.bin' <<<"$decrypt_out" | head -1 || true)
    [ -n "$line" ] || continue
    [ "$decrypt_rc" -eq 0 ] \
      || { printf '%s\n' "$decrypt_out"; echo "FAIL[$label]: single-object decrypt failed for f.bin message $object_id"; FAIL=1; continue; }
    object_size="$(stat -c %s "$object")"
    sizes="${sizes}${sizes:+,}$object_size"
    versions=$((versions + 1))
  done < <(find "$raw" -maxdepth 1 -type f -name 'file-*.tgf' -print0)
  [ "$versions" -ge 1 ] \
    || { echo "FAIL[$label]: no new f.bin TGFV version after Telegram message $baseline"; FAIL=1; }
  echo "MEASURE[$label]: file=f.bin baseline_message_id=$baseline published_tgfvs=$versions sizes_bytes=${sizes:-none}"
  FILE_BASELINE="$max_id"
}

run_unmount() {
  echo "-- [unmount] write ${SIZE_MIB} MiB, then graceful unmount drains --"
  "$BIN" volume mount "$VOL" "$MNT" --password-file "$PASSFILE" >"$WORK/m.log" 2>&1 &
  local mpid=$!
  wait_mounted 200 || { echo "FAIL[unmount]: mount"; FAIL=1; return; }
  cp "$SRC" "$MNT/f.bin" || { echo "FAIL[unmount]: write"; FAIL=1; return; }
  local t; t="$(date +%s)"
  local out unmount_rc
  out="$("$BIN" volume unmount "$MNT" 2>&1)" && unmount_rc=0 || unmount_rc=$?
  echo "   unmount took $(( $(date +%s) - t ))s"
  [ "$unmount_rc" -eq 0 ] \
    || { echo "FAIL[unmount]: command exited $unmount_rc"; FAIL=1; }
  echo "$out" | grep -qiE "flush complete|safe to remount|unmounted" \
    || { echo "FAIL[unmount]: no drain-complete message (got: $(echo "$out" | tail -1))"; FAIL=1; }
  wait_unmounted || { echo "FAIL[unmount]: still mounted"; FAIL=1; return; }
  wait "$mpid" 2>/dev/null || { echo "FAIL[unmount]: mount process exited unsuccessfully"; FAIL=1; }
  verify_object_layout unmount 0
  verify_readback "unmount"
}

run_sigint() {
  echo "-- [sigint] write ${SIZE_MIB} MiB, then SIGINT (Ctrl+C) drains --"
  "$BIN" volume mount "$VOL" "$MNT" --password-file "$PASSFILE" >"$WORK/m.log" 2>&1 &
  local mpid=$!
  wait_mounted 200 || { echo "FAIL[sigint]: mount"; FAIL=1; return; }
  cp "$SRC" "$MNT/f.bin" || { echo "FAIL[sigint]: write"; FAIL=1; return; }
  sync
  kill -INT "$mpid"          # Ctrl+C: the mount must self-unmount + drain, not abort mid-upload
  wait "$mpid" 2>/dev/null || { echo "FAIL[sigint]: mount process exited unsuccessfully"; FAIL=1; }
  wait_unmounted || { echo "FAIL[sigint]: still mounted after SIGINT"; FAIL=1; }
  verify_object_layout sigint "${FILE_BASELINE:-0}"
  verify_readback "sigint"
}

case "$MODE" in
  unmount) run_unmount ;;
  sigint)  run_sigint ;;
  both)    run_unmount; run_sigint ;;
esac

echo "-- authenticated remote cleanup --"
wait_unmounted || { echo "FAIL[cleanup]: volume is still mounted"; FAIL=1; }
delete_output="$(timeout 180 "$BIN" volume delete "$VOL" --force \
  --password-file "$PASSFILE" 2>&1)" && delete_rc=0 || delete_rc=$?
if [ "$delete_rc" -eq 0 ] \
    && grep -Fq "Volume '$VOL' deleted." <<<"$delete_output"; then
  VOL_CREATED=0
  echo "PASS[cleanup]: Telegram blocks and local volume deleted"
else
  echo "FAIL[cleanup]: authenticated volume deletion failed (exit=$delete_rc)"
  tail -5 <<<"$delete_output"
  FAIL=1
fi

[ "$FAIL" -eq 0 ] && echo "== durability-e2e: ALL PASS ==" || echo "== durability-e2e: FAILURES ABOVE =="
exit "$FAIL"
