#!/usr/bin/env bash
#
# teagarden-dev-nbd-fs-e2e.sh — kernel end-to-end proof of the SHIPPED block-device
# commands: `teagarden dev create` + `teagarden dev serve nbd`, with real ext4,
# xfs and btrfs on /dev/nbdN.
#
# THIS IS A LIVE TEST. It needs a live Telegram session and really uploads.
#   The shipped `dev` verbs have no local-only mode: `dev create` creates a
#   forum topic and publishes the first DeviceHead, and `dev serve nbd` opens
#   the device over the real Telegram transport (commands/dev.rs:
#   real_transport). There is deliberately NO mock fallback here: the script
#   it replaces drove a mock-backed test binary and so never proved the
#   shipped path. Without a live session this script FAILS (exit 2), it does
#   not skip.
#
# PER FILESYSTEM (ext4, xfs, btrfs), each on a fresh 1 GiB device:
#   dev create -> dev serve nbd -> nbd-client -> mkfs -> mount -> write a
#   random file -> sha256 -> sync -> umount -> nbd-client -d -> STOP the server
#   (SIGTERM; no graceful close, so the restart recovers from the local staging
#   log) -> START it again -> nbd-client -> mount -> verify sha256 -> STOP the
#   server -> `dev delete --force --password-file` (the script FAILS if that
#   fails, or if the device's registry entry or state directory survive it).
#
# REQUIREMENTS
#   - Linux, passwordless sudo, the nbd kernel module, nbd-client,
#     mkfs.ext4 / mkfs.xfs / mkfs.btrfs, sha256sum
#   - A RELEASE TeaGarden binary built with the `dev` feature (Argon2id is
#     256 MiB / t=4: a debug build looks hung). Default: $HOME/target/release/
#     TeaGarden, then ./target/release/teagarden; override with TEAGARDEN_BIN.
#   - Telegram API credentials: TG_API_ID + TG_API_HASH, or
#     ${XDG_CONFIG_HOME:-~/.config}/teagarden/.env (`teagarden configure`)
#   - An authenticated session: TEAGARDEN_SESSION_PATH, or
#     ${XDG_CONFIG_HOME:-~/.config}/teagarden/teagarden.session
#     (`teagarden auth login`)
#   - A device credential file: PASSFILE (any non-empty file; used for all
#     three throwaway devices)
#   Presence checks are by metadata only — this script never reads the
#   Telegram credential or session files.
#
# KNOBS: NBD_DEV (/dev/nbd0), PORT (10809), FSES ("ext4 xfs btrfs"),
#        FILE_MIB (32), SEGMENT_MIB (8)
#
# SIDE EFFECTS: one forum topic per filesystem in the shared storage group,
# holding that device's segments and heads. Each is deleted with `dev delete`
# once its filesystem has been verified. If the script fails before that, it
# tries `dev delete` again on exit for every device still standing, and prints
# the topic ids of any it could not remove. The device registry and state live
# in a temporary directory that is removed on exit.
#
# Exit 0 only if every requested filesystem verified byte-exact after restart.

set -uo pipefail

NBD_DEV="${NBD_DEV:-/dev/nbd0}"
PORT="${PORT:-10809}"
FSES="${FSES:-ext4 xfs btrfs}"
FILE_MIB="${FILE_MIB:-32}"
SEGMENT_MIB="${SEGMENT_MIB:-8}"
CFG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"

fail() { echo "FAIL: $*" >&2; exit 1; }
need_live() {
  echo "FAIL: LIVE TELEGRAM SESSION REQUIRED — $*" >&2
  echo "  The shipped 'teagarden dev create' / 'dev serve nbd' have no local-only mode;" >&2
  echo "  this proof cannot run without a live, authenticated Telegram session." >&2
  echo "  Set up: teagarden configure && teagarden auth login (then rerun)." >&2
  exit 2
}
log() { echo "[$(date +%H:%M:%S)] $*"; }

# ── preflight (metadata only; fails, never skips) ───────────────────────────
[ "$(uname -s)" = Linux ] || fail "Linux is required (kernel nbd)"
if [ -z "${TEAGARDEN_BIN:-}" ]; then
  for c in "$HOME/target/release/teagarden" ./target/release/teagarden; do
    [ -x "$c" ] && { TEAGARDEN_BIN="$c"; break; }
  done
fi
BIN="${TEAGARDEN_BIN:-}"
[ -n "$BIN" ] && [ -x "$BIN" ] \
  || fail "no release teagarden binary (cargo build --release -p teagarden-cli); or set TEAGARDEN_BIN"
"$BIN" dev serve nbd --help >/dev/null 2>&1 \
  || fail "$BIN has no 'dev serve nbd' (built without the dev feature?)"
"$BIN" dev delete --help >/dev/null 2>&1 \
  || fail "$BIN has no 'dev delete' (built before it existed? rebuild with --release)"
for c in sudo nbd-client sha256sum mountpoint dd; do
  command -v "$c" >/dev/null 2>&1 || fail "$c is required"
done
for fs in $FSES; do command -v "mkfs.$fs" >/dev/null 2>&1 || fail "mkfs.$fs is required"; done
sudo -n true 2>/dev/null || fail "passwordless sudo is required"

if [ -z "${TG_API_ID:-}" ] || [ -z "${TG_API_HASH:-}" ]; then
  [ -s "$CFG_HOME/teagarden/.env" ] \
    || need_live "no Telegram API credentials (TG_API_ID/TG_API_HASH unset and $CFG_HOME/teagarden/.env missing)"
fi
SESSION="${TEAGARDEN_SESSION_PATH:-$CFG_HOME/teagarden/teagarden.session}"
[ -s "$SESSION" ] || need_live "no Telegram session file at $SESSION"
[ -n "${PASSFILE:-}" ] && [ -s "$PASSFILE" ] \
  || fail "PASSFILE must name a non-empty device credential file"

sudo modprobe nbd nbds_max=16 2>/dev/null || true
[ -b "$NBD_DEV" ] || fail "$NBD_DEV is not a block device (nbd module loaded?)"
if sudo nbd-client -c "$NBD_DEV" >/dev/null 2>&1; then
  fail "$NBD_DEV is already connected; pick a free one with NBD_DEV="
fi

# ── state ───────────────────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/teagarden-dev-e2e.XXXXXX)"
MNT="$WORK/mnt"
mkdir -p "$MNT"
export TEAGARDEN_DEV_REGISTRY_DIR="$WORK/registry"
SERVE_PID=""
LEFT=()          # "name:topic" of every device not yet deleted
RESULTS=()

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  set +e
  mountpoint -q "$MNT" && sudo umount "$MNT"
  sudo nbd-client -d "$NBD_DEV" >/dev/null 2>&1
  [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null && wait "$SERVE_PID" 2>/dev/null
  # A failed run: delete what is left before the registry (the only record of
  # where each topic is) goes with $WORK. The server is stopped above.
  local entry left_over=""
  if [ "${#LEFT[@]}" -gt 0 ]; then
    for entry in "${LEFT[@]}"; do
      "$BIN" dev delete "${entry%%:*}" --force --password-file "$PASSFILE" >/dev/null 2>&1 \
        || left_over="$left_over ${entry##*:}"
    done
  fi
  if [ -n "$left_over" ]; then
    echo "NOTE: Telegram topics left in the storage group (dev delete failed):$left_over"
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

start_serve() {  # $1 = device name, $2 = log file
  "$BIN" dev serve nbd "$1" --bind "127.0.0.1:$PORT" --password-file "$PASSFILE" >"$2" 2>&1 &
  SERVE_PID=$!
  for _ in $(seq 1 600); do   # Argon2id + Telegram connect: allow 60 s
    grep -q '^LISTENING ' "$2" && return 0
    kill -0 "$SERVE_PID" 2>/dev/null || break
    sleep 0.1
  done
  echo "--- serve log ---"; cat "$2"
  fail "dev serve nbd did not come up"
}

stop_serve() {   # SIGTERM: no graceful close; recovery is from local staging
  kill "$SERVE_PID" 2>/dev/null
  wait "$SERVE_PID" 2>/dev/null
  SERVE_PID=""
}

attach() {
  sudo nbd-client -b 4096 -N "" 127.0.0.1 "$PORT" "$NBD_DEV" >/dev/null \
    || fail "nbd-client could not attach $NBD_DEV"
}

detach() { sudo nbd-client -d "$NBD_DEV" >/dev/null 2>&1; }

mkfs_quiet() {
  case "$1" in
    ext4)  sudo mkfs.ext4 -q -F "$NBD_DEV" ;;
    xfs)   sudo mkfs.xfs -q -f "$NBD_DEV" ;;
    btrfs) sudo mkfs.btrfs -q -f "$NBD_DEV" ;;
  esac
}

echo "===== teagarden-dev NBD kernel e2e — LIVE Telegram backend, shipped CLI ($BIN) ====="
for FS in $FSES; do
  NAME="e2e-$FS-$$"
  log "── $FS: device $NAME ──"
  CREATE_OUT="$("$BIN" dev create --name "$NAME" --size-gib 1 --segment-mib "$SEGMENT_MIB" \
      --dir "$WORK/state-$FS" --password-file "$PASSFILE" 2>&1)" \
    || { echo "$CREATE_OUT"; fail "$FS: dev create failed"; }
  TOPIC="$(echo "$CREATE_OUT" | awk '/topic/ {print $3; exit}')"
  LEFT+=("$NAME:$TOPIC")
  log "$FS: dev create ok (topic $TOPIC)"

  start_serve "$NAME" "$WORK/serve-$FS-1.log"
  attach
  mkfs_quiet "$FS" || fail "$FS: mkfs.$FS failed"
  sudo mount "$NBD_DEV" "$MNT" || fail "$FS: mount failed"
  sudo dd if=/dev/urandom of="$MNT/payload.bin" bs=1M count="$FILE_MIB" status=none \
    || fail "$FS: writing the payload failed"
  SHA1="$(sudo sha256sum "$MNT/payload.bin" | awk '{print $1}')"
  sync
  sudo umount "$MNT" || fail "$FS: umount failed"
  detach
  log "$FS: wrote ${FILE_MIB} MiB, sha256 $SHA1; unmounted + disconnected"

  stop_serve
  log "$FS: server stopped (SIGTERM, no graceful close)"
  # Device storage is a sequence of fixed-size segment documents. Check the
  # committed segment count from dev status; filesystem block geometry does
  # not predict Telegram object count.
  STATUS_OUT="$("$BIN" dev status "$NAME" --password-file "$PASSFILE" 2>&1)" \
    || { echo "$STATUS_OUT"; fail "$FS: dev status failed"; }
  SEGMENTS="$(printf '%s\n' "$STATUS_OUT" | awk '/segments[[:space:]]*:/ {print $NF; exit}')"
  MIN_SEGMENTS=$(((FILE_MIB + SEGMENT_MIB - 1) / SEGMENT_MIB))
  case "$SEGMENTS" in ''|*[!0-9]*) fail "$FS: dev status did not report a numeric segment count" ;; esac
  [ "$SEGMENTS" -ge "$MIN_SEGMENTS" ] \
    || fail "$FS: expected at least $MIN_SEGMENTS committed segment objects, got $SEGMENTS"
  log "$FS: confirmed $SEGMENTS segment object(s), minimum expected $MIN_SEGMENTS"
  start_serve "$NAME" "$WORK/serve-$FS-2.log"
  log "$FS: server restarted"
  attach
  sudo mount "$NBD_DEV" "$MNT" || fail "$FS: remount after restart failed"
  SHA2="$(sudo sha256sum "$MNT/payload.bin" | awk '{print $1}')"
  sudo umount "$MNT"
  detach
  stop_serve
  if [ "$SHA1" = "$SHA2" ]; then
    log "$FS: VERIFIED byte-exact after server restart ($SHA2)"
    DEL_OUT="$("$BIN" dev delete "$NAME" --force --password-file "$PASSFILE" 2>&1)" \
      || { echo "$DEL_OUT"; fail "$FS: dev delete failed (topic $TOPIC left in the storage group)"; }
    LEFT=()   # one device at a time: it was the only one standing
    [ ! -e "$WORK/state-$FS" ] || fail "$FS: dev delete left the state directory behind"
    [ ! -e "$TEAGARDEN_DEV_REGISTRY_DIR/$NAME.json" ] \
      || fail "$FS: dev delete left the registry entry behind"
    log "$FS: dev delete ok (topic $TOPIC and local state removed)"
    RESULTS+=("$FS OK $SHA2")
  else
    RESULTS+=("$FS MISMATCH $SHA1 != $SHA2")
    printf '%s\n' "${RESULTS[@]}"
    fail "$FS: sha256 mismatch after restart"
  fi
done

echo "===== RESULTS (LIVE Telegram backend) ====="
printf '%s\n' "${RESULTS[@]}"
echo "PASS: $(echo $FSES | tr " " "/") over teagarden dev serve nbd survive a server restart byte-exact"
