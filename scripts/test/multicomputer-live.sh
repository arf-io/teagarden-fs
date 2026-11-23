#!/usr/bin/env bash
# One-host, three-installation live acceptance test for TeaGarden 1.0.
# This script intentionally contacts Telegram and may revoke B's authorization.
# Separately approve B and C from A. Save the returned owner-visible Hash values
# as TG_CONFIRMED_AUTHORIZATION_B and TG_CONFIRMED_AUTHORIZATION_C.
set -Eeuo pipefail
umask 077
export LC_ALL=C LANG=C

# One aggregate deadline covers setup, probes, CLI calls, cleanup, and output.
SCRIPT_TIMEOUT=${SCRIPT_TIMEOUT:-14400}
[[ "$SCRIPT_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { printf 'FAIL: SCRIPT_TIMEOUT must be a positive integer\n' >&2; exit 1; }
(( SCRIPT_TIMEOUT <= 43200 )) || { printf 'FAIL: SCRIPT_TIMEOUT must not exceed 43200 seconds\n' >&2; exit 1; }
if [[ ${LIVE_SCRIPT_WATCHDOG_TOKEN:-} != internal ]]; then
  exec timeout --foreground --signal=TERM --kill-after=3600s "${SCRIPT_TIMEOUT}s" env LIVE_SCRIPT_WATCHDOG_TOKEN=internal "$0" "$@"
fi

BIN=${TEAGARDEN_BIN:-}
PASSFILE=${PASSFILE:-}
TG_CONFIG_A=${TG_CONFIG_A:-}
TG_CONFIG_B=${TG_CONFIG_B:-}
TG_CONFIG_C=${TG_CONFIG_C:-}
POLL_SECONDS=${POLL_SECONDS:-90}
COMMAND_TIMEOUT=${COMMAND_TIMEOUT:-180}
SHARED_SESSION=${SHARED_SESSION:-0}
TG_CONFIRMED_AUTHORIZATION_B=${TG_CONFIRMED_AUTHORIZATION_B:-}
TG_CONFIRMED_AUTHORIZATION_C=${TG_CONFIRMED_AUTHORIZATION_C:-}

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ "$SHARED_SESSION" == 0 || "$SHARED_SESSION" == 1 ]] || fail 'SHARED_SESSION must be 0 or 1'
[[ "$POLL_SECONDS" =~ ^[1-9][0-9]*$ && "$COMMAND_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || fail 'POLL_SECONDS and COMMAND_TIMEOUT must be positive integers'
(( POLL_SECONDS <= 3600 && COMMAND_TIMEOUT <= 300 )) || fail 'POLL_SECONDS must be at most 3600 and COMMAND_TIMEOUT at most 300'
need_file() {
  [[ -n "$1" ]] || fail "$2 must name a readable file"
  timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" python3 -c 'import os,stat,sys; p=sys.argv[1]; s=os.stat(p); raise SystemExit(0 if stat.S_ISREG(s.st_mode) and os.access(p, os.R_OK) else 1)' "$1" || fail "$2 must name a readable file"
}
need_config() {
  [[ -n "$1" ]] || fail "$2 must name an existing logged-in Telegram config directory"
  timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" python3 -c 'import os,sys; raise SystemExit(0 if os.path.isdir(sys.argv[1]) else 1)' "$1" || fail "$2 must name an existing logged-in Telegram config directory"
}
for tool in timeout realpath findmnt sha256sum sort awk sed date find cmp xargs rg tail grep python3 mkdir cp; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done
[[ -n "$BIN" ]] && timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" python3 -c 'import os,sys; raise SystemExit(0 if os.access(sys.argv[1], os.X_OK) else 1)' "$BIN" || fail 'set TEAGARDEN_BIN to the executable 1.0 binary'
need_file "$PASSFILE" PASSFILE
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" python3 -c 'import os,sys; raise SystemExit(0 if os.stat(sys.argv[1]).st_size else 1)' "$PASSFILE" || fail 'PASSFILE must not be empty'
need_config "$TG_CONFIG_A" TG_CONFIG_A
need_config "$TG_CONFIG_B" TG_CONFIG_B
need_config "$TG_CONFIG_C" TG_CONFIG_C
(( BASH_VERSINFO[0] >= 4 )) || fail 'this Linux live harness requires Bash 4 or newer'
sort -V </dev/null >/dev/null 2>&1 || fail 'sort must support -V and -z for portable version and path ordering'
sort -z </dev/null >/dev/null 2>&1 || fail 'sort must support -z for deterministic path ordering'
findmnt --help 2>&1 | grep -- '--mountpoint' >/dev/null || fail 'findmnt must support --mountpoint'
if [[ "$SHARED_SESSION" == 0 ]]; then
  confirmed_hashes=$(python3 - "$TG_CONFIRMED_AUTHORIZATION_B" "$TG_CONFIRMED_AUTHORIZATION_C" <<'PY'
import re, sys
values = sys.argv[1:]
if not all(re.fullmatch(r'-?[0-9]+', value) for value in values):
    raise SystemExit(1)
hashes = [int(value) for value in values]
if len(set(hashes)) != 2 or not all(value and -(1 << 63) <= value < 1 << 63 for value in hashes):
    raise SystemExit(1)
print(*hashes)
PY
  ) || fail 'provide distinct nonzero owner-visible B/C hashes from separate approvals in TG_CONFIRMED_AUTHORIZATION_B and TG_CONFIRMED_AUTHORIZATION_C'
  read -r B_SESSION_HASH C_SESSION_HASH <<<"$confirmed_hashes"
fi

CFG_A=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" realpath -e -- "$TG_CONFIG_A")
CFG_B=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" realpath -e -- "$TG_CONFIG_B")
CFG_C=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" realpath -e -- "$TG_CONFIG_C")
[[ "$CFG_A" != "$CFG_B" && "$CFG_A" != "$CFG_C" && "$CFG_B" != "$CFG_C" ]] || fail 'the three Telegram config directories resolve to the same canonical directory'
SESSION_A=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" realpath -e -- "$CFG_A/teagarden.session") || fail 'TG_CONFIG_A has no default logged-in session at teagarden.session'
SESSION_B=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" realpath -e -- "$CFG_B/teagarden.session") || fail 'TG_CONFIG_B has no default logged-in session at teagarden.session'
SESSION_C=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" realpath -e -- "$CFG_C/teagarden.session") || fail 'TG_CONFIG_C has no default logged-in session at teagarden.session'
[[ "$SESSION_A" != "$SESSION_B" && "$SESSION_A" != "$SESSION_C" && "$SESSION_B" != "$SESSION_C" ]] || fail 'Telegram session files resolve to a shared authorization file'

WORK=$(mktemp -d "${TMPDIR:-/tmp}/teagarden-live.XXXXXXXX")
PRESERVED=${WORK}.preserved
printf 'Run work directory: %s\n' "$WORK"
LOG_DIR=$WORK/logs
VOL=''
VOLUME_ID=''
GROUP_ID=''
TOPIC_ID=''
OWNER_KEY=''
A_CREATED=0
A_MOUNTED=0
B_MOUNTED=0
C_MOUNTED=0
CLEANING=0
CLEANUP_INTERRUPTED=0
PRESERVE_STATUS=not-attempted
declare -a HELPER_PIDS=()
declare -A MOUNT_PIDS=([a]='' [b]='' [c]='')
A_HOME=$WORK/home-a B_HOME=$WORK/home-b C_HOME=$WORK/home-c
A_MNT=$WORK/mnt-a B_MNT=$WORK/mnt-b C_MNT=$WORK/mnt-c
A_VOLS=$WORK/vol-a B_VOLS=$WORK/vol-b C_VOLS=$WORK/vol-c

on_signal() { exit "$2"; }
trap 'printf "Setup stopped before cleanup initialization; work=%s preserved=%s\n" "$WORK" "$PRESERVED" >&2' EXIT
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM
trap 'on_signal HUP 129' HUP
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" mkdir -p "$LOG_DIR" "$A_HOME" "$B_HOME" "$C_HOME" "$A_MNT" "$B_MNT" "$C_MNT" "$A_VOLS" "$B_VOLS" "$C_VOLS" || fail "cannot initialize run directories; work=$WORK"

now_ms() { timeout --signal=TERM --kill-after=2s 5s python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'; }
redact() { sed -E 's/(hash=)-?[0-9]+/\1<redacted>/g; s/(binding=)-?[0-9]+/\1<redacted>/g; s/(telegram_user=)[0-9]+/\1<redacted>/g; s/(id=|This computer: |[Ii]nstallation )[0-9a-fA-F-]{36}/\1<redacted>/g'; }
log_text() { local name=$1 text=$2; printf '%s\n' "$text" | redact >"$LOG_DIR/$name.log"; }
forget_helper() {
  local target=$1 i
  for i in "${!HELPER_PIDS[@]}"; do [[ ${HELPER_PIDS[i]} == "$target" ]] && unset 'HELPER_PIDS[i]'; done
  HELPER_PIDS=("${HELPER_PIDS[@]}")
}
CLI_SEQ=0
run_cli() {
  local app=$1 home=$2 cfg=$3 session=$4 vols=$5 no_tty=$6 out rc tag
  shift 6
  CLI_SEQ=$((CLI_SEQ + 1)); tag="cli-$CLI_SEQ-$app"
  if (( no_tty )); then
    if out=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" env HOME="$home" TEAGARDEN_CONFIG_DIR="$cfg" TEAGARDEN_SESSION_PATH="$session" TEAGARDEN_VOLUMES_DIR="$vols" "$BIN" "$@" </dev/null 2>&1); then rc=0; else rc=$?; fi
  else
    if out=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" env HOME="$home" TEAGARDEN_CONFIG_DIR="$cfg" TEAGARDEN_SESSION_PATH="$session" TEAGARDEN_VOLUMES_DIR="$vols" "$BIN" "$@" 2>&1); then rc=0; else rc=$?; fi
  fi
  log_text "$tag" "$out"
  if (( rc == 0 )); then printf '%s\n' "$out"; else printf '%s\n' "$out" >&2; return "$rc"; fi
}
run_a() { run_cli A "$A_HOME" "$CFG_A" "$SESSION_A" "$A_VOLS" 0 "$@"; }
run_a_no_tty() { run_cli A "$A_HOME" "$CFG_A" "$SESSION_A" "$A_VOLS" 1 "$@"; }
run_b() { run_cli B "$B_HOME" "$CFG_B" "$SESSION_B" "$B_VOLS" 0 "$@"; }
run_b_mount_probe() { timeout --signal=TERM --kill-after=2s 20s env HOME="$B_HOME" TEAGARDEN_CONFIG_DIR="$CFG_B" TEAGARDEN_SESSION_PATH="$SESSION_B" TEAGARDEN_VOLUMES_DIR="$B_VOLS" "$BIN" volume mount "$NAME_B" "$B_MNT" --password-file "$PASSFILE"; }
run_c() { run_cli C "$C_HOME" "$CFG_C" "$SESSION_C" "$C_VOLS" 0 "$@"; }

mounted() { timeout --signal=TERM --kill-after=2s 5s findmnt -rn --mountpoint "$1" >/dev/null 2>>"$LOG_DIR/findmnt.stderr"; }
unmount_confirmed() {
  local output=$1 final_line=${1##*$'\n'}
  [[ "$final_line" == 'Unmounted.' || "$final_line" == 'Flush complete — safe to remount or power off.' ]]
}
mount_absent() {
  local rc=0
  timeout --signal=TERM --kill-after=2s 5s findmnt -rn --mountpoint "$1" >/dev/null 2>>"$LOG_DIR/findmnt.stderr" || rc=$?
  (( rc == 1 ))
}
bounded_read() { timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" cat -- "$1" 2>>"$LOG_DIR/filesystem-read-errors.stderr"; }
bounded_write() { timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" bash -c 'printf "%b" "$1" >"$2"' _ "$1" "$2" 2>>"$LOG_DIR/filesystem-write-errors.stderr"; }
probe_path() {
  local path=$1 kind=${2:-any} probe_timeout=${3:-$COMMAND_TIMEOUT} result
  result=$(timeout --signal=TERM --kill-after=2s "${probe_timeout}s" python3 -c '
import os, sys
path, kind = sys.argv[1:]
try:
    st = os.stat(path)
except FileNotFoundError:
    print("absent")
    raise SystemExit(0)
except OSError as exc:
    print(f"probe error for {path}: {exc}", file=sys.stderr)
    raise SystemExit(2)
if kind == "file" and not os.path.isfile(path):
    print("wrong-kind")
elif kind == "dir" and not os.path.isdir(path):
    print("wrong-kind")
else:
    print("present")
' "$path" "$kind" 2>>"$LOG_DIR/filesystem-probe-errors.stderr") || return $?
  case $result in absent|present) printf '%s\n' "$result";; *) printf 'invalid filesystem probe result: %s\n' "$result" >&2; return 2;; esac
}
assert_absent() {
  local path=$1 result
  result=$(probe_path "$path" any) || fail "filesystem probe failed or timed out for $path"
  [[ "$result" == absent ]] || fail "expected path to remain absent: $path"
}
assert_absent_until() {
  local path=$1 deadline=$2 remaining assert_probe
  remaining=$((deadline - SECONDS))
  (( remaining > 0 )) || fail "filesystem probe deadline expired for $path"
  (( remaining > COMMAND_TIMEOUT )) && remaining=$COMMAND_TIMEOUT
  assert_probe=$(probe_path "$path" any "$remaining") || fail "filesystem probe failed or timed out for $path"
  [[ "$assert_probe" == absent ]] || fail "expected path to remain absent: $path"
}
bounded_read_until() {
  local path=$1 deadline=$2 remaining
  remaining=$((deadline - SECONDS))
  (( remaining > 0 )) || return 124
  (( remaining > COMMAND_TIMEOUT )) && remaining=$COMMAND_TIMEOUT
  timeout --signal=TERM --kill-after=2s "${remaining}s" cat -- "$path" 2>>"$LOG_DIR/filesystem-read-errors.stderr"
}
wait_for() {
  local path=$1 expected=$2 deadline=$((SECONDS + POLL_SECONDS)) got remaining read_timeout probe
  while (( SECONDS < deadline )); do
    remaining=$((deadline - SECONDS))
    (( remaining > 0 )) || return 1
    read_timeout=$remaining
    (( read_timeout > COMMAND_TIMEOUT )) && read_timeout=$COMMAND_TIMEOUT
    probe=$(timeout --signal=TERM --kill-after=2s "${read_timeout}s" python3 -c 'import os,sys; p=sys.argv[1];
try: os.stat(p)
except FileNotFoundError: print("absent")
except OSError as e: print(f"probe error: {e}",file=sys.stderr); raise SystemExit(2)
else: print("present")' "$path" 2>>"$LOG_DIR/filesystem-probe-errors.stderr") || return 1
    if [[ "$probe" == present ]]; then
      remaining=$((deadline - SECONDS))
      (( remaining > 0 )) || return 1
      read_timeout=$remaining
      (( read_timeout > COMMAND_TIMEOUT )) && read_timeout=$COMMAND_TIMEOUT
      if got=$(timeout --signal=TERM --kill-after=2s "${read_timeout}s" cat -- "$path" 2>>"$LOG_DIR/filesystem-read-errors.stderr") && [[ "$got" == "$expected" ]]; then return 0; fi
    fi
    sleep 0.2
  done
  return 1
}
wait_for_dir() {
  local path=$1 deadline=$((SECONDS + POLL_SECONDS)) remaining probe
  while (( SECONDS < deadline )); do
    remaining=$((deadline - SECONDS)); (( remaining > 0 )) || return 1
    (( remaining > COMMAND_TIMEOUT )) && remaining=$COMMAND_TIMEOUT
    probe=$(timeout --signal=TERM --kill-after=2s "${remaining}s" python3 -c 'import os,sys
try: s=os.stat(sys.argv[1])
except FileNotFoundError: print("absent")
except OSError as e: print(f"probe error: {e}",file=sys.stderr); raise SystemExit(2)
else: print("present" if os.path.isdir(sys.argv[1]) else "wrong-kind")' "$path" 2>>"$LOG_DIR/filesystem-probe-errors.stderr") || return 1
    [[ "$probe" == present ]] && (( SECONDS < deadline )) && return 0
    sleep 0.2
  done
  return 1
}
write_and_measure() {
  local source=$1 target=$2 rel=$3 payload=$4 start end
  SAMPLE_SEQ=$((SAMPLE_SEQ + 1))
  rel=${rel%.*}-${SAMPLE_SEQ}-${RUN_NONCE}.txt
  LAST_SAMPLE_REL=$rel
  payload="${payload}-${SAMPLE_SEQ}-${RUN_NONCE}"
  LAST_SAMPLE_PAYLOAD=$payload
  timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" mkdir -p -- "$source/$(dirname "$rel")" 2>>"$LOG_DIR/filesystem-write-errors.stderr"
  start=$(now_ms)
  bounded_write "$payload" "$source/$rel"
  wait_for "$target/$rel" "$payload" || fail "write-to-visible propagation timed out: $rel"
  end=$(now_ms)
  PROPAGATION_MS+=("$((end - start))")
  PROPAGATION_LEDGER+=("sample=$SAMPLE_SEQ source=$source target=$target path=$rel payload=$payload elapsed_ms=$((end-start))")
  printf 'PASS propagation sample: %s\n' "${PROPAGATION_LEDGER[${#PROPAGATION_LEDGER[@]}-1]}"
}
tree_digest() {
  local root=$1
  timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" python3 -c '
import hashlib, os, stat, sys
root = sys.argv[1]
entries = []
root_stat = os.stat(root)
if not stat.S_ISDIR(root_stat.st_mode): raise SystemExit(f"tree root is not a directory: {root}")
def walk_error(error): raise error
for current, dirs, files in os.walk(root, onerror=walk_error, followlinks=False):
    dirs.sort(); files.sort()
    rel_dir = os.path.relpath(current, root)
    if rel_dir != ".":
        st = os.lstat(current)
        entries.append(("D", rel_dir, oct(st.st_mode & 0o777), str(st.st_mtime_ns)))
    for name in dirs:
        path = os.path.join(current, name)
        if not stat.S_ISDIR(os.lstat(path).st_mode): raise SystemExit(f"unexpected non-directory entry: {path}")
    for name in files:
        path = os.path.join(current, name)
        rel = os.path.relpath(path, root)
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode): raise SystemExit(f"unexpected non-regular file: {path}")
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""): digest.update(chunk)
        entries.append(("F", rel, oct(st.st_mode & 0o777), str(st.st_mtime_ns), digest.hexdigest()))
for entry in sorted(entries): print(" ".join(entry))
' "$root" 2>>"$LOG_DIR/tree-errors.stderr"
}
mount_one() {
  local app=$1 mountpoint=$2 home cfg session vols pid start=$SECONDS deadline log
  case $app in
    a) A_MOUNTED=1; home=$A_HOME; cfg=$CFG_A; session=$SESSION_A; vols=$A_VOLS ;;
    b) B_MOUNTED=1; home=$B_HOME; cfg=$CFG_B; session=$SESSION_B; vols=$B_VOLS ;;
    c) C_MOUNTED=1; home=$C_HOME; cfg=$CFG_C; session=$SESSION_C; vols=$C_VOLS ;;
    *) fail "unknown installation for mount: $app" ;;
  esac
  log="$LOG_DIR/mount-$app.log"
  env HOME="$home" TEAGARDEN_CONFIG_DIR="$cfg" TEAGARDEN_SESSION_PATH="$session" TEAGARDEN_VOLUMES_DIR="$vols" "$BIN" volume mount "$VOLUME_ID" "$mountpoint" --password-file "$PASSFILE" >"$log" 2>&1 &
  pid=$!
  MOUNT_PIDS[$app]=$pid
  deadline=$((SECONDS + POLL_SECONDS))
  (( deadline > SECONDS + 30 )) && deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if mounted "$mountpoint"; then
      printf 'PASS mount-%s: foreground_pid=%s mountpoint=%s\n' "$app" "$pid" "$mountpoint"
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      local mount_rc=0
      wait "$pid" || mount_rc=$?
      fail "$app foreground mount exited before becoming live (exit $mount_rc); see $log"
    fi
    sleep 0.2
  done
  fail "$app foreground mount did not become live before its $((deadline-start))s startup deadline; see $log"
}
wait_mount_process() {
  local app=$1 mount_pid deadline rc=0
  mount_pid=${MOUNT_PIDS[$app]}
  [[ -n "$mount_pid" ]] || return 0
  deadline=$((SECONDS + 10))
  while kill -0 "$mount_pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 0.2; done
  if kill -0 "$mount_pid" 2>/dev/null; then
    kill -TERM "$mount_pid" 2>/dev/null || true
    deadline=$((SECONDS + 10))
    while kill -0 "$mount_pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 0.2; done
  fi
  if kill -0 "$mount_pid" 2>/dev/null; then
    printf 'foreground mount %s pid %s did not exit after unmount/TERM\n' "$app" "$mount_pid" >>"$LOG_DIR/mount-$app.log"
    return 1
  fi
  wait "$mount_pid" || rc=$?
  printf 'foreground_mount_exit_status=%s\n' "$rc" >>"$LOG_DIR/mount-$app.log"
  MOUNT_PIDS[$app]=''
  (( rc == 0 )) || { printf 'foreground mount %s exited with status %s\n' "$app" "$rc" >>"$LOG_DIR/mount-$app.log"; return 1; }
}
unmount_one() {
  local app=$1 mountpoint=$2 output
  case $app in
    a) output=$(run_a volume unmount "$mountpoint") ;;
    b) output=$(run_b volume unmount "$mountpoint") ;;
    c) output=$(run_c volume unmount "$mountpoint") ;;
  esac
  log_text "unmount-$app" "$output"
  unmount_confirmed "$output" || fail "$app unmount did not confirm a completed writer drain; see $LOG_DIR/unmount-$app.log"
  mount_absent "$mountpoint" || fail "$app mount remains active or mount state is unknown after unmount"
  wait_mount_process "$app" || fail "$app foreground mount process did not stop cleanly"
  mount_absent "$mountpoint" || fail "$app mount reappeared while its foreground process was stopping"
  case $app in
    a) A_MOUNTED=0 ;;
    b) B_MOUNTED=0 ;;
    c) C_MOUNTED=0 ;;
  esac
}
unmount_b_after_revoke() {
  local out status=0
  if out=$(run_b volume unmount "$B_MNT" 2>&1); then
    log_text b-post-revoke-unmount "$out"
  else
    status=$?
    log_text b-post-revoke-unmount "$out"
  fi
  (( status == 0 )) || fail "B unmount command failed after revoke (exit $status); see $LOG_DIR/b-post-revoke-unmount.log"
  unmount_confirmed "$out" || fail "B unmount did not confirm a completed writer drain; see $LOG_DIR/b-post-revoke-unmount.log"
  mount_absent "$B_MNT" || fail 'B mount remains active or mount state is unknown after post-revoke unmount'
  wait_mount_process b || fail 'B foreground mount process did not stop cleanly after revoke'
  mount_absent "$B_MNT" || fail 'B mount reappeared while its foreground process was stopping'
  B_MOUNTED=0
}
preserve_evidence() {
  local copy_rc=0
  timeout --signal=TERM --kill-after=5s "${COMMAND_TIMEOUT}s" mkdir -m 700 -- "$PRESERVED" || return 1
  timeout --signal=TERM --kill-after=5s "${COMMAND_TIMEOUT}s" mkdir -m 700 -- "$PRESERVED/logs" "$PRESERVED/local-state" "$PRESERVED/artifacts" || return 1
  timeout --signal=TERM --kill-after=10s "${COMMAND_TIMEOUT}s" cp -a -- "$LOG_DIR/." "$PRESERVED/logs/" || copy_rc=$?
  timeout --signal=TERM --kill-after=10s "${COMMAND_TIMEOUT}s" cp -a -- "$A_VOLS" "$PRESERVED/local-state/A" || copy_rc=$?
  timeout --signal=TERM --kill-after=10s "${COMMAND_TIMEOUT}s" cp -a -- "$B_VOLS" "$PRESERVED/local-state/B" || copy_rc=$?
  timeout --signal=TERM --kill-after=10s "${COMMAND_TIMEOUT}s" cp -a -- "$C_VOLS" "$PRESERVED/local-state/C" || copy_rc=$?
  local artifact
  for artifact in "$WORK/export" "$WORK"/object-candidate-* "$WORK/decrypted-tree" "$WORK/decrypted-single" "$WORK/expected-offline-payload.bin" "$WORK/pinned.after"; do
    local artifact_probe
    artifact_probe=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" python3 -c 'import os,sys
try: os.lstat(sys.argv[1])
except FileNotFoundError: print("absent")
else: print("present")' "$artifact") || { copy_rc=1; continue; }
    if [[ "$artifact_probe" == present ]]; then
      timeout --signal=TERM --kill-after=10s "${COMMAND_TIMEOUT}s" cp -a -- "$artifact" "$PRESERVED/artifacts/" || copy_rc=$?
    fi
  done
  {
    printf 'work=%s\npreserved=%s\nvolume_name=%s\nvolume_uuid=%s\ngroup_id=%s\ntopic_id=%s\n' "$WORK" "$PRESERVED" "${VOL:-unknown}" "${VOLUME_ID:-unknown}" "${GROUP_ID:-unknown}" "${TOPIC_ID:-unknown}"
    printf 'local_state_A=%s\nlocal_state_B=%s\nlocal_state_C=%s\n' "$A_VOLS" "$B_VOLS" "$C_VOLS"
    printf 'snapshot_contains=logs,local-state-A-B-C,existing-export-and-decrypt-artifacts\n'
  } >"$PRESERVED/run-identifiers.txt" || copy_rc=1
  (( copy_rc == 0 ))
}
cleanup() {
  local rc=$? clean_rc=0 c_status=0 b_status=0 a_status=0 delete_status=not-attempted preserve_rc=1 helper_pid
  (( CLEANING == 0 )) || return 0
  CLEANING=1
  trap - EXIT
  trap 'CLEANUP_INTERRUPTED=1' INT TERM HUP
  set +e
  if [[ -n "${CONFIRMED_MAP:-}" ]]; then rm -f -- "$CONFIRMED_MAP" || clean_rc=1; fi
  preserve_evidence
  preserve_rc=$?
  if (( preserve_rc == 0 )); then PRESERVE_STATUS=success; else PRESERVE_STATUS=failed; clean_rc=1; fi
  for helper_pid in "${HELPER_PIDS[@]}"; do
    if kill -0 "$helper_pid" 2>/dev/null; then kill -TERM "$helper_pid" 2>/dev/null; fi
  done
  for helper_pid in "${HELPER_PIDS[@]}"; do
    if kill -0 "$helper_pid" 2>/dev/null; then
      clean_rc=1
      local helper_deadline=$((SECONDS + 5))
      while kill -0 "$helper_pid" 2>/dev/null && (( SECONDS < helper_deadline )); do sleep 0.2; done
      if kill -0 "$helper_pid" 2>/dev/null; then kill -KILL "$helper_pid" 2>/dev/null; fi
    fi
    if ! kill -0 "$helper_pid" 2>/dev/null; then wait "$helper_pid" >/dev/null 2>&1; fi
  done
  if (( C_MOUNTED )); then
    local c_out
    if c_out=$(run_c volume unmount "$C_MNT" 2>&1); then c_status=0; else c_status=$?; fi
    log_text cleanup-c-unmount "$c_out"
    if unmount_confirmed "$c_out"; then printf 'drain_confirmed=yes\n' >>"$LOG_DIR/cleanup-c-unmount.log"; else printf 'drain_confirmed=no\n' >>"$LOG_DIR/cleanup-c-unmount.log"; clean_rc=1; fi
    printf 'unmount_exit_status=%s\n' "$c_status" >>"$LOG_DIR/cleanup-c-unmount.log"
    (( c_status == 0 )) || clean_rc=1
    if mount_absent "$C_MNT"; then
      if wait_mount_process c && mount_absent "$C_MNT"; then C_MOUNTED=0; else clean_rc=1; fi
    else clean_rc=1; fi
  fi
  if (( B_MOUNTED )); then
    local b_out
    if b_out=$(run_b volume unmount "$B_MNT" 2>&1); then b_status=0; else b_status=$?; fi
    log_text cleanup-b-unmount "$b_out"
    if unmount_confirmed "$b_out"; then printf 'drain_confirmed=yes\n' >>"$LOG_DIR/cleanup-b-unmount.log"; else printf 'drain_confirmed=no\n' >>"$LOG_DIR/cleanup-b-unmount.log"; clean_rc=1; fi
    printf 'unmount_exit_status=%s\n' "$b_status" >>"$LOG_DIR/cleanup-b-unmount.log"
    (( b_status == 0 )) || clean_rc=1
    if mount_absent "$B_MNT"; then
      if wait_mount_process b && mount_absent "$B_MNT"; then B_MOUNTED=0; else clean_rc=1; fi
    else clean_rc=1; fi
  fi
  if (( A_MOUNTED )); then
    local a_out
    if a_out=$(run_a volume unmount "$A_MNT" 2>&1); then a_status=0; else a_status=$?; fi
    log_text cleanup-a-unmount "$a_out"
    if unmount_confirmed "$a_out"; then printf 'drain_confirmed=yes\n' >>"$LOG_DIR/cleanup-a-unmount.log"; else printf 'drain_confirmed=no\n' >>"$LOG_DIR/cleanup-a-unmount.log"; clean_rc=1; fi
    printf 'unmount_exit_status=%s\n' "$a_status" >>"$LOG_DIR/cleanup-a-unmount.log"
    (( a_status == 0 )) || clean_rc=1
    if mount_absent "$A_MNT"; then
      if wait_mount_process a && mount_absent "$A_MNT"; then A_MOUNTED=0; else clean_rc=1; fi
    else clean_rc=1; fi
  fi
  if (( rc == 0 && clean_rc == 0 && preserve_rc == 0 && CLEANUP_INTERRUPTED == 0 && A_CREATED )) && [[ -n "$VOLUME_ID" ]] && (( A_MOUNTED == 0 && B_MOUNTED == 0 && C_MOUNTED == 0 )); then
    if run_a volume delete "$VOLUME_ID" --password-file "$PASSFILE" --force >"$LOG_DIR/cleanup-delete.log" 2>&1; then
      delete_status=success
    else
      delete_status=$?
      clean_rc=1
    fi
  elif (( rc == 0 && A_CREATED )); then
    clean_rc=1
  fi
  if (( preserve_rc == 0 )); then
    timeout --signal=TERM --kill-after=5s "${COMMAND_TIMEOUT}s" cp -a -- "$LOG_DIR/." "$PRESERVED/logs/" || clean_rc=1
  fi
  if (( rc == 0 && clean_rc == 0 )); then
    if [[ "$SHARED_SESSION" == 1 ]]; then
      printf 'PARTIAL PASS: all steps except revoke\n'
      exit 3
    fi
    printf 'LIVE SCRIPT PASS: volume=%s volume_uuid=%s group_topic=%s:%s\n' "$VOL" "$VOLUME_ID" "$GROUP_ID" "$TOPIC_ID"
    printf 'Pre-cleanup evidence snapshot=%s; run work=%s; A local volume state was deleted on successful cleanup.\n' "$PRESERVED" "$WORK"
    exit 0
  fi
  printf 'Preserved evidence snapshot=%s (status=%s); original work=%s\n  display_name=%s\n  volume_uuid=%s\n  group/topic=%s:%s\n  unmount_exit_statuses=C:%s B:%s A:%s\n  remote_delete=%s\n' "$PRESERVED" "$PRESERVE_STATUS" "$WORK" "${VOL:-unknown}" "${VOLUME_ID:-unknown}" "${GROUP_ID:-unknown}" "${TOPIC_ID:-unknown}" "$c_status" "$b_status" "$a_status" "$delete_status" >&2
  if (( rc != 0 )); then
    printf 'Test failed; remote deletion was not attempted. Preserved local-state copy precedes cleanup.\n' >&2
  elif [[ "$delete_status" == not-attempted ]]; then
    printf 'Unmount failed, evidence copy failed, or mount state was uncertain; remote deletion was skipped.\n' >&2
  else
    printf 'Remote deletion returned failure; the topic may be partially removed. Inspect preserved logs and local state before recovery.\n' >&2
  fi
  if (( CLEANUP_INTERRUPTED )); then printf 'Cleanup received a signal after the evidence snapshot; remote deletion was skipped.\n' >&2; fi
  rc=1
  exit "$rc"
}
trap cleanup EXIT

# A current session hash and installation UUID are discovered through the real
# device registry after each installation has joined and published an object.
declare -a PROPAGATION_MS=() PROPAGATION_LEDGER=()
SAMPLE_SEQ=0
RUN_NONCE=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
printf 'Starting one-host, three-installation 1.0 acceptance run (SHARED_SESSION=%s).\n' "$SHARED_SESSION"

VOL="live-$(date +%s)-$$"
A_CREATED=1 # Preserve the work directory if create partially publishes then fails.
create_out=''
if ! create_out=$(run_a volume create --name "$VOL" --password-file "$PASSFILE" 2>&1); then
  log_text create-failure "$create_out"
  fail "volume create failed; diagnostic: $LOG_DIR/create-failure.log"
fi
log_text create "$create_out"
VOLUME_ID=$(awk -F': *' '/^[[:space:]]*Volume ID:/ {print $2; exit}' <<<"$create_out")
GROUP_ID=$(awk -F': *' '/^[[:space:]]*Group ID:/ {print $2; exit}' <<<"$create_out")
TOPIC_ID=$(awk -F': *' '/^[[:space:]]*Topic ID:/ {print $2; exit}' <<<"$create_out" | awk '{print $1}')
OWNER_KEY=$(awk -F': *' '/^[[:space:]]*Owner public key:/ {print $2; exit}' <<<"$create_out")
[[ "$VOLUME_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || fail "create output lacks a valid volume UUID (see $LOG_DIR/create.log)"
[[ "$GROUP_ID" =~ ^-?[0-9]+$ && "$TOPIC_ID" =~ ^[0-9]+$ ]] || fail "create output lacks numeric group/topic IDs (see $LOG_DIR/create.log)"
[[ "$GROUP_ID" != 0 ]] && (( TOPIC_ID > 0 )) || fail 'create output contains a zero group or nonpositive topic ID'
[[ "$OWNER_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || fail "create output lacks the owner public key (see $LOG_DIR/create.log)"
OWNER_FINGERPRINT=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(bytes.fromhex(sys.argv[1])).hexdigest())' "$OWNER_KEY")
printf 'PASS create: volume_id=%s owner_fingerprint_sha256=%s\n' "$VOLUME_ID" "$OWNER_FINGERPRINT"

attach_start=$(now_ms)
if ! out=$(run_b volume attach "$GROUP_ID:$TOPIC_ID" --password-file "$PASSFILE" --owner-public-key "$OWNER_KEY" 2>&1); then log_text attach-b-failure "$out"; fail "B attach failed: $LOG_DIR/attach-b-failure.log"; fi
attach_end=$(now_ms)
log_text attach-b "$out"
[[ "$out" =~ Attached[[:space:]]+volume[[:space:]]+([0-9a-fA-F-]{36}) ]] || fail 'B attach output did not report its local volume UUID'
NAME_B="${BASH_REMATCH[1]}"
if ! out=$(run_c volume attach "$GROUP_ID:$TOPIC_ID" --password-file "$PASSFILE" --owner-public-key "$OWNER_KEY" 2>&1); then log_text attach-c-failure "$out"; fail "C attach failed: $LOG_DIR/attach-c-failure.log"; fi
log_text attach-c "$out"
[[ "$out" =~ Attached[[:space:]]+volume[[:space:]]+([0-9a-fA-F-]{36}) ]] || fail 'C attach output did not report its local volume UUID'
NAME_C="${BASH_REMATCH[1]}"
[[ "$NAME_B" == "$VOLUME_ID" && "$NAME_C" == "$VOLUME_ID" ]] || fail 'attach did not create local volume records for the published volume UUID'
printf 'PASS attach: attach_ms=%s B_name=%s C_name=%s owner_key_pinned=yes\n' "$((attach_end-attach_start))" "$NAME_B" "$NAME_C"

# Publish unique writes so every installation is registered before identity checks.
mount_one a "$A_MNT"
mount_one b "$B_MNT"
mount_one c "$C_MNT"
write_and_measure "$A_MNT" "$B_MNT" 'probe/a.txt' 'from-A'
write_and_measure "$B_MNT" "$C_MNT" 'probe/b.txt' 'from-B'
write_and_measure "$C_MNT" "$A_MNT" 'probe/c.txt' 'from-C'
write_and_measure "$B_MNT" "$A_MNT" 'probe/b.txt' 'from-B'
write_and_measure "$C_MNT" "$B_MNT" 'probe/c.txt' 'from-C'
write_and_measure "$A_MNT" "$C_MNT" 'probe/a.txt' 'from-A'

# Confirm independent installation IDs and owner-visible session bindings.
# Run each identity query with a process deadline.
id_a=$(run_a device list "$VOLUME_ID" --password-file "$PASSFILE")
id_b=$(run_b device list "$NAME_B" --password-file "$PASSFILE")
id_c=$(run_c device list "$NAME_C" --password-file "$PASSFILE")
log_text identity-a "$id_a"; log_text identity-b "$id_b"; log_text identity-c "$id_c"
ID_A=$(awk '/^This computer:/ {print $3}' <<<"$id_a")
ID_B=$(awk '/^This computer:/ {print $3}' <<<"$id_b")
ID_C=$(awk '/^This computer:/ {print $3}' <<<"$id_c")
HASH_A=$(awk '/hash=/ && /current=true/ {sub(/^.*hash=/,""); sub(/ .*/,""); print; exit}' <<<"$id_a")
HASH_B=$(awk '/hash=/ && /current=true/ {sub(/^.*hash=/,""); sub(/ .*/,""); print; exit}' <<<"$id_b")
HASH_C=$(awk '/hash=/ && /current=true/ {sub(/^.*hash=/,""); sub(/ .*/,""); print; exit}' <<<"$id_c")
[[ "$ID_A" =~ ^[0-9a-fA-F-]{36}$ && "$ID_B" =~ ^[0-9a-fA-F-]{36}$ && "$ID_C" =~ ^[0-9a-fA-F-]{36}$ ]] || fail 'device list did not return three full installation UUIDs'
[[ "$ID_A" != "$ID_B" && "$ID_A" != "$ID_C" && "$ID_B" != "$ID_C" ]] || fail 'the three volumes resolved to a shared installation identity'
[[ "$HASH_A" =~ ^-?[0-9]+$ && "$HASH_B" =~ ^-?[0-9]+$ && "$HASH_C" =~ ^-?[0-9]+$ ]] || fail 'device list did not return a current Telegram authorization for every installation'
USER_A=$(awk -v id="$ID_A" '$0 ~ "id=" id " " {for (i=1;i<=NF;i++) if ($i ~ /^telegram_user=/) {sub(/^telegram_user=/,"",$i); print $i; exit}}' <<<"$id_a")
USER_B=$(awk -v id="$ID_B" '$0 ~ "id=" id " " {for (i=1;i<=NF;i++) if ($i ~ /^telegram_user=/) {sub(/^telegram_user=/,"",$i); print $i; exit}}' <<<"$id_a")
USER_C=$(awk -v id="$ID_C" '$0 ~ "id=" id " " {for (i=1;i<=NF;i++) if ($i ~ /^telegram_user=/) {sub(/^telegram_user=/,"",$i); print $i; exit}}' <<<"$id_a")
[[ "$USER_A" =~ ^[0-9]+$ && "$USER_B" =~ ^[0-9]+$ && "$USER_C" =~ ^[0-9]+$ ]] || fail 'A registry lacks Telegram account IDs for A, B and C'
[[ "$USER_A" == "$USER_B" && "$USER_A" == "$USER_C" ]] || fail "this live harness covers same-account session revocation only; authorize B and C as separate sessions of A's Telegram account"
if [[ "$SHARED_SESSION" == 1 ]]; then
  if [[ "$HASH_A" != 0 && "$HASH_B" != 0 && "$HASH_C" != 0 ]]; then
    [[ "$HASH_A" == "$HASH_B" && "$HASH_A" == "$HASH_C" ]] || fail 'visible current hashes contradict the declared shared-session setup'
  fi
  ACCOUNT_RELATION=same_authorization
  printf 'PASS identity: distinct_installations=3 declared_shared_session=yes revoke=disabled\n'
else
  [[ "$HASH_B" == 0 || "$HASH_B" == "$B_SESSION_HASH" ]] || fail 'B current hash contradicts the owner-confirmed authorization'
  [[ "$HASH_C" == 0 || "$HASH_C" == "$C_SESSION_HASH" ]] || fail 'C current hash contradicts the owner-confirmed authorization'
  for confirmed_hash in "$B_SESSION_HASH" "$C_SESSION_HASH"; do
    grep -F "hash=$confirmed_hash " <<<"$id_a" | grep -F ' current=false' >/dev/null \
      || fail 'a confirmed B/C authorization is unavailable or current from A'
  done
  CONFIRMED_MAP=$WORK/confirmed-sessions.json
  python3 - "$CONFIRMED_MAP" "$ID_B" "$B_SESSION_HASH" "$ID_C" "$C_SESSION_HASH" <<'PY'
import json, sys
path, first_id, first_hash, second_id, second_hash = sys.argv[1:]
with open(path, 'x') as out:
    json.dump([{"installation_id": first_id, "authorization_hash": first_hash},
               {"installation_id": second_id, "authorization_hash": second_hash}], out)
PY
  ACCOUNT_RELATION=same_account
  printf 'PASS identity: distinct_installations=3 owner_confirmed_distinct_authorizations=yes\n'
fi

# Same-file concurrent edits start from the same observed baseline and are released together.
bounded_write 'baseline\n' "$C_MNT/shared.txt"
wait_for "$A_MNT/shared.txt" 'baseline' || fail 'C shared baseline did not reach A'
wait_for "$B_MNT/shared.txt" 'baseline' || fail 'shared baseline did not reach B'
barrier=$WORK/edit.start
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" python3 -c '
import os, sys, time
path, barrier, ready, payload = sys.argv[1:]
fd = os.open(path, os.O_RDWR)
if os.pread(fd, 64, 0) != b"baseline\n": raise SystemExit(41)
with open(ready, "wb"): pass
while not os.path.exists(barrier): time.sleep(0.02)
data = payload.encode() + b"\n"
if len(data) != len(b"baseline\n"): raise SystemExit(42)
if os.pwrite(fd, data, 0) != len(data): raise SystemExit(43)
os.fsync(fd)
os.close(fd)
' "$A_MNT/shared.txt" "$barrier" "$WORK/a.ready" 'edit-A!!' >"$LOG_DIR/concurrent-a.log" 2>&1 & pida=$!
HELPER_PIDS+=("$pida")
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" python3 -c '
import os, sys, time
path, barrier, ready, payload = sys.argv[1:]
fd = os.open(path, os.O_RDWR)
if os.pread(fd, 64, 0) != b"baseline\n": raise SystemExit(41)
with open(ready, "wb"): pass
while not os.path.exists(barrier): time.sleep(0.02)
data = payload.encode() + b"\n"
if len(data) != len(b"baseline\n"): raise SystemExit(42)
if os.pwrite(fd, data, 0) != len(data): raise SystemExit(43)
os.fsync(fd)
os.close(fd)
' "$B_MNT/shared.txt" "$barrier" "$WORK/b.ready" 'edit-B!!' >"$LOG_DIR/concurrent-b.log" 2>&1 & pidb=$!
HELPER_PIDS+=("$pidb")
wait_for "$WORK/a.ready" '' || fail 'A writer did not reach the shared baseline barrier'
wait_for "$WORK/b.ready" '' || fail 'B writer did not reach the shared baseline barrier'
# The readiness files prove both writers opened and observed the same baseline.
[[ "$(probe_path "$WORK/a.ready" file)" == present && "$(probe_path "$WORK/b.ready" file)" == present ]] || fail 'concurrent writers did not reach the shared baseline barrier'
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" touch "$barrier"
wait "$pida" || fail 'bounded A concurrent writer failed'
forget_helper "$pida"
wait "$pidb" || fail 'bounded B concurrent writer failed'
forget_helper "$pidb"
deadline=$((SECONDS + POLL_SECONDS))
while (( SECONDS < deadline )); do
  ca=$(bounded_read_until "$A_MNT/shared.txt" "$deadline" || true)
  cb=$(bounded_read_until "$B_MNT/shared.txt" "$deadline" || true)
  cc=$(bounded_read_until "$C_MNT/shared.txt" "$deadline" || true)
  if [[ -n "$ca" && "$ca" == "$cb" && "$cb" == "$cc" ]]; then break; fi
  (( SECONDS < deadline )) || break
  sleep 0.2
done
[[ "$ca" == "$cb" && "$cb" == "$cc" && ( "$ca" == 'edit-A!!' || "$ca" == 'edit-B!!' ) ]] || fail 'concurrent same-file edits did not converge to one writer value on all mounts'
CONCURRENT_WINNER=$ca

# The same TGFV shared path must show two full version UUIDs and both authors on every installation.
for app in a b c; do
  case $app in a) unmount_one a "$A_MNT"; history=$(run_a volume history "$VOLUME_ID" /shared.txt --password-file "$PASSFILE");;
    b) unmount_one b "$B_MNT"; history=$(run_b volume history "$NAME_B" /shared.txt --password-file "$PASSFILE");;
    c) unmount_one c "$C_MNT"; history=$(run_c volume history "$NAME_C" /shared.txt --password-file "$PASSFILE");; esac
  log_text "history-$app" "$history"
  if [[ $app == a ]]; then
    history_rows=$(awk -v path='shared.txt' '$NF==path && length($2)==36 && substr($2,9,1)=="-" && substr($2,14,1)=="-" && substr($2,19,1)=="-" && substr($2,24,1)=="-" && $2 !~ /[^0-9a-fA-F-]/ {print $2}' <<<"$history") || fail 'failed to parse A history rows'
    if [[ -n "$history_rows" ]]; then mapfile -t HISTORY_BEFORE_RESTORE <<<"$history_rows"; else HISTORY_BEFORE_RESTORE=(); fi
    baseline_rows=$(awk -v path='shared.txt' -v author="$ID_C" '$NF==path && $3==author && length($2)==36 && substr($2,9,1)=="-" && substr($2,14,1)=="-" && substr($2,19,1)=="-" && substr($2,24,1)=="-" && $2 !~ /[^0-9a-fA-F-]/ {print $2}' <<<"$history") || fail 'failed to parse baseline history rows'
    if [[ -n "$baseline_rows" ]]; then mapfile -t BASELINE_VERSIONS <<<"$baseline_rows"; else BASELINE_VERSIONS=(); fi
    [[ "${#BASELINE_VERSIONS[@]}" == 1 ]] || fail 'history does not identify exactly one C-authored common baseline version'
    BASELINE_VERSION_UUID=${BASELINE_VERSIONS[0]}
  fi
  version_rows=$(awk -v path='shared.txt' -v author_a="$ID_A" -v author_b="$ID_B" '$NF==path && ($3==author_a || $3==author_b) && length($2)==36 && substr($2,9,1)=="-" && substr($2,14,1)=="-" && substr($2,19,1)=="-" && substr($2,24,1)=="-" && $2 !~ /[^0-9a-fA-F-]/ {print $2 " " $3}' <<<"$history") || fail "failed to parse $app history rows"
  if [[ -n "$version_rows" ]]; then mapfile -t versions <<<"$version_rows"; else versions=(); fi
  [[ "${#versions[@]}" == 2 && "${versions[0]%% *}" != "${versions[1]%% *}" ]] || fail "history on $app lacks the two distinct concurrent full UUID versions for /shared.txt"
  [[ "$history" == *"$ID_A"* && "$history" == *"$ID_B"* ]] || fail "history on $app lacks both concurrent writer installation UUIDs"
  if [[ $app == a ]]; then CONCURRENT_VERSIONS=("${versions[@]}"); fi
  printf 'PASS history-%s: path=/shared.txt full_version_uuids=%s authors=A,B\n' "$app" "${versions[*]}"
done
mount_one a "$A_MNT"; mount_one b "$B_MNT"; mount_one c "$C_MNT"

# Select the record whose bytes are not the observed namespace winner. History row order can
# tie on HLC and does not establish which branch the mount resolved as the current head.
first_author=${CONCURRENT_VERSIONS[0]#* }
second_author=${CONCURRENT_VERSIONS[1]#* }
[[ "$first_author" != "$second_author" ]] || fail 'concurrent history versions do not identify both writers'
if [[ "$CONCURRENT_WINNER" == 'edit-A!!' ]]; then current_author=$ID_A; current_content='edit-A!!'; else current_author=$ID_B; current_content='edit-B!!'; fi
older=''; older_author=''; older_content=''
for row in "${CONCURRENT_VERSIONS[@]}"; do
  row_author=${row#* }
  if [[ "$row_author" != "$current_author" ]]; then older=${row%% *}; older_author=$row_author; if [[ "$row_author" == "$ID_A" ]]; then older_content='edit-A!!'; else older_content='edit-B!!'; fi; fi
done
[[ -n "$older" && "$older_content" != "$current_content" ]] || fail 'could not identify a concurrent history branch distinct from the live head'
current_before_restore=$(bounded_read "$C_MNT/shared.txt")
[[ "$current_before_restore" == "$current_content" && "$current_before_restore" != "$older_content" ]] || fail 'restore precondition failed: selected history branch is not distinct from the live head'
unmount_one a "$A_MNT"; unmount_one b "$B_MNT"; unmount_one c "$C_MNT"
restore_out=$(run_c volume restore-version "$NAME_C" /shared.txt "$older" --password-file "$PASSFILE")
log_text restore "$restore_out"
restore_history=$(run_c volume history "$NAME_C" /shared.txt --password-file "$PASSFILE")
log_text history-after-restore "$restore_history"
restored_rows=$(awk -v path='shared.txt' '$NF==path && length($2)==36 && substr($2,9,1)=="-" && substr($2,14,1)=="-" && substr($2,19,1)=="-" && substr($2,24,1)=="-" && $2 !~ /[^0-9a-fA-F-]/ {print $2 " " $3}' <<<"$restore_history") || fail 'failed to parse post-restore history rows'
if [[ -n "$restored_rows" ]]; then mapfile -t restored_versions <<<"$restored_rows"; else restored_versions=(); fi
[[ "${#restored_versions[@]}" == "$(( ${#HISTORY_BEFORE_RESTORE[@]} + 1 ))" ]] || fail 'restore did not append exactly one history version'
restore_author_found=0
for row in "${restored_versions[@]}"; do
  version=${row%% *}; author=${row#* }
  known_version=0
  for prior_version in "${HISTORY_BEFORE_RESTORE[@]}"; do [[ "$version" == "$prior_version" ]] && known_version=1; done
  (( known_version == 0 )) || continue
  [[ "$author" == "$ID_C" ]] || fail 'new version created by restore is not authored by C'
  restore_author_found=1
done
(( restore_author_found == 1 )) || fail 'restore history lacks a new C-authored version UUID'
mount_one a "$A_MNT"; mount_one b "$B_MNT"; mount_one c "$C_MNT"
restored=$(bounded_read "$C_MNT/shared.txt")
[[ "$restored" == "$older_content" && "$restored" != "$current_before_restore" ]] || fail 'restore did not change the newer content to the exact selected older version bytes'
for mp in "$A_MNT" "$B_MNT"; do wait_for "$mp/shared.txt" "$restored" || fail 'restored content did not propagate to all mounts'; done
printf 'PASS restore: selected_version_uuid=%s selected_author=%s new_author=C previous_content=%s restored_content=%s\n' "$older" "$older_author" "$current_before_restore" "$restored"

# Verify a version-pinned open handle with pread at offset zero, bounded in a helper process.
bounded_write 'pin-before\n' "$A_MNT/pinned.txt"
wait_for "$B_MNT/pinned.txt" 'pin-before' || fail 'pinning baseline did not reach B'
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" python3 -c '
import os, sys, time
path, ready, release, after = sys.argv[1:]
fd = os.open(path, os.O_RDONLY)
with open(ready, "wb") as out:
    out.write(os.pread(fd, 65536, 0))
while not os.path.exists(release):
    time.sleep(0.05)
with open(after, "wb") as out:
    out.write(os.pread(fd, 65536, 0))
os.close(fd)
' "$B_MNT/pinned.txt" "$WORK/pinned.ready" "$WORK/pinned.release" "$WORK/pinned.after" >"$LOG_DIR/pinned-reader.log" 2>&1 & PIN_PID=$!
HELPER_PIDS+=("$PIN_PID")
wait_for "$WORK/pinned.ready" 'pin-before' || fail 'B did not open and read the original pinned version'
bounded_write 'pin-after\n' "$A_MNT/pinned.txt"
wait_for "$B_MNT/pinned.txt" 'pin-after' || fail 'fresh B lookup did not observe A rewrite'
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" touch "$WORK/pinned.release"
wait_for "$WORK/pinned.after" 'pin-before' || fail 'B open handle did not remain pinned to its original version'
wait "$PIN_PID" || fail 'bounded B pinned-handle reader failed'
forget_helper "$PIN_PID"
[[ "$(bounded_read "$WORK/pinned.after")" == 'pin-before' ]] || fail 'B open handle returned unexpected bytes after A rewrite'
PINNED_VALUE=$(bounded_read "$WORK/pinned.after")
printf 'PASS pinned handle: old_handle=%s fresh_open=pin-after\n' "$PINNED_VALUE"

# Make an empty explicit directory and nested file fixture. The payload file is the final user-file write.
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" mkdir -p "$C_MNT/offline/empty-dir"
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" mkdir -p "$C_MNT/offline/nested"
bounded_write 'offline-object-byte-proof\n' "$C_MNT/offline/nested/payload.bin"
for mp in "$A_MNT" "$B_MNT"; do wait_for "$mp/offline/nested/payload.bin" 'offline-object-byte-proof' || fail 'nested offline fixture did not propagate'; done
wait_for_dir "$A_MNT/offline/empty-dir" || fail 'explicit empty directory did not reach A'
wait_for_dir "$B_MNT/offline/empty-dir" || fail 'explicit empty directory did not reach B'

tree_a=$(tree_digest "$A_MNT")
tree_b=$(tree_digest "$B_MNT")
tree_c=$(tree_digest "$C_MNT")
[[ "$tree_a" == "$tree_b" && "$tree_b" == "$tree_c" ]] || fail 'pre-revoke mounted trees are not identical after convergence'
for mp in "$A_MNT" "$B_MNT" "$C_MNT"; do
  conflicts=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" find "$mp" -type f -iname '*conflict*' -print -quit 2>>"$LOG_DIR/find-errors.stderr")
  [[ -z "$conflicts" ]] || fail "unexpected conflict-copy path found under $mp"
done
printf 'PASS pre-revoke trees: A=B=C sha256_manifest=%s\n' "$(printf '%s' "$tree_a" | sha256sum | awk '{print $1}')"

# A shared authorization copied into all three installations cannot safely be revoked
# per device: Telegram would end the operator's only login in every copy.
if [[ "$SHARED_SESSION" == 1 ]]; then
  printf 'NOT RUN: device revoke (needs distinct Telegram authorizations)\n'
else
# A must see B's exact live installation and binding before revocation.
registry=$(run_a device list "$VOLUME_ID" --password-file "$PASSFILE")
log_text registry-before-revoke "$registry"
grep -F "id=$ID_B " <<<"$registry" >/dev/null || fail 'B installation disappeared from A registry before revoke'
for confirmed_hash in "$B_SESSION_HASH" "$C_SESSION_HASH"; do
  grep -F "hash=$confirmed_hash " <<<"$registry" | grep -F ' current=false' >/dev/null \
    || fail 'a confirmed B/C authorization disappeared before revoke'
done
pre_revoke_b=$(run_b device list "$NAME_B" --password-file "$PASSFILE")
log_text b-remote-control "$pre_revoke_b"
grep -F "id=$ID_B " <<<"$pre_revoke_b" >/dev/null || fail 'B could not perform a successful Telegram device-list operation immediately before revoke'
mounted "$B_MNT" || fail 'B is not mounted immediately before revocation'
pre_revoke_b_read=$(bounded_read "$B_MNT/shared.txt") || fail 'B mounted read failed immediately before revocation'
[[ "$pre_revoke_b_read" == "$restored" ]] || fail 'B mounted read did not return the expected restored content immediately before revocation'
mounted "$B_MNT" || fail 'B detached during the pre-revocation mounted read'
# C is deliberately paused during revocation and will be restarted below.
unmount_one c "$C_MNT"
mounted "$B_MNT" || fail 'B detached before the revoke command began'
revoke_start=$(now_ms)
if ! revoke_out=$(run_a_no_tty device revoke "$VOLUME_ID" "$ID_B" --telegram-session="$B_SESSION_HASH" --confirmed-session-map "$CONFIRMED_MAP" --password-file "$PASSFILE" 2>&1); then log_text revoke-failure "$revoke_out"; fail "device revoke failed: $LOG_DIR/revoke-failure.log"; fi
revoke_end=$(now_ms)
log_text revoke "$revoke_out"
printf 'PASS revoke: target=B relation=%s revoke_ms=%s target_live_mounted=yes\n' "$ACCOUNT_RELATION" "$((revoke_end-revoke_start))"
after_revoke=$(run_a device list "$VOLUME_ID" --password-file "$PASSFILE")
log_text registry-after-revoke "$after_revoke"
if grep -Fq "hash=$B_SESSION_HASH " <<<"$after_revoke"; then fail 'A still sees the target authorization after revoke'; fi
grep -F "hash=$C_SESSION_HASH " <<<"$after_revoke" | grep -F ' current=false' >/dev/null || fail 'A no longer sees the surviving authorization after revoke'
mounted "$B_MNT" || fail 'B detached during revocation; cannot claim a live mounted target'
[[ "$(bounded_read "$B_MNT/shared.txt")" == "$restored" ]] || fail 'B could not read the known existing file immediately after revocation'
mounted "$B_MNT" || fail 'B detached during the post-revocation mounted control read'

# A fresh Telegram operation through B's still-running mount session must fail with the access-cut result.
# The public CLI has no way to author as C from B; the frozen-C spoof injection is covered by
# round3_int_n3_revoked_root_cannot_impersonate_a_frozen_installation in volume.rs.
fresh_path="$B_MNT/post-revoke-probe.txt"
if out=$(run_b device list "$NAME_B" --password-file "$PASSFILE" 2>&1); then
  fail 'B device list unexpectedly reached Telegram after revocation'
else
  log_text b-post-revoke-telegram "$out"
fi
if ! rg -Fq 'not authenticated with Telegram; run `teagarden auth login` first' "$LOG_DIR/b-post-revoke-telegram.log"; then
  fail "B post-revoke device list did not print the CLI's NotAuthenticated refusal: $LOG_DIR/b-post-revoke-telegram.log"
fi
if timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" bash -c 'printf "unauthorized-after-revoke\\n" >"$1"' _ "$fresh_path" 2>"$LOG_DIR/b-post-revoke-write.stderr"; then
  # A cached/local write may return success; it must still never upload to a surviving installation.
  write_diagnostic='local write accepted'
else
  write_diagnostic='local write rejected'
fi
end_check=$((SECONDS + POLL_SECONDS))
while (( SECONDS < end_check )); do
  assert_absent_until "$A_MNT/post-revoke-probe.txt" "$end_check"
  sleep 0.2
done
mount_one c "$C_MNT"
assert_absent "$C_MNT/post-revoke-probe.txt"
post_revoke_write_check=$((SECONDS + POLL_SECONDS))
while (( SECONDS < post_revoke_write_check )); do
  assert_absent_until "$A_MNT/post-revoke-probe.txt" "$post_revoke_write_check"
  assert_absent_until "$C_MNT/post-revoke-probe.txt" "$post_revoke_write_check"
  (( SECONDS < post_revoke_write_check )) && sleep 0.2
done
write_and_measure "$A_MNT" "$C_MNT" 'post-revoke-control.txt' 'A-still-authorized'
post_revoke_a_rel=$LAST_SAMPLE_REL
post_revoke_a_payload=$LAST_SAMPLE_PAYLOAD
fresh_b_path="$B_MNT/$post_revoke_a_rel"
fresh_read_deadline=$((SECONDS + POLL_SECONDS))
while (( SECONDS < fresh_read_deadline )); do
  mounted "$B_MNT" || fail 'B mount disappeared during the post-revocation fresh-path check'
  fresh_control=$(bounded_read_until "$B_MNT/shared.txt" "$fresh_read_deadline") || fail 'B known-file read failed or timed out during the post-revocation fresh-path check'
  [[ "$fresh_control" == "$restored" ]] || fail 'B known-file read changed during the post-revocation fresh-path check'
  remaining=$((fresh_read_deadline - SECONDS))
  (( remaining > 0 )) || break
  (( remaining > COMMAND_TIMEOUT )) && remaining=$COMMAND_TIMEOUT
  if out=$(timeout --signal=TERM --kill-after=2s "${remaining}s" python3 -c 'import errno,sys
try:
    with open(sys.argv[1], "rb") as f: f.read(1)
except OSError as e:
    print(e.errno)
    raise SystemExit(10 if e.errno == errno.ENOENT else 11)
else:
    print("present")' "$fresh_b_path" 2>&1); then
    fail "revoked B's running mount read A's post-revoke object: $fresh_b_path"
  else
    read_status=$?
  fi
  (( read_status != 124 && read_status != 137 )) || fail 'B fresh mounted read timed out'
  [[ "$read_status" == 10 && "$out" == 2 ]] || fail "B fresh mounted read failed for a reason other than ENOENT: $out (exit $read_status)"
  printf 'errno=%s path=%s mount=B\n' "$out" "$post_revoke_a_rel" >>"$LOG_DIR/b-fresh-read-probes.log"
  mounted "$B_MNT" || fail 'B mount disappeared during the post-revocation ENOENT result'
  assert_absent_until "$fresh_b_path" "$fresh_read_deadline"
  (( SECONDS < fresh_read_deadline )) && sleep 0.2
done
unmount_b_after_revoke
# Foreground mode forwards the mount child's auth diagnostic; daemon mode suppresses
# child stdout/stderr and reports only a generic startup failure.
B_MOUNTED=1
if out=$(run_b_mount_probe 2>&1); then
  fail 'B foreground mount unexpectedly restarted after revocation'
else
  log_text b-restart-denied "$out"
fi
if ! rg -Fq 'Not authenticated with Telegram. Run `teagarden auth login` first.' "$LOG_DIR/b-restart-denied.log"; then
  fail "B foreground mount did not print the CLI's NotAuthenticated refusal: $LOG_DIR/b-restart-denied.log"
fi
mount_absent "$B_MNT" || fail 'B foreground mount probe left a mount active or mount state unknown'
B_MOUNTED=0
write_and_measure "$C_MNT" "$A_MNT" 'post-revoke-c-write.txt' 'C-still-authorized'
post_revoke_c_rel=$LAST_SAMPLE_REL
post_revoke_c_payload=$LAST_SAMPLE_PAYLOAD
unmount_one c "$C_MNT"
history_after_revoke=$(run_c volume history "$NAME_C" /shared.txt --password-file "$PASSFILE")
log_text history-c-post-revoke "$history_after_revoke"
[[ "$history_after_revoke" == *"${CONCURRENT_VERSIONS[0]%% *}"* && "$history_after_revoke" == *"${CONCURRENT_VERSIONS[1]%% *}"* ]] || fail 'C lost retained historical versions after the access cut'
mount_one c "$C_MNT"
wait_for "$C_MNT/shared.txt" "$restored" || fail 'C restart could not cold-read restored old-file content'
wait_for "$C_MNT/$post_revoke_a_rel" "$post_revoke_a_payload" || fail 'C restart did not retain the new A object'
wait_for "$A_MNT/$post_revoke_c_rel" "$post_revoke_c_payload" || fail 'C post-revoke write did not reach A'
printf 'PASS post-revoke: B_access_denied=yes B_restart_refused=yes (%s) A_to_C_write=yes C_to_A_write=yes history_retained=yes C_restart=yes leaked_B_object=no\n' "$write_diagnostic"
fi

# Export with the still-valid session. The command requires an exclusive local volume
# lock, so stop every installation that is still mounted in the selected mode.
offline_source_tree=$(tree_digest "$A_MNT")
[[ "$offline_source_tree" == "$(tree_digest "$C_MNT")" ]] || fail 'A and C trees diverged before offline export'
bounded_read "$C_MNT/offline/nested/payload.bin" >"$WORK/expected-offline-payload.bin"
unmount_one a "$A_MNT"
if (( B_MOUNTED )); then unmount_one b "$B_MNT"; fi
unmount_one c "$C_MNT"
EXPORT_DIR=$WORK/export
run_a volume export-objects --out "$EXPORT_DIR" "$VOLUME_ID" --password-file "$PASSFILE"
OBJECT=''
candidate_index=0
candidate_list=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" find "$EXPORT_DIR" -type f -name 'file-*.tgf' -print 2>>"$LOG_DIR/find-errors.stderr")
declare -a candidates=()
if [[ -n "$candidate_list" ]]; then mapfile -t candidates <<<"$candidate_list"; fi
for candidate in "${candidates[@]}"; do
  candidate_index=$((candidate_index + 1))
  candidate_out=$WORK/object-candidate-$candidate_index
  if run_a decrypt "$candidate" --out "$candidate_out" --password-file "$PASSFILE" --owner-public-key "$OWNER_KEY"; then
    candidate_file=$candidate_out/offline/nested/payload.bin
    candidate_probe=$(probe_path "$candidate_file" file) || fail "filesystem probe failed while checking decrypted candidate $candidate"
    if [[ "$candidate_probe" == present ]] && timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" cmp -s "$WORK/expected-offline-payload.bin" "$candidate_file"; then
      [[ -n "$OBJECT" ]] || OBJECT=$candidate
    fi
  fi
done
[[ -n "$OBJECT" ]] || fail 'exported objects contain no single TGFV object that decrypts to the expected nested payload bytes'
mount_one a "$A_MNT"; mount_one c "$C_MNT"

# A directory export must restore explicit empty directories and report both output counts.
TREE_DECRYPT_DIR=$WORK/decrypted-tree
assert_absent "$TREE_DECRYPT_DIR"
tree_decrypt_out=$(run_a decrypt "$EXPORT_DIR" --out "$TREE_DECRYPT_DIR" --password-file "$PASSFILE" --owner-public-key "$OWNER_KEY")
log_text decrypt-directory "$tree_decrypt_out"
tree_summary=${tree_decrypt_out##*$'\n'}
tree_history=${tree_decrypt_out%$'\n'*}
[[ "$tree_summary" =~ ^decrypted\ ([0-9]+)\ file\(s\)\ and\ ([0-9]+)\ explicit\ directory\(s\)\ to\  ]] || fail 'directory decrypt did not end with the verified files/directories summary line'
tree_file_count=${BASH_REMATCH[1]}
tree_dir_count=${BASH_REMATCH[2]}
[[ "$tree_file_count" =~ ^[0-9]+$ && "$tree_dir_count" =~ ^[1-9][0-9]*$ ]] || fail 'directory decrypt did not report at least one explicit directory'
[[ "$tree_summary" == *" to $TREE_DECRYPT_DIR" ]] || fail 'directory decrypt summary names the wrong destination'
[[ "$tree_history" == *"path=offline/nested/payload.bin"* || "$tree_history" == *" offline/nested/payload.bin"* ]] || fail 'directory decrypt did not emit a history row for the nested payload'
for row in "${CONCURRENT_VERSIONS[@]}"; do
  concurrent_version=${row%% *}
  previous_rows=$(awk -v path='path=shared.txt' -v target="version_id=$concurrent_version" '
    $NF==path {
      version=""; previous=""
      for (i=1; i<=NF; i++) {
        if ($i ~ /^version_id=/) version=$i
        if ($i ~ /^previous=/) previous=substr($i,10)
      }
      if (version==target) print previous
    }
  ' <<<"$tree_history") || fail "failed to parse predecessor for concurrent version $concurrent_version"
  if [[ -n "$previous_rows" ]]; then mapfile -t previous_ids <<<"$previous_rows"; else previous_ids=(); fi
  [[ "${#previous_ids[@]}" == 1 && "${previous_ids[0]}" == "$BASELINE_VERSION_UUID" ]] || fail "concurrent version $concurrent_version does not name the common baseline predecessor $BASELINE_VERSION_UUID"
done
printf 'PASS concurrent edits: writer_versions=%s shared_previous_version=%s winner=%s\n' "${CONCURRENT_VERSIONS[*]}" "$BASELINE_VERSION_UUID" "$CONCURRENT_WINNER"
[[ "$(probe_path "$TREE_DECRYPT_DIR/offline/empty-dir" dir)" == present ]] || fail 'directory decrypt did not restore the explicit empty directory'
empty_contents=$(timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" find "$TREE_DECRYPT_DIR/offline/empty-dir" -mindepth 1 -print -quit 2>>"$LOG_DIR/find-errors.stderr")
[[ -z "$empty_contents" ]] || fail 'decrypted explicit empty directory contains unexpected children'
tree_decrypt_digest=$(tree_digest "$TREE_DECRYPT_DIR")
[[ "$tree_decrypt_digest" == "$offline_source_tree" ]] || fail 'directory decrypt did not restore the complete source path and file-content tree'
printf 'PASS directory decrypt: files=%s explicit_dirs=%s complete_tree_matches_source=yes summary=%s\n' "$tree_file_count" "$tree_dir_count" "$tree_summary"

# One downloaded TGFV object must decrypt by itself into a new output directory and preserve its nested path and exact bytes.
DECRYPT_DIR=$WORK/decrypted-single
assert_absent "$DECRYPT_DIR"
decrypt_out=$(run_a decrypt "$OBJECT" --out "$DECRYPT_DIR" --password-file "$PASSFILE" --owner-public-key "$OWNER_KEY")
log_text decrypt-single "$decrypt_out"
decrypt_summary=${decrypt_out##*$'\n'}
decrypt_history=${decrypt_out%$'\n'*}
[[ "$decrypt_summary" == "decrypted 1 file(s) and 0 explicit directory(s) to $DECRYPT_DIR" ]] || fail 'single-object decrypt summary reported unexpected counts or destination'
[[ "$decrypt_history" == *"path=offline/nested/payload.bin"* ]] || fail 'single-object decrypt did not emit the expected labelled nested history row'
DECRYPTED=$DECRYPT_DIR/offline/nested/payload.bin
[[ "$(probe_path "$DECRYPTED" file)" == present ]] || fail 'single-object decrypt did not preserve offline/nested/payload.bin'
timeout --signal=TERM --kill-after=2s "${COMMAND_TIMEOUT}s" cmp -s "$C_MNT/offline/nested/payload.bin" "$DECRYPTED" || fail 'offline decrypted object is not byte-equal to mounted source'
printf 'PASS offline decrypt: one_object=yes nested_path=offline/nested/payload.bin byte_equal=yes\n'

# Evidence-backed propagation metrics: each sample measures write start through remote visibility.
(( ${#PROPAGATION_MS[@]} >= 6 )) || fail 'not all six directed propagation paths were measured'
sorted=$(printf '%s\n' "${PROPAGATION_MS[@]}" | sort -n)
p50=$(awk '{a[NR]=$1} END {if (NR%2) print a[(NR+1)/2]; else print (a[NR/2]+a[NR/2+1])/2}' <<<"$sorted")
max=$(tail -n 1 <<<"$sorted")
printf 'PASS propagation: samples=%s propagation_p50_ms=%s propagation_max_ms=%s\n' "${#PROPAGATION_MS[@]}" "$p50" "$max"

# Final live check: the surviving mounts still agree with the encrypted tree source.
digest_a=$(tree_digest "$A_MNT"); digest_c=$(tree_digest "$C_MNT")
[[ "$digest_a" == "$digest_c" ]] || fail 'A and C trees diverged after revoke'
[[ "$digest_a" == "$offline_source_tree" ]] || fail 'mounted A/C trees changed after offline export/decrypt verification'
printf 'PASS final trees: A=C sha256_manifest=%s\n' "$(printf '%s' "$digest_a" | sha256sum | awk '{print $1}')"
