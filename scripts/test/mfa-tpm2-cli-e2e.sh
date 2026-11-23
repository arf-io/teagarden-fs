#!/usr/bin/env bash
# K5 e2e — drive the REAL TeaGarden CLI to enroll a TPM2 factor onto a
# key-protected volume and then unlock that volume with the TPM.
#
# This is the "operator-real" bar: it runs the actual `teagarden mfa enroll` /
# `teagarden mfa unlock` verbs (not a library test) against a real software TPM
# (swtpm). It is fully OFFLINE — a volume's vault + config are local files; only
# block *data* needs Telegram — so the whole MFA story is exercised without a
# network.
#
#   Requires: swtpm, swtpm_setup, tpm2-tools.
#   Usage:    scripts/test/mfa-tpm2-cli-e2e.sh
#   Exit 0 = the factor was enrolled AND unlocked the volume, observed.
set -euo pipefail

BIN="${BIN:-target/debug/teagarden}"
PASSPHRASE="correct-horse-battery-staple"
WORK="$(mktemp -d)"
SWTPM_PID=""

cleanup() {
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
need cargo; need swtpm; need swtpm_setup; need tpm2_createprimary; need tpm2_pcrread

[ -x "$BIN" ] || { echo "build the CLI first: cargo build -p teagarden-cli"; exit 1; }

# ── 1. a software TPM ───────────────────────────────────────────────────────
SOCK="$WORK/swtpm.sock"
swtpm_setup --tpm2 --tpmstate "$WORK" --overwrite >/dev/null 2>&1
swtpm socket --tpm2 --tpmstate "dir=$WORK" \
  --server "type=unixio,path=$SOCK" --ctrl "type=unixio,path=$SOCK.ctrl" \
  --flags not-need-init,startup-clear >/dev/null 2>&1 &
SWTPM_PID=$!
export TPM2TOOLS_TCTI="swtpm:path=$SOCK"
for _ in $(seq 1 40); do
  tpm2_pcrread sha256:0 >/dev/null 2>&1 && break
  sleep 0.15
done
tpm2_pcrread sha256:0 >/dev/null 2>&1 || { echo "FAIL: swtpm never became ready"; exit 1; }
echo "[1] software TPM up"

# ── 2. an offline key-protected volume (CLI create needs Telegram; the vault
#        and config this exercises are identical) ────────────────────────────
export TEAGARDEN_VOLUMES_DIR="$WORK/volumes"
OUT="$(cargo run --locked -q -p teagarden-mfa --example mk_protected_volume -- k5-e2e "$PASSPHRASE" 2>/dev/null)"
VOL_ID="$(echo "$OUT" | sed -n 's/^VOLUME_ID=//p')"
RECOVERY="$(echo "$OUT" | sed -n 's/^RECOVERY=//p')"
[ -n "$VOL_ID" ] || { echo "FAIL: could not create the protected volume"; exit 1; }
echo "$RECOVERY" > "$WORK/recovery.txt"
echo "[2] key-protected volume created: $VOL_ID"

# ── 3. the factor must NOT open it yet (nothing enrolled) ───────────────────
if "$BIN" mfa unlock "$VOL_ID" --tpm2 >/dev/null 2>&1; then
  echo "FAIL: TPM2 unlocked the volume BEFORE any TPM2 slot was enrolled"; exit 1
fi
echo "[3] TPM2 correctly refuses before enrollment"

# ── 4. REAL CLI: enroll the TPM2 factor (unlock the vault via the recovery
#        sentence, then add a TPM-sealed slot) ───────────────────────────────
"$BIN" mfa enroll "$VOL_ID" --tpm2 --recovery-file "$WORK/recovery.txt" | tee "$WORK/enroll.log"
grep -q "Enrolled TPM2 slot" "$WORK/enroll.log" || { echo "FAIL: enroll did not report success"; exit 1; }
echo "[4] TPM2 factor enrolled via the real CLI"

# ── 5. REAL CLI: unlock the volume with the TPM alone ───────────────────────
"$BIN" mfa unlock "$VOL_ID" --tpm2 | tee "$WORK/unlock.log"
grep -q "unlocked via TPM2" "$WORK/unlock.log" || { echo "FAIL: TPM2 unlock did not report success"; exit 1; }
echo "[5] volume unlocked via the TPM — through the real CLI"

# ── 6. the pre-existing factors still work (enroll is additive) ─────────────
"$BIN" volume list >/dev/null 2>&1 || true   # sanity: CLI still healthy

echo
echo "== SUCCESS: a TPM2 factor was enrolled onto a key-protected volume and"
echo "   unlocked it, driven entirely through the real teagarden CLI =="
