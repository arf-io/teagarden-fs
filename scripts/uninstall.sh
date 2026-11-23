#!/usr/bin/env bash
#
# Remove the TeaGarden binary that scripts/install.sh installed.
#
#   scripts/uninstall.sh                  # remove ~/.local/bin/teagarden
#   scripts/uninstall.sh --prefix /usr/local
#
# Your volumes, Telegram session and settings are NOT touched. They live in the
# TeaGarden config directory (see docs/ENVIRONMENT_VARIABLES.md). Delete volumes
# with `teagarden volume delete` before uninstalling if you want them gone from
# Telegram too.

set -euo pipefail

PREFIX="${HOME}/.local"
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
        -h|--help) sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

if [ -z "$PREFIX" ]; then
    echo "error: --prefix needs a directory" >&2
    exit 1
fi

if [ -x "$HOME/.cargo/bin/cargo" ] && ! command -v cargo >/dev/null 2>&1; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi

if [ ! -e "$PREFIX/bin/teagarden" ]; then
    echo "teagarden is not installed in $PREFIX/bin"
    exit 0
fi

if command -v cargo >/dev/null 2>&1 && cargo uninstall --root "$PREFIX" teagarden-cli; then
    :
else
    rm -f "$PREFIX/bin/teagarden"
fi

[ ! -e "$PREFIX/bin/teagarden" ] || { echo "error: could not remove $PREFIX/bin/teagarden" >&2; exit 1; }
echo "Removed $PREFIX/bin/teagarden. Volumes, session and settings were left in place."
