#!/usr/bin/env bash
# Generate a recursive, byte-for-byte snapshot of the supplied binary's help tree.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || {
    echo "usage: generate-cli-help.sh BINARY [OUTPUT]" >&2
    exit 2
}
binary="$1"
output="${2:-docs/CLI_HELP.txt}"
[ -x "$binary" ] || { echo "FATAL: binary is not executable: $binary" >&2; exit 1; }
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

render_help() {
    local help_text subcommand
    local -a path=("$@")
    help_text="$("$binary" "${path[@]}" --help)"
    if [ "${#path[@]}" -eq 0 ]; then
        printf '===== teagarden =====\n' >> "$tmp"
    else
        printf '===== teagarden %s =====\n' "${path[*]}" >> "$tmp"
    fi
    printf '%s\n\n' "$help_text" >> "$tmp"

    while IFS= read -r subcommand; do
        [ "$subcommand" = help ] && continue
        render_help "${path[@]}" "$subcommand"
    done < <(printf '%s\n' "$help_text" | awk '
        /^Commands:/ { in_commands = 1; next }
        in_commands && /^$/ { exit }
        in_commands { print $1 }
    ')
}

render_help
mkdir -p "$(dirname "$output")"
mv "$tmp" "$output"
trap - EXIT
printf 'generated CLI help: %s\n' "$output"
