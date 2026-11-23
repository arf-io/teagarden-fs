#!/usr/bin/env bash
# Render docs/CLI_REFERENCE.md mechanically from docs/CLI_HELP.txt: a fixed
# header, then one `### teagarden ...` section per `===== teagarden ... =====`
# help screen, each copied verbatim into a ```text block.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
input="${1:-docs/CLI_HELP.txt}"
output="${2:-docs/CLI_REFERENCE.md}"
[ -f "$input" ] || { echo "FATAL: help snapshot not found: $input" >&2; exit 1; }
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

{
    printf '# TeaGarden command reference\n\n'
    printf 'This file is generated mechanically from [CLI_HELP.txt](CLI_HELP.txt), which is the\n'
    printf '`--help` output of the real `teagarden` binary. Each section reproduces one help\n'
    printf 'screen verbatim. If the two ever differ, CLI_HELP.txt is authoritative.\n'
    awk '
        function close_section() {
            if (open) {
                # drop the blank separator lines generate-cli-help.sh appends
                while (n > 0 && body[n] == "") n--
                for (i = 1; i <= n; i++) print body[i]
                print "```"
            }
        }
        /^===== teagarden.* =====$/ {
            close_section()
            title = $0
            sub(/^===== /, "", title)
            sub(/ =====$/, "", title)
            printf "\n### %s\n\n```text\n", title
            open = 1
            n = 0
            next
        }
        { body[++n] = $0 }
        END { close_section() }
    ' "$input"
} > "$tmp"
mv "$tmp" "$output"
trap - EXIT
printf 'rendered CLI reference: %s\n' "$output"
