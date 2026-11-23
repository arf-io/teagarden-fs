#!/usr/bin/env bash
# Fail when a full-feature CLI command has no top-level reference section.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
binary="${1:-target/debug/teagarden}"
[ -x "$binary" ] || {
    echo "FATAL: full-feature teagarden binary not found: $binary" >&2
    exit 1
}

missing=0
while IFS= read -r command; do
    [ "$command" = help ] && continue
    if ! grep -Eq "^### teagarden ${command}( |$)" docs/CLI_REFERENCE.md; then
        echo "FATAL: docs/CLI_REFERENCE.md has no section for '$command'" >&2
        missing=1
    fi
done < <("$binary" --help | awk '
    /^Commands:/ { in_commands = 1; next }
    in_commands && /^$/ { exit }
    in_commands { print $1 }
')

[ "$missing" -eq 0 ] || exit 1
printf 'CLI help/documentation command inventory: PASS\n'
