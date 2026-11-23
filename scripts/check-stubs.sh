#!/usr/bin/env bash
# check-stubs.sh — CI guard against unclassified production stubs.
#
# A line is a violation if it:
#   - Matches the stub patterns (TODO, FIXME, not yet implemented, future release,
#     or explicit simulation/stub warnings)
#   - Is not explicitly marked INTENTIONAL_STUB: or EXPERIMENTAL:
#   - Is not in an excluded category (test code, wordlists, CSS, docs, this script)
#
# Usage: scripts/check-stubs.sh [--report-only]
#   --report-only  Print violations but exit 0 (useful for auditing without blocking CI).

set -euo pipefail

REPORT_ONLY=0
if [[ "${1:-}" == "--report-only" ]]; then
    REPORT_ONLY=1
fi

# Patterns that indicate a possible unimplemented feature. Match marker words
# with or without a colon and the Rust placeholder/panic macros themselves.
PATTERN='TODO:?|FIXME:?|todo!\s*\(|unimplemented!\s*\(|unreachable!\s*\(|not yet implemented|future release|simulation only|stub_warning'

command -v rg >/dev/null 2>&1 || {
    echo "FATAL: ripgrep (rg) is required for the production-stub gate" >&2
    exit 1
}

# Directories to scan (production source only)
SCAN_PATHS=(crates platform scripts system)
SCAN_EXISTING=()
for p in "${SCAN_PATHS[@]}"; do
    [[ -d "$p" || -f "$p" ]] && SCAN_EXISTING+=("$p")
done

if [[ ${#SCAN_EXISTING[@]} -eq 0 ]]; then
    echo "No source paths found. Run from repo root."
    exit 1
fi

VIOLATIONS=0
VIOLATION_LINES=""
RG_STATUS=0
RG_OUTPUT="$(rg -n "$PATTERN" "${SCAN_EXISTING[@]}" 2>/dev/null)" || RG_STATUS=$?
if [[ $RG_STATUS -gt 1 ]]; then
    echo "FATAL: ripgrep failed while scanning production source (exit $RG_STATUS)" >&2
    exit "$RG_STATUS"
fi

while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    file="${line%%:*}"
    rest="${line#*:}"
    lineno="${rest%%:*}"
    content="${rest#*:}"

    # Skip this script itself
    [[ "$file" == *"check-stubs.sh" ]] && continue

    # Allow: INTENTIONAL_STUB: or EXPERIMENTAL: markers
    [[ "$content" == *"INTENTIONAL_STUB:"* ]] && continue
    [[ "$content" == *"EXPERIMENTAL:"* ]] && continue

    # Allow: platform/macos (Swift File Provider — explicitly marked experimental in docs)
    case "$file" in
        platform/macos/*) continue ;;
    esac

    # Allow: test modules and test helper files
    case "$file" in
        */tests/*|*/test_*|*_test.rs) continue ;;
    esac

    # Allow: wordlist data files (contain real English words)
    case "$file" in
        */wordlists_data.rs|*/wordlist*.rs) continue ;;
    esac

    # Allow: placeholder_wordlist function (test scaffolding)
    [[ "$content" == *"placeholder_wordlist"* ]] && continue

    # Allow: bench scripts (documented unsupported-arch message)
    case "$file" in
        scripts/bench/*) continue ;;
    esac

    VIOLATIONS=$((VIOLATIONS + 1))
    VIOLATION_LINES+="${file}:${lineno}: ${content}"$'\n'
done <<< "$RG_OUTPUT"

if [[ $VIOLATIONS -gt 0 ]]; then
    echo "=== Unclassified production stubs found ($VIOLATIONS) ==="
    echo ""
    echo "$VIOLATION_LINES"
    echo "Fix options:"
    echo "  1. Implement the feature."
    echo "  2. Add '// INTENTIONAL_STUB: <reason>' on the line."
    echo "  3. Add '// EXPERIMENTAL: <reason>' if the feature is explicitly experimental."
    echo ""
    if [[ $REPORT_ONLY -eq 1 ]]; then
        echo "(report-only mode — not failing CI)"
        exit 0
    fi
    exit 1
fi

echo "Stub check passed — no unclassified production stubs found."
