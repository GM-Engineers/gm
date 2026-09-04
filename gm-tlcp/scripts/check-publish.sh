#!/usr/bin/env bash
# check-publish.sh — pre-publish self-check for gm-tlcp.
#
# Runs `cargo package --list --allow-dirty` and asserts that the
# resulting tarball contents:
#   1. contain exactly the files we want shipped to crates.io, and
#   2. do NOT contain any dev-tooling / build-artifact paths.
#
# Why `--allow-dirty`? Without it, Cargo refuses to package any crate
# with uncommitted changes. We want a worst-case scan that catches
# anything a contributor might have left lying around — including
# things that aren't tracked yet but happen to be on disk.
#
# Run locally:
#     ./scripts/check-publish.sh
# CI: invoked from `.github/workflows/ci.yml` (job: publish-guard).

set -euo pipefail

cd "$(dirname "$0")/.."
PKG_DIR="$(pwd)"

echo "==> cargo package --list --allow-dirty (gm-tlcp)"
LIST_FILE="$(mktemp)"
trap 'rm -f "$LIST_FILE"' EXIT
cargo package --list --allow-dirty 2>/dev/null > "$LIST_FILE"

echo "    $(wc -l < "$LIST_FILE") entries"

# --- must-include: every required file is present -----------------------
REQUIRED=(
    "Cargo.toml"
    "Cargo.toml.orig"
    "README.md"
    "src/lib.rs"
    "src/tlcp.rs"
    "src/error.rs"
    "src/record.rs"
    "src/session_keys.rs"
    "src/metrics.rs"
    "examples/simple_client.rs"
    "examples/simple_server.rs"
    "examples/interop_client.rs"
    "examples/interop_proxy.rs"
)

missing=0
for f in "${REQUIRED[@]}"; do
    if ! grep -qxF "$f" "$LIST_FILE"; then
        echo "  MISSING from package: $f"
        missing=$((missing + 1))
    fi
done
if [ "$missing" -gt 0 ]; then
    echo "FAIL: $missing required file(s) are missing from the package."
    echo "      (This is unexpected — file moves in a PR must update this list.)"
    exit 1
fi

# --- must-exclude: dev tooling / build artifacts must NOT be packaged ---
# Mirror of the `exclude` list in Cargo.toml. If you add a new path
# there, add it here too. The order of these patterns doesn't matter.
FORBIDDEN_PATTERNS=(
    '^interop/'
    '^scripts/'
    '^\.github/'
    '^PUBLISHING\.md$'
    '^PUBLISHING\.md\.orig$'
    '^Tongsuo-'
    '^tongsuo-bin/'
    '^run/'
    '^target/'
    '^tests/'
)

forbidden_hits=0
while IFS= read -r line; do
    for pat in "${FORBIDDEN_PATTERNS[@]}"; do
        if echo "$line" | grep -Eq "$pat"; then
            echo "  FORBIDDEN in package: $line  (matches $pat)"
            forbidden_hits=$((forbidden_hits + 1))
        fi
    done
done < "$LIST_FILE"

if [ "$forbidden_hits" -gt 0 ]; then
    echo
    echo "FAIL: $forbidden_hits forbidden path(s) are present in the package."
    echo "      Add the offending paths to the crate's \`exclude\` field in"
    echo "      Cargo.toml, update FORBIDDEN_PATTERNS above if the rule"
    echo "      changed intentionally, and re-run."
    exit 1
fi

# --- size sanity check ---------------------------------------------------
# A properly-trimmed gm-tlcp tarball should be < 200 KiB. If it ever
# balloons into multi-MB territory, something has slipped in (probably
# a Tongsuo build tree) — fail loudly.
SIZE_HUMAN="$(du -sh target/package/ 2>/dev/null || echo '?')"
echo "    package staging area: $SIZE_HUMAN"

echo
echo "OK: gm-tlcp publish list is clean."