#!/bin/bash
# Fast test runner — compiles each test file directly from source via
# `mojo run`. The editable-install source symlink is removed to prevent
# the compiler from resolving navette through the site-packages path
# (which would recompile navette from source per target, 6-9× slower).
#
# Usage:
#   scripts/test.sh tests/quic/test_quic_connection.mojo     # specific files
#   scripts/test.sh tests/quic/ tests/h3/test_h3_e2e.mojo    # mixed
#   scripts/test.sh --mojox [mojox-args...]                   # full mojox test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$PROJECT_DIR/.venv"
MOJO="$VENV/bin/mojo"
SITE_MOJO="$VENV/lib/python3.14/site-packages/mojo_packages"

# ── Fix the source-shadows-precompiled symlink ──────────────────────────

_fix_symlink() {
    if [ -L "$SITE_MOJO/navette" ]; then
        rm "$SITE_MOJO/navette"
    fi
}

# ── Parse arguments ─────────────────────────────────────────────────────

if [ "${1:-}" = "--mojox" ]; then
    shift
    uv sync --quiet 2>/dev/null || true
    _fix_symlink
    exec "$VENV/bin/mojox" test "$@"
fi

# ── Direct mojo run (fast path) ────────────────────────────────────────

if [ $# -eq 0 ]; then
    echo "Usage: scripts/test.sh <test-files...>"
    echo "       scripts/test.sh --mojox [mojox-args...]"
    exit 1
fi

# Expand directory arguments to .mojo files
FILES=()
for arg in "$@"; do
    if [ -d "$PROJECT_DIR/$arg" ]; then
        while IFS= read -r f; do
            FILES+=("$f")
        done < <(find "$PROJECT_DIR/$arg" -name "test_*.mojo" -type f | sort)
    elif [ -f "$PROJECT_DIR/$arg" ]; then
        FILES+=("$PROJECT_DIR/$arg")
    elif [ -f "$arg" ]; then
        FILES+=("$arg")
    else
        echo "Not found: $arg" >&2
        exit 1
    fi
done

if [ ${#FILES[@]} -eq 0 ]; then
    echo "No test files found." >&2
    exit 1
fi

_fix_symlink

# Run each test file
PASS=0
FAIL=0
TOTAL_T0=$(date +%s%N)
for f in "${FILES[@]}"; do
    name=$(basename "$f" .mojo)
    t0=$(date +%s%N)
    if HOME="" PATH="$(dirname "$MOJO"):/usr/local/bin:/usr/bin:/bin" \
        MODULAR_DEBUG=stack-trace-on-error \
        "$MOJO" run -O0 --debug-level line-tables \
        -I "$SITE_MOJO" \
        -D ASSERT=all --num-threads 8 \
        -I "$PROJECT_DIR/conformance" \
        -I "$PROJECT_DIR/examples/reverse_proxy" \
        "$f" 2>&1; then
        t1=$(date +%s%N)
        printf "  %-50s %ss  ✓\n" "$name" "$(echo "scale=1; ($t1-$t0)/1000000000" | bc)"
        PASS=$((PASS + 1))
    else
        t1=$(date +%s%N)
        printf "  %-50s %ss  ✗\n" "$name" "$(echo "scale=1; ($t1-$t0)/1000000000" | bc)"
        FAIL=$((FAIL + 1))
    fi
done
TOTAL_T1=$(date +%s%N)

echo ""
echo "$((PASS + FAIL)) targets: $PASS passed, $FAIL failed ($(echo "scale=1; ($TOTAL_T1-$TOTAL_T0)/1000000000" | bc)s)"
[ $FAIL -eq 0 ]
