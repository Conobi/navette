#!/bin/bash
# Fast test runner — uses per-subpackage .mojoc files instead of the
# monolithic `mojo precompile navette` (which takes ~20 min due to a
# compiler scalability issue with whole-package compilation).
#
# Split precompile: ~2 min (10 subpackages compiled independently).
# Per-test compilation: ~3-25s each (no source-shadows-precompiled).
# Skips precompile entirely when .mojoc files are newer than source.
#
# Usage:
#   scripts/test.sh tests/quic/test_quic_connection.mojo     # specific files
#   scripts/test.sh tests/quic/ tests/h3/test_h3_e2e.mojo    # mixed
#   scripts/test.sh --recompile tests/quic/                   # force precompile
#   scripts/test.sh --mojox [mojox-args...]                   # full mojox test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$PROJECT_DIR/.venv"
MOJO="$VENV/bin/mojo"
SITE_MOJO="$VENV/lib/python3.14/site-packages/mojo_packages"
SPLIT_PKG="$PROJECT_DIR/.mojox/build/split-pkg"

SUBMODULES=(util compress net runtime tls h1 quic h2 h3 http)

# ── Fix the source-shadows-precompiled symlink ──────────────────────────

_fix_symlink() {
    if [ -L "$SITE_MOJO/navette" ]; then
        rm "$SITE_MOJO/navette"
    fi
}

# ── Check if split .mojoc files are up to date ──────────────────────────

_split_fresh() {
    [ -d "$SPLIT_PKG/navette" ] || return 1
    for mod in "${SUBMODULES[@]}"; do
        [ -s "$SPLIT_PKG/navette/${mod}.mojoc" ] || return 1
    done
    local stale
    stale=$(find "$PROJECT_DIR/navette/" -name "*.mojo" -newer "$SPLIT_PKG/navette/util.mojoc" -print -quit 2>/dev/null)
    [ -z "$stale" ]
}

# ── Split precompile ────────────────────────────────────────────────────

_precompile_split() {
    echo "Precompiling navette subpackages..."
    mkdir -p "$SPLIT_PKG/navette"
    _fix_symlink
    local total_t0 mod t0 t1
    total_t0=$(date +%s%N)
    for mod in "${SUBMODULES[@]}"; do
        t0=$(date +%s%N)
        "$MOJO" precompile "navette/$mod" \
            -o "$SPLIT_PKG/navette/${mod}.mojoc" \
            -I "$SITE_MOJO" \
            2>&1 | grep -E "^[^/]" || true
        t1=$(date +%s%N)
        printf "  %-12s %ss\n" "$mod" "$(echo "scale=1; ($t1-$t0)/1000000000" | bc)"
    done
    local total_t1
    total_t1=$(date +%s%N)
    echo "Precompile done in $(echo "scale=1; ($total_t1-$total_t0)/1000000000" | bc)s"
}

# ── Parse arguments ─────────────────────────────────────────────────────

FORCE_RECOMPILE=false

if [ "${1:-}" = "--recompile" ]; then
    FORCE_RECOMPILE=true
    shift
fi

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

# Ensure split .mojoc files are up to date
if $FORCE_RECOMPILE || ! _split_fresh; then
    _precompile_split
else
    _fix_symlink
    echo "navette.mojoc up to date — skipping precompile"
fi

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
        -I "$SPLIT_PKG" \
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
