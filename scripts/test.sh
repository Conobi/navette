#!/bin/bash
# Test runner: compiles each test file with `mojo run` against a
# precompiled navette package instead of navette's source tree, in parallel.
#
# Why the indirection:
#   - tests/ is a Mojo package, so the compiler puts its parent (the
#     project root, which holds navette/) on the import path, and that
#     source dir wins over any -I. Test files are therefore compiled
#     through a staging root that links tests/, interop/, bench/ but not
#     navette/.
#   - site-packages/mojo_packages is left off -I: the editable-install
#     .pth hook re-creates a navette source symlink there on every
#     Python start (including the `mojo` wrapper itself).
#
# The package is rebuilt whenever the hash of navette/**/*.mojo, the
# compiler version, bouclette.mojoc or this script changes, so a stale
# package can never shadow edited source. Package build and staging-root
# setup run once, under a lock, before any worker starts; concurrent
# invocations serialize on it.
#
# Builds use -O1 by default (3x faster to compile than -O0, same
# -D ASSERT=all checks). Set NAVETTE_TEST_OPT=-O0 for debugging.
# Raised errors carry no stack trace unless NAVETTE_TEST_TRACE=1: capturing
# one per raise made the fuzz files 20-60x slower (they raise thousands of
# times by design).
#
# Usage:
#   scripts/test.sh                                  # whole suite
#   scripts/test.sh tests/quic/ tests/h3/test_h3_e2e.mojo   # files / dirs
#   scripts/test.sh -j 4 tests/                      # N parallel builds
#   NAVETTE_TEST_OPT=-O0 scripts/test.sh <files>
#
# -j defaults to min(2/3 of cores, available GB / 2.5), at least 1; each build
# gets cores / N compiler threads. Exit status is non-zero if any file fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$PROJECT_DIR/.venv"
MOJO="$VENV/bin/mojo"
# Glob the venv's Python version instead of hard-coding it; "$SITE_MOJO" is the first match.
SITE_MOJO=("$VENV"/lib/python3*/site-packages/mojo_packages)
BUILD_DIR="$PROJECT_DIR/.mojox/build/test"
PKG_DIR="$BUILD_DIR/pkg"
ROOT_DIR="$BUILD_DIR/root"

# ── Precompiled navette package, keyed by a content hash ───────────────

_source_hash() {
    {
        "$MOJO" --version
        sha256sum "$SITE_MOJO/bouclette.mojoc" "$0"
        (cd "$PROJECT_DIR" && find navette -type f -name '*.mojo' -print0 \
            | LC_ALL=C sort -z | xargs -0 sha256sum)
    } | sha256sum | cut -d' ' -f1
}

_ensure_package() {
    mkdir -p "$PKG_DIR" "$ROOT_DIR"
    exec 9>"$BUILD_DIR/.lock"
    flock 9

    # Create links only when missing: re-creating one would open a window
    # in which a concurrent invocation sees it absent.
    [ -L "$PKG_DIR/bouclette.mojoc" ] \
        || ln -sfn "$SITE_MOJO/bouclette.mojoc" "$PKG_DIR/bouclette.mojoc"
    local d
    for d in "$PROJECT_DIR"/*/; do
        d="$(basename "$d")"
        if [ "$d" != navette ] && [ -f "$PROJECT_DIR/$d/__init__.mojo" ] \
            && [ ! -L "$ROOT_DIR/$d" ]; then
            ln -s "$PROJECT_DIR/$d" "$ROOT_DIR/$d"
        fi
    done

    local want have=""
    want="$(_source_hash)"
    [ -f "$PKG_DIR/navette.sha256" ] && have="$(cat "$PKG_DIR/navette.sha256")"
    if [ "$want" != "$have" ] || [ ! -s "$PKG_DIR/navette.mojoc" ]; then
        rm -f "$PKG_DIR/navette.sha256" "$PKG_DIR/navette.mojoc"
        # The package name comes from the output file name, so build as
        # navette.mojoc in a scratch dir and move it into place.
        local t0 tmp="$BUILD_DIR/.tmp.$$"
        rm -rf "$tmp" && mkdir -p "$tmp"
        t0=$SECONDS
        if ! "$MOJO" precompile "$PROJECT_DIR/navette" -I "$SITE_MOJO" \
            -o "$tmp/navette.mojoc" > "$BUILD_DIR/precompile.log" 2>&1; then
            rm -rf "$tmp"
            grep -E 'error' "$BUILD_DIR/precompile.log" >&2 || cat "$BUILD_DIR/precompile.log" >&2
            echo "navette precompile failed (log: $BUILD_DIR/precompile.log)" >&2
            exit 1
        fi
        mv "$tmp/navette.mojoc" "$PKG_DIR/navette.mojoc"
        rm -rf "$tmp"
        echo "$want" > "$PKG_DIR/navette.sha256"
        printf "  %-50s %ss\n" "(precompile navette)" "$((SECONDS - t0))"
    fi

    exec 9>&-
}

# Map a test file under a root-level package (tests/, interop/, ...) to
# its path through the staging root; other files run in place.
_staged_path() {
    local f="$1" rel top
    rel="${f#"$PROJECT_DIR"/}"
    top="${rel%%/*}"
    if [ "$rel" != "$f" ] && [ -L "$ROOT_DIR/$top" ]; then
        echo "$ROOT_DIR/$rel"
    else
        echo "$f"
    fi
}

# Compile and run one test file; one result line on stdout (written in a
# single printf so parallel lines never interleave), full output only on
# failure. Exported for the xargs workers.
_run_one() {
    local f="$1" name t0 t1 ms log
    name=$(basename "$f" .mojo)
    log="$LOG_DIR/$name.$$.log"
    t0=$(date +%s%N)
    [ -z "${NAVETTE_TEST_TRACE:-}" ] || export MODULAR_DEBUG=stack-trace-on-error
    if HOME="" PATH="$(dirname "$MOJO"):/usr/local/bin:/usr/bin:/bin" \
        "$MOJO" run "${NAVETTE_TEST_OPT:--O1}" --debug-level line-tables \
        -D ASSERT=all --num-threads "$THREADS" \
        -I "$PKG_DIR" -I "$PROJECT_DIR/conformance" -I "$PROJECT_DIR/examples/reverse_proxy" \
        "$(_staged_path "$f")" > "$log" 2>&1; then
        t1=$(date +%s%N)
        ms=$(((t1 - t0) / 1000000))
        printf "  %-50s %d.%ds  ✓\n" "$name" $((ms / 1000)) $((ms % 1000 / 100))
    else
        t1=$(date +%s%N)
        ms=$(((t1 - t0) / 1000000))
        printf "  %-50s %d.%ds  ✗\n%s\n" "$name" $((ms / 1000)) $((ms % 1000 / 100)) "$(cat "$log")"
        return 1
    fi
}
export -f _run_one _staged_path

# ── Parse arguments ─────────────────────────────────────────────────────

CORES=$(nproc)
AVAIL_GB=$(awk '/MemAvailable/ {print int($2 / 1048576 * 10 / 25)}' /proc/meminfo)
JOBS=$((CORES * 2 / 3 < AVAIL_GB ? CORES * 2 / 3 : AVAIL_GB))
[ "$JOBS" -ge 1 ] || JOBS=1
if [ "${1:-}" = "-j" ]; then
    [[ "${2:-}" =~ ^[1-9][0-9]*$ ]] || { echo "-j needs a positive integer" >&2; exit 1; }
    JOBS="$2"
    shift 2
fi
[ $# -gt 0 ] || set -- tests conformance/tests

# Expand directory arguments to test_*.mojo files
FILES=()
for arg in "$@"; do
    if [ -d "$PROJECT_DIR/$arg" ]; then
        while IFS= read -r f; do
            FILES+=("$f")
        done < <(find "$PROJECT_DIR/$arg" -name "test_*.mojo" -type f | sort)
    elif [ -f "$PROJECT_DIR/$arg" ]; then
        FILES+=("$PROJECT_DIR/$arg")
    elif [ -f "$arg" ]; then
        FILES+=("$(realpath "$arg")")
    else
        echo "Not found: $arg" >&2
        exit 1
    fi
done

if [ ${#FILES[@]} -eq 0 ]; then
    echo "No test files found." >&2
    exit 1
fi

_ensure_package

for d in "$ROOT_DIR" "$PKG_DIR" "$PROJECT_DIR/conformance" "$PROJECT_DIR/examples/reverse_proxy"; do
    if [ -e "$d/navette" ]; then
        echo "navette source reachable via $d/navette; it would shadow the package" >&2
        exit 1
    fi
done

[ "$JOBS" -le "${#FILES[@]}" ] || JOBS=${#FILES[@]}
export THREADS=$((CORES / JOBS > 0 ? CORES / JOBS : 1))
export PROJECT_DIR MOJO PKG_DIR ROOT_DIR
LOG_DIR="$(mktemp -d)"
export LOG_DIR
trap 'rm -rf "$LOG_DIR"' EXIT

# Largest files first: they are the slowest to compile, so starting them
# early keeps the tail of the run short.
SECONDS=0
echo "${#FILES[@]} files, -j $JOBS, $THREADS threads each, ${NAVETTE_TEST_OPT:--O1}"
set +e
ls -S -- "${FILES[@]}" | xargs -d '\n' -n 1 -P "$JOBS" bash -c '_run_one "$1"' _ | tee "$LOG_DIR/results"
set -e

PASS=$(grep -c '✓$' "$LOG_DIR/results" || true)
FAIL=$(grep -c '✗$' "$LOG_DIR/results" || true)
echo ""
echo "$((PASS + FAIL)) targets: $PASS passed, $FAIL failed (${SECONDS}s)"
[ "$FAIL" -eq 0 ] && [ $((PASS + FAIL)) -eq ${#FILES[@]} ]
