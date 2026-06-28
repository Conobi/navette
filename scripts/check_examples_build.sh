#!/usr/bin/env bash
# scripts/check_examples_build.sh — Build every example to catch bit-rot.
#
# Iterates examples/*/pyproject.toml and, for each, force-rebuilds the editable
# navette pkg from current source (`uv sync --reinstall-package navette`) before
# building the example via `uv run --project examples/<name> mojox build
# main.mojo -o /tmp/_examples_smoke_<name>` with zero -I flags. The reinstall is
# load-bearing: `uv run` does not rebuild an editable Mojo package on source
# change, so without it the gate builds against a stale .venv pkg and tracks
# freshness, not correctness. Reports every example (no fail-fast).
#
# Invoked by scripts/run_tests.sh as a pre-test gate. Designed to be runnable
# standalone for developers iterating on an example.
#
# Exit codes:
#   0 — every example builds cleanly
#   1 — at least one example failed to build (error printed to stderr)
#   2 — preflight check failed (no examples found, missing lib/, etc.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$REPO_ROOT/lib"

if [ ! -d "$LIB_DIR" ]; then
    echo "FAIL: $LIB_DIR not present — run scripts/build_rustls.sh first" >&2
    exit 2
fi

# Discover examples: any examples/<name>/pyproject.toml is a stand-alone consumer.
declare -a EXAMPLES=()
for pyproject in "$REPO_ROOT"/examples/*/pyproject.toml; do
    [ -f "$pyproject" ] || continue
    EXAMPLES+=("$(dirname "$pyproject")")
done

if [ "${#EXAMPLES[@]}" -eq 0 ]; then
    echo "FAIL: no examples/<name>/pyproject.toml found" >&2
    exit 2
fi

echo "examples-smoke: building ${#EXAMPLES[@]} example(s)…"

FAIL_COUNT=0
declare -a FAILED=()

for ex_dir in "${EXAMPLES[@]}"; do
    name="$(basename "$ex_dir")"
    main_file="$ex_dir/main.mojo"
    if [ ! -f "$main_file" ]; then
        echo "  $name: SKIP (no main.mojo)"
        continue
    fi
    out_bin="/tmp/_examples_smoke_$name"
    printf "  %-22s " "$name:"
    # Rebuild the editable navette .mojopkg from current source first: `uv run`
    # does NOT rebuild an editable Mojo package when navette/** changes, so
    # without this the example links against whatever navette pkg its .venv was
    # last synced with — making the gate track .venv freshness, not example
    # correctness (it can false-pass on a stale-but-matching pkg and false-fail
    # on a stale-but-diverged one). boucle is git-pinned (immutable rev) and
    # never goes stale; only the editable navette path-dep needs the reinstall.
    if LD_LIBRARY_PATH="$LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
       uv sync --project "$ex_dir" --reinstall-package navette \
       > "/tmp/_examples_smoke_$name.log" 2>&1 \
       && LD_LIBRARY_PATH="$LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
       uv run --project "$ex_dir" mojox build "$main_file" -o "$out_bin" \
       >> "/tmp/_examples_smoke_$name.log" 2>&1; then
        echo "OK"
        rm -f "$out_bin" "/tmp/_examples_smoke_$name.log"
    else
        echo "FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED+=("$name")
        echo "    --- log: /tmp/_examples_smoke_$name.log ---" >&2
        # Print the last 30 lines of the failure log to surface the actual error
        # without flooding stdout for a successful run.
        tail -n 30 "/tmp/_examples_smoke_$name.log" >&2 || true
        echo "    --- end log ---" >&2
    fi
done

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "examples-smoke: FAILED — $FAIL_COUNT example(s) did not build:" >&2
    for f in "${FAILED[@]}"; do
        echo "  - $f" >&2
    done
    exit 1
fi

echo ""
echo "examples-smoke: all ${#EXAMPLES[@]} example(s) built cleanly"
