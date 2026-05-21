#!/usr/bin/env bash
#
# Run the fuzz-harness suite per specs/2026-05-21-fuzz-harnesses-critical-parsers.md.
#
# Mirrors conformance/scripts/run_tests.sh shape but with FUZZ_FILTER substring
# match (vs CONFORMANCE_FILTER) and a separate HARNESSES list. Harnesses are
# added as they land in S2 / S3.
#
# Per-harness budget at default FUZZ_ITERS=5000: ~30 s wall (8 harnesses ×
# 30 s = ~4 min total). Override with FUZZ_SOAK=1 to remove the iter cap
# (intended for overnight pre-release runs).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/.." && pwd)"

export LD_LIBRARY_PATH="$REPO_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# Harnesses are appended here as they land (S2 + S3 per the plan).
# Empty list at S1 commit time — the script verifies its own structure.
HARNESSES=(
    varint
    h1_parser
    hpack
)

FILTER="${FUZZ_FILTER:-}"
PASSED=0
TOTAL=0

cd "$REPO_ROOT"

if [ "${#HARNESSES[@]}" -eq 0 ]; then
    echo "All 0/0 fuzz harnesses passed."
    exit 0
fi

for h in "${HARNESSES[@]}"; do
    if [ -n "$FILTER" ] && [[ "$h" != *"$FILTER"* ]]; then
        continue
    fi
    TOTAL=$((TOTAL + 1))
    echo "--- $h ---"
    # Note: ASSERT=all is intentionally omitted for fuzz runs. Random-byte
    # generators routinely produce non-UTF-8 sequences that would trip
    # String(unsafe_from_utf8) asserts inside both decoders; the relevant
    # property is parser-level agreement, not String-layer UTF-8 validation.
    if uv run mojox run -I "$REPO_ROOT" -I "$CONFORMANCE_DIR" "tests/fuzz/test_fuzz_$h.mojo"; then
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $h"
        exit 1
    fi
done

echo ""
echo "All $PASSED/$TOTAL fuzz harnesses passed."
