#!/usr/bin/env bash
# h2-hotspots.sh — Phase 0 hotspot extractor.
#
# Reads a perf-folded.txt (output of stackcollapse-perf.pl) and writes
# a markdown report with two ranked tables:
#   1. Top N functions by SELF time   (aggregated by leaf symbol)
#   2. Top N functions by INCLUSIVE time (any frame in the stack)
#
# Self-time tells you "where CPU is actually burning"; inclusive-time
# tells you "what callers depend on this expensive thing." Both are
# useful and they often disagree (e.g. an allocator path is rarely
# hot self but ubiquitous inclusive).
#
# Usage:
#   h2-hotspots.sh [PERF_FOLDED_FILE] [OUT_MD]
# If PERF_FOLDED_FILE is omitted, picks the newest under bench/profile/runs/.
# If OUT_MD is omitted, writes to bench/profile/baselines/h2-hotspots-<sha>.md
#
# Knobs:
#   TOPN    rows per table (default 30)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOPN="${TOPN:-30}"

FOLDED="${1:-}"
if [ -z "$FOLDED" ]; then
    FOLDED="$(find "$REPO_ROOT/bench/profile/runs" -maxdepth 2 -name 'perf-folded.txt' \
        -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | awk '{print $2}')"
fi
if [ -z "$FOLDED" ] || [ ! -s "$FOLDED" ]; then
    echo "error: no perf-folded.txt found. Run h2-perf-record.sh first." >&2
    exit 1
fi

RUN_DIR="$(dirname "$FOLDED")"
SHA="$(basename "$RUN_DIR" | awk -F'-' '{print $NF}')"
[ -z "$SHA" ] && SHA="unknown"

OUT="${2:-$REPO_ROOT/bench/profile/baselines/h2-hotspots-$SHA.md}"
mkdir -p "$(dirname "$OUT")"

TOTAL=$(awk '{n=NF; s+=$n} END{print s+0}' "$FOLDED")
STACKS=$(wc -l <"$FOLDED")

echo "[hotspots] folded=$FOLDED samples_total=$TOTAL unique_stacks=$STACKS sha=$SHA"

# Self-time: leaf symbol = last semicolon-separated frame before the sample count.
SELF_TABLE=$(awk -v total="$TOTAL" '
    {
        n = NF
        count = $n
        # Reconstruct stack string (everything before the final field).
        stack = $1
        for (i = 2; i < n; i++) stack = stack " " $i
        # Leaf = last frame after final ";"
        m = split(stack, frames, ";")
        leaf = frames[m]
        self[leaf] += count
    }
    END {
        for (s in self) printf "%d\t%s\n", self[s], s
    }
' "$FOLDED" | sort -k1 -nr | head -"$TOPN" | awk -v total="$TOTAL" '
    {
        count = $1
        $1 = ""
        sub(/^[ \t]+/, "", $0)
        pct = (total > 0) ? (count * 100.0 / total) : 0
        printf "| %d | %.2f%% | `%s` |\n", count, pct, $0
    }
')

# Inclusive-time: every unique frame that appears anywhere in a stack.
# We split the stack at semicolons and credit each unique frame once per
# stack with that stack's sample count.
INCL_TABLE=$(awk -v total="$TOTAL" '
    {
        n = NF
        count = $n
        stack = $1
        for (i = 2; i < n; i++) stack = stack " " $i
        m = split(stack, frames, ";")
        # de-dupe frames within this stack
        delete seen
        for (j = 1; j <= m; j++) {
            f = frames[j]
            if (f == "") continue
            if (!(f in seen)) {
                seen[f] = 1
                incl[f] += count
            }
        }
    }
    END {
        for (s in incl) printf "%d\t%s\n", incl[s], s
    }
' "$FOLDED" | sort -k1 -nr | head -"$TOPN" | awk -v total="$TOTAL" '
    {
        count = $1
        $1 = ""
        sub(/^[ \t]+/, "", $0)
        pct = (total > 0) ? (count * 100.0 / total) : 0
        printf "| %d | %.2f%% | `%s` |\n", count, pct, $0
    }
')

cat >"$OUT" <<HEAD
# H2 Hotspots — \`$SHA\`

Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) from \`$(realpath --relative-to="$REPO_ROOT" "$FOLDED")\`.

- **Total weight:** $TOTAL
- **Unique stacks:** $STACKS
- **Top N:** $TOPN

> "Weight" is perf's PERIOD field (≈ cycles between samples), not raw
> sample count — it's what \`stackcollapse-perf.pl\` emits. Use the
> percentages, not the absolute numbers.

Self-time = CPU burning **inside** that function (leaf of the stack).
Inclusive-time = stacks that pass **through** that function. Allocators,
syscalls, and other "ubiquitous helpers" usually rank high in
inclusive-time but low in self-time, and vice versa.

## Top $TOPN by SELF time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
$SELF_TABLE

## Top $TOPN by INCLUSIVE time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
$INCL_TABLE
HEAD

echo "[hotspots] wrote $OUT"
