#!/usr/bin/env bash
# Pull the latest results/ directory from a remote bench host to this
# checkout. All three knobs are env-vars so this script can be
# committed without baking in any specific host or path.
#
# Usage:
#   BENCH_REMOTE=user@host:/path/to/navette/bench/flare_compare/results \
#       bash scripts/fetch-vps-results.sh
#
# Or set BENCH_USER / BENCH_HOST / BENCH_REMOTE_PATH separately.
set -euo pipefail

if [ -n "${BENCH_REMOTE:-}" ]; then
    REMOTE="$BENCH_REMOTE"
else
    : "${BENCH_USER:?set BENCH_USER (or BENCH_REMOTE=user@host:/path)}"
    : "${BENCH_HOST:?set BENCH_HOST (or BENCH_REMOTE=user@host:/path)}"
    : "${BENCH_REMOTE_PATH:?set BENCH_REMOTE_PATH (or BENCH_REMOTE=user@host:/path)}"
    REMOTE="${BENCH_USER}@${BENCH_HOST}:${BENCH_REMOTE_PATH}"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_PATH="${LOCAL_PATH:-$ROOT/results}"
mkdir -p "$LOCAL_PATH"

echo "→ Fetching $REMOTE/ to $LOCAL_PATH/"
rsync -avz --info=progress2 "$REMOTE/" "$LOCAL_PATH/"

echo ""
echo "Latest runs:"
ls -1t "$LOCAL_PATH" | head -5

LATEST="$(ls -1t "$LOCAL_PATH" | head -1)"
if [ -n "$LATEST" ] && [ -f "$LOCAL_PATH/$LATEST/summary.md" ]; then
    echo ""
    echo "── summary.md (latest) ──"
    cat "$LOCAL_PATH/$LATEST/summary.md"
fi
