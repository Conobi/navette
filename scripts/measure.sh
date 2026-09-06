#!/usr/bin/env bash
# Recompile the navette package and summarise diagnostics.
# Usage: scripts/measure.sh [logfile]   (default /tmp/nav-lib.log)
set -uo pipefail
cd "$(dirname "$0")/.."
LOG="${1:-/tmp/nav-lib.log}"
MP=$(find .venv -maxdepth 4 -type d -name mojo_packages | head -1)
uv run mojo precompile navette -I "$MP" > "$LOG" 2>&1
echo "exit=$?  errors=$(grep -c ': error:' "$LOG")  warnings=$(grep -c ': warning:' "$LOG")"
