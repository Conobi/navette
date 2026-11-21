#!/usr/bin/env bash
# Recompile the navette package and summarise diagnostics.
# Usage: scripts/measure.sh [logfile]
# Without [logfile] the log goes to a private temp dir, deleted when the build
# is clean and kept (path printed) when it fails or reports errors.
set -uo pipefail
cd "$(dirname "$0")/.."
WORK=""
if [ -z "${1:-}" ]; then
  # mktemp: unique and mode 0700, unlike a fixed /tmp name another user could
  # pre-create or symlink (CWE-377).
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/navette-measure-XXXXXX")
fi
LOG="${1:-$WORK/nav-lib.log}"
MP=$(find .venv -maxdepth 4 -type d -name mojo_packages | head -1)
uv run mojo precompile navette -I "$MP" > "$LOG" 2>&1
rc=$?
errors=$(grep -c ': error:' "$LOG")
echo "exit=$rc  errors=$errors  warnings=$(grep -c ': warning:' "$LOG")"
if [ -n "$WORK" ]; then
  if [ "$rc" -eq 0 ] && [ "$errors" -eq 0 ]; then
    rm -rf "$WORK"
  else
    echo "log kept: $LOG" >&2
  fi
fi
