#!/usr/bin/env bash
# Guard: no IoUringDriver/BufRing/Completion/socle.linux.raw imports in navette.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
FOUND=$(grep -rEn 'from bouclette\.drivers\.io_uring|from bouclette\.drivers\.bufring|from bouclette\.socle\.linux\.raw' \
    "$REPO_ROOT/navette" "$REPO_ROOT/examples" "$REPO_ROOT/bench/servers" "$REPO_ROOT/tests" \
    --include='*.mojo' || true)
if [ -n "$FOUND" ]; then
    echo "FAIL: low-level bouclette imports found (should use WatchLoop):"
    echo "$FOUND"
    exit 1
fi
echo "ok: no IoUringDriver/BufRing/socle.linux.raw imports in navette"
