#!/usr/bin/env bash
# Guard: the H3 servers arm their loop timer only inside _rearm_timer.
#
# Scans the library server and the bench server for the loop-timer call
# sites (`loop.timeout(`, `_loop_ptr[].timeout(`, `_timer.value().reset(`)
# and fails unless every match sits inside `def _rearm_timer`. The bare
# `timeout(` is deliberately not matched: it also hits the per-connection
# `h3.timeout(now)` deadline query.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"

FILES=(
    "$REPO_ROOT/navette/h3/h3_udp_server.mojo"
    "$REPO_ROOT/bench/servers/h3_server.mojo"
)
PATTERN='loop\.timeout\(|_loop_ptr\[\]\.timeout\(|_timer\.value\(\)\.reset\('

# Name of the `def` enclosing line $2 of file $1 (empty when none).
enclosing_def() {
    awk -v n="$2" '
        NR > n { exit }
        /^[[:space:]]*def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/ {
            line = $0
            sub(/^[[:space:]]*def[[:space:]]+/, "", line)
            sub(/[^A-Za-z0-9_].*$/, "", line)
            fn = line
        }
        END { print fn }
    ' "$1"
}

status=0
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "FAIL: missing $f"
        status=1
        continue
    fi
    matches=$(grep -nE "$PATTERN" "$f" || true)
    if [ -z "$matches" ]; then
        # The guard must see the real call sites, or it is vacuous.
        echo "FAIL: no loop-timer call site found in $f (guard would be vacuous)"
        status=1
        continue
    fi
    while IFS= read -r m; do
        ln="${m%%:*}"
        fn="$(enclosing_def "$f" "$ln")"
        if [ "$fn" != "_rearm_timer" ]; then
            echo "FAIL: loop-timer call outside _rearm_timer in $f:$m (in ${fn:-<module>})"
            status=1
        fi
    done <<< "$matches"
done

if [ "$status" -ne 0 ]; then
    exit 1
fi
echo "ok: loop timers armed only inside _rearm_timer (no fixed period)"
