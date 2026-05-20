#!/usr/bin/env bash
# Bring each baseline up in turn and verify GET /plaintext returns
# exactly "Hello, World!" (13 bytes). A target that diverges from the
# spec is rejected before any measurement runs — this is the
# response-byte integrity gate Flare's harness uses (and HttpArena's,
# and TFB's).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${BENCH_PORT:-8080}"
EXPECTED="Hello, World!"

declare -a TARGETS=("$@")
[[ ${#TARGETS[@]} -eq 0 ]] && { echo "_integrity_check.sh: no targets" >&2; exit 2; }

results_pass=0
results_fail=0
printf '%-15s %-9s %s\n' TARGET STATUS BODY
printf '%-15s %-9s %s\n' --------------- --------- ----
for t in "${TARGETS[@]}"; do
    run="$ROOT/baselines/$t/run.sh"
    check="$ROOT/baselines/_common/check.sh"
    [[ -x "$run"   ]] || run="bash $run"
    [[ -x "$check" ]] || check="bash $check"

    bash "$ROOT/scripts/_kill_baseline.sh" "$t" >/dev/null 2>&1 || true
    BENCH_PORT="$PORT" $run >/tmp/integrity-$t.stdout 2>/tmp/integrity-$t.stderr &
    pid=$!
    if BENCH_PORT="$PORT" $check >/dev/null 2>&1; then
        body="$(curl -sS -m 2 "http://127.0.0.1:${PORT}/plaintext" 2>/dev/null || true)"
        if [ "$body" = "$EXPECTED" ]; then
            printf '%-15s %-9s %q\n' "$t" PASS "$body"
            results_pass=$((results_pass + 1))
        else
            printf '%-15s %-9s %q\n' "$t" FAIL "$body"
            results_fail=$((results_fail + 1))
        fi
    else
        printf '%-15s %-9s %s\n' "$t" DOWN "(bring-up failed)"
        results_fail=$((results_fail + 1))
    fi
    bash "$ROOT/scripts/_kill_baseline.sh" "$t" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
done
echo ""
echo "$results_pass passed, $results_fail failed"
[ "$results_fail" -eq 0 ]
