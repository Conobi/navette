#!/usr/bin/env bash
# H-multicore diagnostic: run 1 short-conn iteration with custom server cpuset.
# Single iteration only; outer loop in run-scaling.sh sequences iters with pauses.
#
# Usage: bench-cell.sh <server> <cpuset> <out_json>
#
# Captures: median rps + iqr (single iter so just rps), server CPU%

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: bench-cell.sh <server> <cpuset> <out_json>" >&2
    exit 2
fi

SERVER="$1"
CPUSET="$2"
OUT="$3"
PAYLOAD="1k"
SCENARIO="short-conn"
WARMUP_S=5
DURATION_S=30

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "$SERVER" in
    navette) CONTAINER=bench-h3 ;;
    tquic)    CONTAINER=bench-tquic ;;
    *) echo "unknown server: $SERVER" >&2; exit 2 ;;
esac

"$HERE/scripts/gen-payloads.sh" >/dev/null

"$HERE/scripts/h-multicore/start-server-cpuset.sh" "$SERVER" "$CPUSET" >/dev/null

# Warmup
"$HERE/scripts/run-tquic-client.sh" "$PAYLOAD" "$SCENARIO" "$WARMUP_S" >/dev/null

# CPU sampler aligned with measurement window
rm -f /tmp/cpu.json
"$HERE/scripts/measure-cpu.sh" "$CONTAINER" "$DURATION_S" &
CPU_BG=$!

# Measurement
"$HERE/scripts/run-tquic-client.sh" "$PAYLOAD" "$SCENARIO" "$DURATION_S"

wait "$CPU_BG" || true

python3 - "$OUT" "$SERVER" "$CPUSET" <<'PYEOF'
import json, os, subprocess, sys
out_path, server, cpuset = sys.argv[1:]
parsed = json.loads(subprocess.check_output(
    ["python3",
     os.path.join(os.environ.get("HERE", "."), "scripts/parse-tquic.py")],
    stdin=open("/tmp/client-stdout.log")))
cpu_mean = None
if os.path.exists("/tmp/cpu.json"):
    with open("/tmp/cpu.json") as f:
        cpu_mean = json.load(f).get("mean_pct")
result = {
    "server": server,
    "cpuset": cpuset,
    "rps": parsed.get("rps"),
    "server_cpu_percent": cpu_mean,
}
with open(out_path, "w") as f:
    json.dump(result, f, indent=2)
print(f"[h-multicore] {server} cpuset={cpuset} rps={result['rps']} cpu={cpu_mean}%")
PYEOF

"$HERE/scripts/stop-server.sh" >/dev/null
