#!/usr/bin/env bash
# Run one benchmark cell (or N iterations of one cell) and write JSON results.
#
# Usage:
#   bench.sh <server> <payload> <scenario> <client> [--iters N]
#     server   : mojo-net | tquic
#     payload  : 1k | 5k | 15k | 2m
#     scenario : long-conn | short-conn
#     client   : tquic_client | h2load
#     --iters  : number of iterations (default 1)

set -euo pipefail

if [[ $# -lt 4 ]]; then
    echo "usage: bench.sh <server> <payload> <scenario> <client> [--iters N]" >&2
    exit 2
fi

SERVER="$1"; shift
PAYLOAD="$1"; shift
SCENARIO="$1"; shift
CLIENT="$1"; shift

ITERS=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --iters) ITERS="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"

WARMUP_S=5
DURATION_S=30

case "$CLIENT" in
    tquic_client) RUN_CLIENT="$HERE/scripts/run-tquic-client.sh"; PARSE="$HERE/scripts/parse-tquic.py" ;;
    h2load)       RUN_CLIENT="$HERE/scripts/run-h2load-client.sh"; PARSE="$HERE/scripts/parse-h2load.py" ;;
    *) echo "unknown client: $CLIENT" >&2; exit 2 ;;
esac

case "$SERVER" in
    mojo-net) CONTAINER=bench-h3 ;;
    tquic)    CONTAINER=bench-tquic ;;
    *) echo "unknown server: $SERVER" >&2; exit 2 ;;
esac

"$HERE/scripts/gen-payloads.sh" >/dev/null

# Capture host facts once per invocation.
KERNEL=$(uname -sr)
CPU_MODEL=$(awk -F: '/^model name/ {print $2; exit}' /proc/cpuinfo | sed 's/^ //')
CORES_TOTAL=$(nproc)

mkdir -p "$HERE/results"

for iter in $(seq 1 "$ITERS"); do
    echo "=== bench: $SERVER / $PAYLOAD / $SCENARIO / $CLIENT / iter $iter/$ITERS ==="

    "$HERE/scripts/start-server.sh" "$SERVER" >/dev/null

    # Warmup — discard output.
    "$RUN_CLIENT" "$PAYLOAD" "$SCENARIO" "$WARMUP_S" >/dev/null

    # Start CPU sampler in the background, aligned with the measurement window.
    # Sampler reads cgroup CPU% via `docker stats` (catches all container
    # work, unlike pidstat on a single PID).
    rm -f /tmp/cpu.json
    "$HERE/scripts/measure-cpu.sh" "$CONTAINER" "$DURATION_S" &
    CPU_BG=$!

    # Measurement window.
    "$RUN_CLIENT" "$PAYLOAD" "$SCENARIO" "$DURATION_S"

    # Don't fail the whole run if pidstat is missing.
    wait "$CPU_BG" || true

    # Compose result JSON.
    TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    OUT="$HERE/results/${TS//:/-}-${SERVER}-${PAYLOAD}-${SCENARIO}-${CLIENT}-iter${iter}.json"

    python3 - "$OUT" "$SERVER" "$PAYLOAD" "$SCENARIO" "$CLIENT" "$iter" \
                     "$KERNEL" "$CPU_MODEL" "$CORES_TOTAL" \
                     "$DURATION_S" "$WARMUP_S" \
                     "$PARSE" <<'PYEOF'
import datetime, json, os, subprocess, sys
out_path, server, payload, scenario, client, iter_, kernel, cpu_model, cores_total, dur, warm, parse_script = sys.argv[1:]
with open("/tmp/client-stdout.log") as f:
    parsed = json.loads(subprocess.check_output(["python3", parse_script], stdin=f))
cpu_mean = None
if os.path.exists("/tmp/cpu.json"):
    with open("/tmp/cpu.json") as f:
        cpu = json.load(f)
        cpu_mean = cpu.get("mean_pct")
parsed["server_cpu_percent"] = cpu_mean
result = {
    "schema_version": 1,
    "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "host": {
        "kernel": kernel,
        "cpu_model": cpu_model,
        "cores_total": int(cores_total),
        "server_core": 0,
        "client_cores": [2, 3, 4, 5],
    },
    "server": server,
    "payload": payload,
    "scenario": scenario,
    "client": client,
    "iter": int(iter_),
    "config": {
        "duration_s": int(dur),
        "warmup_s": int(warm),
        "threads": 4 if client == "tquic_client" else 1,
        "max_concurrent_conns": 100,
        "max_requests_per_conn": 0 if scenario == "long-conn" else 1,
        "max_concurrent_requests": 10 if scenario == "long-conn" else 1,
        "send_udp_payload_size": 1350,
    },
    "results": parsed,
}
with open(out_path, "w") as f:
    json.dump(result, f, indent=2)
print(f"[bench] wrote {out_path}")
PYEOF

    "$HERE/scripts/stop-server.sh" >/dev/null
done

echo "[bench] done: $ITERS iteration(s)"
