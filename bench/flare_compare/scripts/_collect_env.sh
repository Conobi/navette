#!/usr/bin/env bash
# Snapshot the host's overall shape into env.json — enough to interpret
# absolute numbers later (CPU class, RAM, loadavg, pinning, commit,
# image digests) without leaking host identity, co-resident workloads,
# or kernel-tunable choices specific to this box.
#
# The host label defaults to a neutral "bench-host" so the artifact is
# safe to publish. Override via $BENCH_HOST_LABEL for local diff/triage
# (e.g. `BENCH_HOST_LABEL=laptop` when running locally).
set -uo pipefail
HOST_LABEL="${BENCH_HOST_LABEL:-bench-host}"
KERNEL="$(uname -srm)"
CPU_MODEL="$(grep -m1 'model name' /proc/cpuinfo | sed 's/^[^:]*: //' || echo unknown)"
NPROC="$(nproc)"
LOADAVG_1="$(awk '{print $1}' /proc/loadavg)"
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
COMMIT="$(git -C "${BENCH_REPO_ROOT:-.}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
WRK2_IMG_DIGEST="$(docker image inspect flare-cmp-wrk2:latest --format '{{.Id}}' 2>/dev/null || echo unknown)"

declare -A IMG_DIGESTS
for t in navette flare nginx go-nethttp hyper axum actix-web; do
    img="flare-cmp-${t}:latest"
    [[ "$t" == "navette" ]] && img="navette-bench:latest"
    IMG_DIGESTS[$t]="$(docker image inspect "$img" --format '{{.Id}}' 2>/dev/null || echo missing)"
done

MEM_TOTAL_GB="$(awk '/^MemTotal:/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)"

python3 - <<PY
import json, os
print(json.dumps({
    "host_label":     "$HOST_LABEL",
    "kernel":         "$KERNEL",
    "cpu_model":      "$CPU_MODEL",
    "logical_cores":  int("$NPROC"),
    "memory_gb":      int("$MEM_TOTAL_GB" or 0),
    "loadavg_1min":   float("$LOADAVG_1" or 0),
    "pinning": {
        "server_cpu": os.environ.get("BENCH_SERVER_CPU", "?"),
        "client_cpu": os.environ.get("BENCH_CLIENT_CPU", "?"),
    },
    "docker_version":    "$DOCKER_VERSION",
    "commit":            "$COMMIT",
    "wrk2_image_digest": "$WRK2_IMG_DIGEST",
    "baseline_image_digests": {
$(for t in navette flare nginx go-nethttp hyper axum actix-web; do echo "        \"$t\": \"${IMG_DIGESTS[$t]}\","; done)
    },
    "captured_utc":  os.environ.get("BENCH_TS", ""),
}, indent=2))
PY
