#!/usr/bin/env bash
# Sample CPU% of <container> every 1 s for <duration> seconds via `docker stats`.
# Writes /tmp/cpu.json with mean and max.
#
# `docker stats` reports cgroup-level CPU usage as a percentage of all host
# CPUs (e.g. 100% = one full core). With `--cpuset-cpus=0` the ceiling is
# ~100%. Cgroup accounting catches all work attributed to the container,
# unlike `pidstat -p <docker-init-pid>` which misses kernel threads and
# child processes.
#
# Usage: measure-cpu.sh <container> <duration_seconds>

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: measure-cpu.sh <container> <duration>" >&2
    exit 2
fi

CONTAINER="$1"
DUR="$2"

if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
    echo "[measure-cpu] container $CONTAINER is not running" >&2
    echo '{"container": "'"$CONTAINER"'", "samples": [], "mean_pct": null, "max_pct": null}' > /tmp/cpu.json
    exit 0
fi

# Sample once per second. `docker stats --no-stream` is a single point read;
# loop it to build a samples array. LC_ALL=C forces `.` decimal separator.
SAMPLES=()
END=$(( $(date +%s) + DUR ))
while [[ $(date +%s) -lt $END ]]; do
    PCT=$(LC_ALL=C docker stats --no-stream --format '{{.CPUPerc}}' "$CONTAINER" 2>/dev/null | tr -d '%' || true)
    if [[ -n "$PCT" ]]; then
        SAMPLES+=("$PCT")
    fi
    # docker stats --no-stream takes ~1s itself, so no extra sleep needed.
done

if [[ ${#SAMPLES[@]} -eq 0 ]]; then
    echo "[measure-cpu] no samples collected for $CONTAINER" >&2
    echo '{"container": "'"$CONTAINER"'", "samples": [], "mean_pct": null, "max_pct": null}' > /tmp/cpu.json
    exit 0
fi

python3 - "$CONTAINER" "${SAMPLES[@]}" <<'PYEOF'
import json, sys
container = sys.argv[1]
samples = [float(x) for x in sys.argv[2:]]
mean = sum(samples) / len(samples) if samples else None
mx = max(samples) if samples else None
out = {"container": container, "samples": samples, "mean_pct": mean, "max_pct": mx}
with open("/tmp/cpu.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"[measure-cpu] container={container} mean={mean} max={mx} samples={len(samples)}")
PYEOF
