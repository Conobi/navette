#!/usr/bin/env bash
# Sample %CPU of <pid> every 1 s for <duration> seconds via pidstat.
# Writes /tmp/cpu.json with mean and max.
#
# Usage: measure-cpu.sh <pid> <duration_seconds>

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: measure-cpu.sh <pid> <duration>" >&2
    exit 2
fi

PID="$1"
DUR="$2"

if ! command -v pidstat >/dev/null 2>&1; then
    echo "[measure-cpu] pidstat not found; install sysstat" >&2
    exit 1
fi

# pidstat -h gives single-line, parse-friendly output.
# Columns: Time UID PID %usr %system %guest %wait %CPU CPU Command
# LC_ALL=C forces a `.` decimal separator regardless of host locale (some
# locales emit `,` and break the downstream float() parser).
RAW=$(LC_ALL=C pidstat -h -p "$PID" 1 "$DUR" 2>/dev/null | awk '/^[ \t]*[0-9]/ {print $8}')

if [[ -z "$RAW" ]]; then
    echo "[measure-cpu] pidstat produced no samples for pid=$PID" >&2
    echo '{"pid": '"$PID"', "samples": [], "mean_pct": null, "max_pct": null}' > /tmp/cpu.json
    exit 0
fi

python3 - "$PID" <<EOF
import json, sys
pid = int(sys.argv[1])
samples = [float(x) for x in """$RAW""".strip().splitlines() if x.strip()]
mean = sum(samples) / len(samples) if samples else None
mx = max(samples) if samples else None
out = {"pid": pid, "samples": samples, "mean_pct": mean, "max_pct": mx}
with open("/tmp/cpu.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"[measure-cpu] pid={pid} mean={mean} max={mx} samples={len(samples)}")
EOF
