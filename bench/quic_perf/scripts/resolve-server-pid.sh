#!/usr/bin/env bash
# Echo the PID inside <container_name> so measure-cpu.sh can sample it.
# For mojo-net we bypass the launcher (--entrypoint /usr/local/bin/h3_server),
# so the container init PID is the worker PID directly. For tquic, same.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: resolve-server-pid.sh <container_name>" >&2
    exit 2
fi

CONTAINER="$1"

PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER" 2>/dev/null || echo 0)
if [[ "$PID" -eq 0 ]]; then
    echo "[resolve-server-pid] container $CONTAINER has no PID (not running)" >&2
    exit 1
fi

echo "$PID"
