#!/usr/bin/env bash
# Idempotent teardown: remove all bench containers if present.

set -euo pipefail

for name in bench-h3 bench-tquic bench-lsquic; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
        # SIGTERM with a 10s grace before the container is force-killed.
        docker stop -t 10 "$name" > /dev/null || true
        docker rm -f "$name" > /dev/null
        echo "[stop-server] stopped + removed $name"
    fi
done
