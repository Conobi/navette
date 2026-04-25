#!/usr/bin/env bash
# Idempotent teardown: remove both possible containers if present.

set -euo pipefail

for name in bench-h3 bench-tquic; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
        docker rm -f "$name" > /dev/null
        echo "[stop-server] removed $name"
    fi
done
