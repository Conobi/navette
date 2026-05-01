#!/usr/bin/env bash
# Idempotent teardown: remove both possible containers if present.

set -euo pipefail

for name in bench-h3 bench-tquic; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
        # Send SIGTERM with 10s grace so PROFILE_ACCEPT-on builds can flush
        # the SIGINT/SIGTERM handler's profile sidecar before the container
        # is force-killed. Off-builds: handler is comptime-elided, no overhead.
        docker stop -t 10 "$name" > /dev/null || true
        docker rm -f "$name" > /dev/null
        echo "[stop-server] stopped + removed $name"
    fi
done
