#!/usr/bin/env bash
# Force-stop a baseline's container by convention name.
set -uo pipefail
TARGET="${1:?usage: _kill_baseline.sh <target>}"
NAME="flare-cmp-${TARGET}"
# `docker rm -f` releases the container's host-network port binding;
# nothing else owns 8080 in this harness.
docker rm -f "$NAME" >/dev/null 2>&1 || true
sleep 0.3
