#!/usr/bin/env bash
# build-comparators.sh — build the Docker images for the comparison set.
#
# Pulls the three reference HTTP servers (hyper, nginx, h2o) plus the
# h2load and wrk load generators from HttpArena's framework definitions.
# mojo-net's own image is built by bench/build.sh — this script does NOT
# rebuild ours.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARENA="$REPO_ROOT/bench/.httparena"

if [ ! -d "$ARENA" ]; then
    echo "error: $ARENA not found. Clone HttpArena into bench/.httparena first."
    echo "see bench/.httparena/INSTRUCTIONS.md (gitignored) for setup."
    exit 1
fi

cd "$ARENA"

for fw in hyper nginx h2o; do
    echo "[build] httparena-$fw"
    docker build -t "httparena-$fw" -f "frameworks/$fw/Dockerfile" "frameworks/$fw"
done

echo "[build] h2load (load generator)"
docker build -t h2load:latest -f docker/h2load.Dockerfile .

echo "[build] wrk (load generator)"
docker build -t wrk:latest -f docker/wrk.Dockerfile .

echo
echo "Built images:"
docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -E "^(httparena-(hyper|nginx|h2o)|h2load|wrk):" | sort
