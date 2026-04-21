#!/usr/bin/env bash
set -euo pipefail

# HttpArena calls this instead of `docker build frameworks/mojo-net/`.
# We need the full repo as context + boucle as a build-context.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BOUCLE_DIR="${BOUCLE_DIR:-$(cd "$REPO_ROOT/../boucle" && pwd)}"

echo "[build.sh] repo=$REPO_ROOT boucle=$BOUCLE_DIR"

docker build \
    -t httparena-mojo-net \
    --build-context boucle="$BOUCLE_DIR" \
    -f "$REPO_ROOT/bench/Dockerfile" \
    "$REPO_ROOT"
