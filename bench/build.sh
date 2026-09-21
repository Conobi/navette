#!/usr/bin/env bash
set -euo pipefail

# HttpArena calls this instead of `docker build frameworks/navette/`.
# We need the full repo as context + bouclette as a build-context.

# Resolve symlinks to find the real repo root
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BOUCLETTE_DIR="${BOUCLETTE_DIR:-$(cd "$REPO_ROOT/../bouclette" && pwd)}"
JSONETTE_DIR="${JSONETTE_DIR:-$(cd "$REPO_ROOT/../jsonette" && pwd)}"

echo "[build.sh] repo=$REPO_ROOT bouclette=$BOUCLETTE_DIR jsonette=$JSONETTE_DIR"

docker build \
    -t httparena-navette \
    --build-context bouclette="$BOUCLETTE_DIR" \
    --build-context jsonette="$JSONETTE_DIR" \
    -f "$REPO_ROOT/bench/Dockerfile" \
    "$REPO_ROOT"
