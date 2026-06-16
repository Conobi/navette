#!/usr/bin/env bash
# Build every Docker image the flare_compare harness needs.
#
# `navette` reuses the existing bench/Dockerfile (multi-stage Mojo build
# with boucle + jsonette build contexts). The rest are local
# minimal Dockerfiles under baselines/<target>/.
#
# On NixOS hosts (the bench VPS) docker bridge DNS is broken at build
# time; pass --network=host to every build via the env var BUILD_NET.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
BUILD_NET="${BUILD_NET:---network=host}"

# Repos that navette's Dockerfile expects as --build-context.
BOUCLE_DIR="${BOUCLE_DIR:-${REPO_ROOT}/../boucle}"
JSONETTE_DIR="${JSONETTE_DIR:-${REPO_ROOT}/../jsonette}"
# Remote-bench convention: rsync'd siblings live alongside this repo as
# *-build dirs. Fall back to those when the canonical names are missing.
[[ -d "$BOUCLE_DIR"   ]] || BOUCLE_DIR="${REPO_ROOT}/../boucle-build"
[[ -d "$JSONETTE_DIR" ]] || JSONETTE_DIR="${REPO_ROOT}/../jsonette-build"

ONLY="${1:-}"
should_build() {
    [[ -z "$ONLY" ]] && return 0
    IFS=',' read -ra arr <<< "$ONLY"
    for e in "${arr[@]}"; do [[ "$e" == "$1" ]] && return 0; done
    return 1
}

echo "→ Repo root: $REPO_ROOT"
echo "→ Boucle:    $BOUCLE_DIR"
echo "→ SimdJSON:  $JSONETTE_DIR"

if should_build wrk2; then
    echo ""; echo "── wrk2 ──"
    docker build $BUILD_NET -t flare-cmp-wrk2:latest \
        -f "$ROOT/baselines/wrk2/Dockerfile" "$ROOT/baselines/wrk2/"
fi

if should_build navette; then
    echo ""; echo "── navette (reuses bench/Dockerfile) ──"
    [[ -d "$BOUCLE_DIR"   ]] || { echo "missing boucle at $BOUCLE_DIR"   >&2; exit 2; }
    [[ -d "$JSONETTE_DIR" ]] || { echo "missing jsonette at $JSONETTE_DIR" >&2; exit 2; }
    docker build $BUILD_NET -t navette-bench:latest \
        --build-context boucle="$BOUCLE_DIR" \
        --build-context jsonette="$JSONETTE_DIR" \
        -f "$REPO_ROOT/bench/Dockerfile" "$REPO_ROOT"
fi

for target in nginx go-nethttp hyper axum actix-web flare; do
    should_build "$target" || continue
    echo ""; echo "── $target ──"
    docker build $BUILD_NET -t "flare-cmp-${target}:latest" \
        -f "$ROOT/baselines/${target}/Dockerfile" "$ROOT/baselines/${target}/"
done

echo ""
echo "✓ All requested images built."
docker images --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}' \
    | grep -E '^(flare-cmp-|navette-bench)' || true
