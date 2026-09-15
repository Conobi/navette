#!/usr/bin/env bash
# bench/ab/build.sh — Build OLD (origin/main, b2) and NEW (HEAD, 1.0.0) Docker images
# for A/B regression benchmarking.
#
# Usage:
#   bash bench/ab/build.sh            # build both
#   bash bench/ab/build.sh old        # build old only
#   bash bench/ab/build.sh new        # build new only
#
# Env:
#   MARCH   — target CPU (default: x86-64-v3+pclmul+aes for local laptop;
#             set to "cascadelake" for VPS at 45.155.169.185)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

MARCH="${MARCH:-x86-64-v3+pclmul+aes}"

# Sibling repos — current (1.0.0) checkouts
BOUCLE_NEW="${BOUCLE_DIR:-$(cd "$REPO_ROOT/../boucle" && pwd)}"
JSONETTE_NEW="${JSONETTE_DIR:-$(cd "$REPO_ROOT/../jsonette" && pwd)}"

# Old (b2) worktrees — created by setup
NAVETTE_OLD="$REPO_ROOT/.worktrees/bench-old"
BOUCLE_OLD="${BOUCLE_OLD_DIR:-$(cd "$REPO_ROOT/../boucle/.worktrees/bench-old" && pwd)}"
JSONETTE_OLD="${JSONETTE_OLD_DIR:-$(cd "$REPO_ROOT/../jsonette/.worktrees/bench-old" && pwd)}"

# Export a git-tracked-only tree to a temp dir (avoids sending .cache, .venv,
# .git, etc. to the Docker daemon — boucle's checkout alone is 16 GB with
# its .cache dir).
export_clean() {
    local src="$1" dest="$2"
    mkdir -p "$dest"
    git -C "$src" archive HEAD | tar x -C "$dest"
}

build_image() {
    local tag="$1" navette_src="$2" boucle_src="$3" jsonette_src="$4" march="$5"
    echo ""
    echo "================================================================"
    echo "  Building $tag  (march=$march)"
    echo "  navette:  $navette_src"
    echo "  boucle:   $boucle_src"
    echo "  jsonette: $jsonette_src"
    echo "================================================================"
    echo ""

    local tmpdir
    tmpdir="$(mktemp -d)"
    cleanup() { rm -rf "$tmpdir"; }
    trap cleanup EXIT

    # Export clean trees for sibling repos
    echo "[build] Exporting clean boucle tree..."
    export_clean "$boucle_src" "$tmpdir/boucle"
    echo "[build] Exporting clean jsonette tree..."
    export_clean "$jsonette_src" "$tmpdir/jsonette"
    echo "[build] Exporting clean navette tree..."
    export_clean "$navette_src" "$tmpdir/navette"

    # Patch --march in Dockerfile
    sed "s|--march=[^ ]*|--march=$march|g" \
        "$navette_src/bench/Dockerfile" > "$tmpdir/Dockerfile"

    docker build \
        -t "$tag" \
        --build-context "boucle=$tmpdir/boucle" \
        --build-context "jsonette=$tmpdir/jsonette" \
        -f "$tmpdir/Dockerfile" \
        "$tmpdir/navette"

    trap - EXIT
    rm -rf "$tmpdir"
}

target="${1:-both}"

case "$target" in
    old)
        if [ ! -d "$NAVETTE_OLD" ]; then
            echo "error: worktree $NAVETTE_OLD not found."
            echo "Run: git worktree add .worktrees/bench-old origin/main --detach"
            exit 1
        fi
        build_image "navette-bench:old" "$NAVETTE_OLD" "$BOUCLE_OLD" "$JSONETTE_OLD" "$MARCH"
        ;;
    new)
        build_image "navette-bench:new" "$REPO_ROOT" "$BOUCLE_NEW" "$JSONETTE_NEW" "$MARCH"
        ;;
    both)
        if [ ! -d "$NAVETTE_OLD" ]; then
            echo "error: worktree $NAVETTE_OLD not found."
            echo "Run: git worktree add .worktrees/bench-old origin/main --detach"
            exit 1
        fi
        build_image "navette-bench:old" "$NAVETTE_OLD" "$BOUCLE_OLD" "$JSONETTE_OLD" "$MARCH"
        build_image "navette-bench:new" "$REPO_ROOT" "$BOUCLE_NEW" "$JSONETTE_NEW" "$MARCH"
        ;;
    *)
        echo "usage: $0 [old|new|both]"
        exit 1
        ;;
esac

echo ""
echo "Done. Images:"
docker images --format '{{.Repository}}:{{.Tag}}  {{.Size}}  {{.CreatedAt}}' | grep navette-bench || true
