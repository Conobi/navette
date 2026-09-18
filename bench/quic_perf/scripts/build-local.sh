#!/usr/bin/env bash
# Build navette bench server binaries locally (no Docker).
#
# Usage:
#   build-local.sh [h1|h2|h2s|h3|h3s|launcher|all]  (default: h3)
#
# Environment:
#   MARCH  — target microarch (default: x86-64-v3+pclmul+aes)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
BUILD_DIR="$REPO_ROOT/bench/build"
BOUCLE_DIR="$REPO_ROOT/../boucle"
JSONETTE_DIR="$REPO_ROOT/../jsonette"

MARCH="${MARCH:-x86-64-v3+pclmul+aes}"
TARGET="${1:-h3}"

mkdir -p "$BUILD_DIR"

# Ensure librustls_mojo.so exists.
if [ ! -f "$REPO_ROOT/lib/librustls_mojo.so" ]; then
    echo "[build-local] building librustls_mojo.so ..."
    cargo build --release \
        --features skip-locks \
        --manifest-path "$REPO_ROOT/crates/librustls-mojo/Cargo.toml"
    mkdir -p "$REPO_ROOT/lib"
    cp "$REPO_ROOT/crates/librustls-mojo/target/release/liblibrustls_mojo.so" \
       "$REPO_ROOT/lib/librustls_mojo.so"
fi

build_server() {
    local src="$1" out="$2" label="$3" extra_i="${4:-}"
    echo "[build-local] $label -> $out"
    local cmd=(
        uv run mojo build
        --march="$MARCH"
        -I "$REPO_ROOT"
        -I "$BOUCLE_DIR"
    )
    if [ -n "$extra_i" ]; then
        cmd+=(-I "$extra_i")
    fi
    cmd+=("$src" -o "$out")
    LD_LIBRARY_PATH="$REPO_ROOT/lib" "${cmd[@]}"
}

case "$TARGET" in
    h1)
        build_server "$REPO_ROOT/bench/servers/h1_server.mojo" "$BUILD_DIR/h1_server" "h1_server" "$JSONETTE_DIR"
        ;;
    h2)
        build_server "$REPO_ROOT/bench/servers/h2_server.mojo" "$BUILD_DIR/h2_server" "h2_server" "$JSONETTE_DIR"
        ;;
    h2s)
        build_server "$REPO_ROOT/bench/servers/h2_streaming_server.mojo" "$BUILD_DIR/h2_streaming_server" "h2_streaming_server" "$JSONETTE_DIR"
        ;;
    h3)
        build_server "$REPO_ROOT/bench/servers/h3_server.mojo" "$BUILD_DIR/h3_server" "h3_server" "$JSONETTE_DIR"
        ;;
    h3s)
        build_server "$REPO_ROOT/bench/servers/h3_streaming_server.mojo" "$BUILD_DIR/h3_streaming_server" "h3_streaming_server" "$JSONETTE_DIR"
        ;;
    launcher)
        build_server "$REPO_ROOT/bench/launcher.mojo" "$BUILD_DIR/launcher" "launcher"
        ;;
    all)
        build_server "$REPO_ROOT/bench/servers/h1_server.mojo" "$BUILD_DIR/h1_server" "h1_server" "$JSONETTE_DIR"
        build_server "$REPO_ROOT/bench/servers/h2_server.mojo" "$BUILD_DIR/h2_server" "h2_server" "$JSONETTE_DIR"
        build_server "$REPO_ROOT/bench/servers/h2_streaming_server.mojo" "$BUILD_DIR/h2_streaming_server" "h2_streaming_server" "$JSONETTE_DIR"
        build_server "$REPO_ROOT/bench/servers/h3_server.mojo" "$BUILD_DIR/h3_server" "h3_server" "$JSONETTE_DIR"
        build_server "$REPO_ROOT/bench/servers/h3_streaming_server.mojo" "$BUILD_DIR/h3_streaming_server" "h3_streaming_server" "$JSONETTE_DIR"
        build_server "$REPO_ROOT/bench/launcher.mojo" "$BUILD_DIR/launcher" "launcher"
        ;;
    *)
        echo "unknown target: $TARGET (expected h1|h2|h2s|h3|h3s|launcher|all)" >&2
        exit 2
        ;;
esac

echo "[build-local] done"
