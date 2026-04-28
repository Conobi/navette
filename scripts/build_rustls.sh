#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$REPO_ROOT/crates/librustls-mojo"
LIB_DIR="$REPO_ROOT/lib"

cd "$CRATE_DIR"
cargo test --features insecure
cargo build --release --features insecure

mkdir -p "$LIB_DIR"
case "$(uname -s)" in
    Darwin*) cp target/release/liblibrustls_mojo.dylib "$LIB_DIR/librustls_mojo.dylib" ;;
    *)       cp target/release/liblibrustls_mojo.so "$LIB_DIR/librustls_mojo.so" ;;
esac

echo "librustls_mojo built and copied to $LIB_DIR/"
