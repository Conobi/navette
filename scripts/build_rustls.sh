#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$REPO_ROOT/crates/librustls-mojo"
LIB_DIR="$REPO_ROOT/lib"

cd "$CRATE_DIR"
cargo test
cargo build --release

mkdir -p "$LIB_DIR"
case "$(uname -s)" in
    Darwin*) cp target/release/librustls_mojo.dylib "$LIB_DIR/" ;;
    *)       cp target/release/librustls_mojo.so "$LIB_DIR/" ;;
esac

echo "librustls_mojo built and copied to $LIB_DIR/"
