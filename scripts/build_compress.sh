#!/usr/bin/env bash
# Build libcompress-mojo into lib/libcompress_mojo.{so,dylib}.
#
# Mirrors scripts/build_rustls.sh but without TLS-specific feature flags
# (libcompress has no security-mode toggles — limits are runtime knobs
# set by the Mojo caller via DecoderLimits).
#
# Profiles:
#   release — default. Standard ship.
#   dev     — functional alias of release; kept for muscle memory.
#   dist    — Cargo `--profile dist` (strip+LTO+CGU=1). For wheels uploaded
#             to PyPI. ~50% smaller .so. Used by the CI workflow via
#             MOJOX_BUILD_PROFILE=dist. Named `dist` because `publish` is a
#             Cargo-reserved profile name.
set -euo pipefail
profile="${1:-release}"
case "$profile" in
    release|dev) cargo_profile="release"; target_subdir="release" ;;
    dist)        cargo_profile="dist";    target_subdir="dist" ;;
    *) echo "unknown profile: $profile (expected: release|dev|dist)" >&2; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$REPO_ROOT/crates/libcompress-mojo"
LIB_DIR="$REPO_ROOT/lib"

cd "$CRATE_DIR"
echo "building libcompress-mojo (profile=$profile)"

cargo test
cargo build --profile "$cargo_profile"

mkdir -p "$LIB_DIR"
case "$(uname -s)" in
    Darwin*) cp "target/$target_subdir/liblibcompress_mojo.dylib" "$LIB_DIR/libcompress_mojo.dylib" ;;
    *)       cp "target/$target_subdir/liblibcompress_mojo.so"    "$LIB_DIR/libcompress_mojo.so" ;;
esac

# Sanity: assert the exported symbol set is exactly the 9 we declared.
# If anyone adds an FFI export, symbols.toml must update too (gen_ffi_bindings.py
# will then pick it up). check_integrations.sh §2.4 enforces the same invariant
# at CI time.
if command -v nm >/dev/null; then
    case "$(uname -s)" in
        Darwin*) nm_args="-gU"; lib_path="$LIB_DIR/libcompress_mojo.dylib" ;;
        *)       nm_args="-D";  lib_path="$LIB_DIR/libcompress_mojo.so"   ;;
    esac
    lcm_count=$(nm $nm_args "$lib_path" 2>/dev/null | grep -cE '\blcm_[a-z_0-9]+$' || true)
    if [ "$lcm_count" -lt 9 ]; then
        echo "FAIL: expected >= 9 lcm_* exports, found $lcm_count" >&2
        exit 1
    fi
fi

echo "libcompress_mojo (profile=$profile) built and copied to $LIB_DIR/"
