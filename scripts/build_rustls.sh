#!/usr/bin/env bash
# Build librustls-mojo into lib/librustls_mojo.{so,dylib}.
#
# Profiles:
#   dev      — feature flags: skip-locks, insecure.   Use for local TLS
#              client tests that skip peer-cert verification.
#   release  — feature flags: skip-locks.             Default. Production-grade.
#   bench    — feature flags: skip-locks.             Same flags as release;
#              kept distinct in case bench gets profile-specific opts later.
#
# CI / Dockerfiles / bench harnesses MUST pass an explicit profile.
# The default is `release` to make accidental insecure shipping impossible.
set -euo pipefail
profile="${1:-release}"
case "$profile" in
    dev)             features="skip-locks,insecure" ;;
    release|bench)   features="skip-locks" ;;
    *) echo "unknown profile: $profile (expected: dev|release|bench)" >&2; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$REPO_ROOT/crates/librustls-mojo"
LIB_DIR="$REPO_ROOT/lib"

cd "$CRATE_DIR"
echo "building librustls-mojo (profile=$profile, features=$features)"
cargo test --features "$features"
cargo build --release --features "$features"

mkdir -p "$LIB_DIR"
case "$(uname -s)" in
    Darwin*) cp target/release/liblibrustls_mojo.dylib "$LIB_DIR/librustls_mojo.dylib" ;;
    *)       cp target/release/liblibrustls_mojo.so "$LIB_DIR/librustls_mojo.so" ;;
esac

# Release/bench builds must NOT export the insecure symbol.
if [ "$profile" != "dev" ]; then
    case "$(uname -s)" in
        Darwin*)
            if command -v nm >/dev/null && nm -gU "$LIB_DIR/librustls_mojo.dylib" 2>/dev/null \
                | grep -q rlsm_quic_client_config_new_insecure; then
                echo "FAIL: $profile build leaked rlsm_quic_client_config_new_insecure" >&2
                exit 1
            fi ;;
        *)
            if command -v nm >/dev/null && nm -D "$LIB_DIR/librustls_mojo.so" 2>/dev/null \
                | grep -q rlsm_quic_client_config_new_insecure; then
                echo "FAIL: $profile build leaked rlsm_quic_client_config_new_insecure" >&2
                exit 1
            fi ;;
    esac
fi

echo "librustls_mojo (profile=$profile) built and copied to $LIB_DIR/"
