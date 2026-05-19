#!/usr/bin/env bash
# Build librustls-mojo into lib/librustls_mojo.{so,dylib}.
#
# Profiles:
#   release  — feature flags: skip-locks, insecure.  Default. Standard ship.
#              Exports `*_insecure` so CLI tools (fetch -k) work like curl.
#              Insecure verification remains opt-in at the API level —
#              production server code must not call `*_new_insecure`.
#   dev      — feature flags: skip-locks, insecure.  Functional alias of
#              release; kept for muscle memory in local-dev workflows.
#   hardened — feature flags: skip-locks.            Strips `*_insecure` for
#              defense-in-depth in production server builds where the .so
#              must be unable to invoke the insecure verifier even if buggy
#              code references the symbol.
#   bench    — feature flags: skip-locks.            Bench harnesses measure
#              prod-like cert paths (same flags as hardened).
#   dist     — feature flags: skip-locks.            Cargo `--profile dist`
#              (strip+LTO+CGU=1). For wheels uploaded to PyPI. Same security
#              contract as hardened (no insecure symbol exported). Named
#              `dist` because Cargo reserves the profile name `publish`.
#
# The default is `release` so a clone-and-go `uv sync` produces a binary
# that behaves like curl. The leak check below fires only for `hardened`,
# `bench`, and `dist` (the profiles whose contract is "no insecure symbol").
set -euo pipefail
profile="${1:-release}"
case "$profile" in
    release|dev)               features="skip-locks,insecure"; cargo_profile="release"; target_subdir="release" ;;
    hardened|bench)            features="skip-locks";          cargo_profile="release"; target_subdir="release" ;;
    dist)                      features="skip-locks";          cargo_profile="dist";    target_subdir="dist" ;;
    *) echo "unknown profile: $profile (expected: release|dev|hardened|bench|dist)" >&2; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$REPO_ROOT/crates/librustls-mojo"
LIB_DIR="$REPO_ROOT/lib"

cd "$CRATE_DIR"
echo "building librustls-mojo (profile=$profile, features=$features)"

# When `skip-locks` is in the feature set, HandleTable swaps its Mutex for an
# UnsafeCell + `unsafe impl Sync` — the safety contract delegates synchronisation
# to the single-threaded Mojo runtime (io_uring event loop). Cargo's default
# test runner spawns multiple threads → violates the contract → HashMap races
# corrupt rustls's internal state and the test process SIGABRTs across the FFI
# boundary. Force `--test-threads=1` whenever skip-locks is enabled.
case ",$features," in
    *,skip-locks,*) cargo test --features "$features" -- --test-threads=1 ;;
    *)              cargo test --features "$features" ;;
esac
cargo build --profile "$cargo_profile" --features "$features"

mkdir -p "$LIB_DIR"
case "$(uname -s)" in
    Darwin*) cp "target/$target_subdir/liblibrustls_mojo.dylib" "$LIB_DIR/librustls_mojo.dylib" ;;
    *)       cp "target/$target_subdir/liblibrustls_mojo.so" "$LIB_DIR/librustls_mojo.so" ;;
esac

# Hardened / bench / publish builds must NOT export the insecure symbol; the
# contract is "this .so cannot perform insecure cert verification even if
# asked." For the release / dev profiles the symbol is intentionally present
# (CLI tools need it for `-k`).
case "$profile" in
    hardened|bench|dist)
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
        ;;
esac

echo "librustls_mojo (profile=$profile) built and copied to $LIB_DIR/"
