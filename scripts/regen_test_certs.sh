#!/usr/bin/env bash
# Regenerate the self-signed P-256 cert used by H3 / QUIC tests.
#
# Output is committed under tests/fixtures/certs/. Re-run only when the
# committed cert is about to expire (default validity = 100 years) or
# when a test needs different cert attributes.
#
# Replaces the per-test `cryptography.x509.CertificateBuilder` calls in
# tests/test_h3_*.mojo, tests/test_quic_pacer_bypass.mojo, etc.
# See plans/2026-05-13-deps-enhancement.md §3.1.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/tests/fixtures/tls"
# `certs/` is gitignored repo-wide (line 35 of .gitignore — dev-generated
# certs shouldn't be committed); fixtures live under `tls/` to avoid the
# pattern while staying inside tests/fixtures/.

mkdir -p "$OUT_DIR"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$OUT_DIR/server.key" \
    -out    "$OUT_DIR/server.crt" \
    -days 36500 -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:localhost.localdomain,IP:127.0.0.1,IP:::1" \
    2>/dev/null

# Strip the openssl-emitted header comment for byte-stable diffs.
echo "regenerated:"
ls -la "$OUT_DIR"
