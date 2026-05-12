#!/usr/bin/env bash
# scripts/gen_test_certs.sh — Generate self-signed test certificates
#
# All certs use `basicConstraints=CA:FALSE` so rustls's QUIC validator
# accepts them as end-entity certs. Without this, modern rustls rejects
# self-signed CA:TRUE certs with `CaUsedAsEndEntity` even when the client
# is configured insecurely.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROXY_DIR="$REPO_ROOT/examples/reverse_proxy/certs"
ROOT_DIR="$REPO_ROOT/certs"
mkdir -p "$PROXY_DIR" "$ROOT_DIR"

_gen() {
    local out_cert="$1"
    local out_key="$2"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$out_key" -out "$out_cert" \
        -days 365 -nodes -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        -addext "basicConstraints=critical,CA:FALSE" 2>/dev/null
}

# Repo-root cert used by the hello_h{1,2,3}_server examples and the
# H3UdpServer smoke test (tests/test_h3_udp_server.mojo).
_gen "$ROOT_DIR/server.crt" "$ROOT_DIR/server.key"

# Reverse-proxy demo certs (client-facing + backend).
_gen "$PROXY_DIR/proxy_cert.pem" "$PROXY_DIR/proxy_key.pem"
_gen "$PROXY_DIR/backend_cert.pem" "$PROXY_DIR/backend_key.pem"

echo "Certificates generated in $ROOT_DIR/ and $PROXY_DIR/"
