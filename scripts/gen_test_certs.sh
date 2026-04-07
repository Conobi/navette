#!/usr/bin/env bash
# scripts/gen_test_certs.sh — Generate self-signed test certificates
set -euo pipefail

CERT_DIR="examples/reverse_proxy/certs"
mkdir -p "$CERT_DIR"

# Proxy server cert (client-facing TLS)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CERT_DIR/proxy_key.pem" -out "$CERT_DIR/proxy_cert.pem" \
    -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# Backend server cert
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CERT_DIR/backend_key.pem" -out "$CERT_DIR/backend_cert.pem" \
    -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

echo "Certificates generated in $CERT_DIR/"
