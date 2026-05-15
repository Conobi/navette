#!/usr/bin/env bash
# Regenerate the test CA + server leaf cert used by H3 / QUIC tests.
#
# Modern rustls / webpki refuses a CA-marked cert as a TLS end-entity
# (OtherError(CaUsedAsEndEntity)), so the server identity cert and the
# trust root must be separate certs. This script emits:
#   - ca.crt / ca.key  : self-signed root CA (CA:TRUE)
#   - server.crt       : leaf signed by the CA (CA:FALSE, EKU=serverAuth,
#                         SAN=localhost/127.0.0.1/::1)
#   - server.key       : leaf private key
#
# Tests load `server.{crt,key}` for the server config and `ca.crt` for
# the client trust root. Re-run only when fixtures are about to expire
# (default validity = 100 years) or when a test needs different attrs.
#
# See plans/2026-05-13-deps-enhancement.md §3.1 (origin) and the
# 2026-05-15 fix that introduced the CA+leaf split.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/tests/fixtures/tls"
# `certs/` is gitignored repo-wide (line 35 of .gitignore — dev-generated
# certs shouldn't be committed); fixtures live under `tls/` to avoid the
# pattern while staying inside tests/fixtures/.

mkdir -p "$OUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# --- 1. CA: P-256 key + self-signed cert with CA:TRUE -----------------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$OUT_DIR/ca.key" 2>/dev/null

openssl req -x509 -new -nodes -key "$OUT_DIR/ca.key" \
    -days 36500 \
    -subj "/CN=mojo-net-test-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$OUT_DIR/ca.crt" 2>/dev/null

# --- 2. Leaf: P-256 key + CSR -----------------------------------------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$OUT_DIR/server.key" 2>/dev/null

openssl req -new -key "$OUT_DIR/server.key" \
    -subj "/CN=localhost" \
    -out "$TMP_DIR/server.csr" 2>/dev/null

# --- 3. Sign leaf CSR with CA (end-entity extensions) -----------------------
cat >"$TMP_DIR/leaf.ext" <<'EOF'
subjectAltName = DNS:localhost,DNS:localhost.localdomain,IP:127.0.0.1,IP:::1
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
EOF

openssl x509 -req \
    -in "$TMP_DIR/server.csr" \
    -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
    -days 36500 \
    -extfile "$TMP_DIR/leaf.ext" \
    -out "$OUT_DIR/server.crt" 2>/dev/null

# --- 4. Sanity: leaf must verify against CA --------------------------------
openssl verify -CAfile "$OUT_DIR/ca.crt" "$OUT_DIR/server.crt" >/dev/null

# Drop the openssl-emitted serial state file (regenerated each run).
rm -f "$OUT_DIR/ca.srl"

# Permissions: keys readable only by owner.
chmod 600 "$OUT_DIR/ca.key" "$OUT_DIR/server.key"

echo "regenerated:"
ls -la "$OUT_DIR"
