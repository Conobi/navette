#!/usr/bin/env bash
# Runs the pinned h3spec against examples/hello_h3_server and gates on pass_count >= conformance/h3spec_min_pass.txt.
# Exit codes:
#   0 — passes >= threshold
#   1 — passes < threshold (regression)
#   2 — environment / setup failure
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/.." && pwd)"
VENDOR="$CONFORMANCE_DIR/vendor/h3spec"
H3SPEC="$VENDOR/h3spec"
# Upstream ships the binary gzipped; SHA256SUMS pins the DECOMPRESSED ELF.
RELEASE_URL="https://github.com/kazu-yamamoto/h3spec/releases/download/v0.1.0/h3spec-linux-x86_64.gz"
THRESHOLD_FILE="$CONFORMANCE_DIR/h3spec_min_pass.txt"
SERVER_BIN="$REPO_ROOT/examples/hello_h3_server/hello_h3_server"

# Ensure the cached binary exists; download + gunzip on first use.
ensure_binary() {
    if [[ -x "$H3SPEC" ]] && (cd "$VENDOR" && sha256sum -c SHA256SUMS >/dev/null 2>&1); then
        return 0
    fi
    echo "[run_h3spec] downloading h3spec from $RELEASE_URL" >&2
    local tmp_gz tmp
    tmp_gz="$(mktemp --suffix=.gz)"
    tmp="${tmp_gz%.gz}"
    if ! curl -L --http1.1 -fSso "$tmp_gz" "$RELEASE_URL"; then
        echo "[run_h3spec] download failed" >&2
        rm -f "$tmp_gz"
        return 2
    fi
    if ! gunzip -f "$tmp_gz"; then
        echo "[run_h3spec] gunzip failed" >&2
        rm -f "$tmp_gz" "$tmp"
        return 2
    fi
    chmod +x "$tmp"
    mv "$tmp" "$H3SPEC"
    if ! (cd "$VENDOR" && sha256sum -c SHA256SUMS >/dev/null); then
        echo "[run_h3spec] checksum mismatch after download; SHA256SUMS may be stale" >&2
        return 2
    fi
}

[[ -f "$VENDOR/SHA256SUMS" ]] || { echo "[run_h3spec] missing $VENDOR/SHA256SUMS — see $VENDOR/README.md for the pin refresh procedure" >&2; exit 2; }
[[ -f "$THRESHOLD_FILE" ]] || { echo "[run_h3spec] missing $THRESHOLD_FILE" >&2; exit 2; }
[[ -x "$SERVER_BIN" ]] || { echo "[run_h3spec] missing $SERVER_BIN — build hello_h3_server first" >&2; exit 2; }
ensure_binary || exit 2

THRESHOLD="$(tr -d '[:space:]' < "$THRESHOLD_FILE")"
[[ "$THRESHOLD" =~ ^[0-9]+$ ]] || { echo "[run_h3spec] threshold is not an integer: '$THRESHOLD'" >&2; exit 2; }

echo "[run_h3spec] threshold=$THRESHOLD (placeholder runner — body added in T4)"
exit 2
