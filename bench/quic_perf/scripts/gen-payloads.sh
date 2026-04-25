#!/usr/bin/env bash
# Generate the four benchmark payloads if they don't already exist.
# Sizes are exact (no padding); content is /dev/urandom for realistic entropy.
# Idempotent: re-running is a no-op if all four files exist with correct sizes.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PAYLOAD_DIR="$HERE/payloads"

mkdir -p "$PAYLOAD_DIR"

generate_if_missing() {
    local name="$1"
    local size="$2"
    local target="$PAYLOAD_DIR/$name"

    if [[ -f "$target" ]]; then
        local actual_size
        actual_size=$(stat -c %s "$target")
        if [[ "$actual_size" -eq "$size" ]]; then
            echo "[gen-payloads] $name: present, $size bytes (skip)"
            return 0
        fi
        echo "[gen-payloads] $name: wrong size ($actual_size != $size); regenerating"
    fi

    head -c "$size" /dev/urandom > "$target"
    echo "[gen-payloads] $name: generated, $size bytes"
}

generate_if_missing "1k.bin"  1024
generate_if_missing "5k.bin"  5120
generate_if_missing "15k.bin" 15360
generate_if_missing "2m.bin"  2097152

echo "[gen-payloads] done"
