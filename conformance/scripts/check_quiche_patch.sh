#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VENDOR="$ROOT/conformance/vendor/quiche-raw-frame"
LIB="$VENDOR/src/lib.rs"
TUL="$VENDOR/src/test_utils.rs"
PATCHMD="$VENDOR/VENDOR_PATCH.md"

fail() { echo "vendor patch integrity check failed: $1" >&2; exit 1; }

test -d "$VENDOR" || fail "vendor dir absent ($VENDOR)"
test -f "$LIB"     || fail "src/lib.rs absent"
test -f "$TUL"     || fail "src/test_utils.rs absent"
test -f "$PATCHMD" || fail "VENDOR_PATCH.md absent"

# Patch 1: pub mod frame
grep -qE '^pub mod frame;' "$LIB" || fail "Patch 1 not applied: 'pub mod frame;' missing"

# Patch 2: pub mod range_buf
grep -qE '^pub mod range_buf;' "$LIB" || fail "Patch 2 not applied: 'pub mod range_buf;' missing"

# Patch 3: encode_pkt_reserved_bits helper after encode_pkt
# Match 'pub fn encode_pkt(' exactly (not encode_pkt_reserved_bits or encode_pkt_num)
awk '/^pub fn encode_pkt[(]/ { seen=1 } seen && /^pub fn encode_pkt_reserved_bits[(]/ { ok=1; exit } END { exit ok ? 0 : 1 }' "$TUL" \
    || fail "Patch 3 not applied: encode_pkt_reserved_bits missing after encode_pkt"

# VENDOR_PATCH.md must list 3 numbered changes + a quiche-commit: SHA line
grep -qE '^(1\.|## (Patch|Change) 1\b)' "$PATCHMD" || fail "VENDOR_PATCH.md missing change 1 header"
grep -qE '^(2\.|## (Patch|Change) 2\b)' "$PATCHMD" || fail "VENDOR_PATCH.md missing change 2 header"
grep -qE '^(3\.|## (Patch|Change) 3\b)' "$PATCHMD" || fail "VENDOR_PATCH.md missing change 3 header"
grep -qE '^quiche-commit:[[:space:]]+[0-9a-f]{7,40}' "$PATCHMD" || fail "VENDOR_PATCH.md missing 'quiche-commit:' SHA line"

echo "vendor patch integrity check: OK"
