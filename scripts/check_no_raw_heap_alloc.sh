#!/usr/bin/env bash
# Anti-regression gate for the memory.alloc Owned[T] adoption (Cycle 2).
#
# Every migrated library file now allocates via `Owned[T]`
# (navette/util/owned_alloc) instead of the raw `_heap_alloc`
# (std.memory.unsafe_pointer.alloc) + manual `.free()` surface. This gate
# fails if a migrated file reintroduces a raw `_heap_alloc[...]` call site
# beyond its pinned residual, catching both regressions and missed sites.
#
# The single permitted residual is `navette/tls/lib.mojo`'s refcounted
# `_SharedLibraryInner` interior (freed in `__del__` via destroy_pointee) —
# an owning interior that is out of the single-scope/clean-RAII scope.
#
# grep (not rg): rg is absent on bash's PATH in CI; grep -E is the portable
# convention used by the repo's other gates.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Each row: "<file> <expected _heap_alloc[ call sites> <expected raw-alloc imports>".
# Counts are EXACT (a missed site or a regression both fail). The import column
# catches an aliased re-import (`import alloc as foo; foo[...]`) that the call
# grep alone would miss. tls/lib keeps its refcounted _SharedLibraryInner site
# + its import; every other migrated file is fully on Owned[T] (0/0).
FILES=(
  "navette/runtime/socket_helpers.mojo 0 0"
  "navette/tls/lib.mojo 1 1"
  "navette/compress/lib.mojo 0 0"
  "navette/http/decode.mojo 0 0"
  "interop/client.mojo 0 0"
  "navette/quic/retry.mojo 0 0"
  "navette/quic/packet_protect.mojo 0 0"
  "navette/tls/config.mojo 0 0"
  "navette/quic/connection.mojo 0 0"
  # Partially-migrated: single-scope temps moved to Owned[T]; the pinned
  # residuals are legitimate out-of-scope sites (helper-returns, escapes,
  # kernel-pinned buf-rings) — pinned here so a regression in them is caught.
  "bench/launcher.mojo 1 1"
  "bench/servers/h1_server.mojo 2 1"
  "bench/servers/h2_server.mojo 3 1"
  "conformance/tests/test_rustls_aead.mojo 2 1"
)

fail=0
for row in "${FILES[@]}"; do
  read -r f exp_call exp_imp <<<"$row"
  got_call=$(grep -cE '_heap_alloc\[' "$f" 2>/dev/null || true)
  # raw allocator import (any alias): from std.memory.unsafe_pointer import ... alloc ...
  got_imp=$(grep -cE 'from std\.memory\.unsafe_pointer import.*\balloc\b' "$f" 2>/dev/null || true)
  if [ "$got_call" -ne "$exp_call" ]; then
    echo "check_no_raw_heap_alloc: FAIL — $f: $got_call '_heap_alloc[' call(s), expected $exp_call" >&2
    fail=1
  fi
  if [ "$got_imp" -ne "$exp_imp" ]; then
    echo "check_no_raw_heap_alloc: FAIL — $f: $got_imp raw-allocator import(s), expected $exp_imp" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "Migrated files must allocate via Owned[T] (navette/util/owned_alloc)." >&2
  echo "See specs/2026-06-23-memory-alloc-adoption.md." >&2
  exit 1
fi
echo "check_no_raw_heap_alloc: PASS"
