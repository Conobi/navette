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

# Migrated library file : max permitted `_heap_alloc[` call sites.
declare -A EXPECTED=(
  ["navette/runtime/socket_helpers.mojo"]=0
  ["navette/tls/lib.mojo"]=1
  ["navette/compress/lib.mojo"]=0
  ["navette/http/decode.mojo"]=0
  ["interop/client.mojo"]=0
  ["navette/quic/retry.mojo"]=0
  ["navette/quic/packet_protect.mojo"]=0
  ["navette/tls/config.mojo"]=0
  ["navette/quic/connection.mojo"]=0
)

fail=0
for f in "${!EXPECTED[@]}"; do
  got=$(grep -cE '_heap_alloc\[' "$f" 2>/dev/null || true)
  exp=${EXPECTED[$f]}
  if [ "$got" -gt "$exp" ]; then
    echo "check_no_raw_heap_alloc: FAIL — $f has $got '_heap_alloc[' site(s), expected <= $exp" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "Migrated files must allocate via Owned[T] (navette/util/owned_alloc)." >&2
  echo "See specs/2026-06-23-memory-alloc-adoption.md." >&2
  exit 1
fi
echo "check_no_raw_heap_alloc: PASS"
