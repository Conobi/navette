#!/usr/bin/env bash
# Fail if a retired origin spelling reappears in in-scope Mojo source.
#
# Mojo 1.0.0 rejects `AnyOrigin` in a struct field outright: the claim "this may
# alias any origin" makes the lifetime checker unsound, and the compiler's own
# note points at `UntrackedOrigin` "if lifetime is managed explicitly", which is
# the case for every raw pointer this codebase holds. The whole repo was
# converted, so any reappearance is a regression.
#
#   as_any_origin           -> as_unsafe_any_origin   (b2 rename)
#   *ExternalOrigin         -> *UntrackedOrigin       (b2 rename)
#   *AnyOrigin              -> *UntrackedOrigin in fields, locals and returns
#                              `Pointer[mut=True, T=..., origin=_]` in PARAMETERS,
#                              where a wildcard is wanted and `MutUntrackedOrigin`
#                              would wrongly reject a caller's tracked origin
#   as_unsafe_any_origin()  -> drop it; `unsafe_alloc` already returns
#                              MutUntrackedOrigin, and the result is
#                              field-illegal
#
# grep (not rg): rg is absent on bash's PATH in CI; grep -rEn is the portable
# convention used by the repo's other gates.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

DIRS=(navette interop tests conformance examples bench probes)
PAT='\b(as_any_origin|as_unsafe_any_origin|ExternalOrigin|ImmutExternalOrigin|MutExternalOrigin|AnyOrigin|ImmutAnyOrigin|MutAnyOrigin|MutUnsafeAnyOrigin|ImmutUnsafeAnyOrigin)\b'

HITS=$(grep -rEn --include='*.mojo' "$PAT" "${DIRS[@]}" 2>/dev/null || true)
if [ -n "$HITS" ]; then
  echo "check_no_deprecated_origins: FAIL — retired origin tokens found:" >&2
  echo "$HITS" >&2
  echo "Field/local/return: use *UntrackedOrigin." >&2
  echo "Parameter: use Pointer[mut=True, T=..., origin=_] to accept any origin." >&2
  exit 1
fi
echo "check_no_deprecated_origins: PASS"
