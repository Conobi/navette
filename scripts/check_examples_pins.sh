#!/usr/bin/env bash
# Fail if any example pyproject/lock regresses off the b2 toolchain or back to
# the stale boucle rev. Guards the examples b2 migration.
#   forbidden: mojo-compiler==1.0.0b1, boucle rev 27f8b3e…, mojox 0.2.0
# The b2 baseline is: mojo-compiler==1.0.0b2, boucle cd91272…, mojox>=0.3.
# grep (not rg): rg is absent on bash's PATH in CI; grep -En is the repo
# convention already used by the other run_tests.sh gates.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

STALE_BOUCLE='27f8b3e666de32d78458fd839377183624461e5e'
fail=0

for pp in examples/*/pyproject.toml; do
  h=$(grep -En "mojo-compiler==1\.0\.0b1|$STALE_BOUCLE" "$pp" 2>/dev/null || true)
  if [ -n "$h" ]; then
    echo "check_examples_pins: FAIL — $pp (b1 compiler / stale boucle rev):" >&2
    echo "$h" >&2; fail=1
  fi
done

for lk in examples/*/uv.lock; do
  h=$(grep -En "1\.0\.0b1|$STALE_BOUCLE" "$lk" 2>/dev/null || true)
  if [ -n "$h" ]; then
    echo "check_examples_pins: FAIL — $lk (b1 compiler / stale boucle rev):" >&2
    echo "$h" >&2; fail=1
  fi
  # mojox runtime floor: 0.2.0 predates the b2 .mojoc toolchain; require >=0.3.
  m=$(grep -A1 'name = "mojox"' "$lk" 2>/dev/null | grep -En 'version = "0\.2\.0"' || true)
  if [ -n "$m" ]; then
    echo "check_examples_pins: FAIL — $lk: mojox 0.2.0 (need >=0.3)" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "Examples must stay on the b2 toolchain (compiler 1.0.0b2, boucle cd91272, mojox>=0.3)." >&2
  exit 1
fi
echo "check_examples_pins: PASS"
