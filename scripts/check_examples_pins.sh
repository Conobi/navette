#!/usr/bin/env bash
# Fail if a nested example project drifts off the parent's toolchain pins.
#
# The examples are separate uv projects so each can be built standalone, which
# means their pins can rot independently -- and they did: they sat on a b2
# compiler, a mojox 0.3/0.4 floor and a boucle rev from before that package was
# reorganised, while the parent had moved on.
#
# This gate DERIVES the expected values from the parent pyproject.toml rather
# than hardcoding a baseline. A hardcoded baseline is what let the drift happen:
# the previous version of this script pinned the then-current toolchain as its
# target, so it kept passing while the parent moved past it.
#
# grep (not rg): rg is absent on bash's PATH in CI; grep -En is the portable
# convention used by the repo's other gates.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PARENT=pyproject.toml
want_compiler=$(grep -m1 -Eo 'mojo-compiler==[0-9][^"]*' "$PARENT")
want_boucle=$(grep -m1 -Eo 'Conobi/boucle#[0-9a-f]{40}' uv.lock | cut -d'#' -f2)

if [ -z "$want_compiler" ] || [ -z "$want_boucle" ]; then
  echo "check_examples_pins: FAIL — cannot read parent pins from $PARENT / uv.lock" >&2
  exit 2
fi

fail=0
for pp in examples/*/pyproject.toml; do
  d=$(dirname "$pp")

  if ! grep -qF "$want_compiler" "$pp"; then
    echo "check_examples_pins: FAIL — $pp does not pin $want_compiler" >&2
    fail=1
  fi
  if ! grep -qF "$want_boucle" "$pp"; then
    echo "check_examples_pins: FAIL — $pp does not pin boucle $want_boucle" >&2
    fail=1
  fi
  # mojox-build reads its manifest from tool.mojox; tool.mojox-build is a dead
  # table name that is silently ignored, so a `binaries` block under it never
  # takes effect.
  if grep -q '^\[tool\.mojox-build\]' "$pp"; then
    echo "check_examples_pins: FAIL — $pp uses the dead [tool.mojox-build] table" >&2
    fail=1
  fi
  want_ver="${want_compiler#mojo-compiler==}"
  # Anchor on the lock's own `version = "..."` form: a plain substring match
  # would accept `1.0.0b2` as satisfying `1.0.0`.
  if [ -f "$d/uv.lock" ] && ! grep -qE "^version = \"${want_ver}\"$" "$d/uv.lock"; then
    echo "check_examples_pins: FAIL — $d/uv.lock is stale; re-run 'uv lock' in $d" >&2
    fail=1
  fi
done

[ "$fail" -eq 0 ] || exit 1
echo "check_examples_pins: PASS"
