#!/usr/bin/env bash
# Guard: the accept/handshake profiling instrumentation stays deleted.
#
# It cost per-connection work in default builds, so a reintroduced
# PROFILE_ACCEPT flag or AcceptProfile type must be deliberate.
# grep (not rg): rg is absent on bash's PATH, so an rg guard passes vacuously.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
FOUND=$(grep -rn 'PROFILE_ACCEPT\|AcceptProfile' \
    "$REPO_ROOT/navette" "$REPO_ROOT/bench/servers" || true)
if [ -n "$FOUND" ]; then
    echo "FAIL: accept-profiling instrumentation found:"
    echo "$FOUND"
    exit 1
fi
echo "ok: no accept-profiling instrumentation in navette/ or bench/servers/"
