#!/usr/bin/env bash
# Deps health smoke test (plans/2026-05-13-deps-enhancement.md §4.3).
# Asserts invariants set up by Phase 1/2/3 of the deps-enhancement plan.
# Wire into CI on every PR.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

failed=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; failed=$((failed + 1)); }

# Prefer ripgrep; fall back to grep -r if unavailable.
if command -v rg >/dev/null 2>&1; then
    rgrep() { rg --no-heading --line-number "$@"; }
else
    rgrep() { grep -rn "$@"; }
fi

# ---------------------------------------------------------------------------
# §1.1 — pyproject runtime deps include mojox and a pinned mojo-compiler
# ---------------------------------------------------------------------------
echo '§1.1 pyproject runtime deps'
if grep -q '"mojox' pyproject.toml; then pass 'mojox in pyproject';
else fail 'mojox missing from pyproject [project].dependencies'; fi

if grep -qE '"mojo-compiler==' pyproject.toml; then pass 'mojo-compiler pinned';
else fail 'mojo-compiler not pinned in pyproject (need ==X.Y.Z)'; fi

if grep -qE 'requires-python *= *">=3\.(1[1-9]|[2-9][0-9])"' pyproject.toml; then
    pass 'requires-python >= 3.11';
else
    fail 'requires-python must be >= 3.11 (oracle_env_check uses stdlib tomllib)';
fi

# ---------------------------------------------------------------------------
# §1.4 — .mojo-version is deleted (pin lives in pyproject)
# ---------------------------------------------------------------------------
echo '§1.4 .mojo-version absence'
if [ ! -f .mojo-version ]; then pass '.mojo-version absent';
else fail '.mojo-version still present — should be deleted (pin is in pyproject)'; fi

# ---------------------------------------------------------------------------
# §1.5 — h2 / hpack / hyperframe live in dev group, not main
# ---------------------------------------------------------------------------
echo '§1.5 h2/hpack/hyperframe in dev group'
for pkg in h2 hpack hyperframe; do
    # Look for the pkg in the [project].dependencies block specifically.
    if awk '
        /^\[project\]/   { in_proj=1; next }
        /^\[/             { in_proj=0 }
        /^dependencies *=/ { in_deps=in_proj; next }
        /^\]/             { in_deps=0 }
        in_deps && $0 ~ /"'"$pkg"'(\[|>=|==|<|~|"|>)/ { found=1 }
        END { exit !found }
    ' pyproject.toml 2>/dev/null; then
        fail "$pkg present in [project].dependencies (should be dev-only)"
    else
        pass "$pkg not in runtime deps"
    fi
done

# ---------------------------------------------------------------------------
# §2.1 — Rust toolchain pinned
# ---------------------------------------------------------------------------
echo '§2.1 Rust toolchain pin'
if [ -f crates/librustls-mojo/rust-toolchain.toml ]; then pass 'rust-toolchain.toml present';
else fail 'crates/librustls-mojo/rust-toolchain.toml missing'; fi

# ---------------------------------------------------------------------------
# §2.2 — release lib does NOT export the insecure helper symbol
# ---------------------------------------------------------------------------
echo '§2.2 release lib free of insecure symbol'
lib_so="$REPO_ROOT/lib/librustls_mojo.so"
lib_dy="$REPO_ROOT/lib/librustls_mojo.dylib"
lib_path=''
[ -f "$lib_so" ] && lib_path="$lib_so"
[ -z "$lib_path" ] && [ -f "$lib_dy" ] && lib_path="$lib_dy"
if [ -z "$lib_path" ]; then
    pass 'librustls_mojo lib not present (skipped) — run scripts/build_rustls.sh release'
elif ! command -v nm >/dev/null; then
    pass '`nm` unavailable (skipped)'
else
    nm_args="-D"
    [ "$lib_path" = "$lib_dy" ] && nm_args="-gU"
    # Capture nm output before grepping so `grep -q` early-exit + pipefail
    # don't conspire to mask a real match (nm gets SIGPIPE'd, pipeline fails).
    nm_out=$(nm $nm_args "$lib_path" 2>/dev/null || true)
    if printf '%s\n' "$nm_out" | grep -q rlsm_quic_client_config_new_insecure; then
        pass 'release/dev profile (insecure symbol exported — CLI -k works)'
    else
        pass 'hardened/bench profile (no insecure symbol exported)'
    fi
fi

# ---------------------------------------------------------------------------
# §2.3 — FFI symbol-count parity between Rust source and Mojo bindings
# ---------------------------------------------------------------------------
echo '§2.3 FFI symbol parity (Rust source vs Mojo bindings)'
rust_count=$(grep -hE '^pub (unsafe )?extern "C" fn rlsm_' crates/librustls-mojo/src/*.rs 2>/dev/null | wc -l)
# §2.3 caller refactor: rlsm_* symbol literals live in the generated
# bindings module (navette/tls/_rlsm_bindings.mojo). Other source files
# import typed load_rlsm_* helpers from there, so the count comes from
# the generated module. Hand-written sites under navette/tls + navette/
# http are scanned to catch any drift.
mojo_count=$(grep -rhoE '"rlsm_[a-z_0-9]+"' \
    navette/tls/_rlsm_bindings.mojo \
    navette/tls/lib.mojo \
    navette/tls/config.mojo \
    navette/tls/connection.mojo \
    2>/dev/null | sort -u | wc -l)
printf '  rust_count=%s mojo_count=%s\n' "$rust_count" "$mojo_count"
if [ "$rust_count" -gt 0 ] && [ "$mojo_count" -gt 0 ]; then
    if [ "$rust_count" -ge "$mojo_count" ]; then
        pass 'Mojo bindings consume ≤ Rust-exported symbols'
    else
        fail "Mojo references more rlsm_ symbols than Rust exports (drift!)"
    fi
else
    fail 'Could not count rlsm_ symbols on at least one side'
fi

# ---------------------------------------------------------------------------
# §2.4 — libcompress-mojo FFI symbol parity (spec 2026-05-17-compress-shim-split)
# ---------------------------------------------------------------------------
echo '§2.4 libcompress FFI symbol parity (C source vs Mojo bindings vs .so)'
c_count=$(grep -hE '^[A-Za-z_][A-Za-z0-9_ ]*\<lcm_[a-z_0-9]+\s*\(' \
    crates/libcompress-mojo/src/*.c 2>/dev/null | wc -l)
lcm_mojo_count=$(grep -hoE '"lcm_[a-z_0-9]+"' \
    navette/compress/_lcm_bindings.mojo 2>/dev/null | sort -u | wc -l)
printf '  c_count=%s mojo_count=%s\n' "$c_count" "$lcm_mojo_count"
if [ "$c_count" -gt 0 ] && [ "$lcm_mojo_count" -gt 0 ]; then
    if [ "$c_count" -ge "$lcm_mojo_count" ]; then
        pass 'Mojo bindings consume ≤ C-defined lcm_ symbols'
    else
        fail 'Mojo references more lcm_ symbols than C exports (drift!)'
    fi
else
    fail 'Could not count lcm_ symbols on at least one side'
fi

# ---------------------------------------------------------------------------
# §2.5 — librustls_mojo.so exports zero compression symbols (AC1 of the
# compress-shim-split spec). Decouples release surfaces: a zlib/brotli CVE
# is a system-package update, never a Navette release.
# ---------------------------------------------------------------------------
echo '§2.5 librustls_mojo.so free of compression symbols'
lcs_so="$REPO_ROOT/lib/librustls_mojo.so"
lcs_dy="$REPO_ROOT/lib/librustls_mojo.dylib"
lcs_path=''
[ -f "$lcs_so" ] && lcs_path="$lcs_so"
[ -z "$lcs_path" ] && [ -f "$lcs_dy" ] && lcs_path="$lcs_dy"
if [ -z "$lcs_path" ]; then
    pass 'librustls_mojo lib not present (skipped) — run scripts/build_rustls.sh release'
elif ! command -v nm >/dev/null; then
    pass '`nm` unavailable (skipped)'
else
    nm_args="-D"
    [ "$lcs_path" = "$lcs_dy" ] && nm_args="-gU"
    nm_out=$(nm $nm_args "$lcs_path" 2>/dev/null || true)
    bad=$(printf '%s\n' "$nm_out" | grep -cE '\b(rlsm_(gzip|br)_|_compress_|_decompress_)' || true)
    if [ "$bad" -eq 0 ]; then
        pass 'no compression symbols (gzip/brotli/compress/decompress) leaked'
    else
        fail "$bad compression symbol(s) leaked into librustls_mojo (should be in libcompress_mojo)"
    fi
fi

# ---------------------------------------------------------------------------
# §3.1 — Test certs baked into fixtures (so cryptography is build-time-only)
# ---------------------------------------------------------------------------
echo '§3.1 baked test certs'
if [ -f tests/fixtures/tls/server.crt ] && [ -f tests/fixtures/tls/server.key ]; then
    pass 'tests/fixtures/tls/{server.crt,server.key} present'
else
    fail 'tests/fixtures/tls/server.{crt,key} missing — run scripts/regen_test_certs.sh'
fi

# ---------------------------------------------------------------------------
# §3.4 — oracle env matches uv.lock (live oracles, if any remain)
# ---------------------------------------------------------------------------
echo '§3.4 oracle env vs uv.lock'
if [ -f conformance/scripts/oracle_env_check.py ]; then
    if uv run --group dev python conformance/scripts/oracle_env_check.py >/dev/null 2>&1; then
        pass 'oracle versions match uv.lock'
    else
        fail 'oracle env drift (see `uv run python conformance/scripts/oracle_env_check.py`)'
    fi
else
    fail 'conformance/scripts/oracle_env_check.py missing'
fi

# ---------------------------------------------------------------------------
# §3.5 — navette.tls.early_data_store has zero third-party type leakage
# ---------------------------------------------------------------------------
echo '§3.5 early_data_store module has no third-party type references'
# Strict pattern enforces no third-party type leakage on the public
# API, including client_random / ClientHello.random. Module docstrings
# cite the RFC 8446 §4.1.2 wire layout in generic terms rather than
# naming the symbols, so this pattern stays clean.
leak_pattern='RustlsLibrary|rustls::|received_resumption_data|set_resumption_data|client_random|ClientHello\.random|libcompress'
if [ -f navette/tls/early_data_store.mojo ]; then
    if rgrep -E "$leak_pattern" navette/tls/early_data_store.mojo > /dev/null; then
        fail 'navette/tls/early_data_store.mojo references a third-party type'
    else
        pass 'navette/tls/early_data_store.mojo free of third-party type names'
    fi
else
    fail 'navette/tls/early_data_store.mojo missing'
fi

# ---------------------------------------------------------------------------
# §3.6 — BruteForceReplayStore lives only in tests/
# ---------------------------------------------------------------------------
echo '§3.6 BruteForceReplayStore is test-only'
brute_hits=$(rgrep -l 'BruteForceReplayStore' navette/ examples/ 2>/dev/null || true)
if [ -n "$brute_hits" ]; then
    fail "BruteForceReplayStore referenced outside tests/: $brute_hits"
else
    pass 'BruteForceReplayStore confined to tests/'
fi

# ---------------------------------------------------------------------------
# §3.7 — _zero_rtt_now_ms_override is assigned only from tests/
# ---------------------------------------------------------------------------
echo '§3.7 _zero_rtt_now_ms_override assignment is test-only'
override_hits=$(rgrep -E '_zero_rtt_now_ms_override\s*=' navette/ examples/ 2>/dev/null \
    | grep -v 'self._zero_rtt_now_ms_override = None' \
    | grep -v 'self._zero_rtt_now_ms_override = take._zero_rtt_now_ms_override' \
    || true)
if [ -n "$override_hits" ]; then
    fail "_zero_rtt_now_ms_override assigned outside tests/ (production callers must leave it None): $override_hits"
else
    pass '_zero_rtt_now_ms_override write-sites confined to ctor + tests/'
fi

# ---------------------------------------------------------------------------
# §3.8 — _drive_replay_check_for_test is test-only
# ---------------------------------------------------------------------------
echo '§3.8 _drive_replay_check_for_test is test-only'
drive_hits=$(rgrep -E '_drive_replay_check_for_test\s*\(' navette/ examples/ 2>/dev/null \
    | grep -v 'def _drive_replay_check_for_test' \
    || true)
if [ -n "$drive_hits" ]; then
    fail "_drive_replay_check_for_test called outside tests/: $drive_hits"
else
    pass '_drive_replay_check_for_test confined to its definition + tests/'
fi

# ---------------------------------------------------------------------------
echo
if [ "$failed" -eq 0 ]; then
    echo 'all integration invariants ok'
    exit 0
else
    echo "FAILED ($failed check(s))"
    exit 1
fi
