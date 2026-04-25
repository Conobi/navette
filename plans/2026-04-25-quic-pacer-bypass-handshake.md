# QUIC Pacer Bypass for Handshake-Space Packets — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bypass the M4a-introduced QUIC pacer for connections that have not yet reached `is_established()` so cold-start handshake throughput is no longer gated by `cwnd ÷ srtt ≈ 60 KiB/s`.

**Architecture:** Three site-local edits to `src/quic/connection.mojo` (gate `_can_send`, deadline `_next_timeout`, post-send commit in `process_send`), gated on the existing public predicate `is_established()`. Anti-amplification (`_anti_amp_ok`) and the CUBIC cwnd check stay in place as the actual handshake-bandwidth safety floors. Mirrors TQUIC, quinn, picoquic, and ngtcp2 (industry consensus: pace 1-RTT only).

**Tech Stack:** Mojo 0.26.2; `src/quic/connection.mojo`; `tests/test_quic_pacer_bypass.mojo` (new); validation via `bench/quic_perf` (Docker + tquic_client + h2load-h3 + `docker stats` CPU sampler).

---

## Required reading before any task

Every subagent dispatched on this plan **must** read first:

1. `docs/project-context.md` — full project context, conventions, decisions.
2. `specs/2026-04-25-quic-pacer-bypass-handshake.md` — the spec this plan implements.
3. The Mojo MCP tools instructions: do **not** use the LSP tool for `.mojo` files (false positives); use Mojo MCP `validate` + `execute` to verify code compiles, `search` / `lookup` for stdlib symbols, `read_file` / `list_files` for project navigation. For non-`.mojo` files (`.sh`, `.md`, `.py`), normal `Read` / `Grep` / `Bash` apply.

The full `docs/project-context.md` content is the first item in the subagent's context per the atelier convention.

## File structure

| File | Status | Responsibility |
|---|---|---|
| `src/quic/connection.mojo` | Modify (3 locations, ~15 LoC delta) | Add handshake-bypass at the pacer gate (`_can_send`), the timer deadline (`_next_timeout` pacer branch), and the post-send commit (`process_send` per-space loop). |
| `tests/test_quic_pacer_bypass.mojo` | Create | Three unit tests gating the bypass: (1) `_can_send` returns True during handshake even when pacer would block; (2) pacer still gates after handshake; (3) Initial-flight padding to MIN_DATAGRAM_SIZE is unchanged. |
| `bench/quic_perf/results/REFERENCE.md` | Modify (full rewrite of "Reference numbers" + "How to read this") | Reflect post-fix benchmark numbers + a one-line diff against the prior baseline (412 long-conn / 1 short-conn). |
| `docs/project-context.md` | Modify (Active specs row + open-question entry only on hypothesis falsification) | Tracking — see Task 6's branches. |

No other files are modified. No new files are created besides the test and (conditionally) the REFERENCE.md rewrite.

---

## Task 1: Add the three pacer-bypass unit tests

**Files:**
- Create: `tests/test_quic_pacer_bypass.mojo`

**Test runner command (used in every step below):**
```bash
LD_LIBRARY_PATH=/home/donokami/Projets/perso/mojo-net/lib uv run mojo run -I /home/donokami/Projets/perso/mojo-net -I /home/donokami/Projets/perso/mojo-net/conformance -D ASSERT=all /home/donokami/Projets/perso/mojo-net/tests/test_quic_pacer_bypass.mojo
```

(Mirrors the invocation in `tests/test_quic_connection.mojo:5-6` and `conformance/scripts/run_tests.sh`.)

- [ ] **Step 1: Verify the helper imports work in the existing test suite**

Run:
```bash
LD_LIBRARY_PATH=/home/donokami/Projets/perso/mojo-net/lib uv run mojo run -I /home/donokami/Projets/perso/mojo-net -I /home/donokami/Projets/perso/mojo-net/conformance -D ASSERT=all /home/donokami/Projets/perso/mojo-net/tests/test_quic_connection.mojo 2>&1 | tail -5
```

Expected: `All test_quic_connection tests passed.` (sanity check that the test environment is healthy before adding new tests).

- [ ] **Step 2: Create the test file with all three tests**

Write `tests/test_quic_pacer_bypass.mojo`:

```mojo
# tests/test_quic_pacer_bypass.mojo
#
# Pacer-bypass unit tests for QuicConnection during handshake.
# See specs/2026-04-25-quic-pacer-bypass-handshake.md for the design.
#
# Run with:
#   cd ~/Projets/perso/mojo-net && LD_LIBRARY_PATH=lib uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_quic_pacer_bypass.mojo

from std.collections import Optional
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_false, assert_equal_int


# ── Helpers (copy/adapt from tests/test_quic_connection.mojo) ────────────


def py_bytes_to_mojo(raw: PythonObject) raises -> List[UInt8]:
    var builtins = Python.import_module("builtins")
    var result = List[UInt8]()
    for i in range(Int(py=builtins.len(raw))):
        result.append(UInt8(Int(py=raw[i])))
    return result^


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    var ec_mod = Python.import_module("cryptography.hazmat.primitives.asymmetric.ec")
    var x509_mod = Python.import_module("cryptography.x509")
    var oid_mod = Python.import_module("cryptography.x509.oid")
    var ser_mod = Python.import_module("cryptography.hazmat.primitives.serialization")
    var hash_mod = Python.import_module("cryptography.hazmat.primitives.hashes")
    var dt_mod = Python.import_module("datetime")
    var builtins = Python.import_module("builtins")

    var py_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
    var name_attrs = builtins.list()
    name_attrs.append(x509_mod.NameAttribute(oid_mod.NameOID.COMMON_NAME, "localhost"))
    var subject = x509_mod.Name(name_attrs)
    var san_list = builtins.list()
    san_list.append(x509_mod.DNSName("localhost"))
    var py_cert = (
        x509_mod.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(py_key.public_key())
        .serial_number(x509_mod.random_serial_number())
        .not_valid_before(dt_mod.datetime(2024, 1, 1))
        .not_valid_after(dt_mod.datetime(2034, 1, 1))
        .add_extension(
            x509_mod.SubjectAlternativeName(san_list),
            critical=False,
        )
        .sign(py_key, hash_mod.SHA256())
    )
    var pem_cert = py_cert.public_bytes(ser_mod.Encoding.PEM)
    var pem_key = py_key.private_bytes(
        ser_mod.Encoding.PEM,
        ser_mod.PrivateFormat.PKCS8,
        ser_mod.NoEncryption(),
    )
    return (py_bytes_to_mojo(pem_cert), py_bytes_to_mojo(pem_key))


def _create_configs_from_lib(
    lib_ptr: UnsafePointer[RustlsLibrary, MutAnyOrigin],
) raises -> Tuple[Int32, Int32]:
    var cert_key = generate_ephemeral_cert()
    var cert_bytes = cert_key[0].copy()
    var key_bytes = cert_key[1].copy()

    var cert_ptr = cert_bytes.unsafe_ptr().as_any_origin()
    var key_ptr = key_bytes.unsafe_ptr().as_any_origin()
    var cert_len = Int32(len(cert_bytes))
    var key_len = Int32(len(key_bytes))

    var alpn_ptr = _heap_alloc[UInt8](2).as_any_origin()
    alpn_ptr[0] = UInt8(ord("h"))
    alpn_ptr[1] = UInt8(ord("3"))
    var alpn_len = Int32(2)

    var srv_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    var rc = lib_ptr[].quic_server_config_new(
        cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len, srv_cfg_ptr,
    )
    assert_true(
        rc == Int32(0),
        "quic_server_config_new failed: " + lib_ptr[].last_error(),
    )
    var server_config = srv_cfg_ptr[0]
    srv_cfg_ptr.free()

    var cli_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    rc = lib_ptr[].quic_client_config_with_ca(
        cert_ptr, cert_len, alpn_ptr, alpn_len, cli_cfg_ptr,
    )
    assert_true(
        rc == Int32(0),
        "quic_client_config_with_ca failed: " + lib_ptr[].last_error(),
    )
    var client_config = cli_cfg_ptr[0]
    cli_cfg_ptr.free()

    alpn_ptr.free()

    return (server_config, client_config)


def _default_params() -> TransportParams:
    var params = default_transport_params()
    params.max_idle_timeout = UInt64(30_000)
    params.initial_max_data = UInt64(1_048_576)
    params.initial_max_stream_data_bidi_local = UInt64(65_536)
    params.initial_max_stream_data_bidi_remote = UInt64(65_536)
    params.initial_max_streams_bidi = UInt64(100)
    return params^


def _establish_handshake(
    mut client: QuicConnection,
    mut server: QuicConnection,
    mut now: UInt64,
) raises -> UInt64:
    var established = False
    for _ in range(20):
        now += UInt64(10_000)
        var c_dg = client.send(now)
        for i in range(len(c_dg)):
            try:
                server.recv(Span(c_dg[i]), now)
            except:
                pass
        var s_dg = server.send(now)
        for i in range(len(s_dg)):
            try:
                client.recv(Span(s_dg[i]), now)
            except:
                pass
        if client.is_established() and server.is_established():
            established = True
            break
    assert_true(established, "handshake did not complete")
    return now


# ── Tests ────────────────────────────────────────────────────────────────


def test_pacer_bypassed_during_handshake() raises:
    """_can_send returns True for non-established connections even when the
    pacer would otherwise block. The bypass is the surgical fix from
    specs/2026-04-25-quic-pacer-bypass-handshake.md."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", params, now,
    )

    # Sanity: handshake has not completed.
    assert_false(client.is_established(), "fresh client must not be established")

    # Make anti-amp permissive: clients are unconditionally allowed to send by
    # _anti_amp_ok (the 3x check applies only to servers); set bytes_received
    # nonetheless so a server-side variant of this test would also pass.
    client.bytes_received = UInt64(2000)

    # Force the pacer into a "would-block" state. With tokens=0,
    # last_sched_time=now, and a finite pacing rate, refill produces 0
    # additional tokens (zero elapsed) and tokens_projected < MIN_DATAGRAM_SIZE
    # => next_send_time returns Some(deadline).
    client.recovery.pacer.tokens = UInt64(0)
    client.recovery.pacer.last_sched_time = now
    client.recovery.smoothed_rtt = UInt64(333_000)  # microseconds; INITIAL_RTT

    # Sanity: the pacer setup actually produces a deadline.
    var rate = client.recovery.cc.pacing_rate(client.recovery.smoothed_rtt)
    var deadline = client.recovery.pacer.next_send_time(rate, now)
    assert_true(
        Bool(deadline),
        "test setup wrong: pacer should produce a deadline with tokens=0 + elapsed=0",
    )

    # The actual assertion under test: bypass kicks in because the connection
    # is not yet established.
    assert_true(
        client._can_send(UInt64(1200), now),
        "_can_send must return True during handshake even when pacer would gate",
    )

    # Anti-amplification is independent of the bypass; this is server-side,
    # but we verify the order of checks is preserved by constructing a
    # server connection with bytes_received=0 and asserting _can_send is
    # False even though the pacer would now allow (server hasn't sent
    # anything yet).
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )
    server.bytes_received = UInt64(0)
    server.bytes_sent = UInt64(0)
    assert_false(
        server._can_send(UInt64(1500), now),
        "anti-amp must still gate non-established server with bytes_received=0",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_pacer_bypassed_during_handshake: PASS")


def test_pacer_active_after_handshake() raises:
    """After is_established(), the pacer continues to gate sends. Regression
    guard ensuring the bypass is scoped strictly to the handshake phase."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    now = _establish_handshake(client, server, now)
    assert_true(client.is_established(), "client must be established")

    # Force the same pacer "would-block" setup as test 1.
    client.recovery.pacer.tokens = UInt64(0)
    client.recovery.pacer.last_sched_time = now
    client.recovery.smoothed_rtt = UInt64(333_000)

    # Now the pacer must gate because is_established() is True.
    assert_false(
        client._can_send(UInt64(1200), now),
        "_can_send must return False after handshake when pacer gates",
    )

    # Advance time past the deadline; the pacer must allow.
    var rate = client.recovery.cc.pacing_rate(client.recovery.smoothed_rtt)
    var deadline = client.recovery.pacer.next_send_time(rate, now)
    assert_true(Bool(deadline), "pacer setup must still produce a deadline")
    var advanced_now = deadline.value() + UInt64(1000)
    assert_true(
        client._can_send(UInt64(1200), advanced_now),
        "_can_send must return True after pacer deadline elapses",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_pacer_active_after_handshake: PASS")


def test_handshake_padding_still_works() raises:
    """A fresh client's first Initial flight is still padded to MIN_DATAGRAM_SIZE
    after the bypass change. Regression guard for the padding logic at
    src/quic/connection.mojo:1714-1728."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", params, now,
    )

    # Drive one round of send: client should emit a padded Initial datagram.
    var dgrams = client.send(now)
    assert_true(len(dgrams) >= 1, "client must emit at least one datagram on first send")

    # The first datagram must be padded to >= MIN_DATAGRAM_SIZE (1200 bytes)
    # per RFC 9000 §14.1; the bypass must not affect the padding logic.
    var first_dg = dgrams[0]
    assert_true(
        len(first_dg) >= 1200,
        "first Initial datagram must be padded to >= 1200 bytes; got " + String(len(first_dg)),
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_handshake_padding_still_works: PASS")


def main() raises:
    print("test_quic_pacer_bypass:")
    test_pacer_bypassed_during_handshake()
    test_pacer_active_after_handshake()
    test_handshake_padding_still_works()
    print("All test_quic_pacer_bypass tests passed.")
```

- [ ] **Step 3: Verify pre-fix expectations**

Run:
```bash
LD_LIBRARY_PATH=/home/donokami/Projets/perso/mojo-net/lib uv run mojo run -I /home/donokami/Projets/perso/mojo-net -I /home/donokami/Projets/perso/mojo-net/conformance -D ASSERT=all /home/donokami/Projets/perso/mojo-net/tests/test_quic_pacer_bypass.mojo
```

Expected on `main` (pre-fix): test 1 **FAILS** with assertion message
`_can_send must return True during handshake even when pacer would gate`. Tests 2 and 3 **PASS** before reaching test 1's failure (Mojo runs them in `main()` order; test 1 runs first and aborts execution). To verify tests 2 and 3 pass independently, temporarily comment out the test 1 call in `main()`, re-run, and confirm:
```
  test_pacer_active_after_handshake: PASS
  test_handshake_padding_still_works: PASS
All test_quic_pacer_bypass tests passed.
```
Then restore the test 1 call.

- [ ] **Step 4: Validate Mojo gotchas before committing**

Use the Mojo MCP `validate` tool on `tests/test_quic_pacer_bypass.mojo` to catch any known-gotcha patterns (e.g. forbidden trait combinations, deinit conventions). If `validate` reports issues, fix them and rerun Step 3.

- [ ] **Step 5: Commit**

Use the `commit-smart` skill. Stage only `tests/test_quic_pacer_bypass.mojo`. Message: `test(quic): add pacer-bypass-during-handshake unit tests`.

---

## Task 2: Apply the three pacer-bypass fixes in connection.mojo

**Files:**
- Modify: `src/quic/connection.mojo:1776-1778` (Location 3 — post-send commit)
- Modify: `src/quic/connection.mojo:2374-2382` (Location 2 — `_next_timeout` pacer branch)
- Modify: `src/quic/connection.mojo:2652-2662` (Location 1 — `_can_send` gate)

- [ ] **Step 1: Apply Location 1 (`_can_send` gate bypass)**

Open `src/quic/connection.mojo`. Find the existing `_can_send` (currently lines 2652-2662):

```mojo
    def _can_send(self, size: UInt64, now: UInt64) -> Bool:
        """Composite send gate: anti-amplification + CC window + pacer (non-mutating).
        Token consumption happens via Pacer.refill_and_check at the actual send site."""
        if not self._anti_amp_ok(size):
            return False
        if self.recovery.cc.cwnd() < self.recovery.bytes_in_flight + size:
            return False
        var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
        if self.recovery.pacer.next_send_time(rate, now):
            return False
        return True
```

Replace with:

```mojo
    def _can_send(self, size: UInt64, now: UInt64) -> Bool:
        """Composite send gate: anti-amplification + CC window + pacer (non-mutating).
        Token consumption happens via Pacer.refill_and_check at the actual send site.

        The pacer is bypassed for connections that have not yet reached
        is_established(). Pacing handshake-space packets caused cold-start
        throughput collapse; anti-amplification and CC cwnd remain the safety
        floors during handshake (see specs/2026-04-25-quic-pacer-bypass-handshake.md).
        """
        if not self._anti_amp_ok(size):
            return False
        if self.recovery.cc.cwnd() < self.recovery.bytes_in_flight + size:
            return False
        if not self.is_established():
            return True
        var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
        if self.recovery.pacer.next_send_time(rate, now):
            return False
        return True
```

- [ ] **Step 2: Apply Location 2 (`_next_timeout` pacer-deadline branch)**

Find the `# --- Pacer branch ---` block in `_next_timeout` (currently lines 2374-2382):

```mojo
        # --- Pacer branch ---
        var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
        var pacer_deadline = self.recovery.pacer.next_send_time(rate, now)
        if pacer_deadline:
            if earliest:
                if pacer_deadline.value() < earliest.value():
                    earliest = pacer_deadline
            else:
                earliest = pacer_deadline
```

Replace with:

```mojo
        # --- Pacer branch ---
        # Pacer deadlines do not gate handshake-space sends (see _can_send).
        if self.is_established():
            var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
            var pacer_deadline = self.recovery.pacer.next_send_time(rate, now)
            if pacer_deadline:
                if earliest:
                    if pacer_deadline.value() < earliest.value():
                        earliest = pacer_deadline
                else:
                    earliest = pacer_deadline
```

- [ ] **Step 3: Apply Location 3 (`process_send` post-send pacer commit)**

Find the post-send block inside the `for space_idx in range(3)` loop (currently lines 1774-1778). It currently looks like:

```mojo
            self.recovery.on_packet_sent(pkt_size, True, pn, now)
            # Commit pacer token for this packet.
            var _pace_rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
            _ = self.recovery.pacer.refill_and_check(_pace_rate, now)
            self.recovery.pacer.on_sent(UInt64(pkt_size))
```

Replace with:

```mojo
            self.recovery.on_packet_sent(pkt_size, True, pn, now)
            # Commit pacer token for this packet — App-space only; matches
            # the gate bypass in _can_send and the deadline bypass in _next_timeout.
            if space_idx == 2:
                var _pace_rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
                _ = self.recovery.pacer.refill_and_check(_pace_rate, now)
                self.recovery.pacer.on_sent(UInt64(pkt_size))
```

- [ ] **Step 4: Validate Mojo gotchas**

Use the Mojo MCP `validate` tool on `src/quic/connection.mojo`. If issues are reported, fix them before proceeding.

- [ ] **Step 5: Run the new pacer-bypass tests — all three must pass**

Run:
```bash
LD_LIBRARY_PATH=/home/donokami/Projets/perso/mojo-net/lib uv run mojo run -I /home/donokami/Projets/perso/mojo-net -I /home/donokami/Projets/perso/mojo-net/conformance -D ASSERT=all /home/donokami/Projets/perso/mojo-net/tests/test_quic_pacer_bypass.mojo
```

Expected:
```
test_quic_pacer_bypass:
  test_pacer_bypassed_during_handshake: PASS
  test_pacer_active_after_handshake: PASS
  test_handshake_padding_still_works: PASS
All test_quic_pacer_bypass tests passed.
```

- [ ] **Step 6: Run the existing QUIC integration tests — anti-amp + pacer-delays-burst must still pass**

Run:
```bash
LD_LIBRARY_PATH=/home/donokami/Projets/perso/mojo-net/lib uv run mojo run -I /home/donokami/Projets/perso/mojo-net -I /home/donokami/Projets/perso/mojo-net/conformance -D ASSERT=all /home/donokami/Projets/perso/mojo-net/tests/test_quic_connection.mojo 2>&1 | tail -3
```

Expected: `All test_quic_connection tests passed.` (Specifically `test_anti_amplification` and `test_pacer_delays_burst` — the M3b/M4a regression canaries.)

- [ ] **Step 7: Run the full src test suite — no regressions anywhere**

Run:
```bash
bash /home/donokami/Projets/perso/mojo-net/scripts/run_tests.sh 2>&1 | tail -5
```

Expected: a final line of the form `All N/N src tests passed` (count is whatever the runner reports today; no failures). Note that `tests/test_quic_pacer_bypass.mojo` is NOT yet registered in `scripts/run_tests.sh` — that's done in Task 2 Step 8.

- [ ] **Step 8: Register the new test in `scripts/run_tests.sh`**

Open `scripts/run_tests.sh`. Find the line that lists `test_quic_connection` in the `TESTS=` array. Add `test_quic_pacer_bypass` immediately after it (alphabetic-ish ordering matches existing convention near the QUIC tests).

Re-run the full src suite to confirm the new entry is picked up:
```bash
bash /home/donokami/Projets/perso/mojo-net/scripts/run_tests.sh 2>&1 | tail -5
```

Expected: count is one higher than Step 7; final line `All N+1/N+1 src tests passed`.

- [ ] **Step 9: Commit**

Use the `commit-smart` skill. Stage `src/quic/connection.mojo` and `scripts/run_tests.sh`. Message: `fix(quic): bypass pacer for non-established connections`.

---

## Task 3: Conformance + interop integration gate

**Files:** None modified.

- [ ] **Step 1: Run the full conformance suite**

Run:
```bash
bash /home/donokami/Projets/perso/mojo-net/conformance/scripts/run_tests.sh 2>&1 | tail -5
```

Expected: `All 36/36 conformance tests passed.` If any test fails, STOP and triage — the pacer fix must not regress any conformance test. The QUIC/H3 cross-tests (`test_cross_quic_hs_keys`, `test_cross_quic_packet_header`, `test_h3_frame_cross`, `test_qpack_cross`) are the most likely to surface a regression.

- [ ] **Step 2: Run the interop endpoint test**

Run:
```bash
bash /home/donokami/Projets/perso/mojo-net/interop/test_local.sh 2>&1 | tail -10
```

Expected:
```
[test] PASS: unsupported testcase exited 127
[test] PASS: downloaded file matches original
[test] PASS: both files match
=== Done ===
```

If any of the three interop testcases (zerortt-must-127, handshake, transfer) fails, STOP and triage.

- [ ] **Step 3: No commit**

This task is verification-only; no code changes. If both gates passed, proceed to Task 4. If either failed, return to Task 2 to triage.

---

## Task 4: Single-cell bench validation gate

**Files:** None modified.

This task takes ~2 min wallclock. It is the **hypothesis confirmation gate**: if the median req/s is < 4,000, the hypothesis is falsified and Task 5 must NOT run.

- [ ] **Step 1: Verify the bench harness is set up**

Run:
```bash
cd /home/donokami/Projets/perso/mojo-net/bench/quic_perf && make setup 2>&1 | tail -5
```

Expected: `[setup] OK` or equivalent. (If first time on this machine, wait ~10 min for Docker build. Re-runs are ~30 s.)

- [ ] **Step 2: Run the single-cell bench**

Run:
```bash
cd /home/donokami/Projets/perso/mojo-net/bench/quic_perf && bash scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3 2>&1 | tail -20
```

Expected: command exits 0 after ~2 min wallclock. Output includes a JSON-shaped result dump and a summary line indicating the median req/s across 3 iterations. The exact final-line format is determined by `bench.sh` — capture it.

- [ ] **Step 3: Extract and assert the median req/s**

Run:
```bash
cd /home/donokami/Projets/perso/mojo-net/bench/quic_perf && python3 scripts/summarize.py 2>&1 | tail -20
```

Expected: a Markdown table including a row for `mojo-net | 1k | long-conn | tquic_client` with a numeric median.

**Hypothesis confirmation:** the median req/s for that row must be **≥ 4,000**.

If confirmed: proceed to Task 5.

If NOT confirmed (req/s ≤ 4,000): STOP. Do NOT run Task 5. Append the following to the "Open questions" section of `docs/project-context.md` (create the section if it doesn't exist) and commit:

```markdown
- **What:** Pacer was not the cold-start handshake floor (single-cell bench gate, 2026-04-25, median <= 4,000 req/s after fix vs 412 baseline). Next hypothesis needed (likely H2: serial single-fiber on_flush in bench/h3_server.mojo).
- **Severity:** required-later
- **Trigger:** before any further QUIC perf work
```

Use `commit-smart` with message: `docs: record pacer-bypass hypothesis falsification`. End the plan execution; the implementer should report `STATUS: BLOCKED — hypothesis falsified` to the dispatcher.

- [ ] **Step 4: No commit (only on confirmation path)**

If the hypothesis confirms, proceed directly to Task 5; no separate commit for this task. If falsified, the commit happened in Step 3 above.

---

## Task 5: Full bench-mvp matrix + REFERENCE.md refresh

**Only run if Task 4 confirmed (median ≥ 4,000 req/s).**

**Files:**
- Modify: `bench/quic_perf/results/REFERENCE.md` (rewrite "Reference numbers" section + "How to read this" guide)

This task takes ~50 min wallclock.

- [ ] **Step 1: Run the full bench-mvp matrix**

Run:
```bash
cd /home/donokami/Projets/perso/mojo-net/bench/quic_perf && make bench-mvp 2>&1 | tee /tmp/bench-mvp-output.log | tail -20
```

Expected: command exits 0 after ~50 min. Final line is a summary or a confirmation that all 8 cells × 3 iters completed. Full results land in `bench/quic_perf/results/*.json`.

- [ ] **Step 2: Generate the summary**

Run:
```bash
cd /home/donokami/Projets/perso/mojo-net/bench/quic_perf && python3 scripts/summarize.py 2>&1
```

Expected: a Markdown table with two sections (`tquic_client (4 threads, 25 conns/thread, saturating)` and `h2load-h3 (single-threaded, regression-tracking)`), each containing 4 rows (1k payload, 2 scenarios long-conn/short-conn, 2 servers mojo-net/tquic). Capture the full output for the REFERENCE.md rewrite.

- [ ] **Step 3: Verify the full-matrix gates pass**

From the summary captured in Step 2, check:
- All 8 cells (4 mojo-net + 4 tquic) completed (no `null` cells).
- mojo-net long-conn req/s for `1k` is **strictly greater than** the prior REFERENCE.md baseline (412 for tquic_client, 125 for h2load).
- mojo-net short-conn req/s for `1k` is **strictly greater than 1**.
- mojo-net CPU% on the long-conn `1k` cell with `tquic_client` crosses **30%** (signal that the pacer was the floor and the server is now doing real work, not idle-waiting on the pacer).

If any gate fails, follow the spec's fallback rule (see `specs/2026-04-25-quic-pacer-bypass-handshake.md` §Validation): "If the single-cell gate is met but the full-matrix gate is not, ship the change anyway — it's a strict improvement — and capture the next-hypothesis data in REFERENCE.md." Note the failed gate(s) in the REFERENCE.md rewrite.

- [ ] **Step 4: Rewrite REFERENCE.md**

Open `bench/quic_perf/results/REFERENCE.md`. Preserve the `## Host` section as-is (host details remain the same). Update:

- The `## Reference numbers` introductory paragraph to reference the new date and the hypothesis-fix commit (use `git log -1 --format='%h'` for the SHA).
- The `### tquic_client (4 threads, 25 conns/thread, saturating)` table — replace the four rows with the new numbers from the summary.
- The `### h2load-h3 (single-threaded, regression-tracking)` table — same.
- The `## How to read this` section — rewrite the bullet list to reflect the new bottleneck signal: e.g. "mojo-net now hits N req/s with X% CPU; the pacer was the floor; next hypothesis is …" (only mention "next hypothesis" if the rps:CPU ratio still suggests headroom, i.e. CPU < 80%).
- Add a new `## Diff vs prior baseline` section with one line per cell: `mojo-net 1k long-conn tquic_client: 412 → <new>` and similar for the other 7 cells, including the relative speedup (e.g. `(<new>/412 = N.Nx)`).
- Update the `## Where the work goes from here` paragraph: if the rps gap to TQUIC closed below 5×, the next pass targets a different bottleneck (rewrite this paragraph based on the actual numbers); if still > 5×, keep the multi-fiber accept fan-out hypothesis as next.

- [ ] **Step 5: Commit**

Use the `commit-smart` skill. Stage `bench/quic_perf/results/REFERENCE.md` and any updated JSON results files under `bench/quic_perf/results/*.json`. Message: `docs(bench/quic_perf): refresh REFERENCE.md after pacer-bypass landing`.

---

## Task 6: Update project-context with implementation outcome

**Files:**
- Modify: `docs/project-context.md` (Active specs row + session history entry)

- [ ] **Step 1: Update the Active specs row**

Open `docs/project-context.md`. Find the row for `specs/2026-04-25-quic-pacer-bypass-handshake.md` (status = `pending`). Update:

- Status column: `pending` → `done`
- Notes column: append a one-line summary of the outcome, e.g.:
  - On confirmation: `Surgical pacer bypass landed. New REFERENCE.md numbers: <key cells>. Speedup: <Nx> long-conn / <Mx> short-conn. CPU% on long-conn 1k crosses <P>%, confirming pacer was the floor.`
  - On falsification (Task 4 stopped): `Hypothesis falsified at single-cell gate (median <= 4,000 req/s). No production code shipped. Open question recorded for next-hypothesis pass.`

- [ ] **Step 2: Add a session-history entry**

Find the `## Session history` section. Add a new bullet at the top (above the existing 2026-04-25 entries):

```markdown
- 2026-04-25 — `<this-session-jsonl-path>` (continued) — QUIC pacer-bypass hypothesis pass 1: <one-line outcome>. Spec specs/2026-04-25-quic-pacer-bypass-handshake.md → plan plans/2026-04-25-quic-pacer-bypass-handshake.md. Three connection.mojo edits + three new unit tests + REFERENCE.md refresh (or open-question entry on falsification). Conformance 36/36 + interop 3/3 stayed green throughout.
```

Replace `<this-session-jsonl-path>` with the output of:
```bash
python3 "$(cat ~/.claude/claude-skills-root)/scripts/find-session.py"
```

Replace `<one-line outcome>` with the same summary used in Step 1's Notes column.

- [ ] **Step 3: Update phase**

Find the `**Current phase:**` line near the top. Change `spec-quic-pacer-bypass-implementing` (or whatever the running tag is) to `spec-quic-pacer-bypass-reviewing`.

- [ ] **Step 4: Commit**

Use the `commit-smart` skill. Stage only `docs/project-context.md`. Message: `docs: record quic pacer-bypass implementation outcome`.

---

## Acceptance gate (final, full plan)

The plan is complete when all of the following hold:

| # | Gate | Source |
|---|---|---|
| 1 | All three new pacer-bypass unit tests pass | Task 2 Step 5 |
| 2 | `tests/test_quic_connection.mojo` still green (anti-amp + pacer-delays-burst canaries) | Task 2 Step 6 |
| 3 | Full src test suite green | Task 2 Step 7 |
| 4 | `tests/test_quic_pacer_bypass` registered in `scripts/run_tests.sh` | Task 2 Step 8 |
| 5 | Conformance 36/36 PASS | Task 3 Step 1 |
| 6 | Interop 3/3 PASS | Task 3 Step 2 |
| 7 | Single-cell bench median req/s ≥ 4,000 (or, on falsification, open-question entry committed) | Task 4 Step 3 |
| 8 | Full bench-mvp matrix run; REFERENCE.md rewritten (only on confirmation) | Task 5 |
| 9 | docs/project-context.md updated (Active specs row + session entry + phase) | Task 6 |

If gate 7 falsifies the hypothesis, gates 8 are skipped and the plan terminates after Task 4 + Task 6 (with falsification notes). The retrospective should explicitly capture the negative result so the next hypothesis pass starts from a known-bad data point, not zero.

## Out-of-scope items (carried from spec, not implemented)

| What | Severity | Trigger |
|---|---|---|
| Multi-fiber accept fan-out (`bench/h3_server.mojo:523-600` `on_flush` serial loop) | required-later | `< 10×` rps from this fix |
| `QuicConnection` slab pre-alloc | optional | profiling shows alloc cost dominates |
| Batch handshake FFI (extend Phase 2 Batch FFI) | optional | profiling shows rustls FFI lock contention |
| Initial cwnd expansion (10×MDS → 32×MDS) | optional | always after this lands; never bundled |
| CID Dict contention reduction (`bench/h3_server.mojo:537,575`) | optional | profiling shows Dict-mutation cost on hot path |
| Intra-process worker sharding | non-goal | use multi-process SO_REUSEPORT |
| Re-running H2 / non-QUIC benchmarks | optional | none expected; change is QUIC-only |
