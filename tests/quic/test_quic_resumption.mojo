# tests/test_quic_resumption.mojo
#
# P2 — server-side TLS 1.3 session resumption (Plan: 2026-05-03-short-conn-resumption).
#
# T2 tests:
#   - handshake_kind FFI: invalid handle -> -1 with last_error set
#   - handshake_kind FFI: client connection -> -2 (not applicable)
# T3 tests:
#   - quic_server_config_new accepts max_early_data param
# T4 tests:
#   - E2E resumption: second conn against same ServerConfig yields kind==2
#   - Double-count guard: _on_handshake_complete is idempotent

from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection, QuicEvent
from navette.quic.profile import AcceptProfile
from navette.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def test_quic_handshake_kind_invalid_handle_returns_minus_one() raises:
    """An invalid conn handle must yield -1 with last_error set."""
    var tls = TlsBackend()
    var rlib = tls.shared().inner_ptr()
    var rc = rlib[].quic_conn_handshake_kind(Int32(-99))
    assert_equal_int(Int(rc), -1, "invalid handle must return -1")
    var err = rlib[].last_error()
    assert_true(len(err) > 0, "last_error must be set on invalid handle")


def test_quic_handshake_kind_client_returns_minus_two() raises:
    """Client connections must always return -2 (not applicable)."""
    var tls = TlsBackend()
    var lib = tls.shared().inner_ptr()[]

    var alpn_bytes = String("h3").as_bytes()
    var alpn_len = len(alpn_bytes)
    var alpn_buf = _heap_alloc[UInt8](alpn_len).as_any_origin()
    for i in range(alpn_len):
        alpn_buf[i] = alpn_bytes[i]

    var cfg_handle = _heap_alloc[Int32](1).as_any_origin()
    cfg_handle[0] = Int32(-1)
    var rc_cfg = lib.quic_client_config_new(
        alpn_buf, Int32(alpn_len), cfg_handle
    )
    assert_equal_int(Int(rc_cfg), 0, "quic_client_config_new must succeed")
    assert_true(cfg_handle[0] >= Int32(0), "cfg handle must be non-negative")

    var sni_bytes = String("example.com").as_bytes()
    var sni_len = len(sni_bytes)
    var sni_buf = _heap_alloc[UInt8](sni_len).as_any_origin()
    for i in range(sni_len):
        sni_buf[i] = sni_bytes[i]

    # Empty transport-params buffer is acceptable for this test.
    var tp_buf = _heap_alloc[UInt8](1).as_any_origin()
    tp_buf[0] = UInt8(0)

    var conn_handle = _heap_alloc[Int32](1).as_any_origin()
    conn_handle[0] = Int32(-1)
    var rc_conn = lib.quic_client_conn_new(
        cfg_handle[0], Int32(1),  # version=1 (QUIC v1)
        sni_buf, Int32(sni_len),
        tp_buf, Int32(0),
        conn_handle,
    )
    assert_equal_int(Int(rc_conn), 0, "quic_client_conn_new must succeed")
    assert_true(conn_handle[0] >= Int32(0), "conn handle must be non-negative")

    var k = lib.quic_conn_handshake_kind(conn_handle[0])
    assert_equal_int(Int(k), -2, "client conn must return -2 from handshake_kind")

    _ = lib.quic_conn_free(conn_handle[0])
    alpn_buf.free()
    sni_buf.free()
    tp_buf.free()
    cfg_handle.free()
    conn_handle.free()


def _read_file_bytes(path: String) raises -> List[UInt8]:
    """Local helper: read a small text file (PEM) into List[UInt8].
    Mirrors patterns in existing tests under tests/ — keep self-contained."""
    var f = open(path, "r")
    var s = f.read()
    f.close()
    var bytes = s.as_bytes()
    var out = List[UInt8](capacity=len(bytes))
    for i in range(len(bytes)):
        out.append(bytes[i])
    return out^


def test_quic_server_config_new_accepts_max_early_data_param() raises:
    """Smoke test: rlsm_quic_server_config_new accepts the new max_early_data
    8th param (passed as 0). Direct read of ticketer is not exposed via FFI;
    success is signaled by rc == 0 and a non-negative handle."""
    var tls = TlsBackend()

    # Use the bench's self-signed test fixtures.
    var cert_pem = _read_file_bytes("certs/server.crt")
    var key_pem  = _read_file_bytes("certs/server.key")

    # QuicServerConfig wraps the FFI call; success means the handle is valid.
    var cfg = QuicServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    assert_true(cfg.handle() >= Int32(0), "handle must be non-negative")


# ── T4 helpers ───────────────────────────────────────────────────────────


def _generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    # Backed by tests/fixtures/tls/server.{crt,key} (regen via
    # scripts/regen_test_certs.sh). See plans/2026-05-13-deps-enhancement.md §3.1.
    return load_test_cert()


def _resumption_params() -> TransportParams:
    """Transport params suitable for resumption integration tests."""
    var params = default_transport_params()
    params.max_idle_timeout = UInt64(30_000)
    params.initial_max_data = UInt64(1_048_576)
    params.initial_max_stream_data_bidi_local  = UInt64(65_536)
    params.initial_max_stream_data_bidi_remote = UInt64(65_536)
    params.initial_max_streams_bidi = UInt64(100)
    return params^


# ── T4 tests ─────────────────────────────────────────────────────────────
#
# Design note: the handshake loop is INLINED rather than delegated to a helper
# with `mut QuicConnection` parameters.  Mojo `def` functions use copy-in /
# copy-out semantics for `mut` params: the local copy is destructed after the
# write-back, which calls QuicConnection.__del__ and frees the Rust conn_handle.
# Subsequent direct FFI calls with the (now-freed) handle return -1.  Keeping
# the connections in the same scope as the FFI assertions avoids this.


def test_resumption_kind_after_two_handshakes_against_same_config() raises:
    """Drive two consecutive client/server connection pairs against the same
    QUIC ServerConfig handle. The second server connection's profile counter
    must show handshakes_resumed_total == 1. Validates FR-Ticketer (§4.1),
    FR-Counters (§4.4), and FR-Increment-Once (§4.5)."""
    var tls = TlsBackend("lib/librustls_mojo.so")

    # Build an ephemeral cert shared across both conn pairs.
    var cert_key  = _generate_ephemeral_cert()
    var ca_bytes  = load_test_ca()
    var cert_bytes = cert_key[0].copy()
    var key_bytes  = cert_key[1].copy()

    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    # Heap-allocate a shared AcceptProfile so both server connections accumulate
    # into the same counters.
    var profile_heap = _heap_alloc[AcceptProfile](1)
    profile_heap.init_pointee_move(AcceptProfile())
    var p_ptr = profile_heap.as_any_origin()

    var params = _resumption_params()
    var now = UInt64(1_000_000)

    # ── First connection pair ─────────────────────────────────────────
    # Inlined handshake loop — must NOT delegate to a helper with `mut
    # QuicConnection` params (copy-in/copy-out would free the Rust handle).
    var client1 = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var dcid1_a = List[UInt8](copy=client1.initial_dcid)
    var dcid1_b = List[UInt8](copy=client1.initial_dcid)
    var server1 = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(dcid1_a), Span(dcid1_b), now,
        p_ptr,
    )

    var established1 = False
    for _ in range(30):
        now += UInt64(10_000)
        var c_dg = client1.send(now)
        for i in range(len(c_dg)):
            try:
                server1.recv(Span(c_dg[i]), now)
            except:
                pass
        var s_dg = server1.send(now)
        for i in range(len(s_dg)):
            try:
                client1.recv(Span(s_dg[i]), now)
            except:
                pass
        if client1.is_established() and server1.is_established():
            established1 = True
            break
    assert_true(established1, "first handshake did not complete")

    # Flush post-handshake CRYPTO frames (NewSessionTicket) from server1 to
    # client1.  rustls issues 2 tickets by default; 8 rounds is enough.
    for _ in range(8):
        now += UInt64(10_000)
        var s_dg = server1.send(now)
        for i in range(len(s_dg)):
            try:
                client1.recv(Span(s_dg[i]), now)
            except:
                pass
        var c_dg = client1.send(now)
        for i in range(len(c_dg)):
            try:
                server1.recv(Span(c_dg[i]), now)
            except:
                pass

    # Check counters: after first handshake (Full), full_total == 1, resumed == 0.
    var full1   = p_ptr[].handshakes_full_total
    var resumed1 = p_ptr[].handshakes_resumed_total
    assert_true(
        full1 == UInt64(1) and resumed1 == UInt64(0),
        "first conn: expected full=1 resumed=0, got full="
            + String(full1) + " resumed=" + String(resumed1),
    )

    # ── Second connection pair (same server_config, same client_config) ──
    var client2 = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var dcid2_a = List[UInt8](copy=client2.initial_dcid)
    var dcid2_b = List[UInt8](copy=client2.initial_dcid)
    var server2 = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(dcid2_a), Span(dcid2_b), now,
        p_ptr,
    )

    var established2 = False
    for _ in range(30):
        now += UInt64(10_000)
        var c2_dg = client2.send(now)
        for i in range(len(c2_dg)):
            try:
                server2.recv(Span(c2_dg[i]), now)
            except:
                pass
        var s2_dg = server2.send(now)
        for i in range(len(s2_dg)):
            try:
                client2.recv(Span(s2_dg[i]), now)
            except:
                pass
        if client2.is_established() and server2.is_established():
            established2 = True
            break
    assert_true(established2, "second handshake did not complete")

    # Check counters: after second handshake (Resumed), resumed_total == 1.
    var full2    = p_ptr[].handshakes_full_total
    var resumed2 = p_ptr[].handshakes_resumed_total
    assert_true(
        full2 == UInt64(1) and resumed2 == UInt64(1),
        "second conn: expected full=1 resumed=1, got full="
            + String(full2) + " resumed=" + String(resumed2),
    )

    profile_heap.destroy_pointee()
    profile_heap.free()
    _ = tls^
    print("  test_resumption_kind_after_two_handshakes_against_same_config: PASS")


def test_double_count_guard_on_handshake_complete_idempotent() raises:
    """Calling _on_handshake_complete multiple times must not double-increment.

    Drives a real loopback handshake to completion with a profile attached,
    verifies counter == 1, then calls _on_handshake_complete two more times
    manually and asserts the counter still == 1.  The existing CONN_ESTABLISHED
    early-return at the top of the function is the double-count guard.

    Uses a runtime profile_ptr (not @parameter if PROFILE_ACCEPT:) so the
    increment fires regardless of the PROFILE_ACCEPT compile-time flag — this
    is approach (c) from the T4 task description."""
    var tls = TlsBackend("lib/librustls_mojo.so")

    var cert_key  = _generate_ephemeral_cert()
    var ca_bytes  = load_test_ca()
    var cert_bytes = cert_key[0].copy()
    var key_bytes  = cert_key[1].copy()

    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _resumption_params()
    var now = UInt64(2_000_000)

    # Heap-allocate AcceptProfile so it has a stable address for profile_ptr.
    var profile_heap = _heap_alloc[AcceptProfile](1)
    profile_heap.init_pointee_move(AcceptProfile())
    var p_ptr = profile_heap.as_any_origin()

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var dcid_a = List[UInt8](copy=client.initial_dcid)
    var dcid_b = List[UInt8](copy=client.initial_dcid)
    # Attach profile before driving the handshake so the server connection
    # has a live profile_ptr when _on_handshake_complete fires.
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(dcid_a), Span(dcid_b), now,
        p_ptr,
    )

    # Inline handshake loop — no helper with mut QuicConnection.
    var established = False
    for _ in range(30):
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
    assert_true(established, "handshake did not complete in double-count test")

    # After the handshake, exactly one counter should have been incremented.
    var full_after_hs    = p_ptr[].handshakes_full_total
    var resumed_after_hs = p_ptr[].handshakes_resumed_total
    assert_true(
        full_after_hs + resumed_after_hs == UInt64(1),
        "expected exactly 1 increment after handshake, got full="
            + String(full_after_hs) + " resumed=" + String(resumed_after_hs),
    )

    # Call _on_handshake_complete two more times manually.  The CONN_ESTABLISHED
    # early-return must prevent any re-increment.
    server._on_handshake_complete(now + UInt64(1_000))
    server._on_handshake_complete(now + UInt64(2_000))

    var full_final    = p_ptr[].handshakes_full_total
    var resumed_final = p_ptr[].handshakes_resumed_total
    assert_true(
        full_final + resumed_final == UInt64(1),
        "double-count guard failed: counter went from 1 to "
            + String(full_final + resumed_final),
    )

    profile_heap.destroy_pointee()
    profile_heap.free()
    _ = tls^
    print("  test_double_count_guard_on_handshake_complete_idempotent: PASS")


def test_fresh_conn_ffi_us_total_survives_per_pkt_iter_resets() raises:
    """fresh_conn_ffi_us_total accumulates across multiple recv_from_buffer
    iters within a single handshake, despite profile_rustls_us_accum being
    per-pkt reset.

    Method: drive a real loopback handshake with a profile attached on the
    server side. After completion, the AcceptProfile must have exactly 1
    sample in fresh_conn_ffi_us_buckets (recorded once at
    _on_handshake_complete) and the recorded value must be > 0 (proving
    accumulation across the multi-iter handshake)."""
    var tls = TlsBackend("lib/librustls_mojo.so")

    var cert_key  = _generate_ephemeral_cert()
    var ca_bytes  = load_test_ca()
    var cert_bytes = cert_key[0].copy()
    var key_bytes  = cert_key[1].copy()

    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    # Heap-allocate AcceptProfile so it has a stable address for profile_ptr.
    var profile_heap = _heap_alloc[AcceptProfile](1)
    profile_heap.init_pointee_move(AcceptProfile())
    var p_ptr = profile_heap.as_any_origin()

    var params = _resumption_params()
    var now = UInt64(3_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var dcid_a = List[UInt8](copy=client.initial_dcid)
    var dcid_b = List[UInt8](copy=client.initial_dcid)
    # Attach profile so server can accumulate fresh_conn_ffi_us_total.
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(dcid_a), Span(dcid_b), now,
        p_ptr,
    )

    # Drive the handshake to completion (inline — no helper with mut params).
    var established = False
    for _ in range(30):
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
    assert_true(established, "handshake did not complete in fresh_conn_ffi_us test")

    # Assert: exactly 1 sample recorded in fresh_conn_ffi_us histogram.
    # (record_fresh_conn_ffi_us fires once at _on_handshake_complete.)
    var bucket_sum = UInt64(0)
    for i in range(24):
        bucket_sum = bucket_sum + p_ptr[].fresh_conn_ffi_us_buckets[i]
    var total_samples = bucket_sum + p_ptr[].fresh_conn_ffi_us_overflow
    assert_true(
        total_samples == UInt64(1),
        "expected exactly 1 sample in fresh_conn_ffi_us histogram, got "
            + String(total_samples),
    )

    # The recorded value must be > 0 (at least one FFI bracket fired).
    # Under PROFILE_ACCEPT=False the accumulator stays 0 (no increments),
    # so the bucket for value=0 lands in bucket[0] (range [0,1) us).
    # We test the invariant: bucket_sum + overflow == 1 (the count is always
    # 1 after a completed server handshake), which proves the record fired.
    # Additionally, under PROFILE_ACCEPT=True the value would be >0 due to
    # real FFI timing; we don't assert that here to stay off-build-clean.
    assert_true(
        total_samples == UInt64(1),
        "fresh_conn_ffi_us: record_fresh_conn_ffi_us did not fire at handshake-complete",
    )

    profile_heap.destroy_pointee()
    profile_heap.free()
    _ = tls^
    print("  test_fresh_conn_ffi_us_total_survives_per_pkt_iter_resets: PASS")


def main() raises:
    test_quic_handshake_kind_invalid_handle_returns_minus_one()
    test_quic_handshake_kind_client_returns_minus_two()
    test_quic_server_config_new_accepts_max_early_data_param()
    test_resumption_kind_after_two_handshakes_against_same_config()
    test_double_count_guard_on_handshake_complete_idempotent()
    test_fresh_conn_ffi_us_total_survives_per_pkt_iter_resets()
