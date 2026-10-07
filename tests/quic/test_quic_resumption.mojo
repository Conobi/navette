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
#   - _on_handshake_complete is idempotent once established

from std.memory import Pointer
from std.collections import Span

from navette.util.owned_alloc import Owned
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.event import QuicEvent
from navette.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def test_quic_handshake_kind_invalid_handle_returns_minus_one() raises:
    """An invalid conn handle must yield -1 with last_error set."""
    var tls = TlsBackend()
    # `shared` has to be a named binding that is still referenced after the
    # FFI calls below. `inner_ptr()` hands back an untracked pointer, so the
    # checker cannot see that those calls depend on it; left as a temporary,
    # ASAP destruction closes the dylib on the very line that opens it and
    # the symbol lookup aborts with "Dylib handle is null".
    var shared = tls.shared()
    var rlib = shared.inner_ptr()
    var rc = rlib[].quic_conn_handshake_kind(Int32(-99))
    assert_equal_int(Int(rc), -1, "invalid handle must return -1")
    var err = rlib[].last_error()
    assert_true(Bool(err), "last_error must be set on invalid handle")
    _ = shared.inner_ptr()  # anchor: keep the dylib open past the calls above


def test_quic_handshake_kind_client_returns_minus_two() raises:
    """Client connections must always return -2 (not applicable)."""
    var tls = TlsBackend()
    var shared = tls.shared()
    var lib_ptr = shared.inner_ptr()
    ref lib = lib_ptr[]

    var alpn_bytes = String("h3").as_bytes()
    var alpn_len = len(alpn_bytes)
    var alpn_owned = Owned[UInt8](alpn_len)
    var alpn_buf = alpn_owned.ptr()
    for i in range(alpn_len):
        alpn_buf[i] = alpn_bytes[i]

    var cfg_handle_owned = Owned[Int32](1)
    var cfg_handle = cfg_handle_owned.ptr()
    cfg_handle[0] = Int32(-1)
    var rc_cfg = lib.quic_client_config_new(
        alpn_buf, Int32(alpn_len), cfg_handle
    )
    assert_equal_int(Int(rc_cfg), 0, "quic_client_config_new must succeed")
    assert_true(cfg_handle[0] >= Int32(0), "cfg handle must be non-negative")

    var sni_bytes = String("example.com").as_bytes()
    var sni_len = len(sni_bytes)
    var sni_owned = Owned[UInt8](sni_len)
    var sni_buf = sni_owned.ptr()
    for i in range(sni_len):
        sni_buf[i] = sni_bytes[i]

    # Empty transport-params buffer is acceptable for this test.
    var tp_owned = Owned[UInt8](1)
    var tp_buf = tp_owned.ptr()
    tp_buf[0] = UInt8(0)

    var conn_handle_owned = Owned[Int32](1)
    var conn_handle = conn_handle_owned.ptr()
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
    # `lib` is a `ref` through an untracked pointer, so the checker cannot
    # see that any FFI call above depends on `shared`. Without this anchor
    # ASAP destruction closes the dylib right after `inner_ptr()` and the
    # first symbol lookup aborts with "Dylib handle is null".
    _ = shared.inner_ptr()
    _ = alpn_owned
    _ = sni_owned
    _ = tp_owned
    _ = cfg_handle_owned
    _ = conn_handle_owned


def _read_file_bytes(path: String) raises -> List[Byte]:
    """Local helper: read a small text file (PEM) into List[Byte].
    Mirrors patterns in existing tests under tests/ — keep self-contained."""
    var f = open(path, "r")
    var s = f.read()
    f.close()
    var bytes = s.as_bytes()
    var out = List[Byte](capacity=len(bytes))
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


def _generate_ephemeral_cert() raises -> Tuple[List[Byte], List[Byte]]:
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
    QUIC ServerConfig handle. rustls must report the first server
    handshake as full and the second as resumed."""
    var tls = TlsBackend("lib/librustls_mojo.so")

    # Build an ephemeral cert shared across both conn pairs.
    var cert_key  = _generate_ephemeral_cert()
    var ca_bytes  = load_test_ca()
    var cert_bytes = cert_key[0].copy()
    var key_bytes  = cert_key[1].copy()

    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _resumption_params()
    var now = UInt64(1_000_000)

    # ── First connection pair ─────────────────────────────────────────
    # Inlined handshake loop — must NOT delegate to a helper with `mut
    # QuicConnection` params (copy-in/copy-out would free the Rust handle).
    var client1 = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var dcid1_a = List[Byte](client1.initial_dcid.as_span())
    var dcid1_b = List[Byte](client1.initial_dcid.as_span())
    var server1 = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(dcid1_a), Span(dcid1_b), now,
    )

    var c_dg = List[List[Byte]](capacity=1)
    var s_dg = List[List[Byte]](capacity=1)
    var established1 = False
    for _ in range(30):
        now += UInt64(10_000)
        c_dg.clear()
        var c_n = client1.send(now, c_dg)
        for i in range(c_n):
            try:
                server1.recv(Span(c_dg[i]), now)
            except:
                pass
        s_dg.clear()
        var s_n = server1.send(now, s_dg)
        for i in range(s_n):
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
        s_dg.clear()
        var s_n2 = server1.send(now, s_dg)
        for i in range(s_n2):
            try:
                client1.recv(Span(s_dg[i]), now)
            except:
                pass
        c_dg.clear()
        var c_n2 = client1.send(now, c_dg)
        for i in range(c_n2):
            try:
                server1.recv(Span(c_dg[i]), now)
            except:
                pass

    # handshake_kind: 1 or 3 = full, 2 = resumed.
    var kind1 = server1._lib.inner_ptr()[].quic_conn_handshake_kind(server1.conn_handle)
    assert_true(
        kind1 == Int32(1) or kind1 == Int32(3),
        "first conn: expected a full handshake, got kind=" + String(kind1),
    )

    # ── Second connection pair (same server_config, same client_config) ──
    var client2 = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var dcid2_a = List[Byte](client2.initial_dcid.as_span())
    var dcid2_b = List[Byte](client2.initial_dcid.as_span())
    var server2 = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(dcid2_a), Span(dcid2_b), now,
    )

    var c2_dg = List[List[Byte]](capacity=1)
    var s2_dg = List[List[Byte]](capacity=1)
    var established2 = False
    for _ in range(30):
        now += UInt64(10_000)
        c2_dg.clear()
        var c2_n = client2.send(now, c2_dg)
        for i in range(c2_n):
            try:
                server2.recv(Span(c2_dg[i]), now)
            except:
                pass
        s2_dg.clear()
        var s2_n = server2.send(now, s2_dg)
        for i in range(s2_n):
            try:
                client2.recv(Span(s2_dg[i]), now)
            except:
                pass
        if client2.is_established() and server2.is_established():
            established2 = True
            break
    assert_true(established2, "second handshake did not complete")

    var kind2 = server2._lib.inner_ptr()[].quic_conn_handshake_kind(server2.conn_handle)
    assert_true(
        kind2 == Int32(2),
        "second conn: expected a resumed handshake, got kind=" + String(kind2),
    )

    # Anchors: keep both servers alive past the FFI reads above (ASAP
    # destruction would free a handle mid-statement).
    _ = server1.conn_handle
    _ = server2.conn_handle
    _ = tls^
    print("  test_resumption_kind_after_two_handshakes_against_same_config: PASS")


def test_double_count_guard_on_handshake_complete_idempotent() raises:
    """Calling _on_handshake_complete again after establishment is a no-op.

    Drives a real loopback handshake to completion, then calls
    _on_handshake_complete two more times. The CONN_ESTABLISHED early return
    must keep the Application-space PN-skip state, which completion seeds
    from the CSPRNG, unchanged."""
    var tls = TlsBackend("lib/librustls_mojo.so")

    var cert_key  = _generate_ephemeral_cert()
    var ca_bytes  = load_test_ca()
    var cert_bytes = cert_key[0].copy()
    var key_bytes  = cert_key[1].copy()

    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _resumption_params()
    var now = UInt64(2_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var dcid_a = List[Byte](client.initial_dcid.as_span())
    var dcid_b = List[Byte](client.initial_dcid.as_span())
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(dcid_a), Span(dcid_b), now,
    )

    # Inline handshake loop — no helper with mut QuicConnection.
    var c_dg = List[List[Byte]](capacity=1)
    var s_dg = List[List[Byte]](capacity=1)
    var established = False
    for _ in range(30):
        now += UInt64(10_000)
        c_dg.clear()
        var c_n = client.send(now, c_dg)
        for i in range(c_n):
            try:
                server.recv(Span(c_dg[i]), now)
            except:
                pass
        s_dg.clear()
        var s_n = server.send(now, s_dg)
        for i in range(s_n):
            try:
                client.recv(Span(s_dg[i]), now)
            except:
                pass
        if client.is_established() and server.is_established():
            established = True
            break
    assert_true(established, "handshake did not complete in double-count test")

    var rng_before = server.spaces[2].pn_skip_rng
    var next_before = server.spaces[2].pn_skip_next
    assert_true(rng_before != UInt64(0), "completion must seed PN skipping")

    # The CONN_ESTABLISHED early return must stop a re-seed.
    server._on_handshake_complete(now + UInt64(1_000))
    server._on_handshake_complete(now + UInt64(2_000))

    assert_true(
        server.spaces[2].pn_skip_rng == rng_before
        and server.spaces[2].pn_skip_next == next_before,
        "repeated _on_handshake_complete re-ran completion",
    )
    _ = tls^
    print("  test_double_count_guard_on_handshake_complete_idempotent: PASS")


def main() raises:
    test_quic_handshake_kind_invalid_handle_returns_minus_one()
    test_quic_handshake_kind_client_returns_minus_two()
    test_quic_server_config_new_accepts_max_early_data_param()
    test_resumption_kind_after_two_handshakes_against_same_config()
    test_double_count_guard_on_handshake_complete_idempotent()
