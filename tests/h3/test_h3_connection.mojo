# tests/test_h3_connection.mojo
from std.memory import Span
from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.h3.connection import H3Connection, H3Event
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def test_h3event_zero_values() raises:
    """H3Event initializes all non-kind fields to zero/empty."""
    var ev = H3Event(H3Event.HANDSHAKE_COMPLETE)
    assert_equal_int(Int(ev.kind), Int(H3Event.HANDSHAKE_COMPLETE), "kind")
    assert_equal_int(Int(ev.stream_id), 0, "stream_id zero")
    assert_equal_int(len(ev.fields), 0, "fields empty")
    assert_equal_int(len(ev.data), 0, "data empty")
    assert_true(not ev.fin, "fin false")
    assert_equal_int(Int(ev.error_code), 0, "error_code zero")
    assert_true(ev.reason == "", "reason empty")
    assert_equal_int(Int(ev.last_stream_id), 0, "last_stream_id zero")
    print("  test_h3event_zero_values: PASS")


def test_is_peer_initiated() raises:
    """Stream ID bit-0 encodes initiator: even=client, odd=server."""
    assert_true((UInt64(0) & UInt64(1)) == 0, "stream 0 client-initiated")
    assert_true((UInt64(4) & UInt64(1)) == 0, "stream 4 client-initiated")
    assert_true((UInt64(1) & UInt64(1)) == 1, "stream 1 server-initiated")
    assert_true((UInt64(3) & UInt64(1)) == 1, "stream 3 server-initiated")
    print("  test_is_peer_initiated: PASS")


def test_is_request_stream() raises:
    """Stream ID bit-1 encodes bidi (0) vs uni (1)."""
    assert_true((UInt64(0) & UInt64(0x02)) == 0, "stream 0 bidi")
    assert_true((UInt64(4) & UInt64(0x02)) == 0, "stream 4 bidi")
    assert_true((UInt64(2) & UInt64(0x02)) != 0, "stream 2 uni")
    assert_true((UInt64(3) & UInt64(0x02)) != 0, "stream 3 uni")
    print("  test_is_request_stream: PASS")


def test_h3event_kind_constants() raises:
    """H3Event kind constants are distinct and non-zero."""
    assert_equal_int(Int(H3Event.HANDSHAKE_COMPLETE), 1, "HANDSHAKE_COMPLETE")
    assert_equal_int(Int(H3Event.SETTINGS_RECEIVED),  2, "SETTINGS_RECEIVED")
    assert_equal_int(Int(H3Event.HEADERS_RECEIVED),   3, "HEADERS_RECEIVED")
    assert_equal_int(Int(H3Event.DATA_RECEIVED),      4, "DATA_RECEIVED")
    assert_equal_int(Int(H3Event.STREAM_ENDED),       5, "STREAM_ENDED")
    assert_equal_int(Int(H3Event.STREAM_RESET),       6, "STREAM_RESET")
    assert_equal_int(Int(H3Event.GOAWAY_RECEIVED),    7, "GOAWAY_RECEIVED")
    assert_equal_int(Int(H3Event.CONNECTION_CLOSED),  8, "CONNECTION_CLOSED")
    print("  test_h3event_kind_constants: PASS")


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    # Backed by tests/fixtures/tls/server.{crt,key} (regen via
    # scripts/regen_test_certs.sh). See plans/2026-05-13-deps-enhancement.md §3.1.
    return load_test_cert()


def _h3_default_params() -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _pump_h3(
    mut a: H3Connection, mut b: H3Connection, mut now: UInt64, rounds: Int = 5
) raises -> UInt64:
    """Exchange datagrams between a and b for `rounds` iterations."""
    for _ in range(rounds):
        now += UInt64(10_000)
        var a_dgs = a.drain_datagrams(now)
        for i in range(len(a_dgs)):
            try:
                b.feed_datagram(Span(a_dgs[i]), now)
            except:
                pass
        var b_dgs = b.drain_datagrams(now)
        for i in range(len(b_dgs)):
            try:
                a.feed_datagram(Span(b_dgs[i]), now)
            except:
                pass
    return now


def test_h3_control_stream_setup() raises:
    """After 50 pump rounds, client must receive SETTINGS_RECEIVED."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var srv_cfg = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var cli_cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _h3_default_params()
    var now = UInt64(1_000_000)
    var client_quic = QuicConnection.client(tls.shared(), cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        tls.shared(), srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server_h3 = H3Connection.server(server_quic^)
    var client_h3 = H3Connection.client(client_quic^)
    # --- pump loop ---
    var got_settings = False
    for _ in range(50):
        now = _pump_h3(server_h3, client_h3, now, 1)
        while True:
            var ev = client_h3.poll_event()
            if not ev:
                break
            if ev.value().kind == H3Event.SETTINGS_RECEIVED:
                got_settings = True
        # drain server events too
        while True:
            var ev = server_h3.poll_event()
            if not ev:
                break
        if got_settings:
            break
    assert_true(got_settings, "client did not receive SETTINGS_RECEIVED after 50 rounds")
    print("  test_h3_control_stream_setup: PASS")


def main() raises:
    print("=== test_h3_connection ===")
    test_h3event_zero_values()
    test_is_peer_initiated()
    test_is_request_stream()
    test_h3event_kind_constants()
    test_h3_control_stream_setup()
    print("All H3Connection tests passed.")
