"""Stream frames that break direction, final-size, flow-control or stream-limit rules close the connection instead of raising (RFC 9000 Sections 4, 19.4, 19.5, 19.8, 19.10).

A raise out of frame dispatch dropped the whole packet unacknowledged,
so the peer retransmitted it forever and the connection never learnt of
the error. Each case checks the close code the connection queued and
that nothing raised. The RESET_STREAM and STOP_SENDING stream-class
checks depend on the endpoint's role: a client receives on server-uni
streams.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.frame import StreamFrame, ResetStreamFrame, StopSendingFrame
from navette.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def _params(max_data: UInt64 = 1_048_576) -> TransportParams:
    var p = default_transport_params()
    p.initial_max_data = max_data
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_stream_data_uni = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


struct Conns(Movable):
    var tls: TlsBackend
    var client: QuicConnection
    var server: QuicConnection

    def __init__(out self, max_data: UInt64 = 1_048_576) raises:
        self.tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert = ck[0].copy()
        var key = ck[1].copy()
        var ca = load_test_ca()
        var scfg = QuicServerConfig(self.tls.shared(), Span(cert), Span(key))
        var ccfg = QuicClientConfig.with_ca(self.tls.shared(), Span(ca))
        var now = UInt64(1_000_000)
        self.client = QuicConnection.client(self.tls.shared(), ccfg, "localhost", _params(max_data), now)
        var orig = List[Byte](self.client.initial_dcid.as_span())
        var orig2 = orig.copy()
        self.server = QuicConnection.server(
            self.tls.shared(), scfg, _params(max_data), Span(orig), Span(orig2), now
        )
        # No handshake ran, so grant what the peer's transport parameters would.
        self.client.stream_map.peer_max_streams_uni = UInt64(100)
        self.server.stream_map.peer_max_streams_uni = UInt64(100)


def _code(conn: QuicConnection) -> Int:
    if conn.close.pending:
        return Int(conn.close.pending.value().error_code)
    return -1


def _stream(mut conn: QuicConnection, sid: UInt64, offset: UInt64, n: Int, fin: Bool) raises:
    var data = List[Byte](length=n, fill=Byte(0x78))
    conn._handle_stream_frame(StreamFrame(sid, offset, List[Byte](), fin), Span(data))


def test_stream_on_local_uni() raises:
    var c = Conns()
    var sid = c.server.open_stream(False)
    _stream(c.server, sid, 0, 4, False)
    assert_equal_int(_code(c.server), 0x05, "STREAM on our own uni stream")
    print("  test_stream_on_local_uni: PASS")


def test_reset_on_client_local_uni() raises:
    var c = Conns()
    var sid = c.client.open_stream(False)  # 2: client-uni, send-only for the client
    c.client._handle_reset_stream(ResetStreamFrame(sid, 0, 0))
    assert_equal_int(_code(c.client), 0x05, "RESET_STREAM on a send-only stream")
    print("  test_reset_on_client_local_uni: PASS")


def test_reset_on_server_uni_accepted_by_client() raises:
    var c = Conns()
    c.client._handle_reset_stream(ResetStreamFrame(UInt64(3), 7, 0))
    assert_equal_int(_code(c.client), -1, "a client receives on server-uni streams")
    print("  test_reset_on_server_uni_accepted_by_client: PASS")


def test_stop_sending_on_peer_uni() raises:
    var c = Conns()
    c.server._handle_stop_sending(StopSendingFrame(UInt64(2), 0))
    assert_equal_int(_code(c.server), 0x05, "STOP_SENDING on a receive-only stream")
    var d = Conns()
    var sid = d.client.open_stream(False)
    d.client._handle_stop_sending(StopSendingFrame(sid, 0))
    assert_equal_int(_code(d.client), -1, "STOP_SENDING on the client's own uni stream is fine")
    print("  test_stop_sending_on_peer_uni: PASS")


def test_max_stream_data_on_freed_peer_uni() raises:
    var c = Conns()
    _stream(c.server, 2, 0, 3, True)
    _ = c.server.recv_stream_data(UInt64(2))
    assert_true(not c.server.stream_map.has_stream(2), "peer uni stream freed after it was read")
    c.server._on_max_stream_data_from_cursor(UInt64(2), UInt64(1_000_000), UInt64(1))
    assert_equal_int(_code(c.server), 0x05, "MAX_STREAM_DATA on a freed receive-only stream")
    print("  test_max_stream_data_on_freed_peer_uni: PASS")


def test_final_size_errors() raises:
    var c = Conns()
    _stream(c.server, 0, 0, 10, True)
    _stream(c.server, 0, 8, 5, False)
    assert_equal_int(_code(c.server), 0x06, "data past the final size")
    var d = Conns()
    _stream(d.server, 0, 0, 10, False)
    _stream(d.server, 0, 0, 4, True)
    assert_equal_int(_code(d.server), 0x06, "final size below data received")
    print("  test_final_size_errors: PASS")


def test_connection_flow_control() raises:
    var c = Conns(max_data=100)
    _stream(c.server, 0, 0, 60, False)
    _stream(c.server, 4, 0, 60, False)
    assert_equal_int(_code(c.server), 0x03, "connection flow control exceeded")
    print("  test_connection_flow_control: PASS")


def test_stream_limit() raises:
    var c = Conns()
    _stream(c.server, UInt64(4 * 100), 0, 1, False)
    assert_equal_int(_code(c.server), 0x04, "stream id above MAX_STREAMS")
    print("  test_stream_limit: PASS")


def main() raises:
    print("test_quic_stream_direction:")
    var failed = 0
    try:
        test_stream_on_local_uni()
    except e:
        failed += 1
        print("  test_stream_on_local_uni: FAIL", e)
    try:
        test_reset_on_client_local_uni()
    except e:
        failed += 1
        print("  test_reset_on_client_local_uni: FAIL", e)
    try:
        test_reset_on_server_uni_accepted_by_client()
    except e:
        failed += 1
        print("  test_reset_on_server_uni_accepted_by_client: FAIL", e)
    try:
        test_stop_sending_on_peer_uni()
    except e:
        failed += 1
        print("  test_stop_sending_on_peer_uni: FAIL", e)
    try:
        test_max_stream_data_on_freed_peer_uni()
    except e:
        failed += 1
        print("  test_max_stream_data_on_freed_peer_uni: FAIL", e)
    try:
        test_final_size_errors()
    except e:
        failed += 1
        print("  test_final_size_errors: FAIL", e)
    try:
        test_connection_flow_control()
    except e:
        failed += 1
        print("  test_connection_flow_control: FAIL", e)
    try:
        test_stream_limit()
    except e:
        failed += 1
        print("  test_stream_limit: FAIL", e)
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
    print("All test_quic_stream_direction tests passed.")
