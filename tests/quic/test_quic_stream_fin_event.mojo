"""A STREAM frame carrying only FIN still tells the application the stream ended.

The readable event used to depend on new bytes being readable, so a bare
FIN after the data had been read raised nothing and an HTTP/3 request
whose body ended that way never completed.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.event import QuicEvent
from navette.quic.frame import StreamFrame
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.h3.connection import H3Connection, H3Event
from navette.h3.frame import HeadersFrame
from navette.h3.qpack import QpackEncoder, QpackHeaderField
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def _params() -> TransportParams:
    var p = default_transport_params()
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _server(tls: TlsBackend) raises -> QuicConnection:
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var ca = load_test_ca()
    var scfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), ccfg, "localhost", _params(), now)
    var orig = List[Byte](client.initial_dcid.as_span())
    var orig2 = orig.copy()
    return QuicConnection.server(tls.shared(), scfg, _params(), Span(orig), Span(orig2), now)


def _readable_events(mut conn: QuicConnection, sid: UInt64) -> Int:
    var n = 0
    while True:
        var ev = conn.poll()
        if not ev:
            return n
        if ev.value().type_id == QuicEvent.STREAM_READABLE and ev.value().payload[UInt64] == sid:
            n += 1


def test_bare_fin_raises_readable() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var server = _server(tls)
    var sid = UInt64(0)
    var abc = List[Byte](length=3, fill=Byte(0x61))
    server._handle_stream_frame(StreamFrame(sid, UInt64(0), List[Byte](), False), Span(abc))
    assert_equal_int(_readable_events(server, sid), 1, "data is readable")
    var got = server.recv_stream_data(sid)
    assert_equal_int(len(got[0]), 3, "three bytes read")
    assert_true(not got[1], "no FIN yet")
    var empty = List[Byte]()
    server._handle_stream_frame(StreamFrame(sid, UInt64(3), List[Byte](), True), Span(empty))
    assert_equal_int(_readable_events(server, sid), 1, "a bare FIN is an event")
    var end = server.recv_stream_data(sid)
    assert_true(end[1], "reading reports the end")
    server._handle_stream_frame(StreamFrame(sid, UInt64(3), List[Byte](), True), Span(empty))
    assert_equal_int(_readable_events(server, sid), 0, "a repeated FIN is not")
    _ = tls^
    print("  test_bare_fin_raises_readable: PASS")


def test_h3_request_ends_on_bare_fin() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var h3 = H3Connection.server(_server(tls))
    var sid = UInt64(0)
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":method", "POST"))
    fields.append(QpackHeaderField(":path", "/"))
    fields.append(QpackHeaderField(":scheme", "https"))
    fields.append(QpackHeaderField(":authority", "localhost"))
    var enc = QpackEncoder(False)
    var block = List[Byte]()
    enc.encode(block, fields)
    var wire = List[Byte]()
    HeadersFrame(block^).encode(wire)
    var now = UInt64(1_000_000)
    h3._quic._handle_stream_frame(StreamFrame(sid, UInt64(0), List[Byte](), False), Span(wire))
    h3._poll_quic_events(now)
    var saw_headers = False
    var ended = False
    while True:
        var ev = h3.poll_event()
        if not ev:
            break
        if ev.value().kind == H3Event.HEADERS_RECEIVED:
            saw_headers = True
            ended = ended or ev.value().fin
    assert_true(saw_headers and not ended, "headers, request still open")
    var empty = List[Byte]()
    h3._quic._handle_stream_frame(StreamFrame(sid, UInt64(len(wire)), List[Byte](), True), Span(empty))
    h3._poll_quic_events(now)
    while True:
        var ev = h3.poll_event()
        if not ev:
            break
        if ev.value().kind == H3Event.STREAM_ENDED or ev.value().fin:
            ended = True
    assert_true(ended, "the bare FIN ends the request")
    _ = tls^
    print("  test_h3_request_ends_on_bare_fin: PASS")


def main() raises:
    print("test_quic_stream_fin_event:")
    test_bare_fin_raises_readable()
    test_h3_request_ends_on_bare_fin()
    print("All test_quic_stream_fin_event tests passed.")
