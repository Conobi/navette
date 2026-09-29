# tests/h3/test_h3_stream_buffer_bounds.mojo
#
# Per-stream buffering bounds on H3Connection. A raw QUIC client (no H3
# layer of its own) writes crafted stream bytes to an H3 server so each
# case controls exactly what the server sees. QUIC returns flow-control
# credit as soon as H3 drains a stream, so any H3 buffering by declared
# frame length is unbounded unless H3 caps it.

from std.collections import Span
from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.event import QuicEvent, ConnectionClosedPayload
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.quic.codec import ByteReader
from navette.h3.connection import H3Connection, H3Event, H3_MAX_FIELD_SECTION_SIZE
from navette.h3.frame import SettingsFrame, SETTINGS_MAX_FIELD_SECTION_SIZE, parse_h3_frame
from navette.h3.error import H3_EXCESSIVE_LOAD, H3_FRAME_ERROR
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca

# Payload bytes actually sent after a header declaring a far larger frame.
comptime _BODY = 20_000
comptime _HUGE_LEN: UInt64 = UInt64(1) << 30
# Anything the server keeps for a stream beyond this is buffering by
# declared length rather than one bounded frame header.
comptime _SMALL = 64


def _varint(mut out: List[Byte], v: UInt64):
    var n = 8
    var tag = UInt64(0xC0)
    if v < 64:
        n = 1
        tag = 0x00
    elif v < 16384:
        n = 2
        tag = 0x40
    elif v < UInt64(1) << 30:
        n = 4
        tag = 0x80
    for i in range(n):
        var byte = (v >> UInt64(8 * (n - 1 - i))) & 0xFF
        if i == 0:
            byte |= tag
        out.append(UInt8(byte))


def _params() -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_stream_data_uni = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


struct _Pair(Movable):
    """H3 server + raw QUIC client, plus what the harness observed."""

    var srv: H3Connection
    var cli: QuicConnection
    var now: UInt64
    var close_code: Int  # app error code the client saw, -1 if none
    var data_bytes: Int  # DATA_RECEIVED payload bytes seen on the server
    var headers_events: Int

    def __init__(out self) raises:
        var tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert = ck[0].copy()
        var key = ck[1].copy()
        var ca = load_test_ca()
        var srv_cfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
        var cli_cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
        self.now = UInt64(1_000_000)
        var cli = QuicConnection.client(tls.shared(), cli_cfg, "localhost", _params(), self.now)
        var odcid = List[Byte](cli.initial_dcid.as_span())
        var cdcid = List[Byte](cli.initial_dcid.as_span())
        var sq = QuicConnection.server(
            tls.shared(), srv_cfg, _params(), Span(odcid), Span(cdcid), self.now,
        )
        self.srv = H3Connection.server(sq^)
        self.cli = cli^
        self.close_code = -1
        self.data_bytes = 0
        self.headers_events = 0
        _ = tls^
        self.pump(20)
        assert_true(self.cli.is_established(), "handshake completes")

    def pump(mut self, rounds: Int) raises:
        var scratch = List[List[Byte]](capacity=1)
        for _ in range(rounds):
            self.now += UInt64(10_000)
            for _ in range(64):
                var n = self.cli.send(self.now, scratch)
                if n == 0:
                    break
                for i in range(n):
                    try:
                        self.srv.feed_datagram(Span(scratch[i]), self.now)
                    except:
                        pass
            var dgs = self.srv.drain_datagrams(self.now)
            for i in range(len(dgs)):
                try:
                    self.cli.recv(Span(dgs[i]), self.now)
                except:
                    pass
            while True:
                var ev = self.cli.poll()
                if not ev:
                    break
                if ev.value().type_id == QuicEvent.CONNECTION_CLOSED:
                    self.close_code = Int(
                        ev.value().payload.unsafe_get[ConnectionClosedPayload]().error_code
                    )
            while True:
                var hev = self.srv.poll_event()
                if not hev:
                    break
                if hev.value().kind == H3Event.DATA_RECEIVED:
                    self.data_bytes += len(hev.value().data)
                elif hev.value().kind == H3Event.HEADERS_RECEIVED:
                    self.headers_events += 1

    def buffered(self, sid: UInt64) -> Int:
        var e = self.srv._stream_bufs.find(Int(sid))
        if not e:
            return 0
        return len(e.value().buf)

    def send(mut self, sid: UInt64, bytes: List[Byte]) raises:
        self.cli.send_stream_data(sid, Span(bytes), False)
        self.pump(30)


def _headers_get() -> List[Byte]:
    """HEADERS frame: empty QPACK prefix + indexed static 17 (:method GET)."""
    var f: List[Byte] = [0x01, 0x03, 0x00, 0x00, 0xD1]
    return f^


def _filler(mut out: List[Byte], n: Int):
    for _ in range(n):
        out.append(0xAB)


def test_huge_headers_declared_length() raises:
    var p = _Pair()
    var sid = p.cli.open_stream(True)
    var b: List[Byte] = [0x01]
    _varint(b, _HUGE_LEN)
    _filler(b, _BODY)
    p.send(sid, b)
    assert_true(p.buffered(sid) <= _SMALL, "HEADERS not buffered by declared length: " + String(p.buffered(sid)))
    assert_equal_int(p.close_code, Int(H3_EXCESSIVE_LOAD), "oversized HEADERS closes with H3_EXCESSIVE_LOAD")
    _ = p.srv.is_closed()
    print("  test_huge_headers_declared_length: PASS")


def test_huge_data_is_streamed() raises:
    var p = _Pair()
    var sid = p.cli.open_stream(True)
    var b = _headers_get()
    b.append(0x00)
    _varint(b, _HUGE_LEN)
    _filler(b, _BODY)
    p.send(sid, b)
    assert_true(p.buffered(sid) <= _SMALL, "DATA payload not buffered: " + String(p.buffered(sid)))
    assert_equal_int(p.data_bytes, _BODY, "DATA payload delivered as it arrives")
    assert_equal_int(p.headers_events, 1, "HEADERS still delivered")
    assert_equal_int(p.close_code, -1, "no close for a large DATA frame")
    print("  test_huge_data_is_streamed: PASS")


def test_unknown_frame_payload_skipped() raises:
    var p = _Pair()
    var sid = p.cli.open_stream(True)
    var b = _headers_get()
    b.append(0x21)  # reserved frame type 0x21 (RFC 9114 Section 7.2.8)
    _varint(b, _HUGE_LEN)
    _filler(b, _BODY)
    p.send(sid, b)
    assert_true(p.buffered(sid) <= _SMALL, "unknown frame payload not buffered: " + String(p.buffered(sid)))
    assert_equal_int(p.close_code, -1, "unknown frames are ignored, not fatal")
    print("  test_unknown_frame_payload_skipped: PASS")


def test_unknown_and_qpack_uni_streams_discarded() raises:
    var p = _Pair()
    var unk = p.cli.open_stream(False)
    var b: List[Byte] = [0x21]
    _filler(b, _BODY)
    p.send(unk, b)
    assert_equal_int(p.buffered(unk), 0, "unknown uni stream data discarded")
    var qenc = p.cli.open_stream(False)
    var q: List[Byte] = [0x02]
    _filler(q, _BODY)
    p.send(qenc, q)
    assert_equal_int(p.buffered(qenc), 0, "QPACK encoder stream bytes not buffered")
    assert_equal_int(p.headers_events, 0, "encoder-stream bytes never parsed as H3 frames")
    print("  test_unknown_and_qpack_uni_streams_discarded: PASS")


def test_oversized_settings_rejected() raises:
    var p = _Pair()
    var ctrl = p.cli.open_stream(False)
    var b: List[Byte] = [0x00, 0x04]
    _varint(b, UInt64(_BODY))
    for _ in range(_BODY):
        b.append(0x21)  # repeated reserved setting id 0x21 = 0x21
    p.send(ctrl, b)
    assert_equal_int(p.close_code, Int(H3_FRAME_ERROR), "oversized SETTINGS closes with H3_FRAME_ERROR")
    print("  test_oversized_settings_rejected: PASS")


def test_decoded_field_section_capped() raises:
    # 1,000 one-byte indexed fields (:method GET, 42 bytes each by the
    # RFC 9114 Section 4.2.2 rule) = 42,000 decoded bytes from a 1 KB frame.
    var p = _Pair()
    var sid = p.cli.open_stream(True)
    var payload: List[Byte] = [0x00, 0x00]
    for _ in range(1000):
        payload.append(0xD1)
    var b: List[Byte] = [0x01]
    _varint(b, UInt64(len(payload)))
    b.extend(Span(payload))
    p.send(sid, b)
    assert_equal_int(p.headers_events, 0, "expanded field section not delivered")
    assert_equal_int(p.close_code, Int(H3_EXCESSIVE_LOAD), "expansion closes with H3_EXCESSIVE_LOAD")
    print("  test_decoded_field_section_capped: PASS")


def test_advertised_max_field_section_size() raises:
    var p = _Pair()
    # Server control stream is the first server-initiated uni stream (id 3).
    var got = p.cli.recv_stream_data(UInt64(3))
    var bytes = got[0].copy()
    assert_true(len(bytes) > 1 and bytes[0] == 0x00, "control stream type byte")
    var r = ByteReader(Span(bytes)[1:])
    var f = parse_h3_frame(r)
    var sf = SettingsFrame.decode(f.payload)
    var v = sf.get(SETTINGS_MAX_FIELD_SECTION_SIZE)
    assert_true(Bool(v), "MAX_FIELD_SECTION_SIZE advertised")
    assert_equal_int(Int(v.value()), H3_MAX_FIELD_SECTION_SIZE, "advertised value is the enforced cap")
    print("  test_advertised_max_field_section_size: PASS")


def main() raises:
    print("test_h3_stream_buffer_bounds:")
    test_huge_headers_declared_length()
    test_huge_data_is_streamed()
    test_unknown_frame_payload_skipped()
    test_unknown_and_qpack_uni_streams_discarded()
    test_oversized_settings_rejected()
    test_decoded_field_section_capped()
    test_advertised_max_field_section_size()
    print("All test_h3_stream_buffer_bounds tests passed.")
