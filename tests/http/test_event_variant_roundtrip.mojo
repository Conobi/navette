# tests/http/test_event_variant_roundtrip.mojo
#
# Verify Variant-based event construction -> accessor round-trips.

from navette.h2.connection import (
    H2Event,
    H2_EVT_SETTINGS_ACKNOWLEDGED,
    H2_EVT_SETTINGS_CHANGED,
    H2_EVT_PING_RECEIVED,
    H2_EVT_PING_ACKNOWLEDGED,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_TRAILERS_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
    H2_EVT_GOAWAY_RECEIVED,
    H2_EVT_WINDOW_UPDATED,
    H2_EVT_CONNECTION_TERMINATED,
    H2HeadersPayload,
    H2DataPayload,
    H2StreamResetPayload,
    H2GoawayPayload,
    H2WindowPayload,
    H2TerminationPayload,
)
from navette.h2.header import Header
from navette.h3.connection import (
    H3Event,
    H3HeadersPayload,
    H3StreamDataPayload,
    H3StreamEndPayload,
    H3StreamResetPayload,
    H3ConnectionClosedPayload,
)
from navette.h3.qpack import QpackHeaderField
from navette.http.body import BodyFrame
from navette.http.handler import StreamError
from navette.http.headers import Headers
from tests._test_util import assert_true, assert_false, assert_equal_int


# ── H2Event round-trips ──────────────────────────────────────────────


def test_h2_settings_acknowledged() raises:
    var e = H2Event.settings_acknowledged()
    assert_equal_int(e.kind, H2_EVT_SETTINGS_ACKNOWLEDGED, "kind")
    assert_true(e.payload.isa[NoneType](), "NoneType payload")


def test_h2_settings_changed() raises:
    var e = H2Event.settings_changed()
    assert_equal_int(e.kind, H2_EVT_SETTINGS_CHANGED, "kind")
    assert_true(e.payload.isa[NoneType](), "NoneType payload")


def test_h2_ping_received() raises:
    var data = List[UInt8]()
    data.append(UInt8(1))
    data.append(UInt8(2))
    var e = H2Event.ping_received(data)
    assert_equal_int(e.kind, H2_EVT_PING_RECEIVED, "kind")
    assert_true(e.payload.isa[List[UInt8]](), "List[UInt8] payload")
    assert_equal_int(len(e.as_ping_data()), 2, "ping data length")


def test_h2_ping_acknowledged() raises:
    var data = List[UInt8]()
    data.append(UInt8(3))
    var e = H2Event.ping_acknowledged(data)
    assert_equal_int(e.kind, H2_EVT_PING_ACKNOWLEDGED, "kind")
    assert_true(e.payload.isa[List[UInt8]](), "List[UInt8] payload")
    assert_equal_int(len(e.as_ping_data()), 1, "ping ack data length")


def test_h2_request_received() raises:
    var hdrs = List[Header]()
    var e = H2Event.request_received(UInt32(5), hdrs, True)
    assert_equal_int(e.kind, H2_EVT_REQUEST_RECEIVED, "kind")
    assert_true(e.payload.isa[H2HeadersPayload](), "H2HeadersPayload")
    assert_equal_int(Int(e.as_headers().stream_id), 5, "stream_id")
    assert_true(e.as_headers().stream_ended, "stream_ended")


def test_h2_response_received() raises:
    var hdrs = List[Header]()
    var e = H2Event.response_received(UInt32(3), hdrs, False)
    assert_equal_int(e.kind, H2_EVT_RESPONSE_RECEIVED, "kind")
    assert_true(e.payload.isa[H2HeadersPayload](), "H2HeadersPayload")
    assert_equal_int(Int(e.as_headers().stream_id), 3, "stream_id")
    assert_false(e.as_headers().stream_ended, "stream_ended")


def test_h2_data_received() raises:
    var data = List[UInt8]()
    data.append(UInt8(0xAB))
    var e = H2Event.data_received(UInt32(7), data, 100, True)
    assert_equal_int(e.kind, H2_EVT_DATA_RECEIVED, "kind")
    assert_true(e.payload.isa[H2DataPayload](), "H2DataPayload")
    assert_equal_int(Int(e.as_data().stream_id), 7, "stream_id")
    assert_equal_int(len(e.as_data().data), 1, "data length")
    assert_equal_int(e.as_data().flow_controlled_length, 100, "fcl")
    assert_true(e.as_data().stream_ended, "stream_ended")


def test_h2_trailers_received() raises:
    var hdrs = List[Header]()
    var e = H2Event.trailers_received(UInt32(9), hdrs)
    assert_equal_int(e.kind, H2_EVT_TRAILERS_RECEIVED, "kind")
    assert_true(e.payload.isa[H2HeadersPayload](), "H2HeadersPayload")
    assert_equal_int(Int(e.as_headers().stream_id), 9, "stream_id")
    assert_true(e.as_headers().stream_ended, "trailers always stream_ended")


def test_h2_stream_ended() raises:
    var e = H2Event.make_stream_ended(UInt32(11))
    assert_equal_int(e.kind, H2_EVT_STREAM_ENDED, "kind")
    assert_true(e.payload.isa[UInt32](), "UInt32 payload")
    assert_equal_int(Int(e.as_stream_id()), 11, "stream_id")


def test_h2_stream_reset() raises:
    var e = H2Event.stream_reset(UInt32(13), UInt32(0x08))
    assert_equal_int(e.kind, H2_EVT_STREAM_RESET, "kind")
    assert_true(e.payload.isa[H2StreamResetPayload](), "H2StreamResetPayload")
    assert_equal_int(Int(e.as_stream_reset().stream_id), 13, "stream_id")
    assert_equal_int(Int(e.as_stream_reset().error_code), 8, "error_code")


def test_h2_goaway_received() raises:
    var debug = List[UInt8]()
    debug.append(UInt8(0xFF))
    var e = H2Event.goaway_received(UInt32(100), UInt32(2), debug)
    assert_equal_int(e.kind, H2_EVT_GOAWAY_RECEIVED, "kind")
    assert_true(e.payload.isa[H2GoawayPayload](), "H2GoawayPayload")
    assert_equal_int(Int(e.as_goaway().last_stream_id), 100, "last_stream_id")
    assert_equal_int(Int(e.as_goaway().error_code), 2, "error_code")
    assert_equal_int(len(e.as_goaway().data), 1, "debug data length")


def test_h2_window_updated() raises:
    var e = H2Event.window_updated(UInt32(15), UInt32(65535))
    assert_equal_int(e.kind, H2_EVT_WINDOW_UPDATED, "kind")
    assert_true(e.payload.isa[H2WindowPayload](), "H2WindowPayload")
    assert_equal_int(Int(e.as_window().stream_id), 15, "stream_id")
    assert_equal_int(Int(e.as_window().window_increment), 65535, "increment")


def test_h2_connection_terminated() raises:
    var e = H2Event.connection_terminated(UInt32(0), UInt32(1), String("bye"))
    assert_equal_int(e.kind, H2_EVT_CONNECTION_TERMINATED, "kind")
    assert_true(e.payload.isa[H2TerminationPayload](), "H2TerminationPayload")
    assert_equal_int(Int(e.as_termination().last_stream_id), 0, "last_stream_id")
    assert_equal_int(Int(e.as_termination().error_code), 1, "error_code")


def test_h2_copy_independence() raises:
    var hdrs = List[Header]()
    var e1 = H2Event.request_received(UInt32(1), hdrs, False)
    var e2 = H2Event(other=e1)
    assert_equal_int(Int(e2.as_headers().stream_id), 1, "copy stream_id")
    assert_false(e2.as_headers().stream_ended, "copy stream_ended")


# ── H3Event round-trips ──────────────────────────────────────────────


def test_h3_handshake_complete() raises:
    var e = H3Event.handshake_complete()
    assert_equal_int(Int(e.kind), Int(H3Event.HANDSHAKE_COMPLETE), "kind")
    assert_true(e.payload.isa[NoneType](), "NoneType payload")


def test_h3_settings_received() raises:
    var e = H3Event.settings_received()
    assert_equal_int(Int(e.kind), Int(H3Event.SETTINGS_RECEIVED), "kind")
    assert_true(e.payload.isa[NoneType](), "NoneType payload")


def test_h3_headers_received() raises:
    var fields = List[QpackHeaderField]()
    var e = H3Event.headers_received(UInt64(7), fields^)
    assert_equal_int(Int(e.kind), Int(H3Event.HEADERS_RECEIVED), "kind")
    assert_true(e.payload.isa[H3HeadersPayload](), "H3HeadersPayload")
    assert_equal_int(Int(e.as_headers().stream_id), 7, "stream_id")


def test_h3_data_received() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x42))
    data.append(UInt8(0x43))
    var e = H3Event.data_received(UInt64(10), data^)
    assert_equal_int(Int(e.kind), Int(H3Event.DATA_RECEIVED), "kind")
    assert_true(e.payload.isa[H3StreamDataPayload](), "H3StreamDataPayload")
    assert_equal_int(Int(e.as_stream_data().stream_id), 10, "stream_id")
    assert_equal_int(len(e.as_stream_data().data), 2, "data length")


def test_h3_stream_ended() raises:
    var e = H3Event.stream_ended(UInt64(14))
    assert_equal_int(Int(e.kind), Int(H3Event.STREAM_ENDED), "kind")
    assert_true(e.payload.isa[H3StreamEndPayload](), "H3StreamEndPayload")
    assert_equal_int(Int(e.as_stream_end().stream_id), 14, "stream_id")


def test_h3_stream_reset() raises:
    var e = H3Event.stream_reset(UInt64(16), UInt64(0x0100))
    assert_equal_int(Int(e.kind), Int(H3Event.STREAM_RESET), "kind")
    assert_true(e.payload.isa[H3StreamResetPayload](), "H3StreamResetPayload")
    assert_equal_int(Int(e.as_stream_reset().stream_id), 16, "stream_id")
    assert_equal_int(Int(e.as_stream_reset().error_code), 256, "error_code")


def test_h3_goaway_received() raises:
    var e = H3Event.goaway_received(UInt64(20))
    assert_equal_int(Int(e.kind), Int(H3Event.GOAWAY_RECEIVED), "kind")
    assert_true(e.payload.isa[UInt64](), "UInt64 payload")
    assert_equal_int(Int(e.as_goaway_stream_id()), 20, "last_stream_id")


def test_h3_connection_closed() raises:
    var e = H3Event.connection_closed(UInt64(0x0A), String("proto err"))
    assert_equal_int(Int(e.kind), Int(H3Event.CONNECTION_CLOSED), "kind")
    assert_true(e.payload.isa[H3ConnectionClosedPayload](), "H3ConnectionClosedPayload")
    assert_equal_int(Int(e.as_connection_closed().error_code), 10, "error_code")


def test_h3_datagram_received() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x42))
    var e = H3Event.datagram_received(UInt64(12), data^)
    assert_equal_int(Int(e.kind), Int(H3Event.DATAGRAM_RECEIVED), "kind")
    assert_true(e.payload.isa[H3StreamDataPayload](), "H3StreamDataPayload")
    assert_equal_int(Int(e.as_stream_data().stream_id), 12, "stream_id")
    assert_equal_int(len(e.as_stream_data().data), 1, "data length")


# ── BodyFrame round-trips ────────────────────────────────────────────


def test_bodyframe_predicate_exclusivity() raises:
    var d = BodyFrame.data(List[UInt8]())
    assert_true(d.is_data(), "data.is_data")
    assert_false(d.is_trailers(), "data.not_trailers")
    assert_false(d.is_end(), "data.not_end")
    assert_false(d.is_error(), "data.not_error")

    var t = BodyFrame.trailers(Headers())
    assert_true(t.is_trailers(), "trailers.is_trailers")
    assert_false(t.is_data(), "trailers.not_data")
    assert_false(t.is_end(), "trailers.not_end")
    assert_false(t.is_error(), "trailers.not_error")

    var end = BodyFrame.end()
    assert_true(end.is_end(), "end.is_end")
    assert_false(end.is_data(), "end.not_data")
    assert_false(end.is_trailers(), "end.not_trailers")
    assert_false(end.is_error(), "end.not_error")

    var err = BodyFrame.error(StreamError.parser(String("x")))
    assert_true(err.is_error(), "error.is_error")
    assert_false(err.is_data(), "error.not_data")
    assert_false(err.is_trailers(), "error.not_trailers")
    assert_false(err.is_end(), "error.not_end")


# ── Main ─────────────────────────────────────────────────────────────


def main() raises:
    # H2 — all 13 event kinds
    test_h2_settings_acknowledged()
    test_h2_settings_changed()
    test_h2_ping_received()
    test_h2_ping_acknowledged()
    test_h2_request_received()
    test_h2_response_received()
    test_h2_data_received()
    test_h2_trailers_received()
    test_h2_stream_ended()
    test_h2_stream_reset()
    test_h2_goaway_received()
    test_h2_window_updated()
    test_h2_connection_terminated()
    test_h2_copy_independence()
    # H3 — all 9 event kinds
    test_h3_handshake_complete()
    test_h3_settings_received()
    test_h3_headers_received()
    test_h3_data_received()
    test_h3_stream_ended()
    test_h3_stream_reset()
    test_h3_goaway_received()
    test_h3_connection_closed()
    test_h3_datagram_received()
    # BodyFrame — all 4 variants
    test_bodyframe_predicate_exclusivity()
    print("test_event_variant_roundtrip: all 24 tests passed")
