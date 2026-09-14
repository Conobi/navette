# tests/http/test_event_variant_roundtrip.mojo
#
# Verify Variant-based event construction -> accessor round-trips.

from navette.h2.connection import (
    H2Event,
    H2_EVT_SETTINGS_ACKNOWLEDGED,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_PING_RECEIVED,
    H2_EVT_GOAWAY_RECEIVED,
    H2_EVT_STREAM_RESET,
    H2_EVT_WINDOW_UPDATED,
    H2_EVT_CONNECTION_TERMINATED,
    H2HeadersPayload,
)
from navette.h2.header import Header
from navette.h3.connection import H3Event, H3HeadersPayload
from navette.h3.qpack import QpackHeaderField
from navette.http.body import BodyFrame
from navette.http.handler import StreamError
from navette.http.headers import Headers
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_h2event_settings_roundtrip() raises:
    """Settings acknowledged produces NoneType payload."""
    var e = H2Event.settings_acknowledged()
    assert_equal_int(e.kind, H2_EVT_SETTINGS_ACKNOWLEDGED, "settings kind")
    assert_true(e.payload.isa[NoneType](), "settings payload is NoneType")


def test_h2event_request_roundtrip() raises:
    """Request received round-trips stream_id and stream_ended."""
    var hdrs = List[Header]()
    var e = H2Event.request_received(UInt32(5), hdrs, True)
    assert_equal_int(e.kind, H2_EVT_REQUEST_RECEIVED, "request kind")
    assert_true(e.payload.isa[H2HeadersPayload](), "request payload is H2HeadersPayload")
    assert_equal_int(Int(e.as_headers().stream_id), 5, "stream_id round-trip")
    assert_true(e.as_headers().stream_ended, "stream_ended round-trip")


def test_h2event_copy_independence() raises:
    """Copy produces an independent H2Event."""
    var hdrs = List[Header]()
    var e1 = H2Event.request_received(UInt32(1), hdrs, False)
    var e2 = H2Event(other=e1)
    assert_equal_int(Int(e2.as_headers().stream_id), 1, "copy stream_id")
    assert_false(e2.as_headers().stream_ended, "copy stream_ended")


def test_h3event_headers_roundtrip() raises:
    """Headers received round-trips stream_id."""
    var fields = List[QpackHeaderField]()
    var e = H3Event.headers_received(UInt64(7), fields^)
    assert_equal_int(Int(e.kind), Int(H3Event.HEADERS_RECEIVED), "headers kind")
    assert_true(e.payload.isa[H3HeadersPayload](), "headers payload is H3HeadersPayload")
    assert_equal_int(Int(e.as_headers().stream_id), 7, "stream_id round-trip")


def test_h3event_datagram_roundtrip() raises:
    """Datagram received round-trips stream_id and data."""
    var data = List[UInt8]()
    data.append(UInt8(0x42))
    var e = H3Event.datagram_received(UInt64(12), data^)
    assert_equal_int(Int(e.kind), Int(H3Event.DATAGRAM_RECEIVED), "datagram kind")
    assert_equal_int(Int(e.as_stream_data().stream_id), 12, "datagram stream_id")
    assert_equal_int(len(e.as_stream_data().data), 1, "datagram data length")


def test_bodyframe_predicate_exclusivity() raises:
    """Each BodyFrame variant satisfies exactly one predicate."""
    var d = BodyFrame.data(List[UInt8]())
    assert_true(d.is_data(), "data.is_data")
    assert_false(d.is_trailers(), "data.not_trailers")
    assert_false(d.is_end(), "data.not_end")
    assert_false(d.is_error(), "data.not_error")

    var t = BodyFrame.trailers(Headers())
    assert_true(t.is_trailers(), "trailers.is_trailers")
    assert_false(t.is_data(), "trailers.not_data")

    var end = BodyFrame.end()
    assert_true(end.is_end(), "end.is_end")
    assert_false(end.is_data(), "end.not_data")

    var err = BodyFrame.error(StreamError.parser(String("x")))
    assert_true(err.is_error(), "error.is_error")
    assert_false(err.is_end(), "error.not_end")


def main() raises:
    test_h2event_settings_roundtrip()
    test_h2event_request_roundtrip()
    test_h2event_copy_independence()
    test_h3event_headers_roundtrip()
    test_h3event_datagram_roundtrip()
    test_bodyframe_predicate_exclusivity()
    print("test_event_variant_roundtrip: all tests passed")
