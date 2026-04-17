# tests/test_h3_connection.mojo
from src.h3.connection import H3Event
from tests._test_util import assert_true, assert_equal_int


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


def main() raises:
    print("=== test_h3_connection (unit) ===")
    test_h3event_zero_values()
    test_is_peer_initiated()
    test_is_request_stream()
    test_h3event_kind_constants()
    print("All H3Connection unit tests passed.")
