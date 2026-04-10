# conformance/tests/test_h2_stream.mojo
#
# HC-4b: HTTP/2 stream data path tests.
from lib.test_util import assert_true, assert_equal, hex_decode, hex_encode
from lib.http2.connection import (
    H2Config,
    H2Settings,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_TRAILERS_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
    H2_EVT_SETTINGS_ACKNOWLEDGED,
    H2_EVT_SETTINGS_CHANGED,
    H2_EVT_PING_RECEIVED,
    H2_EVT_PING_ACKNOWLEDGED,
    H2_EVT_GOAWAY_RECEIVED,
    H2_EVT_WINDOW_UPDATED,
    H2_EVT_CONNECTION_TERMINATED,
    StreamState,
    STREAM_IDLE, STREAM_OPEN, STREAM_HALF_CLOSED_LOCAL,
    STREAM_HALF_CLOSED_REMOTE, STREAM_CLOSED,
    CONN_IDLE, CONN_OPEN, CONN_GOAWAY, CONN_CLOSED,
    H2Connection,
    _append_setting,
    SETTINGS_INITIAL_WINDOW_SIZE,
)
from lib.http2.frame import (
    Frame,
    encode_frame,
    decode_frame,
    H2_NO_ERROR,
    H2_PROTOCOL_ERROR,
    H2_FLOW_CONTROL_ERROR,
    H2_COMPRESSION_ERROR,
    H2_STREAM_CLOSED,
    H2_CANCEL,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    FRAME_CONTINUATION,
    FRAME_WINDOW_UPDATE,
    FLAG_END_STREAM,
    FLAG_ACK,
    FLAG_END_HEADERS,
)
from lib.http2.hpack import HpackEncoder, HpackDecoder, HpackConfig
from lib.http1.types import Header


def test_stream_state_new_fields() raises:
    """StreamState has headers_end_stream and data_received fields."""
    var s = StreamState()
    assert_true(not s.headers_end_stream, "default headers_end_stream")
    assert_true(not s.data_received, "default data_received")
    # Copy preserves new fields
    var s2 = StreamState(other=s)
    assert_true(not s2.headers_end_stream, "copy headers_end_stream")
    assert_true(not s2.data_received, "copy data_received")
    # Move preserves new fields
    var s3 = StreamState(take=s2^)
    assert_true(not s3.headers_end_stream, "move headers_end_stream")
    assert_true(not s3.data_received, "move data_received")


def main() raises:
    test_stream_state_new_fields()
    print("All tests passed.")
