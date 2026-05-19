# conformance/tests/test_h2_send_window_exhaustion.mojo
#
# Reproduces the H2 connection-level send-window exhaustion bug at the codec
# level. Pre-fix: `H2Connection.send_data()` raises when the sender's payload
# exceeds the remaining connection (or stream) window. Post-fix: the codec
# emits as much as fits, queues the remainder, and drains it on WINDOW_UPDATE.
#
# Diagnosis: plans/2026-04-25-h2-flow-control-window-bug.md

from std.memory import Span

from lib.http2.connection import (
    H2Connection,
)
from lib.http1.types import Header
from navette.http.headers import Headers
from navette.http.request import Request
from navette.http.method import Method
from navette.http.version import Version
from navette.h2.h2_session import H2Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_payload(size: Int, byte_val: Int) -> List[UInt8]:
    var data = List[UInt8]()
    for _ in range(size):
        data.append(UInt8(byte_val & 0xFF))
    return data^


def _count_data_bytes(buf: List[UInt8]) -> Int:
    """Sum payload lengths of all DATA frames in a wire-format buffer."""
    var total = 0
    var i = 0
    while i + 9 <= len(buf):
        var length = (Int(buf[i]) << 16) | (Int(buf[i + 1]) << 8) | Int(buf[i + 2])
        var ftype = Int(buf[i + 3])
        if ftype == 0:  # FRAME_DATA
            total += length
        i += 9 + length
    return total


def _count_end_stream_data_frames(buf: List[UInt8]) -> Int:
    """Count DATA frames whose END_STREAM flag is set."""
    var count = 0
    var i = 0
    while i + 9 <= len(buf):
        var length = (Int(buf[i]) << 16) | (Int(buf[i + 1]) << 8) | Int(buf[i + 2])
        var ftype = Int(buf[i + 3])
        var flags = Int(buf[i + 4])
        if ftype == 0 and (flags & 0x01) != 0:
            count += 1
        i += 9 + length
    return count


def _wire_window_update(stream_id: UInt32, increment: UInt32) -> List[UInt8]:
    """Hand-build a wire-format WINDOW_UPDATE frame."""
    var b = List[UInt8]()
    # Length = 4
    b.append(UInt8(0))
    b.append(UInt8(0))
    b.append(UInt8(4))
    # Type = 0x08 (WINDOW_UPDATE), Flags = 0
    b.append(UInt8(0x08))
    b.append(UInt8(0))
    # Stream ID (R bit = 0)
    var sid = Int(stream_id)
    b.append(UInt8((sid >> 24) & 0x7F))
    b.append(UInt8((sid >> 16) & 0xFF))
    b.append(UInt8((sid >> 8) & 0xFF))
    b.append(UInt8(sid & 0xFF))
    # Increment payload (R bit = 0)
    var inc = Int(increment)
    b.append(UInt8((inc >> 24) & 0x7F))
    b.append(UInt8((inc >> 16) & 0xFF))
    b.append(UInt8((inc >> 8) & 0xFF))
    b.append(UInt8(inc & 0xFF))
    return b^


def _do_preface_exchange(
    mut session: H2Session, mut server: H2Connection
) raises:
    """Standard HTTP/2 preface dance between H2Session and a raw H2Connection."""
    var client_preface = session.drain()
    _ = server.receive_data(client_preface)
    var server_resp = server.data_to_send()
    session.feed(Span(server_resp))
    var client_ack = session.drain()
    if len(client_ack) > 0:
        _ = server.receive_data(client_ack)
        _ = server.data_to_send()


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------


def test_send_data_queues_when_window_exhausted() raises:
    """Open 10 streams, push 8000 bytes on each. The default 65535-byte
    connection-level send window admits 8 full responses + a 1535-byte
    fragment of the 9th. The remainder must be queued and only released
    after WINDOW_UPDATE."""
    var session = H2Session()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()  # drain server SETTINGS
    _do_preface_exchange(session, server)

    # Submit 10 GETs → client-initiated stream IDs 1, 3, 5, ..., 19
    var stream_ids = List[Int]()
    for i in range(10):
        var hdrs = Headers()
        hdrs.add("host", "localhost")
        var req = Request(
            method=Method.get(),
            target=String("/") + String(i),
            version=Version.http_2(),
            headers=hdrs^,
        )
        var handle = session.submit(req^)
        stream_ids.append(2 * i + 1)
        _ = handle^

    var req_data = session.drain()
    _ = server.receive_data(req_data)
    _ = server.data_to_send()  # drain anything the server queued in response

    # Send response headers + 8000 bytes of body on every stream.
    # Pre-fix: this raises on iteration 8 (the 8th call exhausts the
    # connection window).
    var BODY_SIZE = 8000
    for i in range(10):
        var rh = List[Header]()
        rh.append(Header(":status", "200"))
        rh.append(Header("content-type", "application/octet-stream"))
        server.send_headers(UInt32(stream_ids[i]), rh^, end_stream=False)
        var body = _make_payload(BODY_SIZE, i + 1)
        server.send_data(UInt32(stream_ids[i]), body, end_stream=True)

    var first_drain = server.data_to_send()
    var first_data_bytes = _count_data_bytes(first_drain)
    var first_end_streams = _count_end_stream_data_frames(first_drain)
    if first_data_bytes != 65535:
        raise Error(
            "expected 65535 DATA bytes in first drain, got "
            + String(first_data_bytes)
        )
    # 8 full streams ended; the 9th got only a partial fragment so its
    # END_STREAM must NOT have been set yet.
    if first_end_streams != 8:
        raise Error(
            "expected 8 END_STREAM DATA frames in first drain, got "
            + String(first_end_streams)
        )

    # Synthesize a connection-level WINDOW_UPDATE giving 20000 more bytes.
    var wu = _wire_window_update(UInt32(0), UInt32(20000))
    _ = server.receive_data(wu)

    var second_drain = server.data_to_send()
    var second_data_bytes = _count_data_bytes(second_drain)
    var second_end_streams = _count_end_stream_data_frames(second_drain)
    var total_data = first_data_bytes + second_data_bytes
    if total_data != 80000:
        raise Error(
            "expected 80000 total DATA bytes after WINDOW_UPDATE, got "
            + String(total_data)
        )
    if second_end_streams != 2:
        raise Error(
            "expected 2 END_STREAM DATA frames in second drain "
            "(streams 9 and 10), got "
            + String(second_end_streams)
        )
    print("PASS test_send_data_queues_when_window_exhausted")


def main() raises:
    print("test_h2_send_window_exhaustion")
    test_send_data_queues_when_window_exhausted()
    print("PASS")
