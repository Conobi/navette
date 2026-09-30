# tests/h3/test_h3_reset_stream_reaped.mojo
#
# A request the client cancels with RESET_STREAM must release its QUIC
# stream once the server has finished its own send side, and hand the
# stream-count credit back through MAX_STREAMS. Otherwise every
# cancellation leaks a stream and, after initial_max_streams_bidi of
# them, the client can open nothing more.

from std.collections import Span
from tests._test_util import assert_true, assert_equal_int
from tests.h3._h3_raw_pair import RawPair, headers_get

# raw_params grants 100 bidi streams; going past it proves credit returns.
comptime _INITIAL_BIDI = 100


def _server_streams(p: RawPair) -> Int:
    return len(p.srv._quic.stream_map.streams)


def _server_fin(mut p: RawPair, sid: UInt64) raises:
    p.srv.send_data(sid, List[Byte](), True)
    p.pump(4)


def test_reset_requests_are_reaped_and_credit_returns() raises:
    var p = RawPair()
    var baseline = _server_streams(p)
    for _ in range(_INITIAL_BIDI + 10):
        var sid = p.cli.open_stream(True)
        var h = headers_get()
        p.cli.send_stream_data(sid, Span(h), False)
        p.pump(3)
        p.cli.reset_stream(sid, UInt64(0x10C))
        p.pump(3)
        _server_fin(p, sid)
    assert_equal_int(p.close_code, -1, "no protocol error")
    assert_equal_int(_server_streams(p), baseline, "reset streams reaped")
    assert_true(
        p.cli.stream_map.peer_max_streams_bidi > UInt64(_INITIAL_BIDI),
        "MAX_STREAMS credit re-granted",
    )
    print("  test_reset_requests_are_reaped_and_credit_returns: PASS")


def test_mixed_reset_and_fin() raises:
    var p = RawPair()
    var baseline = _server_streams(p)
    for i in range(16):
        var sid = p.cli.open_stream(True)
        var reset = (i % 2) == 0
        var h = headers_get()
        p.cli.send_stream_data(sid, Span(h), not reset)
        p.pump(3)
        if reset:
            p.cli.reset_stream(sid, UInt64(0x10C))
            p.pump(3)
        _server_fin(p, sid)
    assert_equal_int(p.close_code, -1, "no protocol error")
    assert_equal_int(_server_streams(p), baseline, "all streams reaped")
    print("  test_mixed_reset_and_fin: PASS")


def test_reset_before_any_data() raises:
    var p = RawPair()
    var baseline = _server_streams(p)
    for _ in range(4):
        var sid = p.cli.open_stream(True)
        p.cli.reset_stream(sid, UInt64(0x10C))
        p.pump(3)
        assert_equal_int(_server_streams(p), baseline + 1, "server still owes its side")
        _server_fin(p, sid)
    assert_equal_int(p.close_code, -1, "no protocol error")
    assert_equal_int(_server_streams(p), baseline, "reset-only streams reaped")
    print("  test_reset_before_any_data: PASS")


def test_reset_after_server_fin() raises:
    var p = RawPair()
    var baseline = _server_streams(p)
    for _ in range(4):
        var sid = p.cli.open_stream(True)
        var h = headers_get()
        p.cli.send_stream_data(sid, Span(h), False)
        p.pump(3)
        _server_fin(p, sid)
        assert_equal_int(_server_streams(p), baseline + 1, "request side still open")
        p.cli.reset_stream(sid, UInt64(0x10C))
        p.pump(4)
    assert_equal_int(p.close_code, -1, "no protocol error")
    assert_equal_int(_server_streams(p), baseline, "streams reset after FIN reaped")
    print("  test_reset_after_server_fin: PASS")


def main() raises:
    print("test_h3_reset_stream_reaped:")
    test_reset_before_any_data()
    test_reset_after_server_fin()
    test_mixed_reset_and_fin()
    test_reset_requests_are_reaped_and_credit_returns()
    print("All test_h3_reset_stream_reaped tests passed.")
