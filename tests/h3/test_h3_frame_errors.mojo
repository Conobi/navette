# tests/h3/test_h3_frame_errors.mojo
#
# Malformed HTTP/3 input must close the connection with the RFC 9114 /
# RFC 9204 error code, never be silently dropped (which leaves the stream
# stalled until the idle timeout).

from std.collections import Span
from navette.h3.error import (
    H3_FRAME_ERROR,
    H3_FRAME_UNEXPECTED,
    H3_CLOSED_CRITICAL_STREAM,
    QPACK_DECOMPRESSION_FAILED,
)
from navette.h3.guard_predicates import H3StreamCtx, predicate_f34_headers_on_control
from tests._test_util import assert_true, assert_equal_int
from tests.h3._h3_raw_pair import RawPair, put_varint, headers_get, filler

comptime _HUGE_LEN: UInt64 = UInt64(1) << 30
comptime _SMALL = 64


def _request_close(var payload: List[Byte]) raises -> Int:
    """Close code after sending one HEADERS frame with `payload`."""
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b: List[Byte] = [0x01]
    put_varint(b, UInt64(len(payload)))
    b.extend(Span(payload))
    p.send(sid, b)
    assert_equal_int(p.headers_events, 0, "malformed field section not delivered")
    return p.close_code


def _control_close(var frames: List[Byte]) raises -> Int:
    """Close code after SETTINGS then `frames` on the control stream."""
    var p = RawPair()
    var ctrl = p.control_stream()
    assert_equal_int(p.close_code, -1, "empty SETTINGS accepted")
    p.send(ctrl, frames)
    return p.close_code


def test_qpack_errors_close_decompression_failed() raises:
    var bad_index: List[Byte] = [0x00, 0x00, 0xFF, 0x24]  # static index 99
    assert_equal_int(_request_close(bad_index^), Int(QPACK_DECOMPRESSION_FAILED), "bad static index")
    var ric: List[Byte] = [0x01, 0x00, 0xD1]  # Required Insert Count 1
    assert_equal_int(_request_close(ric^), Int(QPACK_DECOMPRESSION_FAILED), "non-zero RIC")
    var overflow: List[Byte] = [0x00, 0x00, 0xFF]
    for _ in range(9):
        overflow.append(0xFF)
    overflow.append(0x01)
    assert_equal_int(_request_close(overflow^), Int(QPACK_DECOMPRESSION_FAILED), "62-bit overflow")
    var truncated: List[Byte] = [0x00, 0x00, 0x51, 0x05, 0x61]  # value length 5, 1 byte
    assert_equal_int(_request_close(truncated^), Int(QPACK_DECOMPRESSION_FAILED), "truncated literal")
    print("  test_qpack_errors_close_decompression_failed: PASS")


def test_empty_varint_frames_are_frame_errors() raises:
    var goaway: List[Byte] = [0x07, 0x00]
    assert_equal_int(_control_close(goaway^), Int(H3_FRAME_ERROR), "empty GOAWAY")
    var cancel: List[Byte] = [0x03, 0x00]
    assert_equal_int(_control_close(cancel^), Int(H3_FRAME_ERROR), "empty CANCEL_PUSH")
    var max_push: List[Byte] = [0x0D, 0x00]
    assert_equal_int(_control_close(max_push^), Int(H3_FRAME_ERROR), "empty MAX_PUSH_ID")
    var trailing: List[Byte] = [0x07, 0x02, 0x00, 0x00]
    assert_equal_int(_control_close(trailing^), Int(H3_FRAME_ERROR), "GOAWAY with trailing byte")
    print("  test_empty_varint_frames_are_frame_errors: PASS")


def test_malformed_settings_is_frame_error() raises:
    var p = RawPair()
    var ctrl = p.cli.open_stream(False)
    var b: List[Byte] = [0x00, 0x04, 0x01, 0x06]  # identifier with no value
    p.send(ctrl, b)
    assert_equal_int(p.close_code, Int(H3_FRAME_ERROR), "truncated SETTINGS pair")
    print("  test_malformed_settings_is_frame_error: PASS")


def test_push_promise_to_server_rejected_on_header() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b = headers_get()
    b.append(0x05)
    put_varint(b, _HUGE_LEN)
    filler(b, 20_000)
    p.send(sid, b)
    assert_true(p.buffered(sid) <= _SMALL, "PUSH_PROMISE payload not buffered")
    assert_equal_int(p.close_code, Int(H3_FRAME_UNEXPECTED), "PUSH_PROMISE sent to a server")
    print("  test_push_promise_to_server_rejected_on_header: PASS")


def test_headers_on_control_rejected_on_header() raises:
    var p = RawPair()
    var ctrl = p.control_stream()
    var b: List[Byte] = [0x01]
    put_varint(b, UInt64(40_000))
    filler(b, 20_000)
    p.send(ctrl, b)
    assert_true(p.buffered(ctrl) <= _SMALL, "control-stream HEADERS payload not buffered")
    # The code is the F34 guard's verdict (the guard owns it).
    var ctx = H3StreamCtx(kind=UInt8(1), headers_seen=False, settings_seen=True, first_frame_seen=True)
    var v = predicate_f34_headers_on_control(UInt64(0x01), ctx)
    assert_equal_int(p.close_code, Int(v.value().error_code), "HEADERS on the control stream")
    print("  test_headers_on_control_rejected_on_header: PASS")


def test_http2_reserved_frame_types() raises:
    var types: List[UInt8] = [0x02, 0x06, 0x08, 0x09]
    for t in types:
        var p = RawPair()
        var sid = p.cli.open_stream(True)
        var b = headers_get()
        b.append(t)
        b.append(0x00)
        p.send(sid, b)
        assert_equal_int(p.close_code, Int(H3_FRAME_UNEXPECTED), "HTTP/2 frame type " + String(Int(t)))
    print("  test_http2_reserved_frame_types: PASS")


def test_max_push_id_on_request_stream() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b = headers_get()
    b.append(0x0D)
    b.append(0x01)
    b.append(0x00)
    p.send(sid, b)
    assert_equal_int(p.close_code, Int(H3_FRAME_UNEXPECTED), "MAX_PUSH_ID on a request stream")
    print("  test_max_push_id_on_request_stream: PASS")


def _fin_after(var tail: List[Byte]) raises -> RawPair:
    """Send HEADERS + `tail` with FIN on a fresh request stream."""
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b = headers_get()
    b.extend(Span(tail))
    p.send(sid, b, fin=True)
    return p^


def test_fin_mid_frame_is_frame_error() raises:
    var data_short: List[Byte] = [0x00, 0x40, 0x64]  # DATA declaring 100 bytes
    filler(data_short, 10)
    var p1 = _fin_after(data_short^)
    assert_equal_int(p1.close_code, Int(H3_FRAME_ERROR), "FIN inside a DATA payload")
    assert_equal_int(p1.ended_events, 0, "truncated body is not a finished request")

    var half_header: List[Byte] = [0x00, 0x40]  # DATA type, length varint cut
    var p2 = _fin_after(half_header^)
    assert_equal_int(p2.close_code, Int(H3_FRAME_ERROR), "FIN inside a frame header")
    assert_equal_int(p2.ended_events, 0, "no STREAM_ENDED after a cut header")

    var half_headers: List[Byte] = [0x01, 0x05, 0x00, 0x00]  # 2 of 5 bytes
    var p3 = _fin_after(half_headers^)
    assert_equal_int(p3.close_code, Int(H3_FRAME_ERROR), "FIN inside a HEADERS payload")

    var skipped: List[Byte] = [0x21, 0x10, 0xAB]  # reserved frame, 1 of 16 bytes
    var p4 = _fin_after(skipped^)
    assert_equal_int(p4.close_code, Int(H3_FRAME_ERROR), "FIN inside a skipped payload")

    var clean: List[Byte] = [0x00, 0x02, 0x68, 0x69]
    var p5 = _fin_after(clean^)
    assert_equal_int(p5.close_code, -1, "FIN on a frame boundary is clean")
    assert_equal_int(p5.ended_events, 1, "STREAM_ENDED after a complete body")
    assert_equal_int(len(p5.data), 2, "body delivered")
    print("  test_fin_mid_frame_is_frame_error: PASS")


def test_control_stream_fin_closes_critical() raises:
    var p = RawPair()
    var ctrl = p.control_stream()
    var grease: List[Byte] = [0x21, 0x00]  # FIN rides on a reserved frame
    p.send(ctrl, grease, fin=True)
    assert_equal_int(p.close_code, Int(H3_CLOSED_CRITICAL_STREAM), "control stream closed")
    print("  test_control_stream_fin_closes_critical: PASS")


def main() raises:
    print("test_h3_frame_errors:")
    test_qpack_errors_close_decompression_failed()
    test_empty_varint_frames_are_frame_errors()
    test_malformed_settings_is_frame_error()
    test_push_promise_to_server_rejected_on_header()
    test_headers_on_control_rejected_on_header()
    test_http2_reserved_frame_types()
    test_max_push_id_on_request_stream()
    test_fin_mid_frame_is_frame_error()
    test_control_stream_fin_closes_critical()
    print("All test_h3_frame_errors tests passed.")
