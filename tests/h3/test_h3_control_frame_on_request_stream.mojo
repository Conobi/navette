# tests/h3/test_h3_control_frame_on_request_stream.mojo
#
# SETTINGS, GOAWAY, CANCEL_PUSH and MAX_PUSH_ID belong on the control
# stream only: on a request stream they are rejected as misplaced (RFC
# 9114 Sections 7.2.3-7.2.7) whatever their length, not as H3_FRAME_ERROR
# from a length check meant for the control stream.

from std.collections import Span
from navette.h3.error import H3_FRAME_UNEXPECTED
from navette.h3.guard_predicates import H3StreamCtx, predicate_f36_cancel_push_on_request
from tests._test_util import assert_equal_int
from tests.h3._h3_raw_pair import RawPair, headers_get


def _close_code_after(var frame: List[Byte]) raises -> Int:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b = headers_get()
    b.extend(Span(frame))
    p.send(sid, b)
    return p.close_code


def test_control_frames_on_request_stream() raises:
    var cases = List[List[Byte]]()
    cases.append([0x07, 0x00])              # GOAWAY, zero-length
    cases.append([0x0D, 0x09])              # MAX_PUSH_ID, oversized
    cases.append([0x04, 0x41, 0x2C])        # SETTINGS, 300 bytes declared
    for i in range(len(cases)):
        var code = _close_code_after(cases[i].copy())
        assert_equal_int(code, Int(H3_FRAME_UNEXPECTED), "case " + String(i))
    print("  test_control_frames_on_request_stream: PASS")


def test_oversized_cancel_push_on_request_stream() raises:
    # The code is the CANCEL_PUSH guard's verdict (the guard owns it).
    var ctx = H3StreamCtx(kind=UInt8(0), headers_seen=True, settings_seen=False)
    var v = predicate_f36_cancel_push_on_request(UInt64(0x03), ctx)
    var code = _close_code_after([0x03, 0x09])
    assert_equal_int(code, Int(v.value().error_code), "CANCEL_PUSH, oversized")
    print("  test_oversized_cancel_push_on_request_stream: PASS")


def main() raises:
    print("test_h3_control_frame_on_request_stream:")
    test_control_frames_on_request_stream()
    test_oversized_cancel_push_on_request_stream()
    print("All test_h3_control_frame_on_request_stream tests passed.")
