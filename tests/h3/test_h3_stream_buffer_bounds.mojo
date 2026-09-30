# tests/h3/test_h3_stream_buffer_bounds.mojo
#
# Per-stream buffering bounds on H3Connection. A raw QUIC client (no H3
# layer of its own) writes crafted stream bytes to an H3 server so each
# case controls exactly what the server sees. QUIC returns flow-control
# credit as soon as H3 drains a stream, so any H3 buffering by declared
# frame length is unbounded unless H3 caps it.

from std.collections import Span
from navette.quic.codec import ByteReader
from navette.h3.connection import H3_MAX_FIELD_SECTION_SIZE
from navette.h3.frame import SettingsFrame, SETTINGS_MAX_FIELD_SECTION_SIZE, parse_h3_frame
from navette.h3.error import H3_EXCESSIVE_LOAD, H3_FRAME_ERROR
from tests._test_util import assert_true, assert_equal_int
from tests.h3._h3_raw_pair import RawPair, put_varint, headers_get, filler

# Payload bytes actually sent after a header declaring a far larger frame.
comptime _BODY = 20_000
comptime _HUGE_LEN: UInt64 = UInt64(1) << 30
# Anything the server keeps for a stream beyond this is buffering by
# declared length rather than one bounded frame header.
comptime _SMALL = 64


def test_huge_headers_declared_length() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b: List[Byte] = [0x01]
    put_varint(b, _HUGE_LEN)
    filler(b, _BODY)
    p.send(sid, b)
    assert_true(p.buffered(sid) <= _SMALL, "HEADERS not buffered by declared length: " + String(p.buffered(sid)))
    assert_equal_int(p.close_code, Int(H3_EXCESSIVE_LOAD), "oversized HEADERS closes with H3_EXCESSIVE_LOAD")
    _ = p.srv.is_closed()
    print("  test_huge_headers_declared_length: PASS")


def test_huge_data_is_streamed() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b = headers_get()
    b.append(0x00)
    put_varint(b, _HUGE_LEN)
    var body_at = len(b)
    for i in range(_BODY):
        b.append(UInt8(i % 251))
    p.send(sid, b)
    assert_true(p.buffered(sid) <= _SMALL, "DATA payload not buffered: " + String(p.buffered(sid)))
    assert_equal_int(len(p.data), _BODY, "DATA payload delivered as it arrives")
    for i in range(_BODY):
        if p.data[i] != b[body_at + i]:
            assert_true(False, "DATA byte " + String(i) + " out of order or corrupted")
    assert_equal_int(p.headers_events, 1, "HEADERS still delivered")
    assert_equal_int(p.close_code, -1, "no close for a large DATA frame")
    print("  test_huge_data_is_streamed: PASS")


def test_unknown_frame_payload_skipped() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b = headers_get()
    b.append(0x21)  # reserved frame type 0x21 (RFC 9114 Section 7.2.8)
    put_varint(b, _HUGE_LEN)
    filler(b, _BODY)
    p.send(sid, b)
    assert_true(p.buffered(sid) <= _SMALL, "unknown frame payload not buffered: " + String(p.buffered(sid)))
    assert_equal_int(p.close_code, -1, "unknown frames are ignored, not fatal")
    print("  test_unknown_frame_payload_skipped: PASS")


def test_unknown_and_qpack_uni_streams_discarded() raises:
    var p = RawPair()
    var unk = p.cli.open_stream(False)
    var b: List[Byte] = [0x21]
    filler(b, _BODY)
    p.send(unk, b)
    assert_equal_int(p.buffered(unk), 0, "unknown uni stream data discarded")
    var qenc = p.cli.open_stream(False)
    var q: List[Byte] = [0x02]
    filler(q, _BODY)
    p.send(qenc, q)
    assert_equal_int(p.buffered(qenc), 0, "QPACK encoder stream bytes not buffered")
    assert_equal_int(p.headers_events, 0, "encoder-stream bytes never parsed as H3 frames")
    print("  test_unknown_and_qpack_uni_streams_discarded: PASS")


def test_oversized_settings_rejected() raises:
    var p = RawPair()
    var ctrl = p.cli.open_stream(False)
    var b: List[Byte] = [0x00, 0x04]
    put_varint(b, UInt64(_BODY))
    for _ in range(_BODY):
        b.append(0x21)  # repeated reserved setting id 0x21 = 0x21
    p.send(ctrl, b)
    assert_equal_int(p.close_code, Int(H3_FRAME_ERROR), "oversized SETTINGS closes with H3_FRAME_ERROR")
    print("  test_oversized_settings_rejected: PASS")


def test_decoded_field_section_capped() raises:
    # 1,000 one-byte indexed fields (:method GET, 42 bytes each by the
    # RFC 9114 Section 4.2.2 rule) = 42,000 decoded bytes from a 1 KB frame.
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var payload: List[Byte] = [0x00, 0x00]
    for _ in range(1000):
        payload.append(0xD1)
    var b: List[Byte] = [0x01]
    put_varint(b, UInt64(len(payload)))
    b.extend(Span(payload))
    p.send(sid, b)
    assert_equal_int(p.headers_events, 0, "expanded field section not delivered")
    assert_equal_int(p.close_code, Int(H3_EXCESSIVE_LOAD), "expansion closes with H3_EXCESSIVE_LOAD")
    print("  test_decoded_field_section_capped: PASS")


def test_advertised_max_field_section_size() raises:
    var p = RawPair()
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


def test_headers_split_across_drains() raises:
    # Frame header, then QPACK prefix, then the field line, each in its
    # own drain: the partial frame must wait and decode exactly once.
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var h = headers_get()
    var a: List[Byte] = [h[0]]
    var b2: List[Byte] = [h[1], h[2], h[3]]
    var c: List[Byte] = [h[4]]
    p.send(sid, a)
    assert_equal_int(p.headers_events, 0, "no HEADERS from a lone type byte")
    p.send(sid, b2)
    assert_equal_int(p.headers_events, 0, "no HEADERS from a partial payload")
    p.send(sid, c)
    assert_equal_int(p.headers_events, 1, "HEADERS delivered once complete")
    assert_equal_int(p.close_code, -1, "split HEADERS is not an error")
    print("  test_headers_split_across_drains: PASS")


def main() raises:
    print("test_h3_stream_buffer_bounds:")
    test_huge_headers_declared_length()
    test_huge_data_is_streamed()
    test_unknown_frame_payload_skipped()
    test_unknown_and_qpack_uni_streams_discarded()
    test_oversized_settings_rejected()
    test_decoded_field_section_capped()
    test_advertised_max_field_section_size()
    test_headers_split_across_drains()
    print("All test_h3_stream_buffer_bounds tests passed.")
