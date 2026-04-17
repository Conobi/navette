"""QC-2 H3 Frame cross-validation: parse oracle wire bytes and compare.

Oracle vectors: conformance/vectors/rfc9114/frame.json
"""
from src.h3.frame import parse_h3_frame, SettingsFrame
from src.quic.codec import ByteReader
from tests._test_util import assert_true, assert_equal_int


def hex_to_bytes(h: String) raises -> List[UInt8]:
    """Convert a hex string to bytes. Must be even-length."""
    if len(h) % 2 != 0:
        raise "hex_to_bytes: odd-length hex string"
    var result = List[UInt8]()
    var bytes_view = h.as_bytes()
    for i in range(0, len(h), 2):
        var hi = bytes_view[i]
        var lo = bytes_view[i + 1]
        var val = Int(0)
        if hi >= 48 and hi <= 57:        # '0'-'9'
            val = (Int(hi) - 48) << 4
        elif hi >= 97 and hi <= 102:     # 'a'-'f'
            val = (Int(hi) - 97 + 10) << 4
        elif hi >= 65 and hi <= 70:      # 'A'-'F'
            val = (Int(hi) - 65 + 10) << 4
        else:
            raise "hex_to_bytes: invalid hex character"
        if lo >= 48 and lo <= 57:
            val |= Int(lo) - 48
        elif lo >= 97 and lo <= 102:
            val |= Int(lo) - 97 + 10
        elif lo >= 65 and lo <= 70:
            val |= Int(lo) - 65 + 10
        else:
            raise "hex_to_bytes: invalid hex character"
        result.append(UInt8(val))
    return result^


def test_cross_data_frame_empty() raises:
    # DATA frame empty payload: oracle wire_hex = "0000"
    # type=0x00, length=0x00
    var wire = hex_to_bytes("0000")
    var r = ByteReader(Span(wire))
    var frame = parse_h3_frame(r)
    assert_equal_int(Int(frame.frame_type), 0x00, "frame_type")
    assert_equal_int(len(frame.payload), 0, "payload len")
    print("  test_cross_data_frame_empty: PASS")


def test_cross_data_frame_hello() raises:
    # DATA frame "hello": oracle wire_hex = "000568656c6c6f"
    # type=0x00, length=5, payload="hello"
    var wire = hex_to_bytes("000568656c6c6f")
    var r = ByteReader(Span(wire))
    var frame = parse_h3_frame(r)
    assert_equal_int(Int(frame.frame_type), 0x00, "frame_type")
    assert_equal_int(len(frame.payload), 5, "payload len")
    assert_equal_int(Int(frame.payload[0]), 0x68, "payload[0] 'h'")
    print("  test_cross_data_frame_hello: PASS")


def test_cross_settings_two_pairs() raises:
    # SETTINGS frame two pairs: oracle wire_hex = "04080150000680010000"
    # type=0x04, length=8, pairs: (1, 4096) and (6, 65536)
    var wire = hex_to_bytes("04080150000680010000")
    var r = ByteReader(Span(wire))
    var frame = parse_h3_frame(r)
    assert_equal_int(Int(frame.frame_type), 0x04, "frame_type")
    var settings = SettingsFrame.decode(frame.payload)
    assert_equal_int(len(settings.pairs), 2, "pairs len")
    assert_equal_int(Int(settings.pairs[0].id), 0x01, "pair[0].id")
    assert_equal_int(Int(settings.pairs[0].value), 4096, "pair[0].value")
    print("  test_cross_settings_two_pairs: PASS")


def test_cross_unknown_frame_type() raises:
    # Unknown frame type 0x21: oracle wire_hex = "2102aabb"
    # type=0x21, length=2, payload=[0xAA, 0xBB]
    var wire = hex_to_bytes("2102aabb")
    var r = ByteReader(Span(wire))
    var frame = parse_h3_frame(r)
    assert_equal_int(Int(frame.frame_type), 0x21, "frame_type")
    assert_equal_int(len(frame.payload), 2, "payload len")
    assert_equal_int(Int(frame.payload[0]), 0xAA, "payload[0]")
    assert_equal_int(Int(frame.payload[1]), 0xBB, "payload[1]")
    print("  test_cross_unknown_frame_type: PASS")


def test_cross_goaway_frame() raises:
    # GOAWAY frame stream_id=4: oracle wire_hex = "070104"
    # type=0x07, length=1, payload=[0x04]
    var wire = hex_to_bytes("070104")
    var r = ByteReader(Span(wire))
    var frame = parse_h3_frame(r)
    assert_equal_int(Int(frame.frame_type), 0x07, "frame_type")
    assert_equal_int(len(frame.payload), 1, "payload len")
    assert_equal_int(Int(frame.payload[0]), 0x04, "payload[0]")
    print("  test_cross_goaway_frame: PASS")


def main() raises:
    print("=== test_h3_frame_cross (QC-2) ===")
    test_cross_data_frame_empty()
    test_cross_data_frame_hello()
    test_cross_settings_two_pairs()
    test_cross_unknown_frame_type()
    test_cross_goaway_frame()
    print("All cross-validation tests passed.")
