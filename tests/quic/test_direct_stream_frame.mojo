# Test write_stream_frame_direct — round-trip and budget tests.

from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len
from navette.quic.frame import (
    Frame,
    StreamFrame,
    parse_frame,
    serialize_frame,
    write_stream_frame_direct,
    FRAME_STREAM_BASE,
)


# ── Helpers ──────────────────────────────────────────────────────────────


def _assert_eq(got: UInt64, expected: UInt64, msg: String) raises:
    if got != expected:
        raise msg + ": got " + String(Int(got)) + " expected " + String(Int(expected))


def _assert_eq_int(got: Int, expected: Int, msg: String) raises:
    if got != expected:
        raise msg + ": got " + String(got) + " expected " + String(expected)


def _assert_true(cond: Bool, msg: String) raises:
    if not cond:
        raise msg


def _assert_false(cond: Bool, msg: String) raises:
    if cond:
        raise msg


def _assert_bytes_eq(got: List[UInt8], expected: List[UInt8], msg: String) raises:
    if len(got) != len(expected):
        raise msg + ": length mismatch, got " + String(len(got)) + " expected " + String(len(expected))
    for i in range(len(got)):
        if got[i] != expected[i]:
            raise msg + ": byte " + String(i) + " differs, got " + String(Int(got[i])) + " expected " + String(Int(expected[i]))


# ── Tests ────────────────────────────────────────────────────────────────


def test_direct_stream_roundtrip() raises:
    """Write a STREAM frame with offset via direct writer, parse it back."""
    var data = List[UInt8]()
    for i in range(50):
        data.append(UInt8(i))
    var buf = List[UInt8]()
    var written = write_stream_frame_direct(
        buf,
        budget=200,
        stream_id=UInt64(4),
        offset=UInt64(100),
        data=Span(data),
        fin=False,
    )
    _assert_true(written > 0, "should write bytes")
    _assert_eq_int(len(buf), written, "buf length should match written")
    var reader = ByteReader(Span(buf))
    var frame = parse_frame(reader)
    _assert_true(frame.is_stream(), "should be STREAM")
    ref sf = frame.as_stream()
    _assert_eq(sf.stream_id, UInt64(4), "stream_id")
    _assert_eq(sf.offset, UInt64(100), "offset")
    _assert_false(sf.fin, "fin should be false")
    _assert_eq_int(len(sf.data), 50, "data length")
    for i in range(50):
        if sf.data[i] != UInt8(i):
            raise "data mismatch at byte " + String(i)
    print("  direct_stream_roundtrip: PASS")


def test_direct_stream_zero_offset() raises:
    """Direct write at offset 0 omits the OFF bit."""
    var data = List[UInt8]()
    for _ in range(10):
        data.append(UInt8(0xAA))
    var buf = List[UInt8]()
    var written = write_stream_frame_direct(
        buf,
        budget=200,
        stream_id=UInt64(8),
        offset=UInt64(0),
        data=Span(data),
        fin=False,
    )
    _assert_true(written > 0, "should write bytes")
    var reader = ByteReader(Span(buf))
    var frame = parse_frame(reader)
    ref sf = frame.as_stream()
    _assert_eq(sf.stream_id, UInt64(8), "stream_id")
    _assert_eq(sf.offset, UInt64(0), "offset should be 0")
    _assert_false(sf.fin, "fin")
    _assert_eq_int(len(sf.data), 10, "data length")
    print("  direct_stream_zero_offset: PASS")


def test_direct_stream_fin_with_data() raises:
    """Direct write with FIN flag and data."""
    var data = List[UInt8]()
    for i in range(5):
        data.append(UInt8(0x48 + i))
    var buf = List[UInt8]()
    var written = write_stream_frame_direct(
        buf,
        budget=200,
        stream_id=UInt64(4),
        offset=UInt64(400),
        data=Span(data),
        fin=True,
    )
    _assert_true(written > 0, "should write bytes")
    var reader = ByteReader(Span(buf))
    var frame = parse_frame(reader)
    ref sf = frame.as_stream()
    _assert_eq(sf.stream_id, UInt64(4), "stream_id")
    _assert_eq(sf.offset, UInt64(400), "offset")
    _assert_true(sf.fin, "fin should be true")
    _assert_bytes_eq(sf.data, data, "stream data")
    print("  direct_stream_fin_with_data: PASS")


def test_direct_stream_fin_only() raises:
    """Direct write with FIN and empty data."""
    var data = List[UInt8]()
    var buf = List[UInt8]()
    var written = write_stream_frame_direct(
        buf,
        budget=200,
        stream_id=UInt64(4),
        offset=UInt64(500),
        data=Span(data),
        fin=True,
    )
    _assert_true(written > 0, "should write bytes")
    var reader = ByteReader(Span(buf))
    var frame = parse_frame(reader)
    ref sf = frame.as_stream()
    _assert_eq(sf.stream_id, UInt64(4), "stream_id")
    _assert_eq(sf.offset, UInt64(500), "offset")
    _assert_true(sf.fin, "fin should be true")
    _assert_eq_int(len(sf.data), 0, "data should be empty")
    print("  direct_stream_fin_only: PASS")


def test_direct_stream_budget_truncation() raises:
    """Budget truncates data to fit; output is still a valid frame."""
    var data = List[UInt8]()
    for i in range(200):
        data.append(UInt8(i & 0xFF))
    # Budget 20: 1 (type) + 1 (stream_id=4) + 2 (offset=100) + 1 (len varint)
    # = 5 header bytes, leaving 15 bytes for data.
    var buf = List[UInt8]()
    var written = write_stream_frame_direct(
        buf,
        budget=20,
        stream_id=UInt64(4),
        offset=UInt64(100),
        data=Span(data),
        fin=False,
    )
    _assert_true(written > 0, "should write bytes")
    _assert_true(written <= 20, "should not exceed budget")
    _assert_eq_int(len(buf), written, "buf length")
    var reader = ByteReader(Span(buf))
    var frame = parse_frame(reader)
    ref sf = frame.as_stream()
    _assert_eq(sf.stream_id, UInt64(4), "stream_id")
    _assert_eq(sf.offset, UInt64(100), "offset")
    _assert_true(len(sf.data) > 0 and len(sf.data) < 200, "data should be truncated")
    for i in range(len(sf.data)):
        if sf.data[i] != UInt8(i & 0xFF):
            raise "truncated data mismatch at byte " + String(i)
    print("  direct_stream_budget_truncation: PASS")


def test_direct_stream_budget_too_small() raises:
    """Budget too small for even a minimal header returns 0."""
    var data = List[UInt8]()
    data.append(UInt8(0x42))
    var buf = List[UInt8]()
    var written = write_stream_frame_direct(
        buf,
        budget=2,
        stream_id=UInt64(4),
        offset=UInt64(0),
        data=Span(data),
        fin=False,
    )
    _assert_eq_int(written, 0, "should return 0 for insufficient budget")
    _assert_eq_int(len(buf), 0, "buf should be empty")
    print("  direct_stream_budget_too_small: PASS")


def test_direct_stream_matches_serialize() raises:
    """Direct writer produces byte-identical output to serialize_frame."""
    var data = List[UInt8]()
    for i in range(50):
        data.append(UInt8(i))

    # Via serialize_frame.
    var sf = StreamFrame(UInt64(4), UInt64(100), data, False)
    var frame = Frame.stream(sf)
    var w = ByteWriter()
    serialize_frame(frame, w)
    var expected = w.finish()

    # Via direct writer.
    var buf = List[UInt8]()
    var written = write_stream_frame_direct(
        buf,
        budget=200,
        stream_id=UInt64(4),
        offset=UInt64(100),
        data=Span(data),
        fin=False,
    )
    _assert_eq_int(written, len(expected), "written length should match")
    _assert_bytes_eq(buf, expected, "direct vs serialize_frame bytes")
    print("  direct_stream_matches_serialize: PASS")


def test_direct_stream_no_data_no_fin() raises:
    """Empty data without FIN returns 0 (nothing to emit)."""
    var data = List[UInt8]()
    var buf = List[UInt8]()
    var written = write_stream_frame_direct(
        buf,
        budget=200,
        stream_id=UInt64(4),
        offset=UInt64(0),
        data=Span(data),
        fin=False,
    )
    _assert_eq_int(written, 0, "should return 0 for empty data without FIN")
    print("  direct_stream_no_data_no_fin: PASS")


def test_direct_stream_large_offset() raises:
    """Large stream_id and offset use multi-byte varints correctly."""
    var data = List[UInt8]()
    for _ in range(100):
        data.append(UInt8(0xBB))
    var buf = List[UInt8]()
    var written = write_stream_frame_direct(
        buf,
        budget=500,
        stream_id=UInt64(100000),
        offset=UInt64(5000000),
        data=Span(data),
        fin=True,
    )
    _assert_true(written > 0, "should write bytes")
    var reader = ByteReader(Span(buf))
    var frame = parse_frame(reader)
    ref sf = frame.as_stream()
    _assert_eq(sf.stream_id, UInt64(100000), "stream_id")
    _assert_eq(sf.offset, UInt64(5000000), "offset")
    _assert_true(sf.fin, "fin")
    _assert_eq_int(len(sf.data), 100, "data length")
    print("  direct_stream_large_offset: PASS")


def main() raises:
    print("test_direct_stream_frame:")
    test_direct_stream_roundtrip()
    test_direct_stream_zero_offset()
    test_direct_stream_fin_with_data()
    test_direct_stream_fin_only()
    test_direct_stream_budget_truncation()
    test_direct_stream_budget_too_small()
    test_direct_stream_matches_serialize()
    test_direct_stream_no_data_no_fin()
    test_direct_stream_large_offset()
    print("All test_direct_stream_frame tests passed.")
