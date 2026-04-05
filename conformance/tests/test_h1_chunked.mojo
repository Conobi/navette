# conformance/tests/test_h1_chunked.mojo
#
# Unit tests for the chunked transfer encoding codec.
from lib.test_util import assert_true, assert_equal, assert_bytes_equal, hex_decode
from lib.http1.types import ParseConfig, ChunkedResult, ParserStrictness
from lib.http1.chunked import decode_chunked, encode_chunked


def test_single_chunk() raises:
    """Single chunk: '5\\r\\nhello\\r\\n0\\r\\n\\r\\n'."""
    # "5\r\nhello\r\n0\r\n\r\n"
    var wire = hex_decode("350d0a68656c6c6f0d0a300d0a0d0a")
    var result = decode_chunked(wire)
    assert_true(result.ok(), "single chunk decode failed: " + result.error)
    var expected = hex_decode("68656c6c6f")  # "hello"
    assert_bytes_equal(result.body, expected, "single chunk body")
    assert_equal(len(result.trailers), 0, "no trailers expected")


def test_multiple_chunks() raises:
    """Two chunks: '3\\r\\nabc\\r\\n4\\r\\ndefg\\r\\n0\\r\\n\\r\\n'."""
    var wire = hex_decode("330d0a6162630d0a340d0a646566670d0a300d0a0d0a")
    var result = decode_chunked(wire)
    assert_true(result.ok(), "multi chunk decode failed: " + result.error)
    var expected = hex_decode("61626364656667")  # "abcdefg"
    assert_bytes_equal(result.body, expected, "multi chunk body")


def test_empty_body() raises:
    """Empty body: '0\\r\\n\\r\\n'."""
    var wire = hex_decode("300d0a0d0a")
    var result = decode_chunked(wire)
    assert_true(result.ok(), "empty chunk decode failed: " + result.error)
    assert_equal(len(result.body), 0, "empty body expected")


def test_hex_uppercase() raises:
    """Chunk size in uppercase hex: 'A\\r\\n' = 10 bytes."""
    # "A\r\n" + 10 bytes of 'x' (0x78) + "\r\n0\r\n\r\n"
    var wire = hex_decode("410d0a" + "78" * 10 + "0d0a300d0a0d0a")
    var result = decode_chunked(wire)
    assert_true(result.ok(), "hex uppercase failed: " + result.error)
    assert_equal(len(result.body), 10, "body length")


def test_chunk_extension_strict_rejected() raises:
    """Chunk extension in strict mode: '5;ext=val\\r\\nhello\\r\\n0\\r\\n\\r\\n'."""
    # "5;ext=val\r\nhello\r\n0\r\n\r\n"
    var wire = hex_decode("353b6578743d76616c0d0a68656c6c6f0d0a300d0a0d0a")
    var config = ParseConfig()
    var result = decode_chunked(wire, config)
    assert_true(not result.ok(), "chunk extension should be rejected in strict mode")


def test_chunk_extension_lenient_accepted() raises:
    """Chunk extension in lenient mode: accepted, extension ignored."""
    var wire = hex_decode("353b6578743d76616c0d0a68656c6c6f0d0a300d0a0d0a")
    var config = ParseConfig(strictness=ParserStrictness(allow_chunk_extensions=True))
    var result = decode_chunked(wire, config)
    assert_true(result.ok(), "chunk extension should be accepted in lenient: " + result.error)
    var expected = hex_decode("68656c6c6f")  # "hello"
    assert_bytes_equal(result.body, expected, "lenient chunk ext body")


def test_invalid_hex_size() raises:
    """Invalid chunk size: 'XZ\\r\\n'."""
    var wire = hex_decode("585a0d0a")
    var result = decode_chunked(wire)
    assert_true(not result.ok(), "invalid hex should fail")


def test_missing_crlf_after_data() raises:
    """Missing CRLF after chunk data."""
    # "5\r\nhello" + "0\r\n\r\n" but no CRLF between data and next chunk
    var wire = hex_decode("350d0a68656c6c6f300d0a0d0a")
    var result = decode_chunked(wire)
    assert_true(not result.ok(), "missing CRLF should fail")


def test_oversized_chunk() raises:
    """Chunk exceeds max_chunk_size."""
    # "FFFFF\r\n" = 1048575 bytes, but max is 100
    var wire = hex_decode("46464646460d0a")
    var config = ParseConfig(max_chunk_size=100)
    var result = decode_chunked(wire, config)
    assert_true(not result.ok(), "oversized chunk should fail")


def test_encode_decode_roundtrip() raises:
    """Encode then decode produces original data."""
    var original = hex_decode("48656c6c6f20576f726c6421")  # "Hello World!"
    var encoded = encode_chunked(original, chunk_size=5)
    var result = decode_chunked(encoded)
    assert_true(result.ok(), "roundtrip decode failed: " + result.error)
    assert_bytes_equal(result.body, original, "roundtrip body")


def test_encode_decode_roundtrip_large() raises:
    """Roundtrip with larger data and various chunk sizes."""
    var original = List[UInt8]()
    for i in range(500):
        original.append(UInt8(i % 256))

    var chunk_sizes = List[Int]()
    chunk_sizes.append(1)
    chunk_sizes.append(7)
    chunk_sizes.append(64)
    chunk_sizes.append(500)
    chunk_sizes.append(1024)

    for ci in range(len(chunk_sizes)):
        var cs = chunk_sizes[ci]
        var encoded = encode_chunked(original, chunk_size=cs)
        var result = decode_chunked(encoded)
        assert_true(result.ok(), "roundtrip failed for chunk_size=" + String(cs))
        assert_bytes_equal(result.body, original, "roundtrip body chunk_size=" + String(cs))


def main() raises:
    # Sentinel check
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    test_single_chunk()
    test_multiple_chunks()
    test_empty_body()
    test_hex_uppercase()
    test_chunk_extension_strict_rejected()
    test_chunk_extension_lenient_accepted()
    test_invalid_hex_size()
    test_missing_crlf_after_data()
    test_oversized_chunk()
    test_encode_decode_roundtrip()
    test_encode_decode_roundtrip_large()
    print("test_h1_chunked: all 11 tests passed")
