# tests/test_decode.mojo
#
# Unit tests for ContentDecoder (identity, gzip, brotli).
from navette.http.decode import ContentDecoder, ContentEncoding
from tests._test_util import assert_true, assert_equal_str, assert_equal_int


def _bytes_to_string(data: List[UInt8]) -> String:
    """Convert a List[UInt8] to a String."""
    var s = String()
    for i in range(len(data)):
        s += chr(Int(data[i]))
    return s^


def _make_gzip_hello_world() -> List[UInt8]:
    """gzip.compress(b'hello world') with mtime=0."""
    var b = List[UInt8]()
    b.append(31); b.append(139); b.append(8); b.append(0)
    b.append(0); b.append(0); b.append(0); b.append(0)
    b.append(2); b.append(255); b.append(203); b.append(72)
    b.append(205); b.append(201); b.append(201); b.append(87)
    b.append(40); b.append(207); b.append(47); b.append(202)
    b.append(73); b.append(1); b.append(0); b.append(133)
    b.append(17); b.append(74); b.append(13); b.append(11)
    b.append(0); b.append(0); b.append(0)
    return b^


def _make_brotli_hello_world() -> List[UInt8]:
    """brotli.compress(b'hello world')."""
    var b = List[UInt8]()
    b.append(11); b.append(5); b.append(128); b.append(104)
    b.append(101); b.append(108); b.append(108); b.append(111)
    b.append(32); b.append(119); b.append(111); b.append(114)
    b.append(108); b.append(100); b.append(3)
    return b^


# -- identity passthrough -----------------------------------------------------

def test_identity_passthrough() raises:
    var dec = ContentDecoder(ContentEncoding.identity())
    var input = List[UInt8]()
    var msg = String("hello world")
    var b = msg.as_bytes()
    for i in range(len(b)):
        input.append(b[i])
    var out = dec.feed(input)
    assert_equal_int(len(out), len(input), "identity.len")
    var out_str = _bytes_to_string(out)
    assert_true(out_str.startswith("hello world"), "identity.content")
    var tail = dec.finish()
    assert_equal_int(len(tail), 0, "identity.finish_empty")
    print("PASS: test_identity_passthrough")


# -- gzip decompression -------------------------------------------------------

def test_gzip_decompress() raises:
    var dec = ContentDecoder(ContentEncoding.gzip())
    var gz = _make_gzip_hello_world()
    var out = dec.feed(gz)
    var tail = dec.finish()
    for i in range(len(tail)):
        out.append(tail[i])
    var result = _bytes_to_string(out)
    assert_equal_str(result, String("hello world"), "gzip.content")
    print("PASS: test_gzip_decompress")


# -- brotli decompression -----------------------------------------------------

def test_brotli_decompress() raises:
    var dec = ContentDecoder(ContentEncoding.brotli())
    var br = _make_brotli_hello_world()
    var out = dec.feed(br)
    var tail = dec.finish()
    for i in range(len(tail)):
        out.append(tail[i])
    var result = _bytes_to_string(out)
    assert_equal_str(result, String("hello world"), "brotli.content")
    print("PASS: test_brotli_decompress")


# -- ContentEncoding.from_header -----------------------------------------------

def test_encoding_from_header() raises:
    var g = ContentEncoding.from_header("gzip")
    assert_equal_int(Int(g._tag), 1, "from_header.gzip")
    var xg = ContentEncoding.from_header("x-gzip")
    assert_equal_int(Int(xg._tag), 1, "from_header.x-gzip")
    var b = ContentEncoding.from_header("br")
    assert_equal_int(Int(b._tag), 2, "from_header.br")
    var i = ContentEncoding.from_header("identity")
    assert_equal_int(Int(i._tag), 0, "from_header.identity")
    var u = ContentEncoding.from_header("unknown")
    assert_equal_int(Int(u._tag), 0, "from_header.unknown")
    print("PASS: test_encoding_from_header")


# -- main ----------------------------------------------------------------------

def main() raises:
    test_identity_passthrough()
    test_gzip_decompress()
    test_brotli_decompress()
    test_encoding_from_header()
    print("ALL DECODE TESTS PASSED")
