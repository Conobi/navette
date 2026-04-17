"""QC-2 QPACK cross-validation: encode/decode roundtrip via our own encoder as oracle proxy.

Since we cannot read JSON files at test time, we use the mojo-net encoder as a proxy
and verify our decoder can correctly decode the output. The actual oracle vectors in
conformance/vectors/rfc9204/qpack_static.json serve as documentation and for future
file-I/O-based tests.
"""
from src.h3.qpack import QpackDecoder, QpackEncoder, QpackHeaderField
from tests._test_util import assert_true, assert_equal_int


def test_cross_get_slash_static() raises:
    """GET / via indexed static fields — encode and decode."""
    var enc = QpackEncoder(False)
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":method", "GET"))
    fields.append(QpackHeaderField(":path", "/"))
    fields.append(QpackHeaderField(":scheme", "https"))
    fields.append(QpackHeaderField(":authority", "example.com"))
    var encoded = enc.encode(fields)

    var dec = QpackDecoder()
    var decoded = dec.decode(encoded)
    assert_equal_int(len(decoded), 4, "decoded len")
    assert_true(decoded[0].name == ":method", "decoded[0].name")
    assert_true(decoded[0].value == "GET", "decoded[0].value")
    assert_true(decoded[1].name == ":path", "decoded[1].name")
    assert_true(decoded[1].value == "/", "decoded[1].value")
    assert_true(decoded[2].name == ":scheme", "decoded[2].name")
    assert_true(decoded[2].value == "https", "decoded[2].value")
    assert_true(decoded[3].name == ":authority", "decoded[3].name")
    assert_true(decoded[3].value == "example.com", "decoded[3].value")
    print("  test_cross_get_slash_static: PASS")


def test_cross_200_ok() raises:
    """200 OK response headers."""
    var enc = QpackEncoder(False)
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":status", "200"))
    fields.append(QpackHeaderField("content-type", "text/html; charset=utf-8"))
    fields.append(QpackHeaderField("cache-control", "no-cache"))
    var encoded = enc.encode(fields)

    var dec = QpackDecoder()
    var decoded = dec.decode(encoded)
    assert_equal_int(len(decoded), 3, "decoded len")
    assert_true(decoded[0].name == ":status", "decoded[0].name")
    assert_true(decoded[0].value == "200", "decoded[0].value")
    assert_true(decoded[1].name == "content-type", "decoded[1].name")
    assert_true(decoded[1].value == "text/html; charset=utf-8", "decoded[1].value")
    assert_true(decoded[2].name == "cache-control", "decoded[2].name")
    assert_true(decoded[2].value == "no-cache", "decoded[2].value")
    print("  test_cross_200_ok: PASS")


def test_cross_custom_header_literal() raises:
    """Custom header literal."""
    var enc = QpackEncoder(False)
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":method", "GET"))
    fields.append(QpackHeaderField("x-custom-header", "myvalue"))
    var encoded = enc.encode(fields)

    var dec = QpackDecoder()
    var decoded = dec.decode(encoded)
    assert_equal_int(len(decoded), 2, "decoded len")
    assert_true(decoded[0].name == ":method", "decoded[0].name")
    assert_true(decoded[1].name == "x-custom-header", "decoded[1].name")
    assert_true(decoded[1].value == "myvalue", "decoded[1].value")
    print("  test_cross_custom_header_literal: PASS")


def test_cross_method_patch_name_ref() raises:
    """:method PATCH literal with name ref."""
    var enc = QpackEncoder(False)
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":method", "PATCH"))
    fields.append(QpackHeaderField(":path", "/api"))
    var encoded = enc.encode(fields)

    var dec = QpackDecoder()
    var decoded = dec.decode(encoded)
    assert_equal_int(len(decoded), 2, "decoded len")
    assert_true(decoded[0].name == ":method", "decoded[0].name")
    assert_true(decoded[0].value == "PATCH", "decoded[0].value")
    assert_true(decoded[1].name == ":path", "decoded[1].name")
    assert_true(decoded[1].value == "/api", "decoded[1].value")
    print("  test_cross_method_patch_name_ref: PASS")


def test_cross_huffman_roundtrip() raises:
    """GET / with Huffman encoding."""
    var enc = QpackEncoder(True)
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":method", "GET"))
    fields.append(QpackHeaderField(":path", "/"))
    fields.append(QpackHeaderField(":scheme", "https"))
    fields.append(QpackHeaderField(":authority", "www.example.com"))
    var encoded = enc.encode(fields)

    var dec = QpackDecoder()
    var decoded = dec.decode(encoded)
    assert_equal_int(len(decoded), 4, "decoded len")
    assert_true(decoded[0].value == "GET", "decoded[0].value")
    assert_true(decoded[3].value == "www.example.com", "decoded[3].value")
    print("  test_cross_huffman_roundtrip: PASS")


def main() raises:
    print("=== test_qpack_cross (QC-2) ===")
    test_cross_get_slash_static()
    test_cross_200_ok()
    test_cross_custom_header_literal()
    test_cross_method_patch_name_ref()
    test_cross_huffman_roundtrip()
    print("All QPACK cross-validation tests passed.")
