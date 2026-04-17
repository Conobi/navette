# tests/test_h3_qpack.mojo
# QPACK static table tests — RFC 9204 Appendix A
# Task 2: static table only (Huffman, encoder, decoder in T3-T5)

from src.h3.qpack import (
    QpackStaticEntry,
    QpackHeaderField,
    QPACK_STATIC_TABLE_SIZE,
    qpack_static_get,
    qpack_static_find,
    qpack_static_find_name,
    huffman_encode,
    huffman_decode,
    QpackEncoder,
    QpackDecoder,
)
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_static_get_method_get() raises:
    # RFC 9204 Appendix A: index 17 = (:method, GET)
    var entry = qpack_static_get(17)
    assert_true(entry.name == ":method", "name should be :method")
    assert_true(entry.value == "GET", "value should be GET")
    print("  test_static_get_method_get: PASS")


def test_static_get_out_of_range_raises() raises:
    var raised = False
    try:
        _ = qpack_static_get(QPACK_STATIC_TABLE_SIZE)
    except:
        raised = True
    assert_true(raised, "should raise on out-of-range index")
    print("  test_static_get_out_of_range_raises: PASS")


def test_static_find_exact_match() raises:
    # (:method, GET) should find index 17
    var result = qpack_static_find(":method", "GET")
    assert_true(result.__bool__(), "should find :method GET")
    assert_equal_int(result.value(), 17, "index of :method GET should be 17")
    print("  test_static_find_exact_match: PASS")


def test_static_find_no_match() raises:
    # Unknown header
    var result = qpack_static_find("x-custom", "value")
    assert_false(result.__bool__(), "x-custom should not be found")
    print("  test_static_find_no_match: PASS")


def test_static_find_name_only() raises:
    # :method exists; first :method entry is index 15 (CONNECT)
    var result = qpack_static_find_name(":method")
    assert_true(result.__bool__(), "should find :method by name")
    # First :method entry is index 15 (CONNECT) per RFC 9204 Appendix A
    assert_equal_int(result.value(), 15, "first :method index should be 15")
    print("  test_static_find_name_only: PASS")


def test_static_find_name_no_match() raises:
    var result = qpack_static_find_name("x-unknown-header")
    assert_false(result.__bool__(), "x-unknown-header should not be found")
    print("  test_static_find_name_no_match: PASS")


def test_huffman_encode_decode_roundtrip() raises:
    var original = String("www.example.com")
    var encoded = huffman_encode(original)
    # Huffman-encoded "www.example.com" per RFC 7541 Appendix C.4.1
    # We verify roundtrip, not exact bytes (exact bytes verified by conformance test)
    var decoded = huffman_decode(encoded)
    assert_true(decoded == original, "roundtrip should reproduce original string")
    print("  test_huffman_encode_decode_roundtrip: PASS")


def test_huffman_encode_empty() raises:
    var encoded = huffman_encode(String(""))
    assert_equal_int(len(encoded), 0, "empty string should encode to zero bytes")
    var decoded = huffman_decode(encoded)
    assert_true(decoded == "", "empty encoded should decode to empty string")
    print("  test_huffman_encode_empty: PASS")


def test_huffman_decode_padding_ones() raises:
    # The last byte of a Huffman-encoded string is padded with 1-bits (EOS prefix)
    # Encoding "a" (RFC 7541: code=0x00000003, nbits=5 -> 0b00011 + 0b111 padding = 0x1F)
    # RFC 7541 Appendix B: 'a' = 5 bits, code 0x00000003 (binary: 00011)
    # padded to byte: 00011111 = 0x1F
    var data = List[UInt8]()
    data.append(0x1F)
    var decoded = huffman_decode(data)
    assert_true(decoded == "a", "0x1F should decode to 'a'")
    print("  test_huffman_decode_padding_ones: PASS")


def test_huffman_decode_bad_padding_raises() raises:
    # Last byte padded with 0-bits instead of 1-bits is invalid
    # 'a' = 00011, bad padding 000 => 00011000 = 0x18
    var data = List[UInt8]()
    data.append(0x18)
    var raised = False
    try:
        _ = huffman_decode(data)
    except:
        raised = True
    assert_true(raised, "should raise on bad padding")
    print("  test_huffman_decode_bad_padding_raises: PASS")


def test_huffman_decode_excess_padding_raises() raises:
    # More than 7 padding bits is invalid (RFC 7541 §5.2)
    # "a" (1 byte 0x1F) followed by 0xFF => excess padding
    var data = List[UInt8]()
    data.append(0x1F)
    data.append(0xFF)
    var raised = False
    try:
        _ = huffman_decode(data)
    except:
        raised = True
    assert_true(raised, "should raise on excess padding")
    print("  test_huffman_decode_excess_padding_raises: PASS")


def test_encode_prefix_two_zero_bytes() raises:
    # Any encoded block must start with [0x00, 0x00]
    var enc = QpackEncoder(False)
    var headers = List[QpackHeaderField]()
    headers.append(QpackHeaderField(":method", "GET"))
    var out = enc.encode(headers)
    assert_equal_int(Int(out[0]), 0x00, "first byte should be 0x00")
    assert_equal_int(Int(out[1]), 0x00, "second byte should be 0x00")
    print("  test_encode_prefix_two_zero_bytes: PASS")


def test_encode_indexed_static_method_get() raises:
    # :method GET is static index 17; wire = 0xC0 | 17 = 0xD1
    var enc = QpackEncoder(False)
    var headers = List[QpackHeaderField]()
    headers.append(QpackHeaderField(":method", "GET"))
    var out = enc.encode(headers)
    # prefix [0x00, 0x00] + indexed byte 0xD1
    assert_equal_int(len(out), 3, "output should be 3 bytes")
    assert_equal_int(Int(out[2]), 0xD1, "indexed :method GET should be 0xD1")
    print("  test_encode_indexed_static_method_get: PASS")


def test_encode_literal_name_ref() raises:
    # :method PATCH: name matches first :method entry at index 15, value does not
    # Verify: output is longer than indexed case, and roundtrip via decoder works
    var enc = QpackEncoder(False)
    var headers = List[QpackHeaderField]()
    headers.append(QpackHeaderField(":method", "PATCH"))
    var out = enc.encode(headers)
    assert_true(len(out) > 3, "literal encoding should be longer than indexed")
    # Verify via decoder
    var dec = QpackDecoder()
    var decoded = dec.decode(out)
    assert_equal_int(len(decoded), 1, "should decode 1 header")
    assert_true(decoded[0].name == ":method", "name should be :method")
    assert_true(decoded[0].value == "PATCH", "value should be PATCH")
    print("  test_encode_literal_name_ref: PASS")


def test_encode_literal_no_name_ref() raises:
    # x-custom: myval — not in static table
    var enc = QpackEncoder(False)
    var headers = List[QpackHeaderField]()
    headers.append(QpackHeaderField("x-custom", "myval"))
    var out = enc.encode(headers)
    var dec = QpackDecoder()
    var decoded = dec.decode(out)
    assert_equal_int(len(decoded), 1, "should decode 1 header")
    assert_true(decoded[0].name == "x-custom", "name should be x-custom")
    assert_true(decoded[0].value == "myval", "value should be myval")
    print("  test_encode_literal_no_name_ref: PASS")


def test_encode_multi_headers() raises:
    var enc = QpackEncoder(False)
    var headers = List[QpackHeaderField]()
    headers.append(QpackHeaderField(":method", "GET"))
    headers.append(QpackHeaderField(":path", "/"))
    headers.append(QpackHeaderField(":scheme", "https"))
    headers.append(QpackHeaderField(":authority", "example.com"))
    var out = enc.encode(headers)
    var dec = QpackDecoder()
    var decoded = dec.decode(out)
    assert_equal_int(len(decoded), 4, "should decode 4 headers")
    assert_true(decoded[0].name == ":method", "h0 name")
    assert_true(decoded[0].value == "GET", "h0 value")
    assert_true(decoded[1].name == ":path", "h1 name")
    assert_true(decoded[1].value == "/", "h1 value")
    assert_true(decoded[2].name == ":scheme", "h2 name")
    assert_true(decoded[2].value == "https", "h2 value")
    assert_true(decoded[3].name == ":authority", "h3 name")
    assert_true(decoded[3].value == "example.com", "h3 value")
    print("  test_encode_multi_headers: PASS")


def test_encode_huffman_disabled() raises:
    # With huffman=False, literal strings must not be Huffman-encoded
    var enc = QpackEncoder(False)
    var headers = List[QpackHeaderField]()
    headers.append(QpackHeaderField("x-test", "hello"))
    var out = enc.encode(headers)
    # Find "hello" in raw bytes (should appear as-is since no huffman)
    var found = False
    for i in range(len(out) - 4):
        if (out[i] == 0x68 and out[i+1] == 0x65 and out[i+2] == 0x6c
                and out[i+3] == 0x6c and out[i+4] == 0x6f):
            found = True
    assert_true(found, "hello bytes should appear unencoded")
    print("  test_encode_huffman_disabled: PASS")


def main() raises:
    print("=== test_h3_qpack ===")
    test_static_get_method_get()
    test_static_get_out_of_range_raises()
    test_static_find_exact_match()
    test_static_find_no_match()
    test_static_find_name_only()
    test_static_find_name_no_match()
    test_huffman_encode_decode_roundtrip()
    test_huffman_encode_empty()
    test_huffman_decode_padding_ones()
    test_huffman_decode_bad_padding_raises()
    test_huffman_decode_excess_padding_raises()
    test_encode_prefix_two_zero_bytes()
    test_encode_indexed_static_method_get()
    test_encode_literal_name_ref()
    test_encode_literal_no_name_ref()
    test_encode_multi_headers()
    test_encode_huffman_disabled()
    print("All tests passed.")
