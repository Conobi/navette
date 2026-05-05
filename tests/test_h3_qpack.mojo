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
    var decoded = huffman_decode(encoded)
    assert_true(decoded == original, "roundtrip should reproduce original string")
    print("  test_huffman_encode_decode_roundtrip: PASS")


def test_huffman_encode_known_vector() raises:
    # RFC 7541 C.4.1: Huffman encoding of "custom-key" = 0x25a849e95ba97d7f (8 bytes)
    var encoded = huffman_encode(String("custom-key"))
    assert_equal_int(len(encoded), 8, "custom-key should Huffman-encode to 8 bytes")
    assert_equal_int(Int(encoded[0]), 0x25, "byte 0")
    assert_equal_int(Int(encoded[1]), 0xa8, "byte 1")
    assert_equal_int(Int(encoded[2]), 0x49, "byte 2")
    assert_equal_int(Int(encoded[3]), 0xe9, "byte 3")
    assert_equal_int(Int(encoded[4]), 0x5b, "byte 4")
    assert_equal_int(Int(encoded[5]), 0xa9, "byte 5")
    assert_equal_int(Int(encoded[6]), 0x7d, "byte 6")
    assert_equal_int(Int(encoded[7]), 0x7f, "byte 7")
    print("  test_huffman_encode_known_vector: PASS")


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


def test_huffman_decode_eos_in_stream_raises() raises:
    # RFC 7541 §5.2 + Appendix B: EOS = 30 bits, code 0x3FFFFFFF.
    # Construct an explicit EOS at the start: 30 bits of 1s + 2 padding 1s = 4
    # bytes of 0xFF — this is the "all-ones across 4 bytes" case the TQUIC
    # `huffman_decode_invalid_without_eos` test (huffman.rs:5330) flags as an
    # invalid input the decoder must reject.
    var data = List[UInt8]()
    data.append(0x3F)
    data.append(0xFF)
    data.append(0xFF)
    data.append(0xFE)
    var raised = False
    try:
        _ = huffman_decode(data)
    except:
        raised = True
    assert_true(raised, "should raise on EOS-in-stream (TQUIC-style)")
    print("  test_huffman_decode_eos_in_stream_raises: PASS")


def test_huffman_decode_long_code() raises:
    # Round-trip a string containing chars whose Huffman codes are ≥9 bits,
    # exercising the Tier-2 trie fallback.
    # Per RFC 7541 Appendix B: '!' (33) = 10 bits, '#' (35) = 12 bits,
    # '$' (36) = 13 bits. All are valid UTF-8 (printable ASCII).
    var s = String("a!#$a")
    var encoded = huffman_encode(s)
    var decoded = huffman_decode(encoded)
    assert_true(decoded == s, "long-code roundtrip should match")
    print("  test_huffman_decode_long_code: PASS")


def test_huffman_decode_all_ascii_fast_path() raises:
    # All chars in this string have Huffman code length ≤8 bits, so every byte
    # resolves via the Tier-1 256-entry root fast-path.
    var s = String("abcdefghijklmnopqrstuvwxyz0123456789")
    var encoded = huffman_encode(s)
    var decoded = huffman_decode(encoded)
    assert_true(decoded == s, "all-ASCII fast-path roundtrip should match")
    print("  test_huffman_decode_all_ascii_fast_path: PASS")


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
    # :method PATCH: name matches first :method entry (index 15), value not in table.
    # §4.5.4 wire format (use_huffman=False):
    #   prefix     [0x00, 0x00]
    #   §4.5.4     [0x5F, 0x00]  — 0x50 | 4-bit int(15); 15==max_first → 2 bytes
    #   value      [0x05, 'P','A','T','C','H']  — H=0, length=5
    var enc = QpackEncoder(False)
    var headers = List[QpackHeaderField]()
    headers.append(QpackHeaderField(":method", "PATCH"))
    var out = enc.encode(headers)
    assert_equal_int(len(out), 10, "wire length should be 10 bytes")
    assert_equal_int(Int(out[0]), 0x00, "prefix byte 0")
    assert_equal_int(Int(out[1]), 0x00, "prefix byte 1")
    assert_equal_int(Int(out[2]), 0x5F, "§4.5.4 first byte: N=0 T=1 index=15 multi-byte")
    assert_equal_int(Int(out[3]), 0x00, "§4.5.4 second byte: remainder=0")
    assert_equal_int(Int(out[4]), 0x05, "value: H=0, length=5")
    assert_equal_int(Int(out[5]), 0x50, "value: 'P'")
    assert_equal_int(Int(out[6]), 0x41, "value: 'A'")
    assert_equal_int(Int(out[7]), 0x54, "value: 'T'")
    assert_equal_int(Int(out[8]), 0x43, "value: 'C'")
    assert_equal_int(Int(out[9]), 0x48, "value: 'H'")
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


def test_decode_indexed_static() raises:
    # [0x00, 0x00, 0xD1] = prefix + indexed :method GET (index 17, wire=0xC0|17=0xD1)
    var data = List[UInt8]()
    data.append(0x00)
    data.append(0x00)
    data.append(0xD1)  # 0xC0 | 17
    var dec = QpackDecoder()
    var headers = dec.decode(data)
    assert_equal_int(len(headers), 1, "should decode 1 header")
    assert_true(headers[0].name == ":method", "name should be :method")
    assert_true(headers[0].value == "GET", "value should be GET")
    print("  test_decode_indexed_static: PASS")


def test_decode_literal_name_ref() raises:
    # Decode known-correct §4.5.4 wire bytes for :method PATCH (use_huffman=False).
    # Same bytes as oracle (pylsqpack) for :method PATCH field alone.
    # [0x00, 0x00, 0x5F, 0x00, 0x05, 'P','A','T','C','H']
    var data = List[UInt8]()
    data.append(0x00)  # RIC=0
    data.append(0x00)  # S=0, delta=0
    data.append(0x5F)  # §4.5.4: N=0, T=1 (static), index=15 multi-byte first byte
    data.append(0x00)  # index remainder = 0 → index = 15
    data.append(0x05)  # H=0, length=5
    data.append(0x50)  # 'P'
    data.append(0x41)  # 'A'
    data.append(0x54)  # 'T'
    data.append(0x43)  # 'C'
    data.append(0x48)  # 'H'
    var dec = QpackDecoder()
    var headers = dec.decode(data)
    assert_equal_int(len(headers), 1, "should decode 1 header")
    assert_true(headers[0].name == ":method", "name should be :method")
    assert_true(headers[0].value == "PATCH", "value should be PATCH")
    print("  test_decode_literal_name_ref: PASS")


def test_decode_literal_no_name_ref() raises:
    var enc = QpackEncoder(False)
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField("x-custom", "hello"))
    var encoded = enc.encode(fields)
    var dec = QpackDecoder()
    var headers = dec.decode(encoded)
    assert_equal_int(len(headers), 1, "should decode 1 header")
    assert_true(headers[0].name == "x-custom", "name should be x-custom")
    assert_true(headers[0].value == "hello", "value should be hello")
    print("  test_decode_literal_no_name_ref: PASS")


def test_decode_huffman_value() raises:
    # Encode with Huffman enabled, then decode
    var enc = QpackEncoder(True)
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField("x-custom", "world"))
    var encoded = enc.encode(fields)
    var dec = QpackDecoder()
    var headers = dec.decode(encoded)
    assert_equal_int(len(headers), 1, "should decode 1 header")
    assert_true(headers[0].value == "world", "value should be world")
    print("  test_decode_huffman_value: PASS")


def test_decode_nonzero_insert_count_raises() raises:
    # Required Insert Count must be 0 for static-only
    var data = List[UInt8]()
    data.append(0x02)  # non-zero RIC
    data.append(0x00)
    var dec = QpackDecoder()
    var raised = False
    try:
        _ = dec.decode(data)
    except:
        raised = True
    assert_true(raised, "should raise on non-zero insert count")
    print("  test_decode_nonzero_insert_count_raises: PASS")


def test_decode_truncated_raises() raises:
    # Truncated literal (half of a literal field line)
    var enc2 = QpackEncoder(False)
    var f2 = List[QpackHeaderField]()
    f2.append(QpackHeaderField("x-header", "longvalue"))
    var e2 = enc2.encode(f2)
    # Take only first half (truncated)
    var half = List[UInt8]()
    for i in range(len(e2) // 2):
        half.append(e2[i])
    var dec = QpackDecoder()
    var raised = False
    try:
        _ = dec.decode(half)
    except:
        raised = True
    assert_true(raised, "should raise on truncated data")
    print("  test_decode_truncated_raises: PASS")


def test_decode_multi_fields() raises:
    var enc = QpackEncoder(False)
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":method", "GET"))
    fields.append(QpackHeaderField(":path", "/"))
    fields.append(QpackHeaderField(":scheme", "https"))
    var encoded = enc.encode(fields)
    var dec = QpackDecoder()
    var headers = dec.decode(encoded)
    assert_equal_int(len(headers), 3, "should decode 3 headers")
    assert_true(headers[0].name == ":method", "h0 name should be :method")
    assert_true(headers[1].name == ":path", "h1 name should be :path")
    assert_true(headers[2].name == ":scheme", "h2 name should be :scheme")
    print("  test_decode_multi_fields: PASS")


def test_decode_static_index_out_of_range_raises() raises:
    # Indexed-static flag with an out-of-range index
    var data = List[UInt8]()
    data.append(0x00)
    data.append(0x00)
    # Build a multi-byte indexed static with large index (>>99)
    # 0xFF = 0xC0 | 0x3F (max_first for 6-bit prefix = 63)
    data.append(0xFF)         # first byte: indexed static, max_first = 63
    data.append(0x80 | 50)   # continuation: adds 50*128 to 63 = 6463
    data.append(0x00)         # end continuation
    var dec = QpackDecoder()
    var raised = False
    try:
        _ = dec.decode(data)
    except:
        raised = True
    assert_true(raised, "should raise on out-of-range static index")
    print("  test_decode_static_index_out_of_range_raises: PASS")


def test_decode_s_bit_raises() raises:
    # S=1 in the Delta Base byte means negative delta — not supported
    var data = List[UInt8]()
    data.append(0x00)  # RIC=0
    data.append(0x80)  # S=1 (bit 7 set), Delta Base=0
    var dec = QpackDecoder()
    var raised = False
    try:
        _ = dec.decode(data)
    except:
        raised = True
    assert_true(raised, "should raise on S=1 in Delta Base")
    print("  test_decode_s_bit_raises: PASS")


def main() raises:
    print("=== test_h3_qpack ===")
    test_static_get_method_get()
    test_static_get_out_of_range_raises()
    test_static_find_exact_match()
    test_static_find_no_match()
    test_static_find_name_only()
    test_static_find_name_no_match()
    test_huffman_encode_decode_roundtrip()
    test_huffman_encode_known_vector()
    test_huffman_encode_empty()
    test_huffman_decode_padding_ones()
    test_huffman_decode_bad_padding_raises()
    test_huffman_decode_excess_padding_raises()
    test_huffman_decode_eos_in_stream_raises()
    test_huffman_decode_long_code()
    test_huffman_decode_all_ascii_fast_path()
    test_encode_prefix_two_zero_bytes()
    test_encode_indexed_static_method_get()
    test_encode_literal_name_ref()
    test_encode_literal_no_name_ref()
    test_encode_multi_headers()
    test_encode_huffman_disabled()
    test_decode_indexed_static()
    test_decode_literal_name_ref()
    test_decode_literal_no_name_ref()
    test_decode_huffman_value()
    test_decode_nonzero_insert_count_raises()
    test_decode_truncated_raises()
    test_decode_multi_fields()
    test_decode_static_index_out_of_range_raises()
    test_decode_s_bit_raises()
    print("All tests passed.")
