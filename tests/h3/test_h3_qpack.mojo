# tests/test_h3_qpack.mojo
# QPACK static table tests — RFC 9204 Appendix A
# Task 2: static table only (Huffman, encoder, decoder in T3-T5)

from navette.h3.qpack import (
    QpackStaticEntry,
    FieldSection,
    QPACK_STATIC_TABLE_SIZE,
    qpack_static_get,
    qpack_static_find,
    qpack_static_find_name,
    huffman_encode,
    huffman_decode,
    QpackEncoder,
    QpackDecoder,
)
from navette.http.headers import Headers
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
    var encoded = List[Byte]()
    huffman_encode(encoded, original)
    var decoded = huffman_decode(encoded)
    assert_true(decoded == original, "roundtrip should reproduce original string")
    print("  test_huffman_encode_decode_roundtrip: PASS")


def test_huffman_encode_known_vector() raises:
    # RFC 7541 C.4.1: Huffman encoding of "custom-key" = 0x25a849e95ba97d7f (8 bytes)
    var encoded = List[Byte]()
    huffman_encode(encoded, String("custom-key"))
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
    var encoded = List[Byte]()
    huffman_encode(encoded, String(""))
    assert_equal_int(len(encoded), 0, "empty string should encode to zero bytes")
    var decoded = huffman_decode(encoded)
    assert_true(decoded == "", "empty encoded should decode to empty string")
    print("  test_huffman_encode_empty: PASS")


def test_huffman_decode_padding_ones() raises:
    # The last byte of a Huffman-encoded string is padded with 1-bits (EOS prefix)
    # Encoding "a" (RFC 7541: code=0x00000003, nbits=5 -> 0b00011 + 0b111 padding = 0x1F)
    # RFC 7541 Appendix B: 'a' = 5 bits, code 0x00000003 (binary: 00011)
    # padded to byte: 00011111 = 0x1F
    var data = List[Byte]()
    data.append(0x1F)
    var decoded = huffman_decode(data)
    assert_true(decoded == "a", "0x1F should decode to 'a'")
    print("  test_huffman_decode_padding_ones: PASS")


def test_huffman_decode_bad_padding_raises() raises:
    # Last byte padded with 0-bits instead of 1-bits is invalid
    # 'a' = 00011, bad padding 000 => 00011000 = 0x18
    var data = List[Byte]()
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
    var data = List[Byte]()
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
    var data = List[Byte]()
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
    var encoded = List[Byte]()
    huffman_encode(encoded, s)
    var decoded = huffman_decode(encoded)
    assert_true(decoded == s, "long-code roundtrip should match")
    print("  test_huffman_decode_long_code: PASS")


def test_huffman_decode_all_ascii_fast_path() raises:
    # All chars in this string have Huffman code length ≤8 bits, so every byte
    # resolves via the Tier-1 256-entry root fast-path.
    var s = String("abcdefghijklmnopqrstuvwxyz0123456789")
    var encoded = List[Byte]()
    huffman_encode(encoded, s)
    var decoded = huffman_decode(encoded)
    assert_true(decoded == s, "all-ASCII fast-path roundtrip should match")
    print("  test_huffman_decode_all_ascii_fast_path: PASS")


def _one(name: String, value: String) -> FieldSection:
    var h = Headers()
    h.add(name, value)
    return FieldSection(headers=h^)


def test_encode_prefix_two_zero_bytes() raises:
    # Any encoded block must start with [0x00, 0x00]
    var enc = QpackEncoder(False)
    var out = List[Byte]()
    enc.encode(out, FieldSection(method="GET"))
    assert_equal_int(Int(out[0]), 0x00, "first byte should be 0x00")
    assert_equal_int(Int(out[1]), 0x00, "second byte should be 0x00")
    print("  test_encode_prefix_two_zero_bytes: PASS")


def test_encode_indexed_static_method_get() raises:
    # :method GET is static index 17; wire = 0xC0 | 17 = 0xD1
    var enc = QpackEncoder(False)
    var out = List[Byte]()
    enc.encode(out, FieldSection(method="GET"))
    # prefix [0x00, 0x00] + indexed byte 0xD1
    assert_equal_int(len(out), 3, "output should be 3 bytes")
    assert_equal_int(Int(out[2]), 0xD1, "indexed :method GET should be 0xD1")
    print("  test_encode_indexed_static_method_get: PASS")


def test_encode_literal_name_ref() raises:
    # :method PATCH: name matches first :method entry (index 15), value not in table.
    # Section 4.5.4 wire format (use_huffman=False):
    #   prefix     [0x00, 0x00]
    #   4.5.4      [0x5F, 0x00]  — 0x50 | 4-bit int(15); 15==max_first → 2 bytes
    #   value      [0x05, 'P','A','T','C','H']  — H=0, length=5
    var enc = QpackEncoder(False)
    var out = List[Byte]()
    enc.encode(out, FieldSection(method="PATCH"))
    assert_equal_int(len(out), 10, "wire length should be 10 bytes")
    assert_equal_int(Int(out[0]), 0x00, "prefix byte 0")
    assert_equal_int(Int(out[1]), 0x00, "prefix byte 1")
    assert_equal_int(Int(out[2]), 0x5F, "4.5.4 first byte: N=0 T=1 index=15 multi-byte")
    assert_equal_int(Int(out[3]), 0x00, "4.5.4 second byte: remainder=0")
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
    var out = List[Byte]()
    enc.encode(out, _one("x-custom", "myval"))
    var dec = QpackDecoder()
    var decoded = dec.decode(out)
    assert_equal_int(len(decoded.headers), 1, "should decode 1 header")
    assert_true(decoded.headers.name_at(0) == "x-custom", "name should be x-custom")
    assert_true(decoded.headers.value_at(0) == "myval", "value should be myval")
    print("  test_encode_literal_no_name_ref: PASS")


def test_encode_multi_headers() raises:
    """Every known pseudo-header and regular fields round-trip, in wire order."""
    var enc = QpackEncoder(False)
    var h = Headers()
    h.add("x-a", "1")
    h.add("x-b", "2")
    var out = List[Byte]()
    enc.encode(out, FieldSection(
        method="GET", scheme="https", authority="example.com", path="/", status="200", headers=h^
    ))
    var dec = QpackDecoder()
    var decoded = dec.decode(out)
    assert_true(decoded.method == "GET", ":method")
    assert_true(decoded.scheme == "https", ":scheme")
    assert_true(decoded.authority == "example.com", ":authority")
    assert_true(decoded.path == "/", ":path")
    assert_true(decoded.status == "200", ":status")
    assert_equal_int(len(decoded.headers), 2, "two regular fields")
    assert_true(decoded.headers.name_at(0) == "x-a" and decoded.headers.value_at(1) == "2", "regular fields in order")
    print("  test_encode_multi_headers: PASS")


def test_encode_huffman_disabled() raises:
    # With huffman=False, literal strings must not be Huffman-encoded
    var enc = QpackEncoder(False)
    var out = List[Byte]()
    enc.encode(out, _one("x-test", "hello"))
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
    var data: List[Byte] = [0x00, 0x00, 0xD1]
    var dec = QpackDecoder()
    var section = dec.decode(data)
    assert_true(section.method == "GET", ":method should be GET")
    assert_equal_int(len(section.headers), 0, "no regular fields")
    print("  test_decode_indexed_static: PASS")


def test_decode_literal_name_ref() raises:
    # Decode known-correct Section 4.5.4 wire bytes for :method PATCH (use_huffman=False).
    # Same bytes as oracle (pylsqpack) for :method PATCH field alone.
    # [0x00, 0x00, 0x5F, 0x00, 0x05, 'P','A','T','C','H']
    var data: List[Byte] = [0x00, 0x00, 0x5F, 0x00, 0x05, 0x50, 0x41, 0x54, 0x43, 0x48]
    var dec = QpackDecoder()
    var section = dec.decode(data)
    assert_true(section.method == "PATCH", ":method should be PATCH")
    assert_equal_int(len(section.headers), 0, "no regular fields")
    print("  test_decode_literal_name_ref: PASS")


def test_decode_huffman_value() raises:
    # Encode with Huffman enabled, then decode
    var enc = QpackEncoder(True)
    var encoded = List[Byte]()
    enc.encode(encoded, _one("x-custom", "world"))
    var dec = QpackDecoder()
    var section = dec.decode(encoded)
    assert_equal_int(len(section.headers), 1, "should decode 1 header")
    assert_true(section.headers.value_at(0) == "world", "value should be world")
    print("  test_decode_huffman_value: PASS")


def test_decode_nonzero_insert_count_raises() raises:
    # Required Insert Count must be 0 for static-only
    var data = List[Byte]()
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
    var e2 = List[Byte]()
    enc2.encode(e2, _one("x-header", "longvalue"))
    # Take only first half (truncated)
    var half = List[Byte]()
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


def test_decode_pseudo_header_routing() raises:
    """Unknown pseudo-headers stay in `headers` in wire order; a repeated known one keeps its last value."""
    # Raw literals (Section 4.5.6): ":protocol: x", ":path: /a", then indexed ":path /".
    var data: List[Byte] = [0x00, 0x00, 0x27, 0x02, 0x3A, 0x70, 0x72, 0x6F, 0x74, 0x6F, 0x63, 0x6F, 0x6C, 0x01, 0x78]
    data.extend([UInt8(0x25), 0x3A, 0x70, 0x61, 0x74, 0x68, 0x02, 0x2F, 0x61, 0xC1])
    var dec = QpackDecoder()
    var section = dec.decode(data)
    assert_true(section.path == "/", "last :path wins")
    assert_equal_int(len(section.headers), 1, "unknown pseudo-header kept")
    assert_true(section.headers.name_at(0) == ":protocol" and section.headers.value_at(0) == "x", ":protocol in headers")
    print("  test_decode_pseudo_header_routing: PASS")


def test_decode_static_index_out_of_range_raises() raises:
    # Indexed-static flag with an out-of-range index
    var data = List[Byte]()
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


def test_decode_span_strings() raises:
    # Section 4.5.6 raw name + raw value, both zero length.
    var dec = QpackDecoder()
    var empty_block: List[Byte] = [0x00, 0x00, 0x20, 0x00]
    var empty = dec.decode(empty_block)
    assert_equal_int(len(empty.headers), 1, "exactly one field")
    assert_true(empty.headers.name_at(0) == "" and empty.headers.value_at(0) == "", "zero-length name and value")
    # Section 4.5.6 Huffman name + Huffman value round-trip, then raw/raw.
    for huff in range(2):
        var enc = QpackEncoder(huff == 1)
        var encoded = List[Byte]()
        enc.encode(encoded, _one("x-span-name", "some longer value past 23 bytes"))
        var f = dec.decode(encoded)
        assert_equal_int(len(f.headers), 1, "exactly one field")
        assert_true(f.headers.name_at(0) == "x-span-name", "name round-trips")
        assert_true(f.headers.value_at(0) == "some longer value past 23 bytes", "value round-trips")
    # Section 4.5.4 static name ref (:method) with a raw value byte >= 0x80: Latin-1 transcode.
    var latin_block: List[Byte] = [0x00, 0x00, 0x5F, 0x00, 0x02, 0x41, 0xE9]
    var latin = dec.decode(latin_block)
    assert_true(latin.method == "A" + chr(0xE9), "0xE9 decodes as U+00E9")
    print("  test_decode_span_strings: PASS")


def test_decode_string_past_block_raises() raises:
    # Value length 5 with only 4 bytes left; then a name length past the end.
    var cases: List[List[Byte]] = [
        [0x00, 0x00, 0x5F, 0x00, 0x05, 0x41, 0x42, 0x43, 0x44],
        [0x00, 0x00, 0x23, 0x61, 0x62],
    ]
    for ref data in cases:
        var raised = False
        try:
            var dec = QpackDecoder()
            _ = dec.decode(data)
        except:
            raised = True
        assert_true(raised, "string running past the block must raise")
    print("  test_decode_string_past_block_raises: PASS")


def test_decode_size_cap_boundary() raises:
    # Two indexed fields: ":path /" (5+1+32=38) and ":method GET" (7+3+32=42) = 80.
    var data: List[Byte] = [0x00, 0x00, 0xC1, 0xD1]
    var dec = QpackDecoder()
    assert_true(Bool(dec.decode_bounded(data, 80)), "exactly the cap decodes")
    assert_false(Bool(dec.decode_bounded(data, 79)), "cap+1 returns None")
    assert_false(Bool(dec.decode_bounded(data, 37)), "a first field over the cap returns None")
    print("  test_decode_size_cap_boundary: PASS")


def test_encode_field_all_three_paths() raises:
    """Exercises exact-match, name-only, and literal paths through the index."""
    var enc = QpackEncoder(use_huffman=False)

    # Exact static match: (:method, GET) = index 17
    var exact_bytes = List[Byte]()
    enc.encode(exact_bytes, FieldSection(method="GET"))
    assert_true(len(exact_bytes) == 3, "exact: 2-byte prefix + 1 indexed")
    assert_true(Int(exact_bytes[2]) == 0xD1, "exact: 0xC0 | 17")

    # Name-only: (:authority, example.com) — name at index 0, value literal
    var name_bytes = List[Byte]()
    enc.encode(name_bytes, FieldSection(authority="example.com"))
    assert_true(Int(name_bytes[2]) == 0x50, "name-ref: 0x50 | 0")

    # Literal: (x-custom, val) — no match
    var lit_bytes = List[Byte]()
    enc.encode(lit_bytes, _one("x-custom", "val"))
    assert_true(Int(lit_bytes[2]) & 0xE0 == 0x20, "literal: starts with 001xxxxx")

    print("  test_encode_field_all_three_paths: PASS")


def test_decode_s_bit_raises() raises:
    # S=1 in the Delta Base byte means negative delta — not supported
    var data = List[Byte]()
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


def test_static_table_full_surface() raises:
    """Validate every QPACK static table entry against RFC 9204 Appendix A."""
    # Interleaved (name, value) — independently typed from the RFC, not
    # copy-pasted from production code.
    var expected: List[String] = [
        ":authority", "",  ":path", "/",  "age", "0",  "content-disposition", "",
        "content-length", "0",  "cookie", "",  "date", "",  "etag", "",
        "if-modified-since", "",  "if-none-match", "",  "last-modified", "",  "link", "",
        "location", "",  "referer", "",  "set-cookie", "",  ":method", "CONNECT",
        ":method", "DELETE",  ":method", "GET",  ":method", "HEAD",  ":method", "OPTIONS",
        ":method", "POST",  ":method", "PUT",  ":scheme", "http",  ":scheme", "https",
        ":status", "103",  ":status", "200",  ":status", "304",  ":status", "404",
        ":status", "503",  "accept", "*/*",  "accept", "application/dns-message",
        "accept-encoding", "gzip, deflate, br",  "accept-ranges", "bytes",
        "access-control-allow-headers", "cache-control",
        "access-control-allow-headers", "content-type",
        "access-control-allow-origin", "*",
        "cache-control", "max-age=0",  "cache-control", "max-age=2592000",
        "cache-control", "max-age=604800",  "cache-control", "no-cache",
        "cache-control", "no-store",  "cache-control", "public, max-age=31536000",
        "content-encoding", "br",  "content-encoding", "gzip",
        "content-type", "application/dns-message",  "content-type", "application/javascript",
        "content-type", "application/json",
        "content-type", "application/x-www-form-urlencoded",
        "content-type", "image/gif",  "content-type", "image/jpeg",
        "content-type", "image/png",  "content-type", "text/css",
        "content-type", "text/html; charset=utf-8",  "content-type", "text/plain",
        "content-type", "text/plain;charset=utf-8",  "range", "bytes=0-",
        "strict-transport-security", "max-age=31536000",
        "strict-transport-security", "max-age=31536000; includesubdomains",
        "strict-transport-security", "max-age=31536000; includesubdomains; preload",
        "vary", "accept-encoding",  "vary", "origin",
        "x-content-type-options", "nosniff",  "x-xss-protection", "1; mode=block",
        ":status", "100",  ":status", "204",  ":status", "206",  ":status", "302",
        ":status", "400",  ":status", "403",  ":status", "421",  ":status", "425",
        ":status", "500",  "accept-language", "",
        "access-control-allow-credentials", "FALSE",
        "access-control-allow-credentials", "TRUE",
        "access-control-allow-headers", "*",
        "access-control-allow-methods", "get",
        "access-control-allow-methods", "get, post, options",
        "access-control-allow-methods", "options",
        "access-control-expose-headers", "content-length",
        "access-control-request-headers", "content-type",
        "access-control-request-method", "get",
        "access-control-request-method", "post",
        "alt-svc", "clear",  "authorization", "",
        "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'",
        "early-data", "1",  "expect-ct", "",  "forwarded", "",  "if-range", "",
        "origin", "",  "purpose", "prefetch",  "server", "",
        "timing-allow-origin", "*",  "upgrade-insecure-requests", "1",
        "user-agent", "",  "x-forwarded-for", "",
        "x-frame-options", "deny",  "x-frame-options", "sameorigin",
    ]
    assert_equal_int(QPACK_STATIC_TABLE_SIZE, 99, "QPACK_STATIC_TABLE_SIZE must be 99")
    assert_equal_int(len(expected), 198, "oracle data must have 198 elements (99 pairs)")
    for i in range(99):
        var entry = qpack_static_get(i)
        var exp_name = expected[i * 2]
        var exp_value = expected[i * 2 + 1]
        if entry.name != exp_name or entry.value != exp_value:
            raise Error(
                "QPACK static table mismatch at index " + String(i)
                + ": expected (" + exp_name + ", " + exp_value
                + ") got (" + entry.name + ", " + entry.value + ")"
            )
    print("  test_static_table_full_surface: PASS (99/99 entries verified)")


def main() raises:
    print("=== test_h3_qpack ===")
    test_static_table_full_surface()
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
    test_decode_huffman_value()
    test_decode_nonzero_insert_count_raises()
    test_decode_truncated_raises()
    test_decode_pseudo_header_routing()
    test_decode_static_index_out_of_range_raises()
    test_decode_s_bit_raises()
    test_encode_field_all_three_paths()
    test_decode_span_strings()
    test_decode_string_past_block_raises()
    test_decode_size_cap_boundary()
    print("All tests passed.")
