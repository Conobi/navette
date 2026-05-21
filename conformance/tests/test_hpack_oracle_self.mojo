# conformance/tests/test_hpack_oracle_self.mojo
#
# AC0 — cross-validate the independent HPACK oracle (conformance/lib/http2/
# hpack_oracle.mojo) against RFC 7541 §C example wires.
#
# The "raw_data_stories" sidecar field is permanently empty in the baked
# hpack_states.json fixture, so the inline RFC §C vectors are the PRIMARY
# AC0 gate, not a fallback.

from lib.http2.hpack_oracle import HpackOracleDecoder, HpackOracleConfig
from lib.http1.types import Header
from lib.test_util import hex_decode, assert_true, assert_equal


def _wire(s: String) raises -> List[UInt8]:
    # Helper: strip spaces from hex, decode to bytes.
    var stripped = String("")
    var bs = s.as_bytes()
    for i in range(len(bs)):
        if bs[i] != UInt8(ord(" ")):
            stripped += chr(Int(bs[i]))
    return hex_decode(stripped)


def _assert_headers(
    got: List[Header], expected: List[Header], label: String
) raises:
    assert_equal(
        len(got),
        len(expected),
        label + ": header count (got " + String(len(got)) + ", expected " + String(len(expected)) + ")",
    )
    for i in range(len(got)):
        assert_true(
            got[i].name == expected[i].name,
            label + " hdr " + String(i) + " name: got '" + got[i].name + "' expected '" + expected[i].name + "'",
        )
        assert_true(
            got[i].value == expected[i].value,
            label + " hdr " + String(i) + " value: got '" + got[i].value + "' expected '" + expected[i].value + "'",
        )


def test_c21_literal_with_indexing() raises:
    # RFC 7541 §C.2.1
    var wire = _wire(String("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"))
    var dec = HpackOracleDecoder()
    var r = dec.decode(wire)
    assert_equal(r[1].byte_length(), 0, "C.2.1 decode error: " + r[1])
    var expected = List[Header]()
    expected.append(Header(String("custom-key"), String("custom-header")))
    _assert_headers(r[0], expected, String("C.2.1"))


def test_c22_literal_without_indexing() raises:
    # RFC 7541 §C.2.2 — literal w/o indexing, name from static idx 4 (:path)
    var wire = _wire(String("040c 2f73 616d 706c 652f 7061 7468"))
    var dec = HpackOracleDecoder()
    var r = dec.decode(wire)
    assert_equal(r[1].byte_length(), 0, "C.2.2 decode error: " + r[1])
    var expected = List[Header]()
    expected.append(Header(String(":path"), String("/sample/path")))
    _assert_headers(r[0], expected, String("C.2.2"))


def test_c23_literal_never_indexed() raises:
    # RFC 7541 §C.2.3 — literal never indexed, fresh name
    var wire = _wire(String("1008 7061 7373 776f 7264 0673 6563 7265 74"))
    var dec = HpackOracleDecoder()
    var r = dec.decode(wire)
    assert_equal(r[1].byte_length(), 0, "C.2.3 decode error: " + r[1])
    var expected = List[Header]()
    expected.append(Header(String("password"), String("secret")))
    _assert_headers(r[0], expected, String("C.2.3"))


def test_c24_indexed() raises:
    # RFC 7541 §C.2.4 — indexed (static idx 2 → :method: GET)
    var wire = _wire(String("82"))
    var dec = HpackOracleDecoder()
    var r = dec.decode(wire)
    assert_equal(r[1].byte_length(), 0, "C.2.4 decode error: " + r[1])
    var expected = List[Header]()
    expected.append(Header(String(":method"), String("GET")))
    _assert_headers(r[0], expected, String("C.2.4"))


def test_c3_request_chain_no_huffman() raises:
    # RFC 7541 §C.3 — sequence of three requests, dynamic-table-mediated
    var dec = HpackOracleDecoder()

    # C.3.1: GET http://www.example.com/
    var w1 = _wire(String("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"))
    var r1 = dec.decode(w1)
    assert_equal(r1[1].byte_length(), 0, "C.3.1 decode error: " + r1[1])
    var e1 = List[Header]()
    e1.append(Header(String(":method"), String("GET")))
    e1.append(Header(String(":scheme"), String("http")))
    e1.append(Header(String(":path"), String("/")))
    e1.append(Header(String(":authority"), String("www.example.com")))
    _assert_headers(r1[0], e1, String("C.3.1"))

    # C.3.2: GET http://www.example.com/ with no-cache
    var w2 = _wire(String("8286 84be 5808 6e6f 2d63 6163 6865"))
    var r2 = dec.decode(w2)
    assert_equal(r2[1].byte_length(), 0, "C.3.2 decode error: " + r2[1])
    var e2 = List[Header]()
    e2.append(Header(String(":method"), String("GET")))
    e2.append(Header(String(":scheme"), String("http")))
    e2.append(Header(String(":path"), String("/")))
    e2.append(Header(String(":authority"), String("www.example.com")))
    e2.append(Header(String("cache-control"), String("no-cache")))
    _assert_headers(r2[0], e2, String("C.3.2"))


def test_c4_huffman_request() raises:
    # RFC 7541 §C.4.1 — GET http://www.example.com/ with Huffman-encoded :authority
    var dec = HpackOracleDecoder()
    var wire = _wire(String("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"))
    var r = dec.decode(wire)
    assert_equal(r[1].byte_length(), 0, "C.4.1 decode error: " + r[1])
    var expected = List[Header]()
    expected.append(Header(String(":method"), String("GET")))
    expected.append(Header(String(":scheme"), String("http")))
    expected.append(Header(String(":path"), String("/")))
    expected.append(Header(String(":authority"), String("www.example.com")))
    _assert_headers(r[0], expected, String("C.4.1"))


def main() raises:
    test_c21_literal_with_indexing()
    print("  + C.2.1 literal-with-indexing")
    test_c22_literal_without_indexing()
    print("  + C.2.2 literal-without-indexing")
    test_c23_literal_never_indexed()
    print("  + C.2.3 literal-never-indexed")
    test_c24_indexed()
    print("  + C.2.4 indexed")
    test_c3_request_chain_no_huffman()
    print("  + C.3 request chain (dynamic table)")
    test_c4_huffman_request()
    print("  + C.4.1 huffman-encoded literal")
    print("test_hpack_oracle_self: 6 RFC 7541 §C vector groups cross-validated")
