# conformance/tests/test_hpack_huffman.mojo
#
# HC-3b Task 2: HPACK Huffman encoder/decoder tests.
# Validates encode, decode, roundtrip for all single-byte values,
# known RFC strings, padding edge cases, empty input, and random
# anti-cheat sequences.
from lib.test_util import (
    hex_decode,
    hex_encode,
    assert_true,
    assert_equal,
    assert_bytes_equal,
)
from lib.http2.hpack_huffman import HuffmanCodec
from std.time import perf_counter_ns


def _string_to_bytes(s: String) -> List[UInt8]:
    """Convert a String to a List[UInt8]."""
    var result = List[UInt8]()
    var raw = s.as_bytes()
    for i in range(len(raw)):
        result.append(raw[i])
    return result^


def _bytes_to_string(data: List[UInt8]) -> String:
    """Convert a List[UInt8] to a String (ASCII only)."""
    var result = String()
    for i in range(len(data)):
        # Build one-char string via chr-like approach
        var buf = List[UInt8]()
        buf.append(data[i])
        buf.append(0)  # null terminator
        result += String(buf^)
    return result^


def main() raises:
    # ---- Sentinel anti-cheat: verify assert_true actually fires ----
    var sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        sentinel_ok = True
    assert_true(sentinel_ok, "assertions are not firing")

    var codec = HuffmanCodec()
    print("  HuffmanCodec constructed (trie nodes: " + String(len(codec._trie)) + ")")

    # ================================================================
    # 1. Roundtrip all 256 single-byte values
    # ================================================================
    var single_pass = 0
    for byte_val in range(256):
        var input_data = List[UInt8]()
        input_data.append(UInt8(byte_val))

        var encoded = codec.encode(input_data)
        assert_true(
            len(encoded) > 0,
            "encode of byte " + String(byte_val) + " produced empty output",
        )

        var dec_result = codec.decode(encoded)
        var decoded = dec_result[0].copy()
        var err = dec_result[1].copy()
        assert_true(
            len(err) == 0,
            "decode error for byte "
            + String(byte_val)
            + ": "
            + err,
        )
        assert_equal(
            len(decoded),
            1,
            "roundtrip byte " + String(byte_val) + " length",
        )
        assert_equal(
            Int(decoded[0]),
            byte_val,
            "roundtrip byte " + String(byte_val) + " value",
        )
        single_pass += 1

    print("  [PASS] roundtrip all 256 single-byte values (" + String(single_pass) + ")")

    # ================================================================
    # 2. Known RFC strings (verified against Python hpack library)
    # ================================================================

    # Helper: test encode produces expected hex and decode roundtrips
    # Test case: (input_string, expected_hex)
    # Verified with Python hpack 4.1.0

    # "www.example.com" -> f1e3c2e5f23a6ba0ab90f4ff
    var www_input = _string_to_bytes("www.example.com")
    var www_expected = hex_decode("f1e3c2e5f23a6ba0ab90f4ff")
    var www_encoded = codec.encode(www_input)
    assert_bytes_equal(www_encoded, www_expected, "encode www.example.com")
    var www_dec = codec.decode(www_encoded)
    assert_true(len(www_dec[1]) == 0, "decode www.example.com error: " + www_dec[1])
    assert_bytes_equal(www_dec[0], www_input, "roundtrip www.example.com")
    print("  [PASS] www.example.com")

    # "no-cache" -> a8eb10649cbf
    var nc_input = _string_to_bytes("no-cache")
    var nc_expected = hex_decode("a8eb10649cbf")
    var nc_encoded = codec.encode(nc_input)
    assert_bytes_equal(nc_encoded, nc_expected, "encode no-cache")
    var nc_dec = codec.decode(nc_encoded)
    assert_true(len(nc_dec[1]) == 0, "decode no-cache error: " + nc_dec[1])
    assert_bytes_equal(nc_dec[0], nc_input, "roundtrip no-cache")
    print("  [PASS] no-cache")

    # "custom-key" -> 25a849e95ba97d7f
    var ck_input = _string_to_bytes("custom-key")
    var ck_expected = hex_decode("25a849e95ba97d7f")
    var ck_encoded = codec.encode(ck_input)
    assert_bytes_equal(ck_encoded, ck_expected, "encode custom-key")
    var ck_dec = codec.decode(ck_encoded)
    assert_true(len(ck_dec[1]) == 0, "decode custom-key error: " + ck_dec[1])
    assert_bytes_equal(ck_dec[0], ck_input, "roundtrip custom-key")
    print("  [PASS] custom-key")

    # "custom-value" -> 25a849e95bb8e8b4bf
    var cv_input = _string_to_bytes("custom-value")
    var cv_expected = hex_decode("25a849e95bb8e8b4bf")
    var cv_encoded = codec.encode(cv_input)
    assert_bytes_equal(cv_encoded, cv_expected, "encode custom-value")
    var cv_dec = codec.decode(cv_encoded)
    assert_true(len(cv_dec[1]) == 0, "decode custom-value error: " + cv_dec[1])
    assert_bytes_equal(cv_dec[0], cv_input, "roundtrip custom-value")
    print("  [PASS] custom-value")

    # "302" -> 6402
    var s302_input = _string_to_bytes("302")
    var s302_expected = hex_decode("6402")
    var s302_encoded = codec.encode(s302_input)
    assert_bytes_equal(s302_encoded, s302_expected, "encode 302")
    var s302_dec = codec.decode(s302_encoded)
    assert_true(len(s302_dec[1]) == 0, "decode 302 error: " + s302_dec[1])
    assert_bytes_equal(s302_dec[0], s302_input, "roundtrip 302")
    print("  [PASS] 302")

    # "private" -> aec3771a4b
    var priv_input = _string_to_bytes("private")
    var priv_expected = hex_decode("aec3771a4b")
    var priv_encoded = codec.encode(priv_input)
    assert_bytes_equal(priv_encoded, priv_expected, "encode private")
    var priv_dec = codec.decode(priv_encoded)
    assert_true(len(priv_dec[1]) == 0, "decode private error: " + priv_dec[1])
    assert_bytes_equal(priv_dec[0], priv_input, "roundtrip private")
    print("  [PASS] private")

    # "Mon, 21 Oct 2013 20:13:21 GMT" -> d07abe941054d444a8200595040b8166e082a62d1bff
    var date_input = _string_to_bytes("Mon, 21 Oct 2013 20:13:21 GMT")
    var date_expected = hex_decode("d07abe941054d444a8200595040b8166e082a62d1bff")
    var date_encoded = codec.encode(date_input)
    assert_bytes_equal(date_encoded, date_expected, "encode date string")
    var date_dec = codec.decode(date_encoded)
    assert_true(len(date_dec[1]) == 0, "decode date error: " + date_dec[1])
    assert_bytes_equal(date_dec[0], date_input, "roundtrip date string")
    print("  [PASS] Mon, 21 Oct 2013 20:13:21 GMT")

    # "https://www.example.com" -> 9d29ad171863c78f0b97c8e9ae82ae43d3
    var url_input = _string_to_bytes("https://www.example.com")
    var url_expected = hex_decode("9d29ad171863c78f0b97c8e9ae82ae43d3")
    var url_encoded = codec.encode(url_input)
    assert_bytes_equal(url_encoded, url_expected, "encode URL")
    var url_dec = codec.decode(url_encoded)
    assert_true(len(url_dec[1]) == 0, "decode URL error: " + url_dec[1])
    assert_bytes_equal(url_dec[0], url_input, "roundtrip URL")
    print("  [PASS] https://www.example.com")

    # ================================================================
    # 3. Empty input: encode/decode empty -> empty
    # ================================================================
    var empty_input = List[UInt8]()
    var empty_encoded = codec.encode(empty_input)
    assert_equal(len(empty_encoded), 0, "encode empty length")
    var empty_dec = codec.decode(empty_encoded)
    assert_true(len(empty_dec[1]) == 0, "decode empty error: " + empty_dec[1])
    assert_equal(len(empty_dec[0]), 0, "decode empty length")
    print("  [PASS] empty input")

    # ================================================================
    # 4. Padding validation tests
    # ================================================================

    # 4a. Non-1 padding bits should produce error.
    # Take a valid encoding and corrupt the padding.
    # Encode "a" (code 0x3, 5 bits) -> 0x1f (00011|111) with 3 bits of 1-padding.
    # If we change padding to 0s: 0x18 (00011|000)
    var bad_pad_data = List[UInt8]()
    bad_pad_data.append(UInt8(0x18))  # 'a' code with zero padding
    var bad_pad_result = codec.decode(bad_pad_data)
    assert_true(
        len(bad_pad_result[1]) > 0,
        "expected error for non-1 padding bits, got none",
    )
    print("  [PASS] non-1 padding bits detected")

    # 4b. More than 7 bits of padding (> 7 trailing bits that don't complete a code).
    # Construct 2 bytes where only 1 bit is used for a symbol and 15 are padding.
    # Symbol '0' has code 0x0, 5 bits -> 00000. Then 11 bits of 1-padding
    # across 2 bytes: 00000|111 11111111 = 0x07 0xFF -> but that's
    # 5 bits for '0' + 11 bits padding. However the decoder would see
    # 5 bits completing '0', then 11 bits. But 11 > 7, so only the
    # tail matters. Actually let's think more carefully:
    # The encoder would never produce > 7 bits of padding. We need
    # to fabricate input where after the last decoded symbol there are
    # > 7 bits left. Easiest: 3 bytes of all-1s: 0xFF 0xFF 0xFF.
    # '1' bits walk the all-1s path of the trie. The shortest code on
    # the all-1s path from the root depends on the table.
    # Actually, since the EOS code is 30 all-1 bits, 24 bits of 1s
    # won't reach any symbol. So bits_since_last_symbol=24 > 7 -> error.
    var long_pad = List[UInt8]()
    long_pad.append(UInt8(0xFF))
    long_pad.append(UInt8(0xFF))
    long_pad.append(UInt8(0xFF))
    var long_pad_result = codec.decode(long_pad)
    assert_true(
        len(long_pad_result[1]) > 0,
        "expected error for >7 bits padding, got none",
    )
    print("  [PASS] >7 bits of padding detected")

    # 4c. Verify valid padding is accepted.
    # "a" encodes to 0x1f (00011|111) - 5 data bits, 3 padding bits of 1.
    var valid_a = List[UInt8]()
    valid_a.append(UInt8(0x1F))  # 'a' with proper 1-padding
    var valid_a_result = codec.decode(valid_a)
    assert_true(
        len(valid_a_result[1]) == 0,
        "decode of 'a' with valid padding failed: " + valid_a_result[1],
    )
    assert_equal(len(valid_a_result[0]), 1, "decode 'a' length")
    assert_equal(Int(valid_a_result[0][0]), 97, "decode 'a' value")
    print("  [PASS] valid padding accepted")

    # ================================================================
    # 5. Anti-cheat: 10 random byte sequences, roundtrip each
    # ================================================================
    var rand_pass = 0
    var t = perf_counter_ns()

    for ri in range(10):
        # Generate pseudo-random length 1-50
        var seed = Int(t) ^ (ri * 7919 + 1031)
        if seed < 0:
            seed = -seed
        var length = (seed % 50) + 1

        # Generate pseudo-random bytes
        var rand_data = List[UInt8]()
        for bi in range(length):
            var bseed = seed ^ (bi * 2039 + ri * 3571)
            if bseed < 0:
                bseed = -bseed
            rand_data.append(UInt8(bseed % 256))

        # Encode and decode
        var enc = codec.encode(rand_data)
        var dec = codec.decode(enc)
        var dec_data = dec[0].copy()
        var dec_err = dec[1].copy()

        assert_true(
            len(dec_err) == 0,
            "random roundtrip #"
            + String(ri)
            + " decode error: "
            + dec_err,
        )
        assert_equal(
            len(dec_data),
            len(rand_data),
            "random roundtrip #" + String(ri) + " length",
        )
        for bi in range(len(rand_data)):
            assert_equal(
                Int(dec_data[bi]),
                Int(rand_data[bi]),
                "random roundtrip #"
                + String(ri)
                + " byte "
                + String(bi),
            )
        rand_pass += 1

    print("  [PASS] anti-cheat: " + String(rand_pass) + " random roundtrips")

    # ================================================================
    # Final summary
    # ================================================================
    print(
        "test_hpack_huffman: all checks passed ("
        + String(single_pass)
        + " single-byte, 8 RFC strings, 3 padding, 1 empty, "
        + String(rand_pass)
        + " random)"
    )
