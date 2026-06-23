# conformance/tests/test_hpack_integer.mojo
#
# HC-3b Task 1: HPACK variable-length prefix integer codec tests.
# Loads vectors from rfc7541/c1_integer.json and validates
# encode, decode, roundtrip, overflow, and anti-cheat randomised checks.
from lib.test_util import (
    load_vectors,
    hex_decode,
    hex_encode,
    assert_true,
    assert_equal,
    assert_bytes_equal,
)
from lib.http2.hpack_integer import encode_integer, decode_integer
from std.python import Python, PythonObject
from std.time import perf_counter_ns


def _has_key(obj: PythonObject, key: String) -> Bool:
    """Check if a Python dict has a given key."""
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


def main() raises:
    # ---- Sentinel anti-cheat: verify assert_true actually fires ----
    var sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        sentinel_ok = True
    assert_true(sentinel_ok, "assertions are not firing")

    # ---- Load test vectors ----
    var vectors = load_vectors("vectors/rfc7541/c1_integer.json")
    var builtins = Python.import_module("builtins")
    var vec_count = Int(py=builtins.len(vectors))

    var encode_pass = 0
    var decode_pass = 0
    var roundtrip_pass = 0

    for i in range(vec_count):
        var v = vectors[i]
        var vid = String(v["id"])
        var inp = v["input"]
        var expected_decode = v["expected_decode"]
        var prefix_bits = Int(py=inp["prefix_bits"])

        var is_overflow = _has_key(expected_decode, "error")

        if is_overflow:
            # ---- Overflow vector: only test decode ----
            var wire_hex = String(inp["wire_hex"])
            var wire = hex_decode(wire_hex)
            var result = decode_integer(wire, 0, prefix_bits)
            var err = result[2]
            assert_true(
                len(err) > 0,
                vid + ": expected decode error but got none",
            )
            # Check the error message contains "overflow"
            assert_true(
                "overflow" in err,
                vid + ": expected 'overflow' in error, got: " + err,
            )
            decode_pass += 1
            print("  [PASS] " + vid + " (overflow)")
        else:
            var value = Int(py=inp["value"])
            var expected_hex = String(v["expected_encode_hex"])
            var expected_value = Int(py=expected_decode["value"])
            var expected_consumed = Int(py=expected_decode["bytes_consumed"])

            # ---- 1. Encode test ----
            var encoded = encode_integer(value, prefix_bits)
            var encoded_hex = hex_encode(encoded)
            assert_true(
                encoded_hex == expected_hex,
                vid
                + " encode: got "
                + encoded_hex
                + " expected "
                + expected_hex,
            )
            encode_pass += 1

            # ---- 2. Decode test ----
            var wire = hex_decode(expected_hex)
            var result = decode_integer(wire, 0, prefix_bits)
            var dec_value = result[0]
            var dec_consumed = result[1]
            var dec_err = result[2]
            assert_true(
                len(dec_err) == 0,
                vid + " decode: unexpected error: " + dec_err,
            )
            assert_equal(dec_value, expected_value, vid + " decode value")
            assert_equal(
                dec_consumed,
                expected_consumed,
                vid + " decode bytes_consumed",
            )
            decode_pass += 1

            # ---- 3. Roundtrip test: encode -> decode ----
            var rt_result = decode_integer(encoded, 0, prefix_bits)
            var rt_value = rt_result[0]
            var rt_consumed = rt_result[1]
            var rt_err = rt_result[2]
            assert_true(
                len(rt_err) == 0,
                vid + " roundtrip: unexpected error: " + rt_err,
            )
            assert_equal(rt_value, value, vid + " roundtrip value")
            assert_equal(
                rt_consumed,
                len(encoded),
                vid + " roundtrip bytes_consumed",
            )
            roundtrip_pass += 1

            print("  [PASS] " + vid)

    print(
        "  vectors: "
        + String(encode_pass)
        + " encode, "
        + String(decode_pass)
        + " decode, "
        + String(roundtrip_pass)
        + " roundtrip passed"
    )

    # ---- 4. Additional truncation tests ----
    # Empty wire
    var empty_result = decode_integer(List[UInt8](), 0, 5)
    assert_true(
        len(empty_result[2]) > 0,
        "expected error for empty wire",
    )

    # Truncated continuation: first byte indicates multi-byte, no continuation
    var trunc_wire = List[UInt8]()
    trunc_wire.append(UInt8(0x1F))  # max_prefix for 5-bit
    var trunc_result = decode_integer(trunc_wire, 0, 5)
    assert_true(
        len(trunc_result[2]) > 0,
        "expected error for truncated continuation",
    )

    # Truncated continuation: continuation byte with high bit set, no next byte
    var trunc_wire2 = List[UInt8]()
    trunc_wire2.append(UInt8(0x1F))
    trunc_wire2.append(UInt8(0x80))  # continuation bit set, no next byte
    var trunc_result2 = decode_integer(trunc_wire2, 0, 5)
    assert_true(
        len(trunc_result2[2]) > 0,
        "expected error for truncated continuation (2 bytes)",
    )
    print("  [PASS] truncation edge cases")

    # ---- 5. Anti-cheat: 20 random integers across all 4 prefix sizes ----
    var rand_pass = 0
    var t = perf_counter_ns()
    var prefix_sizes = List[Int]()
    prefix_sizes.append(4)
    prefix_sizes.append(5)
    prefix_sizes.append(6)
    prefix_sizes.append(7)

    for ri in range(20):
        for pi in range(len(prefix_sizes)):
            var prefix = prefix_sizes[pi]
            # Generate pseudo-random value in [0, 2^24)
            # Mix the loop counter and timestamp for variety
            var seed = Int(t) ^ (ri * 7919 + pi * 1031)
            if seed < 0:
                seed = -seed
            var rand_value = seed % (1 << 24)

            var enc = encode_integer(rand_value, prefix)
            var dec = decode_integer(enc, 0, prefix)
            var dec_val = dec[0]
            var dec_consumed = dec[1]
            var dec_err = dec[2]

            assert_true(
                len(dec_err) == 0,
                "random roundtrip error: value="
                + String(rand_value)
                + " prefix="
                + String(prefix)
                + " err="
                + dec_err,
            )
            assert_equal(
                dec_val,
                rand_value,
                "random roundtrip value mismatch: expected="
                + String(rand_value)
                + " got="
                + String(dec_val),
            )
            assert_equal(
                dec_consumed,
                len(enc),
                "random roundtrip consumed mismatch",
            )
            rand_pass += 1

    print(
        "  random roundtrips: "
        + String(rand_pass)
        + " passed (20 values x 4 prefix sizes)"
    )

    # ---- Final summary ----
    var total = encode_pass + decode_pass + roundtrip_pass + rand_pass
    print(
        "test_hpack_integer: all "
        + String(total)
        + " checks passed ("
        + String(encode_pass)
        + " encode, "
        + String(decode_pass)
        + " decode, "
        + String(roundtrip_pass)
        + " roundtrip, "
        + String(rand_pass)
        + " random)"
    )
