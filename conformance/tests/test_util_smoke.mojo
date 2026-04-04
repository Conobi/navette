from lib.test_util import hex_decode, hex_encode, assert_bytes_equal, assert_true, assert_equal


def main() raises:
    # Verify assertions are working (guard against silent no-op)
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    # hex round-trip
    var bytes = hex_decode("deadbeef")
    assert_equal(len(bytes), 4, "should be 4 bytes")
    assert_true(hex_encode(bytes) == "deadbeef", "round-trip failed")

    # assert_bytes_equal - matching
    var a = hex_decode("0102")
    var b = hex_decode("0102")
    assert_bytes_equal(a, b, "identity")

    # hex edge cases
    assert_equal(len(hex_decode("")), 0, "empty hex")
    assert_true(hex_encode(List[UInt8]()) == "", "empty encode")

    # Explicit known-value tests — proves hex_decode isn't silently mangling bytes
    assert_equal(Int(hex_decode("00")[0]), 0x00, "hex 00 -> byte 0x00")
    assert_equal(Int(hex_decode("ff")[0]), 0xFF, "hex ff -> byte 0xFF")
    assert_equal(Int(hex_decode("0a")[0]), 0x0A, "hex 0a -> byte 0x0A")
    assert_equal(Int(hex_decode("a0")[0]), 0xA0, "hex a0 -> byte 0xA0")
    assert_equal(Int(hex_decode("80")[0]), 0x80, "hex 80 -> byte 0x80")
    assert_equal(Int(hex_decode("7f")[0]), 0x7F, "hex 7f -> byte 0x7F")

    # Uppercase hex input
    var upper = hex_decode("DEADBEEF")
    assert_true(hex_encode(upper) == "deadbeef", "uppercase hex input")

    # Verify assert_bytes_equal rejects mismatches
    var mismatch_caught = False
    try:
        assert_bytes_equal(hex_decode("0102"), hex_decode("0103"), "deliberate_mismatch")
    except:
        mismatch_caught = True
    assert_true(mismatch_caught, "assert_bytes_equal should reject mismatched bytes")

    # Verify assert_bytes_equal rejects length mismatches
    var len_mismatch_caught = False
    try:
        assert_bytes_equal(hex_decode("0102"), hex_decode("010203"), "deliberate_len_mismatch")
    except:
        len_mismatch_caught = True
    assert_true(len_mismatch_caught, "assert_bytes_equal should reject length mismatches")

    print("test_util_smoke: all passed")
