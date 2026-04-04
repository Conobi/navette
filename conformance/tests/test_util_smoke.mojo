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

    print("test_util_smoke: all passed")
