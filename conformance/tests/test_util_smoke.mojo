from lib.test_util import hex_decode, hex_encode, assert_bytes_equal


def main() raises:
    # hex round-trip
    var bytes = hex_decode("deadbeef")
    debug_assert(len(bytes) == 4, "should be 4 bytes")
    debug_assert(hex_encode(bytes) == "deadbeef", "round-trip failed")

    # assert_bytes_equal - matching
    var a = hex_decode("0102")
    var b = hex_decode("0102")
    assert_bytes_equal(a, b, "identity")

    # hex edge cases
    debug_assert(len(hex_decode("")) == 0, "empty hex")
    debug_assert(hex_encode(List[UInt8]()) == "", "empty encode")

    print("test_util_smoke: all passed")
