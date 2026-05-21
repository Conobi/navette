from tests._test_util import assert_true, assert_equal_int
from navette.quic.crypto_stream import CryptoStream


def _str_bytes(s: String) -> List[UInt8]:
    """Convert a string to a List[UInt8]."""
    var b = s.as_bytes()
    var result = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        result.append(b[i])
    return result^


def _make_byte(val: UInt8) -> List[UInt8]:
    """Create a single-byte list."""
    var result = List[UInt8]()
    result.append(val)
    return result^


def test_in_order_receive() raises:
    """Receive(0, "hello"), receive(5, "world"); drain() returns "helloworld"."""
    var cs = CryptoStream()
    var hello = _str_bytes("hello")
    var world = _str_bytes("world")
    cs.receive(UInt64(0), Span(hello))
    cs.receive(UInt64(5), Span(world))
    var result = cs.drain()
    assert_equal_int(len(result), 10, "in_order: length should be 10")
    var expected = _str_bytes("helloworld")
    for i in range(len(expected)):
        assert_true(
            result[i] == expected[i],
            "in_order: byte " + String(i) + " mismatch",
        )
    print("  test_in_order_receive: PASS")


def test_out_of_order_receive() raises:
    """Receive(5, "world"), receive(0, "hello"); drain() returns "helloworld"."""
    var cs = CryptoStream()
    var hello = _str_bytes("hello")
    var world = _str_bytes("world")
    cs.receive(UInt64(5), Span(world))
    # "world" is out-of-order, nothing drainable yet.
    assert_true(not cs.has_pending(), "ooo: no contiguous data before hello")
    cs.receive(UInt64(0), Span(hello))
    var result = cs.drain()
    assert_equal_int(len(result), 10, "ooo: length should be 10")
    var expected = _str_bytes("helloworld")
    for i in range(len(expected)):
        assert_true(
            result[i] == expected[i],
            "ooo: byte " + String(i) + " mismatch",
        )
    print("  test_out_of_order_receive: PASS")


def test_overlap_receive() raises:
    """Receive(0, 10 bytes), receive(5, 10 bytes); drain() length is 15."""
    var cs = CryptoStream()
    var data1 = List[UInt8](capacity=10)
    for i in range(10):
        data1.append(UInt8(i))
    var data2 = List[UInt8](capacity=10)
    for i in range(10):
        data2.append(UInt8(100 + i))
    cs.receive(UInt64(0), Span(data1))
    cs.receive(UInt64(5), Span(data2))
    var result = cs.drain()
    assert_equal_int(len(result), 15, "overlap: length should be 15")
    # First 10 bytes from data1 (0..9).
    for i in range(10):
        assert_true(
            result[i] == UInt8(i),
            "overlap: byte " + String(i) + " should be from data1",
        )
    # Last 5 bytes from data2[5..9] (values 105..109).
    for i in range(5):
        assert_true(
            result[10 + i] == UInt8(105 + i),
            "overlap: byte " + String(10 + i) + " should be from data2",
        )
    print("  test_overlap_receive: PASS")


def test_16k_cap() raises:
    """Receive(0, 1 byte), then receive(16386, 1 byte) should raise."""
    var cs = CryptoStream()
    var one = _make_byte(UInt8(0xAA))
    cs.receive(UInt64(0), Span(one))
    var far = _make_byte(UInt8(0xBB))
    var caught = False
    try:
        cs.receive(UInt64(16386), Span(far))
    except:
        caught = True
    assert_true(caught, "16k_cap: should raise for offset exceeding window")
    print("  test_16k_cap: PASS")


def test_duplicate_rejection() raises:
    """Receive(0, 5 bytes) twice; drain() length is 5."""
    var cs = CryptoStream()
    var data = List[UInt8](capacity=5)
    for i in range(5):
        data.append(UInt8(i))
    cs.receive(UInt64(0), Span(data))
    cs.receive(UInt64(0), Span(data))
    var result = cs.drain()
    assert_equal_int(len(result), 5, "dup: length should be 5")
    print("  test_duplicate_rejection: PASS")


def test_send_fragmentation() raises:
    """Write 5000 bytes, pending_crypto_frames(1000); verify 5 frames."""
    var cs = CryptoStream()
    var data = List[UInt8](capacity=5000)
    for i in range(5000):
        data.append(UInt8(i % 256))
    cs.write(Span(data))
    var frames = cs.pending_crypto_frames(1000)
    assert_equal_int(len(frames), 5, "frag: should produce 5 frames")
    # Verify offsets: 0, 1000, 2000, 3000, 4000.
    for i in range(5):
        var expected_offset = UInt64(i * 1000)
        assert_true(
            frames[i].offset == expected_offset,
            "frag: frame " + String(i) + " offset mismatch",
        )
        assert_equal_int(
            len(frames[i].data), 1000,
            "frag: frame " + String(i) + " size should be 1000",
        )
    print("  test_send_fragmentation: PASS")


def test_drain_clears_buffer() raises:
    """Receive + drain; has_pending() returns False."""
    var cs = CryptoStream()
    var data = _str_bytes("abc")
    cs.receive(UInt64(0), Span(data))
    assert_true(cs.has_pending(), "drain_clear: should have pending before drain")
    _ = cs.drain()
    assert_true(not cs.has_pending(), "drain_clear: should not have pending after drain")
    print("  test_drain_clears_buffer: PASS")


def main() raises:
    print("test_quic_crypto_stream:")
    test_in_order_receive()
    test_out_of_order_receive()
    test_overlap_receive()
    test_16k_cap()
    test_duplicate_rejection()
    test_send_fragmentation()
    test_drain_clears_buffer()
    print("All test_quic_crypto_stream tests passed.")
