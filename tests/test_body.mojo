# tests/test_body.mojo
#
# Unit tests for BodyFrame type.
from src.http import BodyFrame, Headers


def assert_true(cond: Bool, msg: String) raises:
    if not cond:
        print("ASSERTION FAILED: " + msg)
        raise "assertion failed: " + msg


def assert_equal_int(got: Int, expected: Int, msg: String) raises:
    if got != expected:
        print("ASSERTION FAILED [" + msg + "]: got " + String(got) + " expected " + String(expected))
        raise "assertion failed: " + msg


def test_data_frame() raises:
    """BodyFrame.data() creates a data variant."""
    var bytes = List[UInt8]()
    bytes.append(0x48)  # H
    bytes.append(0x69)  # i
    var frame = BodyFrame.data(bytes^)
    assert_true(frame.is_data(), "is_data")
    assert_true(not frame.is_trailers(), "not is_trailers")
    assert_equal_int(len(frame.data()), 2, "data len")
    assert_equal_int(Int(frame.data()[0]), 0x48, "data[0]")
    assert_equal_int(Int(frame.data()[1]), 0x69, "data[1]")


def test_trailers_frame() raises:
    """BodyFrame.trailers() creates a trailers variant."""
    var hdrs = Headers()
    hdrs.add("Checksum", "abc123")
    var frame = BodyFrame.trailers(hdrs^)
    assert_true(frame.is_trailers(), "is_trailers")
    assert_true(not frame.is_data(), "not is_data")
    assert_equal_int(len(frame.trailers()), 1, "trailers len")
    assert_true(frame.trailers().has("checksum"), "trailer has checksum")


def test_empty_data_frame() raises:
    """Empty data frame is valid."""
    var frame = BodyFrame.data(List[UInt8]())
    assert_true(frame.is_data(), "is_data")
    assert_equal_int(len(frame.data()), 0, "empty data")


def test_empty_trailers_frame() raises:
    """Empty trailers frame is valid."""
    var frame = BodyFrame.trailers(Headers())
    assert_true(frame.is_trailers(), "is_trailers")
    assert_equal_int(len(frame.trailers()), 0, "empty trailers")


def test_body_frame_list() raises:
    """Body frames can be stored in a List."""
    var frames = List[BodyFrame]()

    var bytes1 = List[UInt8]()
    bytes1.append(0x41)
    frames.append(BodyFrame.data(bytes1^))

    var bytes2 = List[UInt8]()
    bytes2.append(0x42)
    frames.append(BodyFrame.data(bytes2^))

    var hdrs = Headers()
    hdrs.add("Trailer-Field", "value")
    frames.append(BodyFrame.trailers(hdrs^))

    assert_equal_int(len(frames), 3, "list len")
    assert_true(frames[0].is_data(), "first is data")
    assert_true(frames[1].is_data(), "second is data")
    assert_true(frames[2].is_trailers(), "third is trailers")


def main() raises:
    test_data_frame()
    test_trailers_frame()
    test_empty_data_frame()
    test_empty_trailers_frame()
    test_body_frame_list()
    print("test_body: all 5 tests passed")
