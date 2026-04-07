# tests/test_alt_svc.mojo
#
# Unit tests for Alt-Svc (RFC 7838, M2.5b §7.2).
from src.http.alt_svc import Origin
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_origin_roundtrip() raises:
    var o = Origin(scheme=String("https"), host=String("example.com"), port=UInt16(443))
    assert_equal_str(o.scheme, String("https"), "origin.scheme")
    assert_equal_str(o.host, String("example.com"), "origin.host")
    assert_equal_int(Int(o.port), 443, "origin.port")


def test_origin_equality() raises:
    var a = Origin(scheme=String("https"), host=String("a.test"), port=UInt16(443))
    var b = Origin(scheme=String("https"), host=String("a.test"), port=UInt16(443))
    var c = Origin(scheme=String("https"), host=String("b.test"), port=UInt16(443))
    assert_true(a == b, "eq.ab")
    assert_false(a == c, "ne.ac")


def main() raises:
    test_origin_roundtrip()
    test_origin_equality()
    print("test_alt_svc: all tests passed")
