# tests/test_capabilities.mojo
#
# Unit tests for Capabilities (M2.5a §5.1).
from src.http.handler import Capabilities, ALPN_H1, ALPN_H2, ALPN_H3
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_for_h1_flags() raises:
    var c = Capabilities.for_h1()
    assert_false(c.multiplexed, "h1.multiplexed")
    assert_false(c.trailers, "h1.trailers")
    assert_false(c.priority_hints, "h1.priority_hints")
    assert_false(c.datagrams, "h1.datagrams")
    assert_equal_int(c.alpn, ALPN_H1, "h1.alpn")
    assert_true(c.is_h1(), "h1.is_h1")
    assert_false(c.is_h2(), "h1.is_h2")
    assert_false(c.is_h3(), "h1.is_h3")


def test_for_h2_flags() raises:
    var c = Capabilities.for_h2()
    assert_true(c.multiplexed, "h2.multiplexed")
    assert_true(c.trailers, "h2.trailers")
    assert_true(c.priority_hints, "h2.priority_hints")
    assert_false(c.datagrams, "h2.datagrams")
    assert_equal_int(c.alpn, ALPN_H2, "h2.alpn")
    assert_true(c.is_h2(), "h2.is_h2")


def test_for_h3_flags() raises:
    var c = Capabilities.for_h3()
    assert_true(c.multiplexed, "h3.multiplexed")
    assert_true(c.trailers, "h3.trailers")
    assert_true(c.priority_hints, "h3.priority_hints")
    assert_true(c.datagrams, "h3.datagrams")
    assert_equal_int(c.alpn, ALPN_H3, "h3.alpn")
    assert_true(c.is_h3(), "h3.is_h3")


def test_alpn_string() raises:
    assert_equal_str(Capabilities.for_h1().alpn_string(), String("http/1.1"), "h1.alpn_string")
    assert_equal_str(Capabilities.for_h2().alpn_string(), String("h2"), "h2.alpn_string")
    assert_equal_str(Capabilities.for_h3().alpn_string(), String("h3"), "h3.alpn_string")


def test_copy_semantics() raises:
    var a = Capabilities.for_h2()
    var b = a.copy()
    assert_equal_int(a.alpn, b.alpn, "copy.alpn")
    assert_true(a.multiplexed == b.multiplexed, "copy.multiplexed")


def main() raises:
    test_for_h1_flags()
    test_for_h2_flags()
    test_for_h3_flags()
    test_alpn_string()
    test_copy_semantics()
    print("test_capabilities: all tests passed")
