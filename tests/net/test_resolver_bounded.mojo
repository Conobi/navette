"""Fast-path + answer-parsing unit tests for resolver_bounded."""

from std.testing import assert_equal, assert_true, assert_raises

from navette.net.resolver_bounded import resolve_host_bounded
from navette.net.resolver import ResolvedAddr


def test_empty_host_raises() raises:
    """Empty host must raise immediately, no DNS query."""
    with assert_raises():
        _ = resolve_host_bounded(String(""), 80)


def test_ipv4_literal_fast_path() raises:
    """An IPv4 literal returns immediately without any DNS query."""
    var addrs = resolve_host_bounded(String("127.0.0.1"), 8080)
    assert_equal(len(addrs), 1)
    assert_true(addrs[0].is_ipv4())
    assert_equal(addrs[0].v4.port, UInt16(8080))


def test_ipv6_literal_bare() raises:
    """A bare IPv6 literal like `::1` returns immediately."""
    var addrs = resolve_host_bounded(String("::1"), 443)
    assert_equal(len(addrs), 1)
    assert_true(addrs[0].is_ipv6())
    assert_equal(addrs[0].v6.port, UInt16(443))


def test_ipv6_literal_bracketed() raises:
    """A bracketed IPv6 literal like `[::1]` returns immediately."""
    var addrs = resolve_host_bounded(String("[::1]"), 443)
    assert_equal(len(addrs), 1)
    assert_true(addrs[0].is_ipv6())
    assert_equal(addrs[0].v6.port, UInt16(443))


def test_localhost_fast_path() raises:
    """Localhost returns hardcoded [::1, 127.0.0.1]."""
    var addrs = resolve_host_bounded(String("localhost"), 9090)
    assert_equal(len(addrs), 2)
    assert_true(addrs[0].is_ipv6())    # ::1 first
    assert_true(addrs[1].is_ipv4())    # 127.0.0.1 second
    assert_equal(addrs[1].v4.port, UInt16(9090))


def main() raises:
    test_empty_host_raises()
    test_ipv4_literal_fast_path()
    test_ipv6_literal_bare()
    test_ipv6_literal_bracketed()
    test_localhost_fast_path()
    print("All test_resolver_bounded fast-path tests passed.")
