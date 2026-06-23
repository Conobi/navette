"""test_resolver.mojo — resolver.mojo coverage.

Added with the `memory.alloc` `Owned[T]` migration pilot: `resolve_host`'s
`getaddrinfo` path (which holds the migrated `hints`/`host_cstr`/`out_res`
scratch buffers) had no dedicated test. `localhost` exercises that path
deterministically via `/etc/hosts` (no external DNS).
"""

from std.testing import assert_true, assert_equal, assert_raises

from navette.net.resolver import resolve_host, Resolver


def test_dotted_ip_fast_path() raises:
    """A dotted IPv4 literal takes the fast path (no getaddrinfo/Owned)."""
    var addrs = resolve_host("127.0.0.1", 8080)
    assert_equal(len(addrs), 1)
    assert_true(addrs[0].is_ipv4())
    print("PASS test_dotted_ip_fast_path")


def test_localhost_getaddrinfo() raises:
    """`localhost` resolves via getaddrinfo — exercises the migrated buffers."""
    var addrs = resolve_host("localhost", 443)
    assert_true(len(addrs) >= 1)
    for i in range(len(addrs)):
        assert_true(addrs[i].is_ipv4() or addrs[i].is_ipv6())
    print("PASS test_localhost_getaddrinfo (", len(addrs), "addrs )")


def test_empty_host_raises() raises:
    """An empty host raises before any allocation."""
    with assert_raises():
        _ = resolve_host("", 80)
    print("PASS test_empty_host_raises")


def test_resolver_cache() raises:
    """The TTL cache returns equivalent results on the second lookup."""
    var r = Resolver(ttl_secs=60)
    var a1 = r.resolve("127.0.0.1", 80)
    var a2 = r.resolve("127.0.0.1", 80)
    assert_equal(len(a1), len(a2))
    print("PASS test_resolver_cache")


def main() raises:
    test_dotted_ip_fast_path()
    test_localhost_getaddrinfo()
    test_empty_host_raises()
    test_resolver_cache()
    print("All resolver tests passed.")
