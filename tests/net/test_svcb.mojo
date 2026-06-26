"""test_svcb.mojo — DNS HTTPS/SVCB discovery unit tests."""

from std.testing import assert_equal, assert_true

from navette.net.svcb import _parse_resolv_conf, _first_nameserver


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var b = s.as_bytes()
    for i in range(len(b)):
        out.append(b[i])
    return out^


def test_resolv_conf_first_ipv4_nameserver() raises:
    var conf = String(
        "# comment\n; also comment\n"
        "options edns0\n"
        "nameserver 9.9.9.9\n"
        "nameserver 1.1.1.1\n"
    )
    assert_equal(_parse_resolv_conf(_bytes(conf)), String("9.9.9.9"))


def test_resolv_conf_skips_ipv6_nameserver() raises:
    # IPv6 nameserver is ignored; the first *IPv4* line wins.
    var conf = String("nameserver 2001:4860:4860::8888\nnameserver 8.8.4.4\n")
    assert_equal(_parse_resolv_conf(_bytes(conf)), String("8.8.4.4"))


def test_resolv_conf_no_nameserver_returns_empty() raises:
    assert_equal(_parse_resolv_conf(_bytes(String("search lan\n"))), String(""))


def test_resolv_conf_crlf_lines_parsed_correctly() raises:
    # CRLF line endings must be stripped so the nameserver token is not
    # corrupted by a trailing CR byte.
    var conf = String("nameserver 1.2.3.4\r\nnameserver 5.6.7.8\r\n")
    assert_equal(_parse_resolv_conf(_bytes(conf)), String("1.2.3.4"))


def test_first_nameserver_missing_path_returns_default() raises:
    # When the given path does not exist, the fallback address is returned.
    var result = _first_nameserver("/no/such/resolv.conf")
    assert_equal(result, String("127.0.0.53"))


def main() raises:
    test_resolv_conf_first_ipv4_nameserver()
    test_resolv_conf_skips_ipv6_nameserver()
    test_resolv_conf_no_nameserver_returns_empty()
    test_resolv_conf_crlf_lines_parsed_correctly()
    test_first_nameserver_missing_path_returns_default()
    print("All test_svcb resolv.conf tests passed.")
