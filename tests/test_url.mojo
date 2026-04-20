# tests/test_url.mojo
from src.http.url import ParsedUrl, parse_url
from tests._test_util import assert_true, assert_equal_int


def test_https_with_path() raises:
    var u = parse_url("https://example.com/path")
    assert_true(u.scheme == "https", "scheme")
    assert_true(u.host == "example.com", "host")
    assert_equal_int(Int(u.port), 443, "port")
    assert_true(u.path == "/path", "path")


def test_http_with_port_and_query() raises:
    var u = parse_url("http://localhost:8080/api?key=val")
    assert_true(u.scheme == "http", "scheme")
    assert_true(u.host == "localhost", "host")
    assert_equal_int(Int(u.port), 8080, "port")
    assert_true(u.path == "/api?key=val", "path")


def test_https_ipv6() raises:
    var u = parse_url("https://[::1]:9443/foo")
    assert_true(u.scheme == "https", "scheme")
    assert_true(u.host == "::1", "host")
    assert_equal_int(Int(u.port), 9443, "port")
    assert_true(u.path == "/foo", "path")


def test_no_path_defaults_to_slash() raises:
    var u = parse_url("https://example.com")
    assert_true(u.path == "/", "path")


def test_default_port_http() raises:
    var u = parse_url("http://example.com/x")
    assert_equal_int(Int(u.port), 80, "port")


def test_path_with_fragment() raises:
    var u = parse_url("https://example.com/search?q=hello#top")
    assert_true(u.path == "/search?q=hello#top", "path")


def test_invalid_no_scheme() raises:
    var raised = False
    try:
        _ = parse_url("example.com/path")
    except:
        raised = True
    assert_true(raised, "should raise on missing scheme")


def test_to_origin() raises:
    var u = parse_url("https://api.example.com:8443/v1/users")
    var o = u.to_origin()
    assert_true(o.scheme == "https", "origin scheme")
    assert_true(o.host == "api.example.com", "origin host")
    assert_equal_int(Int(o.port), 8443, "origin port")


def main() raises:
    test_https_with_path()
    test_http_with_port_and_query()
    test_https_ipv6()
    test_no_path_defaults_to_slash()
    test_default_port_http()
    test_path_with_fragment()
    test_invalid_no_scheme()
    test_to_origin()
    print("test_url: 8/8 passed")
