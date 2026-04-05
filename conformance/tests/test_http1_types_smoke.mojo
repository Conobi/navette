# conformance/tests/test_http1_types_smoke.mojo
#
# Smoke test: verify the http1 types module compiles and basic operations work.
from lib.http1.types import ParseConfig, Header, ParsedRequest, ChunkedResult
from lib.test_util import assert_true, assert_equal


def test_header_construct() raises:
    var h = Header(String("Content-Type"), String("text/plain"))
    assert_true(h.name == "Content-Type", "header name")
    assert_true(h.value == "text/plain", "header value")


def test_parse_config_defaults() raises:
    var cfg = ParseConfig()
    assert_true(cfg.strict, "strict defaults to True")
    assert_equal(cfg.max_request_line, 8192, "max_request_line default")
    assert_equal(cfg.max_header_count, 100, "max_header_count default")
    assert_equal(cfg.max_header_size, 8192, "max_header_size default")
    assert_equal(cfg.max_headers_total, 65536, "max_headers_total default")
    assert_equal(cfg.max_chunk_size, 1048576, "max_chunk_size default")


def test_parsed_request_ok() raises:
    var req = ParsedRequest()
    assert_true(req.ok(), "empty error means ok")
    assert_equal(len(req.headers), 0, "no headers initially")
    assert_equal(len(req.body), 0, "no body initially")


def test_chunked_result_ok() raises:
    var cr = ChunkedResult()
    assert_true(cr.ok(), "empty error means ok")
    assert_equal(len(cr.body), 0, "no body initially")
    assert_equal(len(cr.trailers), 0, "no trailers initially")


def main() raises:
    test_header_construct()
    test_parse_config_defaults()
    test_parsed_request_ok()
    test_chunked_result_ok()
    print("types ok")
