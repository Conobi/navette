# tests/test_phase_a_smoke.mojo
#
# Phase A (M2) integration smoke test.
#
# Cross-imports every Phase A type from both `src` (re-exports) and
# `src.h1` (ParseConfig / ParserStrictness) and exercises them together
# to verify the whole Phase A surface is wired up and usable.
from src import Method, StatusCode, Version, Headers, BodyFrame, Request, Response
from src.h1 import ParseConfig, ParserStrictness


def assert_true(cond: Bool, msg: String) raises:
    if not cond:
        print("ASSERTION FAILED: " + msg)
        raise "assertion failed: " + msg


def test_phase_a_cross_imports() raises:
    """All Phase A types can be imported together and used."""
    # Method
    var m = Method.get()
    assert_true(String(m) == "GET", "String(Method.get()) == 'GET'")

    # StatusCode
    var s = StatusCode.ok()
    assert_true(s.code() == 200, "StatusCode.ok().code() == 200")

    # Version
    var v = Version.http_1_1()
    assert_true(v.__str__() == "HTTP/1.1", "Version.http_1_1() stringifies")

    # Headers
    var hdrs = Headers()
    hdrs.add("Host", "example.com")
    hdrs.add("Content-Type", "text/plain")
    assert_true(len(hdrs) == 2, "Headers has 2 entries")

    # BodyFrame
    var payload = List[UInt8]()
    payload.append(0x68)  # 'h'
    payload.append(0x69)  # 'i'
    var frames = List[BodyFrame]()
    frames.append(BodyFrame.data(payload^))
    assert_true(len(frames) == 1, "One BodyFrame in list")

    # Request
    var req = Request(
        method=Method.get(),
        target="/index.html",
        version=Version.http_1_1(),
        headers=hdrs^,
        body=frames^,
    )
    assert_true(req.target == "/index.html", "Request.target round-trips")
    assert_true(String(req.method) == "GET", "Request.method is GET")

    # Response
    var resp_hdrs = Headers()
    resp_hdrs.add("Content-Length", "0")
    var resp = Response(
        status=StatusCode.ok(),
        reason="OK",
        version=Version.http_1_1(),
        headers=resp_hdrs^,
        body=List[BodyFrame](),
    )
    assert_true(resp.status.code() == 200, "Response.status.code() == 200")
    assert_true(resp.reason == "OK", "Response.reason == 'OK'")

    # ParseConfig / ParserStrictness (from src.h1)
    var strict = ParserStrictness()
    var cfg = ParseConfig(strictness=strict^)
    assert_true(cfg.max_header_count == 100, "ParseConfig default max_header_count")
    assert_true(cfg.max_body_size == 10485760, "ParseConfig default max_body_size")


def main() raises:
    test_phase_a_cross_imports()
    print("test_phase_a_smoke: all 1 tests passed")
