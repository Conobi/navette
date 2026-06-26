# tests/h1/test_wire_identical.mojo
#
# corpus-wire-identical (§7): the optimized serializer is byte-identical to an
# independent golden oracle across a Cartesian corpus of response shapes. Runs
# under ASSERT=all. The oracle re-derives the RFC 9112 wire from first
# principles (Mojo's String(Int) as the int-render oracle) — it does NOT share
# code with navette/h1/serializer.mojo, so a serializer bug cannot hide in it.

from std.memory import Span
from navette.http import Method, StatusCode, Version, Headers, BodyFrame, Request, Response
from navette.h1.serializer import serialize_response
from navette.h1.connection import H1Connection
from navette.h1 import ParseConfig
from tests._test_util import assert_true


def _buf_to_str(data: List[UInt8]) -> String:
    var s = String()
    for i in range(len(data)):
        s += chr(Int(data[i]))
    return s^


def _str_to_bytes(s: String) -> List[UInt8]:
    var b = s.as_bytes()
    var r = List[UInt8]()
    for i in range(len(b)):
        r.append(b[i])
    return r^


def _assert_bytes_eq_lists(a: List[UInt8], b: List[UInt8], msg: String) raises:
    if len(a) != len(b):
        print("DIVERGENCE [" + msg + "] len " + String(len(a)) + " vs " + String(len(b)))
        print("  opt=[" + _buf_to_str(a) + "]")
        print("  exp=[" + _buf_to_str(b) + "]")
        raise "wire divergence: " + msg
    for i in range(len(a)):
        if a[i] != b[i]:
            print("DIVERGENCE [" + msg + "] byte " + String(i) + ": "
                  + String(Int(a[i])) + " vs " + String(Int(b[i])))
            raise "wire divergence: " + msg


# --- independent golden oracle ---

def _gappend(mut out: List[UInt8], s: String):
    out.extend(s.as_bytes())

def _gcrlf(mut out: List[UInt8]):
    out.append(UInt8(0x0D))
    out.append(UInt8(0x0A))

def _ghex_lower(value: Int) -> String:
    if value == 0:
        return String("0")
    var hex_chars = String("0123456789abcdef")
    var hb = hex_chars.as_bytes()
    var digits = List[UInt8]()
    var v = value
    while v > 0:
        digits.append(hb[v & 0xF])
        v >>= 4
    var result = String()
    var i = len(digits) - 1
    while i >= 0:
        result += chr(Int(digits[i]))
        i -= 1
    return result^

def _gheaders(mut out: List[UInt8], headers: Headers):
    for i in range(len(headers)):
        _gappend(out, headers.name_at(i))
        out.append(UInt8(0x3A)); out.append(UInt8(0x20))
        _gappend(out, headers.value_at(i))
        _gcrlf(out)

def _gframing(mut out: List[UInt8], name: String, value: String):
    _gappend(out, name)
    out.append(UInt8(0x3A)); out.append(UInt8(0x20))
    _gappend(out, value)
    _gcrlf(out)

def _ghas_trailers(body: List[BodyFrame]) -> Bool:
    for i in range(len(body)):
        if body[i].is_trailers():
            return True
    return False

def _gdata_len(body: List[BodyFrame]) -> Int:
    var total = 0
    for i in range(len(body)):
        if body[i].is_data():
            total += len(body[i].data())
    return total

def _gdata(mut out: List[UInt8], body: List[BodyFrame]):
    for i in range(len(body)):
        if body[i].is_data():
            ref chunk = body[i].data()
            out.extend(Span(chunk))

def _gchunked(mut out: List[UInt8], body: List[BodyFrame]):
    for i in range(len(body)):
        if body[i].is_data():
            ref chunk = body[i].data()
            var clen = len(chunk)
            if clen > 0:
                _gappend(out, _ghex_lower(clen))
                _gcrlf(out)
                out.extend(Span(chunk))
                _gcrlf(out)
    out.append(UInt8(0x30))
    _gcrlf(out)
    for i in range(len(body)):
        if body[i].is_trailers():
            _gheaders(out, body[i].trailers())
    _gcrlf(out)

def _expected_wire(
    status_int: Int, reason: String, is_11: Bool,
    headers: Headers, body: List[BodyFrame]
) -> List[UInt8]:
    var out = List[UInt8]()
    if is_11:
        _gappend(out, String("HTTP/1.1"))
    else:
        _gappend(out, String("HTTP/1.0"))
    out.append(UInt8(0x20))
    _gappend(out, String(status_int))
    out.append(UInt8(0x20))
    _gappend(out, reason)
    _gcrlf(out)
    var bodyless = (status_int >= 100 and status_int <= 199) or status_int == 204 or status_int == 304
    if bodyless:
        _gheaders(out, headers)
        _gcrlf(out)
        return out^
    var use_chunked = _ghas_trailers(body)
    var body_len = _gdata_len(body)
    _gheaders(out, headers)
    if use_chunked:
        _gframing(out, String("transfer-encoding"), String("chunked"))
    elif body_len > 0 and not headers.has("content-length"):
        _gframing(out, String("content-length"), String(body_len))
    _gcrlf(out)
    if use_chunked:
        _gchunked(out, body)
    elif body_len > 0:
        _gdata(out, body)
    return out^


# --- corpus builders ---

def _make_headers(count: Int) -> Headers:
    var h = Headers()
    for i in range(count):
        h.add(String("X-H") + String(i), String("v") + String(i))
    return h^

def _small_body() -> List[BodyFrame]:
    var data = List[UInt8]()
    var msg = String("Hello, World!")
    var mb = msg.as_bytes()
    for i in range(len(mb)):
        data.append(mb[i])
    var b = List[BodyFrame]()
    b.append(BodyFrame.data(data^))
    return b^

def _chunked_body() -> List[BodyFrame]:
    var b = List[BodyFrame]()
    for c in range(3):
        var data = List[UInt8]()
        var msg = String("chunk") + String(c)
        var mb = msg.as_bytes()
        for i in range(len(mb)):
            data.append(mb[i])
        b.append(BodyFrame.data(data^))
    var tr = Headers()
    tr.add("X-Trailer", "t")
    b.append(BodyFrame.trailers(tr^))
    return b^


def test_corpus_wire_identical() raises:
    var statuses = List[Int]()
    for s in [100, 101, 200, 201, 204, 206, 301, 304, 400, 404, 500]:
        statuses.append(s)
    var n = 0
    for si in range(len(statuses)):
        for vi in range(2):
            for ri in range(2):
                for hi in range(3):
                    for bi in range(3):
                        var is_11 = vi == 1
                        var hc = 0 if hi == 0 else (1 if hi == 1 else 5)
                        var reason = String("") if ri == 0 else String("Reason")
                        var headers = _make_headers(hc)
                        var headers2 = _make_headers(hc)
                        var body: List[BodyFrame]
                        var body2: List[BodyFrame]
                        if bi == 0:
                            body = List[BodyFrame]()
                            body2 = List[BodyFrame]()
                        elif bi == 1:
                            body = _small_body()
                            body2 = _small_body()
                        else:
                            body = _chunked_body()
                            body2 = _chunked_body()
                        var version = Version.http_1_1() if is_11 else Version.http_1_0()
                        var resp = Response(
                            status=StatusCode(statuses[si]),
                            reason=reason,
                            version=version^,
                            headers=headers^,
                            body=body^,
                        )
                        var opt = serialize_response(resp^)
                        var exp = _expected_wire(statuses[si], reason, is_11, headers2, body2)
                        _assert_bytes_eq_lists(opt, exp, "corpus[" + String(n) + "]")
                        n += 1
    print("corpus-wire-identical: " + String(n) + " shapes byte-identical")


def test_head_and_fastpath_head() raises:
    # fastpath-head: a 200/1.1/empty-reason response to a HEAD request must
    # emit only the status line + framing headers (no body), and the status
    # line is the fast path. Drained wire ends in CRLF CRLF, body suppressed.
    var conn = H1Connection(ParseConfig())
    conn.receive_data(Span(_str_to_bytes("HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")))
    var req = conn.next_request()
    assert_true(req.__bool__(), "head request parsed")
    _ = req.take()
    var resp = Response(
        status=StatusCode(200),
        reason=String(""),
        version=Version.http_1_1(),
        headers=Headers(),
        body=_small_body(),
    )
    conn.send_response(resp^)
    var out = conn.drain()
    _assert_bytes_eq_lists(
        out,
        _str_to_bytes("HTTP/1.1 200 \r\ncontent-length: 13\r\n\r\n"),
        "fastpath-head",
    )
    print("fastpath-head: body suppressed, status line byte-exact")


def main() raises:
    test_corpus_wire_identical()
    test_head_and_fastpath_head()
    print("test_wire_identical: all tests passed")
