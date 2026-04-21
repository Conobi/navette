# bench/handler.mojo
#
# HttpArena benchmark handlers: baseline2 (query-param sum) and 404.

from std.collections.optional import Optional
from src.http.handler import ResponseWriter
from src.http.body import BodyFrame
from src.http.status import StatusCode
from src.http.headers import Headers


def _str_to_bytes(s: String) -> List[UInt8]:
    """Convert a String to List[UInt8] for BodyFrame.data()."""
    var b = s.as_bytes()
    var out = List[UInt8]()
    var i = 0
    while i < len(b):
        out.append(b[i])
        i += 1
    return out^


def _parse_query_int(target: String, name: String) -> Optional[Int]:
    """Extract integer value for ?name=value or &name=value from a URL target."""
    var bytes = target.as_bytes()
    var name_bytes = name.as_bytes()
    var name_len = len(name_bytes)
    var tgt_len = len(bytes)

    var i = 0
    while i < tgt_len:
        if bytes[i] != UInt8(ord("?")) and bytes[i] != UInt8(ord("&")):
            i += 1
            continue
        i += 1

        if i + name_len + 1 > tgt_len:
            break
        var matched = True
        var j = 0
        while j < name_len:
            if bytes[i + j] != name_bytes[j]:
                matched = False
                break
            j += 1
        if not matched or bytes[i + name_len] != UInt8(ord("=")):
            continue
        i += name_len + 1

        var value = 0
        var negative = False
        if i < tgt_len and bytes[i] == UInt8(ord("-")):
            negative = True
            i += 1
        var has_digit = False
        while i < tgt_len and bytes[i] >= UInt8(ord("0")) and bytes[i] <= UInt8(ord("9")):
            value = value * 10 + Int(bytes[i]) - Int(ord("0"))
            has_digit = True
            i += 1
        if not has_digit:
            return None
        if negative:
            value = -value
        return value

    return None


def handle_baseline2(target: String, mut resp: ResponseWriter) raises:
    """GET /baseline2?a=X&b=Y -> text/plain sum."""
    var a = _parse_query_int(target, "a")
    var b = _parse_query_int(target, "b")
    if not a or not b:
        var hdrs = Headers()
        hdrs.add("content-type", "text/plain")
        resp.send_status(StatusCode(400), hdrs^)
        _ = resp.try_send_body(BodyFrame.data(_str_to_bytes(String("Bad Request"))))
        resp.end()
        return

    var result = String(a.value() + b.value())
    var hdrs = Headers()
    hdrs.add("content-type", "text/plain")
    hdrs.add("content-length", String(len(result)))
    resp.send_status(StatusCode(200), hdrs^)
    _ = resp.try_send_body(BodyFrame.data(_str_to_bytes(result)))
    resp.end()


def handle_404(mut resp: ResponseWriter) raises:
    """Return 404 Not Found."""
    var hdrs = Headers()
    hdrs.add("content-type", "text/plain")
    resp.send_status(StatusCode(404), hdrs^)
    _ = resp.try_send_body(BodyFrame.data(_str_to_bytes(String("Not Found"))))
    resp.end()
