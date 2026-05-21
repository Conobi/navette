# bench/handler.mojo
#
# HttpArena benchmark handlers: baseline2 (query-param sum), 404, and static
# file serving with pre-compressed variant support (br/gzip).

from std.collections.optional import Optional
from std.collections import Dict
from std.memory import UnsafePointer
from navette.http.handler import (
    ResponseWriter,
    RecvBody,
    StreamHandler,
    Capabilities,
    StreamError,
)
from navette.http.body import BodyFrame
from navette.http.status import StatusCode
from navette.http.headers import Headers
from navette.http.request import Request
from navette.h2.h2_sync_server import CoroStreamCtx as H2CoroStreamCtx
from navette.h3.h3_sync_server import CoroStreamCtx as H3CoroStreamCtx
from interop.file_io import read_file

from simdjson.parser import Parser
from simdjson.document import Document
from simdjson.value import Value

from bench.json_writer import (
    write_bytes,
    write_uint,
    write_str_escaped,
)


def _str_to_bytes(s: String) -> List[UInt8]:
    """Convert a String to List[UInt8] for BodyFrame.data()."""
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    out.extend(b)
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


def handle_plaintext(mut resp: ResponseWriter) raises:
    """GET /plaintext -> 13-byte "Hello, World!" text/plain.

    Matches Flare's `docs/benchmark.md` headline endpoint (TFB plaintext,
    TechEmpower test #6). Keeps Content-Length explicit and Content-Type
    text/plain so wrk2's response-integrity check accepts the body unchanged.
    """
    var body = String("Hello, World!")
    var hdrs = Headers()
    hdrs.add("content-type", "text/plain")
    hdrs.add("content-length", String(body.byte_length()))
    resp.send_status(StatusCode(200), hdrs^)
    _ = resp.try_send_body(BodyFrame.data(_str_to_bytes(body)))
    resp.end()


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
    hdrs.add("content-length", String(result.byte_length()))
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


# ---------------------------------------------------------------------------
# MIME type map
# ---------------------------------------------------------------------------


def _mime_for_ext(ext: String) -> String:
    """Return Content-Type for a file extension (without leading dot)."""
    if ext == "html" or ext == "htm":
        return String("text/html; charset=utf-8")
    if ext == "css":
        return String("text/css")
    if ext == "js":
        return String("application/javascript")
    if ext == "json":
        return String("application/json")
    if ext == "png":
        return String("image/png")
    if ext == "jpg" or ext == "jpeg":
        return String("image/jpeg")
    if ext == "gif":
        return String("image/gif")
    if ext == "svg":
        return String("image/svg+xml")
    if ext == "ico":
        return String("image/x-icon")
    if ext == "woff":
        return String("font/woff")
    if ext == "woff2":
        return String("font/woff2")
    if ext == "webmanifest":
        return String("application/manifest+json")
    if ext == "xml":
        return String("application/xml")
    if ext == "txt":
        return String("text/plain")
    return String("application/octet-stream")


# ---------------------------------------------------------------------------
# Extension extraction
# ---------------------------------------------------------------------------


def _get_extension(path: String) -> String:
    """Extract file extension (without dot) by scanning backwards for '.'."""
    var bytes = path.as_bytes()
    var n = len(bytes)
    var i = n - 1
    while i >= 0:
        if bytes[i] == UInt8(ord(".")):
            # Build string from i+1 .. n
            var ext = String()
            var j = i + 1
            while j < n:
                ext += chr(Int(bytes[j]))
                j += 1
            return ext^
        if bytes[i] == UInt8(ord("/")):
            break
        i -= 1
    return String("")


# ---------------------------------------------------------------------------
# StaticEntry — cached file with optional pre-compressed variants
# ---------------------------------------------------------------------------


struct StaticEntry(Copyable, Movable, ImplicitlyDestructible):
    """Holds a static file's original bytes plus optional brotli/gzip variants."""

    var data: List[UInt8]
    var br_data: List[UInt8]
    var gz_data: List[UInt8]
    var content_type: String

    def __init__(
        out self,
        var data: List[UInt8],
        var br_data: List[UInt8],
        var gz_data: List[UInt8],
        var content_type: String,
    ):
        self.data = data^
        self.br_data = br_data^
        self.gz_data = gz_data^
        self.content_type = content_type^

    def __init__(out self, *, other: Self):
        self.data = other.data.copy()
        self.br_data = other.br_data.copy()
        self.gz_data = other.gz_data.copy()
        self.content_type = other.content_type.copy()

    def __init__(out self, *, deinit take: Self):
        self.data = take.data^
        self.br_data = take.br_data^
        self.gz_data = take.gz_data^
        self.content_type = take.content_type^


# ---------------------------------------------------------------------------
# Static file loader
# ---------------------------------------------------------------------------

def _try_read_file(path: String) -> List[UInt8]:
    """Try to read a file; return empty list on failure."""
    try:
        return read_file(path)
    except:
        return List[UInt8]()


def _load_one_static(
    static_dir: String,
    name: String,
    mut cache: Dict[String, StaticEntry],
):
    """Load a single static file and its compressed variants into cache."""
    var path = static_dir + "/" + name
    var data = _try_read_file(path)
    if len(data) == 0:
        return
    var br_data = _try_read_file(path + ".br")
    var gz_data = _try_read_file(path + ".gz")
    var ext = _get_extension(name)
    var ct = _mime_for_ext(ext)
    cache[name] = StaticEntry(data^, br_data^, gz_data^, ct^)


def _load_static_files(static_dir: String) -> Dict[String, StaticEntry]:
    """Load the hardcoded set of HttpArena static files from *static_dir*.

    For each file, also attempts to load ``<path>.br`` and ``<path>.gz``
    pre-compressed variants. Missing variants are stored as empty lists.
    """
    var cache = Dict[String, StaticEntry]()
    # HttpArena's standard 20-file static set.
    _load_one_static(static_dir, "analytics.js", cache)
    _load_one_static(static_dir, "app.js", cache)
    _load_one_static(static_dir, "bold.woff2", cache)
    _load_one_static(static_dir, "components.css", cache)
    _load_one_static(static_dir, "footer.html", cache)
    _load_one_static(static_dir, "header.html", cache)
    _load_one_static(static_dir, "helpers.js", cache)
    _load_one_static(static_dir, "hero.webp", cache)
    _load_one_static(static_dir, "icon-sprite.svg", cache)
    _load_one_static(static_dir, "layout.css", cache)
    _load_one_static(static_dir, "logo.svg", cache)
    _load_one_static(static_dir, "manifest.json", cache)
    _load_one_static(static_dir, "regular.woff2", cache)
    _load_one_static(static_dir, "reset.css", cache)
    _load_one_static(static_dir, "router.js", cache)
    _load_one_static(static_dir, "theme.css", cache)
    _load_one_static(static_dir, "thumb1.webp", cache)
    _load_one_static(static_dir, "thumb2.webp", cache)
    _load_one_static(static_dir, "utilities.css", cache)
    _load_one_static(static_dir, "vendor.js", cache)
    # QUIC perf bench payloads (loaded from a different STATIC_DIR mount).
    _load_one_static(static_dir, "1k.bin", cache)
    _load_one_static(static_dir, "5k.bin", cache)
    _load_one_static(static_dir, "15k.bin", cache)
    _load_one_static(static_dir, "2m.bin", cache)
    return cache^


# ---------------------------------------------------------------------------
# DatasetItem — pre-escaped JSON fragments for the /json profile
# ---------------------------------------------------------------------------


struct DatasetItem(Copyable, Movable, ImplicitlyDestructible):
    """One row from data/dataset.json with string fields pre-escaped.

    The renderer at request time only needs to memcpy these byte spans
    and emit fresh integer formats (id, price, quantity, total). All
    JSON escaping happens once at boot.
    """

    var id: UInt64
    var price: UInt64
    var quantity: UInt64
    var active: Bool
    # Each *_quoted fragment includes its surrounding " or [ ] or { }
    # so the renderer can splat it directly between commas / colons.
    var name_quoted: List[UInt8]
    var category_quoted: List[UInt8]
    var tags_array: List[UInt8]
    var rating_object: List[UInt8]

    def __init__(
        out self,
        id: UInt64,
        price: UInt64,
        quantity: UInt64,
        active: Bool,
        var name_quoted: List[UInt8],
        var category_quoted: List[UInt8],
        var tags_array: List[UInt8],
        var rating_object: List[UInt8],
    ):
        self.id = id
        self.price = price
        self.quantity = quantity
        self.active = active
        self.name_quoted = name_quoted^
        self.category_quoted = category_quoted^
        self.tags_array = tags_array^
        self.rating_object = rating_object^

    def __init__(out self, *, other: Self):
        self.id = other.id
        self.price = other.price
        self.quantity = other.quantity
        self.active = other.active
        self.name_quoted = other.name_quoted.copy()
        self.category_quoted = other.category_quoted.copy()
        self.tags_array = other.tags_array.copy()
        self.rating_object = other.rating_object.copy()

    def __init__(out self, *, deinit take: Self):
        self.id = take.id
        self.price = take.price
        self.quantity = take.quantity
        self.active = take.active
        self.name_quoted = take.name_quoted^
        self.category_quoted = take.category_quoted^
        self.tags_array = take.tags_array^
        self.rating_object = take.rating_object^


# ---------------------------------------------------------------------------
# Dataset loader (simdjson)
# ---------------------------------------------------------------------------


def _build_quoted_string(mut doc: Document, val: Value) raises -> List[UInt8]:
    """Render *val* (a JSON string) as an escaped, double-quoted byte fragment."""
    var s = val.get_string(doc)
    var out = List[UInt8]()
    write_str_escaped(out, s.as_bytes())
    return out^


def _build_tags_array(mut doc: Document, tags: Value) raises -> List[UInt8]:
    """Render a JSON array of strings as a single pre-escaped byte fragment."""
    var out = List[UInt8]()
    out.append(UInt8(ord("[")))
    var n = tags.count(doc)
    var i = 0
    while i < n:
        if i > 0:
            out.append(UInt8(ord(",")))
        var s = tags.at(doc, i).get_string(doc)
        write_str_escaped(out, s.as_bytes())
        i += 1
    out.append(UInt8(ord("]")))
    return out^


def _build_rating_object(mut doc: Document, rating: Value) raises -> List[UInt8]:
    """Render the rating object {score, count} as a pre-escaped byte fragment."""
    var score = rating.get(doc, String("score")).get_uint(doc)
    var count = rating.get(doc, String("count")).get_uint(doc)
    var out = List[UInt8]()
    write_bytes(out, String('{"score":').as_bytes())
    write_uint(out, score)
    write_bytes(out, String(',"count":').as_bytes())
    write_uint(out, count)
    out.append(UInt8(ord("}")))
    return out^


def _load_dataset(path: String) -> List[DatasetItem]:
    """Parse *path* with simdjson and materialise pre-escaped DatasetItems.

    Returns an empty list on any error so the bench still boots when the
    data mount is absent.
    """
    var items = List[DatasetItem]()
    var raw: List[UInt8]
    try:
        raw = read_file(path)
    except:
        print("bench: warning: dataset file not found at " + path)
        return items^

    try:
        var parser = Parser()
        var doc = parser.parse(raw^)
        var root = doc.root()
        if not root.is_array(doc):
            print("bench: warning: dataset root is not an array")
            return items^
        var n = root.count(doc)
        var i = 0
        while i < n:
            var item = root.at(doc, i)
            var id = item.get(doc, String("id")).get_uint(doc)
            var price = item.get(doc, String("price")).get_uint(doc)
            var quantity = item.get(doc, String("quantity")).get_uint(doc)
            var active = item.get(doc, String("active")).get_bool(doc)
            var name_quoted = _build_quoted_string(doc, item.get(doc, String("name")))
            var category_quoted = _build_quoted_string(doc, item.get(doc, String("category")))
            var tags_array = _build_tags_array(doc, item.get(doc, String("tags")))
            var rating_object = _build_rating_object(doc, item.get(doc, String("rating")))
            items.append(
                DatasetItem(
                    id=id,
                    price=price,
                    quantity=quantity,
                    active=active,
                    name_quoted=name_quoted^,
                    category_quoted=category_quoted^,
                    tags_array=tags_array^,
                    rating_object=rating_object^,
                )
            )
            i += 1
    except e:
        print("bench: warning: dataset parse failed: " + String(e))

    return items^


# ---------------------------------------------------------------------------
# BenchState — single heap-allocated container shared across servers
# ---------------------------------------------------------------------------


struct BenchState(Movable):
    """Boot-time state passed by pointer to every per-stream handler."""

    var static_cache: Dict[String, StaticEntry]
    var dataset: List[DatasetItem]

    def __init__(
        out self,
        var static_cache: Dict[String, StaticEntry],
        var dataset: List[DatasetItem],
    ):
        self.static_cache = static_cache^
        self.dataset = dataset^

    def __init__(out self, *, deinit take: Self):
        self.static_cache = take.static_cache^
        self.dataset = take.dataset^


# ---------------------------------------------------------------------------
# Accept-Encoding check
# ---------------------------------------------------------------------------


def _accepts_encoding(headers: Headers, encoding: String) -> Bool:
    """Return True if the Accept-Encoding header contains *encoding*."""
    var ae = headers.get("accept-encoding")
    if ae.byte_length() == 0:
        return False
    # Simple substring search: scan for encoding bytes in ae.
    var ae_bytes = ae.as_bytes()
    var enc_bytes = encoding.as_bytes()
    var ae_len = len(ae_bytes)
    var enc_len = len(enc_bytes)
    if enc_len > ae_len:
        return False
    var i = 0
    while i <= ae_len - enc_len:
        var matched = True
        var j = 0
        while j < enc_len:
            if ae_bytes[i + j] != enc_bytes[j]:
                matched = False
                break
            j += 1
        if matched:
            # Word-boundary check: must be at token boundary, not inside "brotli"
            var before_ok = (i == 0
                or ae_bytes[i - 1] == UInt8(ord(" "))
                or ae_bytes[i - 1] == UInt8(ord(","))
                or ae_bytes[i - 1] == UInt8(ord("\t")))
            var end_pos = i + enc_len
            var after_ok = (end_pos == ae_len
                or ae_bytes[end_pos] == UInt8(ord(" "))
                or ae_bytes[end_pos] == UInt8(ord(","))
                or ae_bytes[end_pos] == UInt8(ord(";"))
                or ae_bytes[end_pos] == UInt8(ord("\t")))
            if before_ok and after_ok:
                return True
        i += 1
    return False


# ---------------------------------------------------------------------------
# Static file handler
# ---------------------------------------------------------------------------


def handle_static(
    target: String,
    headers: Headers,
    mut resp: ResponseWriter,
    state_ptr: UnsafePointer[BenchState, MutAnyOrigin],
) raises:
    """Serve a file from the static cache for ``/static/<filename>``.

    Negotiates content-encoding (br > gzip > identity) via Accept-Encoding.
    Sets ``Vary: Accept-Encoding`` on every response.
    Returns 404 if the file is not in the cache.
    """
    # Strip "/static/" prefix (7 chars for "/static/").
    var target_bytes = target.as_bytes()
    var tgt_len = len(target_bytes)

    # Find start of filename after "/static/"
    var prefix_len = 8  # len("/static/")
    if tgt_len <= prefix_len:
        handle_404(resp)
        return

    # Strip query string: find '?'
    var end = tgt_len
    var k = prefix_len
    while k < tgt_len:
        if target_bytes[k] == UInt8(ord("?")):
            end = k
            break
        k += 1

    # Build filename string
    var filename = String()
    var fi = prefix_len
    while fi < end:
        filename += chr(Int(target_bytes[fi]))
        fi += 1

    # Look up in cache
    if filename not in state_ptr[].static_cache:
        handle_404(resp)
        return
    var entry = state_ptr[].static_cache[filename].copy()

    # Content negotiation
    var use_br = _accepts_encoding(headers, String("br")) and len(entry.br_data) > 0
    var use_gz = (not use_br) and _accepts_encoding(headers, String("gzip")) and len(entry.gz_data) > 0

    var body_data: List[UInt8]
    var hdrs = Headers()
    hdrs.add("content-type", entry.content_type)
    hdrs.add("vary", "Accept-Encoding")

    if use_br:
        hdrs.add("content-encoding", "br")
        body_data = entry.br_data.copy()
    elif use_gz:
        hdrs.add("content-encoding", "gzip")
        body_data = entry.gz_data.copy()
    else:
        body_data = entry.data.copy()

    hdrs.add("content-length", String(len(body_data)))
    resp.send_status(StatusCode(200), hdrs^)
    _ = resp.try_send_body(BodyFrame.data(body_data^))
    resp.end()


# ---------------------------------------------------------------------------
# /json/{count}?m=X handler — HttpArena json + json-tls profile
# ---------------------------------------------------------------------------


def _parse_json_path(target: String, mut count_out: Int, mut m_out: Int):
    """Parse ``/json/<count>?m=<m>`` into *count_out* and *m_out*.

    Sets count_out to -1 if count is missing/non-numeric. Defaults *m* to 1
    when ``?m=`` is absent or non-numeric.
    """
    var bytes = target.as_bytes()
    var n = len(bytes)
    var prefix_len = 6  # len("/json/")
    m_out = 1
    count_out = -1
    if n <= prefix_len:
        return

    var count = 0
    var has_digit = False
    var i = prefix_len
    while i < n and bytes[i] >= UInt8(ord("0")) and bytes[i] <= UInt8(ord("9")):
        count = count * 10 + Int(bytes[i]) - Int(ord("0"))
        has_digit = True
        i += 1
    if not has_digit:
        return
    count_out = count

    var m_opt = _parse_query_int(target, "m")
    if m_opt.__bool__():
        var m = m_opt.value()
        if m > 0:
            m_out = m


def handle_json(
    target: String,
    mut resp: ResponseWriter,
    state_ptr: UnsafePointer[BenchState, MutAnyOrigin],
) raises:
    """GET /json/{count}?m=<m> -> application/json with computed totals."""
    var count: Int = -1
    var m: Int = 1
    _parse_json_path(target, count, m)
    if count < 0:
        handle_404(resp)
        return

    var dataset_len = len(state_ptr[].dataset)
    if count > dataset_len:
        count = dataset_len
    if count < 0:
        count = 0

    var body = List[UInt8]()
    write_bytes(body, String('{"items":[').as_bytes())

    var i = 0
    while i < count:
        if i > 0:
            body.append(UInt8(ord(",")))
        ref item = state_ptr[].dataset[i]
        write_bytes(body, String('{"id":').as_bytes())
        write_uint(body, item.id)
        write_bytes(body, String(',"name":').as_bytes())
        write_bytes(body, Span(item.name_quoted))
        write_bytes(body, String(',"category":').as_bytes())
        write_bytes(body, Span(item.category_quoted))
        write_bytes(body, String(',"price":').as_bytes())
        write_uint(body, item.price)
        write_bytes(body, String(',"quantity":').as_bytes())
        write_uint(body, item.quantity)
        write_bytes(body, String(',"active":').as_bytes())
        if item.active:
            write_bytes(body, String("true").as_bytes())
        else:
            write_bytes(body, String("false").as_bytes())
        write_bytes(body, String(',"tags":').as_bytes())
        write_bytes(body, Span(item.tags_array))
        write_bytes(body, String(',"rating":').as_bytes())
        write_bytes(body, Span(item.rating_object))
        write_bytes(body, String(',"total":').as_bytes())
        write_uint(body, item.price * item.quantity * UInt64(m))
        body.append(UInt8(ord("}")))
        i += 1

    write_bytes(body, String('],"count":').as_bytes())
    write_uint(body, UInt64(count))
    body.append(UInt8(ord("}")))

    var hdrs = Headers()
    hdrs.add("content-type", "application/json")
    hdrs.add("content-length", String(len(body)))
    resp.send_status(StatusCode(200), hdrs^)
    _ = resp.try_send_body(BodyFrame.data(body^))
    resp.end()


# ---------------------------------------------------------------------------
# Request dispatcher
# ---------------------------------------------------------------------------


def _starts_with(haystack: String, needle: String) -> Bool:
    """Check if haystack starts with needle via byte comparison."""
    var h = haystack.as_bytes()
    var n = needle.as_bytes()
    if len(n) > len(h):
        return False
    var i = 0
    while i < len(n):
        if h[i] != n[i]:
            return False
        i += 1
    return True


def _dispatch_request(
    target: String,
    headers: Headers,
    mut resp: ResponseWriter,
    state_ptr: UnsafePointer[BenchState, MutAnyOrigin],
) raises:
    """Route a request based on URL path prefix."""
    if _starts_with(target, String("/plaintext")):
        handle_plaintext(resp)
    elif _starts_with(target, String("/baseline2")) or _starts_with(target, String("/baseline11")):
        handle_baseline2(target, resp)
    elif _starts_with(target, String("/json/")):
        handle_json(target, resp, state_ptr)
    elif _starts_with(target, String("/static/")):
        handle_static(target, headers, resp, state_ptr)
    else:
        handle_404(resp)


# ---------------------------------------------------------------------------
# BenchHandler — StreamHandler implementation
# ---------------------------------------------------------------------------


struct BenchHandler(StreamHandler):
    """StreamHandler that dispatches to benchmark endpoints."""

    var state_ptr: UnsafePointer[BenchState, MutAnyOrigin]

    def __init__(out self, state_ptr: UnsafePointer[BenchState, MutAnyOrigin]):
        self.state_ptr = state_ptr

    def __init__(out self, *, deinit take: Self):
        self.state_ptr = take.state_ptr

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        _dispatch_request(req.target, req.headers, resp, self.state_ptr)

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_reset(
        mut self,
        error: StreamError,
    ):
        pass


# ---------------------------------------------------------------------------
# CoroBody functions for H2 and H3 coro servers
# ---------------------------------------------------------------------------


def bench_h2_body_fn(
    ctx_ptr: UnsafePointer[H2CoroStreamCtx, MutAnyOrigin],
) raises:
    """H2BodyFn for H2CoroServer (Sprint 1 Path A — sync handler)."""
    var state_ptr = ctx_ptr[].extra_data.bitcast[BenchState]().as_any_origin()
    _dispatch_request(
        ctx_ptr[].request.target,
        ctx_ptr[].request.headers,
        ctx_ptr[].resp_writer,
        state_ptr,
    )


def bench_h3_body_fn(
    ctx_ptr: UnsafePointer[H3CoroStreamCtx, MutAnyOrigin],
) raises:
    """H3BodyFn for H3CoroServer (Sprint 2A Path A — sync handler)."""
    var state_ptr = ctx_ptr[].extra_data.bitcast[BenchState]().as_any_origin()
    _dispatch_request(
        ctx_ptr[].request.target,
        ctx_ptr[].request.headers,
        ctx_ptr[].resp_writer,
        state_ptr,
    )
