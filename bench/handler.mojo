# bench/handler.mojo
#
# HttpArena benchmark handlers: baseline2 (query-param sum), 404, and static
# file serving with pre-compressed variant support (br/gzip).

from std.collections.optional import Optional
from std.collections import Dict
from src.http.handler import ResponseWriter
from src.http.body import BodyFrame
from src.http.status import StatusCode
from src.http.headers import Headers
from interop.file_io import read_file


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
    _load_one_static(static_dir, "index.html", cache)
    _load_one_static(static_dir, "styles.css", cache)
    _load_one_static(static_dir, "script.js", cache)
    _load_one_static(static_dir, "data.json", cache)
    _load_one_static(static_dir, "image.png", cache)
    _load_one_static(static_dir, "favicon.ico", cache)
    _load_one_static(static_dir, "manifest.webmanifest", cache)
    _load_one_static(static_dir, "robots.txt", cache)
    return cache^


# ---------------------------------------------------------------------------
# Accept-Encoding check
# ---------------------------------------------------------------------------


def _accepts_encoding(headers: Headers, encoding: String) -> Bool:
    """Return True if the Accept-Encoding header contains *encoding*."""
    var ae = headers.get("accept-encoding")
    if len(ae) == 0:
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
    cache: Dict[String, StaticEntry],
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
    if filename not in cache:
        handle_404(resp)
        return
    var entry = cache[filename].copy()

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
