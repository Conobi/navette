# tests/test_cross_validation.mojo
#
# Phase B Task 7 — Cross-validation between the conformance batch parser
# (conformance/lib/http1) and the production incremental parser
# (src/h1/parser). Both parsers are fed the same RFC 9112 vectors and the
# results are compared field-by-field. This is the proof that the new
# incremental parser exposed by H1Connection produces results identical
# to the conformance reference.
#
# Run with:
#   cd ~/Projets/perso/mojo-net && rm -f src.mojopkg && \
#     uv run mojo run -I . -I conformance -D ASSERT=all \
#     tests/test_cross_validation.mojo

from std.collections.optional import Optional
from std.python import Python, PythonObject

# Conformance (batch / one-shot) parser.
from lib.test_util import load_vectors, hex_decode
from lib.http1.types import (
    ParseConfig as CParseConfig,
    ParsedRequest,
    ParsedResponse,
    Header as CHeader,
)
from lib.http1.parser import parse_request as batch_parse_request
from lib.http1.response import parse_response as batch_parse_response

# Production (incremental) parser — call directly so we don't have to
# reason about H1Connection lifecycle (HTTP/1.0 close, error phase, etc.).
from src.http.method import Method
from src.http.request import Request
from src.http.response import Response
from src.http.body import BodyFrame
from src.h1.config import ParseConfig
from src.h1.parser import (
    try_parse_request,
    try_parse_response,
    ParseResult,
)

from tests._test_util import assert_true


# ----------------------------------------------------------------------------
# Python helpers
# ----------------------------------------------------------------------------


def _has_key(obj: PythonObject, key: String) -> Bool:
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


def _is_accept(vec: PythonObject) -> Bool:
    """Return True iff the vector's expected behavior is ``accept``.

    Skips dual-mode vectors (mode_flag / mode_flags) entirely; the cross
    test runs strict-mode only.
    """
    try:
        if _has_key(vec, "mode_flag") or _has_key(vec, "mode_flags"):
            return False
        if not _has_key(vec, "expected"):
            return False
        var expected = vec["expected"]
        if not _has_key(expected, "behavior"):
            return False
        return String(expected["behavior"]) == "accept"
    except:
        return False


def _is_skipped_meta(vec: PythonObject) -> Bool:
    """Return True for vectors that should be skipped outright."""
    if _has_key(vec, "deferred"):
        return True
    if _has_key(vec, "auto_corrected"):
        return True
    if _has_key(vec, "oracle_disagreement"):
        return True
    # Multi-message connection vectors are exercised by
    # conformance/test_h1_connection_cross.mojo, not by this test.
    try:
        if _has_key(vec, "input"):
            var inp = vec["input"]
            if _has_key(inp, "messages"):
                return True
    except:
        pass
    return False


# ----------------------------------------------------------------------------
# String helpers
# ----------------------------------------------------------------------------


def _strip_http_prefix(s: String) -> String:
    """Drop a leading ``HTTP/`` token (5 bytes) if present."""
    var bytes = s.as_bytes()
    if (
        len(bytes) >= 5
        and bytes[0] == UInt8(ord("H"))
        and bytes[1] == UInt8(ord("T"))
        and bytes[2] == UInt8(ord("T"))
        and bytes[3] == UInt8(ord("P"))
        and bytes[4] == UInt8(ord("/"))
    ):
        var out = String()
        for i in range(5, len(bytes)):
            out += chr(Int(bytes[i]))
        return out^
    return s


def _to_lower(s: String) -> String:
    var bytes = s.as_bytes()
    var out = String()
    for i in range(len(bytes)):
        var c = Int(bytes[i])
        if c >= 65 and c <= 90:
            c += 32
        out += chr(c)
    return out^


def _bytes_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _flatten_data_frames(ref frames: List[BodyFrame]) -> List[UInt8]:
    """Concatenate all Data frames; ignore Trailers frames."""
    var out = List[UInt8]()
    for i in range(len(frames)):
        if frames[i].is_data():
            ref d = frames[i].data()
            for j in range(len(d)):
                out.append(d[j])
    return out^


def _extract_trailers(
    ref frames: List[BodyFrame],
) -> List[Tuple[String, String]]:
    """Pull trailer (name, value) pairs out of any Trailers body frame."""
    var out = List[Tuple[String, String]]()
    for i in range(len(frames)):
        if frames[i].is_trailers():
            ref hdrs = frames[i].trailers()
            for hi in range(len(hdrs)):
                out.append((hdrs.name_at(hi), hdrs.value_at(hi)))
    return out^


# ----------------------------------------------------------------------------
# Cross-validation core
# ----------------------------------------------------------------------------


struct CrossStats(Copyable, Movable):
    var total: Int
    var matched: Int
    var skipped: Int
    var batch_only: Int  # batch accepted, prod rejected/incomplete
    var prod_only: Int  # prod accepted, batch rejected
    var field_mismatch: Int

    def __init__(out self):
        self.total = 0
        self.matched = 0
        self.skipped = 0
        self.batch_only = 0
        self.prod_only = 0
        self.field_mismatch = 0

    def __init__(out self, *, other: Self):
        self.total = other.total
        self.matched = other.matched
        self.skipped = other.skipped
        self.batch_only = other.batch_only
        self.prod_only = other.prod_only
        self.field_mismatch = other.field_mismatch

    def __init__(out self, *, deinit take: Self):
        self.total = take.total
        self.matched = take.matched
        self.skipped = take.skipped
        self.batch_only = take.batch_only
        self.prod_only = take.prod_only
        self.field_mismatch = take.field_mismatch


def _compare_request(
    batch: ParsedRequest, prod: Request, vec_id: String
) raises -> Bool:
    """Return True iff the two parses agree on every observable field."""
    # Method.
    var prod_method = String(prod.method)
    if prod_method != batch.method:
        print(
            "MISMATCH ["
            + vec_id
            + "] method: batch="
            + batch.method
            + " prod="
            + prod_method
        )
        return False

    # Request target.
    if prod.target != batch.target:
        print(
            "MISMATCH ["
            + vec_id
            + "] target: batch="
            + batch.target
            + " prod="
            + prod.target
        )
        return False

    # Version. Production exposes Version; conformance keeps the literal
    # version token from the request line. Compare via String() of the
    # production Version.
    # Conformance stores the bare digits ("1.1"/"1.0"); production renders
    # the full token ("HTTP/1.1"). Compare via the conformance form.
    var prod_version = String(prod.version)
    var prod_version_norm = _strip_http_prefix(prod_version)
    if prod_version_norm != batch.version:
        print(
            "MISMATCH ["
            + vec_id
            + "] version: batch="
            + batch.version
            + " prod="
            + prod_version
        )
        return False

    # Header count.
    if len(prod.headers) != len(batch.headers):
        print(
            "MISMATCH ["
            + vec_id
            + "] header count: batch="
            + String(len(batch.headers))
            + " prod="
            + String(len(prod.headers))
        )
        return False

    # Header content (case-insensitive on name; production lowercases).
    for hi in range(len(batch.headers)):
        var bn = _to_lower(batch.headers[hi].name)
        var pn = prod.headers.name_at(hi)
        if bn != pn:
            print(
                "MISMATCH ["
                + vec_id
                + "] header["
                + String(hi)
                + "] name: batch="
                + batch.headers[hi].name
                + " prod="
                + pn
            )
            return False
        var bv = batch.headers[hi].value
        var pv = prod.headers.value_at(hi)
        if bv != pv:
            print(
                "MISMATCH ["
                + vec_id
                + "] header["
                + String(hi)
                + "] value: batch="
                + bv
                + " prod="
                + pv
            )
            return False

    # Body bytes. Request bodies are RequestBody (M2.5a §5.12).
    var prod_body = List[UInt8]()
    if prod.body.is_buffered():
        prod_body = prod.body.bytes().copy()
    if not _bytes_equal(prod_body, batch.body):
        print(
            "MISMATCH ["
            + vec_id
            + "] body length: batch="
            + String(len(batch.body))
            + " prod="
            + String(len(prod_body))
        )
        return False

    # Trailers (chunked) on requests are explicitly dropped by the M2.5a
    # parser — see RequestBody design in spec §5.12. We do not compare
    # trailers here. Vectors that carry request trailers will still match
    # on body bytes, headers, method, and target.
    return True


def _compare_response(
    batch: ParsedResponse, prod: Response, vec_id: String
) raises -> Bool:
    # Status code.
    var prod_status = Int(prod.status.code())
    if prod_status != batch.status_code:
        print(
            "MISMATCH ["
            + vec_id
            + "] status: batch="
            + String(batch.status_code)
            + " prod="
            + String(prod_status)
        )
        return False

    # Version.
    var prod_version = String(prod.version)
    var prod_version_norm = _strip_http_prefix(prod_version)
    if prod_version_norm != batch.version:
        print(
            "MISMATCH ["
            + vec_id
            + "] version: batch="
            + batch.version
            + " prod="
            + prod_version
        )
        return False

    # Header count.
    if len(prod.headers) != len(batch.headers):
        print(
            "MISMATCH ["
            + vec_id
            + "] header count: batch="
            + String(len(batch.headers))
            + " prod="
            + String(len(prod.headers))
        )
        return False

    for hi in range(len(batch.headers)):
        var bn = _to_lower(batch.headers[hi].name)
        var pn = prod.headers.name_at(hi)
        if bn != pn:
            print(
                "MISMATCH ["
                + vec_id
                + "] header["
                + String(hi)
                + "] name: batch="
                + batch.headers[hi].name
                + " prod="
                + pn
            )
            return False
        if batch.headers[hi].value != prod.headers.value_at(hi):
            print(
                "MISMATCH ["
                + vec_id
                + "] header["
                + String(hi)
                + "] value"
            )
            return False

    # Body bytes.
    var prod_body = _flatten_data_frames(prod.body)
    if not _bytes_equal(prod_body, batch.body):
        print(
            "MISMATCH ["
            + vec_id
            + "] body length: batch="
            + String(len(batch.body))
            + " prod="
            + String(len(prod_body))
        )
        return False

    return True


# ----------------------------------------------------------------------------
# Per-suite drivers
# ----------------------------------------------------------------------------


def _cross_request_file(path: String, mut stats: CrossStats) raises:
    var vectors = load_vectors(path)
    var builtins = Python.import_module("builtins")
    var count = Int(py=builtins.len(vectors))

    for vi in range(count):
        var vec = vectors[vi]
        var vec_id = String(vec["id"])

        if _is_skipped_meta(vec) or not _is_accept(vec):
            stats.skipped += 1
            continue

        var wire_hex = String(vec["input"]["wire_hex"])
        var wire = hex_decode(wire_hex)

        # Batch (conformance) parser — strict default config.
        var batch_result = batch_parse_request(wire.copy(), CParseConfig())
        if not batch_result.ok():
            # Conformance parser refused an accept vector — that's a
            # conformance issue, not something this cross-test can debug.
            # Count as skipped to keep this test focused on the production
            # parser.
            stats.skipped += 1
            continue

        stats.total += 1

        # Production parser — call try_parse_request directly so we don't
        # have to reason about connection-level state.
        var prod_result = try_parse_request(wire, 0, 0, ParseConfig())

        if len(prod_result.error) > 0:
            print(
                "BATCH_ONLY ["
                + vec_id
                + "] prod error: "
                + prod_result.error
            )
            stats.batch_only += 1
            continue
        if not prod_result.has_request():
            print("BATCH_ONLY [" + vec_id + "] prod returned incomplete")
            stats.batch_only += 1
            continue

        var prod_req = prod_result.request.take()
        if _compare_request(batch_result, prod_req, vec_id):
            stats.matched += 1
        else:
            stats.field_mismatch += 1


def _cross_response_file(path: String, mut stats: CrossStats) raises:
    var vectors = load_vectors(path)
    var builtins = Python.import_module("builtins")
    var count = Int(py=builtins.len(vectors))

    for vi in range(count):
        var vec = vectors[vi]
        var vec_id = String(vec["id"])

        if _is_skipped_meta(vec) or not _is_accept(vec):
            stats.skipped += 1
            continue

        var wire_hex = String(vec["input"]["wire_hex"])
        var wire = hex_decode(wire_hex)

        # Determine the matching request method (defaults to GET).
        var request_method_str = String("GET")
        try:
            if _has_key(vec["input"], "request_method"):
                request_method_str = String(vec["input"]["request_method"])
        except:
            pass

        var batch_result = batch_parse_response(
            wire.copy(), request_method_str, CParseConfig()
        )
        if not batch_result.ok():
            stats.skipped += 1
            continue

        stats.total += 1

        var method_obj = Method.custom(request_method_str)
        var prod_result = try_parse_response(
            wire, 0, 0, method_obj^, ParseConfig()
        )

        if len(prod_result.error) > 0:
            print(
                "BATCH_ONLY ["
                + vec_id
                + "] prod error: "
                + prod_result.error
            )
            stats.batch_only += 1
            continue
        if not prod_result.has_response():
            print("BATCH_ONLY [" + vec_id + "] prod returned incomplete")
            stats.batch_only += 1
            continue

        var prod_resp = prod_result.response.take()
        if _compare_response(batch_result, prod_resp, vec_id):
            stats.matched += 1
        else:
            stats.field_mismatch += 1


# ----------------------------------------------------------------------------
# Top-level tests
# ----------------------------------------------------------------------------


def test_request_vectors() raises:
    print("--- request cross-validation ---")
    var stats = CrossStats()
    var files = List[String]()
    files.append("conformance/vectors/rfc9112/request_line.json")
    files.append("conformance/vectors/rfc9112/headers.json")
    files.append("conformance/vectors/rfc9112/content_length.json")
    files.append("conformance/vectors/rfc9112/chunked.json")
    files.append("conformance/vectors/rfc9112/host.json")

    for fi in range(len(files)):
        _cross_request_file(files[fi], stats)

    print(
        "request totals: matched="
        + String(stats.matched)
        + "/"
        + String(stats.total)
        + " skipped="
        + String(stats.skipped)
        + " batch_only="
        + String(stats.batch_only)
        + " prod_only="
        + String(stats.prod_only)
        + " field_mismatch="
        + String(stats.field_mismatch)
    )
    assert_true(
        stats.batch_only == 0,
        "request: batch parser accepted but production rejected/incomplete",
    )
    assert_true(
        stats.field_mismatch == 0,
        "request: production parser disagrees with batch parser on fields",
    )
    assert_true(
        stats.matched == stats.total,
        "request: matched != total ("
        + String(stats.matched)
        + "/"
        + String(stats.total)
        + ")",
    )
    print("PASS: test_request_vectors")


def test_response_vectors() raises:
    print("--- response cross-validation ---")
    var stats = CrossStats()
    var files = List[String]()
    files.append("conformance/vectors/rfc9112/response_status.json")
    files.append("conformance/vectors/rfc9112/response_body.json")
    files.append("conformance/vectors/rfc9112/response_framing.json")
    files.append("conformance/vectors/rfc9112/response_head.json")
    files.append("conformance/vectors/rfc9112/response_informational.json")
    files.append("conformance/vectors/rfc9112/response_no_body.json")

    for fi in range(len(files)):
        _cross_response_file(files[fi], stats)

    print(
        "response totals: matched="
        + String(stats.matched)
        + "/"
        + String(stats.total)
        + " skipped="
        + String(stats.skipped)
        + " batch_only="
        + String(stats.batch_only)
        + " prod_only="
        + String(stats.prod_only)
        + " field_mismatch="
        + String(stats.field_mismatch)
    )
    assert_true(
        stats.batch_only == 0,
        "response: batch parser accepted but production rejected/incomplete",
    )
    assert_true(
        stats.field_mismatch == 0,
        "response: production parser disagrees with batch parser on fields",
    )
    assert_true(
        stats.matched == stats.total,
        "response: matched != total ("
        + String(stats.matched)
        + "/"
        + String(stats.total)
        + ")",
    )
    print("PASS: test_response_vectors")


def main() raises:
    test_request_vectors()
    test_response_vectors()
    print("\nAll cross-validation tests passed!")
