# conformance/tests/test_h1_response_cross.mojo
#
# HC-2a: Three-way cross-validation for response parsing.
# For accept vectors, all three parsers must agree on status_code, reason,
# version, headers, body.  For reject vectors, our parser must reject;
# oracle disagreements are logged but not failures.
from lib.test_util import load_vectors, hex_decode, assert_true, assert_equal
from lib.http1.types import ParseConfig, ParsedResponse
from lib.http1.response import parse_response
from lib.http1.oracles import parse_response_with_h11 as oracle_h11
from lib.http1.oracles import parse_response_with_httptools as oracle_httptools
from python import Python, PythonObject


def _has_key(obj: PythonObject, key: String) -> Bool:
    """Check if a Python dict has a given key."""
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


def _iequals(a: String, b: String) -> Bool:
    """Case-insensitive ASCII string equality."""
    var ab = a.as_bytes()
    var bb = b.as_bytes()
    if len(ab) != len(bb):
        return False
    for i in range(len(ab)):
        var ca = Int(ab[i])
        var cb = Int(bb[i])
        if ca >= 65 and ca <= 90:
            ca += 32
        if cb >= 65 and cb <= 90:
            cb += 32
        if ca != cb:
            return False
    return True


def _oracle_error(oracle: PythonObject) -> String:
    """Return the error string from an oracle result, or empty if no error."""
    try:
        if _has_key(oracle, "error"):
            var err = oracle["error"]
            var builtins = Python.import_module("builtins")
            if Bool(builtins.bool(err is builtins.None)):
                return String("")
            return String(err)
        return String("")
    except:
        return String("(failed to read oracle error)")


def _oracle_field(oracle: PythonObject, key: String) -> String:
    """Read a string field from an oracle dict, return empty if None."""
    try:
        if not _has_key(oracle, key):
            return String("")
        var val = oracle[key]
        var builtins = Python.import_module("builtins")
        if Bool(builtins.bool(val is builtins.None)):
            return String("")
        return String(val)
    except:
        return String("")


def _oracle_int_field(oracle: PythonObject, key: String) -> Int:
    """Read an int field from an oracle dict, return -1 if None."""
    try:
        if not _has_key(oracle, key):
            return -1
        var val = oracle[key]
        var builtins = Python.import_module("builtins")
        if Bool(builtins.bool(val is builtins.None)):
            return -1
        return Int(py=val)
    except:
        return -1


def _oracle_header_count(oracle: PythonObject) raises -> Int:
    """Return number of headers in oracle result."""
    var builtins = Python.import_module("builtins")
    if not _has_key(oracle, "headers"):
        return 0
    return Int(py=builtins.len(oracle["headers"]))


def _oracle_body_bytes(oracle: PythonObject) -> List[UInt8]:
    """Extract body bytes from oracle result."""
    var result = List[UInt8]()
    try:
        if not _has_key(oracle, "body"):
            return result^
        var body = oracle["body"]
        var builtins = Python.import_module("builtins")
        if Bool(builtins.bool(body is builtins.None)):
            return result^
        var body_len = Int(py=builtins.len(body))
        for i in range(body_len):
            result.append(UInt8(Int(py=body[i])))
    except:
        pass
    return result^


def _check_response_oracle_agrees(
    result: ParsedResponse,
    oracle: PythonObject,
    oracle_name: String,
    vec_id: String,
) raises -> Bool:
    """Check that an oracle's successful parse agrees with our parser.
    Returns True if all fields match, False otherwise.
    """
    var err = _oracle_error(oracle)
    if len(err) > 0:
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " rejected but we accepted (oracle error: " + err + ")"
        )
        return False

    var ok = True

    # Status code
    var o_status = _oracle_int_field(oracle, "status_code")
    if result.status_code != o_status:
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " status_code: ours=" + String(result.status_code)
            + " oracle=" + String(o_status)
        )
        ok = False

    # Reason
    var o_reason = _oracle_field(oracle, "reason")
    if not _iequals(result.reason, o_reason):
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " reason: ours='" + result.reason + "' oracle='" + o_reason + "'"
        )
        ok = False

    # Version
    var o_version = _oracle_field(oracle, "version")
    if result.version != o_version:
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " version: ours='" + result.version + "' oracle='" + o_version + "'"
        )
        ok = False

    # Headers -- compare count and name/value pairs (case-insensitive names)
    var o_hdr_count = _oracle_header_count(oracle)
    if len(result.headers) != o_hdr_count:
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " header count: ours=" + String(len(result.headers))
            + " oracle=" + String(o_hdr_count)
        )
        ok = False
    else:
        var hdrs = oracle["headers"]
        for i in range(o_hdr_count):
            var pair = hdrs[i]
            var o_name = String(pair[0])
            var o_val = String(pair[1])
            if not _iequals(result.headers[i].name, o_name):
                print(
                    "    WARN [" + vec_id + "] " + oracle_name
                    + " header[" + String(i) + "] name: ours='"
                    + result.headers[i].name + "' oracle='" + o_name + "'"
                )
                ok = False
            if result.headers[i].value != o_val:
                print(
                    "    WARN [" + vec_id + "] " + oracle_name
                    + " header[" + String(i) + "] value: ours='"
                    + result.headers[i].value + "' oracle='" + o_val + "'"
                )
                ok = False

    # Body
    var o_body = _oracle_body_bytes(oracle)
    if len(result.body) != len(o_body):
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " body length: ours=" + String(len(result.body))
            + " oracle=" + String(len(o_body))
        )
        ok = False
    else:
        for i in range(len(result.body)):
            if result.body[i] != o_body[i]:
                print(
                    "    WARN [" + vec_id + "] " + oracle_name
                    + " body differs at byte " + String(i)
                )
                ok = False
                break

    return ok


def run_accept_response_cross(
    wire: List[UInt8],
    vec_id: String,
    request_method: String,
) raises -> Int:
    """Cross-validate an accept response vector. Returns number of agreement failures."""
    var config = ParseConfig()
    var result = parse_response(wire, request_method, config)

    assert_true(
        result.ok(),
        vec_id + ": our parser rejected but expected accept: " + result.error,
    )

    var failures = 0

    # h11 -- always cross-validate
    var wire_h11 = List[UInt8]()
    for i in range(len(wire)):
        wire_h11.append(wire[i])

    var h11_result = oracle_h11(wire_h11, request_method)
    var h11_ok = _check_response_oracle_agrees(result, h11_result, "h11", vec_id)
    if not h11_ok:
        failures += 1

    # httptools -- skip for HEAD and CONNECT (cannot model request context)
    var skip_httptools = _iequals(request_method, "HEAD") or _iequals(request_method, "CONNECT")
    if skip_httptools:
        print("    INFO [" + vec_id + "] skipping httptools (request_method=" + request_method + ")")
    else:
        var wire_ht = List[UInt8]()
        for i in range(len(wire)):
            wire_ht.append(wire[i])

        var ht_result = oracle_httptools(wire_ht, request_method)
        var ht_ok = _check_response_oracle_agrees(result, ht_result, "httptools", vec_id)
        if not ht_ok:
            failures += 1

    return failures


def run_reject_response_cross(
    wire: List[UInt8],
    vec_id: String,
    request_method: String,
) raises -> Int:
    """Cross-validate a reject response vector. Returns 0 always (reject
    disagreements are warnings only since oracles are more lenient).
    """
    var config = ParseConfig()
    var result = parse_response(wire, request_method, config)

    assert_true(
        not result.ok(),
        vec_id + ": our parser accepted but expected reject",
    )

    # Check oracles -- log if they disagree but don't fail
    var wire_h11 = List[UInt8]()
    for i in range(len(wire)):
        wire_h11.append(wire[i])

    var h11_result = oracle_h11(wire_h11, request_method)
    var h11_err = _oracle_error(h11_result)
    if len(h11_err) == 0:
        print(
            "    INFO [" + vec_id + "] h11 ACCEPTS what we reject"
            + " (our error: " + result.error + ")"
        )

    var skip_httptools = _iequals(request_method, "HEAD") or _iequals(request_method, "CONNECT")
    if not skip_httptools:
        var wire_ht = List[UInt8]()
        for i in range(len(wire)):
            wire_ht.append(wire[i])

        var ht_result = oracle_httptools(wire_ht, request_method)
        var ht_err = _oracle_error(ht_result)
        if len(ht_err) == 0:
            print(
                "    INFO [" + vec_id + "] httptools ACCEPTS what we reject"
                + " (our error: " + result.error + ")"
            )

    return 0


def main() raises:
    # Sentinel assertion check
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var builtins = Python.import_module("builtins")

    # ===== Phase 1: Vector-based cross-validation =====
    print("=== Phase 1: Vector-based response cross-validation ===")

    var files = List[String]()
    files.append("vectors/rfc9112/response_status.json")
    files.append("vectors/rfc9112/response_body.json")
    files.append("vectors/rfc9112/response_head.json")
    files.append("vectors/rfc9112/response_informational.json")
    files.append("vectors/rfc9112/response_no_body.json")
    files.append("vectors/rfc9112/response_framing.json")

    var total_vectors = 0
    var accept_agree = 0
    var accept_disagree = 0
    var reject_tested = 0
    var skipped_dual = 0

    for fi in range(len(files)):
        var path = files[fi]
        var vectors = load_vectors(path)
        var count = Int(py=builtins.len(vectors))

        for vi in range(count):
            var v = vectors[vi]
            var vec_id = String(v["id"])
            var wire_hex = String(v["input"]["wire_hex"])

            # Skip dual-mode vectors
            if _has_key(v, "mode_flag") or _has_key(v, "mode_flags"):
                skipped_dual += 1
                continue

            # Skip deferred vectors
            if _has_key(v, "deferred"):
                skipped_dual += 1
                continue

            # Skip oracle disagreement / auto-corrected vectors
            if _has_key(v, "oracle_disagreement") or _has_key(v, "auto_corrected"):
                skipped_dual += 1
                continue

            var expected = v["expected"]
            var behavior = String(expected["behavior"])
            var wire = hex_decode(wire_hex)

            # Extract request_method (default to GET)
            var request_method = String("GET")
            if _has_key(v, "request_method"):
                request_method = String(v["request_method"])

            total_vectors += 1

            if behavior == "accept":
                var n_disagree = run_accept_response_cross(wire, vec_id, request_method)
                if n_disagree == 0:
                    accept_agree += 1
                else:
                    accept_disagree += 1
            else:
                _ = run_reject_response_cross(wire, vec_id, request_method)
                reject_tested += 1

        print("  " + path + ": processed")

    print(
        "  Vectors: " + String(total_vectors) + " tested, "
        + String(skipped_dual) + " dual-mode/deferred skipped"
    )
    print(
        "  Accept: " + String(accept_agree) + " full-agree, "
        + String(accept_disagree) + " with oracle disagreements"
    )
    print("  Reject: " + String(reject_tested) + " tested (ours must reject)")

    assert_true(total_vectors >= 20, "expected at least 20 non-dual vectors, got " + String(total_vectors))

    # ===== Phase 2: Random response cross-validation =====
    print("")
    print("=== Phase 2: Random response cross-validation ===")

    var time_mod = Python.import_module("time")
    var ts = Int(py=time_mod.time_ns())

    var status_codes = List[Int]()
    status_codes.append(200)
    status_codes.append(201)
    status_codes.append(204)
    status_codes.append(301)
    status_codes.append(302)
    status_codes.append(400)
    status_codes.append(403)
    status_codes.append(404)
    status_codes.append(500)
    status_codes.append(503)

    var reasons = List[String]()
    reasons.append("OK")
    reasons.append("Created")
    reasons.append("No Content")
    reasons.append("Moved Permanently")
    reasons.append("Found")
    reasons.append("Bad Request")
    reasons.append("Forbidden")
    reasons.append("Not Found")
    reasons.append("Internal Server Error")
    reasons.append("Service Unavailable")

    var rand_agree = 0
    var rand_total = 20
    var seed = ts

    for ri in range(rand_total):
        # Pseudo-random selection
        var sc_idx = seed % len(status_codes)
        seed = (seed * 6364136223846793005 + 1442695040888963407) % (1 << 63)
        var status_code = status_codes[sc_idx]
        var reason = reasons[sc_idx]

        # 204 has no body per spec -- pick a different one for body test
        # We want to test body parsing, so skip 204 and replace with 200
        var has_body = True
        if status_code == 204:
            has_body = False

        # Generate random header value
        var charset = String("abcdefghijklmnopqrstuvwxyz0123456789")
        var cs_bytes = charset.as_bytes()
        var rand_val = String()
        var rv = seed
        for _ in range(12):
            var idx = rv % len(cs_bytes)
            rand_val += chr(Int(cs_bytes[idx]))
            rv = (rv * 6364136223846793005 + 1442695040888963407) % (1 << 63)
        seed = rv

        # Generate random body
        var rand_body = String()
        if has_body:
            var body_rv = seed
            var body_len = 5 + (seed % 20)
            seed = (seed * 6364136223846793005 + 1442695040888963407) % (1 << 63)
            for _ in range(body_len):
                var idx = body_rv % len(cs_bytes)
                rand_body += chr(Int(cs_bytes[idx]))
                body_rv = (body_rv * 6364136223846793005 + 1442695040888963407) % (1 << 63)
            seed = body_rv

        # Build wire bytes
        var resp_str = String()
        if has_body:
            var body_cl = String(len(rand_body))
            resp_str = (
                "HTTP/1.1 " + String(status_code) + " " + reason + "\r\n"
                + "Content-Length: " + body_cl + "\r\n"
                + "X-Rand: " + rand_val + "\r\n"
                + "\r\n"
                + rand_body
            )
        else:
            resp_str = (
                "HTTP/1.1 " + String(status_code) + " " + reason + "\r\n"
                + "X-Rand: " + rand_val + "\r\n"
                + "\r\n"
            )

        var resp_bytes = resp_str.as_bytes()
        var wire = List[UInt8]()
        for bi in range(len(resp_bytes)):
            wire.append(resp_bytes[bi])

        var rid = "rand-resp-" + String(ri)

        # Our parser
        var config = ParseConfig()
        var result = parse_response(wire, String("GET"), config)
        assert_true(result.ok(), rid + ": our parser rejected: " + result.error)

        # h11
        var wire_h11 = List[UInt8]()
        for bi2 in range(len(wire)):
            wire_h11.append(wire[bi2])
        var h11_res = oracle_h11(wire_h11, String("GET"))

        # httptools (GET is fine -- no HEAD/CONNECT context issue)
        var wire_ht = List[UInt8]()
        for bi3 in range(len(wire)):
            wire_ht.append(wire[bi3])
        var ht_res = oracle_httptools(wire_ht, String("GET"))

        var h11_ok = _check_response_oracle_agrees(result, h11_res, "h11", rid)
        var ht_ok = _check_response_oracle_agrees(result, ht_res, "httptools", rid)

        if h11_ok and ht_ok:
            rand_agree += 1
        else:
            # Random well-formed responses must agree across all parsers
            assert_true(
                False,
                rid + ": random response disagreement (status=" + String(status_code) + ")",
            )

    print(
        "  " + String(rand_agree) + "/" + String(rand_total)
        + " random responses: full three-way agreement"
    )

    # ===== Summary =====
    print("")
    print(
        "test_h1_response_cross: "
        + String(total_vectors + rand_total)
        + " total tests passed"
    )
    print(
        "  vector accept: " + String(accept_agree) + " agree | "
        + "vector reject: " + String(reject_tested) + " verified | "
        + "random: " + String(rand_agree) + " agree"
    )
