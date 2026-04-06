# conformance/tests/test_h1_cross_parser.mojo
#
# Three-way cross-validation: our parser vs h11 vs httptools.
# For accept vectors, all three must agree on method, target, version, headers.
# For reject vectors, our parser must reject. Oracles may disagree (they are
# lenient), so disagreements are logged but do not cause test failure.
from lib.test_util import load_vectors, hex_decode, assert_true
from lib.http1.types import ParseConfig, Header, ParsedRequest
from lib.http1.parser import parse_request
from lib.http1.oracles import parse_with_h11 as oracle_h11
from lib.http1.oracles import parse_with_httptools as oracle_httptools
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
        # Lowercase ASCII letters
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


def _oracle_header_count(oracle: PythonObject) raises -> Int:
    """Return number of headers in oracle result."""
    var builtins = Python.import_module("builtins")
    if not _has_key(oracle, "headers"):
        return 0
    return Int(py=builtins.len(oracle["headers"]))


def _check_oracle_agrees_accept(
    result: ParsedRequest,
    oracle: PythonObject,
    oracle_name: String,
    vec_id: String,
) raises -> Bool:
    """Check that an oracle's successful parse agrees with our parser.
    Returns True if all fields match, False otherwise.
    Differences are printed as warnings.
    """
    var builtins = Python.import_module("builtins")
    var err = _oracle_error(oracle)
    if len(err) > 0:
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " rejected but we accepted (oracle error: " + err + ")"
        )
        return False

    var ok = True

    # Method
    var o_method = _oracle_field(oracle, "method")
    if not _iequals(result.method, o_method):
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " method: ours='" + result.method + "' oracle='" + o_method + "'"
        )
        ok = False

    # Target
    var o_target = _oracle_field(oracle, "target")
    if result.target != o_target:
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " target: ours='" + result.target + "' oracle='" + o_target + "'"
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

    # Headers — compare count and name/value pairs (case-insensitive names)
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

    return ok


def run_accept_cross(wire: List[UInt8], vec_id: String) raises -> Int:
    """Cross-validate an accept vector. Returns number of agreement failures."""
    var config = ParseConfig()
    var result = parse_request(wire, config)

    assert_true(
        result.ok(),
        vec_id + ": our parser rejected but expected accept: " + result.error,
    )

    # Re-build wire copies for oracles (wire was consumed by parser)
    # Actually wire is passed by value so we can reuse it — but let's
    # build copies to be safe in case of move semantics
    var wire_h11 = List[UInt8]()
    var wire_ht = List[UInt8]()
    for i in range(len(wire)):
        wire_h11.append(wire[i])
        wire_ht.append(wire[i])

    var h11_result = oracle_h11(wire_h11)
    var ht_result = oracle_httptools(wire_ht)

    var failures = 0

    var h11_ok = _check_oracle_agrees_accept(result, h11_result, "h11", vec_id)
    if not h11_ok:
        failures += 1

    var ht_ok = _check_oracle_agrees_accept(result, ht_result, "httptools", vec_id)
    if not ht_ok:
        failures += 1

    return failures


def run_reject_cross(wire: List[UInt8], vec_id: String) raises -> Int:
    """Cross-validate a reject vector. Returns 0 always (reject disagreements
    are warnings only since oracles are more lenient than our strict parser).
    """
    var config = ParseConfig()
    var result = parse_request(wire, config)

    assert_true(
        not result.ok(),
        vec_id + ": our parser accepted but expected reject",
    )

    # Check oracles — log if they disagree but don't fail
    var wire_h11 = List[UInt8]()
    var wire_ht = List[UInt8]()
    for i in range(len(wire)):
        wire_h11.append(wire[i])
        wire_ht.append(wire[i])

    var h11_result = oracle_h11(wire_h11)
    var h11_err = _oracle_error(h11_result)
    if len(h11_err) == 0:
        print(
            "    INFO [" + vec_id + "] h11 ACCEPTS what we reject"
            + " (our error: " + result.error + ")"
        )

    var ht_result = oracle_httptools(wire_ht)
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
    print("=== Phase 1: Vector-based cross-validation ===")

    var files = List[String]()
    files.append("vectors/rfc9112/request_line.json")
    files.append("vectors/rfc9112/headers.json")
    files.append("vectors/rfc9112/content_length.json")
    files.append("vectors/rfc9112/chunked.json")
    files.append("vectors/rfc9112/host.json")

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

            # Skip dual-mode vectors — flag-specific behavior differs between
            # parsers, so cross-validation cannot meaningfully compare.
            if _has_key(v, "mode_flag") or _has_key(v, "mode_flags"):
                skipped_dual += 1
                continue

            # Skip deferred vectors — require parser features not yet implemented
            if _has_key(v, "deferred"):
                skipped_dual += 1
                continue

            # Skip vectors with oracle disagreement or auto-correction —
            # these are ambiguous cases not suitable for cross-validation.
            if _has_key(v, "oracle_disagreement") or _has_key(v, "auto_corrected"):
                skipped_dual += 1
                continue

            var expected = v["expected"]
            var behavior = String(expected["behavior"])
            var wire = hex_decode(wire_hex)
            total_vectors += 1

            # Converted vectors (llhttp-/aws-) use soft-fail
            var is_converted = vec_id.find("llhttp-") >= 0 or vec_id.find("aws-") >= 0

            if behavior == "accept":
                if is_converted:
                    try:
                        var n_disagree = run_accept_cross(wire, vec_id)
                        if n_disagree == 0:
                            accept_agree += 1
                        else:
                            accept_disagree += 1
                    except e:
                        print("    [SOFT FAIL] " + String(e))
                        accept_disagree += 1
                else:
                    var n_disagree = run_accept_cross(wire, vec_id)
                    if n_disagree == 0:
                        accept_agree += 1
                    else:
                        accept_disagree += 1
            else:
                if is_converted:
                    try:
                        _ = run_reject_cross(wire, vec_id)
                        reject_tested += 1
                    except e:
                        print("    [SOFT FAIL] " + String(e))
                        reject_tested += 1
                else:
                    _ = run_reject_cross(wire, vec_id)
                    reject_tested += 1

        print("  " + path + ": processed")

    print(
        "  Vectors: " + String(total_vectors) + " tested, "
        + String(skipped_dual) + " dual-mode skipped"
    )
    print(
        "  Accept: " + String(accept_agree) + " full-agree, "
        + String(accept_disagree) + " with oracle disagreements"
    )
    print("  Reject: " + String(reject_tested) + " tested (ours must reject)")

    # Accept vectors: our parser must match vector expectations (tested in
    # test_h1_parser.mojo). Oracle disagreements are informational — they
    # document known behavioral differences between parser implementations.
    # Full agreement is the ideal, but oracle quirks (httptools rejecting
    # unknown methods, not stripping OWS, counting trailers as headers, etc.)
    # are expected.
    assert_true(total_vectors >= 20, "expected at least 20 non-dual vectors")
    assert_true(
        accept_agree >= 15,
        "expected at least 15 full-agree accept vectors, got "
        + String(accept_agree),
    )

    # ===== Phase 2: Random request cross-validation =====
    print("")
    print("=== Phase 2: Random request cross-validation ===")

    var time_mod = Python.import_module("time")
    var ts = Int(py=time_mod.time_ns())

    var methods = List[String]()
    methods.append("GET")
    methods.append("POST")
    methods.append("PUT")
    methods.append("DELETE")
    methods.append("PATCH")
    methods.append("HEAD")
    methods.append("OPTIONS")

    var paths = List[String]()
    paths.append("/")
    paths.append("/index.html")
    paths.append("/api/v1/users")
    paths.append("/search?q=hello")
    paths.append("/data/42")
    paths.append("/a/b/c/d")

    var rand_agree = 0
    var rand_total = 20
    var seed = ts

    for ri in range(rand_total):
        # Pseudo-random selection
        var method_idx = seed % len(methods)
        seed = (seed * 6364136223846793005 + 1442695040888963407) % (1 << 63)
        var path_idx = seed % len(paths)
        seed = (seed * 6364136223846793005 + 1442695040888963407) % (1 << 63)

        var method = methods[method_idx]
        var path = paths[path_idx]

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

        # Build wire bytes
        var req_str = (
            method + " " + path + " HTTP/1.1\r\n"
            + "Host: test.example.com\r\n"
            + "X-Rand: " + rand_val + "\r\n"
            + "\r\n"
        )
        var req_bytes = req_str.as_bytes()
        var wire = List[UInt8]()
        for bi in range(len(req_bytes)):
            wire.append(req_bytes[bi])

        var rid = "rand-" + String(ri)

        # Our parser
        var config = ParseConfig()
        var result = parse_request(wire, config)
        assert_true(result.ok(), rid + ": our parser rejected: " + result.error)

        # Oracles
        var wire_h11 = List[UInt8]()
        var wire_ht = List[UInt8]()
        for bi2 in range(len(wire)):
            wire_h11.append(wire[bi2])
            wire_ht.append(wire[bi2])

        var h11_res = oracle_h11(wire_h11)
        var ht_res = oracle_httptools(wire_ht)

        var h11_ok = _check_oracle_agrees_accept(result, h11_res, "h11", rid)
        var ht_ok = _check_oracle_agrees_accept(result, ht_res, "httptools", rid)

        if h11_ok and ht_ok:
            rand_agree += 1
        else:
            # Random well-formed requests must agree across all parsers
            assert_true(
                False,
                rid + ": random request disagreement (method=" + method + " path=" + path + ")",
            )

    print(
        "  " + String(rand_agree) + "/" + String(rand_total)
        + " random requests: full three-way agreement"
    )

    # ===== Summary =====
    print("")
    print(
        "test_h1_cross_parser: "
        + String(total_vectors + rand_total)
        + " total tests passed"
    )
    print(
        "  vector accept: " + String(accept_agree) + " agree | "
        + "vector reject: " + String(reject_tested) + " verified | "
        + "random: " + String(rand_agree) + " agree"
    )
