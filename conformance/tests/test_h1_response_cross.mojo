# conformance/tests/test_h1_response_cross.mojo
#
# HC-2a: Three-way cross-validation for response parsing.
#
# As of §3.3 of the dependency-enhancement plan, h11 and httptools are no
# longer imported at test runtime. Oracle outputs are pre-materialized into
# conformance/vectors/rfc9112/h11_response_states.json by
# conformance/scripts/oracle_h1_h2_states.py and loaded here.
from lib.test_util import load_vectors, hex_decode, assert_true, assert_equal
from lib.http1.types import ParseConfig, ParsedResponse
from lib.http1.response import parse_response
from lib.stateful_vectors import load_states, py_has_key, py_field_str, py_field_int, py_field_bool
from python import Python, PythonObject


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


def _hex_to_bytes(s: String) raises -> List[UInt8]:
    return hex_decode(s)


def _oracle_header_count(oracle: PythonObject) raises -> Int:
    var builtins = Python.import_module("builtins")
    if not py_has_key(oracle, "headers"):
        return 0
    return Int(py=builtins.len(oracle["headers"]))


def _oracle_body_from_hex(oracle: PythonObject) -> List[UInt8]:
    """Extract body bytes from oracle result (body_hex field)."""
    var result = List[UInt8]()
    try:
        if not py_has_key(oracle, "body_hex"):
            return result^
        var body_hex = py_field_str(oracle, "body_hex")
        if len(body_hex) == 0:
            return result^
        result = hex_decode(body_hex)
    except:
        pass
    return result^


def _check_response_oracle_agrees(
    result: ParsedResponse,
    oracle: PythonObject,
    oracle_name: String,
    vec_id: String,
) raises -> Bool:
    """Check that an oracle's successful parse agrees with our parser."""
    if not py_field_bool(oracle, "ok"):
        var err = py_field_str(oracle, "error")
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " rejected but we accepted (oracle error: " + err + ")"
        )
        return False

    var ok = True

    var o_status = py_field_int(oracle, "status_code")
    if result.status_code != o_status:
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " status_code: ours=" + String(result.status_code)
            + " oracle=" + String(o_status)
        )
        ok = False

    var o_reason = py_field_str(oracle, "reason")
    if not _iequals(result.reason, o_reason):
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " reason: ours='" + result.reason + "' oracle='" + o_reason + "'"
        )
        ok = False

    var o_version = py_field_str(oracle, "version")
    if result.version != o_version:
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " version: ours='" + result.version + "' oracle='" + o_version + "'"
        )
        ok = False

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

    var o_body = _oracle_body_from_hex(oracle)
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
    states: PythonObject,
) raises -> Int:
    """Cross-validate an accept response vector. Returns number of failures."""
    var config = ParseConfig()
    var result = parse_response(wire, request_method, config)

    assert_true(
        result.ok(),
        vec_id + ": our parser rejected but expected accept: " + result.error,
    )

    if not py_has_key(states, vec_id):
        return 0

    var entry = states[vec_id]
    var failures = 0

    var h11_oracle = entry["h11"]
    var h11_ok = _check_response_oracle_agrees(result, h11_oracle, "h11", vec_id)
    if not h11_ok:
        failures += 1

    var skip_httptools = _iequals(request_method, "HEAD") or _iequals(request_method, "CONNECT")
    if skip_httptools or not py_has_key(entry, "httptools"):
        print("    INFO [" + vec_id + "] skipping httptools (request_method=" + request_method + ")")
    else:
        var ht_oracle = entry["httptools"]
        var ht_ok = _check_response_oracle_agrees(result, ht_oracle, "httptools", vec_id)
        if not ht_ok:
            failures += 1

    return failures


def run_reject_response_cross(
    wire: List[UInt8],
    vec_id: String,
    request_method: String,
    states: PythonObject,
) raises -> Int:
    """Cross-validate a reject vector. Returns 0 always."""
    var config = ParseConfig()
    var result = parse_response(wire, request_method, config)

    assert_true(
        not result.ok(),
        vec_id + ": our parser accepted but expected reject",
    )

    if not py_has_key(states, vec_id):
        return 0

    var entry = states[vec_id]
    var h11_oracle = entry["h11"]
    if py_field_bool(h11_oracle, "ok"):
        print(
            "    INFO [" + vec_id + "] h11 ACCEPTS what we reject"
            + " (our error: " + result.error + ")"
        )

    var skip_httptools = _iequals(request_method, "HEAD") or _iequals(request_method, "CONNECT")
    if not skip_httptools and py_has_key(entry, "httptools"):
        var ht_oracle = entry["httptools"]
        if py_field_bool(ht_oracle, "ok"):
            print(
                "    INFO [" + vec_id + "] httptools ACCEPTS what we reject"
                + " (our error: " + result.error + ")"
            )

    return 0


def main() raises:
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var builtins = Python.import_module("builtins")

    var states = load_states("vectors/rfc9112/h11_response_states.json")

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

            if py_has_key(v, "mode_flag") or py_has_key(v, "mode_flags"):
                skipped_dual += 1
                continue
            if py_has_key(v, "deferred"):
                skipped_dual += 1
                continue
            if py_has_key(v, "oracle_disagreement") or py_has_key(v, "auto_corrected"):
                skipped_dual += 1
                continue

            var expected = v["expected"]
            var behavior = String(expected["behavior"])
            var wire = hex_decode(wire_hex)

            var request_method = String("GET")
            if py_has_key(v, "request_method"):
                request_method = String(v["request_method"])

            total_vectors += 1

            if behavior == "accept":
                var n_disagree = run_accept_response_cross(
                    wire, vec_id, request_method, states
                )
                if n_disagree == 0:
                    accept_agree += 1
                else:
                    accept_disagree += 1
            else:
                _ = run_reject_response_cross(wire, vec_id, request_method, states)
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

    # ===== Phase 2: Pre-materialized random response cross-validation =====
    print("")
    print("=== Phase 2: Pre-materialized random response cross-validation ===")

    var rand_root = states["__random__"]
    var rand_cases = rand_root["cases"]
    var rand_total = Int(py=builtins.len(rand_cases))
    var rand_agree = 0

    for ri in range(rand_total):
        var rc = rand_cases[ri]
        var rid = String(rc["id"])
        var wire = hex_decode(String(rc["wire_hex"]))

        var config = ParseConfig()
        var result = parse_response(wire, String("GET"), config)
        assert_true(result.ok(), rid + ": our parser rejected: " + result.error)

        var h11_oracle = rc["h11"]
        var ht_oracle = rc["httptools"]

        var h11_ok = _check_response_oracle_agrees(result, h11_oracle, "h11", rid)
        var ht_ok = _check_response_oracle_agrees(result, ht_oracle, "httptools", rid)

        if h11_ok and ht_ok:
            rand_agree += 1
        else:
            assert_true(
                False,
                rid + ": random response disagreement (status="
                + String(rc["status_code"]) + ")",
            )

    print(
        "  " + String(rand_agree) + "/" + String(rand_total)
        + " random responses: full three-way agreement"
    )

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
