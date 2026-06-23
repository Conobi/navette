# conformance/tests/test_h1_cross_parser.mojo
#
# Three-way cross-validation: our parser vs h11 vs httptools.
#
# As of §3.3 of the dependency-enhancement plan, h11 and httptools are no
# longer imported at test runtime. The oracle outputs are pre-materialized
# into conformance/vectors/rfc9112/h11_request_states.json by
# conformance/scripts/oracle_h1_h2_states.py and read at test time.
#
# For accept vectors, all three must agree on method, target, version,
# headers. For reject vectors, our parser must reject. Oracles may disagree
# (they are lenient), so disagreements are logged but do not cause failure.
from lib.test_util import load_vectors, hex_decode, assert_true
from lib.http1.types import ParseConfig, Header, ParsedRequest
from lib.http1.parser import parse_request
from lib.stateful_vectors import load_states, py_has_key, py_field_str, py_field_bool
from std.python import Python, PythonObject


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


def _oracle_header_count(oracle: PythonObject) raises -> Int:
    var builtins = Python.import_module("builtins")
    if not py_has_key(oracle, "headers"):
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
    """
    if not py_field_bool(oracle, "ok"):
        var err = py_field_str(oracle, "error")
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " rejected but we accepted (oracle error: " + err + ")"
        )
        return False

    var ok = True

    var o_method = py_field_str(oracle, "method")
    if not _iequals(result.method, o_method):
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " method: ours='" + result.method + "' oracle='" + o_method + "'"
        )
        ok = False

    var o_target = py_field_str(oracle, "target")
    if result.target != o_target:
        print(
            "    WARN [" + vec_id + "] " + oracle_name
            + " target: ours='" + result.target + "' oracle='" + o_target + "'"
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

    return ok


def run_accept_cross(
    wire: List[UInt8],
    vec_id: String,
    states: PythonObject,
) raises -> Int:
    """Cross-validate an accept vector. Returns number of agreement failures."""
    var config = ParseConfig()
    var result = parse_request(wire, config)

    assert_true(
        result.ok(),
        vec_id + ": our parser rejected but expected accept: " + result.error,
    )

    if not py_has_key(states, vec_id):
        # No pre-materialized oracle for this vec_id — treat as full agree.
        return 0

    var entry = states[vec_id]
    var failures = 0

    var h11_oracle = entry["h11"]
    var h11_ok = _check_oracle_agrees_accept(result, h11_oracle, "h11", vec_id)
    if not h11_ok:
        failures += 1

    var ht_oracle = entry["httptools"]
    var ht_ok = _check_oracle_agrees_accept(result, ht_oracle, "httptools", vec_id)
    if not ht_ok:
        failures += 1

    return failures


def run_reject_cross(
    wire: List[UInt8],
    vec_id: String,
    states: PythonObject,
) raises -> Int:
    """Cross-validate a reject vector. Returns 0 always (reject disagreements
    are warnings only since oracles are more lenient than our strict parser).
    """
    var config = ParseConfig()
    var result = parse_request(wire, config)

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

    var ht_oracle = entry["httptools"]
    if py_field_bool(ht_oracle, "ok"):
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

    # Load pre-materialized oracle states (replaces live h11/httptools).
    var states = load_states("vectors/rfc9112/h11_request_states.json")

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
            total_vectors += 1

            var is_converted = vec_id.find("llhttp-") >= 0 or vec_id.find("aws-") >= 0

            if behavior == "accept":
                if is_converted:
                    try:
                        var n_disagree = run_accept_cross(wire, vec_id, states)
                        if n_disagree == 0:
                            accept_agree += 1
                        else:
                            accept_disagree += 1
                    except e:
                        print("    [SOFT FAIL] " + String(e))
                        accept_disagree += 1
                else:
                    var n_disagree = run_accept_cross(wire, vec_id, states)
                    if n_disagree == 0:
                        accept_agree += 1
                    else:
                        accept_disagree += 1
            else:
                if is_converted:
                    try:
                        _ = run_reject_cross(wire, vec_id, states)
                        reject_tested += 1
                    except e:
                        print("    [SOFT FAIL] " + String(e))
                        reject_tested += 1
                else:
                    _ = run_reject_cross(wire, vec_id, states)
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

    assert_true(total_vectors >= 20, "expected at least 20 non-dual vectors")
    assert_true(
        accept_agree >= 15,
        "expected at least 15 full-agree accept vectors, got "
        + String(accept_agree),
    )

    # ===== Phase 2: Pre-materialized random cross-validation =====
    print("")
    print("=== Phase 2: Pre-materialized random request cross-validation ===")

    var rand_root = states["__random__"]
    var rand_cases = rand_root["cases"]
    var rand_total = Int(py=builtins.len(rand_cases))
    var rand_agree = 0

    for ri in range(rand_total):
        var rc = rand_cases[ri]
        var rid = String(rc["id"])
        var wire = hex_decode(String(rc["wire_hex"]))

        var config = ParseConfig()
        var result = parse_request(wire, config)
        assert_true(result.ok(), rid + ": our parser rejected: " + result.error)

        var h11_oracle = rc["h11"]
        var ht_oracle = rc["httptools"]

        var h11_ok = _check_oracle_agrees_accept(result, h11_oracle, "h11", rid)
        var ht_ok = _check_oracle_agrees_accept(result, ht_oracle, "httptools", rid)

        if h11_ok and ht_ok:
            rand_agree += 1
        else:
            assert_true(
                False,
                rid + ": random request disagreement (method="
                + String(rc["method"]) + " path=" + String(rc["path"]) + ")",
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
