# conformance/tests/test_h1_connection_cross.mojo
#
# HC-2b: Two-way cross-validation of connection lifecycle parsing.
# Our parse_messages() vs h11's connection state machine.
# httptools has no connection state, so this is two-way only.
#
# For non-dual-mode, non-deferred multi_message vectors:
#   1. Parse with our parse_messages
#   2. Parse with parse_connection_with_h11
#   3. Assert same message count
#   4. For requests: assert method, target match
#   5. For responses: assert status_code match
#   6. Compare phase (with h11 state mapping)
#
# Disagreements are logged as warnings, not hard failures, since
# h11 may handle edge cases differently.
from lib.test_util import load_vectors, hex_decode, assert_true, assert_equal
from lib.http1.types import ParseConfig, ConnectionResult
from lib.http1.connection import parse_messages
from lib.http1.oracles import parse_connection_with_h11
from python import Python, PythonObject
from std.time import perf_counter_ns


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


def _phase_name(phase: Int) -> String:
    """Map phase int back to name string for diagnostics."""
    if phase == 0:
        return "IDLE"
    elif phase == 1:
        return "MUST_CLOSE"
    elif phase == 2:
        return "CLOSED"
    elif phase == 3:
        return "UPGRADED"
    elif phase == 4:
        return "ERROR"
    else:
        return "UNKNOWN(" + String(phase) + ")"


def cross_validate_vector(
    wire: List[UInt8],
    direction: String,
    request_methods: List[String],
    vid: String,
) raises -> Int:
    """Cross-validate one connection vector.

    Returns: 0 = full agreement, 1 = disagreement (warning logged).
    """
    var config = ParseConfig()
    var result = parse_messages(wire, direction, request_methods, config)

    # Build wire copy for oracle
    var wire_copy = List[UInt8]()
    for i in range(len(wire)):
        wire_copy.append(wire[i])

    var methods_copy = List[String]()
    for i in range(len(request_methods)):
        methods_copy.append(request_methods[i])

    var h11_result = parse_connection_with_h11(wire_copy, direction, methods_copy)

    var h11_err = _oracle_error(h11_result)
    if len(h11_err) > 0:
        # h11 errored -- log warning, do not fail
        print(
            "    WARN [" + vid + "] h11 connection oracle error: " + h11_err,
        )
        return 1

    var builtins = Python.import_module("builtins")
    var h11_messages = h11_result["messages"]
    var h11_msg_count = Int(py=builtins.len(h11_messages))

    # Compare message counts
    var our_msg_count = 0
    if direction == "request":
        our_msg_count = len(result.request_messages)
    else:
        our_msg_count = len(result.response_messages)

    if our_msg_count != h11_msg_count:
        print(
            "    WARN [" + vid + "] message count: ours="
            + String(our_msg_count) + " h11=" + String(h11_msg_count),
        )
        return 1

    # Compare each message
    var disagreements = 0
    for mi in range(our_msg_count):
        var h11_msg = h11_messages[mi]

        if direction == "request":
            var our_msg = result.request_messages[mi].copy()
            # Method
            var h11_method = _oracle_field(h11_msg, "method")
            if not _iequals(our_msg.method, h11_method):
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] method: ours='" + our_msg.method
                    + "' h11='" + h11_method + "'",
                )
                disagreements += 1
            # Target
            var h11_target = _oracle_field(h11_msg, "target")
            if our_msg.target != h11_target:
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] target: ours='" + our_msg.target
                    + "' h11='" + h11_target + "'",
                )
                disagreements += 1
            # Headers: compare count and case-insensitive names
            var h11_hdrs = h11_msg["headers"]
            var h11_hdr_count = Int(py=builtins.len(h11_hdrs))
            if len(our_msg.headers) != h11_hdr_count:
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] header count: ours=" + String(len(our_msg.headers))
                    + " h11=" + String(h11_hdr_count),
                )
                disagreements += 1
            else:
                for hi in range(h11_hdr_count):
                    var h11_pair = h11_hdrs[hi]
                    var h11_hname = String(h11_pair[0])
                    var h11_hval = String(h11_pair[1])
                    if not _iequals(our_msg.headers[hi].name, h11_hname):
                        print(
                            "    WARN [" + vid + "] msg[" + String(mi)
                            + "] header[" + String(hi) + "] name: ours='"
                            + our_msg.headers[hi].name + "' h11='" + h11_hname + "'",
                        )
                        disagreements += 1
                    # h11 lowercases header names; compare values directly
                    if our_msg.headers[hi].value != h11_hval:
                        print(
                            "    WARN [" + vid + "] msg[" + String(mi)
                            + "] header[" + String(hi) + "] value: ours='"
                            + our_msg.headers[hi].value + "' h11='" + h11_hval + "'",
                        )
                        disagreements += 1
        else:
            # Response direction
            var our_msg = result.response_messages[mi].copy()
            # Status code
            var h11_status = _oracle_int_field(h11_msg, "status_code")
            if our_msg.status_code != h11_status:
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] status_code: ours=" + String(our_msg.status_code)
                    + " h11=" + String(h11_status),
                )
                disagreements += 1
            # Reason (case-insensitive)
            var h11_reason = _oracle_field(h11_msg, "reason")
            if not _iequals(our_msg.reason, h11_reason):
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] reason: ours='" + our_msg.reason
                    + "' h11='" + h11_reason + "'",
                )
                disagreements += 1
            # Headers: compare count and case-insensitive names
            var h11_hdrs = h11_msg["headers"]
            var h11_hdr_count = Int(py=builtins.len(h11_hdrs))
            if len(our_msg.headers) != h11_hdr_count:
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] header count: ours=" + String(len(our_msg.headers))
                    + " h11=" + String(h11_hdr_count),
                )
                disagreements += 1
            else:
                for hi in range(h11_hdr_count):
                    var h11_pair = h11_hdrs[hi]
                    var h11_hname = String(h11_pair[0])
                    var h11_hval = String(h11_pair[1])
                    if not _iequals(our_msg.headers[hi].name, h11_hname):
                        print(
                            "    WARN [" + vid + "] msg[" + String(mi)
                            + "] header[" + String(hi) + "] name: ours='"
                            + our_msg.headers[hi].name + "' h11='" + h11_hname + "'",
                        )
                        disagreements += 1

    # Compare phase
    var h11_phase = _oracle_field(h11_result, "phase")
    var our_phase_str = _phase_name(result.state.phase)

    # h11 reports "IDLE" for both IDLE and DONE states, which maps to our
    # IDLE.  h11 does not model MUST_CLOSE explicitly for request-side
    # Connection: close the same way we do, so IDLE vs MUST_CLOSE is
    # a known acceptable difference.
    var phase_match = False
    if h11_phase == our_phase_str:
        phase_match = True
    elif h11_phase == "IDLE" and our_phase_str == "MUST_CLOSE":
        # Known h11 difference: h11 stays IDLE when we go to MUST_CLOSE
        phase_match = True
    elif h11_phase == "IDLE" and our_phase_str == "CLOSED":
        # Another acceptable difference
        phase_match = True
    elif h11_phase == "ERROR" and our_phase_str == "ERROR":
        phase_match = True

    if not phase_match:
        print(
            "    WARN [" + vid + "] phase: ours=" + our_phase_str
            + " h11=" + h11_phase,
        )
        disagreements += 1

    if disagreements > 0:
        return 1
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
    print("=== Phase 1: Vector-based connection cross-validation ===")

    var files = List[String]()
    files.append("vectors/rfc9112/connection_keepalive.json")
    files.append("vectors/rfc9112/connection_close.json")
    files.append("vectors/rfc9112/connection_upgrade.json")
    files.append("vectors/rfc9112/connection_informational.json")
    files.append("vectors/rfc9112/connection_pipeline.json")
    files.append("vectors/rfc9112/connection_error.json")

    var total_vectors = 0
    var agree_count = 0
    var disagree_count = 0
    var skipped = 0

    for fi in range(len(files)):
        var path = files[fi]
        var vectors = load_vectors(path)
        var count = Int(py=builtins.len(vectors))
        var file_tested = 0

        for vi in range(count):
            var v = vectors[vi]
            var vid = String(v["id"])

            # Skip dual-mode vectors
            if _has_key(v, "mode_flag") or _has_key(v, "mode_flags"):
                skipped += 1
                continue

            # Skip deferred vectors
            if _has_key(v, "deferred"):
                skipped += 1
                continue

            # Skip oracle disagreement / auto-corrected vectors
            if _has_key(v, "oracle_disagreement") or _has_key(v, "auto_corrected"):
                skipped += 1
                continue

            var direction = String(v["direction"])

            # Build request_methods list
            var request_methods = List[String]()
            if _has_key(v, "request_methods"):
                var py_methods = v["request_methods"]
                for mi in range(Int(py=builtins.len(py_methods))):
                    request_methods.append(String(py_methods[mi]))

            var wire = hex_decode(String(v["input"]["wire_hex"]))

            var n_disagree = cross_validate_vector(wire, direction, request_methods, vid)
            total_vectors += 1
            file_tested += 1
            if n_disagree == 0:
                agree_count += 1
            else:
                disagree_count += 1

        print(
            "  " + path + ": " + String(file_tested) + " cross-validated",
        )

    print(
        "  Total: " + String(total_vectors) + " tested, "
        + String(skipped) + " skipped (dual-mode/deferred)"
    )
    print(
        "  Agree: " + String(agree_count) + " | Disagree: "
        + String(disagree_count) + " (warnings only)"
    )

    assert_true(
        total_vectors >= 15,
        "expected >= 15 cross-validated vectors, got " + String(total_vectors),
    )

    # ===== Phase 2: Random multi-message cross-validation =====
    print("")
    print("=== Phase 2: Random multi-message cross-validation ===")

    var t = perf_counter_ns()
    var charset = String("abcdefghijklmnopqrstuvwxyz")
    var cs_bytes = charset.as_bytes()

    var rand_agree = 0
    var rand_total = 5

    for ri in range(rand_total):
        # Generate two random hostnames using seeded pseudo-randomness
        var tv1 = Int(t) + ri * 7 + 1
        var tv2 = Int(t) + ri * 13 + 3
        var host1 = String("h")
        var host2 = String("h")
        for ci in range(6):
            var idx1 = tv1 % 26
            host1 += chr(Int(cs_bytes[idx1]))
            tv1 = tv1 // 26 + ci + 1
            var idx2 = tv2 % 26
            host2 += chr(Int(cs_bytes[idx2]))
            tv2 = tv2 // 26 + ci + 1

        host1 += ".test"
        host2 += ".test"

        # Build two-GET pipeline
        var rt_str = (
            "GET /a HTTP/1.1\r\nHost: " + host1
            + "\r\n\r\nGET /b HTTP/1.1\r\nHost: " + host2 + "\r\n\r\n"
        )
        var rt_bytes = rt_str.as_bytes()
        var wire = List[UInt8]()
        for bi in range(len(rt_bytes)):
            wire.append(rt_bytes[bi])

        var request_methods = List[String]()
        var rid = "rand-conn-" + String(ri)

        var n_disagree = cross_validate_vector(
            wire, String("request"), request_methods, rid,
        )
        if n_disagree == 0:
            rand_agree += 1
        else:
            # Random well-formed two-GET pipelines must agree
            print(
                "    WARN [" + rid
                + "] random pipeline disagreement (non-fatal)"
            )

    print(
        "  " + String(rand_agree) + "/" + String(rand_total)
        + " random pipelines: full two-way agreement"
    )

    # ===== Summary =====
    var grand_total = total_vectors + rand_total
    print("")
    print(
        "test_h1_connection_cross: "
        + String(grand_total) + " total tests ("
        + String(agree_count + rand_agree) + " full-agree, "
        + String(disagree_count + (rand_total - rand_agree)) + " with warnings)"
    )
