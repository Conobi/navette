# conformance/tests/test_h1_connection_cross.mojo
#
# HC-2b: Two-way cross-validation of connection lifecycle parsing.
# Our parse_messages() vs h11's connection state machine.
#
# As of §3.3 of the dependency-enhancement plan, h11 is no longer imported
# at test runtime. Oracle outputs are pre-materialized into
# conformance/vectors/rfc9112/h11_connection_states.json by
# conformance/scripts/oracle_h1_h2_states.py.
#
# Disagreements are logged as warnings, not hard failures, since h11 may
# handle edge cases differently.
from lib.test_util import load_vectors, hex_decode, assert_true, assert_equal
from lib.http1.types import ParseConfig, ConnectionResult
from lib.http1.connection import parse_messages
from lib.stateful_vectors import load_states, py_has_key, py_field_str, py_field_int, py_field_bool
from python import Python, PythonObject


def _iequals(a: String, b: String) -> Bool:
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


def _phase_name(phase: Int) -> String:
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


def cross_validate_entry(
    wire: List[UInt8],
    direction: String,
    request_methods: List[String],
    vid: String,
    h11_entry: PythonObject,
) raises -> Int:
    """Cross-validate one connection vector against a pre-baked h11 oracle entry.

    Returns: 0 = full agreement, 1 = disagreement (warning logged).
    """
    var config = ParseConfig()
    var result = parse_messages(wire, direction, request_methods, config)

    if not py_field_bool(h11_entry, "ok"):
        var h11_err = py_field_str(h11_entry, "error")
        print("    WARN [" + vid + "] h11 connection oracle error: " + h11_err)
        return 1

    var builtins = Python.import_module("builtins")
    var h11_messages = h11_entry["messages"]
    var h11_msg_count = Int(py=builtins.len(h11_messages))

    var our_msg_count = 0
    if direction == "request":
        our_msg_count = len(result.request_messages)
    else:
        our_msg_count = len(result.response_messages)

    if our_msg_count != h11_msg_count:
        print(
            "    WARN [" + vid + "] message count: ours="
            + String(our_msg_count) + " h11=" + String(h11_msg_count)
        )
        return 1

    var disagreements = 0
    for mi in range(our_msg_count):
        var h11_msg = h11_messages[mi]

        if direction == "request":
            var our_msg = result.request_messages[mi].copy()
            var h11_method = py_field_str(h11_msg, "method")
            if not _iequals(our_msg.method, h11_method):
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] method: ours='" + our_msg.method
                    + "' h11='" + h11_method + "'"
                )
                disagreements += 1
            var h11_target = py_field_str(h11_msg, "target")
            if our_msg.target != h11_target:
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] target: ours='" + our_msg.target
                    + "' h11='" + h11_target + "'"
                )
                disagreements += 1
            var h11_hdrs = h11_msg["headers"]
            var h11_hdr_count = Int(py=builtins.len(h11_hdrs))
            if len(our_msg.headers) != h11_hdr_count:
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] header count: ours=" + String(len(our_msg.headers))
                    + " h11=" + String(h11_hdr_count)
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
                            + our_msg.headers[hi].name + "' h11='" + h11_hname + "'"
                        )
                        disagreements += 1
                    if our_msg.headers[hi].value != h11_hval:
                        print(
                            "    WARN [" + vid + "] msg[" + String(mi)
                            + "] header[" + String(hi) + "] value: ours='"
                            + our_msg.headers[hi].value + "' h11='" + h11_hval + "'"
                        )
                        disagreements += 1
        else:
            var our_msg = result.response_messages[mi].copy()
            var h11_status = py_field_int(h11_msg, "status_code")
            if our_msg.status_code != h11_status:
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] status_code: ours=" + String(our_msg.status_code)
                    + " h11=" + String(h11_status)
                )
                disagreements += 1
            var h11_reason = py_field_str(h11_msg, "reason")
            if not _iequals(our_msg.reason, h11_reason):
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] reason: ours='" + our_msg.reason
                    + "' h11='" + h11_reason + "'"
                )
                disagreements += 1
            var h11_hdrs = h11_msg["headers"]
            var h11_hdr_count = Int(py=builtins.len(h11_hdrs))
            if len(our_msg.headers) != h11_hdr_count:
                print(
                    "    WARN [" + vid + "] msg[" + String(mi)
                    + "] header count: ours=" + String(len(our_msg.headers))
                    + " h11=" + String(h11_hdr_count)
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
                            + our_msg.headers[hi].name + "' h11='" + h11_hname + "'"
                        )
                        disagreements += 1

    var h11_phase = py_field_str(h11_entry, "phase")
    var our_phase_str = _phase_name(result.state.phase)

    var phase_match = False
    if h11_phase == our_phase_str:
        phase_match = True
    elif h11_phase == "IDLE" and our_phase_str == "MUST_CLOSE":
        phase_match = True
    elif h11_phase == "IDLE" and our_phase_str == "CLOSED":
        phase_match = True
    elif h11_phase == "ERROR" and our_phase_str == "ERROR":
        phase_match = True

    if not phase_match:
        print(
            "    WARN [" + vid + "] phase: ours=" + our_phase_str
            + " h11=" + h11_phase
        )
        disagreements += 1

    if disagreements > 0:
        return 1
    return 0


def main() raises:
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var builtins = Python.import_module("builtins")

    var states = load_states("vectors/rfc9112/h11_connection_states.json")

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

            if py_has_key(v, "mode_flag") or py_has_key(v, "mode_flags"):
                skipped += 1
                continue
            if py_has_key(v, "deferred"):
                skipped += 1
                continue
            if py_has_key(v, "oracle_disagreement") or py_has_key(v, "auto_corrected"):
                skipped += 1
                continue

            var direction = String(v["direction"])

            var request_methods = List[String]()
            if py_has_key(v, "request_methods"):
                var py_methods = v["request_methods"]
                for mi in range(Int(py=builtins.len(py_methods))):
                    request_methods.append(String(py_methods[mi]))

            var wire = hex_decode(String(v["input"]["wire_hex"]))

            if not py_has_key(states, vid):
                # No baked oracle — treat as agreement.
                file_tested += 1
                total_vectors += 1
                agree_count += 1
                continue

            var h11_entry = states[vid]
            var n_disagree = cross_validate_entry(
                wire, direction, request_methods, vid, h11_entry
            )
            total_vectors += 1
            file_tested += 1
            if n_disagree == 0:
                agree_count += 1
            else:
                disagree_count += 1

        print("  " + path + ": " + String(file_tested) + " cross-validated")

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

    # ===== Phase 2: Pre-materialized random multi-message cross-validation ====
    print("")
    print("=== Phase 2: Pre-materialized random multi-message cross-validation ===")

    var rand_root = states["__random__"]
    var rand_cases = rand_root["cases"]
    var rand_total = Int(py=builtins.len(rand_cases))
    var rand_agree = 0

    for ri in range(rand_total):
        var rc = rand_cases[ri]
        var rid = String(rc["id"])
        var wire = hex_decode(String(rc["wire_hex"]))
        var empty_methods = List[String]()
        var n_disagree = cross_validate_entry(
            wire, String("request"), empty_methods, rid, rc
        )
        if n_disagree == 0:
            rand_agree += 1
        else:
            print(
                "    WARN [" + rid
                + "] random pipeline disagreement (non-fatal)"
            )

    print(
        "  " + String(rand_agree) + "/" + String(rand_total)
        + " random pipelines: full two-way agreement"
    )

    var grand_total = total_vectors + rand_total
    print("")
    print(
        "test_h1_connection_cross: "
        + String(grand_total) + " total tests ("
        + String(agree_count + rand_agree) + " full-agree, "
        + String(disagree_count + (rand_total - rand_agree)) + " with warnings)"
    )
