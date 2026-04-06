# conformance/tests/test_h1_connection.mojo
#
# HC-2b: Multi-message connection lifecycle compliance tests.
from lib.test_util import load_vectors, hex_decode, hex_encode, assert_true, assert_equal, assert_bytes_equal
from lib.http1.types import ParseConfig, ParserStrictness, Header, ParsedRequest, ParsedResponse, ConnectionState, ConnectionResult
from lib.http1.connection import parse_messages
from python import Python, PythonObject
from std.time import perf_counter_ns


def _phase_to_int(phase_str: String) -> Int:
    """Map phase name string to ConnectionState.phase int constant."""
    if phase_str == "IDLE":
        return 0
    elif phase_str == "MUST_CLOSE":
        return 1
    elif phase_str == "CLOSED":
        return 2
    elif phase_str == "UPGRADED":
        return 3
    elif phase_str == "ERROR":
        return 4
    else:
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


def _has_key(obj: PythonObject, key: String) -> Bool:
    """Check if a Python dict has a given key."""
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


def _str_contains(haystack: String, needle: String) -> Bool:
    """Check if needle is a substring of haystack."""
    var h_bytes = haystack.as_bytes()
    var n_bytes = needle.as_bytes()
    var h_len = len(h_bytes)
    var n_len = len(n_bytes)
    if n_len == 0:
        return True
    if n_len > h_len:
        return False
    for i in range(h_len - n_len + 1):
        var found = True
        for j in range(n_len):
            if h_bytes[i + j] != n_bytes[j]:
                found = False
                break
        if found:
            return True
    return False


def _set_flag(flag: String) -> ParserStrictness:
    """Create a ParserStrictness with one specific flag set to True."""
    if flag == "allow_bare_lf":
        return ParserStrictness(allow_bare_lf=True)
    elif flag == "allow_bare_cr_in_value":
        return ParserStrictness(allow_bare_cr_in_value=True)
    elif flag == "allow_http_09":
        return ParserStrictness(allow_http_09=True)
    elif flag == "allow_nonstandard_version":
        return ParserStrictness(allow_nonstandard_version=True)
    elif flag == "allow_multiple_spaces":
        return ParserStrictness(allow_multiple_spaces=True)
    elif flag == "allow_obs_fold":
        return ParserStrictness(allow_obs_fold=True)
    elif flag == "allow_space_before_colon":
        return ParserStrictness(allow_space_before_colon=True)
    elif flag == "allow_header_value_ctl":
        return ParserStrictness(allow_header_value_ctl=True)
    elif flag == "allow_target_ctl":
        return ParserStrictness(allow_target_ctl=True)
    elif flag == "ignore_invalid_header_names":
        return ParserStrictness(ignore_invalid_header_names=True)
    elif flag == "allow_non_chunked_te":
        return ParserStrictness(allow_non_chunked_te=True)
    elif flag == "allow_chunk_extensions":
        return ParserStrictness(allow_chunk_extensions=True)
    elif flag == "allow_cl_leading_zeros":
        return ParserStrictness(allow_cl_leading_zeros=True)
    elif flag == "allow_duplicate_cl":
        return ParserStrictness(allow_duplicate_cl=True)
    elif flag == "allow_missing_host_11":
        return ParserStrictness(allow_missing_host_11=True)
    elif flag == "allow_duplicate_host":
        return ParserStrictness(allow_duplicate_host=True)
    elif flag == "allow_multiple_spaces_in_status_line":
        return ParserStrictness(allow_multiple_spaces_in_status_line=True)
    elif flag == "allow_space_before_first_header":
        return ParserStrictness(allow_space_before_first_header=True)
    elif flag == "allow_missing_crlf_after_chunk":
        return ParserStrictness(allow_missing_crlf_after_chunk=True)
    elif flag == "allow_missing_reason_sp":
        return ParserStrictness(allow_missing_reason_sp=True)
    elif flag == "allow_response_cl_te":
        return ParserStrictness(allow_response_cl_te=True)
    elif flag == "allow_data_after_close":
        return ParserStrictness(allow_data_after_close=True)
    elif flag == "allow_lenient_keep_alive":
        return ParserStrictness(allow_lenient_keep_alive=True)
    elif flag == "allow_prefix_crlf":
        return ParserStrictness(allow_prefix_crlf=True)
    else:
        print("ERROR: unknown flag: " + flag)
        return ParserStrictness()


def _set_flags(flags: List[String]) -> ParserStrictness:
    """Create a ParserStrictness with multiple flags set to True."""
    var s = ParserStrictness()
    for i in range(len(flags)):
        var f = flags[i]
        if f == "allow_bare_lf": s.allow_bare_lf = True
        elif f == "allow_bare_cr_in_value": s.allow_bare_cr_in_value = True
        elif f == "allow_http_09": s.allow_http_09 = True
        elif f == "allow_nonstandard_version": s.allow_nonstandard_version = True
        elif f == "allow_multiple_spaces": s.allow_multiple_spaces = True
        elif f == "allow_obs_fold": s.allow_obs_fold = True
        elif f == "allow_space_before_colon": s.allow_space_before_colon = True
        elif f == "allow_header_value_ctl": s.allow_header_value_ctl = True
        elif f == "allow_target_ctl": s.allow_target_ctl = True
        elif f == "ignore_invalid_header_names": s.ignore_invalid_header_names = True
        elif f == "allow_non_chunked_te": s.allow_non_chunked_te = True
        elif f == "allow_chunk_extensions": s.allow_chunk_extensions = True
        elif f == "allow_cl_leading_zeros": s.allow_cl_leading_zeros = True
        elif f == "allow_duplicate_cl": s.allow_duplicate_cl = True
        elif f == "allow_missing_host_11": s.allow_missing_host_11 = True
        elif f == "allow_duplicate_host": s.allow_duplicate_host = True
        elif f == "allow_multiple_spaces_in_status_line": s.allow_multiple_spaces_in_status_line = True
        elif f == "allow_space_before_first_header": s.allow_space_before_first_header = True
        elif f == "allow_missing_crlf_after_chunk": s.allow_missing_crlf_after_chunk = True
        elif f == "allow_missing_reason_sp": s.allow_missing_reason_sp = True
        elif f == "allow_response_cl_te": s.allow_response_cl_te = True
        elif f == "allow_data_after_close": s.allow_data_after_close = True
        elif f == "allow_lenient_keep_alive": s.allow_lenient_keep_alive = True
        elif f == "allow_prefix_crlf": s.allow_prefix_crlf = True
        else: print("ERROR: unknown flag: " + f)
    return s^


# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------


def check_request_message(
    msg: ParsedRequest, exp: PythonObject, vid: String, mi: Int,
) raises:
    """Validate a single parsed request message against expected dict."""
    var prefix = vid + ": msg[" + String(mi) + "]"

    # behavior=reject means the message itself was an error
    var behavior = String(exp["behavior"])
    if behavior == "reject":
        assert_true(
            not msg.ok(),
            prefix + " expected reject but parser accepted",
        )
        if _has_key(exp, "reason"):
            var reason = String(exp["reason"])
            if len(reason) > 0 and not _str_contains(msg.error, reason):
                print(
                    "    WARNING: " + prefix + ": error '" + msg.error
                    + "' does not contain expected reason '" + reason + "'"
                )
        return

    assert_true(msg.ok(), prefix + " expected accept but got error: " + msg.error)

    var exp_method = String(exp["method"])
    assert_true(
        msg.method == exp_method,
        prefix + " method mismatch: got '" + msg.method + "' expected '" + exp_method + "'",
    )

    var exp_target = String(exp["target"])
    assert_true(
        msg.target == exp_target,
        prefix + " target mismatch: got '" + msg.target + "' expected '" + exp_target + "'",
    )

    var exp_version = String(exp["version"])
    assert_true(
        msg.version == exp_version,
        prefix + " version mismatch: got '" + msg.version + "' expected '" + exp_version + "'",
    )

    # Headers
    var builtins = Python.import_module("builtins")
    var exp_headers = exp["headers"]
    var exp_hdr_count = Int(py=builtins.len(exp_headers))
    assert_equal(len(msg.headers), exp_hdr_count, prefix + " header count")
    for i in range(exp_hdr_count):
        var pair = exp_headers[i]
        var exp_name = String(pair[0])
        var exp_val = String(pair[1])
        assert_true(
            msg.headers[i].name == exp_name,
            prefix + " header[" + String(i) + "] name: got '" + msg.headers[i].name + "' expected '" + exp_name + "'",
        )
        assert_true(
            msg.headers[i].value == exp_val,
            prefix + " header[" + String(i) + "] value: got '" + msg.headers[i].value + "' expected '" + exp_val + "'",
        )

    # Body
    var exp_body_hex = String(exp["body_hex"])
    var exp_body = hex_decode(exp_body_hex)
    assert_bytes_equal(msg.body, exp_body, prefix + " body")


def check_response_message(
    msg: ParsedResponse, exp: PythonObject, vid: String, mi: Int,
) raises:
    """Validate a single parsed response message against expected dict."""
    var prefix = vid + ": msg[" + String(mi) + "]"

    var behavior = String(exp["behavior"])
    if behavior == "reject":
        assert_true(
            not msg.ok(),
            prefix + " expected reject but parser accepted",
        )
        if _has_key(exp, "reason"):
            var reason = String(exp["reason"])
            if len(reason) > 0 and not _str_contains(msg.error, reason):
                print(
                    "    WARNING: " + prefix + ": error '" + msg.error
                    + "' does not contain expected reason '" + reason + "'"
                )
        return

    assert_true(msg.ok(), prefix + " expected accept but got error: " + msg.error)

    var exp_status = Int(py=exp["status_code"])
    assert_equal(msg.status_code, exp_status, prefix + " status_code")

    var exp_reason = String(exp["reason"])
    assert_true(
        msg.reason == exp_reason,
        prefix + " reason mismatch: got '" + msg.reason + "' expected '" + exp_reason + "'",
    )

    var exp_version = String(exp["version"])
    assert_true(
        msg.version == exp_version,
        prefix + " version mismatch: got '" + msg.version + "' expected '" + exp_version + "'",
    )

    # Headers
    var builtins = Python.import_module("builtins")
    var exp_headers = exp["headers"]
    var exp_hdr_count = Int(py=builtins.len(exp_headers))
    assert_equal(len(msg.headers), exp_hdr_count, prefix + " header count")
    for i in range(exp_hdr_count):
        var pair = exp_headers[i]
        var exp_name = String(pair[0])
        var exp_val = String(pair[1])
        assert_true(
            msg.headers[i].name == exp_name,
            prefix + " header[" + String(i) + "] name: got '" + msg.headers[i].name + "' expected '" + exp_name + "'",
        )
        assert_true(
            msg.headers[i].value == exp_val,
            prefix + " header[" + String(i) + "] value: got '" + msg.headers[i].value + "' expected '" + exp_val + "'",
        )

    # Body
    var exp_body_hex = String(exp["body_hex"])
    var exp_body = hex_decode(exp_body_hex)
    assert_bytes_equal(msg.body, exp_body, prefix + " body")


def check_connection_state(
    result: ConnectionResult,
    exp_conn: PythonObject,
    vid: String,
) raises:
    """Validate ConnectionResult.state against expected_connection dict."""
    # final_phase (mandatory)
    var exp_phase = _phase_to_int(String(exp_conn["final_phase"]))
    assert_true(
        result.state.phase == exp_phase,
        vid + ": final_phase mismatch: got " + _phase_name(result.state.phase)
        + " expected " + String(exp_conn["final_phase"]),
    )

    # messages_parsed (mandatory)
    var exp_mp = Int(py=exp_conn["messages_parsed"])
    assert_equal(
        result.state.messages_parsed,
        exp_mp,
        vid + ": messages_parsed",
    )

    # informational_count (when present)
    if _has_key(exp_conn, "informational_count"):
        var exp_ic = Int(py=exp_conn["informational_count"])
        assert_equal(
            result.state.informational_count,
            exp_ic,
            vid + ": informational_count",
        )

    # keep_alive (when present)
    if _has_key(exp_conn, "keep_alive"):
        var exp_ka_int = Int(py=exp_conn["keep_alive"])
        var exp_ka = exp_ka_int != 0
        assert_true(
            result.state.keep_alive == exp_ka,
            vid + ": keep_alive mismatch: got " + String(result.state.keep_alive)
            + " expected " + String(exp_ka),
        )


def check_trailing_data(
    result: ConnectionResult,
    exp_trailing_hex: String,
    vid: String,
) raises:
    """Validate trailing_data against expected hex string."""
    var exp_data = hex_decode(exp_trailing_hex)
    var got_hex = hex_encode(result.trailing_data)
    assert_equal(
        len(result.trailing_data),
        len(exp_data),
        vid + ": trailing_data length (got hex: " + got_hex + " expected hex: " + exp_trailing_hex + ")",
    )
    assert_bytes_equal(result.trailing_data, exp_data, vid + ": trailing_data")


def check_connection_result(
    result: ConnectionResult,
    exp_msgs: PythonObject,
    exp_conn: PythonObject,
    direction: String,
    vid: String,
    exp_error: String,
    exp_trailing_hex: String,
) raises:
    """Full validation of a ConnectionResult against expected vectors."""
    var builtins = Python.import_module("builtins")
    var exp_count = Int(py=builtins.len(exp_msgs))

    # Check message count
    if direction == "request":
        assert_equal(
            len(result.request_messages),
            exp_count,
            vid + ": request message count",
        )
        # Check each request message
        for mi in range(exp_count):
            check_request_message(result.request_messages[mi], exp_msgs[mi], vid, mi)
    else:
        assert_equal(
            len(result.response_messages),
            exp_count,
            vid + ": response message count",
        )
        # Check each response message
        for mi in range(exp_count):
            check_response_message(result.response_messages[mi], exp_msgs[mi], vid, mi)

    # Check connection state
    check_connection_state(result, exp_conn, vid)

    # Check trailing data (when expected)
    if len(exp_trailing_hex) > 0:
        check_trailing_data(result, exp_trailing_hex, vid)
    elif _has_key(exp_conn, "trailing_data_hex"):
        var conn_trailing = String(exp_conn["trailing_data_hex"])
        if len(conn_trailing) > 0:
            check_trailing_data(result, conn_trailing, vid)
        else:
            # Expect empty trailing data
            assert_equal(
                len(result.trailing_data), 0,
                vid + ": trailing_data should be empty",
            )

    # Check error (when expected)
    if len(exp_error) > 0:
        assert_true(
            len(result.error) > 0,
            vid + ": expected error but result.error is empty",
        )
        if not _str_contains(result.error, exp_error):
            print(
                "    WARNING: " + vid + ": error '" + result.error
                + "' does not contain expected '" + exp_error + "'"
            )


# ---------------------------------------------------------------------------
# Vector runner
# ---------------------------------------------------------------------------


def run_single_mode_vector(
    v: PythonObject, vid: String, direction: String,
    request_methods: List[String], config: ParseConfig,
) raises:
    """Run a single-mode (non-dual) connection vector."""
    var wire = hex_decode(String(v["input"]["wire_hex"]))
    var result = parse_messages(wire, direction, request_methods, config)

    var exp_msgs = v["expected_messages"]
    var exp_conn = v["expected_connection"]

    # Extract expected error from connection or top level
    var exp_error = String("")
    if _has_key(exp_conn, "error"):
        exp_error = String(exp_conn["error"])

    # Extract trailing_data_hex
    var exp_trailing_hex = String("")
    if _has_key(exp_conn, "trailing_data_hex"):
        exp_trailing_hex = String(exp_conn["trailing_data_hex"])

    check_connection_result(
        result, exp_msgs, exp_conn, direction, vid,
        exp_error, exp_trailing_hex,
    )


def run_dual_mode_vector(
    v: PythonObject, vid: String, direction: String,
    request_methods: List[String], flag_name: String,
) raises:
    """Run a dual-mode connection vector (default + flagged)."""
    var wire_hex = String(v["input"]["wire_hex"])

    # --- Default mode (strict) ---
    var wire_default = hex_decode(wire_hex)
    var default_config = ParseConfig()
    var default_result = parse_messages(wire_default, direction, request_methods, default_config)

    var exp_default = v["expected_default"]
    var exp_default_msgs = exp_default["messages"]
    var exp_default_conn = exp_default["connection"]

    var default_error = String("")
    if _has_key(exp_default, "error"):
        default_error = String(exp_default["error"])

    var default_trailing = String("")
    if _has_key(exp_default, "trailing_data_hex"):
        default_trailing = String(exp_default["trailing_data_hex"])

    check_connection_result(
        default_result, exp_default_msgs, exp_default_conn,
        direction, vid + " [default]",
        default_error, default_trailing,
    )

    # --- Flagged mode ---
    var wire_flagged = hex_decode(wire_hex)
    var flagged_strictness = _set_flag(flag_name)
    var flagged_config = ParseConfig(strictness=flagged_strictness)
    var flagged_result = parse_messages(wire_flagged, direction, request_methods, flagged_config)

    var exp_flagged = v["expected_flagged"]
    var exp_flagged_msgs = exp_flagged["messages"]
    var exp_flagged_conn = exp_flagged["connection"]

    var flagged_error = String("")
    if _has_key(exp_flagged, "error"):
        flagged_error = String(exp_flagged["error"])

    var flagged_trailing = String("")
    if _has_key(exp_flagged, "trailing_data_hex"):
        flagged_trailing = String(exp_flagged["trailing_data_hex"])

    check_connection_result(
        flagged_result, exp_flagged_msgs, exp_flagged_conn,
        direction, vid + " [flagged:" + flag_name + "]",
        flagged_error, flagged_trailing,
    )


def run_vector(v: PythonObject) raises -> Bool:
    """Run one connection test vector. Returns False if skipped."""
    var vid = String(v["id"])

    # Skip deferred/disagreement/auto-corrected
    if _has_key(v, "deferred"):
        return False
    if _has_key(v, "oracle_disagreement"):
        return False
    if _has_key(v, "auto_corrected"):
        return False

    var direction = String(v["direction"])

    # Build request_methods list
    var request_methods = List[String]()
    if _has_key(v, "request_methods"):
        var builtins = Python.import_module("builtins")
        var py_methods = v["request_methods"]
        for mi in range(Int(py=builtins.len(py_methods))):
            request_methods.append(String(py_methods[mi]))

    # Dual-mode (mode_flag)
    if _has_key(v, "mode_flag"):
        var flag_name = String(v["mode_flag"])
        run_dual_mode_vector(v, vid, direction, request_methods, flag_name)
        return True

    # Single-mode
    if _has_key(v, "expected_messages") and _has_key(v, "expected_connection"):
        var config = ParseConfig()
        run_single_mode_vector(v, vid, direction, request_methods, config)
        return True

    # Unknown format — skip
    return False


def main() raises:
    # Sentinel assertion check
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var total = 0
    var severe_count = 0

    var files = List[String]()
    files.append("vectors/rfc9112/connection_keepalive.json")
    files.append("vectors/rfc9112/connection_close.json")
    files.append("vectors/rfc9112/connection_upgrade.json")
    files.append("vectors/rfc9112/connection_informational.json")
    files.append("vectors/rfc9112/connection_pipeline.json")
    files.append("vectors/rfc9112/connection_error.json")
    files.append("vectors/security/connection_smuggling.json")

    for fi in range(len(files)):
        var path = files[fi]
        var vectors = load_vectors(path)
        var builtins = Python.import_module("builtins")
        var count = Int(py=builtins.len(vectors))
        var file_count = 0
        var skipped = 0

        for i in range(count):
            var v = vectors[i]

            # Track severity for security vectors
            var is_severe = _has_key(v, "severity") and String(v["severity"]) == "severe"

            if run_vector(v):
                file_count += 1
                total += 1
                if is_severe:
                    severe_count += 1
            else:
                skipped += 1

        # Per-file minimum: at least 5 vectors
        assert_true(
            file_count >= 5,
            path + ": expected >= 5 vectors, got " + String(file_count),
        )

        var msg = "  " + path + ": " + String(file_count) + " vectors passed"
        if skipped > 0:
            msg += " (" + String(skipped) + " skipped)"
        print(msg)

    # ---- Random multi-message sequences (anti-cheat) ----
    var t = perf_counter_ns()
    var charset = String("abcdefghijklmnopqrstuvwxyz")
    var cs_bytes = charset.as_bytes()

    for ri in range(5):
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

        # Build: "GET /a HTTP/1.1\r\nHost: <host1>\r\n\r\nGET /b HTTP/1.1\r\nHost: <host2>\r\n\r\n"
        var rt_str = "GET /a HTTP/1.1\r\nHost: " + host1 + "\r\n\r\nGET /b HTTP/1.1\r\nHost: " + host2 + "\r\n\r\n"
        var rt_bytes = rt_str.as_bytes()
        var rt_wire = List[UInt8]()
        for bi in range(len(rt_bytes)):
            rt_wire.append(rt_bytes[bi])

        var rt_methods = List[String]()
        var rt_config = ParseConfig()
        var rt_result = parse_messages(rt_wire, String("request"), rt_methods, rt_config)

        assert_equal(
            len(rt_result.request_messages), 2,
            "random[" + String(ri) + "]: message count",
        )
        assert_true(
            rt_result.request_messages[0].method == "GET",
            "random[" + String(ri) + "]: msg[0] method",
        )
        assert_true(
            rt_result.request_messages[0].target == "/a",
            "random[" + String(ri) + "]: msg[0] target",
        )
        assert_true(
            rt_result.request_messages[0].headers[0].value == host1,
            "random[" + String(ri) + "]: msg[0] Host got '"
            + rt_result.request_messages[0].headers[0].value + "' expected '" + host1 + "'",
        )
        assert_true(
            rt_result.request_messages[1].method == "GET",
            "random[" + String(ri) + "]: msg[1] method",
        )
        assert_true(
            rt_result.request_messages[1].target == "/b",
            "random[" + String(ri) + "]: msg[1] target",
        )
        assert_true(
            rt_result.request_messages[1].headers[0].value == host2,
            "random[" + String(ri) + "]: msg[1] Host got '"
            + rt_result.request_messages[1].headers[0].value + "' expected '" + host2 + "'",
        )
        # Phase must be IDLE, keep_alive must be true
        assert_true(
            rt_result.state.phase == 0,
            "random[" + String(ri) + "]: expected IDLE, got " + _phase_name(rt_result.state.phase),
        )
        assert_true(
            rt_result.state.keep_alive,
            "random[" + String(ri) + "]: expected keep_alive=true",
        )
        total += 1

    print("  random multi-message: 5 sequences passed")

    # Total minimum: at least 40 vectors
    assert_true(
        total >= 40,
        "expected >= 40 vectors, got " + String(total),
    )

    print("test_h1_connection: all " + String(total) + " vectors passed (including " + String(severe_count) + " severe)")
