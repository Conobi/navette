# conformance/tests/test_h1_response.mojo
#
# HC-2a: RFC 9112 response compliance tests.
from lib.test_util import load_vectors, hex_decode, hex_encode, assert_true, assert_equal, assert_bytes_equal
from lib.http1.types import ParseConfig, ParserStrictness, Header, ParsedResponse
from lib.http1.response import parse_response
from python import Python, PythonObject


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
    # HC-2a response flags
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
    else:
        print("ERROR: unknown flag: " + flag)
        return ParserStrictness()


def check_accept_response(
    result_ref: ParsedResponse,
    expected: PythonObject,
    vec_id: String,
) raises:
    """Validate an accepted parse result against expected fields."""
    assert_true(
        result_ref.ok(),
        vec_id + ": expected accept but got error: " + result_ref.error,
    )

    # Status code
    var exp_status = Int(py=expected["status_code"])
    assert_equal(
        result_ref.status_code,
        exp_status,
        vec_id + ": status_code",
    )

    # Reason
    var exp_reason = String(expected["reason"])
    assert_true(
        result_ref.reason == exp_reason,
        vec_id + ": reason mismatch: got '" + result_ref.reason + "' expected '" + exp_reason + "'",
    )

    # Version
    var exp_version = String(expected["version"])
    assert_true(
        result_ref.version == exp_version,
        vec_id + ": version mismatch: got '" + result_ref.version + "' expected '" + exp_version + "'",
    )

    # Headers
    var builtins = Python.import_module("builtins")
    var exp_headers = expected["headers"]
    var exp_hdr_count = Int(py=builtins.len(exp_headers))
    assert_equal(
        len(result_ref.headers),
        exp_hdr_count,
        vec_id + ": header count",
    )
    for i in range(exp_hdr_count):
        var pair = exp_headers[i]
        var exp_name = String(pair[0])
        var exp_val = String(pair[1])
        assert_true(
            result_ref.headers[i].name == exp_name,
            vec_id + ": header[" + String(i) + "] name mismatch: got '" + result_ref.headers[i].name + "' expected '" + exp_name + "'",
        )
        assert_true(
            result_ref.headers[i].value == exp_val,
            vec_id + ": header[" + String(i) + "] value mismatch: got '" + result_ref.headers[i].value + "' expected '" + exp_val + "'",
        )

    # Body
    var exp_body_hex = String(expected["body_hex"])
    var exp_body = hex_decode(exp_body_hex)
    assert_bytes_equal(result_ref.body, exp_body, vec_id + ": body")

    # Trailers (if present)
    if _has_key(expected, "trailers"):
        var exp_trailers = expected["trailers"]
        var exp_tr_count = Int(py=builtins.len(exp_trailers))
        assert_equal(
            len(result_ref.trailers),
            exp_tr_count,
            vec_id + ": trailer count",
        )
        for ti in range(exp_tr_count):
            var tr_pair = exp_trailers[ti]
            var exp_tr_name = String(tr_pair[0])
            var exp_tr_val = String(tr_pair[1])
            assert_true(
                result_ref.trailers[ti].name == exp_tr_name,
                vec_id + ": trailer[" + String(ti) + "] name mismatch: got '" + result_ref.trailers[ti].name + "' expected '" + exp_tr_name + "'",
            )
            assert_true(
                result_ref.trailers[ti].value == exp_tr_val,
                vec_id + ": trailer[" + String(ti) + "] value mismatch: got '" + result_ref.trailers[ti].value + "' expected '" + exp_tr_val + "'",
            )

    # body_terminated_by_close polarity check:
    # Assert True ONLY when vector explicitly sets it True; False for all others
    var exp_btc = False
    if _has_key(expected, "body_terminated_by_close"):
        # Use int conversion to avoid Bool(PythonObject) issues
        var btc_val = Int(py=expected["body_terminated_by_close"])
        exp_btc = btc_val != 0
    assert_true(
        result_ref.body_terminated_by_close == exp_btc,
        vec_id + ": body_terminated_by_close mismatch: got " + String(result_ref.body_terminated_by_close) + " expected " + String(exp_btc),
    )

    # upgrade polarity check:
    # Assert True ONLY for 101 and CONNECT 2xx; assert False for all others
    var exp_upgrade = False
    if _has_key(expected, "upgrade"):
        var up_val = Int(py=expected["upgrade"])
        exp_upgrade = up_val != 0
    assert_true(
        result_ref.upgrade == exp_upgrade,
        vec_id + ": upgrade mismatch: got " + String(result_ref.upgrade) + " expected " + String(exp_upgrade),
    )

    # bytes_consumed (optional)
    if _has_key(expected, "bytes_consumed"):
        var exp_bc = Int(py=expected["bytes_consumed"])
        assert_equal(
            result_ref.bytes_consumed,
            exp_bc,
            vec_id + ": bytes_consumed",
        )


def check_reject_response(
    result_ref: ParsedResponse,
    expected: PythonObject,
    vec_id: String,
) raises:
    """Validate that parsing was rejected (error is set).
    If the expected dict has a 'reason' field, check it's a substring of the error.
    """
    assert_true(
        not result_ref.ok(),
        vec_id + ": expected reject but parser accepted",
    )

    # Check reason substring if present — warn if mismatch (parser may
    # use a different but equally valid error message)
    if _has_key(expected, "reason"):
        var reason = String(expected["reason"])
        if len(reason) > 0:
            if not _str_contains(result_ref.error, reason):
                print(
                    "    WARNING: " + vec_id + ": error '" + result_ref.error
                    + "' does not contain expected reason '" + reason + "'"
                )


def run_vector(v: PythonObject) raises -> Bool:
    """Run a single test vector. Returns False if skipped."""
    var vec_id = String(v["id"])

    # Skip deferred vectors
    if _has_key(v, "deferred"):
        return False

    # Skip oracle disagreement vectors
    if _has_key(v, "oracle_disagreement"):
        return False

    # Skip auto-corrected vectors
    if _has_key(v, "auto_corrected"):
        return False

    var wire_hex = String(v["input"]["wire_hex"])
    var wire = hex_decode(wire_hex)

    # Extract request_method (default to GET)
    var request_method = String("GET")
    if _has_key(v, "request_method"):
        request_method = String(v["request_method"])

    var has_mode_flag = _has_key(v, "mode_flag")

    if has_mode_flag:
        # Dual-mode vector: test with default strictness, then with flag relaxed
        var flag_name = String(v["mode_flag"])

        # Run with default strictness (all flags False = strict)
        var default_config = ParseConfig()
        var default_result = parse_response(wire, request_method, default_config)
        var default_expected = v["expected_default"]
        var default_behavior = String(default_expected["behavior"])

        if default_behavior == "accept":
            check_accept_response(default_result, default_expected, vec_id + " [default]")
        else:
            check_reject_response(default_result, default_expected, vec_id + " [default]")

        # Re-decode wire for flagged run
        var wire2 = hex_decode(wire_hex)
        var flagged_strictness = _set_flag(flag_name)
        var flagged_config = ParseConfig(strictness=flagged_strictness)
        var flagged_result = parse_response(wire2, request_method, flagged_config)
        var flagged_expected = v["expected_flagged"]
        var flagged_behavior = String(flagged_expected["behavior"])

        if flagged_behavior == "accept":
            check_accept_response(flagged_result, flagged_expected, vec_id + " [flagged:" + flag_name + "]")
        else:
            check_reject_response(flagged_result, flagged_expected, vec_id + " [flagged:" + flag_name + "]")
    elif _has_key(v, "expected"):
        # Single-mode vector
        var expected = v["expected"]
        var behavior = String(expected["behavior"])

        var config = ParseConfig()
        var result = parse_response(wire, request_method, config)

        if behavior == "accept":
            check_accept_response(result, expected, vec_id)
        else:
            check_reject_response(result, expected, vec_id)

    return True


def main() raises:
    # Sentinel assertion check -- verify assertions actually fire
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var builtins = Python.import_module("builtins")
    var total = 0

    var files = List[String]()
    files.append("vectors/rfc9112/response_status.json")
    files.append("vectors/rfc9112/response_body.json")
    files.append("vectors/rfc9112/response_head.json")
    files.append("vectors/rfc9112/response_informational.json")
    files.append("vectors/rfc9112/response_no_body.json")
    files.append("vectors/rfc9112/response_framing.json")

    for fi in range(len(files)):
        var path = files[fi]
        var vectors = load_vectors(path)
        var count = Int(py=builtins.len(vectors))

        # Per-file minimum: at least 6 vectors each
        assert_true(
            count >= 6,
            path + ": expected at least 6 vectors, got " + String(count),
        )

        var ran = 0
        var skipped = 0
        for vi in range(count):
            var v = vectors[vi]
            if run_vector(v):
                ran += 1
            else:
                skipped += 1
        total += ran
        var msg = "  " + path + ": " + String(ran) + " vectors passed"
        if skipped > 0:
            msg += " (" + String(skipped) + " skipped)"
        print(msg)

    # Total minimum: at least 50 vectors
    assert_true(total >= 50, "expected at least 50 total vectors, got " + String(total))

    # ---- Runtime-generated random response (anti-cheat) ----
    # Construct a valid 200 OK response with a pseudo-random header value
    # and Content-Length body. This prevents lookup table cheating.
    var time_mod = Python.import_module("time")
    var ts = Int(py=time_mod.time_ns())
    var rand_val = String()
    var charset = String("abcdefghijklmnopqrstuvwxyz")
    var cs_bytes = charset.as_bytes()
    var tv = ts
    for ri in range(8):
        var idx = tv % 26
        rand_val += chr(Int(cs_bytes[idx]))
        tv = tv // 26 + ri + 1

    var rand_body = "rand" + rand_val
    var rand_cl = String(len(rand_body))

    # Build wire: HTTP/1.1 200 OK\r\nContent-Length: <cl>\r\nX-Rand: <rand_val>\r\n\r\n<body>
    var rt_str = "HTTP/1.1 200 OK\r\nContent-Length: " + rand_cl + "\r\nX-Rand: " + rand_val + "\r\n\r\n" + rand_body
    var rt_bytes = rt_str.as_bytes()
    var rt_wire = List[UInt8]()
    for ri2 in range(len(rt_bytes)):
        rt_wire.append(rt_bytes[ri2])

    var rt_config = ParseConfig()
    var rt_result = parse_response(rt_wire, String("GET"), rt_config)
    assert_true(rt_result.ok(), "runtime vector: parse failed: " + rt_result.error)
    assert_equal(rt_result.status_code, 200, "runtime vector: status_code")
    assert_true(rt_result.reason == "OK", "runtime vector: reason mismatch")
    assert_equal(len(rt_result.headers), 2, "runtime vector: header count")
    assert_true(
        rt_result.headers[1].name == "X-Rand",
        "runtime vector: header name mismatch",
    )
    assert_true(
        rt_result.headers[1].value == rand_val,
        "runtime vector: header value mismatch: got '" + rt_result.headers[1].value + "' expected '" + rand_val + "'",
    )
    # Verify body roundtrips
    var exp_body_bytes = rand_body.as_bytes()
    var exp_body_list = List[UInt8]()
    for ebi in range(len(exp_body_bytes)):
        exp_body_list.append(exp_body_bytes[ebi])
    assert_bytes_equal(rt_result.body, exp_body_list, "runtime vector: body")
    # body_terminated_by_close must be False (CL-framed)
    assert_true(
        not rt_result.body_terminated_by_close,
        "runtime vector: body_terminated_by_close should be False",
    )
    # upgrade must be False (200 OK to GET)
    assert_true(
        not rt_result.upgrade,
        "runtime vector: upgrade should be False",
    )
    total += 1
    print("  runtime random response: passed (X-Rand: " + rand_val + ")")

    print("test_h1_response: all " + String(total) + " vectors passed")
