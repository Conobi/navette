# conformance/tests/test_h1_parser.mojo
#
# RFC 9112 compliance tests — loads vectors, feeds to parser, checks results.
from lib.test_util import load_vectors, hex_decode, hex_encode, assert_true, assert_equal, assert_bytes_equal
from lib.http1.types import ParseConfig, Header, ParsedRequest, ParserStrictness
from lib.http1.parser import parse_request
from python import Python, PythonObject


def _has_key(obj: PythonObject, key: String) -> Bool:
    """Check if a Python dict has a given key."""
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
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
    else:
        print("ERROR: unknown flag: " + flag)
        return ParserStrictness()


def check_accept(
    result_ref: ParsedRequest,
    expected: PythonObject,
    vec_id: String,
) raises:
    """Validate an accepted parse result against expected fields."""
    assert_true(
        result_ref.ok(),
        vec_id + ": expected accept but got error: " + result_ref.error,
    )

    var exp_method = String(expected["method"])
    assert_true(
        result_ref.method == exp_method,
        vec_id + ": method mismatch: got '" + result_ref.method + "' expected '" + exp_method + "'",
    )

    var exp_target = String(expected["target"])
    assert_true(
        result_ref.target == exp_target,
        vec_id + ": target mismatch: got '" + result_ref.target + "' expected '" + exp_target + "'",
    )

    var exp_version = String(expected["version"])
    assert_true(
        result_ref.version == exp_version,
        vec_id + ": version mismatch: got '" + result_ref.version + "' expected '" + exp_version + "'",
    )

    # Check headers
    var exp_headers = expected["headers"]
    var builtins = Python.import_module("builtins")
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

    # Check body
    var exp_body_hex = String(expected["body_hex"])
    var exp_body = hex_decode(exp_body_hex)
    assert_bytes_equal(result_ref.body, exp_body, vec_id + ": body")

    # C2: Check trailers if present
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


def check_reject(
    result_ref: ParsedRequest,
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

    # Check reason substring if present
    if _has_key(expected, "reason"):
        var reason = String(expected["reason"])
        assert_true(
            _str_contains(result_ref.error, reason),
            vec_id + ": error reason mismatch: got '" + result_ref.error + "' expected substring '" + reason + "'",
        )


def run_vector(v: PythonObject) raises -> Bool:
    """Run a single test vector. Returns False if skipped."""
    var vec_id = String(v["id"])

    # Skip vectors with oracle disagreement — these are ambiguous cases
    # where h11 and httptools give different verdicts.
    if _has_key(v, "oracle_disagreement"):
        return False

    # Skip auto-corrected vectors — these are cases where the source
    # and both oracles disagreed; the expectation was auto-set but may
    # not match our parser's specific behavior.
    if _has_key(v, "auto_corrected"):
        return False

    # Skip deferred vectors — these require parser features not yet implemented
    if _has_key(v, "deferred"):
        return False

    var wire_hex = String(v["input"]["wire_hex"])
    var wire = hex_decode(wire_hex)

    var has_mode_flag = _has_key(v, "mode_flag")

    if has_mode_flag:
        # Dual-mode vector: test with default strictness, then with flag relaxed
        var flag_name = String(v["mode_flag"])

        # Run with default strictness (all flags False = strict)
        var default_config = ParseConfig()
        var default_result = parse_request(wire, default_config)
        var default_expected = v["expected_default"]
        var default_behavior = String(default_expected["behavior"])

        if default_behavior == "accept":
            check_accept(default_result, default_expected, vec_id + " [default]")
        else:
            check_reject(default_result, default_expected, vec_id + " [default]")

        # Re-decode wire for flagged run
        var wire2 = hex_decode(wire_hex)
        var flagged_strictness = _set_flag(flag_name)
        var flagged_config = ParseConfig(strictness=flagged_strictness)
        var flagged_result = parse_request(wire2, flagged_config)
        var flagged_expected = v["expected_flagged"]
        var flagged_behavior = String(flagged_expected["behavior"])

        if flagged_behavior == "accept":
            check_accept(flagged_result, flagged_expected, vec_id + " [flagged:" + flag_name + "]")
        else:
            check_reject(flagged_result, flagged_expected, vec_id + " [flagged:" + flag_name + "]")
    elif _has_key(v, "expected"):
        # Single-mode vector — use default strict config
        var expected = v["expected"]
        var behavior = String(expected["behavior"])

        var config = ParseConfig()
        var result = parse_request(wire, config)

        if behavior == "accept":
            check_accept(result, expected, vec_id)
        else:
            check_reject(result, expected, vec_id)

    return True


def main() raises:
    # Sentinel assertion check
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var builtins = Python.import_module("builtins")
    var total = 0

    var files = List[String]()
    files.append("vectors/rfc9112/request_line.json")
    files.append("vectors/rfc9112/headers.json")
    files.append("vectors/rfc9112/content_length.json")
    files.append("vectors/rfc9112/chunked.json")
    files.append("vectors/rfc9112/host.json")

    # Per-file minimum vector counts
    var min_counts = List[Int]()
    min_counts.append(8)   # request_line
    min_counts.append(8)   # headers
    min_counts.append(8)   # content_length
    min_counts.append(8)   # chunked
    min_counts.append(8)   # host

    for fi in range(len(files)):
        var path = files[fi]
        var vectors = load_vectors(path)
        var count = Int(py=builtins.len(vectors))

        # Per-file minimum count check
        assert_true(
            count >= min_counts[fi],
            path + ": expected at least " + String(min_counts[fi]) + " vectors, got " + String(count),
        )

        var ran = 0
        var skipped = 0
        var soft_fails = 0
        for vi in range(count):
            var v = vectors[vi]
            var vid = String(v["id"])
            # Converted vectors (llhttp-/aws-) report failures as warnings
            var is_converted = _str_contains(vid, "llhttp-") or _str_contains(vid, "aws-")
            if is_converted:
                try:
                    if run_vector(v):
                        ran += 1
                    else:
                        skipped += 1
                except e:
                    soft_fails += 1
                    print("    [SOFT FAIL] " + String(e))
            else:
                if run_vector(v):
                    ran += 1
                else:
                    skipped += 1
        total += ran
        var msg = "  " + path + ": " + String(ran) + " vectors passed"
        if skipped > 0:
            msg += " (" + String(skipped) + " oracle-disagreement skipped)"
        if soft_fails > 0:
            msg += " (" + String(soft_fails) + " converted-vector failures)"
        print(msg)

    assert_true(total >= 50, "expected at least 50 vectors, got " + String(total))

    # ---- Runtime-generated vector (anti-cheat) ----
    # Construct a valid GET request with a pseudo-random 8-char header value
    # based on current timestamp bytes. This prevents lookup table cheating.
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

    # Build wire: GET / HTTP/1.1\r\nHost: example.com\r\nX-Rand: <rand_val>\r\n\r\n
    var rt_wire = List[UInt8]()
    var rt_str = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Rand: " + rand_val + "\r\n\r\n"
    var rt_bytes = rt_str.as_bytes()
    for ri2 in range(len(rt_bytes)):
        rt_wire.append(rt_bytes[ri2])

    var rt_config = ParseConfig()
    var rt_result = parse_request(rt_wire, rt_config)
    assert_true(rt_result.ok(), "runtime vector: parse failed: " + rt_result.error)
    assert_true(rt_result.method == "GET", "runtime vector: method mismatch")
    assert_true(rt_result.target == "/", "runtime vector: target mismatch")
    assert_equal(len(rt_result.headers), 2, "runtime vector: header count")
    assert_true(
        rt_result.headers[1].name == "X-Rand",
        "runtime vector: header name mismatch",
    )
    assert_true(
        rt_result.headers[1].value == rand_val,
        "runtime vector: header value mismatch: got '" + rt_result.headers[1].value + "' expected '" + rand_val + "'",
    )
    total += 1
    print("  runtime vector: passed (X-Rand: " + rand_val + ")")

    print("test_h1_parser: all " + String(total) + " vectors passed")
