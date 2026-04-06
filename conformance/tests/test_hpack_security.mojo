# conformance/tests/test_hpack_security.mojo
#
# HC-3b Task 7: HPACK security tests.
# Validates that the HPACK decoder correctly rejects attack payloads
# (bombs, integer overflow, invalid Huffman, invalid index, oversized
# table updates, truncated wire) and accepts clean edge cases.

from lib.test_util import load_vectors, hex_decode, assert_true
from lib.http1.types import Header
from lib.http2.hpack import HpackDecoder, HpackConfig
from python import Python, PythonObject


def _has_key(obj: PythonObject, key: String) -> Bool:
    """Check if a Python dict has a given key."""
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


def main() raises:
    # ---- Sentinel anti-cheat: verify assert_true actually fires ----
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var vectors = load_vectors(
        "vectors/security/hpack_security.json"
    )
    var builtins = Python.import_module("builtins")
    var count = Int(py=builtins.len(vectors))

    var total = 0
    var severe_count = 0
    var severe_passed = 0

    for i in range(count):
        var v = vectors[i]
        var vid = String(v["id"])
        var severity = String(v["severity"])
        var wire = hex_decode(String(v["input"]["wire_hex"]))
        var expected_behavior = String(v["expected"]["behavior"])

        # Fresh decoder per vector (default config: table=4096, list=65536)
        var decoder = HpackDecoder()
        var result = decoder.decode(wire)
        var err = String(result[1])
        var decoded_count = len(result[0])

        if expected_behavior == "reject":
            # Must produce an error
            if severity == "severe":
                severe_count += 1
                assert_true(
                    len(err) > 0,
                    "SECURITY FAILURE: severe vector '"
                    + vid
                    + "' was ACCEPTED — must be rejected",
                )
                severe_passed += 1
            else:
                assert_true(
                    len(err) > 0,
                    vid + ": expected reject but decoder accepted",
                )
            print("  [PASS] " + vid + " (rejected: " + err + ")")

        elif expected_behavior == "accept":
            # Must succeed
            if severity == "severe":
                severe_count += 1
                assert_true(
                    len(err) == 0,
                    "SECURITY FAILURE: severe vector '"
                    + vid
                    + "' was REJECTED ("
                    + err
                    + ") — must be accepted",
                )
                severe_passed += 1
            else:
                assert_true(
                    len(err) == 0,
                    vid
                    + ": expected accept but decoder rejected — "
                    + err,
                )

            # Verify expected headers if present
            if _has_key(v["expected"], "expected_headers"):
                var exp = v["expected"]["expected_headers"]
                var exp_count = Int(py=builtins.len(exp))
                assert_true(
                    decoded_count == exp_count,
                    vid
                    + ": header count mismatch: got "
                    + String(decoded_count)
                    + " expected "
                    + String(exp_count),
                )
                for j in range(exp_count):
                    var exp_name = String(exp[j][0])
                    var exp_value = String(exp[j][1])
                    assert_true(
                        result[0][j].name == exp_name,
                        vid
                        + " header "
                        + String(j)
                        + " name: got '"
                        + result[0][j].name
                        + "' expected '"
                        + exp_name
                        + "'",
                    )
                    assert_true(
                        result[0][j].value == exp_value,
                        vid
                        + " header "
                        + String(j)
                        + " value: got '"
                        + result[0][j].value
                        + "' expected '"
                        + exp_value
                        + "'",
                    )

            print("  [PASS] " + vid + " (accepted)")

        total += 1

    # Anti-cheat: must have at least 4 severe vectors
    assert_true(
        severe_count >= 4,
        "expected at least 4 severe vectors, got "
        + String(severe_count),
    )

    # All severe vectors must pass
    assert_true(
        severe_passed == severe_count,
        String(severe_count - severe_passed)
        + " severe vectors failed out of "
        + String(severe_count),
    )

    print(
        "test_hpack_security: all "
        + String(total)
        + " vectors passed ("
        + String(severe_passed)
        + "/"
        + String(severe_count)
        + " severe)"
    )
