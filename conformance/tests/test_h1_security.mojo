# conformance/tests/test_h1_security.mojo
#
# Security vector tests with tier-based assertion gates.
from lib.test_util import load_vectors, hex_decode, assert_true, assert_equal
from lib.http1.types import ParseConfig
from lib.http1.parser import parse_request
from std.python import Python, PythonObject


def main() raises:
    # Sentinel check
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var security_files = List[String]()
    security_files.append("vectors/security/smuggling_cl_te.json")
    security_files.append("vectors/security/smuggling_te.json")
    security_files.append("vectors/security/header_injection.json")

    var total = 0
    var severe_count = 0
    var severe_rejected = 0
    var ambiguous_count = 0
    var ambiguous_missing_notes = 0

    for fi in range(len(security_files)):
        var vectors = load_vectors(security_files[fi])

        for i in range(len(vectors)):
            var v = vectors[i]
            var vid = String(v["id"])
            var wire = hex_decode(String(v["input"]["wire_hex"]))
            var expected_behavior = String(v["expected"]["behavior"])
            var severity = String(v["severity"])

            var result = parse_request(wire, ParseConfig())

            if severity == "severe":
                severe_count += 1
                # HARD GATE: all severe vectors MUST be rejected
                assert_true(
                    not result.ok(),
                    "SECURITY FAILURE: severe vector '" + vid + "' was ACCEPTED — must be rejected",
                )
                severe_rejected += 1

            elif severity == "ambiguous":
                ambiguous_count += 1
                # DOCUMENTATION GATE: ambiguous vectors must have notes
                var has_notes = False
                try:
                    var notes = String(v["notes"])
                    has_notes = len(notes) > 0
                except:
                    has_notes = False
                if not has_notes:
                    ambiguous_missing_notes += 1

                # Check behavior matches expected
                if expected_behavior == "reject":
                    assert_true(
                        not result.ok(),
                        vid + ": expected reject but parser accepted",
                    )
                else:
                    assert_true(
                        result.ok(),
                        vid + ": expected accept but parser rejected — " + result.error,
                    )

            total += 1

    # Report
    print("  severe:    " + String(severe_rejected) + "/" + String(severe_count) + " rejected")
    print("  ambiguous: " + String(ambiguous_count) + " vectors (" + String(ambiguous_missing_notes) + " missing notes)")

    assert_true(severe_count >= 10, "expected at least 10 severe vectors, got " + String(severe_count))
    assert_true(ambiguous_count >= 5, "expected at least 5 ambiguous vectors, got " + String(ambiguous_count))
    assert_true(ambiguous_missing_notes == 0, String(ambiguous_missing_notes) + " ambiguous vectors are missing notes")
    print("test_h1_security: all " + String(total) + " security vectors passed")
