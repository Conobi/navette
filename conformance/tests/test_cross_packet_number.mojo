# conformance/tests/test_cross_packet_number.mojo
#
# QUIC packet number decoding (RFC 9000 §17.1) — cross-validation against
# the pre-materialized aioquic.quic.packet oracle in
# conformance/vectors/rfc9000/packet_number.json.
#
# As of §3.3 of the dependency-enhancement plan, aioquic is no longer
# imported at test runtime. The vector file includes 20 `random_generated`
# entries that previously came from a live random fuzz against
# aioquic.quic.packet.decode_packet_number.
from lib.test_util import load_vectors, assert_true, assert_equal
from lib.packet import decode_packet_number


def main() raises:
    # Verify assertions are working (guard against silent no-op)
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    var vectors = load_vectors("vectors/rfc9000/packet_number.json")
    assert_true(len(vectors) >= 30, "expected at least 30 packet_number vectors, got " + String(Int(py=len(vectors))))
    var count = 0
    var random_count = 0

    for i in range(len(vectors)):
        var v = vectors[i]
        var name = String(v["name"])
        var operation = String(v["operation"])
        var source = String(v.get("source", ""))

        if operation != "decode":
            continue

        var truncated_pn = Int(py=v["input"]["truncated_pn"])
        var pn_nbits = Int(py=v["input"]["pn_nbits"])
        var largest_pn = Int(py=v["input"]["largest_pn"])
        var expected_full_pn = Int(py=v["expected"]["full_pn"])

        # Our Mojo decoder
        var mojo_result = decode_packet_number(largest_pn, truncated_pn, pn_nbits)

        assert_equal(
            mojo_result,
            expected_full_pn,
            "FAIL ["
            + name
            + "]: mojo="
            + String(mojo_result)
            + " oracle="
            + String(expected_full_pn),
        )
        count += 1
        if source == "random_generated":
            random_count += 1

    print("  + " + String(random_count) + " random decodes cross-validated (pre-materialized aioquic oracle)")
    print(
        "test_cross_packet_number: all "
        + String(count)
        + " decode vectors cross-validated"
    )
