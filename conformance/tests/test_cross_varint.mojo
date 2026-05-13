# conformance/tests/test_cross_varint.mojo
#
# Vector-based cross-validation of QUIC variable-length integer (RFC 9000 §16).
#
# As of §3.3 of the dependency-enhancement plan, this test no longer imports
# aioquic at runtime. The vectors in conformance/vectors/rfc9000/varint.json
# are pre-materialized by conformance/scripts/oracle_quic_frame.py (which uses
# aioquic at build/oracle time) and include `source: random_generated` entries
# that previously came from a live random fuzz against aioquic.
from lib.test_util import hex_decode, hex_encode, assert_bytes_equal, load_vectors, assert_true, assert_equal
from lib.cursor import ByteWriter, ByteReader
from lib.varint import varint_encode, varint_decode


def main() raises:
    # Verify assertions are working (guard against silent no-op)
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    var vectors = load_vectors("vectors/rfc9000/varint.json")
    assert_true(len(vectors) >= 100, "expected at least 100 varint vectors, got " + String(Int(py=len(vectors))))
    var count = 0
    var random_count = 0

    for i in range(len(vectors)):
        var v = vectors[i]
        var name = String(v["name"])
        var source = String(v.get("source", ""))

        # Decode-only vectors (non-minimal encodings, malformed)
        var direction = String(v.get("direction", ""))
        if direction == "decode_only":
            var input_hex = String(v["input"]["bytes"])
            var input_bytes = hex_decode(input_hex)
            var expected_val = Int(py=v["expected"]["value"])

            # Mojo decode
            var r = ByteReader(input_bytes)
            var mojo_val = Int(varint_decode(r))

            assert_equal(
                mojo_val,
                expected_val,
                "FAIL [" + name + "]: mojo decode mismatch vs pre-materialized oracle",
            )
            count += 1
            continue

        # Error vectors
        var expected_str = String(v["expected"])
        if expected_str == "error":
            var input_hex = String(v["input"]["bytes"])
            var input_bytes = hex_decode(input_hex)

            # Mojo should raise
            var r = ByteReader(input_bytes)
            var mojo_raised = False
            try:
                _ = varint_decode(r)
            except:
                mojo_raised = True

            assert_true(
                mojo_raised,
                "FAIL [" + name + "]: mojo should raise on error vector",
            )
            count += 1
            continue

        # Normal encode vectors (boundary_sweep, exhaustive_1byte, random_generated)
        var value = Int(py=v["input"]["value"])
        var expected_hex = String(v["expected"])
        var expected_bytes = hex_decode(expected_hex)

        # Mojo encode
        var w = ByteWriter(capacity=8)
        varint_encode(w, UInt64(value))
        var mojo_encoded = w.finish()

        # Assert mojo matches pre-materialized aioquic oracle
        assert_bytes_equal(mojo_encoded, expected_bytes, name + "_mojo_encode")

        # Test decode round-trip (mojo)
        var r2 = ByteReader(hex_decode(expected_hex))
        var decoded = varint_decode(r2)
        assert_equal(
            Int(decoded),
            value,
            "FAIL [" + name + "_decode]: got " + String(Int(decoded)),
        )

        if source == "random_generated":
            random_count += 1
        count += 1

    print("  + " + String(random_count) + " random values cross-validated (pre-materialized aioquic oracle)")
    print("test_cross_varint: all " + String(count) + " vectors cross-validated")
