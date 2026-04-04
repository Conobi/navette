# conformance/tests/test_cross_packet_number.mojo
from lib.test_util import load_vectors, assert_true, assert_equal
from lib.packet import decode_packet_number
from python import Python, PythonObject


def main() raises:
    # Verify assertions are working (guard against silent no-op)
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    var aioquic_packet = Python.import_module("aioquic.quic.packet")
    var vectors = load_vectors("vectors/rfc9000/packet_number.json")
    assert_true(len(vectors) >= 30, "expected at least 30 packet_number vectors, got " + String(Int(py=len(vectors))))
    var count = 0

    for i in range(len(vectors)):
        var v = vectors[i]
        var name = String(v["name"])
        var operation = String(v["operation"])

        if operation != "decode":
            continue

        var truncated_pn = Int(py=v["input"]["truncated_pn"])
        var pn_nbits = Int(py=v["input"]["pn_nbits"])
        var largest_pn = Int(py=v["input"]["largest_pn"])

        # Our Mojo decoder
        var mojo_result = decode_packet_number(largest_pn, truncated_pn, pn_nbits)

        # aioquic decoder: decode_packet_number(truncated, num_bits, expected)
        # where expected = largest_pn + 1
        var aioquic_result = Int(
            py=aioquic_packet.decode_packet_number(
                truncated_pn, pn_nbits, largest_pn + 1
            )
        )

        assert_equal(
            mojo_result,
            aioquic_result,
            "FAIL ["
            + name
            + "]: mojo="
            + String(mojo_result)
            + " aioquic="
            + String(aioquic_result),
        )
        count += 1

    # Randomized — generate random (largest_pn, truncated_pn, pn_nbits), decode with both
    var py_random = Python.import_module("random")
    var random_count = 0

    for _ in range(50):
        var pn_nbits_py = py_random.choice(Python.evaluate("[8, 16, 24, 32]"))
        var pn_nbits = Int(py=pn_nbits_py)
        var pn_win = 1 << pn_nbits
        var largest_pn_py = py_random.randint(0, 1099511627776)  # 2**40
        var largest_pn = Int(py=largest_pn_py)
        var offset_py = py_random.randint(1, pn_win // 2 - 1)
        var full_pn = largest_pn + Int(py=offset_py)
        var truncated_pn = full_pn & (pn_win - 1)

        # Our decode
        var our_result = decode_packet_number(largest_pn, truncated_pn, pn_nbits)

        # aioquic decode
        var aio_result = Int(py=aioquic_packet.decode_packet_number(truncated_pn, pn_nbits, largest_pn + 1))

        assert_equal(
            our_result,
            aio_result,
            "RANDOM pn decode mismatch: largest=" + String(largest_pn) + " trunc=" + String(truncated_pn) + " nbits=" + String(pn_nbits),
        )

        random_count += 1

    print("  + " + String(random_count) + " random decodes cross-validated")
    print(
        "test_cross_packet_number: all "
        + String(count)
        + " decode vectors cross-validated"
    )
