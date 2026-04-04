# conformance/tests/test_cross_packet_number.mojo
from lib.test_util import load_vectors
from lib.packet import decode_packet_number
from python import Python, PythonObject


def main() raises:
    var aioquic_packet = Python.import_module("aioquic.quic.packet")
    var vectors = load_vectors("vectors/rfc9000/packet_number.json")
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

        debug_assert(
            mojo_result == aioquic_result,
            "FAIL ["
            + name
            + "]: mojo="
            + String(mojo_result)
            + " aioquic="
            + String(aioquic_result),
        )
        count += 1

    print(
        "test_cross_packet_number: all "
        + String(count)
        + " decode vectors cross-validated"
    )
