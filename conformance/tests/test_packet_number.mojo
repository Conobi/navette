# conformance/tests/test_packet_number.mojo
from lib.test_util import load_vectors
from lib.packet import decode_packet_number, encode_packet_number_length
from python import Python, PythonObject


def main() raises:
    var vectors = load_vectors("vectors/rfc9000/packet_number.json")
    var count = 0

    for i in range(len(vectors)):
        var v = vectors[i]
        var name = String(v["name"])
        var operation = String(v["operation"])

        if operation == "decode":
            # Decode test: decode_packet_number(largest_pn, truncated_pn, pn_nbits)
            var truncated_pn = Int(py=v["input"]["truncated_pn"])
            var pn_nbits = Int(py=v["input"]["pn_nbits"])
            var largest_pn = Int(py=v["input"]["largest_pn"])
            var expected_full_pn = Int(py=v["expected"]["full_pn"])

            var full_pn = decode_packet_number(largest_pn, truncated_pn, pn_nbits)
            debug_assert(
                full_pn == expected_full_pn,
                "FAIL [" + name + "]: got " + String(full_pn)
                + " expected " + String(expected_full_pn),
            )
            count += 1

        elif operation == "encode":
            # Encode test: encode_packet_number_length(full_pn, largest_acked)
            var full_pn = Int(py=v["input"]["full_pn"])
            var largest_acked = Int(py=v["input"]["largest_acked"])
            var expected_pn_length = Int(py=v["expected"]["pn_length"])

            var pn_length = encode_packet_number_length(full_pn, largest_acked)
            debug_assert(
                pn_length == expected_pn_length,
                "FAIL [" + name + "]: got " + String(pn_length)
                + " expected " + String(expected_pn_length),
            )
            count += 1

    print("test_packet_number: all " + String(count) + " vectors passed")
