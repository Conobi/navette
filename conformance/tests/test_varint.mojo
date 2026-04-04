# conformance/tests/test_varint.mojo
from lib.test_util import hex_decode, hex_encode, assert_bytes_equal, load_vectors
from lib.cursor import ByteWriter, ByteReader
from lib.varint import varint_encode, varint_decode
from python import Python, PythonObject


def main() raises:
    var vectors = load_vectors("vectors/rfc9000/varint.json")
    var count = 0

    for i in range(len(vectors)):
        var v = vectors[i]
        var name = String(v["name"])

        # Decode-only vectors (non-minimal encodings)
        var direction = String(v.get("direction", ""))
        if direction == "decode_only":
            var input_bytes = hex_decode(String(v["input"]["bytes"]))
            var r = ByteReader(input_bytes)
            var decoded = varint_decode(r)
            var expected_val = Int(py=v["expected"]["value"])
            debug_assert(
                Int(decoded) == expected_val,
                "FAIL [" + name + "]: decode mismatch",
            )
            count += 1
            continue

        # Error vectors
        var expected_str = String(v["expected"])
        if expected_str == "error":
            var input_bytes = hex_decode(String(v["input"]["bytes"]))
            var r = ByteReader(input_bytes)
            var raised = False
            try:
                _ = varint_decode(r)
            except:
                raised = True
            debug_assert(raised, "FAIL [" + name + "]: should raise")
            count += 1
            continue

        # Normal encode vectors
        var value = Int(py=v["input"]["value"])
        var expected_bytes = hex_decode(String(v["expected"]))

        # Test encode
        var w = ByteWriter(capacity=8)
        varint_encode(w, UInt64(value))
        assert_bytes_equal(w.finish(), expected_bytes, name + "_encode")

        # Test decode round-trip
        var r2 = ByteReader(hex_decode(String(v["expected"])))
        var decoded = varint_decode(r2)
        debug_assert(
            Int(decoded) == value,
            "FAIL [" + name + "_decode]: got " + String(Int(decoded)),
        )
        count += 1

    print("test_varint: all " + String(count) + " vectors passed")
