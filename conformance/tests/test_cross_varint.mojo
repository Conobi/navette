# conformance/tests/test_cross_varint.mojo
from lib.test_util import hex_decode, hex_encode, assert_bytes_equal, load_vectors
from lib.cursor import ByteWriter, ByteReader
from lib.varint import varint_encode, varint_decode
from python import Python, PythonObject


def main() raises:
    var binascii = Python.import_module("binascii")
    var aioquic_buf = Python.import_module("aioquic._buffer")

    var vectors = load_vectors("vectors/rfc9000/varint.json")
    var count = 0

    for i in range(len(vectors)):
        var v = vectors[i]
        var name = String(v["name"])

        # Decode-only vectors (non-minimal encodings)
        var direction = String(v.get("direction", ""))
        if direction == "decode_only":
            var input_hex = String(v["input"]["bytes"])
            var input_bytes = hex_decode(input_hex)
            var expected_val = Int(py=v["expected"]["value"])

            # Mojo decode
            var r = ByteReader(input_bytes)
            var mojo_val = Int(varint_decode(r))

            # aioquic decode
            var py_bytes = binascii.unhexlify(input_hex)
            var py_buf = aioquic_buf.Buffer(data=py_bytes)
            var aio_val = Int(py=py_buf.pull_uint_var())

            debug_assert(
                mojo_val == expected_val,
                "FAIL [" + name + "]: mojo decode mismatch",
            )
            debug_assert(
                aio_val == expected_val,
                "FAIL [" + name + "]: aioquic decode mismatch",
            )
            debug_assert(
                mojo_val == aio_val,
                "FAIL [" + name + "]: mojo vs aioquic decode mismatch",
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

            # aioquic should also raise
            var py_bytes = binascii.unhexlify(input_hex)
            var py_buf = aioquic_buf.Buffer(data=py_bytes)
            var aio_raised = False
            try:
                _ = py_buf.pull_uint_var()
            except:
                aio_raised = True

            debug_assert(
                mojo_raised,
                "FAIL [" + name + "]: mojo should raise on error vector",
            )
            debug_assert(
                aio_raised,
                "FAIL [" + name + "]: aioquic should raise on error vector",
            )
            count += 1
            continue

        # Normal encode vectors
        var value = Int(py=v["input"]["value"])
        var expected_hex = String(v["expected"])
        var expected_bytes = hex_decode(expected_hex)

        # Mojo encode
        var w = ByteWriter(capacity=8)
        varint_encode(w, UInt64(value))
        var mojo_encoded = w.finish()

        # aioquic encode
        var py_buf = aioquic_buf.Buffer(capacity=8)
        py_buf.push_uint_var(value)
        var aio_hex = String(binascii.hexlify(py_buf.data).decode("ascii"))
        var aio_encoded = hex_decode(aio_hex)

        # Assert mojo matches expected
        assert_bytes_equal(mojo_encoded, expected_bytes, name + "_mojo_encode")

        # Assert aioquic matches expected
        assert_bytes_equal(aio_encoded, expected_bytes, name + "_aioquic_encode")

        # Assert mojo == aioquic
        assert_bytes_equal(mojo_encoded, aio_encoded, name + "_cross_encode")

        # Test decode round-trip (mojo)
        var r2 = ByteReader(hex_decode(expected_hex))
        var decoded = varint_decode(r2)
        debug_assert(
            Int(decoded) == value,
            "FAIL [" + name + "_decode]: got " + String(Int(decoded)),
        )

        # Test decode round-trip (aioquic)
        var py_bytes2 = binascii.unhexlify(expected_hex)
        var py_buf2 = aioquic_buf.Buffer(data=py_bytes2)
        var aio_decoded = Int(py=py_buf2.pull_uint_var())
        debug_assert(
            aio_decoded == value,
            "FAIL [" + name + "_aioquic_decode]: got " + String(aio_decoded),
        )

        # Assert both decoders agree
        debug_assert(
            Int(decoded) == aio_decoded,
            "FAIL [" + name + "_cross_decode]: mojo=" + String(Int(decoded)) + " aioquic=" + String(aio_decoded),
        )

        count += 1

    print("test_cross_varint: all " + String(count) + " vectors cross-validated")
