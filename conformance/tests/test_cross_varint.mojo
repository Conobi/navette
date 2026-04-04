# conformance/tests/test_cross_varint.mojo
from lib.test_util import hex_decode, hex_encode, assert_bytes_equal, load_vectors, assert_true, assert_equal
from lib.cursor import ByteWriter, ByteReader
from lib.varint import varint_encode, varint_decode
from python import Python, PythonObject


def main() raises:
    # Verify assertions are working (guard against silent no-op)
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    var binascii = Python.import_module("binascii")
    var aioquic_buf = Python.import_module("aioquic._buffer")

    var vectors = load_vectors("vectors/rfc9000/varint.json")
    assert_true(len(vectors) >= 100, "expected at least 100 varint vectors, got " + String(Int(py=len(vectors))))
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

            assert_equal(
                mojo_val,
                expected_val,
                "FAIL [" + name + "]: mojo decode mismatch",
            )
            assert_equal(
                aio_val,
                expected_val,
                "FAIL [" + name + "]: aioquic decode mismatch",
            )
            assert_equal(
                mojo_val,
                aio_val,
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

            assert_true(
                mojo_raised,
                "FAIL [" + name + "]: mojo should raise on error vector",
            )
            assert_true(
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
        assert_equal(
            Int(decoded),
            value,
            "FAIL [" + name + "_decode]: got " + String(Int(decoded)),
        )

        # Test decode round-trip (aioquic)
        var py_bytes2 = binascii.unhexlify(expected_hex)
        var py_buf2 = aioquic_buf.Buffer(data=py_bytes2)
        var aio_decoded = Int(py=py_buf2.pull_uint_var())
        assert_equal(
            aio_decoded,
            value,
            "FAIL [" + name + "_aioquic_decode]: got " + String(aio_decoded),
        )

        # Assert both decoders agree
        assert_equal(
            Int(decoded),
            aio_decoded,
            "FAIL [" + name + "_cross_decode]: mojo=" + String(Int(decoded)) + " aioquic=" + String(aio_decoded),
        )

        count += 1

    # Randomized cross-validation — inputs change every run, lookup tables impossible
    var py_random = Python.import_module("random")
    var random_count = 0

    # Generate random values across all 4 size classes
    var size_ranges = Python.evaluate("[(0, 63), (64, 16383), (16384, 1073741823), (1073741824, 4611686018427387903)]")
    for cls_idx in range(4):
        var lo = size_ranges[cls_idx][0]
        var hi = size_ranges[cls_idx][1]
        for _ in range(25):
            var rand_val_py = py_random.randint(lo, hi)
            var rand_val = Int(py=rand_val_py)

            # Encode with our codec
            var w = ByteWriter(capacity=8)
            varint_encode(w, UInt64(rand_val))
            var our_bytes = w.finish()

            # Encode with aioquic
            var aio_buf = aioquic_buf.Buffer(capacity=8)
            aio_buf.push_uint_var(rand_val_py)
            var aio_hex = String(binascii.hexlify(aio_buf.data).decode("ascii"))

            # Compare
            var our_hex = hex_encode(our_bytes)
            assert_true(
                our_hex == aio_hex,
                "RANDOM varint encode mismatch: value=" + String(rand_val) + " ours=" + our_hex + " aioquic=" + aio_hex,
            )

            random_count += 1

    print("  + " + String(random_count) + " random values cross-validated")
    print("test_cross_varint: all " + String(count) + " vectors cross-validated")
