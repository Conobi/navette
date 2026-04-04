# conformance/tests/test_rustls_initial.mojo
#
# Verify rlsm_initial_keys_raw (librustls_mojo.so) produces correct
# QUIC Initial keys for RFC 9001 Appendix A.1 test vectors.
from lib.test_util import load_vectors, hex_decode, hex_encode, assert_true, assert_bytes_equal
from lib.rustls import RustlsLibrary
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from python import PythonObject


def derive_and_check(
    lib: RustlsLibrary,
    dcid_bytes: List[UInt8],
    is_client: Int32,
    expected_key: List[UInt8],
    expected_iv: List[UInt8],
    expected_hp: List[UInt8],
    label: String,
) raises:
    """Call rlsm_initial_keys_raw and assert outputs match expected values."""
    # Allocate output buffers
    var out_key = _heap_alloc[UInt8](32).as_any_origin()
    var out_iv = _heap_alloc[UInt8](12).as_any_origin()
    var out_hp = _heap_alloc[UInt8](32).as_any_origin()
    var out_key_len = _heap_alloc[Int32](1).as_any_origin()
    var out_iv_len = _heap_alloc[Int32](1).as_any_origin()
    var out_hp_len = _heap_alloc[Int32](1).as_any_origin()

    # Build dcid pointer from the List
    var dcid_ptr = _heap_alloc[UInt8](len(dcid_bytes)).as_any_origin()
    for i in range(len(dcid_bytes)):
        dcid_ptr[i] = dcid_bytes[i]

    var rc = lib.initial_keys_raw(
        Int32(1),  # QUIC v1
        dcid_ptr,
        Int32(len(dcid_bytes)),
        is_client,
        out_key,
        out_key_len,
        out_iv,
        out_iv_len,
        out_hp,
        out_hp_len,
    )

    assert_true(Int(rc) == 0, label + ": rlsm_initial_keys_raw failed (rc=" + String(Int(rc)) + ") — " + lib.last_error())

    # Copy outputs into Lists for comparison
    var got_key = List[UInt8]()
    for i in range(Int(out_key_len[])):
        got_key.append(out_key[i])

    var got_iv = List[UInt8]()
    for i in range(Int(out_iv_len[])):
        got_iv.append(out_iv[i])

    var got_hp = List[UInt8]()
    for i in range(Int(out_hp_len[])):
        got_hp.append(out_hp[i])

    # Free all allocations (before asserts, so they don't leak on failure)
    dcid_ptr.free()
    out_key.free()
    out_iv.free()
    out_hp.free()
    out_key_len.free()
    out_iv_len.free()
    out_hp_len.free()

    # Assert
    assert_bytes_equal(got_key, expected_key, label + " key")
    assert_bytes_equal(got_iv, expected_iv, label + " iv")
    assert_bytes_equal(got_hp, expected_hp, label + " hp")


def main() raises:
    # Verify assertions are working (guard against silent no-op)
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    # Load shared library
    var lib = RustlsLibrary()

    # Load vectors
    var vectors = load_vectors("vectors/rfc9001/initial_protection.json")
    assert_true(
        len(vectors) >= 2,
        "expected at least 2 initial_protection vectors, got " + String(Int(py=len(vectors))),
    )
    var count = 0

    for i in range(len(vectors)):
        var v = vectors[i]
        var operation = String(v["operation"])

        if operation == "key_derivation":
            var dcid_bytes = hex_decode(String(v["input"]["dcid"]))
            var exp = v["expected"]

            # Client side
            derive_and_check(
                lib,
                dcid_bytes,
                Int32(1),
                hex_decode(String(exp["client_key"])),
                hex_decode(String(exp["client_iv"])),
                hex_decode(String(exp["client_hp"])),
                "client",
            )

            # Server side
            derive_and_check(
                lib,
                dcid_bytes,
                Int32(0),
                hex_decode(String(exp["server_key"])),
                hex_decode(String(exp["server_iv"])),
                hex_decode(String(exp["server_hp"])),
                "server",
            )
            count += 1

    assert_true(count >= 1, "expected at least 1 key_derivation vector")
    print("test_rustls_initial: " + String(count) + " vector(s) passed (client + server)")

    # Explicit cleanup — lib owns the DLHandle
    _ = lib^
