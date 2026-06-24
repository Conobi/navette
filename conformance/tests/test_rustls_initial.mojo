# conformance/tests/test_rustls_initial.mojo
#
# Verify rlsm_initial_keys_raw (librustls_mojo.so) produces correct
# QUIC Initial keys for RFC 9001 Appendix A.1 test vectors.
from lib.test_util import load_vectors, hex_decode, hex_encode, assert_true, assert_bytes_equal
from lib.rustls import RustlsLibrary
from std.memory import UnsafePointer
from navette.util.owned_alloc import Owned
from std.python import PythonObject


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
    var out_key_buf = Owned[UInt8](32)
    var out_key = out_key_buf.ptr()
    var out_iv_buf = Owned[UInt8](12)
    var out_iv = out_iv_buf.ptr()
    var out_hp_buf = Owned[UInt8](32)
    var out_hp = out_hp_buf.ptr()
    var out_key_len_buf = Owned[Int32](1)
    var out_key_len = out_key_len_buf.ptr()
    var out_iv_len_buf = Owned[Int32](1)
    var out_iv_len = out_iv_len_buf.ptr()
    var out_hp_len_buf = Owned[Int32](1)
    var out_hp_len = out_hp_len_buf.ptr()
    # rlsm_initial_keys_raw treats *out_*_len as in/out: caller writes capacity.
    out_key_len[] = Int32(32)
    out_iv_len[] = Int32(12)
    out_hp_len[] = Int32(32)

    # Build dcid pointer from the List
    var dcid_ptr_buf = Owned[UInt8](len(dcid_bytes))
    var dcid_ptr = dcid_ptr_buf.ptr()
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

    # Keep buffers alive across the FFI call + post-FFI out-param reads above.
    # `Owned` auto-frees on every path (incl. the assert raises below), so the
    # leak-on-failure the old manual-free-before-asserts guarded against is gone.
    _ = dcid_ptr_buf
    _ = out_key_buf
    _ = out_iv_buf
    _ = out_hp_buf
    _ = out_key_len_buf
    _ = out_iv_len_buf
    _ = out_hp_len_buf

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
