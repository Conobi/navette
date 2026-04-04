# conformance/tests/test_cross_initial_crypto.mojo
#
# Cross-validation test: derives QUIC v1 Initial keys using BOTH
# our Python `cryptography`-based code path AND aioquic's native
# crypto functions, asserting both produce identical keys and both
# match the expected values from the RFC 9001 A.1 vector.
from lib.test_util import load_vectors, assert_true, hex_decode, hex_encode
from lib.rustls import RustlsLibrary
from std.memory.unsafe_pointer import alloc as _heap_alloc
from python import Python, PythonObject


fn py_bytes_to_hex(raw: PythonObject) raises -> String:
    """Convert a Python bytes object to a lowercase hex string."""
    var binascii = Python.import_module("binascii")
    return String(binascii.hexlify(raw).decode("ascii"))


fn hkdf_expand_label_our(
    secret: PythonObject,
    label_str: String,
    length: Int,
    HKDFExpand: PythonObject,
    SHA256: PythonObject,
    struct_mod: PythonObject,
) raises -> PythonObject:
    """HKDF-Expand-Label (our cryptography-based path) as in RFC 8446 / RFC 9001."""
    var builtins = Python.import_module("builtins")
    var py_label = builtins.str("tls13 " + label_str).encode("ascii")
    var label_len = Int(py=builtins.len(py_label))
    # HkdfLabel: uint16(length) || uint8(len(label)) || label || uint8(0) context
    var hkdf_label = (
        struct_mod.pack(">H", length)
        + struct_mod.pack("B", label_len)
        + py_label
        + struct_mod.pack("B", 0)
    )
    var kdf = HKDFExpand(algorithm=SHA256(), length=length, info=hkdf_label)
    return kdf.derive(secret)


def rustls_derive_keys(
    lib: RustlsLibrary,
    dcid_hex: String,
    is_client: Int32,
) raises -> List[String]:
    """Derive key, iv, hp via librustls_mojo.so. Returns list [key, iv, hp] as hex strings."""
    var dcid_bytes = hex_decode(dcid_hex)
    var dcid_ptr = _heap_alloc[UInt8](len(dcid_bytes)).as_any_origin()
    for i in range(len(dcid_bytes)):
        dcid_ptr[i] = dcid_bytes[i]

    var out_key = _heap_alloc[UInt8](32).as_any_origin()
    var out_iv = _heap_alloc[UInt8](12).as_any_origin()
    var out_hp = _heap_alloc[UInt8](32).as_any_origin()
    var out_key_len = _heap_alloc[Int32](1).as_any_origin()
    var out_iv_len = _heap_alloc[Int32](1).as_any_origin()
    var out_hp_len = _heap_alloc[Int32](1).as_any_origin()

    var rc = lib.initial_keys_raw(
        Int32(1),  # QUIC v1
        dcid_ptr,
        Int32(len(dcid_bytes)),
        is_client,
        out_key, out_key_len,
        out_iv, out_iv_len,
        out_hp, out_hp_len,
    )
    assert_true(
        Int(rc) == 0,
        "rustls rlsm_initial_keys_raw failed: " + lib.last_error(),
    )

    var key_list = List[UInt8]()
    for i in range(Int(out_key_len[])):
        key_list.append(out_key[i])
    var iv_list = List[UInt8]()
    for i in range(Int(out_iv_len[])):
        iv_list.append(out_iv[i])
    var hp_list = List[UInt8]()
    for i in range(Int(out_hp_len[])):
        hp_list.append(out_hp[i])

    var key_hex = hex_encode(key_list)
    var iv_hex = hex_encode(iv_list)
    var hp_hex = hex_encode(hp_list)

    dcid_ptr.free()
    out_key.free()
    out_iv.free()
    out_hp.free()
    out_key_len.free()
    out_iv_len.free()
    out_hp_len.free()

    var result = List[String]()
    result.append(key_hex)
    result.append(iv_hex)
    result.append(hp_hex)
    return result^


def test_key_derivation_cross(v: PythonObject, lib: RustlsLibrary) raises -> None:
    """Cross-validate key derivation: our path vs aioquic, both vs JSON expected."""

    # ── Path A: our cryptography-based implementation ──────────────────────
    var hmac_mod = Python.import_module("hmac")
    var hashlib = Python.import_module("hashlib")
    var struct_mod = Python.import_module("struct")
    var hkdf_mod = Python.import_module(
        "cryptography.hazmat.primitives.kdf.hkdf"
    )
    var hashes_mod = Python.import_module(
        "cryptography.hazmat.primitives.hashes"
    )
    var HKDFExpand = hkdf_mod.HKDFExpand
    var SHA256 = hashes_mod.SHA256

    var binascii = Python.import_module("binascii")
    var salt_our = binascii.unhexlify(
        "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
    )
    var dcid = binascii.unhexlify(v["input"]["dcid"])

    # HKDF-Extract = HMAC-SHA256(key=salt, msg=dcid)
    var our_initial_secret = hmac_mod.new(
        salt_our, dcid, hashlib.sha256
    ).digest()

    var our_client_secret = hkdf_expand_label_our(
        our_initial_secret, "client in", 32, HKDFExpand, SHA256, struct_mod
    )
    var our_client_key = hkdf_expand_label_our(
        our_client_secret, "quic key", 16, HKDFExpand, SHA256, struct_mod
    )
    var our_client_iv = hkdf_expand_label_our(
        our_client_secret, "quic iv", 12, HKDFExpand, SHA256, struct_mod
    )
    var our_client_hp = hkdf_expand_label_our(
        our_client_secret, "quic hp", 16, HKDFExpand, SHA256, struct_mod
    )

    var our_server_secret = hkdf_expand_label_our(
        our_initial_secret, "server in", 32, HKDFExpand, SHA256, struct_mod
    )
    var our_server_key = hkdf_expand_label_our(
        our_server_secret, "quic key", 16, HKDFExpand, SHA256, struct_mod
    )
    var our_server_iv = hkdf_expand_label_our(
        our_server_secret, "quic iv", 12, HKDFExpand, SHA256, struct_mod
    )
    var our_server_hp = hkdf_expand_label_our(
        our_server_secret, "quic hp", 16, HKDFExpand, SHA256, struct_mod
    )

    # ── Path B: aioquic's native crypto functions ───────────────────────────
    var aioquic_crypto = Python.import_module("aioquic.quic.crypto")
    var hkdf_extract = aioquic_crypto.hkdf_extract
    var hkdf_expand_label_aio = aioquic_crypto.hkdf_expand_label
    var derive_key_iv_hp = aioquic_crypto.derive_key_iv_hp
    var INITIAL_CIPHER_SUITE = aioquic_crypto.INITIAL_CIPHER_SUITE
    var INITIAL_SALT_VERSION_1 = aioquic_crypto.INITIAL_SALT_VERSION_1

    var algorithm = SHA256()
    var aio_initial_secret = hkdf_extract(algorithm, INITIAL_SALT_VERSION_1, dcid)

    var builtins = Python.import_module("builtins")
    var py_empty = builtins.bytes()
    var aio_client_secret = hkdf_expand_label_aio(
        SHA256(),
        aio_initial_secret,
        builtins.str("client in").encode("ascii"),
        py_empty,
        32,
    )
    var aio_client_tuple = derive_key_iv_hp(
        cipher_suite=INITIAL_CIPHER_SUITE, secret=aio_client_secret, version=1
    )
    var aio_client_key = aio_client_tuple[0]
    var aio_client_iv = aio_client_tuple[1]
    var aio_client_hp = aio_client_tuple[2]

    var aio_server_secret = hkdf_expand_label_aio(
        SHA256(),
        aio_initial_secret,
        builtins.str("server in").encode("ascii"),
        py_empty,
        32,
    )
    var aio_server_tuple = derive_key_iv_hp(
        cipher_suite=INITIAL_CIPHER_SUITE, secret=aio_server_secret, version=1
    )
    var aio_server_key = aio_server_tuple[0]
    var aio_server_iv = aio_server_tuple[1]
    var aio_server_hp = aio_server_tuple[2]

    # ── Assert Path A vs Path B (cross-validation) ─────────────────────────
    assert_true(
        py_bytes_to_hex(our_initial_secret)
            == py_bytes_to_hex(aio_initial_secret),
        "initial_secret: our vs aioquic mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_client_secret)
            == py_bytes_to_hex(aio_client_secret),
        "client_initial_secret: our vs aioquic mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_client_key) == py_bytes_to_hex(aio_client_key),
        "client_key: our vs aioquic mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_client_iv) == py_bytes_to_hex(aio_client_iv),
        "client_iv: our vs aioquic mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_client_hp) == py_bytes_to_hex(aio_client_hp),
        "client_hp: our vs aioquic mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_server_secret)
            == py_bytes_to_hex(aio_server_secret),
        "server_initial_secret: our vs aioquic mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_server_key) == py_bytes_to_hex(aio_server_key),
        "server_key: our vs aioquic mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_server_iv) == py_bytes_to_hex(aio_server_iv),
        "server_iv: our vs aioquic mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_server_hp) == py_bytes_to_hex(aio_server_hp),
        "server_hp: our vs aioquic mismatch",
    )

    # ── Path C: rustls via librustls_mojo.so ───────────────────────────
    var dcid_hex = String(v["input"]["dcid"])
    var rustls_client = rustls_derive_keys(lib, dcid_hex, Int32(1))
    var rustls_client_key = rustls_client[0]
    var rustls_client_iv = rustls_client[1]
    var rustls_client_hp = rustls_client[2]
    var rustls_server = rustls_derive_keys(lib, dcid_hex, Int32(0))
    var rustls_server_key = rustls_server[0]
    var rustls_server_iv = rustls_server[1]
    var rustls_server_hp = rustls_server[2]

    # ── Assert Path C vs Path A (rustls vs our Python crypto) ──────────
    assert_true(
        rustls_client_key == py_bytes_to_hex(our_client_key),
        "client_key: rustls vs our mismatch",
    )
    assert_true(
        rustls_client_iv == py_bytes_to_hex(our_client_iv),
        "client_iv: rustls vs our mismatch",
    )
    assert_true(
        rustls_client_hp == py_bytes_to_hex(our_client_hp),
        "client_hp: rustls vs our mismatch",
    )
    assert_true(
        rustls_server_key == py_bytes_to_hex(our_server_key),
        "server_key: rustls vs our mismatch",
    )
    assert_true(
        rustls_server_iv == py_bytes_to_hex(our_server_iv),
        "server_iv: rustls vs our mismatch",
    )
    assert_true(
        rustls_server_hp == py_bytes_to_hex(our_server_hp),
        "server_hp: rustls vs our mismatch",
    )

    # ── Assert Path C vs Path B (rustls vs aioquic) ────────────────────
    assert_true(
        rustls_client_key == py_bytes_to_hex(aio_client_key),
        "client_key: rustls vs aioquic mismatch",
    )
    assert_true(
        rustls_client_iv == py_bytes_to_hex(aio_client_iv),
        "client_iv: rustls vs aioquic mismatch",
    )
    assert_true(
        rustls_client_hp == py_bytes_to_hex(aio_client_hp),
        "client_hp: rustls vs aioquic mismatch",
    )
    assert_true(
        rustls_server_key == py_bytes_to_hex(aio_server_key),
        "server_key: rustls vs aioquic mismatch",
    )
    assert_true(
        rustls_server_iv == py_bytes_to_hex(aio_server_iv),
        "server_iv: rustls vs aioquic mismatch",
    )
    assert_true(
        rustls_server_hp == py_bytes_to_hex(aio_server_hp),
        "server_hp: rustls vs aioquic mismatch",
    )

    # ── Assert both paths match the JSON vector expected values ─────────────
    var exp = v["expected"]
    assert_true(
        py_bytes_to_hex(our_initial_secret) == String(exp["initial_secret"]),
        "initial_secret: our vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(aio_initial_secret) == String(exp["initial_secret"]),
        "initial_secret: aioquic vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_client_secret)
            == String(exp["client_initial_secret"]),
        "client_initial_secret: our vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(aio_client_secret)
            == String(exp["client_initial_secret"]),
        "client_initial_secret: aioquic vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_client_key) == String(exp["client_key"]),
        "client_key: our vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(aio_client_key) == String(exp["client_key"]),
        "client_key: aioquic vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_client_iv) == String(exp["client_iv"]),
        "client_iv: our vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(aio_client_iv) == String(exp["client_iv"]),
        "client_iv: aioquic vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_client_hp) == String(exp["client_hp"]),
        "client_hp: our vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(aio_client_hp) == String(exp["client_hp"]),
        "client_hp: aioquic vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_server_secret)
            == String(exp["server_initial_secret"]),
        "server_initial_secret: our vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(aio_server_secret)
            == String(exp["server_initial_secret"]),
        "server_initial_secret: aioquic vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_server_key) == String(exp["server_key"]),
        "server_key: our vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(aio_server_key) == String(exp["server_key"]),
        "server_key: aioquic vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_server_iv) == String(exp["server_iv"]),
        "server_iv: our vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(aio_server_iv) == String(exp["server_iv"]),
        "server_iv: aioquic vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(our_server_hp) == String(exp["server_hp"]),
        "server_hp: our vs expected mismatch",
    )
    assert_true(
        py_bytes_to_hex(aio_server_hp) == String(exp["server_hp"]),
        "server_hp: aioquic vs expected mismatch",
    )

    # Path C (rustls) vs expected
    assert_true(
        rustls_client_key == String(exp["client_key"]),
        "client_key: rustls vs expected mismatch",
    )
    assert_true(
        rustls_client_iv == String(exp["client_iv"]),
        "client_iv: rustls vs expected mismatch",
    )
    assert_true(
        rustls_client_hp == String(exp["client_hp"]),
        "client_hp: rustls vs expected mismatch",
    )
    assert_true(
        rustls_server_key == String(exp["server_key"]),
        "server_key: rustls vs expected mismatch",
    )
    assert_true(
        rustls_server_iv == String(exp["server_iv"]),
        "server_iv: rustls vs expected mismatch",
    )
    assert_true(
        rustls_server_hp == String(exp["server_hp"]),
        "server_hp: rustls vs expected mismatch",
    )


def main() raises:
    # Verify assertions are working (guard against silent no-op)
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    var lib = RustlsLibrary()

    var vectors = load_vectors("vectors/rfc9001/initial_protection.json")
    assert_true(len(vectors) >= 2, "expected at least 2 initial_protection vectors, got " + String(Int(py=len(vectors))))
    var count = 0

    for i in range(len(vectors)):
        var v = vectors[i]
        var operation = String(v["operation"])

        if operation == "key_derivation":
            test_key_derivation_cross(v, lib)
            count += 1

    _ = lib^
    print("test_cross_initial_crypto: all keys cross-validated (cryptography + aioquic + rustls)")
