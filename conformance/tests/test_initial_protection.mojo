# conformance/tests/test_initial_protection.mojo
#
# RFC 9001 Appendix A.1–A.2 known-answer tests for QUIC initial packet
# protection. Crypto is performed via Python's `cryptography` library.
from lib.test_util import load_vectors, hex_encode, assert_bytes_equal
from python import Python, PythonObject


fn bytes_from_hex(py_hex: PythonObject) raises -> List[UInt8]:
    """Convert a Python hex string to a Mojo List[UInt8]."""
    var binascii = Python.import_module("binascii")
    var raw = binascii.unhexlify(py_hex)
    var result = List[UInt8]()
    var builtins = Python.import_module("builtins")
    for i in range(Int(py=builtins.len(raw))):
        result.append(UInt8(Int(py=raw[i])))
    return result^


fn py_bytes_to_hex(raw: PythonObject) raises -> String:
    """Convert a Python bytes object to a lowercase hex string."""
    var binascii = Python.import_module("binascii")
    return String(binascii.hexlify(raw).decode("ascii"))


fn hkdf_expand_label(
    secret: PythonObject,
    label_str: String,
    length: Int,
    hkdf_expand: PythonObject,
    sha256: PythonObject,
    struct_mod: PythonObject,
) raises -> PythonObject:
    """HKDF-Expand-Label as defined in TLS 1.3 / RFC 9001."""
    # Build the label in Python to avoid Mojo str->bytes conversion issues
    var builtins = Python.import_module("builtins")
    var py_label = builtins.str("tls13 " + label_str).encode("ascii")
    var label_len = Int(py=builtins.len(py_label))
    # Build HkdfLabel: uint16(length) || uint8(len(label)) || label || uint8(0)
    var hkdf_label = (
        struct_mod.pack(">H", length)
        + struct_mod.pack("B", label_len)
        + py_label
        + struct_mod.pack("B", 0)
    )
    var kdf = hkdf_expand(algorithm=sha256(), length=length, info=hkdf_label)
    return kdf.derive(secret)


def test_key_derivation(v: PythonObject) raises -> None:
    """Test HKDF key derivation against RFC 9001 Appendix A.1."""
    var hmac_mod = Python.import_module("hmac")
    var hashlib = Python.import_module("hashlib")
    var struct_mod = Python.import_module("struct")
    var hkdf_mod = Python.import_module(
        "cryptography.hazmat.primitives.kdf.hkdf"
    )
    var hashes_mod = Python.import_module("cryptography.hazmat.primitives.hashes")
    var HKDFExpand = hkdf_mod.HKDFExpand
    var SHA256 = hashes_mod.SHA256

    # QUIC v1 salt (RFC 9001 Section 5.2)
    var binascii = Python.import_module("binascii")
    var salt = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    var dcid = binascii.unhexlify(v["input"]["dcid"])

    # HKDF-Extract = HMAC-SHA256(key=salt, msg=ikm)
    var initial_secret = hmac_mod.new(salt, dcid, hashlib.sha256).digest()

    var exp = v["expected"]
    debug_assert(
        py_bytes_to_hex(initial_secret) == String(exp["initial_secret"]),
        "initial_secret mismatch",
    )

    # Client derivation
    var client_secret = hkdf_expand_label(
        initial_secret, "client in", 32, HKDFExpand, SHA256, struct_mod
    )
    debug_assert(
        py_bytes_to_hex(client_secret)
            == String(exp["client_initial_secret"]),
        "client_initial_secret mismatch",
    )

    var client_key = hkdf_expand_label(
        client_secret, "quic key", 16, HKDFExpand, SHA256, struct_mod
    )
    debug_assert(
        py_bytes_to_hex(client_key) == String(exp["client_key"]),
        "client_key mismatch",
    )

    var client_iv = hkdf_expand_label(
        client_secret, "quic iv", 12, HKDFExpand, SHA256, struct_mod
    )
    debug_assert(
        py_bytes_to_hex(client_iv) == String(exp["client_iv"]),
        "client_iv mismatch",
    )

    var client_hp = hkdf_expand_label(
        client_secret, "quic hp", 16, HKDFExpand, SHA256, struct_mod
    )
    debug_assert(
        py_bytes_to_hex(client_hp) == String(exp["client_hp"]),
        "client_hp mismatch",
    )

    # Server derivation
    var server_secret = hkdf_expand_label(
        initial_secret, "server in", 32, HKDFExpand, SHA256, struct_mod
    )
    debug_assert(
        py_bytes_to_hex(server_secret)
            == String(exp["server_initial_secret"]),
        "server_initial_secret mismatch",
    )

    var server_key = hkdf_expand_label(
        server_secret, "quic key", 16, HKDFExpand, SHA256, struct_mod
    )
    debug_assert(
        py_bytes_to_hex(server_key) == String(exp["server_key"]),
        "server_key mismatch",
    )

    var server_iv = hkdf_expand_label(
        server_secret, "quic iv", 12, HKDFExpand, SHA256, struct_mod
    )
    debug_assert(
        py_bytes_to_hex(server_iv) == String(exp["server_iv"]),
        "server_iv mismatch",
    )

    var server_hp = hkdf_expand_label(
        server_secret, "quic hp", 16, HKDFExpand, SHA256, struct_mod
    )
    debug_assert(
        py_bytes_to_hex(server_hp) == String(exp["server_hp"]),
        "server_hp mismatch",
    )


def test_header_protection(v: PythonObject) raises -> None:
    """Test AES-128-ECB header protection mask against RFC 9001 Appendix A.2."""
    var ciphers_mod = Python.import_module(
        "cryptography.hazmat.primitives.ciphers"
    )
    var algorithms_mod = Python.import_module(
        "cryptography.hazmat.primitives.ciphers.algorithms"
    )
    var modes_mod = Python.import_module(
        "cryptography.hazmat.primitives.ciphers.modes"
    )
    var binascii = Python.import_module("binascii")

    var hp_key = binascii.unhexlify(v["input"]["hp_key"])
    var sample = binascii.unhexlify(v["input"]["sample"])

    var cipher = ciphers_mod.Cipher(
        algorithms_mod.AES(hp_key), modes_mod.ECB()
    )
    var encryptor = cipher.encryptor()
    var mask_full = encryptor.update(sample) + encryptor.finalize()
    # Take first 5 bytes as the header-protection mask
    var mask = mask_full[0:5]

    var exp = v["expected"]
    debug_assert(
        py_bytes_to_hex(mask) == String(exp["mask"]),
        "header_protection mask mismatch",
    )


def main() raises:
    var vectors = load_vectors("vectors/rfc9001/initial_protection.json")
    var count = 0

    for i in range(len(vectors)):
        var v = vectors[i]
        var operation = String(v["operation"])

        if operation == "key_derivation":
            test_key_derivation(v)
            count += 1
        elif operation == "header_protection":
            test_header_protection(v)
            count += 1

    print("test_initial_protection: all " + String(count) + " vectors passed")
