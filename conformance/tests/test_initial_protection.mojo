# conformance/tests/test_initial_protection.mojo
#
# RFC 9001 Appendix A.1–A.2 known-answer tests for QUIC initial packet
# protection.
#
# As of §3.2 of plans/2026-05-13-deps-enhancement.md, this test no longer
# imports `cryptography.hazmat` at runtime. The expected outputs are
# pre-materialized in conformance/vectors/rfc9001/ by the oracle scripts:
#
#   - conformance/scripts/oracle_hkdf.py    → hkdf.json
#   - conformance/scripts/oracle_aead.py    → aead.json
#   - conformance/scripts/oracle_hp.py      → header_protection.json
#   - conformance/scripts/oracle_initial.py → initial_keys.json
#
# This test asserts the fixture files are well-formed and consistent
# with the legacy initial_protection.json (RFC 9001 A.1/A.2 known
# answers). The actual cross-validation against rustls' AEAD/HKDF/HP
# implementations lives in test_rustls_initial.mojo and
# test_cross_initial_crypto.mojo.
from lib.test_util import load_vectors, assert_true
from python import Python, PythonObject


def _expect_string_field(v: PythonObject, key: String) raises -> String:
    """Read v[key] as a Mojo String, raising if missing or empty."""
    var got = String(v[key])
    if len(got) == 0:
        raise "vector field '" + key + "' is empty"
    return got^


def _vector_field(v: PythonObject, group: String, key: String) raises -> String:
    var raw = String(v[group][key])
    if len(raw) == 0:
        raise "vector field '" + group + "." + key + "' is empty"
    return raw^


def test_hkdf_vectors() raises -> None:
    """Validate the HKDF-Expand-Label vector file structure."""
    var vectors = load_vectors("vectors/rfc9001/hkdf.json")
    var n = Int(py=len(vectors))
    assert_true(n >= 8, "expected at least 8 hkdf vectors, got " + String(n))

    # Spot-check: RFC 9001 A.1 client "quic key" must be the canonical value.
    var saw_client_key = False
    for i in range(n):
        var v = vectors[i]
        var name = _expect_string_field(v, "name")
        var label = _expect_string_field(v, "label")
        var okm = _expect_string_field(v, "okm")
        if name == "rfc9001_a1_client_quic_key":
            assert_true(
                okm == "1f369613dd76d5467730efcbe3b1a22d",
                "client quic_key mismatch: got " + okm,
            )
            assert_true(label == "quic key", "label mismatch")
            saw_client_key = True
    assert_true(saw_client_key, "hkdf vectors missing rfc9001_a1_client_quic_key")


def test_aead_vectors() raises -> None:
    """Validate the AEAD-AES-128-GCM vector file structure."""
    var vectors = load_vectors("vectors/rfc9001/aead.json")
    var n = Int(py=len(vectors))
    assert_true(n >= 4, "expected at least 4 aead vectors, got " + String(n))

    var saw_client_encrypt = False
    for i in range(n):
        var v = vectors[i]
        var name = _expect_string_field(v, "name")
        var op = _expect_string_field(v, "operation")
        var ct = _expect_string_field(v, "ciphertext")
        var tag = _expect_string_field(v, "tag")
        var ct_and_tag = _expect_string_field(v, "ct_and_tag")
        # Self-consistency: ct + tag == ct_and_tag
        assert_true(
            ct + tag == ct_and_tag,
            "ct_and_tag != ct||tag in vector " + name,
        )
        assert_true(
            op == "aead_encrypt" or op == "aead_decrypt",
            "unexpected operation in vector " + name,
        )
        if name == "client_initial_v1_aead_encrypt":
            # Cross-check against the canonical initial_protection.json
            assert_true(
                ct_and_tag == (
                    "31d720f7fb19c243eec520fba0e705ae437e739b86247268"
                    "c513013d43d8ab62686e1e725acf9f21c5"
                ),
                "client_initial_v1 ciphertext drift",
            )
            saw_client_encrypt = True
    assert_true(saw_client_encrypt, "aead vectors missing client_initial_v1_aead_encrypt")


def test_hp_vectors() raises -> None:
    """Validate the AES-128-ECB header-protection vector file structure."""
    var vectors = load_vectors("vectors/rfc9001/header_protection.json")
    var n = Int(py=len(vectors))
    assert_true(n >= 2, "expected at least 2 hp vectors, got " + String(n))

    var saw_a2 = False
    for i in range(n):
        var v = vectors[i]
        var name = _expect_string_field(v, "name")
        var hp_key = _expect_string_field(v, "hp_key")
        var sample = _expect_string_field(v, "sample")
        var mask = _expect_string_field(v, "mask")
        # The HP mask is the first 5 bytes of AES-ECB(hp_key, sample).
        assert_true(len(hp_key) == 32, "hp_key must be 16 bytes (32 hex chars)")
        assert_true(len(sample) == 32, "sample must be 16 bytes (32 hex chars)")
        assert_true(len(mask) == 10,   "mask must be 5 bytes (10 hex chars)")
        if name == "client_initial_v1_header_protection":
            # Cross-check against RFC 9001 A.2 canonical value.
            assert_true(mask == "437b9aec36", "A.2 client mask drift")
            saw_a2 = True
    assert_true(saw_a2, "hp vectors missing rfc9001_a2 client mask")


def test_initial_keys_vectors() raises -> None:
    """Validate the QUIC v1 Initial-keys derivation vector file structure."""
    var vectors = load_vectors("vectors/rfc9001/initial_keys.json")
    var n = Int(py=len(vectors))
    assert_true(n >= 2, "expected client+server initial-keys vectors, got " + String(n))

    var saw_client = False
    var saw_server = False
    for i in range(n):
        var v = vectors[i]
        var role = _expect_string_field(v, "role")
        var key = _expect_string_field(v, "key")
        var iv = _expect_string_field(v, "iv")
        var hp = _expect_string_field(v, "hp")
        assert_true(len(key) == 32, "key must be 16 bytes (32 hex chars)")
        assert_true(len(iv) == 24,  "iv must be 12 bytes (24 hex chars)")
        assert_true(len(hp) == 32,  "hp must be 16 bytes (32 hex chars)")
        if role == "client":
            # RFC 9001 A.1 canonical values.
            assert_true(key == "1f369613dd76d5467730efcbe3b1a22d", "client_key drift")
            assert_true(iv  == "fa044b2f42a3fd3b46fb255c",         "client_iv drift")
            assert_true(hp  == "9f50449e04a0e810283a1e9933adedd2", "client_hp drift")
            saw_client = True
        elif role == "server":
            assert_true(key == "cf3a5331653c364c88f0f379b6067e37", "server_key drift")
            assert_true(iv  == "0ac1493ca1905853b0bba03e",         "server_iv drift")
            assert_true(hp  == "c206b8d9b9f0f37644430b490eeaa314", "server_hp drift")
            saw_server = True
    assert_true(saw_client, "initial_keys vectors missing client role")
    assert_true(saw_server, "initial_keys vectors missing server role")


def main() raises:
    # Verify assertions are working (guard against silent no-op)
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    test_hkdf_vectors()
    test_aead_vectors()
    test_hp_vectors()
    test_initial_keys_vectors()

    print("test_initial_protection: all 4 vector fixtures validated (cryptography-free)")
