# tests/test_quic_retry.mojo
#
# Tests for QUIC Retry token generation/validation and integrity tag
# computation (src/quic/retry.mojo).
#
# Run with:
#   cd ~/Projets/perso/navette && uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_quic_retry.mojo

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.quic.retry import (
    generate_retry_token,
    validate_retry_token,
    compute_retry_integrity_tag,
)
from lib.test_util import hex_decode, hex_encode
from tests._test_util import assert_true, assert_equal_int, assert_equal_str


# --- Helpers ---


def _make_secret() -> List[UInt8]:
    """16-byte server secret for tests."""
    var s = List[UInt8](capacity=16)
    for _ in range(16):
        s.append(UInt8(0xAA))
    return s^


def _make_addr_hash_zeros() -> List[UInt8]:
    """32-byte client address hash (all zeros)."""
    var h = List[UInt8](capacity=32)
    for _ in range(32):
        h.append(UInt8(0x00))
    return h^


def _make_addr_hash_ones() -> List[UInt8]:
    """32-byte client address hash (all ones)."""
    var h = List[UInt8](capacity=32)
    for _ in range(32):
        h.append(UInt8(0x01))
    return h^


# === Test 1: Token round-trip ===


def test_token_round_trip(lib: SharedLibrary) raises:
    """Generate a token and validate immediately; verify returned dcid matches."""
    var secret = _make_secret()
    var dcid = hex_decode("0102030405060708")
    var addr_hash = _make_addr_hash_zeros()
    var now = UInt64(1000)

    var token = generate_retry_token(
        lib,
        Span(secret),
        Span(dcid),
        Span(addr_hash),
        now,
    )

    # Token should be at least 28 bytes (12 nonce + 16 tag)
    assert_true(len(token) >= 28, "token too short: " + String(len(token)))

    var recovered_dcid = validate_retry_token(
        lib,
        Span(secret),
        Span(token),
        Span(addr_hash),
        now,
    )

    assert_equal_int(len(recovered_dcid), len(dcid), "dcid length mismatch")
    assert_equal_str(
        hex_encode(recovered_dcid),
        hex_encode(dcid),
        "dcid content mismatch",
    )
    print("  test_token_round_trip: PASS")


# === Test 2: Token expired ===


def test_token_expired(lib: SharedLibrary) raises:
    """Generate with now=0, validate with now=10 (>5s default max_age); should raise."""
    var secret = _make_secret()
    var dcid = hex_decode("aabbccdd")
    var addr_hash = _make_addr_hash_zeros()

    var token = generate_retry_token(
        lib,
        Span(secret),
        Span(dcid),
        Span(addr_hash),
        UInt64(0),
    )

    var caught = False
    try:
        _ = validate_retry_token(
            lib,
            Span(secret),
            Span(token),
            Span(addr_hash),
            UInt64(10),  # 10 > 5 default max_age
        )
    except e:
        caught = True
        assert_true(
            "expired" in String(e),
            "expected 'expired' in error, got: " + String(e),
        )

    assert_true(caught, "expected token expired error")
    print("  test_token_expired: PASS")


# === Test 3: Token wrong address ===


def test_token_wrong_address(lib: SharedLibrary) raises:
    """Generate with addr_hash A, validate with addr_hash B; should raise."""
    var secret = _make_secret()
    var dcid = hex_decode("deadbeef")
    var addr_a = _make_addr_hash_zeros()
    var addr_b = _make_addr_hash_ones()

    var token = generate_retry_token(
        lib,
        Span(secret),
        Span(dcid),
        Span(addr_a),
        UInt64(1000),
    )

    var caught = False
    try:
        _ = validate_retry_token(
            lib,
            Span(secret),
            Span(token),
            Span(addr_b),
            UInt64(1000),
        )
    except e:
        caught = True
        assert_true(
            "address" in String(e),
            "expected 'address' in error, got: " + String(e),
        )

    assert_true(caught, "expected address mismatch error")
    print("  test_token_wrong_address: PASS")


# === Test 4: Token tampered ===


def test_token_tampered(lib: SharedLibrary) raises:
    """Generate valid token, flip a byte, validate; should raise AEAD auth failure."""
    var secret = _make_secret()
    var dcid = hex_decode("0102030405")
    var addr_hash = _make_addr_hash_zeros()

    var token = generate_retry_token(
        lib,
        Span(secret),
        Span(dcid),
        Span(addr_hash),
        UInt64(1000),
    )

    # Flip byte at index 15 (inside ciphertext area)
    token[15] = token[15] ^ UInt8(0xFF)

    var caught = False
    try:
        _ = validate_retry_token(
            lib,
            Span(secret),
            Span(token),
            Span(addr_hash),
            UInt64(1000),
        )
    except e:
        caught = True
        assert_true(
            "authentication" in String(e) or "failed" in String(e),
            "expected auth failure, got: " + String(e),
        )

    assert_true(caught, "expected AEAD authentication failure")
    print("  test_token_tampered: PASS")


# === Test 5: Integrity tag known vector (RFC 9001 A.4) ===


def test_integrity_tag_known_vector(lib: SharedLibrary) raises:
    """Test compute_retry_integrity_tag against RFC 9001 Appendix A.4.

    RFC 9001 A.4 Retry Packet (QUIC v1):
      Original DCID: 8394c8f03e515708
      Retry packet without tag: ff000000010008f067a5502a4262b5746f6b656e
        - first byte: ff
        - version: 00000001
        - DCID len: 00 (empty)
        - SCID len: 08
        - SCID: f067a5502a4262b5
        - Retry token: 746f6b656e ("token")
      Pseudo-Retry (AAD): 088394c8f03e515708 + retry_without_tag
      Key: be0c690b9f66575a1d766b54e368c84e
      Nonce: 461599d35d632bf2239825bb
      Expected tag: 04a265ba2eff4d829058fb3f0f2496ba
    """
    var orig_dcid = hex_decode("8394c8f03e515708")
    var packet_without_tag = hex_decode(
        "ff000000010008f067a5502a4262b5746f6b656e"
    )
    var expected_tag_hex = "04a265ba2eff4d829058fb3f0f2496ba"

    var computed_tag = compute_retry_integrity_tag(
        lib,
        Span(orig_dcid),
        Span(packet_without_tag),
    )

    assert_equal_int(len(computed_tag), 16, "integrity tag length")
    assert_equal_str(
        hex_encode(computed_tag),
        expected_tag_hex,
        "integrity tag vs RFC 9001 A.4",
    )
    print("  test_integrity_tag_known_vector: PASS")


# === Test 6: Integrity tag deterministic ===


def test_integrity_tag_deterministic(lib: SharedLibrary) raises:
    """Compute the same tag twice with same input; verify identical."""
    var orig_dcid = hex_decode("0102030405060708")
    var retry_packet = hex_decode(
        "ff0000000108aabbccdd0102030405060708cafebabe"
    )

    var tag1 = compute_retry_integrity_tag(
        lib,
        Span(orig_dcid),
        Span(retry_packet),
    )
    var tag2 = compute_retry_integrity_tag(
        lib,
        Span(orig_dcid),
        Span(retry_packet),
    )

    assert_equal_int(len(tag1), 16, "tag1 length")
    assert_equal_int(len(tag2), 16, "tag2 length")
    assert_equal_str(
        hex_encode(tag1),
        hex_encode(tag2),
        "integrity tag determinism",
    )
    print("  test_integrity_tag_deterministic: PASS")


# === Main ===


def main() raises:
    # Verify assertions are working
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(
        _sentinel_ok,
        "assertions are not firing -- test infrastructure is broken",
    )

    var tls = TlsBackend("lib/librustls_mojo.so")
    var shared = tls.shared()

    print("test_quic_retry:")

    test_token_round_trip(shared)
    test_token_expired(shared)
    test_token_wrong_address(shared)
    test_token_tampered(shared)
    test_integrity_tag_known_vector(shared)
    test_integrity_tag_deterministic(shared)

    print("All test_quic_retry tests passed.")

    _ = tls^
