# tests/quic/test_quic_retry.mojo
#
# Tests for QUIC Retry tokens (type byte, µs lifetime, NONE/VALID/INVALID
# classification, address hash) and the Retry integrity tag
# (navette/quic/retry.mojo).

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.quic.retry import (
    RETRY_REJECT_ADDRESS,
    RETRY_REJECT_AUTH,
    RETRY_REJECT_EXPIRED,
    RETRY_REJECT_FUTURE,
    RETRY_REJECT_OK,
    RETRY_REJECT_OVERSIZED,
    RETRY_REJECT_UNDERSIZED,
    RETRY_TOKEN_LIFETIME_US,
    RETRY_TOKEN_MAX_LEN,
    RETRY_TOKEN_MIN_LEN,
    RETRY_TOKEN_TYPE,
    RetryTokenScratch,
    TOKEN_INVALID,
    TOKEN_NONE,
    TOKEN_VALID,
    classify_retry_token,
    compute_retry_integrity_tag,
    generate_retry_token,
    retry_addr_hash,
    validate_retry_token,
    _open_retry_token,
)
from oracle.test_util import hex_decode, hex_encode
from tests._test_util import assert_true, assert_equal_int, assert_equal_str
from tests.protect._prop import Rng, sockaddr_in, sockaddr_in6, mapped_v6


# --- Helpers ---


def _make_secret() -> List[Byte]:
    """16-byte server secret for tests."""
    var s = List[Byte](capacity=16)
    for _ in range(16):
        s.append(UInt8(0xAA))
    return s^


def _hash_of(sa: List[Byte]) -> List[Byte]:
    var h = retry_addr_hash(Span(sa))
    var out = List[Byte](capacity=32)
    for i in range(32):
        out.append(h[i])
    return out^


def _addr_a() -> List[Byte]:
    return _hash_of(sockaddr_in(192, 0, 2, 1, 4433))


def _addr_b() -> List[Byte]:
    return _hash_of(sockaddr_in(192, 0, 2, 1, 4434))


def _addr_c() -> List[Byte]:
    """Same port as `_addr_a`, different IP."""
    return _hash_of(sockaddr_in(198, 51, 100, 1, 4433))


def _classify(
    lib: SharedLibrary, mut scratch: RetryTokenScratch, token: List[Byte], addr: List[Byte], now_us: UInt64
) raises -> Int:
    var out = List[Byte]()
    return classify_retry_token(
        out, lib, scratch, Span(_make_secret()), Span(token), Span(addr), now_us, RETRY_TOKEN_LIFETIME_US
    )


def _token(lib: SharedLibrary, mut scratch: RetryTokenScratch, dcid: List[Byte], addr: List[Byte], now_us: UInt64) raises -> List[Byte]:
    var t = List[Byte]()
    generate_retry_token(t, lib, scratch, Span(_make_secret()), Span(dcid), Span(addr), now_us)
    return t^


# === Test 1: Token round-trip ===


def test_token_round_trip(lib: SharedLibrary) raises:
    """Generate a token and validate immediately; verify returned dcid matches."""
    var scratch = RetryTokenScratch()
    var dcid = hex_decode("0102030405060708")
    var token = _token(lib, scratch, dcid, _addr_a(), UInt64(1000))
    var recovered_dcid = List[Byte]()
    validate_retry_token(
        recovered_dcid, lib, scratch, Span(_make_secret()), Span(token), Span(_addr_a()),
        UInt64(1000), RETRY_TOKEN_LIFETIME_US,
    )
    assert_equal_str(hex_encode(recovered_dcid), hex_encode(dcid), "dcid content mismatch")
    print("  test_token_round_trip: PASS")


# === Test 2: Token expired ===


def test_token_expired(lib: SharedLibrary) raises:
    """Validate 10 µs after issue with a 5 µs max age: raises 'expired'."""
    var scratch = RetryTokenScratch()
    var token = _token(lib, scratch, hex_decode("aabbccdd"), _addr_a(), UInt64(0))
    var caught = False
    try:
        var _discard = List[Byte]()
        validate_retry_token(
            _discard, lib, scratch, Span(_make_secret()), Span(token), Span(_addr_a()),
            UInt64(10), UInt64(5),
        )
    except e:
        caught = True
        assert_true("expired" in String(e), "expected 'expired' in error, got: " + String(e))
    assert_true(caught, "expected token expired error")
    print("  test_token_expired: PASS")


# === Test 3: Token wrong address ===


def test_token_wrong_address(lib: SharedLibrary) raises:
    """Issued to port 4433, presented from port 4434: raises 'address'."""
    var scratch = RetryTokenScratch()
    var token = _token(lib, scratch, hex_decode("deadbeef"), _addr_a(), UInt64(1000))
    var caught = False
    try:
        var _discard = List[Byte]()
        validate_retry_token(
            _discard, lib, scratch, Span(_make_secret()), Span(token), Span(_addr_b()),
            UInt64(1000), RETRY_TOKEN_LIFETIME_US,
        )
    except e:
        caught = True
        assert_true("address" in String(e), "expected 'address' in error, got: " + String(e))
    assert_true(caught, "expected address mismatch error")
    print("  test_token_wrong_address: PASS")


# === Test 4: Token tampered ===


def test_token_tampered(lib: SharedLibrary) raises:
    """Flip a ciphertext byte: raises an AEAD authentication failure."""
    var scratch = RetryTokenScratch()
    var token = _token(lib, scratch, hex_decode("0102030405"), _addr_a(), UInt64(1000))
    token[15] = token[15] ^ UInt8(0xFF)
    var caught = False
    try:
        var _discard = List[Byte]()
        validate_retry_token(
            _discard, lib, scratch, Span(_make_secret()), Span(token), Span(_addr_a()),
            UInt64(1000), RETRY_TOKEN_LIFETIME_US,
        )
    except e:
        caught = True
        assert_true("authentication" in String(e), "expected auth failure, got: " + String(e))
    assert_true(caught, "expected AEAD authentication failure")
    print("  test_token_tampered: PASS")


# === Token format, classification, lifetime units, address hash ===


def test_token_format(lib: SharedLibrary) raises:
    """Type byte 0x01 first; 90 bytes with a 20-byte DCID (1 + 12 + 61 + 16)."""
    var scratch = RetryTokenScratch()
    var dcid = List[Byte](length=20, fill=Byte(0x42))
    var token = _token(lib, scratch, dcid, _addr_a(), UInt64(7))
    assert_true(token[0] == RETRY_TOKEN_TYPE, "type byte first")
    assert_equal_int(len(token), 90, "90-byte token")
    print("  test_token_format: PASS")


def test_classify_none(lib: SharedLibrary) raises:
    """Foreign type byte or shorter than any genuine token: NONE (answer with a Retry)."""
    var scratch = RetryTokenScratch()
    var token = _token(lib, scratch, hex_decode("0102030405060708"), _addr_a(), UInt64(1000))
    var foreign = token.copy()
    foreign[0] = 0x02
    assert_equal_int(_classify(lib, scratch, foreign, _addr_a(), UInt64(1000)), TOKEN_NONE, "foreign type")
    var short = List[Byte](length=28, fill=Byte(0x01))
    assert_equal_int(_classify(lib, scratch, short, _addr_a(), UInt64(1000)), TOKEN_NONE, "28 bytes")
    var empty = List[Byte]()
    assert_equal_int(_classify(lib, scratch, empty, _addr_a(), UInt64(1000)), TOKEN_NONE, "empty")
    print("  test_classify_none: PASS")


def test_classify_invalid_and_valid(lib: SharedLibrary) raises:
    """A corrupted token is NONE (it no longer opens); wrong port, wrong IP, expired and future tokens are INVALID; the genuine one is VALID."""
    var scratch = RetryTokenScratch()
    var dcid = hex_decode("0102030405060708090a")
    var issued = UInt64(50_000_000)
    var token = _token(lib, scratch, dcid, _addr_a(), issued)
    var corrupted = token.copy()
    corrupted[40] = corrupted[40] ^ 0x01
    assert_equal_int(_classify(lib, scratch, corrupted, _addr_a(), issued), TOKEN_NONE, "corrupted")
    assert_equal_int(_classify(lib, scratch, token, _addr_b(), issued), TOKEN_INVALID, "wrong port")
    assert_equal_int(_classify(lib, scratch, token, _addr_c(), issued), TOKEN_INVALID, "same port, wrong IP")
    assert_equal_int(_classify(lib, scratch, token, _addr_a(), issued + RETRY_TOKEN_LIFETIME_US + 1), TOKEN_INVALID, "expired")
    assert_equal_int(_classify(lib, scratch, token, _addr_a(), issued - 1), TOKEN_INVALID, "timestamp in the future")
    var out = List[Byte]()
    var c = classify_retry_token(
        out, lib, scratch, Span(_make_secret()), Span(token), Span(_addr_a()), issued + 1, RETRY_TOKEN_LIFETIME_US
    )
    assert_equal_int(c, TOKEN_VALID, "genuine token")
    assert_equal_str(hex_encode(out), hex_encode(dcid), "original DCID recovered")
    print("  test_classify_invalid_and_valid: PASS")


def test_lifetime_is_ten_seconds_in_microseconds(lib: SharedLibrary) raises:
    """Valid 9.9 s and exactly 10 s after issue, invalid 10 s + 1 µs after: the lifetime is 10 s of the µs protocol clock, inclusive."""
    var scratch = RetryTokenScratch()
    var issued = UInt64(1_000_000)
    var token = _token(lib, scratch, hex_decode("0102030405060708"), _addr_a(), issued)
    assert_equal_int(_classify(lib, scratch, token, _addr_a(), issued + 9_900_000), TOKEN_VALID, "9.9 s")
    assert_equal_int(
        _classify(lib, scratch, token, _addr_a(), issued + RETRY_TOKEN_LIFETIME_US), TOKEN_VALID, "exactly 10 s"
    )
    assert_equal_int(_classify(lib, scratch, token, _addr_a(), issued + 10_000_001), TOKEN_INVALID, "10 s + 1 µs")
    print("  test_lifetime_is_ten_seconds_in_microseconds: PASS")


def test_classify_oversized_is_none(lib: SharedLibrary) raises:
    """A 1,200-byte type-0x01 token is NONE: longer than any we mint, so it is treated as absent (RFC 9000 Section 8.1.3)."""
    var scratch = RetryTokenScratch()
    var big = List[Byte](length=1200, fill=Byte(0x5A))
    big[0] = RETRY_TOKEN_TYPE
    var out = List[Byte]()
    var c = classify_retry_token(
        out, lib, scratch, Span(_make_secret()), Span(big), Span(_addr_a()), UInt64(1000), RETRY_TOKEN_LIFETIME_US
    )
    assert_equal_int(c, TOKEN_NONE, "1,200-byte token")
    assert_equal_int(len(out), 0, "no DCID appended for a NONE token")
    print("  test_classify_oversized_is_none: PASS")


def test_classify_max_length_boundary(lib: SharedLibrary) raises:
    """The longest genuine token (20-byte DCID) is 90 bytes and VALID; 91 bytes are NONE; validate says 'too long'."""
    var scratch = RetryTokenScratch()
    var genuine = _token(lib, scratch, List[Byte](length=20, fill=Byte(0x42)), _addr_a(), UInt64(1000))
    assert_equal_int(len(genuine), RETRY_TOKEN_MAX_LEN, "longest genuine token is the maximum")
    assert_equal_int(RETRY_TOKEN_MAX_LEN, 90, "1 + 12 + (1 + 20 + 32 + 8) + 16")
    assert_equal_int(_classify(lib, scratch, genuine, _addr_a(), UInt64(1000)), TOKEN_VALID, "genuine 90 bytes")
    var forged_90 = List[Byte](length=90, fill=Byte(0x33))
    forged_90[0] = RETRY_TOKEN_TYPE
    assert_equal_int(_classify(lib, scratch, forged_90, _addr_a(), UInt64(1000)), TOKEN_NONE, "forged 90 bytes")
    var long_91 = genuine.copy()
    long_91.append(0x00)
    assert_equal_int(_classify(lib, scratch, long_91, _addr_a(), UInt64(1000)), TOKEN_NONE, "91 bytes")
    var raised = False
    try:
        var _discard = List[Byte]()
        validate_retry_token(
            _discard, lib, scratch, Span(_make_secret()), Span(long_91), Span(_addr_a()),
            UInt64(1000), RETRY_TOKEN_LIFETIME_US,
        )
    except e:
        raised = True
        assert_true("too long" in String(e), "91 bytes: expected 'too long', got: " + String(e))
    assert_true(raised, "validate rejects a 91-byte token")
    print("  test_classify_max_length_boundary: PASS")


def test_malformed_peer_address_is_unusable(lib: SharedLibrary) raises:
    """A sockaddr with no parsable IP yields no token and validates none, so malformed names never share a token."""
    var scratch = RetryTokenScratch()
    var unix_family = List[Byte](length=16, fill=Byte(0))
    unix_family[0] = 1  # AF_UNIX
    var truncated_v6 = List[Byte](length=10, fill=Byte(0))
    truncated_v6[0] = 10  # AF_INET6, too short
    var bad_a = _hash_of(unix_family)
    var bad_b = _hash_of(truncated_v6)
    var dcid = hex_decode("0102030405060708")
    var raised = False
    try:
        _ = _token(lib, scratch, dcid, bad_a, UInt64(1000))
    except e:
        raised = True
        assert_true("address" in String(e), "expected an address error, got: " + String(e))
    assert_true(raised, "generate refuses a malformed peer address")
    var token = _token(lib, scratch, dcid, _addr_a(), UInt64(1000))
    assert_equal_int(_classify(lib, scratch, token, bad_b, UInt64(1000)), TOKEN_INVALID, "malformed presenter")
    assert_equal_int(_reason(lib, scratch, token, bad_b, UInt64(1000)), RETRY_REJECT_ADDRESS, "reject reason")
    var vraised = False
    try:
        var _discard = List[Byte]()
        validate_retry_token(
            _discard, lib, scratch, Span(_make_secret()), Span(token), Span(bad_b),
            UInt64(1000), RETRY_TOKEN_LIFETIME_US,
        )
    except e:
        vraised = True
        assert_true("address" in String(e), "expected 'address', got: " + String(e))
    assert_true(vraised, "validate rejects a malformed presenter")
    print("  test_malformed_peer_address_is_unusable: PASS")


def test_classify_min_length_boundary(lib: SharedLibrary) raises:
    """The shortest genuine token (empty DCID) is 70 bytes and VALID; 70 forged bytes and 69 bytes are NONE.

    1 (type) + 12 (nonce) + 1 (dcid_len) + 32 (addr hash) + 8 (timestamp)
    + 16 (AEAD tag): a foreign type-0x01 token shorter than that cannot be
    ours, so it earns a Retry, not an INVALID_TOKEN close.
    """
    var scratch = RetryTokenScratch()
    var genuine = _token(lib, scratch, List[Byte](), _addr_a(), UInt64(1000))
    assert_equal_int(len(genuine), RETRY_TOKEN_MIN_LEN, "shortest genuine token is the minimum")
    assert_equal_int(RETRY_TOKEN_MIN_LEN, 70, "1 + 12 + 1 + 32 + 8 + 16")
    assert_equal_int(_classify(lib, scratch, genuine, _addr_a(), UInt64(1000)), TOKEN_VALID, "genuine 70 bytes")
    var forged_70 = List[Byte](length=70, fill=Byte(0x33))
    forged_70[0] = RETRY_TOKEN_TYPE
    assert_equal_int(_classify(lib, scratch, forged_70, _addr_a(), UInt64(1000)), TOKEN_NONE, "forged 70 bytes")
    var short_69 = List[Byte](length=69, fill=Byte(0x33))
    short_69[0] = RETRY_TOKEN_TYPE
    assert_equal_int(_classify(lib, scratch, short_69, _addr_a(), UInt64(1000)), TOKEN_NONE, "69 bytes")
    var short_29 = List[Byte](length=29, fill=Byte(0x33))
    short_29[0] = RETRY_TOKEN_TYPE
    assert_equal_int(_classify(lib, scratch, short_29, _addr_a(), UInt64(1000)), TOKEN_NONE, "29 bytes")
    var raised = False
    try:
        var _discard = List[Byte]()
        validate_retry_token(
            _discard, lib, scratch, Span(_make_secret()), Span(short_69), Span(_addr_a()),
            UInt64(1000), RETRY_TOKEN_LIFETIME_US,
        )
    except e:
        raised = True
        assert_true("too short" in String(e), "69 bytes: expected 'too short', got: " + String(e))
    assert_true(raised, "validate rejects a 69-byte token")
    print("  test_classify_min_length_boundary: PASS")


def test_classify_changed_secret_is_none(lib: SharedLibrary) raises:
    """A token sealed under the old server secret no longer opens after the secret changes: NONE, so a Retry."""
    var scratch = RetryTokenScratch()
    var token = _token(lib, scratch, hex_decode("0102030405060708"), _addr_a(), UInt64(1000))
    var other = List[Byte](length=16, fill=Byte(0xAB))
    var out = List[Byte]()
    var c = classify_retry_token(
        out, lib, scratch, Span(other), Span(token), Span(_addr_a()), UInt64(1000), RETRY_TOKEN_LIFETIME_US
    )
    assert_equal_int(c, TOKEN_NONE, "rotated secret")
    assert_equal_int(len(out), 0, "no DCID appended for a token that does not open")
    print("  test_classify_changed_secret_is_none: PASS")


def _reason(
    lib: SharedLibrary, mut scratch: RetryTokenScratch, token: List[Byte], addr: List[Byte], now_us: UInt64
) raises -> Int:
    var out = List[Byte]()
    return _open_retry_token(
        out, lib, scratch, Span(_make_secret()), Span(token), Span(addr), now_us, RETRY_TOKEN_LIFETIME_US
    )


def test_reject_reasons_are_codes(lib: SharedLibrary) raises:
    """Each rejection yields its own integer code, so the INVALID path builds no String."""
    var scratch = RetryTokenScratch()
    var issued = UInt64(50_000_000)
    var token = _token(lib, scratch, hex_decode("0102030405060708"), _addr_a(), issued)
    assert_equal_int(_reason(lib, scratch, token, _addr_a(), issued), RETRY_REJECT_OK, "genuine")
    var big = List[Byte](length=1200, fill=Byte(0x01))
    assert_equal_int(_reason(lib, scratch, big, _addr_a(), issued), RETRY_REJECT_OVERSIZED, "oversized")
    # The helper bounds-checks on its own: a token too short to hold the
    # type byte and nonce must be rejected, not indexed past its end.
    for n in [0, 1, 12, 13, 69]:
        var short = List[Byte](length=n, fill=Byte(0x01))
        assert_equal_int(
            _reason(lib, scratch, short, _addr_a(), issued), RETRY_REJECT_UNDERSIZED, "undersized " + String(n)
        )
    var corrupted = token.copy()
    corrupted[20] = corrupted[20] ^ 0x01
    assert_equal_int(_reason(lib, scratch, corrupted, _addr_a(), issued), RETRY_REJECT_AUTH, "corrupted")
    assert_equal_int(_reason(lib, scratch, token, _addr_b(), issued), RETRY_REJECT_ADDRESS, "wrong port")
    assert_equal_int(_reason(lib, scratch, token, _addr_c(), issued), RETRY_REJECT_ADDRESS, "same port, wrong IP")
    assert_equal_int(_reason(lib, scratch, token, _addr_a(), issued - 1), RETRY_REJECT_FUTURE, "future")
    assert_equal_int(
        _reason(lib, scratch, token, _addr_a(), issued + RETRY_TOKEN_LIFETIME_US + 1), RETRY_REJECT_EXPIRED, "expired"
    )
    print("  test_reject_reasons_are_codes: PASS")


def test_addr_hash_reads_ip_and_port_only() raises:
    """The hash ignores flowinfo and scope_id; IPv4-mapped equals native IPv4; the port does (500 cases)."""
    var rng = Rng(0xADD7)
    for ci in range(500):
        var ip = rng.bytes(4)
        var port = rng.below(65536)
        var native = _hash_of(sockaddr_in(ip[0], ip[1], ip[2], ip[3], port))
        var as_mapped = _hash_of(
            sockaddr_in6(mapped_v6(ip[0], ip[1], ip[2], ip[3]), port, UInt32(rng.below(1 << 20)), UInt32(rng.below(16)))
        )
        assert_equal_str(hex_encode(native), hex_encode(as_mapped), "mapped == native, case " + String(ci))
        var v6 = rng.bytes(16)
        v6[0] = v6[0] | 0x20
        var h1 = _hash_of(sockaddr_in6(v6, port, UInt32(rng.below(1 << 20)), UInt32(rng.below(16))))
        var h2 = _hash_of(sockaddr_in6(v6, port, UInt32(rng.below(1 << 20)), UInt32(rng.below(16))))
        assert_equal_str(hex_encode(h1), hex_encode(h2), "flowinfo/scope ignored, case " + String(ci))
        var other_port = _hash_of(sockaddr_in6(v6, (port + 1) % 65536, 0, 0))
        assert_true(hex_encode(h1) != hex_encode(other_port), "port matters, case " + String(ci))
    print("  test_addr_hash_reads_ip_and_port_only: PASS")


def test_addr_hash_known_answers() raises:
    """SHA-256 over the IP bytes then the big-endian port, pinned against Python hashlib.

    `hashlib.sha256(bytes.fromhex("c00002011151"))` for 192.0.2.1:4433 and
    `hashlib.sha256(bytes.fromhex("20010db8" + "00" * 11 + "01" + "01bb"))`
    for [2001:db8::1]:443. A hash that drops the IP, the port, or reorders
    them fails here.
    """
    assert_equal_str(
        hex_encode(_hash_of(sockaddr_in(192, 0, 2, 1, 4433))),
        "e6c2232729386da9b7411139b141f86a1f58af17e17e687c8ad91de026a0b4c4",
        "192.0.2.1:4433",
    )
    var v6 = List[Byte](length=16, fill=Byte(0))
    v6[0] = 0x20
    v6[1] = 0x01
    v6[2] = 0x0D
    v6[3] = 0xB8
    v6[15] = 0x01
    assert_equal_str(
        hex_encode(_hash_of(sockaddr_in6(v6, 443, UInt32(7), UInt32(3)))),
        "fa0056dad39241a132c61ea1a950b317466216ed2f7cf3fbe53e7f54526bb358",
        "[2001:db8::1]:443",
    )
    print("  test_addr_hash_known_answers: PASS")


def test_addr_hash_ip_matters() raises:
    """Same port, one differing IP bit (IPv4 and IPv6): different hash (500 cases)."""
    var rng = Rng(0x1BAD)
    for ci in range(500):
        var port = rng.below(65536)
        var ip = rng.bytes(4)
        var ip2 = ip.copy()
        ip2[rng.below(4)] ^= UInt8(1 << rng.below(8))
        var h4a = _hash_of(sockaddr_in(ip[0], ip[1], ip[2], ip[3], port))
        var h4b = _hash_of(sockaddr_in(ip2[0], ip2[1], ip2[2], ip2[3], port))
        assert_true(hex_encode(h4a) != hex_encode(h4b), "IPv4 IP matters, case " + String(ci))
        var v6 = rng.bytes(16)
        v6[0] = v6[0] | 0x20
        var v6b = v6.copy()
        v6b[1 + rng.below(15)] ^= UInt8(1 << rng.below(8))  # byte 0 keeps 0x20: never IPv4-mapped
        var h6a = _hash_of(sockaddr_in6(v6, port, 0, 0))
        var h6b = _hash_of(sockaddr_in6(v6b, port, 0, 0))
        assert_true(hex_encode(h6a) != hex_encode(h6b), "IPv6 IP matters, case " + String(ci))
    print("  test_addr_hash_ip_matters: PASS")


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

    var computed_tag = List[Byte]()
    compute_retry_integrity_tag(
        computed_tag,
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

    var tag1 = List[Byte]()
    compute_retry_integrity_tag(
        tag1,
        lib,
        Span(orig_dcid),
        Span(retry_packet),
    )
    var tag2 = List[Byte]()
    compute_retry_integrity_tag(
        tag2,
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
    test_token_format(shared)
    test_classify_none(shared)
    test_classify_invalid_and_valid(shared)
    test_lifetime_is_ten_seconds_in_microseconds(shared)
    test_classify_oversized_is_none(shared)
    test_classify_max_length_boundary(shared)
    test_malformed_peer_address_is_unusable(shared)
    test_classify_min_length_boundary(shared)
    test_classify_changed_secret_is_none(shared)
    test_reject_reasons_are_codes(shared)
    test_addr_hash_reads_ip_and_port_only()
    test_addr_hash_known_answers()
    test_addr_hash_ip_matters()
    test_integrity_tag_known_vector(shared)
    test_integrity_tag_deterministic(shared)

    print("All test_quic_retry tests passed.")

    _ = tls^
