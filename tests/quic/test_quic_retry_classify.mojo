"""Retry token classification per RFC 9000 erratum 7861.

INVALID_TOKEN only for a token that opens under our secret and then
fails the address or time check; a token that does not open is
indistinguishable from a foreign one and classifies as NONE (Retry).
"""

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.quic.retry import (
    RETRY_TOKEN_LIFETIME_US,
    RetryTokenScratch,
    TOKEN_INVALID,
    TOKEN_NONE,
    TOKEN_VALID,
    classify_retry_token,
    generate_retry_token,
    retry_addr_hash,
)
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng, prop_iters, sockaddr_in


def _secret() -> List[Byte]:
    return List[Byte](length=16, fill=Byte(0xAA))


def _other_secret() -> List[Byte]:
    return List[Byte](length=16, fill=Byte(0xAB))


def _hash_of(sa: List[Byte]) -> List[Byte]:
    var h = retry_addr_hash(Span(sa))
    var out = List[Byte](capacity=32)
    for i in range(32):
        out.append(h[i])
    return out^


def _addr_a() -> List[Byte]:
    return _hash_of(sockaddr_in(192, 0, 2, 1, 4433))


def _addr_b() -> List[Byte]:
    """Same IP as `_addr_a`, other port."""
    return _hash_of(sockaddr_in(192, 0, 2, 1, 4434))


def _mint(lib: SharedLibrary, mut scratch: RetryTokenScratch, addr: List[Byte], now_us: UInt64) raises -> List[Byte]:
    var dcid = List[Byte](length=8, fill=Byte(0x42))
    var t = List[Byte]()
    generate_retry_token(t, lib, scratch, Span(_secret()), Span(dcid), Span(addr), now_us)
    return t^


def _classify_with_secret(
    lib: SharedLibrary,
    mut scratch: RetryTokenScratch,
    token: List[Byte],
    secret: List[Byte],
    addr: List[Byte],
    now_us: UInt64,
) raises -> Int:
    var out = List[Byte]()
    var c = classify_retry_token(
        out, lib, scratch, Span(secret), Span(token), Span(addr), now_us, RETRY_TOKEN_LIFETIME_US
    )
    if c != TOKEN_VALID:
        assert_equal_int(len(out), 0, "DCID appended only for a valid token")
    return c


def _classify(
    lib: SharedLibrary, mut scratch: RetryTokenScratch, token: List[Byte], addr: List[Byte], now_us: UInt64
) raises -> Int:
    return _classify_with_secret(lib, scratch, token, _secret(), addr, now_us)


def test_undecryptable_is_none(lib: SharedLibrary) raises:
    var scratch = RetryTokenScratch()
    var token = _mint(lib, scratch, _addr_a(), UInt64(1_000_000))
    var corrupted = token.copy()
    corrupted[40] ^= 0x01
    assert_equal_int(
        _classify(lib, scratch, corrupted, _addr_a(), UInt64(1_000_000)), TOKEN_NONE, "AEAD failure -> NONE (Retry)"
    )
    var rotated = _classify_with_secret(lib, scratch, token, _other_secret(), _addr_a(), UInt64(1_000_000))
    assert_equal_int(rotated, TOKEN_NONE, "rotated secret -> NONE")
    print("  test_undecryptable_is_none: PASS")


def test_authenticated_failures_stay_invalid(lib: SharedLibrary) raises:
    var scratch = RetryTokenScratch()
    var issued = UInt64(1_000_000)
    var token = _mint(lib, scratch, _addr_a(), issued)
    assert_equal_int(_classify(lib, scratch, token, _addr_b(), issued), TOKEN_INVALID, "wrong port")
    assert_equal_int(
        _classify(lib, scratch, token, _addr_a(), issued + RETRY_TOKEN_LIFETIME_US + 1), TOKEN_INVALID, "expired"
    )
    assert_equal_int(_classify(lib, scratch, token, _addr_a(), issued - 1), TOKEN_INVALID, "future")
    assert_equal_int(_classify(lib, scratch, token, _addr_a(), issued), TOKEN_VALID, "valid")
    print("  test_authenticated_failures_stay_invalid: PASS")


def test_bitflip_property(lib: SharedLibrary) raises:
    """Any single-bit flip in token[1:] is NONE (it no longer opens), never INVALID."""
    var scratch = RetryTokenScratch()
    var token = _mint(lib, scratch, _addr_a(), UInt64(1_000_000))
    var rng = Rng(UInt64(0x7861))
    for i in range(prop_iters(200)):
        var t = token.copy()
        var bit = 8 + rng.below((len(t) - 1) * 8)
        t[bit // 8] ^= UInt8(1 << (bit % 8))
        assert_equal_int(
            _classify(lib, scratch, t, _addr_a(), UInt64(1_000_000)),
            TOKEN_NONE,
            "seed 0x7861 case " + String(i) + " bit " + String(bit),
        )
    print("  test_bitflip_property: PASS")


def main() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var shared = tls.shared()
    print("test_quic_retry_classify:")
    test_undecryptable_is_none(shared)
    test_authenticated_failures_stay_invalid(shared)
    test_bitflip_property(shared)
    print("PASS: test_quic_retry_classify")
    _ = tls^
