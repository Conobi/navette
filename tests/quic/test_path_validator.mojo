# tests/quic/test_path_validator.mojo
#
# Unit tests for navette.quic.path_validator — RFC 9000 §8 path validation.
#
# Run with:
#   uv run mojox run -I . -D ASSERT=all tests/quic/test_path_validator.mojo

from std.memory import Span

from tests._test_util import assert_true, assert_false, assert_equal_int
from navette.quic.path_validator import (
    PathChallenge,
    PathKey,
    PathValidator,
    ValidatedPath,
    PATH_TOKEN_LEN,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_addr_a() -> PathKey:
    """A canonical IPv4 test address — 127.0.0.1:5000."""
    return PathKey.from_v4(UInt8(127), UInt8(0), UInt8(0), UInt8(1), UInt16(5000))


def _make_addr_b() -> PathKey:
    """A second IPv4 test address — 127.0.0.1:5001 (differs from A by port)."""
    return PathKey.from_v4(UInt8(127), UInt8(0), UInt8(0), UInt8(1), UInt16(5001))


# ── Test cases ────────────────────────────────────────────────────────────────


def test_start_challenge_produces_eight_byte_token() raises:
    """Verify start_challenge returns an 8-byte token and queues one challenge."""
    var pv = PathValidator()
    var token = pv.start_challenge(_make_addr_a(), UInt64(1000))
    assert_equal_int(len(token), PATH_TOKEN_LEN, "token length is 8 bytes")
    assert_equal_int(len(pv.pending), 1, "exactly one challenge queued")


def test_start_challenge_tokens_are_random() raises:
    """Two successive challenges produce distinct tokens (probabilistic but ~2^-64)."""
    var pv = PathValidator()
    var t1 = pv.start_challenge(_make_addr_a(), UInt64(1000))
    var t2 = pv.start_challenge(_make_addr_b(), UInt64(2000))
    var differ = False
    for i in range(PATH_TOKEN_LEN):
        if t1[i] != t2[i]:
            differ = True
            break
    assert_true(differ, "two random tokens differ in at least one byte")


def test_on_response_with_matching_token_validates_path() raises:
    """A PATH_RESPONSE matching token + addr validates the path and clears pending."""
    var pv = PathValidator()
    var addr = _make_addr_a()
    var token = pv.start_challenge(PathKey(other=addr), UInt64(1000))
    var result = pv.on_response(Span(token), PathKey(other=addr), UInt64(2000))
    assert_true(Bool(result), "response with matching token returns a validated path")
    assert_equal_int(len(pv.pending), 0, "pending challenge consumed on validation")
    assert_true(Bool(pv.current), "current validated path is now set")


def test_on_response_with_wrong_token_returns_none() raises:
    """A PATH_RESPONSE with non-matching data does NOT validate and keeps the challenge pending."""
    var pv = PathValidator()
    var addr = _make_addr_a()
    _ = pv.start_challenge(PathKey(other=addr), UInt64(1000))
    var bogus = List[UInt8](capacity=PATH_TOKEN_LEN)
    for _ in range(PATH_TOKEN_LEN):
        bogus.append(UInt8(0xFF))
    var result = pv.on_response(Span(bogus), PathKey(other=addr), UInt64(2000))
    assert_false(Bool(result), "response with wrong token returns None")
    assert_equal_int(len(pv.pending), 1, "challenge stays pending on mismatch")


def test_on_response_with_wrong_addr_returns_none() raises:
    """A PATH_RESPONSE from a different addr than the challenge target is dropped."""
    var pv = PathValidator()
    var token = pv.start_challenge(_make_addr_a(), UInt64(1000))
    var result = pv.on_response(Span(token), _make_addr_b(), UInt64(2000))
    assert_false(Bool(result), "response from wrong addr returns None")


def test_anti_amp_per_path_budget() raises:
    """The can_send_bytes gate enforces 3× bytes_received minus bytes_sent."""
    var pv = PathValidator()
    var addr = _make_addr_a()
    _ = pv.start_challenge(PathKey(other=addr), UInt64(1000))
    # 100 bytes received → 300-byte budget.
    pv.record_received_bytes(PathKey(other=addr), 100)
    assert_true(
        pv.can_send_bytes(PathKey(other=addr), 250),
        "250 ≤ 300 byte budget",
    )
    pv.record_sent_bytes(PathKey(other=addr), 250)
    # 300 − 250 = 50 bytes remaining.
    assert_true(
        pv.can_send_bytes(PathKey(other=addr), 50),
        "50 ≤ 50 byte remaining budget",
    )
    assert_false(
        pv.can_send_bytes(PathKey(other=addr), 51),
        "51 > 50 byte remaining budget",
    )


def test_anti_amp_isolated_per_path() raises:
    """Each pending challenge tracks its own bytes_received / bytes_sent."""
    var pv = PathValidator()
    _ = pv.start_challenge(_make_addr_a(), UInt64(1000))
    _ = pv.start_challenge(_make_addr_b(), UInt64(1000))
    pv.record_received_bytes(_make_addr_a(), 100)
    # Path B has zero received bytes → zero budget.
    assert_false(
        pv.can_send_bytes(_make_addr_b(), 1),
        "path B has no budget yet",
    )
    # Path A has 300-byte budget.
    assert_true(
        pv.can_send_bytes(_make_addr_a(), 300),
        "path A has full 300-byte budget",
    )


def test_gc_expired_drops_old_challenges() raises:
    """The gc_expired call drops challenges whose age exceeds 3 × PTO."""
    var pv = PathValidator()
    _ = pv.start_challenge(_make_addr_a(), UInt64(1000))
    # 3 × PTO = 30000 ns; challenge age at now=51000 is 50000 > 30000 → drop.
    pv.gc_expired(UInt64(51000), UInt64(10000))
    assert_equal_int(len(pv.pending), 0, "expired challenge dropped")


def test_gc_keeps_fresh_challenges() raises:
    """The gc_expired call keeps challenges whose age is below 3 × PTO."""
    var pv = PathValidator()
    _ = pv.start_challenge(_make_addr_a(), UInt64(1000))
    # age = 5000 ns < 30000 ns threshold → keep.
    pv.gc_expired(UInt64(6000), UInt64(10000))
    assert_equal_int(len(pv.pending), 1, "fresh challenge retained")


def test_pathkey_equality() raises:
    """PathKey.__eq__ compares family + addr bytes + port byte-exactly."""
    var a = _make_addr_a()
    var b = _make_addr_a()
    assert_true(a == b, "two PathKeys with identical (family, addr, port) are equal")
    var c = _make_addr_b()
    assert_false(a == c, "PathKeys with different ports are unequal")


def main() raises:
    print("test_path_validator:")
    test_start_challenge_produces_eight_byte_token()
    print("  test_start_challenge_produces_eight_byte_token: PASS")
    test_start_challenge_tokens_are_random()
    print("  test_start_challenge_tokens_are_random: PASS")
    test_on_response_with_matching_token_validates_path()
    print("  test_on_response_with_matching_token_validates_path: PASS")
    test_on_response_with_wrong_token_returns_none()
    print("  test_on_response_with_wrong_token_returns_none: PASS")
    test_on_response_with_wrong_addr_returns_none()
    print("  test_on_response_with_wrong_addr_returns_none: PASS")
    test_anti_amp_per_path_budget()
    print("  test_anti_amp_per_path_budget: PASS")
    test_anti_amp_isolated_per_path()
    print("  test_anti_amp_isolated_per_path: PASS")
    test_gc_expired_drops_old_challenges()
    print("  test_gc_expired_drops_old_challenges: PASS")
    test_gc_keeps_fresh_challenges()
    print("  test_gc_keeps_fresh_challenges: PASS")
    test_pathkey_equality()
    print("  test_pathkey_equality: PASS")
    print("path_validator tests passed")
