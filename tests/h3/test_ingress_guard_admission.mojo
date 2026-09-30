"""IngressGuard.admit_initial: token classes, the admission order and the stateless-reply bounds."""

from std.collections import Span

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.h3.ingress_guard import (
    IngressGuard,
    ADMIT_CREATE,
    ADMIT_CREATE_VALIDATED,
    ADMIT_RETRY,
    ADMIT_CLOSE,
    ADMIT_DROP,
)
from navette.quic.packet import PacketType, parse_packet_header
from navette.quic.retry import generate_retry_token, retry_addr_hash
from tests._test_util import assert_true, assert_equal_int
from tests.h3._wire import filled, initial, initial_n
from tests.protect._prop import Rng, prop_iters, sockaddr_in


def _addr_a() -> List[Byte]:
    return sockaddr_in(192, 0, 2, 1, 4433)


def _addr_other_port() -> List[Byte]:
    return sockaddr_in(192, 0, 2, 1, 4434)


def _mint(mut g: IngressGuard, orig: List[Byte], addr: List[Byte], now: UInt64) raises -> List[Byte]:
    """A token sealed with the guard's own secret, as its Retry would carry."""
    var h = retry_addr_hash(Span(addr))
    var tok = List[Byte]()
    generate_retry_token(tok, g._lib, g._scratch, Span(g._secret), Span(orig), Span(h), now)
    return tok^


def _initial_with_token(mut g: IngressGuard, mut rng: Rng, kind: Int, now: UInt64) raises -> List[Byte]:
    """kind 0 none, 1 foreign type, 2 valid, 3 corrupted, 4 minted for another port."""
    var dcid = rng.bytes(8 + rng.below(13))
    var token = List[Byte]()
    if kind == 1:
        token = rng.bytes(1 + rng.below(100))
        token[0] = 0x02
    elif kind == 2:
        token = _mint(g, rng.bytes(8 + rng.below(13)), _addr_a(), now - 1_000_000)
    elif kind == 3:
        token = _mint(g, rng.bytes(8), _addr_a(), now - 1_000_000)
        token[13 + rng.below(len(token) - 13)] ^= 0x01
    elif kind == 4:
        token = _mint(g, rng.bytes(8), _addr_other_port(), now - 1_000_000)
    return initial(1200, dcid, token)


def test_admission_oracle_property(lib: SharedLibrary) raises:
    """Property: admit_initial matches the admission order over random (token, counts, cap, require_validation)."""
    var g = IngressGuard(lib)
    var rng = Rng(UInt64(0xAD17))
    for i in range(prop_iters(300)):
        var kind = rng.below(5)
        var unval = rng.below(300)
        var cap = 64 + rng.below(64)
        var admitted = rng.below(cap + 1)
        g.require_validation = rng.chance(10)
        var now = UInt64(10_000_000 + i * 50_000)  # 20 closes/s: the bucket never empties here
        var pkt = _initial_with_token(g, rng, kind, now)
        g.begin_pass()
        var got = g.admit_initial(
            Span(pkt), Span(_addr_a()), now, unval, admitted, cap, free_ids=cap - admitted, backlog=0
        )
        var want: Int
        if kind == 4:
            want = ADMIT_CLOSE
        elif kind == 2:
            want = ADMIT_CREATE_VALIDATED if admitted < cap else ADMIT_CLOSE
        elif unval >= 256 or g.require_validation or admitted >= cap:
            want = ADMIT_RETRY
        else:
            want = ADMIT_CREATE
        assert_equal_int(got, want, "seed 0xAD17 case " + String(i) + " kind " + String(kind))
    print("  test_admission_oracle_property: PASS")


def test_retry_output_and_valid_round_trip(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    var now = UInt64(5_000_000)
    var dcid = filled(0xD1, 20)
    var pkt = initial(1200, dcid)
    g.require_validation = True
    assert_equal_int(g.admit_initial(Span(pkt), Span(_addr_a()), now, 0, 0, 64, free_ids=64, backlog=0), ADMIT_RETRY, "retry")
    assert_equal_int(Int(g.stats.retry_sent), 1, "retry_sent")
    var retry = parse_packet_header(Span(g.out), 8)[0].copy()
    assert_true(retry.packet_type == PacketType.retry(), "Retry in g.out")
    var echoed = initial(1200, List[Byte](retry.scid.as_span()), List[Byte](retry.token_span()))
    assert_equal_int(
        g.admit_initial(Span(echoed), Span(_addr_a()), now + 2_000_000, 0, 0, 64, free_ids=64, backlog=0),
        ADMIT_CREATE_VALIDATED,
        "token from our Retry is VALID",
    )
    assert_true(g.orig_dcid == dcid, "original DCID recovered for the transport parameters")
    assert_true(g.retry_scid == List[Byte](retry.scid.as_span()), "retry_scid = the Retry's SCID")
    print("  test_retry_output_and_valid_round_trip: PASS")


def test_create_reports_the_packet_dcid(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    var dcid = filled(0xD2, 12)
    assert_equal_int(g.admit_initial(Span(initial(1200, dcid)), Span(_addr_a()), 1, 0, 0, 64, free_ids=64, backlog=0), ADMIT_CREATE, "create")
    assert_true(g.orig_dcid == dcid, "orig_dcid = the Initial's DCID")
    assert_equal_int(len(g.retry_scid), 0, "no Retry, no retry_scid")
    assert_equal_int(Int(g.stats.tokens_none), 1, "tokens_none")
    print("  test_create_reports_the_packet_dcid: PASS")


def test_oversized_foreign_token_forces_retry(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    var pkt = initial(1200, filled(0xD1, 8), filled(0x01, 233))
    assert_equal_int(g.admit_initial(Span(pkt), Span(_addr_a()), 1_000_000, 0, 0, 64, free_ids=64, backlog=0), ADMIT_RETRY, "233 B token")
    assert_equal_int(Int(g.stats.tokens_none), 1, "classified NONE")
    print("  test_oversized_foreign_token_forces_retry: PASS")


def test_token_past_the_packet_drops(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    var pkt = initial(1200, filled(0xD1, 8), filled(0x01, 100))
    pkt[1 + 4 + 1 + 8 + 1 + 8] = 0x7F  # 2-byte varint prefix 0x40..: token length 0x3FF0-ish
    pkt[1 + 4 + 1 + 8 + 1 + 8 + 1] = 0xF0
    assert_equal_int(g.admit_initial(Span(pkt), Span(_addr_a()), 1_000_000, 0, 0, 64, free_ids=64, backlog=0), ADMIT_DROP, "token runs past the end")
    assert_equal_int(Int(g.stats.dropped_undecodable), 1, "counted undecodable")
    print("  test_token_past_the_packet_drops: PASS")


def test_close_bucket_and_refuse(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    var now = UInt64(20_000_000)
    var tok = _mint(g, filled(0xD1, 8), _addr_other_port(), now - 1_000_000)
    var pkt = initial(1200, filled(0xD3, 8), tok)
    var closes = 0
    for _ in range(17):
        var r = g.admit_initial(Span(pkt), Span(_addr_a()), now, 0, 0, 64, free_ids=64, backlog=0)
        if r == ADMIT_CLOSE:
            closes += 1
        else:
            assert_equal_int(r, ADMIT_DROP, "17th: dropped")
    assert_equal_int(closes, 16, "burst 16")
    assert_equal_int(Int(g.stats.invalid_token_closes), 16, "invalid_token_closes")
    assert_equal_int(Int(g.stats.stateless_bucket_empty_close), 1, "bucket empty")
    assert_equal_int(Int(g.stats.tokens_invalid), 17, "tokens_invalid")
    var h = parse_packet_header(Span(g.out), 8)[0].copy()
    assert_true(h.packet_type == PacketType.initial(), "close is an Initial")
    # A VALID token with no free connection id: CONNECTION_REFUSED, from the same bucket.
    var later = now + 1_000_000
    var good = initial(1200, filled(0xD4, 8), _mint(g, filled(0xD1, 8), _addr_a(), later))
    assert_equal_int(g.admit_initial(Span(good), Span(_addr_a()), later, 0, 64, 64, free_ids=0, backlog=0), ADMIT_CLOSE, "refused")
    assert_equal_int(Int(g.stats.refused_closes), 1, "refused_closes")
    assert_equal_int(Int(g.stats.cap_rejections), 1, "cap_rejections")
    print("  test_close_bucket_and_refuse: PASS")


def test_response_cap_per_pass(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    g.require_validation = True
    var pkt = initial_n(8, 1200)
    g.begin_pass()
    var retries = 0
    for _ in range(257):
        var r = g.admit_initial(Span(pkt), Span(_addr_a()), 1_000_000, 0, 0, 64, free_ids=64, backlog=0)
        if r == ADMIT_RETRY:
            retries += 1
        else:
            assert_equal_int(r, ADMIT_DROP, "257th: dropped")
    assert_equal_int(retries, 256, "256 per pass")
    assert_equal_int(Int(g.stats.stateless_dropped_egress), 1, "egress drop counted")
    g.begin_pass()
    assert_equal_int(g.admit_initial(Span(pkt), Span(_addr_a()), 1_000_000, 0, 0, 64, free_ids=64, backlog=1280), ADMIT_DROP, "backlog full")
    assert_equal_int(g.admit_initial(Span(pkt), Span(_addr_a()), 1_000_000, 0, 0, 64, free_ids=64, backlog=1279), ADMIT_RETRY, "below the bound")
    print("  test_response_cap_per_pass: PASS")


def test_malformed_sockaddr_drops(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    g.require_validation = True
    var bad = filled(0x02, 3)
    assert_equal_int(g.admit_initial(Span(initial_n(8, 1200)), Span(bad), 1_000_000, 0, 0, 64, free_ids=64, backlog=0), ADMIT_DROP, "3-byte name")
    assert_equal_int(len(g.out), 0, "nothing in g.out")
    assert_equal_int(Int(g.stats.retry_sent), 0, "no Retry")
    print("  test_malformed_sockaddr_drops: PASS")


def test_tokens_valid_admits(lib: SharedLibrary) raises:
    """Pins existing behaviour: a VALID token below the cap creates a validated connection."""
    var g = IngressGuard(lib)
    var now = UInt64(3_000_000)
    var pkt = initial(1200, filled(0xD5, 8), _mint(g, filled(0xD1, 10), _addr_a(), now))
    assert_equal_int(g.admit_initial(Span(pkt), Span(_addr_a()), now, 300, 10, 64, free_ids=54, backlog=0), ADMIT_CREATE_VALIDATED, "valid")
    assert_equal_int(Int(g.stats.tokens_valid), 1, "tokens_valid")
    print("  test_tokens_valid_admits: PASS")


def main() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var lib = tls.shared()
    print("test_ingress_guard_admission:")
    test_admission_oracle_property(lib)
    test_retry_output_and_valid_round_trip(lib)
    test_create_reports_the_packet_dcid(lib)
    test_oversized_foreign_token_forces_retry(lib)
    test_token_past_the_packet_drops(lib)
    test_close_bucket_and_refuse(lib)
    test_response_cap_per_pass(lib)
    test_malformed_sockaddr_drops(lib)
    test_tokens_valid_admits(lib)
    print("PASS: test_ingress_guard_admission")
    _ = tls^
