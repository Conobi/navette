# tests/fuzz/test_fuzz_retry_aead.mojo
#
# Multi-property fuzz: QUIC Retry token AEAD.
# Production: navette.quic.retry.{generate_retry_token, validate_retry_token}
# (AEAD has no in-tree Mojo oracle; roundtrip + tamper + cross-input
# properties cover the security-critical surface.)
#
# Properties (per spec §Retry-AEAD property set):
#   P1 — Inverse identity: validate(generate(...)) returns the orig_dcid.
#   P2 — Tag/ciphertext tamper: flipping any bit in token[13:] → validate raises.
#   P2b — Type/nonce tamper: flipping any bit in token[:13] → validate raises.
#   P3 — Cross-secret rejection: distinct server_secret → validate raises.
#   P4 — Address-hash mismatch: distinct client_addr_hash → validate raises.
#   P5 — Expiry: now_v > now_g + max_age → validate raises.
#   P6 — Nonce uniqueness probe: two generate() calls with identical inputs
#        produce tokens whose nonces (bytes 1..12) differ.
#   C1 — classify: the genuine token is VALID and yields orig_dcid.
#   C2 — classify: any single-bit flip in token[1:] is NONE: the token no
#        longer opens, so it is indistinguishable from a foreign one
#        (RFC 9000 erratum 7861) and earns a Retry, not INVALID_TOKEN.
#   C3 — classify: a type byte other than 0x01 is NONE.
#   C4 — classify: a truncated or extended token is NONE, whether it
#        falls outside the 70..90 byte bounds or no longer opens.
#   C5 — classify: wrong address or expiry is INVALID (the token opens);
#        a rotated secret is NONE (it does not).
#   C6 — the all-zero address hash (malformed peer sockaddr): generate
#        raises, and the genuine token classifies INVALID against it.
#   Non-VALID results never append to the output buffer.
#
# Default: 100 iterations (~1 minute under ASSERT=all). Deep runs:
#   FUZZ_ITERS=10000 FUZZ_SEED=<n> scripts/test.sh tests/fuzz/test_fuzz_retry_aead.mojo
# FUZZ_SOAK=1 keeps going past 20 disagreements.

from std.os import getenv

from tests.fuzz.lib.prng import SplitMix64
from tests.fuzz.lib.report import FuzzReport, ObserveResult

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.quic.retry import (
    RetryTokenScratch,
    TOKEN_INVALID,
    TOKEN_NONE,
    TOKEN_VALID,
    classify_retry_token,
    generate_retry_token,
    validate_retry_token,
)


def _random_bytes(mut rng: SplitMix64, n: Int) -> List[Byte]:
    var out = List[Byte](capacity=n)
    for _ in range(n):
        out.append(rng.next_u8())
    return out^


def _check_all_properties(mut rng: SplitMix64, lib: SharedLibrary, mut scratch: RetryTokenScratch) raises -> ObserveResult:
    """Each invocation exercises P1-P5 on freshly-generated inputs."""
    var secret = _random_bytes(rng, 16)
    var dcid_len = Int(rng.next_below(UInt64(21)))  # 0-20
    var orig_dcid = _random_bytes(rng, dcid_len)
    var addr_hash = _random_bytes(rng, 32)
    var now_g = rng.next_u64() % UInt64(1000000)

    # P1: inverse identity
    var token = List[Byte]()
    try:
        generate_retry_token(token, lib, scratch, Span(secret), Span(orig_dcid), Span(addr_hash), now_g)
    except e:
        return ObserveResult(False, String("P1: generate_retry_token raised: ") + String(e))
    var recovered = List[Byte]()
    try:
        validate_retry_token(recovered, lib, scratch, Span(secret), Span(token), Span(addr_hash), now_g, UInt64(10000))
    except e:
        return ObserveResult(False, String("P1: validate raised on its own token: ") + String(e))
    if len(recovered) != dcid_len:
        return ObserveResult(False, String("P1: recovered dcid len ") + String(len(recovered)) + String(" != ") + String(dcid_len))
    for i in range(dcid_len):
        if recovered[i] != orig_dcid[i]:
            return ObserveResult(False, String("P1: recovered dcid byte ") + String(i) + String(" differs"))

    # P2: tag/ciphertext tamper (flip a bit in token[13:])
    if len(token) > 13:
        var tampered = token.copy()
        var byte_idx = 13 + Int(rng.next_below(UInt64(len(token) - 13)))
        var bit = Int(rng.next_below(UInt64(8)))
        tampered[byte_idx] = tampered[byte_idx] ^ UInt8(1 << bit)
        var raised = False
        try:
            var _p2 = List[Byte]()
            validate_retry_token(_p2, lib, scratch, Span(secret), Span(tampered), Span(addr_hash), now_g, UInt64(10000))
        except:
            raised = True
        if not raised:
            return ObserveResult(False, String("P2: tag/ciphertext tamper did not raise"))

    # P2b: type-byte / nonce tamper
    var nonce_tampered = token.copy()
    var nbit = Int(rng.next_below(UInt64(8)))
    var nbyte = Int(rng.next_below(UInt64(13)))
    nonce_tampered[nbyte] = nonce_tampered[nbyte] ^ UInt8(1 << nbit)
    var raised_2b = False
    try:
        var _p2b = List[Byte]()
        validate_retry_token(_p2b, lib, scratch, Span(secret), Span(nonce_tampered), Span(addr_hash), now_g, UInt64(10000))
    except:
        raised_2b = True
    if not raised_2b:
        return ObserveResult(False, String("P2b: nonce tamper did not raise"))

    # P3: cross-secret rejection
    var secret2 = _random_bytes(rng, 16)
    # Guard against accidental collision
    if secret2[0] == secret[0]:
        secret2[0] = secret2[0] ^ UInt8(0xFF)
    var raised_3 = False
    try:
        var _p3 = List[Byte]()
        validate_retry_token(_p3, lib, scratch, Span(secret2), Span(token), Span(addr_hash), now_g, UInt64(10000))
    except:
        raised_3 = True
    if not raised_3:
        return ObserveResult(False, String("P3: cross-secret accepted"))

    # P4: address-hash mismatch
    var hash2 = _random_bytes(rng, 32)
    if hash2[0] == addr_hash[0]:
        hash2[0] = hash2[0] ^ UInt8(0xFF)
    var raised_4 = False
    try:
        var _p4 = List[Byte]()
        validate_retry_token(_p4, lib, scratch, Span(secret), Span(token), Span(hash2), now_g, UInt64(10000))
    except:
        raised_4 = True
    if not raised_4:
        return ObserveResult(False, String("P4: addr-hash mismatch accepted"))

    # P5: expiry
    var now_v = now_g + UInt64(100)
    var raised_5 = False
    try:
        var _p5 = List[Byte]()
        validate_retry_token(_p5, lib, scratch, Span(secret), Span(token), Span(addr_hash), now_v, UInt64(5))
    except:
        raised_5 = True
    if not raised_5:
        return ObserveResult(False, String("P5: expired token accepted"))

    return ObserveResult(True, String(""))


def _classify_expect(
    lib: SharedLibrary,
    mut scratch: RetryTokenScratch,
    secret: List[Byte],
    token: List[Byte],
    addr_hash: List[Byte],
    now: UInt64,
    max_age: UInt64,
    want: Int,
    label: String,
) raises -> String:
    """Empty when classify returns `want` (and appends only when VALID), else a failure message."""
    var out = List[Byte]()
    var got = classify_retry_token(
        out, lib, scratch, Span(secret), Span(token), Span(addr_hash), now, max_age
    )
    if got != want:
        return label + String(": classify ") + String(got) + String(" != ") + String(want)
    if want != TOKEN_VALID and len(out) != 0:
        return label + String(": non-VALID token appended a DCID")
    return String("")


def _check_classify(mut rng: SplitMix64, lib: SharedLibrary, mut scratch: RetryTokenScratch) raises -> ObserveResult:
    """C1-C6 on freshly generated inputs."""
    var secret = _random_bytes(rng, 16)
    var dcid_len = Int(rng.next_below(UInt64(21)))
    var orig_dcid = _random_bytes(rng, dcid_len)
    var addr_hash = _random_bytes(rng, 32)
    var now_g = rng.next_u64() % UInt64(1000000)
    var age = UInt64(10000)
    var token = List[Byte]()
    generate_retry_token(token, lib, scratch, Span(secret), Span(orig_dcid), Span(addr_hash), now_g)

    # C1
    var out = List[Byte]()
    var c1 = classify_retry_token(out, lib, scratch, Span(secret), Span(token), Span(addr_hash), now_g, age)
    if c1 != TOKEN_VALID:
        return ObserveResult(False, String("C1: genuine token classified ") + String(c1))
    if len(out) != dcid_len:
        return ObserveResult(False, String("C1: recovered dcid length differs"))
    for i in range(dcid_len):
        if out[i] != orig_dcid[i]:
            return ObserveResult(False, String("C1: recovered dcid byte ") + String(i) + String(" differs"))

    # C2
    var flipped = token.copy()
    var fb = 1 + Int(rng.next_below(UInt64(len(token) - 1)))
    flipped[fb] = flipped[fb] ^ UInt8(1 << Int(rng.next_below(UInt64(8))))
    var why = _classify_expect(lib, scratch, secret, flipped, addr_hash, now_g, age, TOKEN_NONE, String("C2 bit flip"))
    if why.byte_length() > 0:
        return ObserveResult(False, why)
    # C3
    var retyped = token.copy()
    # 2..256, where 256 wraps to 0: every type byte except 0x01.
    retyped[0] = UInt8(rng.next_below(UInt64(255))) + 2
    why = _classify_expect(lib, scratch, secret, retyped, addr_hash, now_g, age, TOKEN_NONE, String("C3 retyped"))
    if why.byte_length() > 0:
        return ObserveResult(False, why)
    # C4
    var cut = Int(rng.next_below(UInt64(len(token))))
    var truncated = List[Byte](capacity=cut)
    for i in range(cut):
        truncated.append(token[i])
    why = _classify_expect(lib, scratch, secret, truncated, addr_hash, now_g, age, TOKEN_NONE, String("C4 truncated to ") + String(cut))
    if why.byte_length() > 0:
        return ObserveResult(False, why)
    var extended = token.copy()
    var extra = 1 + Int(rng.next_below(UInt64(64)))
    for _ in range(extra):
        extended.append(rng.next_u8())
    why = _classify_expect(
        lib, scratch, secret, extended, addr_hash, now_g, age, TOKEN_NONE, String("C4 extended to ") + String(len(extended))
    )
    if why.byte_length() > 0:
        return ObserveResult(False, why)
    # C5
    var hash2 = addr_hash.copy()
    hash2[Int(rng.next_below(UInt64(32)))] ^= UInt8(1 << Int(rng.next_below(UInt64(8))))
    why = _classify_expect(lib, scratch, secret, token, hash2, now_g, age, TOKEN_INVALID, String("C5 address"))
    if why.byte_length() > 0:
        return ObserveResult(False, why)
    var secret2 = secret.copy()
    secret2[Int(rng.next_below(UInt64(16)))] ^= UInt8(1 << Int(rng.next_below(UInt64(8))))
    why = _classify_expect(lib, scratch, secret2, token, addr_hash, now_g, age, TOKEN_NONE, String("C5 secret"))
    if why.byte_length() > 0:
        return ObserveResult(False, why)
    why = _classify_expect(lib, scratch, secret, token, addr_hash, now_g + age + 1, age, TOKEN_INVALID, String("C5 expired"))
    if why.byte_length() > 0:
        return ObserveResult(False, why)
    # C6
    var zero_hash = List[Byte](length=32, fill=Byte(0))
    var zero_raised = False
    try:
        var _c6 = List[Byte]()
        generate_retry_token(_c6, lib, scratch, Span(secret), Span(orig_dcid), Span(zero_hash), now_g)
    except:
        zero_raised = True
    if not zero_raised:
        return ObserveResult(False, String("C6: generate accepted the all-zero address hash"))
    why = _classify_expect(lib, scratch, secret, token, zero_hash, now_g, age, TOKEN_INVALID, String("C6 zero hash"))
    if why.byte_length() > 0:
        return ObserveResult(False, why)
    return ObserveResult(True, String(""))


def _check_p6(lib: SharedLibrary, mut scratch: RetryTokenScratch) raises -> ObserveResult:
    """Nonce-uniqueness probe: two calls with identical inputs → distinct nonces."""
    var secret = List[Byte]()
    for i in range(16):
        secret.append(UInt8(i))
    var orig_dcid = List[Byte]()
    for i in range(8):
        orig_dcid.append(UInt8(0xA0 + i))
    var addr_hash = List[Byte]()
    for i in range(32):
        addr_hash.append(UInt8(i))
    var t1 = List[Byte]()
    generate_retry_token(t1, lib, scratch, Span(secret), Span(orig_dcid), Span(addr_hash), UInt64(0))
    var t2 = List[Byte]()
    generate_retry_token(t2, lib, scratch, Span(secret), Span(orig_dcid), Span(addr_hash), UInt64(0))
    var same = True
    for i in range(1, 13):
        if t1[i] != t2[i]:
            same = False
            break
    if same:
        return ObserveResult(False, String("P6: nonces of two generate() calls are identical (getrandom not actually random?)"))
    return ObserveResult(True, String(""))


def _env_u64(name: String, default: UInt64) -> UInt64:
    var raw = getenv(name)
    if raw.byte_length() == 0: return default
    try: return UInt64(Int(raw))
    except: return default


def _env_int(name: String, default: Int) -> Int:
    var raw = getenv(name)
    if raw.byte_length() == 0: return default
    try: return Int(raw)
    except: return default


def _env_bool(name: String) -> Bool:
    var raw = getenv(name)
    return raw.byte_length() > 0 and raw != String("0") and raw != String("false")


def main() raises:
    var seed = _env_u64(String("FUZZ_SEED"), UInt64(0xC0FFEE))
    var iters = _env_int(String("FUZZ_ITERS"), 100)  # keeps the default run near 1 minute
    var soak = _env_bool(String("FUZZ_SOAK"))

    var tls = TlsBackend("lib/librustls_mojo.so")
    var shared = tls.shared()

    var rng = SplitMix64(seed)
    var report = FuzzReport(String("fuzz_retry_aead"), seed, iters)

    var scratch = RetryTokenScratch()

    # P6 once at startup
    report.observe(_check_p6(shared, scratch))

    # P1-P5 per iteration
    var stage = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= 20: break
        report.observe(_check_all_properties(rng, shared, scratch))
        report.observe(_check_classify(rng, shared, scratch))
        stage += 1
    print("stage (P1-P5, C1-C6):", stage, "iters")
    print("plus P6 (nonce-uniqueness probe)")

    report.finish()

    # Keep tls alive past the FFI calls.
    _ = tls^
