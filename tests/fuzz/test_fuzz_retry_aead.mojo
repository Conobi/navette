# tests/fuzz/test_fuzz_retry_aead.mojo
#
# Multi-property fuzz: QUIC Retry token AEAD.
# Production: navette.quic.retry.{generate_retry_token, validate_retry_token}
# (AEAD has no in-tree Mojo oracle; roundtrip + tamper + cross-input
# properties cover the security-critical surface.)
#
# Properties (per spec §Retry-AEAD property set):
#   P1 — Inverse identity: validate(generate(...)) returns the orig_dcid.
#   P2 — Tag/ciphertext tamper: flipping any bit in token[12:] → validate raises.
#   P2b — Nonce tamper: flipping any bit in token[:12] → validate raises.
#   P3 — Cross-secret rejection: distinct server_secret → validate raises.
#   P4 — Address-hash mismatch: distinct client_addr_hash → validate raises.
#   P5 — Expiry: now_v > now_g + max_age → validate raises.
#   P6 — Nonce uniqueness probe: two generate() calls with identical inputs
#        produce tokens whose nonce prefix (bytes 0..11) differs.

from std.os import getenv

from tests.fuzz.lib.prng import SplitMix64
from tests.fuzz.lib.report import FuzzReport, ObserveResult

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.quic.retry import generate_retry_token, validate_retry_token


def _random_bytes(mut rng: SplitMix64, n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(rng.next_u8())
    return out^


def _check_all_properties(mut rng: SplitMix64, lib: SharedLibrary) raises -> ObserveResult:
    """Each invocation exercises P1-P6 on freshly-generated inputs."""
    var secret = _random_bytes(rng, 16)
    var dcid_len = Int(rng.next_below(UInt64(21)))  # 0-20
    var orig_dcid = _random_bytes(rng, dcid_len)
    var addr_hash = _random_bytes(rng, 32)
    var now_g = rng.next_u64() % UInt64(1000000)

    # P1: inverse identity
    var token: List[UInt8]
    try:
        token = generate_retry_token(lib, Span(secret), Span(orig_dcid), Span(addr_hash), now_g)
    except e:
        return ObserveResult(False, String("P1: generate_retry_token raised: ") + String(e))
    var recovered: List[UInt8]
    try:
        recovered = validate_retry_token(lib, Span(secret), Span(token), Span(addr_hash), now_g, UInt64(10000))
    except e:
        return ObserveResult(False, String("P1: validate raised on its own token: ") + String(e))
    if len(recovered) != dcid_len:
        return ObserveResult(False, String("P1: recovered dcid len ") + String(len(recovered)) + String(" != ") + String(dcid_len))
    for i in range(dcid_len):
        if recovered[i] != orig_dcid[i]:
            return ObserveResult(False, String("P1: recovered dcid byte ") + String(i) + String(" differs"))

    # P2: tag/ciphertext tamper (flip a bit in token[12:])
    if len(token) > 12:
        var tampered = token.copy()
        var byte_idx = 12 + Int(rng.next_below(UInt64(len(token) - 12)))
        var bit = Int(rng.next_below(UInt64(8)))
        tampered[byte_idx] = tampered[byte_idx] ^ UInt8(1 << bit)
        var raised = False
        try:
            _ = validate_retry_token(lib, Span(secret), Span(tampered), Span(addr_hash), now_g, UInt64(10000))
        except:
            raised = True
        if not raised:
            return ObserveResult(False, String("P2: tag/ciphertext tamper did not raise"))

    # P2b: nonce tamper
    var nonce_tampered = token.copy()
    var nbit = Int(rng.next_below(UInt64(8)))
    var nbyte = Int(rng.next_below(UInt64(12)))
    nonce_tampered[nbyte] = nonce_tampered[nbyte] ^ UInt8(1 << nbit)
    var raised_2b = False
    try:
        _ = validate_retry_token(lib, Span(secret), Span(nonce_tampered), Span(addr_hash), now_g, UInt64(10000))
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
        _ = validate_retry_token(lib, Span(secret2), Span(token), Span(addr_hash), now_g, UInt64(10000))
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
        _ = validate_retry_token(lib, Span(secret), Span(token), Span(hash2), now_g, UInt64(10000))
    except:
        raised_4 = True
    if not raised_4:
        return ObserveResult(False, String("P4: addr-hash mismatch accepted"))

    # P5: expiry
    var now_v = now_g + UInt64(100)
    var raised_5 = False
    try:
        _ = validate_retry_token(lib, Span(secret), Span(token), Span(addr_hash), now_v, UInt64(5))
    except:
        raised_5 = True
    if not raised_5:
        return ObserveResult(False, String("P5: expired token accepted"))

    return ObserveResult(True, String(""))


def _check_p6(lib: SharedLibrary) raises -> ObserveResult:
    """Nonce-uniqueness probe: two calls with identical inputs → distinct nonces."""
    var secret = List[UInt8]()
    for i in range(16):
        secret.append(UInt8(i))
    var orig_dcid = List[UInt8]()
    for i in range(8):
        orig_dcid.append(UInt8(0xA0 + i))
    var addr_hash = List[UInt8]()
    for i in range(32):
        addr_hash.append(UInt8(i))
    var t1 = generate_retry_token(lib, Span(secret), Span(orig_dcid), Span(addr_hash), UInt64(0))
    var t2 = generate_retry_token(lib, Span(secret), Span(orig_dcid), Span(addr_hash), UInt64(0))
    var same = True
    for i in range(12):
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
    var iters = _env_int(String("FUZZ_ITERS"), 1000)  # AEAD is heavier; smaller default
    var soak = _env_bool(String("FUZZ_SOAK"))

    var tls = TlsBackend("lib/librustls_mojo.so")
    var shared = tls.shared()

    var rng = SplitMix64(seed)
    var report = FuzzReport(String("fuzz_retry_aead"), seed, iters)

    # P6 once at startup
    report.observe(_check_p6(shared))

    # P1-P5 per iteration
    var stage = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= 20: break
        report.observe(_check_all_properties(rng, shared))
        stage += 1
    print("stage (P1-P5):", stage, "iters")
    print("plus P6 (nonce-uniqueness probe)")

    report.finish()

    # Keep tls alive past the FFI calls.
    _ = tls^
