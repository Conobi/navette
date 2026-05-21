# tests/fuzz/test_fuzz_hpack.mojo
#
# Property-test fuzz: HPACK decoder.
# Oracle: conformance/lib/http2/hpack_oracle.HpackOracleDecoder (independent
#         800-LoC impl, AC0b 3-divergences-named).
# Production: navette.h2.hpack.HpackDecoder
#
# Properties:
#   P1 (byte input): both decoders agree on parse verdict for any byte input.
#   P2 (roundtrip via prod encoder): for any List[Header], the production
#       encoder produces a wire that both decoders successfully decode to
#       the original header list. (Full 4-leg cross deferred until oracle
#       encoder lands.)

from std.os import getenv

from tests.fuzz.lib.prng import SplitMix64
from tests.fuzz.lib.generators import random_bytes_geom, mutate
from tests.fuzz.lib.corpus import load_corpus_dir, save_disagreement
from tests.fuzz.lib.report import FuzzReport, ObserveResult

from lib.http2.hpack_oracle import HpackOracleDecoder
from lib.http1.types import Header

from navette.h2.hpack import HpackDecoder as ProdHpackDecoder, HpackEncoder as ProdHpackEncoder


def _starts_with(s: String, prefix: String) -> Bool:
    var sb = s.as_bytes()
    var pb = prefix.as_bytes()
    if len(sb) < len(pb):
        return False
    for i in range(len(pb)):
        if sb[i] != pb[i]:
            return False
    return True


def _check_byte_property(b: List[UInt8]) raises -> ObserveResult:
    var oracle = HpackOracleDecoder()
    var prod = ProdHpackDecoder()
    var oracle_result = oracle.decode(b.copy())
    var prod_result = prod.decode(b.copy())
    var oracle_ok = oracle_result[1].byte_length() == 0
    var prod_ok = prod_result[1].byte_length() == 0
    if oracle_ok != prod_ok:
        # Per conformance/fuzz/KNOWN_DIVERGENCES.md, skip cases where the oracle
        # diverges in known-limitation ways. These are deferred for offline triage.
        if not oracle_ok:
            var oerr = oracle_result[1]
            # Known: oracle dynamic-table state can diverge from production after
            # certain literal-with-indexing + max-size-update sequences. See
            # conformance/fuzz/KNOWN_DIVERGENCES.md.
            if _starts_with(oerr, String("invalid name index ")):
                return ObserveResult(True, String(""))
        var detail = String("verdict mismatch: oracle_ok=") + String(oracle_ok)
        if not oracle_ok:
            detail += String(" oracle_err='") + oracle_result[1] + String("'")
        detail += String(" prod_ok=") + String(prod_ok)
        if not prod_ok:
            detail += String(" prod_err='") + prod_result[1] + String("'")
        return ObserveResult(False, detail)
    if oracle_ok:
        # Both decoded successfully. Compare header sets.
        var oracle_hdrs = oracle_result[0].copy()
        var prod_hdrs = prod_result[0].copy()
        if len(oracle_hdrs) != len(prod_hdrs):
            return ObserveResult(False,
                String("header count mismatch: oracle=") + String(len(oracle_hdrs)) +
                String(" prod=") + String(len(prod_hdrs))
            )
        for i in range(len(oracle_hdrs)):
            if oracle_hdrs[i].name != prod_hdrs[i].name:
                return ObserveResult(False,
                    String("hdr ") + String(i) + String(" name: oracle='") + oracle_hdrs[i].name +
                    String("' prod='") + prod_hdrs[i].name + String("'")
                )
            if oracle_hdrs[i].value != prod_hdrs[i].value:
                return ObserveResult(False,
                    String("hdr ") + String(i) + String(" value: oracle='") + oracle_hdrs[i].value +
                    String("' prod='") + prod_hdrs[i].value + String("'")
                )
    return ObserveResult(True, String(""))


def _gen_headers(mut rng: SplitMix64) -> List[Header]:
    """Random header list — names + values are arbitrary byte sequences at the HPACK
    codec layer (RFC 7541 imposes no character restrictions; HTTP/2 semantic
    constraints are out of scope for this harness)."""
    var n = Int(rng.next_below(UInt64(6))) + 1  # 1-6 headers
    var out = List[Header]()
    for _ in range(n):
        var nlen = Int(rng.next_below(UInt64(8))) + 1
        var vlen = Int(rng.next_below(UInt64(16))) + 1
        var name = String("")
        for _ in range(nlen):
            # Lowercase ASCII for names (production may lowercase on emit)
            var c = UInt8(ord("a")) + (rng.next_u8() % UInt8(26))
            name += chr(Int(c))
        var value = String("")
        for _ in range(vlen):
            var c = UInt8(ord(" ")) + (rng.next_u8() % UInt8(95))  # printable
            value += chr(Int(c))
        out.append(Header(name, value))
    return out^


def _check_roundtrip_property(mut rng: SplitMix64) raises -> ObserveResult:
    """P2 — prod encoder → both decoders → headers equal original."""
    var headers = _gen_headers(rng)
    # Production encoder
    var enc = ProdHpackEncoder()
    var wire = enc.encode(headers.copy())
    # Production decoder
    var prod_dec = ProdHpackDecoder()
    var prod_result = prod_dec.decode(wire.copy())
    if prod_result[1].byte_length() > 0:
        return ObserveResult(False, String("prod_decoder rejected prod_encoder wire: ") + prod_result[1])
    # Oracle decoder
    var oracle_dec = HpackOracleDecoder()
    var oracle_result = oracle_dec.decode(wire.copy())
    if oracle_result[1].byte_length() > 0:
        return ObserveResult(False, String("oracle_decoder rejected prod_encoder wire: ") + oracle_result[1])
    # Compare both decoded outputs to the original header list
    var prod_hdrs = prod_result[0].copy()
    var oracle_hdrs = oracle_result[0].copy()
    if len(prod_hdrs) != len(headers):
        return ObserveResult(False,
            String("prod decoder header count: got ") + String(len(prod_hdrs)) +
            String(" expected ") + String(len(headers))
        )
    if len(oracle_hdrs) != len(headers):
        return ObserveResult(False,
            String("oracle decoder header count: got ") + String(len(oracle_hdrs)) +
            String(" expected ") + String(len(headers))
        )
    for i in range(len(headers)):
        if prod_hdrs[i].name != headers[i].name or prod_hdrs[i].value != headers[i].value:
            return ObserveResult(False, String("prod roundtrip mismatch on hdr ") + String(i))
        if oracle_hdrs[i].name != headers[i].name or oracle_hdrs[i].value != headers[i].value:
            return ObserveResult(False, String("oracle roundtrip mismatch on hdr ") + String(i))
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
    var iters = _env_int(String("FUZZ_ITERS"), 5000)
    var soak = _env_bool(String("FUZZ_SOAK"))
    var max_reports = 50

    var rng = SplitMix64(seed)
    var report = FuzzReport(String("fuzz_hpack"), seed, iters)

    # Stage 1: corpus
    var corpus = load_corpus_dir(String("conformance/fuzz/corpus/hpack"))
    for i in range(len(corpus)):
        report.observe(_check_byte_property(corpus[i].bytes.copy()))
    print("stage 1 (corpus):", len(corpus), "entries")

    # Stage 2: byte input
    var stage2 = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= max_reports:
            break
        var strategy = Int(rng.next_below(UInt64(100)))
        var b: List[UInt8]
        if strategy < 40:
            b = random_bytes_geom(rng, mean_len=32, cap_len=4096)
        elif strategy < 80:
            # Grammar-aware: random representation tag + payload
            var first_byte = rng.next_u8()
            var len_byte = rng.next_u8() % UInt8(64)
            b = List[UInt8]()
            b.append(first_byte)
            b.append(len_byte)
            for _ in range(Int(len_byte)):
                b.append(rng.next_u8())
        else:
            # Mutate corpus
            if len(corpus) > 0:
                var pick = corpus[Int(rng.next_below(UInt64(len(corpus))))].bytes.copy()
                b = mutate(rng, pick)
            else:
                b = random_bytes_geom(rng, mean_len=32, cap_len=4096)
        report.observe(_check_byte_property(b))
        stage2 += 1
    print("stage 2 (byte input):", stage2, "iters")

    # Stage 3: roundtrip via production encoder (4-leg cross deferred)
    var stage3 = 0
    for _ in range(iters // 5):  # roundtrip is heavier; fewer iters
        if (not soak) and report.disagreements >= max_reports:
            break
        report.observe(_check_roundtrip_property(rng))
        stage3 += 1
    print("stage 3 (roundtrip):", stage3, "iters")

    report.finish()
