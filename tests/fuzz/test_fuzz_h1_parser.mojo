# tests/fuzz/test_fuzz_h1_parser.mojo
#
# Property-test fuzz: HTTP/1.1 request parser.
# Oracle: conformance/lib/http1/parser.parse_request (independent 300-LoC impl,
#         cross-validated against h11/httptools at build time).
# Production: navette.h1.parser.try_parse_request
#
# Property: oracle and production agree on parse success vs failure for any
# byte input. (We do NOT compare parsed field values yet — the two APIs
# differ enough in field representation that exact-match fires too many
# benign disagreements. Success/failure parity is the high-signal property.)

from std.os import getenv

from tests.fuzz.lib.prng import SplitMix64
from tests.fuzz.lib.generators import random_bytes_geom, mutate
from tests.fuzz.lib.corpus import load_corpus_dir, save_disagreement
from tests.fuzz.lib.report import FuzzReport, ObserveResult

from lib.http1.parser import parse_request as oracle_parse_request
from lib.http1.types import ParseConfig as OracleParseConfig

from navette.h1.parser import try_parse_request as prod_try_parse_request
from navette.h1.config import ParseConfig as ProdParseConfig


def _check_byte_property(b: List[UInt8]) -> ObserveResult:
    """Property: oracle and production agree on the parse VERDICT (accept vs reject)
    when both have committed. Production is a streaming/incremental parser: when
    it returns no request AND no error, the verdict is 'need more data' — that's
    an open question, not a disagreement.
    """
    # Oracle (whole-message API)
    var oracle_cfg = OracleParseConfig()
    var oracle_result = oracle_parse_request(b, oracle_cfg)
    var oracle_ok = oracle_result.ok()
    # Production (incremental API)
    var prod_cfg = ProdParseConfig()
    var prod_result = prod_try_parse_request(b, 0, 0, prod_cfg)
    var prod_has_request = prod_result.request.__bool__()
    var prod_has_error = prod_result.error.byte_length() > 0
    # Three production verdicts:
    #   ACCEPT  = request.has_value() and no error
    #   REJECT  = error is set
    #   PENDING = no request, no error (need more data)
    # Compare only when production committed.
    if not prod_has_request and not prod_has_error:
        # Production says "need more data". Skip — not a disagreement.
        return ObserveResult(True, String(""))
    var prod_accept = prod_has_request and not prod_has_error
    if oracle_ok != prod_accept:
        var detail = String("verdict mismatch: oracle_ok=") + String(oracle_ok)
        if not oracle_ok:
            detail += String(" oracle_err='") + oracle_result.error + String("'")
        detail += String(" prod_accept=") + String(prod_accept)
        if prod_has_error:
            detail += String(" prod_err='") + prod_result.error + String("'")
        return ObserveResult(False, detail)
    return ObserveResult(True, String(""))


def _gen_request_grammar(mut rng: SplitMix64) -> List[UInt8]:
    """Construct a plausible HTTP/1.1 request: METHOD SP TARGET SP HTTP/1.1 CRLF + headers + CRLFCRLF."""
    var methods = List[String]()
    methods.append(String("GET"))
    methods.append(String("POST"))
    methods.append(String("HEAD"))
    methods.append(String("OPTIONS"))
    methods.append(String("PUT"))
    methods.append(String("DELETE"))
    methods.append(String("PATCH"))
    methods.append(String("CONNECT"))
    methods.append(String("TRACE"))
    var method = methods[Int(rng.next_below(UInt64(len(methods))))]
    # Random target
    var target = String("/")
    var path_len = Int(rng.next_below(UInt64(8)))
    for _ in range(path_len):
        var c = UInt8(ord("a")) + (rng.next_u8() % UInt8(26))
        target += chr(Int(c))
    var line = method + String(" ") + target + String(" HTTP/1.1\r\n")
    # 0-4 random headers
    var n_headers = Int(rng.next_below(UInt64(5)))
    var hdrs = String("")
    for _ in range(n_headers):
        # Pick from a small set of names
        var names = List[String]()
        names.append(String("Host"))
        names.append(String("User-Agent"))
        names.append(String("Accept"))
        names.append(String("Content-Length"))
        names.append(String("X-Custom"))
        var name = names[Int(rng.next_below(UInt64(len(names))))]
        var val = String("v")
        var val_len = Int(rng.next_below(UInt64(8)))
        for _ in range(val_len):
            val += chr(Int(UInt8(ord("a")) + (rng.next_u8() % UInt8(26))))
        hdrs += name + String(": ") + val + String("\r\n")
    var full = line + hdrs + String("\r\n")
    var bs = full.as_bytes()
    var out = List[UInt8](capacity=len(bs))
    for i in range(len(bs)):
        out.append(bs[i])
    return out^


def _env_u64(name: String, default: UInt64) -> UInt64:
    var raw = getenv(name)
    if raw.byte_length() == 0:
        return default
    try:
        return UInt64(Int(raw))
    except:
        return default


def _env_int(name: String, default: Int) -> Int:
    var raw = getenv(name)
    if raw.byte_length() == 0:
        return default
    try:
        return Int(raw)
    except:
        return default


def _env_bool(name: String) -> Bool:
    var raw = getenv(name)
    return raw.byte_length() > 0 and raw != String("0") and raw != String("false")


def main() raises:
    var seed = _env_u64(String("FUZZ_SEED"), UInt64(0xC0FFEE))
    var iters = _env_int(String("FUZZ_ITERS"), 5000)
    var soak = _env_bool(String("FUZZ_SOAK"))
    var max_reports = 50

    var rng = SplitMix64(seed)
    var report = FuzzReport(String("fuzz_h1_parser"), seed, iters)

    # Stage 1: corpus replay
    var corpus = load_corpus_dir(String("conformance/fuzz/corpus/h1_parser"))
    for i in range(len(corpus)):
        report.observe(_check_byte_property(corpus[i].bytes.copy()))
    print("stage 1 (corpus replay):", len(corpus), "entries")

    # Stage 2: generative byte input — weighted mix
    var stage2 = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= max_reports:
            break
        var strategy = Int(rng.next_below(UInt64(100)))
        var b: List[UInt8]
        if strategy < 30:
            # random bytes
            b = random_bytes_geom(rng, mean_len=64, cap_len=4096)
        elif strategy < 70:
            # grammar-aware
            b = _gen_request_grammar(rng)
        else:
            # mutate corpus
            if len(corpus) > 0:
                var pick = corpus[Int(rng.next_below(UInt64(len(corpus))))].bytes.copy()
                b = mutate(rng, pick)
            else:
                b = random_bytes_geom(rng, mean_len=64, cap_len=4096)
        report.observe(_check_byte_property(b))
        stage2 += 1
    print("stage 2 (generative):", stage2, "iters")

    report.finish()
