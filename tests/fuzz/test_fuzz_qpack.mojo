# tests/fuzz/test_fuzz_qpack.mojo
#
# Roundtrip fuzz: QPACK encoder + decoder.
# Production: navette.h3.qpack.{QpackEncoder, QpackDecoder}
# (No in-tree Mojo oracle for QPACK in v1; upgrade when conformance/lib/http3/
# qpack lands.)
#
# Properties:
#   P1 (byte input): decoder must not crash on arbitrary bytes; either decodes
#       cleanly or raises a recoverable error.
#   P2 (encode roundtrip): for any List[QpackHeaderField], decode(encode(h))
#       returns headers equal to h.

from std.os import getenv

from tests.fuzz.lib.prng import SplitMix64
from tests.fuzz.lib.generators import random_bytes_geom, mutate
from tests.fuzz.lib.corpus import load_corpus_dir
from tests.fuzz.lib.report import FuzzReport, ObserveResult

from navette.h3.qpack import QpackEncoder, QpackDecoder, QpackHeaderField


def _check_byte_property(b: List[UInt8]) -> ObserveResult:
    var dec = QpackDecoder()
    try:
        _ = dec.decode(b.copy())
    except:
        pass  # legitimate parse failure
    return ObserveResult(True, String(""))


def _gen_headers(mut rng: SplitMix64) -> List[QpackHeaderField]:
    var n = Int(rng.next_below(UInt64(5))) + 1
    var out = List[QpackHeaderField]()
    for _ in range(n):
        var nlen = Int(rng.next_below(UInt64(8))) + 1
        var vlen = Int(rng.next_below(UInt64(16))) + 1
        var name = String("")
        for _ in range(nlen):
            name += chr(Int(UInt8(ord("a")) + (rng.next_u8() % UInt8(26))))
        var value = String("")
        for _ in range(vlen):
            value += chr(Int(UInt8(ord(" ")) + (rng.next_u8() % UInt8(95))))
        out.append(QpackHeaderField(name, value))
    return out^


def _check_roundtrip_property(mut rng: SplitMix64) -> ObserveResult:
    var headers = _gen_headers(rng)
    var enc = QpackEncoder()
    var wire: List[UInt8]
    try:
        wire = enc.encode(headers.copy())
    except e:
        return ObserveResult(False, String("encode raised: ") + String(e))
    var dec = QpackDecoder()
    var decoded: List[QpackHeaderField]
    try:
        decoded = dec.decode(wire.copy())
    except e:
        return ObserveResult(False, String("decode raised: ") + String(e))
    if len(decoded) != len(headers):
        return ObserveResult(False, String("header count: got ") + String(len(decoded)) + String(" expected ") + String(len(headers)))
    for i in range(len(headers)):
        if decoded[i].name != headers[i].name:
            return ObserveResult(False, String("hdr ") + String(i) + String(" name mismatch"))
        if decoded[i].value != headers[i].value:
            return ObserveResult(False, String("hdr ") + String(i) + String(" value mismatch"))
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

    var rng = SplitMix64(seed)
    var report = FuzzReport(String("fuzz_qpack"), seed, iters)

    var corpus = load_corpus_dir(String("conformance/fuzz/corpus/qpack"))
    for i in range(len(corpus)):
        report.observe(_check_byte_property(corpus[i].bytes.copy()))
    print("stage 1 (corpus):", len(corpus), "entries")

    var stage2 = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= 50: break
        var b = random_bytes_geom(rng, mean_len=32, cap_len=2048)
        report.observe(_check_byte_property(b))
        stage2 += 1
    print("stage 2 (byte input):", stage2, "iters")

    var stage3 = 0
    for _ in range(iters // 5):
        if (not soak) and report.disagreements >= 50: break
        report.observe(_check_roundtrip_property(rng))
        stage3 += 1
    print("stage 3 (roundtrip):", stage3, "iters")

    report.finish()
