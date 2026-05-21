# tests/fuzz/test_fuzz_h3_frame.mojo
#
# Roundtrip fuzz: HTTP/3 frame codec.
# Production: navette.h3.frame.{parse_h3_frame, H3RawFrame.encode}
# (No in-tree Mojo oracle for H3 frames in v1; upgrade when
# conformance/lib/http3/frame lands.)
#
# Properties:
#   P1 (byte input): decoder must not crash on arbitrary bytes; either parses
#       cleanly or raises a recoverable error.
#   P2 (encode roundtrip): for any synthesized H3RawFrame, parse(encode(f))
#       returns frame_type + payload equal to f.

from std.os import getenv

from tests.fuzz.lib.prng import SplitMix64
from tests.fuzz.lib.generators import random_bytes_geom
from tests.fuzz.lib.corpus import load_corpus_dir
from tests.fuzz.lib.report import FuzzReport, ObserveResult

from navette.h3.frame import H3RawFrame, parse_h3_frame
from navette.quic.codec import ByteReader, varint_encode, varint_decode


def _check_byte_property(b: List[UInt8]) -> ObserveResult:
    try:
        var span = Span(b)
        var r = ByteReader(span)
        _ = parse_h3_frame(r)
    except:
        pass  # legitimate parse failure
    return ObserveResult(True, String(""))


def _gen_frame(mut rng: SplitMix64) -> H3RawFrame:
    var ft = rng.next_u64() % UInt64(64)
    var pl_len = Int(rng.next_below(UInt64(128)))
    var payload = List[UInt8](capacity=pl_len)
    for _ in range(pl_len):
        payload.append(rng.next_u8())
    return H3RawFrame(ft, payload^)


def _check_roundtrip_property(mut rng: SplitMix64) -> ObserveResult:
    var f = _gen_frame(rng)
    var wire: List[UInt8]
    try:
        wire = f.encode()
    except e:
        return ObserveResult(False, String("encode raised: ") + String(e))
    var span = Span(wire)
    var r = ByteReader(span)
    var decoded: H3RawFrame
    try:
        decoded = parse_h3_frame(r)
    except e:
        return ObserveResult(False, String("parse raised on encoded frame: ") + String(e))
    if decoded.frame_type != f.frame_type:
        return ObserveResult(False, String("frame_type mismatch"))
    if len(decoded.payload) != len(f.payload):
        return ObserveResult(False, String("payload length mismatch"))
    for i in range(len(f.payload)):
        if decoded.payload[i] != f.payload[i]:
            return ObserveResult(False, String("payload byte ") + String(i) + String(" mismatch"))
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
    var report = FuzzReport(String("fuzz_h3_frame"), seed, iters)

    var corpus = load_corpus_dir(String("conformance/fuzz/corpus/h3_frame"))
    for i in range(len(corpus)):
        report.observe(_check_byte_property(corpus[i].bytes.copy()))
    print("stage 1 (corpus):", len(corpus), "entries")

    var stage2 = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= 50: break
        var b = random_bytes_geom(rng, mean_len=32, cap_len=1024)
        report.observe(_check_byte_property(b))
        stage2 += 1
    print("stage 2 (byte input):", stage2, "iters")

    var stage3 = 0
    for _ in range(iters // 2):
        if (not soak) and report.disagreements >= 50: break
        report.observe(_check_roundtrip_property(rng))
        stage3 += 1
    print("stage 3 (roundtrip):", stage3, "iters")

    report.finish()
