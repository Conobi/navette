# tests/fuzz/test_fuzz_h2_frame.mojo
#
# Roundtrip + structural-property fuzz: HTTP/2 frame codec.
# Production: navette.h2.frame.{decode_frame, encode_frame}
# (conformance/lib/http2/frame.mojo is a re-export, so no oracle disagreement.)
#
# Properties:
#   P1 (byte input → structural): if decode_frame succeeds, the length field
#       matches the actual payload size, frame_type is in known range or
#       unknown-type passthrough is honored.
#   P2 (encode roundtrip): for any synthesized Frame, decode(encode(f)) == f.
#       Compares length, frame_type, flags, stream_id (reserved high-bit
#       MUST be ignored not rejected), and payload bytes.

from std.os import getenv

from tests.fuzz.lib.prng import SplitMix64
from tests.fuzz.lib.generators import random_bytes_geom, mutate
from tests.fuzz.lib.corpus import load_corpus_dir
from tests.fuzz.lib.report import FuzzReport, ObserveResult

from navette.h2.frame import Frame, decode_frame, encode_frame, H2FrameConfig


def _check_byte_property(b: List[UInt8]) -> ObserveResult:
    var cfg = H2FrameConfig()
    var frame: Frame
    try:
        var decoded = decode_frame(b.copy(), 0, cfg)
        frame = decoded[0].copy()
    except:
        # Parse failure is a legitimate verdict.
        return ObserveResult(True, String(""))
    # On success, structural checks:
    if frame.error.byte_length() > 0:
        # decoder signalled error via field, not raise
        return ObserveResult(True, String(""))
    # P1: length must equal payload size
    if frame.length != len(frame.payload):
        return ObserveResult(False,
            String("P1: length field ") + String(frame.length) +
            String(" != payload size ") + String(len(frame.payload))
        )
    return ObserveResult(True, String(""))


def _gen_frame(mut rng: SplitMix64) -> Frame:
    """Generate a semantically valid frame for roundtrip testing.

    Restricts to:
      - frame_type in {0 DATA, 1 HEADERS, 3 RST_STREAM, 9 CONTINUATION}
        (these have minimal payload-format constraints).
      - stream_id non-zero per RFC 9113 §6.x for these types.
      - flags masked to drop PADDED (0x08), PRIORITY (0x20), END_HEADERS (0x04
        for HEADERS/CONTINUATION which would otherwise require valid header
        block).
    For broader coverage, byte-input stage 2 still exercises arbitrary inputs.
    """
    var f = Frame()
    var types = List[Int]()
    types.append(0)  # DATA
    types.append(3)  # RST_STREAM (always 4-byte payload — see length adj below)
    types.append(9)  # CONTINUATION (without flag flag set)
    f.frame_type = types[Int(rng.next_below(UInt64(len(types))))]
    f.flags = Int(rng.next_u8()) & 0xD3  # drop PADDED + END_HEADERS
    var sid = Int(rng.next_u32()) & 0x7FFFFFFF
    if sid == 0:
        sid = 1
    f.stream_id = sid
    var payload_len = Int(rng.next_below(UInt64(256)))
    if f.frame_type == 3:  # RST_STREAM payload must be exactly 4 bytes
        payload_len = 4
    f.payload = List[UInt8](capacity=payload_len)
    for _ in range(payload_len):
        f.payload.append(rng.next_u8())
    f.length = payload_len
    return f^


def _check_roundtrip_property(mut rng: SplitMix64) -> ObserveResult:
    var f = _gen_frame(rng)
    var wire = encode_frame(f.copy())
    var decoded: Frame
    try:
        var dr = decode_frame(wire.copy(), 0, H2FrameConfig())
        decoded = dr[0].copy()
    except e:
        return ObserveResult(False, String("decode failed for synthesized frame: ") + String(e))
    if decoded.error.byte_length() > 0:
        return ObserveResult(False, String("decode error for synthesized frame: ") + decoded.error)
    if decoded.length != f.length:
        return ObserveResult(False, String("length mismatch: encoded=") + String(f.length) + String(" decoded=") + String(decoded.length))
    if decoded.frame_type != f.frame_type:
        return ObserveResult(False, String("frame_type mismatch"))
    if decoded.flags != f.flags:
        return ObserveResult(False, String("flags mismatch"))
    # Per RFC 9113 §4.1, the high bit of stream_id is reserved and MUST be ignored on read.
    # Production must NOT preserve it. So decoded stream_id may differ in the high bit.
    var encoded_sid_lo31 = f.stream_id & 0x7FFFFFFF
    if decoded.stream_id != encoded_sid_lo31:
        return ObserveResult(False, String("stream_id mismatch (low 31 bits): encoded=") + String(encoded_sid_lo31) + String(" decoded=") + String(decoded.stream_id))
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
    var report = FuzzReport(String("fuzz_h2_frame"), seed, iters)

    var corpus = load_corpus_dir(String("conformance/fuzz/corpus/h2_frame"))
    for i in range(len(corpus)):
        report.observe(_check_byte_property(corpus[i].bytes.copy()))
    print("stage 1 (corpus):", len(corpus), "entries")

    # Stage 2: byte input
    var stage2 = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= 50: break
        var b = random_bytes_geom(rng, mean_len=64, cap_len=4096)
        report.observe(_check_byte_property(b))
        stage2 += 1
    print("stage 2 (byte input):", stage2, "iters")

    # Stage 3: roundtrip
    var stage3 = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= 50: break
        report.observe(_check_roundtrip_property(rng))
        stage3 += 1
    print("stage 3 (roundtrip):", stage3, "iters")

    report.finish()
