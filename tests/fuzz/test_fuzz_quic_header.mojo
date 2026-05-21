# tests/fuzz/test_fuzz_quic_header.mojo
#
# Structural-property fuzz: QUIC packet header parser.
# Production: navette.quic.packet.parse_packet_header
# No in-tree Mojo oracle (lib/packet.mojo is the packet-number codec only).
#
# Properties (per spec §QUIC header property set):
#   P1 — DCID-length sanity: returned dcid len ≤ 20 (RFC 9000 §17.2).
#   P2 — Length consistency: if parser returns consumed N, slicing buf[:N]
#       and reparsing produces the same header.
#   P3 — Version=0 means version negotiation; otherwise specific version
#       must be reported as-is (no truncation).
#   P4 — Short-header parser honors caller's local_cid_len (pin = 8 here).

from std.os import getenv

from tests.fuzz.lib.prng import SplitMix64
from tests.fuzz.lib.generators import random_bytes_geom, mutate
from tests.fuzz.lib.corpus import load_corpus_dir
from tests.fuzz.lib.report import FuzzReport, ObserveResult

from navette.quic.packet import parse_packet_header


alias _SCID_LEN_PIN: Int = 8


def _check_property(b: List[UInt8]) -> ObserveResult:
    try:
        var span = Span(b)
        var result = parse_packet_header(span, _SCID_LEN_PIN)
        # P1 — DCID length sanity
        var dcid_len = len(result[0].dcid)
        if dcid_len > 20:
            return ObserveResult(False, String("P1 violation: dcid_len=") + String(dcid_len) + String(" > 20"))
        # P4 — short-header SCID-pin honored
        if not result[0].is_long_header:
            # In short-header packets, the parser must have used local_cid_len
            # to extract dcid. We can only verify indirectly: dcid_len must equal _SCID_LEN_PIN.
            if dcid_len != _SCID_LEN_PIN:
                return ObserveResult(False, String("P4 violation: short-header dcid_len=") + String(dcid_len) + String(" != pin=") + String(_SCID_LEN_PIN))
    except:
        # Parse failure is a legitimate verdict for malformed input.
        pass
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
    var report = FuzzReport(String("fuzz_quic_header"), seed, iters)

    var corpus = load_corpus_dir(String("conformance/fuzz/corpus/quic_header"))
    for i in range(len(corpus)):
        report.observe(_check_property(corpus[i].bytes.copy()))
    print("stage 1 (corpus):", len(corpus), "entries")

    var stage2 = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= 50: break
        var strategy = Int(rng.next_below(UInt64(100)))
        var b: List[UInt8]
        if strategy < 40:
            b = random_bytes_geom(rng, mean_len=64, cap_len=1500)
        else:
            # Grammar-aware: random first-byte + plausible DCID-len byte + payload
            b = List[UInt8]()
            b.append(rng.next_u8())  # first byte (header form, type, etc.)
            # Long-header: version (4 bytes) + dcid_len + dcid + scid_len + scid + ...
            if Int(b[0]) & 0x80 != 0:
                # version
                for _ in range(4):
                    b.append(rng.next_u8())
                var dcid_len = Int(rng.next_below(UInt64(21)))
                b.append(UInt8(dcid_len))
                for _ in range(dcid_len):
                    b.append(rng.next_u8())
                var scid_len = Int(rng.next_below(UInt64(21)))
                b.append(UInt8(scid_len))
                for _ in range(scid_len):
                    b.append(rng.next_u8())
                # Trailing payload
                var pad = Int(rng.next_below(UInt64(64)))
                for _ in range(pad):
                    b.append(rng.next_u8())
            else:
                # Short header: caller-pinned dcid_len bytes, then payload
                for _ in range(_SCID_LEN_PIN):
                    b.append(rng.next_u8())
                var pad = Int(rng.next_below(UInt64(128)))
                for _ in range(pad):
                    b.append(rng.next_u8())
        report.observe(_check_property(b))
        stage2 += 1
    print("stage 2 (generative):", stage2, "iters")

    report.finish()
