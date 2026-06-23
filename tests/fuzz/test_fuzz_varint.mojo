# tests/fuzz/test_fuzz_varint.mojo
#
# Property-test fuzz: QUIC variable-length integers (RFC 9000 §16).
# Oracle: conformance/lib/varint (independent reference impl, 65 LoC).
# Production: navette.quic.codec.varint_{encode,decode,len}
#
# Properties:
#   P1 (byte-input): for any byte sequence, oracle and production agree on
#       (a) raise/no-raise, (b) decoded value when both succeed.
#   P2 (encode roundtrip): for any UInt64 < 2^62, both encoders produce
#       byte sequences that decode (via the opposite stack) to the same value.

from std.os import getenv
from std.python import Python

from tests.fuzz.lib.prng import SplitMix64
from tests.fuzz.lib.generators import random_bytes_geom
from tests.fuzz.lib.corpus import load_corpus_dir, save_disagreement
from tests.fuzz.lib.report import FuzzReport, ObserveResult

from lib.cursor import ByteReader as OracleReader, ByteWriter as OracleWriter
from lib.varint import varint_encode as oracle_encode, varint_decode as oracle_decode

from navette.quic.codec import (
    varint_encode as prod_encode,
    varint_decode as prod_decode,
    ByteReader as ProdReader,
    ByteWriter as ProdWriter,
)


# ============================================================================
# Property checks
# ============================================================================


def _check_byte_property(b: List[UInt8]) -> ObserveResult:
    """P1 — feed bytes to both decoders, observe agreement."""
    # Oracle
    var oracle_err = String("")
    var oracle_val: UInt64 = 0
    try:
        var or_reader = OracleReader(b)
        oracle_val = oracle_decode(or_reader)
    except e:
        oracle_err = String(e)
    # Production
    var prod_err = String("")
    var prod_val: UInt64 = 0
    try:
        var pr_reader = ProdReader(Span(b))
        prod_val = prod_decode(pr_reader)
    except e:
        prod_err = String(e)
    # Compare
    var oracle_raised = oracle_err.byte_length() > 0
    var prod_raised = prod_err.byte_length() > 0
    if oracle_raised != prod_raised:
        var detail = String("error-class mismatch: oracle_raised=") + String(oracle_raised) + String(" oracle_err='") + oracle_err + String("' prod_raised=") + String(prod_raised) + String(" prod_err='") + prod_err + String("'")
        return ObserveResult(False, detail)
    if not oracle_raised and oracle_val != prod_val:
        var detail = String("value mismatch: oracle=") + String(Int(oracle_val)) + String(" prod=") + String(Int(prod_val))
        return ObserveResult(False, detail)
    return ObserveResult(True, String(""))


def _check_encode_property(v: UInt64) -> ObserveResult:
    """P2 — encode v with both, decode each output with the opposite stack."""
    # Skip out-of-range values (varint max is 2^62 - 1)
    if v >= (UInt64(1) << UInt64(62)):
        return ObserveResult(True, String(""))
    # Oracle encode
    var ow = OracleWriter(capacity=8)
    try:
        oracle_encode(ow, v)
    except e:
        return ObserveResult(False, String("oracle encode failed for v=") + String(Int(v)) + String(": ") + String(e))
    var oracle_wire = ow.finish()
    # Production encode
    var pw = ProdWriter(8)
    try:
        prod_encode(pw, v)
    except e:
        return ObserveResult(False, String("prod encode failed for v=") + String(Int(v)) + String(": ") + String(e))
    var prod_wire = pw.finish()
    # Oracle decodes prod wire
    try:
        var rr1 = OracleReader(prod_wire)
        var got = oracle_decode(rr1)
        if got != v:
            return ObserveResult(False, String("oracle decode of prod wire wrong: v=") + String(Int(v)) + String(" got=") + String(Int(got)))
    except e:
        return ObserveResult(False, String("oracle cannot decode prod wire: ") + String(e))
    # Production decodes oracle wire
    try:
        var rr2 = ProdReader(Span(oracle_wire))
        var got = prod_decode(rr2)
        if got != v:
            return ObserveResult(False, String("prod decode of oracle wire wrong: v=") + String(Int(v)) + String(" got=") + String(Int(got)))
    except e:
        return ObserveResult(False, String("prod cannot decode oracle wire: ") + String(e))
    return ObserveResult(True, String(""))


# ============================================================================
# Env helpers
# ============================================================================


def _env_u64(name: String, default: UInt64) -> UInt64:
    var raw = getenv(name)
    if raw.byte_length() == 0:
        return default
    try:
        # Mojo: Int() parses decimal. Strip 0x prefix if present.
        var s = raw
        if s.byte_length() > 2:
            var bs = s.as_bytes()
            if bs[0] == UInt8(ord("0")) and (bs[1] == UInt8(ord("x")) or bs[1] == UInt8(ord("X"))):
                # Hex parse via Python int(s, 0)
                var builtins = Python.import_module("builtins")
                return UInt64(Int(py=builtins.int(s, 0)))
        return UInt64(Int(s))
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
    if raw.byte_length() == 0:
        return False
    return raw != String("") and raw != String("0") and raw != String("false")


# ============================================================================
# Main
# ============================================================================


def main() raises:
    var seed = _env_u64(String("FUZZ_SEED"), UInt64(0xC0FFEE))
    var iters = _env_int(String("FUZZ_ITERS"), 5000)
    var soak = _env_bool(String("FUZZ_SOAK"))
    var max_reports = 50

    var rng = SplitMix64(seed)
    var report = FuzzReport(String("fuzz_varint"), seed, iters)

    # Stage 1: replay seed corpus
    var corpus = load_corpus_dir(String("conformance/fuzz/corpus/varint"))
    for i in range(len(corpus)):
        report.observe(_check_byte_property(corpus[i].bytes.copy()))
    print("stage 1 (corpus replay):", len(corpus), "entries")

    # Stage 2: generative byte-input
    var stage2_count = 0
    for _ in range(iters):
        if (not soak) and report.disagreements >= max_reports:
            break
        # Generate 1-16 random bytes (varint is at most 8 bytes)
        var b = random_bytes_geom(rng, mean_len=4, cap_len=16)
        report.observe(_check_byte_property(b))
        stage2_count += 1
    print("stage 2 (byte input):", stage2_count, "iters")

    # Stage 3: encode-roundtrip
    var stage3_count = 0
    # Boundary values per RFC 9000 §16
    var boundaries = List[UInt64]()
    boundaries.append(UInt64(0))
    boundaries.append(UInt64(63))
    boundaries.append(UInt64(64))
    boundaries.append(UInt64(16383))
    boundaries.append(UInt64(16384))
    boundaries.append(UInt64(1073741823))
    boundaries.append(UInt64(1073741824))
    boundaries.append((UInt64(1) << UInt64(62)) - UInt64(1))
    for i in range(len(boundaries)):
        report.observe(_check_encode_property(boundaries[i]))
        stage3_count += 1
    for _ in range(iters):
        if (not soak) and report.disagreements >= max_reports:
            break
        # Random value < 2^62
        var v = rng.next_u64() % (UInt64(1) << UInt64(62))
        report.observe(_check_encode_property(v))
        stage3_count += 1
    print("stage 3 (encode roundtrip):", stage3_count, "iters")

    report.finish()
