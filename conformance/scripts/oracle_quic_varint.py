#!/usr/bin/env python3
"""Generate QUIC variable-length integer test vectors (RFC 9000 §16).

Pre-materializes aioquic._buffer encode/decode results to
conformance/vectors/rfc9000/varint.json so test runtime no longer needs
aioquic.

Usage:
    uv run python conformance/scripts/oracle_quic_varint.py > \
        conformance/vectors/rfc9000/varint.json
"""
import binascii
import json
import random
import sys
from pathlib import Path

from aioquic._buffer import Buffer  # build-time dep

OUTPUT = Path(__file__).parent.parent / "vectors" / "rfc9000" / "varint.json"


def aioquic_encode(value: int) -> str:
    """Encode `value` with aioquic and return lowercase hex."""
    buf = Buffer(capacity=8)
    buf.push_uint_var(value)
    return binascii.hexlify(buf.data).decode("ascii")


def aioquic_decode(hex_bytes: str) -> int:
    """Decode hex bytes with aioquic; raises on malformed input."""
    buf = Buffer(data=binascii.unhexlify(hex_bytes))
    return buf.pull_uint_var()


def vec_encode(name: str, source: str, value: int) -> dict:
    return {
        "name": name,
        "source": source,
        "input": {"value": value},
        "expected": aioquic_encode(value),
    }


def vec_decode_only(name: str, source: str, hex_in: str, value: int) -> dict:
    return {
        "name": name,
        "source": source,
        "direction": "decode_only",
        "input": {"bytes": hex_in},
        "expected": {"value": value},
    }


def vec_error(name: str, source: str, hex_in: str) -> dict:
    return {
        "name": name,
        "source": source,
        "input": {"bytes": hex_in},
        "expected": "error",
    }


def main() -> None:
    vectors: list[dict] = []

    # Exhaustive 1-byte (0..63) — first 8 + a few boundaries.
    for v in (0, 1, 2, 3, 4, 5, 6, 7, 31, 32, 62, 63):
        vectors.append(vec_encode(f"one_byte_{v}", "exhaustive_1byte", v))

    # Boundary sweep: the 4 size-class boundaries from RFC 9000 §16.
    for v, label in [
        (64, "two_byte_low"),
        (16383, "two_byte_high"),
        (16384, "four_byte_low"),
        (1073741823, "four_byte_high"),
        (1073741824, "eight_byte_low"),
        (4611686018427387903, "eight_byte_high"),
    ]:
        vectors.append(vec_encode(label, "boundary_sweep", v))

    # Random sweep across all 4 size classes.
    rng = random.Random(0xDEADBEEF)
    size_ranges = [
        (2, 63),
        (64, 16383),
        (16384, 1073741823),
        (1073741824, 4611686018427387903),
    ]
    for cls_idx, (lo, hi) in enumerate(size_ranges):
        for k in range(5):
            v = rng.randint(lo, hi)
            vectors.append(vec_encode(f"random_cls{cls_idx}_{k}", "random_generated", v))

    # Decode-only: non-minimal encodings (aioquic accepts these).
    for hex_in, val, label in [
        ("4001", 1, "two_byte_nonmin_1"),
        ("80000001", 1, "four_byte_nonmin_1"),
        ("c000000000000001", 1, "eight_byte_nonmin_1"),
    ]:
        vectors.append(vec_decode_only(label, "gap_fill_non_minimal", hex_in, val))

    # Error vectors: short reads.
    for hex_in, label in [
        ("", "empty"),
        ("40", "two_byte_truncated"),
        ("80", "four_byte_truncated_1"),
        ("8001", "four_byte_truncated_2"),
        ("c0", "eight_byte_truncated_1"),
        ("c000000000", "eight_byte_truncated_5"),
    ]:
        # Confirm aioquic also raises.
        raised = False
        try:
            aioquic_decode(hex_in)
        except Exception:
            raised = True
        assert raised, f"expected aioquic to raise on {label!r} ({hex_in!r})"
        vectors.append(vec_error(label, "gap_fill_malformed", hex_in))

    out = json.dumps(vectors, indent=2, ensure_ascii=False)
    # Default: write to stdout for `uv run ... > file.json`.
    sys.stdout.write(out + "\n")


if __name__ == "__main__":
    main()
