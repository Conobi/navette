#!/usr/bin/env python3
"""Generate QUIC Initial header-protection mask test vectors.

Pre-materializes the AES-128-ECB header-protection oracle so the Mojo
runtime test path no longer imports `cryptography.hazmat.primitives.ciphers`
at test time. The runtime test loads the JSON fixture this script emits
and compares its own HP mask output (or the rustls FFI output) against
the recorded `mask`.

Usage:
    uv run python conformance/scripts/oracle_hp.py \
        > conformance/vectors/rfc9001/header_protection.json

Vector record schema:
    {
        "name":   str,
        "source": str,
        "hp_key": str (hex),   # 16-byte AES-128 key
        "sample": str (hex),   # 16-byte sample drawn from the packet
        "mask":   str (hex),   #  5-byte HP mask (first 5 bytes of AES-ECB(key, sample))
    }

The §3.2 migration: emits the RFC 9001 Appendix A.2 client/server samples
plus a derived synthetic sample for round-trip coverage.
"""
from __future__ import annotations

import json
import sys

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB


# RFC 9001 A.1-derived HP keys
CLIENT_HP_KEY = bytes.fromhex("9f50449e04a0e810283a1e9933adedd2")
SERVER_HP_KEY = bytes.fromhex("c206b8d9b9f0f37644430b490eeaa314")

# RFC 9001 A.2 — the canonical client Initial sample
RFC9001_A2_CLIENT_SAMPLE = bytes.fromhex("d1b1c98dd7689fb8ec11d242b123dc9b")
# A second sample for server-side coverage (deterministic, non-RFC, used
# only to exercise the AES-ECB path end-to-end). Any 16-byte value works.
SYNTHETIC_SERVER_SAMPLE = bytes.fromhex("00112233445566778899aabbccddeeff")


def hp_mask(hp_key: bytes, sample: bytes) -> bytes:
    """AES-128-ECB(hp_key, sample), truncated to 5 bytes (RFC 9001 §5.4.3)."""
    if len(hp_key) != 16:
        raise ValueError(f"hp_key must be 16 bytes, got {len(hp_key)}")
    if len(sample) != 16:
        raise ValueError(f"sample must be 16 bytes, got {len(sample)}")
    cipher = Cipher(AES(hp_key), ECB())
    enc = cipher.encryptor()
    full_mask = enc.update(sample) + enc.finalize()
    return full_mask[:5]


def build_vectors() -> list[dict]:
    return [
        {
            "name": "client_initial_v1_header_protection",
            "source": "rfc9001_appendix_a2",
            "hp_key": CLIENT_HP_KEY.hex(),
            "sample": RFC9001_A2_CLIENT_SAMPLE.hex(),
            "mask": hp_mask(CLIENT_HP_KEY, RFC9001_A2_CLIENT_SAMPLE).hex(),
        },
        {
            "name": "server_initial_v1_header_protection_synthetic",
            "source": "computed_from_rfc9001_keys",
            "hp_key": SERVER_HP_KEY.hex(),
            "sample": SYNTHETIC_SERVER_SAMPLE.hex(),
            "mask": hp_mask(SERVER_HP_KEY, SYNTHETIC_SERVER_SAMPLE).hex(),
        },
    ]


def main() -> int:
    vectors = build_vectors()
    json.dump(vectors, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
