#!/usr/bin/env python3
"""Generate QUIC v1 Initial-keys derivation test vectors (RFC 9001 §5).

Pre-materializes the full RFC 9001 Initial-keys ladder so the Mojo runtime
test path no longer re-derives them from `cryptography.hazmat` at test
time. The runtime test loads the JSON fixture this script emits and
compares its own derivation (or the rustls FFI output) against the
recorded `key`, `iv`, `hp`.

Usage:
    uv run python conformance/scripts/oracle_initial.py \
        > conformance/vectors/rfc9001/initial_keys.json

Vector record schema:
    {
        "name":   str,
        "source": str,
        "version": "v1",
        "cid":     str (hex),   # destination CID (HKDF-Extract `ikm`)
        "role":    "client" | "server",
        "initial_secret":      str (hex),  # HKDF-Extract(salt_v1, cid)
        "client_initial_secret": str (hex),
        "server_initial_secret": str (hex),
        "key":     str (hex),   # 16 bytes (AES-128-GCM)
        "iv":      str (hex),   # 12 bytes
        "hp":      str (hex),   # 16 bytes (AES-128 HP key)
    }

The §3.2 migration: emits per-role derivation vectors. test_rustls_initial
and test_cross_initial_crypto can read these to validate rustls' output
against a pre-computed oracle without importing cryptography at test time.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


# QUIC v1 Initial salt (RFC 9001 §5.2)
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
# RFC 9001 A.1 dcid
RFC9001_A1_DCID = bytes.fromhex("8394c8f03e515708")


def hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full_label = ("tls13 " + label).encode("ascii")
    info = (
        struct.pack(">H", length)
        + struct.pack("B", len(full_label))
        + full_label
        + struct.pack("B", 0)
    )
    kdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return kdf.derive(secret)


def derive_initial_keys(dcid: bytes) -> dict:
    """Run the full RFC 9001 §5 Initial-keys ladder for `dcid`.

    Returns a dict with all intermediates (initial_secret, per-role
    secrets, per-role key/iv/hp) hex-encoded.
    """
    initial_secret = hmac.new(INITIAL_SALT_V1, dcid, hashlib.sha256).digest()

    client_secret = hkdf_expand_label(initial_secret, "client in", 32)
    server_secret = hkdf_expand_label(initial_secret, "server in", 32)

    client_key = hkdf_expand_label(client_secret, "quic key", 16)
    client_iv  = hkdf_expand_label(client_secret, "quic iv", 12)
    client_hp  = hkdf_expand_label(client_secret, "quic hp", 16)

    server_key = hkdf_expand_label(server_secret, "quic key", 16)
    server_iv  = hkdf_expand_label(server_secret, "quic iv", 12)
    server_hp  = hkdf_expand_label(server_secret, "quic hp", 16)

    return {
        "initial_secret": initial_secret.hex(),
        "client_initial_secret": client_secret.hex(),
        "server_initial_secret": server_secret.hex(),
        "client_key": client_key.hex(),
        "client_iv":  client_iv.hex(),
        "client_hp":  client_hp.hex(),
        "server_key": server_key.hex(),
        "server_iv":  server_iv.hex(),
        "server_hp":  server_hp.hex(),
    }


def build_vectors() -> list[dict]:
    derived = derive_initial_keys(RFC9001_A1_DCID)
    base = {
        "source": "rfc9001_appendix_a1",
        "version": "v1",
        "cid": RFC9001_A1_DCID.hex(),
        "initial_secret": derived["initial_secret"],
        "client_initial_secret": derived["client_initial_secret"],
        "server_initial_secret": derived["server_initial_secret"],
    }
    return [
        {
            **base,
            "name": "rfc9001_a1_client_initial_keys",
            "role": "client",
            "key": derived["client_key"],
            "iv":  derived["client_iv"],
            "hp":  derived["client_hp"],
        },
        {
            **base,
            "name": "rfc9001_a1_server_initial_keys",
            "role": "server",
            "key": derived["server_key"],
            "iv":  derived["server_iv"],
            "hp":  derived["server_hp"],
        },
    ]


def main() -> int:
    vectors = build_vectors()
    json.dump(vectors, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
