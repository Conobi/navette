#!/usr/bin/env python3
"""Generate HKDF-Expand-Label (TLS 1.3 / RFC 9001) test vectors.

Pre-materializes the HKDF oracle so the Mojo runtime test path no longer
imports `cryptography.hazmat.primitives.kdf.hkdf` at test time. The
runtime test loads the JSON fixture this script emits and compares its
own HKDF output (or the rustls FFI output) against the recorded `okm`.

Usage:
    uv run python conformance/scripts/oracle_hkdf.py \
        > conformance/vectors/rfc9001/hkdf.json

Vector record schema:
    {
        "name":   str,              # human-readable label
        "source": str,              # citation
        "prk":    str (hex),        # pseudo-random key input
        "label":  str,              # raw label without the "tls13 " prefix
        "length": int,              # output length in octets
        "okm":    str (hex),        # output keying material
    }

The §3.2 migration: emits derivation results for the RFC 9001 Appendix A.1
QUIC v1 Initial keying ladder (client/server initial secrets, key, iv, hp).
"""
from __future__ import annotations

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
    """TLS 1.3 / RFC 9001 §5.1 HKDF-Expand-Label.

    HkdfLabel = uint16(length) || uint8(len("tls13 " + label)) || "tls13 " + label || uint8(0)
    """
    full_label = ("tls13 " + label).encode("ascii")
    info = (
        struct.pack(">H", length)
        + struct.pack("B", len(full_label))
        + full_label
        + struct.pack("B", 0)
    )
    kdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return kdf.derive(secret)


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract = HMAC-SHA256(salt, ikm)."""
    import hmac
    import hashlib
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def build_vectors() -> list[dict]:
    vectors: list[dict] = []

    # Step 0: derive initial_secret from salt + dcid
    initial_secret = hkdf_extract_sha256(INITIAL_SALT_V1, RFC9001_A1_DCID)

    # Step 1: client/server initial secrets (length=32, SHA256.digest_size)
    client_initial_secret = hkdf_expand_label(initial_secret, "client in", 32)
    server_initial_secret = hkdf_expand_label(initial_secret, "server in", 32)

    vectors.append({
        "name": "rfc9001_a1_client_in",
        "source": "rfc9001_appendix_a1",
        "prk": initial_secret.hex(),
        "label": "client in",
        "length": 32,
        "okm": client_initial_secret.hex(),
    })
    vectors.append({
        "name": "rfc9001_a1_server_in",
        "source": "rfc9001_appendix_a1",
        "prk": initial_secret.hex(),
        "label": "server in",
        "length": 32,
        "okm": server_initial_secret.hex(),
    })

    # Step 2: key/iv/hp from client_initial_secret
    for label, length in (("quic key", 16), ("quic iv", 12), ("quic hp", 16)):
        okm = hkdf_expand_label(client_initial_secret, label, length)
        vectors.append({
            "name": f"rfc9001_a1_client_{label.replace(' ', '_')}",
            "source": "rfc9001_appendix_a1",
            "prk": client_initial_secret.hex(),
            "label": label,
            "length": length,
            "okm": okm.hex(),
        })

    # Step 3: key/iv/hp from server_initial_secret
    for label, length in (("quic key", 16), ("quic iv", 12), ("quic hp", 16)):
        okm = hkdf_expand_label(server_initial_secret, label, length)
        vectors.append({
            "name": f"rfc9001_a1_server_{label.replace(' ', '_')}",
            "source": "rfc9001_appendix_a1",
            "prk": server_initial_secret.hex(),
            "label": label,
            "length": length,
            "okm": okm.hex(),
        })

    return vectors


def main() -> int:
    vectors = build_vectors()
    json.dump(vectors, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
