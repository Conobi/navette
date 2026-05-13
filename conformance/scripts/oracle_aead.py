#!/usr/bin/env python3
"""Generate AEAD-AES-128-GCM test vectors.

Pre-materializes the AEAD oracle so the Mojo runtime test path no longer
imports `cryptography.hazmat.primitives.ciphers.aead` at test time. The
runtime test loads the JSON fixture this script emits and compares its
own AEAD output against the recorded `ciphertext` + `tag`.

Usage:
    uv run python conformance/scripts/oracle_aead.py \
        > conformance/vectors/rfc9001/aead.json

Vector record schema:
    {
        "name":       str,
        "source":     str,
        "operation":  "aead_encrypt" | "aead_decrypt",
        "key":        str (hex),
        "nonce":      str (hex),       # full 12-byte IV (PN=0 so IV XOR 0 = IV)
        "aad":        str (hex),
        "plaintext":  str (hex),
        "ciphertext": str (hex),       # encrypted bytes (no tag)
        "tag":        str (hex),       # 16-byte GCM authentication tag
        "ct_and_tag": str (hex),       # convenience: ciphertext || tag
    }

The §3.2 migration: emits AEAD round-trip vectors using the RFC 9001 A.1
client/server initial keys, plus a small payload for cross-validation.
"""
from __future__ import annotations

import json
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# RFC 9001 A.1 derived keys (computed by oracle_hkdf.py; baked in here so
# this script is self-contained and re-runnable in isolation).
CLIENT_KEY  = bytes.fromhex("1f369613dd76d5467730efcbe3b1a22d")
CLIENT_IV   = bytes.fromhex("fa044b2f42a3fd3b46fb255c")
SERVER_KEY  = bytes.fromhex("cf3a5331653c364c88f0f379b6067e37")
SERVER_IV   = bytes.fromhex("0ac1493ca1905853b0bba03e")

# A QUIC-shaped AAD: long-header form, version=1, dcid_len=8, dcid="8394c8f03e515708"
# Same value as the existing initial_protection.json vector → cross-test compat.
AAD_BYTES = bytes.fromhex("c000000001088394c8f03e515708")
PLAINTEXT = b"qc1-aead-conformance-test"


def aead_encrypt_vector(name: str, key: bytes, iv: bytes, aad: bytes,
                        plaintext: bytes) -> dict:
    """Encrypt and emit a record. With PN=0, nonce = IV XOR 0 = IV."""
    nonce = iv
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    # AES-GCM tag is the trailing 16 bytes.
    ct = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]
    return {
        "name": name,
        "source": "computed_from_rfc9001_keys",
        "operation": "aead_encrypt",
        "key": key.hex(),
        "nonce": nonce.hex(),
        "aad": aad.hex(),
        "plaintext": plaintext.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
        "ct_and_tag": ct_and_tag.hex(),
    }


def aead_decrypt_vector(name: str, key: bytes, iv: bytes, aad: bytes,
                        plaintext: bytes) -> dict:
    """Build a decrypt-direction vector. Same crypto, different `operation`."""
    nonce = iv
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    ct = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]
    return {
        "name": name,
        "source": "computed_from_rfc9001_keys",
        "operation": "aead_decrypt",
        "key": key.hex(),
        "nonce": nonce.hex(),
        "aad": aad.hex(),
        "plaintext": plaintext.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
        "ct_and_tag": ct_and_tag.hex(),
    }


def build_vectors() -> list[dict]:
    return [
        aead_encrypt_vector("client_initial_v1_aead_encrypt",
                            CLIENT_KEY, CLIENT_IV, AAD_BYTES, PLAINTEXT),
        aead_decrypt_vector("client_initial_v1_aead_decrypt",
                            CLIENT_KEY, CLIENT_IV, AAD_BYTES, PLAINTEXT),
        aead_encrypt_vector("server_initial_v1_aead_encrypt",
                            SERVER_KEY, SERVER_IV, AAD_BYTES, PLAINTEXT),
        aead_decrypt_vector("server_initial_v1_aead_decrypt",
                            SERVER_KEY, SERVER_IV, AAD_BYTES, PLAINTEXT),
    ]


def main() -> int:
    vectors = build_vectors()
    json.dump(vectors, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
