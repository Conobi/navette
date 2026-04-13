#!/usr/bin/env python3
"""Generate QUIC packet header parse vectors using aioquic as oracle.

Usage: uv run --project .. python3 conformance/scripts/oracle_quic_packet.py
Output: conformance/vectors/rfc9000/packet_header.json

Requires: aioquic>=0.9.25

API note (verified against installed version):
  pull_quic_header(buf: Buffer, host_cid_length: int | None = None) -> QuicHeader
  packet_type is a QuicPacketType enum — use .name.lower() for string mapping.
"""
import json
from pathlib import Path

try:
    from aioquic.quic.packet import pull_quic_header
    from aioquic._buffer import Buffer as AioBuffer
except ImportError:
    print("ERROR: aioquic not installed. Run: uv add aioquic")
    raise

OUTPUT = Path(__file__).parent.parent / "vectors" / "rfc9000" / "packet_header.json"

QUIC_V1 = b"\x00\x00\x00\x01"
HOST_CID_LEN = 8


def oracle_parse(wire: bytes, host_cid_len: int = HOST_CID_LEN) -> dict | None:
    """Call aioquic pull_quic_header. Returns parsed fields or None on error."""
    try:
        buf = AioBuffer(data=wire)
        h = pull_quic_header(buf, host_cid_length=host_cid_len)
        # packet_type: QuicPacketType enum — use .name.lower() for a clean string
        try:
            pt = h.packet_type.name.lower()
        except AttributeError:
            pt = str(h.packet_type)
        result = {
            "is_long_header": h.version is not None,
            "version": h.version if h.version is not None else 0,
            "packet_type": pt,
            "destination_cid_hex": h.destination_cid.hex(),
            "source_cid_hex": h.source_cid.hex() if h.source_cid else "",
            "token_hex": h.token.hex() if h.token else "",
        }
        # packet_length present on all QuicHeader objects in this version
        if hasattr(h, "packet_length") and h.packet_length is not None:
            result["packet_length"] = h.packet_length
        return result
    except Exception:
        return None  # error vector


def make_initial(dcid: bytes, scid: bytes = b"", token: bytes = b"", payload_len: int = 20) -> bytes:
    """Build a minimal QUIC v1 Initial packet wire encoding (no AEAD, just structure)."""
    # First byte: 0xC0 | reserved=00 | pn_len=00 → 0xC0 (1-byte PN)
    first = 0xC0
    # length = varint encoding of (1-byte PN + payload_len)
    total_payload = 1 + payload_len
    if total_payload < 64:
        len_varint = bytes([total_payload])
    else:
        len_varint = bytes([0x40 | (total_payload >> 8), total_payload & 0xFF])
    # Token length varint
    tok_len_varint = bytes([len(token)])  # assume < 64 bytes
    return (
        bytes([first]) + QUIC_V1
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
        + tok_len_varint + token
        + len_varint
        + bytes([0x00])   # packet number = 0
        + bytes(payload_len)  # zeroed payload region
    )


def make_handshake(dcid: bytes, scid: bytes = b"", payload_len: int = 20) -> bytes:
    first = 0xE0  # long header, fixed=1, Handshake type=10, reserved=00, pn_len=00
    total_payload = 1 + payload_len
    len_varint = bytes([total_payload]) if total_payload < 64 else bytes([0x40 | (total_payload >> 8), total_payload & 0xFF])
    return (
        bytes([first]) + QUIC_V1
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
        + len_varint
        + bytes([0x00]) + bytes(payload_len)
    )


def make_zero_rtt(dcid: bytes, scid: bytes = b"", payload_len: int = 20) -> bytes:
    first = 0xD0  # long header, fixed=1, 0-RTT type=01, reserved=00, pn_len=00
    total_payload = 1 + payload_len
    len_varint = bytes([total_payload]) if total_payload < 64 else bytes([0x40 | (total_payload >> 8), total_payload & 0xFF])
    return (
        bytes([first]) + QUIC_V1
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
        + len_varint
        + bytes([0x00]) + bytes(payload_len)
    )


def make_retry(dcid: bytes, scid: bytes, token: bytes) -> bytes:
    first = 0xF0  # long header, fixed=1, Retry type=11, unused=00
    # Retry integrity tag (16 zero bytes for structure test — not a real tag)
    integrity_tag = bytes(16)
    return (
        bytes([first]) + QUIC_V1
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
        + token
        + integrity_tag
    )


def make_short(dcid: bytes, key_phase: int = 0, spin: int = 0) -> bytes:
    # Short header: 0=long/short, 1=fixed, spin, 0=reserved, 0=reserved, key_phase, 00=pn_len
    first = 0x40 | (spin << 5) | (key_phase << 2) | 0x00  # 1-byte PN
    return bytes([first]) + dcid + bytes([0x00])  # PN=0


# ── Build vectors ────────────────────────────────────────────────────────────

DCID8  = bytes.fromhex("8394c8f03e515708")
DCID4  = bytes.fromhex("deadbeef")
SCID8  = bytes.fromhex("0102030405060708")
TOKEN4 = bytes.fromhex("cafebabe")

vectors = []


def add(name: str, category: str, rfc: str, desc: str, wire: bytes, hcl: int = HOST_CID_LEN):
    result = oracle_parse(wire, hcl)
    if result is None:
        v = {
            "id": name, "category": "error", "rfc_section": rfc,
            "description": desc + " [oracle parse failed]",
            "input": {"wire_hex": wire.hex(), "host_cid_length": hcl},
            "expected": {"behavior": "reject"}
        }
    else:
        v = {
            "id": name, "category": category, "rfc_section": rfc,
            "description": desc,
            "input": {"wire_hex": wire.hex(), "host_cid_length": hcl},
            "expected": result
        }
    vectors.append(v)


# Long-header Initial (5 vectors)
add("qc1-pkt-initial-dcid8-scid0-no-token",    "long-header-initial", "RFC 9000 §17.2.2", "Initial, DCID=8, SCID=0, no token",  make_initial(DCID8))
add("qc1-pkt-initial-dcid8-scid8-no-token",    "long-header-initial", "RFC 9000 §17.2.2", "Initial, DCID=8, SCID=8, no token",  make_initial(DCID8, SCID8))
add("qc1-pkt-initial-dcid8-scid8-token4",      "long-header-initial", "RFC 9000 §17.2.2", "Initial, DCID=8, SCID=8, token=4B", make_initial(DCID8, SCID8, TOKEN4))
add("qc1-pkt-initial-dcid4-scid0-no-token",    "long-header-initial", "RFC 9000 §17.2.2", "Initial, DCID=4, SCID=0, no token",  make_initial(DCID4), hcl=4)
add("qc1-pkt-initial-dcid0-scid0-no-token",    "long-header-initial", "RFC 9000 §17.2.2", "Initial, DCID=0, SCID=0, no token",  make_initial(b""))

# Long-header Handshake (3 vectors)
add("qc1-pkt-handshake-dcid8-scid8",           "long-header-handshake", "RFC 9000 §17.2.4", "Handshake, DCID=8, SCID=8",          make_handshake(DCID8, SCID8))
add("qc1-pkt-handshake-dcid8-scid0",           "long-header-handshake", "RFC 9000 §17.2.4", "Handshake, DCID=8, SCID=0",          make_handshake(DCID8))
add("qc1-pkt-handshake-dcid4-scid4",           "long-header-handshake", "RFC 9000 §17.2.4", "Handshake, DCID=4, SCID=4",          make_handshake(DCID4, DCID4), hcl=4)

# Long-header 0-RTT (3 vectors)
add("qc1-pkt-zero-rtt-dcid8-scid8",            "long-header-zero-rtt", "RFC 9000 §17.2.3", "0-RTT, DCID=8, SCID=8",              make_zero_rtt(DCID8, SCID8))
add("qc1-pkt-zero-rtt-dcid8-scid0",            "long-header-zero-rtt", "RFC 9000 §17.2.3", "0-RTT, DCID=8, SCID=0",              make_zero_rtt(DCID8))
add("qc1-pkt-zero-rtt-dcid4-scid4",            "long-header-zero-rtt", "RFC 9000 §17.2.3", "0-RTT, DCID=4, SCID=4",              make_zero_rtt(DCID4, DCID4), hcl=4)

# Long-header Retry (2 vectors)
add("qc1-pkt-retry-dcid8-scid8-token4",        "long-header-retry", "RFC 9000 §17.2.5", "Retry, DCID=8, SCID=8, token=4B",    make_retry(DCID8, SCID8, TOKEN4))
add("qc1-pkt-retry-dcid8-scid4-token8",        "long-header-retry", "RFC 9000 §17.2.5", "Retry, DCID=8, SCID=4, token=8B",    make_retry(DCID8, DCID4, bytes(8)))

# Short-header 1-RTT (5 vectors)
add("qc1-pkt-short-dcid8-kp0-spin0",           "short-header-one-rtt", "RFC 9000 §17.3.1", "1-RTT, DCID=8, key_phase=0, spin=0", make_short(DCID8, key_phase=0, spin=0))
add("qc1-pkt-short-dcid8-kp1-spin0",           "short-header-one-rtt", "RFC 9000 §17.3.1", "1-RTT, DCID=8, key_phase=1, spin=0", make_short(DCID8, key_phase=1, spin=0))
add("qc1-pkt-short-dcid8-kp0-spin1",           "short-header-one-rtt", "RFC 9000 §17.3.1", "1-RTT, DCID=8, key_phase=0, spin=1", make_short(DCID8, key_phase=0, spin=1))
add("qc1-pkt-short-dcid0-kp0-spin0",           "short-header-one-rtt", "RFC 9000 §17.3.1", "1-RTT, DCID=0, key_phase=0, spin=0", make_short(b""), hcl=0)
add("qc1-pkt-short-dcid4-kp0-spin0",           "short-header-one-rtt", "RFC 9000 §17.3.1", "1-RTT, DCID=4, key_phase=0, spin=0", make_short(DCID4), hcl=4)

# Error / truncated (2 vectors)
add("qc1-pkt-truncated-3-bytes",               "error", "RFC 9000 §17.2", "Truncated — only 3 bytes",                   bytes.fromhex("c00000"))
add("qc1-pkt-truncated-initial-mid-dcid",      "error", "RFC 9000 §17.2", "Truncated long header — mid-DCID",           bytes.fromhex("c000000001084444"))

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT, "w") as f:
    json.dump(vectors, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(f"Wrote {len(vectors)} vectors to {OUTPUT}")
