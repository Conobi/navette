#!/usr/bin/env python3
"""Generate QUIC transport parameter parse vectors per RFC 9000 §18.

Usage: uv run python conformance/scripts/oracle_quic_transport_params.py
Output: conformance/vectors/rfc9000/transport_params.json

Wire format: sequence of (param_id varint, param_length varint, param_value bytes).
Integer parameters are encoded as varints within their value bytes.
"""
import json
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "vectors" / "rfc9000" / "transport_params.json"


# ── QUIC varint encoding (RFC 9000 §16) ─────────────────────────────────────

def encode_varint(value: int) -> bytes:
    if value <= 63:
        return bytes([value])
    elif value <= 16383:
        return (value | 0x4000).to_bytes(2, "big")
    elif value <= 1073741823:
        return (value | 0x80000000).to_bytes(4, "big")
    else:
        return (value | 0xC000000000000000).to_bytes(8, "big")


# ── Transport parameter helpers ──────────────────────────────────────────────

def encode_tp_integer(param_id: int, value: int) -> bytes:
    """Encode a transport parameter with a varint integer value."""
    val_bytes = encode_varint(value)
    return encode_varint(param_id) + encode_varint(len(val_bytes)) + val_bytes


def encode_tp_empty(param_id: int) -> bytes:
    """Encode a transport parameter with zero-length value (presence = true)."""
    return encode_varint(param_id) + encode_varint(0)


def encode_tp_bytes(param_id: int, value: bytes) -> bytes:
    """Encode a transport parameter with raw bytes value."""
    return encode_varint(param_id) + encode_varint(len(value)) + value


# ── ByteWriter helper ───────────────────────────────────────────────────────

class ByteWriter:
    """Tiny helper to build wire bytes incrementally."""

    def __init__(self):
        self._buf = bytearray()

    def varint(self, value: int) -> "ByteWriter":
        self._buf.extend(encode_varint(value))
        return self

    def raw(self, data: bytes) -> "ByteWriter":
        self._buf.extend(data)
        return self

    def byte(self, value: int) -> "ByteWriter":
        self._buf.append(value & 0xFF)
        return self

    def bytes(self) -> bytes:
        return bytes(self._buf)


# ── RFC 9000 §18.2 Transport Parameter IDs ──────────────────────────────────
# Param name → (param_id, default_value_or_None)
TP_IDS = {
    "original_destination_connection_id":  0x00,
    "max_idle_timeout":                    0x01,
    "stateless_reset_token":               0x02,
    "max_udp_payload_size":                0x03,
    "initial_max_data":                    0x04,
    "initial_max_stream_data_bidi_local":  0x05,
    "initial_max_stream_data_bidi_remote": 0x06,
    "initial_max_stream_data_uni":         0x07,
    "initial_max_streams_bidi":            0x08,
    "initial_max_streams_uni":             0x09,
    "ack_delay_exponent":                  0x0A,
    "max_ack_delay":                       0x0B,
    "disable_active_migration":            0x0C,
    "preferred_address":                   0x0D,
    "active_connection_id_limit":          0x0E,
    "initial_source_connection_id":        0x0F,
    "retry_source_connection_id":          0x10,
}


# ── Vector list ──────────────────────────────────────────────────────────────

vectors: list[dict] = []


def add_vector(
    id: str,
    description: str,
    wire: bytes,
    expected: dict | str,
):
    v: dict = {
        "id": id,
        "description": description,
        "wire_hex": wire.hex(),
    }
    if isinstance(expected, str) and expected == "error":
        v["expect"] = "error"
    else:
        v["expected"] = expected
    vectors.append(v)


# ── 1. All defaults — empty encoding ────────────────────────────────────────

add_vector(
    "all-defaults",
    "Empty encoding — no parameters present, all defaults apply",
    b"",
    {
        "max_idle_timeout": 0,
        "max_udp_payload_size": 65527,
        "initial_max_data": 0,
        "initial_max_stream_data_bidi_local": 0,
        "initial_max_stream_data_bidi_remote": 0,
        "initial_max_stream_data_uni": 0,
        "initial_max_streams_bidi": 0,
        "initial_max_streams_uni": 0,
        "ack_delay_exponent": 3,
        "max_ack_delay": 25,
        "disable_active_migration": False,
        "active_connection_id_limit": 2,
    },
)


# ── 2. Full params — all known integer parameters with non-default values ───

wire = b"".join([
    encode_tp_integer(0x01, 30000),    # max_idle_timeout
    encode_tp_integer(0x03, 1452),     # max_udp_payload_size
    encode_tp_integer(0x04, 1048576),  # initial_max_data (1 MiB)
    encode_tp_integer(0x05, 524288),   # initial_max_stream_data_bidi_local (512 KiB)
    encode_tp_integer(0x06, 524288),   # initial_max_stream_data_bidi_remote
    encode_tp_integer(0x07, 262144),   # initial_max_stream_data_uni (256 KiB)
    encode_tp_integer(0x08, 100),      # initial_max_streams_bidi
    encode_tp_integer(0x09, 50),       # initial_max_streams_uni
    encode_tp_integer(0x0A, 5),        # ack_delay_exponent (default=3)
    encode_tp_integer(0x0B, 50),       # max_ack_delay (default=25)
    encode_tp_empty(0x0C),             # disable_active_migration
    encode_tp_integer(0x0E, 8),        # active_connection_id_limit (default=2)
])
add_vector(
    "full-params",
    "All known integer parameters set to non-default values",
    wire,
    {
        "max_idle_timeout": 30000,
        "max_udp_payload_size": 1452,
        "initial_max_data": 1048576,
        "initial_max_stream_data_bidi_local": 524288,
        "initial_max_stream_data_bidi_remote": 524288,
        "initial_max_stream_data_uni": 262144,
        "initial_max_streams_bidi": 100,
        "initial_max_streams_uni": 50,
        "ack_delay_exponent": 5,
        "max_ack_delay": 50,
        "disable_active_migration": True,
        "active_connection_id_limit": 8,
    },
)


# ── 3. max_idle_timeout=30000 (single parameter) ────────────────────────────

wire = encode_tp_integer(0x01, 30000)
add_vector(
    "max-idle-timeout",
    "Single parameter: max_idle_timeout=30000ms",
    wire,
    {"max_idle_timeout": 30000},
)


# ── 4. disable_active_migration (zero-length value) ─────────────────────────

wire = encode_tp_empty(0x0C)
add_vector(
    "disable-active-migration",
    "disable_active_migration: zero-length value, presence = true (param_id=0x0C)",
    wire,
    {"disable_active_migration": True},
)


# ── 5. Unknown parameter (preserved in round-trip) ──────────────────────────

unknown_value = bytes.fromhex("01020304")
wire = encode_tp_bytes(0xFFFF, unknown_value)
add_vector(
    "unknown-param",
    "Unknown parameter: ID=0xFFFF, value=0x01020304 (should be preserved)",
    wire,
    {
        "unknown_parameters": [
            {
                "param_id": 0xFFFF,
                "value_hex": unknown_value.hex(),
            }
        ]
    },
)


# ── 6. original_destination_connection_id (0x00) ────────────────────────────

odcid = bytes.fromhex("0102030405060708")
wire = encode_tp_bytes(0x00, odcid)
add_vector(
    "original-dcid",
    "original_destination_connection_id (0x00): 8-byte CID value",
    wire,
    {
        "original_destination_connection_id_hex": odcid.hex(),
    },
)


# ── 7. initial_source_connection_id (0x0F) ──────────────────────────────────

iscid = bytes.fromhex("aabbccddeeff0011")
wire = encode_tp_bytes(0x0F, iscid)
add_vector(
    "initial-scid",
    "initial_source_connection_id (0x0F): 8-byte CID value",
    wire,
    {
        "initial_source_connection_id_hex": iscid.hex(),
    },
)


# ── 8. stateless_reset_token (0x02) ─────────────────────────────────────────

srt = bytes.fromhex("00112233445566778899aabbccddeeff")
wire = encode_tp_bytes(0x02, srt)
add_vector(
    "stateless-reset-token",
    "stateless_reset_token (0x02): 16 bytes",
    wire,
    {
        "stateless_reset_token_hex": srt.hex(),
    },
)


# ── 9. preferred_address (0x0D) ─────────────────────────────────────────────
# Wire format per RFC 9000 §18.2:
#   IPv4 Address (4 bytes) + IPv4 Port (2 bytes, big-endian)
#   IPv6 Address (16 bytes) + IPv6 Port (2 bytes, big-endian)
#   CID Length (1 byte) + CID (variable) + Stateless Reset Token (16 bytes)

ipv4_addr = bytes([192, 168, 1, 1])
ipv4_port = (4433).to_bytes(2, "big")
ipv6_addr = bytes([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
ipv6_port = (4434).to_bytes(2, "big")
pa_cid = bytes.fromhex("aabbccdd")
pa_token = bytes.fromhex("ffeeddccbbaa99887766554433221100")

preferred_addr_value = (
    ipv4_addr + ipv4_port
    + ipv6_addr + ipv6_port
    + bytes([len(pa_cid)]) + pa_cid
    + pa_token
)
wire = encode_tp_bytes(0x0D, preferred_addr_value)
add_vector(
    "preferred-address",
    "preferred_address (0x0D): IPv4=192.168.1.1:4433, IPv6=[2001:db8::1]:4434, CID=4B, token=16B",
    wire,
    {
        "preferred_address": {
            "ipv4_address": "192.168.1.1",
            "ipv4_port": 4433,
            "ipv6_address": "2001:0db8:0000:0000:0000:0000:0000:0001",
            "ipv6_port": 4434,
            "connection_id_length": 4,
            "connection_id_hex": pa_cid.hex(),
            "stateless_reset_token_hex": pa_token.hex(),
        }
    },
)


# ── 10. Error: duplicate parameter ──────────────────────────────────────────

wire = encode_tp_integer(0x01, 30000) + encode_tp_integer(0x01, 60000)
add_vector(
    "error-duplicate-param",
    "Duplicate parameter: max_idle_timeout appears twice — TRANSPORT_PARAMETER_ERROR",
    wire,
    "error",
)


# ── 11. Error: max_udp_payload_size < 1200 ──────────────────────────────────

wire = encode_tp_integer(0x03, 1199)
add_vector(
    "error-max-udp-payload-too-small",
    "max_udp_payload_size=1199 (< 1200 minimum) — TRANSPORT_PARAMETER_ERROR",
    wire,
    "error",
)


# ── 12. Error: ack_delay_exponent > 20 ──────────────────────────────────────

wire = encode_tp_integer(0x0A, 21)
add_vector(
    "error-ack-delay-exponent-too-large",
    "ack_delay_exponent=21 (> 20 maximum) — TRANSPORT_PARAMETER_ERROR",
    wire,
    "error",
)


# ── 13. Error: max_ack_delay >= 2^14 ────────────────────────────────────────

wire = encode_tp_integer(0x0B, 16384)
add_vector(
    "error-max-ack-delay-too-large",
    "max_ack_delay=16384 (>= 2^14) — TRANSPORT_PARAMETER_ERROR",
    wire,
    "error",
)


# ── 14. Error: active_connection_id_limit < 2 ───────────────────────────────

wire = encode_tp_integer(0x0E, 1)
add_vector(
    "error-active-cid-limit-too-small",
    "active_connection_id_limit=1 (< 2 minimum) — TRANSPORT_PARAMETER_ERROR",
    wire,
    "error",
)


# ── 15. Error: truncated value ───────────────────────────────────────────────
# param_id=0x04 (initial_max_data), length says 4 bytes but only 2 available

wire = (
    ByteWriter()
    .varint(0x04)       # param_id: initial_max_data
    .varint(4)          # length: claims 4 bytes
    .raw(b"\x80\x10")   # only 2 bytes present
    .bytes()
)
add_vector(
    "error-truncated-value",
    "Truncated value: length says 4 bytes but only 2 available",
    wire,
    "error",
)


# ── Write output ─────────────────────────────────────────────────────────────

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT, "w") as f:
    json.dump(vectors, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(f"Wrote {len(vectors)} vectors to {OUTPUT}")
