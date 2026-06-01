#!/usr/bin/env python3
"""Generate QUIC frame parse vectors by constructing wire bytes per RFC 9000 §19.

Usage: uv run python conformance/scripts/oracle_quic_frame.py
Output: conformance/vectors/rfc9000/frame.json

Wire bytes are built manually (byte-by-byte) from the RFC wire format.
No aioquic frame serialization is used.
"""
import json
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "vectors" / "rfc9000" / "frame.json"


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


# ── Vector list ──────────────────────────────────────────────────────────────

vectors: list[dict] = []


def add_vector(
    id: str,
    frame_type: str,
    description: str,
    wire: bytes,
    expected: dict | str,
):
    v: dict = {
        "id": id,
        "frame_type": frame_type,
        "description": description,
        "wire_hex": wire.hex(),
    }
    if isinstance(expected, str) and expected == "error":
        v["expect"] = "error"
    else:
        v["expected"] = expected
    vectors.append(v)


# ── Simple frames (no payload) ──────────────────────────────────────────────

# PADDING (0x00) — single zero byte
add_vector(
    "padding-single",
    "PADDING",
    "Single PADDING frame (one zero byte)",
    b"\x00",
    {"frame_type_value": 0},
)

# PING (0x01) — single byte
add_vector(
    "ping",
    "PING",
    "PING frame (single byte 0x01)",
    b"\x01",
    {"frame_type_value": 1},
)

# HANDSHAKE_DONE (0x1E) — single byte
add_vector(
    "handshake-done",
    "HANDSHAKE_DONE",
    "HANDSHAKE_DONE frame (single byte 0x1E)",
    b"\x1e",
    {"frame_type_value": 0x1E},
)


# ── ACK frames (0x02/0x03) ──────────────────────────────────────────────────

# ACK with 0 additional ranges: largest=100, delay=25, range_count=0, first_range=10
wire = ByteWriter().varint(0x02).varint(100).varint(25).varint(0).varint(10).bytes()
add_vector(
    "ack-no-ranges",
    "ACK",
    "ACK with 0 additional ranges (largest=100, delay=25, first_range=10)",
    wire,
    {
        "largest_ack": 100,
        "ack_delay": 25,
        "ack_range_count": 0,
        "first_ack_range": 10,
        "ack_ranges": [],
    },
)

# ACK with 2 additional ranges
# Acked: [90..100], then gap=5 → skip 86..90 (gap encoding: gap=4 means 5 unacked),
# range [80..85] (ack=5 means 6 packets), then gap=9 → skip 70..79,
# range [60..69] (ack=9 means 10 packets)
wire = (
    ByteWriter()
    .varint(0x02)    # type
    .varint(100)     # largest_ack
    .varint(25)      # ack_delay
    .varint(2)       # ack_range_count
    .varint(10)      # first_ack_range (acks 90..100)
    .varint(4)       # gap (skip 5 packets: 85..89)
    .varint(5)       # ack (ack 6 packets: 79..84)
    .varint(9)       # gap (skip 10 packets: 69..78)
    .varint(9)       # ack (ack 10 packets: 59..68)
    .bytes()
)
add_vector(
    "ack-two-ranges",
    "ACK",
    "ACK with 2 additional ranges, no ECN",
    wire,
    {
        "largest_ack": 100,
        "ack_delay": 25,
        "ack_range_count": 2,
        "first_ack_range": 10,
        "ack_ranges": [
            {"gap": 4, "ack_range": 5},
            {"gap": 9, "ack_range": 9},
        ],
    },
)

# ACK_ECN (0x03) with ECN counts
wire = (
    ByteWriter()
    .varint(0x03)    # type (ACK_ECN)
    .varint(100)     # largest_ack
    .varint(25)      # ack_delay
    .varint(0)       # ack_range_count
    .varint(10)      # first_ack_range
    .varint(50)      # ECT0 count
    .varint(20)      # ECT1 count
    .varint(5)       # ECN-CE count
    .bytes()
)
add_vector(
    "ack-ecn",
    "ACK_ECN",
    "ACK_ECN (0x03) with ECN counts (ect0=50, ect1=20, ecn_ce=5)",
    wire,
    {
        "largest_ack": 100,
        "ack_delay": 25,
        "ack_range_count": 0,
        "first_ack_range": 10,
        "ack_ranges": [],
        "ect0_count": 50,
        "ect1_count": 20,
        "ecn_ce_count": 5,
    },
)

# Error: first_ack_range > largest_ack (underflow)
wire = (
    ByteWriter()
    .varint(0x02)
    .varint(10)      # largest_ack = 10
    .varint(0)       # ack_delay
    .varint(0)       # ack_range_count
    .varint(20)      # first_ack_range = 20 > largest_ack → underflow
    .bytes()
)
add_vector(
    "ack-first-range-exceeds-largest",
    "ACK",
    "first_ack_range > largest_ack (underflow)",
    wire,
    "error",
)


# ── CRYPTO frames (0x06) ────────────────────────────────────────────────────

# CRYPTO: offset=0, 4 bytes data
crypto_data = bytes.fromhex("deadbeef")
wire = (
    ByteWriter()
    .varint(0x06)
    .varint(0)               # offset
    .varint(len(crypto_data))  # length
    .raw(crypto_data)
    .bytes()
)
add_vector(
    "crypto-offset0-4bytes",
    "CRYPTO",
    "CRYPTO frame: offset=0, 4 bytes of data",
    wire,
    {
        "offset": 0,
        "length": 4,
        "data_hex": crypto_data.hex(),
    },
)

# CRYPTO: offset=100, empty data (length=0)
wire = ByteWriter().varint(0x06).varint(100).varint(0).bytes()
add_vector(
    "crypto-offset100-empty",
    "CRYPTO",
    "CRYPTO frame: offset=100, empty data (length=0)",
    wire,
    {
        "offset": 100,
        "length": 0,
        "data_hex": "",
    },
)


# ── STREAM frames (0x08–0x0F) ───────────────────────────────────────────────
# Bit layout: 0b00001xxx where xxx = OFF | LEN | FIN

stream_data = bytes.fromhex("48454c4c4f")  # "HELLO"
stream_id = 4

# STREAM (0x08): base type, no flags — data to end of frame
wire = ByteWriter().varint(0x08).varint(stream_id).raw(stream_data).bytes()
add_vector(
    "stream-base-no-flags",
    "STREAM",
    "STREAM (0x08): base type, no OFF/LEN/FIN, data to end of frame",
    wire,
    {
        "stream_id": stream_id,
        "offset": 0,
        "length": len(stream_data),
        "fin": False,
        "has_offset": False,
        "has_length": False,
        "data_hex": stream_data.hex(),
    },
)

# STREAM (0x0A): OFF bit set (offset present), no LEN, no FIN
# 0x0A = 0b00001010 → OFF=1, LEN=0, FIN=0
wire = ByteWriter().varint(0x0A).varint(stream_id).varint(100).raw(stream_data).bytes()
add_vector(
    "stream-off",
    "STREAM",
    "STREAM (0x0A): OFF bit set (offset=100), data to end of frame",
    wire,
    {
        "stream_id": stream_id,
        "offset": 100,
        "length": len(stream_data),
        "fin": False,
        "has_offset": True,
        "has_length": False,
        "data_hex": stream_data.hex(),
    },
)

# STREAM (0x0B): OFF+FIN bits set
# 0x0B = 0b00001011 → OFF=1, LEN=0, FIN=1
wire = ByteWriter().varint(0x0B).varint(stream_id).varint(200).raw(stream_data).bytes()
add_vector(
    "stream-off-fin",
    "STREAM",
    "STREAM (0x0B): OFF+FIN bits set (offset=200), data to end of frame",
    wire,
    {
        "stream_id": stream_id,
        "offset": 200,
        "length": len(stream_data),
        "fin": True,
        "has_offset": True,
        "has_length": False,
        "data_hex": stream_data.hex(),
    },
)

# STREAM (0x0E): LEN+OFF bits set (explicit length)
# 0x0E = 0b00001110 → OFF=1, LEN=1, FIN=0
wire = (
    ByteWriter()
    .varint(0x0E)
    .varint(stream_id)
    .varint(300)                 # offset
    .varint(len(stream_data))    # length
    .raw(stream_data)
    .bytes()
)
add_vector(
    "stream-off-len",
    "STREAM",
    "STREAM (0x0E): OFF+LEN bits set (offset=300, length=5)",
    wire,
    {
        "stream_id": stream_id,
        "offset": 300,
        "length": len(stream_data),
        "fin": False,
        "has_offset": True,
        "has_length": True,
        "data_hex": stream_data.hex(),
    },
)

# STREAM (0x0F): all flags (OFF+LEN+FIN)
# 0x0F = 0b00001111 → OFF=1, LEN=1, FIN=1
wire = (
    ByteWriter()
    .varint(0x0F)
    .varint(stream_id)
    .varint(400)                 # offset
    .varint(len(stream_data))    # length
    .raw(stream_data)
    .bytes()
)
add_vector(
    "stream-off-len-fin",
    "STREAM",
    "STREAM (0x0F): all flags OFF+LEN+FIN (offset=400, length=5)",
    wire,
    {
        "stream_id": stream_id,
        "offset": 400,
        "length": len(stream_data),
        "fin": True,
        "has_offset": True,
        "has_length": True,
        "data_hex": stream_data.hex(),
    },
)

# STREAM with empty data + FIN (legal)
# 0x0B = OFF+FIN, no LEN
wire = ByteWriter().varint(0x0B).varint(stream_id).varint(500).bytes()
add_vector(
    "stream-empty-fin",
    "STREAM",
    "STREAM with empty data + FIN (legal, signals end of stream)",
    wire,
    {
        "stream_id": stream_id,
        "offset": 500,
        "length": 0,
        "fin": True,
        "has_offset": True,
        "has_length": False,
        "data_hex": "",
    },
)


# ── Flow control frames ─────────────────────────────────────────────────────

# MAX_DATA (0x10): maximum=1048576
wire = ByteWriter().varint(0x10).varint(1048576).bytes()
add_vector(
    "max-data",
    "MAX_DATA",
    "MAX_DATA: maximum=1048576 (1 MiB)",
    wire,
    {"maximum": 1048576},
)

# MAX_STREAM_DATA (0x11): stream_id=4, maximum=524288
wire = ByteWriter().varint(0x11).varint(4).varint(524288).bytes()
add_vector(
    "max-stream-data",
    "MAX_STREAM_DATA",
    "MAX_STREAM_DATA: stream_id=4, maximum=524288 (512 KiB)",
    wire,
    {"stream_id": 4, "maximum": 524288},
)

# MAX_STREAMS_BIDI (0x12): maximum=100
wire = ByteWriter().varint(0x12).varint(100).bytes()
add_vector(
    "max-streams-bidi",
    "MAX_STREAMS_BIDI",
    "MAX_STREAMS (bidi): maximum=100",
    wire,
    {"maximum": 100},
)

# MAX_STREAMS_UNI (0x13): maximum=50
wire = ByteWriter().varint(0x13).varint(50).bytes()
add_vector(
    "max-streams-uni",
    "MAX_STREAMS_UNI",
    "MAX_STREAMS (uni): maximum=50",
    wire,
    {"maximum": 50},
)

# DATA_BLOCKED (0x14): maximum=1048576
wire = ByteWriter().varint(0x14).varint(1048576).bytes()
add_vector(
    "data-blocked",
    "DATA_BLOCKED",
    "DATA_BLOCKED: maximum=1048576 (limit at which blocking occurred)",
    wire,
    {"maximum": 1048576},
)

# STREAM_DATA_BLOCKED (0x15): stream_id=4, maximum=524288
wire = ByteWriter().varint(0x15).varint(4).varint(524288).bytes()
add_vector(
    "stream-data-blocked",
    "STREAM_DATA_BLOCKED",
    "STREAM_DATA_BLOCKED: stream_id=4, maximum=524288",
    wire,
    {"stream_id": 4, "maximum": 524288},
)

# STREAMS_BLOCKED_BIDI (0x16): maximum=100
wire = ByteWriter().varint(0x16).varint(100).bytes()
add_vector(
    "streams-blocked-bidi",
    "STREAMS_BLOCKED_BIDI",
    "STREAMS_BLOCKED (bidi): maximum=100",
    wire,
    {"maximum": 100},
)

# STREAMS_BLOCKED_UNI (0x17): maximum=50
wire = ByteWriter().varint(0x17).varint(50).bytes()
add_vector(
    "streams-blocked-uni",
    "STREAMS_BLOCKED_UNI",
    "STREAMS_BLOCKED (uni): maximum=50",
    wire,
    {"maximum": 50},
)


# ── Stream lifecycle frames ─────────────────────────────────────────────────

# RESET_STREAM (0x04): stream_id=4, error_code=0x42, final_size=1000
wire = ByteWriter().varint(0x04).varint(4).varint(0x42).varint(1000).bytes()
add_vector(
    "reset-stream",
    "RESET_STREAM",
    "RESET_STREAM: stream_id=4, error_code=0x42, final_size=1000",
    wire,
    {"stream_id": 4, "error_code": 0x42, "final_size": 1000},
)

# STOP_SENDING (0x05): stream_id=4, error_code=0x42
wire = ByteWriter().varint(0x05).varint(4).varint(0x42).bytes()
add_vector(
    "stop-sending",
    "STOP_SENDING",
    "STOP_SENDING: stream_id=4, error_code=0x42",
    wire,
    {"stream_id": 4, "error_code": 0x42},
)


# ── Connection management frames ────────────────────────────────────────────

# NEW_CONNECTION_ID (0x18): seq=1, retire=0, 8-byte CID, 16-byte reset token
cid_bytes = bytes.fromhex("0102030405060708")
reset_token = bytes.fromhex("00112233445566778899aabbccddeeff")
wire = (
    ByteWriter()
    .varint(0x18)
    .varint(1)                 # sequence_number
    .varint(0)                 # retire_prior_to
    .byte(len(cid_bytes))      # CID length (1 byte, not varint)
    .raw(cid_bytes)
    .raw(reset_token)
    .bytes()
)
add_vector(
    "new-connection-id",
    "NEW_CONNECTION_ID",
    "NEW_CONNECTION_ID: seq=1, retire=0, 8-byte CID, 16-byte reset token",
    wire,
    {
        "sequence_number": 1,
        "retire_prior_to": 0,
        "connection_id_length": 8,
        "connection_id_hex": cid_bytes.hex(),
        "stateless_reset_token_hex": reset_token.hex(),
    },
)

# RETIRE_CONNECTION_ID (0x19): seq=0
wire = ByteWriter().varint(0x19).varint(0).bytes()
add_vector(
    "retire-connection-id",
    "RETIRE_CONNECTION_ID",
    "RETIRE_CONNECTION_ID: sequence_number=0",
    wire,
    {"sequence_number": 0},
)

# CONNECTION_CLOSE transport (0x1C): error=0x0A, frame_type=0x06, reason="test"
reason_bytes = b"test"
wire = (
    ByteWriter()
    .varint(0x1C)
    .varint(0x0A)               # error_code
    .varint(0x06)               # frame_type
    .varint(len(reason_bytes))  # reason_phrase_length
    .raw(reason_bytes)
    .bytes()
)
add_vector(
    "connection-close-transport",
    "CONNECTION_CLOSE",
    "CONNECTION_CLOSE (transport): error=0x0A (PROTOCOL_VIOLATION), frame_type=CRYPTO, reason='test'",
    wire,
    {
        "close_type": "transport",
        "error_code": 0x0A,
        "frame_type": 0x06,
        "reason_phrase_length": 4,
        "reason_phrase": "test",
    },
)

# CONNECTION_CLOSE app (0x1D): error=0x42, reason="app error"
reason_bytes = b"app error"
wire = (
    ByteWriter()
    .varint(0x1D)
    .varint(0x42)               # error_code
    .varint(len(reason_bytes))  # reason_phrase_length
    .raw(reason_bytes)
    .bytes()
)
add_vector(
    "connection-close-app",
    "CONNECTION_CLOSE",
    "CONNECTION_CLOSE (app): error=0x42, reason='app error'",
    wire,
    {
        "close_type": "application",
        "error_code": 0x42,
        "reason_phrase_length": 9,
        "reason_phrase": "app error",
    },
)

# NEW_TOKEN (0x07): 16-byte token
token_data = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
wire = (
    ByteWriter()
    .varint(0x07)
    .varint(len(token_data))
    .raw(token_data)
    .bytes()
)
add_vector(
    "new-token",
    "NEW_TOKEN",
    "NEW_TOKEN: 16-byte token",
    wire,
    {
        "token_length": 16,
        "token_hex": token_data.hex(),
    },
)

# PATH_CHALLENGE (0x1A): 8 bytes of data
path_data = bytes.fromhex("0123456789abcdef")
wire = ByteWriter().varint(0x1A).raw(path_data).bytes()
add_vector(
    "path-challenge",
    "PATH_CHALLENGE",
    "PATH_CHALLENGE: 8 bytes of arbitrary data",
    wire,
    {"data_hex": path_data.hex()},
)

# PATH_RESPONSE (0x1B): 8 bytes of data (same data echoed back)
wire = ByteWriter().varint(0x1B).raw(path_data).bytes()
add_vector(
    "path-response",
    "PATH_RESPONSE",
    "PATH_RESPONSE: 8 bytes matching a prior PATH_CHALLENGE",
    wire,
    {"data_hex": path_data.hex()},
)


# ── Error cases ──────────────────────────────────────────────────────────────

# Unknown frame type 0xFF
wire = ByteWriter().varint(0xFF).bytes()
add_vector(
    "unknown-frame-type",
    "UNKNOWN",
    "Unknown frame type 0xFF",
    wire,
    "error",
)

# NEW_CONNECTION_ID with CID length 0 — error case
# RFC 9000 §19.15: CID in NEW_CONNECTION_ID must be 1-20 bytes.
# Zero-length CID is only valid for the initial CID, not via NEW_CONNECTION_ID.
wire = (
    ByteWriter()
    .varint(0x18)
    .varint(1)                 # sequence_number
    .varint(0)                 # retire_prior_to
    .byte(0)                   # CID length = 0 (invalid)
    .raw(bytes(16))            # 16-byte reset token
    .bytes()
)
add_vector(
    "new-connection-id-cid-len-0",
    "NEW_CONNECTION_ID",
    "NEW_CONNECTION_ID with CID length 0: parser accepts; dispatch closes with FRAME_ENCODING_ERROR (F23).",
    wire,
    {
        "sequence_number": 1,
        "retire_prior_to": 0,
        "connection_id_length": 0,
        "connection_id_hex": "",
        "stateless_reset_token_hex": bytes(16).hex(),
    },
)

# NEW_CONNECTION_ID with retire_prior_to > sequence_number
wire = (
    ByteWriter()
    .varint(0x18)
    .varint(5)                 # sequence_number = 5
    .varint(10)                # retire_prior_to = 10 > sequence_number → error
    .byte(8)                   # CID length
    .raw(cid_bytes)
    .raw(reset_token)
    .bytes()
)
add_vector(
    "new-connection-id-retire-exceeds-seq",
    "NEW_CONNECTION_ID",
    "retire_prior_to (10) > sequence_number (5): parser accepts; dispatch closes with FRAME_ENCODING_ERROR (F22).",
    wire,
    {
        "sequence_number": 5,
        "retire_prior_to": 10,
        "connection_id_length": 8,
        "connection_id_hex": cid_bytes.hex(),
        "stateless_reset_token_hex": reset_token.hex(),
    },
)

# Truncated CRYPTO frame: length says 10 but only 2 bytes of data
wire = (
    ByteWriter()
    .varint(0x06)
    .varint(0)       # offset
    .varint(10)      # length = 10
    .raw(b"\xaa\xbb")  # only 2 bytes
    .bytes()
)
add_vector(
    "crypto-truncated",
    "CRYPTO",
    "Truncated CRYPTO: length says 10 but only 2 bytes present",
    wire,
    "error",
)


# ── Write output ─────────────────────────────────────────────────────────────

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT, "w") as f:
    json.dump(vectors, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(f"Wrote {len(vectors)} vectors to {OUTPUT}")
