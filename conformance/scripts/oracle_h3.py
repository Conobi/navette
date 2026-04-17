#!/usr/bin/env python3
"""Generate H3 frame and QPACK static-only conformance vectors.

Usage:
    uv run python conformance/scripts/oracle_h3.py

Output:
    conformance/vectors/rfc9114/frame.json
    conformance/vectors/rfc9204/qpack_static.json

Requires: aioquic (pulls in pylsqpack for QPACK)
    uv pip install aioquic
"""
import json
import struct
from pathlib import Path


def encode_varint(value: int) -> bytes:
    """Encode a QUIC variable-length integer (RFC 9000 §16)."""
    if value < 0x40:
        return bytes([value])
    elif value < 0x4000:
        return struct.pack(">H", 0x4000 | value)
    elif value < 0x40000000:
        return struct.pack(">I", 0x80000000 | value)
    else:
        return struct.pack(">Q", 0xC000000000000000 | value)


def encode_h3_frame(frame_type: int, payload: bytes) -> bytes:
    return encode_varint(frame_type) + encode_varint(len(payload)) + payload


def generate_frame_vectors() -> list:
    vectors = []

    # DATA frame: empty payload
    vectors.append({
        "description": "DATA frame empty payload",
        "frame_type": 0x00,
        "payload_hex": "",
        "wire_hex": encode_h3_frame(0x00, b"").hex(),
    })

    # DATA frame: "hello"
    vectors.append({
        "description": "DATA frame hello",
        "frame_type": 0x00,
        "payload_hex": b"hello".hex(),
        "wire_hex": encode_h3_frame(0x00, b"hello").hex(),
    })

    # DATA frame: 300 bytes (tests multi-byte varint length)
    big_payload = bytes(range(256)) + bytes(range(44))  # 300 bytes
    vectors.append({
        "description": "DATA frame 300 bytes",
        "frame_type": 0x00,
        "payload_hex": big_payload.hex(),
        "wire_hex": encode_h3_frame(0x00, big_payload).hex(),
    })

    # HEADERS frame: fake QPACK block [0x00, 0x00, 0xC4]
    qpack_block = bytes([0x00, 0x00, 0xC4])
    vectors.append({
        "description": "HEADERS frame with QPACK block",
        "frame_type": 0x01,
        "payload_hex": qpack_block.hex(),
        "wire_hex": encode_h3_frame(0x01, qpack_block).hex(),
    })

    # SETTINGS frame: QPACK_MAX_TABLE_CAPACITY=4096, MAX_FIELD_SECTION_SIZE=65536
    settings_pairs = [(0x01, 4096), (0x06, 65536)]
    settings_payload = b""
    for k, v in settings_pairs:
        settings_payload += encode_varint(k) + encode_varint(v)
    vectors.append({
        "description": "SETTINGS frame two pairs",
        "frame_type": 0x04,
        "payload_hex": settings_payload.hex(),
        "wire_hex": encode_h3_frame(0x04, settings_payload).hex(),
        "settings": [{"id": k, "value": v} for k, v in settings_pairs],
    })

    # SETTINGS frame: unknown ID preserved
    settings_pairs_unk = [(0xFFFF, 42), (0x07, 100)]
    settings_payload_unk = b""
    for k, v in settings_pairs_unk:
        settings_payload_unk += encode_varint(k) + encode_varint(v)
    vectors.append({
        "description": "SETTINGS frame unknown id preserved",
        "frame_type": 0x04,
        "payload_hex": settings_payload_unk.hex(),
        "wire_hex": encode_h3_frame(0x04, settings_payload_unk).hex(),
        "settings": [{"id": k, "value": v} for k, v in settings_pairs_unk],
    })

    # Unknown frame type 0x21
    vectors.append({
        "description": "Unknown frame type 0x21",
        "frame_type": 0x21,
        "payload_hex": "aabb",
        "wire_hex": encode_h3_frame(0x21, bytes([0xAA, 0xBB])).hex(),
    })

    # GOAWAY frame (type 0x07): stream_id=4 (varint)
    goaway_payload = encode_varint(4)
    vectors.append({
        "description": "GOAWAY frame stream_id=4",
        "frame_type": 0x07,
        "payload_hex": goaway_payload.hex(),
        "wire_hex": encode_h3_frame(0x07, goaway_payload).hex(),
    })

    return vectors


def generate_qpack_vectors() -> list:
    """Generate QPACK static-only vectors using pylsqpack (used by aioquic internally)."""
    try:
        import pylsqpack
    except ImportError:
        raise ImportError(
            "pylsqpack not found. Install aioquic (which brings pylsqpack): uv pip install aioquic"
        )

    vectors = []

    header_sets = [
        (
            "GET / via indexed static fields",
            [
                (b":method", b"GET"),
                (b":path", b"/"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
            ],
            False,
        ),
        (
            "POST /upload with content-type",
            [
                (b":method", b"POST"),
                (b":path", b"/upload"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b"content-type", b"application/json"),
                (b"content-length", b"0"),
            ],
            False,
        ),
        (
            "200 OK response",
            [
                (b":status", b"200"),
                (b"content-type", b"text/html; charset=utf-8"),
                (b"cache-control", b"no-cache"),
            ],
            False,
        ),
        (
            "404 Not Found",
            [
                (b":status", b"404"),
            ],
            False,
        ),
        (
            "Custom header literal no name ref",
            [
                (b":method", b"GET"),
                (b"x-custom-header", b"myvalue"),
            ],
            False,
        ),
        (
            ":method PATCH literal with name ref",
            [
                (b":method", b"PATCH"),
                (b":path", b"/api"),
            ],
            False,
        ),
        (
            "GET / with Huffman",
            [
                (b":method", b"GET"),
                (b":path", b"/"),
                (b":scheme", b"https"),
                (b":authority", b"www.example.com"),
            ],
            True,
        ),
    ]

    for description, headers, _huffman in header_sets:
        # pylsqpack.Encoder: encode(stream_id, headers) -> (encoder_stream_bytes, header_block)
        # pylsqpack.Decoder: feed_header(stream_id, header_block) -> (decoder_stream_bytes, headers_list)
        enc = pylsqpack.Encoder()
        dec = pylsqpack.Decoder(4096, 16)

        _enc_stream, encoded = enc.encode(0, headers)
        _dec_stream, decoded = dec.feed_header(0, encoded)

        vectors.append({
            "description": description,
            "headers": [{"name": k.decode(), "value": v.decode()} for k, v in headers],
            "encoded_hex": encoded.hex(),
            "decoded": [{"name": k.decode(), "value": v.decode()} for k, v in decoded],
            # Note: pylsqpack controls Huffman encoding internally; this flag is informational only.
        })

    return vectors


def main():
    repo_root = Path(__file__).parent.parent.parent

    # H3 frame vectors
    frame_vectors = generate_frame_vectors()
    frame_out = repo_root / "conformance" / "vectors" / "rfc9114" / "frame.json"
    frame_out.parent.mkdir(parents=True, exist_ok=True)
    frame_out.write_text(json.dumps({"vectors": frame_vectors}, indent=2))
    print(f"Wrote {len(frame_vectors)} H3 frame vectors -> {frame_out}")

    # QPACK vectors (pylsqpack, which is the QPACK backend used by aioquic)
    qpack_vectors = generate_qpack_vectors()
    qpack_out = repo_root / "conformance" / "vectors" / "rfc9204" / "qpack_static.json"
    qpack_out.parent.mkdir(parents=True, exist_ok=True)
    qpack_out.write_text(json.dumps({"vectors": qpack_vectors}, indent=2))
    print(f"Wrote {len(qpack_vectors)} QPACK vectors -> {qpack_out}")


if __name__ == "__main__":
    main()
