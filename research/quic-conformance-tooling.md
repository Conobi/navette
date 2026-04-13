# Research: QUIC Conformance Tooling

**Date:** 2026-04-13
**Status:** done

## Recommendation: aioquic as primary oracle

**aioquic** (https://github.com/aiortc/aioquic) matches mojo-net's existing methodology:
- Pure Python, same as h11 / httptools / hyperframe / hpack oracles
- Explicit "bring your own I/O" design (no network required for oracle use)
- Native APIs for packet decode, QPACK encode/decode, H3 frame parse

**quiche** (Cloudflare Rust) is production-grade but requires C FFI or PyO3 bindings — far more friction than aioquic for test scripts.

## aioquic Oracle API

```python
# Packet decode (QC-1)
from aioquic.quic.packet import pull_quic_header
header, consumed = pull_quic_header(wire_bytes, host_cid_len=8)
# header.packet_type, .version, .destination_cid, .source_cid, .token, .packet_length

# QPACK (QC-2)
from aioquic.quic.qpack import Encoder, Decoder
encoder = Encoder()
encoded = encoder.encode([(b":method", b"GET"), (b":path", b"/"), ...])

decoder = Decoder()
headers = decoder.decode(encoded)

# H3 frames (QC-2)
from aioquic.h3.frame import Frame
frame, remaining = Frame.parse(wire_bytes)
# frame.frame_type (DATA, HEADERS, SETTINGS, etc.)
```

## Test Vector Sources

### RFC 9001 Appendix A
- Complete Initial packet protection test vectors (DCID, HKDF derivation, AEAD keys, IV, HP keys, protected wire bytes)
- **Format:** Hex in RFC text (not JSON — needs conversion)
- **Coverage:** Initial packets only (no Handshake/1-RTT/0-RTT vectors)
- **URL:** https://datatracker.ietf.org/doc/html/rfc9001#appendix-A

### QUIC WG Wiki
- Initial AEAD key derivation vectors for multiple QUIC drafts
- URL: https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Initial-AEAD-key-derivation

### RFC 9204 Appendix A (QPACK)
- QPACK encoding examples (prose, no JSON vectors)
- No equivalent of HPACK "stories" format

## Proposed Conformance Suite Structure

### QC-1: Crypto + Packet Structure (~35–45 vectors)

| Category | # vectors | Oracle |
|----------|----------|--------|
| Initial key derivation (RFC 9001 §5.2) | 6–8 | Manual HKDF + aioquic |
| AEAD encrypt/decrypt (Initial level) | 8–10 | RFC 9001 Appendix A + aioquic |
| Header protection (hp key, sample, XOR) | 4–5 | RFC 9001 Appendix A |
| Long header parse (Initial, Handshake, Retry) | 8–10 | aioquic pull_quic_header |
| Short header parse (1-RTT, key phase bit) | 4–5 | aioquic |
| PN varint encoding | 4–5 | RFC 9000 §A |

**Vector location:** `conformance/vectors/quic/qc1-*.json`

### QC-2: HTTP/3 + QPACK (~40–55 vectors)

| Category | # vectors | Oracle |
|----------|----------|--------|
| QPACK integer encoding (prefix bits) | 8–10 | aioquic Encoder/Decoder |
| QPACK string encoding (Huffman/literal) | 6–8 | aioquic |
| QPACK static table lookups | 4–6 | aioquic |
| QPACK literal headers | 4–6 | aioquic |
| H3 SETTINGS frame | 4–5 | aioquic h3.frame |
| H3 HEADERS frame | 4–6 | aioquic h3.frame |
| H3 DATA frame | 3–4 | aioquic h3.frame |
| H3 frame ordering rules | 4–6 | aioquic + manual |

**Vector location:** `conformance/vectors/quic/qc2-*.json`

## Vector JSON Structure (following existing h2 pattern)

```json
{
  "id": "qc1-initial-key-derivation-rfc9001-a1",
  "category": "initial-key-derivation",
  "rfc_section": "RFC 9001 Appendix A",
  "input": {
    "dcid_hex": "8394c8f03e515708",
    "version": 1
  },
  "expected": {
    "client_initial_secret_hex": "...",
    "server_initial_secret_hex": "...",
    "client_key_hex": "1f369613dd76d5467730efcbe3b1d4e1",
    "client_iv_hex":  "fa044b2f42a3fd3b46fb255c618e8a79",
    "client_hp_hex":  "9f50449e04a0e810283a1e9933adedd2",
    "server_key_hex": "...",
    "server_iv_hex":  "...",
    "server_hp_hex":  "..."
  }
}
```

## Conformance Script Pattern

```python
# conformance/scripts/oracle_quic.py
from aioquic.quic.packet import pull_quic_header
from aioquic.quic.qpack import Encoder, Decoder
from aioquic.h3.frame import Frame

def parse_quic_header(wire_hex: str) -> dict: ...
def qpack_encode(headers: list) -> dict: ...
def qpack_decode(wire_hex: str) -> dict: ...
def h3_parse_frame(wire_hex: str) -> dict: ...
```

## QUIC Interop Runner

The IETF QUIC WG maintains **https://interop.seemann.io/quic** — a live matrix of implementations tested against each other.

**Test categories relevant for mojo-net milestones:**
| Category | M3 target | M4 target |
|----------|-----------|-----------|
| handshake | ✓ | – |
| transfer | ✓ | – |
| retry | ✓ | – |
| flow-control | ✓ | – |
| resumption | – | ✓ |
| 0-rtt | – | ✓ |
| key-update | – | ✓ |
| migration | – | – |

Participating: quic-go, aioquic, quiche, neqo, msquic, picoquic and ~15 others.

mojo-net could participate by running implementations in Docker with a standard CLI interface (test case passed via env var; exit code 127 = unsupported).

## Python Dependencies

```toml
# pyproject.toml additions
aioquic = ">=0.9.25"
cryptography = ">=42.0"   # already used by aioquic
```
