# Research: QPACK + HTTP/3 Framing Scope (M5)

**Date:** 2026-04-13
**Status:** done
**Sources:** RFC 9114, RFC 9204

## HTTP/3 Frame Types (RFC 9114 §7)

| Value | Name | Stream | Required (minimal server) |
|-------|------|--------|:--:|
| 0x00 | DATA | Request/push only | ✓ |
| 0x01 | HEADERS | Request/push only | ✓ |
| 0x03 | CANCEL_PUSH | Control only | No (server push optional) |
| 0x04 | SETTINGS | Control only, **first frame** | ✓ |
| 0x05 | PUSH_PROMISE | Request only | No |
| 0x07 | GOAWAY | Control only | No (graceful shutdown optional) |
| 0x0D | MAX_PUSH_ID | Control only | No |

**Wire format:** type (varint) + length (varint) + payload.

**Key constraints:**
- SETTINGS MUST be sent exactly once as the first frame on each peer's control stream
- DATA + HEADERS MUST NOT appear on control streams (→ H3_FRAME_UNEXPECTED error)
- HEADERS always precedes DATA on a request stream

## HTTP/3 Stream Architecture

| Stream type | Dir | Creation | Purpose | Required |
|------------|-----|---------|---------|:---:|
| Request stream | Bidi | Client | One request/response | ✓ |
| Control stream | Uni (0x00 prefix) | Both | SETTINGS, GOAWAY | ✓ (1 per endpoint) |
| QPACK encoder stream | Uni (0x02 prefix) | Both | Dynamic table insertions | ✓ (create even if idle) |
| QPACK decoder stream | Uni (0x03 prefix) | Both | Dynamic table ACKs | ✓ (create even if idle) |
| Push stream | Uni | Server | Server push responses | No |

**Minimal setup per connection:** 3 uni streams per endpoint (control + encoder + decoder) = 6 total uni streams before first request.

## QPACK (RFC 9204)

### Static table
- 99 entries, indices 0–98 (hardcoded — same 99 entries as in the RFC)
- Key entries: `:authority` (0), `:path /` (1), `:method GET` (2), `:scheme https` (4), `:status 200` (6), `:status 404` (13), common content-type values, cache-control, etc.
- Stateless: any endpoint can reference static table entries without synchronization

### Dynamic table
- Optional: set `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` to disable entirely
- When enabled: encoder/decoder streams must stay synchronized (complex)
- Blocking: dynamic table refs can block decoding until insertions are acknowledged (HOL risk)

### Static-only QPACK — recommended for M5

**Viable?** YES — production implementations use it (quic-go, some nginx configs).

**What it means:**
- Set `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` in SETTINGS frame
- Create encoder/decoder streams (RFC requires them) but keep them idle
- All headers encoded as static table references (indexed) or uncompressed literals
- No encoder/decoder stream synchronization complexity

**Trade-off:** Custom/uncommon headers sent as uncompressed literals. All standard HTTP headers (method, status, content-type, cache-control, etc.) have static table entries and compress well.

**Recommendation:** M5 = static-only QPACK. M6 adds dynamic table.

### Huffman encoding
- Reuses RFC 7541 (HPACK) Huffman table — same 256-symbol code
- Optional flag bit in QPACK string literals
- ~15–20% size reduction on average; moderate implementation complexity (lookup table)
- Include in M5 (it's a pure codec function with no state)

## H3 Connection Setup Sequence

1. QUIC handshake completes (ALPN="h3")
2. Both endpoints open their 3 unidirectional streams in parallel (control, encoder, decoder)
3. Both send SETTINGS as the first frame on their control stream
4. Client opens bidi stream 0, sends HEADERS (QPACK-encoded request)
5. Server receives HEADERS, sends HEADERS (response) + DATA on same stream

## HTTP/3 vs HTTP/2 — Where Simpler

| Dimension | H2 | H3 |
|-----------|----|----|
| HOL blocking | TCP packet loss blocks all streams | QUIC isolates streams; no transport HOL |
| Flow control | HTTP layer (WINDOW_UPDATE) | QUIC layer; H3 app doesn't manage it |
| Stream multiplexing | HTTP layer (stream states in H2) | QUIC layer; H3 just opens QUIC streams |
| Header compression | HPACK (stateful, ordered, blocking) | QPACK (optional static-only = stateless) |
| Mandatory features | HPACK dynamic table required | QPACK dynamic table optional |
| Push | Widely disabled in practice | Optional and rarely implemented |

**Key insight:** H3 is significantly simpler at the application layer because QUIC subsumes multiplexing and flow control. The complexity cost is paid once in the QUIC transport (M3).

## M5 Scope Recommendation

### Include in M5 (minimum viable H3 server)

- SETTINGS frame encode/decode
- HEADERS frame encode/decode (QPACK static-only + Huffman)
- DATA frame encode/decode
- Control stream lifecycle (creation, SETTINGS exchange)
- Encoder/decoder streams (create + keep idle for M5)
- Request stream demux (bidi stream → request/response handler)
- Pseudo-header validation (`:method`, `:path`, `:scheme`, `:authority`, `:status`)
- QPACK 99-entry static table (hardcoded)
- QPACK string encoding: literal (no Huffman) + Huffman
- QPACK indexed field representation (static table refs)
- QPACK literal field representation (name-ref + literal, or fully literal)
- Connection error handling (H3_FRAME_UNEXPECTED, H3_SETTINGS_ERROR, etc.)

### Defer to M6

- QPACK dynamic table (complex sync via encoder/decoder streams)
- QPACK blocking stream management (SETTINGS_QPACK_BLOCKED_STREAMS)
- Server push (PUSH_PROMISE, push stream)
- GOAWAY (graceful shutdown)
- Priority signaling (RFC 9218)
- WebTransport (RFC draft)

## M5 LoC Estimate

| Component | LoC |
|-----------|-----|
| H3 frame codec (DATA, HEADERS, SETTINGS) | 300–400 |
| QPACK static table (99 entries) | 200–300 |
| QPACK encoder (static-only + Huffman) | 400–600 |
| QPACK decoder (static-only + Huffman) | 400–600 |
| H3 connection lifecycle + stream management | 500–700 |
| Request/response handler integration | 300–400 |
| **Total M5** | **~2100–3000** |

## M3/M5 Split Validation

The split is **confirmed correct** by the research:

- M3 provides everything needed to send/receive QUIC streams reliably
- M5 layers HTTP semantics + header compression on top of QUIC streams
- The two layers have zero code coupling (M5 calls into M3 only via stream send/recv APIs)
- QPACK complexity is entirely isolated in M5; QUIC transport does not care about header encoding

## aioquic Test Oracle Coverage

| M5 component | aioquic coverage |
|-------------|-----------------|
| QPACK encode/decode | `aioquic.quic.qpack.Encoder/Decoder` — full coverage |
| H3 frame parse | `aioquic.h3.frame.Frame.parse()` — full coverage |
| H3 connection preface | `aioquic.h3.connection.H3Connection` — via receive_datagram |
| Huffman encoding | Built into aioquic QPACK — implicit coverage |
