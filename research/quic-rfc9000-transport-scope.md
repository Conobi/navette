# Research: QUIC RFC 9000 Transport Core — M3 Scope

**Date:** 2026-04-13
**Status:** done
**Sources:** RFC 9000, RFC 9001, RFC 9002

## Frame Type Registry — M3 vs M4 vs M5

| Type | Name | M3 | M4 | M5 | Notes |
|------|------|:--:|:--:|:--:|-------|
| 0x00 | PADDING | ✓ | – | – | Required for Initial packet minimum size (1200 B) |
| 0x01 | PING | ✓ | – | – | Keepalive / ack-eliciting trigger |
| 0x02–03 | ACK | ✓ | ✓ | – | Core loss detection; ECN counts in 0x03 |
| 0x04 | RESET_STREAM | – | ✓ | – | Stream abort; stub in M3 |
| 0x05 | STOP_SENDING | – | ✓ | – | Flow control feedback; stub in M3 |
| 0x06 | CRYPTO | ✓ | – | – | TLS handshake bytes; mandatory |
| 0x07 | NEW_TOKEN | – | – | – | Address validation token; defer |
| 0x08–0F | STREAM | ✓ | – | – | Application data (8 flag variants) |
| 0x10 | MAX_DATA | ✓ | – | – | Connection-level FC limit |
| 0x11 | MAX_STREAM_DATA | ✓ | – | – | Stream-level FC limit |
| 0x12–13 | MAX_STREAMS | ✓ | – | – | Bidi (0x12) and uni (0x13) limits |
| 0x14 | DATA_BLOCKED | – | ✓ | – | Informational; stub in M3 |
| 0x15 | STREAM_DATA_BLOCKED | – | ✓ | – | Informational; stub in M3 |
| 0x16–17 | STREAMS_BLOCKED | – | ✓ | – | Informational; stub in M3 |
| 0x18 | NEW_CONNECTION_ID | ✓ | – | – | CID rotation (basic) |
| 0x19 | RETIRE_CONNECTION_ID | – | – | – | Defer |
| 0x1A | PATH_CHALLENGE | – | – | – | Migration; defer |
| 0x1B | PATH_RESPONSE | – | – | – | Migration; defer |
| 0x1C–1D | CONNECTION_CLOSE | ✓ | – | – | 0x1C=app error, 0x1D=transport error |
| 0x1E | HANDSHAKE_DONE | ✓ | – | – | Server confirms handshake; critical |

**M3 minimum: 11 frame types** (PADDING, PING, ACK, CRYPTO, STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS×2, NEW_CONNECTION_ID, CONNECTION_CLOSE×2, HANDSHAKE_DONE).

## Packet Types

### Long Header (connection establishment)

| Type | Byte pattern | PN space | M3? |
|------|-------------|---------|-----|
| Initial | type=00 in long hdr | Initial | ✓ |
| 0-RTT | type=01 | Application | Stub (accept but don't process data) |
| Handshake | type=10 | Handshake | ✓ |
| Retry | type=11 | — (no PN) | ✓ (parse + validate integrity tag) |
| Version Negotiation | special (no type bits, version=0) | — | ✓ (parse + send) |

### Short Header (application data)

| Type | PN space | M3? |
|------|---------|-----|
| 1-RTT | Application | ✓ |

### Parser checklist

1. First byte bit 7: 0=short header, 1=long header
2. Long header: 4-byte version, variable DCID (0–20 B), variable SCID (0–20 B), token (varint-length, Initial/Retry only), payload length (varint)
3. Short header: fixed-bit=1, spin bit, reserved bits, key phase bit, DCID, PN (1–4 B)
4. Initial packets MUST be padded to ≥ 1200 bytes

## Packet Number Spaces

Three independent contexts:

| Space | Encryption | Lifespan | Discard trigger |
|-------|-----------|---------|-----------------|
| Initial | Initial keys (DCID-derived) | Handshake start | Server receives first Handshake packet |
| Handshake | Handshake keys | After ServerHello | Client sends first 1-RTT packet |
| Application | 0-RTT + 1-RTT | Connection lifetime | Never discarded; keys rotate in-place |

Each space has its own: `next_pkt_num`, `largest_rx_pkt_num`, `recv_pkt_num_win` (duplicate detection), `recv_pkt_num_need_ack` (ACK ranges), `sent` history, `lost` list.

## Connection State Machine (simplified)

```
                    START
                      │
          [Client sends Initial CRYPTO(ClientHello)]
                      │
              INITIAL / HANDSHAKING
                      │
          [Both exchange CRYPTO frames, derive 1-RTT keys]
                      │
                  HANDSHAKE
                      │
          [Server sends HANDSHAKE_DONE at 1-RTT level]
                      │
                   CONNECTED ──────────────────────────┐
                      │                                 │
                [idle timeout or error]      [CONNECTION_CLOSE sent]
                      │                                 │
                   DRAINING ←────────────── CLOSING ───┘
                      │            (3× max_ack_delay)
                   CLOSED
```

## Flow Control (dual-level)

**Stream-level (per-stream):**
- Sender: `stream_offset` must stay ≤ peer's `max_stream_data`
- Receiver: sends `MAX_STREAM_DATA` when stream buffer is ≥ 75% consumed

**Connection-level:**
- Sender: sum of all stream offsets must stay ≤ peer's `max_data`
- Receiver: sends `MAX_DATA` when total consumed bytes ≥ 75% of limit

**M3 required:**
- Enforce both limits before sending STREAM frames
- Parse and apply MAX_DATA + MAX_STREAM_DATA on receipt
- Advertise initial limits via transport parameters
- Proactively send updated MAX_DATA / MAX_STREAM_DATA to unblock peers

**M3 stub (informational only):**
- DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED — parse but don't act on them beyond logging

## Stream Multiplexing

**Stream ID scheme:**
```
Client bidi: 0, 4, 8, ... (id mod 4 == 0)
Server bidi: 1, 5, 9, ... (id mod 4 == 1)
Client uni:  2, 6, 10,... (id mod 4 == 2)
Server uni:  3, 7, 11,... (id mod 4 == 3)
```

**Send-side states:** READY → SEND → DATA_SENT → DATA_RECVD (or RESET_SENT on abort)

**Recv-side states:** RECV → SIZE_KNOWN → DATA_READ (or RESET_RECVD on peer abort)

**M3 required:** All states above, MAX_STREAMS enforcement, FIN bit, STREAM reassembly (BTreeMap<offset, bytes>).

**M3 stub:** RESET_STREAM, STOP_SENDING (parse but emit connection error or ignore for now).

## ACK + RTT Estimation (M3 minimum)

**RTT on each ACK received:**
```
latest_rtt = now - sent_time - ack_delay
if latest_rtt < min_rtt: min_rtt = latest_rtt
smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * latest_rtt  (init: 333ms)
rttvar = 3/4 * rttvar + 1/4 * |latest_rtt - smoothed_rtt|  (init: 166ms)
```

**Loss detection (M3 threshold-based):**
```
For each unACKed packet P:
  if largest_acked_pn > P.pn + 3:  → P.lost (packet threshold)
  if now - P.sent_time > 9/8 * max(smoothed_rtt, latest_rtt):  → P.lost (time threshold)
```

**ACK sending:**
- Delay up to max_ack_delay (default 25 ms)
- ACK every 2nd ack-eliciting packet or on timer
- Encode ranges efficiently: [gap, length] pairs

**Deferred to M4:** PTO timer, persistent congestion, congestion window.

## TLS / CRYPTO Integration

**Four encryption levels → 3 PN spaces:**
```
Initial    → Initial PN space    (DCID-derived keys, Wave 1 done)
0-RTT      → Application space   (PSK; stub in M3)
Handshake  → Handshake space     (from KeyChange::Handshake)
1-RTT      → Application space   (from KeyChange::OneRtt)
```

**CRYPTO frame:** offset (varint) + length (varint) + raw TLS handshake bytes. No TLS record layer wrapping.

**M3 caller must:**
1. Assemble CRYPTO frames by offset per space before calling `rlsm_quic_conn_read_hs`
2. Act on `KeyChange` signal from `rlsm_quic_conn_write_hs` immediately
3. Pass transport params in RFC 9000 §18 wire format to `rlsm_quic_conn_new`
4. Retrieve peer's transport params via `rlsm_quic_conn_transport_params` after handshake

## M3 Transport Core Complexity Estimate

| Component | LoC estimate |
|-----------|-------------|
| VARINT codec + frame parser (11 types) | 600–800 |
| Packet header parser + serializer | 300–400 |
| PacketNumSpace (×3) + PN decode | 400–500 |
| Connection state machine (bitflags + dispatch) | 800–1200 |
| Stream + StreamMap | 900–1200 |
| Flow control (connection + stream) | 300–400 |
| ACK generation + RTT + loss threshold | 400–600 |
| CRYPTO frame buffer + integration hooks | 300–400 |
| Transport parameter encode/decode | 200–300 |
| Endpoint (demux, connection table) | 300–400 |
| **Total M3** | **~5000–7200** |
