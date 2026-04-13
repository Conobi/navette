# Research: TQUIC Architecture Survey

**Date:** 2026-04-13
**Status:** done
**Source:** https://github.com/tencent/tquic

## Summary

TQUIC is Tencent's production QUIC stack in Rust. It uses BoringSSL (not rustls), but its module structure, state machine patterns, and sans-I/O design are the reference model for mojo-net M3–M5.

**Key deviation from mojo-net:** TQUIC's TLS layer wraps BoringSSL via C FFI. mojo-net uses rustls via librustls-mojo. The Wave 2 API design replaces TQUIC's `tls/` module entirely.

## Module Map

```
src/
├── codec.rs              # VARINT encode/decode, Encoder/Decoder
├── frame.rs              # Frame enum (19 QUIC frame types + multipath extensions)
├── packet.rs             # PacketHeader, PacketType, header/payload encryption dispatch
├── ranges.rs             # RangeSet (ACK range tracking)
├── window.rs             # SeqNumWindow (duplicate detection bitvector)
├── token.rs              # AddressToken, ResetToken (Retry/stateless reset)
├── trans_param.rs        # TransportParams (wire encode/decode + validation)
├── timer_queue.rs        # Endpoint-level timer scheduling
├── endpoint.rs           # Endpoint (connection table, demux, routing)
│
├── connection/           # M3 TRANSPORT CORE
│   ├── connection.rs     # Connection (7960 LoC) — master state machine
│   ├── stream.rs         # Stream, StreamMap (7446 LoC) — stream multiplexing
│   ├── space.rs          # PacketNumSpace (534 LoC) — 3 independent PN spaces
│   ├── recovery.rs       # Recovery (1658 LoC) — loss detection, RTT, retransmit
│   ├── path.rs           # Path, PathMap — per-path recovery + migration
│   ├── flowcontrol.rs    # FlowControl — window tracking (both levels)
│   ├── rtt.rs            # RttEstimator — EWMA
│   ├── timer.rs          # Timer enum, TimerTable
│   └── cid.rs            # ConnectionId management
│
├── congestion_control/   # M4 CONGESTION CONTROL (pluggable trait)
│   ├── congestion_control.rs  # CongestionController trait
│   ├── cubic.rs               # CUBIC algorithm
│   ├── bbr.rs / bbr3.rs       # BBR / BBRv3
│   └── pacing.rs              # Pacer trait
│
├── tls/                  # CRYPTO (BoringSSL in TQUIC; rustls in mojo-net)
│   ├── tls.rs            # TlsConfig, TlsSession
│   └── boringssl/        # C FFI to BoringSSL (replace entirely with librustls-mojo)
│
└── h3/                   # M5 HTTP/3 (optional feature)
    ├── connection.rs      # Http3Connection
    ├── stream.rs          # Http3Stream (type: request, control, encoder, decoder)
    ├── frame.rs           # HTTP/3 frame types
    └── qpack/             # QPACK (static + dynamic table, Huffman)
```

## State Machine: BitFlags + Derived Predicates

TQUIC does NOT use a state enum. Instead it uses 22 `BitFlags<ConnectionFlags>`:

```
DerivedInitialSecrets, InitiatedClientHandshake, GotPeerCid,
AppliedPeerTransportParams, PeerVerifiedInitialAddress,
HandshakeCompleted, HandshakeConfirmed,
Closed, IdleTimeout, HandshakeTimeout, GotReset,
NeedSendAckEliciting, NeedSendHandshakeDone, HandshakeDoneAcked,
...
```

Derived predicates:
- `is_established()` = `HandshakeCompleted`
- `is_confirmed()` = `HandshakeConfirmed`
- `is_closing()` = `local_error.is_some() && !Closed`
- `is_draining()` = `Closed && !is_closing()`

**mojo-net recommendation:** Adopt the bitflags approach. More composable than explicit state enum for a protocol with this many orthogonal state dimensions.

## Inbound Packet Pipeline

```
UDP datagram
  → Endpoint::recv_packet() [route DCID → Connection]
  → Connection::recv_packet()
      1. Parse PacketHeader (unencrypted: type, version, DCID, SCID, PN-length bits)
      2. header_unprotect() using hp_key (sample-based XOR)
      3. Decode packet number (expand from 1-4B field + largest_rx ref)
      4. Check duplicate via SeqNumWindow bitvector
      5. payload_decrypt() using packet AEAD key
      6. Frame loop:
           ACK     → try_process_acked_frames() → loss recovery
           STREAM  → StreamMap::on_stream_frame() → reassembly buffer
           CRYPTO  → crypto_streams[level].write() → TLS::provide_data()
           MAX_DATA, MAX_STREAM_DATA → FlowControl::increase_window()
           CONNECTION_CLOSE → set peer_error, mark closing
           HANDSHAKE_DONE → set HandshakeConfirmed flag
      7. Update ACK state, schedule ACK timer
      8. Update connection timers (idle_timeout reset)
```

## PacketNumSpace

Three independent objects — never share state:

```rust
PacketNumSpace {
    id: SpaceId,                    // Initial | Handshake | Data
    next_pkt_num: u64,
    largest_rx_pkt_num: u64,
    recv_pkt_num_win: SeqNumWindow, // Duplicate detection (bitvector)
    recv_pkt_num_need_ack: RangeSet,// ACK ranges to send
    sent: VecDeque<SentPacket>,     // Loss recovery history
    lost: Vec<Frame>,               // Frames to retransmit
    acked: Vec<Frame>,              // For congestion control callbacks
    loss_time: Option<Instant>,
    bytes_in_flight: usize,
}
```

Initial and Handshake spaces are **discarded** once their encryption level is no longer needed (RFC 9001 §4.9).

## StreamMap

```rust
StreamMap {
    streams: HashMap<u64, Stream>,
    sendable: BTreeMap<u8, PriorityQueue>,  // urgency 0–7 → streams
    readable: HashSet<u64>,
    writable: HashSet<u64>,
    reset: HashMap<u64, (error_code, final_size)>,
    flow_control: FlowControl,   // connection-level RX window
    send_capacity: SendCapacity, // connection-level TX window
}

Stream {
    id: u64,
    send: { buffer, offset, final_offset, flow_control (TX per-stream) },
    recv: { BTreeMap<offset, Bytes> (reassembly), read_offset, fin_offset, flow_control (RX per-stream) },
    flags: BitFlags<StreamFlags>,
    urgency: u8,  // RFC 9218 priority
}
```

Stream IDs: client bidi=0 mod 4, server bidi=1 mod 4, client uni=2 mod 4, server uni=3 mod 4.

## Loss Recovery vs Congestion Control (M3 vs M4 Separation)

**M3 (cannot defer):** `connection/recovery.rs`
- loss_detection_timer, pto_count
- RTT estimation (EWMA: smoothed_rtt, rttvar, min_rtt)
- Packet-threshold loss detection (3 PN ahead)
- Time-threshold loss detection (9/8 × max(smoothed, latest))
- `PacketNumSpace.lost` population → retransmit scheduling
- CRYPTO frame retransmission (handshake correctness depends on this)

**M4 (pluggable, defer):** `congestion_control/` trait
```rust
trait CongestionController {
    fn on_sent(pkt, bytes_in_flight)
    fn on_ack(pkt, rtt, bytes_in_flight)
    fn on_congestion_event(pkt, is_persistent, lost_bytes, bytes_in_flight)
    fn congestion_window() -> u64
}
```
Implementations: CUBIC, BBRv2, BBRv3, COPA, Dummy (for testing).

**Key insight:** Loss detection and congestion control are separable. In M3, use a "dummy" CC that tracks bytes_in_flight but doesn't reduce cwnd — sufficient for correct transport behavior. Full CC added in M4.

## Sans-I/O Boundary

```rust
// Connection: purely sans-I/O
connection.recv_packet(&[u8], info: &PacketInfo) -> Result<usize>
connection.send_packet_to_buf(&mut [u8]) -> Result<(usize, PacketInfo)>
connection.on_timeout() -> Result<()>

// Endpoint: I/O bridge
endpoint.recv_datagram(&[u8], info: &PacketInfo) -> Result<()>
endpoint.handle_timeout(now: Instant) -> Result<()>

// Application provides:
trait PacketSendHandler { fn send_packet(&self, buf: &[u8], info: &PacketInfo) -> Result<()> }
trait TransportHandler { fn on_stream_readable(...), on_stream_writable(...) }
```

## HTTP/3 Layer (M5 reference)

- `Http3Connection` wraps `Connection`, manages 3 unidirectional system streams (control, encoder, decoder)
- `Http3Stream`: type-tagged wrapper over QUIC stream
- QPACK: full static + dynamic table (99 static entries, dynamic optional via SETTINGS)
- Connection setup: both sides create control+encoder+decoder streams, exchange SETTINGS as first frame on control stream

## mojo-net Module Mapping Recommendation

```
src/quic/
  connection.mojo     → connection/connection.rs (bitflags SM, frame dispatch)
  stream.mojo         → connection/stream.rs     (StreamMap, Stream)
  space.mojo          → connection/space.rs      (PacketNumSpace, SpaceId)
  packet.mojo         → packet.rs                (PacketHeader, PacketType)
  frame.mojo          → frame.rs                 (Frame enum, 11 M3 types)
  flowcontrol.mojo    → connection/flowcontrol.rs
  codec.mojo          → codec.rs                 (VARINT, Encoder/Decoder)
  trans_param.mojo    → trans_param.rs
  endpoint.mojo       → endpoint.rs              (connection table, demux)
  timer.mojo          → connection/timer.rs

src/quic/recovery/
  recovery.mojo       → connection/recovery.rs   (loss detection, RTT)
  rtt.mojo            → connection/rtt.rs

src/quic/congestion/ (M4)
  trait.mojo
  cubic.mojo
  bbr.mojo
  dummy.mojo          (for M3 testing)

src/h3/ (M5)
  connection.mojo
  stream.mojo
  frame.mojo
  qpack.mojo
```
