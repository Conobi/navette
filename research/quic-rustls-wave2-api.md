# Research: rustls::quic Handshake API (Wave 2 Scope)

**Date:** 2026-04-13
**Status:** done

## Summary

Wave 1 (done) covers only QUIC Initial keys — AEAD encrypt/decrypt + header protection.
Wave 2 must expose the full TLS 1.3 handshake lifecycle running over QUIC via `rustls::quic::ClientConnection` / `ServerConnection`.

## Public API Surface (rustls 0.23)

### Connection types

```rust
ClientConnection::new(config: Arc<ClientConfig>, version: Version, name: ServerName, params: Vec<u8>)
ServerConnection::new(config: Arc<ServerConfig>, version: Version, params: Vec<u8>)
```

### Core data-flow methods

| Method | Signature | Purpose |
|--------|-----------|---------|
| `read_hs` | `(&mut self, plaintext: &[u8]) -> Result<(), Error>` | Feed CRYPTO frame content at the current encryption level |
| `write_hs` | `(&mut self, buf: &mut Vec<u8>) -> Option<KeyChange>` | Drain outgoing TLS messages; **signals key change** |

### KeyChange enum (the key-schedule signal)

```rust
pub enum KeyChange {
    Handshake { keys: Keys },              // switch to Handshake encryption level
    OneRtt { keys: Keys, next: Secrets }, // switch to 1-RTT; Secrets::next_packet_keys() for key update
}
```

### Supporting types

| Type | Key members |
|------|-------------|
| `Keys` | `.local: DirectionalKeys`, `.remote: DirectionalKeys`; static `initial()` |
| `DirectionalKeys` | `.header: Box<dyn HeaderProtectionKey>`, `.packet: Box<dyn PacketKey>` |
| `Secrets` | `next_packet_keys() -> PacketKeySet` |
| `PacketKeySet` | `.local`, `.remote` (post-handshake key update) |
| `Version` | `V1`, `V2` (no others currently) |

### State-query methods

| Method | Returns | When to call |
|--------|---------|--------------|
| `is_handshaking()` | `bool` | Any time |
| `alert()` | `Option<AlertDescription>` | Immediately after `read_hs()` returns `Err` |
| `quic_transport_parameters()` | `Option<&[u8]>` | After peer's hello processed; TLS-encoded wire format |
| `alpn_protocol()` | `Option<&[u8]>` | After handshake progresses (e.g. `b"h3"`) |

### 0-RTT / resumption (client only)

| Method | Returns |
|--------|---------|
| `zero_rtt_keys()` | `Option<DirectionalKeys>` — only on resumed sessions |
| `is_early_data_accepted()` | `bool` — valid after handshake |

### PacketKey / HeaderProtectionKey traits

`encrypt_in_place(packet_number, header, payload, path_id: Option<u32>)` — path_id added in 0.23; always pass `None` for RFC 9000.

## Handshake Data Flow (both sides)

```
[CLIENT]                                    [SERVER]
ClientConnection::new(config, V1, name, tp)
write_hs → buf(ClientHello)
  → send as Initial CRYPTO frame
                                            ServerConnection::new(config, V1, tp)
                                            read_hs(ClientHello)
                                            write_hs → buf(ServerHello+EncExt+Cert+Fin)
                                                      → Some(KeyChange::Handshake {keys})
                                              → send as Handshake CRYPTO frames
read_hs(ServerHello+EncExt+Cert+Fin)
write_hs → Some(KeyChange::Handshake {keys})
  → send Finished at Handshake level
                                            read_hs(Finished)
                                            write_hs → Some(KeyChange::OneRtt {keys, next})
read_hs(server CRYPTO at 1-RTT) if any
write_hs → Some(KeyChange::OneRtt {keys, next})
  is_handshaking() = false
  alpn_protocol() = Some(b"h3")
  quic_transport_parameters() = Some(tp_bytes)
```

## Critical Gotchas

1. **Key material is transferred by value.** `write_hs()` returns `Option<KeyChange>` owning the new keys — store them immediately, don't defer.
2. **Encryption levels are independent.** Once `KeyChange::Handshake` fires, never encrypt at Initial level again. Transitions are one-way.
3. **Transport params are TLS-encoded.** Caller constructs them in RFC 9000 §18 wire format before calling `new()`. rustls does not parse/validate them.
4. **CRYPTO frame reassembly is the caller's responsibility.** rustls does not do QUIC frame ordering. Caller must assemble CRYPTO frames at the correct offset before calling `read_hs`.
5. **Alert must be read synchronously.** Check `alert()` immediately after `read_hs()` returns `Err`; rustls may clear it on the next call.
6. **path_id: Option<u32>** exists in 0.23 for multipath QUIC — always pass `None` for RFC 9000 usage.

## Proposed Wave 2 FFI Surface

New file: `crates/librustls-mojo/src/quic_hs.rs` (or extend `quic.rs`).

**Connection lifecycle (2 functions):**
- `rlsm_quic_client_conn_new(config_handle, version, server_name, server_name_len, transport_params, tp_len) -> i32`
- `rlsm_quic_server_conn_new(config_handle, version, transport_params, tp_len) -> i32`
- `rlsm_quic_conn_free(conn_handle) -> i32`

**Handshake data exchange (2 functions):**
- `rlsm_quic_conn_read_hs(conn_handle, plaintext, len) -> i32` (0=ok, -1=error; check `rlsm_last_error()` for alert text)
- `rlsm_quic_conn_write_hs(conn_handle, out_buf, out_capacity, out_written, out_key_change) -> i32`
  - `out_key_change`: 0=none, 1=Handshake, 2=OneRtt

**Key material retrieval (2 functions):**
- `rlsm_quic_conn_take_keys(conn_handle, out_keys_handle) -> i32` — called after `write_hs` signals a key change; takes the pending `Keys` out of the conn state and puts it in the existing KeysEntry table (reusing Wave 1's handle table)
- `rlsm_quic_conn_take_next_keys(conn_handle, out_keys_handle) -> i32` — post-handshake key update from `Secrets::next_packet_keys()`

**State queries (4 functions):**
- `rlsm_quic_conn_is_handshaking(conn_handle) -> i32` (1=yes, 0=no, -1=error)
- `rlsm_quic_conn_transport_params(conn_handle, out_buf, out_capacity, out_written) -> i32`
- `rlsm_quic_conn_alpn(conn_handle, out_buf, out_capacity, out_written) -> i32`
- `rlsm_quic_conn_alert(conn_handle) -> i32` (AlertDescription code or -1)

**0-RTT (2 functions, optional for M3):**
- `rlsm_quic_conn_zero_rtt_keys(conn_handle, out_keys_handle) -> i32` (0=available, 1=unavailable, -1=error)
- `rlsm_quic_conn_is_early_data_accepted(conn_handle) -> i32`

**Total: ~13 new FFI functions** (vs 10 in Wave 1). Keys reuse the existing `KeysEntry` handle table from Wave 1.
