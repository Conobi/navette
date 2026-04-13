# Spec: Wave 2 — librustls QUIC Handshake Lifecycle

**Date:** 2026-04-13
**Status:** approved
**Predecessors:**
- `crates/librustls-mojo/src/quic.rs` (Wave 1 — Initial keys, AEAD, HP)
- `crates/librustls-mojo/src/tcp.rs` (TCP TLS — pattern reference)
- `research/quic-rustls-wave2-api.md` (rustls::quic API surface)
- `research/tquic-architecture.md` (TQUIC module reference)
- `research/quic-rfc9000-transport-scope.md` (M3 transport scope)

## Goal

Extend `librustls-mojo` with 15 new `extern "C"` FFI functions that expose the full TLS 1.3 handshake lifecycle over QUIC — connection creation, CRYPTO frame exchange, key-schedule progression (Initial → Handshake → 1-RTT), state queries, and 0-RTT stubs.

This is the **sole prerequisite for M3** (QUIC transport core). It does not include any Mojo bindings (those live in M3 alongside the QUIC transport that calls them) or QC-1 conformance vectors (separate milestone).

## Non-goals

- Mojo wrapper types — deferred to M3
- QC-1 conformance vectors and oracle scripts — separate milestone
- `reject_early_data()` server-side 0-RTT rejection — add in M4 if needed
- Config `_free` functions — connections hold `Arc`; handles are freed via `HandleTable::remove`
- Certificate validation override or custom verifier — use rustls defaults (webpki-roots for client)
- Key update cycling (calling `take_next_keys` repeatedly) — M3 stub that returns -1 until 1-RTT keys are installed

## Module layout

```
crates/librustls-mojo/src/
├── lib.rs           ← add re-exports for all Wave 2 functions
├── quic.rs          ← Wave 1 unchanged (KEYS_TABLE reused by Wave 2)
└── quic_hs.rs       ← Wave 2 (new)
```

All 15 new functions are declared in `quic_hs.rs` and re-exported from `lib.rs`.

## Handle tables

Wave 2 introduces three static handle tables inside `quic_hs.rs`:

```rust
// TLS configs — QUIC-specific (explicit ALPN control, not shared with TCP)
// QUIC configs are process-lifetime singletons; callers must not create them in unbounded loops.
static QUIC_CLIENT_CFG_TABLE: OnceLock<HandleTable<Arc<ClientConfig>>> = OnceLock::new();
static QUIC_SERVER_CFG_TABLE: OnceLock<HandleTable<Arc<ServerConfig>>> = OnceLock::new();

// QUIC TLS connections
static QUIC_CONN_TABLE: OnceLock<HandleTable<QuicConnEntry>> = OnceLock::new();
```

Wave 2 also reads/writes `KEYS_TABLE` from `quic.rs` — keys from `KeyChange` are materialized directly into Wave 1's handle table as `KeysEntry` objects. The following items in `quic.rs` must be changed from private to `pub(crate)`:
- `fn keys_table() -> &'static HandleTable<KeysEntry>`
- `struct KeysEntry` (and all its fields: `local`, `remote`, `last_local_pn`)

Alternatively, add a `pub(crate) fn insert_keys_entry(local: DirectionalKeys, remote: DirectionalKeys) -> Option<i32>` helper in `quic.rs` to avoid exposing the struct directly — either approach is acceptable.

## Internal types (quic_hs.rs)

```rust
enum QuicConn {
    Client(rustls::quic::ClientConnection),
    Server(rustls::quic::ServerConnection),
}

struct QuicConnEntry {
    conn: QuicConn,
    /// Pending key change: (kind, keys). Kind: 1=Handshake, 2=OneRtt.
    /// Atomically coupled — kind and keys are always set/cleared together.
    /// None when no key change is pending (or after take_keys has consumed it).
    pending: Option<(u8, Keys)>,
    /// 1-RTT key-update secrets from KeyChange::OneRtt. Populated by take_keys
    /// when kind==2; consumed by take_next_keys. Retained until conn_free.
    next_secrets: Option<Secrets>,
    /// Cached alert code from the most recent failed read_hs call.
    /// Populated by rlsm_quic_conn_read_hs on error; cleared and returned by rlsm_quic_conn_alert.
    alert_cache: Option<u8>,
}
```

`pending` is a single `Option<(u8, Keys)>` that atomically couples the key-change kind signal with the key material — no separate `pending_kind` that could desync. `next_secrets` lives separately because it has a longer lifetime: it persists after `take_keys` consumes the pending keys and is only used (and consumed) when `take_next_keys` is called.

## FFI function catalogue

All functions return `0` on success, `-1` on error. On error, `rlsm_last_error()` (existing Wave 1 API) holds a NUL-terminated description string. Integer output parameters are written via raw pointers; callers must provide valid non-null pointers for output parameters.

**Return convention note:** Wave 2 functions consistently return `0`/`-1` status with handles written into `*out_handle` output parameters. This differs from Wave 1's `rlsm_initial_keys` which returns the handle directly as a positive integer. Both conventions coexist in the library; M3 callers must use the output-parameter form for all Wave 2 calls.

### §1 Config lifecycle — 2 functions

```c
/**
 * Create a QUIC client TLS config.
 *
 * Uses webpki-roots as the CA bundle (no custom CA support in Wave 2).
 * alpn_ptr/alpn_len: raw protocol identifier bytes, e.g. for "h3": alpn_ptr=[0x68, 0x33], alpn_len=2.
 *   Do NOT include a length prefix — pass only the raw bytes of the protocol name.
 * On success: *out_handle is a config handle valid for rlsm_quic_client_conn_new.
 */
int32_t rlsm_quic_client_config_new(
    const uint8_t *alpn_ptr, uint32_t alpn_len,
    int32_t *out_handle
);

/**
 * Create a QUIC server TLS config.
 *
 * cert_pem: PEM-encoded certificate chain (chain first, root last).
 * key_pem:  PEM-encoded private key.
 * alpn_ptr/alpn_len: raw protocol identifier bytes (same format as client config — no length prefix).
 * On success: *out_handle is a config handle valid for rlsm_quic_server_conn_new.
 */
int32_t rlsm_quic_server_config_new(
    const uint8_t *cert_pem,  uint32_t cert_len,
    const uint8_t *key_pem,   uint32_t key_len,
    const uint8_t *alpn_ptr,  uint32_t alpn_len,
    int32_t *out_handle
);
```

### §2 Connection lifecycle — 3 functions

```c
/**
 * Create a new QUIC client connection.
 *
 * config_handle: from rlsm_quic_client_config_new.
 * version: 1 = QUIC v1 (RFC 9000), 2 = QUIC v2 (RFC 9369).
 * server_name/name_len: UTF-8 SNI hostname bytes (no NUL terminator needed).
 * transport_params/tp_len: RFC 9000 §18 wire-encoded transport parameters.
 * On success: *out_handle is a connection handle.
 */
int32_t rlsm_quic_client_conn_new(
    int32_t config_handle,
    int32_t version,
    const uint8_t *server_name, uint32_t name_len,
    const uint8_t *transport_params, uint32_t tp_len,
    int32_t *out_handle
);

/**
 * Create a new QUIC server connection.
 *
 * config_handle: from rlsm_quic_server_config_new.
 * transport_params/tp_len: RFC 9000 §18 wire-encoded transport parameters.
 * On success: *out_handle is a connection handle.
 */
int32_t rlsm_quic_server_conn_new(
    int32_t config_handle,
    int32_t version,
    const uint8_t *transport_params, uint32_t tp_len,
    int32_t *out_handle
);

/**
 * Free a QUIC connection. Also frees any buffered pending key change.
 * Returns 0. Returns -1 if conn_handle is not found (no-op).
 */
int32_t rlsm_quic_conn_free(int32_t conn_handle);
```

### §3 Handshake data exchange — 2 functions

```c
/**
 * Feed CRYPTO frame payload to the TLS state machine.
 *
 * plaintext/len: raw TLS handshake bytes for the CURRENT encryption level
 *   (caller is responsible for CRYPTO frame reassembly and level tracking).
 *   Call once per encryption level per batch (Initial bytes in one call,
 *   Handshake bytes in another, etc.).
 *
 * Returns 0=ok, -1=TLS error.
 * On error: rlsm_last_error() contains the alert description string,
 *           rlsm_quic_conn_alert(conn_handle) returns the numeric code.
 */
int32_t rlsm_quic_conn_read_hs(
    int32_t conn_handle,
    const uint8_t *plaintext, uint32_t len
);

/**
 * Drain outgoing TLS bytes from the state machine into caller's buffer.
 *
 * Bytes written are for the CURRENT encryption level. The caller tracks
 * which level is active: Initial until first KeyChange, Handshake after
 * KeyChange::Handshake, 1-RTT after KeyChange::OneRtt.
 *
 * out_buf/out_capacity: caller-provided output buffer. 4096 bytes is
 *   sufficient for all TLS messages in any single write_hs call.
 * *out_written: set to the number of bytes written.
 * *out_key_change_type: 0=no change, 1=KeyChange::Handshake, 2=KeyChange::OneRtt.
 *
 * After a non-zero out_key_change_type, caller MUST call
 * rlsm_quic_conn_take_keys before the next call to rlsm_quic_conn_write_hs.
 * Calling write_hs with a pending key change returns -1.
 *
 * Implementation note: internally allocates a Vec<u8>, calls conn.write_hs(&mut vec),
 * verifies vec.len() <= out_capacity, then copies to out_buf.
 *
 * Returns 0=ok, -1=error (buffer too small or invalid handle).
 */
int32_t rlsm_quic_conn_write_hs(
    int32_t conn_handle,
    uint8_t  *out_buf,       uint32_t out_capacity,
    uint32_t *out_written,
    uint8_t  *out_key_change_type
);
```

**Encryption level tracking:** The caller, not rustls, tracks the current level. Each call to `write_hs` produces bytes for exactly one level (rustls stops at each key-change boundary). The sequence is always: Initial bytes → `KeyChange::Handshake` → Handshake bytes → `KeyChange::OneRtt` → 1-RTT bytes. This sequence is one-way; levels never go backwards.

### §4 Key materialization — 2 functions

```c
/**
 * Move the pending Keys (set by the most recent write_hs key-change signal)
 * into Wave 1's KEYS_TABLE. Returns the new keys handle in *out_keys_handle.
 *
 * The handle returned is identical in semantics to handles from
 * rlsm_initial_keys() (Wave 1) and can be used with all Wave 1
 * encrypt/decrypt/header-protect functions.
 *
 * Returns -1 if no pending key change exists or handle is invalid.
 * The pending key change is consumed; calling take_keys a second time
 * without a new write_hs key change returns -1.
 */
int32_t rlsm_quic_conn_take_keys(
    int32_t conn_handle,
    int32_t *out_keys_handle
);

/**
 * Derive the next 1-RTT packet keys from the Secrets stored after a
 * KeyChange::OneRtt event. Used for post-handshake key updates (RFC 9001 §6).
 *
 * NOTE (M3 stub): Returns -1 unless a KeyChange::OneRtt has been processed.
 * Full key-update cycling (calling multiple times) is a M4 feature.
 * out_keys_handle receives a handle to a KeysEntry with new packet keys;
 * header protection keys are NOT updated by key updates (RFC 9001 §6.3 —
 * the same hp keys remain in use; only packet keys rotate).
 *
 * Implementation note: PacketKeySet has only packet keys (no HP keys).
 * The returned KeysEntry will have no-op HeaderProtectionKey wrappers that
 * return Err("key update: header protection key not available") — so any
 * accidental HP call on a key-update handle fails loudly rather than silently.
 */
int32_t rlsm_quic_conn_take_next_keys(
    int32_t conn_handle,
    int32_t *out_keys_handle
);
```

### §5 State queries — 4 functions

```c
/**
 * Returns 1 if the TLS handshake is still in progress, 0 if complete, -1 on error.
 * Transitions to 0 after both endpoints have exchanged Finished messages.
 */
int32_t rlsm_quic_conn_is_handshaking(int32_t conn_handle);

/**
 * Copy the peer's TLS-encoded transport parameters into out_buf.
 *
 * Returns 0 and sets *out_written if available (trustworthy only after
 * handshake completes — rlsm_quic_conn_is_handshaking returns 0).
 * Returns 1 (with *out_written=0) if not yet available.
 * Returns -1 on error (invalid handle or buffer too small).
 *
 * Wire format: RFC 9000 §18 (varint-length-prefixed parameter pairs).
 */
int32_t rlsm_quic_conn_transport_params(
    int32_t conn_handle,
    uint8_t *out_buf, uint32_t out_capacity,
    uint32_t *out_written
);

/**
 * Copy the negotiated ALPN protocol bytes into out_buf.
 *
 * Returns 0 and sets *out_written after ALPN is available.
 * Returns 1 (with *out_written=0) if ALPN negotiation has not completed.
 * Returns -1 on error.
 *
 * Example: for "h3", writes 0x68 0x33, *out_written = 2.
 */
int32_t rlsm_quic_conn_alpn(
    int32_t conn_handle,
    uint8_t *out_buf, uint32_t out_capacity,
    uint32_t *out_written
);

/**
 * Return the numeric TLS AlertDescription code if a fatal alert has been
 * raised, or -1 if no alert or invalid handle.
 *
 * The alert code is cached in QuicConnEntry.alert_cache when read_hs returns -1.
 * rlsm_quic_conn_alert reads and CLEARS the cache — subsequent calls return -1
 * until the next read_hs error. Call immediately after read_hs failure.
 */
int32_t rlsm_quic_conn_alert(int32_t conn_handle);
```

### §6 0-RTT stubs — 2 functions (not exercised in M3)

```c
/**
 * If a previous session was resumed with 0-RTT, writes the local
 * (client-encrypt / server-encrypt) DirectionalKeys into KEYS_TABLE
 * and returns the handle in *out_keys_handle.
 *
 * Returns 0=available, 1=not available (fresh session or resumption
 * disabled), -1=error.
 *
 * NOTE: Only valid on client connections immediately after connection
 * creation, before any write_hs calls.
 */
int32_t rlsm_quic_conn_zero_rtt_keys(
    int32_t conn_handle,
    int32_t *out_keys_handle
);

/**
 * Returns 1 if the server accepted the client's early data (0-RTT),
 * 0 if rejected or not applicable, -1 on error.
 *
 * Valid only on client connections after the handshake completes
 * (rlsm_quic_conn_is_handshaking returns 0).
 */
int32_t rlsm_quic_conn_is_early_data_accepted(int32_t conn_handle);
```

## Key materialization: bridge to Wave 1

When `write_hs` returns `Some(KeyChange)`, the `Keys` struct is stored in `QuicConnEntry.pending`. On `take_keys`, this is consumed and inserted into Wave 1's `KEYS_TABLE`:

```rust
// Inside rlsm_quic_conn_take_keys (pseudocode — use match, not ?, in extern "C"):
let (kind, keys) = match entry.pending.take() {
    Some(p) => p,
    None => { set_last_error("no pending key change"); return -1; }
};
let new_entry = KeysEntry {
    local: keys.local,
    remote: keys.remote,
    last_local_pn: None,
};
// For OneRtt, rustls::quic::ClientConnection::write_hs returns the Secrets
// via KeyChange::OneRtt { keys, next }. The caller must have stashed `next` in
// entry.next_secrets when storing the pending change in write_hs:
//   KeyChange::OneRtt { keys, next } => {
//       entry.pending = Some((2, keys));
//       entry.next_secrets = Some(next);
//   }
// take_keys reads only pending — next_secrets is already set and persists.
let keys_handle = keys_table().insert(new_entry);
*out_keys_handle = keys_handle;
```

**Note:** Pseudocode uses `match` rather than `?` because `?` does not compile in `extern "C"` functions.

The resulting handle is fully compatible with Wave 1 AEAD and header-protection functions (`rlsm_keys_local_encrypt`, `rlsm_keys_remote_decrypt`, `rlsm_keys_local_header_protect`, `rlsm_keys_remote_header_unprotect`).

For `KeyChange::OneRtt { keys, next }`: `next` (type `Secrets`) is stored in `entry.next_secrets` at `write_hs` call time, simultaneously with storing the pending key change. `take_keys` only consumes the pending key material; `next_secrets` remains available for `take_next_keys`.

## Handshake call sequence (both sides)

```
CLIENT                                  SERVER

rlsm_quic_client_config_new             rlsm_quic_server_config_new
rlsm_quic_client_conn_new               rlsm_quic_server_conn_new

write_hs → (ClientHello bytes,          read_hs(ClientHello bytes)
            key_change=0)               write_hs → (ServerHello+EncExt+Cert+Fin bytes,
→ CRYPTO frame at Initial level                     key_change=1 = Handshake)
                                        take_keys → Handshake keys handle
                                        → CRYPTO frames at Handshake level

read_hs(ServerHello+EncExt+Cert+Fin)
write_hs → (Finished bytes,
            key_change=1 = Handshake)
take_keys → Handshake keys handle
→ CRYPTO frame at Handshake level
                                        read_hs(Finished)
                                        write_hs → (HANDSHAKE_DONE bytes,
                                                    key_change=2 = OneRtt)
                                        take_keys → 1-RTT keys handle
                                        → CRYPTO frame at 1-RTT level

read_hs(HANDSHAKE_DONE bytes)
write_hs → (empty, key_change=2 = OneRtt)
take_keys → 1-RTT keys handle
is_handshaking → 0
alpn → "h3"
transport_params → peer's RFC 9000 §18 bytes
```

## Error propagation

Identical pattern to Wave 1 and TCP modules:

```rust
// On any error:
set_last_error("description");
return -1;

// Caller checks:
int rc = rlsm_quic_conn_read_hs(handle, data, len);
if rc < 0 {
    let alert = rlsm_quic_conn_alert(handle); // AlertDescription code
    let msg = rlsm_last_error();              // human-readable string
}
```

## Buffer sizing guidelines

| Call | Typical output | Safe buffer |
|------|---------------|-------------|
| `write_hs` (ClientHello) | ~350–900 bytes | 4096 |
| `write_hs` (Finished) | ~52 bytes | 4096 |
| `transport_params` | ~100–500 bytes | 1024 |
| `alpn` | 2–8 bytes | 32 |

A single 4096-byte buffer is sufficient for `write_hs` in all cases.

## Tests

Wave 2 must ship with the following Rust unit tests in `quic_hs.rs`:

| # | Test | Description |
|---|------|-------------|
| T1 | `test_full_handshake_client_server` | Complete handshake between an in-memory client and server; verify both sides reach `is_handshaking=0`, matching ALPN, valid transport params, and valid 1-RTT key handles |
| T2 | `test_handshake_keys_available` | After server processes ClientHello, verify `take_keys` returns a Handshake key handle usable with Wave 1 AEAD |
| T3 | `test_1rtt_keys_available` | After handshake, verify `take_keys` returns a 1-RTT key handle; Wave 1 encrypt succeeds with packet_number=0 |
| T4 | `test_double_take_keys_returns_error` | Calling `take_keys` twice without an intervening `write_hs` key change returns -1 |
| T5 | `test_write_hs_with_pending_key_returns_error` | Calling `write_hs` when `pending_kind != 0` returns -1 |
| T6 | `test_alert_on_bad_read_hs` | Feeding garbage bytes to `read_hs` returns -1; `rlsm_quic_conn_alert` returns a non-negative code |
| T7 | `test_transport_params_unavailable_before_hello` | `transport_params` returns 1 (unavailable) before the peer's hello is processed |
| T8 | `test_transport_params_available_after_handshake` | `transport_params` returns 0 with non-empty bytes after handshake |
| T9 | `test_0rtt_keys_unavailable_fresh_session` | `zero_rtt_keys` returns 1 (unavailable) on a fresh (non-resumed) client connection |
| T10 | `test_conn_free_with_pending_key_returns_ok` | Freeing a connection with a pending key change returns 0 and the handle is removed from the table (subsequent operations on the same handle return -1) |

## LoC estimate

| Component | LoC |
|-----------|-----|
| Config creation (2 functions) | 80–120 |
| Connection lifecycle (3 functions) | 100–150 |
| `write_hs` + `read_hs` (2 functions) | 100–150 |
| `take_keys` + `take_next_keys` (2 functions) | 80–120 |
| State queries (4 functions) | 80–120 |
| 0-RTT stubs (2 functions) | 40–60 |
| Internal types + table setup | 60–80 |
| Tests (10 tests) | 300–450 |
| `lib.rs` re-exports | 15–20 |
| **Total** | **~855–1270** |
