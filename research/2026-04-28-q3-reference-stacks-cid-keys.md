# Topic 3 — CID Demux Key Type Across Reference QUIC Stacks

**Date:** 2026-04-28
**Context:** Brainstorming `Dict[String,Int]` (16-char hex) → `Dict[UInt64,Int]` (packed 8-byte DCID) migration of `bench/h3_server.mojo`'s `conn_dcid_map`. Targeting ~6% short-conn RPS uplift. Surveys 5 production QUIC stacks for what their CID-keyed demux table looks like.

## Summary table

| Stack | Language | CID key type | Hasher | Pack to int? | Source |
|---|---|---|---|---|---|
| TQUIC (Tencent) | Rust | `ConnectionId { len: u8, data: [u8; 20] }` (21-byte struct, derives `Hash`) | `FxHashMap` (rustc_hash / FxHash) | No — fixed-size byte array, hashed bytewise | `src/endpoint.rs:872`; type at `src/lib.rs:160-167` |
| quiche (Cloudflare) | Rust | `ConnectionId<'static>` wrapping `Vec<u8>` (variable length) | `std::collections::HashMap` (RandomState / SipHash-1-3) | No — `Vec<u8>` hashed via `as_ref().hash(state)` | `apps/src/common.rs:103`; type at `quiche/src/packet.rs:186-261` |
| lsquic (LiteSpeed) | C | `lsquic_cid_t { len, buf[20] }` — table key is raw `idbuf` + length (variable) | Custom `lsquic_hash` using `rapidhash_withSeed` | No — variable-length bytes, hashed directly | `src/liblsquic/lsquic_engine.c:247,1137,1409`; hash at `src/liblsquic/lsquic_hash.c:91` |
| quic-go | Go | `protocol.ConnectionID { b [20]byte; l uint8 }` (21-byte struct) | Go runtime `memhash` (built-in for map[T]V comparable structs) | No — fixed 20-byte array; uses Go's value-hash | `transport.go:138`; type at `internal/protocol/connection_id.go:35-38` |
| aioquic | Python | `bytes` (raw `header.destination_cid`, variable length) | CPython dict default (SipHash-1-3 via PEP 456) | No — `bytes` is the dict key directly | `src/aioquic/asyncio/server.py:36,86,148-149` |

## Per-stack details

### TQUIC (Tencent)

`src/endpoint.rs:870-878`:
```rust
struct ConnectionTable {
    /// Connections identified based on the locally created CID.
    cid_table: FxHashMap<ConnectionId, u64>,
    /// Connections identified by the four tuple.
    addr_table: HashMap<FourTuple, u64>,
    token_table: FxHashMap<ResetToken, u64>,
    ...
}
```

`src/lib.rs:158-167`:
```rust
/// Connection Id is an identifier used to identify a QUIC connection at an endpoint.
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct ConnectionId {
    len: u8,
    data: [u8; MAX_CID_LEN],   // MAX_CID_LEN = 20
}
```

- `Hash` is derived (default field-wise hashing across `len` + all 20 `data` bytes).
- Hasher is `rustc_hash::FxHashMap` (FxHash — fast, non-cryptographic; chosen by import; no inline rationale comment).
- Note the dual table: `cid_table` keyed by CID, `addr_table` keyed by 4-tuple. The CID table is authoritative for short-header packets; addr_table handles long-header / new-connection fallback.

### quiche (Cloudflare)

quiche's library exposes `ConnectionId<'a>` as either owned `Vec<u8>` or borrowed `&[u8]` (`quiche/src/packet.rs:186-191`). The `Hash` impl forwards to the byte slice (`quiche/src/packet.rs:256-261`), so length is not part of the hash directly but the byte slice naturally encodes it.

The actual server demux lives in the example apps — quiche is sans-I/O, so the production-shape reference is `apps/src/bin/quiche-server.rs` + `apps/src/common.rs:103`:
```rust
pub type ClientIdMap = HashMap<ConnectionId<'static>, ClientId>;
pub type ClientMap   = HashMap<ClientId, Client>;
```

- Default `std::collections::HashMap` (no custom hasher; uses `RandomState` = SipHash-1-3).
- Two-level lookup: CID → `ClientId` (a `u64`), `ClientId` → full `Client` state. This matches mojo-net's two-level shape (CID → idx, idx → conn).

### lsquic (LiteSpeed)

`include/lsquic_types.h:27-32`:
```c
typedef struct ALIGNED_(8) lsquic_cid {
    uint8_t   buf[MAX_CID_LEN];   // MAX_CID_LEN = 20
#define idbuf buf
    uint_fast8_t len;
} lsquic_cid_t;
```

The hash table is `engine->conns_hash` (`src/liblsquic/lsquic_engine.c:247`). Insert at line 1137:
```c
lsquic_hash_insert(engine->conns_hash, cce->cce_cid.idbuf, cce->cce_cid.len, conn, &cce->cce_hash_el)
```

Lookup at line 1409 / 1458 / 1643 uses `lsquic_hash_find(engine->conns_hash, cid->idbuf, cid->len)`.

The hash table itself (`src/liblsquic/lsquic_hash.c:88-92`):
```c
struct lsquic_hash * lsquic_hash_create (void) {
    return lsquic_hash_create_ext(memcmp, rapidhash_withSeed);
}
```

- Custom open-addressing hash, `memcmp` for equality, `rapidhash_withSeed` (recent rapidhash variant) for the hash function.
- Per-table seed `qh_hash_seed = get_seed() ^ (uint64_t)hash` (HashDoS mitigation).
- Variable-length keys hashed directly — no packing to integer.

### quic-go

`transport.go:137-139`:
```go
mutex       sync.Mutex
handlers    map[protocol.ConnectionID]packetHandler
resetTokens map[protocol.StatelessResetToken]packetHandler
```

`internal/protocol/connection_id.go:32-38`:
```go
const maxConnectionIDLen = 20

// A ConnectionID in QUIC
type ConnectionID struct {
    b [20]byte
    l uint8
}
```

- ConnectionID is a comparable Go value type (fixed-size array + uint8) — Go uses runtime `memhash` over its representation (~21 bytes).
- No custom hasher; relies on the runtime map.
- Note `protocol.ConnectionID` is also used directly in the connection-state machine (see `conn_id_manager.go`, `conn_id_generator.go`); the same struct is the table key.

### aioquic

`src/aioquic/asyncio/server.py:36`:
```python
self._protocols: dict[bytes, QuicConnectionProtocol] = {}
```

`src/aioquic/asyncio/server.py:86,148-149`:
```python
protocol = self._protocols.get(header.destination_cid, None)
...
self._protocols[header.destination_cid] = protocol
self._protocols[connection.host_cid] = protocol
```

- Plain CPython `dict[bytes, ...]` — bytes hashed via SipHash-1-3 (PEP 456, with per-process random seed).
- Notable: aioquic registers BOTH the original-DCID and the server-chosen host_cid as separate keys (matches the "B-permissive dual-DCID" pattern called out in the project's prior research note).

## Verdict

`Dict[UInt64, Int]` (packed 8-byte DCID into a u64) is **NOT** mirrored exactly by any of the five surveyed stacks. **All five hash variable-or-fixed-length CID bytes directly**, none pre-pack to a u64.

That said, mojo-net is in a uniquely strong position to do so because the prior `addr_key→DCID` migration spec **locked the SCID length at exactly 8 bytes** (`debug_assert(len==8)` at `bench/h3_server.mojo`, per the project-context line about "the 8-byte SCID invariant"). The reference stacks all support variable-length CIDs (up to 20 bytes), so they cannot pack into a u64 without losing generality. mojo-net's bench server has no such constraint and can legitimately specialize.

**Closest prior art:**
- TQUIC's `ConnectionId { len: u8, data: [u8; 20] }` derives `Hash` byte-wise — but the underlying hasher is FxHash, which itself reduces 8 bytes to a u64 internally with a single `wrapping_mul` and an `xor`. So the CPU cost on TQUIC's hot path for an 8-byte CID is roughly: one 64-bit load + one mul + one xor + table probe. A `Dict[UInt64, Int]` with a no-op-or-mix-only hasher in Mojo has a comparable lower bound; the gain comes from skipping the `String` allocation + UTF-8 hex-encode that `Dict[String, Int]` currently incurs per packet.
- quic-go gets close to "fixed-size struct as map key" — and Go's memhash is also fast-path optimized for small fixed-size keys. The packed-u64 spec is essentially "skip the struct wrapper since len is invariant."

**Verdict:** the migration is **consistent with prior art's intent** (eliminate variable-length string handling on the demux hot path) but **more aggressive than any surveyed stack** (no stack actually packs to u64 because none can — all support variable-length CIDs). The justification is the 8-byte SCID invariant unique to mojo-net's bench scope.

## Surprises / red flags

1. **No stack uses a default-hasher std::HashMap with String keys.** Three out of five (TQUIC, lsquic, quic-go) use either FxHash or a custom rapidhash; even quiche, which uses default RandomState, keys on `Vec<u8>`/`&[u8]` rather than a String. The current mojo-net `Dict[String, Int]` (16-char hex) is the **outlier**, not the spec's proposed `Dict[UInt64, Int]`. The migration moves mojo-net **closer to** mainstream, not further from it.
2. **lsquic uses rapidhash, not FxHash.** rapidhash is newer (post-2023) and ~30% faster than FxHash on small keys per its benchmarks. If Mojo's stdlib `Dict[UInt64, _]` uses a generic mix function, that's already competitive; if Mojo's u64 hasher is identity-like (common for u64 keys in hash maps that assume already-randomized inputs), it will be **faster** than any of these five stacks for the 8-byte CID lookup.
3. **TQUIC keeps a parallel `addr_table: HashMap<FourTuple, u64>`** (default RandomState, not FxHash). The CID table is the hot path; addr_table is fallback for new conns / NAT rebinding. mojo-net's prior migration removed addr_key entirely; TQUIC keeps both. Not a red flag for the spec, but a structural difference worth noting if mojo-net ever needs NAT rebinding handling.
4. **aioquic registers both the original-DCID and the host_cid as separate keys** — the dual-DCID pattern. mojo-net's current spec already does this (per the addr_key→DCID retrospective: "dual-DCID insert with debug_assert(len==8)"), so no change needed. Just a confirmation that the pattern is canonical.
5. **None of the five stacks have a code comment justifying their hasher choice.** No "// using FxHash because..." comments. The choice is implicit / idiomatic per ecosystem (Rust → FxHash for perf, C → custom, Go → runtime, Python → built-in). Don't expect to find external rationale — the spec needs to stand on its own measured uplift (~6% short-conn RPS).
