# Research Plan: librustls Wave 2 + QUIC Transport Core (M3)

> Previous plan (LLVM coroutine intrinsics) superseded — ucontext via C FFI is shipped and working in boucle/stackful.mojo. Topics 1–5 done (Wave 2 scope). Topics 6–13 done (M3 safety deep dive, 2026-04-14).

## Topic Table

| # | Topic | Status | Depends on | Priority | Rationale |
|---|-------|--------|------------|----------|-----------|
| 1 | rustls::quic handshake API | **done** | — | critical | → `research/quic-rustls-wave2-api.md`. 13 new FFI functions: 2 conn_new, read_hs/write_hs, take_keys/take_next_keys, 4 state queries, 2 0-RTT. Keys reuse Wave 1 KeysEntry table. |
| 2 | TQUIC architecture survey | **done** | — | critical | → `research/tquic-architecture.md`. BitFlags SM, 3 PacketNumSpace, StreamMap+priority, loss recovery in M3 (non-deferrable), CC pluggable trait in M4. |
| 3 | QUIC RFC 9000 transport core | **done** | — | high | → `research/quic-rfc9000-transport-scope.md`. 11 M3 frame types, 5 packet types, dual-level FC, stream states, RTT estimation + threshold loss in M3. |
| 4 | QUIC conformance tooling | **done** | 2, 3 | high | → `research/quic-conformance-tooling.md`. aioquic recommended. QC-1 ~35–45 vectors (crypto), QC-2 ~40–55 vectors (QPACK+H3). RFC 9001 Appendix A has initial key vectors. |
| 5 | QPACK + HTTP/3 framing scope | **done** | 2, 3 | medium | → `research/qpack-h3-scope.md`. Static-only QPACK viable for M5 (99 static entries). M3/M5 split confirmed. ~2100–3000 M5 LoC. |

## Dependency Graph

```
1. rustls::quic handshake API  ──────────────┐
                                              ▼
2. TQUIC architecture survey  ──────────────► 4. Conformance tooling
                                              ▲
3. QUIC RFC 9000 transport core ─────────────┘
                    │
                    ▼
             5. QPACK + HTTP/3 framing scope
```

## Context

- **Wave 1 (done):** QUIC Initial keys only — AEAD encrypt/decrypt + header protection, 10 FFI functions in `crates/librustls-mojo/src/quic.rs`
- **Wave 2 (target):** TLS 1.3 handshake lifecycle over QUIC — `rustls::quic::ClientConnection` / `ServerConnection`, key schedule progression (Initial → Handshake → 1-RTT), session resumption / 0-RTT
- **M3 target:** QUIC transport core in Mojo — packet parser, packet number spaces, connection state machine, flow control, stream multiplexing
- **Constraint:** Sans-I/O at every protocol layer; `boucle.stackful` is the only allowed I/O-adjacent primitive in `src/`
- **Style inspiration:** TQUIC (tencent/tquic) — near one-to-one replication where YAGNI/SOLID allows
