# Research Plan — Q3 Dict[UInt64, Int] DCID demux microopt

**Spec target:** replace `Dict[String, Int]` (hex-string-keyed) DCID demux table in `bench/h3_server.mojo` with `Dict[UInt64, Int]` (packed-DCID-keyed) via a new `_dcid_to_u64` helper. Predecessor scoping at `research/2026-04-28-pop-dispatch-finer-split.md`.

**Date:** 2026-04-28

## Topic Table

| # | Topic | Status | Depends on | Priority | Rationale |
|---|-------|--------|------------|----------|-----------|
| 1 | Codebase verification post-Sprint-2 merge | in-progress | — | high | Subagent C's research was on 2026-04-28 pre-merge. Sprint 2 landed ~9.5K LoC since (h3_streaming_server, h3_sync_server, etc.) — line numbers may have drifted. Need exact current call sites + full enumeration of every reader/writer of `conn_dcid_map` + `conn_dcids` + `_bytes_to_hex` to scope blast radius. |
| 2 | Mojo 0.26.2 `Dict[UInt64, Int]` vs `Dict[String, Int]` internals | in-progress | — | high | The whole spec rests on the assumption that integer-keyed Dict is meaningfully faster than hex-string-keyed Dict at 36k entries. Need to verify via Mojo MCP: hash function for String vs UInt64, bucket layout/sizing, per-entry memory, whether String hash is cached. If Mojo's String hash is already O(1)-cached, the cache-miss-reduction half of the lift estimate evaporates. |
| 3 | Reference QUIC stacks — CID-keyed conn-map key type | in-progress | — | medium | What key type do TQUIC, quiche, lsquic, quic-go, aioquic use for their CID demux map? Raw bytes? Packed u64? Custom hasher? Validates the `_dcid_to_u64` direction against prior art (per `feedback_mirror_tquic.md`). |
| 4 | Bench measurement / gate design for sub-percent lifts | in-progress | 1, 2 (synthesised post-hoc) | medium | Conservative estimate is 0.5–1.4% RPS uplift on short-conn. Our 10-iter median IQR sits around 2–3% — RPS gate would be below noise floor. Should the gate use the new sub-leg instrumentation directly (e.g. `loop_pop_dispatch.total drops ≥X μs`) instead of RPS? Validates measurement methodology before spec lockdown. |

## Dependency Graph

```
  ┌─ Topic 1 (codebase) ──┐
  │                       ├──► Topic 4 (gate design)
  └─ Topic 2 (Mojo Dict) ─┘

  Topic 3 (ref stacks) — independent, runs in parallel
```

All 4 topics dispatched in parallel for speed; Topic 4 drafts from the existing 2026-04-28 reports and may need a brief re-spin if Topic 1/2 findings shift the cost model.

## Output paths

- `research/2026-04-28-q3-codebase-verification.md` (Topic 1)
- `research/2026-04-28-q3-mojo-dict-internals.md` (Topic 2)
- `research/2026-04-28-q3-reference-stacks-cid-keys.md` (Topic 3)
- `research/2026-04-28-q3-bench-gate-design.md` (Topic 4)
