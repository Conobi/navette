# Flare-methodology benchmark — navette vs competitors

- Run: 2026-05-20T0750-bench-host-unknown
- Methodology: wrk2 calibrated-peak (Flare docs/benchmark.md).
- Endpoint: GET /plaintext → 13B "Hello, World!", HTTP/1.1 keep-alive.
- Single-worker for every server. Server pinned to CPU 0,
  wrk2 pinned to CPU 2. See env.json.
- Percentile cells: median ± σ over 5 measurement rounds (ms).

| Target | Config | Req/s (median) | σ% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |
|---|---|---:|---:|---:|---:|---:|---:|---|
| flare | throughput-1w | 34219 | 0.00 | 1.80 ± 0.04 | 9.08 ± 0.95 | 13.75 ± 3.10 | 17.58 ± 3.92 | true |
