# Flare-methodology benchmark — navette vs competitors

- Run: 2026-05-20T0649-bench-host-unknown
- Methodology: wrk2 calibrated-peak (Flare docs/benchmark.md).
- Endpoint: GET /plaintext → 13B "Hello, World!", HTTP/1.1 keep-alive.
- Single-worker for every server. Server pinned to CPU 0,
  wrk2 pinned to CPU 2. See env.json.
- Percentile cells: median ± σ over 5 measurement rounds (ms).

| Target | Config | Req/s (median) | σ% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |
|---|---|---:|---:|---:|---:|---:|---:|---|
| actix-web | throughput-1w | 39195 | 1.30 | 2.20 ± 0.11 | 19.53 ± 15.76 | 31.69 ± 19.05 | 39.07 ± 19.76 | true |
| axum | throughput-1w | 38111 | 1.28 | 2.43 ± 0.13 | 13.11 ± 0.95 | 18.91 ± 2.55 | 20.21 ± 2.78 | true |
| go-nethttp | throughput-1w | 23600 | 1.57 | 1.97 ± 0.16 | 11.55 ± 18.93 | 17.36 ± 24.03 | 20.83 ± 24.95 | true |
| hyper | throughput-1w | 40484 | 1.27 | 1.99 ± 0.09 | 11.34 ± 0.64 | 14.51 ± 1.73 | 17.47 ± 2.43 | true |
| navette | throughput-1w | 30346 | 1.57 | 2.10 ± 0.06 | 9.69 ± 3.37 | 14.95 ± 6.27 | 16.45 ± 6.69 | true |
| nginx | throughput-1w | 39630 | 1.58 | 1.98 ± 0.07 | 12.43 ± 1.08 | 20.25 ± 2.54 | 23.20 ± 3.16 | true |
