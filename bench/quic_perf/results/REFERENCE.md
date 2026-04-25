## Host
- Kernel: `Linux 6.19.12-lqx1-1-lqx`
- CPU: `11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz`
- Cores: `8`
- Docker: `29.3.0`
- Date: `2026-04-25T11:34:45Z`
- pidstat: `not installed — server_cpu_percent will be null`

## Reference numbers (from `make bench-mvp` on the host above)

## tquic_client (saturating, 4 threads)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | Ratio |
|---------|------------|---------------------|-----------------|---------------|-------|
| 1k      | long-conn  | 4,444 (1)           | 312 (1)         | —             | 14.26x |
| 1k      | short-conn | 571 (1)             | 28 (1)          | —             | 20.08x |

## h2load-h3 (single-threaded, regression-tracking only)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | Ratio |
|---------|------------|---------------------|-----------------|---------------|-------|
| 1k      | long-conn  | 121 (1)             | 118,951 (1)     | —             | 0.00x |
| 1k      | short-conn | 10 (1)              | 92,623 (1)      | —             | 0.00x |
