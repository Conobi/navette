# Q5 T3 — Smoke gate drift (±5% per host calibration)

**Method:** same-window pre+post pairs, n=3 each, long-conn 1k payload.

## Off-build drift (PROFILE_ACCEPT=False)

- pre-off vals: [14349.8, 14601.2, 14474.4], median = 14474.4
- post-off vals: [14494.9, 14712.9, 14973.2], median = 14712.9
- **drift: +1.65%** (gate ±5%) — **PASS**

## On-build drift (PROFILE_ACCEPT=True)

- pre-on vals: [14950.2, 14908.7, 14916.6], median = 14916.6
- post-on vals: [14601.7, 14671.3, 14646.3], median = 14646.3
- **drift: -1.81%** (gate ±5%) — **PASS**

