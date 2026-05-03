# Gate-width derivation — n=10 long-conn quiesced calibration

**Date:** 2026-05-03  **Image:** `mojo-net-bench:gate-cal-off` (main `2a5defb`, PROFILE_ACCEPT=False)

## Raw values

| iter | rps |
|---|---|
| 1 | 15013.1 |
| 2 | 14953.4 |
| 3 | 14881.8 |
| 4 | 15156.8 |
| 5 | 15077.6 |
| 6 | 15122.9 |
| 7 | 15088.1 |
| 8 | 15155.0 |
| 9 | 15007.1 |
| 10 | 14913.7 |

## Statistics

- Median: **15045.3** rps
- Stdev: 98.7 (0.66% of median)
- Q1: 14943.5, Q3: 15130.9
- IQR: 187.5 (1.25% of median)
- Range (max-min): 1.83% of median

## Derived gate width

Per Q4 retro OQ3 formula: `gate = max(2×IQR, 5%)`
- 2×IQR = **2.49%**
- 5% floor = 5.00%
- **Calibrated gate: ±5.00%** (apply to both off-build and on-build)

## Notes

- Capture window: ~10 min, mid-evening, with Firefox + gnome-shell active.
- This calibration is HOST-bound, not source-bound. It applies to any subsequent diagnostic spec on this hardware.
- Future-spec convention: use the calibrated gate width above. If host load changes substantially (e.g., dedicated bench machine), re-calibrate.
