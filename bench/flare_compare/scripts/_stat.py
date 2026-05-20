#!/usr/bin/env python3
"""Aggregate wrk2 measurement runs into a single JSON summary.

Mirrors Flare's `benchmark/scripts/_stat.py` shape: takes N raw wrk2
stdout files, parses Latency Distribution + Requests/sec out of each,
drops the slowest+fastest req/s, takes the median of the middle three
plus per-percentile stdev, and emits a stability verdict.
"""
from __future__ import annotations
import argparse, json, math, re, statistics, sys
from pathlib import Path

_RE_PCT = re.compile(r"^\s*([0-9]+\.[0-9]+)%\s+([0-9.]+)(us|ms|s|m)\s*$")
_RE_RPS = re.compile(r"^\s*Requests/sec:\s+([0-9.]+)\s*$")

_PCT_KEYS = {
    "50.000": "p50",
    "75.000": "p75",
    "90.000": "p90",
    "99.000": "p99",
    "99.900": "p99_9",
    "99.990": "p99_99",
    "99.999": "p99_999",
}


def _to_ms(value: float, unit: str) -> float:
    if unit == "us":
        return value / 1000.0
    if unit == "ms":
        return value
    if unit == "s":
        return value * 1000.0
    if unit == "m":
        return value * 60_000.0
    raise ValueError(f"unknown unit: {unit}")


def parse_run(path: Path) -> dict:
    text = path.read_text(errors="replace")
    rps = 0.0
    pcts: dict[str, float] = {}
    in_dist = False
    for line in text.splitlines():
        if "Latency Distribution" in line:
            in_dist = True
            continue
        if in_dist:
            if not line.strip() or "Detailed" in line:
                in_dist = False
                continue
            m = _RE_PCT.match(line)
            if m:
                key = _PCT_KEYS.get(m.group(1))
                if key:
                    pcts[key] = _to_ms(float(m.group(2)), m.group(3))
        m_rps = _RE_RPS.match(line)
        if m_rps:
            rps = float(m_rps.group(1))
    return {"req_per_sec": rps, **pcts, "raw_file": path.name}


def summarise(runs: list[dict], peak_rps: float | None) -> dict:
    rps = sorted(r["req_per_sec"] for r in runs)
    middle = rps[1:-1] if len(rps) >= 5 else rps
    median_rps = statistics.median(middle) if middle else 0.0
    mean_rps = statistics.fmean(rps) if rps else 0.0
    sd_rps = statistics.stdev(rps) if len(rps) >= 2 else 0.0
    stdev_pct = (sd_rps / mean_rps * 100.0) if mean_rps > 0 else 0.0

    summary = {
        "n_runs": len(runs),
        "median_req_per_sec": median_rps,
        "mean_req_per_sec": mean_rps,
        "stdev_req_per_sec": sd_rps,
        "stdev_pct": stdev_pct,
        "stable": stdev_pct < 5.0,
        "peak_req_per_sec": peak_rps if peak_rps is not None else median_rps,
    }
    for key in ("p50", "p75", "p90", "p99", "p99_9", "p99_99", "p99_999"):
        values = [r.get(key, math.nan) for r in runs]
        values = [v for v in values if not math.isnan(v)]
        if not values:
            continue
        mid = values[1:-1] if len(values) >= 5 else values
        summary[f"median_{key}_ms"] = statistics.median(mid) if mid else 0.0
        summary[f"stdev_{key}_ms"] = (
            statistics.stdev(values) if len(values) >= 2 else 0.0
        )
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--peak-rps", type=float, default=None,
                    help="Calibrated peak req/s from the find-peak phase.")
    ap.add_argument("output_json")
    ap.add_argument("run_files", nargs="+")
    args = ap.parse_args()

    runs = [parse_run(Path(p)) for p in args.run_files]
    summary = summarise(runs, args.peak_rps)
    out = {"runs": runs, "summary": summary}
    Path(args.output_json).write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
