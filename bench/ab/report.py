#!/usr/bin/env python3
"""bench/ab/report.py — Parse h2load/wrk output and report A/B statistics.

Usage:
    python3 bench/ab/report.py bench/ab/results/<timestamp>

Reads raw-old.txt and raw-new.txt, extracts req/s per iteration,
reports median, IQR, stdev, and a verdict (regression / neutral / improvement).
"""
import json
import re
import statistics
import sys
from pathlib import Path


def extract_h2load_rps(text: str) -> list[float]:
    """Extract req/s values from h2load output blocks."""
    values = []
    for m in re.finditer(r"(\d+(?:\.\d+)?)\s+req/s", text):
        values.append(float(m.group(1)))
    return values


def extract_h2load_latency(text: str) -> list[dict]:
    """Extract time for request (min/max/mean/sd) from h2load output."""
    results = []
    for block in text.split("--- iter"):
        m = re.search(
            r"time for request:\s+"
            r"(\d+(?:\.\d+)?)((?:us|ms|s))\s+"
            r"(\d+(?:\.\d+)?)((?:us|ms|s))\s+"
            r"(\d+(?:\.\d+)?)((?:us|ms|s))\s+"
            r"(\d+(?:\.\d+)?)((?:us|ms|s))",
            block,
        )
        if m:
            def to_us(val: str, unit: str) -> float:
                v = float(val)
                if unit == "s":
                    return v * 1_000_000
                if unit == "ms":
                    return v * 1_000
                return v

            results.append({
                "min_us": to_us(m.group(1), m.group(2)),
                "max_us": to_us(m.group(3), m.group(4)),
                "mean_us": to_us(m.group(5), m.group(6)),
                "sd_us": to_us(m.group(7), m.group(8)),
            })
    return results


def extract_wrk_rps(text: str) -> list[float]:
    """Extract Requests/sec from wrk output blocks."""
    values = []
    for m in re.finditer(r"Requests/sec:\s+(\d+(?:\.\d+)?)", text):
        values.append(float(m.group(1)))
    return values


def report_series(name: str, values: list[float], unit: str = "req/s") -> dict:
    """Compute and print stats for a series."""
    if len(values) < 2:
        print(f"  {name}: insufficient data ({len(values)} points)")
        return {}
    med = statistics.median(values)
    q1 = statistics.quantiles(values, n=4)[0]
    q3 = statistics.quantiles(values, n=4)[2]
    iqr = q3 - q1
    sd = statistics.stdev(values)
    print(f"  {name}:")
    print(f"    n       = {len(values)}")
    print(f"    median  = {med:,.1f} {unit}")
    print(f"    IQR     = [{q1:,.1f}, {q3:,.1f}]  (width {iqr:,.1f})")
    print(f"    stdev   = {sd:,.1f}")
    print(f"    range   = [{min(values):,.1f}, {max(values):,.1f}]")
    return {"median": med, "iqr": iqr, "stdev": sd, "q1": q1, "q3": q3, "n": len(values)}


def verdict(old_stats: dict, new_stats: dict, noise_floor_pct: float = 5.0) -> str:
    """Compare two stat dicts and produce a verdict."""
    if not old_stats or not new_stats:
        return "INSUFFICIENT DATA"
    old_med = old_stats["median"]
    new_med = new_stats["median"]
    diff_pct = ((new_med - old_med) / old_med) * 100
    threshold = max(noise_floor_pct, 2 * old_stats["iqr"] / old_med * 100)
    print(f"\n  Comparison:")
    print(f"    OLD median = {old_med:,.1f}")
    print(f"    NEW median = {new_med:,.1f}")
    print(f"    Δ          = {diff_pct:+.2f}%")
    print(f"    threshold  = ±{threshold:.1f}%  (max(±{noise_floor_pct}%, 2×IQR/median))")
    if abs(diff_pct) < threshold:
        v = "NEUTRAL — within noise floor"
    elif diff_pct > 0:
        v = f"IMPROVEMENT — +{diff_pct:.1f}% (>{threshold:.1f}%)"
    else:
        v = f"REGRESSION — {diff_pct:.1f}% (<-{threshold:.1f}%)"
    print(f"    verdict    = {v}")
    return v


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <results-dir>")
        sys.exit(1)
    results_dir = Path(sys.argv[1])
    meta_path = results_dir / "meta.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        print(f"Run: {meta.get('timestamp', '?')}  proto={meta.get('protocol', '?')}  "
              f"host={meta.get('hostname', '?')}  cpu={meta.get('cpu', '?')}")
        print(f"     iters={meta.get('iterations')}  pause={meta.get('pause_seconds')}s")
        protocol = meta.get("protocol", "h2")
    else:
        protocol = "h2"

    old_raw = (results_dir / "raw-old.txt").read_text()
    new_raw = (results_dir / "raw-new.txt").read_text()

    print("\n── Throughput (req/s) ──────────────────────────")
    if protocol == "h2":
        old_rps = extract_h2load_rps(old_raw)
        new_rps = extract_h2load_rps(new_raw)
    else:
        old_rps = extract_wrk_rps(old_raw)
        new_rps = extract_wrk_rps(new_raw)

    old_stats = report_series("OLD (origin/main, b2)", old_rps)
    new_stats = report_series("NEW (HEAD, 1.0.0)", new_rps)
    v = verdict(old_stats, new_stats)

    if protocol == "h2":
        print("\n── Latency (mean, µs) ─────────────────────────")
        old_lat = extract_h2load_latency(old_raw)
        new_lat = extract_h2load_latency(new_raw)
        old_means = [l["mean_us"] for l in old_lat]
        new_means = [l["mean_us"] for l in new_lat]
        old_lat_stats = report_series("OLD (origin/main, b2)", old_means, unit="µs")
        new_lat_stats = report_series("NEW (HEAD, 1.0.0)", new_means, unit="µs")
        if old_lat_stats and new_lat_stats:
            verdict(old_lat_stats, new_lat_stats)

    summary = {
        "rps_old": old_stats,
        "rps_new": new_stats,
        "verdict": v,
    }
    summary_path = results_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"\nSummary written to {summary_path}")


if __name__ == "__main__":
    main()
