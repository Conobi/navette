#!/usr/bin/env python3
"""Aggregate results/*.json into a Markdown comparison table.

Groups by (client, scenario, payload), takes the median rps over available
iterations per cell, and prints a table per client. Writes results/SUMMARY.md
alongside the stdout output.

Usage: summarize.py
"""

import glob
import json
import os
import statistics
import sys
from collections import defaultdict


PAYLOAD_ORDER = ["1k", "5k", "15k", "2m"]
SCENARIO_ORDER = ["long-conn", "short-conn"]
SERVER_ORDER = ["navette", "tquic"]
CLIENT_HEADERS = {
    "tquic_client": "## tquic_client (saturating, 4 threads)\n",
    "h2load": "## h2load-h3 (single-threaded, regression-tracking only)\n",
}


def median_or_none(values):
    finite = [v for v in values if v is not None]
    if not finite:
        return None
    return statistics.median(finite)


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.normpath(os.path.join(here, "..", "results"))
    files = sorted(glob.glob(os.path.join(results_dir, "*.json")))
    if not files:
        print("no results in results/ — run bench.sh first", file=sys.stderr)
        return 1

    # cell[(client, scenario, payload, server)] = list of (rps, cpu, errors, n_iters_seen)
    bucket = defaultdict(list)
    for path in files:
        with open(path) as f:
            r = json.load(f)
        key = (r["client"], r["scenario"], r["payload"], r["server"])
        bucket[key].append(r["results"])

    out = []
    for client, header in CLIENT_HEADERS.items():
        any_rows = False
        out.append(header)
        out.append("| Payload | Scenario   | navette req/s (n) | TQUIC req/s (n) | navette CPU% | Ratio |")
        out.append("|---------|------------|---------------------|-----------------|---------------|-------|")
        for scenario in SCENARIO_ORDER:
            for payload in PAYLOAD_ORDER:
                cells = {server: bucket.get((client, scenario, payload, server), []) for server in SERVER_ORDER}
                if not any(cells.values()):
                    continue
                any_rows = True

                def fmt(server):
                    cs = cells[server]
                    if not cs:
                        return "—"
                    rps = median_or_none([c.get("rps") for c in cs])
                    return f"{rps:,.0f} ({len(cs)})" if rps is not None else f"err ({len(cs)})"

                cpu_mn = median_or_none([c.get("server_cpu_percent") for c in cells["navette"]])
                rps_m = median_or_none([c.get("rps") for c in cells["navette"]])
                rps_t = median_or_none([c.get("rps") for c in cells["tquic"]])
                ratio = f"{rps_m / rps_t:.2f}x" if rps_m and rps_t else "—"
                cpu_str = f"{cpu_mn:.1f}" if cpu_mn is not None else "—"

                out.append(f"| {payload:<7} | {scenario:<10} | {fmt('navette'):<19} | {fmt('tquic'):<15} | {cpu_str:<13} | {ratio:<5} |")
        if not any_rows:
            out.append("_no runs for this client yet_")
        out.append("")

    text = "\n".join(out)
    print(text)

    summary_path = os.path.join(results_dir, "SUMMARY.md")
    with open(summary_path, "w") as f:
        f.write(text + "\n")
    print(f"\n[summarize] wrote {summary_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
