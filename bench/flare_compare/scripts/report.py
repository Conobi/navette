#!/usr/bin/env python3
"""Post-bench analysis: emit a markdown table that puts the latest run
in context with Flare's published single-worker numbers.

Reads `<results_dir>/{nginx,navette,go-nethttp,...}-throughput-1w.json`
plus the host fingerprint from `env.json`, prints a markdown summary
to stdout. Pipe to a file or append to SYNTHESIS.md.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

# Flare's published 1-worker numbers (docs/benchmark.md, EPYC 7R32).
# Kept here so we can render the cross-host context column even when
# the bench has only run a subset of targets.
FLARE_1W = {
    "nginx":      {"rps": 80239, "p99": 3.45, "p99_99": 4.80},
    "flare":      {"rps": 71619, "p99": 3.01, "p99_99": 3.43},
    "go-nethttp": {"rps": 40173, "p99": 3.21, "p99_99": 4.62},
}


def load_target(results_dir: Path, target: str, config: str = "throughput-1w") -> dict | None:
    fp = results_dir / f"{target}-{config}.json"
    if not fp.exists():
        return None
    return json.loads(fp.read_text())


def fmt_pct(v: float) -> str:
    return f"{v:.2f}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results_dir")
    ap.add_argument("--config", default="throughput-1w")
    args = ap.parse_args()
    rdir = Path(args.results_dir)
    if not rdir.is_dir():
        print(f"not a directory: {rdir}", file=sys.stderr)
        return 1

    env = {}
    env_fp = rdir / "env.json"
    if env_fp.exists():
        env = json.loads(env_fp.read_text())

    # Collect every targets-{config}.json we have.
    rows = {}
    for js in sorted(rdir.glob(f"*-{args.config}.json")):
        target = js.stem.removesuffix(f"-{args.config}")
        if target == "env":
            continue
        rows[target] = load_target(rdir, target, args.config)

    if not rows:
        print(f"no results found in {rdir} for config={args.config}", file=sys.stderr)
        return 1

    nginx_rps_local = rows.get("nginx", {}).get("summary", {}).get("median_req_per_sec", 0.0)
    nginx_rps_flare = FLARE_1W["nginx"]["rps"]
    hw_shift = (nginx_rps_local / nginx_rps_flare) if nginx_rps_flare else 0.0

    print("# navette vs competitors — single-worker /plaintext")
    print()
    print(f"- Host: `{env.get('host', 'unknown')}` — {env.get('cpu_model', 'unknown CPU')}")
    print(f"- Kernel: `{env.get('kernel', '?')}`, Docker `{env.get('docker_version', '?')}`")
    print(f"- Commit: `{env.get('commit', '?')}`")
    if hw_shift > 0:
        print(f"- Hardware shift vs Flare's EPYC 7R32 (nginx-on-nginx): "
              f"**{hw_shift:.2f}×** (use to translate Flare numbers onto this host)")
    print()

    # Headline table (this host).
    print("## This host (single-worker)")
    print()
    print("| Target | Req/s | σ% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | vs nginx | stable |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---|")
    # Order: navette first, then alphabetical.
    order = ["navette"] + sorted(t for t in rows if t != "navette")
    for t in order:
        if not rows.get(t):
            continue
        s = rows[t]["summary"]
        ratio_nginx = (s["median_req_per_sec"] / nginx_rps_local) if nginx_rps_local else 0.0
        print(f"| {t} | {int(s['median_req_per_sec'])} | {fmt_pct(s['stdev_pct'])} | "
              f"{fmt_pct(s['median_p50_ms'])} ± {fmt_pct(s.get('stdev_p50_ms', 0))} | "
              f"{fmt_pct(s['median_p99_ms'])} ± {fmt_pct(s.get('stdev_p99_ms', 0))} | "
              f"{fmt_pct(s.get('median_p99_9_ms', 0))} ± {fmt_pct(s.get('stdev_p99_9_ms', 0))} | "
              f"{fmt_pct(s.get('median_p99_99_ms', 0))} ± {fmt_pct(s.get('stdev_p99_99_ms', 0))} | "
              f"{ratio_nginx:.2f}× | {str(s['stable']).lower()} |")
    print()

    # Cross-host context (Flare's published numbers, EPYC 7R32).
    print("## Cross-host context — Flare's published 1-worker (AWS EPYC 7R32)")
    print()
    print("Different hardware; ratios within a single host are the apples-to-apples comparison.")
    print()
    print("| Server | Req/s (Flare) | Req/s (this host) | p99 (Flare) | p99 (this host) | host/Flare |")
    print("|---|---:|---:|---:|---:|---:|")
    for name, flare in FLARE_1W.items():
        local = rows.get(name)
        if local:
            lr = local["summary"]["median_req_per_sec"]
            lp = local["summary"]["median_p99_ms"]
            ratio = (lr / flare["rps"]) if flare["rps"] else 0.0
            print(f"| {name} | {flare['rps']:,} | {int(lr):,} | {flare['p99']:.2f} | {lp:.2f} | {ratio:.2f}× |")
        else:
            print(f"| {name} | {flare['rps']:,} | — | {flare['p99']:.2f} | — | — |")
    print()
    print("> The first row (nginx) is the **hardware-shift gauge**: it tells you how this")
    print("> host's silicon compares to Flare's EPYC at the same workload. Once you have")
    print("> that ratio, every other Flare number translates onto this host with the same")
    print("> factor — within the limits of microarchitecture-specific quirks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
