#!/usr/bin/env python3
"""Analyze perf folded stacks to find inefficient functions.

Detects two patterns:
  1. Overhead-dominated: functions whose time ends up in allocator/runtime leaves.
  2. Disproportionate-child: functions where one generic operation takes
     unexpectedly large time (e.g. Dict __contains__ inside on_packet_sent).

Produces two views:
  - Ranked anomaly table: (function, operation, cost) tuples.
  - Per-function decomposition: where each function's time goes,
    with recursive path display and fan-out ratio.

Usage:
  perf-analyze.py <folded.txt> [options]
  perf-analyze.py <cpu-folded.txt> --icache <icache-folded.txt>
  perf-analyze.py <folded.txt> --binary <path> --hot-roots func1,func2
"""

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field


OVERHEAD_LEAVES = frozenset({
    "_realloc", "_malloc", "_free", "_alloc_bytes", "alloc", "dealloc",
    "TCMallocInternalCfree", "TCMallocInternalCnew",
    "KGEN_CompilerRT_AlignedAlloc", "KGEN_CompilerRT_AlignedFree",
    "sched_getcpu", "sched_getcpu@plt",
    "__tls_get_addr", "__tls_get_addr@plt",
    "check_bounds",
})

OVERHEAD_PREFIXES = ("KGEN_", "M::AsyncRT", "[lib")

# Process-level wrappers that appear in every stack but aren't actionable
PROCESS_WRAPPERS = frozenset({
    "main", "_start", "__libc_start_main", "__libc_start_call_main",
    "__mojo_main_prototype", "__wrap_and_execute_raising_main",
    "static_h3_serve",
})


def is_overhead_leaf(name: str) -> bool:
    """True if this function is an infrastructure leaf (allocator, runtime)."""
    return name in OVERHEAD_LEAVES or any(
        name.startswith(p) for p in OVERHEAD_PREFIXES
    )


def parse_folded(path: str) -> list[tuple[list[str], int]]:
    """Parse a folded-stack file into (stack_parts, count) pairs."""
    stacks = []
    with open(path) as f:
        for line in f:
            line = line.rstrip()
            m = re.match(r"(.+)\s+(\d+)$", line)
            if m:
                parts = m.group(1).split(";")
                stacks.append((parts, int(m.group(2))))
    return stacks


def get_symbol_sizes(binary_path: str) -> dict[str, int]:
    """Extract symbol sizes from a binary via objdump -t."""
    sizes = {}
    try:
        out = subprocess.check_output(
            ["objdump", "-t", binary_path],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[2] == "F":
                try:
                    size = int(parts[4], 16)
                    name = parts[-1]
                    short = shorten_symbol(name)
                    if size > 0:
                        sizes[short] = max(sizes.get(short, 0), size)
                except ValueError:
                    pass
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return sizes


def shorten_symbol(sym: str) -> str:
    """Shorten a mangled Mojo/C++ symbol to a readable name."""
    if sym.startswith("navette::") or sym.startswith("boucle::"):
        segs = sym.split("::")
        paren = next((i for i, s in enumerate(segs) if "(" in s), len(segs))
        segs = segs[:paren]
        if len(segs) >= 3:
            return "::".join(segs[-2:])
        return segs[-1] if segs else sym
    if sym.startswith("std::"):
        segs = sym.split("::")
        paren = next((i for i, s in enumerate(segs) if "(" in s), len(segs))
        segs = segs[:paren]
        if len(segs) >= 3:
            return "::".join(segs[-2:])
    return sym.split("(")[0][:50]


@dataclass
class FuncStats:
    """Accumulated statistics for one function."""

    inclusive: int = 0
    self_time: int = 0
    child_ops: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    child_paths: dict[str, dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )
    overhead: int = 0


def detect_generics(stacks: list[tuple[list[str], int]], threshold: int = 5) -> set[str]:
    """Detect generic functions: those appearing under many distinct parents."""
    parent_count = defaultdict(set)
    for parts, _ in stacks:
        for i in range(1, len(parts)):
            parent_count[parts[i]].add(parts[i - 1])
    return {
        func
        for func, parents in parent_count.items()
        if len(parents) >= threshold
    }


def analyze(
    stacks: list[tuple[list[str], int]],
    hot_roots: set[str] | None = None,
) -> tuple[dict[str, FuncStats], int, set[str]]:
    """Build per-function stats from folded stacks.

    Returns (func_stats, grand_total, generics).
    """
    generics = detect_generics(stacks)

    if hot_roots:
        stacks = [
            (parts, count)
            for parts, count in stacks
            if any(
                any(root in p for p in parts)
                for root in hot_roots
            )
        ]

    grand_total = sum(count for _, count in stacks)
    stats: dict[str, FuncStats] = defaultdict(FuncStats)

    for parts, count in stacks:
        leaf = parts[-1]

        seen: set[str] = set()
        for p in parts:
            if p not in seen:
                stats[p].inclusive += count
                seen.add(p)

        stats[leaf].self_time += count

        is_leaf_overhead = is_overhead_leaf(leaf)

        # Build list of specific function positions in this stack
        specific_positions = [
            i for i, p in enumerate(parts)
            if p not in generics and not is_overhead_leaf(p)
        ]

        # For each specific function, attribute the segment between it
        # and the next specific function (or the leaf)
        for idx, pos in enumerate(specific_positions):
            func = parts[pos]

            # Determine the end of this function's segment
            if idx + 1 < len(specific_positions):
                next_pos = specific_positions[idx + 1]
            else:
                next_pos = len(parts)

            segment = parts[pos + 1 : next_pos]
            if not segment:
                continue

            child_label = segment[0]
            path_key = " → ".join(segment[:4])

            stats[func].child_ops[child_label] += count
            stats[func].child_paths[child_label][path_key] += count

        # Attribute overhead to the deepest specific function
        if is_leaf_overhead and specific_positions:
            deepest = parts[specific_positions[-1]]
            stats[deepest].overhead += count

    return dict(stats), grand_total, generics


def parse_call_counts(
    path: str, sample_period: int = 1000
) -> dict[str, int]:
    """Parse call-count folded stacks into estimated call counts per function.

    Each sample fires on a CALL instruction. The leaf function in each
    stack is the one being called at that moment. We count leaf occurrences
    to estimate how many times each function is entered, scaled by the
    sampling period.
    """
    stacks = parse_folded(path)
    counts: dict[str, int] = defaultdict(int)
    for parts, count in stacks:
        if parts:
            leaf = parts[-1]
            counts[leaf] += count * sample_period
    return dict(counts)


def fan_out_ratio(func_stats: FuncStats) -> float:
    """Ratio of heaviest child to inclusive time. 1.0 = bottleneck funnel."""
    if not func_stats.child_ops or func_stats.inclusive == 0:
        return 0.0
    max_child = max(func_stats.child_ops.values())
    return max_child / func_stats.inclusive


def cycles_to_us(cycles: int, total_requests: int, cpu_ghz: float = 2.8) -> float:
    """Convert cycles to microseconds per request."""
    if total_requests == 0:
        return 0.0
    cycles_per_req = cycles / total_requests
    return cycles_per_req / (cpu_ghz * 1e3)


def fmt_per_req(cycles: int, total_requests: int, cpu_ghz: float) -> str:
    """Format a per-request cost as µs."""
    us = cycles_to_us(cycles, total_requests, cpu_ghz)
    if us >= 100:
        return f"{us:>.0f}µs"
    if us >= 10:
        return f"{us:>.1f}µs"
    return f"{us:>.2f}µs"


def detect_cpu_ghz() -> float:
    """Read the CPU frequency from /proc/cpuinfo."""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    m = re.search(r"@\s*([\d.]+)\s*GHz", line)
                    if m:
                        return float(m.group(1))
    except OSError:
        pass
    return 2.8


def print_anomaly_table(
    stats: dict[str, FuncStats],
    grand_total: int,
    generics: set[str],
    icache_stats: dict[str, FuncStats] | None = None,
    icache_total: int = 0,
    symbol_sizes: dict[str, int] | None = None,
    call_counts: dict[str, int] | None = None,
    total_requests: int = 0,
    cpu_ghz: float = 2.8,
    min_pct: float = 0.3,
) -> None:
    """Print ranked anomaly table: function × operation pairs.

    Skips pass-through entries where a domain function calls another domain
    function that itself appears in the decomposition (e.g. main → flush).
    Keeps entries where a domain function calls a generic operation
    (__contains__, append, __init__) even if that generic has high inclusive time.
    """
    anomalies = []
    for func, fs in stats.items():
        if is_overhead_leaf(func) or func in PROCESS_WRAPPERS:
            continue
        inc_pct = fs.inclusive / grand_total * 100
        if inc_pct < min_pct:
            continue
        for child, child_time in fs.child_ops.items():
            child_pct = child_time / grand_total * 100
            ratio = child_time / fs.inclusive * 100 if fs.inclusive > 0 else 0
            if child_pct >= 0.2 and ratio >= 10:
                anomalies.append((func, child, child_time, child_pct, ratio, inc_pct))

    anomalies.sort(key=lambda x: -x[3])

    has_reqs = total_requests > 0
    has_calls = call_counts is not None and total_requests > 0
    hdr = f"{'Function':<35} {'Operation':<22} {'%/req':>6} {'of Func':>8}"
    if has_reqs:
        hdr += f" {'µs/req':>7}"
    if has_calls:
        hdr += f" {'calls/req':>9}"
    if icache_stats:
        hdr += f" {'iCache':>7}"
    if symbol_sizes:
        hdr += f" {'CodeKB':>7}"

    title = "ANOMALY TABLE — function × operation pairs ranked by per-request cost"
    if not has_reqs:
        title = "ANOMALY TABLE — function × operation pairs ranked by CPU cost"
    print("=" * len(hdr))
    print(title)
    if has_reqs:
        print(f"  {total_requests:,} requests during recording — percentages are per-request CPU share")
    print("=" * len(hdr))
    print(hdr)
    print("-" * len(hdr))

    total_cycles = 0
    total_pct = 0.0
    for func, child, child_cycles, cost_pct, ratio, inc_pct in anomalies:
        line = f"{func[:35]:<35} {child[:22]:<22} {cost_pct:>5.2f}% {ratio:>6.0f}%"
        if has_reqs:
            line += f" {fmt_per_req(child_cycles, total_requests, cpu_ghz):>7}"
        if has_calls:
            fc = call_counts.get(func, 0)
            cpr = fc / total_requests if total_requests > 0 else 0
            line += f" {cpr:>9.1f}" if cpr >= 1 else f" {cpr:>9.2f}"
        if icache_stats and func in icache_stats and icache_total > 0:
            ic_pct = icache_stats[func].inclusive / icache_total * 100
            line += f" {ic_pct:>6.1f}%"
        elif icache_stats:
            line += f" {'—':>6}"
        if symbol_sizes:
            kb = symbol_sizes.get(func, 0) / 1024
            line += f" {kb:>6.1f}" if kb > 0 else f" {'—':>6}"
        print(line)
        total_cycles += child_cycles
        total_pct += cost_pct

    print("-" * len(hdr))
    total_line = f"{'TOTAL (' + str(len(anomalies)) + ' anomalies)':<58} {total_pct:>5.1f}%"
    if has_reqs:
        total_line += f" {fmt_per_req(total_cycles, total_requests, cpu_ghz):>7}"
        remaining_pct = 100.0 - total_pct
        remaining_us = cycles_to_us(grand_total - total_cycles, total_requests, cpu_ghz)
        total_line += f"  (remaining: {remaining_pct:.1f}% = {remaining_us:.0f}µs/req)"
    print(total_line)
    print()


def print_function_decompositions(
    stats: dict[str, FuncStats],
    grand_total: int,
    generics: set[str],
    icache_stats: dict[str, FuncStats] | None = None,
    icache_total: int = 0,
    symbol_sizes: dict[str, int] | None = None,
    call_counts: dict[str, int] | None = None,
    total_requests: int = 0,
    cpu_ghz: float = 2.8,
    min_pct: float = 0.5,
    child_min_ratio: float = 0.05,
) -> None:
    """Print per-function decompositions with recursive paths and fan-out."""
    has_reqs = total_requests > 0
    funcs = []
    for func, fs in stats.items():
        if func in generics or is_overhead_leaf(func) or func in PROCESS_WRAPPERS:
            continue
        inc_pct = fs.inclusive / grand_total * 100
        if inc_pct >= min_pct:
            funcs.append((func, fs, inc_pct))

    funcs.sort(key=lambda x: -x[2])

    print("=" * 80)
    print("PER-FUNCTION DECOMPOSITION — where each function's time goes")
    if has_reqs:
        print("  Percentages = share of per-request CPU; µs = cost per request")
    print("=" * 80)

    for func, fs, inc_pct in funcs[:20]:
        self_pct = fs.self_time / grand_total * 100
        ovhd_ratio = fs.overhead / fs.inclusive * 100 if fs.inclusive > 0 else 0
        fo = fan_out_ratio(fs)

        tags = []
        if has_reqs:
            tags.append(fmt_per_req(fs.inclusive, total_requests, cpu_ghz))
        if call_counts and func in call_counts and total_requests > 0:
            cpr = call_counts[func] / total_requests
            tags.append(f"{cpr:.1f} calls/req" if cpr >= 1 else f"{cpr:.2f} calls/req")
        if icache_stats and func in icache_stats and icache_total > 0:
            ic_pct = icache_stats[func].inclusive / icache_total * 100
            tags.append(f"icache={ic_pct:.1f}%")
        if symbol_sizes and func in symbol_sizes:
            tags.append(f"code={symbol_sizes[func]/1024:.0f}KB")
        tag_str = f"  [{', '.join(tags)}]" if tags else ""

        print(
            f"\n{func}  ({inc_pct:.2f}% incl, {self_pct:.2f}% self, "
            f"fan-out={fo:.2f}, overhead={ovhd_ratio:.0f}%){tag_str}"
        )

        sorted_children = sorted(
            fs.child_ops.items(), key=lambda x: -x[1]
        )
        shown = 0
        for child, child_time in sorted_children:
            child_pct = child_time / grand_total * 100
            ratio = child_time / fs.inclusive * 100 if fs.inclusive > 0 else 0
            if ratio < child_min_ratio * 100:
                continue

            is_last = shown == len(
                [c for _, c in sorted_children if c / fs.inclusive >= child_min_ratio]
            ) - 1
            connector = "└──" if is_last else "├──"
            per_req = f" {fmt_per_req(child_time, total_requests, cpu_ghz)}" if has_reqs else ""
            print(f"  {connector} {child[:30]:<30} {child_pct:>5.2f}%{per_req} ({ratio:.0f}% of func)")

            paths = fs.child_paths.get(child, {})
            top_paths = sorted(paths.items(), key=lambda x: -x[1])[:2]
            for path, path_count in top_paths:
                path_pct = path_count / grand_total * 100
                if path_pct >= 0.1:
                    print(f"  {'   ' if is_last else '│  '}   → {path}")

            shown += 1

        remainder = fs.inclusive - fs.self_time - sum(
            c for _, c in sorted_children
            if c / fs.inclusive >= child_min_ratio
        )
        if remainder > 0:
            rem_pct = remainder / grand_total * 100
            if rem_pct >= 0.1:
                per_req = f" {fmt_per_req(int(remainder), total_requests, cpu_ghz)}" if has_reqs else ""
                print(f"  └── (other): {rem_pct:.2f}%{per_req}")

    print()


def print_summary(
    stats: dict[str, FuncStats],
    grand_total: int,
    generics: set[str],
    hot_roots: set[str] | None,
    total_requests: int = 0,
    cpu_ghz: float = 2.8,
) -> None:
    """Print a one-line summary of what was analyzed."""
    n_specific = sum(
        1
        for f in stats
        if f not in generics and not is_overhead_leaf(f)
    )
    n_generic = len(generics)

    print(f"Analyzed {grand_total:,} cycles across {n_specific} specific functions "
          f"({n_generic} detected as generic)")
    if total_requests > 0:
        cpr = grand_total / total_requests
        us_per_req = cpr / (cpu_ghz * 1e3)
        ceiling = 1_000_000 / us_per_req if us_per_req > 0 else 0
        print(f"  {total_requests:,} requests — {cpr:,.0f} cycles/req — "
              f"{us_per_req:.0f} µs/req @ {cpu_ghz} GHz — "
              f"single-core ceiling {ceiling:,.0f} rps")
    if hot_roots:
        print(f"Hot-path filter: only stacks through {', '.join(sorted(hot_roots))}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze perf folded stacks for inefficient functions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("folded", help="Path to CPU folded-stack file")
    parser.add_argument(
        "--icache", help="Path to i-cache-miss folded-stack file for cross-reference"
    )
    parser.add_argument(
        "--calls",
        help="Path to call-count folded-stack file (br_inst_retired.near_call, period 1000)",
    )
    parser.add_argument(
        "--binary", help="Path to binary for code-size column (objdump -t)"
    )
    parser.add_argument(
        "--hot-roots",
        help="Comma-separated function substrings to filter hot-path stacks (opt-in)",
    )
    parser.add_argument(
        "--min-pct",
        type=float,
        default=0.5,
        help="Minimum inclusive %% to show a function (default: 0.5)",
    )
    parser.add_argument(
        "--generic-threshold",
        type=int,
        default=5,
        help="Min distinct parents to consider a function generic (default: 5)",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=0,
        help="Total requests during recording (enables per-request µs column)",
    )
    parser.add_argument(
        "--cpu-ghz",
        type=float,
        default=0,
        help="CPU frequency in GHz (default: auto-detect from /proc/cpuinfo)",
    )
    args = parser.parse_args()

    stacks = parse_folded(args.folded)
    if not stacks:
        print(f"error: no stacks found in {args.folded}", file=sys.stderr)
        sys.exit(1)

    hot_roots = (
        set(args.hot_roots.split(",")) if args.hot_roots else None
    )
    cpu_ghz = args.cpu_ghz if args.cpu_ghz > 0 else detect_cpu_ghz()
    total_requests = args.requests

    stats, grand_total, generics = analyze(stacks, hot_roots)

    icache_stats = None
    icache_total = 0
    if args.icache:
        ic_stacks = parse_folded(args.icache)
        icache_stats, icache_total, _ = analyze(ic_stacks, hot_roots)

    symbol_sizes = None
    if args.binary:
        symbol_sizes = get_symbol_sizes(args.binary)

    call_counts = None
    if args.calls:
        call_counts = parse_call_counts(args.calls)

    print_summary(stats, grand_total, generics, hot_roots, total_requests, cpu_ghz)
    print_anomaly_table(
        stats, grand_total, generics,
        icache_stats, icache_total,
        symbol_sizes,
        call_counts=call_counts,
        total_requests=total_requests,
        cpu_ghz=cpu_ghz,
        min_pct=args.min_pct,
    )
    print_function_decompositions(
        stats, grand_total, generics,
        icache_stats, icache_total,
        symbol_sizes,
        call_counts=call_counts,
        total_requests=total_requests,
        cpu_ghz=cpu_ghz,
        min_pct=args.min_pct,
    )


if __name__ == "__main__":
    main()
