#!/usr/bin/env python3
"""Parse tquic_client stdout into the harness's results dict.

Reads tquic_client output of the form:

    finished in 24.303857ms, 12083.33 req/s
    conns: total 100, finish 48, success 48, failure 0
    requests: sent 770, finish 290, success 290
    time for request(µs):
        min: 904.00, max: 4995.00, mean: 4107.63, sd: 1426.01
        median: 4816.00, p80: 4909.00, p90: 4939.63, p99: 4981.29
    recv bytes: 459153, sent bytes: 162823, lost bytes: 74

Emits JSON to stdout suitable for embedding under "results" in the per-run
JSON file.  Latency percentiles are in ms (converted from µs).

Usage: parse-tquic.py < /tmp/client-stdout.log
"""

import json
import re
import sys


def parse(stdout: str) -> dict:
    rps = None
    bytes_per_sec = None
    requests_total = None
    requests_succeeded = None
    requests_failed = None
    p50_ms = None
    p99_ms = None

    for line in stdout.splitlines():
        # "finished in 24.303857ms, 12083.33 req/s"
        m = re.search(r'finished in.*?,\s*([\d.]+)\s*req/s', line)
        if m:
            rps = float(m.group(1))

        # recv bytes line — no per-second throughput in tquic output, skip
        # "requests: sent 770, finish 290, success 290"
        m = re.search(r'requests:\s*sent\s*(\d+),\s*finish\s*(\d+),\s*success\s*(\d+)', line)
        if m:
            requests_total = int(m.group(1))
            requests_succeeded = int(m.group(3))
            requests_failed = requests_total - int(m.group(2))

        # "        median: 4816.00, p80: 4909.00, p90: 4939.63, p99: 4981.29"
        # latency is in µs — convert to ms
        m = re.search(r'median:\s*([\d.]+)', line)
        if m:
            p50_ms = float(m.group(1)) / 1000.0
        m = re.search(r'p99:\s*([\d.]+)', line)
        if m:
            p99_ms = float(m.group(1)) / 1000.0

    return {
        "rps": rps,
        "bytes_per_sec": bytes_per_sec,
        "requests_total": requests_total,
        "requests_succeeded": requests_succeeded,
        "requests_failed": requests_failed,
        "p50_latency_ms": p50_ms,
        "p99_latency_ms": p99_ms,
        "server_cpu_percent": None,
        "raw_client_stdout": stdout,
    }


if __name__ == "__main__":
    print(json.dumps(parse(sys.stdin.read()), indent=2))
