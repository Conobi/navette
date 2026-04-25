#!/usr/bin/env python3
"""Parse h2load stdout into the harness's results dict.

h2load output (relevant lines):

    finished in 30.07s, 9543.20 req/s, 1.11MB/s
    requests: 286296 total, ..., 286296 succeeded, 0 failed, 0 errored
    time for request:  ... mean ... +/- ...
    time for connect:  ...
    time to 1st byte:  ...

Usage: parse-h2load.py < /tmp/client-stdout.log
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

    for line in stdout.splitlines():
        m = re.search(r'finished in [\d.]+s,\s*([\d.]+)\s*req/s,\s*([\d.]+)([KMG]?)B/s', line)
        if m:
            rps = float(m.group(1))
            mag = m.group(3)
            scale = {"": 1, "K": 1_000, "M": 1_000_000, "G": 1_000_000_000}[mag]
            bytes_per_sec = float(m.group(2)) * scale
        m = re.search(r'requests:\s*(\d+)\s*total,.*?(\d+)\s*succeeded,\s*(\d+)\s*failed', line)
        if m:
            requests_total = int(m.group(1))
            requests_succeeded = int(m.group(2))
            requests_failed = int(m.group(3))

    return {
        "rps": rps,
        "bytes_per_sec": bytes_per_sec,
        "requests_total": requests_total,
        "requests_succeeded": requests_succeeded,
        "requests_failed": requests_failed,
        "p50_latency_ms": None,
        "p99_latency_ms": None,
        "raw_client_stdout": stdout,
    }


if __name__ == "__main__":
    print(json.dumps(parse(sys.stdin.read()), indent=2))
