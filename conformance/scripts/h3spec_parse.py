#!/usr/bin/env python3
"""Parse h3spec textual output into structured JSON.

Input: path to a file containing captured h3spec stdout.
Output: JSON {total, passed, failed, skipped, per_test: [{name, status, message?}]}
  on stdout.

Status keys are lowercase: 'pass', 'fail', 'skip'.

h3spec uses the Haskell Hspec runner, which prints one test description per
line in the test-list section that comes before the trailing 'Failures:'
detail block. Each description is indented by two or more spaces. The
trailing token on each description line encodes the outcome:

    <name>                       -> pass  (no trailing status token)
    <name> FAILED [N]            -> fail  (N is the failure index)
    <name> # PENDING (<reason>)  -> skip

Interspersed flush-left lines such as section headers ('QUIC servers',
'H3 servers') and runner debug noise ('Drop packet whose size is N') are
ignored. Iteration stops at the 'Failures:' divider so the per-failure
re-prints below it are not double-counted.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Trailing markers Hspec emits for non-pass outcomes. The capture group on
# the FAILED variant is unused for status but consumed so the regex anchors
# at end-of-line.
_FAILED_RX = re.compile(r"^(?P<name>\s{2,}.+?)\s+FAILED\s+\[\d+\]\s*$")
_PENDING_RX = re.compile(r"^(?P<name>\s{2,}.+?)\s+#\s+PENDING\b.*$")

# A passing test description: indented line that mentions an RFC requirement
# keyword and has no trailing status marker. Section headers ('QUIC servers')
# and 'Drop packet whose size is N' diagnostics are flush-left, so the
# indentation guard rules them out.
_REQ_KEYWORDS = (" MUST ", " SHOULD ", " MAY ")

_FAILURES_DIVIDER = "Failures:"


def parse(text: str) -> dict:
    """Parse h3spec stdout text into a structured result dict.

    Returns a dict with keys ``total``, ``passed``, ``failed``, ``skipped``
    (all int) and ``per_test`` (list of ``{name, status}`` dicts). The
    invariant ``total == passed + failed + skipped`` always holds.
    """
    rows: list[dict] = []

    for raw in text.splitlines():
        line = raw.rstrip()
        if line == _FAILURES_DIVIDER:
            break
        if not line:
            continue

        m = _FAILED_RX.match(line)
        if m:
            rows.append({"name": m.group("name").strip(), "status": "fail"})
            continue

        m = _PENDING_RX.match(line)
        if m:
            rows.append({"name": m.group("name").strip(), "status": "skip"})
            continue

        # Pass candidate: indented line referencing an RFC requirement.
        if line.startswith(("  ", "\t")) and any(kw in line for kw in _REQ_KEYWORDS):
            rows.append({"name": line.strip(), "status": "pass"})

    counts = {"pass": 0, "fail": 0, "skip": 0}
    for row in rows:
        counts[row["status"]] += 1

    return {
        "total": len(rows),
        "passed": counts["pass"],
        "failed": counts["fail"],
        "skipped": counts["skip"],
        "per_test": rows,
    }


def main(argv: list[str]) -> int:
    """Read the fixture path from argv, print parsed JSON to stdout."""
    if len(argv) != 2:
        print("usage: h3spec_parse.py <h3spec_stdout_file>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    json.dump(parse(text), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
