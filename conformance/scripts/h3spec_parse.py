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
ignored. The per-test scan stops at the 'Failures:' divider so the
per-failure re-prints below it are not double-counted; a second pass
re-reads that detail block to harvest per-test diagnostic messages and
attach them to the matching failed rows.
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

# A source-file header line introducing a failure paragraph, e.g.
# "  TransportError.hs:34:13: " (trailing whitespace tolerated).
_FAILURE_HEADER_RX = re.compile(r"^\s+\S+\.hs:\d+:\d+:\s*$")

# A numbered test-name line, e.g.
# "  1) QUIC servers MUST send FLOW_CONTROL_ERROR ... [Transport 4.1]".
_FAILURE_NAME_RX = re.compile(r"^\s+\d+\)\s+(?P<name>.+\S)\s*$")


def _extract_failures(text: str) -> dict[str, str]:
    """Return ``{full_test_name: diagnostic_message}`` mined from the 'Failures:' block.

    The block lives after the ``Failures:`` divider in h3spec stdout. It is
    a sequence of paragraphs (blank-line separated). A failure paragraph has
    three pieces:

        <source_file>.hs:<line>:<col>:
        <N>) <full test name>
            <indented diagnostic lines>

    where the test name is prefixed by the section header from the per-test
    scan ('QUIC servers ...' or 'H3 servers ...') and the diagnostic spans
    one or more indented continuation lines. 'To rerun use: ...' paragraphs
    interleave the failure paragraphs and are skipped. The returned dict
    keys are the full names verbatim; callers reconcile them against the
    section-stripped names captured during the per-test scan.
    """
    lines = text.splitlines()
    try:
        start = next(i for i, raw in enumerate(lines) if raw.rstrip() == _FAILURES_DIVIDER)
    except StopIteration:
        return {}

    # Split the post-divider region into paragraphs on blank-line boundaries.
    paragraphs: list[list[str]] = []
    current: list[str] = []
    for raw in lines[start + 1 :]:
        if raw.strip() == "":
            if current:
                paragraphs.append(current)
                current = []
            continue
        current.append(raw)
    if current:
        paragraphs.append(current)

    messages: dict[str, str] = {}
    for para in paragraphs:
        first = para[0]
        # Skip rerun hints and the trailing 'Randomized with seed ...' /
        # 'Finished in ...' summary lines.
        if first.lstrip().startswith("To rerun use:"):
            continue
        if not _FAILURE_HEADER_RX.match(first):
            continue
        if len(para) < 2:
            continue

        name_match = _FAILURE_NAME_RX.match(para[1])
        if not name_match:
            continue
        name = name_match.group("name").strip()

        # Remaining lines are the diagnostic; strip common leading whitespace
        # so a multi-line message stays readable when surfaced to triage.
        diag_lines = para[2:]
        if not diag_lines:
            continue
        common = min(
            (len(ln) - len(ln.lstrip(" ")) for ln in diag_lines if ln.strip()),
            default=0,
        )
        message = "\n".join(ln[common:] if ln.strip() else "" for ln in diag_lines)
        if message.strip():
            messages[name] = message

    return messages


def parse(text: str) -> dict:
    """Parse h3spec stdout text into a structured result dict.

    Returns a dict with keys ``total``, ``passed``, ``failed``, ``skipped``
    (all int) and ``per_test`` (list of ``{name, status, message?}`` dicts).
    Failed rows additionally carry a ``message`` field with the diagnostic
    text harvested from the 'Failures:' detail block. The invariant
    ``total == passed + failed + skipped`` always holds.
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

    # Attach per-failure diagnostic messages. The Failures-block names carry
    # the section prefix ('QUIC servers ' / 'H3 servers ') that the per-test
    # scan dropped, so reconcile by suffix.
    messages = _extract_failures(text)
    for row in rows:
        if row["status"] != "fail":
            continue
        row_name = row["name"]
        for full_name, msg in messages.items():
            if full_name == row_name or full_name.endswith(" " + row_name):
                row["message"] = msg
                break

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
