#!/usr/bin/env python3
"""Classify each h3spec failure into Pattern A / B / C.

Pattern A_log_drop: h3spec reports failure AND server.err shows a
  matching `feed_datagram error:` line whose significant token
  appears in the test's diagnostic block.
  Implication: navette detects the violation but only logs and drops.

Pattern C_wrong_error: h3spec reports failure with a diagnostic
  mentioning TLS-alert language (e.g. `unexpected_message`,
  `bad_record_mac`, `protocol_version`, `handshake_failure`).
  Implication: H3 violation escalated into a TLS alert instead of
  a QUIC H3 error code.

Pattern B_no_detection: everything else — h3spec reports failure
  with no server-side evidence of detection.

UNCLASSIFIED: the test has no diagnostic block at all; T9 hand
  review must resolve.

CAVEAT: h3spec's stdout does not include per-test start timestamps,
so we cannot align stderr lines to individual tests by wall clock.
The classifier uses substring-based matching of stderr feed_datagram
tokens against the h3spec diagnostic block. If two h3spec tests
share token vocabulary, both may match the same stderr line; T9
hand review breaks the tie.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from h3spec_parse import parse as parse_h3spec  # noqa: E402

_TLS_TOKENS = (
    "TLS alert",
    "unexpected_message",
    "bad_record_mac",
    "protocol_version",
    "handshake_failure",
    "decode_error",
    "illegal_parameter",
)
_FEED_DATAGRAM_RX = re.compile(r"feed_datagram error:\s*(?P<msg>.+)$")
_SIGNIFICANT_TOKEN_RX = re.compile(r"[A-Za-z_][A-Za-z_0-9]{4,}")


def _stderr_messages(server_err_text: str) -> list[str]:
    """Extract every distinct `feed_datagram error: <msg>` payload from server stderr."""
    seen: list[str] = []
    for line in server_err_text.splitlines():
        m = _FEED_DATAGRAM_RX.search(line)
        if m:
            msg = m.group("msg").strip()
            if msg not in seen:
                seen.append(msg)
    return seen


def _classify(test_row: dict, feed_errors: list[str]) -> tuple[str | None, str | None]:
    """Return (classified_pattern, evidence) for a parsed h3spec row.

    Returns (None, None) for passing tests.
    """
    if test_row["status"] != "fail":
        return None, None
    msg = test_row.get("message", "") or ""

    # Pattern A: stderr feed_datagram error token appears in the h3spec diagnostic.
    for err in feed_errors:
        for token in _SIGNIFICANT_TOKEN_RX.findall(err):
            if token in msg:
                return "A_log_drop", f"feed_datagram error: {err}"

    # Pattern C: TLS-alert language in the h3spec diagnostic.
    for token in _TLS_TOKENS:
        if token in msg:
            return "C_wrong_error", f"h3spec diagnostic mentions '{token}'"

    # Pattern B vs UNCLASSIFIED: depends on whether the diagnostic block was empty.
    if msg.strip():
        return "B_no_detection", None
    return "UNCLASSIFIED", None


def triage(h3spec_text: str, server_err_text: str) -> dict:
    """Classify each h3spec failure into A_log_drop / B_no_detection / C_wrong_error / UNCLASSIFIED.

    Returns a dict {rows: [...], summary: {pattern: count}}.
    """
    parsed = parse_h3spec(h3spec_text)
    feed_errors = _stderr_messages(server_err_text)
    rows: list[dict] = []
    for row in parsed["per_test"]:
        pat, evidence = _classify(row, feed_errors)
        rows.append({
            "name": row["name"],
            "h3spec_status": row["status"],
            "classified_pattern": pat,
            "evidence": evidence,
            "h3spec_message": row.get("message", ""),
        })
    summary: dict[str, int] = {
        "A_log_drop": 0, "B_no_detection": 0, "C_wrong_error": 0, "UNCLASSIFIED": 0,
    }
    for r in rows:
        if r["classified_pattern"] in summary:
            summary[r["classified_pattern"]] += 1
    return {"rows": rows, "summary": summary}


def main(argv: list[str]) -> int:
    """CLI entry point: --h3spec <path> --server-err <path> → JSON triage on stdout."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--h3spec", required=True, help="path to captured h3spec stdout")
    ap.add_argument("--server-err", required=True, help="path to captured server stderr")
    args = ap.parse_args(argv[1:])

    h3text = Path(args.h3spec).read_text(encoding="utf-8", errors="replace")
    errtext = Path(args.server_err).read_text(encoding="utf-8", errors="replace")
    result = triage(h3text, errtext)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
