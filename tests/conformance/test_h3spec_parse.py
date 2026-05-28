"""Tests for h3spec_parse.py — parsing h3spec textual output into structured JSON.

The parser must extract per-test status (pass/fail/skip) and a stable
test name for triage cross-referencing. The pass-count derived from
the JSON drives the CI gate's exit decision.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PARSE = REPO / "conformance" / "scripts" / "h3spec_parse.py"
FIXTURE = REPO / "tests" / "conformance" / "fixtures" / "h3spec_stdout_sample.txt"


def _parse() -> dict:
    """Run h3spec_parse.py against the captured fixture and return the parsed JSON."""
    out = subprocess.check_output(["python3", str(PARSE), str(FIXTURE)])
    return json.loads(out)


def test_parse_emits_total_count() -> None:
    result = _parse()
    assert result["total"] == result["passed"] + result["failed"] + result["skipped"]
    assert result["total"] >= 1


def test_parse_per_test_has_name_and_status() -> None:
    result = _parse()
    assert isinstance(result["per_test"], list)
    assert all("name" in row and "status" in row for row in result["per_test"])
    assert all(row["status"] in {"pass", "fail", "skip"} for row in result["per_test"])


def test_parse_pass_count_matches_per_test() -> None:
    result = _parse()
    actual_pass = sum(1 for row in result["per_test"] if row["status"] == "pass")
    assert result["passed"] == actual_pass
