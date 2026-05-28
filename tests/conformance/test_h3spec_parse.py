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


TRIAGE = REPO / "conformance" / "scripts" / "h3spec_triage.py"
CAPTURE_DIR = REPO / "tests" / "conformance" / "fixtures" / "h3spec_triage_capture"


def _triage() -> dict:
    """Run h3spec_triage.py against the captured h3spec+server.err pair and return the parsed JSON."""
    out = subprocess.check_output([
        "python3", str(TRIAGE),
        "--h3spec", str(CAPTURE_DIR / "h3spec.out"),
        "--server-err", str(CAPTURE_DIR / "server.err"),
    ])
    return json.loads(out)


def test_triage_classifies_every_failure() -> None:
    """Every failing h3spec test gets a classification (A/B/C/UNCLASSIFIED)."""
    result = _triage()
    fail_rows = [r for r in result["rows"] if r["h3spec_status"] == "fail"]
    assert len(fail_rows) >= 30, f"expected at least 30 failures in this fixture, got {len(fail_rows)}"
    valid = {"A_log_drop", "B_no_detection", "C_wrong_error", "UNCLASSIFIED"}
    assert all(r["classified_pattern"] in valid for r in fail_rows), \
        [r["classified_pattern"] for r in fail_rows if r["classified_pattern"] not in valid]


def test_triage_pattern_a_attaches_stderr_evidence() -> None:
    """Pattern A rows must include the matching feed_datagram error line as evidence."""
    result = _triage()
    a_rows = [r for r in result["rows"] if r["classified_pattern"] == "A_log_drop"]
    assert all("feed_datagram error" in (r.get("evidence") or "") for r in a_rows)


def test_triage_passed_rows_omit_pattern() -> None:
    """Passing tests should not be classified (the taxonomy applies only to failures)."""
    result = _triage()
    pass_rows = [r for r in result["rows"] if r["h3spec_status"] == "pass"]
    for r in pass_rows:
        assert r.get("classified_pattern") in {None, ""}


CAPTURE = CAPTURE_DIR / "h3spec.out"


def _parse_capture() -> dict:
    """Parse the triage-capture h3spec fixture (richer than the stdout sample)."""
    out = subprocess.check_output(["python3", str(PARSE), str(CAPTURE)])
    return json.loads(out)


def test_parse_failures_block_attaches_messages() -> None:
    """Failed rows should carry a `message` field with diagnostic text from the Failures block."""
    result = _parse_capture()
    fail_rows = [r for r in result["per_test"] if r["status"] == "fail"]
    assert fail_rows, "expected at least one failure"
    rows_with_msg = [r for r in fail_rows if r.get("message", "").strip()]
    assert len(rows_with_msg) >= len(fail_rows) * 0.9, \
        f"expected diagnostic on >=90% of failures, got {len(rows_with_msg)}/{len(fail_rows)}"
