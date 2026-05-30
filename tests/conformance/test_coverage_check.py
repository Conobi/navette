"""Pytests for coverage_check.py — fixture-driven invariant checks."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FIX = Path(__file__).parent / "fixtures" / "coverage_check"
PROX_FIX = Path(__file__).parents[1] / "fixtures" / "tag_proximity"
SCRIPT = Path(__file__).parents[2] / "conformance" / "scripts" / "coverage_check.py"


def _common(coverage=None, tags=None, threshold=None):
    """Build the canonical-good argv, allowing per-test overrides."""
    return [
        "--mode", "lenient",
        "--spec", str(FIX / "good_spec.md"),
        "--triage", str(FIX / "good_triage.md"),
        "--coverage", str(coverage or FIX / "good_coverage.md"),
        "--tags", *(tags or [str(FIX / "good_tags_quic.mojo"), str(FIX / "good_tags_h3.mojo")]),
        "--threshold-file", str(threshold or FIX / "good_threshold.txt"),
        "--scenarios-dir", str(FIX / "good_scenarios_dir"),
        "--connection-files", str(FIX / "good_connection.mojo"),
    ]


def _run(argv, expect_rc):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *argv],
        capture_output=True,
        text=True,
    )
    assert result.returncode == expect_rc, (
        f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return result


def test_triage_rows_present():
    _run(_common(), expect_rc=0)
    _run(_common(coverage=FIX / "bad_missing_triage.md"), expect_rc=1)


def test_gated_has_binary():
    # The good fixture's gated rows all point at declared [[bin]] entries.
    _run(_common(), expect_rc=0)


def test_strict_rejects_red():
    argv = _common(coverage=FIX / "bad_red_strict.md")
    strict = argv.copy()
    strict[strict.index("lenient")] = "strict"
    _run(strict, expect_rc=1)
    _run(argv, expect_rc=0)


def test_threshold_formula():
    _run(_common(threshold=FIX / "bad_off_by_one_threshold.txt"), expect_rc=1)


def test_tag_defined_once():
    argv = _common(tags=[str(FIX / "bad_duplicate_tag.mojo"), str(FIX / "good_tags_h3.mojo")])
    _run(argv, expect_rc=1)


def test_tag_referenced():
    argv = _common(tags=[str(FIX / "good_tags_quic.mojo"), str(FIX / "bad_orphan_tag.mojo")])
    _run(argv, expect_rc=1)


def test_tag_proximity_fixtures():
    good = ["inline.mojo", "before_4_lines.mojo", "after_4_lines.mojo", "line_continuation.mojo"]
    bad = ["far_apart.mojo", "in_comment.mojo"]
    for name in good:
        _run(["--verify-tag-proximity", "--connection-files", str(PROX_FIX / name)], expect_rc=0)
    for name in bad:
        _run(["--verify-tag-proximity", "--connection-files", str(PROX_FIX / name)], expect_rc=1)


def test_cli_triage_filter_accepts_c1_c6():
    """AC-4.tool: --triage-filter C1,C6 is a recognised flag (rc 0 or 1, not 2)."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--mode", "lenient",
         "--triage", str(FIX / "good_triage.md"),
         "--coverage", str(FIX / "good_coverage.md"),
         "--tags", str(FIX / "good_tags_quic.mojo"), str(FIX / "good_tags_h3.mojo"),
         "--threshold-file", str(FIX / "good_threshold.txt"),
         "--scenarios-dir", str(FIX / "good_scenarios_dir"),
         "--triage-filter", "C1,C6"],
        capture_output=True, text=True,
    )
    assert result.returncode in (0, 1), \
        f"unrecognised flag (rc={result.returncode}); stderr={result.stderr}"


def test_triage_filter_c1_c6_yields_thirteen_rows():
    """AC-4.tool: --triage-filter C1,C6 keeps exactly F02-F09 + F25-F29 (13 rows).

    Column extraction must read the LAST `|`-delimited column and apply
    `re.findall(r"\\bC\\d+\\b", cluster_cell)`, not column index 1.
    """
    from conformance.scripts.coverage_check import parse_triage_failure_ids
    triage = Path(__file__).parents[2] / "research" / "h3spec-failure-triage.md"
    ids = parse_triage_failure_ids(triage, cluster_filter={"C1", "C6"})
    assert ids == {
        "F02", "F03", "F04", "F05", "F06", "F07", "F08", "F09",
        "F25", "F26", "F27", "F28", "F29",
    }, f"got {sorted(ids)}"
