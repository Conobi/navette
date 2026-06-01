"""Pytests for coverage_check.py — fixture-driven invariant checks."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FIX = Path(__file__).parent / "fixtures" / "coverage_check"
FIXTURES = FIX  # alias used by tag-scope tests
PROX_FIX = Path(__file__).parents[1] / "fixtures" / "tag_proximity"
REPO_ROOT = Path(__file__).parents[2]
SCRIPT = REPO_ROOT / "conformance" / "scripts" / "coverage_check.py"


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


def test_cli_tag_scope_accepts_explicit_ids():
    """--tag-scope F02,F03 is a recognised flag (rc 0 or 1, not 2)."""
    triage = REPO_ROOT / "research" / "h3spec-failure-triage.md"
    coverage = FIXTURES / "good_coverage.md"
    threshold = FIXTURES / "good_threshold.txt"
    scenarios = FIXTURES / "good_scenarios_dir"
    spec = FIXTURES / "good_spec.md"
    tags = FIXTURES / "good_tags_quic.mojo"
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--spec", str(spec),
         "--triage", str(triage),
         "--coverage", str(coverage),
         "--tags", str(tags),
         "--threshold-file", str(threshold),
         "--scenarios-dir", str(scenarios),
         "--tag-scope", "F02,F03"],
        capture_output=True, text=True,
    )
    assert result.returncode in (0, 1), (
        f"argparse rejected --tag-scope (rc={result.returncode}); "
        f"stderr={result.stderr}"
    )


def test_tag_scope_yields_explicit_subset():
    """--tag-scope F02..F09+F25..F29 returns exactly 13 ids."""
    from conformance.scripts.coverage_check import parse_triage_failure_ids
    triage = REPO_ROOT / "research" / "h3spec-failure-triage.md"
    scope = {
        "F02", "F03", "F04", "F05", "F06", "F07", "F08", "F09",
        "F25", "F26", "F27", "F28", "F29",
    }
    ids = parse_triage_failure_ids(triage, tag_scope=scope)
    assert ids == scope, f"expected {sorted(scope)}, got {sorted(ids)}"


def test_strict_accepts_deferred_status():
    """AC-4.deferred: status starting with 'deferred:' is non-red, non-gated."""
    argv = _common(coverage=FIX / "good_deferred_coverage.md")
    strict = argv.copy()
    strict[strict.index("lenient")] = "strict"
    _run(strict, expect_rc=0)


def test_always_on_count_zero():
    """--always-on-count 0: sanity row already in Table B; no implicit +1."""
    # good_coverage.md has gated(A)=2, gated(B)=1 → default expects 4.
    # With --always-on-count 0 the formula is 2+1+0=3 so threshold=3 passes
    # and threshold=4 (default good_threshold.txt) fails.
    argv_zero = _common(threshold=FIX / "good_threshold_no_implicit.txt") + [
        "--always-on-count", "0"
    ]
    _run(argv_zero, expect_rc=0)
    # Sanity: the same threshold=3 file fails with default always-on-count=1
    # (formula expects 4).
    argv_default = _common(threshold=FIX / "good_threshold_no_implicit.txt")
    _run(argv_default, expect_rc=1)


def test_tag_scope_rejects_malformed_token():
    """Argparse rejects tokens that don't match ^F\\d{2}$."""
    triage = REPO_ROOT / "research" / "h3spec-failure-triage.md"
    coverage = FIXTURES / "good_coverage.md"
    threshold = FIXTURES / "good_threshold.txt"
    scenarios = FIXTURES / "good_scenarios_dir"
    spec = FIXTURES / "good_spec.md"
    tags = FIXTURES / "good_tags_quic.mojo"
    for bad in ("F2", "F100", "f02", "FOO"):
        result = subprocess.run(
            [sys.executable, str(SCRIPT),
             "--spec", str(spec),
             "--triage", str(triage),
             "--coverage", str(coverage),
             "--tags", str(tags),
             "--threshold-file", str(threshold),
             "--scenarios-dir", str(scenarios),
             "--tag-scope", bad],
            capture_output=True, text=True,
        )
        assert result.returncode == 2, (
            f"--tag-scope {bad!r} should argparse-error (rc=2), got rc={result.returncode}"
        )


def test_tag_scope_inv6_catches_typo():
    """--tag-scope F02,F99 raises Inv-6 (F99 not in triage)."""
    triage = REPO_ROOT / "research" / "h3spec-failure-triage.md"
    coverage = FIXTURES / "good_coverage.md"
    threshold = FIXTURES / "good_threshold.txt"
    scenarios = FIXTURES / "good_scenarios_dir"
    spec = FIXTURES / "good_spec.md"
    tags = FIXTURES / "good_tags_quic.mojo"
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--spec", str(spec),
         "--triage", str(triage),
         "--coverage", str(coverage),
         "--tags", str(tags),
         "--threshold-file", str(threshold),
         "--scenarios-dir", str(scenarios),
         "--tag-scope", "F02,F99"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1, f"expected Inv-6 rc=1, got rc={result.returncode}"
    assert "Inv-6" in result.stderr and "F99" in result.stderr, (
        f"expected Inv-6 + F99 in stderr, got: {result.stderr}"
    )


def test_tag_scope_empty_returns_all_rows():
    """Empty --tag-scope returns the full triage set (default semantics)."""
    from conformance.scripts.coverage_check import parse_triage_failure_ids
    triage = REPO_ROOT / "research" / "h3spec-failure-triage.md"
    all_ids = parse_triage_failure_ids(triage, tag_scope=None)
    none_ids = parse_triage_failure_ids(triage, tag_scope=set())
    assert all_ids == none_ids
    assert len(all_ids) >= 30, f"expected ≥30 F-rows, got {len(all_ids)}"


def test_tag_scope_coalesces_duplicates():
    """F02,F02,F02 is accepted; duplicates coalesce via set semantics."""
    from conformance.scripts.coverage_check import parse_triage_failure_ids
    triage = REPO_ROOT / "research" / "h3spec-failure-triage.md"
    ids = parse_triage_failure_ids(triage, tag_scope={"F02"})
    ids_dup = parse_triage_failure_ids(triage, tag_scope={"F02", "F02"})  # noqa: B033
    assert ids == ids_dup == {"F02"}
