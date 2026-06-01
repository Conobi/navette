"""Regen byte-identity test for oracle_quic_frame.py.

Spawns the oracle script in a subprocess against a temporary output path
and asserts the produced JSON is byte-identical to the canonical fixture.
The fixture is captured pre-fix (C1) — the test fails until Fix A + Fix B
land in C2.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ORACLE_SCRIPT = REPO_ROOT / "conformance" / "scripts" / "oracle_quic_frame.py"
CANONICAL_FIXTURE = (
    REPO_ROOT / "tests" / "conformance" / "fixtures" / "oracle_quic_frame_canonical.json"
)
LIVE_OUTPUT = REPO_ROOT / "conformance" / "vectors" / "rfc9000" / "frame.json"


def test_oracle_regen_matches_canonical_fixture(tmp_path):
    """Regenerating the oracle output must produce bytes identical to the fixture."""
    backup = tmp_path / "frame.json.backup"
    shutil.copy(LIVE_OUTPUT, backup)
    try:
        subprocess.run(
            [sys.executable, str(ORACLE_SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        regenerated = LIVE_OUTPUT.read_bytes()
        canonical = CANONICAL_FIXTURE.read_bytes()
        assert regenerated == canonical, (
            "oracle regen drifted from canonical fixture; "
            f"len(regen)={len(regenerated)} len(canonical)={len(canonical)}"
        )
    finally:
        shutil.copy(backup, LIVE_OUTPUT)
