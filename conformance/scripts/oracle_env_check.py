#!/usr/bin/env python3
"""Assert installed Python oracle versions match uv.lock.

Runs once before scripts/run_tests.sh and conformance/scripts/run_tests.sh
(see §3.4 of plans/2026-05-13-deps-enhancement.md). Fails fast on dev/CI
version drift instead of producing oracle mismatches deep in a test run.

Assumes Python >= 3.11 (stdlib tomllib). See pyproject.toml.
"""
from __future__ import annotations

import importlib.metadata as md
import sys
import tomllib
from pathlib import Path

# Python packages this repo treats as live Mojo↔Python oracles.
# Build-only deps (mojo-compiler, mojox, etc.) are not asserted —
# their pin lives in pyproject.toml and is enforced by `uv sync`.
ORACLE_PACKAGES = (
    "aioquic",
    "cryptography",
    "h11",
    "h2",
    "hpack",
    "httptools",
    "hyperframe",
)


def main() -> int:
    if sys.version_info < (3, 11):
        print(
            f"oracle_env_check requires Python >= 3.11 "
            f"(stdlib tomllib); got {sys.version_info[:3]}",
            file=sys.stderr,
        )
        return 1

    repo_root = Path(__file__).resolve().parents[2]
    lock_path = repo_root / "uv.lock"
    if not lock_path.exists():
        print(f"uv.lock not found at {lock_path}", file=sys.stderr)
        return 1

    with lock_path.open("rb") as f:
        lock = tomllib.load(f)

    pkgs = {p["name"]: p["version"] for p in lock.get("package", [])}
    mismatches: list[str] = []

    for name in ORACLE_PACKAGES:
        if name not in pkgs:
            # Not in lock → may be optional / not installed yet.
            continue
        expected = pkgs[name]
        try:
            actual = md.version(name)
        except md.PackageNotFoundError:
            mismatches.append(f"{name}: lock={expected} installed=<missing>")
            continue
        if actual != expected:
            mismatches.append(f"{name}: lock={expected} installed={actual}")

    if mismatches:
        print("oracle env drift:", file=sys.stderr)
        for m in mismatches:
            print(f"  - {m}", file=sys.stderr)
        print(
            "hint: run `uv sync --group dev` to align installed versions.",
            file=sys.stderr,
        )
        return 1

    print(f"oracle env ok ({len(ORACLE_PACKAGES)} packages match uv.lock)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
