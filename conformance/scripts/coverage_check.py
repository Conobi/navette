#!/usr/bin/env python3
"""coverage_check.py — Phase-A coverage invariants.

Invariants enforced:

- Inv-1: every ``F\\d{2}`` row in the triage doc (``--triage``) is present in
  Table A of COVERAGE.md (``--coverage``).
- Inv-2: every ``gated`` row (Table A or B) names a ``scenario_binary`` that
  is declared as a ``[[bin]]`` in ``--scenarios-dir/Cargo.toml``.
- Inv-3 (``--mode strict``): no row carries the literal status ``red``.
- Inv-4: ``int(open(threshold_file).read())`` equals
  ``count(gated, A) + count(gated, B) + always_on_count`` — the
  ``always_on_count`` (default 1) budgets an implicit always-on scenario
  such as h3i's ``sanity_get`` that is not listed in any COVERAGE.md table.
  Pass ``--always-on-count 0`` when the always-on baseline is already
  enumerated as a Table B gated row (e.g. the TLS-conformance harness).
- Inv-5: every ``comptime GUARD_TAG_<NAME> = "[<BRACKETED>]"`` declaration in
  ``--tags`` files appears exactly once across all tag files, AND every
  bracketed tag is referenced at least once from either a COVERAGE.md row,
  a ``.rs`` scenario binary under ``--scenarios-dir/src/bin/``, or a
  ``guard_predicates.mojo`` sibling of any ``--tags`` file. Predicate
  modules are the canonical reference site for guards that ship as
  defensive code without a paired scenario binary.

A separate sub-mode, ``--verify-tag-proximity``, checks ``--connection-files``
only: every ``GUARD_TAG_<NAME>`` *identifier* reference must appear on the
same source line as a ``close_app(`` or ``close_transport(`` opener, OR
within four source lines before/after such an opener. The window is
bidirectional. References that live inside a ``#`` comment cannot satisfy
the proximity rule — they are reported as violations because the runtime
close path will never see them.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TAG_DEF = re.compile(r'^\s*comptime\s+(GUARD_TAG_\w+)\s*=\s*"(\[[A-Z0-9\-]+\])"\s*$')
TRIAGE_ROW = re.compile(r"^\|\s*(F\d{2})\s*\|")
COVERAGE_A_ROW = re.compile(
    r"^\|\s*(F\d{2})\s*\|[^|]*\|\s*([a-zA-Z0-9:\-]+)\s*\|\s*([^\s|]+)\s*\|"
)
COVERAGE_B_ROW = re.compile(
    r"^\|\s*(SY\d{2})\s*\|[^|]*\|\s*([^\s|]+)\s*\|"
)
TAG_SCOPE_TOKEN = re.compile(r"^F\d{2}$")
CARGO_BIN_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"\s*$')
TAG_LITERAL = re.compile(r"\[[A-Z0-9\-]+\]")
GUARD_TAG_REF = re.compile(r"\bGUARD_TAG_\w+\b")
CLOSE_OPENER = re.compile(r"\bclose_(?:app|transport)\(")
PROXIMITY_WINDOW = 4


def parse_tag_defs(paths):
    """Parse all tag-definition files, returning {bracketed_tag: (path, line, ident)}.

    Exits 1 on a duplicate definition across the union of all tag files,
    which violates the first half of Inv-5. The ``ident`` is the
    ``GUARD_TAG_<NAME>`` identifier — predicate modules reference tags via
    this identifier rather than the bracketed string literal.
    """
    tags = {}
    for raw in paths:
        path = Path(raw)
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            match = TAG_DEF.match(line)
            if not match:
                continue
            ident = match.group(1)
            tag = match.group(2)
            if tag in tags:
                prior_path, prior_line, _ = tags[tag]
                print(
                    f"Inv-5: duplicate tag {tag} defined at "
                    f"{prior_path}:{prior_line} and {path}:{lineno}",
                    file=sys.stderr,
                )
                sys.exit(1)
            tags[tag] = (str(path), lineno, ident)
    return tags


def parse_triage_failure_ids(triage_path, tag_scope=None):
    """Return the set of F-row ids declared in the triage document.

    When ``tag_scope`` is ``None`` or empty the function returns every
    F-row id (default behaviour).

    When ``tag_scope`` is a non-empty set of F-row ids (e.g.
    ``{"F02", "F03"}``), only rows whose id is in that set are returned.
    The semantic check that every id in ``tag_scope`` exists in the
    triage doc (Inv-6) is performed by the caller against the unfiltered
    triage set.
    """
    ids = set()
    use_filter = bool(tag_scope)
    for line in Path(triage_path).read_text().splitlines():
        match = TRIAGE_ROW.match(line)
        if not match:
            continue
        fid = match.group(1)
        if use_filter and fid not in tag_scope:
            continue
        ids.add(fid)
    return ids


def parse_coverage(coverage_path):
    """Walk COVERAGE.md and return (table_a_rows, table_b_rows).

    Each row is a dict with at minimum ``id``, ``status``, and
    ``scenario_binary`` keys. Table B rows store the status implicitly as
    ``gated`` since the schema in COVERAGE.md does not surface a status
    column for synthetic scenarios.
    """
    text = Path(coverage_path).read_text()
    table_a = []
    table_b = []
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## Table A"):
            current = "A"
            continue
        if stripped.startswith("## Table B"):
            current = "B"
            continue
        if stripped.startswith("## ") and current is not None:
            current = None
            continue
        if current == "A":
            match = COVERAGE_A_ROW.match(line)
            if match:
                table_a.append(
                    {
                        "id": match.group(1),
                        "status": match.group(2),
                        "scenario_binary": match.group(3),
                    }
                )
        elif current == "B":
            match = COVERAGE_B_ROW.match(line)
            if match:
                table_b.append(
                    {
                        "id": match.group(1),
                        "status": "gated",
                        "scenario_binary": match.group(2),
                    }
                )
    return table_a, table_b


def parse_cargo_bins(scenarios_dir):
    """Return the set of [[bin]] target names declared in Cargo.toml."""
    cargo = Path(scenarios_dir) / "Cargo.toml"
    bins = set()
    in_bin = False
    for line in cargo.read_text().splitlines():
        stripped = line.strip()
        if stripped == "[[bin]]":
            in_bin = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_bin = False
            continue
        if in_bin:
            match = CARGO_BIN_NAME.match(line)
            if match:
                bins.add(match.group(1))
    return bins


def collect_tag_references(coverage_path, scenarios_dir, tag_paths, ident_to_tag):
    """Collect every bracketed tag referenced by an in-tree reference site.

    Reference sites scanned, in order:

    - COVERAGE.md (bracketed literals).
    - ``.rs`` scenario binaries under ``--scenarios-dir/src/bin/``
      (bracketed literals).
    - ``guard_predicates.mojo`` files that sit alongside each ``--tags``
      file (``GUARD_TAG_<NAME>`` identifier references, translated through
      ``ident_to_tag`` into bracketed form). Predicate modules are the
      canonical reference site when a scenario binary has been deferred.
    """
    refs = set()
    refs.update(TAG_LITERAL.findall(Path(coverage_path).read_text()))
    src_bin = Path(scenarios_dir) / "src" / "bin"
    if src_bin.is_dir():
        for rs in src_bin.glob("*.rs"):
            refs.update(TAG_LITERAL.findall(rs.read_text()))
    for raw in tag_paths:
        predicate = Path(raw).parent / "guard_predicates.mojo"
        if not predicate.is_file():
            continue
        for ident in GUARD_TAG_REF.findall(predicate.read_text()):
            tag = ident_to_tag.get(ident)
            if tag is not None:
                refs.add(tag)
    return refs


def check_invariants(args):
    """Run Inv-1..5 against the resolved fixture set."""
    violations = []

    tag_scope = {t.strip() for t in args.tag_scope.split(",") if t.strip()}
    triage_all = parse_triage_failure_ids(args.triage, tag_scope=None)
    triage_ids = parse_triage_failure_ids(args.triage, tag_scope=tag_scope or None)
    # Inv-6: every F-row in the scope must exist in the triage doc.
    for fid in sorted(tag_scope - triage_all):
        violations.append(
            f"Inv-6: --tag-scope contains F-row {fid} not in triage doc"
        )
    table_a, table_b = parse_coverage(args.coverage)
    a_ids = {row["id"] for row in table_a}

    # Inv-1
    for fid in sorted(triage_ids):
        if fid not in a_ids:
            violations.append(f"Inv-1: triage row {fid} missing from COVERAGE.md Table A")

    # Inv-2 + Inv-3
    cargo_bins = parse_cargo_bins(args.scenarios_dir)
    gated_a = 0
    gated_b = 0
    for row in table_a:
        status = row["status"]
        if status == "red" and args.mode == "strict":
            violations.append(f"Inv-3: row {row['id']} has status 'red' (strict mode)")
        if status == "gated":
            gated_a += 1
            if row["scenario_binary"] not in cargo_bins:
                violations.append(
                    f"Inv-2: Table A row {row['id']} names scenario_binary "
                    f"{row['scenario_binary']!r} but no matching [[bin]] in Cargo.toml"
                )
    for row in table_b:
        if row["status"] == "red" and args.mode == "strict":
            violations.append(f"Inv-3: Table B row {row['id']} has status 'red' (strict mode)")
        gated_b += 1
        if row["scenario_binary"] not in cargo_bins:
            violations.append(
                f"Inv-2: Table B row {row['id']} names scenario_binary "
                f"{row['scenario_binary']!r} but no matching [[bin]] in Cargo.toml"
            )

    # Inv-4: threshold == gated(A) + gated(B) + always_on_count.
    # The always_on_count (default 1) budgets an implicit "always-on" sanity
    # scenario (e.g. h3i's sanity_get) that is not listed in any COVERAGE.md
    # table. Pass --always-on-count 0 when the always-on baseline is explicitly
    # enumerated as a Table B gated row (as in the TLS-conformance harness,
    # where tls_sanity_handshake appears as SY01 and is already counted in
    # gated_b).
    always_on = args.always_on_count
    raw_threshold = Path(args.threshold_file).read_text().strip()
    try:
        threshold = int(raw_threshold)
    except ValueError:
        violations.append(f"Inv-4: threshold file does not contain an integer: {raw_threshold!r}")
        threshold = None
    if threshold is not None:
        expected = gated_a + gated_b + always_on
        if threshold != expected:
            violations.append(
                f"Inv-4: threshold {threshold} != gated(A)={gated_a} + "
                f"gated(B)={gated_b} + always_on={always_on} = {expected}"
            )

    # Inv-5
    tags = parse_tag_defs(args.tags)
    ident_to_tag = {ident: tag for tag, (_, _, ident) in tags.items()}
    refs = collect_tag_references(
        args.coverage, args.scenarios_dir, args.tags, ident_to_tag
    )
    for tag, (path, line, _) in sorted(tags.items()):
        if tag not in refs:
            violations.append(
                f"Inv-5: tag {tag} defined at {path}:{line} is never referenced "
                f"in COVERAGE.md, scenario binaries, or guard_predicates.mojo"
            )

    return violations


def verify_tag_proximity(connection_files):
    """Verify the ±4-line bidirectional proximity heuristic.

    Returns a list of violation messages. A reference is in-bounds when:

    - The reference and a ``close_app(``/``close_transport(`` opener appear on
      the same source line, OR
    - The reference is within ``PROXIMITY_WINDOW`` lines (4) of such an
      opener, in either direction.

    Lines whose first non-blank character is ``#`` are treated as comments
    and never count as references.
    """
    violations = []
    for raw in connection_files:
        path = Path(raw)
        lines = path.read_text().splitlines()
        opener_lines = {
            i for i, line in enumerate(lines) if CLOSE_OPENER.search(line)
        }
        for i, line in enumerate(lines):
            for match in GUARD_TAG_REF.finditer(line):
                ident = match.group(0)
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    # A comment can never feed a runtime close path.
                    violations.append(
                        f"proximity: {ident} at {path}:{i + 1} sits inside a "
                        f"`#` comment and is unreachable from any close opener"
                    )
                    continue
                in_range = any(
                    abs(i - opener) <= PROXIMITY_WINDOW for opener in opener_lines
                )
                if not in_range:
                    violations.append(
                        f"proximity: {ident} at {path}:{i + 1} is not within "
                        f"{PROXIMITY_WINDOW} lines of any close_app/close_transport opener"
                    )
    return violations


def main(argv=None):
    parser = argparse.ArgumentParser(description="Phase-A coverage invariants")
    parser.add_argument("--mode", choices=("strict", "lenient"), default="strict")
    parser.add_argument("--spec")
    parser.add_argument("--triage")
    parser.add_argument("--coverage")
    parser.add_argument("--tags", nargs="*", default=[])
    parser.add_argument("--threshold-file")
    parser.add_argument("--scenarios-dir")
    parser.add_argument("--connection-files", nargs="*", default=[])
    def _tag_scope_value(raw: str) -> str:
        """Argparse validator for --tag-scope tokens."""
        for token in raw.split(","):
            tok = token.strip()
            if not tok:
                continue
            if not TAG_SCOPE_TOKEN.match(tok):
                import argparse as _ap
                raise _ap.ArgumentTypeError(
                    f"--tag-scope token {tok!r} does not match ^F\\d{{2}}$ "
                    f"(must be uppercase F followed by exactly two digits)"
                )
        return raw

    parser.add_argument(
        "--tag-scope", default="", type=_tag_scope_value,
        help=(
            "Comma-separated F-row ids to scope Inv-1 against, e.g. "
            "F02,F03,F04. Empty (default) means all triage rows. "
            "Canonical token shape: ^F\\d{2}$."
        ),
    )
    parser.add_argument(
        "--always-on-count", type=int, default=1, metavar="N",
        help=(
            "Number of implicit always-on scenarios not listed in any COVERAGE.md "
            "table (default: 1, budgeting a sanity scenario such as h3i's "
            "sanity_get). Pass 0 when the always-on baseline is explicitly "
            "enumerated as a Table B gated row so it is not double-counted."
        ),
    )
    parser.add_argument(
        "--verify-tag-proximity",
        action="store_true",
        help="Run only the bidirectional proximity heuristic on --connection-files.",
    )
    args = parser.parse_args(argv)

    if args.verify_tag_proximity:
        violations = verify_tag_proximity(args.connection_files)
    else:
        required = ("triage", "coverage", "threshold_file", "scenarios_dir")
        missing = [name for name in required if getattr(args, name) is None]
        if missing:
            parser.error(f"missing required args for invariant mode: {missing}")
        violations = check_invariants(args)

    if violations:
        for msg in violations:
            print(msg, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
