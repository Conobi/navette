"""AC-0 evidence probe: GUARD-TAG comptime form is valid in Mojo 1.0.0b1.

This file is the committed artefact behind AC-0 of
`specs/2026-05-29-h3i-phase-a-completion.md`. It must compile and run
to exit code 0 with the expected output (below) before the spec's
predicate modules land. If a Mojo language sweep ever invalidates the
`comptime X = "..."` form or `String(X) + dynamic` concatenation, this
probe fails first and the spec's guard-tag mechanism must be revised.

Expected output:
    case1: [H3-TEST] some runtime detail
    case2: [H3-TEST]
    case3-contains: True
    case4-comptime-in-string: True

Captured live via mcp__mojo-mcp__execute on 2026-05-29 against Mojo 1.0.0b1
(returncode 0, 2.3s).
"""

comptime GUARD_TAG_TEST = "[H3-TEST]"


def use_reason(reason: String) -> String:
    return reason


def main():
    var dynamic = String(" some runtime detail")
    var combined = String(GUARD_TAG_TEST) + dynamic
    print("case1:", use_reason(combined))
    print("case2:", use_reason(GUARD_TAG_TEST))
    var haystack = String(GUARD_TAG_TEST) + " trailing"
    print("case3-contains:", "[H3-TEST]" in haystack)
    # case 4: substring `in` with the comptime symbol directly — this is the
    # form Mojo unit tests use: `tag in connection.pending_close.reason`.
    print("case4-comptime-in-string:", GUARD_TAG_TEST in haystack)
