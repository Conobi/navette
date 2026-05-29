"""Single source of truth for QUIC conformance guard reason tags.

Grep-friendly format: exactly one `comptime GUARD_TAG_*` per line, no
inline comments after the literal, no re-exports. The coverage_check.py
helper depends on this format (one tag per line, leading literal name
matches `GUARD_TAG_<UPPER>`).

Module name intentionally has no leading underscore: Mojo 1.0.0b1's
module resolver rejects underscore-prefixed module imports
(`unable to locate module '_guard_tags'`). The module is internal by
convention — package `__init__.mojo` does not re-export it.
"""

comptime GUARD_TAG_RESET_SEND_ONLY = "[QUIC-RESET-SEND-ONLY]"
comptime GUARD_TAG_STOP_LOCAL_NOT_CREATED = "[QUIC-STOP-LOCAL-NOT-CREATED]"
