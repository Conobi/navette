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
comptime GUARD_TAG_NO_FRAMES = "[QUIC-NO-FRAMES]"
comptime GUARD_TAG_UNKNOWN_FRAME = "[QUIC-UNKNOWN-FRAME]"
comptime GUARD_TAG_RESERVED_BITS_HS = "[QUIC-RESERVED-BITS-HS]"
comptime GUARD_TAG_RESERVED_BITS_SHORT = "[QUIC-RESERVED-BITS-SHORT]"
comptime GUARD_TAG_PATH_CHALLENGE_HS = "[QUIC-PATH-CHALLENGE-HS]"

# C1 — transport parameter validation (RFC 9000 §7 / §18)
comptime GUARD_TAG_TP_INITIAL_SCID_MISSING      = "[QUIC-TP-INITIAL-SCID-MISSING]"
comptime GUARD_TAG_TP_ORIGINAL_DCID_FORBIDDEN   = "[QUIC-TP-ORIGINAL-DCID-FORBIDDEN]"
comptime GUARD_TAG_TP_PREFERRED_ADDR_FORBIDDEN  = "[QUIC-TP-PREFERRED-ADDR-FORBIDDEN]"
comptime GUARD_TAG_TP_RETRY_SCID_FORBIDDEN      = "[QUIC-TP-RETRY-SCID-FORBIDDEN]"
comptime GUARD_TAG_TP_STATELESS_RESET_FORBIDDEN = "[QUIC-TP-STATELESS-RESET-FORBIDDEN]"
comptime GUARD_TAG_TP_MAX_UDP_PAYLOAD_RANGE     = "[QUIC-TP-MAX-UDP-PAYLOAD-RANGE]"
comptime GUARD_TAG_TP_ACK_DELAY_EXP_RANGE       = "[QUIC-TP-ACK-DELAY-EXP-RANGE]"
comptime GUARD_TAG_TP_MAX_ACK_DELAY_RANGE       = "[QUIC-TP-MAX-ACK-DELAY-RANGE]"
