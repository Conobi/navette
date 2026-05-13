# src/quic/ecn.mojo
# QUIC ECN support — RFC 9000 §13.4 + RFC 9002 §7.9.
# Types, constants, and state machine for ECN path validation.


# ── IP ECN codepoints (RFC 3168) ────────────────────────────────────────────

comptime ECN_NOT_ECT: UInt8 = 0   # non-ECN-capable
comptime ECN_ECT1: UInt8 = 1      # ECN-capable (ECT(1)) — not used for sending
comptime ECN_ECT0: UInt8 = 2      # ECN-capable (ECT(0)) — used for outgoing packets
comptime ECN_CE: UInt8 = 3        # Congestion Experienced — network signal


# ── ECN path-validation states (RFC 9000 §13.4.2) ───────────────────────────

comptime ECN_STATE_PROBING: UInt8 = 0   # sending ECT(0), verifying path supports ECN
comptime ECN_STATE_CAPABLE: UInt8 = 1   # ECN confirmed working
comptime ECN_STATE_DISABLED: UInt8 = 2  # path strips or corrupts ECN; disable


# ── EcnCounts ────────────────────────────────────────────────────────────────


struct EcnCounts(Copyable, Movable):
    """Cumulative ECN mark counts for one direction in one PN space."""
    var ect0: UInt64
    var ect1: UInt64
    var ce: UInt64

    def __init__(out self):
        self.ect0 = UInt64(0)
        self.ect1 = UInt64(0)
        self.ce = UInt64(0)

    def __init__(out self, ect0: UInt64, ect1: UInt64, ce: UInt64):
        self.ect0 = ect0
        self.ect1 = ect1
        self.ce = ce

    def __init__(out self, *, other: Self):
        self.ect0 = other.ect0
        self.ect1 = other.ect1
        self.ce = other.ce

    def __init__(out self, *, deinit take: Self):
        self.ect0 = take.ect0
        self.ect1 = take.ect1
        self.ce = take.ce

    def total(self) -> UInt64:
        """Sum of all three codepoint counts."""
        return self.ect0 + self.ect1 + self.ce

    def is_zero(self) -> Bool:
        """True if no ECN marks have been observed."""
        return self.ect0 == UInt64(0) and self.ect1 == UInt64(0) and self.ce == UInt64(0)
