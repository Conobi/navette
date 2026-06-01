# src/quic/path_validator.mojo
#
# Path validator — RFC 9000 §8 + §9.5 path validation for QUIC migration.
#
# Tracks pending PATH_CHALLENGE frames (8-byte random tokens) sent to
# candidate peer addresses, validates on matching PATH_RESPONSE, and
# enforces the §8.1 anti-amplification budget (3× received bytes per
# unvalidated path).
#
# Used by QuicConnection to gate path migration. Stays a pure
# data-structure module — no I/O, no socket access; the caller serializes
# PATH_CHALLENGE/RESPONSE frames and computes "now" timestamps.

from std.ffi import external_call
from std.memory import Span
from std.memory.unsafe_pointer import alloc as _pv_alloc


# ── RFC 9000 limits ───────────────────────────────────────────────────────────

# RFC 9000 §8.2: max 3 PATH_CHALLENGE attempts per challenge before abandon.
comptime MAX_CHALLENGE_ATTEMPTS: UInt8 = 3
# RFC 9000 §8.1: anti-amplification factor — server-sent ≤ 3× server-received
# on an unvalidated path.
comptime ANTI_AMP_FACTOR: Int64 = 3
# RFC 9000 §8.2: PATH_CHALLENGE / PATH_RESPONSE data is exactly 8 bytes.
comptime PATH_TOKEN_LEN: Int = 8


# ── PathKey — canonical comparable identifier for a peer 4-tuple ──────────────


struct PathKey(Copyable, Movable):
    """Canonical comparable identifier for a peer (family, addr, port).

    Holds family + 16-byte address buffer (IPv4 lives in the last 4 bytes,
    IPv6 fills all 16) + port. Equality is byte-exact across all three
    fields, so PATH_RESPONSE matching by-path is a single struct compare
    regardless of address family.
    """

    var family: Int32
    var addr: List[UInt8]   # always 16 bytes; IPv4 zero-padded in the high 12
    var port: UInt16

    def __init__(out self, family: Int32, var addr: List[UInt8], port: UInt16):
        """Construct from explicit family + 16-byte addr + port."""
        self.family = family
        self.addr = addr^
        self.port = port

    def __init__(out self, *, other: Self):
        """Copy constructor — deep-copies the address buffer."""
        self.family = other.family
        self.addr = List[UInt8](copy=other.addr)
        self.port = other.port

    def __init__(out self, *, deinit take: Self):
        """Move constructor — transfers ownership of the address buffer."""
        self.family = take.family
        self.addr = take.addr^
        self.port = take.port

    def __eq__(self, other: Self) -> Bool:
        """Byte-exact equality across family, addr, port."""
        if self.family != other.family or self.port != other.port:
            return False
        if len(self.addr) != len(other.addr):
            return False
        for i in range(len(self.addr)):
            if self.addr[i] != other.addr[i]:
                return False
        return True

    @staticmethod
    def from_v4(a: UInt8, b: UInt8, c: UInt8, d: UInt8, port: UInt16) -> Self:
        """Build a PathKey from a 4-octet IPv4 address + port.

        The 4 octets occupy the last four bytes of the 16-byte buffer; the
        high 12 bytes are zero. Family is AF_INET (2).
        """
        var bytes = List[UInt8](capacity=16)
        for _ in range(12):
            bytes.append(UInt8(0))
        bytes.append(a)
        bytes.append(b)
        bytes.append(c)
        bytes.append(d)
        return Self(Int32(2), bytes^, port)


# ── PathChallenge — a PATH_CHALLENGE in flight ────────────────────────────────


struct PathChallenge(Copyable, Movable):
    """A PATH_CHALLENGE in flight: target address + 8-byte token + anti-amp.

    Per RFC 9000 §8.1 the anti-amp budget is per-path (not per-conn);
    each pending challenge tracks its own bytes_received / bytes_sent.
    """

    var token: List[UInt8]       # exactly 8 random bytes
    var target: PathKey          # address being validated
    var sent_at_ns: UInt64       # monotonic timestamp the challenge was queued
    var attempts: UInt8          # PATH_CHALLENGE retransmits (≤ MAX_CHALLENGE_ATTEMPTS)
    var bytes_received: Int64    # post-AEAD UDP datagram bytes from this path
    var bytes_sent: Int64        # bytes the server has sent on this path

    def __init__(
        out self,
        var token: List[UInt8],
        var target: PathKey,
        sent_at_ns: UInt64,
    ):
        """Construct a fresh pending challenge.

        attempts starts at 1 (this constructor records the initial send);
        the byte counters start at 0.
        """
        self.token = token^
        self.target = target^
        self.sent_at_ns = sent_at_ns
        self.attempts = UInt8(1)
        self.bytes_received = Int64(0)
        self.bytes_sent = Int64(0)

    def __init__(out self, *, other: Self):
        """Copy constructor — deep-copies the token + target buffers."""
        self.token = List[UInt8](copy=other.token)
        self.target = PathKey(other=other.target)
        self.sent_at_ns = other.sent_at_ns
        self.attempts = other.attempts
        self.bytes_received = other.bytes_received
        self.bytes_sent = other.bytes_sent

    def __init__(out self, *, deinit take: Self):
        """Move constructor — transfers token + target ownership."""
        self.token = take.token^
        self.target = take.target^
        self.sent_at_ns = take.sent_at_ns
        self.attempts = take.attempts
        self.bytes_received = take.bytes_received
        self.bytes_sent = take.bytes_sent


# ── ValidatedPath — a successfully validated peer path ────────────────────────


struct ValidatedPath(Copyable, Movable):
    """A path that has passed PATH_RESPONSE validation.

    Recorded for the lifetime of the connection's "currently validated"
    path; replaced when a new path validates per RFC 9000 §9.
    """

    var addr: PathKey
    var validated_at_ns: UInt64

    def __init__(out self, var addr: PathKey, validated_at_ns: UInt64):
        """Construct from validated address + timestamp."""
        self.addr = addr^
        self.validated_at_ns = validated_at_ns

    def __init__(out self, *, other: Self):
        """Copy constructor — deep-copies the address."""
        self.addr = PathKey(other=other.addr)
        self.validated_at_ns = other.validated_at_ns

    def __init__(out self, *, deinit take: Self):
        """Move constructor — transfers the address."""
        self.addr = take.addr^
        self.validated_at_ns = take.validated_at_ns


# ── PathValidator — per-connection path validation state machine ──────────────


struct PathValidator(Movable):
    """RFC 9000 §8 + §9 path validation state machine for one connection.

    Holds the current validated path + a list of in-flight PATH_CHALLENGEs.
    Per-path anti-amplification accounting lives on each PathChallenge.
    Pure data-structure: no I/O, no socket access — the caller emits
    frames and supplies "now" timestamps.
    """

    var current: Optional[ValidatedPath]      # active validated path (or None)
    var pending: List[PathChallenge]          # challenges in flight

    def __init__(out self):
        """Start with no validated path and no pending challenges."""
        self.current = Optional[ValidatedPath](None)
        self.pending = List[PathChallenge]()

    def __init__(out self, *, deinit take: Self):
        """Move constructor — transfers ownership of current + pending."""
        self.current = take.current^
        self.pending = take.pending^

    def start_challenge(
        mut self,
        var target: PathKey,
        now_ns: UInt64,
    ) raises -> List[UInt8]:
        """Generate an 8-byte random token, queue a PathChallenge, return the token.

        Returns the 8-byte token so the caller can wrap it in a
        PATH_CHALLENGE frame and emit it. The token is drawn from
        getrandom(2) — same primitive used by CidManager.generate_cid.
        """
        var buf = _pv_alloc[UInt8](PATH_TOKEN_LEN).as_any_origin()
        _ = external_call["getrandom", Int](buf, UInt64(PATH_TOKEN_LEN), UInt32(0))
        var token = List[UInt8](capacity=PATH_TOKEN_LEN)
        for i in range(PATH_TOKEN_LEN):
            token.append(buf[i])
        buf.free()
        var token_copy = List[UInt8](copy=token)
        var chal = PathChallenge(token_copy^, target^, now_ns)
        self.pending.append(chal^)
        return token^

    def on_response(
        mut self,
        token: Span[UInt8, _],
        from_addr: PathKey,
        now_ns: UInt64,
    ) -> Optional[ValidatedPath]:
        """Process incoming PATH_RESPONSE; validate on token + addr match.

        Per RFC 9000 §8.2 the response MUST come from the same address
        the challenge targeted, AND the 8-byte token MUST match a pending
        challenge's token byte-for-byte. On match, the challenge is
        removed from the pending list and the path becomes current.
        Returns the now-validated path on success, None otherwise.
        """
        var match_idx: Int = -1
        for i in range(len(self.pending)):
            var p_target = PathKey(other=self.pending[i].target)
            if not (p_target == from_addr):
                continue
            if len(self.pending[i].token) != len(token):
                continue
            var eq = True
            for k in range(len(self.pending[i].token)):
                if self.pending[i].token[k] != token[k]:
                    eq = False
                    break
            if eq:
                match_idx = i
                break
        if match_idx < 0:
            return Optional[ValidatedPath](None)
        # Pop the matched challenge; preserve order of the rest.
        var matched_target = PathKey(other=self.pending[match_idx].target)
        var new_pending = List[PathChallenge]()
        for j in range(len(self.pending)):
            if j != match_idx:
                new_pending.append(PathChallenge(other=self.pending[j]))
        self.pending = new_pending^
        var vp = ValidatedPath(matched_target^, now_ns)
        var vp_copy = ValidatedPath(other=vp)
        self.current = Optional[ValidatedPath](vp_copy^)
        return Optional[ValidatedPath](vp^)

    def record_sent_bytes(mut self, target: PathKey, n: Int):
        """Add `n` to the bytes_sent counter for the pending challenge targeting `target`.

        Callers MUST only invoke this for traffic emitted on a still-pending
        (unvalidated) path; traffic on the validated path is not anti-amp
        constrained and is not tracked here.
        """
        for i in range(len(self.pending)):
            var t = PathKey(other=self.pending[i].target)
            if t == target:
                self.pending[i].bytes_sent += Int64(n)
                return
        # No pending challenge for `target` — caller used the wrong target;
        # silently ignore (the validated path has no per-path budget).

    def record_received_bytes(mut self, target: PathKey, n: Int):
        """Add `n` to the bytes_received counter for the pending challenge targeting `target`.

        See record_sent_bytes — same constraints; called by the receive
        site whenever a UDP datagram arrives from an unvalidated path.
        """
        for i in range(len(self.pending)):
            var t = PathKey(other=self.pending[i].target)
            if t == target:
                self.pending[i].bytes_received += Int64(n)
                return

    def can_send_bytes(self, target: PathKey, n: Int) -> Bool:
        """Anti-amp gate per RFC 9000 §8.1.

        Returns True iff the server may transmit `n` more bytes on the
        unvalidated path identified by `target`. Budget is
        ANTI_AMP_FACTOR × bytes_received − bytes_sent; emission is refused
        once the remaining budget drops below `n`.

        If no pending challenge matches `target`, the path is either
        already validated (no gate) or unknown to the validator (caller
        is responsible for starting a challenge first); returns True.
        """
        for i in range(len(self.pending)):
            var t = PathKey(other=self.pending[i].target)
            if t == target:
                var budget = (
                    ANTI_AMP_FACTOR * self.pending[i].bytes_received
                    - self.pending[i].bytes_sent
                )
                return Int64(n) <= budget
        return True

    def gc_expired(mut self, now_ns: UInt64, pto_ns: UInt64):
        """Drop pending challenges older than 3 × PTO (RFC 9000 §8.2.1).

        Called by the connection event loop on each tick; expired
        challenges abandon the candidate path and free their slot in
        the pending list.
        """
        var threshold = pto_ns * UInt64(3)
        var kept = List[PathChallenge]()
        for i in range(len(self.pending)):
            var age = now_ns - self.pending[i].sent_at_ns
            if age < threshold:
                kept.append(PathChallenge(other=self.pending[i]))
        self.pending = kept^
