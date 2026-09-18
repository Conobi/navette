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
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _pv_alloc
from navette.quic.frame import Frame


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
    var addr: InlineArray[UInt8, 16]
    var port: UInt16

    def __init__(out self, family: Int32, var addr: InlineArray[UInt8, 16], port: UInt16):
        """Construct from explicit family + 16-byte addr + port."""
        self.family = family
        self.addr = addr^
        self.port = port

    def __init__(out self, *, copy: Self):
        """Copy constructor."""
        self.family = copy.family
        self.addr = InlineArray[UInt8, 16](copy=copy.addr)
        self.port = copy.port

    def __init__(out self, *, deinit move: Self):
        self.family = move.family
        self.addr = move.addr^
        self.port = move.port

    def __eq__(self, other: Self) -> Bool:
        """Byte-exact equality across family, addr, port."""
        if self.family != other.family or self.port != other.port:
            return False
        for i in range(16):
            if self.addr[i] != other.addr[i]:
                return False
        return True

    @staticmethod
    def zero() -> Self:
        """Build a sentinel PathKey with family=0 and zero address+port.

        Used as the initial value for `QuicConnection.peer_addr` /
        `_current_recv_addr` before the bench server has observed any
        traffic; equality against any real peer 4-tuple (family=AF_INET
        or AF_INET6 — both nonzero) is always False, so the first packet
        seen always triggers the address-change branch unless the caller
        has already promoted the validated path.
        """
        return Self(Int32(0), InlineArray[UInt8, 16](fill=Byte(0)), UInt16(0))

    @staticmethod
    def from_v4(a: UInt8, b: UInt8, c: UInt8, d: UInt8, port: UInt16) -> Self:
        """Build a PathKey from a 4-octet IPv4 address + port.

        The 4 octets occupy the last four bytes of the 16-byte buffer; the
        high 12 bytes are zero. Family is AF_INET (2).
        """
        var buf = InlineArray[UInt8, 16](fill=Byte(0))
        buf[12] = a
        buf[13] = b
        buf[14] = c
        buf[15] = d
        return Self(Int32(2), buf^, port)


# ── PathChallenge — a PATH_CHALLENGE in flight ────────────────────────────────


struct PathChallenge(Copyable, Movable):
    """A PATH_CHALLENGE in flight: target address + 8-byte token + anti-amp.

    Per RFC 9000 §8.1 the anti-amp budget is per-path (not per-conn);
    each pending challenge tracks its own bytes_received / bytes_sent.
    """

    var token: List[Byte]       # exactly 8 random bytes
    var target: PathKey          # address being validated
    var sent_at_ns: UInt64       # monotonic timestamp the challenge was queued
    var attempts: UInt8          # PATH_CHALLENGE retransmits (≤ MAX_CHALLENGE_ATTEMPTS)
    var bytes_received: Int64    # post-AEAD UDP datagram bytes from this path
    var bytes_sent: Int64        # bytes the server has sent on this path

    def __init__(
        out self,
        var token: List[Byte],
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

    def __init__(out self, *, copy: Self):
        """Copy constructor — deep-copies the token + target buffers."""
        self.token = List[Byte](copy=copy.token)
        self.target = PathKey(copy=copy.target)
        self.sent_at_ns = copy.sent_at_ns
        self.attempts = copy.attempts
        self.bytes_received = copy.bytes_received
        self.bytes_sent = copy.bytes_sent

    def __init__(out self, *, deinit move: Self):
        """Move constructor — transfers token + target ownership."""
        self.token = move.token^
        self.target = move.target^
        self.sent_at_ns = move.sent_at_ns
        self.attempts = move.attempts
        self.bytes_received = move.bytes_received
        self.bytes_sent = move.bytes_sent


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

    def __init__(out self, *, copy: Self):
        """Copy constructor — deep-copies the address."""
        self.addr = PathKey(copy=copy.addr)
        self.validated_at_ns = copy.validated_at_ns

    def __init__(out self, *, deinit move: Self):
        """Move constructor — transfers the address."""
        self.addr = move.addr^
        self.validated_at_ns = move.validated_at_ns


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

    def __init__(out self, *, deinit move: Self):
        """Move constructor — transfers ownership of current + pending."""
        self.current = move.current^
        self.pending = move.pending^

    def start_challenge(
        mut self,
        var target: PathKey,
        now_ns: UInt64,
    ) raises -> List[Byte]:
        """Generate an 8-byte random token, queue a PathChallenge, return the token.

        Returns the 8-byte token so the caller can wrap it in a
        PATH_CHALLENGE frame and emit it. The token is drawn from
        getrandom(2) — same primitive used by CidManager.generate_cid.
        """
        var buf = _pv_alloc[UInt8](PATH_TOKEN_LEN)
        _ = external_call["getrandom", Int](buf, UInt64(PATH_TOKEN_LEN), UInt32(0))
        var token = List[Byte](capacity=PATH_TOKEN_LEN)
        for i in range(PATH_TOKEN_LEN):
            token.append(buf[unsafe_offset=i])
        buf.unsafe_free()
        var token_copy = List[Byte](copy=token)
        var chal = PathChallenge(token_copy^, target^, now_ns)
        self.pending.append(chal^)
        return token^

    def on_response(
        mut self,
        token: Span[Byte, _],
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
            var p_target = PathKey(copy=self.pending[i].target)
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
        var matched_target = PathKey(copy=self.pending[match_idx].target)
        var new_pending = List[PathChallenge]()
        for j in range(len(self.pending)):
            if j != match_idx:
                new_pending.append(PathChallenge(copy=self.pending[j]))
        self.pending = new_pending^
        var vp = ValidatedPath(matched_target^, now_ns)
        var vp_copy = ValidatedPath(copy=vp)
        self.current = Optional[ValidatedPath](vp_copy^)
        return Optional[ValidatedPath](vp^)

    def record_sent_bytes(mut self, target: PathKey, n: Int):
        """Add `n` to the bytes_sent counter for the pending challenge targeting `target`.

        Callers MUST only invoke this for traffic emitted on a still-pending
        (unvalidated) path; traffic on the validated path is not anti-amp
        constrained and is not tracked here.
        """
        for i in range(len(self.pending)):
            var t = PathKey(copy=self.pending[i].target)
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
            var t = PathKey(copy=self.pending[i].target)
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
        for ref entry in self.pending:
            var t = PathKey(copy=entry.target)
            if t == target:
                var budget = (
                    ANTI_AMP_FACTOR * entry.bytes_received
                    - entry.bytes_sent
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
        for ref entry in self.pending:
            var age = now_ns - entry.sent_at_ns
            if age < threshold:
                kept.append(PathChallenge(copy=entry))
        self.pending = kept^


# ── PathState ──────────────────────────────────────────────────────────


@fieldwise_init
struct PathState(Movable):
    """Per-connection path validation and address tracking state."""

    var validator: PathValidator
    var pending_responses: List[List[Byte]]
    var peer_addr: PathKey
    var current_recv_addr: PathKey

    def on_challenge_received(mut self, data: Span[Byte, _]):
        """Stash an 8-byte PATH_CHALLENGE token for echo as PATH_RESPONSE."""
        var copy = List[Byte](capacity=len(data))
        for ref byte in data:
            copy.append(byte)
        self.pending_responses.append(copy^)

    def emit_response_frames(mut self) raises -> List[Frame]:
        """Drain pending PATH_RESPONSE frames."""
        var out = List[Frame]()
        for ref resp in self.pending_responses:
            var data = List[Byte](copy=resp)
            out.append(Frame.path_response(data^))
        self.pending_responses = List[List[Byte]]()
        return out^

    def emit_challenge_frames(mut self) raises -> List[Frame]:
        """Build PATH_CHALLENGE frames for every pending challenge."""
        var out = List[Frame]()
        for ref chal in self.validator.pending:
            var token = List[Byte](copy=chal.token)
            out.append(Frame.path_challenge(token^))
        return out^

    def begin_challenge(mut self, var target: PathKey, now: UInt64) raises:
        """Begin path validation for `target`."""
        _ = self.validator.start_challenge(target^, now)

    def has_pending_challenge(self, target: PathKey) -> Bool:
        """True iff a challenge for `target` is already pending."""
        for ref chal in self.validator.pending:
            var t = PathKey(copy=chal.target)
            if t == target:
                return True
        return False

    def stamp_recv_addr(mut self, var addr: PathKey):
        """Set the per-receive source-address cursor before feeding a datagram."""
        self.current_recv_addr = addr^

    def seed_peer_addr(mut self, var addr: PathKey):
        """Seed peer_addr to the first observed source address."""
        self.peer_addr = addr^

    def can_send(self, target: PathKey, n_bytes: Int) -> Bool:
        """Anti-amp gate for outbound traffic to `target`."""
        return self.validator.can_send_bytes(target, n_bytes)

    def record_send(mut self, target: PathKey, n_bytes: Int):
        """Credit `n_bytes` to the per-path bytes_sent counter for `target`."""
        self.validator.record_sent_bytes(target, n_bytes)
