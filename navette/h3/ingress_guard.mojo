"""The H3 server's door: what to do with an Initial that matched no connection.

Every decision here is taken on header bytes, before any connection
state, crypto or allocation (the only work is the one stateless reply a
datagram may earn, written into the preallocated `out`). The server
supplies the clock and acts on the verdict. Counters use the
`ProtectionStats` names.
"""

from std.collections import InlineArray, Span

from navette.protect.config import ProtectionStats
from navette.quic.error import CONNECTION_REFUSED, INVALID_TOKEN
from navette.quic.packet import MIN_INITIAL_PACKET_SIZE, PacketHeader, parse_packet_header
from navette.quic.packet_protect import PacketProtect
from navette.quic.retry import (
    RETRY_TOKEN_LIFETIME_US,
    RETRY_TOKEN_MAX_LEN,
    TOKEN_INVALID,
    TOKEN_NONE,
    RetryTokenScratch,
    classify_retry_token,
    generate_retry_token,
)
from navette.quic.stateless import RETRY_SCID_LEN, build_retry, build_stateless_close_initial
from navette.tls.lib import SharedLibrary
from navette.util.secure_random import fill_random

# `admit_initial` verdicts. CREATE: open a connection (its address is
# validated when `retry_scid` is set). REPLY: send `out` (a Retry, or an
# INVALID_TOKEN / CONNECTION_REFUSED close) and keep no state. DROP: nothing.
comptime ADMIT_CREATE: Int = 0
comptime ADMIT_REPLY: Int = 1
comptime ADMIT_DROP: Int = 2

comptime UNVALIDATED_RETRY_THRESHOLD: Int = 256

# Stateless replies per receive pass, and the egress backlog (datagrams)
# at which they are dropped instead of queued. A stateless close is
# smaller than the Initial that earns it and a Retry is bounded by
# admission, so these bounds are all the pacing they need.
comptime STATELESS_PER_PASS: Int = 256
comptime EGRESS_DROP_AT: Int = 1280
# A Retry or a close is under 200 bytes.
comptime STATELESS_OUT_CAP: Int = 256

comptime _MAX_V1_CID_LEN: Int = 20
comptime _MIN_NEW_DCID_LEN: Int = 8


struct IngressGuard(Movable):
    """Initial admission and the stateless-reply budget for one H3 server.

    Owns the Retry token secret (16 random bytes, per server and per
    process: tokens do not survive a restart) and every scratch buffer
    the stateless paths use, so they allocate nothing. `out` holds the
    last stateless reply built and `orig_dcid` / `retry_scid` the last
    admission's connection parameters; each is valid until the next call
    that sets it, so the server acts on it at once. At most
    `STATELESS_PER_PASS` replies are built between `begin_pass` calls,
    and none while the egress backlog is at `EGRESS_DROP_AT`.
    """

    var stats: ProtectionStats
    var out: List[Byte]
    # After ADMIT_CREATE: the `orig_dcid` and `retry_scid` arguments of
    # `QuicConnection.server` (`retry_scid` empty when no Retry was sent).
    var orig_dcid: List[Byte]
    var retry_scid: List[Byte]
    var unvalidated_retry_threshold: Int
    var _lib: SharedLibrary
    var _secret: InlineArray[UInt8, 16]
    var _scratch: RetryTokenScratch
    var _token: List[Byte]
    var _close_protect: PacketProtect
    var _server_scid: InlineArray[UInt8, RETRY_SCID_LEN]
    var _responses: Int

    def __init__(out self, lib: SharedLibrary) raises:
        """Raises only if the kernel CSPRNG fails to supply the token secret."""
        self.stats = ProtectionStats()
        self.out = List[Byte](capacity=STATELESS_OUT_CAP)
        self.orig_dcid = List[Byte](capacity=_MAX_V1_CID_LEN)
        self.retry_scid = List[Byte](capacity=_MAX_V1_CID_LEN)
        self.unvalidated_retry_threshold = UNVALIDATED_RETRY_THRESHOLD
        self._lib = SharedLibrary(copy=lib)
        self._secret = InlineArray[UInt8, 16](fill=UInt8(0))
        fill_random(Span(self._secret))
        self._scratch = RetryTokenScratch()
        self._token = List[Byte](capacity=RETRY_TOKEN_MAX_LEN)
        self._close_protect = PacketProtect(lib)
        self._server_scid = InlineArray[UInt8, RETRY_SCID_LEN](fill=UInt8(0))
        self._responses = 0

    def begin_pass(mut self):
        """Start a receive pass: the per-pass reply budget refills."""
        self._responses = 0

    def admit_initial(
        mut self,
        pkt: Span[Byte, _],
        peer_name: Span[Byte, _],
        now_us: UInt64,
        unvalidated: Int,
        admitted: Int,
        conn_cap: Int,
        backlog: Int,
    ) raises -> Int:
        """Admission verdict (ADMIT_*) for a datagram whose DCID matched no connection.

        Only a v1 Initial of at least 1,200 bytes (RFC 9000 Section 14.1)
        with an 8-20 byte DCID (Section 7.2) may open a connection;
        anything else is dropped (no stateless reset, no Version
        Negotiation). `peer_name` is the sender's raw sockaddr;
        `unvalidated` counts connections whose address is not validated
        yet, `admitted` all of them. Order: a token that opens under our
        secret but fails address validation gets INVALID_TOKEN (RFC 9000
        Section 8.1.3); no usable token gets a Retry when `unvalidated`
        reached the threshold or the server is at `conn_cap`, else an
        unvalidated connection; a valid token gets a validated
        connection, or CONNECTION_REFUSED at the cap. Raises only on an
        FFI failure.
        """
        # Long header, fixed bit, type Initial; then version 1.
        if len(pkt) < 6 or (pkt[0] & 0xF0) != 0xC0 or (pkt[1] | pkt[2] | pkt[3]) != 0 or pkt[4] != 1:
            self.stats.dropped_unknown_dcid += 1
            return ADMIT_DROP
        if len(pkt) < MIN_INITIAL_PACKET_SIZE:
            self.stats.dropped_initial_size += 1
            return ADMIT_DROP
        if Int(pkt[5]) < _MIN_NEW_DCID_LEN or Int(pkt[5]) > _MAX_V1_CID_LEN:
            self.stats.dropped_initial_dcid_len += 1
            return ADMIT_DROP
        var parsed: Tuple[PacketHeader, Int]
        try:
            parsed = parse_packet_header(pkt.as_imm(), 0)
        except:
            self.stats.dropped_undecodable += 1
            return ADMIT_DROP
        ref header = parsed[0]
        var dcid = header.dcid.as_span()
        var scid = header.scid.as_span()
        var token = header.token_span()

        self.orig_dcid.clear()
        self.retry_scid.clear()
        var class_ = TOKEN_NONE
        if len(token) > 0:
            class_ = classify_retry_token(
                self.orig_dcid, self._lib, self._scratch, Span(self._secret),
                token, peer_name, now_us, RETRY_TOKEN_LIFETIME_US,
            )
        if class_ == TOKEN_INVALID:
            self.stats.tokens_invalid += 1
            return self._close(dcid, scid, INVALID_TOKEN, backlog)
        if class_ == TOKEN_NONE:
            self.stats.tokens_none += 1
            if (
                unvalidated >= self.unvalidated_retry_threshold
                or admitted >= conn_cap
            ):
                return self._retry(dcid, scid, peer_name, now_us, backlog)
            self.orig_dcid.extend(dcid)
            return ADMIT_CREATE
        self.stats.tokens_valid += 1
        if admitted >= conn_cap:
            self.stats.cap_rejections += 1
            return self._close(dcid, scid, CONNECTION_REFUSED, backlog)
        # Our Retry's SCID became the client's DCID (RFC 9000 Section 7.3).
        self.retry_scid.extend(dcid)
        return ADMIT_CREATE

    def _retry(
        mut self,
        dcid: Span[Byte, _],
        scid: Span[Byte, _],
        peer_name: Span[Byte, _],
        now_us: UInt64,
        backlog: Int,
    ) raises -> Int:
        """Build a Retry with a fresh SCID and a token binding `dcid` to the sender; ADMIT_DROP if bounded out."""
        if not self._room(backlog):
            return ADMIT_DROP
        fill_random(Span(self._server_scid))
        self._token.clear()
        try:
            generate_retry_token(
                self._token, self._lib, self._scratch, Span(self._secret), dcid, peer_name, now_us
            )
        except:
            return ADMIT_DROP
        build_retry(self.out, self._lib, dcid, scid, Span(self._server_scid), Span(self._token))
        self.stats.retry_sent += 1
        self._responses += 1
        return ADMIT_REPLY

    def _close(mut self, dcid: Span[Byte, _], scid: Span[Byte, _], code: UInt64, backlog: Int) raises -> Int:
        """Build one stateless CONNECTION_CLOSE with `code` (RFC 9000 Section 10.2); ADMIT_DROP if bounded out."""
        if not self._room(backlog):
            return ADMIT_DROP
        fill_random(Span(self._server_scid))
        build_stateless_close_initial(
            self.out, self._close_protect, dcid, scid, Span(self._server_scid), code
        )
        if code == INVALID_TOKEN:
            self.stats.invalid_token_closes += 1
        else:
            self.stats.refused_closes += 1
        self._responses += 1
        return ADMIT_REPLY

    def _room(mut self, backlog: Int) -> Bool:
        """Whether one more stateless reply fits this pass and the egress backlog; counts the refusal."""
        if self._responses < STATELESS_PER_PASS and backlog < EGRESS_DROP_AT:
            return True
        self.stats.stateless_dropped_egress += 1
        return False
