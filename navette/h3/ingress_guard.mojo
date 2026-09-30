"""The H3 server's door: what to do with a datagram before any connection state exists.

Every decision here is taken on raw header bytes, before connection
lookup side effects, crypto or allocation (the only work is the one
stateless reply a datagram may earn, written into the preallocated
`out`). The server supplies each GRO segment on its own and the clock;
it acts on the verdict. Counters use the `ProtectionStats` names.
"""

from std.collections import InlineArray, Span

from navette.protect.config import ProtectionStats
from navette.protect.token_bucket import TokenBucket
from navette.quic.error import CONNECTION_REFUSED, INVALID_TOKEN
from navette.quic.packet import MAX_TOKEN_LEN, MIN_INITIAL_PACKET_SIZE
from navette.quic.packet_protect import PacketProtect
from navette.quic.retry import (
    RETRY_TOKEN_LIFETIME_US,
    RETRY_TOKEN_MAX_LEN,
    TOKEN_INVALID,
    TOKEN_NONE,
    RetryTokenScratch,
    classify_retry_token,
    generate_retry_token,
    retry_addr_hash,
)
from navette.quic.stateless import (
    RETRY_SCID_LEN,
    build_retry,
    build_stateless_close_initial,
    build_version_negotiation,
)
from navette.tls.lib import SharedLibrary
from navette.util.secure_random import fill_random

comptime PRE_PASS: Int = 0
comptime PRE_DROP: Int = 1
comptime PRE_VN: Int = 2

# `admit_initial` verdicts. CREATE: open an unvalidated connection.
# CREATE_VALIDATED: open one whose address a Retry token proved. RETRY and
# CLOSE: send `out` (a Retry, or an INVALID_TOKEN / CONNECTION_REFUSED
# close) and keep no state. DROP: nothing.
comptime ADMIT_CREATE: Int = 0
comptime ADMIT_CREATE_VALIDATED: Int = 1
comptime ADMIT_RETRY: Int = 2
comptime ADMIT_CLOSE: Int = 3
comptime ADMIT_DROP: Int = 4

comptime UNVALIDATED_RETRY_THRESHOLD: Int = 256

# Stateless replies per receive pass, and the egress backlog (datagrams)
# at which they are dropped instead of queued.
comptime STATELESS_PER_PASS: Int = 256
comptime EGRESS_DROP_AT: Int = 1280
# A stateless reply is at most a Retry or a close (< 200 B) or a VN
# echoing two 255-byte CIDs (525 B); 1,252 covers every case.
comptime STATELESS_OUT_CAP: Int = 1252

comptime _QUIC_V1: UInt32 = 1
comptime _MAX_V1_CID_LEN: Int = 20
comptime _MIN_NEW_DCID_LEN: Int = 8
# Short header: first byte and our 8-byte CID.
comptime _MIN_SHORT_LEN: Int = 9
# Long header: first byte, version, DCID length.
comptime _MIN_LONG_LEN: Int = 6


@always_inline
def _version(seg: Span[Byte, _]) -> UInt32:
    """Bytes 1..4, big-endian; the caller checked `len(seg) >= 5`."""
    return (
        (UInt32(seg[1]) << 24) | (UInt32(seg[2]) << 16) | (UInt32(seg[3]) << 8) | UInt32(seg[4])
    )


@always_inline
def _is_initial(first: UInt8) -> Bool:
    """Long header with packet type bits 00 (QUIC v1)."""
    return (first & 0x80) != 0 and (first & 0x30) == 0


struct IngressGuard(Movable):
    """Pre-state checks, Version Negotiation, Initial admission and the stateless-reply budget for one H3 server.

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
    # After ADMIT_CREATE*: the `orig_dcid` and `retry_scid` arguments of
    # `QuicConnection.server` (`retry_scid` empty when no Retry was sent).
    var orig_dcid: List[Byte]
    var retry_scid: List[Byte]
    # An optional extension point: the embedding application may demand
    # address validation for every new connection.
    var require_validation: Bool
    var unvalidated_retry_threshold: Int
    var _lib: SharedLibrary
    var _secret: InlineArray[UInt8, 16]
    var _scratch: RetryTokenScratch
    var _token: List[Byte]
    var _close_protect: PacketProtect
    var _server_scid: InlineArray[UInt8, RETRY_SCID_LEN]
    var _vn_bucket: TokenBucket
    var _close_bucket: TokenBucket
    var _responses: Int

    def __init__(out self, lib: SharedLibrary) raises:
        """Raises only if the kernel CSPRNG fails to supply the token secret."""
        self.stats = ProtectionStats()
        self.out = List[Byte](capacity=STATELESS_OUT_CAP)
        self.orig_dcid = List[Byte](capacity=_MAX_V1_CID_LEN)
        self.retry_scid = List[Byte](capacity=_MAX_V1_CID_LEN)
        self.require_validation = False
        self.unvalidated_retry_threshold = UNVALIDATED_RETRY_THRESHOLD
        self._lib = SharedLibrary(copy=lib)
        self._secret = InlineArray[UInt8, 16](fill=UInt8(0))
        fill_random(Span(self._secret))
        self._scratch = RetryTokenScratch()
        self._token = List[Byte](capacity=RETRY_TOKEN_MAX_LEN)
        self._close_protect = PacketProtect(lib)
        self._server_scid = InlineArray[UInt8, RETRY_SCID_LEN](fill=UInt8(0))
        self._vn_bucket = TokenBucket(rate_per_s=100, burst=4)
        self._close_bucket = TokenBucket(rate_per_s=500, burst=16)
        self._responses = 0

    def begin_pass(mut self):
        """Start a receive pass: the per-pass reply budget refills."""
        self._responses = 0

    def precheck(mut self, seg: Span[Byte, _]) -> Int:
        """Verdict on one datagram (or GRO segment) before demux; counts every drop.

        PRE_DROP: undecodable (truncated header, version 0, a v1 DCID over
        20 bytes, a v1 packet with the fixed bit 0: RFC 9000 Section 17.2
        and 17.3 allow discarding it, and we never negotiate greasing it)
        or a v1 Initial under 1,200 bytes (RFC 9000 Section
        14.1), or an unknown version under 1,200 bytes (never answered, so
        a VN cannot amplify). PRE_VN: an unknown version at full size,
        answer with `answer_vn`. PRE_PASS: go on to demux.
        """
        var n = len(seg)
        if n == 0:
            self.stats.dropped_undecodable += 1
            return PRE_DROP
        var first = seg[0]
        if (first & 0x80) == 0:
            if n < _MIN_SHORT_LEN or (first & 0x40) == 0:
                self.stats.dropped_undecodable += 1
                return PRE_DROP
            return PRE_PASS
        if n < _MIN_LONG_LEN:
            self.stats.dropped_undecodable += 1
            return PRE_DROP
        var version = _version(seg)
        if version == 0:
            # A client never sends Version Negotiation.
            self.stats.dropped_undecodable += 1
            return PRE_DROP
        if version != _QUIC_V1:
            if n < MIN_INITIAL_PACKET_SIZE:
                self.stats.dropped_vn_small += 1
                return PRE_DROP
            return PRE_VN
        var dcid_len = Int(seg[5])
        if (first & 0x40) == 0 or dcid_len > _MAX_V1_CID_LEN or n < _MIN_LONG_LEN + dcid_len:
            self.stats.dropped_undecodable += 1
            return PRE_DROP
        if _is_initial(first) and n < MIN_INITIAL_PACKET_SIZE:
            self.stats.dropped_initial_size += 1
            return PRE_DROP
        return PRE_PASS

    def unknown_dcid(mut self, pkt: Span[Byte, _]) -> Int:
        """Verdict on a `precheck`-passed packet whose DCID matched no connection.

        Only a v1 Initial with a DCID of 8 to 20 bytes may open a
        connection (RFC 9000 Section 7.2); everything else is dropped:
        a stateless reset is not sent.
        """
        if not _is_initial(pkt[0]):
            self.stats.dropped_unknown_dcid += 1
            return PRE_DROP
        var dcid_len = Int(pkt[5])
        if dcid_len < _MIN_NEW_DCID_LEN or dcid_len > _MAX_V1_CID_LEN:
            self.stats.dropped_initial_dcid_len += 1
            return PRE_DROP
        return PRE_PASS

    def answer_vn(mut self, pkt: Span[Byte, _], now_us: UInt64, backlog: Int) raises -> Bool:
        """Build a Version Negotiation reply to a PRE_VN packet into `out`; False if paced or egress-bound.

        Paced at 100/s, burst 4 (RFC 9000 Section 5.2.2 lets a server
        limit VN). `pkt` is at least 1,200 bytes, so both 255-byte-max
        CIDs of RFC 8999 lie inside it. `backlog` is the server's queued
        egress datagrams.
        """
        if not self._room(backlog):
            return False
        if not self._vn_bucket.take(now_us):
            self.stats.stateless_bucket_empty_vn += 1
            return False
        var dcid_len = Int(pkt[5])
        var scid_at = _MIN_LONG_LEN + dcid_len
        if len(pkt) <= scid_at or len(pkt) < scid_at + 1 + Int(pkt[scid_at]):
            self.stats.dropped_undecodable += 1
            return False
        var scid_len = Int(pkt[scid_at])
        var ro = pkt.as_imm()
        build_version_negotiation(
            self.out, ro[_MIN_LONG_LEN:scid_at], ro[scid_at + 1 : scid_at + 1 + scid_len]
        )
        self.stats.vn_sent += 1
        self._responses += 1
        return True

    def admit_initial(
        mut self,
        pkt: Span[Byte, _],
        peer_name: Span[Byte, _],
        now_us: UInt64,
        unvalidated: Int,
        admitted: Int,
        conn_cap: Int,
        free_ids: Int,
        backlog: Int,
    ) raises -> Int:
        """Admission verdict (ADMIT_*) for an Initial that passed `precheck` and `unknown_dcid`.

        `peer_name` is the sender's raw sockaddr; `unvalidated` counts
        handshaking connections whose address is not validated yet,
        `admitted` all connections, `free_ids` connection ids left.
        Order: a token that opens under our secret but fails address
        validation gets INVALID_TOKEN (RFC 9000 Section 8.1.3); no usable
        token gets a Retry when `unvalidated` reached the threshold, the
        application requires validation, the server is at `conn_cap`, or
        the token is too long for the connection's header parser, else an
        unvalidated connection; a valid token gets a validated connection,
        or CONNECTION_REFUSED with no id free. Retry is never paced (a
        bucket would deny it to honest clients in proportion to a flood);
        closes share a 500/s bucket. Raises only on an FFI failure.
        """
        # Header: first byte, version, DCID, SCID, token length and token.
        var n = len(pkt)
        var dcid_len = Int(pkt[5])
        var scid_at = _MIN_LONG_LEN + dcid_len
        if scid_at >= n or Int(pkt[scid_at]) > _MAX_V1_CID_LEN:
            self.stats.dropped_undecodable += 1
            return ADMIT_DROP
        var scid_len = Int(pkt[scid_at])
        var tl_at = scid_at + 1 + scid_len
        if tl_at >= n:
            self.stats.dropped_undecodable += 1
            return ADMIT_DROP
        var tl_size = 1 << Int(pkt[tl_at] >> 6)
        if tl_at + tl_size > n:
            self.stats.dropped_undecodable += 1
            return ADMIT_DROP
        var token_len = UInt64(pkt[tl_at] & 0x3F)
        for i in range(1, tl_size):
            token_len = (token_len << 8) | UInt64(pkt[tl_at + i])
        var token_at = tl_at + tl_size
        if token_len > UInt64(n - token_at):
            self.stats.dropped_undecodable += 1
            return ADMIT_DROP
        var ro = pkt.as_imm()
        var dcid = ro[_MIN_LONG_LEN:scid_at]
        var scid = ro[scid_at + 1 : tl_at]
        var token = ro[token_at : token_at + Int(token_len)]

        var addr_hash = retry_addr_hash(peer_name)
        var usable = UInt8(0)
        for i in range(32):
            usable |= addr_hash[i]
        if usable == 0:
            # No parsable IP in the sockaddr: nothing to bind a token to.
            return ADMIT_DROP

        self.orig_dcid.clear()
        self.retry_scid.clear()
        var force_retry = len(token) > MAX_TOKEN_LEN
        var class_ = TOKEN_NONE
        if len(token) > 0 and not force_retry:
            class_ = classify_retry_token(
                self.orig_dcid, self._lib, self._scratch, Span(self._secret),
                token, Span(addr_hash), now_us, RETRY_TOKEN_LIFETIME_US,
            )
        if class_ == TOKEN_INVALID:
            self.stats.tokens_invalid += 1
            return self._close(dcid, scid, INVALID_TOKEN, now_us, backlog)
        if class_ == TOKEN_NONE:
            self.stats.tokens_none += 1
            if (
                force_retry
                or unvalidated >= self.unvalidated_retry_threshold
                or self.require_validation
                or admitted >= conn_cap
            ):
                return self._retry(dcid, scid, Span(addr_hash), now_us, backlog)
            self.orig_dcid.extend(dcid)
            return ADMIT_CREATE
        self.stats.tokens_valid += 1
        if free_ids <= 0:
            self.stats.cap_rejections += 1
            return self._close(dcid, scid, CONNECTION_REFUSED, now_us, backlog)
        # Our Retry's SCID became the client's DCID (RFC 9000 Section 7.3).
        self.retry_scid.extend(dcid)
        return ADMIT_CREATE_VALIDATED

    def _retry(
        mut self,
        dcid: Span[Byte, _],
        scid: Span[Byte, _],
        addr_hash: Span[Byte, _],
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
                self._token, self._lib, self._scratch, Span(self._secret), dcid, addr_hash, now_us
            )
        except:
            return ADMIT_DROP
        build_retry(self.out, self._lib, dcid, scid, Span(self._server_scid), Span(self._token))
        self.stats.retry_sent += 1
        self._responses += 1
        return ADMIT_RETRY

    def _close(
        mut self, dcid: Span[Byte, _], scid: Span[Byte, _], code: UInt64, now_us: UInt64, backlog: Int
    ) raises -> Int:
        """Build one stateless CONNECTION_CLOSE with `code` (RFC 9000 Section 10.2); ADMIT_DROP if paced or bounded out."""
        if not self._room(backlog):
            return ADMIT_DROP
        if not self._close_bucket.take(now_us):
            self.stats.stateless_bucket_empty_close += 1
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
        return ADMIT_CLOSE

    def _room(mut self, backlog: Int) -> Bool:
        """Whether one more stateless reply fits this pass and the egress backlog; counts the refusal."""
        if self._responses < STATELESS_PER_PASS and backlog < EGRESS_DROP_AT:
            return True
        self.stats.stateless_dropped_egress += 1
        return False
