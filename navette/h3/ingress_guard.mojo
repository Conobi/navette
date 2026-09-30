"""The H3 server's door: what to do with a datagram before any connection state exists.

Every decision here is taken on raw header bytes, before connection
lookup side effects, crypto or allocation (the only work is the one
stateless reply a datagram may earn, written into the preallocated
`out`). The server supplies each GRO segment on its own and the clock;
it acts on the verdict. Counters use the `ProtectionStats` names.
"""

from std.collections import Span

from navette.protect.config import ProtectionStats
from navette.protect.token_bucket import TokenBucket
from navette.quic.packet import MIN_INITIAL_PACKET_SIZE
from navette.quic.stateless import build_version_negotiation
from navette.tls.lib import SharedLibrary

comptime PRE_PASS: Int = 0
comptime PRE_DROP: Int = 1
comptime PRE_VN: Int = 2

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
    """Pre-state checks, Version Negotiation and the stateless-reply budget for one H3 server.

    `out` holds the last stateless reply built; it is valid until the
    next call that builds one, so the server hands it off at once. At
    most `STATELESS_PER_PASS` replies are built between `begin_pass`
    calls, and none while the egress backlog is at `EGRESS_DROP_AT`.
    """

    var stats: ProtectionStats
    var out: List[Byte]
    var _lib: SharedLibrary
    var _vn_bucket: TokenBucket
    var _responses: Int

    def __init__(out self, lib: SharedLibrary):
        self.stats = ProtectionStats()
        self.out = List[Byte](capacity=STATELESS_OUT_CAP)
        self._lib = SharedLibrary(copy=lib)
        self._vn_bucket = TokenBucket(rate_per_s=100, burst=4)
        self._responses = 0

    def begin_pass(mut self):
        """Start a receive pass: the per-pass reply budget refills."""
        self._responses = 0

    def precheck(mut self, seg: Span[Byte, _]) -> Int:
        """Verdict on one datagram (or GRO segment) before demux; counts every drop.

        PRE_DROP: undecodable (truncated header, version 0, a v1 DCID over
        20 bytes) or a v1 Initial under 1,200 bytes (RFC 9000 Section
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
            if n < _MIN_SHORT_LEN:
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
        if dcid_len > _MAX_V1_CID_LEN or n < _MIN_LONG_LEN + dcid_len:
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
        var ro = pkt.get_immutable()
        build_version_negotiation(
            self.out, ro[_MIN_LONG_LEN:scid_at], ro[scid_at + 1 : scid_at + 1 + scid_len]
        )
        self.stats.vn_sent += 1
        self._responses += 1
        return True

    def _room(mut self, backlog: Int) -> Bool:
        """Whether one more stateless reply fits this pass and the egress backlog; counts the refusal."""
        if self._responses < STATELESS_PER_PASS and backlog < EGRESS_DROP_AT:
            return True
        self.stats.stateless_dropped_egress += 1
        return False
