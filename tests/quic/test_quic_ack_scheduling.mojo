# tests/quic/test_quic_ack_scheduling.mojo
#
# ACK scheduling, PTO, CLOSE and per-packet budget contracts of
# QuicConnection.send()/timeout()/_check_timers(), exercised with two
# in-process connections and a scripted clock. Each test is named after the
# requirement it pins.

from std.collections import Optional
from std.collections import Span

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import (
    QuicConnection, QuicEvent, SentStreamFrame, SSF_STREAM,
    CONN_ADDR_VALIDATED, CONN_ESTABLISHED, CONN_CLOSING, CONN_HANDSHAKING,
    MAX_DATAGRAM_SIZE, MAX_CLOSE_REASON_BYTES,
)
from navette.quic.frame import Frame
from navette.quic.pn_space import SentPacket, EncryptionLevel, PacketNumberSpace
from navette.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_false, assert_equal_int, load_test_cert, load_test_ca


# ── Helpers ──────────────────────────────────────────────────────────────


def _default_params() -> TransportParams:
    var params = default_transport_params()
    params.max_idle_timeout = UInt64(30_000)
    params.initial_max_data = UInt64(4_194_304)
    params.initial_max_stream_data_bidi_local = UInt64(262_144)
    params.initial_max_stream_data_bidi_remote = UInt64(262_144)
    params.initial_max_streams_bidi = UInt64(100)
    return params^


struct _Rng:
    """Xorshift64 for deterministic randomized properties."""
    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed if seed != 0 else UInt64(0x9E3779B97F4A7C15)

    def next(mut self) -> UInt64:
        self.s ^= self.s << 13
        self.s ^= self.s >> 7
        self.s ^= self.s << 17
        return self.s

    def below(mut self, n: Int) -> Int:
        return Int(self.next() % UInt64(n))


def _deliver(mut src: QuicConnection, mut dst: QuicConnection, now: UInt64) raises -> Int:
    """One send() on src fed to dst; returns the number of datagrams moved."""
    var dgs = src.send(now)
    for i in range(len(dgs)):
        assert_true(len(dgs[i]) <= MAX_DATAGRAM_SIZE, "datagram exceeds budget")
        try:
            dst.recv(Span(dgs[i]), now)
        except:
            pass
    return len(dgs)


def _drain_to(mut src: QuicConnection, mut dst: QuicConnection, now: UInt64) raises -> Int:
    """Call send() on src until empty (cap 64), each datagram fed to dst."""
    var total = 0
    for _ in range(64):
        var n = _deliver(src, dst, now)
        if n == 0:
            break
        total += n
    return total


def _establish(mut client: QuicConnection, mut server: QuicConnection, mut now: UInt64) raises -> UInt64:
    """Drive the handshake to completion and settle both sides (no ACK owed)."""
    var established = False
    for _ in range(40):
        now += UInt64(10_000)
        _ = _drain_to(client, server, now)
        _ = _drain_to(server, client, now)
        if client.is_established() and server.is_established():
            established = True
            break
    assert_true(established, "handshake did not complete")
    now = _settle(client, server, now)
    return now


def _settle(mut client: QuicConnection, mut server: QuicConnection, mut now: UInt64) raises -> UInt64:
    """Exchange until both sides return empty from send() at the same instant."""
    for _ in range(12):
        now += UInt64(30_000)
        var a = _drain_to(client, server, now)
        var b = _drain_to(server, client, now)
        if a == 0 and b == 0:
            break
    _drain_events(client)
    _drain_events(server)
    return now


def _warm_ae(mut client: QuicConnection, mut server: QuicConnection, sid: UInt64, mut now: UInt64) raises -> UInt64:
    """One ack-eliciting client packet, acknowledged by the server's delayed
    ACK, so the next client packet's PN is contiguous with the last
    ack-eliciting one (otherwise the out-of-order rule acks it at once)."""
    var d = _bytes(3)
    client.send_stream_data(sid, Span(d), False)
    now += UInt64(1_000)
    _ = _deliver(client, server, now)
    now += UInt64(26_000)
    _ = _drain_to(server, client, now)
    assert_false(server.spaces[2].has_unacked_ack_eliciting(), "warm-up acknowledged")
    return now


def _client_with_handshake_keys(mut p: _Pair, mut now: UInt64) raises -> UInt64:
    """Deliver the whole ClientHello, then server datagrams one at a time
    until the client holds Handshake keys (the ML-KEM ServerHello itself
    spans two datagrams); flush whatever the client then owes."""
    now += UInt64(10_000)
    _ = _drain_to(p.client, p.server, now)
    for _ in range(8):
        var s = p.server.send(now)
        assert_true(len(s) > 0, "server keeps emitting its flight")
        try:
            p.client.recv(Span(s[0]), now)
        except:
            pass
        if p.client.protect.has_keys(1):
            break
    assert_true(p.client.protect.has_keys(1), "client holds Handshake keys")
    # Flush what the client owes without delivering it: the server must keep
    # its Handshake keys so it can still decrypt what the tests send next.
    now += UInt64(1_000)
    for _ in range(8):
        if len(p.client.send(now)) == 0:
            break
    return now


def _drain_events(mut conn: QuicConnection):
    while True:
        var ev = conn.poll()
        if not ev:
            break


def _last_sent_pn(conn: QuicConnection, space: Int) -> Int:
    var best = -1
    for entry in conn.spaces[space].sent_packets.items():
        if entry.key > best:
            best = entry.key
    return best


def _frames_of(conn: QuicConnection, space: Int, pn: Int) raises -> List[Frame]:
    if pn not in conn.spaces[space].sent_packets:
        raise "no sent record for pn " + String(pn)
    return List[Frame](copy=conn.spaces[space].sent_packets[pn].frames)


def _has_kind(frames: List[Frame], kind: String) -> Bool:
    for i in range(len(frames)):
        if kind == "ack" and frames[i].is_ack():
            return True
        if kind == "stream" and frames[i].is_stream():
            return True
        if kind == "ping" and frames[i].is_ping():
            return True
        if kind == "close" and frames[i].is_connection_close():
            return True
        if kind == "crypto" and frames[i].is_crypto():
            return True
    return False


def _pn_has_stream_data(conn: QuicConnection, pn: Int) raises -> Bool:
    """Check app_frames_sent for STREAM records at a given PN.

    Since the direct-write optimization, STREAM frames bypass the Frame
    struct and are tracked in app_frames_sent, not SentPacket.frames.
    """
    if pn not in conn.app_frames_sent:
        return False
    for i in range(len(conn.app_frames_sent[pn])):
        if conn.app_frames_sent[pn][i].kind == SSF_STREAM:
            return True
    return False


def _bytes(n: Int, seed: UInt8 = UInt8(0x41)) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8((Int(seed) + i) & 0xFF))
    return out^


def _open_gate(mut conn: QuicConnection):
    """Force the congestion gate open: huge cwnd, pacer off."""
    conn.recovery.cc.cubic._cwnd_value = UInt64(1 << 30)
    conn.recovery.pacer.enabled = False


struct _Pair:
    """A client/server pair sharing one TLS backend."""
    var tls: TlsBackend
    var client: QuicConnection
    var server: QuicConnection

    def __init__(
        out self,
        client_params: TransportParams,
        server_params: TransportParams,
        now: UInt64,
    ) raises:
        self.tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert_bytes = ck[0].copy()
        var key_bytes = ck[1].copy()
        var ca_bytes = load_test_ca()
        var server_config = QuicServerConfig(self.tls.shared(), Span(cert_bytes), Span(key_bytes))
        var client_config = QuicClientConfig.with_ca(self.tls.shared(), Span(ca_bytes))
        self.client = QuicConnection.client(
            self.tls.shared(), client_config, "localhost", client_params, now,
        )
        var orig_dcid = List[UInt8](copy=self.client.initial_dcid)
        var client_dcid = List[UInt8](copy=self.client.initial_dcid)
        self.server = QuicConnection.server(
            self.tls.shared(), server_config, server_params,
            Span(orig_dcid), Span(client_dcid), now,
        )

    def __init__(out self, *, deinit move: Self):
        self.tls = move.tls^
        self.client = move.client^
        self.server = move.server^


# ── Tests ────────────────────────────────────────────────────────────────


def test_ack_bundled_on_send() raises:
    """`ack-bundled-on-send`: the first response packet carries the ACK of the
    lone request packet even though ack_needed is false."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)

    var sid = p.client.open_stream(True)
    now = _warm_ae(p.client, p.server, sid, now)
    var req = _bytes(40)
    p.client.send_stream_data(sid, Span(req), True)
    now += UInt64(1_000)
    var n = _deliver(p.client, p.server, now)
    assert_equal_int(n, 1, "one request datagram")
    var req_pn = _last_sent_pn(p.client, 2)
    assert_false(p.server.spaces[2].ack_needed, "a lone 1-RTT packet does not owe an ACK yet")
    assert_true(Bool(p.server.spaces[2].ack_deadline), "delayed-ACK deadline armed")

    _drain_events(p.server)
    var resp = _bytes(50)
    p.server.send_stream_data(UInt64(sid), Span(resp), True)
    now += UInt64(500)
    var dgs = p.server.send(now)
    assert_equal_int(len(dgs), 1, "one response datagram")
    var resp_pn = _last_sent_pn(p.server, 2)
    # ACK is direct-written into the payload, not stored in frames.
    # Verify ACK was committed via side-effect checks below.
    assert_true(_pn_has_stream_data(p.server, resp_pn), "response packet carries STREAM")
    assert_false(p.server.spaces[2].has_unacked_ack_eliciting(), "bundled ACK cleared the count")
    assert_false(Bool(p.server.spaces[2].ack_deadline), "bundled ACK cleared the deadline")
    p.client.recv(Span(dgs[0]), now)
    assert_true(req_pn not in p.client.spaces[2].sent_packets, "request PN acknowledged by the first response packet")
    print("  test_ack_bundled_on_send: PASS")


def test_ack_within_max_ack_delay() raises:
    """`ack-within-max-ack-delay`: over 1000 random Application-space arrival
    patterns, every ack-eliciting packet is either acknowledged at once or
    covered by a deadline no later than max_ack_delay after its receipt; and
    at the connection level the deadline is reported by timeout() and the
    ACK leaves on the send() at that deadline."""
    var rng = _Rng(UInt64(0xACE5))
    var mad = UInt64(25_000)
    for _ in range(1000):
        var space = PacketNumberSpace(EncryptionLevel.application())
        var t = UInt64(rng.below(1_000_000))
        var next_pn = 0
        for _ in range(1 + rng.below(6)):
            t += UInt64(rng.below(20_000))
            var pn = next_pn
            var r = rng.below(10)
            if r == 0 and next_pn > 0:
                pn = next_pn - 1        # reorder below largest
            elif r == 1:
                pn = next_pn + 2        # gap
            var ae = rng.below(4) != 0
            space.on_packet_received(UInt64(pn), ae, t, mad)
            if pn >= next_pn:
                next_pn = pn + 1
            if ae:
                if not space.ack_needed:
                    assert_true(Bool(space.ack_deadline), "ack-eliciting packet without ack_needed must arm a deadline")
                    assert_true(space.ack_deadline.value() <= t + mad, "deadline within max_ack_delay of receipt")
            # A receiver that sends at/after the deadline (what _check_timers
            # does) commits an ACK covering everything received so far.
            if space.ack_deadline and space.ack_deadline.value() <= t:
                space.ack_needed = True
                space.ack_deadline = None
            if space.ack_needed:
                var f = space.peek_ack_frame(t, UInt64(3))
                assert_true(Bool(f), "ACK owed must peek a frame")
                assert_true(Int(f.value().largest_ack) == space.largest_recv_pn, "ACK covers the largest PN")
                space.mark_ack_sent()

    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)
    var sid = p.client.open_stream(True)
    now = _warm_ae(p.client, p.server, sid, now)
    var data = _bytes(10)
    p.client.send_stream_data(sid, Span(data), False)
    now += UInt64(1_000)
    _ = _deliver(p.client, p.server, now)
    var pn = _last_sent_pn(p.client, 2)
    var deadline = p.server.timeout(now)
    assert_true(Bool(deadline), "server reports a deadline")
    assert_true(deadline.value() == now + mad, "ack deadline = receipt + max_ack_delay")
    assert_equal_int(len(p.server.send(now + UInt64(1))), 0, "nothing owed before the deadline")
    now = deadline.value()
    var dgs = p.server.send(now)
    assert_equal_int(len(dgs), 1, "ACK leaves at the deadline")
    var frames = _frames_of(p.server, 2, _last_sent_pn(p.server, 2))
    # ACK is direct-written into the payload; frames list is empty for
    # an ACK-only packet.
    assert_equal_int(len(frames), 0, "ACK-only packet has no tracked frames")
    p.client.recv(Span(dgs[0]), now)
    assert_true(pn not in p.client.spaces[2].sent_packets, "packet acknowledged")
    print("  test_ack_within_max_ack_delay: PASS")


def test_ack_only_bypasses_cc() raises:
    """`ack-only-bypasses-cc`: with the congestion gate closed the owed ACK
    still leaves, alone, recorded not in flight and consuming no builder
    state; once the gate opens the data follows."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)

    # Two ack-eliciting packets -> server owes an immediate ACK.
    var sid = p.client.open_stream(True)
    for _ in range(2):
        var d = _bytes(5)
        p.client.send_stream_data(sid, Span(d), False)
        now += UInt64(500)
        _ = _deliver(p.client, p.server, now)
    assert_true(p.server.spaces[2].ack_needed, "threshold reached")

    # Server has data waiting and a closed gate.
    _drain_events(p.server)
    var resp = _bytes(300)
    p.server.send_stream_data(UInt64(sid), Span(resp), False)
    p.server.recovery.cc.cubic._cwnd_value = UInt64(2400)
    p.server.recovery.bytes_in_flight = UInt64(2400)
    p.server.recovery.pacer.enabled = False
    var bif_before = p.server.recovery.bytes_in_flight
    now += UInt64(100)
    var dgs = p.server.send(now)
    assert_equal_int(len(dgs), 1, "ACK-only datagram despite closed gate")
    var pn = _last_sent_pn(p.server, 2)
    var frames = _frames_of(p.server, 2, pn)
    # ACK is direct-written into the payload, not in frames.
    assert_equal_int(len(frames), 0, "ACK-only packet has no tracked frames")
    assert_false(p.server.spaces[2].sent_packets[pn].in_flight, "ACK-only packet not in flight")
    assert_false(p.server.spaces[2].sent_packets[pn].ack_eliciting, "ACK-only packet not ack-eliciting")
    assert_true(p.server.recovery.bytes_in_flight == bif_before, "bytes_in_flight untouched")
    assert_false(Bool(p.server.spaces[2].time_of_last_ae_sent) and p.server.spaces[2].time_of_last_ae_sent.value() == now,
                 "ACK-only send does not re-arm the PTO base")
    assert_true(len(p.server.stream_map.sendable_set) == 1, "stream data still queued (builders did not run)")
    assert_equal_int(len(p.server.send(now)), 0, "gate closed: nothing more to send")

    p.server.recovery.bytes_in_flight = UInt64(0)
    now += UInt64(100)
    dgs = p.server.send(now)
    assert_equal_int(len(dgs), 1, "data leaves once the gate opens")
    frames = _frames_of(p.server, 2, _last_sent_pn(p.server, 2))
    assert_true(_pn_has_stream_data(p.server, _last_sent_pn(p.server, 2)), "STREAM emitted after the gate opened")
    print("  test_ack_only_bypasses_cc: PASS")


def _assert_no_past_deadline(conn: QuicConnection, now: UInt64, label: String) raises:
    var t = conn.timeout(now)
    if not t:
        return
    if conn.is_closed():
        return  # idle/close/drain expiry in this call: reaped by the caller
    assert_true(t.value() > now, label + ": deadline " + String(t.value()) + " <= now " + String(now))


def test_no_past_deadline_after_send() raises:
    """`no-past-deadline-after-send`: over random operation sequences (data,
    time jumps, deliveries, local close, packets after close, draining) the
    deadline reported right after send(now) is None or strictly > now."""
    var rng = _Rng(UInt64(0x5EED)
    )
    for round in range(6):
        var now = UInt64(1_000_000)
        var p = _Pair(_default_params(), _default_params(), now)
        now = _establish(p.client, p.server, now)
        var sid = p.client.open_stream(True)
        var ssid = p.server.open_stream(True)
        var closed_at = -1
        for step in range(120):
            var op = rng.below(10)
            if op < 3:
                var d = _bytes(1 + rng.below(1500))
                try:
                    p.client.send_stream_data(sid, Span(d), False)
                except:
                    pass
            elif op == 3:
                var d = _bytes(1 + rng.below(1500))
                try:
                    p.server.send_stream_data(ssid, Span(d), False)
                except:
                    pass
            elif op == 4:
                now += UInt64(rng.below(400_000))
            elif op == 5 and closed_at < 0 and step > 20:
                p.client.close_transport(UInt64(0), String("bye"), now)
                closed_at = step
            elif op == 6:
                # PTO-scale jump so probes and close timers fire.
                now += UInt64(rng.below(2_000_000))
            now += UInt64(rng.below(5_000))
            # Client sends (possibly its CLOSE) and the server receives.
            var cd = p.client.send(now)
            _assert_no_past_deadline(p.client, now, "client after send")
            for i in range(len(cd)):
                try:
                    p.server.recv(Span(cd[i]), now)
                except:
                    pass
            var sd = p.server.send(now)
            _assert_no_past_deadline(p.server, now, "server after send")
            for i in range(len(sd)):
                if rng.below(3) == 0:
                    continue  # random loss
                try:
                    p.client.recv(Span(sd[i]), now)
                except:
                    pass
            # A second send at the same instant must also leave no past deadline.
            _ = p.client.send(now)
            _assert_no_past_deadline(p.client, now, "client after 2nd send")
            _ = p.server.send(now)
            _assert_no_past_deadline(p.server, now, "server after 2nd send")
            if p.client.is_closed() and p.server.is_closed():
                break
        _ = round
    print("  test_no_past_deadline_after_send: PASS")


def test_pto_armed_only_with_ae_in_flight() raises:
    """`pto-armed-only-with-ae-in-flight`: an idle established server has no
    PTO deadline and emits nothing across ten PTO intervals; an
    amplification-limited server with its CRYPTO flight outstanding reports
    only its idle deadline and sends nothing."""
    var now = UInt64(1_000_000)
    var no_idle = _default_params()
    no_idle.max_idle_timeout = UInt64(0)
    var p = _Pair(no_idle, no_idle, now)
    now = _establish(p.client, p.server, now)
    assert_false(p.server.spaces[2].has_ack_eliciting_in_flight(), "settled: nothing in flight")
    assert_false(Bool(p.server.timeout(now)), "idle server reports no deadline")
    var pings = 0
    for _ in range(10):
        now += p.server._pto_interval() + UInt64(1)
        var dgs = p.server.send(now)
        assert_equal_int(len(dgs), 0, "idle server sends nothing on PTO intervals")
        assert_false(Bool(p.server.timeout(now)), "still no deadline")
        for entry in p.server.spaces[2].sent_packets.items():
            if _has_kind(entry.value.frames, "ping"):
                pings += 1
    assert_equal_int(pings, 0, "no PING probes from an idle server")
    assert_equal_int(p.server.recovery.pto_count, 0, "pto_count never incremented")

    # Amplification-limited server: one client Initial, its flight in flight.
    var now2 = UInt64(5_000_000)
    var q = _Pair(_default_params(), _default_params(), now2)
    now2 += UInt64(10_000)
    _ = _drain_to(q.client, q.server, now2)          # whole ClientHello
    var sent = _drain_to(q.server, q.client, now2)   # client never answers below
    assert_true(sent >= 1, "server emitted its first flight")
    assert_true((q.server.state & CONN_ADDR_VALIDATED) == 0, "server still amplification-limited")
    var idle_deadline = q.server.idle_timer + UInt64(30_000_000)
    for _ in range(10):
        now2 += q.server._pto_interval() + UInt64(1)
        assert_equal_int(len(q.server.send(now2)), 0, "amp-limited server sends nothing more")
        var t = q.server.timeout(now2)
        assert_true(Bool(t) and t.value() == idle_deadline, "only the idle deadline is reported")
    assert_equal_int(q.server.recovery.pto_count, 0, "no PTO fired while amplification-limited")
    print("  test_pto_armed_only_with_ae_in_flight: PASS")


def _ping_record(pn: UInt64, t: UInt64) -> SentPacket:
    var frames = List[Frame]()
    frames.append(Frame.ping())
    return SentPacket(pn=pn, time_sent=t, ack_eliciting=True, in_flight=True, size=40, frames=frames)


def test_pto_fires_once_per_expiry() raises:
    """`pto-fires-once-per-expiry`: several keyed spaces expiring in the same
    call raise pto_count once, all get probe_pending, none is reported by
    timeout() until its probe is sent, and the probes go out in one datagram."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _client_with_handshake_keys(p, now)
    var keyed = List[Int]()
    for s in range(3):
        if p.client.protect.has_keys(s):
            keyed.append(s)
    assert_true(len(keyed) >= 2, "at least two keyed spaces")
    # Construct: one ack-eliciting packet outstanding in each keyed space.
    for i in range(len(keyed)):
        var s = keyed[i]
        var pn = p.client.spaces[s].alloc_pn()
        p.client.spaces[s].on_packet_sent(_ping_record(pn, now))
    var base = p.client.recovery.pto_count
    var latest = now
    for i in range(len(keyed)):
        var d = p.client._pto_deadline(keyed[i])
        assert_true(Bool(d), "space armed")
        if d.value() + UInt64(1) > latest:
            latest = d.value() + UInt64(1)
    now = latest
    p.client._check_timers(now)
    assert_equal_int(p.client.recovery.pto_count, base + 1, "pto_count incremented exactly once")
    for i in range(len(keyed)):
        assert_true(p.client.spaces[keyed[i]].probe_pending, "probe pending in every keyed space")
        assert_false(Bool(p.client._pto_deadline(keyed[i])), "pending probe reports no PTO term")
    var again = p.client.recovery.pto_count
    p.client._check_timers(now)
    assert_equal_int(p.client.recovery.pto_count, again, "a pending space is not re-fired")
    var dgs = p.client.send(now)
    assert_equal_int(len(dgs), 1, "probes coalesce into one datagram")
    for i in range(len(keyed)):
        assert_false(p.client.spaces[keyed[i]].probe_pending, "probe delivered")
        var d = p.client._pto_deadline(keyed[i])
        assert_true(Bool(d) and d.value() > now, "re-armed from the probe commit")
    print("  test_pto_fires_once_per_expiry: PASS")


def test_pto_probe_emits_ping() raises:
    """`pto-probe-emits-ping`: a Handshake-space PTO with no CRYPTO to re-queue
    yields a PING packet that the peer decrypts (exercising the long-header
    4-byte plaintext minimum)."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _client_with_handshake_keys(p, now)
    assert_false(p.client.crypto_streams[1].has_unsent(), "no Handshake CRYPTO staged")
    # Construct "Handshake PTO with no CRYPTO to re-queue": forget the
    # Finished packet the flush recorded, leave only a PING-only record.
    var old = List[Int]()
    for entry in p.client.spaces[1].sent_packets.items():
        old.append(entry.key)
    for i in range(len(old)):
        _ = p.client.spaces[1].forget_sent(old[i])
    var pn = p.client.spaces[1].alloc_pn()
    p.client.spaces[1].on_packet_sent(_ping_record(pn, now))
    var d = p.client._pto_deadline(1)
    assert_true(Bool(d), "Handshake PTO armed")
    now = d.value() + UInt64(1)
    var before = p.server.spaces[1].largest_recv_pn
    var dgs = p.client.send(now)
    assert_equal_int(len(dgs), 1, "probe datagram emitted")
    assert_equal_int(len(dgs[0]), MAX_DATAGRAM_SIZE, "client handshake datagram padded to 1200")
    var probe_pn = _last_sent_pn(p.client, 1)
    var frames = _frames_of(p.client, 1, probe_pn)
    assert_true(_has_kind(frames, "ping"), "probe packet carries PING")
    assert_true(p.client.spaces[1].sent_packets[probe_pn].ack_eliciting, "probe is ack-eliciting")
    assert_true(p.client.spaces[1].sent_packets[probe_pn].in_flight, "probe is in flight")
    p.server.recv(Span(dgs[0]), now)
    assert_true(p.server.spaces[1].largest_recv_pn > before, "peer decrypted the Handshake probe")
    print("  test_pto_probe_emits_ping: PASS")


def test_close_sent_once_per_trigger() raises:
    """`close-sent-once-per-trigger`: one CLOSE datagram on close_transport,
    then empty; one more per peer datagram at most once per PTO."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)
    _open_gate(p.server)
    var ssid = p.server.open_stream(True)

    now += UInt64(1_000)
    p.client.close_transport(UInt64(0), String("done"), now)
    var dgs = p.client.send(now)
    assert_equal_int(len(dgs), 1, "exactly one CLOSE datagram on transition")
    assert_true(_has_kind(_frames_of(p.client, 2, _last_sent_pn(p.client, 2)), "close"), "it carries CONNECTION_CLOSE")
    assert_equal_int(len(p.client.send(now)), 0, "second send is empty")
    assert_equal_int(len(p.client.send(now + UInt64(1_000))), 0, "still empty without a trigger")

    # Ten peer datagrams within one PTO: at most one CLOSE.
    var chunk = _bytes(1200)
    for _ in range(10):
        p.server.send_stream_data(ssid, Span(chunk), False)
    var closes = 0
    for _ in range(10):
        now += UInt64(100)
        var sd = p.server.send(now)
        assert_equal_int(len(sd), 1, "server emits one datagram per send")
        p.client.recv(Span(sd[0]), now)
        closes += len(p.client.send(now))
    assert_true(closes <= 1, "at most one CLOSE per PTO; got " + String(closes))

    # After a PTO, one more peer datagram re-owes exactly one CLOSE.
    now += p.client._pto_interval() + UInt64(1)
    p.server.send_stream_data(ssid, Span(chunk), False)
    var sd2 = p.server.send(now)
    assert_equal_int(len(sd2), 1, "server datagram after PTO")
    p.client.recv(Span(sd2[0]), now)
    assert_equal_int(len(p.client.send(now)), 1, "one CLOSE after a PTO-spaced trigger")
    assert_equal_int(len(p.client.send(now)), 0, "then empty again")
    print("  test_close_sent_once_per_trigger: PASS")


def test_close_reason_bounded() raises:
    """`close-reason-bounded`: a 2 kB reason yields one in-budget datagram whose
    reason is truncated to MAX_CLOSE_REASON_BYTES; a handshake-time close
    puts a CLOSE in both Initial and Handshake in one padded datagram."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)
    var reason = String("")
    for _ in range(2048):
        reason += "x"
    p.client.close_app(UInt64(0x0100), reason, now)
    assert_equal_int(len(p.client.close.pending.value().reason), MAX_CLOSE_REASON_BYTES, "reason truncated")
    var dgs = p.client.send(now)
    assert_equal_int(len(dgs), 1, "one datagram")
    assert_true(len(dgs[0]) <= MAX_DATAGRAM_SIZE, "within budget")
    assert_equal_int(len(p.client.send(now)), 0, "then empty")

    var now2 = UInt64(9_000_000)
    var q = _Pair(_default_params(), _default_params(), now2)
    now2 = _client_with_handshake_keys(q, now2)
    assert_false(q.client.is_established(), "not established yet")
    q.client.close_transport(UInt64(0x0A), String("early"), now2)
    var cds = q.client.send(now2)
    assert_equal_int(len(cds), 1, "one handshake-time CLOSE datagram")
    assert_equal_int(len(cds[0]), MAX_DATAGRAM_SIZE, "client handshake datagram padded to 1200")
    for s in range(3):
        if q.client.protect.has_keys(s):
            assert_true(_has_kind(_frames_of(q.client, s, _last_sent_pn(q.client, s)), "close"),
                        "CLOSE in keyed space " + String(s))
    assert_true(_has_kind(_frames_of(q.client, 1, _last_sent_pn(q.client, 1)), "close"), "CLOSE in Handshake")
    assert_equal_int(len(q.client.send(now2)), 0, "second send empty")
    q.server.recv(Span(cds[0]), now2)
    assert_true(q.server.is_draining(), "server entered draining on the handshake-time CLOSE")
    print("  test_close_reason_bounded: PASS")


def test_send_returns_empty_when_idle() raises:
    """`send-returns-empty-when-idle`: after a completed exchange both sides
    return empty twice; after close_transport one CLOSE then empty."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)
    var sid = p.client.open_stream(True)
    var req = _bytes(100)
    p.client.send_stream_data(sid, Span(req), True)
    now += UInt64(1_000)
    _ = _drain_to(p.client, p.server, now)
    _drain_events(p.server)
    var resp = _bytes(3000)
    p.server.send_stream_data(UInt64(sid), Span(resp), True)
    now = _settle(p.client, p.server, now)
    assert_equal_int(len(p.client.send(now)), 0, "client idle: empty")
    assert_equal_int(len(p.client.send(now)), 0, "client idle: empty again")
    assert_equal_int(len(p.server.send(now)), 0, "server idle: empty")
    assert_equal_int(len(p.server.send(now)), 0, "server idle: empty again")
    assert_false(p.client._space_has_other_sendable(2), "client predicate false when idle")
    assert_false(p.server._space_has_other_sendable(2), "server predicate false when idle")
    p.server.close_transport(UInt64(0), String("bye"), now)
    assert_equal_int(len(p.server.send(now)), 1, "one CLOSE datagram")
    assert_equal_int(len(p.server.send(now)), 0, "then empty")
    print("  test_send_returns_empty_when_idle: PASS")


def test_bundle_predicate_sound() raises:
    """`bundle-predicate-sound`: over random Application-space states with the
    gate forced open, `not _space_has_other_sendable(2)` implies the step-4
    builders produce no frame."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)
    _open_gate(p.server)
    var rng = _Rng(UInt64(0xB0B))
    var ssid = p.server.open_stream(True)
    var false_cases = 0
    for it in range(300):
        # Randomly perturb state.
        var k = rng.below(9)
        if k == 0:
            var d = _bytes(1 + rng.below(200))
            p.server.send_stream_data(ssid, Span(d), False)
        elif k == 1:
            p.server.stream_map.needs_max_data = True
        elif k == 2:
            p.server.stream_map.needs_max_streams_bidi = True
        elif k == 3:
            var d = _bytes(8)
            p.server.path.pending_responses.append(d^)
        elif k == 4:
            p.server.cid_mgr.requeue_retire(UInt64(rng.below(4)))
        elif k == 5:
            p.server.spaces[2].probe_pending = True
        elif k == 6:
            var d = _bytes(10)
            _ = p.server.send_datagram(Span(d))
        # k in {7, 8}: no change (exercises the idle case).
        var may = p.server._space_has_other_sendable(2)
        var frames = List[Frame]()
        var records = List[SentStreamFrame]()
        var stream_payload = List[UInt8]()
        p.server._build_frames_for_space(2, now, frames, records, stream_payload, 1100)
        if p.server.spaces[2].probe_pending and len(frames) == 0:
            frames.append(Frame.ping())
        if not may:
            false_cases += 1
            assert_equal_int(len(frames), 0, "predicate false but builders produced frames (iter " + String(it) + ")")
        # Consume whatever state the builders left so later iterations vary.
        p.server.spaces[2].probe_pending = False
        _ = p.server.send(now)
        now += UInt64(1_000)
    assert_true(false_cases > 20, "property must cover idle states; got " + String(false_cases))
    print("  test_bundle_predicate_sound: PASS")


def test_datagram_never_exceeds_budget() raises:
    """`datagram-never-exceeds-budget`: random mixes of STREAM data on 1-8
    streams, control frames, DATAGRAMs and ACK ranges never produce a
    datagram longer than MAX_DATAGRAM_SIZE."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)
    _open_gate(p.server)
    _open_gate(p.client)
    var rng = _Rng(UInt64(0xB0D6E7))
    var sids = List[UInt64]()
    for _ in range(8):
        sids.append(p.server.open_stream(True))
    var csid = p.client.open_stream(True)
    var total = 0
    for _ in range(120):
        var n_streams = 1 + rng.below(8)
        for i in range(n_streams):
            var d = _bytes(1 + rng.below(2500), UInt8(i))
            try:
                p.server.send_stream_data(sids[i], Span(d), rng.below(20) == 0)
            except:
                pass  # FIN already queued on this stream
        if rng.below(3) == 0:
            var d = _bytes(1 + rng.below(1100))
            _ = p.server.send_datagram(Span(d))
        if rng.below(4) == 0:
            p.server.stream_map.needs_max_data = True
        # Some client packets so the server has ACK ranges to carry.
        for _ in range(rng.below(4)):
            var d = _bytes(1 + rng.below(50))
            try:
                p.client.send_stream_data(csid, Span(d), False)
            except:
                pass
            now += UInt64(100)
            _ = _deliver(p.client, p.server, now)
        for _ in range(64):
            now += UInt64(200)
            var dgs = p.server.send(now)
            if len(dgs) == 0:
                break
            for i in range(len(dgs)):
                assert_true(len(dgs[i]) <= MAX_DATAGRAM_SIZE, "datagram of " + String(len(dgs[i])) + " bytes exceeds budget")
                total += 1
                try:
                    p.client.recv(Span(dgs[i]), now)
                except:
                    pass
        now += UInt64(1_000)
        _ = _drain_to(p.client, p.server, now)
    assert_true(total > 100, "property must emit many datagrams; got " + String(total))
    print("  test_datagram_never_exceeds_budget: PASS")


def test_crypto_split_lossless() raises:
    """`crypto-split-lossless`: a 3 kB CRYPTO requeue is emitted across three
    or more in-budget datagrams whose frames concatenate to the original
    bytes with contiguous offsets."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)
    _open_gate(p.server)
    var data = _bytes(3000, UInt8(7))
    p.server.crypto_streams[2].requeue(UInt64(0), Span(data))
    var dg_count = 0
    var pns = List[Int]()
    for _ in range(16):
        now += UInt64(1_000)
        var dgs = p.server.send(now)
        if len(dgs) == 0:
            break
        dg_count += len(dgs)
        assert_true(len(dgs[0]) <= MAX_DATAGRAM_SIZE, "within budget")
        pns.append(_last_sent_pn(p.server, 2))
    assert_true(dg_count >= 3, "at least three datagrams; got " + String(dg_count))
    var out = List[UInt8]()
    var expected_offset = UInt64(0)
    for i in range(len(pns)):
        var frames = _frames_of(p.server, 2, pns[i])
        for f in range(len(frames)):
            if frames[f].is_crypto():
                ref cf = frames[f].as_crypto()
                assert_true(cf.offset == expected_offset, "contiguous CRYPTO offsets")
                expected_offset += UInt64(len(cf.data))
                for j in range(len(cf.data)):
                    out.append(cf.data[j])
    assert_equal_int(len(out), 3000, "all bytes emitted exactly once")
    for i in range(3000):
        assert_true(out[i] == data[i], "byte " + String(i) + " preserved")
    assert_false(p.server.crypto_streams[2].has_unsent(), "nothing left unsent")
    print("  test_crypto_split_lossless: PASS")


def _fingerprint(conn: QuicConnection) -> String:
    var s = String(Int(conn.state)) + "/" + String(conn.recovery.pto_count)
    s += "/" + String(Int(conn.close.timer)) + "/" + String(Int(conn.close.drain_timer))
    for i in range(3):
        s += "/" + String(conn.spaces[i].ack_needed) + String(conn.spaces[i].probe_pending)
        s += String(Bool(conn.spaces[i].ack_deadline))
    return s


def test_pto_deadline_single_source() raises:
    """`pto-deadline-single-source`: whenever timeout(now) <= now, _check_timers(now)
    changes state (PTO, ack deadline, idle, close or drain), over random
    states of handshaking, established and closing connections."""
    var rng = _Rng(UInt64(0x51E)
    )
    var checks = 0
    for round in range(4):
        var now = UInt64(1_000_000)
        var p = _Pair(_default_params(), _default_params(), now)
        if round % 2 == 1:
            now = _establish(p.client, p.server, now)
        var sid = -1
        if p.client.is_established():
            sid = Int(p.client.open_stream(True))
        for step in range(150):
            var op = rng.below(6)
            if op == 0 and sid >= 0:
                var d = _bytes(1 + rng.below(300))
                p.client.send_stream_data(UInt64(sid), Span(d), False)
            elif op == 1:
                now += UInt64(rng.below(3_000_000))
            elif op == 2 and step == 100:
                p.client.close_transport(UInt64(0), String("x"), now)
            now += UInt64(rng.below(20_000))
            # Client side.
            var t = p.client.timeout(now)
            if t and t.value() <= now and not p.client.is_closed():
                var before = _fingerprint(p.client)
                p.client._check_timers(now)
                assert_true(_fingerprint(p.client) != before, "client: expired deadline must change state at step " + String(step))
                checks += 1
            var cd = p.client.send(now)
            for i in range(len(cd)):
                if rng.below(4) == 0:
                    continue
                try:
                    p.server.recv(Span(cd[i]), now)
                except:
                    pass
            # Server side.
            var ts = p.server.timeout(now)
            if ts and ts.value() <= now and not p.server.is_closed():
                var before_s = _fingerprint(p.server)
                p.server._check_timers(now)
                assert_true(_fingerprint(p.server) != before_s, "server: expired deadline must change state at step " + String(step))
                checks += 1
            var sd = p.server.send(now)
            for i in range(len(sd)):
                if rng.below(4) == 0:
                    continue
                try:
                    p.client.recv(Span(sd[i]), now)
                except:
                    pass
            if p.client.is_closed() and p.server.is_closed():
                break
    assert_true(checks > 10, "property must observe expired deadlines; got " + String(checks))
    print("  test_pto_deadline_single_source: PASS")


def test_pto_uses_peer_max_ack_delay() raises:
    """PTO = srtt + max(4·rttvar, 1 ms) + the PEER's max_ack_delay once the
    handshake is confirmed (RFC 9002 §6.2.1): peer 200 ms, local 25 ms."""
    var now = UInt64(1_000_000)
    var cp = _default_params()
    cp.max_ack_delay = UInt64(25)
    var sp = _default_params()
    sp.max_ack_delay = UInt64(200)
    var p = _Pair(cp, sp, now)
    now = _establish(p.client, p.server, now)
    assert_true(p.client.handshake_confirmed, "client confirmed")
    assert_true(p.client.peer_params.value().max_ack_delay == UInt64(200), "peer advertised 200 ms")
    var sid = p.client.open_stream(True)
    var d = _bytes(20)
    p.client.send_stream_data(sid, Span(d), False)
    now += UInt64(1_000)
    var dgs = p.client.send(now)
    assert_equal_int(len(dgs), 1, "one data packet")
    var expected = now + p.client.recovery.pto_timeout(UInt64(200_000))
    var t = p.client.timeout(now)
    assert_true(Bool(t) and t.value() == expected,
                "PTO deadline uses the peer's max_ack_delay; got " + String(t.value()) + " expected " + String(expected))
    assert_true(p.client._pto_interval() == p.client.recovery.pto_timeout(UInt64(200_000)), "_pto_interval matches")
    # Before confirmation (space 1) no max_ack_delay is added.
    assert_true(p.client._pto_interval(1) == p.client.recovery.pto_timeout(UInt64(0)), "Handshake-space PTO adds no max_ack_delay")
    print("  test_pto_uses_peer_max_ack_delay: PASS")


def _client_flight_checked(mut p: _Pair, now: UInt64, mut checked: Int, mut ack_only_seen: Bool) raises:
    """Drain the client to the server, asserting every pre-establishment
    datagram is exactly 1200 bytes and that a padded ACK-only packet is
    recorded in flight."""
    for _ in range(64):
        var was_established = p.client.is_established()
        var dgs = p.client.send(now)
        if len(dgs) == 0:
            break
        if not was_established:
            assert_equal_int(len(dgs[0]), MAX_DATAGRAM_SIZE, "client handshake datagram padded to 1200")
            checked += 1
            for s in range(2):
                var pn = _last_sent_pn(p.client, s)
                if pn >= 0 and pn in p.client.spaces[s].sent_packets:
                    ref rec = p.client.spaces[s].sent_packets[pn]
                    if rec.time_sent == now and not rec.ack_eliciting:
                        ack_only_seen = True
                        assert_true(rec.in_flight, "padded ACK-only packet is in flight")
        for i in range(len(dgs)):
            try:
                p.server.recv(Span(dgs[i]), now)
            except:
                pass


def test_client_pads_all_initial_datagrams() raises:
    """`client-pads-all-initial-datagrams`: every client datagram before
    establishment (Initial or Handshake present, including ACK-only) is
    exactly 1200 bytes; a padded ACK-only packet counts as in flight."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    var checked = 0
    var ack_only_seen = False
    for _ in range(40):
        now += UInt64(10_000)
        _client_flight_checked(p, now, checked, ack_only_seen)
        # Server flight one datagram at a time, the client answering each.
        for _ in range(64):
            var sd = p.server.send(now)
            if len(sd) == 0:
                break
            try:
                p.client.recv(Span(sd[0]), now)
            except:
                pass
            _client_flight_checked(p, now, checked, ack_only_seen)
        if p.client.is_established() and p.server.is_established():
            break
    assert_true(p.client.is_established(), "handshake completed")
    assert_true(checked >= 2, "several handshake datagrams checked")
    assert_true(ack_only_seen, "an ACK-only client packet was observed")
    print("  test_client_pads_all_initial_datagrams: PASS")


def test_server_pads_initial_datagrams() raises:
    """`server-pads-initial-datagrams` + `anti-amp-per-datagram` + step 1b: the
    server's first datagram (ack-eliciting Initial) is 1200 bytes; with an
    allowance below 1200 and the ServerHello unsent, no CRYPTO is consumed;
    once the allowance grows the flight resumes with contiguous offsets."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now += UInt64(10_000)
    _ = _drain_to(p.client, p.server, now)
    assert_true(p.server.crypto_streams[0].has_unsent(), "ServerHello staged")

    # Allowance 800: 3*300 - 100.
    var real_received = p.server.bytes_received
    p.server.bytes_received = UInt64(300)
    var dgs = p.server.send(now)
    if len(dgs) > 0:
        # Only an ACK-only Initial may leave; nothing ack-eliciting.
        assert_equal_int(len(dgs), 1, "at most one datagram")
        assert_true(len(dgs[0]) <= 800, "within the amplification allowance")
        var pn = _last_sent_pn(p.server, 0)
        assert_false(p.server.spaces[0].sent_packets[pn].ack_eliciting, "deferred Initial is not ack-eliciting")
        assert_false(_has_kind(_frames_of(p.server, 0, pn), "crypto"), "no CRYPTO consumed")
        assert_equal_int(_last_sent_pn(p.server, 1), -1, "no Handshake packet built while the ServerHello is deferred")
    assert_true(p.server.crypto_streams[0].has_unsent(), "ServerHello still unsent")
    assert_equal_int(len(p.server.send(now)), 0, "nothing more while short of allowance")

    p.server.bytes_received = real_received
    now += UInt64(1_000)
    var first = p.server.send(now)
    assert_equal_int(len(first), 1, "flight resumes")
    assert_equal_int(len(first[0]), MAX_DATAGRAM_SIZE, "ack-eliciting server Initial datagram padded to 1200")
    assert_true(_has_kind(_frames_of(p.server, 0, _last_sent_pn(p.server, 0)), "crypto"), "ServerHello sent")
    # Contiguous Handshake CRYPTO offsets across the flight.
    var all_dgs = List[List[UInt8]]()
    all_dgs.append(first[0].copy())
    for _ in range(8):
        var more = p.server.send(now)
        if len(more) == 0:
            break
        all_dgs.append(more[0].copy())
    var expected_offset = UInt64(0)
    var keys = List[Int]()
    for entry in p.server.spaces[1].sent_packets.items():
        keys.append(entry.key)
    for _ in range(len(keys)):
        var lowest = -1
        for j in range(len(keys)):
            if keys[j] >= 0 and (lowest < 0 or keys[j] < keys[lowest]):
                lowest = j
        var frames = _frames_of(p.server, 1, keys[lowest])
        keys[lowest] = -1
        for f in range(len(frames)):
            if frames[f].is_crypto():
                ref cf = frames[f].as_crypto()
                assert_true(cf.offset == expected_offset, "contiguous Handshake CRYPTO offsets")
                expected_offset += UInt64(len(cf.data))
    assert_true(expected_offset > UInt64(0), "Handshake CRYPTO was emitted")
    for i in range(len(all_dgs)):
        try:
            p.client.recv(Span(all_dgs[i]), now)
        except:
            pass
    _ = _establish(p.client, p.server, now)
    print("  test_server_pads_initial_datagrams: PASS")


def test_ack_scheduling_suspended_in_closing() raises:
    """`ack-scheduling-suspended-in-closing`: packets received after
    _close_impl are neither acknowledged nor scheduled; send() emits only
    CLOSE packets; after DRAINING receipt changes nothing."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    now = _establish(p.client, p.server, now)
    _open_gate(p.server)
    var ssid = p.server.open_stream(True)
    p.client.close_transport(UInt64(0), String("bye"), now)
    var close_dg = p.client.send(now)
    assert_equal_int(len(close_dg), 1, "CLOSE emitted")
    var idle_before = p.client.idle_timer
    var largest_before = p.client.spaces[2].largest_recv_pn
    # Two PTO-spaced triggers fit inside the 3*PTO closing period.
    for _ in range(2):
        var d = _bytes(100)
        p.server.send_stream_data(ssid, Span(d), False)
        now += p.client._pto_interval() + UInt64(1)
        var sd = p.server.send(now)
        p.client.recv(Span(sd[0]), now)
        assert_true(p.client.idle_timer == idle_before, "idle timer not refreshed while closing")
        assert_false(p.client.spaces[2].ack_needed or Bool(p.client.spaces[2].ack_deadline), "no ACK scheduled while closing")
        assert_true(p.client.spaces[2].largest_recv_pn == largest_before, "PN window frozen while closing")
        var out = p.client.send(now)
        assert_equal_int(len(out), 1, "one CLOSE per trigger")
        var frames = _frames_of(p.client, 2, _last_sent_pn(p.client, 2))
        assert_true(len(frames) == 1 and frames[0].is_connection_close(), "CLOSE-only packet, no ACK")
        var t = p.client.timeout(now)
        assert_true(Bool(t) and t.value() > now, "closing: deadline in the future")
    # Server drains on the CLOSE; further packets change nothing.
    p.server.recv(Span(close_dg[0]), now)
    assert_true(p.server.is_draining(), "server draining")
    var fp = _fingerprint(p.server)
    var rec_before = p.server.bytes_received
    var d2 = _bytes(30)
    p.client.close.pending = None
    p.client.state = p.client.state & ~CONN_CLOSING
    # Craft one more client datagram by reopening the client's send path.
    var sid = p.client.open_stream(True)
    p.client.send_stream_data(sid, Span(d2), False)
    var cd = p.client.send(now)
    if len(cd) > 0:
        p.server.recv(Span(cd[0]), now)
        assert_true(p.server.bytes_received > rec_before, "bytes credited")
        assert_true(_fingerprint(p.server) == fp, "draining: no state change on receipt")
        assert_equal_int(len(p.server.send(now)), 0, "draining: nothing sent")
    print("  test_ack_scheduling_suspended_in_closing: PASS")


def test_event_fifo() raises:
    """`event-fifo`: poll() yields events in append order, one per call, for
    random interleavings of append and poll."""
    var now = UInt64(1_000_000)
    var p = _Pair(_default_params(), _default_params(), now)
    _drain_events(p.client)
    var rng = _Rng(UInt64(0xF1F0))
    var next_id = UInt64(0)
    var expect = UInt64(0)
    for _ in range(2000):
        if rng.below(2) == 0:
            p.client.events.append(QuicEvent.stream_readable(next_id))
            next_id += 1
        else:
            var ev = p.client.poll()
            if expect < next_id:
                assert_true(Bool(ev), "event available")
                assert_true(ev.value().stream_id == expect, "FIFO order")
                expect += 1
            else:
                assert_false(Bool(ev), "empty queue yields None")
    while expect < next_id:
        var ev = p.client.poll()
        assert_true(Bool(ev) and ev.value().stream_id == expect, "drain in order")
        expect += 1
    assert_false(Bool(p.client.poll()), "drained")
    assert_equal_int(len(p.client.events), 0, "list reset once drained")
    print("  test_event_fifo: PASS")


def main() raises:
    print("test_quic_ack_scheduling:")
    test_ack_bundled_on_send()
    test_ack_within_max_ack_delay()
    test_ack_only_bypasses_cc()
    test_no_past_deadline_after_send()
    test_pto_armed_only_with_ae_in_flight()
    test_pto_fires_once_per_expiry()
    test_pto_probe_emits_ping()
    test_close_sent_once_per_trigger()
    test_close_reason_bounded()
    test_send_returns_empty_when_idle()
    test_bundle_predicate_sound()
    test_datagram_never_exceeds_budget()
    test_crypto_split_lossless()
    test_pto_deadline_single_source()
    test_pto_uses_peer_max_ack_delay()
    test_client_pads_all_initial_datagrams()
    test_server_pads_initial_datagrams()
    test_ack_scheduling_suspended_in_closing()
    test_event_fifo()
    print("All test_quic_ack_scheduling tests passed.")
