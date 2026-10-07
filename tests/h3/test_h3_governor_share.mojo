"""H3Connection's governor hooks: per-connection counts, the narrowed window, shedding above the share, held drains.

In-memory raw QUIC client (`RawPair`, or `_HPair` for the handler server): the test sees exactly the bytes and
frames the server emits.
"""

from std.collections import Span
from navette.h3.connection import ConnTally, H3Connection
from navette.h3.h3_handler_server import H3HandlerServer
from navette.http.handler import Capabilities, RecvBody, ResponseWriter, StreamError, StreamHandler
from navette.http.request import Request
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.quic.connection import QuicConnection
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.tls.lib import TlsBackend
from navette.h3.error import H3_NO_ERROR
from navette.h3.qpack import QpackDecoder, FieldSection
from navette.protect.governor import UNLIMITED, GovState, Mode, Sample, step
from navette.quic.event import QuicEvent, StreamStoppedPayload
from tests._test_util import assert_true, load_test_cert, load_test_ca
from tests.h3._h3_raw_pair import RawPair, headers_get, raw_params


def _requests(mut p: RawPair, n: Int, fin: Bool) raises -> List[UInt64]:
    """Open `n` request streams (GET HEADERS) in one flight."""
    var sids = List[UInt64]()
    for _ in range(n):
        var sid = p.cli.open_stream(True)
        p.cli.send_stream_data(sid, Span(headers_get()), fin)
        sids.append(sid)
    p.pump(5)
    return sids^


def _respond(mut p: RawPair, sid: UInt64) raises:
    p.srv.send_headers(sid, FieldSection(status="200"), True)


def _shed_at(mut h3: H3Connection, k: UInt64):
    """Pressure with a stream window of `k`, the even split, already reached."""
    _ = h3.apply_governor(UNLIMITED, 0, 1, k, 1)
    h3._quic.stream_map.regrant_window = k


def _tally(mut p: RawPair) -> ConnTally:
    var acc = ConnTally(work=0, active=0, done=0, refused_503=0, cap=0)
    p.srv.gov_tally(acc)
    return acc^


def test_tally() raises:
    var p = RawPair()
    var sids = _requests(p, 5, True)
    assert_true(p.srv.take_opened() == 5, "five requests arrived")
    assert_true(p.srv.take_opened() == 0, "none since")
    for i in range(3):
        _respond(p, sids[i])
    p.pump(10)
    var t = _tally(p)
    assert_true(t.work == 2 and t.active == 1, "two open, one active connection: " + String(t.work))
    assert_true(t.done == 3, "three completions: " + String(t.done))
    assert_true(t.cap == 100, "cap is the stream ceiling")
    t = _tally(p)
    assert_true(t.done == 0 and t.work == 2, "completions are counted once")
    p.srv.long_lived = 1
    assert_true(_tally(p).work == 1, "long-lived streams are not work")
    var dying = ConnTally(work=0, active=0, done=0, refused_503=0, cap=0)
    _respond(p, sids[3])
    p.pump(10)
    p.srv.gov_tally(dying, live=False)
    assert_true(dying.done == 1 and dying.work == 0 and dying.active == 0, "a dying connection adds completions, not work")


def test_window_narrowed_then_released() raises:
    var p = RawPair()
    var sids = _requests(p, 5, True)
    for i in range(3):
        _respond(p, sids[i])
    p.pump(10)
    _ = p.srv.apply_governor(1, 1000, 1, UNLIMITED, 1)
    _ = p.srv.apply_governor(1, 1000, 1, UNLIMITED, 1)
    ref sm = p.srv._quic.stream_map
    assert_true(sm.regrant_window == 25, "two over-budget closes halve the window twice: " + String(sm.regrant_window))
    var limit = p.cli.stream_map.peer_max_streams_bidi
    for i in range(3, 5):
        _respond(p, sids[i])
    p.pump(10)
    assert_true(p.cli.stream_map.peer_max_streams_bidi == limit, "no MAX_STREAMS while D + 25 is under the limit")
    assert_true(p.srv.apply_governor(UNLIMITED, 0, 1, UNLIMITED, 1), "release grants")
    var dgs = List[List[Byte]]()
    p.srv.drain_datagrams(p.now, dgs)
    assert_true(len(dgs) > 0, "the grant leaves without a client datagram")
    for i in range(len(dgs)):
        p.cli.recv(Span(dgs[i]), p.now)
    assert_true(p.cli.stream_map.peer_max_streams_bidi == 105, "MAX_STREAMS = D + 100: " + String(p.cli.stream_map.peer_max_streams_bidi))


def test_shed_above_share_and_hold() raises:
    var p = RawPair()
    var sids = _requests(p, 40, False)
    _shed_at(p.srv, 32)
    for i in range(40):
        var shed = p.srv.shed_if_over_share(sids[i])
        assert_true(shed == (i >= 32), "request " + String(i + 1) + " shed=" + String(shed))
    assert_true(p.srv.refused_503 == 8, "eight 503s")
    var held = List[List[Byte]]()
    p.srv.drain_datagrams(p.now, held, hold=True)
    assert_true(len(held) == 0, "a held drain sends nothing")
    assert_true(p.srv.has_pending_egress(), "and leaves the connection due")
    var dgs = List[List[Byte]]()
    p.srv.drain_datagrams(p.now, dgs)
    assert_true(len(dgs) > 0, "the next drain sends")
    for i in range(len(dgs)):
        p.cli.recv(Span(dgs[i]), p.now)
    var stopped = 0
    while True:
        var ev = p.cli.poll()
        if not ev:
            break
        if ev.value().type_id == QuicEvent.STREAM_STOPPED:
            var s = ev.value().payload.unsafe_get[StreamStoppedPayload]().copy()
            assert_true(s.error_code == H3_NO_ERROR and s.stream_id >= sids[32], "STOP_SENDING(H3_NO_ERROR) on a shed stream")
            stopped += 1
    assert_true(stopped == 8, "eight STOP_SENDING: " + String(stopped))
    for i in range(32, 40):
        var got = p.cli.recv_stream_data(sids[i])
        assert_true(got[1], "503 ends with FIN")
        var b = got[0].copy()
        assert_true(len(b) > 2 and b[0] == 0x01 and Int(b[1]) == len(b) - 2, "one HEADERS frame")
        var dec = QpackDecoder()
        var section = dec.decode(List[Byte](b[2:]))
        assert_true(section.status == "503", "status 503")
        assert_true(len(section.headers) == 1 and section.headers.get("retry-after") == "1", "retry-after: 1")
    var q = RawPair()
    var many = _requests(q, 40, False)
    for i in range(40):
        assert_true(not q.srv.shed_if_over_share(many[i]), "UNLIMITED share never sheds")


def test_crossing_fin_while_shedding() raises:
    """The client's FIN crosses our STOP_SENDING: the shed streams still complete and return their credit."""
    var p = RawPair()
    var sids = _requests(p, 40, False)
    _shed_at(p.srv, 32)
    for i in range(32, 40):
        assert_true(p.srv.shed_if_over_share(sids[i]), "shed")
        p.cli.send_stream_data(sids[i], Span(List[Byte]()), True)
    p.srv._quic.stream_map.regrant_window = 100  # released: completions re-grant D + 100
    p.pump(60)
    for i in range(32, 40):
        assert_true(Int(sids[i]) not in p.srv._quic.stream_map.streams, "shed stream reaped: " + String(sids[i]))
        assert_true(Int(sids[i]) not in p.srv._stream_bufs, "its H3 buffer released")
    assert_true(p.srv._quic.stream_map.peer_completed_bidi == 8, "eight completed: " + String(p.srv._quic.stream_map.peer_completed_bidi))
    assert_true(p.cli.stream_map.peer_max_streams_bidi == 108, "credit returned: " + String(p.cli.stream_map.peer_max_streams_bidi))


def test_credit_first_then_503() raises:
    """200 connections, budget 147: no 503 within granted credit; once the window has come down below the open
    streams, only the streams opened on the older credit get 503."""
    var p = RawPair()
    var sids = _requests(p, 10, False)
    var s = GovState()
    s.mode, s.budget, s.since_cut = Mode.HOLDING, 147, 0
    var d = step(s, Sample(delay_us=100_000, done=3_000, work=2_000, active=200), 5_000, 100)
    _ = p.srv.apply_governor(d.budget, 2_000, 200, d.shed_above, d.retry_after_s)
    assert_true(p.srv._quic.stream_map.regrant_window == 50 and not p.srv.shed_if_over_share(sids[9]), "credit 50: no 503")
    for _ in range(4):
        _ = p.srv.apply_governor(d.budget, 2_000, 200, d.shed_above, d.retry_after_s)
    assert_true(p.srv._quic.stream_map.regrant_window == 8, "one halving per close while open <= window, down to MIN_CREDIT: " + String(p.srv._quic.stream_map.regrant_window))
    for i in range(10):
        assert_true(p.srv.shed_if_over_share(sids[i]) == (i >= 8), "request " + String(i + 1))
    assert_true(p.srv.refused_503 == 2, "two 503s: " + String(p.srv.refused_503))


def test_threshold_moves_with_completions() raises:
    """The 503 threshold counts open streams (ordinal minus completed), not stream ordinals."""
    var p = RawPair()
    var first = _requests(p, 2, True)
    _shed_at(p.srv, 2)
    for i in range(2):
        assert_true(not p.srv.shed_if_over_share(first[i]), "under the threshold")
        _respond(p, first[i])
    p.pump(10)
    assert_true(p.srv._quic.stream_map.peer_completed_bidi == 2, "both completed")
    var later = _requests(p, 2, True)
    for i in range(2):
        assert_true(not p.srv.shed_if_over_share(later[i]), "completed streams free their place: " + String(later[i]))


struct _Counting(StreamHandler):
    """Counts the requests it runs; detaches the body of the next one when asked; answers only with `answer`."""

    var calls: Int
    var detach_next: Bool
    var answer: Bool

    def __init__(out self):
        self.calls, self.detach_next, self.answer = 0, False, False

    def on_request(mut self, var req: Request, mut body: RecvBody, mut resp: ResponseWriter, caps: Capabilities) raises:
        self.calls += 1
        if self.detach_next:
            self.detach_next = False
            _ = body.try_detach()
        if self.answer:
            resp.send_status(StatusCode(200), Headers())
            resp.end()

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


struct _HPair(Movable):
    """Raw QUIC client against an `H3HandlerServer`, pumped in memory."""

    var srv: H3HandlerServer[_Counting]
    var cli: QuicConnection
    var now: UInt64

    def __init__(out self) raises:
        var tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert = ck[0].copy()
        var key = ck[1].copy()
        var ca = load_test_ca()
        var srv_cfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
        var cli_cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
        self.now = UInt64(1_000_000)
        var cli = QuicConnection.client(tls.shared(), cli_cfg, "localhost", raw_params(), self.now)
        var odcid = List[Byte](cli.initial_dcid.as_span())
        var cdcid = odcid.copy()
        var sq = QuicConnection.server(tls.shared(), srv_cfg, raw_params(), Span(odcid), Span(cdcid), self.now)
        self.srv = H3HandlerServer[_Counting](quic=sq^, handler=_Counting())
        self.cli = cli^
        _ = tls^
        self.pump(20)
        assert_true(self.cli.is_established(), "handshake completes")

    def pump(mut self, rounds: Int) raises:
        var scratch = List[List[Byte]](capacity=1)
        for _ in range(rounds):
            self.now += UInt64(10_000)
            for _ in range(64):
                scratch.clear()
                var n = self.cli.send(self.now, scratch)
                if n == 0:
                    break
                for i in range(n):
                    self.srv.feed_datagram(Span(scratch[i]), self.now)
            var dgs = List[List[Byte]]()
            self.srv.drain_datagrams(self.now, dgs)
            for i in range(len(dgs)):
                self.cli.recv(Span(dgs[i]), self.now)
            while self.cli.poll():
                pass

    def request(mut self) raises -> UInt64:
        var sid = self.cli.open_stream(True)
        self.cli.send_stream_data(sid, Span(headers_get()), False)
        return sid


def test_handler_sheds_above_share() raises:
    var p = _HPair()
    _shed_at(p.srv.h3(), 32)
    for _ in range(40):
        _ = p.request()
    p.pump(5)
    assert_true(p.srv.handler.calls == 32, "the handler runs 32 times: " + String(p.srv.handler.calls))
    assert_true(p.srv.h3().refused_503 == 8, "eight 503s")


def test_detached_stream_is_long_lived() raises:
    var p = _HPair()
    p.srv.handler.detach_next = True
    var sid = p.request()
    _ = p.request()
    p.pump(5)
    assert_true(p.srv.h3().long_lived == 1, "a detached body is long-lived: " + String(p.srv.h3().long_lived))
    var acc = ConnTally(work=0, active=0, done=0, refused_503=0, cap=0)
    p.srv.h3().gov_tally(acc)
    assert_true(acc.work == 1, "work excludes it: " + String(acc.work))
    p.cli.reset_stream(sid, UInt64(0x10C))
    p.pump(4)
    assert_true(p.srv.h3().long_lived == 0, "its reset frees it")
    var q = _HPair()
    q.srv.handler.detach_next, q.srv.handler.answer = True, True
    var done = q.cli.open_stream(True)
    q.cli.send_stream_data(done, Span(headers_get()), True)
    q.pump(10)
    assert_true(q.srv.handler.calls == 1 and q.srv._streams.find(Int(done)) is None, "answered and freed")
    assert_true(q.srv.h3().long_lived == 0, "a detached stream that completes normally is no longer long-lived")


def main() raises:
    var failed = 0
    try:
        test_tally()
    except e:
        print("FAIL test_tally:", e)
        failed += 1
    try:
        test_window_narrowed_then_released()
    except e:
        print("FAIL test_window_narrowed_then_released:", e)
        failed += 1
    try:
        test_shed_above_share_and_hold()
    except e:
        print("FAIL test_shed_above_share_and_hold:", e)
        failed += 1
    try:
        test_crossing_fin_while_shedding()
    except e:
        print("FAIL test_crossing_fin_while_shedding:", e)
        failed += 1
    try:
        test_credit_first_then_503()
    except e:
        print("FAIL test_credit_first_then_503:", e)
        failed += 1
    try:
        test_threshold_moves_with_completions()
    except e:
        print("FAIL test_threshold_moves_with_completions:", e)
        failed += 1
    try:
        test_handler_sheds_above_share()
    except e:
        print("FAIL test_handler_sheds_above_share:", e)
        failed += 1
    try:
        test_detached_stream_is_long_lived()
    except e:
        print("FAIL test_detached_stream_is_long_lived:", e)
        failed += 1
    if failed:
        raise Error(String(failed) + " failed")
    print("PASS: test_h3_governor_share")
