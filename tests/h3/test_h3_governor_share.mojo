"""H3Connection's governor hooks: per-connection counts, the narrowed window, shedding above the share, held drains.

In-memory raw QUIC client (`RawPair`): the test sees exactly the bytes and frames the server emits.
"""

from std.collections import Span
from navette.h3.connection import ConnTally
from navette.h3.error import H3_NO_ERROR
from navette.h3.qpack import QpackDecoder, QpackHeaderField
from navette.protect.governor import UNLIMITED
from navette.quic.event import QuicEvent, StreamStoppedPayload
from tests._test_util import assert_true
from tests.h3._h3_raw_pair import RawPair, headers_get


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
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(String(":status"), String("200")))
    p.srv.send_headers(sid, fields, True)


def _tally(mut p: RawPair) -> ConnTally:
    var acc = ConnTally(work=0, active=0, done=0, rtt_us=0, refused_503=0, cap=0)
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
    var min_rtt = p.srv._quic.recovery.min_rtt
    var t = _tally(p)
    assert_true(t.work == 2 and t.active == 1, "two open, one active connection: " + String(t.work))
    assert_true(t.done == 3 and t.rtt_us == 3 * min_rtt, "three completions: " + String(t.done))
    assert_true(t.cap == 100, "cap is the stream ceiling")
    t = _tally(p)
    assert_true(t.done == 0 and t.work == 2, "completions are counted once")
    p.srv.long_lived = 1
    assert_true(_tally(p).work == 1, "long-lived streams are not work")


def test_window_narrowed_then_released() raises:
    var p = RawPair()
    var sids = _requests(p, 5, True)
    for i in range(3):
        _respond(p, sids[i])
    p.pump(10)
    _ = p.srv.apply_governor(1, 1000, 1, UNLIMITED, 1)
    _ = p.srv.apply_governor(1, 1000, 1, UNLIMITED, 1)
    ref sm = p.srv._quic.stream_map
    assert_true(sm.regrant_window == 32, "two over-budget closes narrow to the floor: " + String(sm.regrant_window))
    var limit = p.cli.stream_map.peer_max_streams_bidi
    for i in range(3, 5):
        _respond(p, sids[i])
    p.pump(10)
    assert_true(p.cli.stream_map.peer_max_streams_bidi == limit, "no MAX_STREAMS while D + 32 is under the limit")
    assert_true(p.srv.apply_governor(UNLIMITED, 0, 1, UNLIMITED, 1), "release grants")
    var dgs = p.srv.drain_datagrams(p.now)
    assert_true(len(dgs) > 0, "the grant leaves without a client datagram")
    for i in range(len(dgs)):
        p.cli.recv(Span(dgs[i]), p.now)
    assert_true(p.cli.stream_map.peer_max_streams_bidi == 105, "MAX_STREAMS = D + 100: " + String(p.cli.stream_map.peer_max_streams_bidi))


def test_shed_above_share_and_hold() raises:
    var p = RawPair()
    var sids = _requests(p, 40, False)
    _ = p.srv.apply_governor(UNLIMITED, 0, 1, 32, 1)
    for i in range(40):
        var shed = p.srv.shed_if_over_share(sids[i])
        assert_true(shed == (i >= 32), "request " + String(i + 1) + " shed=" + String(shed))
    assert_true(p.srv.refused_503 == 8, "eight 503s")
    assert_true(len(p.srv.drain_datagrams(p.now, hold=True)) == 0, "a held drain sends nothing")
    assert_true(p.srv.has_pending_egress(), "and leaves the connection due")
    var dgs = p.srv.drain_datagrams(p.now)
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
        var fields = dec.decode(List[Byte](b[2:]))
        assert_true(fields[0].name == ":status" and fields[0].value == "503", "status 503")
        assert_true(fields[1].name == "retry-after" and fields[1].value == "1", "retry-after: 1")
    var q = RawPair()
    var many = _requests(q, 40, False)
    for i in range(40):
        assert_true(not q.srv.shed_if_over_share(many[i]), "UNLIMITED share never sheds")


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
    if failed:
        raise Error(String(failed) + " failed")
    print("PASS: test_h3_governor_share")
