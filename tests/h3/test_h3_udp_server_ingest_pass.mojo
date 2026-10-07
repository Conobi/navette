"""Ingest-pass policy of `H3UdpServer`: budgeted re-step and fair drain.

A loaded pass must not stop at the kernel's multishot batch (33 or 66
deliveries per step): `ingest_more` re-steps while the last step came back
full, bounded by the per-pass budget and the buffer pool. `_flush_ingress`
then drains each connection that received datagrams exactly once, in an
order that rotates from pass to pass.
"""

from std.collections import Span

from navette.h3.h3_udp_server import INGEST_BUDGET_DATAGRAMS
from navette.h3.qpack import QpackHeaderField
from navette.http.body import BodyFrame
from navette.http.handler import (
    StreamHandler,
    Request,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
)
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.quic.trans_param import TransportParams, default_transport_params

from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness, HarnessClient


# One burst: at least `_RESTEP_MIN_BATCH` (32), so the step that returns it
# counts as full. Three bursts (150) exceed two kernel batches (2 x 33) and
# stay under what the loopback socket's default receive buffer holds.
comptime _BURST: Int = 50


struct OkHandler(StreamHandler):
    """Answers every request at once with a two-byte 200 body."""

    def __init__(out self):
        pass

    def __init__(out self, *, deinit move: Self):
        pass

    def on_request(
        mut self, var req: Request, mut body: RecvBody,
        mut resp: ResponseWriter, caps: Capabilities,
    ) raises:
        resp.send_status(StatusCode.ok(), Headers())
        var body_bytes = List[Byte]()
        body_bytes.append(UInt8(111))
        body_bytes.append(UInt8(107))
        _ = resp.try_send_body(BodyFrame.data(body_bytes^))
        resp.end()

    def on_body_available(
        mut self, mut body: RecvBody, mut resp: ResponseWriter,
    ) raises:
        pass

    def on_request_end(
        mut self, mut body: RecvBody, mut resp: ResponseWriter,
    ) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


def make_ok_handler() raises -> OkHandler:
    return OkHandler()


def _params() -> TransportParams:
    """Generous windows so no test is limited by flow control."""
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(4_194_304)
    p.initial_max_stream_data_bidi_local = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_remote = UInt64(1_048_576)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _junk_datagram(i: Int) -> List[Byte]:
    """A 40-byte short-header datagram for an unknown DCID (dropped at demux)."""
    var dg = List[Byte](capacity=40)
    dg.append(UInt8(0x40))
    for j in range(1, 40):
        dg.append(UInt8((i + j) & 0xFF))
    return dg^


def _flood(h: UdpServerHarness[OkHandler], n: Int) raises:
    """Queue `n` junk datagrams on the server socket from one client socket."""
    var sock = h.new_socket()
    for i in range(n):
        h.send_raw(sock, _junk_datagram(i))


def _queued(h: UdpServerHarness[OkHandler]) -> Int:
    """Deliveries the recv stream holds that `flush()` has not taken yet."""
    return h.srv[]._recv_stream.value().pending()


def _partial_request(mut client: HarnessClient) raises:
    """An ack-eliciting stream packet that draws no response (HEADERS never ends)."""
    var sid = client.h3.open_bidi_stream()
    var partial = List[Byte]()
    partial.append(UInt8(0x01))  # HEADERS frame type
    partial.append(UInt8(0x20))  # declared length 32; payload withheld
    client.h3._quic.send_stream_data(sid, Span(partial), False)


def _send_get(mut client: HarnessClient) raises:
    """Queue `GET /` with FIN on a fresh bidi stream."""
    var sid = client.h3.open_bidi_stream()
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":method", "GET"))
    fields.append(QpackHeaderField(":path", "/"))
    fields.append(QpackHeaderField(":scheme", "https"))
    fields.append(QpackHeaderField(":authority", "localhost"))
    client.h3.send_headers(sid, fields, True)


def _settle(mut h: UdpServerHarness[OkHandler]) raises:
    """Flush with a frozen clock until a flush issues no deadline refresh."""
    for _ in range(16):
        var before = h.srv[]._deadline_refresh_count
        h.flush()
        if h.srv[]._deadline_refresh_count == before:
            return
    raise "settle: refresh count still moving"


def _connect(mut h: UdpServerHarness[OkHandler], mut c: HarnessClient) raises:
    """Handshake, a few settling round trips, then let delayed ACKs fire."""
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = h.pump(c)


# ── Re-step ──────────────────────────────────────────────────────────────
#
# How many deliveries one step returns is kernel-dependent: the VPS kernel
# stops each multishot round at 33, a recent one drains the socket up to
# the pool in one go. The tests therefore make "more data after a full
# step" deterministic: one burst, one step (a full batch), then more bursts
# queued before `ingest_more` runs.


def test_ingest_beyond_kernel_batch() raises:
    """ingest-beyond-kernel-batch: a full step is followed by re-steps that ingest the rest."""
    var h = UdpServerHarness[OkHandler](make_ok_handler, _params(), _params())
    _flood(h, _BURST)
    _ = h.step(20)
    assert_equal_int(_queued(h), _BURST, "premise: the first step returns one full burst")
    _flood(h, 2 * _BURST)
    var resteps = h.srv[].ingest_more()
    var total = _queued(h)
    var pool = h.srv[]._recv_pool.value().capacity()
    assert_true(resteps >= 1, "a full batch triggers a re-step")
    assert_true(total > 66, "one pass ingests past two kernel batches (got " + String(total) + ")")
    assert_equal_int(
        total, min(3 * _BURST, pool),
        "re-step continues until the socket or the pool runs dry",
    )
    h.flush()
    # Whatever the pool could not hold arrives on the next passes.
    var seen = total
    for _ in range(8):
        if seen >= 3 * _BURST:
            break
        _ = h.step(20)
        _ = h.srv[].ingest_more()
        seen += _queued(h)
        h.flush()
    assert_equal_int(seen, 3 * _BURST, "every datagram ingested across passes")
    print("PASS: test_ingest_beyond_kernel_batch")


def _quiesce(mut h: UdpServerHarness[OkHandler]) raises:
    """Pass until nothing is left queued on the socket."""
    for _ in range(4):
        _ = h.step(5)
        h.flush()


def test_restep_respects_budget() raises:
    """budget-respected: no re-step once the budget is reached; the pool bounds the rest."""
    var h = UdpServerHarness[OkHandler](make_ok_handler, _params(), _params())
    assert_equal_int(h.srv[].ingest_budget, INGEST_BUDGET_DATAGRAMS, "default budget")

    # A budget the first step already covers: no re-step at all.
    _flood(h, _BURST)
    _ = h.step(20)
    var first = _queued(h)
    assert_equal_int(first, _BURST, "premise: one full burst")
    _flood(h, _BURST)
    h.srv[].ingest_budget = first
    assert_equal_int(h.srv[].ingest_more(), 0, "budget reached -> no re-step")
    assert_equal_int(_queued(h), first, "nothing more was ingested")
    h.flush()
    _quiesce(h)

    # One datagram of headroom: exactly one re-step, then the budget stops it.
    _flood(h, _BURST)
    _ = h.step(20)
    first = _queued(h)
    _flood(h, 2 * _BURST)
    h.srv[].ingest_budget = first + 1
    assert_equal_int(h.srv[].ingest_more(), 1, "one re-step crosses the budget, then stop")
    h.flush()
    _quiesce(h)

    # A budget far above the pool: the pool (or an empty socket) ends the pass.
    h.srv[].ingest_budget = 1_000_000
    var pool = h.srv[]._recv_pool.value().capacity()
    _flood(h, _BURST)
    _ = h.step(20)
    _flood(h, 2 * _BURST)
    var resteps = h.srv[].ingest_more()
    assert_true(_queued(h) <= pool, "never more deliveries than pool buffers")
    assert_equal_int(_queued(h), min(3 * _BURST, pool), "ingested up to the pool")
    if pool <= 3 * _BURST:
        assert_equal_int(resteps, 1, "an exhausted pool stops re-stepping")
    else:
        assert_equal_int(resteps, 2, "an empty re-step stops re-stepping")
    h.flush()
    print("PASS: test_restep_respects_budget")


# ── Fair drain ───────────────────────────────────────────────────────────


def test_dirty_connection_drained_once_per_pass() raises:
    """dirty-connection-drained-once-per-pass: N datagrams for one conn -> one drain."""
    var h = UdpServerHarness[OkHandler](make_ok_handler, _params(), _params())
    var a = h.new_client()
    var b = h.new_client()
    _connect(h, a)
    _connect(h, b)
    assert_equal_int(h.slot_count(), 2, "two slots")
    h.advance(h.srv[].transport_params.max_ack_delay * UInt64(1_000) + UInt64(1_000))
    _settle(h)

    _partial_request(a)
    var dga = List[List[Byte]]()
    a.h3.drain_datagrams(h.now(), dga)
    _partial_request(b)
    var dgb = List[List[Byte]]()
    b.h3.drain_datagrams(h.now(), dgb)
    assert_true(len(dga) >= 1 and len(dgb) >= 1, "both clients produced a datagram")
    # Interleaved duplicates: the QUIC layer discards the replays, but each
    # one still reaches the per-datagram ingress path.
    for _ in range(10):
        h.send_raw(a.sock, dga[0])
        h.send_raw(b.sock, dgb[0])
    _ = h.step(20)
    _ = h.srv[].ingest_more()
    assert_equal_int(_queued(h), 20, "all 20 datagrams in one pass")
    var before = h.srv[]._deadline_refresh_count
    h.flush()
    assert_equal_int(
        h.srv[]._deadline_refresh_count - before, 2,
        "20 datagrams for 2 conns -> one drain each",
    )
    _ = h.slot_count()
    print("PASS: test_dirty_connection_drained_once_per_pass")


def test_round_robin_across_passes() raises:
    """round-robin-fairness: the conn drained first alternates between passes."""
    var h = UdpServerHarness[OkHandler](make_ok_handler, _params(), _params())
    var a = h.new_client()
    var b = h.new_client()
    _connect(h, a)
    _connect(h, b)
    assert_equal_int(h.slot_count(), 2, "two slots")
    _settle(h)

    var firsts = List[Int]()
    for p in range(4):
        # A's request always reaches the socket first.
        _send_get(a)
        _ = h.client_send(a)
        _send_get(b)
        _ = h.client_send(b)
        _ = h.step(20)
        _ = h.srv[].ingest_more()
        h.srv[]._drain_recv_stream()
        h.srv[]._flush_ingress()
        var seen_a = False
        var seen_b = False
        for k in range(len(h.srv[]._egress_backlog)):
            var ci = h.srv[]._egress_backlog[k].conn_idx
            seen_a = seen_a or ci == 0
            seen_b = seen_b or ci == 1
        assert_true(seen_a and seen_b, "both conns answered in pass " + String(p))
        firsts.append(h.srv[]._egress_backlog[0].conn_idx)
        h.flush()
        h.advance(UInt64(1_000))
        _ = h.client_recv(a, 50)
        _ = h.client_recv(b, 50)
    for p in range(1, 4):
        assert_true(
            firsts[p] != firsts[p - 1],
            "first-served conn alternates (pass " + String(p) + ")",
        )
    _ = h.slot_count()
    print("PASS: test_round_robin_across_passes")


def main() raises:
    test_ingest_beyond_kernel_batch()
    test_restep_respects_budget()
    test_dirty_connection_drained_once_per_pass()
    test_round_robin_across_passes()
