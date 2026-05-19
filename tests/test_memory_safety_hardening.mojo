"""Memory-safety hardening tests.

Covers: PtrBox roundtrip + null, ConnSlot swap-and-pop invariant,
stale-generation demux lookup.

H3UdpHandler.__del__ freeing pbuf_pool / msghdr_template / timeout_ts
is exercised implicitly by tests/test_h3_udp_server.mojo (construct +
tick + drop). The buf-ring `_acquire_buf` / `_release_buf` ledger is
unit-tested via its `debug_assert`s, which fire under ASSERT=all
whenever any test runs a real recvmsg CQE path through the server.

See specs/2026-05-18-memory-safety-hardening.md.
"""

from std.testing import assert_equal, assert_true, assert_false

from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.util.ptrbox import PtrBox

from navette.h3.h3_udp_server import (
    H3UdpServer,
    ConnSlot,
    _DcidEntry,
)
from navette.h3.h3_handler_server import H3HandlerServer
from navette.http.handler import (
    StreamHandler,
    Request,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
)
from navette.io.udp_socket import udp_listener
from navette.quic.trans_param import default_transport_params


# ---------------------------------------------------------------------------
# PtrBox tests (AC1)
# ---------------------------------------------------------------------------


def test_ptrbox_roundtrip() raises:
    var p = _heap_alloc[Int](1).as_any_origin()
    p.init_pointee_move(123)
    var box = PtrBox[Int](p)
    assert_true(box.is_some())
    assert_equal(box.ptr()[], 123)

    var box2 = PtrBox[Int](other=box)
    assert_equal(box2.ptr()[], 123)

    var raw = box.ptr()
    raw.destroy_pointee()
    raw.free()


def test_ptrbox_null() raises:
    var box = PtrBox[Int].null()
    assert_false(box.is_some())


# ---------------------------------------------------------------------------
# ConnSlot demux tests (AC4 + AC5)
# ---------------------------------------------------------------------------
# Stub handler used only to satisfy the H3UdpServer[H: StreamHandler] type
# constraint. The demux-lookup tests never reach handler dispatch, so the
# methods are all `pass`.


struct StubHandler(StreamHandler):
    def __init__(out self):
        pass

    def __init__(out self, *, deinit take: Self):
        pass

    def on_request(
        mut self, var req: Request, mut body: RecvBody,
        mut resp: ResponseWriter, caps: Capabilities,
    ) raises:
        pass

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


def make_stub_handler() raises -> StubHandler:
    return StubHandler()


def _push_fake_slot(
    mut server: H3UdpServer[StubHandler],
    dcids: List[UInt64],
    generation: UInt64,
):
    """Push a ConnSlot with a NULL h3 pointer for demux-only tests.

    Lookup paths never deref h3, so null is safe — provided we drain
    these entries before the server drops (server's __del__ walks
    conn_slots and would destroy_pointee+free a null h3).
    """
    var slot = ConnSlot[StubHandler](
        UnsafePointer[H3HandlerServer[StubHandler], MutAnyOrigin](),
        List[UInt8](),
        dcids.copy(),
        generation,
    )
    server.conn_slots.append(slot^)


def _drain_fake_slots(mut server: H3UdpServer[StubHandler]):
    """Pop every fake slot before the server is dropped, so __del__
    doesn't try to destroy_pointee+free their null h3 pointers."""
    while len(server.conn_slots) > 0:
        _ = server.conn_slots.pop()


def _make_test_server() raises -> H3UdpServer[StubHandler]:
    """Minimal H3UdpServer for demux-only tests.

    Uses dummy lib_addr / server_config — never reached on this code
    path since we only call _find_conn_by_dcid. UDP socket is real
    (ephemeral port) because H3UdpServer wants an OwnedHandle.
    """
    var sock = udp_listener(0)
    var tp = default_transport_params()
    return H3UdpServer[StubHandler](
        sock^,
        UInt64(0),
        Int32(-1),
        tp^,
        make_stub_handler,
    )


def test_conn_slot_swap_and_pop_preserves_demux() raises:
    """AC4 — after closing slot 0, the survivor's DCIDs still resolve
    to the right (now-rewritten) slot; the closed conn's DCIDs are
    gone from the demux map."""
    var server = _make_test_server()

    # Slot 0: dcids = [0xAAA, 0xBBB], gen 0
    var d0 = List[UInt64]()
    d0.append(UInt64(0xAAAA_AAAA_AAAA_AAAA))
    d0.append(UInt64(0xBBBB_BBBB_BBBB_BBBB))
    _push_fake_slot(server, d0, UInt64(0))
    server.conn_dcid_map[UInt64(0xAAAA_AAAA_AAAA_AAAA)] = _DcidEntry(0, UInt64(0))
    server.conn_dcid_map[UInt64(0xBBBB_BBBB_BBBB_BBBB)] = _DcidEntry(0, UInt64(0))

    # Slot 1: dcids = [0xCCC, 0xDDD], gen 1
    var d1 = List[UInt64]()
    d1.append(UInt64(0xCCCC_CCCC_CCCC_CCCC))
    d1.append(UInt64(0xDDDD_DDDD_DDDD_DDDD))
    _push_fake_slot(server, d1, UInt64(1))
    server.conn_dcid_map[UInt64(0xCCCC_CCCC_CCCC_CCCC)] = _DcidEntry(1, UInt64(1))
    server.conn_dcid_map[UInt64(0xDDDD_DDDD_DDDD_DDDD)] = _DcidEntry(1, UInt64(1))

    server.next_generation = UInt64(2)

    # Sanity: pre-swap lookups all succeed.
    assert_equal(server._find_conn_by_dcid(UInt64(0xAAAA_AAAA_AAAA_AAAA)), 0)
    assert_equal(server._find_conn_by_dcid(UInt64(0xCCCC_CCCC_CCCC_CCCC)), 1)

    # Simulate closing slot 0: drop its DCID entries, then swap-and-pop
    # the survivor into idx 0 with a fresh generation.
    for dcid_u64 in server.conn_slots[0].dcids:
        _ = server.conn_dcid_map.pop(dcid_u64)
    var survivor = server.conn_slots.pop()
    var new_gen = server.next_generation
    server.next_generation += UInt64(1)
    survivor.generation = new_gen
    for dcid_u64 in survivor.dcids:
        server.conn_dcid_map[dcid_u64] = _DcidEntry(0, new_gen)
    server.conn_slots[0] = survivor^

    # Closed conn's DCIDs are gone.
    assert_equal(server._find_conn_by_dcid(UInt64(0xAAAA_AAAA_AAAA_AAAA)), -1)
    assert_equal(server._find_conn_by_dcid(UInt64(0xBBBB_BBBB_BBBB_BBBB)), -1)

    # Survivor's DCIDs still resolve, now to idx 0.
    assert_equal(server._find_conn_by_dcid(UInt64(0xCCCC_CCCC_CCCC_CCCC)), 0)
    assert_equal(server._find_conn_by_dcid(UInt64(0xDDDD_DDDD_DDDD_DDDD)), 0)

    _drain_fake_slots(server)


def test_conn_slot_stale_generation_returns_negative_one() raises:
    """AC5 — a stale `(idx, gen)` entry whose generation no longer
    matches the slot's current generation must resolve to -1."""
    var server = _make_test_server()

    # One real slot at idx 0 with generation 5.
    var dcids = List[UInt64]()
    dcids.append(UInt64(0x1234_5678_9ABC_DEF0))
    _push_fake_slot(server, dcids, UInt64(5))
    server.conn_dcid_map[UInt64(0x1234_5678_9ABC_DEF0)] = _DcidEntry(0, UInt64(5))

    # Sanity: matching generation resolves.
    assert_equal(server._find_conn_by_dcid(UInt64(0x1234_5678_9ABC_DEF0)), 0)

    # Forge a stale demux entry: same dcid → (idx=0, gen=99).
    server.conn_dcid_map[UInt64(0x1234_5678_9ABC_DEF0)] = _DcidEntry(0, UInt64(99))
    assert_equal(server._find_conn_by_dcid(UInt64(0x1234_5678_9ABC_DEF0)), -1)

    # And a stale entry pointing past the end of conn_slots also resolves to -1.
    server.conn_dcid_map[UInt64(0xDEAD_BEEF_DEAD_BEEF)] = _DcidEntry(99, UInt64(0))
    assert_equal(server._find_conn_by_dcid(UInt64(0xDEAD_BEEF_DEAD_BEEF)), -1)

    _drain_fake_slots(server)


def main() raises:
    test_ptrbox_roundtrip()
    test_ptrbox_null()
    test_conn_slot_swap_and_pop_preserves_demux()
    test_conn_slot_stale_generation_returns_negative_one()
    print("OK")
