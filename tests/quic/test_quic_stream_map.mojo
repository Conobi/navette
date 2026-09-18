# tests/test_quic_stream_map.mojo
# TDD tests for StreamMap module (src/quic/stream_map.mojo).
# RFC 9000 §4 — stream concurrency, connection-level flow control.
#
# Run with:
#   uv run mojo run -I . -D ASSERT=all tests/test_quic_stream_map.mojo

from tests._test_util import assert_true, assert_false, assert_equal_int
from navette.quic.stream_map import StreamMap
from navette.quic.stream import (
    SendState,
    RecvState,
    Stream,
)


# ── Setup helpers ──────────────────────────────────────────────────────────────


def make_stream_map(is_server: Bool) -> StreamMap:
    return StreamMap(
        is_server=is_server,
        conn_recv_limit=UInt64(10485760),
        conn_recv_window=UInt64(10485760),
        conn_send_limit=UInt64(0),
        local_max_streams_bidi=UInt64(100),
        local_max_streams_uni=UInt64(100),
        local_window_bidi_local=UInt64(1048576),
        local_window_bidi_remote=UInt64(1048576),
        local_window_uni=UInt64(1048576),
    )


def setup_peer_limits(mut sm: StreamMap, max_streams_bidi: UInt64 = UInt64(100)) raises:
    sm.set_peer_limits(
        max_streams_bidi=max_streams_bidi,
        max_streams_uni=UInt64(100),
        stream_fc_bidi_local=UInt64(1048576),
        stream_fc_bidi_remote=UInt64(1048576),
        stream_fc_uni=UInt64(1048576),
        conn_fc_send_limit=UInt64(10485760),
    )


# ── Tests ──────────────────────────────────────────────────────────────────────


def test_open_stream_bidi_client() raises:
    """Client opens 3 bidi streams — IDs should be 0, 4, 8."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    var id0 = sm.open_stream(bidi=True)
    var id1 = sm.open_stream(bidi=True)
    var id2 = sm.open_stream(bidi=True)

    assert_equal_int(Int(id0), 0, "client bidi 0: id=0")
    assert_equal_int(Int(id1), 4, "client bidi 1: id=4")
    assert_equal_int(Int(id2), 8, "client bidi 2: id=8")
    assert_equal_int(Int(sm.local_opened_bidi), 3, "client bidi: local_opened_bidi=3")
    assert_equal_int(len(sm.streams), 3, "client bidi: 3 streams in dict")
    print("  test_open_stream_bidi_client: PASS")


def test_open_stream_bidi_server() raises:
    """Server opens 3 bidi streams — IDs should be 1, 5, 9."""
    var sm = make_stream_map(True)
    setup_peer_limits(sm)

    var id0 = sm.open_stream(bidi=True)
    var id1 = sm.open_stream(bidi=True)
    var id2 = sm.open_stream(bidi=True)

    assert_equal_int(Int(id0), 1, "server bidi 0: id=1")
    assert_equal_int(Int(id1), 5, "server bidi 1: id=5")
    assert_equal_int(Int(id2), 9, "server bidi 2: id=9")
    assert_equal_int(Int(sm.local_opened_bidi), 3, "server bidi: local_opened_bidi=3")
    print("  test_open_stream_bidi_server: PASS")


def test_open_stream_uni_client() raises:
    """Client opens 2 uni streams — IDs should be 2, 6."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    var id0 = sm.open_stream(bidi=False)
    var id1 = sm.open_stream(bidi=False)

    assert_equal_int(Int(id0), 2, "client uni 0: id=2")
    assert_equal_int(Int(id1), 6, "client uni 1: id=6")
    assert_equal_int(Int(sm.local_opened_uni), 2, "client uni: local_opened_uni=2")
    print("  test_open_stream_uni_client: PASS")


def test_open_stream_limit() raises:
    """Peer allows 2 bidi streams — 3rd open should raise."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm, max_streams_bidi=UInt64(2))

    _ = sm.open_stream(bidi=True)
    _ = sm.open_stream(bidi=True)

    var caught = False
    try:
        _ = sm.open_stream(bidi=True)
    except e:
        if "stream limit" in String(e):
            caught = True
    assert_true(caught, "open_stream limit: should raise on 3rd stream")
    print("  test_open_stream_limit: PASS")


def test_peer_stream_creation_basic() raises:
    """Server receives frame for client stream 0 — creates it, returns [0]."""
    var sm = make_stream_map(True)  # server
    setup_peer_limits(sm)

    # Stream 0 is client-initiated bidi (bit0=0, bit1=0)
    var new_ids = sm.get_or_create_peer_stream(UInt64(0))
    assert_equal_int(len(new_ids), 1, "peer basic: 1 new stream created")
    assert_equal_int(Int(new_ids[0]), 0, "peer basic: stream id=0")
    assert_equal_int(len(sm.streams), 1, "peer basic: 1 stream in dict")
    print("  test_peer_stream_creation_basic: PASS")


def test_peer_stream_creation_implicit() raises:
    """Server receives frame for client stream 8 (ordinal 2) — implicitly creates 0, 4, 8."""
    var sm = make_stream_map(True)  # server
    setup_peer_limits(sm)

    # Stream 8: client-bidi, ordinal=2 (0-based)
    var new_ids = sm.get_or_create_peer_stream(UInt64(8))
    assert_equal_int(len(new_ids), 3, "peer implicit: 3 new streams created")
    assert_equal_int(Int(new_ids[0]), 0, "peer implicit: first id=0")
    assert_equal_int(Int(new_ids[1]), 4, "peer implicit: second id=4")
    assert_equal_int(Int(new_ids[2]), 8, "peer implicit: third id=8")
    assert_equal_int(Int(sm.peer_opened_bidi), 3, "peer implicit: peer_opened_bidi=3")
    assert_equal_int(len(sm.streams), 3, "peer implicit: 3 streams in dict")
    print("  test_peer_stream_creation_implicit: PASS")


def test_peer_stream_limit_exceeded() raises:
    """Limit=2 bidi streams; peer sends frame for stream 8 (ordinal 2) → STREAM_LIMIT_ERROR."""
    # StreamMap with only 2 bidi streams allowed from peer
    var sm = StreamMap(
        is_server=True,
        conn_recv_limit=UInt64(10485760),
        conn_recv_window=UInt64(10485760),
        conn_send_limit=UInt64(0),
        local_max_streams_bidi=UInt64(2),
        local_max_streams_uni=UInt64(100),
        local_window_bidi_local=UInt64(1048576),
        local_window_bidi_remote=UInt64(1048576),
        local_window_uni=UInt64(1048576),
    )
    setup_peer_limits(sm)

    var caught = False
    try:
        # Stream 8 = client bidi ordinal 2, which exceeds local_max_streams_bidi=2
        _ = sm.get_or_create_peer_stream(UInt64(8))
    except e:
        if "STREAM_LIMIT_ERROR" in String(e):
            caught = True
    assert_true(caught, "peer limit: should raise STREAM_LIMIT_ERROR")
    print("  test_peer_stream_limit_exceeded: PASS")


def test_peer_stream_already_exists() raises:
    """Second call for same stream ID returns empty list."""
    var sm = make_stream_map(True)
    setup_peer_limits(sm)

    var new_ids1 = sm.get_or_create_peer_stream(UInt64(0))
    assert_equal_int(len(new_ids1), 1, "peer exists first call: 1 new")

    var new_ids2 = sm.get_or_create_peer_stream(UInt64(0))
    assert_equal_int(len(new_ids2), 0, "peer exists second call: 0 new (already exists)")
    assert_equal_int(len(sm.streams), 1, "peer exists: still 1 stream")
    print("  test_peer_stream_already_exists: PASS")


def test_set_peer_limits_retro_bumps_zero_rtt_streams() raises:
    """Peer-initiated bidi streams created BEFORE set_peer_limits — i.e.
    during 0-RTT processing on the server — start with `fc_send.limit=0`.
    `set_peer_limits` must retroactively raise their send limit to the
    peer's advertised value so server response data can flow on those
    streams. Without this, the server's STREAM frames for stream 0 are
    silent-dropped at the `fc.available()==0` gate in
    `_build_app_frames` and the H3 response never reaches the peer
    (R03/R04 regression caught this).
    """
    var sm = make_stream_map(True)  # server side

    # Create a peer-initiated bidi stream BEFORE setting peer limits.
    # This mirrors what `_handle_stream_frame` does when a 0-RTT
    # packet carries a STREAM frame for stream 0 prior to the peer's
    # transport parameters being parsed in `_on_handshake_complete`.
    var new_ids = sm.get_or_create_peer_stream(UInt64(0))
    assert_equal_int(len(new_ids), 1, "peer-initiated stream 0 created")
    assert_true(0 in sm.streams, "stream 0 in map")

    # The pre-handshake fc_send limit is 0 (peer_stream_fc_limit_bidi_local
    # defaults to 0 until set_peer_limits is called).
    var stream_pre = sm.streams[0][].copy()
    assert_true(Bool(stream_pre.fc_send), "stream 0 has fc_send")
    var fc_pre = stream_pre.fc_send.value().copy()
    assert_equal_int(Int(fc_pre.limit), 0, "fc_send.limit=0 before set_peer_limits")

    # Apply peer limits as if the handshake just completed.
    setup_peer_limits(sm)

    # Stream 0's fc_send should now be bumped to 1048576 (the bidi_local
    # limit from setup_peer_limits).
    var stream_post = sm.streams[0][].copy()
    assert_true(Bool(stream_post.fc_send), "stream 0 retains fc_send")
    var fc_post = stream_post.fc_send.value().copy()
    assert_equal_int(
        Int(fc_post.limit),
        1048576,
        "fc_send.limit retroactively raised to bidi_local",
    )
    print("  test_set_peer_limits_retro_bumps_zero_rtt_streams: PASS")


def test_set_peer_limits_does_not_lower_existing_fc_send() raises:
    """`set_peer_limits` retroactive bump must be MONOTONIC.

    `FlowControl.ensure_limit` raises a limit but never lowers it. If a
    peer-initiated bidi stream has already had its `fc_send.limit`
    elevated above the peer's advertised value (e.g. by a future
    MAX_STREAM_DATA bump arriving out-of-band, or by a test fixture
    pre-loading the limit), the post-handshake `set_peer_limits` retro
    pass must NOT clobber that higher limit. This guards against a
    regression where `fc.limit = target_limit` (unconditional assign)
    would silently shrink a stream's send window during the 0-RTT →
    1-RTT transition.
    """
    var sm = make_stream_map(True)  # server side

    # Create peer-initiated bidi stream 0 before peer limits are set.
    _ = sm.get_or_create_peer_stream(UInt64(0))
    assert_true(0 in sm.streams, "stream 0 in map")

    # Manually elevate fc_send.limit to 2 MiB — HIGHER than the 1 MiB
    # `setup_peer_limits` will advertise as stream_fc_bidi_local.
    var stream_boost = Stream(copy=sm.streams[0][])
    assert_true(Bool(stream_boost.fc_send), "stream 0 has fc_send")
    var fc_boost = stream_boost.fc_send.value().copy()
    var ELEVATED: UInt64 = UInt64(2097152)  # 2 MiB
    fc_boost.ensure_limit(ELEVATED)
    assert_equal_int(
        Int(fc_boost.limit), Int(ELEVATED),
        "pre-handshake fc_send.limit elevated to 2 MiB",
    )
    stream_boost.fc_send = fc_boost^
    sm.set_stream(0, stream_boost^)

    # Apply peer limits (advertises 1 MiB stream_fc_bidi_local).
    setup_peer_limits(sm)

    # The 2 MiB elevated limit must survive — set_peer_limits MUST NOT
    # lower it to the peer's 1 MiB advertisement.
    var stream_post = sm.streams[0][].copy()
    assert_true(Bool(stream_post.fc_send), "stream 0 retains fc_send")
    var fc_post = stream_post.fc_send.value().copy()
    assert_equal_int(
        Int(fc_post.limit),
        Int(ELEVATED),
        "fc_send.limit must NOT drop from 2 MiB to peer's 1 MiB",
    )
    print("  test_set_peer_limits_does_not_lower_existing_fc_send: PASS")


def test_maybe_cleanup_bidi_both_terminal() raises:
    """Local bidi stream with both sides terminal → cleanup returns True, Dict empty."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    var id = sm.open_stream(bidi=True)
    assert_equal_int(len(sm.streams), 1, "before cleanup: 1 stream")

    # Mark both sides terminal
    var s = sm.get_stream(Int(id))
    s.send_state = SendState.DATA_RECVD
    s.recv_state = RecvState.DATA_READ
    sm.set_stream(Int(id), s^)

    var removed = sm.maybe_cleanup(Int(id))
    assert_true(removed, "cleanup bidi both terminal: returns True")
    assert_equal_int(len(sm.streams), 0, "cleanup bidi both terminal: Dict empty")
    print("  test_maybe_cleanup_bidi_both_terminal: PASS")


def test_maybe_cleanup_bidi_one_terminal() raises:
    """Local bidi stream with only send terminal → cleanup returns False."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    var id = sm.open_stream(bidi=True)

    # Mark only send side terminal
    var s = sm.get_stream(Int(id))
    s.send_state = SendState.DATA_RECVD
    # recv_state stays RecvState.RECV (not terminal)
    sm.set_stream(Int(id), s^)

    var removed = sm.maybe_cleanup(Int(id))
    assert_false(removed, "cleanup bidi one terminal: returns False")
    assert_equal_int(len(sm.streams), 1, "cleanup bidi one terminal: still 1 stream")
    print("  test_maybe_cleanup_bidi_one_terminal: PASS")


def test_maybe_cleanup_peer_bidi_increments_completed() raises:
    """Peer bidi fully closed → peer_completed_bidi incremented to 1."""
    var sm = make_stream_map(True)  # server
    setup_peer_limits(sm)

    # Create peer stream (client-initiated)
    _ = sm.get_or_create_peer_stream(UInt64(0))

    # Mark both sides terminal
    var s = sm.get_stream(0)
    s.send_state = SendState.DATA_RECVD
    s.recv_state = RecvState.DATA_READ
    sm.set_stream(0, s^)

    var removed = sm.maybe_cleanup(0)
    assert_true(removed, "peer bidi completed: removed")
    assert_equal_int(Int(sm.peer_completed_bidi), 1, "peer bidi completed: peer_completed_bidi=1")
    print("  test_maybe_cleanup_peer_bidi_increments_completed: PASS")


def test_max_streams_update_threshold() raises:
    """Initial=4 peer streams, complete 1 → new limit = 5, needs_max_streams_bidi=True."""
    var sm = StreamMap(
        is_server=True,
        conn_recv_limit=UInt64(10485760),
        conn_recv_window=UInt64(10485760),
        conn_send_limit=UInt64(0),
        local_max_streams_bidi=UInt64(4),
        local_max_streams_uni=UInt64(4),
        local_window_bidi_local=UInt64(1048576),
        local_window_bidi_remote=UInt64(1048576),
        local_window_uni=UInt64(1048576),
    )
    setup_peer_limits(sm)

    # Create and close one peer bidi stream
    _ = sm.get_or_create_peer_stream(UInt64(0))
    var s = sm.get_stream(0)
    s.send_state = SendState.DATA_RECVD
    s.recv_state = RecvState.DATA_READ
    sm.set_stream(0, s^)
    _ = sm.maybe_cleanup(0)

    assert_equal_int(Int(sm.peer_completed_bidi), 1, "max_streams update: completed=1")
    assert_true(sm.needs_max_streams_bidi, "max_streams update: needs_max_streams_bidi=True")
    assert_equal_int(Int(sm.local_max_streams_bidi), 5, "max_streams update: new limit=5")
    print("  test_max_streams_update_threshold: PASS")


def test_sendable_deque_round_robin() raises:
    """Add 3 stream IDs, Deque popleft returns them in FIFO order."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    sm.add_sendable(10)
    sm.add_sendable(20)
    sm.add_sendable(30)

    assert_equal_int(len(sm.sendable_queue), 3, "deque round robin: 3 entries")
    assert_equal_int(len(sm.sendable_set), 3, "deque round robin: set has 3")

    var id0 = sm.sendable_queue.popleft()
    var id1 = sm.sendable_queue.popleft()
    var id2 = sm.sendable_queue.popleft()

    assert_equal_int(id0, 10, "deque round robin: first=10")
    assert_equal_int(id1, 20, "deque round robin: second=20")
    assert_equal_int(id2, 30, "deque round robin: third=30")
    assert_equal_int(len(sm.sendable_queue), 0, "deque round robin: queue empty")
    print("  test_sendable_deque_round_robin: PASS")


def test_sendable_remove() raises:
    """Remove middle element — set shrinks, Deque retains the stale entry."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    sm.add_sendable(10)
    sm.add_sendable(20)
    sm.add_sendable(30)
    assert_equal_int(len(sm.sendable_set), 3, "sendable remove: set=3 before remove")

    sm.remove_sendable(20)
    assert_equal_int(len(sm.sendable_set), 2, "sendable remove: set=2 after remove")

    # 20 should not be in the set anymore
    assert_false(20 in sm.sendable_set, "sendable remove: 20 not in set")

    # 10 and 30 should still be there
    assert_true(10 in sm.sendable_set, "sendable remove: 10 still in set")
    assert_true(30 in sm.sendable_set, "sendable remove: 30 still in set")

    # Deque still has the stale entry (lazy eviction)
    assert_equal_int(len(sm.sendable_queue), 3, "sendable remove: queue=3 (lazy)")
    print("  test_sendable_remove: PASS")


def test_stream_ref_mutation_visible() raises:
    """Mutations through `stream_ref` land in the map (no hidden copy)."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)
    var sid = Int(sm.open_stream(bidi=True))
    assert_true(sm.has_stream(sid), "has_stream: opened stream present")
    assert_false(sm.has_stream(sid + 4), "has_stream: unopened id absent")

    var payload = List[Byte]()
    for i in range(300):
        payload.append(UInt8(i % 256))
    ref s = sm.stream_ref(sid)
    s.send_buf.value().write(Span(payload), True)
    s.needs_max_stream_data = True
    _ = s.send_buf.value().make_frame(UInt64(sid), 100)

    var seen = sm.get_stream(sid)
    assert_true(seen.needs_max_stream_data, "stream_ref: flag write visible")
    assert_equal_int(len(seen.send_buf.value().data), 300, "stream_ref: buffered bytes visible")
    assert_equal_int(Int(seen.send_buf.value().unsent_offset), 100, "stream_ref: framing progress visible")
    assert_true(seen.send_buf.value().fin, "stream_ref: FIN visible")

    # A second borrow sees the first borrow's mutation.
    ref again = sm.stream_ref(sid)
    _ = again.send_buf.value().make_frame(UInt64(sid), 100)
    assert_equal_int(
        Int(sm.get_stream(sid).send_buf.value().unsent_offset), 200,
        "stream_ref: repeated in-place framing accumulates",
    )
    print("  test_stream_ref_mutation_visible: PASS")


def test_stream_ref_missing_raises() raises:
    """`stream_ref` on an unknown id raises the same error as `get_stream`."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)
    var raised = False
    var msg = String("")
    try:
        ref s = sm.stream_ref(12)
        _ = s.id
    except e:
        raised = True
        msg = String(e)
    assert_true(raised, "stream_ref: missing id raises")
    var get_msg = String("")
    try:
        _ = sm.get_stream(12)
    except e:
        get_msg = String(e)
    assert_true(msg == get_msg, "stream_ref: same error text as get_stream")
    print("  test_stream_ref_missing_raises: PASS")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() raises:
    print("test_quic_stream_map:")

    test_open_stream_bidi_client()
    test_open_stream_bidi_server()
    test_open_stream_uni_client()
    test_open_stream_limit()
    test_peer_stream_creation_basic()
    test_peer_stream_creation_implicit()
    test_peer_stream_limit_exceeded()
    test_peer_stream_already_exists()
    test_set_peer_limits_retro_bumps_zero_rtt_streams()
    test_set_peer_limits_does_not_lower_existing_fc_send()
    test_maybe_cleanup_bidi_both_terminal()
    test_maybe_cleanup_bidi_one_terminal()
    test_maybe_cleanup_peer_bidi_increments_completed()
    test_max_streams_update_threshold()
    test_sendable_deque_round_robin()
    test_sendable_remove()
    test_stream_ref_mutation_visible()
    test_stream_ref_missing_raises()
    test_try_stream_ptr_found()
    test_try_stream_ptr_not_found()
    test_sendable_deque_add_dedup()
    test_sendable_deque_remove_lazy()
    test_mark_control_lists()

    print("All test_quic_stream_map tests passed.")


def test_try_stream_ptr_found() raises:
    """Verify try_stream_ptr returns the pointer for an existing stream."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)
    _ = sm.open_stream(bidi=True)  # creates stream 0
    var result = sm.try_stream_ptr(0)
    assert_true(Bool(result), "expected Some for stream 0")
    print("  test_try_stream_ptr_found: PASS")


def test_try_stream_ptr_not_found() raises:
    """Verify try_stream_ptr returns None for a missing stream."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)
    var result = sm.try_stream_ptr(999)
    assert_false(Bool(result), "expected None for stream 999")
    print("  test_try_stream_ptr_not_found: PASS")


def test_sendable_deque_add_dedup() raises:
    """Adding the same stream ID twice produces one entry in the set and Deque."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    sm.add_sendable(42)
    sm.add_sendable(42)

    assert_equal_int(len(sm.sendable_set), 1, "deque add dedup: set has 1 entry")
    assert_equal_int(len(sm.sendable_queue), 1, "deque add dedup: queue has 1 entry")
    print("  test_sendable_deque_add_dedup: PASS")


def test_sendable_deque_remove_lazy() raises:
    """After removal the set is empty but the Deque retains the stale entry."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    sm.add_sendable(7)
    assert_equal_int(len(sm.sendable_set), 1, "deque remove lazy: set=1 before remove")
    assert_equal_int(len(sm.sendable_queue), 1, "deque remove lazy: queue=1 before remove")

    sm.remove_sendable(7)
    assert_equal_int(len(sm.sendable_set), 0, "deque remove lazy: set empty after remove")
    assert_equal_int(len(sm.sendable_queue), 1, "deque remove lazy: queue still has stale entry")
    print("  test_sendable_deque_remove_lazy: PASS")


def test_mark_control_lists() raises:
    """Each mark_* method appends to the corresponding control list."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    sm.mark_max_stream_data(4)
    sm.mark_reset(8)
    sm.mark_stop_sending(12)

    assert_equal_int(len(sm.control_max_stream_data), 1, "mark control: max_stream_data len=1")
    assert_equal_int(sm.control_max_stream_data[0], 4, "mark control: max_stream_data[0]=4")
    assert_equal_int(len(sm.control_reset), 1, "mark control: reset len=1")
    assert_equal_int(sm.control_reset[0], 8, "mark control: reset[0]=8")
    assert_equal_int(len(sm.control_stop_sending), 1, "mark control: stop_sending len=1")
    assert_equal_int(sm.control_stop_sending[0], 12, "mark control: stop_sending[0]=12")
    print("  test_mark_control_lists: PASS")
