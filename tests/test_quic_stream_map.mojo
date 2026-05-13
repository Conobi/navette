# tests/test_quic_stream_map.mojo
# TDD tests for StreamMap module (src/quic/stream_map.mojo).
# RFC 9000 §4 — stream concurrency, connection-level flow control.
#
# Run with:
#   uv run mojo run -I . -D ASSERT=all tests/test_quic_stream_map.mojo

from tests._test_util import assert_true, assert_false, assert_equal_int
from mojo_net.quic.stream_map import StreamMap
from mojo_net.quic.stream import (
    SEND_DATA_RECVD,
    RECV_DATA_READ,
    RECV_RECV,
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


def setup_peer_limits(mut sm: StreamMap, max_streams_bidi: UInt64 = UInt64(100)):
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


def test_maybe_cleanup_bidi_both_terminal() raises:
    """Local bidi stream with both sides terminal → cleanup returns True, Dict empty."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    var id = sm.open_stream(bidi=True)
    assert_equal_int(len(sm.streams), 1, "before cleanup: 1 stream")

    # Mark both sides terminal
    var s = sm.get_stream(Int(id))
    s.send_state = SEND_DATA_RECVD
    s.recv_state = RECV_DATA_READ
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
    s.send_state = SEND_DATA_RECVD
    # recv_state stays RECV_RECV (not terminal)
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
    s.send_state = SEND_DATA_RECVD
    s.recv_state = RECV_DATA_READ
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
    s.send_state = SEND_DATA_RECVD
    s.recv_state = RECV_DATA_READ
    sm.set_stream(0, s^)
    _ = sm.maybe_cleanup(0)

    assert_equal_int(Int(sm.peer_completed_bidi), 1, "max_streams update: completed=1")
    assert_true(sm.needs_max_streams_bidi, "max_streams update: needs_max_streams_bidi=True")
    assert_equal_int(Int(sm.local_max_streams_bidi), 5, "max_streams update: new limit=5")
    print("  test_max_streams_update_threshold: PASS")


def test_sendable_list_round_robin() raises:
    """Add 3 stream IDs, get_next_sendable returns them in rotation."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    sm.add_sendable(10)
    sm.add_sendable(20)
    sm.add_sendable(30)

    # First rotation
    var id0 = sm.get_next_sendable()
    assert_true(id0.__bool__(), "round robin: first call returns Some")
    var id1 = sm.get_next_sendable()
    assert_true(id1.__bool__(), "round robin: second call returns Some")
    var id2 = sm.get_next_sendable()
    assert_true(id2.__bool__(), "round robin: third call returns Some")

    # All 3 unique values returned
    var v0 = id0.value()
    var v1 = id1.value()
    var v2 = id2.value()
    assert_true(v0 != v1 or v1 != v2 or v0 != v2, "round robin: not all same")

    # After a full rotation, wraps back
    var id3 = sm.get_next_sendable()
    assert_true(id3.__bool__(), "round robin: wraps around")
    print("  test_sendable_list_round_robin: PASS")


def test_sendable_remove() raises:
    """Remove middle element from sendable list — list shrinks correctly."""
    var sm = make_stream_map(False)
    setup_peer_limits(sm)

    sm.add_sendable(10)
    sm.add_sendable(20)
    sm.add_sendable(30)
    assert_equal_int(len(sm.sendable_ids), 3, "sendable remove: 3 before remove")

    sm.remove_sendable(20)
    assert_equal_int(len(sm.sendable_ids), 2, "sendable remove: 2 after remove")

    # 20 should not be in the list anymore
    var found = False
    for i in range(len(sm.sendable_ids)):
        if sm.sendable_ids[i] == 20:
            found = True
    assert_false(found, "sendable remove: 20 not in list")

    # 10 and 30 should still be there
    var has10 = False
    var has30 = False
    for i in range(len(sm.sendable_ids)):
        if sm.sendable_ids[i] == 10:
            has10 = True
        if sm.sendable_ids[i] == 30:
            has30 = True
    assert_true(has10, "sendable remove: 10 still in list")
    assert_true(has30, "sendable remove: 30 still in list")
    print("  test_sendable_remove: PASS")


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
    test_maybe_cleanup_bidi_both_terminal()
    test_maybe_cleanup_bidi_one_terminal()
    test_maybe_cleanup_peer_bidi_increments_completed()
    test_max_streams_update_threshold()
    test_sendable_list_round_robin()
    test_sendable_remove()

    print("All test_quic_stream_map tests passed.")
