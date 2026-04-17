# tests/test_quic_stream.mojo
# TDD tests for Stream module (src/quic/stream.mojo).
# RFC 9000 §2, §3 — per-stream state machines, send/recv buffers.
#
# Run with:
#   uv run mojo run -I . -D ASSERT=all tests/test_quic_stream.mojo

from tests._test_util import assert_true, assert_false, assert_equal_int
from src.quic.stream import (
    # State constants
    SEND_READY,
    SEND_SEND,
    SEND_DATA_SENT,
    SEND_DATA_RECVD,
    SEND_RESET_SENT,
    SEND_RESET_RECVD,
    RECV_RECV,
    RECV_SIZE_KNOWN,
    RECV_DATA_RECVD,
    RECV_DATA_READ,
    RECV_STOP_SENDING_SENT,
    RECV_RESET_RECVD,
    RECV_RESET_READ,
    # Helper functions
    stream_is_bidi,
    stream_is_local,
    stream_is_client_initiated,
    send_state_is_terminal,
    recv_state_is_terminal,
    # Structs
    RecvBuf,
    SendBuf,
    Stream,
)


# ── Stream ID helpers ─────────────────────────────────────────────────────────


def test_stream_id_helpers() raises:
    # RFC 9000 §2.1: stream ID low bits
    # bit 0: 0=client, 1=server
    # bit 1: 0=bidi, 1=uni
    # ID 0: client bidi
    assert_true(stream_is_bidi(UInt64(0)), "0 is bidi")
    assert_true(stream_is_client_initiated(UInt64(0)), "0 is client-initiated")
    assert_false(stream_is_local(UInt64(0), True), "0 is not local for server")
    assert_true(stream_is_local(UInt64(0), False), "0 is local for client")

    # ID 1: server bidi
    assert_true(stream_is_bidi(UInt64(1)), "1 is bidi")
    assert_false(stream_is_client_initiated(UInt64(1)), "1 is server-initiated")
    assert_true(stream_is_local(UInt64(1), True), "1 is local for server")
    assert_false(stream_is_local(UInt64(1), False), "1 is not local for client")

    # ID 2: client uni
    assert_false(stream_is_bidi(UInt64(2)), "2 is uni")
    assert_true(stream_is_client_initiated(UInt64(2)), "2 is client-initiated")

    # ID 3: server uni
    assert_false(stream_is_bidi(UInt64(3)), "3 is uni")
    assert_false(stream_is_client_initiated(UInt64(3)), "3 is server-initiated")

    # ID 4: next client bidi
    assert_true(stream_is_bidi(UInt64(4)), "4 is bidi")
    assert_true(stream_is_client_initiated(UInt64(4)), "4 is client-initiated")

    # ID 5: next server bidi
    assert_true(stream_is_bidi(UInt64(5)), "5 is bidi")
    assert_false(stream_is_client_initiated(UInt64(5)), "5 is server-initiated")

    print("  test_stream_id_helpers: PASS")


def test_send_state_terminal() raises:
    assert_true(send_state_is_terminal(SEND_DATA_RECVD), "SEND_DATA_RECVD is terminal")
    assert_true(send_state_is_terminal(SEND_RESET_RECVD), "SEND_RESET_RECVD is terminal")
    assert_false(send_state_is_terminal(SEND_READY), "SEND_READY is not terminal")
    assert_false(send_state_is_terminal(SEND_SEND), "SEND_SEND is not terminal")
    assert_false(send_state_is_terminal(SEND_DATA_SENT), "SEND_DATA_SENT is not terminal")
    assert_false(send_state_is_terminal(SEND_RESET_SENT), "SEND_RESET_SENT is not terminal")
    print("  test_send_state_terminal: PASS")


def test_recv_state_terminal() raises:
    assert_true(recv_state_is_terminal(RECV_DATA_READ), "RECV_DATA_READ is terminal")
    assert_true(recv_state_is_terminal(RECV_RESET_READ), "RECV_RESET_READ is terminal")
    assert_false(recv_state_is_terminal(RECV_RECV), "RECV_RECV is not terminal")
    assert_false(recv_state_is_terminal(RECV_SIZE_KNOWN), "RECV_SIZE_KNOWN is not terminal")
    assert_false(recv_state_is_terminal(RECV_DATA_RECVD), "RECV_DATA_RECVD is not terminal")
    assert_false(recv_state_is_terminal(RECV_STOP_SENDING_SENT), "RECV_STOP_SENDING_SENT is not terminal")
    assert_false(recv_state_is_terminal(RECV_RESET_RECVD), "RECV_RESET_RECVD is not terminal")
    print("  test_recv_state_terminal: PASS")


# ── RecvBuf ───────────────────────────────────────────────────────────────────


def test_recv_buf_in_order() raises:
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    var data0 = List[UInt8]()
    for i in range(5):
        data0.append(UInt8(i))
    _ = buf.write(UInt64(0), Span(data0), False, fin_offset)

    var data1 = List[UInt8]()
    for i in range(5, 10):
        data1.append(UInt8(i))
    _ = buf.write(UInt64(5), Span(data1), False, fin_offset)

    var result = buf.read(fin_offset)
    var bytes = result[0].copy()
    var fin_reached = result[1]

    assert_equal_int(len(bytes), 10, "in-order: got 10 bytes")
    assert_false(fin_reached, "in-order: no fin")
    for i in range(10):
        assert_equal_int(Int(bytes[i]), i, "in-order: byte " + String(i))
    print("  test_recv_buf_in_order: PASS")


def test_recv_buf_out_of_order() raises:
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    var data1 = List[UInt8]()
    for i in range(5, 10):
        data1.append(UInt8(i))
    _ = buf.write(UInt64(5), Span(data1), False, fin_offset)

    var data0 = List[UInt8]()
    for i in range(5):
        data0.append(UInt8(i))
    _ = buf.write(UInt64(0), Span(data0), False, fin_offset)

    var result = buf.read(fin_offset)
    var bytes = result[0].copy()
    var fin_reached = result[1]

    assert_equal_int(len(bytes), 10, "out-of-order: got 10 bytes")
    assert_false(fin_reached, "out-of-order: no fin")
    for i in range(10):
        assert_equal_int(Int(bytes[i]), i, "out-of-order: byte " + String(i))
    print("  test_recv_buf_out_of_order: PASS")


def test_recv_buf_overlapping() raises:
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    var data0 = List[UInt8]()
    for i in range(10):
        data0.append(UInt8(i))
    _ = buf.write(UInt64(0), Span(data0), False, fin_offset)

    # Overlapping write: bytes [5,15), first 5 overlap, last 5 are new
    var data1 = List[UInt8]()
    for i in range(5, 15):
        data1.append(UInt8(100 + i))  # different values to test accept-first-copy
    _ = buf.write(UInt64(5), Span(data1), False, fin_offset)

    var result = buf.read(fin_offset)
    var bytes = result[0].copy()

    assert_equal_int(len(bytes), 15, "overlapping: got 15 bytes")
    # First 10 bytes should be original (accept-first-copy)
    for i in range(10):
        assert_equal_int(Int(bytes[i]), i, "overlapping: original byte " + String(i))
    # Bytes 10-14 are from second write (offset 10-14 → 100+10..100+14)
    for i in range(10, 15):
        assert_equal_int(Int(bytes[i]), 100 + i, "overlapping: new byte " + String(i))
    print("  test_recv_buf_overlapping: PASS")


def test_recv_buf_gap_limit() raises:
    # Set max_gaps to 2 by using recv_window that gives max_gaps=2
    # max_gaps = max(64, recv_window // 512) — so to get 2 we need to use
    # small recv_window; but max(64, ...) means minimum is 64.
    # We need to set max_gaps directly or use a large window
    # Actually per spec: max_gaps = max(64, recv_window // 512)
    # For max_gaps=64, we need recv_window < 512*64 = 32768 → window=256 → max_gaps=max(64,0)=64
    # So minimum max_gaps is 64. Let's create 65 gaps:
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(256))  # max_gaps = max(64, 0) = 64

    var caught = False
    try:
        # Create 65 non-contiguous writes starting at even offsets (each 1 byte apart with gaps)
        # Each write at offset 2*i creates a gap before it (except the first)
        for i in range(65):
            var d = List[UInt8]()
            d.append(UInt8(i))
            _ = buf.write(UInt64(i * 2 + 2), Span(d), False, fin_offset)
    except e:
        if "PROTOCOL_VIOLATION" in String(e):
            caught = True

    assert_true(caught, "gap limit: should raise PROTOCOL_VIOLATION when gaps exceed max_gaps")
    print("  test_recv_buf_gap_limit: PASS")


def test_recv_buf_fin() raises:
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    var data = List[UInt8]()
    for i in range(5):
        data.append(UInt8(i))
    _ = buf.write(UInt64(0), Span(data), True, fin_offset)

    var result = buf.read(fin_offset)
    var bytes = result[0].copy()
    var fin_reached = result[1]

    assert_equal_int(len(bytes), 5, "fin: got 5 bytes")
    assert_true(fin_reached, "fin: fin_reached is True")
    print("  test_recv_buf_fin: PASS")


def test_recv_buf_fin_mismatch() raises:
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    # First FIN at offset 10
    var data0 = List[UInt8]()
    for i in range(10):
        data0.append(UInt8(i))
    _ = buf.write(UInt64(0), Span(data0), True, fin_offset)

    # Second FIN with different final size → FINAL_SIZE_ERROR
    var caught = False
    try:
        var data1 = List[UInt8]()
        for i in range(5):
            data1.append(UInt8(i))
        _ = buf.write(UInt64(0), Span(data1), True, fin_offset)
    except e:
        if "FINAL_SIZE_ERROR" in String(e):
            caught = True

    assert_true(caught, "fin mismatch: should raise FINAL_SIZE_ERROR")
    print("  test_recv_buf_fin_mismatch: PASS")


def test_recv_buf_data_beyond_fin() raises:
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    # Establish FIN at offset 5
    var data0 = List[UInt8]()
    for i in range(5):
        data0.append(UInt8(i))
    _ = buf.write(UInt64(0), Span(data0), True, fin_offset)

    # Data that extends past final size → FINAL_SIZE_ERROR
    var caught = False
    try:
        var data1 = List[UInt8]()
        for i in range(3):
            data1.append(UInt8(i))
        _ = buf.write(UInt64(4), Span(data1), False, fin_offset)  # ends at 7 > 5
    except e:
        if "FINAL_SIZE_ERROR" in String(e):
            caught = True

    assert_true(caught, "data beyond fin: should raise FINAL_SIZE_ERROR")
    print("  test_recv_buf_data_beyond_fin: PASS")


def test_recv_buf_empty_fin() raises:
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    # Zero-length data with fin=True
    var empty = List[UInt8]()
    _ = buf.write(UInt64(0), Span(empty), True, fin_offset)

    var result = buf.read(fin_offset)
    var bytes = result[0].copy()
    var fin_reached = result[1]

    assert_equal_int(len(bytes), 0, "empty fin: 0 bytes")
    assert_true(fin_reached, "empty fin: fin_reached is True")
    print("  test_recv_buf_empty_fin: PASS")


def test_recv_buf_new_bytes_count() raises:
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    # Write [0,10) → 10 new bytes
    var data0 = List[UInt8]()
    for i in range(10):
        data0.append(UInt8(i))
    var count0 = buf.write(UInt64(0), Span(data0), False, fin_offset)
    assert_equal_int(Int(count0), 10, "new bytes: first write = 10")

    # Duplicate write [0,10) → 0 new bytes
    var data1 = List[UInt8]()
    for i in range(10):
        data1.append(UInt8(i))
    var count1 = buf.write(UInt64(0), Span(data1), False, fin_offset)
    assert_equal_int(Int(count1), 0, "new bytes: duplicate = 0")

    # Overlapping write [5,15) → 5 new bytes
    var data2 = List[UInt8]()
    for i in range(10):
        data2.append(UInt8(i))
    var count2 = buf.write(UInt64(5), Span(data2), False, fin_offset)
    assert_equal_int(Int(count2), 5, "new bytes: overlap = 5")

    # Gap write [20,25) → 5 new bytes
    var data3 = List[UInt8]()
    for i in range(5):
        data3.append(UInt8(i))
    var count3 = buf.write(UInt64(20), Span(data3), False, fin_offset)
    assert_equal_int(Int(count3), 5, "new bytes: gap write = 5")

    print("  test_recv_buf_new_bytes_count: PASS")


# ── SendBuf ───────────────────────────────────────────────────────────────────


def test_send_buf_write_and_frame() raises:
    var buf = SendBuf()

    var data = List[UInt8]()
    for i in range(10):
        data.append(UInt8(i))
    buf.write(Span(data), False)

    assert_true(buf.has_pending(), "send_buf: has pending after write")
    assert_equal_int(Int(buf.pending_len()), 10, "send_buf: pending_len = 10")

    var frame_opt = buf.make_frame(UInt64(4), 10)
    assert_true(frame_opt.__bool__(), "send_buf: make_frame returns Some")
    var frame = frame_opt.value().copy()
    assert_equal_int(Int(frame.stream_id), 4, "send_buf: stream_id = 4")
    assert_equal_int(Int(frame.offset), 0, "send_buf: offset = 0")
    assert_equal_int(len(frame.data), 10, "send_buf: data length = 10")
    assert_false(frame.fin, "send_buf: fin = False")

    # No more pending
    assert_false(buf.has_pending(), "send_buf: no pending after frame")
    print("  test_send_buf_write_and_frame: PASS")


def test_send_buf_on_ack_trims() raises:
    var buf = SendBuf()

    var data = List[UInt8]()
    for i in range(20):
        data.append(UInt8(i))
    buf.write(Span(data), False)

    # Frame all 20 bytes
    _ = buf.make_frame(UInt64(0), 20)

    # ACK first 10 bytes
    buf.on_ack(UInt64(0), UInt64(10))
    assert_equal_int(Int(buf.offset), 10, "on_ack: offset advanced to 10")
    assert_equal_int(Int(buf.acked_offset), 10, "on_ack: acked_offset = 10")

    # ACK bytes 10..20
    buf.on_ack(UInt64(10), UInt64(10))
    assert_equal_int(Int(buf.offset), 20, "on_ack: offset advanced to 20")
    assert_equal_int(Int(buf.acked_offset), 20, "on_ack: acked_offset = 20")

    print("  test_send_buf_on_ack_trims: PASS")


def test_send_buf_on_loss() raises:
    var buf = SendBuf()

    var data = List[UInt8]()
    for i in range(20):
        data.append(UInt8(i))
    buf.write(Span(data), False)

    # Frame first 10 bytes (unsent_offset = 10)
    _ = buf.make_frame(UInt64(0), 10)
    assert_equal_int(Int(buf.unsent_offset), 10, "before loss: unsent_offset = 10")

    # Loss of bytes [0,10)
    buf.on_loss(UInt64(0), UInt64(10))
    assert_equal_int(Int(buf.unsent_offset), 0, "on_loss: unsent_offset reset to 0")

    # ACK bytes 0..5 first, then loss of 5..10 → floor at acked
    buf.on_ack(UInt64(0), UInt64(5))
    buf.on_loss(UInt64(3), UInt64(7))  # loss includes acked region
    # unsent_offset must be >= acked_offset=5
    assert_true(buf.unsent_offset >= buf.acked_offset, "on_loss: floor at acked_offset")

    print("  test_send_buf_on_loss: PASS")


def test_send_buf_fin() raises:
    var buf = SendBuf()

    var data = List[UInt8]()
    for i in range(5):
        data.append(UInt8(i))
    buf.write(Span(data), True)

    assert_true(buf.fin, "send_buf fin: fin flag set")
    assert_true(buf.has_pending(), "send_buf fin: has pending")

    # Frame the data + FIN
    var frame_opt = buf.make_frame(UInt64(0), 100)
    assert_true(frame_opt.__bool__(), "send_buf fin: frame returned")
    var frame = frame_opt.value().copy()
    assert_true(frame.fin, "send_buf fin: frame.fin = True")
    assert_true(buf.fin_offset.__bool__(), "send_buf fin: fin_offset set after framing")
    assert_equal_int(Int(buf.fin_offset.value()), 5, "send_buf fin: fin_offset = 5")

    # No more pending after framing FIN
    assert_false(buf.has_pending(), "send_buf fin: no pending after FIN framed")

    print("  test_send_buf_fin: PASS")


def test_send_buf_is_fully_acked() raises:
    var buf = SendBuf()

    var data = List[UInt8]()
    for i in range(5):
        data.append(UInt8(i))
    buf.write(Span(data), True)

    # Before framing FIN, not fully acked
    assert_false(buf.is_fully_acked(), "fully acked: False before framing")

    # Frame and ACK data+FIN
    _ = buf.make_frame(UInt64(0), 100)

    # ACK all 5 bytes
    buf.on_ack(UInt64(0), UInt64(5))
    # fin_acked should be set because fin_offset=5 and acked_offset=5
    assert_true(buf.is_fully_acked(), "fully acked: True after full ack with FIN")

    print("  test_send_buf_is_fully_acked: PASS")


# ── Stream struct ─────────────────────────────────────────────────────────────


def test_stream_bidi_lifecycle() raises:
    var s = Stream.new_local_bidi(UInt64(0), UInt64(65536), UInt64(65536), UInt64(65536))

    assert_true(s.is_bidi, "bidi lifecycle: is_bidi")
    assert_true(s.is_local, "bidi lifecycle: is_local")
    assert_true(s.send_state.__bool__(), "bidi lifecycle: send_state present")
    assert_true(s.recv_state.__bool__(), "bidi lifecycle: recv_state present")
    assert_equal_int(Int(s.send_state.value()), Int(SEND_READY), "bidi lifecycle: send_state = SEND_READY")
    assert_equal_int(Int(s.recv_state.value()), Int(RECV_RECV), "bidi lifecycle: recv_state = RECV_RECV")
    assert_true(s.send_buf.__bool__(), "bidi lifecycle: send_buf present")
    assert_true(s.recv_buf.__bool__(), "bidi lifecycle: recv_buf present")
    assert_true(s.fc_send.__bool__(), "bidi lifecycle: fc_send present")
    assert_true(s.fc_recv.__bool__(), "bidi lifecycle: fc_recv present")

    print("  test_stream_bidi_lifecycle: PASS")


def test_stream_uni_local() raises:
    var s = Stream.new_local_uni(UInt64(2), UInt64(65536))

    assert_false(s.is_bidi, "local uni: not bidi")
    assert_true(s.is_local, "local uni: is_local")
    assert_true(s.send_state.__bool__(), "local uni: send_state present")
    assert_false(s.recv_state.__bool__(), "local uni: recv_state absent")
    assert_true(s.send_buf.__bool__(), "local uni: send_buf present")
    assert_false(s.recv_buf.__bool__(), "local uni: recv_buf absent")
    assert_true(s.fc_send.__bool__(), "local uni: fc_send present")
    assert_false(s.fc_recv.__bool__(), "local uni: fc_recv absent")

    print("  test_stream_uni_local: PASS")


def test_stream_uni_remote() raises:
    var s = Stream.new_remote_uni(UInt64(3), UInt64(65536), UInt64(65536))

    assert_false(s.is_bidi, "remote uni: not bidi")
    assert_false(s.is_local, "remote uni: not local")
    assert_false(s.send_state.__bool__(), "remote uni: send_state absent")
    assert_true(s.recv_state.__bool__(), "remote uni: recv_state present")
    assert_false(s.send_buf.__bool__(), "remote uni: send_buf absent")
    assert_true(s.recv_buf.__bool__(), "remote uni: recv_buf present")
    assert_false(s.fc_send.__bool__(), "remote uni: fc_send absent")
    assert_true(s.fc_recv.__bool__(), "remote uni: fc_recv present")

    print("  test_stream_uni_remote: PASS")


def test_stream_fully_closed_bidi() raises:
    var s = Stream.new_local_bidi(UInt64(0), UInt64(65536), UInt64(65536), UInt64(65536))

    assert_false(s.is_fully_closed(), "fully closed bidi: False initially")

    # Set both states to terminal
    s.send_state = SEND_DATA_RECVD
    s.recv_state = RECV_DATA_READ
    assert_true(s.is_fully_closed(), "fully closed bidi: True when both terminal")

    # Only send terminal
    s.recv_state = RECV_RECV
    assert_false(s.is_fully_closed(), "fully closed bidi: False when only send terminal")

    print("  test_stream_fully_closed_bidi: PASS")


def test_stream_fully_closed_uni() raises:
    # Local uni: only send side
    var s_local = Stream.new_local_uni(UInt64(2), UInt64(65536))
    assert_false(s_local.is_fully_closed(), "fully closed local uni: False initially")
    s_local.send_state = SEND_DATA_RECVD
    assert_true(s_local.is_fully_closed(), "fully closed local uni: True when send terminal")

    # Remote uni: only recv side
    var s_remote = Stream.new_remote_uni(UInt64(3), UInt64(65536), UInt64(65536))
    assert_false(s_remote.is_fully_closed(), "fully closed remote uni: False initially")
    s_remote.recv_state = RECV_DATA_READ
    assert_true(s_remote.is_fully_closed(), "fully closed remote uni: True when recv terminal")

    print("  test_stream_fully_closed_uni: PASS")


def test_stream_remote_bidi() raises:
    var s = Stream.new_remote_bidi(UInt64(1), UInt64(65536), UInt64(65536), UInt64(65536))

    assert_true(s.is_bidi, "remote bidi: is_bidi")
    assert_false(s.is_local, "remote bidi: not local")
    assert_true(s.send_state.__bool__(), "remote bidi: send_state present")
    assert_true(s.recv_state.__bool__(), "remote bidi: recv_state present")
    assert_equal_int(Int(s.send_state.value()), Int(SEND_READY), "remote bidi: send_state = SEND_READY")
    assert_equal_int(Int(s.recv_state.value()), Int(RECV_RECV), "remote bidi: recv_state = RECV_RECV")

    print("  test_stream_remote_bidi: PASS")


def test_send_buf_fin_loss_retransmit() raises:
    # Regression: FIN must be re-included in the retransmitted frame after loss.
    var buf = SendBuf()

    var data = List[UInt8]()
    for i in range(5):
        data.append(UInt8(i))
    buf.write(Span(data), True)

    # First make_frame — should include FIN
    var frame1_opt = buf.make_frame(UInt64(0), 100)
    assert_true(frame1_opt.__bool__(), "fin loss retransmit: first frame returned")
    var frame1 = frame1_opt.value().copy()
    assert_true(frame1.fin, "fin loss retransmit: first frame has fin=True")
    assert_true(buf.fin_offset.__bool__(), "fin loss retransmit: fin_offset set after first frame")

    # Simulate loss of the entire frame (covers FIN)
    buf.on_loss(UInt64(0), UInt64(5))

    # fin_offset must be cleared so make_frame re-includes FIN
    assert_false(buf.fin_offset.__bool__(), "fin loss retransmit: fin_offset cleared after loss")
    assert_false(buf.fin_acked, "fin loss retransmit: fin_acked reset to False")

    # Second make_frame — must re-include FIN
    var frame2_opt = buf.make_frame(UInt64(0), 100)
    assert_true(frame2_opt.__bool__(), "fin loss retransmit: retransmit frame returned")
    var frame2 = frame2_opt.value().copy()
    assert_true(frame2.fin, "fin loss retransmit: retransmit frame has fin=True")
    assert_true(buf.fin_offset.__bool__(), "fin loss retransmit: fin_offset set again after retransmit")

    print("  test_send_buf_fin_loss_retransmit: PASS")


def test_recv_buf_is_complete_after_read() raises:
    # Regression: is_complete() must remain True after partial reads consume segments.
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    # Write [0,5) — no fin
    var data0 = List[UInt8]()
    for i in range(5):
        data0.append(UInt8(i))
    _ = buf.write(UInt64(0), Span(data0), False, fin_offset)

    # Write [5,10) with fin=True
    var data1 = List[UInt8]()
    for i in range(5, 10):
        data1.append(UInt8(i))
    _ = buf.write(UInt64(5), Span(data1), True, fin_offset)

    # All data received — is_complete should be True
    assert_true(buf.is_complete(fin_offset), "is_complete after read: True before any read")

    # Perform a read (consumes and removes the first segment)
    var result = buf.read(fin_offset)
    _ = result[0].copy()

    # After the read, is_complete must still be True
    assert_true(buf.is_complete(fin_offset), "is_complete after read: True after partial read")

    print("  test_recv_buf_is_complete_after_read: PASS")


def test_stream_urgency_default() raises:
    # All factory methods must default urgency to 127 (lowest priority per spec).
    var s1 = Stream.new_local_bidi(UInt64(0), UInt64(65536), UInt64(65536), UInt64(65536))
    assert_equal_int(Int(s1.urgency), 127, "urgency default: new_local_bidi = 127")

    var s2 = Stream.new_remote_bidi(UInt64(1), UInt64(65536), UInt64(65536), UInt64(65536))
    assert_equal_int(Int(s2.urgency), 127, "urgency default: new_remote_bidi = 127")

    var s3 = Stream.new_local_uni(UInt64(2), UInt64(65536))
    assert_equal_int(Int(s3.urgency), 127, "urgency default: new_local_uni = 127")

    var s4 = Stream.new_remote_uni(UInt64(3), UInt64(65536), UInt64(65536))
    assert_equal_int(Int(s4.urgency), 127, "urgency default: new_remote_uni = 127")

    print("  test_stream_urgency_default: PASS")


def test_recv_buf_duplicate_after_read() raises:
    """After reading bytes, a retransmit of the same bytes must not inflate total_received."""
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))
    var data1 = List[UInt8](capacity=5)
    for i in range(5):
        data1.append(UInt8(i))
    var n1 = buf.write(UInt64(0), Span(data1), False, fin_offset)
    assert_true(n1 == 5, "first write: 5 new bytes")

    var result = buf.read(fin_offset)
    assert_true(len(result[0]) == 5, "read returned 5 bytes")
    assert_true(buf.read_offset == UInt64(5), "read_offset advanced to 5")

    # Retransmit [0,5) — should count as 0 new bytes
    var data2 = List[UInt8](capacity=5)
    for i in range(5):
        data2.append(UInt8(i))
    var n2 = buf.write(UInt64(0), Span(data2), False, fin_offset)
    assert_true(n2 == 0, "retransmit after read: 0 new bytes")
    assert_true(buf.total_received == UInt64(5), "total_received stays at 5")
    print("  test_recv_buf_duplicate_after_read: PASS")


def test_recv_buf_is_complete_not_premature() raises:
    """Ensure is_complete does not return True until ALL data has arrived."""
    var fin_offset = Optional[UInt64](None)
    var buf = RecvBuf(UInt64(65536))

    # Write [0,5)
    var data1 = List[UInt8](capacity=5)
    for i in range(5):
        data1.append(UInt8(i))
    _ = buf.write(UInt64(0), Span(data1), False, fin_offset)

    # Read [0,5)
    _ = buf.read(fin_offset)
    assert_true(buf.read_offset == UInt64(5), "read_offset = 5 after read")

    # Retransmit [0,5) — should NOT advance total_received
    var data2 = List[UInt8](capacity=5)
    for i in range(5):
        data2.append(UInt8(i))
    _ = buf.write(UInt64(0), Span(data2), False, fin_offset)
    assert_true(buf.total_received == UInt64(5), "total_received still 5 after retransmit")

    # [5,10) not yet arrived — is_complete with fin_offset=10 must be False
    var fo10 = Optional[UInt64](UInt64(10))
    assert_false(buf.is_complete(fo10), "is_complete False — [5,10) not yet received")

    # Now write [5,10) with fin=True
    var data3 = List[UInt8](capacity=5)
    for i in range(5):
        data3.append(UInt8(i + 5))
    _ = buf.write(UInt64(5), Span(data3), True, fin_offset)

    # fin_offset should now be set to 10
    assert_true(fin_offset.__bool__(), "fin_offset set after FIN write")
    assert_true(fin_offset.value() == UInt64(10), "fin_offset == 10")
    assert_true(buf.is_complete(fin_offset), "is_complete True — all 10 bytes received")
    print("  test_recv_buf_is_complete_not_premature: PASS")


def test_send_buf_bare_fin_acked() raises:
    """Regression: bare-FIN frame (0 data bytes + FIN=True) must mark fin_acked."""
    var buf = SendBuf()

    # Write 0 bytes with FIN — creates a bare-FIN stream frame
    var empty_data = List[UInt8]()
    buf.write(Span[UInt8](empty_data), True)
    assert_true(buf.fin, "bare fin: fin flag set")

    # Frame the bare FIN (offset=0, data=[], fin=True)
    var frame_opt = buf.make_frame(UInt64(0), 100)
    assert_true(frame_opt.__bool__(), "bare fin: frame returned")
    var frame = frame_opt.value().copy()
    assert_true(frame.fin, "bare fin: frame.fin = True")
    assert_equal_int(len(frame.data), 0, "bare fin: frame.data is empty")
    assert_true(buf.fin_offset.__bool__(), "bare fin: fin_offset set after framing")
    assert_equal_int(Int(buf.fin_offset.value()), 0, "bare fin: fin_offset = 0")

    # Before ACK: not fully acked
    assert_false(buf.is_fully_acked(), "bare fin: not fully acked before ACK")

    # ACK the bare-FIN frame: ack_off=0, ack_len=0
    buf.on_ack(UInt64(0), UInt64(0))

    # After bare-FIN ACK: fin_acked must be True
    assert_true(buf.fin_acked, "bare fin: fin_acked set after bare-FIN ACK")
    assert_true(buf.is_fully_acked(), "bare fin: is_fully_acked() after bare-FIN ACK")

    print("  test_send_buf_bare_fin_acked: PASS")


def test_send_buf_write_after_fin() raises:
    """After FIN is queued, additional writes must raise."""
    var sb = SendBuf()
    var data = List[UInt8](capacity=3)
    data.append(UInt8(1))
    data.append(UInt8(2))
    data.append(UInt8(3))
    sb.write(Span(data), True)  # FIN queued

    # Zero-length write after FIN: OK (no data to append)
    var empty = List[UInt8]()
    sb.write(Span(empty), False)

    # Non-empty write after FIN: must raise
    var more = List[UInt8](capacity=1)
    more.append(UInt8(9))
    var raised = False
    try:
        sb.write(Span(more), False)
    except:
        raised = True
    assert_true(raised, "write after FIN must raise")
    print("  test_send_buf_write_after_fin: PASS")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() raises:
    print("test_quic_stream:")

    test_stream_id_helpers()
    test_send_state_terminal()
    test_recv_state_terminal()

    test_recv_buf_in_order()
    test_recv_buf_out_of_order()
    test_recv_buf_overlapping()
    test_recv_buf_gap_limit()
    test_recv_buf_fin()
    test_recv_buf_fin_mismatch()
    test_recv_buf_data_beyond_fin()
    test_recv_buf_empty_fin()
    test_recv_buf_new_bytes_count()

    test_send_buf_write_and_frame()
    test_send_buf_on_ack_trims()
    test_send_buf_on_loss()
    test_send_buf_fin()
    test_send_buf_is_fully_acked()

    test_stream_bidi_lifecycle()
    test_stream_uni_local()
    test_stream_uni_remote()
    test_stream_fully_closed_bidi()
    test_stream_fully_closed_uni()
    test_stream_remote_bidi()

    test_send_buf_fin_loss_retransmit()
    test_recv_buf_is_complete_after_read()
    test_stream_urgency_default()

    test_recv_buf_duplicate_after_read()
    test_recv_buf_is_complete_not_premature()

    test_send_buf_write_after_fin()
    test_send_buf_bare_fin_acked()

    print("All test_quic_stream tests passed.")
