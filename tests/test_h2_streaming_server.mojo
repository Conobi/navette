# tests/test_h2_streaming_server.mojo
#
# Tests for H2StreamingServer (Plan 2B — stackful coroutine streaming).
# Mirrors tests/test_h3_streaming_server.mojo with H2 substitutions.
#
# Transport: H2 TCP loopback via lib.http2.connection (client-side H2Connection),
# mirroring the pattern in tests/test_h2_sync_server.mojo.
# No TLS/QUIC needed — tests drive the H2 framing layer directly.
#
# Run with:
#   uv run mojo run -I . -I conformance -I "$HOME/Projets/perso/boucle" \
#       tests/test_h2_streaming_server.mojo

from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from lib.http1.types import Header
from lib.http2.connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
    H2_EVT_TRAILERS_RECEIVED,
)

from boucle.stackful import CoroYielder

from navette.h2.h2_streaming_server import (
    H2StreamingServer,
    H2StreamingCtx,
    H2StreamingHandlerFn,
    next_chunk,
    write_chunk,
    finish,
    cancelled,
)
from navette.http.handler import Capabilities, RecvBody, ResponseWriter, StreamError
from navette.http.headers import Headers
from navette.http.body import BodyFrame
from navette.http.status import StatusCode
from tests._test_util import assert_true, assert_equal_int


# ── Shared loopback helpers ──────────────────────────────────────────────────


def _do_preface(
    mut server: H2StreamingServer,
    mut client: H2Connection,
) raises:
    """Perform the HTTP/2 preface exchange between H2StreamingServer and a
    client-side H2Connection. Mirrors _do_preface in test_h2_sync_server.mojo."""
    var server_initial = server.drain()
    var client_preface = client.data_to_send()  # magic + SETTINGS

    # Feed client preface to server
    server.feed(Span(client_preface))
    var server_resp = server.drain()  # server SETTINGS + SETTINGS ACK

    # Feed server output to client
    var combined = List[UInt8]()
    for i in range(len(server_initial)):
        combined.append(server_initial[i])
    for i in range(len(server_resp)):
        combined.append(server_resp[i])
    _ = client.receive_data(combined)
    var client_settings_ack = client.data_to_send()  # client SETTINGS ACK

    # Feed client SETTINGS ACK to server
    if len(client_settings_ack) > 0:
        server.feed(Span(client_settings_ack))
        _ = server.drain()


def _pump(
    mut server: H2StreamingServer,
    mut client: H2Connection,
    mut client_events: List[H2Event],
    rounds: Int = 5,
) raises:
    """Exchange bytes between server and client for `rounds` iterations.
    Accumulates all H2Events received by the client into client_events."""
    for _ in range(rounds):
        var s_out = server.drain()
        if len(s_out) > 0:
            var evts = client.receive_data(s_out)
            for k in range(len(evts)):
                client_events.append(H2Event(other=evts[k]))
        var c_out = client.data_to_send()
        if len(c_out) > 0:
            server.feed(Span(c_out))


# ── Streaming handler bodies ─────────────────────────────────────────────────
#
# Each handler uses the CoroBody shape: fn(mut CoroYielder) raises -> None
# (must be `fn`, not `def`, to match CoroBody function-pointer type)
# ctx is accessed via yld.user_data().bitcast[H2StreamingCtx]().as_any_origin()


def _echo_body_streaming(mut yld: CoroYielder) raises:
    """POST handler: reads all body chunks, responds with 200 + x-body-length header."""
    var ctx_ptr = yld.user_data().bitcast[H2StreamingCtx]().as_any_origin()

    # Accumulate all body bytes
    var total_len = Int(0)
    while True:
        var chunk_opt = next_chunk(ctx_ptr, yld)
        if not chunk_opt:
            break
        var chunk = chunk_opt.unsafe_take()
        if chunk.is_data():
            total_len += len(chunk.data())

    # Send response headers
    var hdrs = Headers()
    hdrs.add("x-body-length", String(total_len))
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)

    # Empty body
    var empty = List[UInt8]()
    write_chunk(ctx_ptr, yld, empty^)
    finish(ctx_ptr, yld)


def _trailer_check_streaming(mut yld: CoroYielder) raises:
    """POST with trailers: reads body + trailer, sets found_ptr[]=1 if trailer seen."""
    var ctx_ptr = yld.user_data().bitcast[H2StreamingCtx]().as_any_origin()
    var found_ptr = ctx_ptr[].extra_data.bitcast[Int]().as_any_origin()

    # Consume body and trailers
    while True:
        var chunk_opt = next_chunk(ctx_ptr, yld)
        if not chunk_opt:
            break
        var chunk = chunk_opt.unsafe_take()
        if chunk.is_trailers():
            var trailer_hdrs = chunk.trailers().copy()
            for i in range(len(trailer_hdrs)):
                if trailer_hdrs.name_at(i) == "x-custom-trailer":
                    found_ptr[0] = Int(1)

    # Send minimal 200 response
    var hdrs = Headers()
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
    var empty = List[UInt8]()
    write_chunk(ctx_ptr, yld, empty^)
    finish(ctx_ptr, yld)


def _blocking_body_streaming(mut yld: CoroYielder) raises:
    """POST handler that suspends in next_chunk waiting for body.
    On cancellation (H2StreamCancelled), writes signal=42 to extra_data."""
    var ctx_ptr = yld.user_data().bitcast[H2StreamingCtx]().as_any_origin()
    var signal_ptr = ctx_ptr[].extra_data.bitcast[Int]().as_any_origin()

    try:
        # This will suspend, then raise H2StreamCancelled when reset arrives
        var chunk_opt = next_chunk(ctx_ptr, yld)
        # If we somehow got a chunk (shouldn't happen in this test), just end
        var hdrs = Headers()
        ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
        finish(ctx_ptr, yld)
    except e:
        # Cancellation path: write signal value 42
        signal_ptr[0] = Int(42)


def _multi_chunk_concat_body(mut yld: CoroYielder) raises:
    """POST handler: yield once to let multiple DATA frames queue into
    body_frame_ring before draining, then read chunks in arrival order
    and concatenate into extra_data (max 64 bytes).

    This exercises the FIFO ordering invariant: the explicit pre-drain
    yield is what causes ≥2 frames to coexist in the ring at the moment
    next_chunk pops the first one. Without that, the server delivers
    one frame at a time and a LIFO pop hides itself."""
    var ctx_ptr = yld.user_data().bitcast[H2StreamingCtx]().as_any_origin()
    var sink_ptr = ctx_ptr[].extra_data.bitcast[UInt8]().as_any_origin()
    var written = Int(0)
    # Yield three times before reading so the adapter can deliver all
    # three DATA events into body_frame_ring while we're suspended —
    # this is what forces multiple frames to coexist when next_chunk pops.
    yld.yield_to_caller()
    yld.yield_to_caller()
    yld.yield_to_caller()
    while True:
        var chunk_opt = next_chunk(ctx_ptr, yld)
        if not chunk_opt:
            break
        var chunk = chunk_opt.unsafe_take()
        if chunk.is_data():
            var data = chunk.data().copy()
            for i in range(len(data)):
                if written < 64:
                    sink_ptr[written] = data[i]
                    written += 1
    var hdrs = Headers()
    hdrs.add("x-chunks-len", String(written))
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
    var empty = List[UInt8]()
    write_chunk(ctx_ptr, yld, empty^)
    finish(ctx_ptr, yld)


def _cancel_signal_handler(mut yld: CoroYielder) raises:
    """Streaming handler for cancel test. Writes 99 to extra_data on cancellation."""
    var ctx_ptr = yld.user_data().bitcast[H2StreamingCtx]().as_any_origin()
    var signal_ptr = ctx_ptr[].extra_data.bitcast[Int]().as_any_origin()

    try:
        # Will suspend here, then raise H2StreamCancelled when reset arrives
        _ = next_chunk(ctx_ptr, yld)
        # Unexpected: body arrived instead of cancellation
        var hdrs = Headers()
        ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
        finish(ctx_ptr, yld)
    except e:
        # Cancellation path — write signal 99
        signal_ptr[0] = Int(99)


# ── Tests ────────────────────────────────────────────────────────────────────


def test_h2_streaming_post_with_body() raises:
    """POST /upload with body 'hello world' → server echoes body length 11."""
    var server = H2StreamingServer(handler_fn=_echo_body_streaming)
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    var client_events = List[H2Event]()
    _do_preface(server, client)

    # Client sends POST /upload with body 'hello world' + END_STREAM
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/upload"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    headers.append(Header("content-length", "11"))
    client.send_headers(UInt32(1), headers^, end_stream=False)

    var body_bytes = List[UInt8]()
    var src = String("hello world").as_bytes()
    for i in range(len(src)):
        body_bytes.append(src[i])
    client.send_data(UInt32(1), body_bytes^, end_stream=True)

    var req_data = client.data_to_send()
    server.feed(Span(req_data))

    _pump(server, client, client_events, 10)

    var got_200 = False
    var got_body_length = String("")
    for i in range(len(client_events)):
        if client_events[i].kind == H2_EVT_RESPONSE_RECEIVED:
            for j in range(len(client_events[i].headers)):
                if client_events[i].headers[j].name == ":status" and client_events[i].headers[j].value == "200":
                    got_200 = True
                elif client_events[i].headers[j].name == "x-body-length":
                    got_body_length = client_events[i].headers[j].value

    assert_true(got_200, "did not receive 200 OK")
    assert_true(got_body_length == "11", "expected body length 11, got: " + got_body_length)
    print("  test_h2_streaming_post_with_body: PASS")


def test_h2_streaming_trailers() raises:
    """POST with trailers → coroutine reads trailer header x-custom-trailer."""
    var found_ptr = _heap_alloc[Int](1).as_any_origin()
    found_ptr.init_pointee_move(Int(0))
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(found_ptr)
    )

    var server = H2StreamingServer(handler_fn=_trailer_check_streaming, extra_data=extra)
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    var client_events2 = List[H2Event]()
    _do_preface(server, client)

    # Client sends POST with body + trailers
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    # trailers require TE: trailers header
    headers.append(Header("te", "trailers"))
    client.send_headers(UInt32(1), headers^, end_stream=False)

    var body_data = List[UInt8]()
    body_data.append(UInt8(65))  # 'A'
    client.send_data(UInt32(1), body_data^, end_stream=False)

    # Send trailers (HEADERS frame with end_stream=True)
    var trailer_headers = List[Header]()
    trailer_headers.append(Header("x-custom-trailer", "test"))
    client.send_headers(UInt32(1), trailer_headers^, end_stream=True)

    var req_data = client.data_to_send()
    server.feed(Span(req_data))

    _pump(server, client, client_events2, 10)

    var found_val = found_ptr[]
    found_ptr.destroy_pointee()
    found_ptr.free()
    assert_equal_int(found_val, 1, "trailer header x-custom-trailer not received by coroutine")
    print("  test_h2_streaming_trailers: PASS")


def test_h2_streaming_rst_stream() raises:
    """Client resets a stream → coroutine receives H2StreamCancelled, sets signal=42."""
    var signal_ptr = _heap_alloc[Int](1).as_any_origin()
    signal_ptr.init_pointee_move(Int(0))
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(signal_ptr)
    )

    var server = H2StreamingServer(handler_fn=_blocking_body_streaming, extra_data=extra)
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    var client_events3 = List[H2Event]()
    _do_preface(server, client)

    # Send POST without END_STREAM — handler suspends waiting for body
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    var req_data = client.data_to_send()
    server.feed(Span(req_data))

    _pump(server, client, client_events3, 5)

    # Client resets the stream
    client.send_rst_stream(UInt32(1), UInt32(8))  # CANCEL
    var rst_data = client.data_to_send()
    server.feed(Span(rst_data))

    _pump(server, client, client_events3, 5)

    var signal_val = signal_ptr[]
    signal_ptr.destroy_pointee()
    signal_ptr.free()
    assert_equal_int(signal_val, 42, "coroutine did not receive stream reset error")
    print("  test_h2_streaming_rst_stream: PASS")


def test_h2_streaming_cancel_via_rst_stream() raises:
    """Cancellation path: server sets ctx.cancelled=True directly, handler unwinds.

    Verifies the cancellation unwind path end-to-end:
    1. Client opens POST stream (no body) — handler suspends in next_chunk().
    2. Client sends RST_STREAM — server _on_stream_reset sets ctx.cancelled=True
       and resumes the coroutine once.
    3. Handler catches H2StreamCancelled and writes signal=99 to extra_data.
    4. Assert: signal == 99.
    """
    var signal_ptr = _heap_alloc[Int](1).as_any_origin()
    signal_ptr.init_pointee_move(Int(0))
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(signal_ptr)
    )

    var server = H2StreamingServer(handler_fn=_cancel_signal_handler, extra_data=extra)
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    var client_events4 = List[H2Event]()
    _do_preface(server, client)

    # Open stream; POST without body — handler will suspend waiting for next_chunk
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/stream"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    var req_data = client.data_to_send()
    server.feed(Span(req_data))

    # Pump enough to ensure the handler has started and suspended
    _pump(server, client, client_events4, 5)

    # Client resets the stream — triggers _on_stream_reset on server side
    client.send_rst_stream(UInt32(1), UInt32(8))  # CANCEL
    var rst_data = client.data_to_send()
    server.feed(Span(rst_data))

    # Pump to deliver reset to server
    _pump(server, client, client_events4, 5)

    var signal_val = signal_ptr[]
    signal_ptr.destroy_pointee()
    signal_ptr.free()

    # Handler should have caught H2StreamCancelled and written 99
    assert_equal_int(signal_val, 99, "cancellation handler did not write signal=99; got: " + String(signal_val))
    print("  test_h2_streaming_cancel_via_rst_stream: PASS")


def test_h2_streaming_multi_chunk_body_fifo_order() raises:
    """Regression test: 3 separate DATA frames must be delivered to
    next_chunk in arrival order (FIFO), not reverse order (LIFO).

    Caught a real bug where body_frame_ring.pop() (default = pop last)
    paired with append() to deliver multi-chunk POST bodies in REVERSE
    order — silent data corruption."""
    var sink_ptr = _heap_alloc[UInt8](64).as_any_origin()
    for i in range(64):
        sink_ptr[i] = UInt8(0)
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(sink_ptr)
    )

    var server = H2StreamingServer(handler_fn=_multi_chunk_concat_body, extra_data=extra)
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    var client_events = List[H2Event]()
    _do_preface(server, client)

    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/multi"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=False)

    # Send 3 distinct body chunks via 3 separate DATA frames, batched
    # in a single feed() so the server queues all three into
    # body_frame_ring BEFORE the handler drains them. This is the
    # condition under which a LIFO pop() reverses the order; if we
    # interleaved feed/resume per chunk the handler would consume each
    # chunk before the next arrived and the LIFO bug would be hidden.
    var c1 = List[UInt8]()
    c1.append(UInt8(ord("A"))); c1.append(UInt8(ord("A"))); c1.append(UInt8(ord("A")))
    client.send_data(UInt32(1), c1^, end_stream=False)
    var c2 = List[UInt8]()
    c2.append(UInt8(ord("B"))); c2.append(UInt8(ord("B"))); c2.append(UInt8(ord("B")))
    client.send_data(UInt32(1), c2^, end_stream=False)
    var c3 = List[UInt8]()
    c3.append(UInt8(ord("C"))); c3.append(UInt8(ord("C"))); c3.append(UInt8(ord("C")))
    client.send_data(UInt32(1), c3^, end_stream=True)

    var batched = client.data_to_send()
    server.feed(Span(batched))
    _pump(server, client, client_events, 5)

    # Read sink and free
    var observed = List[UInt8]()
    for i in range(9):
        observed.append(sink_ptr[i])
    sink_ptr.free()

    var observed_str = String(unsafe_from_utf8=observed)
    assert_true(
        observed_str == "AAABBBCCC",
        "expected FIFO order 'AAABBBCCC', got: '" + observed_str + "'"
        " — body chunk ring is delivering in reverse order"
    )
    print("  test_h2_streaming_multi_chunk_body_fifo_order: PASS")


def main() raises:
    print("=== test_h2_streaming_server ===")
    test_h2_streaming_post_with_body()
    test_h2_streaming_trailers()
    test_h2_streaming_rst_stream()
    test_h2_streaming_cancel_via_rst_stream()
    test_h2_streaming_multi_chunk_body_fifo_order()
    print("All H2StreamingServer tests passed.")
    print("ok")
