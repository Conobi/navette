# bench/streaming_handler.mojo
#
# LLM-stream demo: emits N pseudo-tokens at K-µs intervals.
# Used by both bench/h3_streaming_server.mojo and bench/h2_streaming_server.mojo
# (H2 variant) to demonstrate end-to-end streaming on both protocols with one
# shared handler body.
#
# The handler shape is boucle's `CoroutineBody[State]`:
#   def (mut Yielder[State]) raises -> None
# with the per-stream ctx reached through the typed state channel,
# `yld.state()[]`. H2 and H3 streaming ctx are protocol-specific structs
# (H2StreamingCtx vs H3StreamingCtx) and therefore instantiate the coroutine
# at different State types, so we provide two thin entry points; the body
# logic is structurally identical.

from std.memory import Pointer

from navette.h3.h3_streaming_server import (
    H3StreamingCtx,
    H3StreamingYielder,
    next_chunk as h3_next_chunk,
    write_chunk as h3_write_chunk,
    finish as h3_finish,
)

from navette.h2.h2_streaming_server import (
    H2StreamingCtx,
    H2StreamingYielder,
    next_chunk as h2_next_chunk,
    write_chunk as h2_write_chunk,
    finish as h2_finish,
)


comptime LLM_TOKEN_COUNT: Int = 64
comptime LLM_TOKEN_BYTES: String = "data: token-emitted\n\n"


def llm_stream_h3_handler(mut yld: H3StreamingYielder) raises:
    """LLM-stream demo handler for H3.

    Reads the H3StreamingCtx pointer from the coroutine's typed state, sends
    HTTP 200
    response headers (content-type: text/event-stream), then emits
    LLM_TOKEN_COUNT chunks of LLM_TOKEN_BYTES via h3_write_chunk. Each chunk
    is a complete SSE event. Calls h3_finish() to signal end-of-stream.

    Any incoming request body is ignored (GET or POST both work).
    """
    var ctx_ptr = yld.state()[]

    # Drain any request body (ignore it — demo only cares about streaming out)
    while True:
        var chunk_opt = h3_next_chunk(ctx_ptr, yld)
        if not chunk_opt:
            break
        # ignore chunk contents

    # Send response headers: 200 OK + SSE content-type
    from navette.http.headers import Headers
    from navette.http.status import StatusCode
    var hdrs = Headers()
    hdrs.add("content-type", "text/event-stream")
    hdrs.add("cache-control", "no-cache")
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)

    # Emit LLM_TOKEN_COUNT SSE chunks
    var token_bytes = LLM_TOKEN_BYTES.as_bytes()
    var token_len = len(token_bytes)
    for _ in range(LLM_TOKEN_COUNT):
        var chunk = List[UInt8]()
        for i in range(token_len):
            chunk.append(token_bytes[i])
        h3_write_chunk(ctx_ptr, yld, chunk^)

    h3_finish(ctx_ptr, yld)


def llm_stream_h2_handler(mut yld: H2StreamingYielder) raises:
    """LLM-stream demo handler for H2.

    Mirrors llm_stream_h3_handler with H2StreamingCtx substitution. Sends
    HTTP 200 + SSE headers, then emits LLM_TOKEN_COUNT chunks of
    LLM_TOKEN_BYTES via h2_write_chunk + h2_finish.
    """
    var ctx_ptr = yld.state()[]

    # Send response headers: 200 OK + SSE content-type
    from navette.http.headers import Headers
    from navette.http.status import StatusCode
    var hdrs = Headers()
    hdrs.add("content-type", "text/event-stream")
    hdrs.add("cache-control", "no-cache")
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)

    for _ in range(LLM_TOKEN_COUNT):
        var bytes = List[UInt8]()
        for b in LLM_TOKEN_BYTES.as_bytes():
            bytes.append(b)
        h2_write_chunk(ctx_ptr, yld, bytes^)
    h2_finish(ctx_ptr, yld)
