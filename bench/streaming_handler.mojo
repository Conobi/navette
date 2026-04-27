# bench/streaming_handler.mojo
#
# LLM-stream demo: emits N pseudo-tokens at K-µs intervals.
# Used by both bench/h3_streaming_server.mojo and bench/h2_streaming_server.mojo
# (H2 variant) to demonstrate end-to-end streaming on both protocols with one
# shared handler body.
#
# The handler shape is boucle's CoroBody: `fn(mut yld) raises -> None` with
# ctx accessed via yld.user_data(). H2 and H3 streaming ctx are protocol-
# specific structs (H2StreamingCtx vs H3StreamingCtx), so we provide two
# thin entry-point fns; the body logic is identical structurally but the
# ctx pointer types differ.
#
# Note: H2 streaming server doesn't exist yet (Phase 2 work). Imports for it
# will be added by Phase 2 Task 2.4 alongside `llm_stream_h2_handler`.

from std.memory import UnsafePointer

from boucle.stackful import CoroYielder

from src.h3.h3_streaming_server import (
    H3StreamingCtx,
    next_chunk as h3_next_chunk,
    write_chunk as h3_write_chunk,
    finish as h3_finish,
)

# H2 streaming server imports will be added in Phase 2 Task 2.4:
# from src.h2.h2_streaming_server import (
#     H2StreamingCtx,
#     next_chunk as h2_next_chunk,
#     write_chunk as h2_write_chunk,
#     finish as h2_finish,
# )


comptime LLM_TOKEN_COUNT: Int = 64
comptime LLM_TOKEN_BYTES: String = "data: token-emitted\n\n"


def llm_stream_h3_handler(mut yld: CoroYielder) raises:
    """LLM-stream demo handler for H3.

    Extracts H3StreamingCtx from the CoroYielder user_data, sends HTTP 200
    response headers (content-type: text/event-stream), then emits
    LLM_TOKEN_COUNT chunks of LLM_TOKEN_BYTES via h3_write_chunk. Each chunk
    is a complete SSE event. Calls h3_finish() to signal end-of-stream.

    Any incoming request body is ignored (GET or POST both work).
    """
    var ctx_ptr = yld.user_data().bitcast[H3StreamingCtx]().as_any_origin()

    # Drain any request body (ignore it — demo only cares about streaming out)
    while True:
        var chunk_opt = h3_next_chunk(ctx_ptr, yld)
        if not chunk_opt:
            break
        # ignore chunk contents

    # Send response headers: 200 OK + SSE content-type
    from src.http.headers import Headers
    from src.http.status import StatusCode
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


# Phase 2 Task 2.4 will add:
#
# fn llm_stream_h2_handler(mut yld: CoroYielder) raises:
#     """LLM-stream demo handler for H2. Same logic as H3 variant."""
#     var ctx_ptr = yld.user_data().bitcast[H2StreamingCtx]().as_any_origin()
#     ...
