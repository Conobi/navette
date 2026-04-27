# H3 coro test classification (Plan 2A Task 2.1, 2026-04-27)

Audit of `tests/test_h3_coro_server.mojo` to determine which tests survive
the H3 coro→sync rewrite, which migrate to Plan 2B's streaming server
tests, and which can be deleted outright.

| Test | Verdict | Reason |
|---|---|---|
| test_h3_coro_simple_get  | REWRITE | Uses `_simple_get_body` which never calls `y.yield_to_caller()`; responds synchronously with 200 + "hello", directly portable to a sync handler test. |
| test_h3_coro_post_with_body | MOVE | Uses `_echo_body_coro` which calls `y.yield_to_caller()` in a loop while waiting for body frames; suspension is load-bearing for the body accumulation path. |
| test_h3_coro_trailers    | MOVE | Uses `_trailer_check_coro` which calls `y.yield_to_caller()` while waiting for the trailer HEADERS frame; trailer detection depends on suspension loop. |
| test_h3_coro_rst_stream  | MOVE | Uses `_blocking_body_coro` which calls `y.yield_to_caller()` indefinitely until a StreamError arrives; the RST_STREAM signal path is only reachable via the suspension/resume cycle. |
| test_h3_coro_goaway      | REWRITE | Server calls `send_goaway(0)` before any request and client asserts `GOAWAY_RECEIVED`; no body function with suspension is exercised, and the GOAWAY state-machine path is fully sync-portable. |
