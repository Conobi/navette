# H2 Hotspots — `3bdd92a`

Generated 2026-04-25T16:27:35Z from `bench/profile/runs/20260425-182632-3bdd92a/perf-folded.txt`.

- **Total weight:** 106833966583
- **Unique stacks:** 451
- **Top N:** 30

> "Weight" is perf's PERIOD field (≈ cycles between samples), not raw
> sample count — it's what `stackcollapse-perf.pl` emits. Use the
> percentages, not the absolute numbers.

Self-time = CPU burning **inside** that function (leaf of the stack).
Inclusive-time = stacks that pass **through** that function. Allocators,
syscalls, and other "ubiquitous helpers" usually rank high in
inclusive-time but low in self-time, and vice versa.

## Top 30 by SELF time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
| 21570620220 | 20.19% | `[libAsyncRTRuntimeGlobals.so]` |
| 9063029127 | 8.48% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 8614202143 | 8.06% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 6548435879 | 6.13% | `[unknown]` |
| 4901761754 | 4.59% | `__tls_get_addr` |
| 4883837743 | 4.57% | `src::h2::connection::H2Connection::receive_data` |
| 4073985911 | 3.81% | `src::h2::connection::H2Connection::send_headers` |
| 3688294553 | 3.45% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 3407150688 | 3.19% | `std::collections::dict::Dict::_insert[::Bool]` |
| 3246361463 | 3.04% | `swapcontext` |
| 2808872541 | 2.63% | `bench::handler::bench_h2_body_fn` |
| 2453702711 | 2.30% | `TCMallocInternalCfree` |
| 2293217146 | 2.15% | `std::collections::list::List::_realloc` |
| 2137928928 | 2.00% | `std::utils::variant::Variant::__init__` |
| 1760475419 | 1.65% | `h2_server::main` |
| 1412341051 | 1.32% | `__tls_get_addr@plt` |
| 1356267483 | 1.27% | `KGEN_CompilerRT_AlignedAlloc` |
| 1347993497 | 1.26% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1208629156 | 1.13% | `src::http::headers::_to_lower` |
| 999715177 | 0.94% | `std::collections::list::List::extend[::Bool,LITOrigin[$1._mlir_value],::Origin[$1, $2]]` |
| 957185612 | 0.90% | `src::h2::hpack::HpackDecoder::decode` |
| 891283557 | 0.83% | `M::AsyncRT::TCMallocGlobals::tc_delete` |
| 866746243 | 0.81% | `src::h2::connection::H2Connection::send_data` |
| 866031497 | 0.81% | `[libc.so.6]` |
| 828654290 | 0.78% | `getcontext` |
| 816700391 | 0.76% | `std::collections::deque::Deque::append` |
| 705945195 | 0.66% | `[ld-linux-x86-64.so.2]` |
| 657161212 | 0.62% | `M::AsyncRT::TCMallocGlobals::tc_new` |
| 637891203 | 0.60% | `KGEN_CompilerRT_AlignedFree` |
| 629584099 | 0.59% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |

## Top 30 by INCLUSIVE time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
| 106833966583 | 100.00% | `h2_server` |
| 65517486676 | 61.33% | `h2_server::main` |
| 27625787494 | 25.86% | `src::h2::connection::H2Connection::receive_data` |
| 27133692582 | 25.40% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 24527858752 | 22.96% | `[libAsyncRTRuntimeGlobals.so]` |
| 19354616099 | 18.12% | `std::collections::list::List::_realloc` |
| 14163313410 | 13.26% | `src::h2::hpack::HpackDecoder::decode` |
| 14051706913 | 13.15% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 13123452078 | 12.28% | `[unknown]` |
| 12100650802 | 11.33% | `src::h2::hpack::HpackDecoder::_decode_literal` |
| 11719501710 | 10.97% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 8596188195 | 8.05% | `boucle::stackful::_coro_trampoline` |
| 8289205284 | 7.76% | `src::h2::connection::H2Connection::send_headers` |
| 8170591330 | 7.65% | `bench::handler::bench_h2_body_fn` |
| 4901761754 | 4.59% | `__tls_get_addr` |
| 4321023341 | 4.04% | `src::h2::connection::H2Connection::send_data` |
| 3530756251 | 3.30% | `swapcontext` |
| 3407150688 | 3.19% | `std::collections::dict::Dict::_insert[::Bool]` |
| 3349942906 | 3.14% | `TCMallocInternalCfree` |
| 3324528985 | 3.11% | `main` |
| 3313846880 | 3.10% | `src::h2::connection::H2Connection::_queue_frame` |
| 3200174218 | 3.00% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |
| 2774244745 | 2.60% | `src::http::headers::_to_lower` |
| 2513375915 | 2.35% | `src::h2::h2_coro_server::_free_stream` |
| 2137928928 | 2.00% | `std::utils::variant::Variant::__init__` |
| 2025901279 | 1.90% | `src::h2::payloads::decode_headers_payload` |
| 1765969686 | 1.65% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1762371106 | 1.65% | `src::http::headers::Headers::add` |
| 1717116095 | 1.61% | `[libc.so.6]` |
| 1484932640 | 1.39% | `src::h2::h2_coro_server::H2CoroServer::_resume_and_handle_error` |
