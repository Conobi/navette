# H2 Hotspots — `4b77271`

Generated 2026-04-25T16:31:06Z from `bench/profile/runs/20260425-183003-4b77271/perf-folded.txt`.

- **Total weight:** 106648509461
- **Unique stacks:** 455
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
| 22028097726 | 20.65% | `[libAsyncRTRuntimeGlobals.so]` |
| 9068753208 | 8.50% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 9036463195 | 8.47% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 6952719694 | 6.52% | `[unknown]` |
| 4679362108 | 4.39% | `src::h2::connection::H2Connection::receive_data` |
| 4651020803 | 4.36% | `__tls_get_addr` |
| 3499087739 | 3.28% | `src::h2::connection::H2Connection::send_headers` |
| 3391194257 | 3.18% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 3194323960 | 3.00% | `std::collections::dict::Dict::_insert[::Bool]` |
| 3151696772 | 2.96% | `bench::handler::bench_h2_body_fn` |
| 2991917723 | 2.81% | `swapcontext` |
| 2927953128 | 2.75% | `TCMallocInternalCfree` |
| 2728997651 | 2.56% | `std::collections::list::List::_realloc` |
| 2078363432 | 1.95% | `h2_server::main` |
| 2033090684 | 1.91% | `std::utils::variant::Variant::__init__` |
| 1550438628 | 1.45% | `__tls_get_addr@plt` |
| 1311532320 | 1.23% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1258274065 | 1.18% | `src::http::headers::_to_lower` |
| 1164700907 | 1.09% | `src::h2::hpack::HpackDecoder::decode` |
| 1142831190 | 1.07% | `[libc.so.6]` |
| 1102595927 | 1.03% | `std::collections::list::List::extend[::Bool,LITOrigin[$1._mlir_value],::Origin[$1, $2]]` |
| 1023693064 | 0.96% | `KGEN_CompilerRT_AlignedAlloc` |
| 909957750 | 0.85% | `KGEN_CompilerRT_AlignedFree` |
| 855853546 | 0.80% | `getcontext` |
| 837426701 | 0.79% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |
| 698161850 | 0.65% | `std::collections::deque::Deque::append` |
| 653018595 | 0.61% | `M::AsyncRT::TCMallocGlobals::tc_delete` |
| 636407505 | 0.60% | `src::h2::connection::H2Connection::send_data` |
| 562755879 | 0.53% | `src::http::handler::ResponseWriter::try_send_body` |
| 562753186 | 0.53% | `M::AsyncRT::TCMallocGlobals::tc_new` |

## Top 30 by INCLUSIVE time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
| 106648509461 | 100.00% | `h2_server` |
| 65830707823 | 61.73% | `h2_server::main` |
| 28453671788 | 26.68% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 26111686930 | 24.48% | `src::h2::connection::H2Connection::receive_data` |
| 24754011451 | 23.21% | `[libAsyncRTRuntimeGlobals.so]` |
| 20863057647 | 19.56% | `std::collections::list::List::_realloc` |
| 15019176212 | 14.08% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 14354484104 | 13.46% | `[unknown]` |
| 13737746488 | 12.88% | `src::h2::hpack::HpackDecoder::decode` |
| 11708111253 | 10.98% | `src::h2::hpack::HpackDecoder::_decode_literal` |
| 11378506817 | 10.67% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 9237032391 | 8.66% | `src::h2::connection::H2Connection::send_headers` |
| 8173865369 | 7.66% | `bench::handler::bench_h2_body_fn` |
| 7932345901 | 7.44% | `boucle::stackful::_coro_trampoline` |
| 4891603345 | 4.59% | `src::h2::connection::H2Connection::send_data` |
| 4651020803 | 4.36% | `__tls_get_addr` |
| 3538277568 | 3.32% | `src::h2::frame::encode_frame` |
| 3506591285 | 3.29% | `main` |
| 3484654746 | 3.27% | `TCMallocInternalCfree` |
| 3416908919 | 3.20% | `swapcontext` |
| 3237629566 | 3.04% | `std::collections::dict::Dict::_insert[::Bool]` |
| 3036506774 | 2.85% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |
| 2587250994 | 2.43% | `src::http::headers::_to_lower` |
| 2135084602 | 2.00% | `src::h2::h2_coro_server::_free_stream` |
| 2033090684 | 1.91% | `std::utils::variant::Variant::__init__` |
| 1835659577 | 1.72% | `src::h2::payloads::decode_headers_payload` |
| 1826262785 | 1.71% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1687905007 | 1.58% | `std::collections::list::List::extend` |
| 1627389131 | 1.53% | `[libc.so.6]` |
| 1550438628 | 1.45% | `__tls_get_addr@plt` |
