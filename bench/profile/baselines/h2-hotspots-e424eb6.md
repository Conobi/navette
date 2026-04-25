# H2 Hotspots — `e424eb6`

Generated 2026-04-25T16:20:40Z from `bench/profile/runs/20260425-181937-e424eb6/perf-folded.txt`.

- **Total weight:** 110681729474
- **Unique stacks:** 407
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
| 21599748133 | 19.52% | `[libAsyncRTRuntimeGlobals.so]` |
| 8623636393 | 7.79% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 7766864289 | 7.02% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 6732139964 | 6.08% | `[unknown]` |
| 4570256064 | 4.13% | `src::http::headers::_to_lower` |
| 4411502533 | 3.99% | `src::h2::connection::H2Connection::receive_data` |
| 4160078815 | 3.76% | `__tls_get_addr` |
| 3983519697 | 3.60% | `src::h2::connection::H2Connection::send_headers` |
| 3446101202 | 3.11% | `std::collections::string::string::String::_iadd[LITImmutOrigin,::Origin[::Bool` |
| 3378824554 | 3.05% | `swapcontext` |
| 3167028751 | 2.86% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 3110017828 | 2.81% | `std::collections::dict::Dict::_insert[::Bool]` |
| 2615011328 | 2.36% | `TCMallocInternalCfree` |
| 2421363764 | 2.19% | `std::collections::string::string::String::unsafe_ptr_mut` |
| 2109431704 | 1.91% | `std::utils::variant::Variant::__init__` |
| 2017962320 | 1.82% | `h2_server::main` |
| 1931650211 | 1.75% | `bench::handler::bench_h2_body_fn` |
| 1899535675 | 1.72% | `std::collections::list::List::_realloc` |
| 1650032055 | 1.49% | `std::collections::string::string::chr` |
| 1352910466 | 1.22% | `std::builtin::simd::SIMD::write_to[::Writer]` |
| 1280688998 | 1.16% | `__tls_get_addr@plt` |
| 1221385633 | 1.10% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1151915237 | 1.04% | `std::collections::list::List::extend[::Bool,LITOrigin[$1._mlir_value],::Origin[$1, $2]]` |
| 869055533 | 0.79% | `[libc.so.6]` |
| 865718516 | 0.78% | `src::h2::hpack::HpackDecoder::decode` |
| 845946840 | 0.76% | `src::http::handler::ResponseWriter::try_send_body` |
| 810019470 | 0.73% | `KGEN_CompilerRT_AlignedAlloc` |
| 694337067 | 0.63% | `getcontext` |
| 631514957 | 0.57% | `src::h2::connection::H2Connection::_queue_frame` |
| 628317693 | 0.57% | `M::AsyncRT::TCMallocGlobals::tc_new` |

## Top 30 by INCLUSIVE time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
| 110681729474 | 100.00% | `h2_server` |
| 65022418041 | 58.75% | `h2_server::main` |
| 27628590290 | 24.96% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 25220137596 | 22.79% | `src::h2::connection::H2Connection::receive_data` |
| 24345506678 | 22.00% | `[libAsyncRTRuntimeGlobals.so]` |
| 18814377147 | 17.00% | `std::collections::list::List::_realloc` |
| 17264534845 | 15.60% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 15739257103 | 14.22% | `[unknown]` |
| 12543663536 | 11.33% | `src::h2::hpack::HpackDecoder::decode` |
| 10461838412 | 9.45% | `src::h2::hpack::HpackDecoder::_decode_literal` |
| 10245420445 | 9.26% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 9284951990 | 8.39% | `boucle::stackful::_coro_trampoline` |
| 8752194058 | 7.91% | `bench::handler::bench_h2_body_fn` |
| 8443562883 | 7.63% | `src::h2::connection::H2Connection::send_headers` |
| 7932916039 | 7.17% | `src::http::headers::_to_lower` |
| 4627573278 | 4.18% | `src::h2::connection::H2Connection::send_data` |
| 4160078815 | 3.76% | `__tls_get_addr` |
| 4027652677 | 3.64% | `std::collections::string::string::String::_iadd[LITImmutOrigin,::Origin[::Bool` |
| 3713018289 | 3.35% | `swapcontext` |
| 3426347860 | 3.10% | `main` |
| 3378944565 | 3.05% | `src::h2::connection::H2Connection::_queue_frame` |
| 3193093468 | 2.88% | `TCMallocInternalCfree` |
| 3152054470 | 2.85% | `std::collections::dict::Dict::_insert[::Bool]` |
| 2967988911 | 2.68% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |
| 2548441312 | 2.30% | `std::collections::string::string::String::unsafe_ptr_mut` |
| 2390415672 | 2.16% | `std::collections::string::string::String::__init__[*::Writable]` |
| 2384725195 | 2.15% | `src::h2::h2_coro_server::_free_stream` |
| 2109431704 | 1.91% | `std::utils::variant::Variant::__init__` |
| 2101101815 | 1.90% | `std::collections::string::string::chr` |
| 1801612461 | 1.63% | `src::h2::payloads::decode_headers_payload` |
