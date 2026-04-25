# H2 Hotspots — `d6fdbcb`

Generated 2026-04-25T15:02:26Z from `bench/profile/runs/20260425-170117-d6fdbcb/perf-folded.txt`.

- **Total weight:** 114624552227
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
| 20885556308 | 18.22% | `[libAsyncRTRuntimeGlobals.so]` |
| 9079605104 | 7.92% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 7743715036 | 6.76% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 7407212759 | 6.46% | `[unknown]` |
| 5079308448 | 4.43% | `src::http::headers::_to_lower` |
| 4690226511 | 4.09% | `__tls_get_addr` |
| 4527246789 | 3.95% | `src::h2::connection::H2Connection::receive_data` |
| 4154591261 | 3.62% | `src::h2::connection::H2Connection::send_headers` |
| 3959345988 | 3.45% | `std::collections::string::string::String::_iadd[LITImmutOrigin,::Origin[::Bool` |
| 3385389399 | 2.95% | `swapcontext` |
| 3379870126 | 2.95% | `std::collections::dict::Dict::_insert[::Bool]` |
| 3295123205 | 2.87% | `std::collections::string::string::String::unsafe_ptr_mut` |
| 3108678474 | 2.71% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 2840707041 | 2.48% | `TCMallocInternalCfree` |
| 2595185964 | 2.26% | `std::collections::list::List::_realloc` |
| 2079560389 | 1.81% | `std::utils::variant::Variant::__init__` |
| 1971289163 | 1.72% | `bench::handler::bench_h2_body_fn` |
| 1810462059 | 1.58% | `std::collections::string::string::chr` |
| 1716311166 | 1.50% | `h2_server::main` |
| 1508876990 | 1.32% | `__tls_get_addr@plt` |
| 1382903341 | 1.21% | `std::builtin::simd::SIMD::write_to[::Writer]` |
| 978909346 | 0.85% | `src::h2::hpack::HpackDecoder::decode` |
| 963898643 | 0.84% | `KGEN_CompilerRT_AlignedAlloc` |
| 933768422 | 0.81% | `getcontext` |
| 916408075 | 0.80% | `std::collections::string::string::String::__init__[*::Writable]` |
| 775487959 | 0.68% | `std::collections::deque::Deque::append` |
| 744095402 | 0.65% | `std::collections::list::List::extend[::Bool,LITOrigin[$1._mlir_value],::Origin[$1, $2]]` |
| 720008464 | 0.63% | `[libc.so.6]` |
| 705824092 | 0.62% | `src::h2::connection::H2Connection::_queue_frame` |
| 676376959 | 0.59% | `KGEN_CompilerRT_AlignedFree` |

## Top 30 by INCLUSIVE time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
| 114624552227 | 100.00% | `h2_server` |
| 66711046351 | 58.20% | `h2_server::main` |
| 28408612974 | 24.78% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 26317451816 | 22.96% | `src::h2::connection::H2Connection::receive_data` |
| 23605813466 | 20.59% | `[libAsyncRTRuntimeGlobals.so]` |
| 20702868868 | 18.06% | `std::collections::list::List::_realloc` |
| 17496868508 | 15.26% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 16679722727 | 14.55% | `[unknown]` |
| 13919514718 | 12.14% | `src::h2::hpack::HpackDecoder::decode` |
| 11963727632 | 10.44% | `src::h2::hpack::HpackDecoder::_decode_literal` |
| 11876205710 | 10.36% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 9643170346 | 8.41% | `boucle::stackful::_coro_trampoline` |
| 9113659077 | 7.95% | `bench::handler::bench_h2_body_fn` |
| 9012750564 | 7.86% | `src::h2::connection::H2Connection::send_headers` |
| 8622034328 | 7.52% | `src::http::headers::_to_lower` |
| 4830353057 | 4.21% | `src::h2::connection::H2Connection::send_data` |
| 4732967463 | 4.13% | `std::collections::string::string::String::_iadd[LITImmutOrigin,::Origin[::Bool` |
| 4690226511 | 4.09% | `__tls_get_addr` |
| 3864794443 | 3.37% | `TCMallocInternalCfree` |
| 3634194916 | 3.17% | `swapcontext` |
| 3516548595 | 3.07% | `std::collections::dict::Dict::_insert[::Bool]` |
| 3516065527 | 3.07% | `std::collections::string::string::String::unsafe_ptr_mut` |
| 3438659945 | 3.00% | `src::h2::connection::H2Connection::_queue_frame` |
| 3085197312 | 2.69% | `main` |
| 2624098452 | 2.29% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |
| 2484006144 | 2.17% | `std::collections::string::string::chr` |
| 2079560389 | 1.81% | `std::utils::variant::Variant::__init__` |
| 2068936159 | 1.80% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1982374756 | 1.73% | `src::h2::h2_coro_server::_free_stream` |
| 1814159102 | 1.58% | `src::h2::payloads::decode_headers_payload` |
