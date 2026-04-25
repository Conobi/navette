# H2 Hotspots — `b06a061`

Generated 2026-04-25T16:01:15Z from `bench/profile/runs/20260425-180008-b06a061/perf-folded.txt`.

- **Total weight:** 113556657869
- **Unique stacks:** 419
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
| 20452212634 | 18.01% | `[libAsyncRTRuntimeGlobals.so]` |
| 8784692428 | 7.74% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 8106044284 | 7.14% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 6615148811 | 5.83% | `[unknown]` |
| 5028297589 | 4.43% | `src::http::headers::_to_lower` |
| 4273137316 | 3.76% | `__tls_get_addr` |
| 4115029895 | 3.62% | `src::h2::connection::H2Connection::receive_data` |
| 3917563333 | 3.45% | `src::h2::connection::H2Connection::send_headers` |
| 3594276294 | 3.17% | `std::collections::string::string::String::_iadd[LITImmutOrigin,::Origin[::Bool` |
| 3441902811 | 3.03% | `swapcontext` |
| 3308920602 | 2.91% | `std::collections::dict::Dict::_insert[::Bool]` |
| 3212551070 | 2.83% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 3071578894 | 2.70% | `TCMallocInternalCfree` |
| 3026990295 | 2.67% | `std::collections::string::string::String::unsafe_ptr_mut` |
| 2501454927 | 2.20% | `bench::handler::bench_h2_body_fn` |
| 2326077749 | 2.05% | `std::collections::list::List::_realloc` |
| 2079657368 | 1.83% | `h2_server::main` |
| 1779690112 | 1.57% | `std::collections::string::string::chr` |
| 1752382477 | 1.54% | `std::utils::variant::Variant::__init__` |
| 1595832987 | 1.41% | `std::builtin::simd::SIMD::write_to[::Writer]` |
| 1345631295 | 1.18% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1224743343 | 1.08% | `__tls_get_addr@plt` |
| 1146667619 | 1.01% | `KGEN_CompilerRT_AlignedAlloc` |
| 1108865714 | 0.98% | `getcontext` |
| 1068554867 | 0.94% | `[libc.so.6]` |
| 839049215 | 0.74% | `src::h2::hpack::HpackDecoder::decode` |
| 751151615 | 0.66% | `std::collections::deque::Deque::append` |
| 721508241 | 0.64% | `KGEN_CompilerRT_AlignedFree` |
| 719686163 | 0.63% | `src::h2::connection::H2Connection::send_data` |
| 713716916 | 0.63% | `M::AsyncRT::TCMallocGlobals::tc_delete` |

## Top 30 by INCLUSIVE time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
| 113556657869 | 100.00% | `h2_server` |
| 65893678746 | 58.03% | `h2_server::main` |
| 26536694433 | 23.37% | `src::h2::connection::H2Connection::receive_data` |
| 26113802877 | 23.00% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 23103686999 | 20.35% | `[libAsyncRTRuntimeGlobals.so]` |
| 20860377305 | 18.37% | `std::collections::list::List::_realloc` |
| 17683691370 | 15.57% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 15321993743 | 13.49% | `[unknown]` |
| 14642194646 | 12.89% | `src::h2::hpack::HpackDecoder::decode` |
| 12906271282 | 11.37% | `src::h2::hpack::HpackDecoder::_decode_literal` |
| 12601007560 | 11.10% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 10392863932 | 9.15% | `boucle::stackful::_coro_trampoline` |
| 10039182936 | 8.84% | `bench::handler::bench_h2_body_fn` |
| 8861803949 | 7.80% | `src::http::headers::_to_lower` |
| 8474155459 | 7.46% | `src::h2::connection::H2Connection::send_headers` |
| 4612227924 | 4.06% | `std::collections::string::string::String::_iadd[LITImmutOrigin,::Origin[::Bool` |
| 4273137316 | 3.76% | `__tls_get_addr` |
| 4049804709 | 3.57% | `src::h2::connection::H2Connection::send_data` |
| 3802571000 | 3.35% | `TCMallocInternalCfree` |
| 3739074830 | 3.29% | `swapcontext` |
| 3458764316 | 3.05% | `src::h2::connection::H2Connection::_queue_frame` |
| 3457242919 | 3.04% | `main` |
| 3392047750 | 2.99% | `std::collections::dict::Dict::_insert[::Bool]` |
| 3189261932 | 2.81% | `std::collections::string::string::String::unsafe_ptr_mut` |
| 2852591540 | 2.51% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |
| 2766647224 | 2.44% | `std::collections::string::string::String::__init__[*::Writable]` |
| 2306673360 | 2.03% | `std::collections::string::string::chr` |
| 2237021481 | 1.97% | `src::h2::h2_coro_server::_free_stream` |
| 1974807614 | 1.74% | `std::builtin::simd::SIMD::write_to[::Writer]` |
| 1918381531 | 1.69% | `src::h2::payloads::decode_headers_payload` |
