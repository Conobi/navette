# H2 Hotspots — `174aed8`

Generated 2026-04-25T16:24:08Z from `bench/profile/runs/20260425-182305-174aed8/perf-folded.txt`.

- **Total weight:** 107136412519
- **Unique stacks:** 471
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
| 20210402417 | 18.86% | `[libAsyncRTRuntimeGlobals.so]` |
| 9072574853 | 8.47% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 8133130896 | 7.59% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 6860471906 | 6.40% | `[unknown]` |
| 4319225432 | 4.03% | `src::h2::connection::H2Connection::receive_data` |
| 4198312215 | 3.92% | `__tls_get_addr` |
| 4029339903 | 3.76% | `src::h2::connection::H2Connection::send_headers` |
| 3918239995 | 3.66% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 3698533456 | 3.45% | `bench::handler::bench_h2_body_fn` |
| 3639548622 | 3.40% | `swapcontext` |
| 3140001203 | 2.93% | `TCMallocInternalCfree` |
| 2917540415 | 2.72% | `std::collections::dict::Dict::_insert[::Bool]` |
| 2662250145 | 2.48% | `std::collections::list::List::_realloc` |
| 2347111447 | 2.19% | `std::utils::variant::Variant::__init__` |
| 2042134833 | 1.91% | `h2_server::main` |
| 1569801487 | 1.47% | `src::http::headers::_to_lower` |
| 1310733160 | 1.22% | `__tls_get_addr@plt` |
| 1278877387 | 1.19% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1019193717 | 0.95% | `KGEN_CompilerRT_AlignedAlloc` |
| 898149377 | 0.84% | `src::h2::connection::H2Connection::send_data` |
| 883890634 | 0.83% | `src::h2::hpack::HpackDecoder::decode` |
| 864152621 | 0.81% | `M::AsyncRT::TCMallocGlobals::tc_new` |
| 858581673 | 0.80% | `src::h2::connection::H2Connection::_queue_frame` |
| 829760715 | 0.77% | `std::collections::list::List::extend[::Bool,LITOrigin[$1._mlir_value],::Origin[$1, $2]]` |
| 828504531 | 0.77% | `getcontext` |
| 812304609 | 0.76% | `M::AsyncRT::TCMallocGlobals::tc_delete` |
| 784351375 | 0.73% | `[libc.so.6]` |
| 760237040 | 0.71% | `KGEN_CompilerRT_AlignedFree` |
| 747115647 | 0.70% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |
| 690000067 | 0.64% | `src::http::handler::ResponseWriter::try_send_body` |

## Top 30 by INCLUSIVE time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
| 107136412519 | 100.00% | `h2_server` |
| 63191165042 | 58.98% | `h2_server::main` |
| 28005006439 | 26.14% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 24242674228 | 22.63% | `src::h2::connection::H2Connection::receive_data` |
| 22764398073 | 21.25% | `[libAsyncRTRuntimeGlobals.so]` |
| 18136951619 | 16.93% | `std::collections::list::List::_realloc` |
| 15265705804 | 14.25% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 14662554835 | 13.69% | `[unknown]` |
| 12785969399 | 11.93% | `src::h2::hpack::HpackDecoder::decode` |
| 11169413832 | 10.43% | `src::h2::hpack::HpackDecoder::_decode_literal` |
| 10589888376 | 9.88% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 8916416070 | 8.32% | `boucle::stackful::_coro_trampoline` |
| 8908112943 | 8.31% | `bench::handler::bench_h2_body_fn` |
| 8674614531 | 8.10% | `src::h2::connection::H2Connection::send_headers` |
| 4652268002 | 4.34% | `src::h2::connection::H2Connection::send_data` |
| 4198312215 | 3.92% | `__tls_get_addr` |
| 3949028161 | 3.69% | `swapcontext` |
| 3827801867 | 3.57% | `src::h2::connection::H2Connection::_queue_frame` |
| 3741500327 | 3.49% | `TCMallocInternalCfree` |
| 3474952864 | 3.24% | `main` |
| 3456158442 | 3.23% | `src::http::headers::Headers::add` |
| 3026409739 | 2.82% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |
| 2984422227 | 2.79% | `src::http::headers::_to_lower` |
| 2980872820 | 2.78% | `std::collections::dict::Dict::_insert[::Bool]` |
| 2347111447 | 2.19% | `std::utils::variant::Variant::__init__` |
| 2174227249 | 2.03% | `src::h2::h2_coro_server::_free_stream` |
| 1878115556 | 1.75% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1858989619 | 1.74% | `src::h2::h2_coro_server::H2CoroServer::_resume_and_handle_error` |
| 1727488224 | 1.61% | `src::h2::payloads::decode_headers_payload` |
| 1310733160 | 1.22% | `__tls_get_addr@plt` |
