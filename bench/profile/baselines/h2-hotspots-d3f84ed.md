# H2 Hotspots — `d3f84ed`

Generated 2026-04-25T16:34:07Z from `bench/profile/runs/20260425-183201-d3f84ed/perf-folded.txt`.

- **Total weight:** 229313019580
- **Unique stacks:** 528
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
| 43547886430 | 18.99% | `[libAsyncRTRuntimeGlobals.so]` |
| 16507444702 | 7.20% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 14136743880 | 6.16% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 13666238672 | 5.96% | `__tls_get_addr` |
| 13140776174 | 5.73% | `[unknown]` |
| 9213029290 | 4.02% | `src::h2::connection::H2Connection::receive_data` |
| 8815943920 | 3.84% | `src::http::headers::_to_lower` |
| 7333566155 | 3.20% | `std::collections::string::string::String::_iadd[LITImmutOrigin,::Origin[::Bool` |
| 6813644261 | 2.97% | `src::h2::connection::H2Connection::send_headers` |
| 6450498853 | 2.81% | `swapcontext` |
| 6356770921 | 2.77% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 6344069871 | 2.77% | `std::collections::dict::Dict::_insert[::Bool]` |
| 5999750558 | 2.62% | `TCMallocInternalCfree` |
| 5857012008 | 2.55% | `std::collections::string::string::String::unsafe_ptr_mut` |
| 5031210374 | 2.19% | `std::collections::list::List::_realloc` |
| 4386287424 | 1.91% | `bench::handler::bench_h2_body_fn` |
| 4076902291 | 1.78% | `h2_server::main` |
| 3906275462 | 1.70% | `std::utils::variant::Variant::__init__` |
| 3880671718 | 1.69% | `std::collections::string::string::chr` |
| 2533930716 | 1.11% | `__tls_get_addr@plt` |
| 2344884768 | 1.02% | `boucle::stackful::_coro_trampoline` |
| 2118329460 | 0.92% | `src::h2::connection::H2Connection::_queue_frame` |
| 2012176890 | 0.88% | `std::collections::string::string::String::__init__[*::Writable]` |
| 1914739326 | 0.83% | `getcontext` |
| 1876612949 | 0.82% | `src::h2::hpack::HpackDecoder::decode` |
| 1818950868 | 0.79% | `src::h2::connection::H2Connection::send_data` |
| 1811565534 | 0.79% | `std::collections::list::List::extend[::Bool,LITOrigin[$1._mlir_value],::Origin[$1, $2]]` |
| 1731799367 | 0.76% | `KGEN_CompilerRT_AlignedAlloc` |
| 1632112150 | 0.71% | `[libc.so.6]` |
| 1266814108 | 0.55% | `src::http::handler::ResponseWriter::try_send_body` |

## Top 30 by INCLUSIVE time

| Weight | % of total | Symbol |
|-------:|-----------:|--------|
| 229313019580 | 100.00% | `h2_server` |
| 139675394016 | 60.91% | `h2_server::main` |
| 62073270583 | 27.07% | `src::h2::h2_coro_server::H2CoroServer::_drain_responses` |
| 52956699982 | 23.09% | `[libAsyncRTRuntimeGlobals.so]` |
| 50695822665 | 22.11% | `src::h2::connection::H2Connection::receive_data` |
| 49056642581 | 21.39% | `std::collections::list::List::_realloc` |
| 33783947330 | 14.73% | `src::h2::h2_coro_server::H2CoroServer::_dispatch_events` |
| 32086558823 | 13.99% | `[unknown]` |
| 27032743579 | 11.79% | `src::h2::hpack::HpackDecoder::decode` |
| 26566122552 | 11.59% | `main` |
| 23232488864 | 10.13% | `src::h2::hpack::HpackDecoder::_decode_literal` |
| 22864107563 | 9.97% | `src::h2::hpack::HpackDecoder::_decode_string` |
| 19954497562 | 8.70% | `boucle::stackful::_coro_trampoline` |
| 19856364540 | 8.66% | `src::h2::connection::H2Connection::send_data` |
| 17596216627 | 7.67% | `src::h2::connection::H2Connection::_queue_frame` |
| 16827923845 | 7.34% | `src::h2::connection::H2Connection::send_headers` |
| 16083041678 | 7.01% | `bench::handler::bench_h2_body_fn` |
| 15003453334 | 6.54% | `src::http::headers::_to_lower` |
| 13666238672 | 5.96% | `__tls_get_addr` |
| 9141890037 | 3.99% | `std::collections::string::string::String::_iadd[LITImmutOrigin,::Origin[::Bool` |
| 8237321666 | 3.59% | `TCMallocInternalCfree` |
| 7153307383 | 3.12% | `swapcontext` |
| 6459391650 | 2.82% | `std::collections::dict::Dict::_insert[::Bool]` |
| 6337901524 | 2.76% | `std::collections::string::string::String::unsafe_ptr_mut` |
| 5679209466 | 2.48% | `src::h2::h2_coro_server::H2CoroServer::_maybe_cleanup_stream` |
| 5086332437 | 2.22% | `std::collections::string::string::chr` |
| 4317167936 | 1.88% | `src::h2::h2_coro_server::_free_stream` |
| 3906275462 | 1.70% | `std::utils::variant::Variant::__init__` |
| 3412146626 | 1.49% | `src::h2::payloads::decode_headers_payload` |
| 3303037653 | 1.44% | `src::h2::h2_coro_server::H2CoroServer::_resume_and_handle_error` |
