<h1 align="center">
  ⛵<br/>
  Navette
</h1>

<p align="center">
  <b>N</b>avette · <b>A</b>llows · <b>V</b>ersatile · <b>E</b>ncrypted · <b>T</b>wo-way · <b>T</b>ransfers · <b>E</b>ffortlessly
</p>

<p align="center">
  <i>Pure-Mojo networking stack: QUIC, HTTP/3, HTTP/2, HTTP/1.1.</i>
</p>

> [!WARNING]
> **Active development — not production-ready.**
> APIs are unstable, and the only supported I/O backend is `io_uring` on Linux.
---

## Why Navette

Most networking stacks start at HTTP/1.1 and bolt on newer protocols as they age. Navette starts at HTTP/3 and treats H1/H2 as graceful projections of the same shape.

- **HTTP/3 first.** Designed against H3 semantics. H2 and H1 are projections, not vice versa.
- **One client, three protocols.** ALPN picks the wire; you write the request once. H3 only on Alt-Svc — never speculative.
- **Sans-I/O everywhere.** Zero I/O imports in `navette/`. Bring your own loop; we ship `boucle` (io_uring) for the examples.
- **One native dep: rustls.** No OpenSSL, no BoringSSL. A thin C-FFI shim is the only non-Mojo code on the protocol path.
- **Compression is the OS's problem.** Gzip and brotli go through the system `zlib` + `libbrotlidec`. A CVE is a package update, not our release.
- **Strict by default.** 24 named leniency flags for H1 — every relaxation is opt-in, every shape is documented.
- **Security MUST.** RFC `SHOULD`s and `MAY`s are mandatory: PN skipping, anti-amplification, ACK validation, PATH_RESPONSE caps. Never off.
- **Conformance-driven.** Cross-validated against h11, httptools, hyperframe, `hpack`, aioquic, quiche. RFC bugs caught — and fixed.
- **Three handler shapes.** Callback (`*HandlerServer`), coroutine (`*CoroServer`), explicit-yield streaming (`*StreamingServer`).

### Protocol coverage

| Protocol | Server | Client | RFC | Notes |
|---|:-:|:-:|---|---|
| HTTP/3 over QUIC | ✅ | ✅ | 9114 | Primary target. |
| HTTP/2 + TLS + ALPN | ✅ | ✅ | 9113 | HPACK (7541). |
| HTTP/1.1 | ✅ | ✅ | 9112 | Strict parser + 24 leniency flags. |
| QUIC v1 | ✅ | ✅ | 9000 | CUBIC + HyStart++, ECN, stateless Retry, PN skipping. |
| QPACK | ✅ | ✅ | 9204 | Static-only + Huffman; dynamic table post-v1. |
| TLS 1.3 | ✅ | ✅ | — | `rustls` 0.23. |
| Content decoding | gzip / brotli | gzip / brotli | 9110 §8.4 | System libs via `libcompress-mojo`. |

---

## Install / build

Navette is a Mojo library. You build against it with [`mojox`](https://pypi.org/project/mojox/) under [`uv`](https://docs.astral.sh/uv/).

```bash
# clone Navette + sibling deps
git clone https://github.com/Conobi/navette.git
git clone https://github.com/Conobi/boucle.git   # io_uring I/O backend

cd navette
./scripts/gen_test_certs.sh   # one-time: self-signed certs for the examples
uv sync                       # pulls mojox + the Mojo compiler
```

## Run the demos

Each example is a self-contained Mojo binary with its own `pyproject.toml`.

| Example | What it does |
|---|---|
| [`examples/hello_h1_server`](examples/hello_h1_server) | Plain HTTP/1.1 server on `:8080`. |
| [`examples/hello_h2_server`](examples/hello_h2_server) | HTTP/2 + TLS + ALPN on `:4433`. |
| [`examples/hello_h3_server`](examples/hello_h3_server) | HTTP/3 over QUIC on `:4433/udp`. |
| [`examples/fetch`](examples/fetch) | `curl`-equivalent client. Picks H3 if Alt-Svc advertises, else H2/H1 via ALPN. |
| [`examples/h2_client`](examples/h2_client) | Bare HTTP/2 client. |
| [`examples/reverse_proxy`](examples/reverse_proxy) | TLS reverse proxy with token auth (H1 ⇄ H1, H2 ⇄ H1/H2). |

Same run pattern for all of them:

```bash
cd examples/hello_h3_server
uv sync
uv run mojox build main.mojo -o hello_h3_server
./hello_h3_server
# in another shell:
h2load --h3 -n 4 -c 1 https://127.0.0.1:4433/
```

## Use as a library

You write a handler that implements `StreamHandler`; the server owns everything else (socket, TLS, demux, body backpressure):

```mojo
from navette.http.handler import (
    StreamHandler, Request, RecvBody, ResponseWriter,
    Capabilities, StreamError, BodyFrame,
)
from navette.http.headers import Headers
from navette.http.status import StatusCode


struct HelloHandler(StreamHandler):
    def __init__(out self): pass
    def __init__(out self, *, deinit take: Self): pass

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        var hdrs = Headers()
        hdrs.set("content-type", "text/plain")
        resp.send_status(StatusCode(200), hdrs^)

        var payload = String("Hello, H3!\n").as_bytes()
        var buf = List[UInt8](capacity=len(payload))
        for b in payload: buf.append(b)
        _ = resp.try_send_body(BodyFrame.data(buf^))
        _ = resp.try_send_body(BodyFrame.end())

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises: pass
    def on_request_end   (mut self, mut body: RecvBody, mut resp: ResponseWriter) raises: pass
    def on_send_drained  (mut self, mut resp: ResponseWriter) raises: pass
    def on_reset         (mut self, error: StreamError): pass
```

The same handler trait drives H1, H2, and H3 servers. For the full wiring (rustls config, UDP socket, transport params, `serve_forever`) see [`examples/hello_h3_server/main.mojo`](examples/hello_h3_server/main.mojo).

---

## Benchmarks

All numbers are pre-1.0, single-host, single-NIC, reproducible from the scripts under `bench/`.

### HTTP/3 — vs TQUIC

Reference: [`TQUIC`](https://github.com/Tencent/tquic) (Tencent), one of the fastest pure-Rust QUIC stacks. Both sides run single-thread / single-socket. Driver: `tquic_client` for long-conn throughput, `h2load --h3` for short-conn rps. TLS via rustls 0.23 (Navette) / boringssl (TQUIC). Endpoint: `GET /` → small response. Reproducer: `bench/quic_perf/scripts/bench.sh`.

| Workload | Driver | Navette | TQUIC | Navette/TQUIC |
|---|---|---:|---:|---:|
| Long-lived conn, 1k req-pipeline (steady-state throughput) | `tquic_client` | ~5,400 req/s | ~4,700 req/s | **1.15×** |
| Short-lived conn, 1 req/conn (handshake-bound rps) | `h2load --h3` |  ~412 req/s | ~885 req/s | **0.466×** |

**Long-conn parity** was reached via the four-lever stack: io_uring multishot recvmsg → zero-copy HP+AEAD FFI → batched key-derivation FFI → IORING_ACCEPT_MULTISHOT.

**Short-conn gap** is structural and well-characterized. Server CPU sits at ~55%; the io_uring loop parks 97.7% of wall-clock in `io_uring_enter` with recvmsg drawing 1 CQE per wake — per-wake productivity, not raw compute, is the bound. `_flush_impl` decomposed to ≥97% via existing per-packet + h3-phases counters; dominant sub-legs are `sm_us → ffi_read_hs` (rustls, ~30% of `_flush_impl`) and `drain_egress_build` (~19%). 17 hypothesis-passes between handshake-cycle close and v1 freeze closed without a viable lever — see [`bench/quic_perf/results/REFERENCE.md`](bench/quic_perf/results/REFERENCE.md) for the full ledger.

### HTTP/1.1 plaintext — `wrk2` calibrated-peak (single-worker)

Methodology from [Flare's](https://github.com/ehsanmok/flare) `docs/benchmark.md` — `wrk2` calibrated-peak, `GET /plaintext` → 13 B "Hello, World!", HTTP/1.1 keep-alive. Every server runs single-worker, pinned to CPU 0; `wrk2` pinned to CPU 2; 5 measurement rounds; coordinated-omission-corrected. Reproducer: `bench/flare_compare/scripts/bench_vs_baseline.sh`.

| Server | Language | Req/s (median) | p99 (ms) | p99.9 (ms) | vs Navette |
|---|---|---:|---:|---:|---:|
| nginx       | C        | 41,211 | 12.69 ± 3.59  | 18.64 ± 18.31 | 1.51× |
| hyper       | Rust     | 40,310 | 10.58 ± 1.18  | 17.45 ± 2.59  | 1.47× |
| actix-web   | Rust     | 37,974 | 11.53 ± 2.45  | 15.73 ± 4.69  | 1.39× |
| flare       | Mojo     | 36,396 |  9.98 ± 0.53  | 15.34 ± 1.84  | 1.33× |
| axum        | Rust     | 36,351 | 10.49 ± 1.03  | 14.21 ± 1.41  | 1.33× |
| **navette** | **Mojo** | **27,337** | **7.81 ± 30.24**  | **9.76 ± 50.81**  | **1.00×** |
| go-nethttp  | Go       | 23,966 | 11.77 ± 10.42 | 19.65 ± 22.39 | 0.88× |

Run: `2026-05-22T1845`, on a NixOS VPS with an Intel Xeon Platinum 8260 (8 logical, server pinned to CPU 0). Throughput σ% is 1.28% — stable. Navette holds the lowest *median* tail latency in the field, but the σ on the tail is large (±30 ms on p99, ±50 ms on p99.9) — individual rounds had occasional spikes that the other stacks didn't. Read the tail numbers with that asymmetry in mind.

---

## Project layout

```
navette/        Mojo source (sans-I/O protocol code)
├── http/      Method, headers, body, URL, content-decoder
├── h1/        HTTP/1.1
├── h2/        HTTP/2 + HPACK
├── h3/        HTTP/3 + QPACK
├── quic/      QUIC v1 (+ cc/ subsystem)
├── tls/       librustls-mojo FFI surface
├── compress/  libcompress-mojo FFI surface
└── io/        ECN, loopback helpers

crates/         Native Rust + C shims (TLS, compression)
conformance/    Test oracles + cross-validation vectors
tests/          Unit + integration suite (grouped by module)
bench/          HttpArena benchmark stack
examples/       End-to-end runnable demos
```

## License

[MIT](LICENSE)
