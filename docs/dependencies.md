# mojo-net external dependencies

Living map of every external dependency mojo-net carries. Last updated: 2026-05-13.

When dependencies change, update this doc in the same PR. The deps-health smoke test
(`scripts/check_integrations.sh`) asserts a subset of these invariants on every CI run.

## Audience

- Future maintainers asking "what does this repo actually depend on?"
- Anyone planning a major upgrade (Python minor, Mojo compiler, rustls, etc.)
- Security review: complete BOM for SBOM purposes.

## Layout

1. [Python — runtime / interop](#1-python--runtime--interop)
2. [Mojo sibling projects](#2-mojo-sibling-projects)
3. [Rust crates / FFI shims](#3-rust-crates--ffi-shims)
4. [C / system shared libraries](#4-c--system-shared-libraries)
5. [Build / toolchain](#5-build--toolchain)
6. [Container & bench dependencies](#6-container--bench-dependencies)
7. [Conformance external corpora](#7-conformance-external-corpora)
8. [Risk register](#8-risk-register)

---

## 1. Python — runtime / interop

### CPython embedding posture

- **Where**: `tests/` and `conformance/` only — `src/` and `fetch/` do not import Python.
- **API surface**: full CPython via Mojo's `std.python` (`Python.import_module`, attribute access, `__call__`). Not Limited API.
- **Provided by**: Mojo runtime, which resolves libpython from the active uv-managed venv.
- **Python floor**: `>=3.11` (set in `pyproject.toml`; bumped from 3.10 on 2026-05-13 so `oracle_env_check.py` and `check_integrations.sh` can use stdlib `tomllib`).

### Declared Python packages

`pyproject.toml` runtime (`[project].dependencies`):

| Package            | Version | Purpose                                                      |
|--------------------|---------|--------------------------------------------------------------|
| `mojox`            | ≥0.2    | Runtime resolver for `.mojopkg` paths; injects `-I` / `LD_LIBRARY_PATH` for `mojo run`. |
| `mojo-compiler`    | ==0.26.2.0 | The Mojo compiler itself.                                 |

`pyproject.toml` dev (`[dependency-groups].dev`):

| Package        | Version (lock)  | Purpose                                                      |
|----------------|-----------------|--------------------------------------------------------------|
| `aioquic`      | 1.3.0           | Oracle for QUIC frame/packet/transport-params cross-validation tests. |
| `cryptography` | 46.0.6          | Self-signed test cert generation (§3.1 baked-PEM track in progress) + AEAD/HKDF/HP oracle. |
| `h11`          | 0.16.0          | HTTP/1.1 wire-format oracle (HC vector validation).          |
| `h2`           | 4.3.0           | HTTP/2 reference impl used by `scripts/test_h2_backend.py` and conformance cross-validation. |
| `hpack`        | 4.1.0           | HPACK reference encoder/decoder for HC vectors.              |
| `httptools`    | 0.7.1           | nodejs llhttp wrapper — h11/llhttp cross-validation.         |
| `hyperframe`   | 6.1.0           | HTTP/2 frame parser used by `convert_h2_vectors.py`.         |
| `pyyaml`       | 6.0.3           | Vector / config file loading.                                |

Transitive (resolved by uv, not directly imported): `attrs`, `certifi`, `cffi`, `pyasn1`, `pyasn1-modules`, `pycparser`, `pylsqpack 0.3.24`, `pyopenssl 26.0.0`, `service-identity`, `typing-extensions`, `mojo-compiler-mojo-libs 0.26.2.0`.

### In-repo Python scripts (17)

**Conformance vector generation** (`conformance/scripts/`):

| Script | Purpose | Imports |
|---|---|---|
| `convert_h2_vectors.py`         | Clones http2jp/http2-frame-test-case, validates via hyperframe, merges into rfc9113/. | hyperframe, json, subprocess |
| `convert_vectors.py`            | Fetches llhttp + AWS http-desync-guardian fixtures; validates against h11/httptools. | h11, httptools, json |
| `download_hpack_stories.py`     | Clones http2jp/hpack-test-case. | subprocess |
| `oracle_h3.py`                  | Generates H3 frame + QPACK static vectors. | json, struct |
| `oracle_helpers.py`             | Wraps h11 / httptools / hyperframe parsers for cross-validation. | h11, httptools, hyperframe |
| `oracle_quic_frame.py`          | RFC 9000 §19 byte-level vector synthesis. | json, struct |
| `oracle_quic_packet.py`         | Uses aioquic `pull_quic_header` as oracle. | aioquic, json |
| `oracle_quic_transport_params.py` | RFC 9000 §18 wire-format vectors. | json |
| `retriage_deferred.py`          | Re-runs h11/httptools oracles against 67 deferred HC-2 vectors. | oracle_helpers |
| `triage_disagreements.py`       | Same, for ~142 skipped vectors. | oracle_helpers |
| `oracle_env_check.py`           | **(new 2026-05-13, §3.4)** Asserts installed oracle versions match uv.lock. | tomllib (stdlib, 3.11+), importlib.metadata |

**Bench parsing** (`bench/quic_perf/scripts/`):

| Script | Purpose | Imports |
|---|---|---|
| `parse-h2load.py` | h2load stdout → JSON | json, re, argparse |
| `parse-tquic.py`  | tquic_client stdout → JSON | json, re, argparse |
| `summarize.py`    | Aggregate `results/*.json` → Markdown | json, statistics, pathlib |

**Reverse-proxy E2E backends** (`scripts/`):

| Script | Purpose | Imports |
|---|---|---|
| `test_backend.py`    | Minimal HTTPS/1.1 backend on :9443 | http.server, ssl |
| `test_h2_backend.py` | HTTPS/2 backend on :9444 with ALPN h2 | h2.{config,connection,events}, ssl |

**FFI codegen** (`scripts/`):

| Script | Purpose | Imports |
|---|---|---|
| `gen_rlsm_bindings.py` | **(new 2026-05-13, §2.3)** Reads `crates/librustls-mojo/symbols.toml` and emits Mojo bindings. | tomllib |

---

## 2. Mojo sibling projects

| Sibling       | Source                                            | Purpose                                                  | Consumers in mojo-net                                                                                                |
|---------------|---------------------------------------------------|----------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **boucle**    | `$HOME/Projets/perso/boucle` (publishable via mojox-build, 2026-05-13) | io_uring loop, raw fd handles, stackful coroutines, Linux syscall raw types. | `src/io/{io_uring,io_uring_udp,udp_io,tcp_socket,udp_socket}.mojo`, `src/h{2,3}/*streaming_server.mojo`, `src/tls/lib.mojo`. |
| **json-simd-mojo** | `$HOME/Projets/perso/json-simd-mojo` (publishable via mojox-build, 2026-05-13) | simdjson bindings.                                       | `bench/handler.mojo` only.                                                                                          |

Resolution (currently): both filesystem-local under `$HOME/Projets/perso/`, exposed via `mojox`-injected `-I` at build time. As of 2026-05-13 both have `[build-system]` declared, so a future PR can switch to `uv add boucle` / `uv add json-simd-mojo` once they're published to PyPI (or pinned by git commit via `[tool.uv.sources]`).

---

## 3. Rust crates / FFI shims

### In-repo crate: `crates/librustls-mojo/`

Single workspace, `edition = "2021"`, crate-type `["cdylib", "rlib"]`. Toolchain pinned to **1.88.0** by `rust-toolchain.toml` (matches `bench/quic_perf/Dockerfile.tquic` base).

Build script: `scripts/build_rustls.sh {dev|release|bench}` — only `dev` includes the `insecure` feature (which exports `rlsm_client_config_new_insecure` + `rlsm_quic_client_config_new_insecure` for accept-any-cert dev workflows).

Direct Cargo dependencies:

| Crate            | Version  | Purpose                                                |
|------------------|----------|--------------------------------------------------------|
| `rustls`         | 0.23     | TLS 1.3 client + server (used for TCP-TLS and QUIC-TLS) |
| `aws-lc-rs`      | 1        | Crypto backend for rustls (replaces ring).             |
| `rustls-pemfile` | 2        | PEM cert/key parsing.                                  |
| `webpki-roots`   | 1        | Mozilla WebPKI root store.                             |
| `flate2`         | 1        | gzip codec for Content-Encoding.                       |
| `brotli`         | 7        | brotli codec for Content-Encoding.                     |
| `rcgen` (dev)    | 0.12     | Self-signed certs for `cargo test`.                    |
| `hex` (dev)      | 0.4      | Test fixtures.                                         |

Features: `default`, `skip-locks` (release default), `insecure` (dev only — opt-in escape hatch via separate symbol).

### FFI surface

**~57 `rlsm_*` symbols** exported as `pub (unsafe )?extern "C" fn`. Mojo side loads them via `OwnedDLHandle.get_function_unsafe[...]` in:

- `src/tls/lib.mojo` — TLS handshake, QUIC keys, AEAD ops.
- `src/http/decode.mojo` — content-encoding codecs (brotli, gzip).

Schema source of truth (in progress): `crates/librustls-mojo/symbols.toml` (scaffolded 2026-05-13; full migration pending — see plans/2026-05-13-deps-enhancement.md §2.3). Drift between Rust source and Mojo bindings is asserted by `check_integrations.sh`.

---

## 4. C / system shared libraries

All loaded via `external_call[...]` from Mojo or transitively through boucle:

| Library          | Symbols                                                                  | Callsites                                                                  |
|------------------|--------------------------------------------------------------------------|----------------------------------------------------------------------------|
| **libc (glibc)** | `socket`, `bind`, `listen`, `connect`, `setsockopt`                       | `src/io/{tcp_socket,udp_socket}.mojo`                                       |
| **libresolv/NSS** | `getaddrinfo`, `freeaddrinfo`                                            | `src/io/resolver.mojo`                                                      |
| **librt / vDSO** | `clock_gettime(CLOCK_MONOTONIC)`                                          | `src/io/resolver.mojo`, `src/quic/profile.mojo`                             |
| **kernel random** | `getrandom`                                                              | `src/quic/{connection,retry,cid}.mojo`                                      |
| **liburing**     | (via boucle's raw syscall bindings)                                       | `src/io/{io_uring,io_uring_udp,udp_io}.mojo` — delegates to boucle           |
| **librustls_mojo.so** | ~57 `rlsm_*` symbols                                                | `src/tls/lib.mojo`, `src/http/decode.mojo`                                  |
| **libpython**    | Mojo `std.python` runtime                                                 | Tests/conformance only                                                      |
| **libssl3 / libcrypto3** | (bench runtime image only, h2load w/ quictls)                    | Not linked by mojo-net runtime — only by `bench/Dockerfile.h2load-h3`       |

---

## 5. Build / toolchain

| Tool           | Version (pin)      | Source                                                  |
|----------------|--------------------|---------------------------------------------------------|
| Mojo compiler  | 0.26.2.0           | `pyproject.toml` runtime deps + `uv.lock`               |
| mojox          | ≥0.2               | PyPI                                                    |
| uv             | latest             | Installed in Dockerfiles via `curl -LsSf https://astral.sh/uv/install.sh` |
| Rust           | 1.88.0             | `crates/librustls-mojo/rust-toolchain.toml`             |
| Cargo          | bundled with rustc | (matches rust-toolchain)                                |
| Docker         | host-provided      | bench / interop images                                  |
| Python         | ≥3.11              | `pyproject.toml`                                        |
| OpenSSL / libssl-dev / pkg-config / CMake / Clang / Perl / Go | host-provided | aws-lc-sys + TQUIC build deps |

---

## 6. Container & bench dependencies

### Base images

| Image                                     | Purpose                                              |
|-------------------------------------------|------------------------------------------------------|
| `ubuntu:22.04`                            | `bench/Dockerfile`, `bench/Dockerfile.h2load-h3`, `interop/Dockerfile` |
| `rust:1.88-bookworm` → `debian:bookworm-slim` | `bench/quic_perf/Dockerfile.tquic`            |

### Bench client tooling

| Tool             | Source / pin                                                       | Purpose                                          |
|------------------|--------------------------------------------------------------------|--------------------------------------------------|
| **h2load**       | nghttp2 v1.60.0 + nghttp3 v1.5.0 + ngtcp2 v1.5.0 + quictls/openssl 3.1.4+quic | HTTP/2 + HTTP/3 load generator              |
| **tquic_client / tquic_server** | Tencent/tquic@4dcec0f2fcd6fd4a49366e2c759a169e4e81c48e (v1.0.0) | QUIC perf comparator                  |
| httparena vendor (`bench/.httparena/`) | Local checkout, ~50 framework Dockerfiles + wrk/ghz/gcannon helpers | Framework comparison sweeps (planned move out — §4.2) |

apt builder packages (bench/Dockerfile): `curl ca-certificates build-essential pkg-config libssl-dev git`. Runtime: `ca-certificates libssl3 openssl`.

---

## 7. Conformance external corpora

| Corpus                                  | Source / pin                                          | Status        |
|------------------------------------------|-------------------------------------------------------|---------------|
| HPACK stories                           | http2jp/hpack-test-case (vendored at `conformance/vectors/hpack-stories/`) | vendored     |
| HTTP/2 frame fixtures                   | http2jp/http2-frame-test-case (cloned + merged to rfc9113/) | scripted     |
| llhttp fixtures                         | nodejs/llhttp (fetched + validated against h11/httptools) | scripted     |
| AWS http-desync-guardian fixtures       | aws/http-desync-guardian                              | scripted     |
| h2spec, qpack-interop runner, quic-interop runner | **not integrated**                          | self-rolled Python oracles instead |

Vector directories under `conformance/vectors/`: `rfc7541` (HPACK), `rfc9000` (QUIC transport), `rfc9001` (TLS-in-QUIC), `rfc9112` (HTTP/1.1), `rfc9113` (HTTP/2), `rfc9114` (HTTP/3), `rfc9204` (QPACK), `security/`, `hpack-stories/`.

---

## 8. Risk register

| Risk                                                                       | Blast radius                       | Mitigation                                       |
|----------------------------------------------------------------------------|------------------------------------|--------------------------------------------------|
| **boucle bug / unavailability**                                           | Entire I/O layer; both servers     | Now publishable (mojox-build). Pin in pyproject once published. |
| **librustls-mojo / rustls breaking change**                                | All TLS / QUIC                     | Rust toolchain pinned; FFI codegen in progress (§2.3). |
| **CPython 3.x minor bump**                                                | Test/conformance suite             | Full ABI, no Limited API. `oracle_env_check.py` catches lock drift; `requires-python>=3.11`. |
| **Mojo compiler 0.26.x → 0.27.x**                                         | Compiles everywhere                | Pinned to `==0.26.2.0` in pyproject; bumps are intentional PRs. |
| **quictls/openssl 3.1.4+quic abandoned**                                  | h2load HTTP/3 bench only           | Mirror plan in §4.1 (private fork); not on production critical path. |
| **TQUIC repo deletion**                                                   | Perf comparator only               | Mirror plan in §4.1.                             |
| **liburing version drift**                                                | io_uring backend stability         | Audit found no in-tree version pin — siblings install via apt. Add explicit pin if a future Dockerfile begins vendoring. |
| **rustls `--features insecure` accidentally shipped**                     | Dev escape hatch in release binary | `scripts/build_rustls.sh release` + post-build `nm` check; `scripts/check_integrations.sh` WARNs on stray insecure symbol. |
| **Sibling repo (boucle, json-simd-mojo) without pyproject `[build-system]`** | `uv add` against them fails       | Fixed 2026-05-13 — both have `[build-system]` + `[tool.mojox-build]`. |
| **Mojo flat-layout setuptools-discovery footgun**                          | Library posture upgrade blocked    | Documented (§1.3 plan); requires `src/mojo_net/` reshuffle. |

---

## How to regenerate

This doc is hand-maintained, but most of the dependency state can be re-derived:

- Python deps: `cat pyproject.toml uv.lock`
- Rust crates: `cat crates/librustls-mojo/Cargo.toml`; full transitive set: `cargo tree --manifest-path crates/librustls-mojo/Cargo.toml`
- FFI symbols: `grep -hE '^pub (unsafe )?extern "C" fn rlsm_' crates/librustls-mojo/src/*.rs | wc -l`
- Mojo-imported Python modules: `grep -rh 'Python.import_module' tests/ conformance/ | sort -u`
- Dockerfile bases / apt: `find . -name 'Dockerfile*' -not -path '*/.worktrees*' -exec head -20 {} \;`

Smoke test asserting Phase 1/2/3 invariants: `bash scripts/check_integrations.sh`.
