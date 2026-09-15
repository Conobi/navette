# static_h3_server

Fast static-payload HTTP/3 server built on navette's `H3UdpServer`.
Serves a fixed-size response body to every request — useful as a
baseline for benchmarks and integration tests.

## Quick start

```sh
# One-time: generate test certificates in the repo root
../../scripts/gen_test_certs.sh

# Build and run
uv sync
uv run mojox build main.mojo -o static_h3_server
./static_h3_server
```

## Configuration (env vars)

| Variable          | Default             | Description                     |
|-------------------|---------------------|---------------------------------|
| `STATIC_PORT`     | `8443`              | UDP listen port                 |
| `STATIC_BODY_SIZE`| `1024`              | Response body size in bytes     |
| `STATIC_CERT`     | `certs/server.crt`  | PEM certificate path            |
| `STATIC_KEY`      | `certs/server.key`  | PEM private key path            |

## Test with a QUIC client

```sh
# h2load (nghttp2)
h2load --h3 -n 4 -c 1 https://127.0.0.1:8443/

# tquic_client (via docker)
docker run --rm --network host --entrypoint /usr/local/bin/tquic_client \
  tquic-bench:latest --max-requests-per-conn 1 \
  --connect-to 127.0.0.1:8443 https://127.0.0.1:8443/
```
