# syntax=docker/dockerfile:1
# HttpArena Benchmark Server — multi-stage build
#
# Build:
#   docker build -t navette-bench:latest \
#       --build-context boucle=../boucle \
#       --build-context simdjson=../json-simd-mojo \
#       -f bench/Dockerfile .

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        build-essential \
        pkg-config \
        libssl-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --no-modify-path
ENV PATH="/root/.cargo/bin:${PATH}"

# Install uv (Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app

# Copy dependency files first for Docker layer caching
COPY pyproject.toml uv.lock ./

# Install Python deps (includes mojox which pulls mojo-compiler 0.26.2)
RUN uv sync --group dev

# Copy boucle source (from --build-context boucle=../boucle)
COPY --from=boucle . /boucle

# Copy json-simd-mojo source (from --build-context simdjson=../json-simd-mojo).
# The package layout is /simdjson/simdjson/, so -I /simdjson lets bench code
# `from simdjson.parser import Parser` resolve correctly.
COPY --from=simdjson . /simdjson

# Copy the rest of the source tree
COPY . .

# Build the Rust shared library
RUN cargo build --release --features skip-locks --manifest-path crates/librustls-mojo/Cargo.toml

# Copy the .so into the conventional lib/ directory
RUN mkdir -p lib && cp crates/librustls-mojo/target/release/liblibrustls_mojo.so lib/librustls_mojo.so

# Build the three benchmark server binaries (h1 covers both plaintext and TLS modes)
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . -I /boucle -I /simdjson bench/h1_server.mojo -o /bench-h1
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . -I /boucle -I /simdjson bench/h2_server.mojo -o /bench-h2
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . -I /boucle -I /simdjson bench/h3_server.mojo -o /bench-h3
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . -I /boucle bench/launcher.mojo -o /bench-launcher

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# Generate self-signed TLS certificate for H2/H3 benchmarks
RUN mkdir -p /certs && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout /certs/server.key -out /certs/server.crt -days 365 -nodes \
        -subj "/CN=localhost"

# Copy compiled binaries
COPY --from=build /bench-h1 /usr/local/bin/h1_server
COPY --from=build /bench-h2 /usr/local/bin/h2_server
COPY --from=build /bench-h3 /usr/local/bin/h3_server
COPY --from=build /bench-launcher /usr/local/bin/launcher

# Copy the Rust shared library
COPY --from=build /app/lib/librustls_mojo.so /usr/local/lib/librustls_mojo.so

# Copy all Mojo runtime shared libraries
COPY --from=build /app/.venv/lib/python3.14/site-packages/modular/lib/*.so /usr/local/lib/

# Create lib/ symlink so RustlsLibrary("lib/librustls_mojo.so") resolves
RUN mkdir -p /app/lib && ln -s /usr/local/lib/librustls_mojo.so /app/lib/librustls_mojo.so
WORKDIR /app

ENV LD_LIBRARY_PATH=/usr/local/lib
ENV CERTS_DIR=/certs
ENV DATA_DIR=/data

# Vendor the dataset for the /json profile so the image is self-contained.
COPY --from=build /app/bench/data/dataset.json /data/dataset.json

# HttpArena uses host network mode — ports 8080 (H1), 8081 (H1+TLS), 8443 (H2+H3)
EXPOSE 8080 8081 8443
ENTRYPOINT ["/usr/local/bin/launcher"]
