# syntax=docker/dockerfile:1
# QUIC Interop Runner — multi-stage build
# Mojo version: 0.26.2 via mojox (uv dependency)

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

# Copy the rest of the source tree
COPY . .

# Build the Rust shared library
RUN cargo build --release --manifest-path crates/librustls-mojo/Cargo.toml

# Copy the .so into the conventional lib/ directory so Mojo can find it.
# Cargo produces liblibrustls_mojo.so but RustlsLibrary() loads librustls_mojo.so.
RUN cp crates/librustls-mojo/target/release/liblibrustls_mojo.so lib/librustls_mojo.so

# Build Mojo interop binaries
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . interop/server.mojo -o /interop-server
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . interop/client.mojo -o /interop-client

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binaries
COPY --from=build /interop-server  /usr/local/bin/interop-server
COPY --from=build /interop-client  /usr/local/bin/interop-client

# Copy the Rust shared library (name must match what RustlsLibrary() dlopen's)
COPY --from=build /app/lib/librustls_mojo.so /usr/local/lib/librustls_mojo.so

# Copy all Mojo runtime shared libraries
COPY --from=build /app/.venv/lib/python3.14/site-packages/modular/lib/*.so /usr/local/lib/

# Create lib/ symlink so RustlsLibrary("lib/librustls_mojo.so") resolves
RUN mkdir -p /app/lib && ln -s /usr/local/lib/librustls_mojo.so /app/lib/librustls_mojo.so
WORKDIR /app

# Copy ROLE-based dispatch script
COPY interop/run_endpoint.sh /usr/local/bin/run_endpoint.sh

ENV LD_LIBRARY_PATH=/usr/local/lib

# The interop runner passes ROLE=client or ROLE=server (default).
# run_endpoint.sh dispatches to the correct binary.
ENTRYPOINT ["/usr/local/bin/run_endpoint.sh"]
