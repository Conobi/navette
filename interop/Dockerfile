# syntax=docker/dockerfile:1
# QUIC Interop Runner — multi-stage build
# Mojo version: 0.26.2 (see .mojo-version)

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

# Install magic (Modular package manager) and Mojo 0.26.2
# The magic installer writes to ~/.modular; we add its bin to PATH.
RUN curl -ssL https://magic.modular.com/d03e03a0-af92-4ea6-be73-3d3f1b3b5482 | bash
ENV PATH="/root/.modular/bin:${PATH}"

# magic uses a project-local .mojo-version file to pin the Mojo release.
# Copying just that file first lets Docker cache the install layer.
WORKDIR /app
COPY .mojo-version ./
RUN magic install

# Copy the rest of the source tree
COPY . .

# Build the Rust shared library
RUN cargo build --release --manifest-path crates/librustls-mojo/Cargo.toml

# Copy the .so into the conventional lib/ directory so Mojo can find it.
# Cargo produces liblibrustls_mojo.so but RustlsLibrary() loads librustls_mojo.so.
RUN cp crates/librustls-mojo/target/release/liblibrustls_mojo.so lib/librustls_mojo.so

# Build Mojo interop binaries (include project root so `import mojo_net` works)
RUN magic run mojo build -I . interop/server.mojo -o /interop-server
RUN magic run mojo build -I . interop/client.mojo -o /interop-client

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

ENV LD_LIBRARY_PATH=/usr/local/lib

# The interop runner calls these via $SERVER / $CLIENT env vars.
# Default entrypoint is the server; override with --entrypoint for the client.
ENTRYPOINT ["/usr/local/bin/interop-server"]
