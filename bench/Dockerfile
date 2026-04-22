# syntax=docker/dockerfile:1
# HttpArena Benchmark Server — multi-stage build
#
# Build:
#   docker build -t mojo-net-bench:latest \
#       --build-context boucle=../boucle \
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

# Copy the rest of the source tree
COPY . .

# Build the Rust shared library
RUN cargo build --release --manifest-path crates/librustls-mojo/Cargo.toml

# Copy the .so into the conventional lib/ directory
RUN cp crates/librustls-mojo/target/release/liblibrustls_mojo.so lib/librustls_mojo.so

# Build the three benchmark server binaries
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . -I /boucle bench/h1_server.mojo -o /bench-h1
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . -I /boucle bench/h2_server.mojo -o /bench-h2
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . -I /boucle bench/h3_server.mojo -o /bench-h3
RUN LD_LIBRARY_PATH=lib uv run mojox build -I . -I /boucle bench/launcher.mojo -o /bench-launcher

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

# HttpArena uses host network mode — ports 8080 (H1) and 8443 (H2+H3)
ENTRYPOINT ["/usr/local/bin/launcher"]
