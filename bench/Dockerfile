# syntax=docker/dockerfile:1
# HttpArena Benchmark Server — multi-stage build
#
# Build:
#   docker build -t navette-bench:latest \
#       --build-context boucle=../boucle \
#       --build-context jsonette=../jsonette \
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

# Bench builds don't pip-install navette as a Python package -- the
# bench binaries are produced by `mojox build` with explicit `-I` paths
# (see the per-server build steps further down). All we need from the
# Python side is the mojox CLI + the Mojo compiler. Skipping the
# project's [build-system] avoids dragging boucle's git+ssh source
# into the build env, which would require an SSH client + deploy key
# the bench image deliberately does not carry.
RUN cat > pyproject.toml <<'EOF'
[project]
name = "navette-bench-build"
version = "0.0.0"
requires-python = ">=3.11"
dependencies = [
    "mojox==0.2.0",
    "mojo-compiler==1.0.0b1",
    "mojo-compiler-mojo-libs==1.0.0b1",
]

[tool.uv]
package = false
EOF
RUN uv sync

# Copy boucle source (from --build-context boucle=../boucle) and
# jsonette (from --build-context jsonette=../jsonette).
# `mojox build` consumes them via -I /boucle / -I /jsonette; neither
# is installed as a Python package.
COPY --from=boucle . /boucle
COPY --from=jsonette . /jsonette

# Copy the rest of the source tree, then re-stamp the stub pyproject
# so the venv mojox we installed earlier isn't disturbed by uv
# re-resolving the project's git+ssh boucle dep when the canonical
# pyproject.toml lands on top. The COPY . . above clobbers it; the
# re-stamp keeps the venv untouched for the mojox builds below.
COPY . .
RUN mv pyproject.toml pyproject.toml.navette \
    && cat > pyproject.toml <<'EOF'
[project]
name = "navette-bench-build"
version = "0.0.0"
requires-python = ">=3.11"
dependencies = []

[tool.uv]
package = false
EOF
RUN rm -f uv.lock

# Build the Rust shared library
RUN cargo build --release --features skip-locks --manifest-path crates/librustls-mojo/Cargo.toml

# Copy the .so into the conventional lib/ directory
RUN mkdir -p lib && cp crates/librustls-mojo/target/release/liblibrustls_mojo.so lib/librustls_mojo.so

# Build the three benchmark server binaries directly via the venv mojox
# (bypassing `uv run` so uv doesn't try to re-resolve the (now-stubbed)
# project).
RUN LD_LIBRARY_PATH=lib /app/.venv/bin/mojox build -I . -I /boucle -I /jsonette bench/servers/h1_server.mojo -o /bench-h1
RUN LD_LIBRARY_PATH=lib /app/.venv/bin/mojox build -I . -I /boucle -I /jsonette bench/servers/h2_server.mojo -o /bench-h2
RUN LD_LIBRARY_PATH=lib /app/.venv/bin/mojox build -I . -I /boucle -I /jsonette bench/servers/h3_server.mojo -o /bench-h3
RUN LD_LIBRARY_PATH=lib /app/.venv/bin/mojox build -I . -I /boucle bench/launcher.mojo -o /bench-launcher

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
