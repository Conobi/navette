# Flare v0.7.0 — Mojo HTTP/1.1 reactor server, 1-worker plaintext baseline.
#
# Built straight from ehsanmok/flare's own benchmark/baselines/flare/main.mojo
# entry point. Uses pixi to pull Mojo nightly (the conda-forge max-nightly
# channel) and `mojo build -D ASSERT=none` (matches Flare's published
# production-posture build flags). Single-stage image: the runtime needs
# the pixi-managed Mojo libraries, so we keep them in the final image and
# launch via `pixi run`.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git build-essential libtinfo6 libffi8 \
    && rm -rf /var/lib/apt/lists/*

# Install pixi (Modular's recommended Mojo project manager).
ENV PIXI_HOME=/opt/pixi
ENV PATH="${PIXI_HOME}/bin:${PATH}"
RUN curl -fsSL https://pixi.sh/install.sh | sh

# Clone Flare at the v0.7.0 tag and let pixi pull Mojo nightly + Flare deps.
WORKDIR /flare
ARG FLARE_REF=v0.7.0
RUN git clone --depth 1 --branch "$FLARE_REF" https://github.com/ehsanmok/flare.git . \
    && pixi install --environment bench

# Build the single-worker plaintext bench server with the same posture
# Flare's own published numbers use: `mojo build -D ASSERT=none`.
RUN pixi run --environment bench \
        mojo build -D ASSERT=none -I . \
            benchmark/baselines/flare/main.mojo \
            -o /usr/local/bin/flare-1w

EXPOSE 8080
ENV FLARE_BENCH_PORT=8080
# `pixi run` keeps the Mojo runtime on LD_LIBRARY_PATH; running the
# binary directly would miss libKGENCompilerRTShared.so and friends.
ENTRYPOINT ["pixi", "run", "--environment", "bench", "/usr/local/bin/flare-1w"]
