# wrk2 — Gil Tene's coordinated-omission-correcting fork of wrk.
#
# Pinned to a known-good commit so calibrated-peak numbers are
# reproducible across hosts. Don't substitute the upstream wrk
# package: it omits the queue-time accounting that the calibrated
# rate harness depends on.
#
# Build context: empty (everything fetched at build time).
FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git build-essential libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN git clone https://github.com/giltene/wrk2.git . && \
    git checkout 44a94c17d8e6a0bac8559b53da76848e430cb7a7 && \
    make -j"$(nproc)"

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 zlib1g ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/wrk /usr/local/bin/wrk2
ENTRYPOINT ["wrk2"]
