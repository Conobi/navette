# hyper 1.x on tokio current_thread runtime. Flare's hyper baseline runs
# multi-thread; we run current_thread here because the task brief mandates
# single-threaded for every implementation.
FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
# Cargo.lock isn't checked in for these tiny throwaway servers; cargo
# generates one on first build inside the image. After that the layer
# is cached and the build is reproducible.
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/hyper-plaintext /hyper-plaintext
EXPOSE 8080
ENTRYPOINT ["/hyper-plaintext"]
