# axum on tokio current_thread runtime, single-threaded.
FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/axum-plaintext /axum-plaintext
EXPOSE 8080
ENTRYPOINT ["/axum-plaintext"]
