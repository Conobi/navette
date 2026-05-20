# actix-web with workers=1 (single OS worker).
FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/actix-plaintext /actix-plaintext
EXPOSE 8080
ENTRYPOINT ["/actix-plaintext"]
