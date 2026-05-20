# Go net/http with runtime.GOMAXPROCS(1) — Flare's go_nethttp baseline.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY main.go go.mod ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /go-plaintext main.go

FROM gcr.io/distroless/static:nonroot
COPY --from=build /go-plaintext /go-plaintext
EXPOSE 8080
ENTRYPOINT ["/go-plaintext"]
