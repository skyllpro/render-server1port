FROM golang:1.26-bookworm AS build

WORKDIR /src

COPY server1port/go.mod server1port/go.sum /src/server1port/
WORKDIR /src/server1port
RUN go mod download

COPY server1port/ /src/server1port/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/server1port .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /out/server1port /app/server1port

EXPOSE 10000

CMD ["/bin/sh", "-c", "exec /app/server1port -ws 0.0.0.0:${PORT:-10000}"]
