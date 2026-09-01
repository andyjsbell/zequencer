# syntax=docker/dockerfile:1

# ---- build ---------------------------------------------------------------
FROM rust:1.90-slim-bookworm AS build
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches

# BuildKit cache mounts keep the crate registry and the compiled artifacts
# across builds. They live outside the image, so the binary has to be copied
# out of the target dir before the layer ends.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --bin zequencer \
 && cp target/release/zequencer /usr/local/bin/zequencer

# ---- run -----------------------------------------------------------------
FROM debian:bookworm-slim

# curl is here only so compose can health-check the HTTP surface rather than
# just probing that the TCP port accepts a connection.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home zequencer

COPY --from=build /usr/local/bin/zequencer /usr/local/bin/zequencer

USER 10001
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/zequencer"]
