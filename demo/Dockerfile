# Build stage — nightly Rust (required by halo2-lib)
FROM rust:slim-bookworm AS builder

# Install nightly toolchain
RUN rustup install nightly && rustup default nightly

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    make \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY demo/server ./demo/server

# Build the demo server in release mode
RUN cargo +nightly build --release -p demo-server

# Runtime stage — minimal image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" --uid 1001 app

WORKDIR /app

# Copy the built binary
COPY --from=builder /app/target/release/demo-server /app/demo-server

# Copy static files (frontend build)
COPY demo/web/dist /app/web/dist

# Run as non-root
USER app

EXPOSE 8080

ENV RUST_LOG=demo_server=info,tower_http=info \
    PORT=8080 \
    BIND_ADDRESS=0.0.0.0

CMD ["./demo-server"]
