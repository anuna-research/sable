# Build stage
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY demo/server ./demo/server

# Build the demo server
RUN cargo build --release -p demo-server

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary
COPY --from=builder /app/target/release/demo-server /app/demo-server

# Copy static files (frontend build)
COPY demo/web/dist /app/web/dist

EXPOSE 3000

ENV RUST_LOG=demo_server=info,tower_http=info

CMD ["./demo-server"]
