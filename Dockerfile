# Build stage
FROM rust:1.98-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Create a new empty shell project
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy source to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY src ./src
COPY dist ./dist

# Build the application
RUN touch src/main.rs && \
    cargo build --release --locked

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    iptables \
    ip6tables \
    nftables \
    iproute2 \
    ca-certificates

# Copy the binary from builder
COPY --from=builder /app/target/release/nat-gate /usr/local/bin/nat-gate

# Create config directory
RUN mkdir -p /etc/nat-gate

# Set entrypoint
ENTRYPOINT ["nat-gate"]

# Default command shows help
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="nat-gate"
LABEL org.opencontainers.image.description="CLI tool for iptables port forwarding through Tailscale tunnels"
LABEL org.opencontainers.image.url="https://github.com/h3nr1-d14z/nat-gate"
LABEL org.opencontainers.image.source="https://github.com/h3nr1-d14z/nat-gate"
LABEL org.opencontainers.image.vendor="h3nr1-d14z"
LABEL org.opencontainers.image.licenses="MIT"
