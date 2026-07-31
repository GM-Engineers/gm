# GM CA Server Dockerfile
# Uses pre-built binary from target/aarch64-unknown-linux-gnu/release/
# Build with: cross build --release -p gm-ca-server --target aarch64-unknown-linux-gnu
# (requires: cross build --release -p gm-ca-server --target aarch64-unknown-linux-gnu --force-non-host)

FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/* || \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl libssl3 && rm -rf /var/lib/apt/lists/* || \
    echo "Package install attempted"

# Create non-root user for security
RUN useradd -r -u 1000 -s /bin/false appuser

# Copy pre-built binary
COPY gm-ca-server /app/gm-ca-server

# Create data directory
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose gRPC port
EXPOSE 50051

# Run the server
CMD ["./gm-ca-server"]
