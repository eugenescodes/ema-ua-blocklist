# ---------- Build stage ----------
FROM rust:1.98 AS builder

WORKDIR /app

# 1. Compile dependencies in their own layer. This layer is only invalidated
#    when Cargo.toml / Cargo.lock change, so day-to-day source edits reuse the
#    (expensive) dependency build instead of recompiling everything from scratch.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
 && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src

# 2. Build the real binary, reusing the cached dependency artifacts above.
#    --locked ensures the exact versions in Cargo.lock are used, never
#    silently re-resolved during the image build.
COPY src ./src
RUN cargo build --release --locked

# Strip symbols and stage the binary for the runtime stage.
RUN strip target/release/ema-ua-blocklist

# ---------- Runtime stage ----------
FROM debian:stable-slim

# Install only required system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /output

# Copy only the compiled binary
COPY --from=builder /app/target/release/ema-ua-blocklist /app/ema-ua-blocklist

# Generated blocklists land in the working directory (/output).
# Mount a host directory there to collect them:
#   docker run --rm -v "$(pwd)":/output ema-ua-blocklist
ENTRYPOINT ["/app/ema-ua-blocklist"]
