# ---------- Build stage ----------
# Pin base images to immutable digests; Dependabot manages digest updates.
FROM rust:1.99@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS builder

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
FROM debian:stable-slim@sha256:fbfb4059d2127120aa05b6e6064523d2102552f0cf0026ddf0701c12f1f8f3e0

# Reuse the pinned builder image's CA bundle instead of installing packages
# from a mutable Debian repository during the runtime image build.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /output

# Run with an unprivileged user. The directory remains writable when no bind
# mount is provided; bind mounts should be run with the host user's UID/GID.
RUN mkdir -p /output && chown 10001:10001 /output

# Copy only the compiled binary
COPY --from=builder /app/target/release/ema-ua-blocklist /app/ema-ua-blocklist

# Generated blocklists land in the working directory (/output).
# Mount a host directory there to collect them:
#   docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
#     --user "$(id -u):$(id -g)" -v "$(pwd)":/output ema-ua-blocklist
USER 10001:10001

ENTRYPOINT ["/app/ema-ua-blocklist"]
