# Dockerfile for lightswitch - CPU profiler for Linux
# Multi-stage build for optimal size and build caching

# Build stage
FROM rust:1.85-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    clang-19 \
    lld-19 \
    llvm-19-dev \
    libclang-19-dev \
    libelf-dev \
    zlib1g-dev \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Set LLVM/Clang environment variables
ENV LIBCLANG_PATH=/usr/lib/llvm-19/lib \
    CLANG=/usr/bin/clang-19 \
    CC=/usr/bin/clang-19 \
    CXX=/usr/bin/clang++-19

# Set working directory
WORKDIR /build

# Copy dependency manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY lightswitch-proto/Cargo.toml ./lightswitch-proto/
COPY lightswitch-capabilities/Cargo.toml ./lightswitch-capabilities/
COPY lightswitch-metadata/Cargo.toml ./lightswitch-metadata/
COPY lightswitch-object/Cargo.toml ./lightswitch-object/

# Create dummy source files to cache dependencies
RUN mkdir -p src/cli \
    && echo "fn main() {}" > src/cli/main.rs \
    && mkdir -p lightswitch-proto/src lightswitch-capabilities/src \
       lightswitch-metadata/src lightswitch-object/src \
    && echo "fn main() {}" > lightswitch-proto/src/lib.rs \
    && echo "fn main() {}" > lightswitch-capabilities/src/lib.rs \
    && echo "fn main() {}" > lightswitch-metadata/src/lib.rs \
    && echo "fn main() {}" > lightswitch-object/src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release --bin lightswitch || true \
    && rm -rf src lightswitch-proto/src lightswitch-capabilities/src \
       lightswitch-metadata/src lightswitch-object/src

# Copy the actual source code
COPY . .

# Build the project
RUN cargo build --release --bin lightswitch

# Runtime stage
FROM debian:bookworm-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    zlib1g \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /build/target/release/lightswitch /usr/local/bin/lightswitch

# Set runtime environment
ENV RUST_BACKTRACE=1

# Run as non-root user when possible (profiling may require root/CAP_PERFMON)
# Uncomment if running without privileged capabilities:
# USER nobody:nogroup

ENTRYPOINT ["/usr/local/bin/lightswitch"]
CMD ["--help"]
