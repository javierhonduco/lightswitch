FROM --platform=linux/amd64 rust:latest AS builder

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libclang-dev \
    libz-dev \
    zlib1g-dev \
    pkg-config \
    make \
    autoconf \
    automake \
    autopoint \
    libtool \
    gettext \
    bison \
    flex \
    curl \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://sourceware.org/elfutils/ftp/0.192/elfutils-0.192.tar.bz2 | tar xj && \
    cd elfutils-0.192 && \
    ./configure --disable-debuginfod --disable-libdebuginfod --without-zstd --prefix=/usr/local && \
    make -j$(nproc) && \
    make install && \
    cp lib/libeu.a /usr/local/lib/ && \
    cd .. && rm -rf elfutils-0.192

RUN ln -s /usr/lib/llvm-*/lib/libclang*.so* /usr/lib/ 2>/dev/null || true
ENV LIBCLANG_PATH=/usr/lib
ENV LIBBPF_SYS_LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

RUN rustup component add rustfmt

WORKDIR /src
COPY . .
ENV RUSTFLAGS="-C link-arg=-leu -C link-arg=-L/usr/local/lib"
RUN cargo build --release

FROM --platform=linux/amd64 debian:trixie-slim

RUN apt-get update && apt-get install -y \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/lightswitch /usr/local/bin/
ENTRYPOINT ["lightswitch"]
