# Compilation
FROM docker.io/library/debian:bullseye-slim as build
WORKDIR /usr/src/komodo-defi-proxy

## Install Rust
RUN apt-get update \
	&& apt-get install -y build-essential curl pkg-config libssl-dev \
	&& rm -rf /var/lib/apt/lists/*
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

## Jemalloc tweaks
ENV JEMALLOC_SYS_WITH_MALLOC_CONF="background_thread:true,narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,metadata_thp:auto"

COPY . .

RUN cargo build --release

# Runtime
FROM docker.io/library/debian:bullseye-slim

RUN apt-get update \
	&& apt-get install -y ca-certificates \
	&& rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

## Get binary
COPY --from=build /usr/src/komodo-defi-proxy/target/release/atomicdex-auth /usr/local/bin/

## Init command
CMD ["atomicdex-auth"]
