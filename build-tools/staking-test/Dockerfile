ARG CARGO_TARGET_DIR=/src/target
ARG RUST_VER=1.78

# Use a separate "source" stage so that build-tools is not copied into the builder image,
# while still not excluding it from the build context (it's needed to copy node_runner.sh below).
FROM rust:$RUST_VER as source
COPY . /src
RUN rm -r /src/build-tools

FROM rust:$RUST_VER as builder
ARG CARGO_TARGET_DIR

WORKDIR /src/

COPY --from=source /src/ .

ARG NUM_JOBS=16

# Override the target directory back to the default value (in case the user has a non-default target
# directory specified in their .cargo/config.toml).
ENV CARGO_TARGET_DIR=$CARGO_TARGET_DIR

RUN cargo build --release -j${NUM_JOBS} --bin node-daemon --bin wallet-cli --bin wallet-rpc-daemon

FROM debian:bookworm-slim
ARG CARGO_TARGET_DIR

RUN apt-get update && \
    apt-get install -y dnsutils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workdir
WORKDIR /workdir

COPY build-tools/staking-test/node_runner.sh /usr/bin
COPY --from=builder $CARGO_TARGET_DIR/release/node-daemon /usr/bin
COPY --from=builder $CARGO_TARGET_DIR/release/wallet-cli /usr/bin
COPY --from=builder $CARGO_TARGET_DIR/release/wallet-rpc-daemon /usr/bin
