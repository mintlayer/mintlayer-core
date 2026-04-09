ARG CARGO_TARGET_DIR=/src/target

# Use a separate "source" stage so that build-tools is not copied into the builder image,
# while still not excluding it from the build context (it's needed to copy node_runner.sh below).
FROM rust:bookworm AS source
COPY . /src
RUN rm -r /src/build-tools

FROM rust:bookworm AS builder
ARG CARGO_TARGET_DIR

WORKDIR /src/

COPY --from=source /src/ .

ARG NUM_JOBS=16

# Override the target directory back to the default value (in case the user has a non-default target
# directory specified in their .cargo/config.toml).
ENV CARGO_TARGET_DIR=$CARGO_TARGET_DIR

RUN apt-get update && \
    apt-get install -y libdbus-1-dev libusb-1.0-0-dev && \
    rm -rf /var/lib/apt/lists/*

RUN cargo build --release -j${NUM_JOBS} --bin node-daemon --bin wallet-cli --bin wallet-rpc-daemon

FROM debian:bookworm-slim
ARG CARGO_TARGET_DIR

RUN apt-get update && \
    apt-get install -y dnsutils libdbus-1-3 libusb-1.0-0 && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workdir
WORKDIR /workdir

COPY build-tools/staking-test/node_runner.sh /usr/bin
COPY --from=builder $CARGO_TARGET_DIR/release/node-daemon /usr/bin
COPY --from=builder $CARGO_TARGET_DIR/release/wallet-cli /usr/bin
COPY --from=builder $CARGO_TARGET_DIR/release/wallet-rpc-daemon /usr/bin
