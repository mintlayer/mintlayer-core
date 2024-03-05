FROM rust:1.75

WORKDIR /src/

RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    nmap procps net-tools iputils-ping dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY . .

ARG NUM_JOBS=16
RUN cargo build --release -j${NUM_JOBS} --bin node-daemon
RUN cargo build --release -j${NUM_JOBS} --bin wallet-cli

RUN cp /src/target/release/node-daemon /usr/bin
RUN cp /src/target/release/wallet-cli /usr/bin
