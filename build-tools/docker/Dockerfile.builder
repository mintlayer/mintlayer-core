FROM rust AS builder

WORKDIR /usr/src/

COPY . .

ARG NUM_JOBS=1
RUN cargo build --release -j${NUM_JOBS}
