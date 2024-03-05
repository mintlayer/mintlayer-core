FROM rust AS builder

WORKDIR /usr/src/

# Install necessary build dependencies for the GUI (such as X11, etc.)
RUN apt-get update && apt-get install -y ca-certificate && rm -rf /var/lib/apt/lists/*

COPY . .

ARG NUM_JOBS=1
RUN cargo build --release -j${NUM_JOBS}
