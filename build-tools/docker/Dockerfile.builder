FROM rust AS builder

WORKDIR /usr/src/

# Install necessary build dependencies for the GUI (such as X11, GTK, etc.)
RUN apt-get update && apt-get install -y ca-certificates libgtk-3-dev && rm -rf /var/lib/apt/lists/*

COPY . .

ARG NUM_JOBS=1
RUN cargo build --release -j${NUM_JOBS}
