# Note: this "source" stage only exists so that we could copy the source tree into
# the "builder" stage excluding the "build-tools" directory. This is to avoid rebuilding
# all the images every time when a file in "build-tools" is modified. Note that for most
# of the contents of "build-tools" this could be solved by adding them to .dockerignore,
# but there are files (e.g. entrypoint.sh) that are needed inside images, so they can't
# be ignored.
#
# TODO: dockerfile 1.7 syntax allows specifying --exclude for COPY, so the same can be done
# without an additional stage. But at the moment of writing this it's still experimental.
# Switch to using it when it becomes stable.
FROM rust as source
COPY . /src
RUN rm -r /src/build-tools

FROM rust AS builder

WORKDIR /usr/src/

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=source /src/ /usr/src/

ARG NUM_JOBS=1
RUN cargo build --release -j${NUM_JOBS}
