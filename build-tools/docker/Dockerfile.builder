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

# Note: the base image here doesn't really matter, we just use the same one as in the "builder"
# stage below.
FROM rust:bookworm as source
COPY . /src
RUN rm -r /src/build-tools

# Note: the builder image should use the same or an older distro compared to the runner images,
# so that its GLIBC version is also the same or older. Otherwise the built executables have
# a chance to get a dependency on a newer version of some GLIBC symbol that is not present
# in the runner's GLIBC, and the executables won't work.
# TODO: consider producing musl-based executables instead.
FROM rust:bookworm AS builder

WORKDIR /usr/src/

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=source /src/ /usr/src/

ARG NUM_JOBS=1
RUN cargo build --release -j${NUM_JOBS}
