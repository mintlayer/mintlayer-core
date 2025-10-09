#!/bin/bash

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PYTHON=$(which python || which python3)

cd "$SCRIPT_DIR"

cargo fmt --check -- --config newline_style=Unix

# Install cargo deny first with: cargo install cargo-deny.
# Note: "--allow duplicate" silences the warning "found x duplicate entries for crate y".
cargo deny check --allow duplicate --hide-inclusion-graph

CLIPPY_VERSION_RESPONSE=$(cargo clippy --version)
# Note: clippy version starts from 0, e.g. '0.1.90'
if [[ "$CLIPPY_VERSION_RESPONSE" =~ clippy[[:space:]]+0\.([0-9]+)\.([0-9]+) ]]; then
    CLIPPY_VERSION_MAJOR="${BASH_REMATCH[1]}"
    CLIPPY_VERSION_MINOR="${BASH_REMATCH[2]}"
    # Note: for 1.90 CLIPPY_VERSION will be 1090
    CLIPPY_VERSION=$(($CLIPPY_VERSION_MAJOR * 1000 + $CLIPPY_VERSION_MINOR))
else
    echo "Unable to determine the version of Clippy"
    exit 1
fi

# Checks enabled everywhere, including tests, benchmarks.
# Note:
# 1) "uninlined_format_args" is about changing `format!("{}", x)` to `format!("{x}")`.
#   Most of the time this makes the code look better, but:
#     * there are way too many places like this;
#     * in some cases it may lead to uglier code; in particular, when the format string is already
#       quite long.
#   So we disable it for now.
# 2) "manual_is_multiple_of" - starting from v1.90 clippy insists that `x % 2 == 0` should be
#   replaced with `x.is_multiple_of(2)`, which is a questionable improvement.
EXTRA_ARGS=()
if [[ $CLIPPY_VERSION -ge 1090 ]]; then
    EXTRA_ARGS+=(-A clippy::manual_is_multiple_of)
fi
cargo clippy --all-features --workspace --all-targets -- \
    -D warnings \
    -A clippy::unnecessary_literal_unwrap \
    -A clippy::new_without_default \
    -A clippy::uninlined_format_args \
    -D clippy::implicit_saturating_sub \
    -D clippy::implicit_clone \
    -D clippy::map_unwrap_or \
    -D clippy::unnested_or_patterns \
    -D clippy::manual_assert \
    -D clippy::unused_async \
    -D clippy::mut_mut \
    -D clippy::todo \
    "${EXTRA_ARGS[@]}"

# Checks that only apply to production code
cargo clippy --all-features --workspace --lib --bins --examples -- \
    -A clippy::all \
    -D clippy::float_arithmetic \
    -D clippy::unwrap_used \
    -D clippy::dbg_macro \
    -D clippy::items_after_statements \
    -D clippy::fallible_impl_from \
    -D clippy::string_slice

# Install requirements with: pip install -r ./build-tools/codecheck/requirements.txt
"$PYTHON" "build-tools/codecheck/codecheck.py"

# Ensure that wasm documentation is up-to-date
cargo run -p wasm-doc-gen -- -o wasm-wrappers/WASM-API.md --check
