#!/bin/bash

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PYTHON=$(which python || which python3)

cargo fmt --check

# Install cargo deny first with: cargo install cargo-deny
cargo deny check --hide-inclusion-graph

# Checks enabled everywhere, including tests, benchmarks
cargo clippy --all-features --workspace --all-targets -- \
    -D warnings \
    -A clippy::unnecessary_literal_unwrap \
    -A clippy::new_without_default \
    -W clippy::implicit_saturating_sub \
    -W clippy::implicit_clone \
    -W clippy::map_unwrap_or \
    -W clippy::unnested_or_patterns \
    -W clippy::manual_assert \
    -W clippy::unused_async \
    -W clippy::mut_mut \
    -W clippy::todo

# Checks that only apply to production code
cargo clippy --all-features --workspace --lib --bins --examples -- \
    -A clippy::all \
    -D clippy::float_arithmetic \
    -W clippy::unwrap_used \
    -W clippy::dbg_macro \
    -W clippy::items_after_statements \
    -W clippy::fallible_impl_from \
    -W clippy::string_slice

# Install requirements with: pip install -r ./build-tools/codecheck/requirements.txt
"$PYTHON" "$SCRIPT_DIR/build-tools/codecheck/codecheck.py"
