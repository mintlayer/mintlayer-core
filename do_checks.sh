#!/bin/bash

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PYTHON=$(which python || which python3)

cargo fmt --check -- --config newline_style=Unix

# Install cargo deny first with: cargo install cargo-deny
# cargo deny check --hide-inclusion-graph

# Checks enabled everywhere, including tests, benchmarks
cargo clippy --all-features --workspace --all-targets -- \
    -D warnings \
    -A clippy::unnecessary_literal_unwrap \
    -A clippy::new_without_default \
    -D clippy::implicit_saturating_sub \
    -D clippy::implicit_clone \
    -D clippy::map_unwrap_or \
    -D clippy::unnested_or_patterns \
    -D clippy::manual_assert \
    -D clippy::unused_async \
    -D clippy::mut_mut \
    -D clippy::todo

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
"$PYTHON" "$SCRIPT_DIR/build-tools/codecheck/codecheck.py"

# Ensure that wasm documentation is up-to-date
cargo run -p wasm-doc-gen -- -o wasm-wrappers/WASM-API.md --check
