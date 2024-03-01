#!/bin/bash

# Get the dir where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Delete the old versions of docs, if any
rm -rf ${SCRIPT_DIR}/../../target/doc/
rm -rf ${SCRIPT_DIR}/../../wasm-wrappers/doc/

# Create the docs, which will be in the `target` directory
cargo doc --no-deps --manifest-path ${SCRIPT_DIR}/../../Cargo.toml -p wasm-wrappers --lib

# Move the docs to the wasm directory
mv ${SCRIPT_DIR}/../../target/doc ${SCRIPT_DIR}/../../wasm-wrappers/
