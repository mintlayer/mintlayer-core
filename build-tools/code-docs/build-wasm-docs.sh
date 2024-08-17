#!/bin/bash

# Get the dir where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

cd ${SCRIPT_DIR}/../../
cargo run -p wasm-doc-gen -- -o wasm-wrappers/WASM-API.md
