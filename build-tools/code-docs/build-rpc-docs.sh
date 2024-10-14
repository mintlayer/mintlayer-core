#!/bin/bash

# Get the dir where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

cd ${SCRIPT_DIR}/../../
UPDATE_EXPECT=1 cargo test -p node-daemon --test rpc_docs
UPDATE_EXPECT=1 cargo test -p wallet-rpc-daemon --test rpc_docs --features trezor
