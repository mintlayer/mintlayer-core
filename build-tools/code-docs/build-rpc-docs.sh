#!/bin/bash

echo 'Checking we are in the top-level directory of the project' >&2
set -x
[ -f 'Cargo.toml' ] || exit 1
grep 'name = "mintlayer-core"' Cargo.toml || exit 1

cargo run -p node-lib --example node-rpc-docs >./node-daemon/RPC_INTERFACE.md
cargo run -p wallet-rpc-lib --example wallet-rpc-docs >./wallet/wallet-rpc-daemon/RPC_INTERFACE.md
