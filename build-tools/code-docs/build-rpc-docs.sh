#!/bin/bash

echo 'Checking we are in the top-level directory of the project' >&2
set -x
[ -f 'Cargo.toml' ] || exit 1
grep 'name = "mintlayer-core"' Cargo.toml || exit 1

mkdir -p ./node-daemon/docs/
cargo run -p gen-rpc-docs -- node > ./node-daemon/docs/RPC.md

mkdir -p ./wallet/wallet-rpc-daemon/docs/
cargo run -p gen-rpc-docs -- wallet > ./wallet/wallet-rpc-daemon/docs/RPC.md
