#!/bin/bash

echo 'Checking we are in the top-level directory of the project' >&2
set -x
[ -f 'Cargo.toml' ] || exit 1
grep 'name = "mintlayer-core"' Cargo.toml || exit 1

CHECK=false
case "$1" in
    --check) CHECK=true ;;
    '') ;;
    *) echo "Unrecognized argument '$1'" && exit 2 ;;
esac

TMP_DIR=./target/tmp/rpc-docs
mkdir -p "$TMP_DIR"
cargo run -p gen-rpc-docs -- node > "$TMP_DIR/NODE_RPC.md"
cargo run -p gen-rpc-docs -- wallet > "$TMP_DIR/WALLET_RPC.md"

NODE_DIR="./node-daemon/docs"
WALLET_DIR="./wallet/wallet-rpc-daemon/docs"

if $CHECK; then
    diff "$TMP_DIR/NODE_RPC.md" "$NODE_DIR/RPC.md" || exit 1
    diff "$TMP_DIR/WALLET_RPC.md" "$WALLET_DIR/RPC.md" || exit 1
else
    mkdir -p "$NODE_DIR" "$WALLET_DIR"
    mv "$TMP_DIR/NODE_RPC.md" "$NODE_DIR/RPC.md"
    mv "$TMP_DIR/WALLET_RPC.md" "$WALLET_DIR/RPC.md"
fi
