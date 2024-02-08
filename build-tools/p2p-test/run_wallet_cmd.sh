#!/bin/bash

set -e
set -o nounset

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

source "$SCRIPT_DIR/.env"

if [[ $# -lt 2 ]]; then
    echo "Run a wallet command on the specified node"
    echo "Usage: $(basename "$0") container_idx wallet_cmd [wallet_cmd_params...]"
    echo "  node_idx - the index of the node, e.g. 1, 2, 3 etc"
    echo "  wallet_cmd - the command to send to the wallet, e.g. node-list-connected-peers"
    echo "  wallet_cmd_params - optional parameters for the specified command"
    exit 1
fi

cd "$SCRIPT_DIR"

NODE_NAME_SUFFIX=$(printf '%02d' "$1")
shift

NODE=node${NODE_NAME_SUFFIX}

docker compose exec "${NODE}" bash -c "echo $@ > /tmp/cmd.txt"
# Note: by default, 'docker compose exec' will print everything to stdout, even if originally
# it was printed to stderr, e.g. the logs, making it a PITA to parse the normal output.
# The '-T' AKA '--no-TTY' option solves this somehow. But the logs become non-colored in this case
# though.
docker compose exec -T "${NODE}" wallet-cli testnet --commands-file /tmp/cmd.txt
