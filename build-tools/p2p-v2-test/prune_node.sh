#!/bin/bash

set -e
set -o nounset

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

source "$SCRIPT_DIR/.env"

if [[ $# -lt 1 ]]; then
    echo "Stop the specified node, remove its data, start it again"
    echo "Usage: $(basename "$0") container_idx"
    echo "  node_idx - the index of the node, e.g. 1, 2, 3 etc"
    exit 1
fi

NODE_NAME_SUFFIX=$(printf '%02d' "$1")
shift

cd "$SCRIPT_DIR"

docker compose stop "node${NODE_NAME_SUFFIX}"
docker compose rm --force "node${NODE_NAME_SUFFIX}"
docker volume rm "${BASE_NAME}_data${NODE_NAME_SUFFIX}"
docker compose up -d "node${NODE_NAME_SUFFIX}"
