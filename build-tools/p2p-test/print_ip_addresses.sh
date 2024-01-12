#!/bin/bash

set -e
set -o nounset

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

cd "$SCRIPT_DIR"

for i in {1..15}
do
    NODE_NAME_SUFFIX=$(printf '%02d' "$i")
    # Note: from address resolution perspective, it doesn't matter which container to execute 'dig'
    # in. But since some containers may be down, it makes sense to use the one the address
    # of which we're trying to resolve.
    ADDR=$(docker compose exec "node${NODE_NAME_SUFFIX}" dig +short "node${NODE_NAME_SUFFIX}")
    echo "node${NODE_NAME_SUFFIX}: $ADDR"
done
