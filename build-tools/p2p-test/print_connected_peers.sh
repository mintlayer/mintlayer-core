#!/bin/bash

set -e
set -o nounset

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

print_peers() {
    local node_id=$1
    echo "Node ${node_id}'s peers:"
    "${SCRIPT_DIR}/run_wallet_cmd.sh" "$node_id" node-list-connected-peers-json 2> /dev/null | \
        jq -c '.[] | [.peer_id, .address, .software_version, .peer_role]'
    echo
}

if [[ $# -lt 1 ]]; then
    for i in {1..15}
    do
        print_peers "$i"
    done
else
    for i in "$@"
    do
        print_peers "$i"
    done
fi
