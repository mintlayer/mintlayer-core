#!/bin/bash

set -e
set -o nounset

NODE_INDEX=$1

node-daemon \
    --datadir=$WORK_DIR_IN_CONTAINER/node$NODE_INDEX $COMMON_NODE_DAEMON_ARGS \
    $(dig +short $NODES_LIST | xargs printf '--p2p-reserved-nodes %s ')
