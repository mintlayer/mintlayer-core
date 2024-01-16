Here we have helper docker files that allow us to run multiple nodes on the same machine
in order to check that the p2p protocol works correctly after an upgrade.

### Usage:

`cd` to this directory and run
```
docker compose up --build
```
or
```
docker compose up --build -d
```
In the latter case the containers will be run in the background. To view their console output, you can run:
```
docker compose logs -f
```
When you are done, run
```
docker compose down
```
to shut down the containers.

### Details:

"docker compose up..." will build a docker image containing `node-daemon` and `wallet-cli` and launch multiple containers (currently 15) that will be running the nodes. Each node will get other nodes' ip addresses at the start via the `--p2p-boot-node` option, so they all will be able to start connecting to each other immediately.

### Helper scripts:
#### run_wallet_cmd.sh
```
run_wallet_cmd.sh node_idx cmd [cmd_params...]
```
Run the specified wallet-cli command on the specified node. E.g. `run_wallet_cmd.sh 1 node-list-connected-peers` will print peer information for the 1st node.

#### prune_node.sh
```
prune_node.sh node_idx
```
Stop the node's container, remove its data and start the container again.

#### print_ip_addresses.sh
```
print_ip_addresses.sh
```
Print nodes' ip addresses.

#### print_connected_peers.sh
```
print_connected_peers.sh [node_idx1 node_idx2 ...]
```
Call `run_wallet_cmd.sh` for each specified node index or, if no indices are specified, for all node indices and print a short summary of the node's connected peers.

This script uses the `jq` tool, so make sure it's installed.
