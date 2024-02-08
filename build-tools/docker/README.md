# Mintlayer Node-Daemon and Wallet-CLI Docker Deployment

This guide will cover how to use Docker to deploy and run the Mintlayer `node-daemon` and `wallet-cli`.

## Prerequisites

You need to have Docker installed on your system. For Docker installation guide, please visit [official Docker documentation](https://docs.docker.com/get-docker/).

## Mintlayer Node-Daemon

First, let's pull the docker image for `node-daemon`:

```bash
docker pull mintlayer/node-daemon:latest
```

Create a network for the containers to communicate:

```bash
docker network create mintlayer-net
```

To run the `node-daemon` detached and on the testnet network:

```bash
docker run -d -p 13030:13030 -p 13031:13031 --network=mintlayer-net --name mintlayer_node_daemon --user "$(id -u):$(id -g)" -v ~/.mintlayer:/root/.mintlayer mintlayer/node-daemon:latest node-daemon testnet  --rpc-bind-address 0.0.0.0:13030
```

The `-v` option is used to mount a local directory (in this case `~/.mintlayer`) as a volume in the Docker container.
The `--user` option is used to specify the user that will write to the `~/.mintlayer` directory.
NOTE: this won't work on windows hosts.

If you want to display logs you can pass the `-e RUST_LOG=info` argument, such as:

```bash
docker run -d -p 13030:13030 -p 13031:13031 -e RUST_LOG=info --network=mintlayer-net --name mintlayer_node_daemon --user "$(id -u):$(id -g)" -v ~/.mintlayer:/root/.mintlayer mintlayer/node-daemon:latest node-daemon testnet  --rpc-bind-address 0.0.0.0:13030
```

## Mintlayer Wallet-CLI

Pull the docker image for `wallet-cli`:

```bash
docker pull mintlayer/wallet-cli:latest
```

Before running `wallet-cli`, ensure that the `node-daemon` container is running, as it generates the `.cookie` file required by wallet-cli, then find the IP address of the node:

```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -aqf "name=mintlayer_node_daemon")
```

this will display the IP address of your node in the `mintlayer-net`

To run `wallet-cli` with the RPC cookie file:

```bash
docker run -it --network=mintlayer-net -v ~/.mintlayer:/root/.mintlayer mintlayer/wallet-cli:latest wallet-cli --rpc-cookie-file /root/.mintlayer/<NETWORK>/.cookie --rpc-bind-address <IP_ADDRESS>:13030
```

replace `<NETWORK>` with `mainnet` or `testnet` depending on what network you're running and `<IP_ADDRESS>` with the result of the command above.

This command mounts the same `~/.mintlayer` directory as a volume in the `wallet-cli` container and uses the `--rpc-cookie-file` option to specify the path to the cookie file.
