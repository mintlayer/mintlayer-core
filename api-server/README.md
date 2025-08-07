## Mintlayer API server

### Introduction

The Mintlayer API server is a tool that scans the blockchain and publishes its data in a database for easy access. Technically speaking, this is done to achieve the trade-off where the blockchain itself contains the minimal required amount of data, while the API server indexes all the data for easy reach. The API server is used by block explorers and web wallets. The API server is made to be usable in many ways, including in exchanges, by people interested in writing tooling for the blockchain, or anything else.

For example to understand what problem the API server solves, the node software only stores blocks of the blockchain, but it does not index the transactions by their id. Meaning: Attempting to find a transaction by its id is virtually impossible without going through all blocks. The same applies to more information that's not directly, minimally, required to operate the blockchain. In that case, using the API server solves all these problems, since the API server is made to index the information and put it in the database.

## Architecture

#### The API web server

The API web server contains the restful endpoints that can be reached by the client application, such as the block explorer or the web wallet. The API web server communicates with the database in the backend to respond to queries, in addition to the optional possibility to communicate with the node for specialized requests, such as submitting transactions or finding out the current transaction fee in the mempool.

#### The blockchain scanner daemon

The blockchain scanner daemon is a tool that runs in the backend, scans the blockchain, and updates the database information.

#### How the API web server and the blockchain scanner daemon work together

The architecture of the API server is made to be distributed as much as desired. You can run the database on as many servers as you wish in master-slave mode. This is achieved by separating the "API web server" from the "blockchain scanner daemon". You can have a single "blockchain scanner daemon", communicating with the `node-daemon` of Mintlayer, collecting information about new blocks and writing it to the master database, while having as many instances of the API web server reading from the slave databases. This ensures virtually an infinitely scalable infrastructure.

### Using other database infrastructures

Currently, the API server uses PostgreSQL for storage, but the design is extremely flexible and any desired database can be added if needed by implementing some interface (trait) in the rust code.

In addition to the PostgreSQL, an implementation of a full in-memory storage exists, which we use for testing and as a reference implementation. Hence, when adding a new database implementation, the in-memory implementation can be used as a reference one. Our tests ensure that both PostgreSQL and in-memory implementation, through the beautiful abstractions of rust, arrive to the same result. Any additional implementation can be added to the same test suite.

## How to run

In the following we present the minimal requirements to run the API server in action. In this example, we will be using the testnet. Replace every `testnet` with `mainnet` for the mainnet.

### Make sure you have a node running

If you don't have a node running, the API server won't have a source, from which it can read block data. To run the node, please consult the [main readme file of the repo](/README.md).

### How to run the database

To run the database, you can use use docker or podman. For simplicity, so that root isn't needed, podman can be used:

```
podman run --detach --rm --name MintlayerAPIServerDB -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=mintlayer-testnet -p 127.0.0.1:5432:5432 docker.io/library/postgres
```

Notice a few things:

1. This command doesn't need root
2. The database is running in trust mode, which means no username or password required
3. The command line argument `--rm` is used, so that the container will be deleted on exit
4. The database name is `mintlayer-testnet`. This is the default database name that the API server will use for testnet. In general, the default database name is `mintlayer-`, followed by the network name (mainnet, testnet, etc).
5. The port binding `127.0.0.1:5432:5432` doesn't allow external computers in the network to connect. Binding to `0.0.0.0` has security implications that are out of the scope of this documentation. Please make sure to have proper network security when running a database.
6. There's no volume set. Meaning: Once the container is stopped and removed, all the data in the database may be lost (based on this container's volume policy, it will be stored in the common volume storage of the OS). Please consult the documentation of the container to learn how to preserve the database data.

Please understand that this is just a minimal example, and for real infrastructure, proper security must be considered.

### How to run the blockchain scanner daemon

Assuming the database works as described earlier, the blockchain scanner daemon can be run from the source code using:

```
cargo run --bin api-blockchain-scanner-daemon --release -- --network testnet
```

or if you want to run using the executable directly:

```
api-blockchain-scanner-daemon --network testnet
```

And this should immediately work. The blockchain scanner daemon will communicate with the default network RPC network port of the node (13030 for testnet, 3030 for mainnet), and it will also communicate with the database and write the data it finds in the blockchain.

If you need to configure extra options, such as postgres username and password, just add `--help` to the commands above, and the options will be shown.

### How to run the API web server

After having filled the database with information, the API web server can use this information to respond to http requests, whether for requests from the public, or your internal infrastructure for other purposes.

Assuming the database server is setup on the same machine and is reachable via `127.0.0.1:5432`, you can use the following command to run the API web server, compiled from the source code:

```
cargo run --bin api-web-server --release -- --network testnet --bind-address 127.0.0.1:3000
```

Or, you can just run the executable if you have the binary `api-web-server` and use it directly:

```
api-web-server --network testnet --bind-address 127.0.0.1:3000
```

The API web server will immediately start and connect to the database locally. A specific remote database can be specified using command line arguments. Add `--help` to the previously mentioned commands to see how to do this.

### Testing the API web server

Once the previous steps are complete, you're ready to communicate with the API web server. The following curl command should work (or you can put the link in your browser directly):

```
curl http://127.0.0.1:3000/api/v2/chain/tip
```

which will return the best block information in the blockchain. Or:

```
curl http://127.0.0.1:3000/api/v2/chain/10
```

to get the id of the block at height 10.

Make sure the scanner is fully synced to get correct information about the current state of the blockchain.

### Logging

The same logging rules [in the main readme file](/README.md) apply here as well. By default, all our programs use INFO level logging.
