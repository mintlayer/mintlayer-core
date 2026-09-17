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

#### Real-time event streaming

The scanner daemon and the API web server also cooperate to provide a real-time event stream for block explorer clients. When the scanner indexes new blocks, it writes the corresponding events into the `ml.emitted_events` table *inside the same database transaction* that performs the indexing, and a notification is delivered to listeners when the transaction commits. The API web server runs an "event pump" that listens for these notifications on a dedicated database connection (with automatic reconnection and a periodic polling fallback) and forwards the events to connected clients. Independently of this, transactions reaching the node's mempool are bridged from the node's WebSocket RPC and delivered as `tx_seen` events immediately, before the block containing them is indexed. The key guarantee for clients: once a `block` event is delivered, the referenced block and its transactions are immediately queryable through the regular REST endpoints; there is no race between the event and the data it refers to.

### Using other database infrastructures

Currently, the API server uses PostgreSQL for storage, but the design is extremely flexible and any desired database can be added if needed by implementing some interface (trait) in the rust code.

In addition to the PostgreSQL, an implementation of a full in-memory storage exists, which we use for testing and as a reference implementation. Hence, when adding a new database implementation, the in-memory implementation can be used as a reference one. Our tests ensure that both PostgreSQL and in-memory implementation, through the beautiful abstractions of rust, arrive to the same result. Any additional implementation can be added to the same test suite.

#### Database schema versions and upgrades

The storage schema is versioned (`CURRENT_STORAGE_VERSION` in the source code, currently 26). When the blockchain scanner daemon encounters a database with a different version than the one it expects, it re-initializes the database from scratch, dropping the old data and performing a full re-scan of the blockchain; this is also when missing tables are created. Version 26 added the `ml.emitted_events` table, the append-only log that backs the [real-time event stream](#real-time-event-stream). Since the event stream has no replay and old events are never read again, the scanner prunes stream events older than the most recent 10,000.

## Real-time event stream

The API web server exposes a real-time event stream for block explorer clients, based on Server-Sent Events (SSE). Any standard SSE client works: the connection stays open, and the server pushes events as they happen.

### Endpoint

```
GET /api/v2/stream
```

The endpoint requires no authentication, consistent with the other `/api/v2` GET endpoints, and responds with the `text/event-stream` content type.

An optional `types` query parameter restricts the streamed event kinds to a comma-separated subset of `tx_seen`, `block`, and `reorg`; by default, all kinds are streamed. Invalid values are rejected with HTTP 400. For example, to receive only block and reorganization events:

```
GET /api/v2/stream?types=block,reorg
```

### Event format

Events are *named* SSE events, so clients can subscribe to specific kinds with `EventSource.addEventListener("block", ...)` and so on. Every payload is a JSON object of the form `{"type": <event name>, "content": {...}}`. A `block` event looks like this on the wire:

```
event: block
data: {"type":"block","content":{"block_id":"<hex>","height":3,"timestamp":1639975460,"tx_ids":["<hex>"]}}
```

The content per event kind:

| Event | Content fields |
| ----- | -------------- |
| `tx_seen` | `tx_id` (hex); `origin`, which is `local` when the transaction was submitted through this node and `remote` when it was observed coming from the network |
| `block` | `block_id` (hex); `height`; `timestamp` (unix seconds); `tx_ids`, the list of the block's transaction ids (hex) |
| `reorg` | `common_ancestor_height`; `removed_block_ids`, the blocks disconnected by the reorganization (hex); `new_tip_height` |

A few additional frames to be aware of:

- The first frame is a `retry:` hint of 3 seconds, telling conforming clients how long to wait before reconnecting.
- Keepalive comment lines (`: keepalive`) are sent while the stream is idle, every 30 seconds by default, so that proxies and clients can tell the connection is alive.
- The response carries an `x-accel-buffering: no` header to keep reverse proxies from buffering the stream. If you operate a reverse proxy in front of the web server, make sure response buffering stays disabled, or the events will not reach the clients in real time.
- If a client falls further behind than the server's per-client event buffer (1024 events by default), it receives a `lag` advisory event, `data: {"skipped": N}`, instead of the missed events. When this happens, reconcile the current state through the regular REST endpoints.

A minimal browser client:

```js
const source = new EventSource("http://127.0.0.1:3000/api/v2/stream?types=block,reorg");
source.addEventListener("block", (e) => console.log("block:", JSON.parse(e.data).content));
source.addEventListener("reorg", (e) => console.log("reorg:", JSON.parse(e.data).content));
```

### Semantics and limitations

- There is **no replay**: events missed while disconnected, or skipped on lag, are not re-sent, and the `Last-Event-ID` header is not supported. Recover missed data through the regular REST endpoints.
- `tx_seen` events refer to transactions currently in the node's mempool; such a transaction may never be mined. Only successfully processed transactions are streamed.
- A `block` event means the block has been fully indexed: the block and its transactions are immediately available through the REST endpoints.

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

The [real-time event stream](#real-time-event-stream) works out of the box, with no configuration changes needed for existing deployments. Four options are available for tuning:

- `--stream-events-broadcast-capacity` (default 1024): how many events are buffered per connected client before the client receives a `lag` advisory event instead of the missed events.
- `--stream-events-max-subscribers` (default 128): the maximum number of concurrently served stream connections; further clients are rejected with `429 Too Many Requests`.
- `--stream-events-poll-interval-secs` (default 30): how often the event pump polls the database for new events, as a safety net for missed notifications.
- `--stream-events-keepalive-interval-secs` (default 30): how often keepalive comments are sent to connected stream clients.

Note that the event pump behind the stream uses the PostgreSQL LISTEN/NOTIFY mechanism on a dedicated connection, so the real-time stream requires the PostgreSQL backend.

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
