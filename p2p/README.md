# P2P subsystem

TODO: this document is very incomplete.

## Protocol specification

This section provides the protocol specification for Mintlayer's P2P networking.

There are four distinct phases in the protocol:
* peer discovery
* connection establishment
* connection maintenance
* message exchange

### Peer discovery

The peer discovery of any P2P system is constructed of two things: the initial connection to well-known hosts and subsequent connections to discovered nodes. It means that there must always be at least one reachable node that the Mintlayer node can connect to and learn the addresses of all other nodes it can try connecting to.

#### Bootstrapping

When the node starts for the first time, it obtains peer addresses from the so-called dns seeds; if it fails to do so, a predefined list of addresses is used.

#### Peer-to-peer connections

Once a Mintlayer node has started and established a connection with a bootnode, it receives a list of other active nodes that are present in the network. It then tries to connect to each of these until either the list is exhausted or it has established enough outbound connections.

#### Future extensions

Research: Can Mintlayer reduce the possibility of network splits by diversifying the bootstrapping procedure by using protocols such as [Yggdrasil](https://yggdrasil-network.github.io/), [I2P](https://geti2p.net/en/) or [Tor](https://www.torproject.org/)?

Research: TCP hole punching with the help of bootnodes to allow inbound connections without opening firewall ports?

### Connection establishment and maintenance

The connection between peers is established first at the network service provider level and if that succeeds, the P2P system performs a handshake to verify that the peers are running compatible software and chain.

When that is done, the connection is kept open by exchanging messages and as the number of connections change, the Mintlayer node will respond to it by either rejecting connections or establishing new connections.

### Connection establishment

When Mintlayer nodes are connecting to each other, they perform a handshake that verifies that they are capable of having a meaningful exchange of messages, i.e., the peers are running the same version of the software and they are both on the same network. Furthermore, they provide information about themselves, e.g., do they accept inbound connections or are they a light client.

This information is exchanged in the `Hello` and `HelloAck` messages. The node who is connecting sends the `Hello` message and the node who accepted the connection responds to it with `HelloAck` message. When a `Hello` message is received, the peer checks whether it's running compatible node and if so, it responds to with a `HelloAck` message that has the exact same format as `Hello`. If the peers are not compatible, receiver of the `Hello` closes the connection, which signals to the sender that they are incompatible.

### Connection maintenance

Once a minute, the node will check if the remote peer is still active by sending a `PingRequest` message. The peer that receives a `PingRequest` must respond with a `PingResponse` message. If no response is heard, the connection is closed. `PingRequest`/`PingResponse` are exchanged only if there has been no activity on the socket in the last minute. Each `PingRequest` message contains a 64-bit nonce that the corresponding `PingResponse` sends back to ascertain that a correct `PingRequest` message was acknowledged.

In addition to maintaining each connection individually, the Mintlayer node will also maintain the overall set of connections by accepting incoming connections/establishing new outbound connections to maintain the total amount of connections at the specified number. This means that the event loop of the node will reject new connections if the number of active connections is higher than it should be; if the number of connections is lower than the lower bound for the number of active connections, the node will try establishing new connections with peers it has learned from previous connections.

### Message exchange

Each message starts with a 4-bytes header that contains the length of the message, not including the header itself.

| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| 4 bytes | Message length | `u32` | The length of the message body that follows.
| Variable | Message body | `enum Message` | An encoded `Rust` enum.

The message body is a SCALE-encoded `Rust` enum. With this encoding, the first byte of the encoded data specifies the enum variant contained in the enum; the rest is that variant's encoded data.

The encoded `enum Message`:
| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| 1 byte | Message variant index | `u8` | The index that specifies which enum variant is encoded below.
| Variable | The encoded message variant | Depends on the previous field

Currently, the following message variants exist:
| Variant index | Type |
|---------------|------|
| 0 | HandshakeMessage
| 1 | PingRequest
| 2 | PingResponse
| 3 | NewTransaction
| 4 | HeaderListRequest
| 5 | HeaderList
| 6 | BlockListRequest
| 7 | BlockResponse
| 8 | AnnounceAddrRequest
| 9 | AddrListRequest
| 10 | AddrListResponse
| 11 | TransactionRequest
| 12 | TransactionResponse

#### HandshakeMessage

`HandshakeMessage` is itself an enum that consists of 2 variants:
| Variant index | Type |
|---------------|------|
| 0 | Hello
| 1 | HelloAck

`Hello` is used by the connecting node to initiate a handshake.

| Length | Description | Type | Comments |
|--------|-------------|---------|----------|
| 4 bytes | Protocol version | `u32`   | The latest protocol version that the node supports.
| 4 bytes | Network | `[u8; 4]` | "Magic bytes" that identify the network. For mainnet, this will be equal to `B0075FA0`; for testnet, this will be `2B7E19F8`.
| 8 bytes | Services | `u64`   | Bitmap of services that the node provides/supports.
| Variable | User agent | `Vec<u8>` | An ASCII string containing the name of the user's software.
| 4 bytes | Software version | `SemVer`   | The version of the user's software.
| Variable | Receiver address | `Option<PeerAddress>` | Socket address of the remote peer as seen by the sending node.
| Variable | Current time | Compact `u64` | Unix timestamp in seconds.
| 8 bytes | Handshake nonce | `u64` | A random nonce value that is used to detect self-connects.

`HelloAck` is used to conclude the handshake with the node that initiated it. It is identical to `Hello` except for the last field, the handshake nonce, which is absent for `HelloAck`.

#### PingRequest

Check if the peer is still alive.

| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| 8 bytes | Nonce | `u64` | Random nonce

#### PingResponse

Respond to an aliveness check.

| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| 8 bytes | Nonce | `u64` | Random nonce

The random nonce carried in the `PingResponse` message must be the same that was in the `PingRequest` message that this `PingResponse` is now acknowledging.

#### NewTransaction

Announce a new transaction.

| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| 32 bytes | Transaction ID | `Id<Transaction>`
