# P2P subsystem

TODO

## Protocol specification

This section provides the protocol specification for Mintlayer's P2P networking.

There are four distinct phases in the protocol:
* peer discovery
* connection establishment
* connection maintenance
* message exchange

The network service provider may implement its own handshaking and connectivity monitoring but they are not part of the Mintlayer P2P protocol and thus there may be overlapping functionality between the two.

The protocol relies on an assumption that a connection is formed between the peers and that the local peer is able to notice when the remote peer has closed the connection. This means that the protocol cannot be directly built on top of a connectionless protocol, e.g., UDP. Additionally, it is required from the protocol that it provides a message-based API instead of a stream-based API. It can internally fragment and reconstruct the messages as it wants but the P2P protocol requires that it's capable of both sending and receiving discrete messages, instead of fragments of those messages.

The network service provider *should* provide End-to-End Encryption (E2EE) for the transportation.

### Peer discovery

The peer discovery of any P2P system is constructed of two things: the initial connection to well-known hosts and subsequent connections to discovered nodes. It means that there must always be at least one reachable node that the Mintlayer node can connect to and learn the addresses of all other nodes it can try connecting to.

#### Bootstrapping

To get something simple working, Mintlayer assumes that a webserver reachable via HTTPS (such as Github) contains a list of bootnodes. When the node is booting, it fetches this list from the server and reseeds itself with the nodes specified in the list. The nodes listed in the file can either be just bootnodes that do nothing but help other nodes to boot, or they can be full Mintlayer nodes that in addition to providing booting services also handle block validation etc.

#### Peer-to-peer connections

Once a Mintlayer node has started and established a connection with a bootnode, it has received a list of other active nodes that are present in the network. It then tries to connect to each of these until either the list is exhausted or it has established enough outbound connections which is configurable and by default is set to 32.

Each time peer connects to another peer, they exchange their peer info in `Pex` and `PexAck` messages, following the idea of [BitTorrent's peer exchange (PEX) protocol](https://en.wikipedia.org/wiki/Peer_exchange). This reduces the load on bootnodes as they are only used to learn the initial set of peers and all further peer exchanging happens directly between the peers.

#### Future extensions

Research: Can Mintlayer reduce the possibility of network splits by diversifying the bootstrapping procedure by using protocols such as [Yggdrasil](https://yggdrasil-network.github.io/), [I2P](https://geti2p.net/en/) or [Tor](https://www.torproject.org/)?

Research: TCP hole punching with the help of bootnodes to allow inbound connections without opening firewall ports?

### Connection establishment and maintenance

The connection between peers is established first at the network service provider level and if that succeeds, the socket is passed onto the P2P system which performs a handshake to verify that the peers are running compatible software and chain.

When that is done, the connection is kept open by exchanging messages and as the number of connections change, the Mintlayer node must respond to it by either rejecting connections or establishing new connections.

### Connection establishment

When Mintlayer nodes are connecting to each other, they must perform a handshake that verifies that they are capable of having a meaningful exchange of messages, i.e., the peers are running the same version of the software and they are both on the same network. Furthermore, they must provide information about themselves, e.g., do they accept inbound connections or are they are a light client.

This information is exchanged in the `Hello` and `HelloAck` messages. The node who is connecting sends the `Hello` message and the node who accepted the connection responds to it with `HelloAck` message. When a `Hello` message is received, the peer checks whether it's running compatible node and if so, it responds to with a `HelloAck` message that has the exact same format as `Hello`. If the peers are not compatible, receiver of the `Hello` closes the connection, which signals to the sender that they are incompatible.

After `Hello` and `HelloAck` messages have been exchanged, the peer that sent the `Hello` message sends a `Pex` message which contains the peers it knows about and the receiver responds to that with a `PexAck` message which in turn contains the peers it knows about.

### Connection maintenance

Once a minute, the node must check if the remote peer is still active by sending a `Ping` message. The peer that receives a `Ping` must respond with a `Pong` message within 10 seconds. If no response is heard, the `Ping` is sent again. If no response is heard after 3 retries, he connection is closed. `Ping`/`Pong` is exchange only if there has been no activity on the socket in the last minute.

Additionally, once every 5 minutes, the peers shall exchange peer information they've learned within the last 5 minutes. This means that the peer which initiated the connection sends a `Pex` message which contains either an empty list (if it hasn't discovered new nodes) or a list of nodes it has discovered within the last 5 minutes. The other node responds to this message with a `PexAck` message that also contains either an empty list or a list of new nodes discovered within the last 5 minutes.

In addition to maintaining each connection individually by exchanging `Ping`/`Pong` and `Pex`/`PexAck` messages, the Mintlayer node must also maintain the overall set of connections by accepting incoming connections/establishing new outbound connections to maintain the total amount of connections at the specified number which is by default set to 32. This means that the event loop of the node must reject new connections if the number of active connections is higher than it should be or if the number of connections is lower than the lower bound for number of active connections, the node must try establishing new connections with peers it has learned from previous connections. In case there aren't 32 peers in the network, the node must try to connect to as many nodes as it can as the number of nodes in the network grows, it must try to connect to the new nodes until it reaches 32 active connections.

### Message exchange

The peers exchange messages directly between each other and apart from blocks and transactions which are most likely published on a separate gossip topics (instead of being exchanged directly between peers), all messages form a request/response pairs. It's a violation of the protocol not to respond to a request with a proper response, even with an empty response if the data query could not be fulfilled. The transport channel is available for use while a request/response pair is still in progress meaning the communication is not blocked for other uses socket before the response for the request is heard.

Each message contains at least the header which indicates the message type it carries, the network this message originated from and whether the message carries any paylaod. Table below depicts the header format.

| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| 4 bytes | Magic number | `u32` | Magic number that identifies a Mintlayer P2P message
| 2 bytes | Message type | `enum MessageType` | Number that identifies the message type (`Hello`, `Transaction`, etc.)
| 4 bytes | Length | `u32` | Length of the payload
| N bytes | Payload | `Vec<u8>` | Byte vector containing the SCALE-encoded representation of the message

#### Hello

`Hello` is used by the connecting peer to initiate a handshake and to verify whether the remote peer running compatible software.

| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| 4 bytes | Version | `u32` | Version of the software the node is running
| 4 bytes | Network ID | `u32` | Mainnet, testnet
| 4 bytes | Services | `u32` | Bitmap of services that the node provides/supports (inbound connections, validation, block relay, etc.)
| 8 bytes | Timestamp | `u64` | Unix timestamp in seconds

#### HelloAck

`HelloAck` is used to conclude the handshake with the peer that initiated it, if they are running compatible software and are in the same network.

The format of `HelloAck` message is the same as the format of `Hello` with the exception that message type in the header is different.

#### Ping

Check if the peer is still alive

The `Ping` does not transfer any payload data

#### Pong

Respond to an aliveness check

The `Pong` does not transfer any payload data

#### Pex

`Pex` message is used to exchange peer information directly between the peers. By enforcing on the protocol level that peers establish connections with each other only if they are compatible, is automatically follows that the peers listed in `Pex` are also running compatible version of the software with the receiver. If the node doesn't know about any new peers, `Length` is set to zero.

| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| 1 bytes | Length | `u8` | Number of peer entries
| N bytes | Peers | `Vec<u8>` | Byte vector containing SCALE-encodeded vector of `(socket address, services)` tuples.

#### PexAck

`PexAck` is a response to a `Pex` message and it contains all the new peers the node has discovered since the last PEX exchange with the remote peer was performed.

The format of `PexAck` message is the same as the format of `Pex` with the exception that message type in the header is different.

#### Transaction

Publish a transaction on the network

| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| N bytes | Block | `Vec<u8>` | SCALE-encoded transaction

#### Block

Publish a block on the network.

| Length | Description | Type | Comments |
|--------|-------------|------|----------|
| N bytes | Transaction | `Vec<u8>` | SCALE-encoded block
