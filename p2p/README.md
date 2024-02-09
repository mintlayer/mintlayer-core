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

In addition to maintaining each connection individually, the Mintlayer node will also maintain the overall set of connections by accepting incoming connections/establishing new outbound connections to maintain the total amount of connections at the specified number. This means that the event loop of the node will reject new connections if the number of active connections is higher than it should be; if the number of connections is lower than the lower bound for number of active connections, the node will try establishing new connections with peers it has learned from previous connections.

### Message exchange

#### Hello

`Hello` is used by the connecting peer to initiate a handshake and to verify whether the remote peer running compatible software.

#### HelloAck

`HelloAck` is used to conclude the handshake with the peer that initiated it, if they are running compatible software and are in the same network.

#### PingRequest

Check if the peer is still alive

#### PingResponse

Respond to an aliveness check
