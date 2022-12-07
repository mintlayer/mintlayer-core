use crate::net::mock::transport::TransportSocket;

use libp2p::Multiaddr;
use std::net::SocketAddr;

/// An interface for creating the address.
///
/// This abstraction layer is needed to uniformly create an address in the tests for different
/// mocks transport implementations.
pub trait MakeTestAddress {
    /// A transport type.
    type Transport;

    /// An address type.
    type Address: Clone + Eq + std::fmt::Debug + std::hash::Hash + Send + Sync + ToString;

    /// Creates new transport instance, generating new keys if needed.
    fn make_transport() -> Self::Transport;

    /// Creates a new unused address.
    ///
    /// This should work similar to requesting a port of number 0 when opening a TCP connection.
    fn make_address() -> Self::Address;
}

pub struct MakeP2pAddress {}

impl MakeTestAddress for MakeP2pAddress {
    type Transport = crate::net::libp2p::Libp2pTransport;

    type Address = Multiaddr;

    fn make_transport() -> Self::Transport {
        let p2p_config = Default::default();
        crate::net::libp2p::make_transport(&p2p_config)
    }

    fn make_address() -> Self::Address {
        "/ip6/::1/tcp/0".parse().unwrap()
    }
}

pub struct MakeTcpAddress {}

impl MakeTestAddress for MakeTcpAddress {
    type Transport = crate::net::mock::transport::TcpTransportSocket;

    type Address = SocketAddr;

    fn make_transport() -> Self::Transport {
        crate::net::mock::transport::TcpTransportSocket::new()
    }

    fn make_address() -> Self::Address {
        "[::1]:0".parse().unwrap()
    }
}

pub struct MakeChannelAddress {}

impl MakeTestAddress for MakeChannelAddress {
    type Transport = crate::net::mock::transport::MockChannelTransport;

    type Address = u64;

    fn make_transport() -> Self::Transport {
        crate::net::mock::transport::MockChannelTransport::new()
    }

    fn make_address() -> Self::Address {
        0
    }
}

pub struct MakeNoiseAddress {}

impl MakeTestAddress for MakeNoiseAddress {
    type Transport = crate::net::mock::transport::NoiseTcpTransport;

    type Address = SocketAddr;

    fn make_transport() -> Self::Transport {
        crate::net::mock::transport::NoiseTcpTransport::new()
    }

    fn make_address() -> Self::Address {
        "[::1]:0".parse().unwrap()
    }
}
