// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use crate::error;
use async_trait::async_trait;
use parity_scale_codec::{Decode, Encode};

pub mod libp2p;
pub mod mock;

/// `NetworkService` provides the low-level network interface
/// that each network service provider must implement
#[async_trait]
pub trait NetworkService {
    /// Generic socket address that the underlying implementation uses
    ///
    /// # Examples
    /// For an implementation built on `TcpListener`, the address format is:
    ///     `0.0.0.0:8888`
    ///
    /// For an implementation built on libp2p, the address format is:
    ///     `/ip4/0.0.0.0/tcp/8888/p2p/<peer ID>`
    type Address;

    /// Generic socket object that the underlying implementation uses
    type Socket: SocketService + Send;

    /// Initialize the network service provider
    ///
    /// # Arguments
    /// `addr` - socket address for incoming P2P traffic
    async fn new(addr: Self::Address) -> error::Result<Self>
    where
        Self: Sized;

    /// Connect to a remote node
    ///
    /// If the connection succeeds, the socket object is returned
    /// which can be used to exchange messages with the remote peer
    ///
    /// # Arguments
    /// `addr` - socket address of the peer
    async fn connect(&mut self, addr: Self::Address) -> error::Result<Self::Socket>;

    /// Listen for an incoming connection on the P2P port
    ///
    /// When a peer connects, the underlying protocol implementation
    /// performs any initialization/handshaking it needs and then returns
    /// the initialized `Socket` object which the caller of `accept()` can
    /// use to perform the upper-level handshake and initializations.
    ///
    /// This returns a future that the caller must poll and after a connection
    /// with a peer has been established, the function returns. To start listening
    /// for another incoming connection on the P2P port, `accept()` must be called again.
    async fn accept(&mut self) -> error::Result<Self::Socket>;

    /// Publish data in a given gossip topic
    ///
    /// # Arguments
    /// `topic` - identifier for the topic
    /// `data` - generic data to send
    async fn publish<T>(&mut self, topic: &'static str, data: &T)
    where
        T: Sync + Send + Encode;

    /// Subscribe to a gossip topic
    ///
    /// # Arguments
    /// `topic` - identifier for the topic
    /// `tx` - channel for communication between the caller and the event loop
    async fn subscribe<T>(&mut self, topic: &'static str, tx: tokio::sync::mpsc::Sender<T>)
    where
        T: Sync + Send + Decode;
}

/// `SocketService` provides the low-level socket interface that
/// the `NetworkService::Socket` object must implement in order to do networking
#[async_trait]
pub trait SocketService {
    /// Send data to a remote peer we're connected to
    ///
    /// # Arguments
    /// `data` - generic data to send
    async fn send<T>(&mut self, data: &T) -> error::Result<()>
    where
        T: Sync + Send + Encode;

    /// Receive data from a remote peer we're connected to
    async fn recv<T>(&mut self) -> error::Result<T>
    where
        T: Decode;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::MockService;
    use crate::peer::Peer;
    use parity_scale_codec::{Decode, Encode};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[derive(Debug, Encode, Decode, PartialEq, Eq)]
    struct Transaction {
        hash: u64,
        value: u128,
    }

    #[tokio::test]
    async fn test_new() {
        let srv_ipv4 = MockService::new("127.0.0.1:5555".parse().unwrap()).await;
        assert!(srv_ipv4.is_ok());

        // address already in use
        let err = MockService::new("127.0.0.1:5555".parse().unwrap()).await;
        assert!(err.is_err());

        // bind to IPv6 localhost
        let srv_ipv6 = MockService::new("[::1]:5555".parse().unwrap()).await;
        assert!(srv_ipv6.is_ok());

        // address already in use
        let s_ipv6 = MockService::new("[::1]:5555".parse().unwrap()).await;
        assert!(s_ipv6.is_err());
    }

    #[tokio::test]
    async fn test_connect() {
        use tokio::net::TcpListener;

        // create `TcpListener`, spawn a task, and start accepting connections
        let addr: SocketAddr = "127.0.0.1:6666".parse().unwrap();
        let server = TcpListener::bind(addr).await.unwrap();

        tokio::spawn(async move {
            loop {
                if server.accept().await.is_ok() {}
            }
        });

        // create service that is used for testing `connect()`
        let srv = MockService::new("127.0.0.1:7777".parse().unwrap()).await;
        assert!(srv.is_ok());
        let mut srv = srv.unwrap();

        // try to connect to self, should fail
        let res = srv.connect("127.0.0.1:7777".parse().unwrap()).await;
        assert!(res.is_err());

        // try to connect to an address that (hopefully)
        // doesn't have a `TcpListener` running, should fail
        let res = srv.connect("127.0.0.1:1".parse().unwrap()).await;
        assert!(res.is_err());

        // try to connect to the `TcpListener` that was spawned above, should succeeed
        let res = srv.connect("127.0.0.1:6666".parse().unwrap()).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_accept() {
        // create service that is used for testing `accept()`
        let addr: SocketAddr = "[::1]:9999".parse().unwrap();
        let mut srv = MockService::new("[::1]:9999".parse().unwrap()).await.unwrap();

        let (acc, con) = tokio::join!(srv.accept(), TcpStream::connect(addr));
        assert!(acc.is_ok());
        assert!(con.is_ok());

        // TODO: is there any sensible way to make `accept()` fail?
    }

    #[tokio::test]
    async fn test_peer_send() {
        let addr: SocketAddr = "[::1]:11112".parse().unwrap();
        let mut server = MockService::new(addr).await.unwrap();
        let remote_fut = TcpStream::connect(addr);

        let (server_res, remote_res) = tokio::join!(server.accept(), remote_fut);
        assert!(server_res.is_ok());
        assert!(remote_res.is_ok());

        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let mut peer = Peer::<MockService>::new(1, server_res.unwrap(), peer_tx, rx);
        let mut socket = remote_res.unwrap();

        // try to send data that implements `Encode + Decode`
        // and verify that it was received correctly
        let tx = Transaction {
            hash: 12345u64,
            value: 67890u128,
        };

        let mut buf = vec![0u8; 256];
        let (server_res, peer_res) = tokio::join!(socket.read(&mut buf), peer.socket.send(&tx));

        assert!(peer_res.is_ok());
        assert!(server_res.is_ok());
        assert_eq!(Decode::decode(&mut &buf[..]), Ok(tx));
    }

    #[tokio::test]
    async fn test_peer_recv() {
        // create a `MockService`, connect to it with a `TcpStream` and exchange data
        let addr: SocketAddr = "[::1]:11113".parse().unwrap();
        let mut server = MockService::new(addr).await.unwrap();
        let remote_fut = TcpStream::connect(addr);

        let (server_res, remote_res) = tokio::join!(server.accept(), remote_fut);
        assert!(server_res.is_ok());
        assert!(remote_res.is_ok());

        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let mut peer = Peer::<MockService>::new(1, server_res.unwrap(), peer_tx, rx);
        let mut socket = remote_res.unwrap();

        // send data and decode it successfully
        let tx = Transaction {
            hash: 12345u64,
            value: 67890u128,
        };
        let encoded = tx.encode();

        let (socket_res, peer_res): (_, Result<Transaction, _>) =
            tokio::join!(socket.write(&encoded), peer.socket.recv());
        assert!(socket_res.is_ok());
        assert!(peer_res.is_ok());
        assert_eq!(peer_res.unwrap(), tx);
    }
}
