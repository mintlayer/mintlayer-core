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
#![allow(dead_code, unused_variables, unused_imports)]
use crate::error::{self, P2pError};
use crate::net::{NetworkService, SocketService};
use crate::peer::Peer;
use async_trait::async_trait;
use parity_scale_codec::{Decode, Encode};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// This file provides a mock implementation of the network service.
/// It implements the `NetworkService` trait on top of `tokio::net::TcpListener`

#[derive(Debug)]
pub struct MockService {
    /// Local node's TCP socket for listening to incoming connections
    socket: TcpListener,

    /// Address the local node has bind itself to
    addr: SocketAddr,
}

#[derive(Debug)]
pub struct MockSocket {
    socket: TcpStream,
}

impl MockSocket {
    pub fn new(socket: TcpStream) -> Self {
        MockSocket { socket }
    }
}

#[async_trait]
impl NetworkService for MockService {
    type Address = SocketAddr;
    type Socket = MockSocket;

    async fn new(addr: Self::Address) -> error::Result<Self> {
        Ok(Self {
            addr,
            socket: TcpListener::bind(addr).await?,
        })
    }

    async fn connect(&mut self, addr: Self::Address) -> error::Result<Self::Socket> {
        if self.addr == addr {
            return Err(P2pError::SocketError(ErrorKind::AddrNotAvailable));
        }

        Ok(MockSocket {
            socket: TcpStream::connect(addr).await?,
        })
    }

    async fn accept(&mut self) -> error::Result<Self::Socket> {
        // 0 is `TcpStream`, 1 is `SocketAddr`
        Ok(MockSocket {
            socket: self.socket.accept().await?.0,
        })
    }

    async fn publish<T>(&mut self, topic: &'static str, data: &T)
    where
        T: Sync + Send + Encode,
    {
        todo!();
    }

    async fn subscribe<T>(&mut self, topic: &'static str, tx: tokio::sync::mpsc::Sender<T>)
    where
        T: Send + Sync + Decode,
    {
        todo!();
    }
}

#[async_trait]
impl SocketService for MockSocket {
    async fn send<T>(&mut self, data: &T) -> error::Result<()>
    where
        T: Sync + Send + Encode,
    {
        match self.socket.write(&data.encode()).await? {
            0 => Err(P2pError::PeerDisconnected),
            _ => Ok(()),
        }
    }

    async fn recv<T>(&mut self) -> error::Result<T>
    where
        T: Decode,
    {
        let mut data = vec![0u8; 1024 * 1024];

        match self.socket.read(&mut data).await? {
            0 => Err(P2pError::PeerDisconnected),
            _ => Decode::decode(&mut &data[..]).map_err(|e| e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::MockService;
    use crate::peer::{Peer, PeerRole};
    use common::chain::config;
    use parity_scale_codec::{Decode, Encode};
    use std::net::SocketAddr;
    use std::sync::Arc;
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

        let config = Arc::new(config::create_mainnet());
        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let mut peer = Peer::<MockService>::new(
            1,
            PeerRole::Initiator,
            config.clone(),
            server_res.unwrap(),
            peer_tx,
            rx,
        );
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

        let config = Arc::new(config::create_mainnet());
        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let mut peer = Peer::<MockService>::new(
            1,
            PeerRole::Initiator,
            config.clone(),
            server_res.unwrap(),
            peer_tx,
            rx,
        );
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
