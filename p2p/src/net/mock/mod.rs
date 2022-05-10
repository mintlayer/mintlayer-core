// Copyright (c) 2021-2022 RBB S.r.l
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
use crate::{
    error::{self, P2pError},
    net::{
        ConnectivityEvent, ConnectivityService, NetworkService, PeerInfo, PubSubEvent,
        PubSubService, PubSubTopic, SocketService, ValidationResult,
    },
};
use async_trait::async_trait;
use futures::FutureExt;
use logging::log;
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};

pub mod backend;
pub mod types;

#[derive(Debug)]
pub enum MockStrategy {}

#[derive(Debug)]
pub struct MockService;

#[derive(Debug, Copy, Clone)]
pub struct MockMessageId(u64);

#[derive(Debug)]
pub struct MockSocket {
    socket: TcpStream,
}

impl MockSocket {
    pub fn new(socket: TcpStream) -> Self {
        MockSocket { socket }
    }
}

pub struct MockConnectivityHandle<T>
where
    T: NetworkService,
{
    /// Socket address of the network service provider
    addr: SocketAddr,

    /// TX channel for sending commands to mock backend
    cmd_tx: mpsc::Sender<types::Command>,

    /// RX channel for receiving connectivity events from mock backend
    conn_rx: mpsc::Receiver<types::ConnectivityEvent>,
    _marker: std::marker::PhantomData<T>,
}

pub struct MockPubSubHandle<T>
where
    T: NetworkService,
{
    /// TX channel for sending commands to mock backend
    cmd_tx: mpsc::Sender<types::Command>,

    /// RX channel for receiving floodsub events from mock backend
    _flood_rx: mpsc::Receiver<types::FloodsubEvent>,
    _marker: std::marker::PhantomData<T>,
}

#[async_trait]
impl NetworkService for MockService {
    type Address = SocketAddr;
    type Socket = MockSocket;
    type Strategy = MockStrategy;
    type PeerId = SocketAddr;
    type ProtocolId = String;
    type MessageId = MockMessageId;
    type ConnectivityHandle = MockConnectivityHandle<Self>;
    type PubSubHandle = MockPubSubHandle<Self>;

    async fn start(
        addr: Self::Address,
        _strategies: &[Self::Strategy],
        _topics: &[PubSubTopic],
        _config: Arc<common::chain::ChainConfig>,
        timeout: std::time::Duration,
    ) -> error::Result<(Self::ConnectivityHandle, Self::PubSubHandle)> {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (conn_tx, conn_rx) = mpsc::channel(16);
        let (flood_tx, _flood_rx) = mpsc::channel(16);
        let socket = TcpListener::bind(addr).await?;

        tokio::spawn(async move {
            let mut mock = backend::Backend::new(addr, socket, cmd_rx, conn_tx, flood_tx, timeout);
            let _ = mock.run().await;
        });

        Ok((
            Self::ConnectivityHandle {
                addr,
                cmd_tx: cmd_tx.clone(),
                conn_rx,
                _marker: Default::default(),
            },
            Self::PubSubHandle {
                cmd_tx,
                _flood_rx,
                _marker: Default::default(),
            },
        ))
    }
}

#[async_trait]
impl<T> ConnectivityService<T> for MockConnectivityHandle<T>
where
    T: NetworkService<Address = SocketAddr, PeerId = SocketAddr, Socket = MockSocket> + Send,
{
    async fn connect(&mut self, addr: T::Address) -> error::Result<PeerInfo<T>> {
        log::debug!("try to establish outbound connection, address {:?}", addr);

        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::Connect { addr, response: tx }).await?;

        let socket = rx
            .await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e)?; // command failure

        todo!();
        // Ok(
        // PeerInfo {
        // id: addr,
        // net: chain::config::ChainType,
        // version: primitives::version::SemVer,
        // agent: Option<String>,
        // protocols: Vec<String>,
        // }
        // )
    }

    fn local_addr(&self) -> &T::Address {
        &self.addr
    }

    async fn poll_next(&mut self) -> error::Result<ConnectivityEvent<T>> {
        match self.conn_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            types::ConnectivityEvent::IncomingConnection { peer_id, socket } => {
                Ok(ConnectivityEvent::IncomingConnection {
                    peer_id,
                    socket: MockSocket { socket },
                })
            }
        }
    }

    async fn register_peer(&mut self, peer: T::PeerId) -> error::Result<()> {
        Ok(())
    }

    async fn unregister_peer(&mut self, peer: T::PeerId) -> error::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl<T> PubSubService<T> for MockPubSubHandle<T>
where
    T: NetworkService<PeerId = SocketAddr> + Send,
{
    async fn publish<U>(&mut self, topic: PubSubTopic, data: &U) -> error::Result<()>
    where
        U: Sync + Send + Encode,
    {
        todo!();
    }

    async fn report_validation_result(
        &mut self,
        source: T::PeerId,
        msg_id: T::MessageId,
        result: ValidationResult,
    ) -> error::Result<()> {
        todo!();
    }

    async fn poll_next(&mut self) -> error::Result<PubSubEvent<T>> {
        todo!();
    }
}

#[async_trait]
impl SocketService for MockSocket {
    async fn send<T>(&mut self, data: &T) -> error::Result<()>
    where
        T: Sync + Send + Encode,
    {
        let encoded = data.encode();

        log::trace!("try to send message, {} bytes", encoded.len());

        match self.socket.write(&encoded).await? {
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
    use crate::net::ConnectivityEvent;
    use crate::peer::{Peer, PeerRole};
    use common::chain::config;
    use parity_scale_codec::{Decode, Encode};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket};

    #[derive(Debug, Encode, Decode, PartialEq, Eq)]
    struct Transaction {
        hash: u64,
        value: u128,
    }

    #[tokio::test]
    async fn test_new() {
        let srv_ipv4 = MockService::start(
            "127.0.0.1:5555".parse().unwrap(),
            &[],
            &[],
            std::time::Duration::from_secs(10),
        )
        .await;
        assert!(srv_ipv4.is_ok());

        // address already in use
        let err = MockService::start(
            "127.0.0.1:5555".parse().unwrap(),
            &[],
            &[],
            std::time::Duration::from_secs(10),
        )
        .await;
        assert!(err.is_err());

        // bind to IPv6 localhost
        let srv_ipv6 = MockService::start(
            "[::1]:5555".parse().unwrap(),
            &[],
            &[],
            std::time::Duration::from_secs(10),
        )
        .await;
        assert!(srv_ipv6.is_ok());

        // address already in use
        let s_ipv6 = MockService::start(
            "[::1]:5555".parse().unwrap(),
            &[],
            &[],
            std::time::Duration::from_secs(10),
        )
        .await;
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
        let srv = MockService::start(
            "127.0.0.1:7777".parse().unwrap(),
            &[],
            &[],
            std::time::Duration::from_secs(10),
        )
        .await;
        assert!(srv.is_ok());
        let (mut srv, _) = srv.unwrap();

        // try to connect to self, should fail
        let res = srv.connect("127.0.0.1:7777".parse().unwrap()).await;
        println!("{:?}", res);
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
        let (mut srv, _) = MockService::start(
            "[::1]:9999".parse().unwrap(),
            &[],
            &[],
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

        let (acc, con) = tokio::join!(srv.poll_next(), TcpStream::connect(addr));
        assert!(acc.is_ok());
        assert!(con.is_ok());
        let acc: ConnectivityEvent<MockService> = acc.unwrap();

        // TODO: is there any sensible way to make `accept()` fail?
    }

    #[tokio::test]
    async fn test_peer_send() {
        let addr: SocketAddr = "[::1]:11112".parse().unwrap();
        let (mut server, _) =
            MockService::start(addr, &[], &[], std::time::Duration::from_secs(10))
                .await
                .unwrap();
        let remote_fut = TcpStream::connect(addr);

        let (server_res, remote_res) = tokio::join!(server.poll_next(), remote_fut);
        assert!(server_res.is_ok());
        assert!(remote_res.is_ok());

        let server_res: ConnectivityEvent<MockService> = server_res.unwrap();
        let server_res = match server_res {
            ConnectivityEvent::IncomingConnection { peer_id: _, socket } => socket,
            _ => panic!("invalid event received, expected incoming connection"),
        };

        let config = Arc::new(config::create_mainnet());
        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (sync_tx, _sync_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let mut peer = Peer::<MockService>::new(
            test_utils::get_mock_id(),
            PeerRole::Outbound,
            config.clone(),
            server_res,
            peer_tx,
            sync_tx,
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
        let (mut server, _) =
            MockService::start(addr, &[], &[], std::time::Duration::from_secs(10))
                .await
                .unwrap();
        let remote_fut = TcpStream::connect(addr);

        let (server_res, remote_res) = tokio::join!(server.poll_next(), remote_fut);
        assert!(server_res.is_ok());
        assert!(remote_res.is_ok());

        let server_res: ConnectivityEvent<MockService> = server_res.unwrap();
        let server_res = match server_res {
            ConnectivityEvent::IncomingConnection { peer_id: _, socket } => socket,
            _ => panic!("invalid event received, expected incoming connection"),
        };

        let config = Arc::new(config::create_mainnet());
        let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
        let (sync_tx, _sync_rx) = tokio::sync::mpsc::channel(1);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let mut peer = Peer::<MockService>::new(
            test_utils::get_mock_id(),
            PeerRole::Outbound,
            config.clone(),
            server_res,
            peer_tx,
            sync_tx,
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

    impl PartialEq for MockSocket {
        fn eq(&self, _other: &MockSocket) -> bool {
            true
        }
    }

    // try to connect to a service that is not listening with a small timeout
    // and verify that the connection fails
    // TODO: verify on windows/mac
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_connect_with_timeout() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut service, _) =
            MockService::start(addr, &[], &[], std::time::Duration::from_secs(2))
                .await
                .unwrap();

        let port = portpicker::pick_unused_port().unwrap();
        let conn_addr: SocketAddr = format!("[::1]:{}", port).parse().unwrap();
        let start = std::time::SystemTime::now();
        assert_eq!(
            service.connect(conn_addr).await,
            Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
        );
        assert_eq!(
            std::time::SystemTime::now().duration_since(start).unwrap().as_secs(),
            0
        );

        // try to connect to a non-routable host
        let conn_addr: SocketAddr = "10.255.255.255:8888".parse().unwrap();
        let start = std::time::SystemTime::now();
        assert_eq!(
            service.connect(conn_addr).await,
            Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
        );
        assert!(std::time::SystemTime::now().duration_since(start).unwrap().as_secs() >= 2);
    }
}
