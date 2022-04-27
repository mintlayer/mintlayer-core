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
    message,
    net::{
        ConnectivityEvent, ConnectivityService, NetworkService, PeerInfo, PubSubEvent,
        PubSubService, PubSubTopic, SyncingMessage, SyncingService, ValidationResult,
    },
};
use async_trait::async_trait;
use futures::FutureExt;
use logging::log;
use serialization::{Decode, Encode};
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

#[derive(Debug, Copy, Clone)]
pub struct MockRequestId(u64);

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

pub struct MockSyncingHandle<T>
where
    T: NetworkService,
{
    /// TX channel for sending commands to mock backend
    cmd_tx: mpsc::Sender<types::Command>,

    _sync_rx: mpsc::Receiver<types::SyncingEvent>,
    _marker: std::marker::PhantomData<T>,
}

#[async_trait]
impl NetworkService for MockService {
    type Address = SocketAddr;
    type Strategy = MockStrategy;
    type PeerId = SocketAddr;
    type ProtocolId = String;
    type RequestId = MockRequestId;
    type MessageId = MockMessageId;
    type ConnectivityHandle = MockConnectivityHandle<Self>;
    type PubSubHandle = MockPubSubHandle<Self>;
    type SyncingHandle = MockSyncingHandle<Self>;

    async fn start(
        addr: Self::Address,
        _strategies: &[Self::Strategy],
        _topics: &[PubSubTopic],
        _config: Arc<common::chain::ChainConfig>,
        timeout: std::time::Duration,
    ) -> error::Result<(
        Self::ConnectivityHandle,
        Self::PubSubHandle,
        Self::SyncingHandle,
    )> {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (conn_tx, conn_rx) = mpsc::channel(16);
        let (flood_tx, _flood_rx) = mpsc::channel(16);
        let (sync_tx, _sync_rx) = mpsc::channel(16);
        let socket = TcpListener::bind(addr).await?;

        tokio::spawn(async move {
            let mut mock =
                backend::Backend::new(addr, socket, cmd_rx, conn_tx, flood_tx, sync_tx, timeout);
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
                cmd_tx: cmd_tx.clone(),
                _flood_rx,
                _marker: Default::default(),
            },
            Self::SyncingHandle {
                cmd_tx,
                _sync_rx,
                _marker: Default::default(),
            },
        ))
    }
}

#[async_trait]
impl<T> ConnectivityService<T> for MockConnectivityHandle<T>
where
    T: NetworkService<Address = SocketAddr, PeerId = SocketAddr> + Send,
{
    async fn connect(&mut self, addr: T::Address) -> error::Result<PeerInfo<T>> {
        log::debug!("try to establish outbound connection, address {:?}", addr);

        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::Connect { addr, response: tx }).await?;

        let _ = rx
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

    fn peer_id(&self) -> &T::PeerId {
        &self.addr
    }

    async fn poll_next(&mut self) -> error::Result<ConnectivityEvent<T>> {
        todo!();
        // match self.conn_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
        //     types::ConnectivityEvent::IncomingConnection { peer_id, socket } => {
        //         Ok(ConnectivityEvent::IncomingConnection {
        //             peer_id,
        //             socket: MockSocket { socket },
        //         })
        //     }
        // }
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
impl<T> SyncingService<T> for MockSyncingHandle<T>
where
    T: NetworkService<PeerId = SocketAddr, RequestId = MockRequestId> + Send,
{
    async fn send_request(
        &mut self,
        peer_id: T::PeerId,
        message: message::Message,
    ) -> error::Result<T::RequestId> {
        todo!();
    }

    async fn send_response(
        &mut self,
        request_id: T::RequestId,
        message: message::Message,
    ) -> error::Result<()> {
        todo!();
    }

    async fn poll_next(&mut self) -> error::Result<SyncingMessage<T>> {
        todo!();
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::MockService;
    use crate::net::ConnectivityEvent;
    use crate::peer::{Peer, PeerRole};
    use common::chain::config;
    use serialization::{Decode, Encode};
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
}
*/
