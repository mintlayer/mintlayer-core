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
    error::{self, P2pError, ProtocolError},
    message,
    net::{
        self,
        mock::types::{MockPeerId, MockPeerInfo, MockRequestId},
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
use utils::ensure;

pub mod backend;
pub mod peer;
pub mod socket;
pub mod types;

// TODO: create common protocol type defined in net/mod.rs!
impl<T> TryInto<net::PeerInfo<T>> for MockPeerInfo
where
    T: NetworkService<PeerId = MockPeerId, ProtocolId = String>,
{
    type Error = P2pError;

    fn try_into(self) -> Result<net::PeerInfo<T>, Self::Error> {
        Ok(net::PeerInfo {
            peer_id: self.peer_id,
            net: self.net,
            version: self.version,
            agent: None,
            protocols: self.protocols.iter().map(|proto| proto.name()).cloned().collect::<Vec<_>>(),
        })
    }
}

#[derive(Debug)]
pub enum MockDiscoveryStrategy {}

#[derive(Debug)]
pub struct MockService;

#[derive(Debug, Copy, Clone)]
pub struct MockMessageId(u64);

pub struct MockConnectivityHandle<T>
where
    T: NetworkService,
{
    /// Socket address of the network service provider
    addr: SocketAddr,

    /// Unique peer ID of the local node
    peer_id: types::MockPeerId,

    /// Timeout for operations
    timeout: std::time::Duration,

    /// TX channel for sending commands to mock backend
    cmd_tx: mpsc::Sender<types::Command>,

    /// RX channel for receiving connectivity events from mock backend
    conn_rx: mpsc::Receiver<types::ConnectivityEvent>,

    _marker: std::marker::PhantomData<fn() -> T>,
}

pub struct MockPubSubHandle<T>
where
    T: NetworkService,
{
    /// TX channel for sending commands to mock backend
    cmd_tx: mpsc::Sender<types::Command>,

    /// RX channel for receiving floodsub events from mock backend
    _flood_rx: mpsc::Receiver<types::FloodsubEvent>,

    _marker: std::marker::PhantomData<fn() -> T>,
}

pub struct MockSyncingHandle<T>
where
    T: NetworkService,
{
    /// TX channel for sending commands to mock backend
    cmd_tx: mpsc::Sender<types::Command>,

    sync_rx: mpsc::Receiver<types::SyncingEvent>,
    _marker: std::marker::PhantomData<fn() -> T>,
}

#[async_trait]
impl NetworkService for MockService {
    type Address = SocketAddr;
    type DiscoveryStrategy = MockDiscoveryStrategy;
    type PeerId = types::MockPeerId;
    type ProtocolId = String;
    type RequestId = MockRequestId;
    type MessageId = MockMessageId;
    type ConnectivityHandle = MockConnectivityHandle<Self>;
    type PubSubHandle = MockPubSubHandle<Self>;
    type SyncingHandle = MockSyncingHandle<Self>;

    async fn start(
        addr: Self::Address,
        _strategies: &[Self::DiscoveryStrategy],
        _topics: &[PubSubTopic],
        config: Arc<common::chain::ChainConfig>,
        timeout: std::time::Duration,
    ) -> error::Result<(
        Self::ConnectivityHandle,
        Self::PubSubHandle,
        Self::SyncingHandle,
    )> {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (conn_tx, conn_rx) = mpsc::channel(16);
        let (flood_tx, _flood_rx) = mpsc::channel(16);
        let (sync_tx, sync_rx) = mpsc::channel(16);
        let socket = TcpListener::bind(addr).await?;

        tokio::spawn(async move {
            if let Err(err) = backend::Backend::new(
                addr,
                socket,
                Arc::clone(&config),
                cmd_rx,
                conn_tx,
                flood_tx,
                sync_tx,
                timeout,
            )
            .run()
            .await
            {
                log::error!("mock backend failed: {:?}", err);
            }
        });

        Ok((
            Self::ConnectivityHandle {
                addr,
                cmd_tx: cmd_tx.clone(),
                conn_rx,
                timeout,
                peer_id: types::MockPeerId::from_socket_address(&addr),
                _marker: Default::default(),
            },
            Self::PubSubHandle {
                cmd_tx: cmd_tx.clone(),
                _flood_rx,
                _marker: Default::default(),
            },
            Self::SyncingHandle {
                cmd_tx,
                sync_rx,
                _marker: Default::default(),
            },
        ))
    }
}

#[async_trait]
impl<T> ConnectivityService<T> for MockConnectivityHandle<T>
where
    T: NetworkService<Address = SocketAddr, PeerId = types::MockPeerId> + Send,
    MockPeerInfo: TryInto<net::PeerInfo<T>, Error = P2pError>,
{
    async fn connect(&mut self, addr: T::Address) -> error::Result<PeerInfo<T>> {
        log::debug!("try to establish outbound connection, address {:?}", addr);

        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::Connect { addr, response: tx }).await?;

        let peer_info = rx
            .await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e)?; // command failure

        Ok(peer_info.try_into()?)
    }

    async fn disconnect(&mut self, peer_id: T::PeerId) -> error::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::Disconnect {
                peer_id,
                response: tx,
            })
            .await?;

        rx.await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e)
    }

    fn local_addr(&self) -> &T::Address {
        &self.addr
    }

    fn peer_id(&self) -> &T::PeerId {
        &self.peer_id
    }

    async fn poll_next(&mut self) -> error::Result<ConnectivityEvent<T>> {
        match self.conn_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            types::ConnectivityEvent::IncomingConnection { addr, peer_info } => {
                Ok(ConnectivityEvent::IncomingConnection {
                    addr,
                    peer_info: peer_info.try_into()?,
                })
            }
            types::ConnectivityEvent::Disconnected { peer_id } => {
                Ok(ConnectivityEvent::Disconnected { peer_id })
            }
        }
    }
}

#[async_trait]
impl<T> PubSubService<T> for MockPubSubHandle<T>
where
    T: NetworkService<PeerId = types::MockPeerId> + Send,
{
    async fn publish(&mut self, message: message::Message) -> error::Result<()> {
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
    T: NetworkService<PeerId = types::MockPeerId, RequestId = MockRequestId> + Send,
{
    async fn send_request(
        &mut self,
        peer_id: T::PeerId,
        message: message::Message,
    ) -> error::Result<T::RequestId> {
        ensure!(
            std::matches!(
                message.msg,
                message::MessageType::Syncing(message::SyncingMessage::Request(_))
            ),
            P2pError::ProtocolError(ProtocolError::InvalidMessage)
        );

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::SendRequest {
                peer_id,
                message,
                response: tx,
            })
            .await?;

        rx.await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e) // command failure
    }

    async fn send_response(
        &mut self,
        request_id: T::RequestId,
        message: message::Message,
    ) -> error::Result<()> {
        ensure!(
            std::matches!(
                message.msg,
                message::MessageType::Syncing(message::SyncingMessage::Response(_))
            ),
            P2pError::ProtocolError(ProtocolError::InvalidMessage)
        );

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::SendResponse {
                request_id,
                message,
                response: tx,
            })
            .await?;

        rx.await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e) // command failure
    }

    async fn poll_next(&mut self) -> error::Result<SyncingMessage<T>> {
        match self.sync_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            types::SyncingEvent::Request {
                peer_id,
                request_id,
                request,
            } => Ok(net::SyncingMessage::Request {
                peer_id,
                request_id,
                request,
            }),
            types::SyncingEvent::Response {
                peer_id,
                request_id,
                response,
            } => Ok(net::SyncingMessage::Response {
                peer_id,
                request_id,
                response,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_to_remote() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let (mut conn1, _, _) = MockService::start(
            test_utils::make_address("[::1]:"),
            &[],
            &[],
            Arc::clone(&config),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

        let (conn2, _, _) = MockService::start(
            test_utils::make_address("[::1]:"),
            &[],
            &[],
            config,
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

        assert_eq!(
            conn1.connect(*conn2.local_addr()).await,
            Ok(net::PeerInfo {
                peer_id: *conn2.peer_id(),
                net: common::chain::config::ChainType::Mainnet,
                version: common::primitives::version::SemVer::new(0, 1, 0),
                agent: None,
                protocols: vec!["floodsub".to_string(), "ping".to_string()],
            })
        );
    }

    #[tokio::test]
    async fn accept_incoming() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let (mut conn1, _, _) = MockService::start(
            test_utils::make_address("[::1]:"),
            &[],
            &[],
            Arc::clone(&config),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

        let (mut conn2, _, _) = MockService::start(
            test_utils::make_address("[::1]:"),
            &[],
            &[],
            config,
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

        let (res1, res2) = tokio::join!(conn1.connect(*conn2.local_addr()), conn2.poll_next());
        let conn1_id = match res2.unwrap() {
            ConnectivityEvent::IncomingConnection { peer_info, .. } => {
                assert_eq!(peer_info.net, common::chain::config::ChainType::Mainnet);
                assert_eq!(
                    peer_info.version,
                    common::primitives::version::SemVer::new(0, 1, 0),
                );
                assert_eq!(peer_info.agent, None);
                assert_eq!(
                    peer_info.protocols,
                    vec!["floodsub".to_string(), "ping".to_string()],
                );
            }
            _ => panic!("invalid event received, expected incoming connection"),
        };
    }

    #[tokio::test]
    async fn disconnect() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let timeout = std::time::Duration::from_secs(10);

        let addr = test_utils::make_address("[::1]:");
        let (mut conn1, _, _) =
            MockService::start(addr, &[], &[], Arc::clone(&config), timeout).await.unwrap();

        let addr = test_utils::make_address("[::1]:");
        let (mut conn2, _, _) = MockService::start(addr, &[], &[], config, timeout).await.unwrap();

        let (res1, res2) = tokio::join!(conn1.connect(*conn2.local_addr()), conn2.poll_next());
        let peer_id = res1.unwrap().peer_id;

        assert_eq!(conn1.disconnect(peer_id).await, Ok(()));
    }

    #[tokio::test]
    async fn test_request_response() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let timeout = std::time::Duration::from_secs(10);

        let addr = test_utils::make_address("[::1]:");
        let (mut conn1, _, mut sync1) =
            MockService::start(addr, &[], &[], Arc::clone(&config), timeout).await.unwrap();

        let addr = test_utils::make_address("[::1]:");
        let (mut conn2, _, mut sync2) =
            MockService::start(addr, &[], &[], config, timeout).await.unwrap();

        let (res1, res2) = tokio::join!(conn1.connect(*conn2.local_addr()), conn2.poll_next());
        let peer_id = res1.unwrap().peer_id;
        let request = message::Message {
            magic: [1, 2, 3, 4],
            msg: message::MessageType::Syncing(message::SyncingMessage::Request(
                message::SyncingRequest::GetHeaders { locator: vec![] },
            )),
        };
        sync1.send_request(peer_id, request.clone()).await.unwrap();

        let request_id = if let Ok(net::SyncingMessage::Request {
            request_id,
            request: recv_req,
            ..
        }) = sync2.poll_next().await
        {
            assert_eq!(recv_req, request);
            request_id
        } else {
            panic!("invalid message received");
        };

        let response = message::Message {
            magic: [1, 2, 3, 4],
            msg: message::MessageType::Syncing(message::SyncingMessage::Response(
                message::SyncingResponse::Headers { headers: vec![] },
            )),
        };
        sync2.send_response(request_id, response.clone()).await.unwrap();

        if let Ok(net::SyncingMessage::Response {
            request_id,
            response: recv_resp,
            ..
        }) = sync1.poll_next().await
        {
            assert_eq!(recv_resp, response);
        } else {
            panic!("invalid message received");
        }
    }
}
