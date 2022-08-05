// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod backend;
pub mod peer;
pub mod request_manager;
pub mod socket;
pub mod types;

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};

use logging::log;

use crate::{
    config,
    error::P2pError,
    message,
    net::{
        self,
        types::{ConnectivityEvent, PubSubEvent, PubSubTopic, SyncingEvent, ValidationResult},
        ConnectivityService, NetworkingService, PubSubService, SyncingMessagingService,
    },
};

#[derive(Debug)]
pub struct MockService;

#[derive(Debug, Copy, Clone)]
pub struct MockMessageId(u64);

pub struct MockConnectivityHandle<T: NetworkingService> {
    /// Socket address of the network service provider
    local_addr: SocketAddr,

    /// Peer ID of local node
    peer_id: types::MockPeerId,

    /// TX channel for sending commands to mock backend
    cmd_tx: mpsc::Sender<types::Command>,

    /// RX channel for receiving connectivity events from mock backend
    conn_rx: mpsc::Receiver<types::ConnectivityEvent>,
    _marker: std::marker::PhantomData<fn() -> T>,
}

pub struct MockPubSubHandle<T>
where
    T: NetworkingService,
{
    /// TX channel for sending commands to mock backend
    _cmd_tx: mpsc::Sender<types::Command>,

    /// RX channel for receiving pubsub events from mock backend
    _pubsub_rx: mpsc::Receiver<types::PubSubEvent>,
    _marker: std::marker::PhantomData<fn() -> T>,
}

pub struct MockSyncingMessagingHandle<T: NetworkingService> {
    /// TX channel for sending commands to mock backend
    cmd_tx: mpsc::Sender<types::Command>,

    /// RX channel for receiving syncing events
    sync_rx: mpsc::Receiver<types::SyncingEvent>,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T> TryInto<net::types::PeerInfo<T>> for types::MockPeerInfo
where
    T: NetworkingService<PeerId = types::MockPeerId>,
{
    type Error = P2pError;

    fn try_into(self) -> Result<net::types::PeerInfo<T>, Self::Error> {
        Ok(net::types::PeerInfo {
            peer_id: self.peer_id,
            magic_bytes: self.network,
            version: self.version,
            agent: None,
            protocols: self.protocols.into_iter().collect(),
        })
    }
}

#[async_trait]
impl NetworkingService for MockService {
    type Address = SocketAddr;
    type PeerId = types::MockPeerId;
    type SyncingPeerRequestId = types::MockRequestId;
    type PubSubMessageId = MockMessageId;
    type ConnectivityHandle = MockConnectivityHandle<Self>;
    type PubSubHandle = MockPubSubHandle<Self>;
    type SyncingMessagingHandle = MockSyncingMessagingHandle<Self>;

    async fn start(
        addr: Self::Address,
        _config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<config::P2pConfig>,
    ) -> crate::Result<(
        Self::ConnectivityHandle,
        Self::PubSubHandle,
        Self::SyncingMessagingHandle,
    )> {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (conn_tx, conn_rx) = mpsc::channel(16);
        let (pubsub_tx, _pubsub_rx) = mpsc::channel(16);
        let (sync_tx, sync_rx) = mpsc::channel(16);
        let socket = TcpListener::bind(addr).await?;
        let local_addr = socket.local_addr().expect("to have bind address available");

        tokio::spawn(async move {
            let mut backend = backend::Backend::new(
                local_addr,
                socket,
                Arc::clone(&_config),
                cmd_rx,
                conn_tx,
                pubsub_tx,
                sync_tx,
                std::time::Duration::from_secs(p2p_config.outbound_connection_timeout),
            );

            if let Err(err) = backend.run().await {
                log::error!("failed to run backend: {err}");
            }
        });

        Ok((
            Self::ConnectivityHandle {
                local_addr,
                cmd_tx: cmd_tx.clone(),
                peer_id: types::MockPeerId::from_socket_address(&local_addr),
                conn_rx,
                _marker: Default::default(),
            },
            Self::PubSubHandle {
                _cmd_tx: cmd_tx.clone(),
                _pubsub_rx,
                _marker: Default::default(),
            },
            Self::SyncingMessagingHandle {
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
    T: NetworkingService<Address = SocketAddr, PeerId = types::MockPeerId> + Send,
    types::MockPeerInfo: TryInto<net::types::PeerInfo<T>, Error = P2pError>,
{
    async fn connect(&mut self, address: T::Address) -> crate::Result<()> {
        log::debug!(
            "try to establish outbound connection, address {:?}",
            address
        );

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::Connect {
                address,
                response: tx,
            })
            .await?;

        rx.await?
    }

    async fn disconnect(&mut self, peer_id: T::PeerId) -> crate::Result<()> {
        log::debug!("close connection with remote, {peer_id}");

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::Disconnect {
                peer_id,
                response: tx,
            })
            .await?;

        rx.await?
    }

    async fn local_addr(&self) -> crate::Result<Option<T::Address>> {
        Ok(Some(self.local_addr))
    }

    fn peer_id(&self) -> &T::PeerId {
        &self.peer_id
    }

    async fn ban_peer(&mut self, peer_id: T::PeerId) -> crate::Result<()> {
        log::debug!("ban remote peer, peer id {peer_id}");

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::BanPeer {
                peer_id,
                response: tx,
            })
            .await?;

        rx.await?
    }

    async fn poll_next(&mut self) -> crate::Result<ConnectivityEvent<T>> {
        match self.conn_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            types::ConnectivityEvent::OutboundAccepted { address, peer_info } => {
                Ok(ConnectivityEvent::OutboundAccepted {
                    address,
                    peer_info: peer_info.try_into()?,
                })
            }
            types::ConnectivityEvent::InboundAccepted { address, peer_info } => {
                Ok(ConnectivityEvent::InboundAccepted {
                    address,
                    peer_info: peer_info.try_into()?,
                })
            }
            types::ConnectivityEvent::ConnectionError { address, error } => {
                Ok(ConnectivityEvent::ConnectionError { address, error })
            }
            types::ConnectivityEvent::ConnectionClosed { peer_id } => {
                Ok(ConnectivityEvent::ConnectionClosed { peer_id })
            }
        }
    }
}

#[async_trait]
impl<T> PubSubService<T> for MockPubSubHandle<T>
where
    T: NetworkingService<PeerId = types::MockPeerId> + Send,
{
    async fn publish(&mut self, _announcement: message::Announcement) -> crate::Result<()> {
        todo!();
    }

    async fn report_validation_result(
        &mut self,
        _source: T::PeerId,
        _msg_id: T::PubSubMessageId,
        _result: ValidationResult,
    ) -> crate::Result<()> {
        todo!();
    }

    async fn subscribe(&mut self, _topics: &[PubSubTopic]) -> crate::Result<()> {
        todo!();
    }

    async fn poll_next(&mut self) -> crate::Result<PubSubEvent<T>> {
        todo!();
    }
}

#[async_trait]
impl<T> SyncingMessagingService<T> for MockSyncingMessagingHandle<T>
where
    T: NetworkingService<PeerId = types::MockPeerId, SyncingPeerRequestId = types::MockRequestId>
        + Send,
{
    async fn send_request(
        &mut self,
        peer_id: T::PeerId,
        request: message::Request,
    ) -> crate::Result<T::SyncingPeerRequestId> {
        let (tx, rx) = oneshot::channel();

        self.cmd_tx
            .send(types::Command::SendRequest {
                peer_id,
                message: request,
                response: tx,
            })
            .await?;
        rx.await?
    }

    async fn send_response(
        &mut self,
        request_id: T::SyncingPeerRequestId,
        response: message::Response,
    ) -> crate::Result<()> {
        let (tx, rx) = oneshot::channel();

        self.cmd_tx
            .send(types::Command::SendResponse {
                request_id,
                message: response,
                response: tx,
            })
            .await?;
        rx.await?
    }

    async fn poll_next(&mut self) -> crate::Result<SyncingEvent<T>> {
        match self.sync_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            types::SyncingEvent::Request {
                peer_id,
                request_id,
                request,
            } => Ok(net::types::SyncingEvent::Request {
                peer_id,
                request_id,
                request,
            }),
            types::SyncingEvent::Response {
                peer_id,
                request_id,
                response,
            } => Ok(net::types::SyncingEvent::Response {
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
    use crate::net::types::{Protocol, ProtocolType};
    use common::primitives::semver::SemVer;

    #[tokio::test]
    async fn connect_to_remote() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config: Arc<config::P2pConfig> = Arc::new(Default::default());

        let (mut conn1, _, _) = MockService::start(
            p2p_test_utils::make_mock_addr(),
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        let (conn2, _, _) = MockService::start(
            p2p_test_utils::make_mock_addr(),
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        let addr = conn2.local_addr().await.unwrap().unwrap();
        assert_eq!(conn1.connect(addr).await, Ok(()));

        if let Ok(net::types::ConnectivityEvent::OutboundAccepted { address, peer_info }) =
            conn1.poll_next().await
        {
            assert_eq!(address, conn2.local_addr().await.unwrap().unwrap());
            assert_eq!(
                peer_info,
                net::types::PeerInfo {
                    peer_id: *conn2.peer_id(),
                    magic_bytes: *config.magic_bytes(),
                    version: common::primitives::semver::SemVer::new(0, 1, 0),
                    agent: None,
                    protocols: [
                        Protocol::new(ProtocolType::PubSub, SemVer::new(0, 1, 0)),
                        Protocol::new(ProtocolType::Ping, SemVer::new(0, 1, 0)),
                    ]
                    .into_iter()
                    .collect(),
                }
            );
        } else {
            panic!("invalid event received");
        }
    }

    #[tokio::test]
    async fn accept_incoming() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config: Arc<config::P2pConfig> = Arc::new(Default::default());

        let (mut conn1, _, _) = MockService::start(
            p2p_test_utils::make_mock_addr(),
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        let (mut conn2, _, _) = MockService::start(
            p2p_test_utils::make_mock_addr(),
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        let bind_address = conn2.local_addr().await.unwrap().unwrap();
        let (_res1, res2) = tokio::join!(conn1.connect(bind_address), conn2.poll_next());
        match res2.unwrap() {
            ConnectivityEvent::InboundAccepted {
                address: _,
                peer_info,
            } => {
                assert_eq!(peer_info.magic_bytes, *config.magic_bytes());
                assert_eq!(
                    peer_info.version,
                    common::primitives::semver::SemVer::new(0, 1, 0),
                );
                assert_eq!(peer_info.agent, None);
                assert_eq!(
                    peer_info.protocols,
                    [
                        Protocol::new(ProtocolType::PubSub, SemVer::new(0, 1, 0)),
                        Protocol::new(ProtocolType::Ping, SemVer::new(0, 1, 0)),
                    ]
                    .into_iter()
                    .collect()
                );
            }
            _ => panic!("invalid event received, expected incoming connection"),
        }
    }

    #[tokio::test]
    async fn disconnect() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config: Arc<config::P2pConfig> = Arc::new(Default::default());

        let (mut conn1, _, _) = MockService::start(
            p2p_test_utils::make_mock_addr(),
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();
        let (mut conn2, _, _) =
            MockService::start(p2p_test_utils::make_mock_addr(), config, p2p_config)
                .await
                .unwrap();

        let (_res1, res2) = tokio::join!(
            conn1.connect(conn2.local_addr().await.unwrap().unwrap()),
            conn2.poll_next()
        );

        match res2.unwrap() {
            ConnectivityEvent::InboundAccepted {
                address: _,
                peer_info,
            } => {
                assert_eq!(conn2.disconnect(peer_info.peer_id).await, Ok(()));
            }
            _ => panic!("invalid event received, expected incoming connection"),
        }
    }
}
