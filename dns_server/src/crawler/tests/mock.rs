// Copyright (c) 2023 RBB S.r.l
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

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use common::primitives::semver::SemVer;
use p2p::{
    config::P2pConfig,
    error::{DialError, P2pError},
    message::{AnnounceAddrRequest, Announcement, PeerManagerMessage, SyncMessage},
    net::{
        default_backend::{transport::TransportAddress, types::PeerId},
        types::{ConnectivityEvent, PeerInfo, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
};
use tokio::sync::mpsc;

use crate::crawler::CrawlerConfig;

#[derive(Clone)]
pub struct MockStateRef {
    pub crawler_config: CrawlerConfig,
    pub online: Arc<Mutex<BTreeSet<SocketAddr>>>,
    pub connected: Arc<Mutex<BTreeMap<SocketAddr, PeerId>>>,
    pub connection_attempts: Arc<Mutex<Vec<SocketAddr>>>,
    pub conn_tx: mpsc::UnboundedSender<ConnectivityEvent<MockNetworkingService>>,
}

impl MockStateRef {
    pub fn node_online(&self, ip: SocketAddr) {
        let added = self.online.lock().unwrap().insert(ip);
        assert!(added);
    }

    pub fn node_offline(&self, ip: SocketAddr) {
        let removed = self.online.lock().unwrap().remove(&ip);
        assert!(removed);
        if let Some(peer_id) = self.connected.lock().unwrap().remove(&ip) {
            self.conn_tx.send(ConnectivityEvent::ConnectionClosed { peer_id }).unwrap();
        }
    }

    pub fn announce_address(&self, from: SocketAddr, announced_ip: SocketAddr) {
        let peer = *self.connected.lock().unwrap().get(&from).unwrap();
        self.conn_tx
            .send(ConnectivityEvent::Message {
                peer,
                message: PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest {
                    address: announced_ip.as_peer_address(),
                }),
            })
            .unwrap();
    }
}

#[derive(Debug)]
pub struct MockNetworkingService {}

pub struct MockConnectivityHandle {
    pub state: MockStateRef,
    pub conn_rx: mpsc::UnboundedReceiver<ConnectivityEvent<MockNetworkingService>>,
}

pub struct MockSyncingMessagingHandle {}

#[async_trait]
impl NetworkingService for MockNetworkingService {
    type Transport = ();
    type Address = SocketAddr;
    type BannableAddress = IpAddr;
    type PeerId = PeerId;
    type ConnectivityHandle = MockConnectivityHandle;
    type SyncingMessagingHandle = MockSyncingMessagingHandle;

    async fn start(
        _transport: Self::Transport,
        _bind_addresses: Vec<Self::Address>,
        _chain_config: Arc<common::chain::ChainConfig>,
        _p2p_config: Arc<P2pConfig>,
    ) -> p2p::Result<(Self::ConnectivityHandle, Self::SyncingMessagingHandle)> {
        unreachable!()
    }
}

#[async_trait]
impl ConnectivityService<MockNetworkingService> for MockConnectivityHandle {
    fn connect(&mut self, address: SocketAddr) -> p2p::Result<()> {
        self.state.connection_attempts.lock().unwrap().push(address);
        if self.state.online.lock().unwrap().contains(&address) {
            let peer_id = PeerId::new();
            let peer_info = PeerInfo {
                peer_id,
                network: self.state.crawler_config.network,
                version: SemVer::new(1, 2, 3),
                agent: None,
                subscriptions: BTreeSet::new(),
            };
            let old = self.state.connected.lock().unwrap().insert(address, peer_id);
            assert!(old.is_none());
            self.state
                .conn_tx
                .send(ConnectivityEvent::OutboundAccepted {
                    address,
                    peer_info,
                    receiver_address: None,
                })
                .unwrap();
        } else {
            self.state
                .conn_tx
                .send(ConnectivityEvent::ConnectionError {
                    address,
                    error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                })
                .unwrap();
        }
        Ok(())
    }

    fn disconnect(&mut self, _peer_id: PeerId) -> p2p::Result<()> {
        unreachable!()
    }

    fn send_message(&mut self, _peer_id: PeerId, _request: PeerManagerMessage) -> p2p::Result<()> {
        unreachable!()
    }

    fn local_addresses(&self) -> &[SocketAddr] {
        unreachable!()
    }

    async fn poll_next(&mut self) -> p2p::Result<ConnectivityEvent<MockNetworkingService>> {
        Ok(self.conn_rx.recv().await.unwrap())
    }
}

#[async_trait]
impl SyncingMessagingService<MockNetworkingService> for MockSyncingMessagingHandle {
    fn send_message(&mut self, _peer_id: PeerId, _request: SyncMessage) -> p2p::Result<()> {
        unreachable!()
    }

    fn make_announcement(&mut self, _announcement: Announcement) -> p2p::Result<()> {
        unreachable!()
    }

    async fn poll_next(&mut self) -> p2p::Result<SyncingEvent<MockNetworkingService>> {
        std::future::pending().await
    }
}
