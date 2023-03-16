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

//! # Mock NetworkingService implementation for DNS server tests
//!
//! The mock simulates a network where peers go online and offline.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use common::{chain::ChainConfig, primitives::semver::SemVer};
use p2p::{
    config::P2pConfig,
    error::{DialError, P2pError},
    message::{AnnounceAddrRequest, Announcement, PeerManagerMessage, SyncMessage},
    net::{
        default_backend::transport::TransportAddress,
        types::{ConnectivityEvent, PeerInfo, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    testing_utils::P2pTokioTestTimeGetter,
    types::peer_id::PeerId,
};
use tokio::sync::mpsc;

use crate::{
    crawler_p2p::crawler_manager::{
        storage_impl::DnsServerStorageImpl, CrawlerManager, CrawlerManagerConfig,
    },
    dns_server::DnsServerCommand,
};

pub struct TestNode {
    pub chain_config: Arc<ChainConfig>,
}

#[derive(Clone)]
pub struct MockStateRef {
    pub crawler_config: CrawlerManagerConfig,
    pub online: Arc<Mutex<BTreeMap<SocketAddr, TestNode>>>,
    pub connected: Arc<Mutex<BTreeMap<SocketAddr, PeerId>>>,
    pub connection_attempts: Arc<Mutex<Vec<SocketAddr>>>,
    pub conn_tx: mpsc::UnboundedSender<ConnectivityEvent<SocketAddr>>,
}

impl MockStateRef {
    pub fn node_online(&self, ip: SocketAddr) {
        let old = self.online.lock().unwrap().insert(
            ip,
            TestNode {
                chain_config: Arc::new(common::chain::config::create_mainnet()),
            },
        );
        assert!(old.is_none());
    }

    pub fn node_offline(&self, ip: SocketAddr) {
        let old = self.online.lock().unwrap().remove(&ip);
        assert!(old.is_some());
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

#[derive(Debug, PartialEq, Eq)]
pub struct MockNetworkingService {}

pub struct MockConnectivityHandle {
    pub state: MockStateRef,
    pub conn_rx: mpsc::UnboundedReceiver<ConnectivityEvent<SocketAddr>>,
}

pub struct MockSyncingMessagingHandle {}

#[async_trait]
impl NetworkingService for MockNetworkingService {
    type Transport = ();
    type Address = SocketAddr;
    type BannableAddress = IpAddr;
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
        if let Some(node) = self.state.online.lock().unwrap().get(&address) {
            let peer_id = PeerId::new();
            let peer_info = PeerInfo {
                peer_id,
                network: *node.chain_config.magic_bytes(),
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

    fn accept(&mut self, _peer_id: PeerId) -> p2p::Result<()> {
        Ok(())
    }

    fn disconnect(&mut self, peer_id: PeerId) -> p2p::Result<()> {
        let address = *self
            .state
            .connected
            .lock()
            .unwrap()
            .iter()
            .find(|(_addr, id)| **id == peer_id)
            .unwrap()
            .0;
        self.state.connected.lock().unwrap().remove(&address).unwrap();
        Ok(())
    }

    fn send_message(&mut self, _peer_id: PeerId, _request: PeerManagerMessage) -> p2p::Result<()> {
        unreachable!()
    }

    fn local_addresses(&self) -> &[SocketAddr] {
        &[]
    }

    async fn poll_next(&mut self) -> p2p::Result<ConnectivityEvent<SocketAddr>> {
        Ok(self.conn_rx.recv().await.unwrap())
    }
}

#[async_trait]
impl SyncingMessagingService for MockSyncingMessagingHandle {
    fn send_message(&mut self, _peer_id: PeerId, _request: SyncMessage) -> p2p::Result<()> {
        unreachable!()
    }

    fn make_announcement(&mut self, _announcement: Announcement) -> p2p::Result<()> {
        unreachable!()
    }

    async fn poll_next(&mut self) -> p2p::Result<SyncingEvent> {
        std::future::pending().await
    }
}

pub fn test_crawler(
    reserved_nodes: Vec<SocketAddr>,
) -> (
    CrawlerManager<MockNetworkingService, DnsServerStorageImpl<storage::inmemory::InMemory>>,
    MockStateRef,
    mpsc::UnboundedReceiver<DnsServerCommand>,
    P2pTokioTestTimeGetter,
) {
    let (conn_tx, conn_rx) = mpsc::unbounded_channel();
    let reserved_nodes = reserved_nodes.iter().map(ToString::to_string).collect();
    let crawler_config = CrawlerManagerConfig {
        reserved_nodes,
        default_p2p_port: 3031,
    };

    let state = MockStateRef {
        crawler_config: crawler_config.clone(),
        online: Default::default(),
        connected: Default::default(),
        connection_attempts: Default::default(),
        conn_tx,
    };

    let conn = MockConnectivityHandle {
        state: state.clone(),
        conn_rx,
    };
    let sync = MockSyncingMessagingHandle {};

    let storage = storage::inmemory::InMemory::new();
    let store = DnsServerStorageImpl::new(storage).unwrap();

    let (dns_server_cmd_tx, dns_server_cmd_rx) = mpsc::unbounded_channel();
    let chain_config = Arc::new(common::chain::config::create_mainnet());

    let crawler = CrawlerManager::<MockNetworkingService, _>::new(
        crawler_config,
        chain_config,
        conn,
        sync,
        store,
        dns_server_cmd_tx,
    )
    .unwrap();

    let time_getter = P2pTokioTestTimeGetter::new();

    (crawler, state, dns_server_cmd_rx, time_getter)
}

/// Move tokio time multiple times in specified steps, polling the crawler at the same time
/// Used to simulate elapsed time more accurately.
pub async fn advance_time(
    crawler: &mut CrawlerManager<
        MockNetworkingService,
        DnsServerStorageImpl<storage::inmemory::InMemory>,
    >,
    time_getter: &P2pTokioTestTimeGetter,
    step: Duration,
    count: u32,
) {
    for _ in 0..count {
        tokio::select! {
            biased;
            _ = crawler.run() => {
                unreachable!("run should not return")
            }
            _ = time_getter.advance_time(step) => {}
        }
    }
}
