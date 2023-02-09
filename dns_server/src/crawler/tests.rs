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
    time::Duration,
};

use async_trait::async_trait;
use common::primitives::semver::SemVer;
use p2p::{
    config::P2pConfig,
    error::{DialError, P2pError},
    message::{
        AnnounceAddrRequest, Announcement, PeerManagerRequest, PeerManagerResponse, SyncRequest,
        SyncResponse,
    },
    net::{
        default_backend::{
            transport::TransportAddress,
            types::{PeerId, RequestId},
        },
        types::{ConnectivityEvent, PeerInfo, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    testing_utils::P2pTestTimeGetter,
};
use tokio::sync::mpsc;

use crate::{
    crawler::{
        storage::{DnsServerStorageRead, DnsServerTransactional},
        Crawler, CrawlerConfig,
    },
    dns_server::ServerCommands,
};

use super::storage_impl::DnsServerStorageImpl;

#[derive(Clone)]
struct MockStateRef {
    crawler_config: CrawlerConfig,
    online: Arc<Mutex<BTreeSet<SocketAddr>>>,
    connected: Arc<Mutex<BTreeMap<SocketAddr, PeerId>>>,
    connection_attempts: Arc<Mutex<Vec<SocketAddr>>>,
    conn_tx: mpsc::UnboundedSender<ConnectivityEvent<MockNetworkingService>>,
}

impl MockStateRef {
    fn node_online(&self, ip: SocketAddr) {
        let added = self.online.lock().unwrap().insert(ip);
        assert!(added);
    }

    fn node_offline(&self, ip: SocketAddr) {
        let removed = self.online.lock().unwrap().remove(&ip);
        assert!(removed);
        if let Some(peer_id) = self.connected.lock().unwrap().remove(&ip) {
            self.conn_tx.send(ConnectivityEvent::ConnectionClosed { peer_id }).unwrap();
        }
    }

    fn announce_address(&self, from: SocketAddr, announced_ip: SocketAddr) {
        let peer_id = *self.connected.lock().unwrap().get(&from).unwrap();
        self.conn_tx
            .send(ConnectivityEvent::Request {
                peer_id,
                request_id: RequestId::new(),
                request: PeerManagerRequest::AnnounceAddrRequest(AnnounceAddrRequest {
                    address: announced_ip.as_peer_address(),
                }),
            })
            .unwrap();
    }
}

#[derive(Debug)]
struct MockNetworkingService {}

struct MockConnectivityHandle {
    state: MockStateRef,
    conn_rx: mpsc::UnboundedReceiver<ConnectivityEvent<MockNetworkingService>>,
}

struct MockSyncingMessagingHandle {}

#[async_trait]
impl NetworkingService for MockNetworkingService {
    type Transport = ();
    type Address = SocketAddr;
    type BannableAddress = IpAddr;
    type PeerId = PeerId;
    type PeerRequestId = RequestId;
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

    fn send_request(
        &mut self,
        _peer_id: PeerId,
        _request: PeerManagerRequest,
    ) -> p2p::Result<RequestId> {
        unreachable!()
    }

    fn send_response(
        &mut self,
        _request_id: RequestId,
        _response: PeerManagerResponse,
    ) -> p2p::Result<()> {
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
    fn send_request(&mut self, _peer_id: PeerId, _request: SyncRequest) -> p2p::Result<RequestId> {
        unreachable!()
    }

    fn send_response(
        &mut self,
        _request_id: RequestId,
        _response: SyncResponse,
    ) -> p2p::Result<()> {
        unreachable!()
    }

    fn make_announcement(&mut self, _announcement: Announcement) -> p2p::Result<()> {
        unreachable!()
    }

    async fn poll_next(&mut self) -> p2p::Result<SyncingEvent<MockNetworkingService>> {
        std::future::pending().await
    }
}

fn test_crawler(
    add_node: Vec<SocketAddr>,
) -> (
    Crawler<MockNetworkingService, DnsServerStorageImpl<storage::inmemory::InMemory>>,
    MockStateRef,
    mpsc::UnboundedReceiver<ServerCommands>,
    P2pTestTimeGetter,
) {
    let (conn_tx, conn_rx) = mpsc::unbounded_channel();
    let add_node = add_node.iter().map(ToString::to_string).collect();
    let crawler_config = CrawlerConfig {
        add_node,
        network: [1, 2, 3, 4],
        p2p_port: 3031,
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

    let (command_tx, command_rx) = mpsc::unbounded_channel();

    let crawler =
        Crawler::<MockNetworkingService, _>::new(crawler_config, conn, sync, store, command_tx)
            .unwrap();

    let time_getter = P2pTestTimeGetter::new();

    (crawler, state, command_rx, time_getter)
}

async fn advance_time(
    crawler: &mut Crawler<MockNetworkingService, DnsServerStorageImpl<storage::inmemory::InMemory>>,
    time_getter: &P2pTestTimeGetter,
    hours: u32,
) {
    for _ in 0..hours * 60 {
        tokio::select! {
            _ = crawler.run() => {
                unreachable!("run should not return")
            }
            _ = time_getter.advance_time(Duration::from_secs(60)) => {}
        }
    }
}

#[tokio::test]
async fn dns_crawler_basic() {
    let node1: SocketAddr = "1.2.3.4:3031".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node1]);

    // Node goes online, DNS record added
    state.node_online(node1);
    advance_time(&mut crawler, &time_getter, 1).await;
    assert_eq!(
        command_rx.recv().await.unwrap(),
        ServerCommands::AddAddress(node1.ip())
    );

    // Node goes offline, DNS record removed
    state.node_offline(node1);
    advance_time(&mut crawler, &time_getter, 1).await;
    assert_eq!(
        command_rx.recv().await.unwrap(),
        ServerCommands::DelAddress(node1.ip())
    );
}

#[tokio::test]
async fn dns_crawler_long_offline() {
    let node1: SocketAddr = "1.2.3.4:3031".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node1]);

    // Two weeks passed
    advance_time(&mut crawler, &time_getter, 14 * 24).await;

    // Node goes online, DNS record is added in 24 hours
    state.node_online(node1);
    advance_time(&mut crawler, &time_getter, 24).await;
    assert_eq!(
        command_rx.recv().await.unwrap(),
        ServerCommands::AddAddress(node1.ip())
    );
}

#[tokio::test]
async fn dns_crawler_announced_online() {
    let node1: SocketAddr = "1.2.3.4:3031".parse().unwrap();
    let node2: SocketAddr = "1.2.3.5:3031".parse().unwrap();
    let node3: SocketAddr = "[2a00::1]:3031".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node1]);

    state.node_online(node1);
    state.node_online(node2);
    state.node_online(node3);

    advance_time(&mut crawler, &time_getter, 1).await;
    assert_eq!(
        command_rx.recv().await.unwrap(),
        ServerCommands::AddAddress(node1.ip())
    );

    state.announce_address(node1, node2);
    advance_time(&mut crawler, &time_getter, 1).await;
    assert_eq!(
        command_rx.recv().await.unwrap(),
        ServerCommands::AddAddress(node2.ip())
    );

    state.announce_address(node2, node3);
    advance_time(&mut crawler, &time_getter, 1).await;
    assert_eq!(
        command_rx.recv().await.unwrap(),
        ServerCommands::AddAddress(node3.ip())
    );

    let addresses = crawler.storage.transaction_ro().unwrap().get_addresses().unwrap();
    assert_eq!(
        addresses,
        vec![node1.to_string(), node2.to_string(), node3.to_string()]
    );
}

#[tokio::test]
async fn dns_crawler_announced_offline() {
    let node1: SocketAddr = "1.2.3.4:3031".parse().unwrap();
    let node2: SocketAddr = "1.2.3.5:3031".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node1]);

    state.node_online(node1);

    advance_time(&mut crawler, &time_getter, 1).await;
    assert_eq!(
        command_rx.recv().await.unwrap(),
        ServerCommands::AddAddress(node1.ip())
    );
    assert_eq!(state.connection_attempts.lock().unwrap().len(), 1);

    // Check that the crawler tries to connect to an offline node just once
    state.announce_address(node1, node2);
    advance_time(&mut crawler, &time_getter, 24).await;
    assert_eq!(state.connection_attempts.lock().unwrap().len(), 2);

    // Check that the crawler tries to connect if the same address is announced later
    state.node_online(node2);
    state.announce_address(node1, node2);
    advance_time(&mut crawler, &time_getter, 24).await;
    assert_eq!(
        command_rx.recv().await.unwrap(),
        ServerCommands::AddAddress(node2.ip())
    );
    assert_eq!(state.connection_attempts.lock().unwrap().len(), 3);
}
