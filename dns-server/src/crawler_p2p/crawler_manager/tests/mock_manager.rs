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
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use crypto::random::Rng;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use common::{chain::ChainConfig, primitives::time::Time, time_getter::TimeGetter};
use p2p::{
    config::{NodeType, P2pConfig},
    disconnection_reason::DisconnectionReason,
    error::{DialError, P2pError},
    message::{AnnounceAddrRequest, PeerManagerMessage},
    net::{
        types::{ConnectivityEvent, PeerInfo, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingEventReceiver,
    },
    testing_utils::{TestAddressMaker, TEST_PROTOCOL_VERSION},
    types::{
        bannable_address::BannableAddress, peer_id::PeerId, services::Services,
        socket_address::SocketAddress,
    },
    P2pEventHandler,
};
use p2p_test_utils::P2pBasicTestTimeGetter;
use utils::atomics::SeqCstAtomicBool;
use utils_networking::IpOrSocketAddress;

use crate::{
    crawler_p2p::{
        crawler::{address_data::SoftwareInfo, CrawlerConfig},
        crawler_manager::{
            storage::DnsServerStorage, storage_impl::DnsServerStorageImpl, CrawlerManager,
            CrawlerManagerConfig,
        },
    },
    dns_server::DnsServerCommand,
};

pub enum ErraticNodeConnectError {
    ConnectionError(P2pError),
    MisbehavedOnHandshake(P2pError),
}

pub struct TestNode {
    pub chain_config: Arc<ChainConfig>,
    pub software_info: SoftwareInfo,
    /// If this is set, the corresponding ConnectivityEvent's will be generated by "connect".
    pub erratic_node_connect_errors: Option<Vec<ErraticNodeConnectError>>,
}

#[derive(Clone)]
pub struct MockStateRef {
    pub crawler_mgr_config: CrawlerManagerConfig,
    pub online: Arc<Mutex<BTreeMap<SocketAddress, TestNode>>>,
    pub connected: Arc<Mutex<BTreeMap<SocketAddress, PeerId>>>,
    pub connection_attempts: Arc<Mutex<Vec<SocketAddress>>>,
    pub conn_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    pub bind_address: SocketAddress,
}

impl MockStateRef {
    pub fn node_online(&self, ip: SocketAddress, software_info: SoftwareInfo) {
        self.node_online_impl(ip, software_info, None)
    }

    pub fn erratic_node_online(
        &self,
        ip: SocketAddress,
        software_info: SoftwareInfo,
        erratic_node_connect_errors: Vec<ErraticNodeConnectError>,
    ) {
        self.node_online_impl(ip, software_info, Some(erratic_node_connect_errors))
    }

    fn node_online_impl(
        &self,
        ip: SocketAddress,
        software_info: SoftwareInfo,
        erratic_node_connect_errors: Option<Vec<ErraticNodeConnectError>>,
    ) {
        let old = self.online.lock().unwrap().insert(
            ip,
            TestNode {
                chain_config: Arc::new(common::chain::config::create_mainnet()),
                software_info,
                erratic_node_connect_errors,
            },
        );
        assert!(old.is_none());
    }

    pub fn node_offline(&self, ip: SocketAddress) {
        let old = self.online.lock().unwrap().remove(&ip);
        assert!(old.is_some());
        if let Some(peer_id) = self.connected.lock().unwrap().remove(&ip) {
            self.conn_tx.send(ConnectivityEvent::ConnectionClosed { peer_id }).unwrap();
        }
    }

    pub fn announce_address(&self, from: SocketAddress, announced_ip: SocketAddress) {
        let peer_id = *self.connected.lock().unwrap().get(&from).unwrap();
        self.conn_tx
            .send(ConnectivityEvent::Message {
                peer_id,
                message: PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest {
                    address: announced_ip.as_peer_address(),
                }),
            })
            .unwrap();
    }

    pub fn report_misbehavior(&self, ip: SocketAddress, error: P2pError) {
        let peer_id = *self.connected.lock().unwrap().get(&ip).unwrap();
        self.conn_tx.send(ConnectivityEvent::Misbehaved { peer_id, error }).unwrap();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MockNetworkingService {}

pub struct MockConnectivityHandle {
    pub state: MockStateRef,
    pub conn_rx: mpsc::UnboundedReceiver<ConnectivityEvent>,
}

pub struct MockSyncingEventReceiver {}

#[async_trait]
impl NetworkingService for MockNetworkingService {
    type Transport = ();
    type ConnectivityHandle = MockConnectivityHandle;
    type MessagingHandle = ();
    type SyncingEventReceiver = MockSyncingEventReceiver;

    async fn start(
        _networking_enabled: bool,
        _transport: Self::Transport,
        _bind_addresses: Vec<SocketAddress>,
        _chain_config: Arc<ChainConfig>,
        _p2p_config: Arc<P2pConfig>,
        _time_getter: TimeGetter,
        _shutdown: Arc<SeqCstAtomicBool>,
        _shutdown_receiver: oneshot::Receiver<()>,
        _subscribers_receiver: mpsc::UnboundedReceiver<P2pEventHandler>,
    ) -> p2p::Result<(
        Self::ConnectivityHandle,
        Self::MessagingHandle,
        Self::SyncingEventReceiver,
        JoinHandle<()>,
    )> {
        unreachable!()
    }
}

#[async_trait]
impl ConnectivityService<MockNetworkingService> for MockConnectivityHandle {
    fn enable_networking(&mut self, _enable: bool) -> p2p::Result<()> {
        Ok(())
    }

    fn connect(&mut self, address: SocketAddress, _services: Option<Services>) -> p2p::Result<()> {
        self.state.connection_attempts.lock().unwrap().push(address);
        match self.state.online.lock().unwrap().get(&address) {
            None => {
                self.state
                    .conn_tx
                    .send(ConnectivityEvent::ConnectionError {
                        peer_address: address,
                        error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                    })
                    .unwrap();
            }
            Some(node) if node.erratic_node_connect_errors.is_some() => {
                for event in node.erratic_node_connect_errors.as_ref().unwrap() {
                    let conn_event = match event {
                        ErraticNodeConnectError::ConnectionError(error) => {
                            ConnectivityEvent::ConnectionError {
                                peer_address: address,
                                error: error.clone(),
                            }
                        }
                        ErraticNodeConnectError::MisbehavedOnHandshake(error) => {
                            ConnectivityEvent::MisbehavedOnHandshake {
                                peer_address: address,
                                error: error.clone(),
                            }
                        }
                    };

                    self.state.conn_tx.send(conn_event).unwrap();
                }
            }
            Some(node) => {
                let peer_id = PeerId::new();
                let peer_info = PeerInfo {
                    peer_id,
                    protocol_version: TEST_PROTOCOL_VERSION,
                    network: *node.chain_config.magic_bytes(),
                    software_version: node.software_info.version,
                    user_agent: node.software_info.user_agent.clone(),
                    common_services: NodeType::DnsServer.into(),
                };
                let old = self.state.connected.lock().unwrap().insert(address, peer_id);
                assert!(old.is_none());
                self.state
                    .conn_tx
                    .send(ConnectivityEvent::OutboundAccepted {
                        peer_address: address,
                        bind_address: self.state.bind_address,
                        peer_info,
                        node_address_as_seen_by_peer: None,
                    })
                    .unwrap();
            }
        }

        Ok(())
    }

    fn accept(&mut self, _peer_id: PeerId) -> p2p::Result<()> {
        Ok(())
    }

    fn disconnect(
        &mut self,
        peer_id: PeerId,
        _reason: Option<DisconnectionReason>,
    ) -> p2p::Result<()> {
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
        self.state
            .conn_tx
            .send(ConnectivityEvent::ConnectionClosed { peer_id })
            .unwrap();
        Ok(())
    }

    fn send_message(&mut self, _peer_id: PeerId, _request: PeerManagerMessage) -> p2p::Result<()> {
        Ok(())
    }

    fn local_addresses(&self) -> &[SocketAddress] {
        &[]
    }

    async fn poll_next(&mut self) -> p2p::Result<ConnectivityEvent> {
        Ok(self.conn_rx.recv().await.unwrap())
    }
}

#[async_trait]
impl SyncingEventReceiver for MockSyncingEventReceiver {
    async fn poll_next(&mut self) -> p2p::Result<SyncingEvent> {
        std::future::pending().await
    }
}

pub fn test_crawler(
    reserved_nodes: Vec<SocketAddress>,
    rng: &mut impl Rng
) -> (
    CrawlerManager<MockNetworkingService, DnsServerStorageImpl<storage::inmemory::InMemory>>,
    MockStateRef,
    mpsc::UnboundedReceiver<DnsServerCommand>,
    P2pBasicTestTimeGetter,
) {
    let (conn_tx, conn_rx) = mpsc::unbounded_channel();
    let reserved_nodes = reserved_nodes
        .into_iter()
        .map(|addr| IpOrSocketAddress::new_socket_address(addr.socket_addr()))
        .collect();
    let crawler_mgr_config = CrawlerManagerConfig {
        reserved_nodes,
        default_p2p_port: 3031,
    };
    let crawler_config = CrawlerConfig {
        ban_duration: Default::default(),
        ban_threshold: Default::default(),
        addr_list_request_interval: Default::default(),
    };

    let state = MockStateRef {
        crawler_mgr_config: crawler_mgr_config.clone(),
        online: Default::default(),
        connected: Default::default(),
        connection_attempts: Default::default(),
        conn_tx,
        bind_address: TestAddressMaker::new_random_address(rng),
    };

    let conn = MockConnectivityHandle {
        state: state.clone(),
        conn_rx,
    };
    let sync = MockSyncingEventReceiver {};

    let storage = storage::inmemory::InMemory::new();
    let store = DnsServerStorageImpl::new(storage).unwrap();

    let (dns_server_cmd_tx, dns_server_cmd_rx) = mpsc::unbounded_channel();
    let chain_config = Arc::new(common::chain::config::create_mainnet());

    let time_getter = P2pBasicTestTimeGetter::new();

    let crawler = CrawlerManager::<MockNetworkingService, _>::new(
        time_getter.get_time_getter(),
        crawler_mgr_config,
        crawler_config,
        chain_config,
        conn,
        sync,
        store,
        dns_server_cmd_tx,
    )
    .unwrap();

    (crawler, state, dns_server_cmd_rx, time_getter)
}

/// Move tokio time multiple times in specified steps, polling the crawler at the same time
/// Used to simulate elapsed time more accurately.
pub async fn advance_time(
    crawler: &mut CrawlerManager<
        MockNetworkingService,
        DnsServerStorageImpl<storage::inmemory::InMemory>,
    >,
    time_getter: &P2pBasicTestTimeGetter,
    step: Duration,
    count: u32,
) {
    for _ in 0..count {
        time_getter.advance_time(step);
        crawler.heartbeat();
    }

    tokio::time::timeout(Duration::from_millis(10), crawler.run())
        .await
        .expect_err("run should not return");
}

pub fn assert_known_addresses<N, S>(
    crawler: &CrawlerManager<N, S>,
    expected: &[(SocketAddress, SoftwareInfo)],
) where
    N: NetworkingService,
    S: DnsServerStorage,
    N::SyncingEventReceiver: SyncingEventReceiver,
    N::ConnectivityHandle: ConnectivityService<N>,
{
    let loaded_storage = crawler.load_storage_for_tests().unwrap();
    let actual: BTreeMap<_, _> = loaded_storage
        .known_addresses
        .iter()
        .map(|(addr, addr_info)| (*addr, addr_info.software_info.clone()))
        .collect();
    let expected: BTreeMap<_, _> = expected.iter().cloned().collect();
    assert_eq!(actual, expected);
}

pub fn assert_banned_addresses<N, S>(
    crawler: &CrawlerManager<N, S>,
    expected: &[(BannableAddress, Time)],
) where
    N: NetworkingService,
    S: DnsServerStorage,
    N::SyncingEventReceiver: SyncingEventReceiver,
    N::ConnectivityHandle: ConnectivityService<N>,
{
    let loaded_storage = crawler.load_storage_for_tests().unwrap();
    let expected: BTreeMap<_, _> = expected.iter().copied().collect();
    assert_eq!(loaded_storage.banned_addresses, expected);
}
