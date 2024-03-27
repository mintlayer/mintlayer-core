// Copyright (c) 2021-2023 RBB S.r.l
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
    collections::BTreeSet,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use chainstate::{
    make_chainstate, ChainstateConfig, ChainstateHandle, DefaultTransactionVerificationStrategy,
};
use mempool::MempoolConfig;
use p2p_test_utils::{P2pBasicTestTimeGetter, SHORT_TIMEOUT};
use p2p_types::{p2p_event::P2pEventHandler, socket_address::SocketAddress};
use storage_inmemory::InMemory;
use subsystem::ShutdownTrigger;
use tokio::{
    sync::{
        mpsc::{self},
        oneshot,
    },
    task::JoinHandle,
    time,
};
use utils_networking::IpOrSocketAddress;

use crate::{
    config::P2pConfig,
    error::P2pError,
    net::{
        default_backend::{
            transport::{TransportListener, TransportSocket},
            DefaultNetworkingService,
        },
        types::ConnectionType,
        ConnectivityService,
    },
    peer_manager::{
        peerdb::storage_impl::PeerDbStorageImpl,
        test_utils::{mutate_peer_manager, query_peer_manager},
        PeerManager,
    },
    protocol::ProtocolVersion,
    sync::SyncManager,
    testing_utils::peerdb_inmemory_store,
    utils::oneshot_nofail,
    PeerManagerEvent,
};
use common::chain::ChainConfig;
use utils::atomics::SeqCstAtomicBool;

use super::{PeerManagerNotification, PeerManagerObserver, TestDnsSeed, TestPeersInfo};

type PeerMgr<Transport> =
    PeerManager<DefaultNetworkingService<Transport>, PeerDbStorageImpl<InMemory>>;

pub struct TestNode<Transport>
where
    Transport: TransportSocket,
{
    time_getter: P2pBasicTestTimeGetter,
    p2p_config: Arc<P2pConfig>,
    peer_mgr_event_sender: mpsc::UnboundedSender<PeerManagerEvent>,
    local_address: SocketAddress,
    shutdown: Arc<SeqCstAtomicBool>,
    backend_shutdown_sender: oneshot::Sender<()>,
    _subscribers_sender: mpsc::UnboundedSender<P2pEventHandler>,
    backend_join_handle: JoinHandle<()>,
    peer_mgr_join_handle: JoinHandle<(PeerMgr<Transport>, P2pError)>,
    sync_mgr_join_handle: JoinHandle<P2pError>,
    shutdown_trigger: ShutdownTrigger,
    subsystem_mgr_join_handle: subsystem::ManagerJoinHandle,
    peer_mgr_notification_receiver: mpsc::UnboundedReceiver<PeerManagerNotification>,
    chainstate: ChainstateHandle,
    dns_seed_addresses: Arc<Mutex<Vec<SocketAddress>>>,
}

// This is what's left of a test node after it has been stopped.
// TODO: it should be possible to use PeerManagerEvent::GenericQuery to examine peer manager's
// internals on the fly.
pub struct TestNodeRemnants<Transport>
where
    Transport: TransportSocket,
{
    pub peer_mgr: PeerMgr<Transport>,
    pub peer_mgr_error: P2pError,
    pub sync_mgr_error: P2pError,
}

impl<Transport> TestNode<Transport>
where
    Transport: TransportSocket,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        networking_enabled: bool,
        time_getter: P2pBasicTestTimeGetter,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        transport: Transport,
        bind_address: SocketAddress,
        protocol_version: ProtocolVersion,
        node_name: Option<&str>,
    ) -> Self {
        let socket = transport.bind(vec![bind_address]).await.unwrap();
        let local_address = socket.local_addresses().unwrap()[0];

        let tracing_span = if let Some(node_name) = node_name {
            tracing::debug_span!(
                parent: &tracing::Span::current(),
                "",
                node = node_name,
                addr = ?local_address.socket_addr()
            )
        } else {
            tracing::Span::current()
        };

        let _tracing_span_guard = tracing_span.enter();

        let chainstate = make_chainstate(
            Arc::clone(&chain_config),
            ChainstateConfig::new(),
            chainstate_storage::inmemory::Store::new_empty().unwrap(),
            DefaultTransactionVerificationStrategy::new(),
            None,
            time_getter.get_time_getter(),
        )
        .unwrap();

        let mempool_config = Arc::new(MempoolConfig::new());

        let (chainstate, mempool, shutdown_trigger, subsystem_mgr_join_handle) =
            p2p_test_utils::start_subsystems_generic(
                chainstate,
                Arc::clone(&chain_config),
                mempool_config,
                time_getter.get_time_getter(),
                tracing_span.clone(),
            );

        let (peer_mgr_event_sender, peer_mgr_event_receiver) = mpsc::unbounded_channel();
        let shutdown = Arc::new(SeqCstAtomicBool::new(false));
        let (backend_shutdown_sender, backend_shutdown_receiver) = oneshot::channel();
        let (subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();

        let (conn_handle, messaging_handle, syncing_event_receiver, backend_join_handle) =
            DefaultNetworkingService::<Transport>::start_generic(
                networking_enabled,
                transport,
                socket,
                Arc::clone(&chain_config),
                Arc::clone(&p2p_config),
                time_getter.get_time_getter(),
                Arc::clone(&shutdown),
                backend_shutdown_receiver,
                subscribers_receiver,
                protocol_version,
                tracing_span.clone(),
            )
            .unwrap();

        let local_address = conn_handle.local_addresses()[0];

        let (peer_mgr_notification_sender, peer_mgr_notification_receiver) =
            mpsc::unbounded_channel();
        let peer_mgr_observer = Box::new(PeerManagerObserver::new(peer_mgr_notification_sender));
        let dns_seed_addresses = Arc::new(Mutex::new(Vec::new()));

        let peer_mgr = PeerMgr::<Transport>::new_generic(
            networking_enabled,
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            conn_handle,
            peer_mgr_event_receiver,
            time_getter.get_time_getter(),
            peerdb_inmemory_store(),
            Some(peer_mgr_observer),
            Box::new(TestDnsSeed::new(dns_seed_addresses.clone())),
        )
        .unwrap();
        let peer_mgr_join_handle = logging::spawn_in_span(
            async move {
                let mut peer_mgr = peer_mgr;
                let err = match peer_mgr.run_without_consuming_self().await {
                    Err(err) => err,
                    Ok(never) => match never {},
                };

                (peer_mgr, err)
            },
            tracing_span.clone(),
        );

        let sync_mgr = SyncManager::<DefaultNetworkingService<Transport>>::new(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            messaging_handle,
            syncing_event_receiver,
            chainstate.clone(),
            mempool,
            peer_mgr_event_sender.clone(),
            time_getter.get_time_getter(),
        );
        let sync_mgr_join_handle = logging::spawn_in_span(
            async move {
                match sync_mgr.run().await {
                    Err(err) => err,
                    Ok(never) => match never {},
                }
            },
            tracing_span.clone(),
        );

        TestNode {
            time_getter,
            p2p_config,
            peer_mgr_event_sender,
            local_address,
            shutdown,
            backend_shutdown_sender,
            _subscribers_sender: subscribers_sender,
            backend_join_handle,
            peer_mgr_join_handle,
            sync_mgr_join_handle,
            shutdown_trigger,
            subsystem_mgr_join_handle,
            peer_mgr_notification_receiver,
            chainstate,
            dns_seed_addresses,
        }
    }

    pub fn time_getter(&self) -> &P2pBasicTestTimeGetter {
        &self.time_getter
    }

    pub fn p2p_config(&self) -> &P2pConfig {
        &self.p2p_config
    }

    pub fn local_address(&self) -> &SocketAddress {
        &self.local_address
    }

    pub fn chainstate(&self) -> &ChainstateHandle {
        &self.chainstate
    }

    // Note: the returned receiver will become readable only after the handshake is finished.
    pub fn start_connecting(
        &self,
        address: SocketAddress,
    ) -> oneshot_nofail::Receiver<Result<(), P2pError>> {
        let (result_sender, result_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::Connect(
                IpOrSocketAddress::Socket(address.socket_addr()),
                result_sender,
            ))
            .unwrap();

        result_receiver
    }

    pub async fn expect_no_punishment(&mut self) {
        time::timeout(SHORT_TIMEOUT, async {
            loop {
                match self.peer_mgr_notification_receiver.recv().await.unwrap() {
                    PeerManagerNotification::BanScoreAdjustment {
                        address: _,
                        new_score: _,
                    }
                    | PeerManagerNotification::Ban { address: _ } => {
                        break;
                    }
                    | PeerManagerNotification::Discourage { address: _ } => {
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap_err();
    }

    pub async fn wait_for_ban_score_adjustment(&mut self) -> (SocketAddress, u32) {
        loop {
            if let PeerManagerNotification::BanScoreAdjustment { address, new_score } =
                self.peer_mgr_notification_receiver.recv().await.unwrap()
            {
                return (address, new_score);
            }
        }
    }

    pub fn try_recv_peer_mgr_notification(&mut self) -> Option<PeerManagerNotification> {
        self.peer_mgr_notification_receiver.try_recv().ok()
    }

    pub async fn get_peers_info(&self) -> TestPeersInfo {
        query_peer_manager(&self.peer_mgr_event_sender, |peer_mgr| {
            TestPeersInfo::from_peer_mgr_peer_contexts(peer_mgr.peers())
        })
        .await
    }

    pub async fn get_peer_ip_addresses(&self) -> BTreeSet<IpAddr> {
        let peers_info = self.get_peers_info().await;
        peers_info.info.keys().map(|addr| addr.ip_addr()).collect()
    }

    // Get addresses of all peers, including pending outbound connections.
    pub async fn get_all_peer_addresses(&self) -> BTreeSet<SocketAddress> {
        query_peer_manager(&self.peer_mgr_event_sender, |peer_mgr| {
            peer_mgr
                .peers()
                .values()
                .map(|ctx| ctx.peer_address)
                .chain(peer_mgr.pending_outbound_conn_addrs().into_iter())
                .collect()
        })
        .await
    }

    pub async fn get_all_peer_ip_addresses(&self) -> BTreeSet<IpAddr> {
        self.get_all_peer_addresses().await.iter().map(|addr| addr.ip_addr()).collect()
    }

    pub async fn discover_peer(&mut self, address: SocketAddress) {
        mutate_peer_manager(&self.peer_mgr_event_sender, move |peer_mgr| {
            peer_mgr.peer_db_mut().peer_discovered(address);
        })
        .await;
    }

    pub async fn enable_networking(&mut self, enable: bool) {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::EnableNetworking {
                enable,
                response_sender,
            })
            .unwrap();
        response_receiver.await.unwrap().unwrap();
    }

    pub async fn assert_connected_to(
        &self,
        expected_connections: &[(SocketAddress, ConnectionType)],
    ) {
        let peers_info = self.get_peers_info().await;
        assert_eq!(peers_info.info.len(), expected_connections.len());

        for (addr, conn_type) in expected_connections {
            let peer_info = peers_info.info.get(addr).unwrap();
            assert_eq!(peer_info.conn_type, *conn_type);
        }
    }

    // Assert that the number of outbound full/block relay connections is at least
    // outbound_xxx_relay_count.
    // Still, the number shouldn't exceed outbound_xxx_relay_count + outbound_xxx_relay_extra_count.
    pub async fn assert_outbound_conn_count_maximums_reached(&self) {
        let peer_mgr_config = &self.p2p_config.peer_manager_config;

        let peers_info = self.get_peers_info().await;
        let outbound_full_relay_peers_count =
            peers_info.count_peers_by_conn_type(ConnectionType::OutboundFullRelay);
        let outbound_block_relay_peers_count =
            peers_info.count_peers_by_conn_type(ConnectionType::OutboundBlockRelay);

        assert!(outbound_full_relay_peers_count >= *peer_mgr_config.outbound_full_relay_count);
        assert!(
            outbound_full_relay_peers_count
                <= *peer_mgr_config.outbound_full_relay_count
                    + *peer_mgr_config.outbound_full_relay_extra_count
        );

        assert!(outbound_block_relay_peers_count >= *peer_mgr_config.outbound_block_relay_count);
        assert!(
            outbound_block_relay_peers_count
                <= *peer_mgr_config.outbound_block_relay_count
                    + *peer_mgr_config.outbound_block_relay_extra_count
        );
    }

    // Assert that the number of outbound full/block relay connections doesn't exceed
    // outbound_xxx_relay_count + outbound_xxx_relay_extra_count.
    pub async fn assert_outbound_conn_count_within_limits(&self) {
        let peer_mgr_config = &self.p2p_config.peer_manager_config;

        let peers_info = self.get_peers_info().await;
        let outbound_full_relay_peers_count =
            peers_info.count_peers_by_conn_type(ConnectionType::OutboundFullRelay);
        let outbound_block_relay_peers_count =
            peers_info.count_peers_by_conn_type(ConnectionType::OutboundBlockRelay);

        assert!(
            outbound_full_relay_peers_count
                <= *peer_mgr_config.outbound_full_relay_count
                    + *peer_mgr_config.outbound_full_relay_extra_count
        );

        assert!(
            outbound_block_relay_peers_count
                <= *peer_mgr_config.outbound_block_relay_count
                    + *peer_mgr_config.outbound_block_relay_extra_count
        );
    }

    pub fn set_dns_seed_addresses(&self, addresses: Vec<SocketAddress>) {
        *self.dns_seed_addresses.lock().unwrap() = addresses;
    }

    pub async fn join(self) -> TestNodeRemnants<Transport> {
        self.shutdown.store(true);
        let _ = self.backend_shutdown_sender.send(());
        let (peer_mgr, peer_mgr_error) = self.peer_mgr_join_handle.await.unwrap();
        let sync_mgr_error = self.sync_mgr_join_handle.await.unwrap();
        self.backend_join_handle.await.unwrap();
        self.shutdown_trigger.initiate();
        self.subsystem_mgr_join_handle.join().await;

        TestNodeRemnants {
            peer_mgr,
            peer_mgr_error,
            sync_mgr_error,
        }
    }
}
