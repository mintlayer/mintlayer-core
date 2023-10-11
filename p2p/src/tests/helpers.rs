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

//! A module for tests that behave like integration tests but still need access to private data
//! via methods under #[cfg(test)],

use std::sync::Arc;

use futures::Future;
use p2p_test_utils::{expect_recv, P2pBasicTestTimeGetter, LONG_TIMEOUT, SHORT_TIMEOUT};
use p2p_types::{
    bannable_address::BannableAddress, p2p_event::P2pEventHandler, socket_address::SocketAddress,
};
use storage_inmemory::InMemory;
use subsystem::ShutdownTrigger;
use tokio::{
    sync::{
        mpsc::{self, UnboundedSender},
        oneshot,
    },
    task::JoinHandle,
    time,
};

use crate::{
    config::P2pConfig,
    error::P2pError,
    net::{
        default_backend::{transport::TransportSocket, DefaultNetworkingService},
        ConnectivityService,
    },
    peer_manager::{self, peerdb::storage_impl::PeerDbStorageImpl, PeerManager},
    protocol::ProtocolVersion,
    sync::BlockSyncManager,
    testing_utils::{peerdb_inmemory_store, test_p2p_config, TestTransportMaker},
    types::ip_or_socket_address::IpOrSocketAddress,
    utils::oneshot_nofail,
    PeerManagerEvent,
};
use common::chain::ChainConfig;
use utils::atomics::SeqCstAtomicBool;

type PeerMgr<TTM> = PeerManager<
    DefaultNetworkingService<<TTM as TestTransportMaker>::Transport>,
    PeerDbStorageImpl<InMemory>,
>;

pub struct TestNode<TTM>
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    time_getter: P2pBasicTestTimeGetter,
    peer_mgr_event_tx: mpsc::UnboundedSender<PeerManagerEvent>,
    local_address: SocketAddress,
    shutdown: Arc<SeqCstAtomicBool>,
    shutdown_sender: oneshot::Sender<()>,
    _subscribers_sender: mpsc::UnboundedSender<P2pEventHandler>,
    peer_mgr_join_handle: JoinHandle<(PeerMgr<TTM>, P2pError)>,
    sync_mgr_join_handle: JoinHandle<P2pError>,
    shutdown_trigger: ShutdownTrigger,
    subsystem_mgr_join_handle: subsystem::ManagerJoinHandle,
    peer_mgr_notification_rx: mpsc::UnboundedReceiver<PeerManagerNotification>,
}

// This is what's left of a test node after it has been stopped.
// TODO: this is kind of ugly; instead of examining the remnants, tests should be able to observe
// the innards of the p2p components (such as the peer db) on the fly.
pub struct TestNodeRemnants<TTM>
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    pub peer_mgr: PeerMgr<TTM>,
    pub peer_mgr_error: P2pError,
    pub sync_mgr_error: P2pError,
}

impl<TTM> TestNode<TTM>
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    pub async fn start(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        bind_address: SocketAddress,
        protocol_version: ProtocolVersion,
    ) -> Self {
        let time_getter = P2pBasicTestTimeGetter::new();
        let (peer_mgr_event_tx, peer_mgr_event_rx) = mpsc::unbounded_channel();
        let (chainstate, mempool, shutdown_trigger, subsystem_mgr_join_handle) =
            p2p_test_utils::start_subsystems(Arc::clone(&chain_config));
        let shutdown = Arc::new(SeqCstAtomicBool::new(false));
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let (subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();

        let (conn_handle, messaging_handle, syncing_event_rx, _) =
            DefaultNetworkingService::<TTM::Transport>::start_with_version(
                TTM::make_transport(),
                vec![bind_address],
                Arc::clone(&chain_config),
                Arc::new(test_p2p_config()),
                time_getter.get_time_getter(),
                Arc::clone(&shutdown),
                shutdown_receiver,
                subscribers_receiver,
                protocol_version,
            )
            .await
            .unwrap();

        let local_address = conn_handle.local_addresses()[0];

        let (peer_mgr_notification_tx, peer_mgr_notification_rx) = mpsc::unbounded_channel();
        let peer_mgr_observer = Box::new(PeerManagerObserver::new(peer_mgr_notification_tx));

        let peer_mgr = PeerMgr::<TTM>::new_with_observer(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            conn_handle,
            peer_mgr_event_rx,
            time_getter.get_time_getter(),
            peerdb_inmemory_store(),
            Some(peer_mgr_observer),
        )
        .unwrap();
        let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
            let mut peer_mgr = peer_mgr;
            let err = match peer_mgr.run_without_consuming_self().await {
                Err(err) => err,
                Ok(never) => match never {},
            };

            (peer_mgr, err)
        });

        let sync_mgr = BlockSyncManager::<DefaultNetworkingService<TTM::Transport>>::new(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            messaging_handle,
            syncing_event_rx,
            chainstate,
            mempool,
            peer_mgr_event_tx.clone(),
            time_getter.get_time_getter(),
        );
        let sync_mgr_join_handle = logging::spawn_in_current_span(async move {
            match sync_mgr.run().await {
                Err(err) => err,
                Ok(never) => match never {},
            }
        });

        TestNode {
            time_getter,
            peer_mgr_event_tx,
            local_address,
            shutdown,
            shutdown_sender,
            _subscribers_sender: subscribers_sender,
            peer_mgr_join_handle,
            sync_mgr_join_handle,
            shutdown_trigger,
            subsystem_mgr_join_handle,
            peer_mgr_notification_rx,
        }
    }

    pub fn local_address(&self) -> &SocketAddress {
        &self.local_address
    }

    pub fn time_getter(&self) -> &P2pBasicTestTimeGetter {
        &self.time_getter
    }

    // Note: the returned receiver will become readable only after the handshake is finished.
    pub fn start_connecting(
        &self,
        address: SocketAddress,
    ) -> oneshot_nofail::Receiver<Result<(), P2pError>> {
        let (connect_result_tx, connect_result_rx) = oneshot_nofail::channel();
        self.peer_mgr_event_tx
            .send(PeerManagerEvent::Connect(
                IpOrSocketAddress::Socket(address.socket_addr()),
                connect_result_tx,
            ))
            .unwrap();

        connect_result_rx
    }

    pub async fn expect_peer_mgr_notification(&mut self) -> PeerManagerNotification {
        expect_recv!(self.peer_mgr_notification_rx)
    }

    pub async fn expect_no_banning(&mut self) {
        // Note: at the moment the loop is useless, because all existing notification types
        // are related to banning, but it may change in the future.
        time::timeout(SHORT_TIMEOUT, async {
            #[allow(clippy::never_loop)]
            loop {
                match self.peer_mgr_notification_rx.recv().await.unwrap() {
                    PeerManagerNotification::BanScoreAdjustment {
                        address: _,
                        new_score: _,
                    }
                    | PeerManagerNotification::Ban { address: _ } => {
                        break;
                    }
                }
            }
        })
        .await
        .unwrap_err();
    }

    pub async fn join(self) -> TestNodeRemnants<TTM> {
        self.shutdown.store(true);
        let _ = self.shutdown_sender.send(());
        let (peer_mgr, peer_mgr_error) = self.peer_mgr_join_handle.await.unwrap();
        let sync_mgr_error = self.sync_mgr_join_handle.await.unwrap();
        self.shutdown_trigger.initiate();
        self.subsystem_mgr_join_handle.join().await;

        TestNodeRemnants {
            peer_mgr,
            peer_mgr_error,
            sync_mgr_error,
        }
    }
}

pub async fn timeout<F>(future: F)
where
    F: Future,
{
    // TODO: in the case of timeout, a panic is likely to occur in an unrelated place,
    // e.g. "subsystem manager's handle hasn't been joined" is a common one. This can be
    // confusing, so we need a way to abort the test before some unrelated code decides to panic.
    time::timeout(LONG_TIMEOUT, future).await.unwrap();
}

#[derive(Debug)]
pub enum PeerManagerNotification {
    BanScoreAdjustment {
        address: SocketAddress,
        new_score: u32,
    },
    Ban {
        address: BannableAddress,
    },
}

pub struct PeerManagerObserver {
    event_tx: UnboundedSender<PeerManagerNotification>,
}

impl PeerManagerObserver {
    pub fn new(event_tx: UnboundedSender<PeerManagerNotification>) -> Self {
        Self { event_tx }
    }
}

impl peer_manager::Observer for PeerManagerObserver {
    fn on_peer_ban_score_adjustment(&mut self, address: SocketAddress, new_score: u32) {
        self.event_tx
            .send(PeerManagerNotification::BanScoreAdjustment { address, new_score })
            .unwrap();
    }

    fn on_peer_ban(&mut self, address: BannableAddress) {
        self.event_tx.send(PeerManagerNotification::Ban { address }).unwrap();
    }
}
