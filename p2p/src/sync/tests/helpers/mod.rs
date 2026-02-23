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

use std::{collections::BTreeSet, panic, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{
    sync::{
        mpsc::{self, Sender, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
    task::JoinHandle,
    time,
};

use chainstate::{
    chainstate_interface::ChainstateInterface, make_chainstate, BlockSource, ChainstateConfig,
    ChainstateHandle, DefaultTransactionVerificationStrategy, Locator,
};
use common::{
    chain::{
        block::{
            signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp, BlockReward,
            ConsensusData,
        },
        config::create_unit_test_config,
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        Block, ChainConfig, Destination, GenBlock, SignedTransaction, Transaction, TxInput,
        TxOutput,
    },
    primitives::{Amount, BlockHeight, Id, Idable, H256},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::{event::TransactionProcessed, MempoolConfig, MempoolHandle, MempoolInit};
use networking::transport::TcpTransportSocket;
use p2p_test_utils::{expect_future_val, expect_no_recv, expect_recv, SHORT_TIMEOUT};
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};
use randomness::Rng;
use subsystem::{ManagerJoinHandle, ShutdownTrigger};
use test_utils::random::Seed;
use utils::{atomics::SeqCstAtomicBool, tokio_spawn_in_current_tracing_span};
use utils_networking::IpOrSocketAddress;

use crate::{
    message::{BlockSyncMessage, HeaderList, TransactionSyncMessage},
    net::types::SyncingEvent,
    protocol::{choose_common_protocol_version, ProtocolVersion},
    sync::{subscribe_to_new_tip, subscribe_to_tx_processed, Observer, SyncManager},
    test_helpers::test_p2p_config,
    types::peer_id::PeerId,
    MessagingService, NetworkingService, P2pConfig, P2pError, P2pEventHandler, PeerManagerEvent,
    Result, SyncingEventReceiver,
};

pub mod test_node_group;

/// A wrapper over other ends of the sync manager channels that simulates a test node.
///
/// Provides methods for manipulating and observing the sync manager state.
pub struct TestNode {
    /// This node's peer id, as seen by other nodes.
    peer_id: PeerId,
    p2p_config: Arc<P2pConfig>,
    peer_manager_event_receiver: UnboundedReceiver<PeerManagerEvent>,
    syncing_event_sender: UnboundedSender<SyncingEvent>,
    block_sync_msg_receiver: UnboundedReceiver<(PeerId, BlockSyncMessage)>,
    transaction_sync_msg_receiver: UnboundedReceiver<(PeerId, TransactionSyncMessage)>,
    error_receiver: UnboundedReceiver<P2pError>,
    sync_manager_handle: JoinHandle<()>,
    shutdown_trigger: ShutdownTrigger,
    subsystem_manager_handle: ManagerJoinHandle,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    new_tip_receiver: UnboundedReceiver<Id<Block>>,
    tx_processed_receiver: UnboundedReceiver<TransactionProcessed>,
    sync_mgr_notification_receiver: UnboundedReceiver<SyncManagerNotification>,
    protocol_version: ProtocolVersion,
}

impl TestNode {
    /// Starts the sync manager event loop and returns a handle for manipulating and observing the
    /// manager state.
    pub async fn start(protocol_version: ProtocolVersion) -> Self {
        Self::builder(protocol_version).build().await
    }

    pub fn builder(protocol_version: ProtocolVersion) -> TestNodeBuilder {
        TestNodeBuilder::new(protocol_version)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_params(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        shutdown_trigger: ShutdownTrigger,
        subsystem_manager_handle: ManagerJoinHandle,
        time_getter: TimeGetter,
        protocol_version: ProtocolVersion,
    ) -> Self {
        let (peer_manager_event_sender, peer_manager_event_receiver) = mpsc::unbounded_channel();

        let (block_sync_msg_sender, block_sync_msg_receiver) = mpsc::unbounded_channel();
        let (transaction_sync_msg_sender, transaction_sync_msg_receiver) =
            mpsc::unbounded_channel();
        let (syncing_event_sender, syncing_event_receiver) = mpsc::unbounded_channel();
        let messaging_handle = MessagingHandleMock {
            block_sync_msg_sender,
            transaction_sync_msg_sender,
        };
        let syncing_event_receiver_mock = SyncingEventReceiverMock {
            events_receiver: syncing_event_receiver,
        };
        let (sync_mgr_notification_sender, sync_mgr_notification_receiver) =
            mpsc::unbounded_channel();
        let sync_mgr_observer = Box::new(SyncManagerObserver::new(sync_mgr_notification_sender));

        let sync_manager = SyncManager::<NetworkingServiceStub>::new_generic(
            chain_config,
            Arc::clone(&p2p_config),
            messaging_handle,
            syncing_event_receiver_mock,
            chainstate_handle.clone(),
            mempool_handle.clone(),
            peer_manager_event_sender,
            time_getter,
            Some(sync_mgr_observer),
        );

        let sync_manager_chainstate_handle = sync_manager.chainstate().clone();

        let (error_sender, error_receiver) = mpsc::unbounded_channel();
        let sync_manager_handle = tokio_spawn_in_current_tracing_span(
            async move {
                let e = sync_manager.run().await.unwrap_err();
                let _ = error_sender.send(e);
            },
            "",
        );

        let new_tip_receiver = subscribe_to_new_tip(&sync_manager_chainstate_handle).await.unwrap();
        let tx_processed_receiver = subscribe_to_tx_processed(&mempool_handle).await.unwrap();

        Self {
            peer_id: PeerId::new(),
            p2p_config,
            peer_manager_event_receiver,
            syncing_event_sender,
            block_sync_msg_receiver,
            transaction_sync_msg_receiver,
            error_receiver,
            sync_manager_handle,
            shutdown_trigger,
            subsystem_manager_handle,
            chainstate_handle,
            mempool_handle,
            new_tip_receiver,
            tx_processed_receiver,
            sync_mgr_notification_receiver,
            protocol_version,
        }
    }

    pub fn chainstate(&self) -> &ChainstateHandle {
        &self.chainstate_handle
    }

    pub async fn get_block(&self, block_id: Id<Block>) -> Option<Block> {
        self.chainstate_handle
            .call(move |cs| cs.get_block(&block_id))
            .await
            .unwrap()
            .unwrap()
    }

    pub fn mempool(&self) -> &MempoolHandle {
        &self.mempool_handle
    }

    /// Sends the `SyncControlEvent::Connected` event without checking outgoing messages.
    #[must_use]
    pub fn try_connect_peer(
        &mut self,
        peer_id: PeerId,
        protocol_version: ProtocolVersion,
    ) -> TestPeer {
        let (block_sync_msg_sender, block_sync_msg_receiver) = mpsc::channel(20);
        let (transaction_sync_msg_sender, transaction_sync_msg_receiver) = mpsc::channel(20);
        let common_protocol_version =
            choose_common_protocol_version(self.protocol_version, protocol_version).unwrap();
        self.syncing_event_sender
            .send(SyncingEvent::Connected {
                peer_id,
                common_services: (*self.p2p_config.node_type).into(),
                protocol_version: common_protocol_version,
                block_sync_msg_receiver,
                transaction_sync_msg_receiver,
            })
            .unwrap();
        TestPeer::new(peer_id, block_sync_msg_sender, transaction_sync_msg_sender)
    }

    /// Connects a peer and checks that the header list request is sent to that peer.
    #[must_use]
    pub async fn connect_peer(
        &mut self,
        peer_id: PeerId,
        protocol_version: ProtocolVersion,
    ) -> TestPeer {
        let peer = self.try_connect_peer(peer_id, protocol_version);

        let (sent_to, message) = self.get_sent_block_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        assert!(matches!(message, BlockSyncMessage::HeaderListRequest(_)));
        peer
    }

    /// Sends the `SyncControlEvent::Disconnected` event.
    pub fn disconnect_peer(&mut self, peer_id: PeerId) {
        self.syncing_event_sender.send(SyncingEvent::Disconnected { peer_id }).unwrap();
    }

    /// Get a message that was sent from the node's sync manager by reading it from
    /// the channel
    pub async fn get_sent_block_sync_message(&mut self) -> (PeerId, BlockSyncMessage) {
        expect_recv!(self.block_sync_msg_receiver)
    }

    pub fn try_get_sent_block_sync_message(&mut self) -> Option<(PeerId, BlockSyncMessage)> {
        match self.block_sync_msg_receiver.try_recv() {
            Ok(message) => Some(message),
            Err(mpsc::error::TryRecvError::Empty) => None,
            Err(mpsc::error::TryRecvError::Disconnected) => panic!("Failed to receive event"),
        }
    }

    pub async fn get_sent_transaction_sync_message(&mut self) -> (PeerId, TransactionSyncMessage) {
        expect_recv!(self.transaction_sync_msg_receiver)
    }

    /// Panics if the sync manager returns an error.
    pub async fn assert_no_error(&mut self) {
        expect_no_recv!(self.error_receiver);
    }

    /// Expect an `AdjustPeerScore` event from the peer manager.
    /// PeerBlockSyncStatusUpdate events are ignored.
    pub async fn receive_adjust_peer_score_event(&mut self) -> (PeerId, u32) {
        let future = async {
            loop {
                match self.peer_manager_event_receiver.recv().await.unwrap() {
                    PeerManagerEvent::AdjustPeerScore {
                        peer_id,
                        adjust_by,
                        reason: _,
                        response_sender,
                    } => {
                        response_sender.send(Ok(()));
                        break (peer_id, adjust_by);
                    }
                    PeerManagerEvent::PeerBlockSyncStatusUpdate { .. } => {}
                    e => panic!("Expected peer score adjustment, received: {e:?}"),
                }
            }
        };

        expect_future_val!(future)
    }

    pub async fn receive_new_tip_event(&mut self) -> Id<Block> {
        expect_recv!(self.new_tip_receiver)
    }

    pub async fn receive_transaction_processed_event_from_mempool(
        &mut self,
    ) -> TransactionProcessed {
        expect_recv!(self.tx_processed_receiver)
    }

    pub async fn assert_no_transaction_processed_event_from_mempool(&mut self) {
        expect_no_recv!(self.tx_processed_receiver);
    }

    /// Expect a `Disconnect` event from the peer manager.
    /// PeerBlockSyncStatusUpdate events are ignored.
    pub async fn receive_disconnect_peer_event(&mut self, id: PeerId) {
        let future = async {
            loop {
                match self.peer_manager_event_receiver.recv().await.unwrap() {
                    PeerManagerEvent::Disconnect(peer_id, _peerdb_action, _, sender) => {
                        assert_eq!(id, peer_id);
                        sender.send(Ok(()));
                        break;
                    }
                    PeerManagerEvent::PeerBlockSyncStatusUpdate { .. } => {}
                    e => panic!("Expected PeerManagerEvent::Disconnect, received: {e:?}"),
                }
            }
        };

        expect_future_val!(future);
    }

    pub async fn receive_peer_manager_events(
        &mut self,
        mut events: BTreeSet<PeerManagerEventDesc>,
    ) {
        while !events.is_empty() {
            let event = expect_recv!(self.peer_manager_event_receiver);
            assert!(
                events.remove(&(&event).into()),
                "Unexpected peer manager event: {event:?}"
            );
        }
    }

    pub async fn receive_or_ignore_peer_manager_events(
        &mut self,
        mut events: BTreeSet<PeerManagerEventDesc>,
        should_ignore: impl Fn(&PeerManagerEvent) -> bool,
    ) {
        while !events.is_empty() {
            let event = expect_recv!(self.peer_manager_event_receiver);
            if !should_ignore(&event) {
                assert!(
                    events.remove(&(&event).into()),
                    "Unexpected peer manager event: {event:?}"
                );
            }
        }
    }

    pub async fn assert_no_disconnect_peer_event(&mut self, id: PeerId) {
        time::timeout(SHORT_TIMEOUT, async {
            loop {
                match self.peer_manager_event_receiver.recv().await.unwrap() {
                    PeerManagerEvent::Disconnect(peer_id, _peerdb_action, _, _)
                        if id == peer_id =>
                    {
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap_err();
    }

    /// Panics if there is an event from the peer manager (except for "informational" messages,
    /// like NewTipReceived/NewChainstateTip etc).
    // TODO: Rename the function
    pub async fn assert_no_peer_manager_event(&mut self) {
        time::timeout(SHORT_TIMEOUT, async {
            loop {
                let peer_event = self.peer_manager_event_receiver.recv().await.unwrap();
                match peer_event {
                    PeerManagerEvent::Connect(_, _)
                    | PeerManagerEvent::Disconnect(_, _, _, _)
                    | PeerManagerEvent::GetPeerCount(_)
                    | PeerManagerEvent::GetBindAddresses(_)
                    | PeerManagerEvent::GetConnectedPeers(_)
                    | PeerManagerEvent::AdjustPeerScore { .. }
                    | PeerManagerEvent::GetReserved(_)
                    | PeerManagerEvent::AddReserved(_, _)
                    | PeerManagerEvent::RemoveReserved(_, _)
                    | PeerManagerEvent::ListBanned(_)
                    | PeerManagerEvent::Ban(_, _, _)
                    | PeerManagerEvent::Unban(_, _)
                    | PeerManagerEvent::ListDiscouraged(_)
                    | PeerManagerEvent::Undiscourage(_, _)
                    | PeerManagerEvent::EnableNetworking { .. }
                    | PeerManagerEvent::GenericQuery(_)
                    | PeerManagerEvent::GenericMut(_) => {
                        panic!("Unexpected peer manager event: {peer_event:?}");
                    }
                    PeerManagerEvent::NewTipReceived { .. }
                    | PeerManagerEvent::NewChainstateTip(_)
                    | PeerManagerEvent::NewValidTransactionReceived { .. }
                    | PeerManagerEvent::PeerBlockSyncStatusUpdate { .. } => {
                        // Ignored
                    }
                }
            }
        })
        .await
        .unwrap_err();
    }

    /// Panics if the sync manager sends a message.
    pub async fn assert_no_sync_message(&mut self) {
        let future = async {
            tokio::select! {
                _ = self.block_sync_msg_receiver.recv() => {},
                _ = self.transaction_sync_msg_receiver.recv() => {},
            }
        };

        time::timeout(SHORT_TIMEOUT, future).await.unwrap_err();
    }

    pub async fn assert_peer_score_adjustment(
        &mut self,
        expected_peer: PeerId,
        expected_score: u32,
    ) {
        let (adjusted_peer, score) = self.receive_adjust_peer_score_event().await;
        assert_eq!(adjusted_peer, expected_peer);
        assert_eq!(score, expected_score);
    }

    /// Awaits on the sync manager join handle and rethrows the panic.
    pub async fn resume_panic(self) {
        let err = self.sync_manager_handle.await.unwrap_err();
        self.shutdown_trigger.initiate();
        self.subsystem_manager_handle.join().await;
        panic::resume_unwind(err.into_panic());
    }

    pub async fn join_subsystem_manager(self) {
        // Shutdown sync manager first
        drop(self.syncing_event_sender);
        let _ = self.sync_manager_handle.await;

        // Shutdown remaining subsystems
        self.shutdown_trigger.initiate();
        self.subsystem_manager_handle.join().await;

        // Finally, when all services are down, receivers could be closed too
        drop(self.block_sync_msg_receiver);
        drop(self.transaction_sync_msg_receiver);
        drop(self.error_receiver);
        drop(self.peer_manager_event_receiver);
    }

    pub async fn get_locator_from_height(&self, height: BlockHeight) -> Locator {
        self.chainstate_handle
            .call_mut(move |this| this.get_locator_from_height(height))
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn wait_for_notification(&mut self, notification: SyncManagerNotification) {
        let wait_loop = async {
            loop {
                if self.sync_mgr_notification_receiver.recv().await.unwrap() == notification {
                    break;
                }
            }
        };

        expect_future_val!(wait_loop);
    }

    pub async fn clear_notifications(&mut self) {
        while time::timeout(SHORT_TIMEOUT, self.sync_mgr_notification_receiver.recv())
            .await
            .is_ok()
        {}
    }
}

// Represents a peer that can send messages to a node it is connected to
pub struct TestPeer {
    peer_id: PeerId,
    block_sync_msg_sender: Sender<BlockSyncMessage>,
    transaction_sync_msg_sender: Sender<TransactionSyncMessage>,
}

impl TestPeer {
    pub fn new(
        peer_id: PeerId,
        block_sync_msg_sender: Sender<BlockSyncMessage>,
        transaction_sync_msg_sender: Sender<TransactionSyncMessage>,
    ) -> Self {
        Self {
            peer_id,
            block_sync_msg_sender,
            transaction_sync_msg_sender,
        }
    }

    pub fn get_id(&self) -> PeerId {
        self.peer_id
    }

    pub async fn send_block_sync_message(&self, message: BlockSyncMessage) {
        self.block_sync_msg_sender.send(message).await.unwrap();
    }

    pub async fn send_transaction_sync_message(&self, message: TransactionSyncMessage) {
        self.transaction_sync_msg_sender.send(message).await.unwrap();
    }

    pub async fn send_headers(&self, headers: Vec<SignedBlockHeader>) {
        self.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers)))
            .await;
    }
}

pub struct TestNodeBuilder {
    chain_config: Arc<ChainConfig>,
    mempool_config: MempoolConfig,
    p2p_config: Arc<P2pConfig>,
    chainstate_config: Option<ChainstateConfig>,
    chainstate: Option<Box<dyn ChainstateInterface>>,
    time_getter: TimeGetter,
    blocks: Vec<Block>,
    protocol_version: ProtocolVersion,
}

impl TestNodeBuilder {
    pub fn new(protocol_version: ProtocolVersion) -> Self {
        Self {
            chain_config: Arc::new(create_unit_test_config()),
            mempool_config: MempoolConfig::new(),
            p2p_config: Arc::new(test_p2p_config()),
            chainstate_config: None,
            chainstate: None,
            time_getter: TimeGetter::default(),
            blocks: Vec::new(),
            protocol_version,
        }
    }

    pub fn with_chain_config(mut self, chain_config: Arc<ChainConfig>) -> Self {
        self.chain_config = chain_config;
        self
    }

    pub fn with_chainstate_config(mut self, chainstate_config: ChainstateConfig) -> Self {
        self.chainstate_config = Some(chainstate_config);
        self
    }

    pub fn with_chainstate(mut self, chainstate: Box<dyn ChainstateInterface>) -> Self {
        self.chainstate = Some(chainstate);
        self
    }

    pub fn with_mempool_config(mut self, mempool_config: MempoolConfig) -> Self {
        self.mempool_config = mempool_config;
        self
    }

    pub fn with_p2p_config(mut self, p2p_config: Arc<P2pConfig>) -> Self {
        self.p2p_config = p2p_config;
        self
    }

    pub fn with_time_getter(mut self, time_getter: TimeGetter) -> Self {
        self.time_getter = time_getter;
        self
    }

    pub fn with_blocks(mut self, blocks: Vec<Block>) -> Self {
        self.blocks = blocks;
        self
    }

    pub async fn build(self) -> TestNode {
        let TestNodeBuilder {
            chain_config,
            mempool_config,
            p2p_config,
            chainstate_config,
            chainstate,
            time_getter,
            blocks,
            protocol_version,
        } = self;

        let mut manager = subsystem::Manager::new("p2p-sync-test-manager");
        let shutdown_trigger = manager.make_shutdown_trigger();

        assert!(chainstate_config.is_none() || chainstate.is_none());

        let mut chainstate = chainstate.unwrap_or_else(|| {
            let chainstate_config = chainstate_config.unwrap_or_else(ChainstateConfig::new);
            make_chainstate(
                Arc::clone(&chain_config),
                chainstate_config,
                chainstate_storage::inmemory::Store::new_empty().unwrap(),
                DefaultTransactionVerificationStrategy::new(),
                None,
                time_getter.clone(),
            )
            .unwrap()
        });
        for block in blocks {
            chainstate.process_block(block, BlockSource::Local).unwrap();
        }
        let chainstate = manager.add_subsystem("p2p-sync-test-chainstate", chainstate);

        let mempool_init = MempoolInit::new(
            Arc::clone(&chain_config),
            mempool_config,
            chainstate.clone(),
            time_getter.clone(),
        );
        let mempool =
            manager.add_custom_subsystem("p2p-sync-test-mempool", |h| mempool_init.init(h));

        let manager_handle = manager.main_in_task();

        TestNode::start_with_params(
            chain_config,
            p2p_config,
            chainstate.clone(),
            mempool,
            shutdown_trigger,
            manager_handle,
            time_getter,
            protocol_version,
        )
        .await
    }
}

// A "descriptor" for PeerManagerEvent that can be put into a set.
// TODO: put it somewhere else
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum PeerManagerEventDesc {
    Connect(IpOrSocketAddress),
    Disconnect(PeerId),
    GetPeerCount,
    GetBindAddresses,
    GetConnectedPeers,
    AdjustPeerScore {
        peer_id: PeerId,
        score: u32,
    },
    NewTipReceived {
        peer_id: PeerId,
        block_id: Id<Block>,
    },
    NewChainstateTip(Id<Block>),
    NewValidTransactionReceived {
        peer_id: PeerId,
        txid: Id<Transaction>,
    },
    PeerBlockSyncStatusUpdate {
        peer_id: PeerId,
        // Note: we don't include PeerBlockSyncStatus here, because the purpose of
        // PeerManagerEventDesc is to be able to easily form a set of expected values and those
        // values must be easy to predict. Currently, PeerBlockSyncStatus only contains a Time
        // value, which may be hard to predict, depending on the test.
    },
    GetReserved,
    AddReserved(IpOrSocketAddress),
    RemoveReserved(IpOrSocketAddress),
    ListBanned,
    Ban(BannableAddress, Duration),
    Unban(BannableAddress),
    ListDiscouraged,
    Undiscourage(BannableAddress),
    EnableNetworking {
        enable: bool,
    },
    GenericQuery,
    GenericMut,
}

impl From<&PeerManagerEvent> for PeerManagerEventDesc {
    fn from(event: &PeerManagerEvent) -> Self {
        match event {
            PeerManagerEvent::Connect(addr, _) => PeerManagerEventDesc::Connect(addr.clone()),
            PeerManagerEvent::Disconnect(peer_id, _, _, _) => {
                PeerManagerEventDesc::Disconnect(*peer_id)
            }
            PeerManagerEvent::GetPeerCount(_) => PeerManagerEventDesc::GetPeerCount,
            PeerManagerEvent::GetBindAddresses(_) => PeerManagerEventDesc::GetBindAddresses,
            PeerManagerEvent::GetConnectedPeers(_) => PeerManagerEventDesc::GetConnectedPeers,
            PeerManagerEvent::AdjustPeerScore {
                peer_id,
                adjust_by,
                reason: _,
                response_sender: _,
            } => PeerManagerEventDesc::AdjustPeerScore {
                peer_id: *peer_id,
                score: *adjust_by,
            },
            PeerManagerEvent::NewTipReceived { peer_id, block_id } => {
                PeerManagerEventDesc::NewTipReceived {
                    peer_id: *peer_id,
                    block_id: *block_id,
                }
            }
            PeerManagerEvent::NewChainstateTip(block_id) => {
                PeerManagerEventDesc::NewChainstateTip(*block_id)
            }
            PeerManagerEvent::NewValidTransactionReceived { peer_id, txid } => {
                PeerManagerEventDesc::NewValidTransactionReceived {
                    peer_id: *peer_id,
                    txid: *txid,
                }
            }
            PeerManagerEvent::PeerBlockSyncStatusUpdate {
                peer_id,
                new_status: _,
            } => PeerManagerEventDesc::PeerBlockSyncStatusUpdate { peer_id: *peer_id },
            PeerManagerEvent::GetReserved(_) => PeerManagerEventDesc::GetReserved,
            PeerManagerEvent::AddReserved(addr, _) => {
                PeerManagerEventDesc::AddReserved(addr.clone())
            }
            PeerManagerEvent::RemoveReserved(addr, _) => {
                PeerManagerEventDesc::RemoveReserved(addr.clone())
            }
            PeerManagerEvent::ListBanned(_) => PeerManagerEventDesc::ListBanned,
            PeerManagerEvent::Ban(addr, duration, _) => PeerManagerEventDesc::Ban(*addr, *duration),
            PeerManagerEvent::Unban(addr, _) => PeerManagerEventDesc::Unban(*addr),
            PeerManagerEvent::ListDiscouraged(_) => PeerManagerEventDesc::ListDiscouraged,
            PeerManagerEvent::Undiscourage(addr, _) => PeerManagerEventDesc::Undiscourage(*addr),
            PeerManagerEvent::EnableNetworking {
                enable,
                response_sender: _,
            } => PeerManagerEventDesc::EnableNetworking { enable: *enable },
            PeerManagerEvent::GenericQuery(_) => PeerManagerEventDesc::GenericQuery,
            PeerManagerEvent::GenericMut(_) => PeerManagerEventDesc::GenericMut,
        }
    }
}

/// A networking service stub.
///
/// This type should never be used directly and its only purpose is to be used as a generic
/// parameter in the sync manager tests.
#[derive(Debug)]
struct NetworkingServiceStub {}

#[async_trait]
impl NetworkingService for NetworkingServiceStub {
    type Transport = TcpTransportSocket;
    type ConnectivityHandle = ();
    type MessagingHandle = MessagingHandleMock;
    type SyncingEventReceiver = SyncingEventReceiverMock;

    async fn start(
        _: bool,
        _: Self::Transport,
        _: Vec<SocketAddress>,
        _: Arc<ChainConfig>,
        _: Arc<P2pConfig>,
        _: TimeGetter,
        _: Arc<SeqCstAtomicBool>,
        _: oneshot::Receiver<()>,
        _: mpsc::UnboundedReceiver<P2pEventHandler>,
    ) -> Result<(
        Self::ConnectivityHandle,
        Self::MessagingHandle,
        Self::SyncingEventReceiver,
        JoinHandle<()>,
    )> {
        panic!("Stub service shouldn't be used directly");
    }
}

#[derive(Clone)]
struct MessagingHandleMock {
    block_sync_msg_sender: UnboundedSender<(PeerId, BlockSyncMessage)>,
    transaction_sync_msg_sender: UnboundedSender<(PeerId, TransactionSyncMessage)>,
}

impl MessagingService for MessagingHandleMock {
    fn send_block_sync_message(&mut self, peer: PeerId, message: BlockSyncMessage) -> Result<()> {
        self.block_sync_msg_sender.send((peer, message)).unwrap();
        Ok(())
    }

    fn send_transaction_sync_message(
        &mut self,
        peer: PeerId,
        message: TransactionSyncMessage,
    ) -> Result<()> {
        self.transaction_sync_msg_sender.send((peer, message)).unwrap();
        Ok(())
    }
}

struct SyncingEventReceiverMock {
    events_receiver: UnboundedReceiver<SyncingEvent>,
}

#[async_trait]
impl SyncingEventReceiver for SyncingEventReceiverMock {
    async fn poll_next(&mut self) -> Result<SyncingEvent> {
        expect_future_val!(self.events_receiver.recv()).ok_or(P2pError::ChannelClosed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncManagerNotification {
    NewTxSyncManagerMainLoopIteration { peer_id: PeerId },
}

#[derive(Clone)]
pub struct SyncManagerObserver {
    notification_sender: UnboundedSender<SyncManagerNotification>,
}

impl SyncManagerObserver {
    pub fn new(notification_sender: UnboundedSender<SyncManagerNotification>) -> Self {
        Self {
            notification_sender,
        }
    }

    fn send_notification(&self, notification: SyncManagerNotification) {
        let send_result = self.notification_sender.send(notification.clone());

        if let Err(err) = send_result {
            log::warn!("Error sending sync manager notification {notification:?}: {err}");
        }
    }
}

impl Observer for SyncManagerObserver {
    fn on_new_transaction_sync_mgr_main_loop_iteration(&mut self, peer_id: PeerId) {
        self.send_notification(SyncManagerNotification::NewTxSyncManagerMainLoopIteration {
            peer_id,
        });
    }
}

pub fn make_new_block(
    chain_config: &ChainConfig,
    prev_block: Option<&Block>,
    time_getter: &TimeGetter,
    rng: &mut impl Rng,
) -> Block {
    let random_bytes = get_random_bytes(rng);
    let timestamp = BlockTimestamp::from_time(time_getter.get_time());

    let input = match prev_block {
        None => common::chain::OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
        Some(block) => {
            let tx = block.transactions()[0].clone();
            let tx_id = tx.transaction().get_id();
            common::chain::OutPointSourceId::Transaction(tx_id)
        }
    };

    let input = TxInput::from_utxo(input, 0);
    let output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(100000)),
        Destination::AnyoneCanSpend,
    );
    let transaction = Transaction::new(0, vec![input], vec![output]).unwrap();
    let witness = InputWitness::NoSignature(Some(random_bytes));
    let signed_transaction = SignedTransaction::new(transaction, vec![witness]).unwrap();

    let prev_block_id: Id<GenBlock> = prev_block.map_or(chain_config.genesis_block_id(), |block| {
        block.header().block_id().into()
    });

    Block::new(
        vec![signed_transaction],
        prev_block_id,
        timestamp,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap()
}

pub fn make_new_blocks(
    chain_config: &ChainConfig,
    prev_block: Option<&Block>,
    time_getter: &TimeGetter,
    count: usize,
    rng: &mut impl Rng,
) -> Vec<Block> {
    let mut result = Vec::new();
    let mut last_block = prev_block;

    for _ in 0..count {
        let new_block = make_new_block(chain_config, last_block, time_getter, rng);

        result.push(new_block);
        last_block = result.last();
    }

    result
}

/// Create the specified number of blocks on top of the current best block asynchronously.
///
/// Note: normally, this function should not be used to create initial blocks, because there is
/// no guarantee on how fast the "new tip" event will reach the p2p subsystem. So, your test
/// will be expecting the test node not to be in the initial block download state, while it
/// actually still may be in that state.
pub async fn make_new_top_blocks_return_headers(
    chainstate: &ChainstateHandle,
    time_getter: TimeGetter,
    rng: &mut impl Rng,
    start_distance_from_top: u64,
    count: usize,
) -> Vec<SignedBlockHeader> {
    assert!(count > 0);

    let new_rng = test_utils::random::make_seedable_rng(Seed::from_u64(rng.gen()));

    chainstate
        .call_mut(move |this| {
            let mut new_rng = new_rng;
            let mut block_headers = Vec::new();
            let start_height = this
                .get_best_block_height()
                .unwrap()
                .into_int()
                .saturating_sub(start_distance_from_top);
            let start_block_id =
                this.get_block_id_from_height(start_height.into()).unwrap().unwrap();
            let mut last_block = match start_block_id.classify(this.get_chain_config()) {
                common::chain::GenBlockId::Genesis(_) => None,
                common::chain::GenBlockId::Block(id) => this.get_block(&id).unwrap(),
            };

            for _ in 0..count {
                let new_block = make_new_block(
                    this.get_chain_config(),
                    last_block.as_ref(),
                    &time_getter,
                    &mut new_rng,
                );

                block_headers.push(new_block.header().clone());
                this.process_block(new_block.clone(), BlockSource::Local).unwrap();
                last_block = Some(new_block);
            }

            block_headers
        })
        .await
        .unwrap()
}

/// A wrapper for make_new_top_blocks_return_headers.
///
/// Avoid using this function to create initial blocks.
// TODO: need better naming to distinguish between make_new_top_blocks..., which are async,
// and the synchronous make_new_blocks.
pub async fn make_new_top_blocks(
    chainstate: &ChainstateHandle,
    time_getter: TimeGetter,
    rng: &mut impl Rng,
    start_distance_from_top: u64,
    count: usize,
) -> Id<Block> {
    let headers = make_new_top_blocks_return_headers(
        chainstate,
        time_getter,
        rng,
        start_distance_from_top,
        count,
    )
    .await;
    headers.last().unwrap().block_id()
}

pub fn get_random_hash(rng: &mut impl Rng) -> H256 {
    let mut bytes: [u8; 32] = [0; 32];
    rng.fill_bytes(&mut bytes);
    bytes.into()
}

pub fn get_random_bytes(rng: &mut impl Rng) -> Vec<u8> {
    get_random_hash(rng).as_bytes().to_vec()
}
