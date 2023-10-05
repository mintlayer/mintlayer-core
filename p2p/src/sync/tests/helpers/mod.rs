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

use std::{collections::BTreeMap, panic, sync::Arc};

use async_trait::async_trait;
use crypto::random::Rng;
use p2p_test_utils::{expect_future_val, expect_no_recv, expect_recv, SHORT_TIMEOUT};
use p2p_types::socket_address::SocketAddress;
use test_utils::random::Seed;
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
        config::create_mainnet,
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        Block, ChainConfig, Destination, GenBlock, SignedTransaction, Transaction, TxInput,
        TxOutput,
    },
    primitives::{Amount, BlockHeight, Id, Idable, H256},
    time_getter::TimeGetter,
};
use mempool::{MempoolHandle, MempoolSubsystemInterface};
use subsystem::manager::{ManagerJoinHandle, ShutdownTrigger};
use utils::atomics::SeqCstAtomicBool;

use crate::{
    message::{HeaderList, SyncMessage},
    net::{default_backend::transport::TcpTransportSocket, types::SyncingEvent},
    protocol::{choose_common_protocol_version, ProtocolVersion},
    sync::{subscribe_to_new_tip, BlockSyncManager},
    testing_utils::test_p2p_config,
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
    sync_msg_receiver: UnboundedReceiver<(PeerId, SyncMessage)>,
    error_receiver: UnboundedReceiver<P2pError>,
    sync_manager_handle: JoinHandle<()>,
    shutdown_trigger: ShutdownTrigger,
    subsystem_manager_handle: ManagerJoinHandle,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    _new_tip_receiver: UnboundedReceiver<Id<Block>>,
    connected_peers: BTreeMap<PeerId, Sender<SyncMessage>>,
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
        let connected_peers = Default::default();

        let (sync_msg_sender, sync_msg_receiver) = mpsc::unbounded_channel();
        let (syncing_event_sender, syncing_event_receiver) = mpsc::unbounded_channel();
        let messaging_handle = MessagingHandleMock { sync_msg_sender };
        let syncing_event_receiver_mock = SyncingEventReceiverMock {
            events_receiver: syncing_event_receiver,
        };

        let sync_manager = BlockSyncManager::<NetworkingServiceStub>::new(
            chain_config,
            Arc::clone(&p2p_config),
            messaging_handle,
            syncing_event_receiver_mock,
            chainstate_handle.clone(),
            mempool_handle.clone(),
            peer_manager_event_sender,
            time_getter,
        );

        let sync_manager_chanstate_handle = sync_manager.chainstate().clone();

        let (error_sender, error_receiver) = mpsc::unbounded_channel();
        let sync_manager_handle = logging::spawn_in_current_span(async move {
            let e = sync_manager.run().await.unwrap_err();
            let _ = error_sender.send(e);
        });

        let new_tip_receiver = subscribe_to_new_tip(&sync_manager_chanstate_handle).await.unwrap();

        Self {
            peer_id: PeerId::new(),
            p2p_config,
            peer_manager_event_receiver,
            syncing_event_sender,
            sync_msg_receiver,
            error_receiver,
            sync_manager_handle,
            shutdown_trigger,
            subsystem_manager_handle,
            chainstate_handle,
            mempool_handle,
            _new_tip_receiver: new_tip_receiver,
            connected_peers,
            protocol_version,
        }
    }

    pub fn chainstate(&self) -> &ChainstateHandle {
        &self.chainstate_handle
    }

    pub fn mempool(&self) -> &MempoolHandle {
        &self.mempool_handle
    }

    /// Sends the `SyncControlEvent::Connected` event without checking outgoing messages.
    pub fn try_connect_peer(&mut self, peer_id: PeerId, protocol_version: ProtocolVersion) {
        let (sync_msg_tx, sync_msg_rx) = mpsc::channel(20);
        let common_protocol_version =
            choose_common_protocol_version(self.protocol_version, protocol_version).unwrap();
        self.syncing_event_sender
            .send(SyncingEvent::Connected {
                peer_id,
                common_services: (*self.p2p_config.node_type).into(),
                protocol_version: common_protocol_version,
                sync_msg_rx,
            })
            .unwrap();
        self.connected_peers.insert(peer_id, sync_msg_tx);
    }

    /// Connects a peer and checks that the header list request is sent to that peer.
    pub async fn connect_peer(&mut self, peer: PeerId, protocol_version: ProtocolVersion) {
        self.try_connect_peer(peer, protocol_version);

        let (sent_to, message) = self.message().await;
        assert_eq!(peer, sent_to);
        assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    }

    /// Sends the `SyncControlEvent::Disconnected` event.
    pub fn disconnect_peer(&mut self, peer_id: PeerId) {
        self.syncing_event_sender.send(SyncingEvent::Disconnected { peer_id }).unwrap();
        self.connected_peers.remove(&peer_id);
    }

    // TODO: naming of methods in this struct should be reconsidered.
    // E.g. message, try_message, adjust_peer_score_event should at least get a prefix like
    // "get", "receive" etc.
    // Secondly, send_message and send_headers should be named more specifically, e.g.
    // "send_message_as_if_from" to indicate that they "send" a message to the current node
    // and not from it.
    // Also, methods dealing with SyncMessage's should probably have "sync" in their name.

    /// Sends an announcement to the sync manager.
    pub async fn send_message(&mut self, peer: PeerId, message: SyncMessage) {
        let sync_tx = self.connected_peers.get(&peer).unwrap().clone();
        sync_tx.send(message).await.unwrap();
    }

    /// Receives a message from the sync manager.
    pub async fn message(&mut self) -> (PeerId, SyncMessage) {
        expect_recv!(self.sync_msg_receiver)
    }

    /// Try to receive a message from the sync manager.
    pub fn try_message(&mut self) -> Option<(PeerId, SyncMessage)> {
        match self.sync_msg_receiver.try_recv() {
            Ok(message) => Some(message),
            Err(mpsc::error::TryRecvError::Empty) => None,
            Err(mpsc::error::TryRecvError::Disconnected) => panic!("Failed to receive event"),
        }
    }

    /// Send the specified headers.
    pub async fn send_headers(&mut self, peer: PeerId, headers: Vec<SignedBlockHeader>) {
        self.send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers))).await;
    }

    /// Panics if the sync manager returns an error.
    pub async fn assert_no_error(&mut self) {
        expect_no_recv!(self.error_receiver);
    }

    /// Receives the `AdjustPeerScore` event from the peer manager.
    pub async fn adjust_peer_score_event(&mut self) -> (PeerId, u32) {
        match self.peer_manager_event_receiver.recv().await.unwrap() {
            PeerManagerEvent::AdjustPeerScore(peer, score, sender) => {
                sender.send(Ok(()));
                (peer, score)
            }
            e => panic!("Unexpected peer manager event: {e:?}"),
        }
    }

    pub async fn assert_disconnect_peer_event(&mut self, id: PeerId) {
        match self.peer_manager_event_receiver.recv().await.unwrap() {
            PeerManagerEvent::Disconnect(peer_id, _peerdb_action, sender) => {
                assert_eq!(id, peer_id);
                sender.send(Ok(()));
            }
            e => panic!("Expected PeerManagerEvent::Disconnect, received: {e:?}"),
        }
    }

    pub async fn assert_no_disconnect_peer_event(&mut self, id: PeerId) {
        time::timeout(SHORT_TIMEOUT, async {
            loop {
                match self.peer_manager_event_receiver.recv().await.unwrap() {
                    PeerManagerEvent::Disconnect(peer_id, _peerdb_action, _) if id == peer_id => {
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap_err();
    }

    /// Panics if there is an event from the peer manager (except for the NewTipReceived/NewValidTransactionReceived messages)
    // TODO: Rename the function
    pub async fn assert_no_peer_manager_event(&mut self) {
        time::timeout(SHORT_TIMEOUT, async {
            loop {
                let peer_event = self.peer_manager_event_receiver.recv().await.unwrap();
                match peer_event {
                    PeerManagerEvent::Connect(_, _)
                    | PeerManagerEvent::Disconnect(_, _, _)
                    | PeerManagerEvent::GetPeerCount(_)
                    | PeerManagerEvent::GetBindAddresses(_)
                    | PeerManagerEvent::GetConnectedPeers(_)
                    | PeerManagerEvent::AdjustPeerScore(_, _, _)
                    | PeerManagerEvent::AddReserved(_, _)
                    | PeerManagerEvent::RemoveReserved(_, _)
                    | PeerManagerEvent::ListBanned(_)
                    | PeerManagerEvent::Ban(_, _)
                    | PeerManagerEvent::Unban(_, _) => {
                        panic!("Unexpected peer manager event: {peer_event:?}");
                    }
                    PeerManagerEvent::NewTipReceived { .. }
                    | PeerManagerEvent::NewValidTransactionReceived { .. } => {
                        // Ignored
                    }
                }
            }
        })
        .await
        .unwrap_err();
    }

    /// Panics if the sync manager sends an event (message or announcement).
    pub async fn assert_no_event(&mut self) {
        time::timeout(SHORT_TIMEOUT, self.sync_msg_receiver.recv()).await.unwrap_err();
    }

    pub async fn assert_peer_score_adjustment(
        &mut self,
        expected_peer: PeerId,
        expected_score: u32,
    ) {
        let (adjusted_peer, score) = self.adjust_peer_score_event().await;
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
        drop(self.sync_msg_receiver);
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
}

pub struct TestNodeBuilder {
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate: Option<Box<dyn ChainstateInterface>>,
    time_getter: TimeGetter,
    blocks: Vec<Block>,
    protocol_version: ProtocolVersion,
}

impl TestNodeBuilder {
    pub fn new(protocol_version: ProtocolVersion) -> Self {
        Self {
            chain_config: Arc::new(create_mainnet()),
            p2p_config: Arc::new(test_p2p_config()),
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

    pub fn with_chainstate(mut self, chainstate: Box<dyn ChainstateInterface>) -> Self {
        self.chainstate = Some(chainstate);
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
            p2p_config,
            chainstate,
            time_getter,
            blocks,
            protocol_version,
        } = self;

        let mut manager = subsystem::Manager::new("p2p-sync-test-manager");
        let shutdown_trigger = manager.make_shutdown_trigger();

        let mut chainstate = chainstate.unwrap_or_else(|| {
            make_chainstate(
                Arc::clone(&chain_config),
                ChainstateConfig::new(),
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

        let mempool = mempool::make_mempool(
            Arc::clone(&chain_config),
            chainstate.clone(),
            time_getter.clone(),
        );
        let mempool = manager.add_subsystem_with_custom_eventloop("p2p-sync-test-mempool", {
            move |call, shutdn| mempool.run(call, shutdn)
        });

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
    sync_msg_sender: UnboundedSender<(PeerId, SyncMessage)>,
}

impl MessagingService for MessagingHandleMock {
    fn send_message(&mut self, peer: PeerId, message: SyncMessage) -> Result<()> {
        self.sync_msg_sender.send((peer, message)).unwrap();
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
                this.get_block_id_from_height(&start_height.into()).unwrap().unwrap();
            let mut last_block = match start_block_id.classify(this.get_chain_config()) {
                common::chain::GenBlockId::Genesis(_) => None,
                common::chain::GenBlockId::Block(id) => this.get_block(id).unwrap(),
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
