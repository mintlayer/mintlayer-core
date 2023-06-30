// Copyright (c) 2022 RBB S.r.l
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
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    panic,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use crypto::random::Rng;
use itertools::Itertools;
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
    ChainstateHandle, DefaultTransactionVerificationStrategy,
};
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        config::create_mainnet,
        signature::inputsig::InputWitness,
        tokens::OutputValue,
        Block, ChainConfig, Destination, GenBlock, SignedTransaction, Transaction, TxInput,
        TxOutput,
    },
    primitives::{Amount, Id, Idable, H256},
    time_getter::TimeGetter,
};
use mempool::{MempoolHandle, MempoolSubsystemInterface};
use subsystem::manager::{ManagerJoinHandle, ShutdownTrigger};
use utils::atomics::SeqCstAtomicBool;

use crate::{
    config::NodeType,
    message::{SyncMessage, TransactionResponse},
    net::{default_backend::transport::TcpTransportSocket, types::SyncingEvent},
    sync::{subscribe_to_new_tip, BlockSyncManager},
    testing_utils::test_p2p_config,
    types::peer_id::PeerId,
    MessagingService, NetworkingService, P2pConfig, P2pError, P2pEventHandler, PeerManagerEvent,
    Result, SyncingEventReceiver,
};

/// A timeout for blocking calls.
const LONG_TIMEOUT: Duration = Duration::from_secs(60);
/// A short timeout for events that shouldn't occur.
const SHORT_TIMEOUT: Duration = Duration::from_millis(500);

/// A wrapper over other ends of the sync manager channels.
///
/// Provides methods for manipulating and observing the sync manager state.
pub struct SyncManagerHandle {
    pub peer_id: PeerId,
    peer_manager_receiver: UnboundedReceiver<PeerManagerEvent<NetworkingServiceStub>>,
    sync_event_sender: UnboundedSender<SyncingEvent>,
    sync_event_receiver: UnboundedReceiver<(PeerId, SyncMessage)>,
    error_receiver: UnboundedReceiver<P2pError>,
    sync_manager_handle: JoinHandle<()>,
    shutdown_trigger: ShutdownTrigger,
    subsystem_manager_handle: ManagerJoinHandle,
    chainstate_handle: ChainstateHandle,
    _new_tip_receiver: UnboundedReceiver<Id<Block>>,
    connected_peers: Arc<Mutex<BTreeMap<PeerId, Sender<SyncMessage>>>>,
}

impl SyncManagerHandle {
    /// Starts the sync manager event loop and returns a handle for manipulating and observing the
    /// manager state.
    pub async fn start() -> Self {
        Self::builder().build().await
    }

    pub fn builder() -> SyncManagerHandleBuilder {
        SyncManagerHandleBuilder::new()
    }

    pub async fn start_with_params(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        shutdown_trigger: ShutdownTrigger,
        subsystem_manager_handle: ManagerJoinHandle,
        time_getter: TimeGetter,
    ) -> Self {
        let (peer_manager_sender, peer_manager_receiver) = mpsc::unbounded_channel();
        let connected_peers = Default::default();

        let (messaging_sender, handle_receiver) = mpsc::unbounded_channel();
        let (handle_sender, messaging_receiver) = mpsc::unbounded_channel();
        let messaging_handle = MessagingHandleMock {
            events_sender: messaging_sender,
            connected_peers: Arc::clone(&connected_peers),
        };
        let sync_event_receiver = SyncingEventReceiverMock {
            events_receiver: messaging_receiver,
        };

        let mut sync = BlockSyncManager::new(
            chain_config,
            p2p_config,
            messaging_handle,
            sync_event_receiver,
            chainstate_handle.clone(),
            mempool_handle,
            peer_manager_sender,
            time_getter,
        );

        let (error_sender, error_receiver) = mpsc::unbounded_channel();
        let sync_manager_handle = tokio::spawn(async move {
            let e = sync.run().await.unwrap_err();
            let _ = error_sender.send(e);
        });

        let new_tip_receiver = subscribe_to_new_tip(&chainstate_handle).await.unwrap();

        Self {
            peer_id: PeerId::new(),
            peer_manager_receiver,
            sync_event_sender: handle_sender,
            sync_event_receiver: handle_receiver,
            error_receiver,
            sync_manager_handle,
            shutdown_trigger,
            subsystem_manager_handle,
            chainstate_handle,
            _new_tip_receiver: new_tip_receiver,
            connected_peers,
        }
    }

    pub fn chainstate(&self) -> &ChainstateHandle {
        &self.chainstate_handle
    }

    /// Sends the `SyncControlEvent::Connected` event without checking outgoing messages.
    pub fn try_connect_peer(&mut self, peer: PeerId) {
        let (sync_tx, sync_rx) = mpsc::channel(20);
        self.sync_event_sender
            .send(SyncingEvent::Connected {
                peer_id: peer,
                services: NodeType::Full.into(),
                sync_rx,
            })
            .unwrap();
        self.connected_peers.lock().unwrap().insert(peer, sync_tx);
    }

    /// Connects a peer and checks that the header list request is sent to that peer.
    pub async fn connect_peer(&mut self, peer: PeerId) {
        self.try_connect_peer(peer);

        let (sent_to, message) = self.message().await;
        assert_eq!(peer, sent_to);
        assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    }

    /// Sends the `SyncControlEvent::Disconnected` event.
    pub fn disconnect_peer(&mut self, peer: PeerId) {
        self.sync_event_sender
            .send(SyncingEvent::Disconnected { peer_id: peer })
            .unwrap();
        self.connected_peers.lock().unwrap().remove(&peer);
    }

    /// Sends an announcement to the sync manager.
    pub async fn send_message(&mut self, peer: PeerId, message: SyncMessage) {
        let sync_tx = self.connected_peers.lock().unwrap().get(&peer).unwrap().clone();
        sync_tx.send(message).await.unwrap();
    }

    /// Receives a message from the sync manager.
    pub async fn message(&mut self) -> (PeerId, SyncMessage) {
        time::timeout(LONG_TIMEOUT, self.sync_event_receiver.recv())
            .await
            .expect("Failed to receive event in time")
            .unwrap()
    }

    /// Panics if the sync manager returns an error.
    pub async fn assert_no_error(&mut self) {
        time::timeout(SHORT_TIMEOUT, self.error_receiver.recv()).await.unwrap_err();
    }

    /// Receives the `AdjustPeerScore` event from the peer manager.
    pub async fn adjust_peer_score_event(&mut self) -> (PeerId, u32) {
        match self.peer_manager_receiver.recv().await.unwrap() {
            PeerManagerEvent::AdjustPeerScore(peer, score, sender) => {
                sender.send(Ok(()));
                (peer, score)
            }
            e => panic!("Unexpected peer manager event: {e:?}"),
        }
    }

    pub async fn assert_disconnect_peer_event(&mut self, id: PeerId) {
        match self.peer_manager_receiver.recv().await.unwrap() {
            PeerManagerEvent::Disconnect(peer_id, sender) => {
                assert_eq!(id, peer_id);
                sender.send(Ok(()));
            }
            e => panic!("Expected PeerManagerEvent::Disconnect, received: {e:?}"),
        }
    }

    pub async fn assert_no_disconnect_peer_event(&mut self, id: PeerId) {
        time::timeout(SHORT_TIMEOUT, async {
            loop {
                match self.peer_manager_receiver.recv().await.unwrap() {
                    PeerManagerEvent::Disconnect(peer_id, _) if id == peer_id => {
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap_err();
    }

    /// Panics if there is an event from the peer manager.
    pub async fn assert_no_peer_manager_event(&mut self) {
        time::timeout(SHORT_TIMEOUT, self.peer_manager_receiver.recv())
            .await
            .unwrap_err();
    }

    /// Panics if the sync manager sends an event (message or announcement).
    pub async fn assert_no_event(&mut self) {
        time::timeout(SHORT_TIMEOUT, self.sync_event_receiver.recv()).await.unwrap_err();
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
        drop(self.sync_event_sender);
        let _ = self.sync_manager_handle.await;

        // Shutdown remaining subsystems
        self.shutdown_trigger.initiate();
        self.subsystem_manager_handle.join().await;

        // Finally, when all services are down, receivers could be closed too
        drop(self.sync_event_receiver);
        drop(self.error_receiver);
        drop(self.peer_manager_receiver);
    }
}

pub async fn sync_managers_in_sync(managers: &[&mut SyncManagerHandle]) -> bool {
    let best_blocks = futures::future::join_all(managers.iter().map(|manager| async {
        manager
            .chainstate()
            .call(|this| this.get_best_block_id().unwrap())
            .await
            .unwrap()
    }))
    .await;
    best_blocks.iter().tuple_windows().all(|(l, r)| l == r)
}

pub async fn try_sync_managers_once(
    rng: &mut impl Rng,
    managers: &mut [&mut SyncManagerHandle],
    message_limit: usize,
) -> bool {
    let peer_ids = managers.iter().map(|mng| mng.peer_id).collect::<Vec<_>>();
    for manager in managers.iter_mut() {
        let sender_peer_id = manager.peer_id;

        // Request a non-existent transaction to ensure that the event loop has a chance to process all pending requests
        let tx_peer_id = *peer_ids.iter().find(|peer_id| **peer_id != sender_peer_id).unwrap();
        let requested_txid = get_random_hash(rng).into();
        manager
            .send_message(tx_peer_id, SyncMessage::TransactionRequest(requested_txid))
            .await;

        if let Ok(peer_event) = manager.peer_manager_receiver.try_recv() {
            // There should be no peer scoring or disconnections
            panic!("Unexpected message: {peer_event:?}");
        }

        for _ in 0..message_limit {
            let (peer, sync_event) = manager.sync_event_receiver.recv().await.unwrap();

            // Send sync messages between peers
            match &sync_event {
                SyncMessage::TransactionResponse(tx_resp) => match tx_resp {
                    TransactionResponse::NotFound(txid) if *txid == requested_txid => {
                        break;
                    }
                    _ => {}
                },
                message => {
                    let other_manager = managers.iter_mut().find(|m| m.peer_id == peer).unwrap();
                    let sync_tx = other_manager
                        .connected_peers
                        .lock()
                        .unwrap()
                        .get(&sender_peer_id)
                        .unwrap()
                        .clone();
                    sync_tx.send(message.clone()).await.unwrap();
                    return true;
                }
            }
        }
    }

    false
}

pub async fn sync_managers(rng: &mut impl Rng, managers: &mut [&mut SyncManagerHandle]) {
    let sync_managers_helper = async move {
        while !sync_managers_in_sync(managers).await {
            while try_sync_managers_once(rng, managers, usize::MAX).await {}
        }
    };

    tokio::time::timeout(Duration::from_secs(60), sync_managers_helper)
        .await
        .unwrap();
}

pub struct SyncManagerHandleBuilder {
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate: Option<Box<dyn ChainstateInterface>>,
    time_getter: TimeGetter,
    blocks: Vec<Block>,
}

impl SyncManagerHandleBuilder {
    pub fn new() -> Self {
        Self {
            chain_config: Arc::new(create_mainnet()),
            p2p_config: Arc::new(test_p2p_config()),
            chainstate: None,
            time_getter: TimeGetter::default(),
            blocks: Vec::new(),
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

    pub async fn build(self) -> SyncManagerHandle {
        let SyncManagerHandleBuilder {
            chain_config,
            p2p_config,
            chainstate,
            time_getter,
            blocks,
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

        SyncManagerHandle::start_with_params(
            chain_config,
            p2p_config,
            chainstate.clone(),
            mempool,
            shutdown_trigger,
            manager_handle,
            time_getter,
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
    type Address = SocketAddr;
    type BannableAddress = IpAddr;
    type ConnectivityHandle = ();
    type MessagingHandle = MessagingHandleMock;
    type SyncingEventReceiver = SyncingEventReceiverMock;

    async fn start(
        _: Self::Transport,
        _: Vec<Self::Address>,
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
    events_sender: UnboundedSender<(PeerId, SyncMessage)>,
    connected_peers: Arc<Mutex<BTreeMap<PeerId, Sender<SyncMessage>>>>,
}
struct SyncingEventReceiverMock {
    events_receiver: UnboundedReceiver<SyncingEvent>,
}

impl MessagingService for MessagingHandleMock {
    fn send_message(&mut self, peer: PeerId, message: SyncMessage) -> Result<()> {
        self.events_sender.send((peer, message)).unwrap();
        Ok(())
    }

    fn broadcast_message(&mut self, message: SyncMessage) -> Result<()> {
        for peer_id in self.connected_peers.lock().unwrap().keys() {
            self.events_sender.send((*peer_id, message.clone())).unwrap();
        }
        Ok(())
    }
}

#[async_trait]
impl SyncingEventReceiver for SyncingEventReceiverMock {
    async fn poll_next(&mut self) -> Result<SyncingEvent> {
        time::timeout(LONG_TIMEOUT, self.events_receiver.recv())
            .await
            .expect("Failed to receive event in time")
            .ok_or(P2pError::ChannelClosed)
    }
}

pub fn new_block(
    chain_config: &ChainConfig,
    prev_block: Option<&Block>,
    timestamp: BlockTimestamp,
    random_bytes: Vec<u8>,
) -> Block {
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

pub async fn new_top_blocks(
    chainstate: &ChainstateHandle,
    timestamp: BlockTimestamp,
    random_bytes: Vec<u8>,
    start_distance_from_top: u64,
    count: u32,
) {
    chainstate
        .call_mut(move |this| {
            let start_height = this
                .get_best_block_height()
                .unwrap()
                .into_int()
                .saturating_sub(start_distance_from_top);
            let start_block_id =
                this.get_block_id_from_height(&start_height.into()).unwrap().unwrap();
            let mut start_block = match start_block_id.classify(this.get_chain_config()) {
                common::chain::GenBlockId::Genesis(_) => None,
                common::chain::GenBlockId::Block(id) => this.get_block(id).unwrap(),
            };

            for _ in 0..count {
                let new_block = new_block(
                    this.get_chain_config(),
                    start_block.as_ref(),
                    timestamp,
                    random_bytes.clone(),
                );

                this.process_block(new_block.clone(), BlockSource::Local).unwrap();

                start_block = Some(new_block);
            }
        })
        .await
        .unwrap();
}

pub fn get_random_hash(rng: &mut impl Rng) -> H256 {
    let mut bytes: [u8; 32] = [0; 32];
    rng.fill_bytes(&mut bytes);
    bytes.into()
}

pub fn get_random_bytes(rng: &mut impl Rng) -> Vec<u8> {
    get_random_hash(rng).as_bytes().to_vec()
}
