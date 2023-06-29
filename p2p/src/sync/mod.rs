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

//! This module is responsible for both initial syncing and further blocks processing (the reaction
//! to block announcement from peers and the announcement of blocks produced by this node).

mod peer;
mod types;

use std::collections::HashMap;

use futures::never::Never;
use tokio::{
    sync::mpsc::{self, Receiver, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use chainstate::{chainstate_interface::ChainstateInterface, ChainstateHandle};
use common::{
    chain::{block::Block, config::ChainConfig},
    primitives::Id,
    time_getter::TimeGetter,
};
use logging::log;
use mempool::{event::OrphanProcessed, MempoolHandle, TxOrigin};
use utils::atomics::AcqRelAtomicBool;
use utils::sync::Arc;
use utils::tap_error_log::LogError;

use crate::{
    config::P2pConfig,
    error::P2pError,
    message::{HeaderList, SyncMessage},
    net::{
        types::{services::Services, SyncingEvent},
        MessagingService, NetworkingService, SyncingEventReceiver,
    },
    sync::peer::Peer,
    types::peer_id::PeerId,
    PeerManagerEvent, Result,
};

/// Sync manager is responsible for syncing the local blockchain to the chain with most trust
/// and keeping up with updates to different branches of the blockchain.
pub struct BlockSyncManager<T: NetworkingService> {
    /// The chain configuration.
    chain_config: Arc<ChainConfig>,

    /// The p2p configuration.
    p2p_config: Arc<P2pConfig>,

    messaging_handle: T::MessagingHandle,
    sync_event_receiver: T::SyncingEventReceiver,

    /// A sender for the peer manager events.
    peer_manager_sender: UnboundedSender<PeerManagerEvent<T>>,

    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    mempool_handle: MempoolHandle,

    /// A cached result of the `ChainstateInterface::is_initial_block_download` call.
    is_initial_block_download: Arc<AcqRelAtomicBool>,

    /// The list of connected peers
    peers: HashMap<PeerId, JoinHandle<()>>,

    time_getter: TimeGetter,
}

/// Syncing manager
impl<T> BlockSyncManager<T>
where
    T: NetworkingService + 'static,
    T::MessagingHandle: MessagingService,
    T::SyncingEventReceiver: SyncingEventReceiver,
{
    /// Creates a new sync manager instance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        messaging_handle: T::MessagingHandle,
        sync_event_receiver: T::SyncingEventReceiver,
        chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
        mempool_handle: MempoolHandle,
        peer_manager_sender: UnboundedSender<PeerManagerEvent<T>>,
        time_getter: TimeGetter,
    ) -> Self {
        Self {
            chain_config,
            p2p_config,
            messaging_handle,
            sync_event_receiver,
            peer_manager_sender,
            chainstate_handle,
            mempool_handle,
            is_initial_block_download: Arc::new(true.into()),
            peers: Default::default(),
            time_getter,
        }
    }

    /// Runs the sync manager event loop.
    pub async fn run(mut self) -> Result<Never> {
        log::info!("Starting SyncManager");

        let mut new_tip_receiver = subscribe_to_new_tip(&self.chainstate_handle).await?;
        self.is_initial_block_download.store(
            self.chainstate_handle
                .call(|c| c.is_initial_block_download())
                .await
                // This shouldn't fail unless the chainstate subsystem is down which shouldn't
                // happen since subsystems are shutdown in reverse order.
                .expect("Chainstate call failed")?,
        );

        let mut orphan_tx_processed_receiver =
            subscribe_to_orphan_tx_processed(&self.mempool_handle).await?;

        loop {
            tokio::select! {
                block_id = new_tip_receiver.recv() => {
                    // This error can only occur when chainstate drops an events subscriber.
                    let block_id = block_id.expect("New tip sender was closed");
                    self.handle_new_tip(block_id).await?;
                },

                orphan_proc = orphan_tx_processed_receiver.recv() => {
                    let orphan_proc = orphan_proc.expect("Orphan processed sender closed");
                    self.handle_orphan_processed(&orphan_proc)?;
                },

                event = self.sync_event_receiver.poll_next() => {
                    self.handle_peer_event(event?);
                },
            }
        }
    }

    /// Starts a task for the new peer.
    pub fn register_peer(
        &mut self,
        peer_id: PeerId,
        remote_services: Services,
        sync_rx: Receiver<SyncMessage>,
    ) {
        log::debug!("Register peer {peer_id} to sync manager");

        let mut peer = Peer::<T>::new(
            peer_id,
            remote_services,
            Arc::clone(&self.chain_config),
            Arc::clone(&self.p2p_config),
            self.chainstate_handle.clone(),
            self.mempool_handle.clone(),
            self.peer_manager_sender.clone(),
            sync_rx,
            self.messaging_handle.clone(),
            Arc::clone(&self.is_initial_block_download),
            self.time_getter.clone(),
        );
        let peer_task = tokio::spawn(async move {
            peer.run().await;
        });

        let prev_task = self.peers.insert(peer_id, peer_task);
        assert!(prev_task.is_none(), "Registered duplicated peer: {peer_id}");
    }

    /// Stops the task of the given peer by closing the corresponding channel.
    fn unregister_peer(&mut self, peer_id: PeerId) {
        log::debug!("Unregister peer {peer_id} from sync manager");
        let peer_task = self
            .peers
            .remove(&peer_id)
            .unwrap_or_else(|| panic!("Unregistering unknown peer: {peer_id}"));
        // Call `abort` because the peer task may be sleeping for a long time in the `sync_clock` function
        peer_task.abort();
    }

    /// Announces the header of a new block to peers.
    async fn handle_new_tip(&mut self, block_id: Id<Block>) -> Result<()> {
        let is_initial_block_download = if self.is_initial_block_download.load() {
            let is_ibd = self.chainstate_handle.call(|c| c.is_initial_block_download()).await??;
            self.is_initial_block_download.store(is_ibd);
            is_ibd
        } else {
            false
        };

        if is_initial_block_download {
            return Ok(());
        }

        let header = self
            .chainstate_handle
            .call(move |c| c.get_block_header(block_id))
            .await??
            // This should never happen because this block has just been produced by chainstate.
            .expect("A new tip block unavailable");

        log::debug!("Broadcasting a new tip header {}", header.block_id());
        self.messaging_handle
            .broadcast_message(SyncMessage::HeaderList(HeaderList::new(vec![header])))
    }

    fn handle_orphan_processed(&mut self, orphan_proc: &OrphanProcessed) -> Result<()> {
        let tx_id = *orphan_proc.tx_id();
        let origin = orphan_proc.origin();
        match orphan_proc.result() {
            Ok(()) => match origin {
                TxOrigin::Peer(_) | TxOrigin::LocalP2p => {
                    log::info!("Broadcasting former orphan {tx_id} originating in {origin}");
                    self.messaging_handle.broadcast_message(SyncMessage::NewTransaction(tx_id))?;
                }
                TxOrigin::LocalMempool | TxOrigin::PastBlock => {
                    log::trace!("Not propagating processed orphan {tx_id} originating in {origin}");
                }
            },
            Err(_) => match origin {
                TxOrigin::Peer(peer_id) => {
                    // Punish the original peer for submitting an invalid transaction according
                    // to mempool ban score.
                    let ban_score = orphan_proc.ban_score();
                    if ban_score > 0 {
                        let (sx, _rx) = crate::utils::oneshot_nofail::channel();
                        let event = PeerManagerEvent::AdjustPeerScore(peer_id, ban_score, sx);
                        self.peer_manager_sender
                            .send(event)
                            .map_err(|_| P2pError::ChannelClosed)?;
                    }
                }
                TxOrigin::PastBlock | TxOrigin::LocalMempool | TxOrigin::LocalP2p => (),
            },
        }
        Ok(())
    }

    /// Sends an event to the corresponding peer.
    fn handle_peer_event(&mut self, event: SyncingEvent) {
        match event {
            SyncingEvent::Connected {
                peer_id,
                services,
                sync_rx,
            } => self.register_peer(peer_id, services, sync_rx),
            SyncingEvent::Disconnected { peer_id } => self.unregister_peer(peer_id),
        }
    }
}

/// Returns a receiver for the chainstate `NewTip` events.
pub async fn subscribe_to_new_tip(
    chainstate_handle: &ChainstateHandle,
) -> Result<UnboundedReceiver<Id<Block>>> {
    let (sender, receiver) = mpsc::unbounded_channel();

    let subscribe_func =
        Arc::new(
            move |chainstate_event: chainstate::ChainstateEvent| match chainstate_event {
                chainstate::ChainstateEvent::NewTip(block_id, _) => {
                    let _ = sender.send(block_id).log_err_pfx("The new tip receiver closed");
                }
            },
        );

    chainstate_handle
        .call_mut(|this| this.subscribe_to_events(subscribe_func))
        .await
        .map_err(|_| P2pError::SubsystemFailure)?;

    Ok(receiver)
}

/// Returns a receiver for the mempool `OrphanProcessed` events.
pub async fn subscribe_to_orphan_tx_processed(
    mempool_handle: &MempoolHandle,
) -> Result<UnboundedReceiver<OrphanProcessed>> {
    let (sender, receiver) = mpsc::unbounded_channel();

    let subscribe_func =
        Arc::new(
            move |mempool_event: mempool::event::MempoolEvent| match mempool_event {
                mempool::event::MempoolEvent::OrphanProcessed(op) => {
                    let _ = sender.send(op).log_err_pfx("The orphan processed receiver closed");
                }
                mempool::event::MempoolEvent::NewTip(_) => (),
            },
        );

    mempool_handle
        .call_mut(|this| this.subscribe_to_events(subscribe_func))
        .await
        .map_err(|_| P2pError::SubsystemFailure)?;

    Ok(receiver)
}

/// Check the incoming transaction and propagate it to peer if it's valid
// TODO: Do we want to return the TxStatus?
pub async fn process_incoming_transaction(
    mempool: &MempoolHandle,
    messaging: &mut impl MessagingService,
    transaction: common::chain::SignedTransaction,
    origin: mempool::TxOrigin,
) -> Result<mempool::TxStatus> {
    use mempool::TxStatus;
    let tx_id = common::primitives::Idable::get_id(transaction.transaction());

    let status = mempool.call_mut(move |m| m.add_transaction(transaction, origin)).await??;
    match status {
        // Transaction accepted to local mempool, propagate it to the peers
        TxStatus::InMempool => messaging.broadcast_message(SyncMessage::NewTransaction(tx_id))?,
        // We don't know whether the orphan is valid, don't propagate at this point
        TxStatus::InOrphanPool => (),
    };

    Ok(status)
}

#[cfg(test)]
mod tests;
