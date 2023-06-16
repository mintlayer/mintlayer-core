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

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use futures::never::Never;
use tokio::{
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
    task::JoinHandle,
};

use chainstate::{chainstate_interface::ChainstateInterface, ChainstateHandle};
use common::{
    chain::{block::Block, config::ChainConfig},
    primitives::Id,
    time_getter::TimeGetter,
};
use logging::log;
use mempool::MempoolHandle;
use utils::tap_error_log::LogError;

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError},
    message::{HeaderList, SyncMessage},
    net::{
        types::{services::Services, SyncingEvent},
        MessagingService, NetworkingService, SyncingEventReceiver,
    },
    sync::peer::{Peer, PeerContext},
    types::peer_id::PeerId,
    PeerManagerEvent, Result,
};

/// Sync manager is responsible for syncing the local blockchain to the chain with most trust
/// and keeping up with updates to different branches of the blockchain.
pub struct BlockSyncManager<T: NetworkingService> {
    /// The chain configuration.
    _chain_config: Arc<ChainConfig>,

    /// The p2p configuration.
    p2p_config: Arc<P2pConfig>,

    messaging_handle: T::MessagingHandle,
    sync_event_receiver: T::SyncingEventReceiver,
    shutdown_receiver: oneshot::Receiver<()>,

    /// A sender for the peer manager events.
    peer_manager_sender: UnboundedSender<PeerManagerEvent<T>>,

    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    mempool_handle: MempoolHandle,

    /// A cached result of the `ChainstateInterface::is_initial_block_download` call.
    is_initial_block_download: Arc<AtomicBool>,

    /// A mapping from a peer identifier to the channel.
    peers: HashMap<PeerId, PeerContext>,

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
        shutdown_receiver: oneshot::Receiver<()>,
        chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
        mempool_handle: MempoolHandle,
        peer_manager_sender: UnboundedSender<PeerManagerEvent<T>>,
        time_getter: TimeGetter,
    ) -> Self {
        Self {
            _chain_config: chain_config,
            p2p_config,
            messaging_handle,
            sync_event_receiver,
            shutdown_receiver,
            peer_manager_sender,
            chainstate_handle,
            mempool_handle,
            is_initial_block_download: Arc::new(true.into()),
            peers: Default::default(),
            time_getter,
        }
    }

    /// Runs the sync manager event loop.
    pub async fn run(&mut self) -> Result<Never> {
        log::info!("Starting sync manager");

        let mut new_tip_receiver = subscribe_to_new_tip(&self.chainstate_handle).await?;
        self.is_initial_block_download.store(
            self.chainstate_handle
                .call(|c| c.is_initial_block_download())
                .await
                // This shouldn't fail unless the chainstate subsystem is down which shouldn't
                // happen since subsystems are shutdown in reverse order.
                .expect("Chainstate call failed")?,
            Ordering::Release,
        );

        loop {
            tokio::select! {
                block_id = new_tip_receiver.recv() => {
                    // This error can only occur when chainstate drops an events subscriber.
                    let block_id = block_id.expect("New tip sender was closed");
                    self.handle_new_tip(block_id).await?;
                },

                event = self.sync_event_receiver.poll_next() => {
                    self.handle_peer_event(event?).await?;
                },

                _ = &mut self.shutdown_receiver => {
                    log::info!("Cancelling sync manager");
                    let to_cancel: Vec<_> = self.peers.keys().cloned().collect();
                    // Wait for the peers to shut down.
                    futures::future::join_all(
                        to_cancel.into_iter().map(|peer_id| self.unregister_peer(peer_id))
                    ).await;
                    return Err(P2pError::Cancelled);
                }
            }
        }
    }

    /// Starts a task for the new peer.
    pub fn register_peer(&mut self, peer: PeerId, remote_services: Services) -> Result<()> {
        log::debug!("Register peer {peer} to sync manager");

        if self.peers.contains_key(&peer) {
            // This should never happen because a peer can only connect once.
            return Err(P2pError::PeerError(PeerError::PeerAlreadyExists));
        }

        let (sender, receiver) = mpsc::unbounded_channel();
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

        let messaging_handle = self.messaging_handle.clone();
        let peer_manager_sender = self.peer_manager_sender.clone();
        let chainstate_handle = self.chainstate_handle.clone();
        let mempool_handle = self.mempool_handle.clone();
        let p2p_config = self.p2p_config.clone();
        let is_initial_block_download = self.is_initial_block_download.clone();
        let time_getter = self.time_getter.clone();
        let handle = tokio::spawn(async move {
            Peer::<T>::new(
                peer,
                remote_services,
                p2p_config,
                chainstate_handle,
                mempool_handle,
                peer_manager_sender,
                messaging_handle,
                receiver,
                shutdown_receiver,
                is_initial_block_download,
                time_getter,
            )
            .run()
            .await;
        });

        self.peers.insert(
            peer,
            PeerContext {
                tx: sender,
                shutdown_tx: shutdown_sender,
                handle,
            },
        );

        Ok(())
    }

    /// Stops the task of the given peer by closing the corresponding channel.
    fn unregister_peer(&mut self, peer: PeerId) -> JoinHandle<()> {
        log::debug!("Unregister peer {peer} from sync manager");
        let peer_ctx = self
            .peers
            .remove(&peer)
            .unwrap_or_else(|| panic!("Unregistering unknown peer: {peer}"));
        let _ = peer_ctx.shutdown_tx.send(());
        peer_ctx.handle
    }

    /// Announces the header of a new block to peers.
    async fn handle_new_tip(&mut self, block_id: Id<Block>) -> Result<()> {
        let is_initial_block_download = if self.is_initial_block_download.load(Ordering::Relaxed) {
            let is_ibd = self.chainstate_handle.call(|c| c.is_initial_block_download()).await??;
            self.is_initial_block_download.store(is_ibd, Ordering::Release);
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

    /// Sends an event to the corresponding peer.
    async fn handle_peer_event(&mut self, event: SyncingEvent) -> Result<()> {
        let (peer, message) = match event {
            SyncingEvent::Connected { peer_id, services } => {
                self.register_peer(peer_id, services)?;
                return Ok(());
            }
            SyncingEvent::Disconnected { peer_id } => {
                let handle = self.unregister_peer(peer_id);
                let _ = handle.await;
                return Ok(());
            }
            SyncingEvent::Message { peer, message } => (peer, message),
        };

        let peer_channel = self.peers.get(&peer).unwrap_or_else(|| {
            panic!("Received a message from unknown peer ({peer}): {message:?}")
        });

        Ok(peer_channel.tx.send(message)?)
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

/// Check the incoming transaction and propagate it to peer if it's valid
// TODO: Do we want to return the TxStatus?
pub async fn process_incoming_transaction(
    mempool: &MempoolHandle,
    messaging: &mut impl MessagingService,
    transaction: common::chain::SignedTransaction,
) -> Result<()> {
    use mempool::TxStatus;
    let tx_id = common::primitives::Idable::get_id(transaction.transaction());

    match mempool.call_mut(|m| m.add_transaction(transaction)).await?? {
        // Transaction accepted to local mempool, propagate it to the peers
        TxStatus::InMempool => messaging.broadcast_message(SyncMessage::NewTransaction(tx_id)),
        // We don't know whether the orphan is valid, don't propagate at this point
        TxStatus::InOrphanPool => Ok(()),
    }
}

#[cfg(test)]
mod tests;
