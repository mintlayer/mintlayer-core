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

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use void::Void;

use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{block::Block, config::ChainConfig},
    primitives::Id,
};
use logging::log;
use mempool::MempoolHandle;
use utils::tap_error_log::LogError;

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError},
    event::PeerManagerEvent,
    message::{Announcement, SyncMessage},
    net::{types::SyncingEvent, NetworkingService, SyncingMessagingService},
    sync::peer::{Peer, PeerEvent},
    types::peer_id::PeerId,
    Result,
};

/// Sync manager is responsible for syncing the local blockchain to the chain with most trust
/// and keeping up with updates to different branches of the blockchain.
pub struct BlockSyncManager<T: NetworkingService> {
    /// The chain configuration.
    _chain_config: Arc<ChainConfig>,

    /// The p2p configuration.
    p2p_config: Arc<P2pConfig>,

    /// A handle for sending/receiving syncing events.
    messaging_handle: T::SyncingMessagingHandle,

    /// A sender for the peer manager events.
    peer_manager_sender: UnboundedSender<PeerManagerEvent<T>>,

    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    mempool_handle: MempoolHandle,

    /// A cached result of the `ChainstateInterface::is_initial_block_download` call.
    is_initial_block_download: Arc<AtomicBool>,

    /// A mapping from a peer identifier to the channel.
    peers: HashMap<PeerId, UnboundedSender<PeerEvent>>,

    peer_sender: UnboundedSender<(PeerId, SyncMessage)>,
    peer_receiver: UnboundedReceiver<(PeerId, SyncMessage)>,
}

/// Syncing manager
impl<T> BlockSyncManager<T>
where
    T: NetworkingService + 'static,
    T::SyncingMessagingHandle: SyncingMessagingService,
{
    /// Creates a new sync manager instance.
    pub fn new(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        messaging_handle: T::SyncingMessagingHandle,
        chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
        mempool_handle: MempoolHandle,
        peer_manager_sender: UnboundedSender<PeerManagerEvent<T>>,
    ) -> Self {
        let (peer_sender, peer_receiver) = mpsc::unbounded_channel();

        Self {
            _chain_config: chain_config,
            p2p_config,
            messaging_handle,
            peer_manager_sender,
            chainstate_handle,
            mempool_handle,
            is_initial_block_download: Arc::new(true.into()),
            peers: Default::default(),
            peer_sender,
            peer_receiver,
        }
    }

    /// Runs the sync manager event loop.
    pub async fn run(&mut self) -> Result<Void> {
        log::info!("Starting SyncManager");

        let mut new_tip_receiver = self.subscribe_to_new_tip().await?;
        self.is_initial_block_download.store(
            self.chainstate_handle.call(|c| c.is_initial_block_download()).await??,
            Ordering::Release,
        );

        loop {
            tokio::select! {
                block_id = new_tip_receiver.recv() => {
                    // This error can only occur when chainstate drops an events subscriber.
                    let block_id = block_id.ok_or(P2pError::ChannelClosed)?;
                    self.handle_new_tip(block_id).await?;
                },

                // Resend messages from peers to the backend.
                message = self.peer_receiver.recv() => {
                    let (peer, message) = message.ok_or(P2pError::ChannelClosed)?;
                    self.messaging_handle.send_message(peer, message)?;
                },

                event = self.messaging_handle.poll_next() => {
                    self.handle_peer_event(event?)?;
                },
            }
        }
    }

    /// Returns a receiver for the chainstate `NewTip` events.
    async fn subscribe_to_new_tip(&mut self) -> Result<UnboundedReceiver<Id<Block>>> {
        let (sender, receiver) = mpsc::unbounded_channel();

        let subscribe_func =
            Arc::new(
                move |chainstate_event: chainstate::ChainstateEvent| match chainstate_event {
                    chainstate::ChainstateEvent::NewTip(block_id, _) => {
                        let _ = sender.send(block_id).log_err_pfx("The new tip receiver closed");
                    }
                },
            );

        self.chainstate_handle
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .map_err(|_| P2pError::SubsystemFailure)?;

        Ok(receiver)
    }

    /// Starts a task for the new peer.
    pub fn register_peer(&mut self, peer: PeerId) -> Result<()> {
        log::debug!("Register peer {peer} to sync manager");

        let (sender, receiver) = mpsc::unbounded_channel();
        self.peers
            .insert(peer, sender)
            // This should never happen because a peer can only connect once.
            .map(|_| Err::<(), _>(P2pError::PeerError(PeerError::PeerAlreadyExists)))
            .transpose()?;

        let peer_sender = self.peer_sender.clone();
        let peer_manager_sender = self.peer_manager_sender.clone();
        let chainstate_handle = self.chainstate_handle.clone();
        let mempool_handle = self.mempool_handle.clone();
        let p2p_config = Arc::clone(&self.p2p_config);
        let is_initial_block_download = Arc::clone(&self.is_initial_block_download);
        tokio::spawn(async move {
            let mut peer = Peer::<T>::new(
                peer,
                p2p_config,
                chainstate_handle,
                mempool_handle,
                peer_manager_sender,
                peer_sender,
                receiver,
                is_initial_block_download,
            );
            if let Err(e) = peer.run().await {
                log::error!("Sync manager peer ({}) error: {e:?}", peer.id());
            }
        });

        Ok(())
    }

    /// Stops the task of the given peer by closing the corresponding channel.
    fn unregister_peer(&mut self, peer: PeerId) {
        log::debug!("Unregister peer {peer} from sync manager");
        self.peers
            .remove(&peer)
            .unwrap_or_else(|| panic!("Unregistering unknown peer: {peer}"));
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
            .call(move |c| c.get_block(block_id))
            .await??
            // This should never happen because this block has just been produced by chainstate.
            .expect("A new tip block unavailable")
            .header()
            .clone();
        self.messaging_handle.make_announcement(Announcement::Block(Box::new(header)))
    }

    /// Sends an event to the corresponding peer.
    fn handle_peer_event(&mut self, event: SyncingEvent) -> Result<()> {
        let (peer, event) = match event {
            SyncingEvent::Connected { peer_id } => {
                self.register_peer(peer_id)?;
                return Ok(());
            }
            SyncingEvent::Disconnected { peer_id } => {
                self.unregister_peer(peer_id);
                return Ok(());
            }
            SyncingEvent::Message { peer, message } => (peer, PeerEvent::Message { message }),
            SyncingEvent::Announcement { peer, announcement } => {
                (peer, PeerEvent::Announcement { announcement })
            }
        };

        let peer_channel = self
            .peers
            .get(&peer)
            .unwrap_or_else(|| panic!("Received a message from unknown peer ({peer}): {event:?}"));

        if let Err(e) = peer_channel.send(event) {
            log::warn!("The {peer} peer event loop is stopped unexpectedly: {e:?}");
            self.unregister_peer(peer);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
