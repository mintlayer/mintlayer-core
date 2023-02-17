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

mod peer_context;
mod protocol;

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use tokio::sync::mpsc;
use void::Void;

use chainstate::chainstate_interface;
use common::{
    chain::{
        block::{Block, BlockHeader},
        config::ChainConfig,
    },
    primitives::{Id, Idable},
};
use logging::log;
use utils::tap_error_log::LogError;

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError, ProtocolError},
    event::{PeerManagerEvent, SyncControlEvent},
    message::{Announcement, BlockListRequest, BlockResponse, HeaderListRequest, SyncMessage},
    net::{types::SyncingEvent, NetworkingService, SyncingMessagingService},
    sync::peer_context::PeerContext,
    Result,
};

/// Sync manager is responsible for syncing the local blockchain to the chain with most trust
/// and keeping up with updates to different branches of the blockchain.
///
/// It keeps track of the state of each individual peer and holds an intermediary block index
/// which represents the local block index of every peer it's connected to.
///
/// Currently its only mode of operation is greedy so it will download all changes from every
/// peer it's connected to and actively keep track of the peer's state.
pub struct BlockSyncManager<T: NetworkingService> {
    /// The chain configuration.
    _chain_config: Arc<ChainConfig>,

    /// The p2p configuration.
    p2p_config: Arc<P2pConfig>,

    /// A handle for sending/receiving syncing events.
    messaging_handle: T::SyncingMessagingHandle,

    /// A receiver for connect/disconnect events.
    peer_event_receiver: mpsc::UnboundedReceiver<SyncControlEvent<T>>,

    /// A sender for the peer manager events.
    peer_manager_sender: mpsc::UnboundedSender<PeerManagerEvent<T>>,

    /// A mapping from a peer identifier to the context for every connected peer.
    peers: HashMap<T::PeerId, PeerContext>,

    /// A handle to the chainstate subsystem.
    chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,

    /// A queue of the blocks requested by peers.
    ///
    /// The block identifiers are added to the queue as a result of BlockListRequest processing
    /// and removed either after sending a response or when the peer is disconnected. A number of
    /// blocks is limited by `P2pConfig::requested_blocks_limit` per peer.
    blocks_queue: VecDeque<(T::PeerId, Id<Block>)>,
}

/// Syncing manager
impl<T> BlockSyncManager<T>
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::PeerId: 'static,
{
    /// Creates a new sync manager instance.
    pub fn new(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        messaging_handle: T::SyncingMessagingHandle,
        chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
        peer_event_receiver: mpsc::UnboundedReceiver<SyncControlEvent<T>>,
        peer_manager_sender: mpsc::UnboundedSender<PeerManagerEvent<T>>,
    ) -> Self {
        Self {
            _chain_config: chain_config,
            p2p_config,
            messaging_handle,
            peer_event_receiver,
            peer_manager_sender,
            chainstate_handle,
            peers: Default::default(),
            blocks_queue: Default::default(),
        }
    }

    /// Runs the sync manager event loop.
    pub async fn run(&mut self) -> Result<Void> {
        log::info!("Starting SyncManager");

        let mut new_tip_receiver = self.subscribe_to_new_tip().await?;
        loop {
            tokio::select! {
                event = self.messaging_handle.poll_next() => match event? {
                    SyncingEvent::Message { peer, message } => {
                        let res = self.handle_message(peer, message).await;
                        self.handle_result(peer, res).await?;
                    },
                    SyncingEvent::Announcement{ peer, announcement } => {
                        let res = self.handle_announcement(peer, announcement).await;
                        self.handle_result(peer, res).await?;
                    }
                },
                event = self.peer_event_receiver.recv() => match event.ok_or(P2pError::ChannelClosed)? {
                    SyncControlEvent::Connected(peer_id) => self.register_peer(peer_id).await?,
                    SyncControlEvent::Disconnected(peer_id) => self.unregister_peer(peer_id),
                },
                block_id = new_tip_receiver.recv(), if !self.chainstate_handle.call(|c| c.is_initial_block_download()).await?? => {
                    // This error can only occur when chainstate drops an events subscriber.
                    let block_id = block_id.ok_or(P2pError::ChannelClosed)?;
                    self.handle_new_tip(block_id).await?;
                },
                (peer, block) = async { self.blocks_queue.pop_front().expect("The block queue is empty") }, if !self.blocks_queue.is_empty() => {
                    let res = self.send_block(peer, block).await;
                    self.handle_result(peer, res).await?;
                }
            }
        }
    }

    /// Returns a receiver for the chainstate `NewTip` events.
    async fn subscribe_to_new_tip(&mut self) -> Result<mpsc::UnboundedReceiver<Id<Block>>> {
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

    // TODO: This shouldn't be public.
    /// Registers the connected peer by creating a context for it.
    ///
    /// The `HeaderListRequest` message is sent to newly connected peers.
    pub async fn register_peer(&mut self, peer: T::PeerId) -> Result<()> {
        log::debug!("Register peer {peer} to sync manager");

        self.request_headers(peer).await?;
        match self.peers.insert(peer, PeerContext::new()) {
            // This should never happen because a peer can only connect once.
            Some(_) => Err(P2pError::PeerError(PeerError::PeerAlreadyExists)),
            None => Ok(()),
        }
    }

    /// Removes the state (`PeerContext`) of the given peer.
    fn unregister_peer(&mut self, peer: T::PeerId) {
        log::debug!("Unregister peer {peer} from sync manager");

        // Remove the queued block responses associated with the disconnected peer.
        self.blocks_queue.retain(|(p, _)| p != &peer);

        if self.peers.remove(&peer).is_some() {
            log::warn!("Unregistering unknown peer: {peer}");
        }
    }

    /// Announces the header of a new block to peers.
    async fn handle_new_tip(&mut self, block_id: Id<Block>) -> Result<()> {
        let header = self
            .chainstate_handle
            .call(move |c| c.get_block(block_id))
            .await??
            // This should never happen because this block has just been produced by chainstate.
            .expect("A new tip block unavailable")
            .header()
            .clone();
        self.messaging_handle.make_announcement(Announcement::Block(header))
    }

    /// Sends a block to the peer.
    async fn send_block(&mut self, peer: T::PeerId, block: Id<Block>) -> Result<()> {
        self.peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
            .num_blocks_to_send -= 1;

        let block = self.chainstate_handle.call(move |c| c.get_block(block)).await??.ok_or(
            P2pError::ProtocolError(ProtocolError::UnknownBlockRequested),
        )?;
        self.messaging_handle
            .send_message(peer, SyncMessage::BlockResponse(BlockResponse::new(block)))
    }

    /// Sends a header list request to the given peer.
    async fn request_headers(&mut self, peer: T::PeerId) -> Result<()> {
        let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
        debug_assert!(locator.len() <= *self.p2p_config.msg_max_locator_count);

        self.messaging_handle
            .send_message(
                peer,
                SyncMessage::HeaderListRequest(HeaderListRequest::new(locator)),
            )
            .map(|_| ())
    }

    /// Sends a block list request to the given peer.
    ///
    /// The number of headers sent equals to `P2pConfig::requested_blocks_limit`, the remaining
    /// headers are stored in the peer context.
    fn request_blocks(&mut self, peer: T::PeerId, mut headers: Vec<BlockHeader>) -> Result<()> {
        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        debug_assert!(peer_state.known_headers.is_empty());
        if headers.len() > *self.p2p_config.max_request_blocks_count {
            peer_state.known_headers = headers.split_off(*self.p2p_config.max_request_blocks_count);
        }

        let block_ids: Vec<_> = headers.into_iter().map(|h| h.get_id()).collect();
        self.messaging_handle.send_message(
            peer,
            SyncMessage::BlockListRequest(BlockListRequest::new(block_ids.clone())),
        )?;
        peer_state.requested_blocks.extend(block_ids);

        Ok(())
    }
}

#[cfg(test)]
mod tests;
