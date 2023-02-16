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

use std::{
    collections::{HashMap, VecDeque},
    mem,
    sync::Arc,
};

use tokio::sync::mpsc;
use void::Void;

use chainstate::{ban_score::BanScore, chainstate_interface, BlockError, ChainstateError, Locator};
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
    message::{
        Announcement, BlockListRequest, BlockResponse, HeaderListRequest, HeaderListResponse,
        SyncMessage,
    },
    net::{types::SyncingEvent, NetworkingService, SyncingMessagingService},
    sync::peer_context::PeerContext,
    utils::oneshot_nofail,
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

    async fn handle_message(&mut self, peer: T::PeerId, message: SyncMessage) -> Result<()> {
        match message {
            SyncMessage::HeaderListRequest(r) => {
                self.handle_header_request(peer, r.into_locator()).await
            }
            SyncMessage::BlockListRequest(r) => {
                self.handle_block_request(peer, r.into_block_ids()).await
            }
            SyncMessage::HeaderListResponse(r) => {
                self.handle_header_response(peer, r.into_headers()).await
            }
            SyncMessage::BlockResponse(r) => self.handle_block_response(peer, r.into_block()).await,
        }
    }

    /// Processes a header request by sending requested data to the peer.
    async fn handle_header_request(&mut self, peer: T::PeerId, locator: Locator) -> Result<()> {
        log::debug!("Headers request from peer {peer}");

        // Check that the peer is connected.
        self.peers.get(&peer).ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        if locator.len() > *self.p2p_config.msg_max_locator_count {
            return Err(P2pError::ProtocolError(ProtocolError::LocatorSizeExceeded(
                locator.len(),
                *self.p2p_config.msg_max_locator_count,
            )));
        }
        log::trace!("locator: {locator:#?}");

        if self.chainstate_handle.call(|c| c.is_initial_block_download()).await?? {
            // TODO: Check if a peer has permissions to ask for headers during the initial block download.
            log::debug!("Ignoring headers request because the node is in initial block download");
            return Ok(());
        }

        let headers = self.chainstate_handle.call(|c| c.get_headers(locator)).await??;
        debug_assert!(headers.len() <= *self.p2p_config.msg_header_count_limit);
        self.messaging_handle.send_message(
            peer,
            SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
        )?;

        Ok(())
    }

    /// Processes the blocks request.
    async fn handle_block_request(
        &mut self,
        peer: T::PeerId,
        mut block_ids: Vec<Id<Block>>,
    ) -> Result<()> {
        log::debug!("Blocks request from peer {peer}");

        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        if self.chainstate_handle.call(|c| c.is_initial_block_download()).await?? {
            log::debug!("Ignoring blocks request because the node is in initial block download");
            return Ok(());
        }

        let requested_blocks_limit = *self.p2p_config.max_request_blocks_count;
        if block_ids.len() > requested_blocks_limit {
            return Err(P2pError::ProtocolError(
                ProtocolError::BlocksRequestLimitExceeded(block_ids.len(), requested_blocks_limit),
            ));
        }
        log::trace!("Requested block ids: {block_ids:#?}");

        // Check that all blocks are known.
        for id in block_ids.clone() {
            self.chainstate_handle.call(move |c| c.get_block_index(&id)).await??.ok_or(
                P2pError::ProtocolError(ProtocolError::UnknownBlockRequested),
            )?;
        }

        block_ids.truncate(requested_blocks_limit - peer_state.num_blocks_to_send);
        peer_state.num_blocks_to_send += block_ids.len();
        debug_assert!(peer_state.num_blocks_to_send <= requested_blocks_limit);
        self.blocks_queue.extend(block_ids.into_iter().map(|id| (peer, id)));

        Ok(())
    }

    async fn handle_header_response(
        &mut self,
        peer: T::PeerId,
        headers: Vec<BlockHeader>,
    ) -> Result<()> {
        log::debug!("Headers response from peer {peer}");

        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        if !peer_state.known_headers.is_empty() {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "headers response",
            )));
        }

        if headers.len() > *self.p2p_config.msg_header_count_limit {
            return Err(P2pError::ProtocolError(
                ProtocolError::HeadersLimitExceeded(
                    headers.len(),
                    *self.p2p_config.msg_header_count_limit,
                ),
            ));
        }
        log::trace!("Received headers: {headers:#?}");

        // We are in sync with this peer.
        if headers.is_empty() {
            return Ok(());
        }

        // Each header must be connected to the previous one.
        if !headers
            .iter()
            .zip(&headers[1..])
            .all(|(left, right)| &left.get_id() == right.prev_block_id())
        {
            return Err(P2pError::ProtocolError(ProtocolError::DisconnectedHeaders));
        }

        // The first header must be connected to a known block.
        let prev_id = *headers
            .first()
            // This is OK because of the `headers.is_empty()` check above.
            .expect("Headers shouldn't be empty")
            .prev_block_id();
        if self
            .chainstate_handle
            .call(move |c| c.get_gen_block_index(&prev_id))
            .await??
            .is_none()
        {
            return Err(P2pError::ProtocolError(ProtocolError::DisconnectedHeaders));
        }

        let is_max_headers = headers.len() == *self.p2p_config.msg_header_count_limit;
        let headers = self
            .chainstate_handle
            .call(|c| c.filter_already_existing_blocks(headers))
            .await??;
        if headers.is_empty() {
            // A peer can have more headers if we have received the maximum amount of them.
            if is_max_headers {
                self.request_headers(peer).await?;
            }
            return Ok(());
        }

        // Only the first header can be checked with the `preliminary_header_check` function.
        let first_header = headers
            .first()
            // This is OK because of the `headers.is_empty()` check above.
            .expect("Headers shouldn't be empty")
            .clone();
        self.chainstate_handle
            .call(|c| c.preliminary_header_check(first_header))
            .await??;

        self.request_blocks(peer, headers)
    }

    async fn handle_block_response(&mut self, peer: T::PeerId, block: Block) -> Result<()> {
        log::debug!("Block ({}) from peer {peer}", block.get_id());

        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        if peer_state.requested_blocks.take(&block.get_id()).is_none() {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "block response",
            )));
        }

        match self
            .chainstate_handle
            .call_mut(|c| {
                c.preliminary_block_check(block)
                    .and_then(|block| c.process_block(block, chainstate::BlockSource::Peer))
            })
            .await?
        {
            // It is OK to receive an already processed block.
            Ok(_) | Err(ChainstateError::ProcessBlockError(BlockError::BlockAlreadyExists(_))) => {}
            Err(e) => return Err(P2pError::ChainstateError(e)),
        }

        if peer_state.requested_blocks.is_empty() {
            if peer_state.known_headers.is_empty() {
                // Request more headers.
                self.request_headers(peer).await?;
            } else {
                // Download remaining blocks.
                let mut headers = Vec::new();
                mem::swap(&mut headers, &mut peer_state.known_headers);
                self.request_blocks(peer, headers)?;
            }
        }

        Ok(())
    }

    async fn handle_announcement(
        &mut self,
        peer: T::PeerId,
        announcement: Announcement,
    ) -> Result<()> {
        match announcement {
            Announcement::Block(header) => self.handle_block_announcement(peer, header).await,
        }
    }

    async fn handle_block_announcement(
        &mut self,
        peer: T::PeerId,
        header: BlockHeader,
    ) -> Result<()> {
        log::debug!("Block announcement from peer {peer}: {header:?}");

        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        if !peer_state.requested_blocks.is_empty() {
            // We will download this block as part of syncing anyway.
            return Ok(());
        }

        let prev_id = *header.prev_block_id();
        if self
            .chainstate_handle
            .call(move |c| c.get_gen_block_index(&prev_id))
            .await??
            .is_none()
        {
            // TODO: Investigate this case. This can be used by malicious peers for a DoS attack.
            self.request_headers(peer).await?;
            return Ok(());
        }

        let header_ = header.clone();
        //self.chainstate_handle.call(|c| c.preliminary_header_check(header_)).await??;
        self.chainstate_handle
            .call(|c| c.preliminary_header_check(header_))
            .await?
            .unwrap();
        self.request_blocks(peer, vec![header])
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

    /// Handles a result of message processing.
    ///
    /// There are three possible types of errors:
    /// - Fatal errors will be propagated by this function effectively stopping the sync manager
    ///   and the whole p2p subsystem.
    /// - Non-fatal errors aren't propagated, but the peer score will be increased by the
    ///   "ban score" value of the given error.
    /// - Ignored errors aren't propagated and don't affect the peer score.
    async fn handle_result(&mut self, peer: T::PeerId, result: Result<()>) -> Result<()> {
        let error = match result {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };

        match error {
            // A protocol error - increase the ban score of a peer.
            e @ (P2pError::ProtocolError(_)
            | P2pError::ChainstateError(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(_),
            ))) => {
                log::info!(
                    "Adjusting the '{peer}' peer score by {}: {:?}",
                    e.ban_score(),
                    e
                );

                let (sender, receiver) = oneshot_nofail::channel();
                self.peer_manager_sender.send(PeerManagerEvent::AdjustPeerScore(
                    peer,
                    e.ban_score(),
                    sender,
                ))?;
                receiver.await?.or_else(|e| match e {
                    P2pError::PeerError(PeerError::PeerDoesntExist) => Ok(()),
                    e => Err(e),
                })
            }
            // Due to the fact that p2p is split into several tasks, it is possible to send a
            // request/response after a peer is disconnected, but before receiving the disconnect
            // event. Therefore this error can be safely ignored.
            P2pError::PeerError(PeerError::PeerDoesntExist) => Ok(()),
            // Some of these errors aren't technically fatal, but they shouldn't occur in the sync
            // manager.
            e @ (P2pError::DialError(_)
            | P2pError::ConversionError(_)
            | P2pError::PeerError(_)
            | P2pError::NoiseHandshakeError(_)
            | P2pError::PublishError(_)
            | P2pError::InvalidConfigurationValue(_)
            | P2pError::ChainstateError(_)) => Err(e),
            // Fatal errors, simply propagate them to stop the sync manager.
            e @ (P2pError::ChannelClosed
            | P2pError::SubsystemFailure
            | P2pError::StorageFailure(_)) => Err(e),
        }
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
