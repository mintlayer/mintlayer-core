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
        SyncRequest, SyncResponse,
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
    blocks_queue: VecDeque<(T::PeerId, T::PeerRequestId, Id<Block>)>,
}

/// Syncing manager
impl<T> BlockSyncManager<T>
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::PeerRequestId: 'static,
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
                    SyncingEvent::Request {
                        peer_id,
                        request_id,
                        request,
                    } => {
                        let res = self.handle_request(peer_id, request_id, request).await;
                        self.handle_result(peer_id, res).await?;
                    },
                    SyncingEvent::Response {
                        peer_id,
                        request_id,
                        response,
                    } => {
                        let res = self.handle_response(peer_id, request_id, response).await;
                        self.handle_result(peer_id, res).await?;
                    },
                    SyncingEvent::Announcement{ peer_id, announcement } => {
                        self.handle_announcement(peer_id, announcement).await?;
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
                }
                _ = async {}, if !self.blocks_queue.is_empty() => {
                    self.handle_block_queue().await?
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

    // TODO: Remove.
    /// Get mutable reference to the handle
    pub fn handle_mut(&mut self) -> &mut T::SyncingMessagingHandle {
        // TODO: get rid of this function as it's used only in tests; perhaps a better way to do this is by
        // creating p2p objects and make them communicate together instead of having access to internal
        // private parts of the sync manager
        &mut self.messaging_handle
    }

    async fn handle_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::PeerRequestId,
        request: SyncRequest,
    ) -> Result<()> {
        match request {
            SyncRequest::HeaderListRequest(request) => {
                self.handle_header_request(peer_id, request_id, request.into_locator()).await
            }
            SyncRequest::BlockListRequest(request) => {
                self.handle_block_request(peer_id, request_id, request.into_block_ids()).await
            }
        }
    }

    // TODO: This shouldn't be public.
    /// Processes a header request by sending requested data to the peer.
    pub async fn handle_header_request(
        &mut self,
        peer: T::PeerId,
        request_id: T::PeerRequestId,
        locator: Locator,
    ) -> Result<()> {
        log::debug!("process header request (id {request_id:?}) from peer {peer}");

        // Check that the peer is connected.
        self.peers.get(&peer).ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        if locator.len() > self.p2p_config.max_locator_size.clone().into() {
            return Err(P2pError::ProtocolError(ProtocolError::LocatorSizeExceeded(
                locator.len(),
                self.p2p_config.max_locator_size.clone().into(),
            )));
        }
        log::trace!("locator: {locator:#?}");

        if self.chainstate_handle.call(|c| c.is_initial_block_download()).await?? {
            // TODO: Check if a peer has permissions to ask for headers during the initial block download.
            log::debug!("Ignoring headers request because the node is in initial block download");
            return Ok(());
        }

        let headers = self.chainstate_handle.call(|c| c.get_headers(locator)).await??;
        self.messaging_handle.send_response(
            request_id,
            SyncResponse::HeaderListResponse(HeaderListResponse::new(headers)),
        )?;

        Ok(())
    }

    // TODO: This shouldn't be public.
    /// Processes the blocks request.
    pub async fn handle_block_request(
        &mut self,
        peer: T::PeerId,
        request_id: T::PeerRequestId,
        mut block_ids: Vec<Id<Block>>,
    ) -> Result<()> {
        log::debug!("process block request (id {request_id:?}) from peer {peer}");

        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        if self.chainstate_handle.call(|c| c.is_initial_block_download()).await?? {
            log::debug!("Ignoring blocks request because the node is in initial block download");
            return Ok(());
        }

        let requested_blocks_limit = self.p2p_config.requested_blocks_limit.clone().into();
        if block_ids.len() > requested_blocks_limit {
            return Err(P2pError::ProtocolError(
                ProtocolError::BlocksRequestLimitExceeded(block_ids.len(), requested_blocks_limit),
            ));
        }
        log::trace!("requested block ids: {block_ids:#?}");

        // Check that all blocks are known.
        for id in block_ids.clone() {
            self.chainstate_handle.call(move |c| c.get_block_index(&id)).await??.ok_or(
                P2pError::ProtocolError(ProtocolError::UnknownBlockRequested),
            )?;
        }

        block_ids.truncate(requested_blocks_limit - peer_state.num_blocks_to_send);
        peer_state.num_blocks_to_send += block_ids.len();
        debug_assert!(peer_state.num_blocks_to_send <= requested_blocks_limit);
        self.blocks_queue.extend(block_ids.into_iter().map(|id| (peer, request_id, id)));

        Ok(())
    }

    // TODO: This shouldn't be public.
    pub async fn handle_response(
        &mut self,
        peer: T::PeerId,
        request_id: T::PeerRequestId,
        response: SyncResponse,
    ) -> Result<()> {
        match response {
            SyncResponse::HeaderListResponse(response) => {
                self.handle_header_response(peer, request_id, response.into_headers()).await
            }
            SyncResponse::BlockResponse(response) => {
                self.handle_block_response(peer, request_id, response.into_block()).await
            }
        }
    }

    // TODO: This shouldn't be public.
    pub async fn handle_header_response(
        &mut self,
        peer: T::PeerId,
        request_id: T::PeerRequestId,
        headers: Vec<BlockHeader>,
    ) -> Result<()> {
        log::debug!("process header response (id {request_id:?}) from peer {peer}");

        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        if !peer_state.known_headers.is_empty() {
            return Err(P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "headers response",
            )));
        }

        if headers.len() > self.p2p_config.header_limit.clone().into() {
            return Err(P2pError::ProtocolError(
                ProtocolError::HeadersLimitExceeded(
                    headers.len(),
                    self.p2p_config.header_limit.clone().into(),
                ),
            ));
        }
        log::trace!("received headers: {headers:#?}");

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

        let is_max_headers =
            headers.len() == Into::<usize>::into(self.p2p_config.header_limit.clone());
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

        let first_header = headers
            .first()
            // This is OK because of the `headers.is_empty()` check above.
            .expect("Headers shouldn't be empty")
            .clone();
        self.chainstate_handle
            .call(|c| c.preliminary_header_check(first_header))
            .await??;
        self.request_blocks(peer, headers).await
    }

    // TODO: This shouldn't be public.
    pub async fn handle_block_response(
        &mut self,
        peer: T::PeerId,
        request_id: T::PeerRequestId,
        block: Block,
    ) -> Result<()> {
        log::debug!("process block response (id {request_id:?}) from peer {peer}");

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
                self.request_blocks(peer, headers).await?;
            }
        }

        Ok(())
    }

    // TODO: This shouldn't be public.
    pub async fn handle_announcement(
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
        log::debug!("block announcement from {peer} peer: {header:?}");

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
            self.request_headers(peer).await?;
            return Ok(());
        }

        let header_ = header.clone();
        self.chainstate_handle.call(|c| c.preliminary_header_check(header_)).await??;
        self.request_blocks(peer, vec![header]).await
    }

    // TODO: This shouldn't be public.
    /// Registers the connected peer by creating a context for it.
    ///
    /// The `HeaderListRequest` message is sent to newly connected peers.
    pub async fn register_peer(&mut self, peer: T::PeerId) -> Result<()> {
        log::debug!("register peer {peer} to sync manager");

        self.request_headers(peer).await?;
        match self.peers.insert(peer, PeerContext::new()) {
            // This should never happen because a peer can only connect once.
            Some(_) => Err(P2pError::PeerError(PeerError::PeerAlreadyExists)),
            None => Ok(()),
        }
    }

    // TODO: This shouldn't be public.
    /// Removes the state (`PeerContext`) of the given peer.
    pub fn unregister_peer(&mut self, peer: T::PeerId) {
        log::debug!("unregister peer {peer} from sync manager");

        // Remove the queued block responses associated with the disconnected peer.
        self.blocks_queue.retain(|(p, _, _)| p != &peer);

        self.peers.remove(&peer);
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

    async fn handle_block_queue(&mut self) -> Result<()> {
        debug_assert!(!self.blocks_queue.is_empty());

        let (peer, request_id, block_id) = self
            .blocks_queue
            .pop_front()
            // This function is only called when the queue isn't empty.
            .expect("The block queue is empty");
        match self.peers.get_mut(&peer) {
            Some(state) => state.num_blocks_to_send -= 1,
            None => return Ok(()),
        }

        let block = self.chainstate_handle.call(move |c| c.get_block(block_id)).await??.ok_or(
            P2pError::ProtocolError(ProtocolError::UnknownBlockRequested),
        )?;
        self.messaging_handle.send_response(
            request_id,
            SyncResponse::BlockResponse(BlockResponse::new(block)),
        )
    }

    /// Handles a result of request/response processing.
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
            P2pError::ProtocolError(e) => {
                log::debug!(
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

    async fn request_headers(&mut self, peer: T::PeerId) -> Result<()> {
        let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
        debug_assert!(locator.len() <= self.p2p_config.max_locator_size.clone().into());

        self.messaging_handle
            .send_request(
                peer,
                SyncRequest::HeaderListRequest(HeaderListRequest::new(locator.clone())),
            )
            .map(|_| ())
    }

    async fn request_blocks(
        &mut self,
        peer: T::PeerId,
        mut headers: Vec<BlockHeader>,
    ) -> Result<()> {
        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        debug_assert!(peer_state.known_headers.is_empty());

        if headers.len() > self.p2p_config.requested_blocks_limit.clone().into() {
            peer_state.known_headers =
                headers.split_off(self.p2p_config.requested_blocks_limit.clone().into());
        }

        let block_ids: Vec<_> = headers.into_iter().map(|h| h.get_id()).collect();
        self.messaging_handle.send_request(
            peer,
            SyncRequest::BlockListRequest(BlockListRequest::new(block_ids.clone())),
        )?;
        peer_state.requested_blocks.extend(block_ids);

        Ok(())
    }
}

#[cfg(test)]
mod tests;
