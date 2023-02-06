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

// TODO: FIXME:
// pub mod peer;
//
// mod request;

use std::{collections::HashMap, sync::Arc};

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
    message::{self, Announcement, BlockResponse, SyncRequest, SyncResponse},
    net::{types::SyncingEvent, NetworkingService, SyncingMessagingService},
    utils::oneshot_nofail,
    Result,
};

// TODO: FIXME: Move to the peer module.
// TODO: FIXME: Use enum as in the previous version?
// TODO: FIXME: Recheck if all fields are really needed.
struct PeerContext {
    // TODO: FIXME: Do we need it here?
    locator: Locator,
}

// TODO: FIXME: Update the description.
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
    chain_config: Arc<ChainConfig>,

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
            chain_config,
            p2p_config,
            messaging_handle,
            peer_event_receiver,
            peer_manager_sender,
            chainstate_handle,
            peers: Default::default(),
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
                        self.handle_request(peer_id, request_id, request).await.or_else(|e| self.handle_error(peer_id, e))?;
                    },
                    SyncingEvent::Response {
                        peer_id,
                        request_id,
                        response,
                    } => {
                        self.handle_response(peer_id, request_id, response).await.or_else(|e| self.handle_error(peer_id, e))?;
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
            SyncResponse::HeaderListResponse(message::HeaderListResponse::new(headers)),
        )?;

        // TODO: FIXME: Check if we need `pindexBestHeaderSent` in the peer context and if so, update it here.
        Ok(())
    }

    // TODO: This shouldn't be public.
    // TODO: FIXME: Recheck the ProcessGetData logic!
    /// Process block request
    pub async fn handle_block_request(
        &mut self,
        peer: T::PeerId,
        request_id: T::PeerRequestId,
        block_ids: Vec<Id<Block>>,
    ) -> Result<()> {
        log::debug!("process block request (id {request_id:?}) from peer {peer}");

        if self.chainstate_handle.call(|c| c.is_initial_block_download()).await?? {
            log::debug!("Ignoring blocks request because the node is in initial block download");
            return Ok(());
        }

        if block_ids.len() > self.p2p_config.requested_blocks_limit.clone().into() {
            return Err(P2pError::ProtocolError(
                ProtocolError::BlocksRequestLimitExceeded(
                    block_ids.len(),
                    self.p2p_config.requested_blocks_limit.clone().into(),
                ),
            ));
        }
        log::trace!("requested block ids: {block_ids:#?}");

        // TODO: FIXME: Check for more conditions before sending blocks.
        // TODO: FIXME: Don't send all blocks at once?..
        for id in block_ids {
            let block = self.chainstate_handle.call(move |c| c.get_block(id)).await??.ok_or(
                P2pError::ProtocolError(ProtocolError::UnknownBlockRequested),
            )?;
            self.messaging_handle.send_response(
                request_id,
                SyncResponse::BlockResponse(BlockResponse::new(block)),
            )?;
        }

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

        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

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

        let headers = self
            .chainstate_handle
            .call(|c| c.filter_already_existing_blocks(headers))
            .await??;

        // TODO: FIXME: Send the blocks request, but keep `requested_blocks_limit` in mind.

        todo!();
        todo!()

        // match self.validate_header_response(&peer_id, headers).await {
        //     Ok(Some(header)) => self.send_block_request(peer_id, header.get_id()).await,
        //     Ok(None) => {
        //         self.peers
        //             .get_mut(&peer_id)
        //             .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
        //             .set_state(peer::PeerSyncState::Idle);
        //         Ok(())
        //     }
        //     Err(err) => Err(err),
        // }
    }

    // TODO: This shouldn't be public.
    pub async fn handle_block_response(
        &mut self,
        peer: T::PeerId,
        request_id: T::PeerRequestId,
        block: Block,
    ) -> Result<()> {
        log::debug!("process block response (id {request_id:?}) from peer {peer}");

        todo!();
        todo!()
        // log::trace!(
        //     "# of received blocks: {}, block ids: {:#?}",
        //     response.blocks().len(),
        //     response.blocks().iter().map(|block| block.get_id()).collect::<Vec<_>>(),
        // );
        //
        // // TODO: remove the limitation of sending only one block, and allow sending multiple blocks (up to a cap)
        // ensure!(
        //     blocks.len() == 1,
        //     P2pError::ProtocolError(ProtocolError::InvalidMessage),
        // );
        //
        // match self.validate_block_response(&peer_id, blocks).await {
        //     Ok(Some(next_block)) => self.send_block_request(peer_id, next_block.get_id()).await,
        //     Ok(None) => {
        //         // last block from peer received, ask if peer knows of any new headers
        //         let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
        //         self.send_header_request(peer_id, locator).await
        //     }
        //     Err(err) => Err(err),
        // }
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
        //  TODO: FIXME: Change the logic to handle headers instead of blocks!

        // TODO: FIXME: NEXT: "nCount < MAX_BLOCKS_TO_ANNOUNCE) {"
        // TODO: FIXME: Checl if the header is connected!

        // let result = match self
        //     .chainstate_handle
        //     .call(move |this| this.preliminary_block_check(block))
        //     .await?
        // {
        //     Ok(block) => {
        //         self.chainstate_handle
        //             .call_mut(move |this| this.process_block(block, chainstate::BlockSource::Peer))
        //             .await?
        //     }
        //     Err(err) => Err(err),
        // };
        //
        // let score = match result {
        //     Ok(_) => 0,
        //     Err(e) => match e {
        //         ChainstateError::FailedToInitializeChainstate(_) => 0,
        //         ChainstateError::ProcessBlockError(err) => err.ban_score(),
        //         ChainstateError::FailedToReadProperty(_) => 0,
        //         ChainstateError::BootstrapError(_) => 0,
        //     },
        // };
        //
        // if score > 0 {
        //     // TODO: better abstraction over channels
        //     let (tx, rx) = oneshot::channel();
        //     self.tx_peer_manager
        //         .send(PeerManagerEvent::AdjustPeerScore(peer, score, tx))
        //         .map_err(P2pError::from)?;
        //     let _ = rx.await.map_err(P2pError::from)?;
        // }
        //
        // Ok(())

        todo!();
        todo!()
    }

    // TODO: This shouldn't be public.
    /// Registers the connected peer by creating a context for it.
    pub async fn register_peer(&mut self, peer: T::PeerId) -> Result<()> {
        log::debug!("register peer {peer} to sync manager");

        let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
        self.messaging_handle.send_request(
            peer,
            SyncRequest::HeaderListRequest(message::HeaderListRequest::new(locator.clone())),
        )?;

        match self.peers.insert(peer, PeerContext { locator }) {
            // This should never happen because a peer can only connect once.
            Some(_) => Err(P2pError::PeerError(PeerError::PeerAlreadyExists)),
            None => Ok(()),
        }
    }

    // TODO: This shouldn't be public.
    /// Removes the state (`PeerContext`) of the given peer.
    pub fn unregister_peer(&mut self, peer: T::PeerId) {
        log::debug!("unregister peer {peer} from sync manager");
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

    /// Handles an error occurred during request/response processing.
    ///
    /// There are three possible types of errors:
    /// - Fatal errors will be propagated by this function effectively stopping the sync manager
    ///   and the whole p2p subsystem.
    /// - Non-fatal errors aren't propagated, but the peer score will be increased by the
    ///   "ban score" value of the given error.
    /// - Ignored errors aren't propagated and don't affect the peer score.
    fn handle_error(&mut self, peer: T::PeerId, error: P2pError) -> Result<()> {
        match error {
            P2pError::ProtocolError(FIXME) => todo!(),
            P2pError::PublishError(FIXME) => todo!(),
            P2pError::DialError(FIXME) => todo!(),
            // Due to the fact that p2p is split into several tasks, it is possible to send a
            // request/response after a peer is disconnected, but before receiving the disconnect
            // event. Therefore this error can be safely ignored.
            P2pError::PeerError(PeerError::PeerDoesntExist) => Ok(()),
            P2pError::PeerError(FIXME) => todo!(),
            P2pError::ChainstateError(FIXME) => todo!(),
            P2pError::StorageFailure(FIXME) => todo!(),
            P2pError::ConversionError(FIXME) => todo!(),
            P2pError::NoiseHandshakeError(String) => todo!(),
            // Fatal errors, simply propagate them to stop the sync manager.
            e @ (P2pError::ChannelClosed | P2pError::SubsystemFailure | P2pError::Other(_)) => {
                Err(e)
            }
        }

        // // TODO: refactor this
        // pub async fn handle_error(
        //     &mut self,
        //     peer_id: T::PeerId,
        //     result: crate::Result<()>,
        // ) -> crate::Result<()> {
        //     match result {
        //         Ok(_) => Ok(()),
        //         Err(P2pError::ChannelClosed) => Err(P2pError::ChannelClosed),
        //         Err(P2pError::ProtocolError(err)) => {
        //             log::error!("Peer {peer_id} committed a protocol error: {err}");
        //
        //             let (tx, rx) = oneshot::channel();
        //             self.tx_peer_manager
        //                 .send(PeerManagerEvent::AdjustPeerScore(
        //                     peer_id,
        //                     err.ban_score(),
        //                     tx,
        //                 ))
        //                 .map_err(P2pError::from)?;
        //             rx.await.map_err(P2pError::from)?
        //         }
        //         Err(P2pError::ChainstateError(err)) => match err {
        //             ChainstateError::ProcessBlockError(err) => {
        //                 if err.ban_score() > 0 {
        //                     let (tx, rx) = oneshot::channel();
        //                     self.tx_peer_manager
        //                         .send(PeerManagerEvent::AdjustPeerScore(
        //                             peer_id,
        //                             err.ban_score(),
        //                             tx,
        //                         ))
        //                         .map_err(P2pError::from)?;
        //                     let _ = rx.await.map_err(P2pError::from);
        //                 }
        //
        //                 Ok(())
        //             }
        //             err => {
        //                 log::error!("Peer {peer_id} caused a chainstate error: {err}");
        //                 Ok(())
        //             }
        //         },
        //         Err(P2pError::PeerError(err)) => {
        //             log::error!("Peer error: {err}");
        //             Ok(())
        //         }
        //         Err(err) => {
        //             log::error!("Unexpected error occurred: {err}");
        //
        //             if err.ban_score() > 0 {
        //                 // TODO: better abstraction over channels
        //                 let (tx, rx) = oneshot::channel();
        //                 self.tx_peer_manager
        //                     .send(PeerManagerEvent::AdjustPeerScore(
        //                         peer_id,
        //                         err.ban_score(),
        //                         tx,
        //                     ))
        //                     .map_err(P2pError::from)?;
        //                 let _ = rx.await.map_err(P2pError::from);
        //             }
        //
        //             Ok(())
        //         }
        //     }
        // }
    }

    async fn adjust_peer_score(&mut self, peer: T::PeerId, score: u32, reason: &str) -> Result<()> {
        log::debug!("Adjusting the '{peer}' peer score by {score}. {reason}");

        let (sender, receiver) = oneshot_nofail::channel();
        // Sending can only fail if the channel is closed that can only occurs on shutdown.
        self.peer_manager_sender
            .send(PeerManagerEvent::AdjustPeerScore(peer, score, sender))?;
        // The peer manager ignores non-existing peers, and all other errors are considered fatal.
        receiver.await?
    }

    // /// Validate incoming block response
    // async fn validate_block_response(
    //     &mut self,
    //     peer_id: &T::PeerId,
    //     blocks: Vec<Block>,
    // ) -> crate::Result<Option<BlockHeader>> {
    //     let peer = self
    //         .peers
    //         .get_mut(peer_id)
    //         .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
    //
    //     let block = blocks.into_iter().next().expect("block to exist");
    //     let header = block.header().clone();
    //
    //     let result = match self
    //         .chainstate_handle
    //         .call(move |this| this.preliminary_block_check(block))
    //         .await?
    //     {
    //         Ok(block) => {
    //             self.chainstate_handle
    //                 .call_mut(move |this| this.process_block(block, chainstate::BlockSource::Peer))
    //                 .await?
    //         }
    //         Err(err) => Err(err),
    //     };
    //
    //     match result {
    //         Ok(_) => {}
    //         Err(ChainstateError::ProcessBlockError(BlockError::BlockAlreadyExists(_id))) => {}
    //         Err(err) => return Err(P2pError::ChainstateError(err)),
    //     }
    //
    //     peer.register_block_response(&header)
    // }
}

#[cfg(test)]
mod tests;
