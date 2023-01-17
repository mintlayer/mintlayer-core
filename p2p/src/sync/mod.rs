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

pub mod peer;

mod request;

use std::{collections::HashMap, sync::Arc};

use tokio::sync::{mpsc, oneshot};
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
use utils::{ensure, tap_error_log::LogError};

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError, ProtocolError},
    event::{PeerManagerEvent, SyncControlEvent},
    message::{self, Announcement, SyncRequest},
    net::{types::SyncingEvent, NetworkingService, SyncingMessagingService},
};

// TODO: from config? global constant?
const HEADER_LIMIT: usize = 2000;

// TODO: add more tests
// TODO: cache locator and invalidate it when `NewTip` event is received

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
    _p2p_config: Arc<P2pConfig>,

    /// Handle for sending/receiving syncing events
    peer_sync_handle: T::SyncingMessagingHandle,

    /// RX channel for receiving control events
    rx_sync: mpsc::UnboundedReceiver<SyncControlEvent<T>>,

    /// A sender for the peer manager events.
    tx_peer_manager: mpsc::UnboundedSender<PeerManagerEvent<T>>,

    /// Hashmap of connected peers
    peers: HashMap<T::PeerId, peer::PeerContext<T>>,

    /// Subsystem handle to Chainstate
    chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
}

/// Syncing manager
impl<T> BlockSyncManager<T>
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::SyncingPeerRequestId: 'static,
    T::PeerId: 'static,
{
    pub fn new(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        handle: T::SyncingMessagingHandle,
        chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
        rx_sync: mpsc::UnboundedReceiver<SyncControlEvent<T>>,
        tx_peer_manager: mpsc::UnboundedSender<PeerManagerEvent<T>>,
    ) -> Self {
        Self {
            chain_config,
            _p2p_config: p2p_config,
            peer_sync_handle: handle,
            rx_sync,
            tx_peer_manager,
            chainstate_handle,
            peers: Default::default(),
        }
    }

    /// Get mutable reference to the handle
    pub fn handle_mut(&mut self) -> &mut T::SyncingMessagingHandle {
        // TODO: get rid of this function as it's used only in tests; perhaps a better way to do this is by
        // creating p2p objects and make them communicate together instead of having access to internal
        // private parts of the sync manager
        &mut self.peer_sync_handle
    }

    /// Register peer to the `SyncManager`
    pub async fn register_peer(&mut self, peer_id: T::PeerId) -> crate::Result<()> {
        ensure!(
            !self.peers.contains_key(&peer_id),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );

        let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;

        self.send_request(
            peer_id,
            SyncRequest::HeaderListRequest(message::HeaderListRequest::new(locator.clone())),
        )
        .await
        .map(|_| {
            self.peers.insert(
                peer_id,
                peer::PeerContext::new_with_locator(peer_id, locator),
            );
        })
    }

    /// Unregister peer from the `SyncManager`
    pub fn unregister_peer(&mut self, peer_id: T::PeerId) {
        self.peers.remove(&peer_id);
    }

    /// Process header request
    pub async fn process_header_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::SyncingPeerRequestId,
        locator: Locator,
    ) -> crate::Result<()> {
        log::debug!("send header response to peer {peer_id}, request_id: {request_id:?}");

        // TODO: check if remote has already asked for these headers?
        let headers = self.chainstate_handle.call(move |this| this.get_headers(locator)).await??;
        self.send_header_response(request_id, headers).await
    }

    /// Process block request
    pub async fn process_block_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::SyncingPeerRequestId,
        headers: Vec<Id<Block>>,
    ) -> crate::Result<()> {
        ensure!(
            headers.len() == 1,
            P2pError::ProtocolError(ProtocolError::InvalidMessage),
        );

        // TODO: handle processing requests for multiple blocks
        let block_id =
            *headers.get(0).ok_or(P2pError::ProtocolError(ProtocolError::InvalidMessage))?;
        ensure!(
            self.peers.contains_key(&peer_id),
            P2pError::PeerError(PeerError::PeerDoesntExist),
        );

        let block_result =
            self.chainstate_handle.call(move |this| this.get_block(block_id)).await?;

        match block_result {
            Ok(Some(block)) => self.send_block_response(request_id, vec![block]).await,
            Ok(None) => {
                // TODO: check if remote has already asked for these headers?
                Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
            }
            Err(err) => Err(P2pError::ChainstateError(err)),
        }
    }

    /// Validate incoming header response
    async fn validate_header_response(
        &mut self,
        peer_id: &T::PeerId,
        headers: Vec<BlockHeader>,
    ) -> crate::Result<Option<BlockHeader>> {
        ensure!(
            headers.len() <= HEADER_LIMIT,
            P2pError::ProtocolError(ProtocolError::InvalidMessage),
        );

        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        // empty response means that local and remote are in sync
        if headers.is_empty() {
            return Ok(None);
        }

        // verify that the first headers attaches to local and chain
        // and that the received headers are in order
        match peer.state() {
            peer::PeerSyncState::UploadingHeaders(ref locator) => {
                let genesis_id = self.chain_config.genesis_block_id();
                let mut locator = locator.iter().chain(std::iter::once(&genesis_id));
                let anchor_point = headers[0].prev_block_id();
                ensure!(
                    locator.any(|id| anchor_point == id),
                    P2pError::ProtocolError(ProtocolError::InvalidMessage),
                );
            }
            _ => return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
        }

        for (a, b) in headers.iter().zip(&headers[1..]) {
            ensure!(
                b.prev_block_id() == &a.get_id(),
                P2pError::ProtocolError(ProtocolError::InvalidMessage),
            );
        }

        // call chainstate to get the blocks that the local node doesn't know about
        match self
            .chainstate_handle
            .call(|this| this.filter_already_existing_blocks(headers))
            .await?
        {
            Ok(headers) => {
                peer.register_header_response(&headers);
                Ok(peer.get_header_for_download())
            }
            Err(err) => Err(P2pError::ChainstateError(err)),
        }
    }

    /// Process incoming header response
    pub async fn process_header_response(
        &mut self,
        peer_id: T::PeerId,
        headers: Vec<BlockHeader>,
    ) -> crate::Result<()> {
        match self.validate_header_response(&peer_id, headers).await {
            Ok(Some(header)) => self.send_block_request(peer_id, header.get_id()).await,
            Ok(None) => {
                self.peers
                    .get_mut(&peer_id)
                    .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
                    .set_state(peer::PeerSyncState::Idle);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Validate incoming block response
    async fn validate_block_response(
        &mut self,
        peer_id: &T::PeerId,
        blocks: Vec<Block>,
    ) -> crate::Result<Option<BlockHeader>> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        let block = blocks.into_iter().next().expect("block to exist");
        let header = block.header().clone();

        let result = match self
            .chainstate_handle
            .call(move |this| this.preliminary_block_check(block))
            .await?
        {
            Ok(block) => {
                self.chainstate_handle
                    .call_mut(move |this| this.process_block(block, chainstate::BlockSource::Peer))
                    .await?
            }
            Err(err) => Err(err),
        };

        match result {
            Ok(_) => {}
            Err(ChainstateError::ProcessBlockError(BlockError::BlockAlreadyExists(_id))) => {}
            Err(err) => return Err(P2pError::ChainstateError(err)),
        }

        peer.register_block_response(&header)
    }

    /// Process block response
    pub async fn process_block_response(
        &mut self,
        peer_id: T::PeerId,
        blocks: Vec<Block>,
    ) -> crate::Result<()> {
        // TODO: remove the limitation of sending only one block, and allow sending multiple blocks (up to a cap)
        ensure!(
            blocks.len() == 1,
            P2pError::ProtocolError(ProtocolError::InvalidMessage),
        );

        match self.validate_block_response(&peer_id, blocks).await {
            Ok(Some(next_block)) => self.send_block_request(peer_id, next_block.get_id()).await,
            Ok(None) => {
                // last block from peer received, ask if peer knows of any new headers
                let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
                self.send_header_request(peer_id, locator).await
            }
            Err(err) => Err(err),
        }
    }

    pub async fn process_response(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::SyncingPeerRequestId,
        response: message::SyncResponse,
    ) -> crate::Result<()> {
        match response {
            message::SyncResponse::HeaderListResponse(response) => {
                log::debug!("process header response (id {request_id:?}) from peer {peer_id}");
                log::trace!("received headers: {:#?}", response.headers());

                let result = self.process_header_response(peer_id, response.into_headers()).await;
                self.handle_error(peer_id, result).await?;
            }
            message::SyncResponse::BlockListResponse(response) => {
                log::debug!("process block response (id {request_id:?}) from peer {peer_id}");
                log::trace!(
                    "# of received blocks: {}, block ids: {:#?}",
                    response.blocks().len(),
                    response.blocks().iter().map(|block| block.get_id()).collect::<Vec<_>>(),
                );

                let result = self.process_block_response(peer_id, response.into_blocks()).await;
                self.handle_error(peer_id, result).await?;
            }
        }

        Ok(())
    }

    pub async fn process_announcement(
        &mut self,
        peer_id: T::PeerId,
        announcement: Announcement,
    ) -> crate::Result<()> {
        // TODO: Discuss if we should announce blocks or headers, because announcing
        // blocks seems wasteful, in the sense that it's possible for peers to get
        // blocks again, and again, wasting their bandwidth.
        match announcement {
            Announcement::Block(block) => self.process_block_announcement(peer_id, block).await,
        }
    }

    // TODO: refactor this
    pub async fn handle_error(
        &mut self,
        peer_id: T::PeerId,
        result: crate::Result<()>,
    ) -> crate::Result<()> {
        match result {
            Ok(_) => Ok(()),
            Err(P2pError::ChannelClosed) => Err(P2pError::ChannelClosed),
            Err(P2pError::ProtocolError(err)) => {
                log::error!("Peer {peer_id} committed a protocol error: {err}");

                let (tx, rx) = oneshot::channel();
                self.tx_peer_manager
                    .send(PeerManagerEvent::AdjustPeerScore(
                        peer_id,
                        err.ban_score(),
                        tx,
                    ))
                    .map_err(P2pError::from)?;
                rx.await.map_err(P2pError::from)?
            }
            Err(P2pError::ChainstateError(err)) => match err {
                ChainstateError::ProcessBlockError(err) => {
                    if err.ban_score() > 0 {
                        let (tx, rx) = oneshot::channel();
                        self.tx_peer_manager
                            .send(PeerManagerEvent::AdjustPeerScore(
                                peer_id,
                                err.ban_score(),
                                tx,
                            ))
                            .map_err(P2pError::from)?;
                        let _ = rx.await.map_err(P2pError::from);
                    }

                    Ok(())
                }
                err => {
                    log::error!("Peer {peer_id} caused a chainstate error: {err}");
                    Ok(())
                }
            },
            Err(P2pError::PeerError(err)) => {
                log::error!("Peer error: {err}");
                Ok(())
            }
            Err(err) => {
                log::error!("Unexpected error occurred: {err}");

                if err.ban_score() > 0 {
                    // TODO: better abstraction over channels
                    let (tx, rx) = oneshot::channel();
                    self.tx_peer_manager
                        .send(PeerManagerEvent::AdjustPeerScore(
                            peer_id,
                            err.ban_score(),
                            tx,
                        ))
                        .map_err(P2pError::from)?;
                    let _ = rx.await.map_err(P2pError::from);
                }

                Ok(())
            }
        }
    }

    /// Runs the SyncManager event loop.
    pub async fn run(&mut self) -> crate::Result<Void> {
        log::info!("Starting SyncManager");

        let mut block_rx = self.subscribe_to_chainstate_events().await?;

        loop {
            tokio::select! {
                event = self.peer_sync_handle.poll_next() => match event? {
                    SyncingEvent::Request {
                        peer_id,
                        request_id,
                        request,
                    } => match request {
                        message::SyncRequest::HeaderListRequest(request) => {
                            log::debug!("process header request (id {request_id:?}) from peer {peer_id}");
                            log::trace!("locator: {:#?}", request.locator());

                            let result = self.process_header_request(
                                peer_id,
                                request_id,
                                request.into_locator(),
                            ).await;
                            self.handle_error(peer_id, result).await?;
                        }
                        message::SyncRequest::BlockListRequest(request) => {
                            log::debug!("process block request (id {request_id:?}) from peer {peer_id}");
                            log::trace!("requested block ids: {:#?}", request.block_ids());

                            let result = self.process_block_request(
                                peer_id,
                                request_id,
                                request.into_block_ids(),
                            ).await;
                            self.handle_error(peer_id, result).await?;
                        }
                    },
                    SyncingEvent::Response {
                        peer_id,
                        request_id,
                        response,
                    } => {
                        self.process_response(peer_id, request_id, response).await?;
                    },
                    SyncingEvent::Announcement{ peer_id, announcement } => {
                        self.process_announcement(peer_id, announcement).await?;
                    }
                },
                event = self.rx_sync.recv() => match event.ok_or(P2pError::ChannelClosed)? {
                    SyncControlEvent::Connected(peer_id) => {
                        log::debug!("register peer {peer_id} to sync manager");
                        let result = self.register_peer(peer_id).await;
                        self.handle_error(peer_id, result).await?;
                    }
                    SyncControlEvent::Disconnected(peer_id) => {
                        log::debug!("unregister peer {peer_id} from sync manager");
                        self.unregister_peer(peer_id)
                    }
                },
                block_id = block_rx.recv(), if !self.chainstate_handle.call(|c| c.is_initial_block_download()).await?? => {
                    let block_id = block_id.ok_or(P2pError::ChannelClosed)?;

                    match self.chainstate_handle.call(move |this| this.get_block(block_id)).await?? {
                        Some(block) => {
                            let _ = self.peer_sync_handle.make_announcement(Announcement::Block(block)).await.log_err();
                        }
                        None => log::error!("CRITICAL: best block not available"),
                    }
                }
            }
        }
    }

    /// Returns a receiver for the chainstate `NewTip` events.
    async fn subscribe_to_chainstate_events(
        &mut self,
    ) -> crate::Result<mpsc::UnboundedReceiver<Id<Block>>> {
        let (tx, rx) = mpsc::unbounded_channel();

        let subscribe_func =
            Arc::new(
                move |chainstate_event: chainstate::ChainstateEvent| match chainstate_event {
                    chainstate::ChainstateEvent::NewTip(block_id, _) => {
                        if let Err(e) = tx.send(block_id) {
                            log::error!("PubSubMessageHandler closed: {e:?}")
                        }
                    }
                },
            );

        self.chainstate_handle
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .map_err(|_| P2pError::SubsystemFailure)?;

        Ok(rx)
    }

    async fn process_block_announcement(
        &mut self,
        peer_id: T::PeerId,
        block: Block,
    ) -> crate::Result<()> {
        let result = match self
            .chainstate_handle
            .call(move |this| this.preliminary_block_check(block))
            .await?
        {
            Ok(block) => {
                self.chainstate_handle
                    .call_mut(move |this| this.process_block(block, chainstate::BlockSource::Peer))
                    .await?
            }
            Err(err) => Err(err),
        };

        let score = match result {
            Ok(_) => 0,
            Err(e) => match e {
                ChainstateError::FailedToInitializeChainstate(_) => 0,
                ChainstateError::ProcessBlockError(err) => err.ban_score(),
                ChainstateError::FailedToReadProperty(_) => 0,
                ChainstateError::BootstrapError(_) => 0,
            },
        };

        if score > 0 {
            // TODO: better abstraction over channels
            let (tx, rx) = oneshot::channel();
            self.tx_peer_manager
                .send(PeerManagerEvent::AdjustPeerScore(peer_id, score, tx))
                .map_err(P2pError::from)?;
            let _ = rx.await.map_err(P2pError::from)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
