// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
#![allow(unused)]
use crate::{
    error::{FatalError, P2pError, PeerError, ProtocolError},
    event,
    message::{Message, MessageType, SyncingMessage, SyncingRequest, SyncingResponse},
    net::{self, types::SyncingEvent, NetworkingService, SyncingCodecService},
};
use chainstate::{
    chainstate_interface, BlockError, BlockSource, ChainstateError::ProcessBlockError,
};
use common::{
    chain::{
        block::{Block, BlockHeader},
        config::ChainConfig,
    },
    primitives::{Id, Idable},
};
use futures::FutureExt;
use logging::log;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot};
use utils::ensure;

pub mod peer;
mod request;

// TODO: from config? global constant?
const HEADER_LIMIT: usize = 2000;

// TODO: this comes from spec?
const RETRY_LIMIT: usize = 3;

// TODO: add more tests
// TODO: match against error in `run()` and deal with `ProtocolError`
// TODO: cache locator and invalidate it when `NewTip` event is received

// Define which errors are fatal for the sync manager as the error is bubbled
// up to the main event loop which then decides how to act on errors.
// Peer not existing is not a fatal error for SyncManager but it is fatal error
// for the function that tries to update peer state.
//
// This is just a convenience method to have access to nicer error handling
impl<T> FatalError for crate::Result<T> {
    fn map_fatal_err(self) -> core::result::Result<(), P2pError> {
        if let Err(err) = self {
            match err {
                P2pError::ChannelClosed | P2pError::ChainstateError(_) => {
                    log::error!("fatal error occurred: {:#?}", err);
                    return Err(err);
                }
                _ => {
                    log::error!("non-fatal error occurred: {:#?}", err);
                }
            }
        }

        Ok(())
    }
}

/// Syncing state of the local node
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// Local node's state is uninitialized
    Uninitialized,

    /// Downloading blocks from remote node(s)
    DownloadingBlocks,

    /// Local block index is fully synced
    Idle,
}

/// Sync manager is responsible for syncing the local blockchain to the chain with most trust
/// and keeping up with updates to different branches of the blockchain.
///
/// It keeps track of the state of each individual peer and holds an intermediary block index
/// which represents the local block index of every peer it's connected to.
///
/// Currently its only mode of operation is greedy so it will download all changes from every
/// peer it's connected to and actively keep track of the peer's state.
pub struct SyncManager<T: NetworkingService> {
    /// Chain config
    config: Arc<ChainConfig>,

    /// Syncing state of the local node
    state: SyncState,

    /// Handle for sending/receiving connectivity events
    handle: T::SyncingCodecHandle,

    /// RX channel for receiving control events
    rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,

    /// TX channel for sending control events to swarm
    tx_swarm: mpsc::Sender<event::SwarmEvent<T>>,

    /// TX channel for sending control events to pubsub
    tx_pubsub: mpsc::Sender<event::PubSubControlEvent>,

    /// Hashmap of connected peers
    peers: HashMap<T::PeerId, peer::PeerContext<T>>,

    /// Subsystem handle to Chainstate
    chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,

    /// Pending requests
    requests: HashMap<T::RequestId, request::RequestState<T>>,
}

/// Syncing manager
impl<T> SyncManager<T>
where
    T: NetworkingService,
    T::SyncingCodecHandle: SyncingCodecService<T>,
{
    pub fn new(
        config: Arc<ChainConfig>,
        handle: T::SyncingCodecHandle,
        chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
        rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,
        tx_swarm: mpsc::Sender<event::SwarmEvent<T>>,
        tx_pubsub: mpsc::Sender<event::PubSubControlEvent>,
    ) -> Self {
        Self {
            config,
            handle,
            rx_sync,
            tx_swarm,
            tx_pubsub,
            chainstate_handle,
            peers: Default::default(),
            requests: HashMap::new(),
            state: SyncState::Uninitialized,
        }
    }

    /// Get current sync state
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// Get mutable reference to the handle
    pub fn handle_mut(&mut self) -> &mut T::SyncingCodecHandle {
        &mut self.handle
    }

    /// Register peer to the `SyncManager`
    pub async fn register_peer(&mut self, peer_id: T::PeerId) -> crate::Result<()> {
        match self.peers.entry(peer_id) {
            Entry::Occupied(_) => Err(P2pError::PeerError(PeerError::PeerAlreadyExists)),
            Entry::Vacant(entry) => {
                let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
                entry.insert(peer::PeerContext::new(peer_id, locator.clone()));
                self.send_header_request(peer_id, locator, 0).await
            }
        }
    }

    /// Unregister peer from the `SyncManager`
    pub fn unregister_peer(&mut self, peer_id: T::PeerId) {
        self.peers.remove(&peer_id);
    }

    /// Process header request
    pub async fn process_header_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        locator: Vec<BlockHeader>,
    ) -> crate::Result<()> {
        // TODO: check if remote has already asked for these headers?
        let headers = self.chainstate_handle.call(move |this| this.get_headers(locator)).await??;
        self.send_header_response(request_id, headers).await
    }

    /// Process block request
    pub async fn process_block_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        headers: Vec<Id<Block>>,
    ) -> crate::Result<()> {
        ensure!(
            headers.len() == 1,
            P2pError::ProtocolError(ProtocolError::InvalidMessage),
        );
        ensure!(
            self.peers.contains_key(&peer_id),
            P2pError::PeerError(PeerError::PeerDoesntExist),
        );

        // TODO: check if remote has already asked for these headers?

        let block_id = headers.get(0).expect("header to exist").clone();
        // TODO: check error
        let block = self
            .chainstate_handle
            .call(move |this| this.get_block(headers.get(0).expect("header to exist").clone()))
            .await??
            .ok_or_else(|| {
                // TODO: handle these two errors separate
                log::error!(
                    "peer {:?} requested block we don't have \
                        or database doesn't have a block it previously had, block id: {:?}",
                    peer_id,
                    block_id
                );
                P2pError::ProtocolError(ProtocolError::InvalidMessage)
            })?;

        self.send_block_response(request_id, vec![block]).await
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

        // make sure the first header attaches to the locator that was sent out
        let mut prev_id = headers
            .get(0)
            .expect("first header to exist")
            .prev_block_id()
            .clone()
            .ok_or_else(|| {
                // TODO: ban peer
                log::error!("peer {:?} sent a header with invalid previous id", peer_id);
                P2pError::ProtocolError(ProtocolError::InvalidMessage)
            })?;

        match peer.state() {
            peer::PeerSyncState::UploadingHeaders(ref locator) => {
                if !locator.iter().any(|header| header.get_id() == prev_id)
                    && self.config.genesis_block_id() != prev_id
                {
                    // TODO: ban peer
                    log::error!(
                        "peer {:?} sent headers that don't attach to the sent locator or to genesis block",
                        peer_id
                    );

                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                }
            }
            _ => {
                log::error!("peer is in wrong state to send header response");
                return Err(P2pError::ProtocolError(ProtocolError::InvalidState(
                    "",
                    "UploadingHeaders",
                )));
            }
        }

        for header in &headers {
            ensure!(
                header.prev_block_id() == &Some(prev_id),
                P2pError::ProtocolError(ProtocolError::InvalidMessage),
            );
            prev_id = header.get_id();
        }

        let unknown_headers = self
            .chainstate_handle
            .call(|this| this.filter_already_existing_blocks(headers))
            .await??;

        peer.register_header_response(&unknown_headers);
        Ok(peer.get_header_for_download())
    }

    /// Process incoming header response
    pub async fn process_header_response(
        &mut self,
        peer_id: T::PeerId,
        headers: Vec<BlockHeader>,
    ) -> crate::Result<()> {
        match self.validate_header_response(&peer_id, headers).await {
            Ok(Some(header)) => self.send_block_request(peer_id, header.get_id(), 0).await?,
            Ok(None) => self
                .peers
                .get_mut(&peer_id)
                .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
                .set_state(peer::PeerSyncState::Idle),
            Err(err) => {
                // TODO: handle errror, ban peer?
            }
        }

        Ok(())
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

        // TODO: check error, ban peer
        let header = blocks.get(0).expect("block to exist").header().clone();
        let block = blocks.into_iter().next().expect("block to exist");
        let result = self
            .chainstate_handle
            .call_mut(move |this| this.process_block(block, BlockSource::Peer))
            .await?;

        // TODO: check all errors
        // TODO: ban peer if needed
        match result {
            Ok(_) => {}
            Err(ProcessBlockError(BlockError::BlockAlreadyExists(id))) => {
                log::debug!("block {:?} already exists", id)
            }
            Err(e) => return Err(P2pError::ChainstateError(e)),
        }

        peer.register_block_response(&header)
    }

    /// Process block response
    pub async fn process_block_response(
        &mut self,
        peer_id: T::PeerId,
        blocks: Vec<Block>,
    ) -> crate::Result<()> {
        ensure!(
            blocks.len() == 1,
            P2pError::ProtocolError(ProtocolError::InvalidMessage),
        );

        match self.validate_block_response(&peer_id, blocks).await {
            Ok(Some(next_block)) => self.send_block_request(peer_id, next_block.get_id(), 0).await,
            Ok(None) => {
                // last block from peer received, ask if peer knows of any new headers
                let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
                self.send_header_request(peer_id, locator, 0).await
            }
            Err(e) => {
                // TODO: ban peer
                Ok(())
            }
        }
    }

    /// Check the current state of syncing
    ///
    /// The node is considered fully synced, i.e., that its initial block download is done, if:
    /// - all of its peers are in `Idle` state
    ///
    /// When the node is synced, [`crate::PubSubMessageHandler`] is notified so it knows to
    /// subscribe to the needed publish-subscribe topics.
    pub async fn check_state(&mut self) -> crate::Result<()> {
        // TODO: improve "initial block download done" check

        if self.peers.is_empty() {
            self.state = SyncState::Uninitialized;
            return Ok(());
        }

        for peer in self.peers.values() {
            match peer.state() {
                peer::PeerSyncState::UploadingBlocks(_) => {
                    self.state = SyncState::DownloadingBlocks;
                    return Ok(());
                }
                peer::PeerSyncState::UploadingHeaders(_) | peer::PeerSyncState::Unknown => {
                    self.state = SyncState::Uninitialized;
                    return Ok(());
                }
                peer::PeerSyncState::Idle => {}
            }
        }

        self.state = SyncState::Idle;
        // TODO: global event system
        self.tx_pubsub
            .send(event::PubSubControlEvent::InitialBlockDownloadDone)
            .await
            .map_err(P2pError::from)
    }

    pub async fn process_error(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        error: net::types::RequestResponseError,
    ) -> crate::Result<()> {
        match error {
            // TODO: through peermanager!
            net::types::RequestResponseError::ConnectionClosed => {
                self.unregister_peer(peer_id);
            }
            net::types::RequestResponseError::Timeout => {
                if let Some(request) = self.requests.remove(&request_id) {
                    log::warn!(
                        "outbound request {:?} for peer {:?} timed out",
                        request_id,
                        peer_id
                    );

                    if request.retry_count == RETRY_LIMIT {
                        log::error!(
                            "peer {:?} failed to respond to request, close connection",
                            peer_id
                        );
                        self.unregister_peer(peer_id);
                        // TODO: global event system
                        let (tx, rx) = oneshot::channel();
                        self.tx_swarm
                            .send(event::SwarmEvent::Disconnect(peer_id, tx))
                            .await
                            .map_err(P2pError::from)?;
                        return rx.await.map_err(P2pError::from)?;
                    }

                    match request.request_type {
                        request::RequestType::GetHeaders => {
                            let locator =
                                self.chainstate_handle.call(|this| this.get_locator()).await??;
                            self.send_header_request(peer_id, locator, request.retry_count + 1)
                                .await?;
                        }
                        request::RequestType::GetBlocks(block_ids) => {
                            assert_eq!(block_ids.len(), 1);
                            self.send_block_request(
                                peer_id,
                                block_ids.get(0).expect("block id to exist").clone(),
                                request.retry_count + 1,
                            )
                            .await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Run SyncManager event loop
    pub async fn run(&mut self) -> crate::Result<void::Void> {
        log::info!("Starting SyncManager");

        loop {
            tokio::select! {
                event = self.handle.poll_next() => match event? {
                    SyncingEvent::Request {
                        peer_id,
                        request_id,
                        request:
                            Message {
                                msg: MessageType::Syncing(SyncingMessage::Request(message)),
                                magic: _,
                            },
                    } => {
                        match message {
                            SyncingRequest::GetHeaders { locator } => {
                                log::debug!(
                                    "process header request (id {:?}) from peer {}",
                                    request_id, peer_id
                                );
                                log::trace!("locator: {:#?}", locator);

                                self.process_header_request(peer_id, request_id, locator).await?;
                            }
                            SyncingRequest::GetBlocks { block_ids } => {
                                log::debug!(
                                    "process block request (id {:?}) from peer {}",
                                    request_id, peer_id
                                );
                                log::trace!("requested block ids: {:#?}", block_ids);

                                self.process_block_request(peer_id, request_id, block_ids).await?;
                            }
                        }
                    }
                    SyncingEvent::Response {
                        peer_id,
                        request_id,
                        response:
                            Message {
                                msg: MessageType::Syncing(SyncingMessage::Response(message)),
                                magic: _,
                            },
                    } => {
                        match message {
                            SyncingResponse::Headers { headers } => {
                                log::debug!(
                                    "process header response (id {:?}) from peer {}",
                                    request_id, peer_id
                                );
                                log::trace!("received headers: {:#?}", headers);

                                self.process_header_response(peer_id, headers).await?;
                            }
                            SyncingResponse::Blocks { blocks } => {
                                log::debug!(
                                    "process block response (id {:?}) from peer {}",
                                    request_id, peer_id
                                );
                                log::trace!("# of received blocks: {:#?}", blocks.len());

                                self.process_block_response(peer_id, blocks).await?;
                            }
                        }
                    },
                    SyncingEvent::Error {
                        peer_id,
                        request_id,
                        error,
                    } => {
                        self.process_error(peer_id, request_id, error).await?;
                    },
                    SyncingEvent::Request { peer_id, .. } | SyncingEvent::Response { peer_id, .. } => {
                        log::error!("received an invalid message from peer {}", peer_id);
                        // TODO: disconnect peer and ban it
                        // TODO: send `Misbehaved` event to PeerManager
                        // return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                    }
                },
                event = self.rx_sync.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    event::SyncControlEvent::Connected(peer_id) => {
                        log::debug!("register peer {} to sync manager", peer_id);
                        self.register_peer(peer_id).await?;
                    }
                    event::SyncControlEvent::Disconnected(peer_id) => {
                        log::debug!("unregister peer {} from sync manager", peer_id);
                        self.unregister_peer(peer_id);
                    }
                }
            }

            // TODO: handle error
            self.check_state().await.map_fatal_err()?;
        }
    }
}

#[cfg(test)]
mod tests;
