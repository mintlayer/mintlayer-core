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
use crate::{
    error::{FatalError, P2pError, PeerError, ProtocolError},
    event,
    message::{Message, MessageType, SyncingMessage, SyncingRequest, SyncingResponse},
    net::{self, NetworkingService, SyncingCodecService},
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

pub mod peer;

// TODO: from config? global constant?
const HEADER_LIMIT: usize = 2000;

// TODO: this comes from spec?
const RETRY_LIMIT: usize = 3;

// TODO: add more tests
// TODO: split syncing into separate files
// TODO: match against error in `run()` and deal with `ProtocolError`
// TODO: use ensure
// TODO: create better api for request/response codec
// TODO: create helper function for creating requests/responses
// TODO: cache locator and invalidate it when `NewTip` event is received
// TODO: simplify code: remove code duplication, move code to submodules, add req/resp api, etc.

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

enum RequestType {
    GetHeaders,
    GetBlocks(Vec<Id<Block>>),
}

struct PendingRequest<T: NetworkingService> {
    _peer_id: T::PeerId,
    request_type: RequestType,
    retry_count: usize,
}

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
pub struct SyncManager<T>
where
    T: NetworkingService,
{
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
    requests: HashMap<T::RequestId, PendingRequest<T>>,
}

// TODO: refactor this code
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

    pub fn state(&self) -> &SyncState {
        &self.state
    }

    pub fn handle_mut(&mut self) -> &mut T::SyncingCodecHandle {
        &mut self.handle
    }

    pub async fn send_header_request(
        &mut self,
        peer_id: T::PeerId,
        locator: Vec<BlockHeader>,
        retry_count: usize,
    ) -> crate::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        let request_id = self
            .handle
            .send_request(
                peer_id,
                Message {
                    magic: *self.config.magic_bytes(),
                    msg: MessageType::Syncing(SyncingMessage::Request(
                        SyncingRequest::GetHeaders { locator },
                    )),
                },
            )
            .await?;
        self.requests.insert(
            request_id,
            PendingRequest {
                _peer_id: peer_id,
                request_type: RequestType::GetHeaders,
                retry_count,
            },
        );
        peer.set_state(peer::PeerSyncState::UploadingHeaders);

        Ok(())
    }

    pub async fn send_block_request(
        &mut self,
        peer_id: T::PeerId,
        block_id: Id<Block>,
        retry_count: usize,
    ) -> crate::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        let request_id = self
            .handle
            .send_request(
                peer_id,
                Message {
                    magic: *self.config.magic_bytes(),
                    msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                        block_ids: vec![block_id.clone()],
                    })),
                },
            )
            .await?;
        self.requests.insert(
            request_id,
            PendingRequest {
                _peer_id: peer_id,
                request_type: RequestType::GetBlocks(vec![block_id.clone()]),
                retry_count,
            },
        );
        peer.set_state(peer::PeerSyncState::UploadingBlocks(block_id));

        Ok(())
    }

    pub async fn register_peer(&mut self, peer_id: T::PeerId) -> crate::Result<()> {
        log::info!("register peer {:?} to sync manager", peer_id);

        match self.peers.entry(peer_id) {
            Entry::Occupied(_) => {
                log::error!("peer {:?} already known by sync manager", peer_id);
                Err(P2pError::PeerError(PeerError::PeerAlreadyExists))
            }
            Entry::Vacant(entry) => {
                let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
                entry.insert(peer::PeerContext::new(peer_id, locator.clone()));
                self.send_header_request(peer_id, locator, 0).await
            }
        }
    }

    pub fn unregister_peer(&mut self, peer_id: T::PeerId) {
        log::info!("unregister peer {:?}", peer_id);

        self.peers.remove(&peer_id);
    }

    pub async fn process_header_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        locator: Vec<BlockHeader>,
    ) -> crate::Result<()> {
        log::trace!(
            "received a header request from peer {:?}, locator {:#?}",
            peer_id,
            locator
        );

        let headers = self.chainstate_handle.call(move |this| this.get_headers(locator)).await??;
        self.handle
            .send_response(
                request_id,
                Message {
                    magic: *self.config.magic_bytes(),
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers,
                    })),
                },
            )
            .await
    }

    async fn process_block_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        headers: Vec<Id<Block>>,
    ) -> crate::Result<()> {
        log::trace!(
            "received a block request from peer {:?}, header counter {}",
            peer_id,
            headers.len(),
        );

        if headers.len() != 1 {
            log::error!("expected 1 header, received {} headers", headers.len());
            return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
        }

        let _peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        let block_id = headers.get(0).expect("header to exist").clone();
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

        self.handle
            .send_response(
                request_id,
                Message {
                    magic: *self.config.magic_bytes(),
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Blocks {
                        blocks: vec![block],
                    })),
                },
            )
            .await
    }

    // TODO: get rid of the awful `set_state()` calls
    // TODO: simplify this code massively
    async fn process_header_response(
        &mut self,
        peer_id: T::PeerId,
        headers: Vec<BlockHeader>,
    ) -> crate::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        log::debug!(
            "initialize peer {:?} state, number of headers: {}",
            peer_id,
            headers.len(),
        );
        log::trace!("headers: {:#?}", headers);

        if headers.len() > HEADER_LIMIT {
            // TODO: ban peer
            log::error!(
                "peer sent {} headers while the maximum is {}",
                headers.len(),
                HEADER_LIMIT
            );
            return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
        }
        if headers.is_empty() {
            log::debug!("local node is in sync with peer {:?}", peer_id);
            peer.set_state(peer::PeerSyncState::Idle);
            return Ok(());
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

        if !peer.locator().iter().any(|header| header.get_id() == prev_id)
            && self.config.genesis_block_id() != prev_id
        {
            // TODO: ban peer
            log::error!(
                "peer {:?} sent headers that don't attach to the sent locator or to genesis block",
                peer_id
            );

            return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
        }

        for header in &headers {
            if header.prev_block_id() != &Some(prev_id) {
                log::error!("peer {:?} sent headers that are out of order", peer_id);
                return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
            }
            prev_id = header.get_id();
        }

        let unknown_headers = self
            .chainstate_handle
            .call(|this| this.filter_already_existing_blocks(headers))
            .await??;

        peer.register_header_response(&unknown_headers);
        if let Some(header) = peer.get_header_for_download() {
            let request_id = self
                .handle
                .send_request(
                    peer_id,
                    Message {
                        magic: *self.config.magic_bytes(),
                        msg: MessageType::Syncing(SyncingMessage::Request(
                            SyncingRequest::GetBlocks {
                                block_ids: vec![header.get_id()],
                            },
                        )),
                    },
                )
                .await?;
            self.requests.insert(
                request_id,
                PendingRequest {
                    _peer_id: peer_id,
                    request_type: RequestType::GetBlocks(vec![header.get_id()]),
                    retry_count: 0,
                },
            );
            peer.set_state(peer::PeerSyncState::UploadingBlocks(header.get_id()));
        } else {
            peer.set_state(peer::PeerSyncState::Idle);
        }

        Ok(())
    }

    // TODO: create process_block function?
    async fn process_block_response(
        &mut self,
        peer_id: T::PeerId,
        blocks: Vec<Block>,
    ) -> crate::Result<()> {
        log::trace!("received {} blocks from peer {:?}", blocks.len(), peer_id,);

        if blocks.len() != 1 {
            log::error!("expected 1 block, received {} blocks", blocks.len());
            return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
        }

        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        // TODO: check error, ban peer
        let header = blocks.get(0).expect("block to exist").header().clone();
        let block = blocks.into_iter().next().expect("block to exist");
        let result = self
            .chainstate_handle
            .call_mut(move |this| this.process_block(block, BlockSource::Peer))
            .await?;

        match result {
            Ok(_) => {}
            Err(ProcessBlockError(BlockError::BlockAlreadyExists(id))) => {
                log::debug!("block {:?} already exists", id)
            }
            Err(e) => return Err(P2pError::ChainstateError(e)),
        }

        let next_header = peer.register_block_response(&header);
        match next_header {
            Ok(Some(next_block)) => {
                let request_id = self
                    .handle
                    .send_request(
                        peer_id,
                        Message {
                            magic: *self.config.magic_bytes(),
                            msg: MessageType::Syncing(SyncingMessage::Request(
                                SyncingRequest::GetBlocks {
                                    block_ids: vec![next_block.get_id()],
                                },
                            )),
                        },
                    )
                    .await?;
                self.requests.insert(
                    request_id,
                    PendingRequest {
                        _peer_id: peer_id,
                        request_type: RequestType::GetBlocks(vec![next_block.get_id()]),
                        retry_count: 0,
                    },
                );
                peer.set_state(peer::PeerSyncState::UploadingBlocks(next_block.get_id()));
                Ok(())
            }
            Ok(None) => {
                // last block from peer, ask if peer knows of any new headers
                let locator = self.chainstate_handle.call(|this| this.get_locator()).await??;
                peer.set_locator(locator.clone());
                let request_id = self
                    .handle
                    .send_request(
                        peer_id,
                        Message {
                            magic: *self.config.magic_bytes(),
                            msg: MessageType::Syncing(SyncingMessage::Request(
                                SyncingRequest::GetHeaders { locator },
                            )),
                        },
                    )
                    .await?;
                self.requests.insert(
                    request_id,
                    PendingRequest {
                        _peer_id: peer_id,
                        request_type: RequestType::GetHeaders,
                        retry_count: 0,
                    },
                );
                peer.set_state(peer::PeerSyncState::UploadingHeaders);
                Ok(())
            }
            Err(e) => {
                // TODO: ban peer
                log::error!(
                    "peer sent invalid or unexpected data, close connection: {:?}",
                    e
                );
                Ok(())
            }
        }
    }

    // if all peers are idling, then it means we're idling -> fully synced
    pub async fn check_state(&mut self) -> crate::Result<()> {
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
                peer::PeerSyncState::UploadingHeaders | peer::PeerSyncState::Unknown => {
                    self.state = SyncState::Uninitialized;
                    return Ok(());
                }
                peer::PeerSyncState::Idle => {}
            }
        }

        self.state = SyncState::Idle;
        self.tx_pubsub
            .send(event::PubSubControlEvent::InitialBlockDownloadDone)
            .await
            .map_err(P2pError::from)
    }

    async fn process_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        request: SyncingRequest,
    ) -> crate::Result<()> {
        match request {
            SyncingRequest::GetHeaders { locator } => {
                self.process_header_request(peer_id, request_id, locator).await
            }
            SyncingRequest::GetBlocks { block_ids } => {
                self.process_block_request(peer_id, request_id, block_ids).await
            }
        }
    }

    async fn process_response(
        &mut self,
        peer_id: T::PeerId,
        response: SyncingResponse,
    ) -> crate::Result<()> {
        match response {
            SyncingResponse::Headers { headers } => {
                self.process_header_response(peer_id, headers).await
            }
            SyncingResponse::Blocks { blocks } => {
                self.process_block_response(peer_id, blocks).await
            }
        }
    }

    async fn process_error(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        error: net::types::RequestResponseError,
    ) -> crate::Result<()> {
        match error {
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
                        let (tx, rx) = oneshot::channel();
                        self.tx_swarm
                            .send(event::SwarmEvent::Disconnect(peer_id, tx))
                            .await
                            .map_err(P2pError::from)?;
                        return rx.await.map_err(P2pError::from)?;
                    }

                    match request.request_type {
                        RequestType::GetHeaders => {
                            let locator =
                                self.chainstate_handle.call(|this| this.get_locator()).await??;
                            self.send_header_request(peer_id, locator, request.retry_count + 1)
                                .await?;
                        }
                        RequestType::GetBlocks(block_ids) => {
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

    /// Handle incoming block/header request/response
    pub async fn on_syncing_event(
        &mut self,
        event: net::types::SyncingEvent<T>,
    ) -> crate::Result<()> {
        match event {
            net::types::SyncingEvent::Request {
                peer_id,
                request_id,
                request:
                    Message {
                        msg: MessageType::Syncing(SyncingMessage::Request(message)),
                        magic: _,
                    },
            } => {
                log::debug!(
                    "process incoming request (id {:?}) from peer {:?}",
                    request_id,
                    peer_id
                );
                self.process_request(peer_id, request_id, message).await
            }
            net::types::SyncingEvent::Response {
                peer_id,
                request_id,
                response:
                    Message {
                        msg: MessageType::Syncing(SyncingMessage::Response(message)),
                        magic: _,
                    },
            } => {
                log::debug!(
                    "process incoming response (id {:?}) from peer {:?}",
                    request_id,
                    peer_id
                );
                self.process_response(peer_id, message).await
            }
            net::types::SyncingEvent::Error {
                peer_id,
                request_id,
                error,
            } => self.process_error(peer_id, request_id, error).await,
            net::types::SyncingEvent::Request { peer_id, .. }
            | net::types::SyncingEvent::Response { peer_id, .. } => {
                log::error!("received an invalid message from peer {:?}", peer_id);
                // TODO: disconnect peer and ban it
                // TODO: send `Misbehaved` event to PeerManager
                Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
            }
        }
    }

    /// Handle control-related sync event from P2P/PeerManager
    async fn on_control_event(&mut self, event: event::SyncControlEvent<T>) -> crate::Result<()> {
        match event {
            event::SyncControlEvent::Connected(peer_id) => self.register_peer(peer_id).await,
            event::SyncControlEvent::Disconnected(peer_id) => {
                self.unregister_peer(peer_id);
                Ok(())
            }
        }
    }

    /// Run SyncManager event loop
    pub async fn run(&mut self) -> crate::Result<()> {
        log::info!("starting sync manager event loop");

        loop {
            tokio::select! {
                res = self.handle.poll_next() => {
                    self.on_syncing_event(res?).await.map_fatal_err()?;
                }
                res = self.rx_sync.recv().fuse() => {
                    self.on_control_event(res.ok_or(P2pError::ChannelClosed)?).await.map_fatal_err()?;
                }
            }

            self.check_state().await.map_fatal_err()?;
        }
    }
}

#[cfg(test)]
mod tests;
