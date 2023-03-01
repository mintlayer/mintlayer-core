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

use std::mem;

use itertools::Itertools;

use chainstate::{ban_score::BanScore, BlockError, BlockSource, ChainstateError, Locator};
use common::{
    chain::{block::BlockHeader, Block},
    primitives::{Id, Idable},
};
use logging::log;

use crate::{
    error::{P2pError, PeerError, ProtocolError},
    message::{Announcement, HeaderListResponse},
    sync::{BlockSyncManager, SyncMessage},
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    NetworkingService, PeerManagerEvent, Result, SyncingMessagingService,
};

impl<T> BlockSyncManager<T>
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    pub(super) async fn handle_message(
        &mut self,
        peer: PeerId,
        message: SyncMessage,
    ) -> Result<()> {
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
    async fn handle_header_request(&mut self, peer: PeerId, locator: Locator) -> Result<()> {
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

        if self.is_initial_block_download {
            // TODO: Check if a peer has permissions to ask for headers during the initial block download.
            log::debug!("Ignoring headers request because the node is in initial block download");
            return Ok(());
        }

        let limit = *self.p2p_config.msg_header_count_limit;
        let headers = self.chainstate_handle.call(move |c| c.get_headers(locator, limit)).await??;
        debug_assert!(headers.len() <= limit);
        self.messaging_handle.send_message(
            peer,
            SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
        )?;

        Ok(())
    }

    /// Processes the blocks request.
    async fn handle_block_request(
        &mut self,
        peer: PeerId,
        block_ids: Vec<Id<Block>>,
    ) -> Result<()> {
        log::debug!("Blocks request from peer {peer}");

        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        if self.is_initial_block_download {
            log::debug!("Ignoring blocks request because the node is in initial block download");
            return Ok(());
        }

        // Check that a peer doesn't exceed the blocks limit.
        self.p2p_config
            .max_request_blocks_count
            .checked_sub(block_ids.len())
            .and_then(|n| n.checked_sub(peer_state.num_blocks_to_send))
            .ok_or(P2pError::ProtocolError(
                ProtocolError::BlocksRequestLimitExceeded(
                    block_ids.len() + peer_state.num_blocks_to_send,
                    *self.p2p_config.max_request_blocks_count,
                ),
            ))?;
        log::trace!("Requested block ids: {block_ids:#?}");

        // Check that all blocks are known.
        let ids = block_ids.clone();
        self.chainstate_handle
            .call(move |c| {
                for id in ids {
                    c.get_block_index(&id)?.ok_or(P2pError::ProtocolError(
                        ProtocolError::UnknownBlockRequested,
                    ))?;
                }
                Result::<_>::Ok(())
            })
            .await??;

        peer_state.num_blocks_to_send += block_ids.len();
        self.blocks_queue.extend(block_ids.into_iter().map(|id| (peer, id)));

        Ok(())
    }

    async fn handle_header_response(
        &mut self,
        peer: PeerId,
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
            .tuple_windows()
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

    async fn handle_block_response(&mut self, peer: PeerId, block: Block) -> Result<()> {
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

        let block = self.chainstate_handle.call(|c| c.preliminary_block_check(block)).await??;
        match self
            .chainstate_handle
            .call_mut(|c| c.process_block(block, BlockSource::Peer))
            .await?
        {
            Ok(_) => Ok(()),
            // It is OK to receive an already processed block.
            Err(ChainstateError::ProcessBlockError(BlockError::BlockAlreadyExists(_))) => Ok(()),
            Err(e) => Err(e),
        }?;

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

    pub(super) async fn handle_announcement(
        &mut self,
        peer: PeerId,
        announcement: Announcement,
    ) -> Result<()> {
        match announcement {
            Announcement::Block(header) => self.handle_block_announcement(peer, header).await,
        }
    }

    async fn handle_block_announcement(&mut self, peer: PeerId, header: BlockHeader) -> Result<()> {
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
        self.chainstate_handle.call(|c| c.preliminary_header_check(header_)).await??;
        self.request_blocks(peer, vec![header])
    }

    /// Handles a result of message processing.
    ///
    /// There are three possible types of errors:
    /// - Fatal errors will be propagated by this function effectively stopping the sync manager
    ///   and the whole p2p subsystem.
    /// - Non-fatal errors aren't propagated, but the peer score will be increased by the
    ///   "ban score" value of the given error.
    /// - Ignored errors aren't propagated and don't affect the peer score.
    pub async fn handle_result(&mut self, peer: PeerId, result: Result<()>) -> Result<()> {
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
            | P2pError::StorageFailure(_)
            | P2pError::InvalidStorageState(_)) => Err(e),
        }
    }
}
