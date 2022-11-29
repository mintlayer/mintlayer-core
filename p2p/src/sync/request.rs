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

//! Utility functions for sending header/block requests/responses

use tokio::time::{self, Duration};

use chainstate::Locator;
use common::{
    chain::{block::BlockHeader, Block},
    primitives::Id,
};
use logging::log;
use utils::ensure;

use crate::{
    error::{P2pError, PeerError},
    message,
    sync::{peer::PeerSyncState, BlockSyncManager},
    NetworkingService, SyncingMessagingService,
};

impl<T> BlockSyncManager<T>
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::SyncingPeerRequestId: 'static,
    T::PeerId: 'static,
{
    /// Creates a blocks request message.
    pub fn make_block_request(&self, block_ids: Vec<Id<Block>>) -> message::Request {
        message::Request::BlockListRequest(message::BlockListRequest::new(block_ids))
    }

    /// Creates a headers request message with the given locator.
    pub fn make_header_request(&self, locator: Locator) -> message::Request {
        message::Request::HeaderListRequest(message::HeaderListRequest::new(locator))
    }

    /// Make header response
    ///
    /// # Arguments
    /// * `headers` - the headers that were requested
    pub fn make_header_response(&self, headers: Vec<BlockHeader>) -> message::Response {
        message::Response::HeaderListResponse(message::HeaderListResponse::new(headers))
    }

    /// Make block response
    ///
    /// # Arguments
    /// * `blocks` - the blocks that were requested
    pub fn make_block_response(&self, blocks: Vec<Block>) -> message::Response {
        message::Response::BlockListResponse(message::BlockListResponse::new(blocks))
    }

    /// Sends a request to the given peer.
    pub async fn send_request(
        &mut self,
        peer_id: T::PeerId,
        request: message::Request,
    ) -> crate::Result<()> {
        let request_id = self.peer_sync_handle.send_request(peer_id, request).await?;
        let is_inserted = self.pending_responses.insert(request_id);
        debug_assert!(is_inserted);

        let timeout = self.p2p_config.request_timeout.clone().into();
        let sender = self.timeouts_sender.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_secs(timeout)).await;
            let _ = sender.send((request_id, peer_id));
        });

        Ok(())
    }

    /// Send block request to remote peer
    ///
    /// Send block request to remote peer and update the state to `UploadingBlocks`.
    /// For now only one block can be requested at a time
    ///
    /// # Arguments
    /// * `peer_id` - peer ID of the remote node
    /// * `block_id` - ID of the block that is requested
    /// * `retry_count` - how many times the request has been resent
    pub async fn send_block_request(
        &mut self,
        peer_id: T::PeerId,
        block_id: Id<Block>,
    ) -> crate::Result<()> {
        ensure!(
            self.peers.contains_key(&peer_id),
            P2pError::PeerError(PeerError::PeerDoesntExist),
        );

        log::trace!("send block request to {peer_id}, block id {block_id}");

        // send request to remote peer and start tracking its progress
        let wanted_blocks = self.make_block_request(vec![block_id]);
        self.send_request(peer_id, wanted_blocks).await?;

        self.peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
            .set_state(PeerSyncState::UploadingBlocks(block_id));
        Ok(())
    }

    /// Send header request to remote peer
    ///
    /// Send header request to remote peer and update the state to `UploadingHeaders`.
    /// For now the number of headers is limited to one header
    ///
    /// # Arguments
    /// * `peer_id` - peer ID of the remote node
    /// * `locator` - local locator object
    /// * `retry_count` - how many times the request has been resent
    pub async fn send_header_request(
        &mut self,
        peer_id: T::PeerId,
        locator: Locator,
    ) -> crate::Result<()> {
        ensure!(
            self.peers.contains_key(&peer_id),
            P2pError::PeerError(PeerError::PeerDoesntExist),
        );

        log::trace!("send header request to {peer_id}");

        // send header request and start tracking its progress
        let wanted_headers = self.make_header_request(locator.clone());
        self.send_request(peer_id, wanted_headers).await?;

        self.peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?
            .set_state(PeerSyncState::UploadingHeaders(locator));
        Ok(())
    }

    /// Send header response to remote peer
    ///
    /// The header request that is removed from remote peer contains
    /// a locator object. Local node uses this object to find common
    ///
    /// # Arguments
    /// * `request_id` - ID of the request that this is a response to
    /// * `headers` - headers that the remote requested
    pub async fn send_header_response(
        &mut self,
        request_id: T::SyncingPeerRequestId,
        headers: Vec<BlockHeader>,
    ) -> crate::Result<()> {
        log::trace!("send header response, request id {request_id:?}");

        // TODO: save sent header IDs somewhere and validate future requests against those?
        let message = self.make_header_response(headers);
        self.peer_sync_handle.send_response(request_id, message).await
    }

    /// Send header response to remote peer
    ///
    /// The header request that is removed from remote peer contains
    /// a locator object. Local node uses this object to find common
    ///
    /// # Arguments
    /// * `request_id` - ID of the request that this is a response to
    /// * `headers` - headers that the remote requested
    pub async fn send_block_response(
        &mut self,
        request_id: T::SyncingPeerRequestId,
        blocks: Vec<Block>,
    ) -> crate::Result<()> {
        log::trace!("send block response, request id {request_id:?}");

        // TODO: save sent block IDs somewhere and validate future requests against those?
        let message = self.make_block_response(blocks);
        self.peer_sync_handle.send_response(request_id, message).await
    }
}
