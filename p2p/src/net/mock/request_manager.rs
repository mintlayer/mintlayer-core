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

//! Request-response manager
//!
//! The request-response manager is responsible for handling all activity related to inbound/outbound
//! requests/responses. When a new peer joins, it allocates a 16-bit wide request ID zone for it which
//! it uses for the requests it sends to that particular peer.
//!
//! For inbound requests, the original request ID is stored inside the manager's storage and an ephemeral
//! request ID is allocated for the request which is then forwarded to the frontend. This is to allow the
//! remote peers to use whatever request IDs they want for book keeping while still being able to associate
//! outbound responses with correct inbound requests.

use crate::{
    error::{P2pError, PeerError},
    message,
    net::mock::types,
};
use std::collections::{hash_map::Entry, HashMap, HashSet};

#[derive(Debug, Default)]
pub struct RequestManager {
    /// Active ephemeral IDs
    ephemerals: HashMap<types::MockPeerId, HashSet<types::MockRequestId>>,

    /// Pending outbound requests (TODO: timeouts)
    _pending: HashMap<types::MockRequestId, types::MockRequestId>,

    // Next ID for outbound request
    next_request_id: types::MockRequestId,

    /// Next ephemeral request ID
    next_ephemeral_id: types::MockRequestId,

    /// Ephemeral requests IDs which are mapped to remote peer ID/request ID pair
    ephemeral: HashMap<types::MockRequestId, (types::MockPeerId, types::MockRequestId)>,
}

impl RequestManager {
    pub fn new() -> Self {
        Default::default()
    }

    /// Register peer to the request manager
    ///
    /// Initialize peer context and allocate request ID slice for the peer
    pub fn register_peer(&mut self, peer_id: types::MockPeerId) -> crate::Result<()> {
        match self.ephemerals.entry(peer_id) {
            Entry::Occupied(_) => Err(P2pError::PeerError(PeerError::PeerAlreadyExists)),
            Entry::Vacant(entry) => {
                entry.insert(Default::default());
                Ok(())
            }
        }
    }

    /// Unregister peer from the request manager
    pub fn unregister_peer(&mut self, peer_id: &types::MockPeerId) {
        if let Some(ephemerals) = self.ephemerals.remove(peer_id) {
            ephemerals.iter().for_each(|id| {
                self.ephemeral.remove(id);
            });
        }
    }

    /// Create new outgoing request
    pub fn make_request(
        &mut self,
        _peer_id: &types::MockPeerId, // TODO: timeouts
        request: message::Request,
    ) -> crate::Result<(types::MockRequestId, Box<types::Message>)> {
        let request_id = self.next_request_id.fetch_and_inc();

        Ok((
            request_id,
            Box::new(types::Message::Request {
                request_id,
                request,
            }),
        ))
    }

    /// Create new outgoing response
    ///
    /// Use the assigned ephemeral ID to fetch the peer ID and the actual request ID
    /// of the remote node and return all information to the caller.
    pub fn make_response(
        &mut self,
        request_id: &types::MockRequestId,
        response: message::Response,
    ) -> Option<(types::MockPeerId, Box<types::Message>)> {
        if let Some((peer_id, request_id)) = self.ephemeral.remove(request_id) {
            return Some((
                peer_id,
                Box::new(types::Message::Response {
                    request_id,
                    response,
                }),
            ));
        }

        None
    }

    /// Register inbound request
    ///
    /// The request ID is stored into a temporary storage holding all pending
    /// inbound requests.
    pub fn register_request(
        &mut self,
        peer_id: &types::MockPeerId,
        request_id: &types::MockRequestId,
        _request: &message::Request,
    ) -> crate::Result<types::MockRequestId> {
        let peer_ephemerals = self
            .ephemerals
            .get_mut(peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;

        let ephemeral_id = self.next_ephemeral_id.fetch_and_inc();

        peer_ephemerals.insert(ephemeral_id);
        self.ephemeral.insert(ephemeral_id, (*peer_id, *request_id));
        Ok(ephemeral_id)
    }

    /// Register inbound response
    pub fn register_response(
        &mut self,
        _peer_id: &types::MockPeerId,
        _request_id: &types::MockRequestId,
        _response: &message::Response,
    ) -> crate::Result<()> {
        // TODO: implement request timeouts
        Ok(())
    }
}
