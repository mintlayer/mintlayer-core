// Copyright (c) 2023 RBB S.r.l
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

use std::collections::HashSet;

use tokio::time::Instant;

use crate::{
    interface::types::ConnectedPeer,
    net::types::{self, Role},
};

#[derive(Debug)]
pub struct SentPing {
    pub nonce: u64,
    pub timestamp: Instant,
}

#[derive(Debug)]
pub struct PeerContext<A> {
    /// Peer information
    pub info: types::PeerInfo,

    /// Peer's address
    pub address: A,

    /// Peer's role (inbound or outbound)
    pub role: Role,

    /// Peer score
    pub score: u32,

    /// Sent ping details
    pub sent_ping: Option<SentPing>,

    /// All addresses that were announced to or from some peer.
    /// Used to prevent infinity loops while broadcasting addresses.
    // TODO: Use bloom filter (like it's done in Bitcoin Core).
    pub announced_addresses: HashSet<A>,
}

impl<T: ToString> From<&PeerContext<T>> for ConnectedPeer {
    fn from(context: &PeerContext<T>) -> Self {
        ConnectedPeer {
            peer_id: context.info.peer_id,
            address: context.address.to_string(),
            inbound: context.role == Role::Inbound,
            ban_score: context.score,
        }
    }
}
