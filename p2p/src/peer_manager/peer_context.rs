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

use crate::{
    interface::types::ConnectedPeer,
    net::{
        types::{self, Role},
        NetworkingService,
    },
};

#[derive(Debug)]
pub struct PeerContext<T: NetworkingService> {
    /// Peer information
    pub info: types::PeerInfo<T::PeerId>,

    /// Peer's address
    pub address: T::Address,

    /// Peer's role (inbound or outbound)
    pub role: Role,

    /// Peer score
    pub score: u32,
}

impl<T: NetworkingService> From<&PeerContext<T>> for ConnectedPeer {
    fn from(context: &PeerContext<T>) -> Self {
        ConnectedPeer {
            peer_id: context.info.peer_id.to_string(),
            address: context.address.to_string(),
            inbound: context.role == Role::Inbound,
            ban_score: context.score,
        }
    }
}
