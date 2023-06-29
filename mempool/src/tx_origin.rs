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

use p2p_types::peer_id::PeerId;

/// Tracks where a transaction originates
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum TxOrigin {
    /// Transaction was submitted to local node's mempool. It should not be propagated further.
    LocalMempool,

    /// Transaction was submitted via local node's RPC subsystem. It should be propagated if valid.
    LocalP2p,

    /// Transaction was in a block but moved into the mempool upon a reorg.
    PastBlock,

    /// Transaction was received from a peer.
    ///
    /// If it eventually turns out to be valid, it should be propagated further to other peers.
    /// If it's not valid, the original peer should be penalized as appropriate.
    Peer(PeerId),
}

impl std::fmt::Display for TxOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxOrigin::LocalMempool => write!(f, "local node mempool"),
            TxOrigin::LocalP2p => write!(f, "local node p2p"),
            TxOrigin::PastBlock => write!(f, "reorged-out block"),
            TxOrigin::Peer(peer_id) => write!(f, "peer node {peer_id}"),
        }
    }
}

#[cfg(test)]
impl TxOrigin {
    /// Origin that serves as a reasonable default for testing
    pub const TEST: Self = Self::LocalMempool;
}
