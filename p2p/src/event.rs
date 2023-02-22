// Copyright (c) 2021-2022 RBB S.r.l
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

use common::chain::block::Block;

use crate::{
    interface::types::ConnectedPeer, net::NetworkingService, types::peer_id::PeerId,
    utils::oneshot_nofail,
};

#[derive(Debug)]
pub enum PeerManagerEvent<T: NetworkingService> {
    /// Try to establish connection with a remote peer
    Connect(T::Address, oneshot_nofail::Sender<crate::Result<()>>),

    /// Disconnect node using peer ID
    Disconnect(PeerId, oneshot_nofail::Sender<crate::Result<()>>),

    /// Get the total number of peers local node has a connection with
    GetPeerCount(oneshot_nofail::Sender<usize>),

    /// Get the bind address of the local node
    GetBindAddresses(oneshot_nofail::Sender<Vec<String>>),

    /// Get peer IDs and addresses of connected peers
    GetConnectedPeers(oneshot_nofail::Sender<Vec<ConnectedPeer>>),

    /// Increases the ban score of a peer by the given amount.
    ///
    /// The peer is banned if the new score exceeds the threshold (`P2pConfig::ban_threshold`).
    AdjustPeerScore(PeerId, u32, oneshot_nofail::Sender<crate::Result<()>>),
}

#[derive(Debug)]
pub enum SyncEvent {
    /// Publish a block to the network
    PublishBlock(Block),
}

#[derive(Debug)]
pub enum SyncControlEvent {
    /// Peer connected
    Connected(PeerId),

    /// Peer disconnected
    Disconnected(PeerId),
}
