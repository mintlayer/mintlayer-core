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

use tokio::sync::oneshot;

use common::chain::block::Block;

use crate::{interface::types::ConnectedPeer, net::NetworkingService};

#[derive(Debug)]
pub enum PeerManagerEvent<T: NetworkingService> {
    /// Try to establish connection with a remote peer
    Connect(T::Address, oneshot::Sender<crate::Result<()>>),

    /// Disconnect node using peer ID
    Disconnect(T::PeerId, oneshot::Sender<crate::Result<()>>),

    /// Get the total number of peers local node has a connection with
    GetPeerCount(oneshot::Sender<usize>),

    /// Get the bind address of the local node
    GetBindAddresses(oneshot::Sender<Vec<String>>),

    /// Get peer IDs and addresses of connected peers
    GetConnectedPeers(oneshot::Sender<Vec<ConnectedPeer>>),

    /// Adjust peer score
    AdjustPeerScore(T::PeerId, u32, oneshot::Sender<crate::Result<()>>),
}

#[derive(Debug)]
pub enum SyncEvent {
    /// Publish a block to the network
    PublishBlock(Block),
}

#[derive(Debug)]
pub enum SyncControlEvent<T: NetworkingService> {
    /// Peer connected
    Connected(T::PeerId),

    /// Peer disconnected
    Disconnected(T::PeerId),
}
