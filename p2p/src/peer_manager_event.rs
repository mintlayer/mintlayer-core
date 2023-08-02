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

use p2p_types::{bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress};

use crate::{interface::types::ConnectedPeer, types::peer_id::PeerId, utils::oneshot_nofail};

#[derive(Debug)]
pub enum PeerDisconnectionDbAction {
    /// The address is kept in the PeerDb and there can be automatic reconnects
    Keep,
    /// The address will be removed from the PeerDb and there will be no reconnect attempts
    /// (at least until the peer address is rediscovered).
    /// It only affects outbound addresses.
    RemoveIfOutbound,
}

#[derive(Debug)]
pub enum PeerManagerEvent {
    /// Try to establish connection with a remote peer
    Connect(IpOrSocketAddress, oneshot_nofail::Sender<crate::Result<()>>),

    /// Disconnect node using peer ID
    Disconnect(
        PeerId,
        PeerDisconnectionDbAction,
        oneshot_nofail::Sender<crate::Result<()>>,
    ),

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

    AddReserved(IpOrSocketAddress, oneshot_nofail::Sender<crate::Result<()>>),

    RemoveReserved(IpOrSocketAddress, oneshot_nofail::Sender<crate::Result<()>>),

    ListBanned(oneshot_nofail::Sender<Vec<BannableAddress>>),
    Ban(BannableAddress, oneshot_nofail::Sender<crate::Result<()>>),
    Unban(BannableAddress, oneshot_nofail::Sender<crate::Result<()>>),
}
