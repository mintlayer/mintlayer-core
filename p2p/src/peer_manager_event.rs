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

use std::time::Duration;

use common::{
    chain::{Block, Transaction},
    primitives::{time::Time, Id},
};
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};
use utils_networking::IpOrSocketAddress;

use crate::{
    interface::types::ConnectedPeer, peer_manager::PeerManagerInterface,
    sync::sync_status::PeerBlockSyncStatus, types::peer_id::PeerId, utils::oneshot_nofail,
};

#[derive(Debug)]
pub enum PeerDisconnectionDbAction {
    /// The address is kept in the PeerDb and there can be automatic reconnects
    Keep,
    /// The address will be removed from the PeerDb and there will be no reconnect attempts
    /// (at least until the peer address is rediscovered).
    /// It only affects outbound addresses.
    RemoveIfOutbound,
}

// TODO: this is more like PeerManagerCommand
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
    GetBindAddresses(oneshot_nofail::Sender<Vec<SocketAddress>>),

    /// Get peer IDs and addresses of connected peers
    GetConnectedPeers(oneshot_nofail::Sender<Vec<ConnectedPeer>>),

    /// Increases the ban score of a peer by the given amount.
    ///
    /// The peer is discouraged if the new score exceeds the corresponding threshold.
    AdjustPeerScore(PeerId, u32, oneshot_nofail::Sender<crate::Result<()>>),

    /// New tip block received.
    ///
    /// In PoW all valid blocks have a cost, but in PoS new blocks are practically free.
    /// So, unlike Bitcoin Core, we only consider new tips.
    /// It is used as an eviction criterion.
    NewTipReceived {
        peer_id: PeerId,
        block_id: Id<Block>,
    },

    /// A new tip block has been added to the chainstate
    ///
    /// Note: normally, NewTipReceived and NewChainstateTip are dependent in the sense
    /// that if NewTipReceived is produced, it will be accompanied by NewChainstateTip.
    /// However, peer manager should not use this fact and treat them as independent
    /// events instead.
    NewChainstateTip(Id<Block>),

    /// New valid unseen transaction received.
    /// It is used as an eviction criterion.
    NewValidTransactionReceived {
        peer_id: PeerId,
        txid: Id<Transaction>,
    },

    /// PeerBlockSyncStatus has changed for the specified peer.
    PeerBlockSyncStatusUpdate {
        peer_id: PeerId,
        new_status: PeerBlockSyncStatus,
    },

    GetReserved(oneshot_nofail::Sender<Vec<SocketAddress>>),
    AddReserved(IpOrSocketAddress, oneshot_nofail::Sender<crate::Result<()>>),
    RemoveReserved(IpOrSocketAddress, oneshot_nofail::Sender<crate::Result<()>>),

    ListBanned(oneshot_nofail::Sender<Vec<(BannableAddress, Time)>>),
    Ban(
        BannableAddress,
        Duration,
        oneshot_nofail::Sender<crate::Result<()>>,
    ),
    Unban(BannableAddress, oneshot_nofail::Sender<crate::Result<()>>),

    ListDiscouraged(oneshot_nofail::Sender<Vec<(BannableAddress, Time)>>),

    GenericQuery(Box<dyn PeerManagerQueryFunc>),
    #[cfg(test)]
    GenericMut(Box<dyn PeerManagerMutFunc>),
}

pub trait PeerManagerQueryFunc: FnOnce(&dyn PeerManagerInterface) + Send {}

impl<F> PeerManagerQueryFunc for F where F: FnOnce(&dyn PeerManagerInterface) + Send {}

impl std::fmt::Debug for dyn PeerManagerQueryFunc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerManagerQueryFunc")
    }
}

pub trait PeerManagerMutFunc: FnOnce(&mut dyn PeerManagerInterface) + Send {}

impl<F> PeerManagerMutFunc for F where F: FnOnce(&mut dyn PeerManagerInterface) + Send {}

impl std::fmt::Debug for dyn PeerManagerMutFunc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerManagerMutFunc")
    }
}
