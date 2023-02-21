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

use std::{
    collections::BTreeSet,
    fmt::{Debug, Display},
};

use common::{chain::ChainConfig, primitives::semver::SemVer};
use serialization::{Decode, Encode};

use crate::{
    message::{Announcement, PeerManagerMessage, SyncMessage},
    types::peer_address::PeerAddress,
    NetworkingService, P2pError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Inbound,
    Outbound,
}

// TODO: Introduce and check the maximum allowed peer information size. See
// https://github.com/mintlayer/mintlayer-core/issues/594 for details.
/// Peer information learned during handshaking
///
/// When an inbound/outbound connection succeeds, the networking service handshakes with the remote
/// peer, exchanges node information with them and verifies that the bare minimum requirements are met
/// (both are Mintlayer nodes and that both support mandatory protocols). If those checks pass,
/// the information is passed on to [crate::peer_manager::PeerManager] which decides whether it
/// wants to keep the connection open or close it and possibly ban the peer from.
#[derive(Debug, PartialEq, Eq)]
pub struct PeerInfo<P> {
    /// Unique ID of the peer
    pub peer_id: P,

    /// Peer network
    pub network: [u8; 4],

    /// Peer software version
    pub version: SemVer,

    /// User agent of the peer
    pub agent: Option<String>,

    /// The announcements list that a peer interested is.
    pub subscriptions: BTreeSet<PubSubTopic>,
}

impl<P> PeerInfo<P> {
    pub fn is_compatible(&self, chain_config: &ChainConfig) -> bool {
        // TODO: Check version here
        self.network == *chain_config.magic_bytes()
    }
}

impl<P: Debug> Display for PeerInfo<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Peer information:")?;
        writeln!(f, "--> Peer ID: {:?}", self.peer_id)?;
        writeln!(f, "--> Network: {:x?}", self.network)?;
        writeln!(f, "--> Software version: {}", self.version)?;
        writeln!(
            f,
            "--> User agent: {}",
            self.agent.as_ref().unwrap_or(&"No user agent".to_string())
        )?;

        Ok(())
    }
}

/// Connectivity-related events received from the network
#[derive(Debug)]
pub enum ConnectivityEvent<T: NetworkingService> {
    Message {
        peer: T::PeerId,
        message: PeerManagerMessage,
    },
    /// Outbound connection accepted
    OutboundAccepted {
        /// Peer address
        address: T::Address,

        /// Peer information
        peer_info: PeerInfo<T::PeerId>,

        /// Socket address of this node as seen by remote peer
        receiver_address: Option<PeerAddress>,
    },

    /// Inbound connection received
    InboundAccepted {
        /// Peer address
        address: T::Address,

        /// Peer information
        peer_info: PeerInfo<T::PeerId>,

        /// Socket address of this node as seen by remote peer
        receiver_address: Option<PeerAddress>,
    },

    /// Outbound connection failed
    ConnectionError {
        /// Address that was dialed
        address: T::Address,

        /// Error that occurred
        error: P2pError,
    },

    /// Remote closed connection
    ConnectionClosed {
        /// Unique ID of the peer
        peer_id: T::PeerId,
    },

    /// Protocol violation
    Misbehaved {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        /// Error code of the violation
        error: P2pError,
    },
}

/// Syncing-related events
#[derive(Debug)]
pub enum SyncingEvent<T: NetworkingService> {
    Message {
        peer: T::PeerId,
        message: SyncMessage,
    },
    /// An announcement that is broadcast to all peers.
    Announcement {
        peer: T::PeerId,
        announcement: Box<Announcement>,
    },
}

/// Publish-subscribe topics
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum PubSubTopic {
    /// Transactions
    Transactions,
    /// Blocks
    Blocks,

    /// Peer address announcements from new nodes joining the network
    PeerAddresses,
}
