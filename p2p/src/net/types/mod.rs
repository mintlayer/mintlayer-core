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

pub mod services;

use std::fmt::{Debug, Display};

use common::{
    chain::ChainConfig,
    primitives::{semver::SemVer, user_agent::UserAgent},
};
use tokio::sync::mpsc::Receiver;

use crate::{
    message::{PeerManagerMessage, SyncMessage},
    protocol::NetworkProtocol,
    types::{peer_address::PeerAddress, peer_id::PeerId},
    P2pError,
};

use self::services::Services;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Inbound,
    Outbound,
}

/// Peer information learned during handshaking
///
/// When an inbound/outbound connection succeeds, the networking service handshakes with the remote
/// peer, exchanges node information with them and verifies that the bare minimum requirements are met
/// (both are Mintlayer nodes and that both support mandatory protocols). If those checks pass,
/// the information is passed on to [crate::peer_manager::PeerManager] which decides whether it
/// wants to keep the connection open or close it and possibly ban the peer from.
///
/// If new fields are added, make sure they are limited in size.
#[derive(Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Unique ID of the peer
    pub peer_id: PeerId,

    pub protocol: NetworkProtocol,

    /// Peer network
    pub network: [u8; 4],

    /// Peer software version
    pub version: SemVer,

    /// User agent of the peer
    pub user_agent: UserAgent,

    /// The announcements list that a peer interested is.
    pub services: Services,
}

impl PeerInfo {
    pub fn is_compatible(&self, chain_config: &ChainConfig) -> bool {
        // Check node version here if necessary
        self.network == *chain_config.magic_bytes()
    }
}

impl Display for PeerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Peer information:")?;
        writeln!(f, "--> Peer ID: {:?}", self.peer_id)?;
        writeln!(f, "--> Protocol: {:?}", self.protocol)?;
        writeln!(f, "--> Network: {:x?}", self.network)?;
        writeln!(f, "--> Software version: {}", self.version)?;
        writeln!(f, "--> User agent: {}", self.user_agent)?;

        Ok(())
    }
}

/// Connectivity-related events received from the network
#[derive(Debug)]
pub enum ConnectivityEvent<A> {
    Message {
        peer: PeerId,
        message: PeerManagerMessage,
    },
    /// Outbound connection accepted
    OutboundAccepted {
        /// Peer address
        address: A,

        /// Peer information
        peer_info: PeerInfo,

        /// Socket address of this node as seen by remote peer
        receiver_address: Option<PeerAddress>,
    },

    /// Inbound connection received
    InboundAccepted {
        /// Peer address
        address: A,

        /// Peer information
        peer_info: PeerInfo,

        /// Socket address of this node as seen by remote peer
        receiver_address: Option<PeerAddress>,
    },

    /// Outbound connection failed
    ConnectionError {
        /// Address that was dialed
        address: A,

        /// Error that occurred
        error: P2pError,
    },

    /// Remote closed connection
    ConnectionClosed {
        /// Unique ID of the peer
        peer_id: PeerId,
    },

    /// Protocol violation
    Misbehaved {
        /// Unique ID of the peer
        peer_id: PeerId,

        /// Error code of the violation
        error: P2pError,
    },
}

/// Syncing-related events (sent from the backend)
#[derive(Debug)]
pub enum SyncingEvent {
    /// Peer connected
    Connected {
        peer_id: PeerId,
        services: Services,
        sync_rx: Receiver<SyncMessage>,
    },

    /// Peer disconnected
    Disconnected { peer_id: PeerId },
}
