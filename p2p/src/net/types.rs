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

pub use crate::types::services;

use std::fmt::{Debug, Display};

use common::{
    chain::{config::MagicBytes, ChainConfig},
    primitives::{semver::SemVer, user_agent::UserAgent},
};
use p2p_types::socket_address::SocketAddress;
use tokio::sync::mpsc::Receiver;

use crate::{
    error::ConnectionValidationError,
    message::{BlockSyncMessage, PeerManagerMessage, TransactionSyncMessage},
    protocol::SupportedProtocolVersion,
    types::{peer_address::PeerAddress, peer_id::PeerId},
    P2pError,
};

use self::services::Services;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    rpc_description::HasValueHint,
    enum_iterator::Sequence,
)]
pub enum ConnectionType {
    Inbound,
    OutboundFullRelay,
    OutboundBlockRelay,
    OutboundReserved,
    OutboundManual,
    Feeler,
}

impl ConnectionType {
    pub fn is_outbound(&self) -> bool {
        use ConnectionType::*;

        match self {
            Inbound => false,
            OutboundFullRelay | OutboundBlockRelay | OutboundReserved | OutboundManual | Feeler => {
                true
            }
        }
    }

    pub fn is_outbound_manual(&self) -> bool {
        use ConnectionType::*;

        match self {
            OutboundManual => true,
            Inbound | OutboundFullRelay | OutboundBlockRelay | OutboundReserved | Feeler => false,
        }
    }
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PeerInfo {
    /// Unique ID of the peer
    pub peer_id: PeerId,

    /// Best protocol version that is supported both by us and by the peer.
    pub protocol_version: SupportedProtocolVersion,

    /// Peer network
    pub network: MagicBytes,

    /// Peer software version
    pub software_version: SemVer,

    /// User agent of the peer
    pub user_agent: UserAgent,

    /// Intersection of requested (set by us) and available (set by the peer) services.
    /// All services that will be enabled for this peer if it's accepted.
    /// The Peer Manager can disconnect the peer if some required services are missing.
    pub common_services: Services,
}

impl PeerInfo {
    pub fn is_compatible(&self, chain_config: &ChainConfig) -> bool {
        self.check_compatibility(chain_config).is_ok()
    }

    pub fn check_compatibility(&self, chain_config: &ChainConfig) -> crate::Result<()> {
        if self.network != *chain_config.magic_bytes() {
            Err(P2pError::ConnectionValidationFailed(
                ConnectionValidationError::DifferentNetwork {
                    our_network: *chain_config.magic_bytes(),
                    their_network: self.network,
                },
            ))
        } else {
            Ok(())
        }
    }
}

impl Display for PeerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Peer information:")?;
        writeln!(f, "--> Peer ID: {:?}", self.peer_id)?;
        writeln!(f, "--> Protocol version: {:?}", self.protocol_version)?;
        writeln!(f, "--> Network: {:x?}", self.network)?;
        writeln!(f, "--> Software version: {}", self.software_version)?;
        writeln!(f, "--> User agent: {}", self.user_agent)?;

        Ok(())
    }
}

/// Connectivity-related events received from the network
#[derive(Debug)]
pub enum ConnectivityEvent {
    Message {
        peer_id: PeerId,
        message: PeerManagerMessage,
    },
    /// Outbound connection accepted
    OutboundAccepted {
        /// Peer address
        peer_address: SocketAddress,

        /// Bind address of this node's side of the connection.
        bind_address: SocketAddress,

        /// Peer information
        peer_info: PeerInfo,

        /// Socket address of this node as seen by remote peer
        node_address_as_seen_by_peer: Option<PeerAddress>,
    },

    /// Inbound connection received
    InboundAccepted {
        /// Peer address
        peer_address: SocketAddress,

        /// Bind address of this node's side of the connection.
        bind_address: SocketAddress,

        /// Peer information
        peer_info: PeerInfo,

        /// Socket address of this node as seen by remote peer
        node_address_as_seen_by_peer: Option<PeerAddress>,
    },

    /// Outbound connection failed
    ///
    // Note: the contained error is not supposed to be bannable. For bannable errors that happen
    // during handshake, an additional MisbehavedOnHandshake event will be produced.
    ConnectionError {
        /// Address that was dialed
        peer_address: SocketAddress,

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

    /// Protocol violation during handshake
    ///
    /// This event is used to report protocol violations at the handshake stage, when no peer id
    /// has been assigned yet.
    ///
    // Note: unlike ConnectionError, it may be produced both for outbound and inbound connections.
    // TODO: we should probably have a single ConnectionError variant, which would be produced
    // for both outbound and inbound connections, and which could be used to report bannable errors
    // that happen during handshake as well.
    MisbehavedOnHandshake {
        /// Peer's address
        peer_address: SocketAddress,

        /// Error that occurred
        error: P2pError,
    },
}

/// Syncing-related events (sent from the backend)
#[derive(Debug)]
pub enum SyncingEvent {
    /// Peer connected
    Connected {
        peer_id: PeerId,
        common_services: Services,
        protocol_version: SupportedProtocolVersion,
        block_sync_msg_receiver: Receiver<BlockSyncMessage>,
        transaction_sync_msg_receiver: Receiver<TransactionSyncMessage>,
    },

    /// Peer disconnected
    Disconnected { peer_id: PeerId },
}
