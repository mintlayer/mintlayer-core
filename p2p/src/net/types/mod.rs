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

use std::{collections::BTreeSet, fmt::Display};

use common::primitives::semver::SemVer;
use serialization::{Decode, Encode};

use crate::{message, types::peer_address::PeerAddress, NetworkingService, P2pError};

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
#[derive(Debug)]
pub struct PeerInfo<T: NetworkingService> {
    /// Unique ID of the peer
    pub peer_id: T::PeerId,

    /// Peer network
    pub magic_bytes: [u8; 4],

    /// Peer software version
    pub version: SemVer,

    /// User agent of the peer
    pub agent: Option<String>,

    /// The announcements list that a peer interested is.
    pub subscriptions: BTreeSet<PubSubTopic>,
}

impl<T: NetworkingService> Display for PeerInfo<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Peer information:")?;
        writeln!(f, "--> Peer ID: {}", self.peer_id)?;
        writeln!(f, "--> Magic bytes: {:x?}", self.magic_bytes)?;
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
    /// An incoming request.
    Request {
        /// Unique ID of the sender
        peer_id: T::PeerId,

        /// Unique ID of the request
        request_id: T::PeerRequestId,

        /// Received request
        request: message::PeerManagerRequest,
    },
    /// An incoming response.
    Response {
        /// Unique ID of the sender
        peer_id: T::PeerId,

        /// Unique ID of the request this message is a response to
        request_id: T::PeerRequestId,

        /// Received response
        response: message::PeerManagerResponse,
    },
    /// Outbound connection accepted
    OutboundAccepted {
        /// Peer address
        address: T::Address,

        /// Peer information
        peer_info: PeerInfo<T>,

        /// Socket address of this node as seen by remote peer
        receiver_address: Option<PeerAddress>,
    },

    /// Inbound connection received
    InboundAccepted {
        /// Peer address
        address: T::Address,

        /// Peer information
        peer_info: PeerInfo<T>,

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

    /// New peer discovered
    AddressDiscovered {
        /// Address information
        address: T::Address,
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
    /// An incoming request.
    Request {
        /// Unique ID of the sender
        peer_id: T::PeerId,

        /// Unique ID of the request
        request_id: T::PeerRequestId,

        /// Received request
        request: message::SyncRequest,
    },
    /// An incoming response.
    Response {
        /// Unique ID of the sender
        peer_id: T::PeerId,

        /// Unique ID of the request this message is a response to
        request_id: T::PeerRequestId,

        /// Received response
        response: message::SyncResponse,
    },
    /// An announcement that is broadcast to all peers.
    Announcement {
        peer_id: T::PeerId,
        announcement: message::Announcement,
    },
}

/// Publish-subscribe topics
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum PubSubTopic {
    /// Transactions
    Transactions,

    /// Blocks
    Blocks,
}
