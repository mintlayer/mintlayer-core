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

pub use protocol::{Protocol, ProtocolType};

mod protocol;

use std::{collections::BTreeSet, fmt::Display, net::IpAddr};

use common::primitives::semver::SemVer;
use serialization::{Decode, Encode};

use crate::{message, NetworkingService, P2pError};

/// Discovered peer address information
#[derive(Debug, PartialEq, Eq)]
pub struct AddrInfo<T: NetworkingService> {
    /// Unique ID of the peer
    pub peer_id: T::PeerId,

    /// List of discovered IPv4 addresses
    pub ip4: Vec<T::Address>,

    /// List of discovered IPv6 addresses
    pub ip6: Vec<T::Address>,
}

/// Peer information learned during handshaking
///
/// When an inbound/outbound connection succeeds, the networking service handshakes with the remote
/// peer, exchanges node information with them and verifies that the bare minimum requirements are met
/// (both are Mintlayer nodes and that both support mandatory protocols). If those checks pass,
/// the information is passed on to [crate::swarm::PeerManager] which decides whether it wants to keep
/// the connection open or close it and possibly ban the peer from.
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

    /// A set of supported protocols.
    pub protocols: BTreeSet<Protocol>,
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
        write!(f, "--> Protocols: ")?;

        for protocol in &self.protocols {
            write!(f, "{} ", protocol)?;
        }

        Ok(())
    }
}

/// Connectivity-related events received from the network
#[derive(Debug)]
pub enum ConnectivityEvent<T: NetworkingService> {
    /// Outbound connection accepted
    OutboundAccepted {
        /// Peer address
        address: T::Address,

        /// Peer information
        peer_info: PeerInfo<T>,
    },

    /// Inbound connection received
    InboundAccepted {
        /// Peer address
        address: T::Address,

        /// Peer information
        peer_info: PeerInfo<T>,
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

    /// One or more peers discovered (libp2p defines discovering as finding new addresses through mDNS or otherwise)
    Discovered {
        /// Address information
        peers: Vec<AddrInfo<T>>,
    },

    /// One one more peers have expired (libp2p defines expired addresses as addresses that haven't appeared in later refreshes of available addresses)
    Expired {
        /// Address information
        peers: Vec<AddrInfo<T>>,
    },

    /// Protocol violation
    Misbehaved {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        /// Error code of the violation
        error: P2pError,
    },
}

/// Request-response errors
#[derive(Debug, PartialEq, Eq)]
pub enum RequestResponseError {
    /// Request timed out
    Timeout,
}

/// Syncing-related events
#[derive(Debug)]
pub enum SyncingEvent<T: NetworkingService> {
    /// Incoming request
    Request {
        /// Unique ID of the sender
        peer_id: T::PeerId,

        /// Unique ID of the request
        request_id: T::SyncingPeerRequestId,

        /// Received request
        request: message::Request,
    },

    /// Incoming response to a sent request
    Response {
        /// Unique ID of the sender
        peer_id: T::PeerId,

        /// Unique ID of the request this message is a response to
        request_id: T::SyncingPeerRequestId,

        /// Received response
        response: message::Response,
    },

    /// Error occurred with syncing codec
    Error {
        peer_id: T::PeerId,
        request_id: T::SyncingPeerRequestId,
        error: RequestResponseError,
    },

    Announcement {
        peer_id: T::PeerId,
        message_id: T::SyncingMessageId,
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

/// Validation result for an incoming PubSub message
#[derive(Debug)]
pub enum ValidationResult {
    /// Message was valid and can be forwarded to other peers
    Accept,

    /// Message was invalid and mustn't be forwarded to other peers
    Reject,

    /// Message is not invalid but it shouldn't be forwarded to other peers
    Ignore,
}

pub trait GetIp {
    fn ip(&self) -> IpAddr;
}
