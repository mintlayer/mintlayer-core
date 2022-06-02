// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use super::*;

/// Discovered peer address information
#[derive(Debug, PartialEq, Eq)]
pub struct AddrInfo<T>
where
    T: NetworkingService,
{
    /// Unique ID of the peer
    pub id: T::PeerId,

    /// List of discovered IPv4 addresses
    pub ip4: Vec<Arc<T::Address>>,

    /// List of discovered IPv6 addresses
    pub ip6: Vec<Arc<T::Address>>,
}

/// Peer information learned during handshaking
///
/// When an inbound/outbound connection succeeds, the networking service handshakes with the remote
/// peer, exchanges node information with them and verifies that the bare minimum requirements are met
/// (both are Mintlayer nodes and that both support mandatory protocols). If those checks pass,
/// the information is passed on to [crate::swarm::PeerManager] which decides whether it wants to keep
/// the connection open or close it and possibly ban the peer from.
#[derive(Debug)]
pub struct PeerInfo<T>
where
    T: NetworkingService,
{
    /// Unique ID of the peer
    pub peer_id: T::PeerId,

    /// Peer network
    pub magic_bytes: [u8; 4],

    /// Peer software version
    pub version: primitives::version::SemVer,

    /// User agent of the peer
    pub agent: Option<String>,

    // TODO: protocolid must not generic!
    /// List of supported protocols
    pub protocols: Vec<T::ProtocolId>,
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
pub enum ConnectivityEvent<T>
where
    T: NetworkingService,
{
    /// Outbound connection accepted
    ConnectionAccepted {
        /// Peer information
        peer_info: PeerInfo<T>,
    },

    /// Inbound connection received
    IncomingConnection {
        /// Peer address
        addr: T::Address,

        /// Peer information
        peer_info: PeerInfo<T>,
    },

    /// Remote closed connection
    ConnectionClosed {
        /// Unique ID of the peer
        peer_id: T::PeerId,
    },

    /// One or more peers discovered
    Discovered {
        /// Address information
        peers: Vec<AddrInfo<T>>,
    },

    /// One one more peers have expired
    Expired {
        /// Address information
        peers: Vec<AddrInfo<T>>,
    },

    /// Peer disconnected
    Disconnected {
        /// Unique ID of the peer
        peer_id: T::PeerId,
    },

    /// Error occurred with peer
    Error {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        /// Error that occurred
        error: error::P2pError,
    },

    /// Peer misbehaved
    Misbehaved {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        // TODO: fix
        behaviour: u32,
    },
}

/// Publish-subscribe related events
#[derive(Debug)]
pub enum PubSubEvent<T>
where
    T: NetworkingService,
{
    /// Message received from a PubSub topic
    MessageReceived {
        /// Unique ID of the sender
        peer_id: T::PeerId,

        /// Unique ID of the message
        message_id: T::MessageId,

        /// Received PubSub message
        message: message::Message,
    },
}

/// Request-response errors
#[derive(Debug, PartialEq, Eq)]
pub enum RequestResponseError {
    /// Request timed out
    Timeout,

    /// Connection was closed by remote
    // TODO: peer manager
    ConnectionClosed,
}

/// Syncing-related events
#[derive(Debug)]
pub enum SyncingEvent<T>
where
    T: NetworkingService,
{
    /// Incoming request
    Request {
        /// Unique ID of the sender
        peer_id: T::PeerId,

        /// Unique ID of the request
        request_id: T::RequestId,

        /// Received request
        request: message::Message,
    },

    /// Incoming response to a sent request
    Response {
        /// Unique ID of the sender
        peer_id: T::PeerId,

        /// Unique ID of the request this message is a response to
        request_id: T::RequestId,

        /// Received response
        response: message::Message,
    },

    /// Error occurred with syncing codec
    Error {
        peer_id: T::PeerId,
        request_id: T::RequestId,
        error: RequestResponseError,
    },
}

/// Publish-subscribe topics
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
