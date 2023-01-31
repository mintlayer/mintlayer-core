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
    hash::Hash,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use tokio::sync::oneshot;

use common::primitives::semver::SemVer;
use serialization::{Decode, Encode};

use crate::{
    error, message,
    net::{
        self,
        default_backend::transport::TransportSocket,
        types::{PeerInfo, PubSubTopic},
    },
    types::peer_address::PeerAddress,
};

#[derive(Debug)]
pub enum Command<T: TransportSocket> {
    Connect {
        address: T::Address,
        response: oneshot::Sender<crate::Result<()>>,
    },
    Disconnect {
        peer_id: PeerId,
        response: oneshot::Sender<crate::Result<()>>,
    },
    SendRequest {
        peer_id: PeerId,
        request_id: RequestId,
        message: message::Request,
    },
    /// Send response to remote peer
    SendResponse {
        request_id: RequestId,
        message: message::Response,
    },
    AnnounceData {
        topic: PubSubTopic,
        message: Vec<u8>,
    },
}

pub enum SyncingEvent {
    Request {
        peer_id: PeerId,
        request_id: RequestId,
        request: message::SyncRequest,
    },
    Response {
        peer_id: PeerId,
        request_id: RequestId,
        response: message::SyncResponse,
    },
    Announcement {
        peer_id: PeerId,
        announcement: Box<message::Announcement>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectivityEvent<T: TransportSocket> {
    Request {
        peer_id: PeerId,
        request_id: RequestId,
        request: message::PeerManagerRequest,
    },
    Response {
        peer_id: PeerId,
        request_id: RequestId,
        response: message::PeerManagerResponse,
    },
    InboundAccepted {
        address: T::Address,
        peer_info: PeerInfo<PeerId>,
        receiver_address: Option<PeerAddress>,
    },
    OutboundAccepted {
        address: T::Address,
        peer_info: PeerInfo<PeerId>,
        receiver_address: Option<PeerAddress>,
    },
    ConnectionError {
        address: T::Address,
        error: error::P2pError,
    },
    ConnectionClosed {
        peer_id: PeerId,
    },
    /// A peer misbehaved and its reputation must be adjusted according to the error type.
    Misbehaved {
        peer_id: PeerId,
        error: error::P2pError,
    },
}

// TODO: use two events, one for txs and one for blocks?
pub enum PubSubEvent<T: TransportSocket> {
    /// Message received from one of the pubsub topics
    Announcement {
        peer_id: T::Address,
        topic: net::types::PubSubTopic,
        message: message::Announcement,
    },
}

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Encode, Decode, Default)]
pub struct RequestId(u64);

impl RequestId {
    pub fn new() -> Self {
        let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        Self(id)
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Debug, Encode, Decode)]
pub struct PeerId(u64);

impl FromStr for PeerId {
    type Err = <u64 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u64::from_str(s).map(Self)
    }
}

static NEXT_PEER_ID: AtomicU64 = AtomicU64::new(1);

impl PeerId {
    pub fn new() -> Self {
        let id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
        Self(id)
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Random nonce sent in outbound handshake.
/// Used to detect and drop self connections.
pub type HandshakeNonce = u64;

#[derive(Debug, PartialEq, Eq)]
pub enum PeerEvent {
    /// Peer information received from remote
    PeerInfoReceived {
        network: [u8; 4],
        version: SemVer,
        subscriptions: BTreeSet<PubSubTopic>,
        receiver_address: Option<PeerAddress>,

        /// For outbound connections that is what we sent.
        /// For inbound connections that is what was received from remote peer.
        handshake_nonce: HandshakeNonce,
    },

    /// Connection closed to remote
    ConnectionClosed,

    /// Message received from remote
    MessageReceived { message: Message },
}

/// Events sent by the default_backend backend to peers
#[derive(Debug)]
pub enum Event {
    Disconnect,
    SendMessage(Box<Message>),
}

// TODO: Decide what to do about protocol upgrades.
// For example adding new address type to PeerAddress might break handshakes with older nodes.
#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    Hello {
        version: SemVer,
        network: [u8; 4],
        subscriptions: BTreeSet<PubSubTopic>,

        /// Socket address of the remote peer as seen by this node (addr_you in bitcoin)
        receiver_address: Option<PeerAddress>,

        /// Random nonce that is only used to detect and drop self-connects
        handshake_nonce: HandshakeNonce,
    },
    HelloAck {
        version: SemVer,
        network: [u8; 4],
        subscriptions: BTreeSet<PubSubTopic>,

        /// Socket address of the remote peer as seen by this node (addr_you in bitcoin)
        receiver_address: Option<PeerAddress>,
    },
}

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub enum Message {
    Handshake(HandshakeMessage),
    Request {
        request_id: RequestId,
        request: message::Request,
    },
    Response {
        request_id: RequestId,
        response: message::Response,
    },
    Announcement {
        announcement: message::Announcement,
    },
}
