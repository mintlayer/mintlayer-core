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
    collections::{hash_map::DefaultHasher, BTreeSet},
    hash::{Hash, Hasher},
    str::FromStr,
};

use tokio::sync::oneshot;

use common::primitives::semver;
use crypto::random::{make_pseudo_rng, Rng};
use serialization::{Decode, Encode};

use crate::{
    error, message,
    net::{
        self,
        mock::transport::TransportSocket,
        types::{Protocol, PubSubTopic},
    },
};

pub enum Command<T: TransportSocket> {
    Connect {
        address: T::Address,
        response: oneshot::Sender<crate::Result<()>>,
    },
    Disconnect {
        peer_id: MockPeerId,
        response: oneshot::Sender<crate::Result<()>>,
    },
    BanPeer {
        peer_id: MockPeerId,
        response: oneshot::Sender<crate::Result<()>>,
    },
    SendRequest {
        peer_id: MockPeerId,
        message: message::Request,
        response: oneshot::Sender<crate::Result<MockRequestId>>,
    },
    /// Send response to remote peer
    SendResponse {
        request_id: MockRequestId,
        message: message::Response,
        response: oneshot::Sender<crate::Result<()>>,
    },
    AnnounceData {
        topic: PubSubTopic,
        message: Vec<u8>,
        response: oneshot::Sender<crate::Result<()>>,
    },
}

pub enum SyncingEvent {
    Request {
        peer_id: MockPeerId,
        request_id: MockRequestId,
        request: message::Request,
    },
    Response {
        peer_id: MockPeerId,
        request_id: MockRequestId,
        response: message::Response,
    },
    RequestTimeout {
        peer_id: MockPeerId,
        request_id: MockRequestId,
    },
    Announcement {
        peer_id: MockPeerId,
        announcement: Box<message::Announcement>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectivityEvent<T: TransportSocket> {
    InboundAccepted {
        address: T::Address,
        peer_info: MockPeerInfo,
    },
    OutboundAccepted {
        address: T::Address,
        peer_info: MockPeerInfo,
    },
    ConnectionError {
        address: T::Address,
        error: error::P2pError,
    },
    ConnectionClosed {
        peer_id: MockPeerId,
    },
    /// A peer misbehaved and its reputation must be adjusted according to the error type.
    Misbehaved {
        peer_id: MockPeerId,
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

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Encode, Decode, Default)]
pub struct MockRequestId(u64);

impl MockRequestId {
    pub fn new(request_id: u64) -> Self {
        Self(request_id)
    }

    pub fn fetch_and_inc(&mut self) -> Self {
        let id = self.0;
        self.0 += 1;

        Self(id)
    }
}

impl std::fmt::Display for MockRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct MockPeerId(u64);

impl FromStr for MockPeerId {
    type Err = <u64 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u64::from_str(s).map(Self)
    }
}

impl MockPeerId {
    pub fn random() -> Self {
        let mut rng = make_pseudo_rng();
        Self(rng.gen::<u64>())
    }

    pub fn from_socket_address<T: TransportSocket>(addr: &T::Address) -> Self {
        let mut hasher = DefaultHasher::new();
        addr.hash(&mut hasher);
        Self(hasher.finish())
    }
}

impl std::fmt::Display for MockPeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// This type is only needed to satisfy the `NetworkingService` trait requirements. It should be
// removed along with the libp2p backend.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct MockMessageId;

#[derive(Debug, PartialEq, Eq)]
pub struct MockPeerInfo {
    pub peer_id: MockPeerId,
    pub network: [u8; 4],
    pub version: common::primitives::semver::SemVer,
    pub agent: Option<String>,
    pub protocols: Vec<Protocol>,
    pub subscriptions: BTreeSet<PubSubTopic>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeerEvent {
    /// Peer information received from remote
    PeerInfoReceived {
        network: [u8; 4],
        version: semver::SemVer,
        protocols: Vec<Protocol>,
        subscriptions: BTreeSet<PubSubTopic>,
    },

    /// Connection closed to remote
    ConnectionClosed,

    /// Message received from remote
    MessageReceived { message: Message },
}

/// Events sent by the mock backend to peers
#[derive(Debug)]
pub enum MockEvent {
    Disconnect,
    SendMessage(Box<Message>),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    Hello {
        version: common::primitives::semver::SemVer,
        network: [u8; 4],
        protocols: Vec<Protocol>,
        subscriptions: BTreeSet<PubSubTopic>,
    },
    HelloAck {
        version: common::primitives::semver::SemVer,
        network: [u8; 4],
        protocols: Vec<Protocol>,
        subscriptions: BTreeSet<PubSubTopic>,
    },
}

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub enum Message {
    Handshake(HandshakeMessage),
    Request {
        request_id: MockRequestId,
        request: message::Request,
    },
    Response {
        request_id: MockRequestId,
        response: message::Response,
    },
    Announcement {
        announcement: message::Announcement,
    },
}
