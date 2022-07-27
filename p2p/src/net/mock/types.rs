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
use crate::{error, message, net};
use common::primitives::semver;
use crypto::random::{make_pseudo_rng, Rng};
use serialization::{Decode, Encode};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::SocketAddr,
};
use tokio::sync::oneshot;

pub enum Command {
    Connect {
        address: SocketAddr,
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
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectivityEvent {
    InboundAccepted {
        address: SocketAddr,
        peer_info: MockPeerInfo,
    },
    OutboundAccepted {
        address: SocketAddr,
        peer_info: MockPeerInfo,
    },
    ConnectionError {
        address: SocketAddr,
        error: error::P2pError,
    },
    ConnectionClosed {
        peer_id: MockPeerId,
    },
}

// TODO: use two events, one for txs and one for blocks?
pub enum PubSubEvent {
    /// Message received from one of the pubsub topics
    Announcement {
        peer_id: SocketAddr,
        topic: net::types::PubSubTopic,
        message: message::Announcement,
    },
}

pub enum SyncingEvent {}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct MockPeerId(u64);

impl MockPeerId {
    pub fn random() -> Self {
        let mut rng = make_pseudo_rng();
        Self(rng.gen::<u64>())
    }

    pub fn from_socket_address(addr: &SocketAddr) -> Self {
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

#[derive(Debug, PartialEq, Eq)]
pub struct MockPeerInfo {
    pub peer_id: MockPeerId,
    pub network: [u8; 4],
    pub version: common::primitives::semver::SemVer,
    pub agent: Option<String>,
    pub protocols: Vec<Protocol>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeerEvent {
    PeerInfoReceived {
        peer_id: MockPeerId,
        network: [u8; 4],
        version: semver::SemVer,
        protocols: Vec<Protocol>,
    },
    ConnectionClosed,
}

/// Events sent by the mock backend to peers
#[derive(Debug)]
pub enum MockEvent {
    Disconnect,
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct Protocol {
    name: String,
    version: semver::SemVer,
}

impl Protocol {
    pub fn new(name: &str, version: semver::SemVer) -> Self {
        Self {
            name: name.to_string(),
            version,
        }
    }

    pub fn name(&self) -> &String {
        &self.name
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    Hello {
        peer_id: MockPeerId,
        version: common::primitives::semver::SemVer,
        network: [u8; 4],
        protocols: Vec<Protocol>,
    },
    HelloAck {
        peer_id: MockPeerId,
        version: common::primitives::semver::SemVer,
        network: [u8; 4],
        protocols: Vec<Protocol>,
    },
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Message {
    Handshake(HandshakeMessage),
    Announcement(message::Announcement),
    Request(message::Request),
    Response(message::Response),
}
