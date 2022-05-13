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
use common::{chain::config, primitives::version};
use crypto::random::{make_pseudo_rng, Rng};
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::SocketAddr,
};
use tokio::{net::TcpStream, sync::oneshot};

pub type MockRequestId = u64;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
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

#[derive(Debug)]
pub struct MockPeerInfo {
    pub peer_id: MockPeerId,
    pub magic_bytes: [u8; 4],
    pub version: common::primitives::version::SemVer,
    pub agent: Option<String>,
    pub protocols: Vec<Protocol>,
}

pub enum Command {
    /// Connect to a remote peer at address `peer_addr`
    Connect {
        addr: SocketAddr,
        response: oneshot::Sender<error::Result<MockPeerInfo>>,
    },

    /// Disconnect remote peer
    Disconnect {
        peer_id: MockPeerId,
        response: oneshot::Sender<error::Result<()>>,
    },

    /// Send request to remote peer
    SendRequest {
        peer_id: MockPeerId,
        message: message::Message,
        response: oneshot::Sender<error::Result<MockRequestId>>,
    },

    /// Send response to remote peer
    SendResponse {
        request_id: MockRequestId,
        message: message::Message,
        response: oneshot::Sender<error::Result<()>>,
    },
}

pub enum SyncingEvent {
    Request {
        peer_id: MockPeerId,
        request_id: MockRequestId,
        request: message::Message,
    },

    Response {
        peer_id: MockPeerId,
        request_id: MockRequestId,
        response: message::Message,
    },
}

#[derive(Debug)]
pub enum ConnectivityEvent {
    IncomingConnection {
        addr: SocketAddr,
        peer_info: MockPeerInfo,
    },

    Disconnected {
        peer_id: MockPeerId,
    },
}

// TODO: use two events, one for txs and one for blocks?
pub enum FloodsubEvent {
    /// Message received from one of the floodsub topics
    MessageReceived {
        peer_id: SocketAddr,
        topic: net::PubSubTopic,
        message: message::Message,
    },
}

/// Events sent by the peer object to mock backend
#[derive(Debug, PartialEq)]
pub enum PeerEvent {
    PeerInfoReceived {
        magic_bytes: [u8; 4],
        version: version::SemVer,
        protocols: Vec<Protocol>,
    },

    MessageReceived {
        message: Message,
    },
}

// TODO: Handle?
/// Events sent by the mock backend to peers
#[derive(Debug)]
pub enum MockEvent {
    Disconnect,
    SendMessage(Box<Message>),
}

#[derive(Debug, Encode, Decode, PartialEq)]
pub struct Protocol {
    name: String,
    version: version::SemVer,
}

impl Protocol {
    pub fn new(name: &str, version: version::SemVer) -> Self {
        Self {
            name: name.to_string(),
            version,
        }
    }

    pub fn name(&self) -> &String {
        &self.name
    }
}

#[derive(Debug, Encode, Decode, PartialEq)]
pub enum HandshakeMessage {
    Hello {
        version: common::primitives::version::SemVer,
        network: [u8; 4],
        protocols: Vec<Protocol>,
    },
    HelloAck {
        version: common::primitives::version::SemVer,
        network: [u8; 4],
        protocols: Vec<Protocol>,
    },
}

#[derive(Debug, Encode, Decode, PartialEq)]
pub enum SyncingMessage {
    Request {
        request_id: u64,
        request: message::Message,
    },
    Response {
        request_id: u64,
        response: message::Message,
    },
}

#[derive(Debug, Encode, Decode, PartialEq)]
pub enum Message {
    Handshake(HandshakeMessage),
    Syncing(SyncingMessage),
}
