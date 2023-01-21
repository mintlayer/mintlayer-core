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

use std::collections::BTreeSet;

use tokio::sync::oneshot;

use common::primitives::semver::SemVer;
use serialization::{Decode, Encode};

use crate::{
    message,
    net::{self, default_backend::transport::TransportSocket, types::PubSubTopic},
    types::{PeerAddress, PeerId, RequestId},
};

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

// TODO: use two events, one for txs and one for blocks?
pub enum PubSubEvent<T: TransportSocket> {
    /// Message received from one of the pubsub topics
    Announcement {
        peer_id: T::Address,
        topic: net::types::PubSubTopic,
        message: message::Announcement,
    },
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
