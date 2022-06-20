// Copyright (c) 2021 Protocol Labs
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
use crate::{
    error, message,
    net::{
        self,
        libp2p::{SyncRequest, SyncResponse, SyncingCodec},
    },
};
use libp2p::{
    gossipsub::{
        Gossipsub, GossipsubEvent, IdentTopic as Topic, MessageAcceptance, MessageId, TopicHash,
    },
    identify::{Identify, IdentifyEvent, IdentifyInfo},
    mdns::{Mdns, MdnsEvent},
    ping::{self, PingEvent},
    request_response::{RequestId, RequestResponse, RequestResponseEvent},
    Multiaddr, NetworkBehaviour, PeerId,
};
use tokio::sync::oneshot;

// TODO: rename `response` -> `channel`
#[derive(Debug)]
pub enum Command {
    /// Start listening on the network interface specified by `addr`
    Listen {
        addr: Multiaddr,
        response: oneshot::Sender<crate::Result<()>>,
    },

    /// Connect to a remote peer at address `peer_addr`
    Connect {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        response: oneshot::Sender<crate::Result<()>>,
    },

    /// Disconnect remote peer
    Disconnect {
        peer_id: PeerId,
        response: oneshot::Sender<crate::Result<()>>,
    },

    // TODO: rethink this message
    /// Publish a message on the designated GossipSub topic
    SendMessage {
        topic: net::types::PubSubTopic,
        message: Vec<u8>,
        response: oneshot::Sender<crate::Result<()>>,
    },

    /// Report validation result of a received Gossipsub
    ReportValidationResult {
        message_id: MessageId,
        source: PeerId,
        result: MessageAcceptance,
        response: oneshot::Sender<crate::Result<()>>,
    },

    /// Send block request to remote peer
    SendRequest {
        peer_id: PeerId,
        request: Box<SyncRequest>,
        response: oneshot::Sender<crate::Result<RequestId>>,
    },

    /// Send block response to remote peer
    SendResponse {
        request_id: RequestId,
        response: Box<SyncResponse>,
        channel: oneshot::Sender<crate::Result<()>>,
    },
}

#[derive(Debug)]
pub enum ConnectivityEvent {
    #[allow(unused)]
    /// Outbound connection accepted by remote
    ConnectionAccepted {
        addr: Multiaddr,
        peer_info: Box<IdentifyInfo>,
    },

    /// Inbound connection incoming
    IncomingConnection {
        addr: Multiaddr,
        peer_info: Box<IdentifyInfo>,
    },

    /// Outbound connection failed
    ConnectionError {
        addr: Multiaddr,
        error: error::P2pError,
    },

    /// Remote closed connection
    ConnectionClosed { peer_id: PeerId },

    /// One or more peers were discovered by one of the discovery strategies
    Discovered { peers: Vec<(PeerId, Multiaddr)> },

    /// One or more peers that were previously discovered have expired
    Expired { peers: Vec<(PeerId, Multiaddr)> },

    /// Peer disconnected from the swarm
    Disconnected { peer_id: PeerId },

    /// An error occurred with a connected peer
    Error {
        peer_id: PeerId,
        error: error::P2pError,
    },

    /// Peer misbehaved
    Misbehaved { peer_id: PeerId, behaviour: u32 },
}

#[derive(Debug, Clone)]
pub enum PubSubEvent {
    // TODO: rethink this event
    // TODO: box?
    // Message received from one of the PubSub topics
    MessageReceived {
        peer_id: PeerId,
        message_id: MessageId,
        message: message::Message,
    },
}

pub enum SyncingEvent {
    Request {
        peer_id: PeerId,
        request_id: RequestId,
        request: Box<SyncRequest>,
    },
    Response {
        peer_id: PeerId,
        request_id: RequestId,
        response: Box<SyncResponse>,
    },
    Error {
        peer_id: PeerId,
        request_id: RequestId,
        error: net::types::RequestResponseError,
    },
}

impl From<&net::types::PubSubTopic> for Topic {
    fn from(t: &net::types::PubSubTopic) -> Topic {
        match t {
            net::types::PubSubTopic::Transactions => Topic::new("mintlayer-gossipsub-transactions"),
            net::types::PubSubTopic::Blocks => Topic::new("mintlayer-gossipsub-blocks"),
        }
    }
}

impl TryFrom<TopicHash> for net::types::PubSubTopic {
    type Error = &'static str;

    fn try_from(t: TopicHash) -> Result<Self, Self::Error> {
        match t.as_str() {
            "mintlayer-gossipsub-transactions" => Ok(net::types::PubSubTopic::Transactions),
            "mintlayer-gossipsub-blocks" => Ok(net::types::PubSubTopic::Blocks),
            _ => Err("Invalid Gossipsub topic"),
        }
    }
}

impl From<net::types::ValidationResult> for MessageAcceptance {
    fn from(t: net::types::ValidationResult) -> MessageAcceptance {
        match t {
            net::types::ValidationResult::Accept => MessageAcceptance::Accept,
            net::types::ValidationResult::Reject => MessageAcceptance::Reject,
            net::types::ValidationResult::Ignore => MessageAcceptance::Ignore,
        }
    }
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Libp2pBehaviourEvent {
    MdnsEvent(MdnsEvent),
    GossipsubEvent(GossipsubEvent),
    PingEvent(PingEvent),
    IdentifyEvent(IdentifyEvent),
    SyncingEvent(RequestResponseEvent<SyncRequest, SyncResponse>),

    /// One or more peers were discovered by one of the discovery strategies
    Discovered {
        peers: Vec<(PeerId, Multiaddr)>,
    },

    /// One or more peers that were previously discovered have expired
    Expired {
        peers: Vec<(PeerId, Multiaddr)>,
    },

    /// Peer disconnected from the swarm
    Disconnected {
        peer_id: PeerId,
    },
}

impl From<GossipsubEvent> for Libp2pBehaviourEvent {
    fn from(event: GossipsubEvent) -> Self {
        Libp2pBehaviourEvent::GossipsubEvent(event)
    }
}

impl From<PingEvent> for Libp2pBehaviourEvent {
    fn from(event: PingEvent) -> Self {
        Libp2pBehaviourEvent::PingEvent(event)
    }
}

impl From<IdentifyEvent> for Libp2pBehaviourEvent {
    fn from(event: IdentifyEvent) -> Self {
        Libp2pBehaviourEvent::IdentifyEvent(event)
    }
}

impl From<RequestResponseEvent<SyncRequest, SyncResponse>> for Libp2pBehaviourEvent {
    fn from(event: RequestResponseEvent<SyncRequest, SyncResponse>) -> Self {
        Libp2pBehaviourEvent::SyncingEvent(event)
    }
}
