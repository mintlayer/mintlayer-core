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
#![allow(unused)]

use crate::{
    error, message,
    net::{
        self,
        libp2p::{Libp2pService, SyncRequest, SyncResponse, SyncingCodec},
    },
};
use libp2p::{
    gossipsub::{
        Gossipsub, GossipsubEvent, GossipsubMessage, IdentTopic as Topic, MessageAcceptance,
        MessageAuthenticity, MessageId, TopicHash, ValidationMode,
    },
    identify::{Identify, IdentifyEvent, IdentifyInfo},
    mdns::{Mdns, MdnsEvent},
    ping::{self, PingEvent},
    // TODO: do not use *
    request_response::*,
    swarm::NegotiatedSubstream,
    Multiaddr,
    NetworkBehaviour,
    PeerId,
};
// use std::sync::Arc;
use tokio::sync::oneshot;

// TODO: rename `response` -> `channel`
#[derive(Debug)]
pub enum Command {
    /// Start listening on the network interface specified by `addr`
    Listen {
        addr: Multiaddr,
        response: oneshot::Sender<error::Result<()>>,
    },

    /// Connect to a remote peer at address `peer_addr`
    Connect {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        response: oneshot::Sender<error::Result<IdentifyInfo>>,
    },

    /// Disconnect remote peer
    Disconnect {
        peer_id: PeerId,
        response: oneshot::Sender<error::Result<()>>,
    },

    // TODO: rethink this message
    /// Publish a message on the designated GossipSub topic
    SendMessage {
        topic: net::PubSubTopic,
        message: Vec<u8>,
        response: oneshot::Sender<error::Result<()>>,
    },

    /// Report validation result of a received Gossipsub
    ReportValidationResult {
        message_id: MessageId,
        source: PeerId,
        result: MessageAcceptance,
        response: oneshot::Sender<error::Result<()>>,
    },

    /// Send block request to remote peer
    SendRequest {
        peer_id: PeerId,
        request: Box<SyncRequest>,
        response: oneshot::Sender<error::Result<RequestId>>,
    },

    /// Send block response to remote peer
    SendResponse {
        request_id: RequestId,
        response: Box<SyncResponse>,
        channel: oneshot::Sender<error::Result<()>>,
    },
}

#[derive(Debug)]
pub enum ConnectivityEvent {
    /// Outbound connection accepted by remote
    ConnectionAccepted { peer_info: Box<IdentifyInfo> },

    /// Inbound connection incoming
    IncomingConnection {
        addr: Multiaddr,
        peer_info: Box<IdentifyInfo>,
    },

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
    SyncRequest {
        peer_id: PeerId,
        request_id: RequestId,
        request: Box<SyncRequest>,
    },
    SyncResponse {
        peer_id: PeerId,
        request_id: RequestId,
        response: Box<SyncResponse>,
    },
}

impl From<&net::PubSubTopic> for Topic {
    fn from(t: &net::PubSubTopic) -> Topic {
        match t {
            net::PubSubTopic::Transactions => Topic::new("mintlayer-gossipsub-transactions"),
            net::PubSubTopic::Blocks => Topic::new("mintlayer-gossipsub-blocks"),
        }
    }
}

impl TryFrom<TopicHash> for net::PubSubTopic {
    type Error = &'static str;

    fn try_from(t: TopicHash) -> Result<Self, Self::Error> {
        match t.as_str() {
            "mintlayer-gossipsub-transactions" => Ok(net::PubSubTopic::Transactions),
            "mintlayer-gossipsub-blocks" => Ok(net::PubSubTopic::Blocks),
            _ => Err("Invalid Gossipsub topic"),
        }
    }
}

impl From<net::ValidationResult> for MessageAcceptance {
    fn from(t: net::ValidationResult) -> MessageAcceptance {
        match t {
            net::ValidationResult::Accept => MessageAcceptance::Accept,
            net::ValidationResult::Reject => MessageAcceptance::Reject,
            net::ValidationResult::Ignore => MessageAcceptance::Ignore,
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedEvent")]
pub struct ComposedBehaviour {
    pub mdns: Mdns,
    pub gossipsub: Gossipsub,
    pub ping: ping::Behaviour,
    pub identify: Identify,
    pub sync: RequestResponse<SyncingCodec>,
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ComposedEvent {
    MdnsEvent(MdnsEvent),
    GossipsubEvent(GossipsubEvent),
    PingEvent(PingEvent),
    IdentifyEvent(IdentifyEvent),
    SyncingEvent(RequestResponseEvent<SyncRequest, SyncResponse>),
}

impl From<MdnsEvent> for ComposedEvent {
    fn from(event: MdnsEvent) -> Self {
        ComposedEvent::MdnsEvent(event)
    }
}

impl From<GossipsubEvent> for ComposedEvent {
    fn from(event: GossipsubEvent) -> Self {
        ComposedEvent::GossipsubEvent(event)
    }
}

impl From<PingEvent> for ComposedEvent {
    fn from(event: PingEvent) -> Self {
        ComposedEvent::PingEvent(event)
    }
}

impl From<IdentifyEvent> for ComposedEvent {
    fn from(event: IdentifyEvent) -> Self {
        ComposedEvent::IdentifyEvent(event)
    }
}

impl From<RequestResponseEvent<SyncRequest, SyncResponse>> for ComposedEvent {
    fn from(event: RequestResponseEvent<SyncRequest, SyncResponse>) -> Self {
        ComposedEvent::SyncingEvent(event)
    }
}
