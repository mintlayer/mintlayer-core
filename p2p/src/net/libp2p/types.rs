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
    net::{self, libp2p::Libp2pService},
};
use libp2p::{
    gossipsub::{
        Gossipsub, GossipsubEvent, GossipsubMessage, IdentTopic as Topic, MessageAcceptance,
        MessageAuthenticity, MessageId, TopicHash, ValidationMode,
    },
    identify::{Identify, IdentifyEvent, IdentifyInfo},
    mdns::{Mdns, MdnsEvent},
    ping::{self, PingEvent},
    streaming::{IdentityCodec, StreamHandle, Streaming, StreamingEvent},
    swarm::NegotiatedSubstream,
    Multiaddr, NetworkBehaviour, PeerId,
};
use tokio::sync::oneshot;

#[derive(Debug)]
pub enum Command {
    /// Start listening on the network interface specified by `addr`
    Listen {
        addr: Multiaddr,
        response: oneshot::Sender<error::Result<()>>,
    },

    /// Connect to a remote peer at address `peer_addr` whose PeerId is `peer_id`
    Connect {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        response: oneshot::Sender<error::Result<IdentifyInfo>>,
    },

    /// Open a bidirectional data stream to a remote peer
    ///
    /// Before opening a stream, connection must've been established with the peer
    /// and the peer's identity is signaled using `peer_id` argument
    OpenStream {
        peer_id: PeerId,
        response: oneshot::Sender<error::Result<StreamHandle<NegotiatedSubstream>>>,
    },

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

    // /// Wait for identifying information of the peer
    // WaitForPeerInfo {
    //     peer_id: PeerId,
    //     response: oneshot::Sender<error::Result<IdentifyInfo>>,
    // },
    /// Register peer to libp2p
    Register {
        peer: PeerId,
        response: oneshot::Sender<error::Result<()>>,
    },

    /// Unregister peer from libp2p
    Unregister {
        peer: PeerId,
        response: oneshot::Sender<error::Result<()>>,
    },
}

pub enum ConnectivityEvent {
    /// Connection with a data stream has been opened by a remote peer
    ConnectionAccepted { peer_info: Box<IdentifyInfo> },

    /// One or more peers were discovered by one of the discovery strategies
    PeerDiscovered { peers: Vec<(PeerId, Multiaddr)> },

    /// One or more peers that were previously discovered have expired
    PeerExpired { peers: Vec<(PeerId, Multiaddr)> },
}

#[derive(Clone)]
pub enum PubSubEvent {
    // Message received from one of the PubSub topics
    MessageReceived {
        peer_id: PeerId,
        topic: net::PubSubTopic,
        message: message::Message,
        message_id: MessageId,
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
    pub streaming: Streaming<IdentityCodec>,
    pub mdns: Mdns,
    pub gossipsub: Gossipsub,
    pub ping: ping::Behaviour,
    pub identify: Identify,
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ComposedEvent {
    StreamingEvent(StreamingEvent<IdentityCodec>),
    MdnsEvent(MdnsEvent),
    GossipsubEvent(GossipsubEvent),
    PingEvent(PingEvent),
    IdentifyEvent(IdentifyEvent),
}

impl From<StreamingEvent<IdentityCodec>> for ComposedEvent {
    fn from(event: StreamingEvent<IdentityCodec>) -> Self {
        ComposedEvent::StreamingEvent(event)
    }
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
