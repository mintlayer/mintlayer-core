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
use crate::{error, message, net};
use libp2p::{
    floodsub::{Floodsub, FloodsubEvent as Libp2pFloodsubEvent, Topic},
    mdns::{Mdns, MdnsEvent},
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
    Dial {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        response: oneshot::Sender<error::Result<()>>,
    },

    /// Open a bidirectional data stream to a remote peer
    ///
    /// Before opening a stream, connection must've been established with the peer
    /// and the peer's identity is signaled using `peer_id` argument
    OpenStream {
        peer_id: PeerId,
        response: oneshot::Sender<error::Result<StreamHandle<NegotiatedSubstream>>>,
    },

    /// Publish a message on the designated Floodsub topic
    SendMessage {
        topic: net::FloodsubTopic,
        message: Vec<u8>,
        response: oneshot::Sender<error::Result<()>>,
    },

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
    ConnectionAccepted {
        socket: Box<net::libp2p::Libp2pSocket>,
    },

    /// One or more peers were discovered by one of the discovery strategies
    PeerDiscovered { peers: Vec<(PeerId, Multiaddr)> },

    /// One or more peers that were previously discovered have expired
    PeerExpired { peers: Vec<(PeerId, Multiaddr)> },
}

#[derive(Clone)]
pub enum FloodsubEvent {
    // Message received from one of the Floodsub topics
    MessageReceived {
        peer_id: PeerId,
        topic: net::FloodsubTopic,
        message: message::Message,
    },
}

impl From<&net::FloodsubTopic> for Topic {
    fn from(t: &net::FloodsubTopic) -> Topic {
        match t {
            net::FloodsubTopic::Transactions => Topic::new("mintlayer-floodsub-transactions"),
            net::FloodsubTopic::Blocks => Topic::new("mintlayer-floodsub-blocks"),
        }
    }
}

impl TryFrom<&Topic> for net::FloodsubTopic {
    type Error = &'static str;

    fn try_from(t: &Topic) -> Result<Self, Self::Error> {
        match t.id() {
            "mintlayer-floodsub-transactions" => Ok(net::FloodsubTopic::Transactions),
            "mintlayer-floodsub-blocks" => Ok(net::FloodsubTopic::Blocks),
            _ => Err("Invalid Floodsub topic"),
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedEvent")]
pub struct ComposedBehaviour {
    pub streaming: Streaming<IdentityCodec>,
    pub mdns: Mdns,
    pub floodsub: Floodsub,
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ComposedEvent {
    StreamingEvent(StreamingEvent<IdentityCodec>),
    MdnsEvent(MdnsEvent),
    Libp2pFloodsubEvent(Libp2pFloodsubEvent),
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

impl From<Libp2pFloodsubEvent> for ComposedEvent {
    fn from(event: Libp2pFloodsubEvent) -> Self {
        ComposedEvent::Libp2pFloodsubEvent(event)
    }
}
