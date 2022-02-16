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
    gossipsub::{IdentTopic as Topic, TopicHash},
    streaming::StreamHandle,
    swarm::NegotiatedSubstream,
    Multiaddr, PeerId,
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

    /// Publish a message on the designated Gossipsub topic
    SendMessage {
        topic: net::GossipsubTopic,
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

pub enum Event {
    /// Connection with a data stream has been opened by a remote peer
    ConnectionAccepted {
        socket: Box<net::libp2p::Libp2pSocket>,
    },

    /// One or more peers were discovered by one of the discovery strategies
    PeerDiscovered { peers: Vec<(PeerId, Multiaddr)> },

    /// One or more peers that were previously discovered have expired
    PeerExpired { peers: Vec<(PeerId, Multiaddr)> },

    // Message received from one of the Gossipsub topics
    MessageReceived {
        topic: net::GossipsubTopic,
        message: message::Message,
    },
}

impl From<&net::GossipsubTopic> for Topic {
    fn from(t: &net::GossipsubTopic) -> Topic {
        match t {
            net::GossipsubTopic::Transactions => Topic::new("mintlayer-gossipsub-transactions"),
            net::GossipsubTopic::Blocks => Topic::new("mintlayer-gossipsub-blocks"),
        }
    }
}

impl TryFrom<TopicHash> for net::GossipsubTopic {
    type Error = &'static str;

    fn try_from(t: TopicHash) -> Result<Self, Self::Error> {
        match t.as_str() {
            "mintlayer-gossipsub-transactions" => Ok(net::GossipsubTopic::Transactions),
            "mintlayer-gossipsub-blocks" => Ok(net::GossipsubTopic::Blocks),
            _ => Err("Invalid Gossipsub topic"),
        }
    }
}
