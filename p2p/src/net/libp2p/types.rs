// Copyright (c) 2021 Protocol Labs
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

use std::net::IpAddr;

use libp2p::{
    gossipsub::{IdentTopic as Topic, MessageAcceptance, MessageId, TopicHash},
    identify::IdentifyInfo,
    request_response::RequestId,
    Multiaddr, PeerId,
};
use tokio::sync::oneshot;

use crate::{
    error, message,
    net::{
        self,
        libp2p::behaviour::sync_codec::message_types::{SyncRequest, SyncResponse},
        types::GetIp,
    },
};

#[derive(Debug)]
pub struct IdentifyInfoWrapper(Box<IdentifyInfo>);

impl IdentifyInfoWrapper {
    pub fn new(info: IdentifyInfo) -> Self {
        Self(Box::new(info))
    }
}

impl std::ops::Deref for IdentifyInfoWrapper {
    type Target = Box<IdentifyInfo>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq for IdentifyInfoWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.public_key == other.0.public_key
            && self.0.protocol_version == other.0.protocol_version
            && self.0.agent_version == other.0.agent_version
            && self.0.listen_addrs == other.0.listen_addrs
            && self.0.protocols == other.0.protocols
            && self.0.observed_addr == other.0.observed_addr
    }
}

impl Eq for IdentifyInfoWrapper {}

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

    /// Publish a message on the designated GossipSub topic
    AnnounceData {
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

    /// Subscribe to gossipsub topics
    Subscribe {
        topics: Vec<Topic>,
        response: oneshot::Sender<crate::Result<()>>,
    },

    /// Get the active listen address
    ListenAddress {
        response: oneshot::Sender<Option<Multiaddr>>,
    },

    /// Ban remote peer
    BanPeer {
        peer_id: PeerId,
        response: oneshot::Sender<crate::Result<()>>,
    },
}

#[derive(Debug)]
pub enum ConnectivityEvent {
    /// Outbound connection accepted by remote
    OutboundAccepted {
        address: Multiaddr,
        peer_info: IdentifyInfoWrapper,
    },

    /// Inbound connection incoming
    InboundAccepted {
        address: Multiaddr,
        peer_info: IdentifyInfoWrapper,
    },

    /// Outbound connection failed
    ConnectionError {
        address: Multiaddr,
        error: error::P2pError,
    },

    /// Remote closed connection
    ConnectionClosed { peer_id: PeerId },

    /// One or more peers were discovered by one of the discovery strategies
    Discovered { peers: Vec<(PeerId, Multiaddr)> },

    /// One or more peers that were previously discovered have expired
    Expired { peers: Vec<(PeerId, Multiaddr)> },

    /// Peer misbehaved, adjust its reputation
    Misbehaved {
        peer_id: PeerId,
        error: error::P2pError,
    },
}

#[derive(Debug)]
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
    Announcement {
        peer_id: PeerId,
        message_id: MessageId,
        announcement: Box<message::Announcement>,
    },
}

#[derive(Debug)]
pub enum ControlEvent {
    CloseConnection { peer_id: PeerId },
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
    Connectivity(ConnectivityEvent),
    Syncing(SyncingEvent),
    Control(ControlEvent),
}

impl GetIp for libp2p::Multiaddr {
    fn ip(&self) -> IpAddr {
        // TODO: This is ugly and incorrect.
        while let Some(component) = self.iter().next() {
            match component {
                libp2p::multiaddr::Protocol::Ip4(a) => return a.into(),
                libp2p::multiaddr::Protocol::Ip6(a) => return a.into(),
                _ => continue,
            }
        }
        panic!("Unable to get ip from the {:?} address", self)
    }
}
