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

use std::time::Duration;

use common::{
    chain::Transaction,
    primitives::{semver::SemVer, user_agent::UserAgent, Id},
};
use p2p_types::socket_address::SocketAddress;
use serialization::{Decode, Encode};
use tokio::sync::mpsc::Sender;

use crate::{
    message::{
        AddrListRequest, AddrListResponse, AnnounceAddrRequest, BlockListRequest, BlockResponse,
        HeaderList, HeaderListRequest, PeerManagerMessage, PingRequest, PingResponse, SyncMessage,
        TransactionResponse,
    },
    net::types::services::Services,
    protocol::NetworkProtocol,
    types::{peer_address::PeerAddress, peer_id::PeerId},
};

#[derive(Debug)]
pub enum Command {
    Connect { address: SocketAddress },
    Accept { peer_id: PeerId },
    Disconnect { peer_id: PeerId },
    SendMessage { peer: PeerId, message: Message },
}

/// Random nonce sent in outbound handshake.
/// Used to detect and drop self connections.
pub type HandshakeNonce = u64;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Encode, Decode)]
pub struct P2pTimestamp(#[codec(compact)] u64);

impl P2pTimestamp {
    #[cfg(test)]
    pub fn from_int_seconds(timestamp: u64) -> Self {
        Self(timestamp)
    }

    pub fn from_duration_since_epoch(duration: Duration) -> Self {
        Self(duration.as_secs())
    }

    pub fn as_duration_since_epoch(&self) -> Duration {
        Duration::from_secs(self.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeerEvent {
    /// Peer information received from remote
    PeerInfoReceived {
        protocol: NetworkProtocol,
        network: [u8; 4],
        services: Services,
        user_agent: UserAgent,
        version: SemVer,
        receiver_address: Option<PeerAddress>,

        /// For outbound connections that is what we sent.
        /// For inbound connections that is what was received from remote peer.
        handshake_nonce: HandshakeNonce,
    },

    /// Connection closed to remote
    ConnectionClosed,

    /// Message received from remote
    MessageReceived { message: PeerManagerMessage },
}

/// Events sent by the default_backend backend to peers
#[derive(Debug)]
pub enum Event {
    Accepted { sync_tx: Sender<SyncMessage> },
    SendMessage(Box<Message>),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    Hello {
        protocol: NetworkProtocol,
        network: [u8; 4],
        services: Services,
        user_agent: UserAgent,
        version: SemVer,

        /// Socket address of the remote peer as seen by this node (addr_you in bitcoin)
        receiver_address: Option<PeerAddress>,

        current_time: P2pTimestamp,

        /// Random nonce that is only used to detect and drop self-connects
        handshake_nonce: HandshakeNonce,
    },
    HelloAck {
        protocol: NetworkProtocol,
        network: [u8; 4],
        services: Services,
        user_agent: UserAgent,
        version: SemVer,

        /// Socket address of the remote peer as seen by this node (addr_you in bitcoin)
        receiver_address: Option<PeerAddress>,

        current_time: P2pTimestamp,
    },
}

#[derive(Debug, Encode, Decode, PartialEq, Eq, Clone)]
pub enum Message {
    #[codec(index = 0)]
    Handshake(HandshakeMessage),

    #[codec(index = 1)]
    PingRequest(PingRequest),
    #[codec(index = 2)]
    PingResponse(PingResponse),

    #[codec(index = 3)]
    NewTransaction(Id<Transaction>),
    #[codec(index = 4)]
    HeaderListRequest(HeaderListRequest),
    #[codec(index = 5)]
    HeaderList(HeaderList),
    #[codec(index = 6)]
    BlockListRequest(BlockListRequest),
    #[codec(index = 7)]
    BlockResponse(BlockResponse),
    #[codec(index = 11)]
    TransactionRequest(Id<Transaction>),
    #[codec(index = 12)]
    TransactionResponse(TransactionResponse),

    #[codec(index = 8)]
    AnnounceAddrRequest(AnnounceAddrRequest),
    #[codec(index = 9)]
    AddrListRequest(AddrListRequest),
    #[codec(index = 10)]
    AddrListResponse(AddrListResponse),
}

impl From<PeerManagerMessage> for Message {
    fn from(message: PeerManagerMessage) -> Self {
        match message {
            PeerManagerMessage::AddrListRequest(r) => Message::AddrListRequest(r),
            PeerManagerMessage::AnnounceAddrRequest(r) => Message::AnnounceAddrRequest(r),
            PeerManagerMessage::PingRequest(r) => Message::PingRequest(r),
            PeerManagerMessage::AddrListResponse(r) => Message::AddrListResponse(r),
            PeerManagerMessage::PingResponse(r) => Message::PingResponse(r),
        }
    }
}

impl From<SyncMessage> for Message {
    fn from(message: SyncMessage) -> Self {
        match message {
            SyncMessage::HeaderListRequest(r) => Message::HeaderListRequest(r),
            SyncMessage::BlockListRequest(r) => Message::BlockListRequest(r),
            SyncMessage::HeaderList(r) => Message::HeaderList(r),
            SyncMessage::BlockResponse(r) => Message::BlockResponse(r),
            SyncMessage::NewTransaction(id) => Message::NewTransaction(id),
            SyncMessage::TransactionRequest(id) => Message::TransactionRequest(id),
            SyncMessage::TransactionResponse(tx) => Message::TransactionResponse(tx),
        }
    }
}
