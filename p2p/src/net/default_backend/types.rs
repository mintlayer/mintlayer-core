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

use common::{
    chain::{SignedTransaction, Transaction},
    primitives::{semver::SemVer, user_agent::UserAgent, Id},
};
use serialization::{Decode, Encode};

use crate::{
    message::{
        AddrListRequest, AddrListResponse, AnnounceAddrRequest, Announcement, BlockListRequest,
        BlockResponse, HeaderListRequest, HeaderListResponse, PeerManagerMessage, PingRequest,
        PingResponse, SyncMessage,
    },
    net::types::services::{Service, Services},
    protocol::NetworkProtocol,
    types::{peer_address::PeerAddress, peer_id::PeerId},
};

#[derive(Debug)]
pub enum Command<A> {
    Connect { address: A },
    Accept { peer_id: PeerId },
    Disconnect { peer_id: PeerId },
    SendMessage { peer: PeerId, message: Message },
    AnnounceData { service: Service, message: Vec<u8> },
}

/// Random nonce sent in outbound handshake.
/// Used to detect and drop self connections.
pub type HandshakeNonce = u64;

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
    MessageReceived { message: Message },
}

/// Events sent by the default_backend backend to peers
#[derive(Debug)]
pub enum Event {
    Accepted,
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
    Announcement(Box<Announcement>),

    #[codec(index = 4)]
    HeaderListRequest(HeaderListRequest),
    #[codec(index = 5)]
    HeaderListResponse(HeaderListResponse),
    #[codec(index = 6)]
    BlockListRequest(BlockListRequest),
    #[codec(index = 7)]
    BlockResponse(BlockResponse),
    #[codec(index = 11)]
    TransactionRequest(Id<Transaction>),
    #[codec(index = 12)]
    TransactionResponse(SignedTransaction),

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
            SyncMessage::HeaderListResponse(r) => Message::HeaderListResponse(r),
            SyncMessage::BlockResponse(r) => Message::BlockResponse(r),
            SyncMessage::TransactionRequest(id) => Message::TransactionRequest(id),
            SyncMessage::TransactionResponse(tx) => Message::TransactionResponse(tx),
        }
    }
}
