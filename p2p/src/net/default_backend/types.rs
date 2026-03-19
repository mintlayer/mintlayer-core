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

use tokio::sync::{mpsc::Sender, oneshot};

use common::{
    chain::{config::MagicBytes, Transaction},
    primitives::{semver::SemVer, time::Time, user_agent::UserAgent, Id, Idable as _},
};
use p2p_types::socket_address::SocketAddress;
use serialization::{Decode, Encode};
use utils::displayable_option::DisplayableOption;

use crate::{
    disconnection_reason::DisconnectionReason,
    error::P2pError,
    message::{
        AddrListRequest, AddrListResponse, AnnounceAddrRequest, BlockListRequest, BlockResponse,
        BlockSyncMessage, HeaderList, HeaderListRequest, PeerManagerMessage, PingRequest,
        PingResponse, TransactionResponse, TransactionSyncMessage, WillDisconnectMessage,
    },
    net::types::{services::Services, PeerManagerMessageExt},
    protocol::{ProtocolVersion, SupportedProtocolVersion},
    types::{peer_address::PeerAddress, peer_id::PeerId},
};

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Connect {
        address: SocketAddress,
        local_services_override: Option<Services>,
    },
    Accept {
        peer_id: PeerId,
    },
    Disconnect {
        peer_id: PeerId,
        reason: Option<DisconnectionReason>,
    },
    SendMessage {
        peer_id: PeerId,
        message: Message,
    },
    EnableNetworking {
        enable: bool,
    },
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

    pub fn from_time(time: Time) -> Self {
        Self::from_duration_since_epoch(time.as_duration_since_epoch())
    }
}

pub mod peer_event {
    use common::chain::config::MagicBytes;

    use super::*;

    /// The "peer info" from PeerEvent's perspective.
    ///
    /// Note that we also have another `PeerInfo` in a higher-level module that has slightly
    /// different fields.
    #[derive(Debug, PartialEq, Eq)]
    pub struct PeerInfo {
        pub protocol_version: SupportedProtocolVersion,
        pub network: MagicBytes,
        pub common_services: Services,
        pub user_agent: UserAgent,
        pub software_version: SemVer,
        pub node_address_as_seen_by_peer: Option<PeerAddress>,

        /// For outbound connections that is what we sent.
        /// For inbound connections that is what was received from remote peer.
        pub handshake_nonce: HandshakeNonce,
    }
}

/// Events sent by `Peer` to `Backend`.
#[derive(Debug)]
pub enum PeerEvent {
    /// Peer information received from remote
    PeerInfoReceived(peer_event::PeerInfo),

    /// Connection closed to remote
    ConnectionClosed,

    /// Message received from remote
    MessageReceived(PeerManagerMessageExt),

    /// Protocol violation
    Misbehaved { error: P2pError },

    /// Protocol violation during handshake
    MisbehavedOnHandshake { error: P2pError },

    /// Upon receiving this event, `Backend` should send a value through the provided one-shot
    /// sender. By awaiting on the corresponding receiver, `Peer` can make sure that all previously
    /// sent events have already been processed by `Backend`.
    Sync {
        event_received_confirmation_sender: oneshot::Sender<()>,
    },
}

/// Events sent by `Backend` to `Peer`.
#[derive(Debug)]
pub enum BackendEvent {
    Accepted {
        block_sync_msg_sender: Sender<BlockSyncMessage>,
        transaction_sync_msg_sender: Sender<TransactionSyncMessage>,
    },
    SendMessage(Box<Message>),
    Disconnect {
        reason: Option<DisconnectionReason>,
    },
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    #[codec(index = 0)]
    Hello {
        protocol_version: ProtocolVersion,
        network: MagicBytes,
        services: Services,
        user_agent: UserAgent,
        software_version: SemVer,

        /// Socket address of the remote peer as seen by the sending node (addr_you in bitcoin)
        receiver_address: Option<PeerAddress>,

        current_time: P2pTimestamp,

        /// Random nonce that is only used to detect and drop self-connects
        handshake_nonce: HandshakeNonce,
    },
    #[codec(index = 1)]
    HelloAck {
        protocol_version: ProtocolVersion,
        network: MagicBytes,
        services: Services,
        user_agent: UserAgent,
        software_version: SemVer,

        /// Socket address of the remote peer as seen by the sending node (addr_you in bitcoin)
        receiver_address: Option<PeerAddress>,

        current_time: P2pTimestamp,
    },
}

#[derive(Debug, Encode, Decode, PartialEq, Eq, Clone, strum::EnumDiscriminants)]
#[strum_discriminants(name(MessageTag))]
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

    /// Indicates that the peer will be disconnected immediately, providing a reason
    /// for the disconnection. Available since protocol V3.
    #[codec(index = 13)]
    WillDisconnect(WillDisconnectMessage),

    // A message that corresponds to BlockSyncMessage::TestSentinel.
    #[cfg(test)]
    #[codec(index = 255)]
    TestBlockSyncMsgSentinel(Id<()>),
}

impl From<PeerManagerMessage> for Message {
    fn from(message: PeerManagerMessage) -> Self {
        match message {
            PeerManagerMessage::AddrListRequest(r) => Message::AddrListRequest(r),
            PeerManagerMessage::AnnounceAddrRequest(r) => Message::AnnounceAddrRequest(r),
            PeerManagerMessage::PingRequest(r) => Message::PingRequest(r),
            PeerManagerMessage::AddrListResponse(r) => Message::AddrListResponse(r),
            PeerManagerMessage::PingResponse(r) => Message::PingResponse(r),
            PeerManagerMessage::WillDisconnect(r) => Message::WillDisconnect(r),
        }
    }
}

impl From<BlockSyncMessage> for Message {
    fn from(message: BlockSyncMessage) -> Self {
        match message {
            BlockSyncMessage::HeaderListRequest(r) => Message::HeaderListRequest(r),
            BlockSyncMessage::BlockListRequest(r) => Message::BlockListRequest(r),
            BlockSyncMessage::HeaderList(r) => Message::HeaderList(r),
            BlockSyncMessage::BlockResponse(r) => Message::BlockResponse(r),
            #[cfg(test)]
            BlockSyncMessage::TestSentinel(id) => Message::TestBlockSyncMsgSentinel(id),
        }
    }
}

impl From<TransactionSyncMessage> for Message {
    fn from(message: TransactionSyncMessage) -> Self {
        match message {
            TransactionSyncMessage::NewTransaction(id) => Message::NewTransaction(id),
            TransactionSyncMessage::TransactionRequest(id) => Message::TransactionRequest(id),
            TransactionSyncMessage::TransactionResponse(tx) => Message::TransactionResponse(tx),
        }
    }
}

/// The main purpose of this message type is to simplify conversion from `Message`
/// to `HandshakeMessage`/`PeerManagerMessage`/`XxxSyncMessage`.
#[derive(Debug)]
pub enum CategorizedMessage {
    Handshake(HandshakeMessage),
    PeerManagerMessage(PeerManagerMessage),
    BlockSyncMessage(BlockSyncMessage),
    TransactionSyncMessage(TransactionSyncMessage),
}

impl Message {
    pub fn categorize(self) -> CategorizedMessage {
        match self {
            Message::Handshake(msg) => CategorizedMessage::Handshake(msg),

            Message::PingRequest(msg) => {
                CategorizedMessage::PeerManagerMessage(PeerManagerMessage::PingRequest(msg))
            }
            Message::PingResponse(msg) => {
                CategorizedMessage::PeerManagerMessage(PeerManagerMessage::PingResponse(msg))
            }
            Message::AnnounceAddrRequest(msg) => {
                CategorizedMessage::PeerManagerMessage(PeerManagerMessage::AnnounceAddrRequest(msg))
            }
            Message::AddrListRequest(msg) => {
                CategorizedMessage::PeerManagerMessage(PeerManagerMessage::AddrListRequest(msg))
            }
            Message::AddrListResponse(msg) => {
                CategorizedMessage::PeerManagerMessage(PeerManagerMessage::AddrListResponse(msg))
            }
            Message::WillDisconnect(msg) => {
                CategorizedMessage::PeerManagerMessage(PeerManagerMessage::WillDisconnect(msg))
            }

            Message::HeaderListRequest(msg) => {
                CategorizedMessage::BlockSyncMessage(BlockSyncMessage::HeaderListRequest(msg))
            }
            Message::HeaderList(msg) => {
                CategorizedMessage::BlockSyncMessage(BlockSyncMessage::HeaderList(msg))
            }
            Message::BlockListRequest(msg) => {
                CategorizedMessage::BlockSyncMessage(BlockSyncMessage::BlockListRequest(msg))
            }
            Message::BlockResponse(msg) => {
                CategorizedMessage::BlockSyncMessage(BlockSyncMessage::BlockResponse(msg))
            }
            #[cfg(test)]
            Message::TestBlockSyncMsgSentinel(id) => {
                CategorizedMessage::BlockSyncMessage(BlockSyncMessage::TestSentinel(id))
            }

            Message::NewTransaction(msg) => CategorizedMessage::TransactionSyncMessage(
                TransactionSyncMessage::NewTransaction(msg),
            ),
            Message::TransactionRequest(msg) => CategorizedMessage::TransactionSyncMessage(
                TransactionSyncMessage::TransactionRequest(msg),
            ),
            Message::TransactionResponse(msg) => CategorizedMessage::TransactionSyncMessage(
                TransactionSyncMessage::TransactionResponse(msg),
            ),
        }
    }
}

/// A type that implements `Display` and produces a summary for the message to print to debug log.
///
/// Note that this is supposed to be printed on every received or sent message, so even though
/// it's debug info, it's better to keep it compact.
#[derive(Debug, Clone, Copy)]
pub struct MessageDebugLogSummary<'a>(pub &'a Message);

impl<'a> std::fmt::Display for MessageDebugLogSummary<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Message::Handshake(msg) => match msg {
                HandshakeMessage::Hello { .. } => {
                    write!(f, "Handshake-Hello")
                }
                HandshakeMessage::HelloAck { .. } => {
                    write!(f, "Handshake-HelloAck")
                }
            },
            Message::PingRequest(msg) => write!(f, "PingRequest(nonce={})", msg.nonce),
            Message::PingResponse(msg) => write!(f, "PingResponse(nonce={})", msg.nonce),
            Message::NewTransaction(id) => write!(f, "NewTransaction(id={id:x})"),
            Message::HeaderListRequest(msg) => write!(
                f,
                "HeaderListRequest(locator 1st block id={:x})",
                msg.locator().iter().next().as_displayable()
            ),
            Message::HeaderList(msg) => {
                let first_header_id = msg.headers().first().map(|hdr| hdr.block_id());
                write!(
                    f,
                    "HeaderList(1st hdr id={:x}, count={})",
                    first_header_id.as_displayable(),
                    msg.headers().len()
                )
            }
            Message::BlockListRequest(msg) => {
                write!(
                    f,
                    "BlockListRequest(1st block id={:x}, count = {})",
                    msg.block_ids().first().as_displayable(),
                    msg.block_ids().len()
                )
            }
            Message::BlockResponse(msg) => {
                write!(f, "BlockResponse(id={})", msg.block().get_id())
            }
            Message::TransactionRequest(id) => write!(f, "TransactionRequest(id={id:x})"),
            Message::TransactionResponse(msg) => match msg {
                TransactionResponse::NotFound(id) => {
                    write!(f, "TransactionResponse-NotFound(id={id:x})")
                }
                TransactionResponse::Found(tx) => {
                    write!(
                        f,
                        "TransactionResponse-Found(id={})",
                        tx.transaction().get_id()
                    )
                }
            },
            Message::AnnounceAddrRequest(msg) => {
                write!(f, "AnnounceAddrRequest(addr={})", msg.address)
            }
            Message::AddrListRequest(_) => write!(f, "AddrListRequest"),
            Message::AddrListResponse(msg) => write!(
                f,
                "AddrListResponse(1st addr={}, count={})",
                msg.addresses.first().as_displayable(),
                msg.addresses.len()
            ),
            Message::WillDisconnect(msg) => write!(f, "WillDisconnect(reason='{}')", msg.reason),
            #[cfg(test)]
            Message::TestBlockSyncMsgSentinel(id) => {
                write!(f, "TestBlockSyncMsgSentinel(id={id:x})")
            }
        }
    }
}

/// Return true if the WillDisconnect message can be sent to a peer with the specified
/// protocol version.
pub fn can_send_will_disconnect(peer_protocol_version: ProtocolVersion) -> bool {
    peer_protocol_version >= SupportedProtocolVersion::V3.into()
}

/// Backend observer, used by tests.
pub trait BackendObserver {
    /// Called before the message is written to the socket.
    fn on_message_write(&self, peer_id: PeerId, msg: &Message);

    /// Called after the message has been read from the socket.
    fn on_message_read(&self, peer_id: PeerId, msg: &Message);
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use chainstate::Locator;
    use chainstate_test_framework::TestFramework;
    use common::{
        chain::config::MagicBytes,
        primitives::{semver::SemVer, Id},
    };
    use networking::test_helpers::{get_two_connected_sockets, TestTransportChannel};
    use networking::transport::{new_message_stream, MpscChannelTransport};
    use p2p_types::services::Service;
    use randomness::Rng;
    use test_utils::random::Seed;

    use crate::{
        message::{
            AddrListRequest, AddrListResponse, AnnounceAddrRequest, BlockListRequest,
            BlockResponse, HeaderList, HeaderListRequest, PingRequest, PingResponse,
            TransactionResponse,
        },
        net::default_backend::types::{HandshakeMessage, P2pTimestamp},
        protocol::ProtocolVersion,
        test_helpers::test_p2p_config,
    };

    use super::*;

    // Send and receive each variant of Message once and assert that its value hasn't changed.
    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn message_roundtrip(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let p2p_config = test_p2p_config();
        let mut tf = TestFramework::builder(&mut rng).build();
        let block = tf
            .make_block_builder()
            .add_test_transaction_from_best_block(&mut rng)
            .build(&mut rng);

        let messages = [
            Message::Handshake(HandshakeMessage::Hello {
                protocol_version: ProtocolVersion::new(rng.gen()),
                network: MagicBytes::new([rng.gen(), rng.gen(), rng.gen(), rng.gen()]),
                services: [Service::Blocks].as_slice().into(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: SemVer {
                    major: rng.gen(),
                    minor: rng.gen(),
                    patch: rng.gen(),
                },
                receiver_address: Some(
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())),
                        rng.gen(),
                    )
                    .into(),
                ),
                current_time: P2pTimestamp::from_int_seconds(rng.gen()),
                handshake_nonce: rng.gen(),
            }),
            Message::Handshake(HandshakeMessage::HelloAck {
                protocol_version: ProtocolVersion::new(rng.gen()),
                network: MagicBytes::new([rng.gen(), rng.gen(), rng.gen(), rng.gen()]),
                services: [Service::Blocks].as_slice().into(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: SemVer {
                    major: rng.gen(),
                    minor: rng.gen(),
                    patch: rng.gen(),
                },
                receiver_address: Some(
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())),
                        rng.gen(),
                    )
                    .into(),
                ),
                current_time: P2pTimestamp::from_int_seconds(rng.gen()),
            }),
            Message::PingRequest(PingRequest { nonce: rng.gen() }),
            Message::PingResponse(PingResponse { nonce: rng.gen() }),
            Message::NewTransaction(Id::new(rng.gen())),
            Message::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![
                Id::new(rng.gen()),
                Id::new(rng.gen()),
            ]))),
            Message::HeaderList(HeaderList::new(vec![block.header().clone()])),
            Message::BlockListRequest(BlockListRequest::new(vec![
                Id::new(rng.gen()),
                Id::new(rng.gen()),
            ])),
            Message::BlockResponse(BlockResponse::new(block.clone())),
            Message::TransactionRequest(Id::new(rng.gen())),
            Message::TransactionResponse(TransactionResponse::NotFound(Id::new(rng.gen()))),
            Message::TransactionResponse(TransactionResponse::Found(
                block.transactions()[0].clone(),
            )),
            Message::AnnounceAddrRequest(AnnounceAddrRequest {
                address: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())),
                    rng.gen(),
                )
                .into(),
            }),
            Message::AddrListRequest(AddrListRequest {}),
            Message::AddrListResponse(AddrListResponse {
                addresses: vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())),
                    rng.gen(),
                )
                .into()],
            }),
        ];

        let (socket1, socket2) =
            get_two_connected_sockets::<TestTransportChannel, MpscChannelTransport>().await;
        let (_, mut sender) =
            new_message_stream(socket1, Some(*p2p_config.protocol_config.max_message_size));
        let (mut receiver, _) = new_message_stream::<_, Message>(
            socket2,
            Some(*p2p_config.protocol_config.max_message_size),
        );

        for message in messages {
            sender.send(message.clone()).await.unwrap();
            let received_message = receiver.recv().await.unwrap();
            assert_eq!(received_message, message);
        }

        assert!(receiver.is_empty());
    }
}
