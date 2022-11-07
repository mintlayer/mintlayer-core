// Copyright (c) 2021-2022 RBB S.r.l
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

use chainstate::ban_score::BanScore;
use common::primitives::semver::SemVer;
use libp2p::{
    gossipsub::error::{
        PublishError as GossipsubPublishError, SubscriptionError as GossipsubSubscriptionError,
    },
    swarm::{handler::ConnectionHandlerUpgrErr, DialError::*},
};
use thiserror::Error;

/// Errors related to invalid data/peer information that results in connection getting closed
/// and the peer getting banned.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Peer is in different network. Our network {0:?}, their network {1:?}")]
    DifferentNetwork([u8; 4], [u8; 4]),
    #[error("Peer has an unsupported version. Our version {0}, their version {1}")]
    InvalidVersion(SemVer, SemVer),
    #[error("Peer sent an invalid message")]
    InvalidMessage,
    #[error("Peer is incompatible")]
    Incompatible,
    #[error("Peer is unresponsive")]
    Unresponsive,
    #[error("Peer uses an invalid protocol")]
    InvalidProtocol,
    #[error("Peer state is invalid for this operation. State is {0} but should be {1}")]
    InvalidState(&'static str, &'static str),
    #[error("Unable to convert the address to a bannable form: {0}")]
    UnableToConvertAddressToBannable(String),
}

/// Peer state errors (Errors either for an individual peer or for the [`PeerManager`])
#[derive(Error, Debug, PartialEq, Eq)]
pub enum PeerError {
    #[error("Peer disconnected")]
    PeerDisconnected,
    #[error("No peers")]
    NoPeers,
    #[error("Peer doesn't exist")]
    PeerDoesntExist,
    #[error("Peer already exists")]
    PeerAlreadyExists,
    #[error("Address {0} is banned")]
    BannedAddress(String),
    #[error("Peer {0} is banned")]
    BannedPeer(String),
    #[error("PeerManager has too many peers")]
    TooManyPeers,
    #[error("Connection to address {0} already pending")]
    Pending(String),
}

/// PubSub errors for announcements
#[derive(Error, Debug, PartialEq, Eq)]
pub enum PublishError {
    #[error("Message has already been published")]
    Duplicate,
    #[error("Failed to sign message")]
    SigningFailed,
    #[error("No peers in topic")]
    InsufficientPeers,
    // TODO: The sizes are optional for now only because libp2p hides this information.
    #[error("Message is too large. Tried to send {0:?} bytes when limit is {1:?}")]
    MessageTooLarge(Option<usize>, Option<usize>),
    #[error("Failed to compress the message")]
    TransformFailed,
}

/// PubSub errors for subscriptions
#[derive(Error, Debug, PartialEq, Eq)]
pub enum SubscriptionError {
    #[error("Failed to publish subscription: {0}")]
    FailedToPublish(PublishError),
    #[error("Not allowed to subscribe to this topic")]
    NotAllowed,
}

/// Errors related to establishing a connection with a remote peer
#[derive(Error, Debug, PartialEq, Eq)]
pub enum DialError {
    #[error("Peer is banned")]
    Banned,
    #[error("Limit for outgoing connections reached: {0}")]
    ConnectionLimit(usize),
    #[error("Tried to dial self")]
    AttemptToDialSelf,
    #[error("Peer doesn't have any known addresses")]
    NoAddresses,
    #[error("Peer state not correct for dialing")]
    DialPeerConditionFalse,
    #[error("Connection has been aborted")]
    Aborted,
    #[error("Invalid PeerId")]
    InvalidPeerId,
    #[error("PeerId doesn't match the PeerId of endpoint")]
    WrongPeerId,
    #[error("Connection refused or timed out")]
    ConnectionRefusedOrTimedOut,
    #[error("I/O error: `{0:?}`")]
    IoError(std::io::ErrorKind),
    #[error("Failed to negotiate transport protocol")]
    Transport,
}

/// Low-level connection errors caused by libp2p
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ConnectionError {
    #[error("Timeout")]
    Timeout,
    #[error("Timer failed")]
    Timer,
    #[error("Failed to upgrade protocol")]
    Upgrade,
}

/// Conversion errors
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ConversionError {
    #[error("Invalid peer ID: `{0}`")]
    InvalidPeerId(String),
    #[error("Invalid address: `{0}`")]
    InvalidAddress(String),
    #[error("Failed to decode data: `{0}`")]
    DecodeError(serialization::Error),
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum P2pError {
    #[error("Protocol violation: `{0}`")]
    ProtocolError(ProtocolError),
    #[error("Failed to publish message: `{0}`")]
    PublishError(PublishError),
    #[error("Failed to subscribe to pubsub topic: `{0}`")]
    SubscriptionError(SubscriptionError),
    #[error("Failed to upgrade connection: `{0}`")]
    ConnectionError(ConnectionError),
    #[error("Failed to dial peer: `{0}`")]
    DialError(DialError),
    #[error("Connection to other task lost")]
    ChannelClosed,
    #[error("Peer-related error: `{0}`")]
    PeerError(PeerError),
    #[error("SubsystemFailure")]
    SubsystemFailure,
    #[error("ConsensusError: `{0}`")]
    ChainstateError(chainstate::ChainstateError),
    #[error("DatabaseFailure")]
    DatabaseFailure,
    #[error("Failed to convert data `{0}`")]
    ConversionError(ConversionError),
    #[error("Other: `{0}`")]
    Other(&'static str),
}

impl From<std::io::Error> for P2pError {
    fn from(e: std::io::Error) -> P2pError {
        P2pError::DialError(DialError::IoError(e.kind()))
    }
}

impl From<serialization::Error> for P2pError {
    fn from(err: serialization::Error) -> P2pError {
        P2pError::ConversionError(ConversionError::DecodeError(err))
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for P2pError {
    fn from(_: tokio::sync::oneshot::error::RecvError) -> P2pError {
        P2pError::ChannelClosed
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for P2pError {
    fn from(_: tokio::sync::mpsc::error::SendError<T>) -> P2pError {
        P2pError::ChannelClosed
    }
}

impl From<subsystem::subsystem::CallError> for P2pError {
    fn from(_e: subsystem::subsystem::CallError) -> P2pError {
        P2pError::ChannelClosed
    }
}

impl From<chainstate::ChainstateError> for P2pError {
    fn from(e: chainstate::ChainstateError) -> P2pError {
        P2pError::ChainstateError(e)
    }
}

impl From<libp2p::gossipsub::error::PublishError> for PublishError {
    fn from(err: libp2p::gossipsub::error::PublishError) -> PublishError {
        match err {
            GossipsubPublishError::Duplicate => PublishError::Duplicate,
            GossipsubPublishError::SigningError(_) => PublishError::SigningFailed,
            GossipsubPublishError::InsufficientPeers => PublishError::InsufficientPeers,
            GossipsubPublishError::MessageTooLarge => PublishError::MessageTooLarge(None, None),
            GossipsubPublishError::TransformFailed(_) => PublishError::TransformFailed,
        }
    }
}

impl From<libp2p::gossipsub::error::PublishError> for P2pError {
    fn from(err: libp2p::gossipsub::error::PublishError) -> P2pError {
        P2pError::PublishError(PublishError::from(err))
    }
}

impl From<libp2p::gossipsub::error::SubscriptionError> for P2pError {
    fn from(err: libp2p::gossipsub::error::SubscriptionError) -> P2pError {
        match err {
            GossipsubSubscriptionError::PublishError(error) => P2pError::SubscriptionError(
                SubscriptionError::FailedToPublish(PublishError::from(error)),
            ),
            GossipsubSubscriptionError::NotAllowed => {
                P2pError::SubscriptionError(SubscriptionError::NotAllowed)
            }
        }
    }
}

impl From<libp2p::swarm::DialError> for P2pError {
    fn from(err: libp2p::swarm::DialError) -> P2pError {
        match err {
            Banned => P2pError::DialError(DialError::Banned),
            ConnectionLimit(limit) => {
                P2pError::DialError(DialError::ConnectionLimit(limit.limit as usize))
            }
            LocalPeerId => P2pError::DialError(DialError::AttemptToDialSelf),
            NoAddresses => P2pError::DialError(DialError::NoAddresses),
            DialPeerConditionFalse(_) => P2pError::DialError(DialError::DialPeerConditionFalse),
            Aborted => P2pError::DialError(DialError::Aborted),
            InvalidPeerId(_) => P2pError::DialError(DialError::InvalidPeerId),
            WrongPeerId { .. } => P2pError::DialError(DialError::WrongPeerId),
            ConnectionIo(error) => P2pError::DialError(DialError::IoError(error.kind())),
            Transport(_) => P2pError::DialError(DialError::Transport),
        }
    }
}

impl<T> From<libp2p::swarm::handler::ConnectionHandlerUpgrErr<T>> for P2pError {
    fn from(err: libp2p::swarm::handler::ConnectionHandlerUpgrErr<T>) -> P2pError {
        match err {
            ConnectionHandlerUpgrErr::Timeout => {
                P2pError::ConnectionError(ConnectionError::Timeout)
            }
            ConnectionHandlerUpgrErr::Timer => P2pError::ConnectionError(ConnectionError::Timer),
            ConnectionHandlerUpgrErr::Upgrade(_) => {
                P2pError::ConnectionError(ConnectionError::Upgrade)
            }
        }
    }
}

impl BanScore for P2pError {
    fn ban_score(&self) -> u32 {
        match self {
            P2pError::ProtocolError(err) => err.ban_score(),
            P2pError::PublishError(err) => err.ban_score(),
            P2pError::SubscriptionError(err) => err.ban_score(),
            P2pError::ConnectionError(_) => 0,
            P2pError::DialError(_) => 0,
            P2pError::ChannelClosed => 0,
            P2pError::PeerError(_) => 0,
            P2pError::SubsystemFailure => 0,
            P2pError::ChainstateError(_) => 0,
            P2pError::DatabaseFailure => 0,
            P2pError::ConversionError(err) => err.ban_score(),
            P2pError::Other(_) => 0,
        }
    }
}

impl BanScore for ProtocolError {
    fn ban_score(&self) -> u32 {
        match self {
            ProtocolError::DifferentNetwork(_, _) => 100,
            ProtocolError::InvalidVersion(_, _) => 100,
            ProtocolError::InvalidMessage => 100,
            ProtocolError::Incompatible => 100,
            ProtocolError::Unresponsive => 100,
            ProtocolError::InvalidProtocol => 100,
            ProtocolError::InvalidState(_, _) => 100,
            ProtocolError::UnableToConvertAddressToBannable(_) => 100,
        }
    }
}

impl BanScore for PublishError {
    fn ban_score(&self) -> u32 {
        match self {
            PublishError::Duplicate => 0,
            PublishError::SigningFailed => 0,
            PublishError::InsufficientPeers => 0,
            PublishError::MessageTooLarge(_, _) => 100,
            PublishError::TransformFailed => 0,
        }
    }
}

impl BanScore for SubscriptionError {
    fn ban_score(&self) -> u32 {
        match self {
            SubscriptionError::FailedToPublish(err) => err.ban_score(),
            SubscriptionError::NotAllowed => 0,
        }
    }
}

impl BanScore for ConversionError {
    fn ban_score(&self) -> u32 {
        match self {
            ConversionError::InvalidPeerId(_) => 0,
            ConversionError::InvalidAddress(_) => 0,
            ConversionError::DecodeError(_) => 100,
        }
    }
}
