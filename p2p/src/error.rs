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
use thiserror::Error;

/// Errors related to invalid data/peer information that results in connection getting closed
/// and the peer getting banned.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Peer is in different network. Our network {0:?}, their network {1:?}")]
    DifferentNetwork([u8; 4], [u8; 4]),
    #[error("Peer has an unsupported version. Our version {0}, their version {1}")]
    InvalidVersion(SemVer, SemVer),
    // TODO: This error is very generic and probably should be replaced with several different ones,
    // because it has a ban score of 100 and in many cases it is too harsh.
    #[error("Peer sent an invalid message")]
    InvalidMessage,
    #[error("Peer is unresponsive")]
    Unresponsive,
    #[error("Locator size ({0}) exceeds allowed limit ({1})")]
    LocatorSizeExceeded(usize, usize),
    #[error("Requested {0} blocks with limit of {1}")]
    BlocksRequestLimitExceeded(usize, usize),
    #[error("Number of headers in message ({0}) exceeds allowed limit ({1})")]
    HeadersLimitExceeded(usize, usize),
    #[error("A peer requested an unknown block")]
    UnknownBlockRequested,
    #[error("Headers aren't connected")]
    DisconnectedHeaders,
    #[error("Received a message ({0}) that wasn't expected")]
    UnexpectedMessage(&'static str),
    #[error("Unknown request identifier")]
    UnknownRequestId,
}

/// Peer state errors (Errors either for an individual peer or for the [`PeerManager`](crate::peer_manager::PeerManager))
#[derive(Error, Debug, PartialEq, Eq)]
pub enum PeerError {
    #[error("Peer disconnected")]
    PeerDisconnected,
    #[error("Peer doesn't exist")]
    PeerDoesntExist,
    #[error("Peer already exists")]
    PeerAlreadyExists,
    #[error("Address {0} is banned")]
    BannedAddress(String),
    #[error("PeerManager has too many peers")]
    TooManyPeers,
    #[error("Connection to address {0} already pending")]
    Pending(String),
}

/// PubSub errors for announcements
#[derive(Error, Debug, PartialEq, Eq)]
pub enum PublishError {
    #[error("Message is too large. Tried to send {0:?} bytes when limit is {1:?}")]
    MessageTooLarge(usize, usize),
}

/// Errors related to establishing a connection with a remote peer
#[derive(Error, Debug, PartialEq, Eq)]
pub enum DialError {
    #[error("Tried to dial self")]
    AttemptToDialSelf,
    #[error("Peer doesn't have any known addresses")]
    NoAddresses,
    #[error("Connection refused or timed out")]
    ConnectionRefusedOrTimedOut,
    #[error("I/O error: `{0:?}`")]
    IoError(std::io::ErrorKind),
}

/// Conversion errors
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ConversionError {
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
    StorageFailure(#[from] storage::Error),
    #[error("Failed to convert data `{0}`")]
    ConversionError(ConversionError),
    #[error("Noise protocol handshake error")]
    NoiseHandshakeError(String),
    #[error("The configuration value is invalid: {0}")]
    InvalidConfigurationValue(String),
    #[error("The storage state is invalid: {0}")]
    InvalidStorageState(String),
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

impl BanScore for P2pError {
    fn ban_score(&self) -> u32 {
        match self {
            P2pError::ProtocolError(err) => err.ban_score(),
            P2pError::PublishError(err) => err.ban_score(),
            P2pError::DialError(_) => 0,
            P2pError::ChannelClosed => 0,
            P2pError::PeerError(_) => 0,
            P2pError::SubsystemFailure => 0,
            P2pError::ChainstateError(_) => 20,
            P2pError::StorageFailure(_) => 0,
            P2pError::ConversionError(err) => err.ban_score(),
            // Could be a noise protocol violation but also a network error, do not ban peer
            P2pError::NoiseHandshakeError(_) => 0,
            P2pError::InvalidConfigurationValue(_) => 0,
            P2pError::InvalidStorageState(_) => 0,
        }
    }
}

impl BanScore for ProtocolError {
    fn ban_score(&self) -> u32 {
        match self {
            ProtocolError::DifferentNetwork(_, _) => 100,
            ProtocolError::InvalidVersion(_, _) => 100,
            ProtocolError::InvalidMessage => 100,
            ProtocolError::Unresponsive => 100,
            ProtocolError::LocatorSizeExceeded(_, _) => 20,
            ProtocolError::BlocksRequestLimitExceeded(_, _) => 20,
            ProtocolError::HeadersLimitExceeded(_, _) => 20,
            ProtocolError::UnknownBlockRequested => 20,
            ProtocolError::DisconnectedHeaders => 20,
            ProtocolError::UnexpectedMessage(_) => 20,
            ProtocolError::UnknownRequestId => 20,
        }
    }
}

impl BanScore for PublishError {
    fn ban_score(&self) -> u32 {
        match self {
            PublishError::MessageTooLarge(_, _) => 100,
        }
    }
}

impl BanScore for ConversionError {
    fn ban_score(&self) -> u32 {
        match self {
            ConversionError::InvalidAddress(_) => 0,
            ConversionError::DecodeError(_) => 100,
        }
    }
}
