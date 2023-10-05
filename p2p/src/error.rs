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

use std::time::Duration;

use p2p_types::services::Services;
use thiserror::Error;

use chainstate::{ban_score::BanScore, ChainstateError};
use common::{
    chain::{Block, Transaction},
    primitives::Id,
};
use mempool::error::{Error as MempoolError, MempoolBanScore};

use crate::protocol::ProtocolVersion;

/// Errors related to invalid data/peer information that results in connection getting closed
/// and the peer getting banned.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Peer has an unsupported network protocol: {0:?}")]
    UnsupportedProtocol(ProtocolVersion),
    #[error("Peer is in different network. Our network {0:?}, their network {1:?}")]
    DifferentNetwork([u8; 4], [u8; 4]),
    #[error("Peer is unresponsive")]
    Unresponsive,
    #[error("Locator size ({0}) exceeds allowed limit ({1})")]
    LocatorSizeExceeded(usize, usize),
    #[error("Requested {0} blocks with limit of {1}")]
    BlocksRequestLimitExceeded(usize, usize),
    #[error("Number of headers in message ({0}) exceeds allowed limit ({1})")]
    HeadersLimitExceeded(usize, usize),
    #[error("A peer requested an unknown block ({0})")]
    UnknownBlockRequested(Id<Block>),
    #[error("A peer tried to download same block ({0})")]
    DuplicatedBlockRequest(Id<Block>),
    #[error("Headers aren't connected")]
    DisconnectedHeaders,
    #[error("Received a message ({0}) that wasn't expected")]
    UnexpectedMessage(String),
    #[error("Empty block list requested")]
    ZeroBlocksInRequest,
    #[error("Handshake expected")]
    HandshakeExpected,
    #[error("More than MAX_ADDRESS_COUNT addresses sent")]
    AddressListLimitExceeded,
    #[error("A peer tried to announce the same transaction ({0})")]
    DuplicatedTransactionAnnouncement(Id<Transaction>),
    #[error("Announced too many transactions (limit is {0})")]
    TransactionAnnouncementLimitExceeded(usize),
}

/// Peer state errors (Errors either for an individual peer or for the [`PeerManager`](crate::peer_manager::PeerManager))
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PeerError {
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
    #[error("Time difference is too large: {0:?}")]
    TimeDiff(Duration),
    #[error("Selected services are empty")]
    EmptyServices,
    #[error(
        "Unexpected services, expected: {expected_services:?}, available: {available_services:?}"
    )]
    UnexpectedServices {
        expected_services: Services,
        available_services: Services,
    },
}

/// Errors related to establishing a connection with a remote peer
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DialError {
    #[error("Tried to dial self")]
    AttemptToDialSelf,
    #[error("Peer doesn't have any known addresses")]
    NoAddresses,
    #[error("Connection refused or timed out")]
    ConnectionRefusedOrTimedOut,
    #[error("I/O error: {0:?}")]
    IoError(std::io::ErrorKind),
    #[error("Proxy error: {0}")]
    ProxyError(String),
}

/// Conversion errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ConversionError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Failed to decode data: {0}")]
    DecodeError(serialization::Error),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum MessageCodecError {
    #[error("Message size {actual_size} exceeds the maximum size {max_size}")]
    MessageTooLarge { actual_size: usize, max_size: usize },
    #[error("Cannot decode data: {0}")]
    InvalidEncodedData(serialization::Error),
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum P2pError {
    #[error("Protocol violation: {0}")]
    ProtocolError(ProtocolError),
    #[error("Failed to dial peer: {0}")]
    DialError(DialError),
    #[error("Connection to other task lost")]
    ChannelClosed,
    #[error("Peer-related error: {0}")]
    PeerError(PeerError),
    #[error("SubsystemFailure")]
    SubsystemFailure,
    #[error("ConsensusError: {0}")]
    ChainstateError(ChainstateError),
    #[error("DatabaseFailure")]
    StorageFailure(#[from] storage::Error),
    #[error("Failed to convert data {0}")]
    ConversionError(ConversionError),
    #[error("Noise protocol handshake error")]
    NoiseHandshakeError(String),
    #[error("The configuration value is invalid: {0}")]
    InvalidConfigurationValue(String),
    #[error("The storage state is invalid: {0}")]
    InvalidStorageState(String),
    #[error("Mempool error: {0}")]
    MempoolError(#[from] MempoolError),
    #[error("Message codec error: {0}")]
    MessageCodecError(#[from] MessageCodecError),
}

impl From<DialError> for P2pError {
    fn from(e: DialError) -> P2pError {
        P2pError::DialError(e)
    }
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

impl From<subsystem::error::CallError> for P2pError {
    fn from(_e: subsystem::error::CallError) -> P2pError {
        P2pError::ChannelClosed
    }
}

impl From<ChainstateError> for P2pError {
    fn from(e: ChainstateError) -> P2pError {
        P2pError::ChainstateError(e)
    }
}

impl BanScore for P2pError {
    fn ban_score(&self) -> u32 {
        match self {
            P2pError::ProtocolError(err) => err.ban_score(),
            P2pError::DialError(_) => 0,
            P2pError::ChannelClosed => 0,
            P2pError::PeerError(_) => 0,
            P2pError::SubsystemFailure => 0,
            P2pError::ChainstateError(err) => err.ban_score(),
            P2pError::StorageFailure(_) => 0,
            P2pError::ConversionError(err) => err.ban_score(),
            // Could be a noise protocol violation but also a network error, do not ban peer
            P2pError::NoiseHandshakeError(_) => 0,
            P2pError::InvalidConfigurationValue(_) => 0,
            P2pError::InvalidStorageState(_) => 0,
            P2pError::MempoolError(err) => err.mempool_ban_score(),
            P2pError::MessageCodecError(_) => 0,
        }
    }
}

impl BanScore for ProtocolError {
    fn ban_score(&self) -> u32 {
        match self {
            ProtocolError::UnsupportedProtocol(_) => 0,
            ProtocolError::DifferentNetwork(_, _) => 0, // Do not ban peers if after deploying a new testnet
            ProtocolError::Unresponsive => 100,
            ProtocolError::LocatorSizeExceeded(_, _) => 20,
            ProtocolError::BlocksRequestLimitExceeded(_, _) => 20,
            ProtocolError::HeadersLimitExceeded(_, _) => 20,
            ProtocolError::UnknownBlockRequested(_) => 20,
            ProtocolError::DuplicatedBlockRequest(_) => 20,
            ProtocolError::DisconnectedHeaders => 20,
            ProtocolError::UnexpectedMessage(_) => 20,
            ProtocolError::ZeroBlocksInRequest => 20,
            ProtocolError::HandshakeExpected => 100,
            ProtocolError::AddressListLimitExceeded => 100,
            ProtocolError::DuplicatedTransactionAnnouncement(_) => 20,
            ProtocolError::TransactionAnnouncementLimitExceeded(_) => 20,
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
