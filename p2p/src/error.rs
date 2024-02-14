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

use p2p_types::{services::Services, socket_address::SocketAddress, PeerId};
use thiserror::Error;

use chainstate::{ban_score::BanScore, ChainstateError};
use common::{
    chain::{Block, Transaction},
    primitives::{time::Time, Id},
};
use mempool::error::{Error as MempoolError, MempoolBanScore};
use utils::try_as::TryAsRef;

use crate::{net::types::PeerRole, peer_manager::peerdb_common, protocol::ProtocolVersion};

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
    #[error("Peer sent a message ({0}) that wasn't expected")]
    UnexpectedMessage(String),
    #[error("Peer sent a block ({0}) that wasn't requested")]
    UnsolicitedBlockReceived(Id<Block>),
    #[error("Peer sent block {expected_block_id} while it was expected to send {actual_block_id}")]
    BlocksReceivedInWrongOrder {
        expected_block_id: Id<Block>,
        actual_block_id: Id<Block>,
    },
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
    #[error("Peer {0} already exists")]
    PeerAlreadyExists(PeerId),
    #[error(
        "Rejecting {new_peer_role:?} connection to {new_peer_addr:?} \
             because we already have {existing_peer_role:?} connection to {existing_peer_addr:?}"
    )]
    AlreadyConnected {
        existing_peer_addr: SocketAddress,
        existing_peer_role: PeerRole,
        new_peer_addr: SocketAddress,
        new_peer_role: PeerRole,
    },
    #[error("Address {0} is banned")]
    BannedAddress(String),
    #[error("Address {0} is discouraged")]
    DiscouragedAddress(String),
    #[error("PeerManager has too many peers")]
    TooManyPeers,
    #[error("Connection to address {0} already pending")]
    Pending(String),
    #[error("Peer time {0:?} out of the acceptable range {1:?}")]
    TimeDiff(Time, std::ops::RangeInclusive<Time>),
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
    #[error("Noise protocol handshake error")]
    NoiseHandshakeError(String),
    #[error("The configuration value is invalid: {0}")]
    InvalidConfigurationValue(String),
    #[error("The storage state is invalid: {0}")]
    InvalidStorageState(String),
    #[error("Peer db storage version mismatch: expected {expected_version}, got {actual_version}")]
    PeerDbStorageVersionMismatch {
        expected_version: peerdb_common::StorageVersion,
        actual_version: peerdb_common::StorageVersion,
    },
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
            // Could be a noise protocol violation but also a network error, do not ban peer
            P2pError::NoiseHandshakeError(_) => 0,
            P2pError::InvalidConfigurationValue(_) => 0,
            P2pError::InvalidStorageState(_) => 0,
            P2pError::PeerDbStorageVersionMismatch {
                expected_version: _,
                actual_version: _,
            } => 0,
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
            ProtocolError::UnsolicitedBlockReceived(_) => 20,
            ProtocolError::BlocksReceivedInWrongOrder {
                expected_block_id: _,
                actual_block_id: _,
            } => 20,
            ProtocolError::ZeroBlocksInRequest => 20,
            ProtocolError::HandshakeExpected => 100,
            ProtocolError::AddressListLimitExceeded => 100,
            ProtocolError::DuplicatedTransactionAnnouncement(_) => 20,
            ProtocolError::TransactionAnnouncementLimitExceeded(_) => 20,
        }
    }
}

impl TryAsRef<storage::Error> for P2pError {
    fn try_as_ref(&self) -> Option<&storage::Error> {
        match self {
            P2pError::ProtocolError(_)
            | P2pError::DialError(_)
            | P2pError::ChannelClosed
            | P2pError::PeerError(_)
            | P2pError::SubsystemFailure
            | P2pError::ChainstateError(_)
            | P2pError::NoiseHandshakeError(_)
            | P2pError::InvalidConfigurationValue(_)
            | P2pError::InvalidStorageState(_)
            | P2pError::PeerDbStorageVersionMismatch {
                expected_version: _,
                actual_version: _,
            }
            | P2pError::MempoolError(_)
            | P2pError::MessageCodecError(_) => None,
            P2pError::StorageFailure(err) => Some(err),
        }
    }
}
