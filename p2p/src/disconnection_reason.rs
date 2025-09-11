// Copyright (c) 2021-2024 RBB S.r.l
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

use common::{chain::config::MagicBytes, primitives::time::Time};

use p2p_types::services::Services;
use thiserror::Error;

use crate::{
    error::{ConnectionValidationError, P2pError},
    protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
};

/// The reason why a peer is being disconnected. This will be converted to string and sent
/// to the peer in a WillDisconnect message.
///
/// Note: we derive `thiserror::Error` here just for the convenience of implementing `Display`.
/// But conceptually this enum is not an error and it's not supposed to be used with `Result`.
// TODO: use `derive_more::Display` instead of `thiserror::Error`.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DisconnectionReason {
    #[error("Your address is banned")]
    AddressBanned,
    #[error("Your address is discouraged")]
    AddressDiscouraged,
    #[error("You are evicted")]
    PeerEvicted,
    #[error("This was a feeler connection")]
    FeelerConnection,
    #[error("We think you are a self-connection")]
    ConnectionFromSelf,
    #[error("Manual disconnection")]
    ManualDisconnect,
    #[error("You ignore our ping requests")]
    PingIgnored,
    #[error("You ignore our sync requests")]
    SyncRequestsIgnored,
    #[error("Too many inbound connections and your address is discouraged")]
    TooManyInboundPeersAndThisOneIsDiscouraged,
    #[error("Too many inbound connections, which can't be evicted")]
    TooManyInboundPeersAndCannotEvictAnyone,
    #[error("Unsupported protocol version, our min version is {}", *MIN_SUPPORTED_PROTOCOL_VERSION as u32)]
    UnsupportedProtocol,
    #[error("Your time {remote_time:?} is out of the acceptable range {accepted_peer_time:?}")]
    TimeDiff {
        remote_time: Time,
        accepted_peer_time: std::ops::RangeInclusive<Time>,
    },
    #[error("Wrong network; our network is '{our_network}'")]
    DifferentNetwork { our_network: MagicBytes },
    #[error("No common services")]
    NoCommonServices,
    #[error("Insufficient services, we need {needed_services:?}")]
    InsufficientServices { needed_services: Services },
    #[error("Networking disabled")]
    NetworkingDisabled,
}

impl DisconnectionReason {
    pub fn from_result<T>(res: &crate::Result<T>) -> Option<Self> {
        match res {
            Ok(_) => None,
            Err(err) => Self::from_error(err),
        }
    }

    pub fn from_error(err: &P2pError) -> Option<Self> {
        match err {
            P2pError::NetworkingError(_)
            | P2pError::ProtocolError(_)
            | P2pError::DialError(_)
            | P2pError::ChannelClosed
            | P2pError::PeerError(_)
            | P2pError::SubsystemFailure
            | P2pError::ChainstateError(_)
            | P2pError::StorageFailure(_)
            | P2pError::NoiseHandshakeError(_)
            | P2pError::InvalidConfigurationValue(_)
            | P2pError::InvalidStorageState(_)
            | P2pError::PeerDbStorageVersionMismatch { .. }
            | P2pError::MempoolError(_)
            | P2pError::SyncError(_) => None,
            P2pError::ConnectionValidationFailed(err) => match err {
                ConnectionValidationError::UnsupportedProtocol {
                    peer_protocol_version: _,
                } => Some(Self::UnsupportedProtocol),
                ConnectionValidationError::TimeDiff {
                    remote_time,
                    accepted_peer_time,
                } => Some(Self::TimeDiff {
                    remote_time: *remote_time,
                    accepted_peer_time: accepted_peer_time.clone(),
                }),
                ConnectionValidationError::DifferentNetwork {
                    our_network,
                    their_network: _,
                } => Some(Self::DifferentNetwork {
                    our_network: *our_network,
                }),
                ConnectionValidationError::TooManyInboundPeersAndThisOneIsDiscouraged => {
                    Some(Self::TooManyInboundPeersAndThisOneIsDiscouraged)
                }
                ConnectionValidationError::TooManyInboundPeersAndCannotEvictAnyone => {
                    Some(Self::TooManyInboundPeersAndCannotEvictAnyone)
                }
                ConnectionValidationError::AddressBanned { address: _ } => {
                    Some(Self::AddressBanned)
                }
                ConnectionValidationError::AddressDiscouraged { address: _ } => {
                    Some(Self::AddressDiscouraged)
                }
                ConnectionValidationError::NoCommonServices => Some(Self::NoCommonServices),
                ConnectionValidationError::InsufficientServices {
                    needed_services,
                    available_services: _,
                } => Some(Self::InsufficientServices {
                    needed_services: *needed_services,
                }),
                ConnectionValidationError::NetworkingDisabled => Some(Self::NetworkingDisabled),
            },
        }
    }
}
