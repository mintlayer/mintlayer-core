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

use std::fmt::Display;

use common::{chain::config::MagicBytes, primitives::time::Time};

use p2p_types::services::Services;

use crate::{
    error::{ConnectionValidationError, P2pError},
    protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectionReason {
    AddressBanned,
    AddressDiscouraged,
    PeerEvicted,
    FeelerConnection,
    ConnectionFromSelf,
    ManualDisconnect,
    PingIgnored,
    SyncRequestsIgnored,
    TooManyInboundPeersAndThisOneIsDiscouraged,
    TooManyInboundPeersAndCannotEvictAnyone,
    UnsupportedProtocol,
    TimeDiff {
        remote_time: Time,
        accepted_peer_time: std::ops::RangeInclusive<Time>,
    },
    DifferentNetwork {
        our_network: MagicBytes,
    },
    NoCommonServices,
    InsufficientServices {
        needed_services: Services,
    },
}

impl Display for DisconnectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DisconnectionReason::AddressBanned => write!(f, "Your address is banned"),
            DisconnectionReason::AddressDiscouraged => write!(f, "Your address is discouraged"),
            DisconnectionReason::PeerEvicted => write!(f, "You are evicted"),
            DisconnectionReason::FeelerConnection => write!(f, "This was a feeler connection"),
            DisconnectionReason::ConnectionFromSelf => {
                write!(f, "We think you are a self-connection")
            }
            DisconnectionReason::ManualDisconnect => write!(f, "Manual disconnection"),
            DisconnectionReason::PingIgnored => write!(f, "You ignore our ping requests"),
            DisconnectionReason::SyncRequestsIgnored => write!(f, "You ignore our sync requests"),

            DisconnectionReason::TooManyInboundPeersAndThisOneIsDiscouraged => {
                write!(
                    f,
                    "Too many inbound connections and your address is discouraged"
                )
            }
            DisconnectionReason::TooManyInboundPeersAndCannotEvictAnyone => {
                write!(f, "Too many inbound connections, which can't be evicted")
            }

            DisconnectionReason::UnsupportedProtocol => write!(
                f,
                "Unsupported protocol version, out min version is {}",
                *MIN_SUPPORTED_PROTOCOL_VERSION as u32
            ),

            DisconnectionReason::TimeDiff {
                remote_time,
                accepted_peer_time,
            } => write!(
                f,
                "Your time {:?} is out of the acceptable range {:?}",
                remote_time, accepted_peer_time
            ),
            DisconnectionReason::DifferentNetwork { our_network } => {
                write!(f, "Wrong network; out network is '{our_network}'")
            }
            DisconnectionReason::NoCommonServices => write!(f, "No common services"),
            DisconnectionReason::InsufficientServices { needed_services } => {
                write!(f, "Insufficient services, we need {needed_services:?}")
            }
        }
    }
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
            P2pError::ProtocolError(_)
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
            | P2pError::MessageCodecError(_) => None,
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
            },
        }
    }
}

// impl Display for DisconnectionReason {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{}", self.description)
//     }
// }
