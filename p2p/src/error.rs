// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use thiserror::Error;

// TODO: think about which errors should be returned and when
// TODO: store peerid where appropriate!
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    DifferentNetwork,
    InvalidVersion,
    InvalidMessage,
    Incompatible,
    Unresponsive,
    InvalidProtocol,
    UnknownNetwork,
    InvalidState,
}

// TODO: refactor error code
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Libp2pError {
    #[error("NoiseError: `{0:?}`")]
    NoiseError(String),
    #[error("TransportError: `{0:?}`")]
    TransportError(String),
    #[error("DialError: `{0:?}`")]
    DialError(String),
    #[error("SubscriptionError: `{0:?}`")]
    SubscriptionError(String),
    #[error("PublishError: `{0:?}`")]
    PublishError(String),
    #[error("IdentifyError: `{0:?}`")]
    IdentifyError(String),
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum P2pError {
    #[error("SocketError: `{0:?}`")]
    SocketError(std::io::ErrorKind),
    #[error("PeerDisconnected")]
    PeerDisconnected,
    #[error("DecodeFailure: `{0:?}`")]
    DecodeFailure(String),
    #[error("ProtocolError: `{0:?}`")]
    ProtocolError(ProtocolError),
    #[error("TimeError: `{0:?}`")]
    TimeError(String),
    #[error("Libp2pError: `{0:?}`")]
    Libp2pError(Libp2pError),
    #[error("Unknown: `{0:?}`")]
    Unknown(String),
    #[error("ChannelClosed")]
    ChannelClosed,
    #[error("NoPeers")]
    NoPeers,
    #[error("PeerDoesntExist")]
    PeerDoesntExist,
    #[error("InvalidAddress")]
    InvalidAddress,
    #[error("InvalidData")]
    InvalidData,
    #[error("PeerExists")]
    PeerExists,
    #[error("SubsystemFailure")]
    SubsystemFailure,
    #[error("ConsensusError: `{0:?}`")]
    ConsensusError(chainstate::ConsensusError),
    #[error("DatabaseFailure")]
    DatabaseFailure,
    #[error("InvalidPeerId")]
    InvalidPeerId,
}

// TODO: move this to src/lib.rs
pub type Result<T> = core::result::Result<T, P2pError>;

pub trait FatalError {
    fn map_fatal_err(self) -> core::result::Result<(), P2pError>;
}

impl From<std::io::Error> for P2pError {
    fn from(e: std::io::Error) -> P2pError {
        P2pError::SocketError(e.kind())
    }
}

impl From<serialization::Error> for P2pError {
    fn from(e: serialization::Error) -> P2pError {
        P2pError::DecodeFailure(e.to_string())
    }
}

impl From<std::time::SystemTimeError> for P2pError {
    fn from(e: std::time::SystemTimeError) -> P2pError {
        P2pError::TimeError(e.to_string())
    }
}

impl From<libp2p::noise::NoiseError> for P2pError {
    fn from(e: libp2p::noise::NoiseError) -> P2pError {
        P2pError::Libp2pError(Libp2pError::NoiseError(e.to_string()))
    }
}

impl<T> From<libp2p::TransportError<T>> for P2pError {
    fn from(e: libp2p::TransportError<T>) -> P2pError {
        let e = match e {
            libp2p::TransportError::MultiaddrNotSupported(addr) => {
                format!("Multiaddr {} not supported", addr)
            }
            _ => "Unknown transport error".to_string(),
        };

        P2pError::Libp2pError(Libp2pError::TransportError(e))
    }
}

impl From<libp2p::swarm::DialError> for P2pError {
    fn from(e: libp2p::swarm::DialError) -> P2pError {
        P2pError::Libp2pError(Libp2pError::DialError(e.to_string()))
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

impl From<&str> for P2pError {
    fn from(e: &str) -> P2pError {
        P2pError::Unknown(e.to_owned())
    }
}

impl From<libp2p::gossipsub::error::SubscriptionError> for P2pError {
    fn from(e: libp2p::gossipsub::error::SubscriptionError) -> P2pError {
        P2pError::Libp2pError(Libp2pError::SubscriptionError(e.to_string()))
    }
}

impl From<libp2p::gossipsub::error::PublishError> for P2pError {
    fn from(e: libp2p::gossipsub::error::PublishError) -> P2pError {
        P2pError::Libp2pError(Libp2pError::PublishError(e.to_string()))
    }
}

impl From<subsystem::subsystem::CallError> for P2pError {
    fn from(e: subsystem::subsystem::CallError) -> P2pError {
        P2pError::ChannelClosed
    }
}

impl From<chainstate::ConsensusError> for P2pError {
    fn from(e: chainstate::ConsensusError) -> P2pError {
        P2pError::ConsensusError(e)
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ProtocolError::DifferentNetwork => {
                write!(f, "Remote peer is in different network")
            }
            ProtocolError::InvalidVersion => {
                write!(f, "Remote peer has an incompatible version")
            }
            ProtocolError::InvalidMessage => {
                write!(f, "Invalid protocol message")
            }
            ProtocolError::Incompatible => {
                write!(f, "Remote deemed us incompatible, connection closed")
            }
            ProtocolError::Unresponsive => {
                write!(f, "No response from remote peer")
            }
            ProtocolError::InvalidProtocol => {
                write!(f, "Invalid protocol string")
            }
            ProtocolError::UnknownNetwork => {
                write!(f, "Unknown network")
            }
            ProtocolError::InvalidState => {
                write!(f, "Invalid state")
            }
        }
    }
}

// impl std::fmt::Display for ProtocolError {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
