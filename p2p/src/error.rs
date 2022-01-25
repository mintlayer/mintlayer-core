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
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    DifferentNetwork,
    InvalidVersion,
    InvalidMessage,
    Incompatible,
    Unresponsive,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Libp2pError {
    NoiseError(String),
    TransportError(String),
    DialError(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum P2pError {
    SocketError(std::io::ErrorKind),
    PeerDisconnected,
    DecodeFailure(String),
    ProtocolError(ProtocolError),
    TimeError(String),
    Libp2pError(Libp2pError),
    Unknown(String),
    ChannelClosed,
}

pub type Result<T> = core::result::Result<T, P2pError>;

impl From<std::io::Error> for P2pError {
    fn from(e: std::io::Error) -> P2pError {
        P2pError::SocketError(e.kind())
    }
}

impl From<parity_scale_codec::Error> for P2pError {
    fn from(e: parity_scale_codec::Error) -> P2pError {
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
        }
    }
}
