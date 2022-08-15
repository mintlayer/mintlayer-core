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

//! Types and utils used by the `ConnectionManager`

use crate::{error::P2pError, net::libp2p::types::IdentifyInfoWrapper};
use libp2p::{identify, Multiaddr, PeerId};

#[derive(Debug, PartialEq, Eq)]
/// Events used to command the swarm
pub enum ControlEvent {
    /// Close the connection to peer
    CloseConnection { peer_id: PeerId },
}

#[derive(Debug, PartialEq, Eq)]
/// Events used to report swarm behaviour to front-end
pub enum BehaviourEvent {
    /// Inbound connection accepted
    InboundAccepted {
        address: Multiaddr,
        peer_info: IdentifyInfoWrapper,
    },

    /// Outbound connection accepted
    OutboundAccepted {
        address: Multiaddr,
        peer_info: IdentifyInfoWrapper,
    },

    /// Connection closed
    ConnectionClosed { peer_id: PeerId },

    /// Connection error
    ConnectionError { address: Multiaddr, error: P2pError },
}

#[derive(Debug, PartialEq, Eq)]
/// Events emitted by the `ConnectionManager`
pub enum ConnectionManagerEvent {
    Behaviour(BehaviourEvent),
    Control(ControlEvent),
}

/// State of a pending connection
pub enum ConnectionState {
    /// Outbound connection has been dialed, wait for `ConnectionEstablished` event
    Dialing,

    /// Connection established for outbound connection
    OutboundAccepted,

    /// Connection established for inbound connection
    InboundAccepted,

    /// Connection is active
    Active,

    /// Connection is in the process of getting closed
    Closing,
}

/// Entry for an established and active connections
pub struct Connection {
    /// Active address of the remote peer
    addr: Multiaddr,

    /// Connection state of the remote peer
    state: ConnectionState,

    /// `IdentifyInfo` of the remote peer
    peer_info: Option<identify::IdentifyInfo>,
}

impl Connection {
    pub fn new(
        addr: Multiaddr,
        state: ConnectionState,
        peer_info: Option<identify::IdentifyInfo>,
    ) -> Self {
        Self {
            addr,
            state,
            peer_info,
        }
    }

    /// Get active address of the connection
    pub fn addr(&self) -> &Multiaddr {
        &self.addr
    }

    /// Get connection state
    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    /// Get peer information
    pub fn peer_info(&self) -> &Option<identify::IdentifyInfo> {
        &self.peer_info
    }

    /// Set active address
    pub fn set_addr(&mut self, addr: Multiaddr) {
        self.addr = addr;
    }

    /// Set connection state
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    /// Set peer info
    pub fn set_peer_info(&mut self, peer_info: Option<identify::IdentifyInfo>) {
        self.peer_info = peer_info;
    }

    /// Is the connection still pending (either respose or `IdentifyInfo`)
    pub fn is_pending(&self) -> bool {
        std::matches!(
            self.state,
            ConnectionState::Dialing
                | ConnectionState::OutboundAccepted
                | ConnectionState::InboundAccepted
        )
    }

    /// Is an outbound connection pending
    pub fn is_outbound_pending(&self) -> bool {
        std::matches!(
            self.state,
            ConnectionState::Dialing | ConnectionState::OutboundAccepted
        )
    }

    /// Is the connection getting closed
    pub fn is_closing(&self) -> bool {
        std::matches!(self.state, ConnectionState::Closing)
    }
}
