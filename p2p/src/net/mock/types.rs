// Copyright (c) 2022 RBB S.r.l
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
use crate::{error, message, net};
use std::net::SocketAddr;
use tokio::{net::TcpStream, sync::oneshot};

pub enum Command {
    Connect {
        /// Remote address
        addr: SocketAddr,

        /// Channel for returning the result
        response: oneshot::Sender<error::Result<(SocketAddr, TcpStream)>>,
    },

    /// Publish a message on a floodsub topic
    SendMessage {
        /// Floodsub topic where the message should be published
        topic: net::FloodsubTopic,

        /// Encoded message
        message: Vec<u8>,

        /// Channel for returning the status of the operation
        response: oneshot::Sender<error::Result<()>>,
    },

    /// Register peer to the networking backend
    RegisterPeer {
        /// Unique ID of the peer
        peer: SocketAddr,

        /// Channel for returning the status of the operation
        response: oneshot::Sender<error::Result<()>>,
    },

    /// Unregister peer from the networking backend
    UnregisterPeer {
        /// Unique ID of the peer
        peer: SocketAddr,

        /// Channel for returning the status of the operation
        response: oneshot::Sender<error::Result<()>>,
    },
}

pub enum FloodsubCommand {
    /// Peer connected
    PeerConnected {
        /// Unique ID of the peer
        peer: SocketAddr,

        /// Floodsub socket of the peer
        socket: net::mock::MockSocket,

        /// Floodsub topics the peer listens to
        topics: Vec<net::FloodsubTopic>,
    },

    /// Peer disconnected
    PeerDisconnected {
        /// Unique ID of the peer
        peer: SocketAddr,
    },

    /// Publish a message on a floodsub topic
    SendMessage {
        /// Floodsub topic where the message should be published
        topic: net::FloodsubTopic,

        /// Encoded message
        message: Vec<u8>,

        /// Channel for returning the status of the operation
        response: oneshot::Sender<error::Result<()>>,
    },
}

pub enum ConnectivityEvent {
    IncomingConnection {
        peer_id: SocketAddr,
        socket: TcpStream,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum FloodsubEvent {
    /// Message received from one of the floodsub topics
    MessageReceived {
        /// Unique peer ID of the sender
        peer_id: SocketAddr,

        /// Topic where the message was received from
        topic: net::FloodsubTopic,

        /// Actual data that was received
        message: Vec<u8>,
    },
}
