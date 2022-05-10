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
        addr: SocketAddr,
        response: oneshot::Sender<error::Result<TcpStream>>,
    },
}

pub enum ConnectivityEvent {
    IncomingConnection {
        peer_id: SocketAddr,
        socket: TcpStream,
    },
}

// TODO: use two events, one for txs and one for blocks?
pub enum FloodsubEvent {
    /// Message received from one of the floodsub topics
    MessageReceived {
        peer_id: SocketAddr,
        topic: net::PubSubTopic,
        message: message::Message,
    },
}

pub enum SyncingEvent {}
