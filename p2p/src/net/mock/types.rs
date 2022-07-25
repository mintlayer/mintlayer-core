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
use crate::{message, net};
use crypto::random::{make_pseudo_rng, Rng};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::SocketAddr,
};
use tokio::{net::TcpStream, sync::oneshot};

pub enum Command {
    Connect {
        addr: SocketAddr,
        response: oneshot::Sender<crate::Result<TcpStream>>,
    },
}

pub enum ConnectivityEvent {
    IncomingConnection {
        peer_id: SocketAddr,
        socket: TcpStream,
    },
}

// TODO: use two events, one for txs and one for blocks?
pub enum PubSubEvent {
    /// Message received from one of the pubsub topics
    Announcement {
        peer_id: SocketAddr,
        topic: net::types::PubSubTopic,
        message: message::Announcement,
    },
}

pub enum SyncingEvent {}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct MockPeerId(u64);

impl MockPeerId {
    pub fn random() -> Self {
        let mut rng = make_pseudo_rng();
        Self(rng.gen::<u64>())
    }

    pub fn from_socket_address(addr: &SocketAddr) -> Self {
        let mut hasher = DefaultHasher::new();
        addr.hash(&mut hasher);
        Self(hasher.finish())
    }
}

impl std::fmt::Display for MockPeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(Debug)]
pub struct MockPeerInfo {
    pub peer_id: MockPeerId,
    pub net: common::chain::config::ChainType,
    pub version: common::primitives::semver::SemVer,
    pub agent: Option<String>,
    pub protocols: Vec<String>,
}

#[derive(Debug)]
pub enum PeerEvent {
    Dummy,
}
