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
#![allow(unused)]

use crate::{message, net::NetworkService, sync};
use parity_scale_codec::{Decode, Encode};
use tokio::sync::{mpsc, oneshot};
use util::Handle;

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub enum PeerEvent<T>
where
    T: NetworkService,
{
    Swarm(PeerSwarmEvent<T>),
    Syncing(PeerSyncEvent<T>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeerSwarmEvent<T>
where
    T: NetworkService,
{
    /// Handshaking failed
    HandshakeFailed { peer_id: T::PeerId },

    /// Handshaking succeeded
    HandshakeSucceeded { peer_id: T::PeerId },

    /// Remote peer disconnected
    Disconnected { peer_id: T::PeerId },

    /// Inbound or outbound message
    Message {
        peer_id: T::PeerId,
        message: message::Message,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeerSyncEvent<T>
where
    T: NetworkService,
{
    GetHeaders {
        peer_id: Option<T::PeerId>,
        locator: Vec<sync::mock_consensus::BlockHeader>,
    },
    Headers {
        peer_id: Option<T::PeerId>,
        headers: Vec<sync::mock_consensus::BlockHeader>,
    },
    GetBlocks {
        peer_id: Option<T::PeerId>,
        headers: Vec<sync::mock_consensus::BlockHeader>,
    },
    Blocks {
        peer_id: Option<T::PeerId>,
        blocks: Vec<sync::mock_consensus::Block>,
    },
}

#[derive(Debug)]
pub enum SwarmControlEvent<T>
where
    T: NetworkService,
{
    Connect { addr: T::Address },
}

#[derive(Debug)]
pub enum SyncControlEvent<T>
where
    T: NetworkService,
{
    /// Peer connected
    Connected {
        /// Unique peer ID
        peer_id: T::PeerId,

        /// TX channel for sending syncing messages to peer
        tx: mpsc::Sender<PeerEvent<T>>,
    },

    /// Peer disconnected
    Disconnected {
        /// Unique peer ID
        peer_id: T::PeerId,
    },
}

#[derive(Debug, Handle)]
pub enum P2pEvent {
    GetLocator {
        response: oneshot::Sender<Vec<sync::mock_consensus::BlockHeader>>,
    },
    NewBlock {
        block: sync::mock_consensus::Block,
        response: oneshot::Sender<()>,
    },
    GetBlocks {
        headers: Vec<sync::mock_consensus::BlockHeader>,
        response: oneshot::Sender<Vec<sync::mock_consensus::Block>>,
    },
    GetHeaders {
        locator: Vec<sync::mock_consensus::BlockHeader>,
        response: oneshot::Sender<Vec<sync::mock_consensus::BlockHeader>>,
    },
    GetBestBlockHeader {
        response: oneshot::Sender<sync::mock_consensus::BlockHeader>,
    },
    GetUniqHeaders {
        headers: Vec<sync::mock_consensus::BlockHeader>,
        response: oneshot::Sender<Vec<sync::mock_consensus::BlockHeader>>,
    },
}
