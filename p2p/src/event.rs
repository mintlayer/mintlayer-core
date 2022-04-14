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
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use util::Handle;

// TODO: unify naming of events
// TODO: make return value channel option with an attribute
// TODO: remove peerswarmevent and replace it with swarmevent that controls the connected peer!

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub enum PeerEvent<T>
where
    T: NetworkService,
{
    Swarm(PeerSwarmEvent<T>),
    Syncing(SyncEvent),
}

/// Swarm-related messages received from one of the connected peers
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

/// Syncing-related event received from one of the connected peers
#[derive(Debug, PartialEq, Eq)]
pub enum PeerSyncEvent<T>
where
    T: NetworkService,
{
    /// Peer requested headers
    GetHeaders {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        /// Set of headers that are used to find common ancestor between chains
        locator: Vec<sync::mock_consensus::BlockHeader>,
    },

    /// Peer with unique ID `peer_id` responded to header request
    Headers {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        /// Headers that were requested
        headers: Vec<sync::mock_consensus::BlockHeader>,
    },

    /// Peer with unique ID `peer_id` requested blocks
    GetBlocks {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        /// Headers of those blocks that are requested
        headers: Vec<sync::mock_consensus::BlockHeader>,
    },

    /// Peer with unique ID `peer_id` responded to block request
    Blocks {
        /// Unique ID of the peer
        peer_id: T::PeerId,

        /// Blocks that were requested
        blocks: Vec<Arc<sync::mock_consensus::Block>>,
    },
}

/// Syncing-related event sent to a connected peer
#[derive(Debug, PartialEq, Eq, Encode, Decode)]
pub enum SyncEvent {
    /// Send header request to peer
    GetHeaders {
        /// Set of headers that are used to find common ancestor between chains
        locator: Vec<sync::mock_consensus::BlockHeader>,
    },

    /// Response to header request
    Headers {
        /// Headers that were requested
        headers: Vec<sync::mock_consensus::BlockHeader>,
    },

    /// Block request
    GetBlocks {
        /// Headers of those blocks that are requested
        headers: Vec<sync::mock_consensus::BlockHeader>,
    },

    /// Response to block request
    Blocks {
        /// Blocks that were requested
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
        response: oneshot::Sender<Option<Vec<sync::mock_consensus::BlockHeader>>>,
    },
}

pub enum BlockFloodEvent {
    Block(Arc<sync::mock_consensus::Block>),
}
