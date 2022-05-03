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
use common::chain::{
    block::{Block, BlockHeader},
    transaction::Transaction,
};
use serialization::{Decode, Encode};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use util::Handle;

#[derive(Debug)]
pub enum PeerSyncEvent<T>
where
    T: NetworkService,
{
    Dummy { peer_id: T::PeerId },
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
        response: oneshot::Sender<Vec<BlockHeader>>,
    },
    NewBlock {
        block: Block,
        response: oneshot::Sender<()>,
    },
    GetBlocks {
        headers: Vec<BlockHeader>,
        response: oneshot::Sender<Vec<Block>>,
    },
    GetHeaders {
        locator: Vec<BlockHeader>,
        response: oneshot::Sender<Vec<BlockHeader>>,
    },
    GetBestBlockHeader {
        response: oneshot::Sender<BlockHeader>,
    },
    GetUniqHeaders {
        headers: Vec<BlockHeader>,
        response: oneshot::Sender<Option<Vec<BlockHeader>>>,
    },
}
