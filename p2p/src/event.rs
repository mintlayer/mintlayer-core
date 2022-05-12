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

use crate::{message, net::NetworkService};
use common::chain::block::Block;
use serialization::{Decode, Encode};

#[derive(Debug)]
pub enum SwarmEvent<T: NetworkService> {
    /// Try to establish connection with a remote peer
    Connect(T::Address),
}

#[derive(Debug)]
pub enum SyncEvent {
    /// Publish a block to the network
    PublishBlock(Block),
}

#[derive(Debug)]
pub enum SyncControlEvent<T>
where
    T: NetworkService,
{
    /// Peer connected
    Connected(T::PeerId),

    /// Peer disconnected
    Disconnected(T::PeerId),
}
