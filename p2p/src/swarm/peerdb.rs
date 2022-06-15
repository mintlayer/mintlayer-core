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

//! Peer database
//!
//! TODO

use crate::net::{types, NetworkingService};

pub struct PeerDb<T: NetworkingService> {
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T: NetworkingService> PeerDb<T> {
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }

    /// Verify is the peer ID banned
    pub fn is_id_banned(&self, _peer_id: &T::PeerId) -> bool {
        false // TODO: implement
    }

    /// Verify is the address banned
    pub fn is_address_banned(&self, _address: &T::Address) -> bool {
        false // TODO: implement
    }

    pub fn _discover_peers(&mut self, _peers: &[types::AddrInfo<T>]) {}

    pub fn _expire_peers(&mut self, _peers: &[types::AddrInfo<T>]) {}
}
