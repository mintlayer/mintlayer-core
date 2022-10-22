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

use std::ops::{Deref, DerefMut};

use super::p2p_interface::P2pInterface;

impl<T: Deref<Target = dyn P2pInterface> + DerefMut<Target = dyn P2pInterface> + Send> P2pInterface
    for T
{
    fn connect(&mut self, addr: String) -> crate::Result<()> {
        self.deref_mut().connect(addr)
    }

    fn disconnect(&self, peer_id: String) -> crate::Result<()> {
        self.deref().disconnect(peer_id)
    }

    fn get_peer_count(&self) -> crate::Result<usize> {
        self.deref().get_peer_count()
    }

    fn get_bind_address(&self) -> crate::Result<String> {
        self.deref().get_bind_address()
    }

    fn get_peer_id(&self) -> crate::Result<String> {
        self.deref().get_peer_id()
    }

    fn get_connected_peers(&self) -> crate::Result<Vec<String>> {
        self.deref().get_connected_peers()
    }
}
