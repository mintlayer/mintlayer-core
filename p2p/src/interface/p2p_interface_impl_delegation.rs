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

use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use common::chain::SignedTransaction;

use crate::{types::peer_id::PeerId, P2pEvent};

use super::{p2p_interface::P2pInterface, types::ConnectedPeer};

#[async_trait::async_trait]
impl<T: Deref<Target = dyn P2pInterface> + DerefMut<Target = dyn P2pInterface> + Send + Sync>
    P2pInterface for T
{
    async fn connect(&mut self, addr: String) -> crate::Result<()> {
        self.deref_mut().connect(addr).await
    }

    async fn disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        self.deref_mut().disconnect(peer_id).await
    }

    async fn get_peer_count(&self) -> crate::Result<usize> {
        self.deref().get_peer_count().await
    }

    async fn get_bind_addresses(&self) -> crate::Result<Vec<String>> {
        self.deref().get_bind_addresses().await
    }

    async fn get_connected_peers(&self) -> crate::Result<Vec<ConnectedPeer>> {
        self.deref().get_connected_peers().await
    }

    async fn add_reserved_node(&mut self, addr: String) -> crate::Result<()> {
        self.deref_mut().add_reserved_node(addr).await
    }

    async fn remove_reserved_node(&mut self, addr: String) -> crate::Result<()> {
        self.deref_mut().remove_reserved_node(addr).await
    }

    async fn submit_transaction(
        &mut self,
        tx: SignedTransaction,
        origin: mempool::TxOrigin,
    ) -> crate::Result<mempool::TxStatus> {
        self.deref_mut().submit_transaction(tx, origin).await
    }

    fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(P2pEvent) + Send + Sync>,
    ) -> crate::Result<()> {
        self.deref_mut().subscribe_to_events(handler)
    }
}
