// Copyright (c) 2021-2022 RBB S.r.l
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

use std::sync::Arc;

use common::chain::SignedTransaction;

use crate::{
    error::{ConversionError, P2pError},
    interface::{p2p_interface::P2pInterface, types::ConnectedPeer},
    net::NetworkingService,
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    MessagingService, P2p, P2pEvent, PeerManagerEvent,
};

#[async_trait::async_trait]
impl<T> P2pInterface for P2p<T>
where
    T: NetworkingService,
    T::MessagingHandle: MessagingService,
{
    async fn connect(&mut self, addr: String) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();
        let addr = addr
            .parse::<T::Address>()
            .map_err(|_| P2pError::ConversionError(ConversionError::InvalidAddress(addr)))?;
        self.tx_peer_manager
            .send(PeerManagerEvent::Connect(addr, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await?
    }

    async fn disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();

        self.tx_peer_manager
            .send(PeerManagerEvent::Disconnect(peer_id, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await?
    }

    async fn get_peer_count(&self) -> crate::Result<usize> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager.send(PeerManagerEvent::GetPeerCount(tx))?;
        Ok(rx.await?)
    }

    async fn get_bind_addresses(&self) -> crate::Result<Vec<String>> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager.send(PeerManagerEvent::GetBindAddresses(tx))?;
        Ok(rx.await?)
    }

    async fn get_connected_peers(&self) -> crate::Result<Vec<ConnectedPeer>> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager.send(PeerManagerEvent::GetConnectedPeers(tx))?;
        Ok(rx.await?)
    }

    async fn add_reserved_node(&mut self, addr: String) -> crate::Result<()> {
        let addr = addr
            .parse::<T::Address>()
            .map_err(|_| P2pError::ConversionError(ConversionError::InvalidAddress(addr)))?;
        self.tx_peer_manager
            .send(PeerManagerEvent::AddReserved(addr))
            .map_err(|_| P2pError::ChannelClosed)?;
        Ok(())
    }

    async fn remove_reserved_node(&mut self, addr: String) -> crate::Result<()> {
        let addr = addr
            .parse::<T::Address>()
            .map_err(|_| P2pError::ConversionError(ConversionError::InvalidAddress(addr)))?;
        self.tx_peer_manager
            .send(PeerManagerEvent::RemoveReserved(addr))
            .map_err(|_| P2pError::ChannelClosed)?;
        Ok(())
    }

    async fn submit_transaction(
        &mut self,
        tx: SignedTransaction,
        origin: mempool::TxOrigin,
    ) -> crate::Result<mempool::TxStatus> {
        crate::sync::process_incoming_transaction(
            &self.mempool_handle,
            &mut self.messaging_handle,
            tx,
            origin,
        )
        .await
    }

    fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(P2pEvent) + Send + Sync>,
    ) -> crate::Result<()> {
        Ok(self.subscribers_sender.send(handler)?)
    }
}
