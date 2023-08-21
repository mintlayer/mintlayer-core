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
use mempool::tx_origin::LocalTxOrigin;
use p2p_types::{
    bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress,
    socket_address::SocketAddress,
};

use crate::{
    error::P2pError,
    interface::{p2p_interface::P2pInterface, types::ConnectedPeer},
    net::NetworkingService,
    peer_manager_event::PeerDisconnectionDbAction,
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    MessagingService, P2p, P2pEvent, PeerManagerEvent,
};

#[async_trait::async_trait]
impl<T> P2pInterface for P2p<T>
where
    T: NetworkingService + Send + Sync,
    T::MessagingHandle: MessagingService,
{
    async fn connect(&mut self, addr: IpOrSocketAddress) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::Connect(addr, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await?
    }

    async fn disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::Disconnect(
                peer_id,
                PeerDisconnectionDbAction::RemoveIfOutbound,
                tx,
            ))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await?
    }

    async fn list_banned(&mut self) -> crate::Result<Vec<BannableAddress>> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::ListBanned(tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        let list = rx.await?;
        Ok(list)
    }
    async fn ban(&mut self, addr: BannableAddress) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::Ban(addr, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await?
    }
    async fn unban(&mut self, addr: BannableAddress) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::Unban(addr, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await?
    }

    async fn get_peer_count(&self) -> crate::Result<usize> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager.send(PeerManagerEvent::GetPeerCount(tx))?;
        Ok(rx.await?)
    }

    async fn get_bind_addresses(&self) -> crate::Result<Vec<SocketAddress>> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager.send(PeerManagerEvent::GetBindAddresses(tx))?;
        Ok(rx.await?)
    }

    async fn get_connected_peers(&self) -> crate::Result<Vec<ConnectedPeer>> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager.send(PeerManagerEvent::GetConnectedPeers(tx))?;
        Ok(rx.await?)
    }

    async fn add_reserved_node(&mut self, addr: IpOrSocketAddress) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::AddReserved(addr, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        Ok(rx.await??)
    }

    async fn remove_reserved_node(&mut self, addr: IpOrSocketAddress) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::RemoveReserved(addr, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        Ok(rx.await??)
    }

    async fn submit_transaction(&mut self, tx: SignedTransaction) -> crate::Result<()> {
        let res = self
            .mempool_handle
            .call_mut(move |mempool| mempool.add_transaction_local(tx, LocalTxOrigin::P2p))
            .await??;
        Ok(res)
    }

    fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(P2pEvent) + Send + Sync>,
    ) -> crate::Result<()> {
        Ok(self.subscribers_sender.send(handler)?)
    }
}
