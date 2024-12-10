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

use std::{sync::Arc, time::Duration};

use common::{chain::SignedTransaction, primitives::time::Time};
use mempool::{
    tx_options::{TxOptions, TxOptionsOverrides},
    tx_origin::LocalTxOrigin,
};
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};
use utils_networking::IpOrSocketAddress;

use crate::{
    disconnection_reason::DisconnectionReason,
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
    async fn enable_networking(&mut self, enable: bool) -> crate::Result<()> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::EnableNetworking {
                enable,
                response_sender,
            })
            .map_err(|_| P2pError::ChannelClosed)?;
        response_receiver.await?
    }

    async fn connect(&mut self, addr: IpOrSocketAddress) -> crate::Result<()> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::Connect(addr, response_sender))
            .map_err(|_| P2pError::ChannelClosed)?;
        response_receiver.await?
    }

    async fn disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::Disconnect(
                peer_id,
                PeerDisconnectionDbAction::RemoveIfOutbound,
                Some(DisconnectionReason::ManualDisconnect),
                response_sender,
            ))
            .map_err(|_| P2pError::ChannelClosed)?;
        response_receiver.await?
    }

    async fn list_banned(&self) -> crate::Result<Vec<(BannableAddress, Time)>> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::ListBanned(response_sender))
            .map_err(|_| P2pError::ChannelClosed)?;
        let list = response_receiver.await?;
        Ok(list)
    }

    async fn ban(&mut self, addr: BannableAddress, duration: Duration) -> crate::Result<()> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::Ban(addr, duration, response_sender))
            .map_err(|_| P2pError::ChannelClosed)?;
        response_receiver.await?
    }

    async fn unban(&mut self, addr: BannableAddress) -> crate::Result<()> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::Unban(addr, response_sender))
            .map_err(|_| P2pError::ChannelClosed)?;
        response_receiver.await?
    }

    async fn undiscourage(&mut self, addr: BannableAddress) -> crate::Result<()> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::Undiscourage(addr, response_sender))
            .map_err(|_| P2pError::ChannelClosed)?;
        response_receiver.await?
    }

    async fn list_discouraged(&self) -> crate::Result<Vec<(BannableAddress, Time)>> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::ListDiscouraged(response_sender))
            .map_err(|_| P2pError::ChannelClosed)?;
        let list = response_receiver.await?;
        Ok(list)
    }

    async fn get_peer_count(&self) -> crate::Result<usize> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::GetPeerCount(response_sender))?;
        Ok(response_receiver.await?)
    }

    async fn get_bind_addresses(&self) -> crate::Result<Vec<SocketAddress>> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::GetBindAddresses(response_sender))?;
        Ok(response_receiver.await?)
    }

    async fn get_connected_peers(&self) -> crate::Result<Vec<ConnectedPeer>> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::GetConnectedPeers(response_sender))?;
        Ok(response_receiver.await?)
    }

    async fn get_reserved_nodes(&self) -> crate::Result<Vec<SocketAddress>> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::GetReserved(response_sender))
            .map_err(|_| P2pError::ChannelClosed)?;
        let list = response_receiver.await?;
        Ok(list)
    }

    async fn add_reserved_node(&mut self, addr: IpOrSocketAddress) -> crate::Result<()> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::AddReserved(addr, response_sender))
            .map_err(|_| P2pError::ChannelClosed)?;
        Ok(response_receiver.await??)
    }

    async fn remove_reserved_node(&mut self, addr: IpOrSocketAddress) -> crate::Result<()> {
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        self.peer_mgr_event_sender
            .send(PeerManagerEvent::RemoveReserved(addr, response_sender))
            .map_err(|_| P2pError::ChannelClosed)?;
        Ok(response_receiver.await??)
    }

    async fn submit_transaction(
        &mut self,
        tx: SignedTransaction,
        options: TxOptionsOverrides,
    ) -> crate::Result<()> {
        let origin = LocalTxOrigin::P2p;
        let options = TxOptions::default_for(origin.into()).with_overrides(options);
        let res = self
            .mempool_handle
            .call_mut(move |mempool| mempool.add_transaction_local(tx, origin, options))
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
