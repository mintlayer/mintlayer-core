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

use common::{chain::SignedTransaction, primitives::Idable};
use logging::log;
use subsystem::{CallRequest, ShutdownRequest};

use crate::{
    error::{ConversionError, P2pError},
    event::PeerManagerEvent,
    interface::{
        p2p_interface::{P2pInterface, P2pSubsystemInterface},
        types::ConnectedPeer,
    },
    message::SyncMessage,
    net::NetworkingService,
    run_p2p,
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    MessagingService, P2p, P2pInit, PeerDbStorage,
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
        rx.await.map_err(P2pError::from)?
    }

    async fn disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        let (tx, rx) = oneshot_nofail::channel();

        self.tx_peer_manager
            .send(PeerManagerEvent::Disconnect(peer_id, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await.map_err(P2pError::from)?
    }

    async fn get_peer_count(&self) -> crate::Result<usize> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::GetPeerCount(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    async fn get_bind_addresses(&self) -> crate::Result<Vec<String>> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::GetBindAddresses(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    async fn get_connected_peers(&self) -> crate::Result<Vec<ConnectedPeer>> {
        let (tx, rx) = oneshot_nofail::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::GetConnectedPeers(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
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

    async fn submit_transaction(&mut self, tx: SignedTransaction) -> crate::Result<()> {
        let id = tx.transaction().get_id();
        self.mempool_handle.call_mut(|m| m.add_transaction(tx)).await??;
        self.messaging_handle.broadcast_message(SyncMessage::NewTransaction(id))
    }
}

#[async_trait::async_trait]
impl<S: PeerDbStorage + 'static> P2pSubsystemInterface for P2pInit<S> {
    async fn run(mut self, call: CallRequest<dyn P2pInterface>, shutdown: ShutdownRequest) {
        if let Err(e) = run_p2p(
            self.chain_config,
            self.p2p_config,
            self.chainstate_handle,
            self.mempool_handle,
            self.time_getter,
            self.peerdb_storage,
            self.bind_addresses,
            call,
            shutdown,
        )
        .await
        {
            log::error!("Failed to run p2p: {e:?}");
        }
    }
}
