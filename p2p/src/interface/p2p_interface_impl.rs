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

use std::str::FromStr;

use tokio::sync::oneshot;

use crate::{
    error::{ConversionError, P2pError},
    event::PeerManagerEvent,
    net::NetworkingService,
    P2p,
};

use super::p2p_interface::P2pInterface;

#[async_trait::async_trait]
impl<T> P2pInterface for P2p<T>
where
    T: NetworkingService,
{
    async fn connect(&mut self, addr: String) -> crate::Result<()>
    where
        <T as NetworkingService>::Address: FromStr,
        <T as NetworkingService>::PeerId: FromStr,
    {
        let (tx, rx) = oneshot::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::Connect(
                addr.parse::<T::Address>().map_err(|_| {
                    P2pError::ConversionError(ConversionError::InvalidAddress(addr))
                })?,
                tx,
            ))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await.map_err(P2pError::from)?
    }

    async fn disconnect(&self, peer_id: String) -> crate::Result<()>
    where
        <T as NetworkingService>::PeerId: FromStr,
    {
        let (tx, rx) = oneshot::channel();
        let peer_id = peer_id
            .parse::<T::PeerId>()
            .map_err(|_| P2pError::ConversionError(ConversionError::InvalidPeerId(peer_id)))?;

        self.tx_peer_manager
            .send(PeerManagerEvent::Disconnect(peer_id, tx))
            .map_err(|_| P2pError::ChannelClosed)?;
        rx.await.map_err(P2pError::from)?
    }

    async fn get_peer_count(&self) -> crate::Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::GetPeerCount(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    async fn get_bind_address(&self) -> crate::Result<String> {
        let (tx, rx) = oneshot::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::GetBindAddress(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }

    async fn get_connected_peers(&self) -> crate::Result<Vec<String>> {
        let (tx, rx) = oneshot::channel();
        self.tx_peer_manager
            .send(PeerManagerEvent::GetConnectedPeers(tx))
            .map_err(P2pError::from)?;
        rx.await.map_err(P2pError::from)
    }
}
