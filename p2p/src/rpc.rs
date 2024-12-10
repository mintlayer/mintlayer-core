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

use std::time::Duration;

use common::{chain::SignedTransaction, primitives::time::Time};
use mempool::tx_options::TxOptionsOverrides;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};
use serialization::hex_encoded::HexEncoded;
use utils_networking::IpOrSocketAddress;

use crate::{interface::types::ConnectedPeer, types::peer_id::PeerId};
use rpc::RpcResult;

#[rpc::describe]
#[rpc::rpc(server, client, namespace = "p2p")]
trait P2pRpc {
    /// Enable or disable networking
    #[method(name = "enable_networking")]
    async fn enable_networking(&self, enable: bool) -> RpcResult<()>;

    /// Attempt to connect to a remote node (just once).
    ///
    /// For persistent connections see `add_reserved_node` should be used.
    /// Keep in mind that `add_reserved_node` works completely differently.
    #[method(name = "connect")]
    async fn connect(&self, addr: IpOrSocketAddress) -> RpcResult<()>;

    /// Disconnect peer, given its id.
    #[method(name = "disconnect")]
    async fn disconnect(&self, peer_id: PeerId) -> RpcResult<()>;

    /// List banned peers and their ban expiry time.
    #[method(name = "list_banned")]
    async fn list_banned(&self) -> RpcResult<Vec<(BannableAddress, Time)>>;

    /// Ban a peer by their address for a given amount of time.
    #[method(name = "ban")]
    async fn ban(&self, address: BannableAddress, duration: Duration) -> RpcResult<()>;

    /// Unban a banned peer by their IP address.
    #[method(name = "unban")]
    async fn unban(&self, address: BannableAddress) -> RpcResult<()>;

    /// List peers that have been discouraged.
    ///
    /// Discouragement is similar to banning, except that inbound connections from such peers
    /// are still allowed.
    ///
    /// Peers are discouraged automatically if they misbehave.
    #[method(name = "list_discouraged")]
    async fn list_discouraged(&self) -> RpcResult<Vec<(BannableAddress, Time)>>;

    /// Undiscourage a previously discouraged peer by their IP address.
    #[method(name = "undiscourage")]
    async fn undiscourage(&self, address: BannableAddress) -> RpcResult<()>;

    /// Get the number of peers connected to this node.
    #[method(name = "get_peer_count")]
    async fn get_peer_count(&self) -> RpcResult<usize>;

    /// Get p2p bind address(es) of this node.
    #[method(name = "get_bind_addresses")]
    async fn get_bind_addresses(&self) -> RpcResult<Vec<SocketAddress>>;

    /// Get details of connected peers.
    #[method(name = "get_connected_peers")]
    async fn get_connected_peers(&self) -> RpcResult<Vec<ConnectedPeer>>;

    /// Get addresses of reserved nodes.
    #[method(name = "get_reserved_nodes")]
    async fn get_reserved_nodes(&self) -> RpcResult<Vec<SocketAddress>>;

    /// Add the address to the reserved nodes list.
    ///
    /// The node will try to keep connections open to all reserved peers.
    /// A reserved peer is a peer that you trust and you want your node to remain connected to, no matter what they do.
    #[method(name = "add_reserved_node")]
    async fn add_reserved_node(&self, addr: IpOrSocketAddress) -> RpcResult<()>;

    /// Remove the address from the reserved nodes list.
    ///
    /// Existing connection to the peer is not closed.
    #[method(name = "remove_reserved_node")]
    async fn remove_reserved_node(&self, addr: IpOrSocketAddress) -> RpcResult<()>;

    /// Submits a transaction to mempool, and if it is valid, broadcasts it to the network as well.
    #[method(name = "submit_transaction")]
    async fn submit_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        options: TxOptionsOverrides,
    ) -> RpcResult<()>;
}

#[async_trait::async_trait]
impl P2pRpcServer for super::P2pHandle {
    async fn enable_networking(&self, enable: bool) -> RpcResult<()> {
        let res = self.call_async_mut(move |this| this.enable_networking(enable)).await;
        rpc::handle_result(res)
    }

    async fn connect(&self, addr: IpOrSocketAddress) -> RpcResult<()> {
        let res = self.call_async_mut(|this| this.connect(addr)).await;
        rpc::handle_result(res)
    }

    async fn disconnect(&self, peer_id: PeerId) -> RpcResult<()> {
        let res = self.call_async_mut(move |this| this.disconnect(peer_id)).await;
        rpc::handle_result(res)
    }

    async fn list_banned(&self) -> RpcResult<Vec<(BannableAddress, Time)>> {
        let res = self.call_async(|this| this.list_banned()).await;
        rpc::handle_result(res)
    }

    async fn ban(&self, address: BannableAddress, duration: Duration) -> RpcResult<()> {
        let res = self.call_async_mut(move |this| this.ban(address, duration)).await;
        rpc::handle_result(res)
    }

    async fn unban(&self, address: BannableAddress) -> RpcResult<()> {
        let res = self.call_async_mut(move |this| this.unban(address)).await;
        rpc::handle_result(res)
    }

    async fn list_discouraged(&self) -> RpcResult<Vec<(BannableAddress, Time)>> {
        let res = self.call_async(|this| this.list_discouraged()).await;
        rpc::handle_result(res)
    }

    async fn undiscourage(&self, address: BannableAddress) -> RpcResult<()> {
        let res = self.call_async_mut(move |this| this.undiscourage(address)).await;
        rpc::handle_result(res)
    }

    async fn get_peer_count(&self) -> RpcResult<usize> {
        let res = self.call_async(|this| this.get_peer_count()).await;
        rpc::handle_result(res)
    }

    async fn get_bind_addresses(&self) -> RpcResult<Vec<SocketAddress>> {
        let res = self.call_async(|this| this.get_bind_addresses()).await;
        rpc::handle_result(res)
    }

    async fn get_connected_peers(&self) -> RpcResult<Vec<ConnectedPeer>> {
        let res = self.call_async(|this| this.get_connected_peers()).await;
        rpc::handle_result(res)
    }

    async fn get_reserved_nodes(&self) -> RpcResult<Vec<SocketAddress>> {
        let res = self.call_async(|this| this.get_reserved_nodes()).await;
        rpc::handle_result(res)
    }

    async fn add_reserved_node(&self, addr: IpOrSocketAddress) -> RpcResult<()> {
        let res = self.call_async_mut(|this| this.add_reserved_node(addr)).await;
        rpc::handle_result(res)
    }

    async fn remove_reserved_node(&self, addr: IpOrSocketAddress) -> RpcResult<()> {
        let res = self.call_async_mut(move |this| this.remove_reserved_node(addr)).await;
        rpc::handle_result(res)
    }

    async fn submit_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        options: TxOptionsOverrides,
    ) -> RpcResult<()> {
        let res = self
            .call_async_mut(move |this| this.submit_transaction(tx.take(), options))
            .await;
        rpc::handle_result(res)
    }
}
