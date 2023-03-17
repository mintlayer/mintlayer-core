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

use common::chain::SignedTransaction;
use serialization::DecodeAll;

use crate::{error::P2pError, interface::types::ConnectedPeer, types::peer_id::PeerId};
use subsystem::subsystem::CallError;

#[rpc::rpc(server, namespace = "p2p")]
trait P2pRpc {
    /// Try to connect to a remote node (just once).
    /// For persistent connections `add_reserved_node` should be used.
    #[method(name = "connect")]
    async fn connect(&self, addr: String) -> rpc::Result<()>;

    /// Disconnect peer
    #[method(name = "disconnect")]
    async fn disconnect(&self, peer_id: PeerId) -> rpc::Result<()>;

    /// Get the number of peers
    #[method(name = "get_peer_count")]
    async fn get_peer_count(&self) -> rpc::Result<usize>;

    /// Get bind address of the local node
    #[method(name = "get_bind_addresses")]
    async fn get_bind_addresses(&self) -> rpc::Result<Vec<String>>;

    /// Get details of connected peers
    #[method(name = "get_connected_peers")]
    async fn get_connected_peers(&self) -> rpc::Result<Vec<ConnectedPeer>>;

    /// Add the address to the reserved nodes list.
    /// The node will try to keep connections open to all reserved peers.
    #[method(name = "add_reserved_node")]
    async fn add_reserved_node(&self, addr: String) -> rpc::Result<()>;

    /// Remove the address from the reserved nodes list.
    /// Existing connection to the peer is not closed.
    #[method(name = "remove_reserved_node")]
    async fn remove_reserved_node(&self, addr: String) -> rpc::Result<()>;

    /// Submits a transaction to mempool, and if it is valid, broadcasts it to the network.
    #[method(name = "submit_transaction")]
    async fn submit_transaction(&self, tx_hex: String) -> rpc::Result<()>;
}

#[async_trait::async_trait]
impl P2pRpcServer for super::P2pHandle {
    async fn connect(&self, addr: String) -> rpc::Result<()> {
        let res = self.call_async_mut(|this| this.connect(addr)).await;
        handle_error(res)
    }

    async fn disconnect(&self, peer_id: PeerId) -> rpc::Result<()> {
        let res = self.call_async_mut(move |this| this.disconnect(peer_id)).await;
        handle_error(res)
    }

    async fn get_peer_count(&self) -> rpc::Result<usize> {
        let res = self.call_async(|this| this.get_peer_count()).await;
        handle_error(res)
    }

    async fn get_bind_addresses(&self) -> rpc::Result<Vec<String>> {
        let res = self.call_async(|this| this.get_bind_addresses()).await;
        handle_error(res)
    }

    async fn get_connected_peers(&self) -> rpc::Result<Vec<ConnectedPeer>> {
        let res = self.call_async(|this| this.get_connected_peers()).await;
        handle_error(res)
    }

    async fn add_reserved_node(&self, addr: String) -> rpc::Result<()> {
        let res = self.call_async_mut(|this| this.add_reserved_node(addr)).await;
        handle_error(res)
    }

    async fn remove_reserved_node(&self, addr: String) -> rpc::Result<()> {
        let res = self.call_async_mut(move |this| this.remove_reserved_node(addr)).await;
        handle_error(res)
    }

    async fn submit_transaction(&self, tx_hex: String) -> rpc::Result<()> {
        let tx = hex::decode(tx_hex).map_err(rpc::Error::to_call_error)?;
        let tx = SignedTransaction::decode_all(&mut &tx[..]).map_err(rpc::Error::to_call_error)?;
        handle_error(self.call_async_mut(|s| s.submit_transaction(tx)).await)
    }
}

fn handle_error<T>(e: Result<Result<T, P2pError>, CallError>) -> rpc::Result<T> {
    e.map_err(rpc::Error::to_call_error)
        .and_then(|r| r.map_err(rpc::Error::to_call_error))
}
