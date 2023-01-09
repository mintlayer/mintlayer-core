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

use crate::{error::P2pError, interface::types::ConnectedPeer};
use subsystem::subsystem::CallError;

#[rpc::rpc(server, namespace = "p2p")]
trait P2pRpc {
    /// Connect to remote node
    #[method(name = "connect")]
    async fn connect(&self, addr: String) -> rpc::Result<()>;

    /// Disconnect peer
    #[method(name = "disconnect")]
    async fn disconnect(&self, peer_id: String) -> rpc::Result<()>;

    /// Get the number of peers
    #[method(name = "get_peer_count")]
    async fn get_peer_count(&self) -> rpc::Result<usize>;

    /// Get bind address of the local node
    #[method(name = "get_bind_addresses")]
    async fn get_bind_addresses(&self) -> rpc::Result<Vec<String>>;

    /// Get details of connected peers
    #[method(name = "get_connected_peers")]
    async fn get_connected_peers(&self) -> rpc::Result<Vec<ConnectedPeer>>;
}

#[async_trait::async_trait]
impl P2pRpcServer for super::P2pHandle {
    async fn connect(&self, addr: String) -> rpc::Result<()> {
        let res = self.call_async_mut(|this| Box::pin(this.connect(addr))).await;
        handle_error(res)
    }

    async fn disconnect(&self, peer_id: String) -> rpc::Result<()> {
        let res = self.call_async_mut(|this| Box::pin(this.disconnect(peer_id))).await;
        handle_error(res)
    }

    async fn get_peer_count(&self) -> rpc::Result<usize> {
        let res = self.call_async(|this| Box::pin(this.get_peer_count())).await;
        handle_error(res)
    }

    async fn get_bind_addresses(&self) -> rpc::Result<Vec<String>> {
        let res = self.call_async(|this| Box::pin(this.get_bind_address())).await;
        handle_error(res)
    }

    async fn get_connected_peers(&self) -> rpc::Result<Vec<ConnectedPeer>> {
        let res = self.call_async(|this| Box::pin(this.get_connected_peers())).await;
        handle_error(res)
    }
}

fn handle_error<T>(e: Result<Result<T, P2pError>, CallError>) -> rpc::Result<T> {
    e.map_err(rpc::Error::to_call_error)
        .and_then(|r| r.map_err(rpc::Error::to_call_error))
}
