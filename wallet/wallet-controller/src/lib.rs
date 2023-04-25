// Copyright (c) 2023 RBB S.r.l
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

//! Common code for wallet UI applications

pub mod cookie;
pub mod mnemonic;
mod sync;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
pub use node_comm::node_traits::{ConnectedPeer, NodeInterface, PeerId};
pub use node_comm::{
    handles_client::WalletHandlesClient, make_rpc_client, rpc_client::NodeRpcClient,
};
use tokio::sync::oneshot;
use wallet::DefaultWallet;

#[derive(thiserror::Error, Debug)]
pub enum ControllerError<T: NodeInterface> {
    #[error("RPC error: {0}")]
    RpcError(T::Error),
}

pub struct Controller<T> {
    chain_config: Arc<ChainConfig>,
    rpc_client: T,
    wallet: DefaultWallet,
}

pub type RpcController = Controller<NodeRpcClient>;
pub type HandlesController = Controller<WalletHandlesClient>;

impl<T: NodeInterface + Clone + Send + Sync + 'static> Controller<T> {
    pub fn new(chain_config: Arc<ChainConfig>, rpc_client: T, wallet: DefaultWallet) -> Self {
        Self {
            chain_config,
            rpc_client,
            wallet,
        }
    }

    pub async fn get_best_block_id(&self) -> Result<Id<GenBlock>, ControllerError<T>> {
        self.rpc_client.get_best_block_id().await.map_err(ControllerError::RpcError)
    }

    pub async fn get_block(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<Block>, ControllerError<T>> {
        self.rpc_client.get_block(block_id).await.map_err(ControllerError::RpcError)
    }

    pub async fn get_best_block_height(&self) -> Result<BlockHeight, ControllerError<T>> {
        self.rpc_client.get_best_block_height().await.map_err(ControllerError::RpcError)
    }

    pub async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, ControllerError<T>> {
        self.rpc_client
            .get_block_id_at_height(height)
            .await
            .map_err(ControllerError::RpcError)
    }

    pub async fn submit_block(&self, block_hex: String) -> Result<(), ControllerError<T>> {
        self.rpc_client.submit_block(block_hex).await.map_err(ControllerError::RpcError)
    }

    pub async fn submit_transaction(
        &self,
        transaction_hex: String,
    ) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .submit_transaction(transaction_hex)
            .await
            .map_err(ControllerError::RpcError)
    }

    pub async fn node_shutdown(&self) -> Result<(), ControllerError<T>> {
        self.rpc_client.node_shutdown().await.map_err(ControllerError::RpcError)
    }

    pub async fn node_version(&self) -> Result<String, ControllerError<T>> {
        self.rpc_client.node_version().await.map_err(ControllerError::RpcError)
    }

    pub async fn p2p_connect(&self, address: String) -> Result<(), ControllerError<T>> {
        self.rpc_client.p2p_connect(address).await.map_err(ControllerError::RpcError)
    }

    pub async fn p2p_disconnect(&self, peer_id: PeerId) -> Result<(), ControllerError<T>> {
        self.rpc_client.p2p_disconnect(peer_id).await.map_err(ControllerError::RpcError)
    }

    pub async fn p2p_get_peer_count(&self) -> Result<usize, ControllerError<T>> {
        self.rpc_client.p2p_get_peer_count().await.map_err(ControllerError::RpcError)
    }

    pub async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, ControllerError<T>> {
        self.rpc_client
            .p2p_get_connected_peers()
            .await
            .map_err(ControllerError::RpcError)
    }

    pub async fn p2p_add_reserved_node(&self, address: String) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .p2p_add_reserved_node(address)
            .await
            .map_err(ControllerError::RpcError)
    }

    pub async fn p2p_remove_reserved_node(
        &self,
        address: String,
    ) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .p2p_remove_reserved_node(address)
            .await
            .map_err(ControllerError::RpcError)
    }

    pub async fn get_block_fetcher(
        &self,
    ) -> oneshot::Receiver<Result<sync::NewSyncState, sync::SyncError<T>>> {
        let (wallet_block_id, wallet_block_height) =
            self.wallet.get_best_block().expect("`get_best_block` should not fail normally");

        let (tx, rx) = oneshot::channel();
        let mut rpc_client = self.rpc_client.clone();
        let chain_config = Arc::clone(&self.chain_config);
        tokio::spawn(async move {
            while !tx.is_closed() {
                let sync_state_res_opt = sync::notify_new_block(
                    &chain_config,
                    &mut rpc_client,
                    wallet_block_id,
                    wallet_block_height,
                )
                .await
                .transpose();
                if let Some(sync_state_res) = sync_state_res_opt {
                    let _ = tx.send(sync_state_res);
                    return;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        rx
    }

    pub fn apply_sync_state(
        &mut self,
        sync_state: sync::NewSyncState,
    ) -> Result<(), wallet::WalletError> {
        sync::apply_sync_state(&self.chain_config, sync_state, &mut self.wallet)
    }
}

pub async fn make_rpc_controller(
    chain_config: Arc<ChainConfig>,
    remote_socket_address: SocketAddr,
    username_password: Option<(&str, &str)>,
    wallet: DefaultWallet,
) -> Result<RpcController, ControllerError<NodeRpcClient>> {
    let rpc_client = make_rpc_client(remote_socket_address, username_password)
        .await
        .map_err(ControllerError::RpcError)?;
    Ok(Controller::new(chain_config, rpc_client, wallet))
}
