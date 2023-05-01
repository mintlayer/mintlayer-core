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

use std::{net::SocketAddr, sync::Arc};

use chainstate::ChainInfo;
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
pub use node_comm::node_traits::{ConnectedPeer, NodeInterface, PeerId};
pub use node_comm::{
    handles_client::WalletHandlesClient, make_rpc_client, rpc_client::NodeRpcClient,
};
use wallet::DefaultWallet;

// Disabled until wallet implements required API
const BLOCK_SYNC_ENABLED: bool = false;

#[derive(thiserror::Error, Debug)]
pub enum ControllerError<T: NodeInterface> {
    #[error("Node call error: {0}")]
    NodeCallError(T::Error),
}

pub struct Controller<T: NodeInterface> {
    rpc_client: T,

    wallet: DefaultWallet,

    block_sync: sync::BlockSyncing<T>,
}

pub type RpcController = Controller<NodeRpcClient>;
pub type HandlesController = Controller<WalletHandlesClient>;

impl<T: NodeInterface + Clone + Send + Sync + 'static> Controller<T> {
    pub fn new(chain_config: Arc<ChainConfig>, rpc_client: T, wallet: DefaultWallet) -> Self {
        let block_sync = sync::BlockSyncing::new(
            sync::BlockSyncingConfig::default(),
            Arc::clone(&chain_config),
            rpc_client.clone(),
        );

        Self {
            rpc_client,
            wallet,
            block_sync,
        }
    }

    pub async fn chainstate_info(&self) -> Result<ChainInfo, ControllerError<T>> {
        self.rpc_client.chainstate_info().await.map_err(ControllerError::NodeCallError)
    }

    pub async fn get_best_block_id(&self) -> Result<Id<GenBlock>, ControllerError<T>> {
        self.rpc_client
            .get_best_block_id()
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn get_block(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<Block>, ControllerError<T>> {
        self.rpc_client
            .get_block(block_id)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn get_best_block_height(&self) -> Result<BlockHeight, ControllerError<T>> {
        self.rpc_client
            .get_best_block_height()
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, ControllerError<T>> {
        self.rpc_client
            .get_block_id_at_height(height)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn submit_block(&self, block_hex: String) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .submit_block(block_hex)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn submit_transaction(
        &self,
        transaction_hex: String,
    ) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .submit_transaction(transaction_hex)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn node_shutdown(&self) -> Result<(), ControllerError<T>> {
        self.rpc_client.node_shutdown().await.map_err(ControllerError::NodeCallError)
    }

    pub async fn node_version(&self) -> Result<String, ControllerError<T>> {
        self.rpc_client.node_version().await.map_err(ControllerError::NodeCallError)
    }

    pub async fn p2p_connect(&self, address: String) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .p2p_connect(address)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn p2p_disconnect(&self, peer_id: PeerId) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .p2p_disconnect(peer_id)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn p2p_get_peer_count(&self) -> Result<usize, ControllerError<T>> {
        self.rpc_client
            .p2p_get_peer_count()
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, ControllerError<T>> {
        self.rpc_client
            .p2p_get_connected_peers()
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn p2p_add_reserved_node(&self, address: String) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .p2p_add_reserved_node(address)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn p2p_remove_reserved_node(
        &self,
        address: String,
    ) -> Result<(), ControllerError<T>> {
        self.rpc_client
            .p2p_remove_reserved_node(address)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    /// Sync the wallet block chain from the node.
    /// This function is cancel safe.
    pub async fn run_sync(&mut self) {
        if BLOCK_SYNC_ENABLED {
            self.block_sync.run(&mut self.wallet).await;
        } else {
            std::future::pending::<()>().await;
        }
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
        .map_err(ControllerError::NodeCallError)?;
    Ok(Controller::new(chain_config, rpc_client, wallet))
}
