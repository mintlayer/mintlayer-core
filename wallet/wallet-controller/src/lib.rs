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

use chainstate::ChainInfo;
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
pub use node_comm::node_traits::{ConnectedPeer, NodeInterface, PeerId};
pub use node_comm::{
    handles_client::WalletHandlesClient, make_rpc_client, rpc_client::NodeRpcClient,
};
use sync::{BlockFetchResult, FetchedBlock};
use tokio::{sync::mpsc, task::JoinHandle};
use wallet::DefaultWallet;

#[derive(thiserror::Error, Debug)]
pub enum ControllerError<T: NodeInterface> {
    #[error("RPC error: {0}")]
    RpcError(T::Error),
}

pub struct Controller<T: NodeInterface> {
    chain_config: Arc<ChainConfig>,
    rpc_client: T,
    wallet: DefaultWallet,
    node_tip_rx: mpsc::Receiver<ChainInfo>,
    node_chain_info: Option<ChainInfo>,
    sync_task: Option<JoinHandle<BlockFetchResult<T>>>,
}

pub type RpcController = Controller<NodeRpcClient>;
pub type HandlesController = Controller<WalletHandlesClient>;

const BLOCK_SYNC_ENABLED: bool = false;

impl<T: NodeInterface + Clone + Send + Sync + 'static> Controller<T> {
    pub fn new(chain_config: Arc<ChainConfig>, rpc_client: T, wallet: DefaultWallet) -> Self {
        let (tip_tx, tip_rx) = mpsc::channel(1);
        tokio::spawn(sync::run_state_sync(tip_tx, rpc_client.clone()));

        Self {
            chain_config,
            rpc_client,
            wallet,
            node_tip_rx: tip_rx,
            node_chain_info: None,
            sync_task: None,
        }
    }

    pub async fn chainstate_info(&self) -> Result<ChainInfo, ControllerError<T>> {
        self.rpc_client.chainstate().await.map_err(ControllerError::RpcError)
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

    fn handle_node_tip_change(&mut self, chain_info: ChainInfo) {
        self.node_chain_info = Some(chain_info);
    }

    fn start_block_fetch_if_needed(&mut self) {
        if !BLOCK_SYNC_ENABLED {
            return;
        }

        if self.sync_task.is_some() {
            return;
        }

        let (node_block_id, node_block_height) = match self.node_chain_info.as_ref() {
            Some(info) => (info.best_block_id, info.best_block_height),
            None => return,
        };

        let (wallet_block_id, wallet_block_height) =
            self.wallet.get_best_block().expect("`get_best_block` should not fail normally");

        if node_block_id == wallet_block_id || node_block_height < wallet_block_height {
            return;
        }

        let chain_config = Arc::clone(&self.chain_config);
        let mut rpc_client = self.rpc_client.clone();

        self.sync_task = Some(tokio::spawn(async move {
            let sync_res = sync::fetch_new_block(
                &chain_config,
                &mut rpc_client,
                node_block_id,
                node_block_height,
                wallet_block_id,
                wallet_block_height,
            )
            .await;

            if let Err(e) = &sync_res {
                logging::log::error!("Block fetch failed: {e}");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }

            sync_res
        }));
    }

    fn handle_block_fetch_result(&mut self, res: BlockFetchResult<T>) {
        if let Ok(FetchedBlock {
            block,
            block_height,
        }) = res
        {
            let scan_res = self.wallet.scan_new_blocks(block_height, vec![block]);
            if let Err(e) = scan_res {
                logging::log::error!("Block scan failed: {e}");
            }
        }
    }

    async fn recv_block_fetch_result(
        sync_task: &mut Option<JoinHandle<BlockFetchResult<T>>>,
    ) -> BlockFetchResult<T> {
        // This must be cancel safe!
        match sync_task {
            Some(task) => {
                let res = task.await.expect("Block fetch should not panic");
                *sync_task = None;
                res
            }
            None => std::future::pending().await,
        }
    }

    /// Sync the wallet block chain from the node.
    /// This function is cancel safe.
    pub async fn run_sync(&mut self) {
        // This must be cancel safe!
        loop {
            self.start_block_fetch_if_needed();

            tokio::select! {
                tip = self.node_tip_rx.recv() => {
                    // Channel is always open because [run_tip_sync] does not return
                    self.handle_node_tip_change(tip.expect("Channel must be open"));
                }
                sync_result = Self::recv_block_fetch_result(&mut self.sync_task) => {
                    self.handle_block_fetch_result(sync_result);
                }
            }
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
        .map_err(ControllerError::RpcError)?;
    Ok(Controller::new(chain_config, rpc_client, wallet))
}
