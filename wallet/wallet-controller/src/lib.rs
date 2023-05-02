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

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use chainstate::ChainInfo;
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
use futures::future::join_all;
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
    #[error("Wallet file {0} error: {0}")]
    WalletFileError(PathBuf, String),
    #[error("Wallet error: {0}")]
    WalletError(wallet::wallet::WalletError),
}

pub struct Controller<T: NodeInterface> {
    chain_config: Arc<ChainConfig>,

    rpc_client: T,

    wds: Vec<WalletData<T>>,
}

struct WalletData<T: NodeInterface> {
    wallet: DefaultWallet,
    block_sync: sync::BlockSyncing<T>,
}

pub type RpcController = Controller<NodeRpcClient>;
pub type HandlesController = Controller<WalletHandlesClient>;

impl<T: NodeInterface + Clone + Send + Sync + 'static> Controller<T> {
    pub fn new(chain_config: Arc<ChainConfig>, rpc_client: T) -> Self {
        Self {
            chain_config,
            rpc_client,
            wds: Vec::new(),
        }
    }

    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        &self.chain_config
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

    pub fn create_wallet(
        &mut self,
        file_path: impl AsRef<Path>,
        mnemonic: mnemonic::Mnemonic,
        passphrase: Option<&str>,
    ) -> Result<(), ControllerError<T>> {
        utils::ensure!(
            !file_path.as_ref().exists(),
            ControllerError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File already exists".to_owned()
            )
        );

        let db = wallet::wallet::open_or_create_wallet_file(file_path)
            .map_err(ControllerError::WalletError)?;
        let wallet = wallet::Wallet::new_wallet(
            Arc::clone(&self.chain_config),
            db,
            &mnemonic.to_string(),
            passphrase,
        )
        .map_err(ControllerError::WalletError)?;

        self.add_wallet(wallet);
        Ok(())
    }

    pub fn open_wallet(&mut self, file_path: impl AsRef<Path>) -> Result<(), ControllerError<T>> {
        utils::ensure!(
            file_path.as_ref().exists(),
            ControllerError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File does not exist".to_owned()
            )
        );

        let db = wallet::wallet::open_or_create_wallet_file(file_path)
            .map_err(ControllerError::WalletError)?;
        let wallet = wallet::Wallet::load_wallet(Arc::clone(&self.chain_config), db)
            .map_err(ControllerError::WalletError)?;

        self.add_wallet(wallet);
        Ok(())
    }

    fn add_wallet(&mut self, wallet: DefaultWallet) {
        let block_sync = sync::BlockSyncing::new(
            sync::BlockSyncingConfig::default(),
            Arc::clone(&self.chain_config),
            self.rpc_client.clone(),
        );
        self.wds.push(WalletData { wallet, block_sync })
    }

    pub fn remove_wallet(&mut self, index: usize) {
        self.wds.remove(index);
    }

    pub fn wallets_len(&mut self) -> usize {
        self.wds.len()
    }

    pub fn get_wallet(&self, index: usize) -> &DefaultWallet {
        &self.wds[index].wallet
    }

    pub fn get_wallet_mut(&mut self, index: usize) -> &mut DefaultWallet {
        &mut self.wds[index].wallet
    }

    /// Sync the wallet block chain from the node.
    /// This function is cancel safe.
    pub async fn run_sync(&mut self) {
        if BLOCK_SYNC_ENABLED && !self.wds.is_empty() {
            join_all(self.wds.iter_mut().map(|wd| wd.block_sync.run(&mut wd.wallet))).await;
        } else {
            std::future::pending::<()>().await;
        }
    }
}

pub async fn make_rpc_controller(
    chain_config: Arc<ChainConfig>,
    remote_socket_address: SocketAddr,
    username_password: Option<(&str, &str)>,
) -> Result<RpcController, ControllerError<NodeRpcClient>> {
    let rpc_client = make_rpc_client(remote_socket_address, username_password)
        .await
        .map_err(ControllerError::NodeCallError)?;
    Ok(Controller::new(chain_config, rpc_client))
}
