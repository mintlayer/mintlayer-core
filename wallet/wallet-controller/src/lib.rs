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

pub mod mnemonic;
mod sync;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use common::{
    address::Address,
    chain::{tokens::TokenId, Block, ChainConfig, OutPoint, SignedTransaction, TxOutput},
    primitives::Amount,
};
use consensus::GenerateBlockInputData;
pub use node_comm::node_traits::{ConnectedPeer, NodeInterface, PeerId};
pub use node_comm::{
    handles_client::WalletHandlesClient, make_rpc_client, rpc_client::NodeRpcClient,
};
use wallet::{send_request::make_address_output, DefaultWallet};
pub use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    utxo_types::{UtxoType, UtxoTypes},
};

#[derive(thiserror::Error, Debug)]
pub enum ControllerError<T: NodeInterface> {
    #[error("Node call error: {0}")]
    NodeCallError(T::Error),
    #[error("Wallet file {0} error: {1}")]
    WalletFileError(PathBuf, String),
    #[error("Wallet error: {0}")]
    WalletError(wallet::wallet::WalletError),
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

    pub fn create_wallet(
        chain_config: Arc<ChainConfig>,
        file_path: impl AsRef<Path>,
        mnemonic: mnemonic::Mnemonic,
        passphrase: Option<&str>,
    ) -> Result<DefaultWallet, ControllerError<T>> {
        utils::ensure!(
            !file_path.as_ref().exists(),
            ControllerError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File already exists".to_owned()
            )
        );

        let db = wallet::wallet::open_or_create_wallet_file(file_path)
            .map_err(ControllerError::WalletError)?;
        let mut wallet = wallet::Wallet::new_wallet(
            Arc::clone(&chain_config),
            db,
            &mnemonic.to_string(),
            passphrase,
        )
        .map_err(ControllerError::WalletError)?;

        wallet
            .create_account(DEFAULT_ACCOUNT_INDEX)
            .map_err(ControllerError::WalletError)?;

        Ok(wallet)
    }

    pub fn open_wallet(
        chain_config: Arc<ChainConfig>,
        file_path: impl AsRef<Path>,
    ) -> Result<DefaultWallet, ControllerError<T>> {
        utils::ensure!(
            file_path.as_ref().exists(),
            ControllerError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File does not exist".to_owned()
            )
        );

        let db = wallet::wallet::open_or_create_wallet_file(file_path)
            .map_err(ControllerError::WalletError)?;
        let wallet = wallet::Wallet::load_wallet(Arc::clone(&chain_config), db)
            .map_err(ControllerError::WalletError)?;

        Ok(wallet)
    }

    pub fn get_balance(&self) -> Result<(Amount, BTreeMap<TokenId, Amount>), ControllerError<T>> {
        self.wallet
            .get_balance(
                DEFAULT_ACCOUNT_INDEX,
                UtxoType::Transfer | UtxoType::LockThenTransfer,
            )
            .map_err(ControllerError::WalletError)
    }

    pub fn get_utxos(
        &self,
        utxo_types: UtxoTypes,
    ) -> Result<BTreeMap<OutPoint, TxOutput>, ControllerError<T>> {
        self.wallet
            .get_utxos(DEFAULT_ACCOUNT_INDEX, utxo_types)
            .map_err(ControllerError::WalletError)
    }

    pub fn new_address(&mut self) -> Result<Address, ControllerError<T>> {
        self.wallet
            .get_new_address(DEFAULT_ACCOUNT_INDEX)
            .map_err(ControllerError::WalletError)
    }

    pub async fn send_to_address(
        &mut self,
        address: Address,
        amount: Amount,
    ) -> Result<(), ControllerError<T>> {
        let output = make_address_output(address, amount).map_err(ControllerError::WalletError)?;
        let tx = self
            .wallet
            .create_transaction_to_addresses(DEFAULT_ACCOUNT_INDEX, [output])
            .map_err(ControllerError::WalletError)?;
        self.rpc_client
            .submit_transaction(tx)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn create_stake_pool_tx(&mut self, amount: Amount) -> Result<(), ControllerError<T>> {
        let tx = self
            .wallet
            .create_stake_pool_tx(DEFAULT_ACCOUNT_INDEX, amount)
            .map_err(ControllerError::WalletError)?;
        self.rpc_client
            .submit_transaction(tx)
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn generate_block(
        &mut self,
        transactions_opt: Option<Vec<SignedTransaction>>,
    ) -> Result<Block, ControllerError<T>> {
        let pos_data = self
            .wallet
            .get_pos_gen_block_data(DEFAULT_ACCOUNT_INDEX)
            .map_err(ControllerError::WalletError)?;
        let block = self
            .rpc_client
            .generate_block(
                GenerateBlockInputData::PoS(pos_data.into()),
                transactions_opt,
            )
            .await
            .map_err(ControllerError::NodeCallError)?;
        Ok(block)
    }

    /// Synchronize the wallet continuously from the node's blockchain.
    /// This function is cancel safe.
    pub async fn run_sync(&mut self) {
        self.block_sync.run(&mut self.wallet, None).await;
    }

    /// Synchronize the wallet to the current tip height and return.
    /// Most useful in scripts and unit tests to make sure the wallet state is up to date.
    pub async fn sync_once(&mut self) -> Result<(), ControllerError<T>> {
        let node_state = self
            .rpc_client
            .chainstate_info()
            .await
            .map_err(ControllerError::NodeCallError)?;
        self.block_sync.run(&mut self.wallet, Some(node_state.best_block_height)).await;
        Ok(())
    }
}
