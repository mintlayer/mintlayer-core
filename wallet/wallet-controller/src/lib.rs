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

const NORMAL_DELAY: Duration = Duration::from_secs(1);
const ERROR_DELAY: Duration = Duration::from_secs(10);

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use common::{
    address::Address,
    chain::{Block, ChainConfig, PoolId, SignedTransaction, Transaction, TxOutput, UtxoOutPoint},
    primitives::{id::WithId, Amount, BlockHeight, Id, Idable},
};
use consensus::GenerateBlockInputData;
use crypto::{
    key::{hdkd::u31::U31, PublicKey},
    vrf::VRFPublicKey,
};
use logging::log;
use mempool_types::TxStatus;
pub use node_comm::node_traits::{ConnectedPeer, NodeInterface, PeerId};
pub use node_comm::{
    handles_client::WalletHandlesClient, make_rpc_client, rpc_client::NodeRpcClient,
};
use wallet::{account::Currency, send_request::make_address_output, DefaultWallet};
pub use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    utxo_types::{UtxoState, UtxoStates, UtxoType, UtxoTypes},
};

#[derive(thiserror::Error, Debug)]
pub enum ControllerError<T: NodeInterface> {
    #[error("Node call error: {0}")]
    NodeCallError(T::Error),
    #[error("Wallet sync error: {0}")]
    SyncError(String),
    #[error("Synchronization is paused until the node has {0} blocks ({1} blocks currently)")]
    NotEnoughBlockHeight(BlockHeight, BlockHeight),
    #[error("Wallet file {0} error: {1}")]
    WalletFileError(PathBuf, String),
    #[error("Wallet error: {0}")]
    WalletError(wallet::wallet::WalletError),
}

pub struct Controller<T: NodeInterface> {
    chain_config: Arc<ChainConfig>,

    rpc_client: T,

    wallet: DefaultWallet,

    staking_started: Option<U31>,
}

pub type RpcController = Controller<NodeRpcClient>;
pub type HandlesController = Controller<WalletHandlesClient>;

impl<T: NodeInterface + Clone + Send + Sync + 'static> Controller<T> {
    pub fn new(chain_config: Arc<ChainConfig>, rpc_client: T, wallet: DefaultWallet) -> Self {
        Self {
            chain_config,
            rpc_client,
            wallet,
            staking_started: None,
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
        let wallet = wallet::Wallet::new_wallet(
            Arc::clone(&chain_config),
            db,
            &mnemonic.to_string(),
            passphrase,
        )
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

    /// Encrypts the wallet using the specified `password`, or removes the existing encryption if `password` is `None`.
    ///
    /// # Arguments
    ///
    /// * `password` - An optional `String` representing the new password for encrypting the wallet.
    ///
    /// # Returns
    ///
    /// This method returns an error if the wallet is locked
    pub fn encrypt_wallet(&mut self, password: &Option<String>) -> Result<(), ControllerError<T>> {
        self.wallet.encrypt_wallet(password).map_err(ControllerError::WalletError)
    }

    /// Unlocks the wallet using the specified password.
    ///
    /// # Arguments
    ///
    /// * `password` - A `String` representing the password that was used to encrypt the wallet.
    ///
    /// # Returns
    ///
    /// This method returns an error if the password is incorrect
    pub fn unlock_wallet(&mut self, password: &String) -> Result<(), ControllerError<T>> {
        self.wallet.unlock_wallet(password).map_err(ControllerError::WalletError)
    }

    /// Locks the wallet by making the encrypted private keys inaccessible.
    ///
    /// # Returns
    ///
    /// This method returns an error if the wallet is not encrypted.
    pub fn lock_wallet(&mut self) -> Result<(), ControllerError<T>> {
        self.wallet.lock_wallet().map_err(ControllerError::WalletError)
    }

    pub fn get_balance(
        &self,
        account_index: U31,
        utxo_states: UtxoStates,
    ) -> Result<BTreeMap<Currency, Amount>, ControllerError<T>> {
        self.wallet
            .get_balance(
                account_index,
                UtxoType::Transfer | UtxoType::LockThenTransfer,
                utxo_states,
            )
            .map_err(ControllerError::WalletError)
    }

    pub fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
    ) -> Result<BTreeMap<UtxoOutPoint, TxOutput>, ControllerError<T>> {
        self.wallet
            .get_utxos(account_index, utxo_types, utxo_states)
            .map_err(ControllerError::WalletError)
    }

    pub fn pending_transactions(
        &self,
        account_index: U31,
    ) -> Result<Vec<&WithId<Transaction>>, ControllerError<T>> {
        self.wallet
            .pending_transactions(account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn abandon_transaction(
        &mut self,
        account_index: U31,
        tx_id: Id<Transaction>,
    ) -> Result<(), ControllerError<T>> {
        self.wallet
            .abandon_transaction(account_index, tx_id)
            .map_err(ControllerError::WalletError)
    }

    pub fn new_address(&mut self, account_index: U31) -> Result<Address, ControllerError<T>> {
        self.wallet.get_new_address(account_index).map_err(ControllerError::WalletError)
    }

    pub fn new_public_key(&mut self, account_index: U31) -> Result<PublicKey, ControllerError<T>> {
        self.wallet
            .get_new_public_key(account_index)
            .map_err(ControllerError::WalletError)
    }

    pub fn get_pool_ids(&self, account_index: U31) -> Result<BTreeSet<PoolId>, ControllerError<T>> {
        self.wallet.get_pool_ids(account_index).map_err(ControllerError::WalletError)
    }

    pub fn get_vrf_public_key(
        &mut self,
        account_index: U31,
    ) -> Result<VRFPublicKey, ControllerError<T>> {
        self.wallet
            .get_vrf_public_key(account_index)
            .map_err(ControllerError::WalletError)
    }

    pub async fn send_to_address(
        &mut self,
        account_index: U31,
        address: Address,
        amount: Amount,
    ) -> Result<TxStatus, ControllerError<T>> {
        let output = make_address_output(address, amount).map_err(ControllerError::WalletError)?;
        let tx = self
            .wallet
            .create_transaction_to_addresses(account_index, [output])
            .map_err(ControllerError::WalletError)?;
        self.rpc_client
            .submit_transaction(tx.clone())
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn create_stake_pool_tx(
        &mut self,
        account_index: U31,
        amount: Amount,
        decomission_key: Option<PublicKey>,
    ) -> Result<TxStatus, ControllerError<T>> {
        let tx = self
            .wallet
            .create_stake_pool_tx(account_index, amount, decomission_key)
            .map_err(ControllerError::WalletError)?;
        self.rpc_client
            .submit_transaction(tx.clone())
            .await
            .map_err(ControllerError::NodeCallError)
    }

    pub async fn generate_block(
        &mut self,
        account_index: U31,
        transactions_opt: Option<Vec<SignedTransaction>>,
    ) -> Result<Block, ControllerError<T>> {
        let pos_data = self
            .wallet
            .get_pos_gen_block_data(account_index)
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

    pub async fn generate_blocks(
        &mut self,
        account_index: U31,
        count: u32,
    ) -> Result<(), ControllerError<T>> {
        for _ in 0..count {
            self.sync_once().await?;
            let block = self.generate_block(account_index, None).await?;
            self.rpc_client
                .submit_block(block)
                .await
                .map_err(ControllerError::NodeCallError)?;
        }
        self.sync_once().await
    }

    pub fn create_account(
        &mut self,
        name: Option<String>,
    ) -> Result<(U31, Option<String>), ControllerError<T>> {
        self.wallet.create_account(name).map_err(ControllerError::WalletError)
    }

    pub fn start_staking(&mut self, account_index: U31) -> Result<(), ControllerError<T>> {
        self.staking_started = Some(account_index);
        Ok(())
    }

    pub fn stop_staking(&mut self) -> Result<(), ControllerError<T>> {
        self.staking_started = None;
        Ok(())
    }

    /// Synchronize the wallet to the current node tip height and return
    pub async fn sync_once(&mut self) -> Result<(), ControllerError<T>> {
        sync::sync_once(&self.chain_config, &self.rpc_client, &mut self.wallet).await?;
        Ok(())
    }

    /// Synchronize the wallet in the background from the node's blockchain.
    /// Try staking new blocks if staking was started.
    pub async fn run(&mut self) {
        loop {
            let sync_res = self.sync_once().await;

            if let Err(e) = sync_res {
                log::error!("Wallet sync error: {e}");
                tokio::time::sleep(ERROR_DELAY).await;
                continue;
            }

            if let Some(account_index) = self.staking_started {
                let generate_res = self.generate_block(account_index, None).await;

                if let Ok(block) = generate_res {
                    log::info!(
                        "New block generated successfully, block id: {}",
                        block.get_id()
                    );

                    let submit_res = self.rpc_client.submit_block(block).await;
                    if let Err(e) = submit_res {
                        log::error!("Block submit failed: {e}");
                        tokio::time::sleep(ERROR_DELAY).await;
                    }

                    continue;
                }
            }

            tokio::time::sleep(NORMAL_DELAY).await;
        }
    }
}
