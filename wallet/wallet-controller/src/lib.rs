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

use mempool_types::TxStatus;
use utils::tap_error_log::LogError;

use common::{
    address::Address,
    chain::{
        tokens::{
            Metadata,
            RPCTokenInfo::{FungibleToken, NonFungibleToken},
            TokenId, TokenIssuance,
        },
        Block, ChainConfig, GenBlock, PoolId, SignedTransaction, Transaction, TxOutput,
        UtxoOutPoint,
    },
    primitives::{id::WithId, time::get_time, Amount, BlockHeight, Id, Idable},
};
use consensus::GenerateBlockInputData;
use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, u31::U31},
        PublicKey,
    },
    random::{make_pseudo_rng, Rng},
    vrf::VRFPublicKey,
};
use futures::stream::FuturesUnordered;
use futures::TryStreamExt;
use logging::log;
pub use node_comm::node_traits::{ConnectedPeer, NodeInterface, PeerId};
pub use node_comm::{
    handles_client::WalletHandlesClient, make_rpc_client, rpc_client::NodeRpcClient,
};
use wallet::{
    account::transaction_list::TransactionList,
    account::Currency,
    send_request::{make_address_output, make_address_output_token},
    wallet_events::WalletEvents,
    DefaultWallet, WalletError,
};
use wallet_types::BlockInfo;
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

pub struct Controller<T, W> {
    chain_config: Arc<ChainConfig>,

    rpc_client: T,

    wallet: DefaultWallet,

    staking_started: BTreeSet<U31>,

    wallet_events: W,
}

impl<T, WalletEvents> std::fmt::Debug for Controller<T, WalletEvents> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller").finish()
    }
}

pub type RpcController<WalletEvents> = Controller<NodeRpcClient, WalletEvents>;
pub type HandlesController<WalletEvents> = Controller<WalletHandlesClient, WalletEvents>;

impl<T: NodeInterface + Clone + Send + Sync + 'static, W: WalletEvents> Controller<T, W> {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        rpc_client: T,
        wallet: DefaultWallet,
        wallet_events: W,
    ) -> Self {
        Self {
            chain_config,
            rpc_client,
            wallet,
            staking_started: BTreeSet::new(),
            wallet_events,
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

    pub fn account_names(&self) -> impl Iterator<Item = &Option<String>> {
        self.wallet.account_names()
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

    #[allow(clippy::too_many_arguments)]
    pub async fn issue_new_token(
        &mut self,
        account_index: U31,
        address: Address,
        token_ticker: Vec<u8>,
        amount_to_issue: Amount,
        number_of_decimals: u8,
        metadata_uri: Vec<u8>,
    ) -> Result<(TokenId, TxStatus), ControllerError<T>> {
        let current_fee_rate = self
            .rpc_client
            .mempool_get_fee_rate(5)
            .await
            .map_err(ControllerError::NodeCallError)?;

        let consolidate_fee_rate = current_fee_rate;
        let (token_id, tx) = self
            .wallet
            .issue_new_token(
                account_index,
                address,
                TokenIssuance {
                    token_ticker,
                    amount_to_issue,
                    number_of_decimals,
                    metadata_uri,
                },
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;
        self.rpc_client
            .submit_transaction(tx.clone())
            .await
            .map_err(ControllerError::NodeCallError)
            .map(|status| (token_id, status))
    }

    pub async fn issue_new_nft(
        &mut self,
        account_index: U31,
        address: Address,
        metadata: Metadata,
    ) -> Result<(TokenId, TxStatus), ControllerError<T>> {
        let current_fee_rate = self
            .rpc_client
            .mempool_get_fee_rate(5)
            .await
            .map_err(ControllerError::NodeCallError)?;

        let consolidate_fee_rate = current_fee_rate;
        let (token_id, tx) = self
            .wallet
            .issue_new_nft(
                account_index,
                address,
                metadata,
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;
        self.rpc_client
            .submit_transaction(tx.clone())
            .await
            .map_err(ControllerError::NodeCallError)
            .map(|status| (token_id, status))
    }

    pub fn new_address(
        &mut self,
        account_index: U31,
    ) -> Result<(ChildNumber, Address), ControllerError<T>> {
        self.wallet.get_new_address(account_index).map_err(ControllerError::WalletError)
    }

    pub fn new_public_key(&mut self, account_index: U31) -> Result<PublicKey, ControllerError<T>> {
        self.wallet
            .get_new_public_key(account_index)
            .map_err(ControllerError::WalletError)
    }

    async fn get_pool_info(
        &self,
        pool_id: PoolId,
        block_info: BlockInfo,
    ) -> Result<(PoolId, BlockInfo, Amount), ControllerError<T>> {
        self.rpc_client
            .get_stake_pool_balance(pool_id)
            .await
            .map_err(ControllerError::NodeCallError)
            .and_then(|balance| {
                balance.ok_or(ControllerError::SyncError(format!(
                    "Pool id {} from wallet not found in node",
                    pool_id
                )))
            })
            .map(|balance| (pool_id, block_info, balance))
            .log_err()
    }

    pub async fn get_pool_ids(
        &self,
        account_index: U31,
    ) -> Result<Vec<(PoolId, BlockInfo, Amount)>, ControllerError<T>> {
        let pools =
            self.wallet.get_pool_ids(account_index).map_err(ControllerError::WalletError)?;

        let tasks: FuturesUnordered<_> = pools
            .into_iter()
            .map(|(pool_id, block_info)| self.get_pool_info(pool_id, block_info))
            .collect();

        tasks.try_collect().await
    }

    pub fn get_vrf_public_key(
        &mut self,
        account_index: U31,
    ) -> Result<VRFPublicKey, ControllerError<T>> {
        self.wallet
            .get_vrf_public_key(account_index)
            .map_err(ControllerError::WalletError)
    }

    /// Broadcast a singed transaction to the mempool and update the wallets state if the
    /// transaction has been added to the mempool
    async fn broadcast_to_mempool(
        &mut self,
        tx: SignedTransaction,
    ) -> Result<TxStatus, ControllerError<T>> {
        let status = self
            .rpc_client
            .submit_transaction(tx.clone())
            .await
            .map_err(ControllerError::NodeCallError)?;

        match status {
            mempool::TxStatus::InMempool => {
                self.wallet
                    .add_unconfirmed_tx(tx, &mut self.wallet_events)
                    .map_err(ControllerError::WalletError)?;
            }
            mempool::TxStatus::InOrphanPool => {
                // Mempool should reject the transaction and not return `InOrphanPool`
                log::warn!("Newly created Transaction was sent to the orphan pool")
                // We will not save the Tx in our wallet so that we don't start building other
                // transactions on top of it
            }
        };

        Ok(status)
    }

    pub async fn send_to_address(
        &mut self,
        account_index: U31,
        address: Address,
        amount: Amount,
    ) -> Result<TxStatus, ControllerError<T>> {
        let output = make_address_output(self.chain_config.as_ref(), address, amount)
            .map_err(ControllerError::WalletError)?;
        let current_fee_rate = self
            .rpc_client
            .mempool_get_fee_rate(5)
            .await
            .map_err(ControllerError::NodeCallError)?;

        let consolidate_fee_rate = current_fee_rate;

        let tx = self
            .wallet
            .create_transaction_to_addresses(
                account_index,
                [output],
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
    }

    pub async fn send_tokens_to_address(
        &mut self,
        account_index: U31,
        token_id: TokenId,
        address: Address,
        amount: Amount,
    ) -> Result<SignedTransaction, ControllerError<T>> {
        let current_fee_rate = self
            .rpc_client
            .mempool_get_fee_rate(5)
            .await
            .map_err(ControllerError::NodeCallError)?;

        let consolidate_fee_rate = current_fee_rate;
        let output =
            make_address_output_token(self.chain_config.as_ref(), address, amount, token_id)
                .map_err(ControllerError::WalletError)?;
        self.wallet
            .create_transaction_to_addresses(
                account_index,
                [output],
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)
    }

    pub async fn get_token_number_of_decimals(
        &mut self,
        token_id: TokenId,
    ) -> Result<u8, ControllerError<T>> {
        let token_info = self
            .rpc_client
            .get_token_info(token_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::WalletError(WalletError::UnknownTokenId(
                token_id,
            )))?;
        let decimals = match token_info {
            FungibleToken(token_info) => token_info.number_of_decimals,
            // TODO: for now use 0 so you can transfer NFTs with the same command as tokens
            // later we can separate it into separate commands
            NonFungibleToken(_) => 0,
        };
        Ok(decimals)
    }

    pub async fn create_stake_pool_tx(
        &mut self,
        account_index: U31,
        amount: Amount,
        decomission_key: Option<PublicKey>,
    ) -> Result<TxStatus, ControllerError<T>> {
        let current_fee_rate = self
            .rpc_client
            .mempool_get_fee_rate(5)
            .await
            .map_err(ControllerError::NodeCallError)?;

        let consolidate_fee_rate = current_fee_rate;

        let tx = self
            .wallet
            .create_stake_pool_tx(
                account_index,
                amount,
                decomission_key,
                current_fee_rate,
                consolidate_fee_rate,
            )
            .map_err(ControllerError::WalletError)?;

        self.broadcast_to_mempool(tx).await
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

    pub fn get_transaction_list(
        &self,
        account_index: U31,
        skip: usize,
        count: usize,
    ) -> Result<TransactionList, ControllerError<T>> {
        self.wallet
            .get_transaction_list(account_index, skip, count)
            .map_err(ControllerError::WalletError)
    }

    pub fn start_staking(&mut self, account_index: U31) -> Result<(), ControllerError<T>> {
        self.staking_started.insert(account_index);
        Ok(())
    }

    pub fn stop_staking(&mut self, account_index: U31) -> Result<(), ControllerError<T>> {
        self.staking_started.remove(&account_index);
        Ok(())
    }

    /// Wallet sync progress
    pub fn best_block(&self) -> (Id<GenBlock>, BlockHeight) {
        *self
            .wallet
            .get_best_block()
            .values()
            .min_by_key(|(_block_id, block_height)| block_height)
            .expect("there must be at least one account")
    }

    pub async fn get_stake_pool_balances(
        &self,
        account_index: U31,
    ) -> Result<BTreeMap<PoolId, Amount>, ControllerError<T>> {
        let stake_pool_utxos = self
            .wallet
            .get_utxos(
                account_index,
                UtxoType::CreateStakePool | UtxoType::ProduceBlockFromStake,
                UtxoState::Confirmed.into(),
            )
            .map_err(ControllerError::WalletError)?;
        let pool_ids = stake_pool_utxos.values().filter_map(|utxo| match utxo {
            TxOutput::ProduceBlockFromStake(_, pool_id) | TxOutput::CreateStakePool(pool_id, _) => {
                Some(pool_id)
            }
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => None,
        });
        let mut balances = BTreeMap::new();
        for pool_id in pool_ids {
            let balance_opt = self
                .rpc_client
                .get_stake_pool_balance(*pool_id)
                .await
                .map_err(ControllerError::NodeCallError)?;
            if let Some(balance) = balance_opt {
                balances.insert(*pool_id, balance);
            }
        }
        Ok(balances)
    }

    pub fn get_all_issued_addresses(
        &self,
        account_index: U31,
    ) -> Result<BTreeMap<ChildNumber, Address>, ControllerError<T>> {
        self.wallet
            .get_all_issued_addresses(account_index)
            .map_err(ControllerError::WalletError)
    }

    /// Synchronize the wallet to the current node tip height and return
    pub async fn sync_once(&mut self) -> Result<(), ControllerError<T>> {
        sync::sync_once(
            &self.chain_config,
            &self.rpc_client,
            &mut self.wallet,
            &mut self.wallet_events,
        )
        .await?;
        Ok(())
    }

    /// Synchronize the wallet in the background from the node's blockchain.
    /// Try staking new blocks if staking was started.
    pub async fn run(&mut self) -> Result<(), ControllerError<T>> {
        let mut rebroadcast_txs_timer = get_time();
        loop {
            let sync_res = self.sync_once().await;

            if let Err(e) = sync_res {
                log::error!("Wallet sync error: {e}");
                tokio::time::sleep(ERROR_DELAY).await;
                continue;
            }

            // TODO: Try to remove the `clone` call
            for account_index in self.staking_started.clone().iter() {
                let generate_res = self.generate_block(*account_index, None).await;

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

            self.rebroadcast_txs(&mut rebroadcast_txs_timer);
        }
    }

    /// Rebroadcast not confirmed transactions
    fn rebroadcast_txs(&mut self, rebroadcast_txs_timer: &mut Duration) {
        if get_time() >= *rebroadcast_txs_timer {
            let _ = self
                .wallet
                .get_transactions_to_be_broadcast()
                .map(|txs| async {
                    for tx in txs {
                        let tx_id = tx.transaction().get_id();
                        let res = self.rpc_client.submit_transaction(tx).await;
                        if let Err(e) = res {
                            log::warn!("Rebroadcasting for tx {tx_id} failed: {e}");
                        }
                    }
                })
                .log_err_pfx("Fetching transactions for rebroadcasting failed:");

            // Reset the timer with a new random interval between 2 and 5 minutes
            let sleep_interval_sec = make_pseudo_rng().gen_range(120..=300);
            *rebroadcast_txs_timer = get_time() + Duration::from_secs(sleep_interval_sec);
        }
    }
}
