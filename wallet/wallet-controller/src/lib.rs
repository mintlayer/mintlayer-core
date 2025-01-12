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

mod helpers;
pub mod mnemonic;
pub mod read;
mod runtime_wallet;
mod sync;
pub mod synced_controller;
pub mod types;

const NORMAL_DELAY: Duration = Duration::from_secs(1);
const ERROR_DELAY: Duration = Duration::from_secs(10);

use blockprod::BlockProductionError;
use chainstate::tx_verifier::{
    self, error::ScriptError, input_check::signature_only_check::SignatureOnlyVerifiable,
};
use futures::{never::Never, stream::FuturesOrdered, TryStreamExt};
use helpers::{fetch_token_info, fetch_utxo, fetch_utxo_extra_info, into_balances};
use node_comm::rpc_client::ColdWalletClient;
use runtime_wallet::RuntimeWallet;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    ops::Add,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use types::{
    Balances, GenericCurrencyTransferToTxOutputConversionError, InspectTransaction,
    SeedWithPassPhrase, SignatureStats, TransactionToInspect, ValidatedSignatures, WalletInfo,
    WalletTypeArgsComputed,
};
use wallet_storage::DefaultBackend;

use read::ReadOnlyController;
use sync::InSync;
use synced_controller::SyncedController;

use common::{
    address::AddressError,
    chain::{
        block::timestamp::BlockTimestamp,
        htlc::HtlcSecret,
        signature::{inputsig::InputWitness, DestinationSigError, Transactable},
        tokens::{RPCTokenInfo, TokenId},
        Block, ChainConfig, Destination, GenBlock, OrderId, PoolId, RpcOrderInfo,
        SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{
        time::{get_time, Time},
        Amount, BlockHeight, Id, Idable,
    },
};
use consensus::{GenerateBlockInputData, PoSTimestampSearchInputData};
use crypto::{ephemeral_e2e::EndToEndPrivateKey, key::hdkd::u31::U31};
use logging::log;
use mempool::tx_accumulator::PackingStrategy;
pub use node_comm::node_traits::{ConnectedPeer, NodeInterface, PeerId};
pub use node_comm::{
    handles_client::WalletHandlesClient, make_cold_wallet_rpc_client, make_rpc_client,
    rpc_client::NodeRpcClient,
};
use randomness::{make_pseudo_rng, make_true_rng, Rng};
#[cfg(feature = "trezor")]
use wallet::signer::trezor_signer::TrezorSignerProvider;
#[cfg(feature = "trezor")]
use wallet::signer::SignerError;

use wallet::{
    account::{
        currency_grouper::{self},
        TransactionToSign,
    },
    destination_getters::{get_tx_output_destination, HtlcSpendingCondition},
    signer::software_signer::SoftwareSignerProvider,
    wallet::WalletPoolsFilter,
    wallet_events::WalletEvents,
    WalletError, WalletResult,
};

pub use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    utxo_types::{UtxoState, UtxoStates, UtxoType, UtxoTypes},
};
use wallet_types::{
    partially_signed_transaction::{PartiallySignedTransaction, TxAdditionalInfo},
    signature_status::SignatureStatus,
    wallet_type::{WalletControllerMode, WalletType},
    with_locked::WithLocked,
    Currency,
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
    WalletError(#[from] wallet::wallet::WalletError),
    #[error("Encoding error: {0}")]
    AddressEncodingError(#[from] AddressError),
    #[error("No staking pool found")]
    NoStakingPool,
    #[error("Token with Id {0} is frozen")]
    FrozenToken(TokenId),
    #[error("Wallet is locked")]
    WalletIsLocked,
    #[error("Cannot lock wallet because staking is running")]
    StakingRunning,
    #[error("End-to-end encryption error: {0}")]
    EndToEndEncryptionError(#[from] crypto::ephemeral_e2e::error::Error),
    #[error("The node is not in sync yet")]
    NodeNotInSyncYet,
    #[error("Lookahead size cannot be 0")]
    InvalidLookaheadSize,
    #[error("Wallet file already open")]
    WalletFileAlreadyOpen,
    #[error("Please open or create wallet file first")]
    NoWallet,
    #[error("Search for timestamps failed: {0}")]
    SearchForTimestampsFailed(BlockProductionError),
    #[error("Expecting non-empty inputs")]
    ExpectingNonEmptyInputs,
    #[error("Expecting non-empty outputs")]
    ExpectingNonEmptyOutputs,
    #[error("No coin UTXOs to pay fee from")]
    NoCoinUtxosToPayFeeFrom,
    #[error("Invalid tx output: {0}")]
    InvalidTxOutput(GenericCurrencyTransferToTxOutputConversionError),
    #[error("The specified token {0} is not a fungible token")]
    NotFungibleToken(TokenId),
}

#[derive(Clone, Copy)]
pub struct ControllerConfig {
    /// In which top N MB should we aim for our transactions to be in the mempool
    /// e.g. for 5, we aim to be in the top 5 MB of transactions based on paid fees
    /// This is to avoid getting trimmed off the lower end if the mempool runs out of memory
    pub in_top_x_mb: usize,

    /// Should the controller broadcast the created transactions to the mempool
    /// Set to False by the GUI wallet to allow for a confirmation dialog before broadcasting
    pub broadcast_to_mempool: bool,
}

pub struct Controller<T, W, B: storage::Backend + 'static> {
    chain_config: Arc<ChainConfig>,

    rpc_client: T,

    wallet: RuntimeWallet<B>,

    staking_started: BTreeSet<U31>,

    wallet_events: W,
}

impl<T, WalletEvents, B: storage::Backend> std::fmt::Debug for Controller<T, WalletEvents, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller").finish()
    }
}

pub type RpcController<N, WalletEvents> = Controller<N, WalletEvents, DefaultBackend>;
pub type HandlesController<WalletEvents> =
    Controller<WalletHandlesClient, WalletEvents, DefaultBackend>;
pub type ColdController<WalletEvents> = Controller<ColdWalletClient, WalletEvents, DefaultBackend>;

impl<T, W> Controller<T, W, DefaultBackend>
where
    T: NodeInterface + Clone + Send + Sync + 'static,
    W: WalletEvents,
{
    pub async fn new(
        chain_config: Arc<ChainConfig>,
        rpc_client: T,
        wallet: RuntimeWallet<DefaultBackend>,
        wallet_events: W,
    ) -> Result<Self, ControllerError<T>> {
        let mut controller = Self {
            chain_config,
            rpc_client,
            wallet,
            staking_started: BTreeSet::new(),
            wallet_events,
        };

        log::info!("Syncing the wallet...");
        controller.try_sync_once().await?;

        Ok(controller)
    }

    pub fn new_unsynced(
        chain_config: Arc<ChainConfig>,
        rpc_client: T,
        wallet: RuntimeWallet<DefaultBackend>,
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
        args: WalletTypeArgsComputed,
        best_block: (BlockHeight, Id<GenBlock>),
        wallet_type: WalletType,
    ) -> Result<RuntimeWallet<DefaultBackend>, ControllerError<T>> {
        utils::ensure!(
            !file_path.as_ref().exists(),
            ControllerError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File already exists".to_owned()
            )
        );

        let db = wallet::wallet::open_or_create_wallet_file(file_path)
            .map_err(ControllerError::WalletError)?;
        match args {
            WalletTypeArgsComputed::Software {
                mnemonic,
                passphrase,
                store_seed_phrase,
            } => {
                let passphrase_ref = passphrase.as_ref().map(|x| x.as_ref());

                let wallet = wallet::Wallet::create_new_wallet(
                    Arc::clone(&chain_config),
                    db,
                    best_block,
                    wallet_type,
                    |db_tx| {
                        Ok(SoftwareSignerProvider::new_from_mnemonic(
                            chain_config.clone(),
                            db_tx,
                            &mnemonic.to_string(),
                            passphrase_ref,
                            store_seed_phrase,
                        )?)
                    },
                )
                .map_err(ControllerError::WalletError)?;
                Ok(RuntimeWallet::Software(wallet))
            }
            #[cfg(feature = "trezor")]
            WalletTypeArgsComputed::Trezor => {
                let wallet = wallet::Wallet::create_new_wallet(
                    Arc::clone(&chain_config),
                    db,
                    best_block,
                    wallet_type,
                    |_db_tx| Ok(TrezorSignerProvider::new().map_err(SignerError::TrezorError)?),
                )
                .map_err(ControllerError::WalletError)?;
                Ok(RuntimeWallet::Trezor(wallet))
            }
        }
    }

    pub fn recover_wallet(
        chain_config: Arc<ChainConfig>,
        file_path: impl AsRef<Path>,
        args: WalletTypeArgsComputed,
        wallet_type: WalletType,
    ) -> Result<RuntimeWallet<DefaultBackend>, ControllerError<T>> {
        utils::ensure!(
            !file_path.as_ref().exists(),
            ControllerError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File already exists".to_owned()
            )
        );

        let db = wallet::wallet::open_or_create_wallet_file(file_path)
            .map_err(ControllerError::WalletError)?;

        match args {
            WalletTypeArgsComputed::Software {
                mnemonic,
                passphrase,
                store_seed_phrase,
            } => {
                let passphrase_ref = passphrase.as_ref().map(|x| x.as_ref());

                let wallet = wallet::Wallet::recover_wallet(
                    Arc::clone(&chain_config),
                    db,
                    wallet_type,
                    |db_tx| {
                        Ok(SoftwareSignerProvider::new_from_mnemonic(
                            chain_config.clone(),
                            db_tx,
                            &mnemonic.to_string(),
                            passphrase_ref,
                            store_seed_phrase,
                        )?)
                    },
                )
                .map_err(ControllerError::WalletError)?;
                Ok(RuntimeWallet::Software(wallet))
            }
            #[cfg(feature = "trezor")]
            WalletTypeArgsComputed::Trezor => {
                let wallet = wallet::Wallet::recover_wallet(
                    Arc::clone(&chain_config),
                    db,
                    wallet_type,
                    |_db_tx| Ok(TrezorSignerProvider::new().map_err(SignerError::TrezorError)?),
                )
                .map_err(ControllerError::WalletError)?;
                Ok(RuntimeWallet::Trezor(wallet))
            }
        }
    }

    fn make_backup_wallet_file(file_path: impl AsRef<Path>, version: u32) -> WalletResult<()> {
        let backup_name = file_path
            .as_ref()
            .file_name()
            .map(|file_name| {
                let mut file_name = file_name.to_os_string();
                file_name.push(format!("_backup_v{version}"));
                file_name
            })
            .ok_or(WalletError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File path is not a file".to_owned(),
            ))?;
        let backup_file_path = file_path.as_ref().with_file_name(backup_name);
        logging::log::info!(
            "The wallet DB requires a migration, creating a backup file: {}",
            backup_file_path.to_string_lossy()
        );
        fs::copy(&file_path, backup_file_path).map_err(|_| {
            WalletError::WalletFileError(
                file_path.as_ref().to_owned(),
                "Could not make a backup of the file before migrating it".to_owned(),
            )
        })?;
        Ok(())
    }

    pub fn open_wallet(
        chain_config: Arc<ChainConfig>,
        file_path: impl AsRef<Path>,
        password: Option<String>,
        current_controller_mode: WalletControllerMode,
        force_change_wallet_type: bool,
        open_as_wallet_type: WalletType,
    ) -> Result<RuntimeWallet<DefaultBackend>, ControllerError<T>> {
        utils::ensure!(
            file_path.as_ref().exists(),
            ControllerError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File does not exist".to_owned()
            )
        );

        let db = wallet::wallet::open_or_create_wallet_file(&file_path)
            .map_err(ControllerError::WalletError)?;

        match open_as_wallet_type {
            WalletType::Cold | WalletType::Hot => {
                let wallet = wallet::Wallet::load_wallet(
                    Arc::clone(&chain_config),
                    db,
                    password,
                    |version| Self::make_backup_wallet_file(file_path.as_ref(), version),
                    current_controller_mode,
                    force_change_wallet_type,
                    |db_tx| SoftwareSignerProvider::load_from_database(chain_config.clone(), db_tx),
                )
                .map_err(ControllerError::WalletError)?;
                Ok(RuntimeWallet::Software(wallet))
            }
            #[cfg(feature = "trezor")]
            WalletType::Trezor => {
                let wallet = wallet::Wallet::load_wallet(
                    Arc::clone(&chain_config),
                    db,
                    password,
                    |version| Self::make_backup_wallet_file(file_path.as_ref(), version),
                    current_controller_mode,
                    force_change_wallet_type,
                    |db_tx| TrezorSignerProvider::load_from_database(chain_config.clone(), db_tx),
                )
                .map_err(ControllerError::WalletError)?;
                Ok(RuntimeWallet::Trezor(wallet))
            }
        }
    }

    pub fn seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, ControllerError<T>> {
        self.wallet
            .seed_phrase()
            .map(|opt| opt.map(SeedWithPassPhrase::from_serializable_seed_phrase))
            .map_err(ControllerError::WalletError)
    }

    /// Delete the seed phrase if stored in the database
    pub fn delete_seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, ControllerError<T>> {
        self.wallet
            .delete_seed_phrase()
            .map(|opt| opt.map(SeedWithPassPhrase::from_serializable_seed_phrase))
            .map_err(ControllerError::WalletError)
    }

    /// Rescan the blockchain
    /// Resets the wallet to the genesis block
    pub fn reset_wallet_to_genesis(&mut self) -> Result<(), ControllerError<T>> {
        self.wallet.reset_wallet_to_genesis().map_err(ControllerError::WalletError)
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
        utils::ensure!(
            self.staking_started.is_empty(),
            ControllerError::StakingRunning
        );
        self.wallet.lock_wallet().map_err(ControllerError::WalletError)
    }

    /// Sets the lookahead size for key generation
    ///
    /// # Returns
    ///
    /// This method returns an error if you try to set lookahead size to 0
    pub fn set_lookahead_size(
        &mut self,
        lookahead_size: u32,
        force_reduce: bool,
    ) -> Result<(), ControllerError<T>> {
        utils::ensure!(lookahead_size > 0, ControllerError::InvalidLookaheadSize);

        self.wallet
            .set_lookahead_size(lookahead_size, force_reduce)
            .map_err(ControllerError::WalletError)
    }

    pub fn wallet_info(&self) -> WalletInfo {
        let (wallet_id, account_names) = self.wallet.wallet_info();
        WalletInfo {
            wallet_id,
            account_names,
        }
    }

    pub async fn get_token_number_of_decimals(
        &self,
        token_id: TokenId,
    ) -> Result<u8, ControllerError<T>> {
        Ok(self.get_token_info(token_id).await?.token_number_of_decimals())
    }

    pub async fn get_token_info(
        &self,
        token_id: TokenId,
    ) -> Result<RPCTokenInfo, ControllerError<T>> {
        fetch_token_info(&self.rpc_client, token_id).await
    }

    pub async fn get_order_info(
        &self,
        order_id: OrderId,
    ) -> Result<RpcOrderInfo, ControllerError<T>> {
        self.rpc_client
            .get_order_info(order_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::WalletError(WalletError::UnknownOrderId(
                order_id,
            )))
    }

    pub async fn generate_block_by_pool(
        &self,
        account_index: U31,
        pool_id: PoolId,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, ControllerError<T>> {
        let pos_data = self
            .wallet
            .get_pos_gen_block_data(account_index, pool_id)
            .map_err(ControllerError::WalletError)?;

        let public_key = self
            .rpc_client
            .blockprod_e2e_public_key()
            .await
            .map_err(ControllerError::NodeCallError)?;

        let input_data = GenerateBlockInputData::PoS(pos_data.into());

        let mut rng = make_true_rng();
        let ephemeral_private_key = EndToEndPrivateKey::new_from_rng(&mut rng);
        let ephemeral_public_key = ephemeral_private_key.public_key();
        let shared_secret = ephemeral_private_key.shared_secret(&public_key);
        let encrypted_input_data = shared_secret.encode_then_encrypt(&input_data, &mut rng)?;

        self.rpc_client
            .generate_block_e2e(
                encrypted_input_data,
                ephemeral_public_key,
                transactions,
                transaction_ids,
                packing_strategy,
            )
            .await
            .map_err(ControllerError::NodeCallError)
    }

    /// Attempt to generate a new block by trying all pools. If all pools fail,
    /// the last pool block generation error is returned (or `ControllerError::NoStakingPool` if there are no staking pools).
    pub async fn generate_block(
        &self,
        account_index: U31,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, ControllerError<T>> {
        let pools = self
            .wallet
            .get_pool_ids(account_index, WalletPoolsFilter::Stake)
            .map_err(ControllerError::WalletError)?;

        let mut last_error = ControllerError::NoStakingPool;
        for (pool_id, _) in pools {
            let block_res = self
                .generate_block_by_pool(
                    account_index,
                    pool_id,
                    transactions.clone(),
                    transaction_ids.clone(),
                    packing_strategy,
                )
                .await;
            match block_res {
                Ok(block) => return Ok(block),
                Err(err) => last_error = err,
            }
        }
        Err(last_error)
    }

    /// Try to generate the `block_count` number of blocks.
    /// The function may return an error early if some attempt fails.
    pub async fn generate_blocks(
        &mut self,
        account_index: U31,
        block_count: u32,
    ) -> Result<(), ControllerError<T>> {
        for _ in 0..block_count {
            self.sync_once().await?;
            let block = self
                .generate_block(
                    account_index,
                    vec![],
                    vec![],
                    PackingStrategy::FillSpaceFromMempool,
                )
                .await?;

            self.rpc_client
                .submit_block(block)
                .await
                .map_err(ControllerError::NodeCallError)?;
        }

        self.sync_once().await
    }

    /// For each block height in the specified range, find timestamps where staking is/was possible
    /// for the given pool.
    ///
    /// `min_height` must not be zero; `max_height` must not exceed the best block height plus one.
    ///
    /// If `check_all_timestamps_between_blocks` is `false`, `seconds_to_check_for_height + 1` is the number
    /// of seconds that will be checked at each height in the range.
    /// If `check_all_timestamps_between_blocks` is `true`, `seconds_to_check_for_height` only applies to the
    /// last height in the range; for all other heights the maximum timestamp is the timestamp
    /// of the next block.
    pub async fn find_timestamps_for_staking(
        &self,
        pool_id: PoolId,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        check_all_timestamps_between_blocks: bool,
    ) -> Result<BTreeMap<BlockHeight, Vec<BlockTimestamp>>, ControllerError<T>> {
        let pos_data = self
            .wallet
            .get_pos_gen_block_data_by_pool_id(pool_id)
            .map_err(ControllerError::WalletError)?;

        let input_data =
            PoSTimestampSearchInputData::new(pool_id, pos_data.vrf_private_key().clone());

        let search_data = self
            .rpc_client
            .collect_timestamp_search_data(
                pool_id,
                min_height,
                max_height,
                seconds_to_check_for_height,
                check_all_timestamps_between_blocks,
            )
            .await
            .map_err(ControllerError::NodeCallError)?;

        blockprod::find_timestamps_for_staking(input_data, search_data)
            .await
            .map_err(|err| ControllerError::SearchForTimestampsFailed(err))
    }

    pub fn create_account(
        &mut self,
        name: Option<String>,
    ) -> Result<(U31, Option<String>), ControllerError<T>> {
        self.wallet.create_next_account(name).map_err(ControllerError::WalletError)
    }

    pub fn update_account_name(
        &mut self,
        account_index: U31,
        name: Option<String>,
    ) -> Result<(U31, Option<String>), ControllerError<T>> {
        self.wallet
            .set_account_name(account_index, name)
            .map_err(ControllerError::WalletError)
    }

    pub fn stop_staking(&mut self, account_index: U31) -> Result<(), ControllerError<T>> {
        log::info!("Stop staking, account_index: {}", account_index);
        self.staking_started.remove(&account_index);
        Ok(())
    }

    pub fn is_staking(&mut self, account_index: U31) -> bool {
        self.staking_started.contains(&account_index)
    }

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
                WithLocked::Unlocked,
            )
            .map_err(ControllerError::WalletError)?;
        let pool_ids = stake_pool_utxos.into_iter().filter_map(|(_, utxo)| match utxo {
            TxOutput::ProduceBlockFromStake(_, pool_id) | TxOutput::CreateStakePool(pool_id, _) => {
                Some(pool_id)
            }
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => None,
        });
        let mut balances = BTreeMap::new();
        for pool_id in pool_ids {
            let balance_opt = self
                .rpc_client
                .get_stake_pool_balance(pool_id)
                .await
                .map_err(ControllerError::NodeCallError)?;
            if let Some(balance) = balance_opt {
                balances.insert(pool_id, balance);
            }
        }
        Ok(balances)
    }

    /// Synchronize the wallet to the current node tip height and return
    pub async fn sync_once(&mut self) -> Result<(), ControllerError<T>> {
        let res = match &mut self.wallet {
            RuntimeWallet::Software(w) => {
                sync::sync_once(&self.chain_config, &self.rpc_client, w, &self.wallet_events).await
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => {
                sync::sync_once(&self.chain_config, &self.rpc_client, w, &self.wallet_events).await
            }
        }?;

        match res {
            InSync::Synced => Ok(()),
            InSync::NodeOutOfSync => Err(ControllerError::NodeNotInSyncYet),
        }
    }

    pub async fn try_sync_once(&mut self) -> Result<(), ControllerError<T>> {
        match &mut self.wallet {
            RuntimeWallet::Software(w) => {
                sync::sync_once(&self.chain_config, &self.rpc_client, w, &self.wallet_events)
                    .await?;
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => {
                sync::sync_once(&self.chain_config, &self.rpc_client, w, &self.wallet_events)
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn synced_controller(
        &mut self,
        account_index: U31,
        config: ControllerConfig,
    ) -> Result<SyncedController<'_, T, W, DefaultBackend>, ControllerError<T>> {
        self.sync_once().await?;
        Ok(SyncedController::new(
            &mut self.wallet,
            self.rpc_client.clone(),
            self.chain_config.as_ref(),
            &self.wallet_events,
            &mut self.staking_started,
            account_index,
            config,
        ))
    }

    pub fn readonly_controller(
        &self,
        account_index: U31,
    ) -> ReadOnlyController<'_, T, DefaultBackend> {
        ReadOnlyController::new(
            &self.wallet,
            self.rpc_client.clone(),
            self.chain_config.as_ref(),
            account_index,
        )
    }

    pub async fn inspect_transaction(
        &self,
        tx: TransactionToInspect,
    ) -> Result<InspectTransaction, ControllerError<T>> {
        let result = match tx {
            TransactionToInspect::Tx(tx) => self.inspect_tx(tx).await?,
            TransactionToInspect::Partial(ptx) => self.inspect_partial_tx(ptx).await?,
            TransactionToInspect::Signed(stx) => self.inspect_signed_tx(stx).await?,
        };

        Ok(result)
    }

    async fn inspect_signed_tx(
        &self,
        stx: SignedTransaction,
    ) -> Result<InspectTransaction, ControllerError<T>> {
        let (fees, signature_statuses) = match self.calculate_fees_and_valid_signatures(&stx).await
        {
            Ok((fees, num_valid_signatures)) => (Some(fees), Some(num_valid_signatures)),
            Err(_) => (None, None),
        };

        let num_inputs = stx.inputs().len();
        let total_signatures = stx.signatures().len();
        let validated_signatures = signature_statuses.map(|signature_statuses| {
            let num_invalid_signatures = signature_statuses
                .iter()
                .copied()
                .filter(|x| *x == SignatureStatus::InvalidSignature)
                .count();
            let num_valid_signatures = signature_statuses
                .iter()
                .copied()
                .filter(|x| *x == SignatureStatus::FullySigned)
                .count();
            ValidatedSignatures {
                num_valid_signatures,
                num_invalid_signatures,
                signature_statuses,
            }
        });

        Ok(InspectTransaction {
            tx: stx.take_transaction().into(),
            fees,
            stats: SignatureStats {
                num_inputs,
                total_signatures,
                validated_signatures,
            },
        })
    }

    async fn calculate_fees_and_valid_signatures(
        &self,
        stx: &SignedTransaction,
    ) -> Result<(Balances, Vec<SignatureStatus>), ControllerError<T>> {
        let tasks: FuturesOrdered<_> =
            stx.inputs().iter().map(|input| self.fetch_opt_utxo(input)).collect();
        let input_utxos: Vec<Option<TxOutput>> = tasks.try_collect().await?;
        let only_input_utxos: Vec<_> = input_utxos.clone().into_iter().flatten().collect();
        let fees = self.get_fees(&only_input_utxos, stx.outputs()).await?;
        let inputs_utxos_refs: Vec<_> = input_utxos.iter().map(|out| out.as_ref()).collect();
        let destinations = inputs_utxos_refs
            .iter()
            .map(|txo| {
                txo.map(|txo| {
                    get_tx_output_destination(txo, &|_| None, HtlcSpendingCondition::Skip)
                        .ok_or_else(|| {
                            WalletError::UnsupportedTransactionOutput(Box::new(txo.clone()))
                        })
                })
                .transpose()
            })
            .collect::<Result<Vec<_>, WalletError>>()
            .map_err(ControllerError::WalletError)?;
        let signature_statuses = stx
            .signatures()
            .iter()
            .enumerate()
            .zip(destinations)
            .map(|((input_num, w), d)| match (w, d) {
                (InputWitness::NoSignature(_), None) => SignatureStatus::FullySigned,
                (InputWitness::NoSignature(_), Some(_)) => SignatureStatus::NotSigned,
                (InputWitness::Standard(_), None) => SignatureStatus::InvalidSignature,
                (InputWitness::Standard(_), Some(dest)) => {
                    self.verify_tx_signature(stx, &inputs_utxos_refs, input_num, &dest)
                }
            })
            .collect();
        Ok((fees, signature_statuses))
    }

    async fn inspect_partial_tx(
        &self,
        ptx: PartiallySignedTransaction,
    ) -> Result<InspectTransaction, ControllerError<T>> {
        let input_utxos: Vec<_> = ptx.input_utxos().iter().flatten().cloned().collect();
        let fees = self.get_fees(&input_utxos, ptx.tx().outputs()).await?;
        let inputs_utxos_refs: Vec<_> = ptx.input_utxos().iter().map(|out| out.as_ref()).collect();
        let signature_statuses: Vec<_> = ptx
            .witnesses()
            .iter()
            .enumerate()
            .zip(ptx.destinations())
            .map(|((input_num, w), d)| match (w, d) {
                (Some(InputWitness::NoSignature(_)), None) => SignatureStatus::FullySigned,
                (Some(InputWitness::NoSignature(_)), Some(_)) => SignatureStatus::InvalidSignature,
                (Some(InputWitness::Standard(_)), None) => SignatureStatus::UnknownSignature,
                (Some(InputWitness::Standard(_)), Some(dest)) => {
                    self.verify_tx_signature(&ptx, &inputs_utxos_refs, input_num, dest)
                }
                (None, _) => SignatureStatus::NotSigned,
            })
            .collect();
        let num_inputs = ptx.count_inputs();
        let total_signatures = signature_statuses
            .iter()
            .copied()
            .filter(|x| *x != SignatureStatus::NotSigned)
            .count();
        Ok(InspectTransaction {
            tx: ptx.take_tx().into(),
            fees: Some(fees),
            stats: SignatureStats {
                num_inputs,
                total_signatures,
                validated_signatures: Some(ValidatedSignatures::new(signature_statuses)),
            },
        })
    }

    async fn inspect_tx(&self, tx: Transaction) -> Result<InspectTransaction, ControllerError<T>> {
        let inputs: Vec<_> = tx
            .inputs()
            .iter()
            .filter_map(|inp| match inp {
                TxInput::Utxo(utxo) => Some(utxo.clone()),
                TxInput::Account(_) => None,
                TxInput::AccountCommand(_, _) => None,
            })
            .collect();
        let fees = match self.fetch_utxos(&inputs).await {
            Ok(input_utxos) => Some(self.get_fees(&input_utxos, tx.outputs()).await?),
            Err(_) => None,
        };
        let num_inputs = tx.inputs().len();
        Ok(InspectTransaction {
            tx: tx.into(),
            fees,
            stats: SignatureStats {
                num_inputs,
                total_signatures: 0,
                validated_signatures: Some(ValidatedSignatures::new(vec![])),
            },
        })
    }

    fn verify_tx_signature(
        &self,
        tx: &(impl Transactable + SignatureOnlyVerifiable),
        inputs_utxos_refs: &[Option<&TxOutput>],
        input_num: usize,
        dest: &Destination,
    ) -> SignatureStatus {
        let valid = tx_verifier::input_check::signature_only_check::verify_tx_signature(
            &self.chain_config,
            dest,
            tx,
            inputs_utxos_refs,
            input_num,
        );

        match valid {
            Ok(_) => SignatureStatus::FullySigned,
            Err(e) => match e.error() {
                tx_verifier::error::InputCheckErrorPayload::MissingUtxo(_)
                | tx_verifier::error::InputCheckErrorPayload::UtxoView(_)
                | tx_verifier::error::InputCheckErrorPayload::Translation(_) => {
                    SignatureStatus::InvalidSignature
                }

                tx_verifier::error::InputCheckErrorPayload::Verification(
                    ScriptError::Signature(
                        DestinationSigError::IncompleteClassicalMultisigSignature(
                            required_signatures,
                            num_signatures,
                        ),
                    ),
                ) => SignatureStatus::PartialMultisig {
                    required_signatures: *required_signatures,
                    num_signatures: *num_signatures,
                },

                _ => SignatureStatus::InvalidSignature,
            },
        }
    }

    pub async fn compose_transaction(
        &self,
        inputs: Vec<UtxoOutPoint>,
        outputs: Vec<TxOutput>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        only_transaction: bool,
    ) -> Result<(TransactionToSign, Balances), ControllerError<T>> {
        let input_utxos = self.fetch_utxos(&inputs).await?;
        let fees = self.get_fees(&input_utxos, &outputs).await?;

        let num_inputs = inputs.len();
        let inputs = inputs.into_iter().map(TxInput::Utxo).collect();

        let tx = Transaction::new(0, inputs, outputs)
            .map_err(|err| ControllerError::WalletError(WalletError::TransactionCreation(err)))?;

        let tx = if only_transaction {
            TransactionToSign::Tx(tx)
        } else {
            let destinations = input_utxos
                .iter()
                .enumerate()
                .map(|(i, txo)| {
                    let htlc_spending =
                        htlc_secrets.as_ref().map_or(HtlcSpendingCondition::Skip, |secrets| {
                            secrets.get(i).map_or(HtlcSpendingCondition::WithMultisig, |_| {
                                HtlcSpendingCondition::WithSecret
                            })
                        });

                    get_tx_output_destination(txo, &|_| None, htlc_spending).ok_or_else(|| {
                        WalletError::UnsupportedTransactionOutput(Box::new(txo.clone()))
                    })
                })
                .collect::<Result<Vec<_>, WalletError>>()
                .map_err(ControllerError::WalletError)?;

            let (input_utxos, additional_infos) =
                self.fetch_utxos_extra_info(input_utxos).await?.into_iter().fold(
                    (Vec::new(), TxAdditionalInfo::new()),
                    |(mut input_utxos, additional_info), (x, y)| {
                        input_utxos.push(x);
                        (input_utxos, additional_info.join(y))
                    },
                );

            let additional_infos = self
                .fetch_utxos_extra_info(tx.outputs().to_vec())
                .await?
                .into_iter()
                .fold(additional_infos, |acc, (_, info)| acc.join(info));
            let tx = PartiallySignedTransaction::new(
                tx,
                vec![None; num_inputs],
                input_utxos.into_iter().map(Option::Some).collect(),
                destinations.into_iter().map(Option::Some).collect(),
                htlc_secrets,
                additional_infos,
            )
            .map_err(WalletError::PartiallySignedTransactionCreation)?;

            TransactionToSign::Partial(tx)
        };

        Ok((tx, fees))
    }

    async fn get_fees(
        &self,
        inputs: &[TxOutput],
        outputs: &[TxOutput],
    ) -> Result<Balances, ControllerError<T>> {
        let mut inputs = self.group_inputs(inputs)?;
        let outputs = self.group_outputs(outputs)?;

        let mut fees = BTreeMap::new();

        for (currency, output) in outputs {
            let input_amount = inputs.remove(&currency).ok_or(
                ControllerError::<T>::WalletError(WalletError::NotEnoughUtxo(Amount::ZERO, output)),
            )?;

            let fee = (input_amount - output).ok_or(ControllerError::<T>::WalletError(
                WalletError::NotEnoughUtxo(input_amount, output),
            ))?;
            fees.insert(currency, fee);
        }
        // add any leftover inputs
        fees.extend(inputs);

        into_balances(&self.rpc_client, &self.chain_config, fees).await
    }

    fn group_outputs(
        &self,
        outputs: &[TxOutput],
    ) -> Result<BTreeMap<Currency, Amount>, ControllerError<T>> {
        let best_block_height = self.best_block().1;
        currency_grouper::group_outputs_with_issuance_fee(
            outputs.iter(),
            |&output| output,
            |grouped: &mut Amount, _, new_amount| -> Result<(), WalletError> {
                *grouped = grouped.add(new_amount).ok_or(WalletError::OutputAmountOverflow)?;
                Ok(())
            },
            Amount::ZERO,
            &self.chain_config,
            best_block_height,
        )
        .map_err(|err| ControllerError::WalletError(err))
    }

    fn group_inputs(
        &self,
        input_utxos: &[TxOutput],
    ) -> Result<BTreeMap<Currency, Amount>, ControllerError<T>> {
        currency_grouper::group_utxos_for_input(
            input_utxos.iter(),
            |tx_output| tx_output,
            |total: &mut Amount, _, amount| -> Result<(), WalletError> {
                *total = (*total + amount).ok_or(WalletError::OutputAmountOverflow)?;
                Ok(())
            },
            Amount::ZERO,
        )
        .map_err(|err| ControllerError::WalletError(err))
    }

    async fn fetch_utxos(
        &self,
        inputs: &[UtxoOutPoint],
    ) -> Result<Vec<TxOutput>, ControllerError<T>> {
        let tasks: FuturesOrdered<_> = inputs
            .iter()
            .map(|input| fetch_utxo(&self.rpc_client, input, &self.wallet))
            .collect();
        let input_utxos: Vec<TxOutput> = tasks.try_collect().await?;
        Ok(input_utxos)
    }

    async fn fetch_utxos_extra_info(
        &self,
        inputs: Vec<TxOutput>,
    ) -> Result<Vec<(TxOutput, TxAdditionalInfo)>, ControllerError<T>> {
        let tasks: FuturesOrdered<_> = inputs
            .into_iter()
            .map(|input| fetch_utxo_extra_info(&self.rpc_client, input))
            .collect();
        tasks.try_collect().await
    }

    async fn fetch_opt_utxo(
        &self,
        input: &TxInput,
    ) -> Result<Option<TxOutput>, ControllerError<T>> {
        match input {
            TxInput::Utxo(utxo) => fetch_utxo(&self.rpc_client, utxo, &self.wallet).await.map(Some),
            TxInput::Account(_) => Ok(None),
            TxInput::AccountCommand(_, _) => Ok(None),
        }
    }

    /// Synchronize the wallet in the background from the node's blockchain.
    /// Try staking new blocks if staking was started.
    pub async fn run(&mut self) -> Result<Never, ControllerError<T>> {
        let mut rebroadcast_txs_timer = get_time();
        let staking_started = self.staking_started.clone();

        'outer: loop {
            let sync_res = self.sync_once().await;

            if let Err(e) = sync_res {
                log::error!("Wallet sync error: {e}");
                tokio::time::sleep(ERROR_DELAY).await;
                continue;
            }

            for account_index in staking_started.iter() {
                let generate_res = self
                    .generate_block(
                        *account_index,
                        vec![],
                        vec![],
                        PackingStrategy::FillSpaceFromMempool,
                    )
                    .await;

                if let Ok(block) = generate_res {
                    log::info!(
                        "New block generated successfully, with block id: {:x}",
                        block.get_id()
                    );

                    let submit_res = self.rpc_client.submit_block(block).await;
                    if let Err(e) = submit_res {
                        log::error!("Block submit failed: {e}");
                        tokio::time::sleep(ERROR_DELAY).await;
                    }

                    continue 'outer;
                }
            }

            tokio::time::sleep(NORMAL_DELAY).await;

            self.rebroadcast_txs(&mut rebroadcast_txs_timer).await;
        }
    }

    /// Rebroadcast not confirmed transactions
    async fn rebroadcast_txs(&mut self, rebroadcast_txs_again_at: &mut Time) {
        if get_time() >= *rebroadcast_txs_again_at {
            let txs = self.wallet.get_transactions_to_be_broadcast();
            match txs {
                Err(error) => {
                    log::error!("Fetching transactions for rebroadcasting failed: {error}");
                }
                Ok(txs) => {
                    for tx in txs {
                        let tx_id = tx.transaction().get_id();
                        let res = self.rpc_client.submit_transaction(tx, Default::default()).await;
                        if let Err(e) = res {
                            log::warn!("Rebroadcasting for tx {tx_id} failed: {e}");
                        }
                    }
                }
            }

            // Reset the timer with a new random interval between 2 and 5 minutes
            let sleep_interval_sec = make_pseudo_rng().gen_range(120..=300);
            *rebroadcast_txs_again_at = (get_time() + Duration::from_secs(sleep_interval_sec))
                .expect("Sleep intervals cannot be this large");
        }
    }
}
