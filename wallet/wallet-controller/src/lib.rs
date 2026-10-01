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
mod rebroadcast;
mod runtime_wallet;
mod sync;
pub mod synced_controller;
#[cfg(test)]
mod tests;
pub mod types;

const NORMAL_DELAY: Duration = Duration::from_secs(1);
const ERROR_DELAY: Duration = Duration::from_secs(10);

use blockprod::BlockProductionError;
use chainstate::tx_verifier::{
    self, error::ScriptError, input_check::signature_only_check::SignatureOnlyVerifiable,
};
use futures::StreamExt;
use futures::{TryStreamExt, never::Never, stream::FuturesOrdered};
use helpers::{
    fetch_input_infos, fetch_rpc_token_info, fetch_utxo, fetch_utxo_extra_info, into_balances,
};
use itertools::Itertools as _;
use mempool::MempoolConfig;
use node_comm::node_traits::NodeInterfaceError as _;
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
        AccountCommand, Block, ChainConfig, Currency, Destination, GenBlock, OrderAccountCommand,
        OrderId, OutPointSourceId, PoolId, SighashInputCommitmentVersion, SignedTransaction,
        Transaction, TxInput, TxOutput, UtxoOutPoint,
        block::timestamp::BlockTimestamp,
        htlc::HtlcSecret,
        output_value::OutputValue,
        signature::{
            DestinationSigError, Transactable, inputsig::InputWitness,
            sighash::input_commitments::SighashInputCommitment,
        },
        tokens::{RPCTokenInfo, TokenId},
    },
    primitives::{
        Amount, BlockHeight, Id, Idable,
        time::{Time, get_time},
    },
};
use consensus::{GenerateBlockInputData, PoSTimestampSearchInputData};
use crypto::{ephemeral_e2e::EndToEndPrivateKey, key::hdkd::u31::U31};
use logging::log;
use mempool::tx_accumulator::PackingStrategy;
pub use node_comm::node_traits::{
    ConnectedPeer, MempoolEvent, MempoolEvents, NodeInterface, PeerId,
};
pub use node_comm::{
    handles_client::WalletHandlesClient, make_cold_wallet_rpc_client, make_rpc_client,
    rpc_client::NodeRpcClient,
};
use randomness::{RngExt as _, make_pseudo_rng, make_true_rng};
#[cfg(feature = "trezor")]
use wallet::signer::SignerError;
#[cfg(feature = "ledger")]
use wallet::signer::ledger_signer::LedgerSignerProvider;
#[cfg(feature = "trezor")]
use wallet::signer::trezor_signer::{SelectedDevice, TrezorSignerProvider};

use wallet::{
    WalletError, WalletResult,
    account::{
        TransactionToSign,
        currency_grouper::{self},
    },
    destination_getters::{HtlcSpendingCondition, get_tx_output_destination},
    signer::software_signer::SoftwareSignerProvider,
    wallet::{WalletCreation, WalletPoolsFilter},
    wallet_events::WalletEvents,
};

pub use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    utxo_types::{UtxoState, UtxoStates, UtxoType, UtxoTypes},
};

#[cfg(any(feature = "trezor", feature = "ledger"))]
use wallet_types::hw_data::HardwareWalletFullInfo;
use wallet_types::{
    partially_signed_transaction::{
        OrderAdditionalInfo, PartiallySignedTransaction, PartiallySignedTransactionError,
        PartiallySignedTransactionWalletExt as _, PtxAdditionalInfo,
        SighashInputCommitmentCreationError, make_sighash_input_commitments,
    },
    signature_status::SignatureStatus,
    wallet_type::{WalletControllerMode, WalletType},
    with_locked::WithLocked,
};

use crate::types::WalletExtraInfo;

// Note: the standard `Debug` macro is not smart enough and requires N to implement the `Debug`
// trait even though only `N::Error` needs it. So we use `derive_more::Debug` instead.
#[derive(thiserror::Error, derive_more::Debug)]
pub enum ControllerError<N: NodeInterface> {
    #[error("Node call error: {0}")]
    NodeCallError(N::Error),

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

    #[error("Invalid coin amount")]
    InvalidCoinAmount,

    #[error("Partially signed transaction error: {0}")]
    PartiallySignedTransactionError(#[from] PartiallySignedTransactionError),

    #[error("Invalid token ID")]
    InvalidTokenId,

    #[error("Error creating sighash input commitment")]
    SighashInputCommitmentCreationError(#[from] SighashInputCommitmentCreationError),

    #[error("The number of htlc secrets does not match the number of inputs")]
    InvalidHtlcSecretsCount,
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
    wallet_mode: WalletControllerMode,

    staking_started: BTreeSet<U31>,

    wallet_events: W,

    mempool_events: MempoolEvents,
    should_rescan_mempool_txs: bool,

    repush_tracker: rebroadcast::RepushTracker,
}

impl<T, WalletEvents, B: storage::Backend> std::fmt::Debug for Controller<T, WalletEvents, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller").finish()
    }
}

pub type RpcController<N, WalletEvents> = Controller<N, WalletEvents, DefaultBackend>;

impl<N, W, B> Controller<N, W, B>
where
    N: NodeInterface + Clone + Send + Sync + 'static,
    W: WalletEvents,
    B: storage::BackendWithSendableTransactions + 'static,
{
    pub async fn new(
        chain_config: Arc<ChainConfig>,
        rpc_client: N,
        wallet: RuntimeWallet<B>,
        wallet_events: W,
    ) -> Result<Self, ControllerError<N>> {
        let mut controller =
            Self::new_unsynced(chain_config, rpc_client, wallet, wallet_events).await?;

        // In the cold mode, try_sync_once is a no-op, so it doesn't matter whether we call it.
        // We omit the call to avoid printing the "Syncing the wallet" log line, which looks
        // confusing in the cold mode.
        match controller.wallet_mode {
            WalletControllerMode::Cold => {}
            WalletControllerMode::Hot => {
                log::info!("Syncing the wallet...");
                controller.try_sync_once().await?;
            }
        };

        Ok(controller)
    }

    pub async fn new_unsynced(
        chain_config: Arc<ChainConfig>,
        rpc_client: N,
        wallet: RuntimeWallet<B>,
        wallet_events: W,
    ) -> Result<Self, ControllerError<N>> {
        let wallet_mode = rpc_client.is_cold_wallet_node().await;

        let mempool_events = rpc_client
            .mempool_subscribe_to_events()
            .await
            .map_err(ControllerError::NodeCallError)?;

        Ok(Self {
            chain_config,
            rpc_client,
            wallet,
            wallet_mode,
            staking_started: BTreeSet::new(),
            wallet_events,
            mempool_events,
            should_rescan_mempool_txs: true,
            repush_tracker: rebroadcast::RepushTracker::new(),
        })
    }

    pub async fn create_wallet(
        chain_config: Arc<ChainConfig>,
        mempool_config: Arc<MempoolConfig>,
        file_path: impl AsRef<Path>,
        args: WalletTypeArgsComputed,
        best_block: (BlockHeight, Id<GenBlock>),
        wallet_type: WalletType,
        overwrite_wallet_file: bool,
    ) -> Result<WalletCreation<RuntimeWallet<DefaultBackend>>, ControllerError<N>> {
        utils::ensure!(
            overwrite_wallet_file || !file_path.as_ref().exists(),
            ControllerError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File already exists".to_owned()
            )
        );

        let db = wallet::wallet::open_or_create_wallet_file(file_path.as_ref())
            .map_err(ControllerError::WalletError)?;
        let res = match args {
            WalletTypeArgsComputed::Software {
                mnemonic,
                passphrase,
                store_seed_phrase,
            } => {
                let passphrase_ref = passphrase.as_ref().map(|x| x.as_ref());

                wallet::Wallet::create_new_wallet(
                    Arc::clone(&chain_config),
                    mempool_config,
                    db,
                    best_block,
                    wallet_type,
                    async |db_tx| {
                        SoftwareSignerProvider::new_from_mnemonic(
                            chain_config.clone(),
                            db_tx,
                            &mnemonic.to_string(),
                            passphrase_ref,
                            store_seed_phrase,
                        )
                        .map_err(Into::into)
                    },
                )
                .await
                .map_err(ControllerError::WalletError)
                .map(|w| w.map_wallet(RuntimeWallet::Software))
            }
            #[cfg(feature = "trezor")]
            WalletTypeArgsComputed::Trezor { device_id } => wallet::Wallet::create_new_wallet(
                Arc::clone(&chain_config),
                mempool_config,
                db,
                best_block,
                wallet_type,
                async |_db_tx| {
                    TrezorSignerProvider::new(
                        device_id.map(|device_id| SelectedDevice { device_id }),
                    )
                    .map_err(SignerError::TrezorError)
                    .map_err(Into::into)
                },
            )
            .await
            .map_err(ControllerError::WalletError)
            .map(|w| w.map_wallet(RuntimeWallet::Trezor)),
            #[cfg(feature = "ledger")]
            WalletTypeArgsComputed::Ledger => wallet::Wallet::create_new_wallet(
                Arc::clone(&chain_config),
                mempool_config,
                db,
                best_block,
                wallet_type,
                async |_db_tx| LedgerSignerProvider::new().await.map_err(Into::into),
            )
            .await
            .map_err(ControllerError::WalletError)
            .map(|w| w.map_wallet(RuntimeWallet::Ledger)),
        };

        Self::delete_wallet_file_on_wallet_creation_failure(&res, file_path);
        res
    }

    pub async fn recover_wallet(
        chain_config: Arc<ChainConfig>,
        mempool_config: Arc<MempoolConfig>,
        file_path: impl AsRef<Path>,
        args: WalletTypeArgsComputed,
        wallet_type: WalletType,
    ) -> Result<WalletCreation<RuntimeWallet<DefaultBackend>>, ControllerError<N>> {
        utils::ensure!(
            !file_path.as_ref().exists(),
            ControllerError::WalletFileError(
                file_path.as_ref().to_owned(),
                "File already exists".to_owned()
            )
        );

        let db = wallet::wallet::open_or_create_wallet_file(file_path.as_ref())
            .map_err(ControllerError::WalletError)?;

        let res = match args {
            WalletTypeArgsComputed::Software {
                mnemonic,
                passphrase,
                store_seed_phrase,
            } => {
                let passphrase_ref = passphrase.as_ref().map(|x| x.as_ref());

                let wallet = wallet::Wallet::recover_wallet(
                    Arc::clone(&chain_config),
                    mempool_config,
                    db,
                    wallet_type,
                    async |db_tx| {
                        SoftwareSignerProvider::new_from_mnemonic(
                            chain_config.clone(),
                            db_tx,
                            &mnemonic.to_string(),
                            passphrase_ref,
                            store_seed_phrase,
                        )
                        .map_err(Into::into)
                    },
                )
                .await
                .map_err(ControllerError::WalletError)?;
                Ok(wallet.map_wallet(RuntimeWallet::Software))
            }
            #[cfg(feature = "trezor")]
            WalletTypeArgsComputed::Trezor { device_id } => {
                let wallet = wallet::Wallet::recover_wallet(
                    Arc::clone(&chain_config),
                    mempool_config,
                    db,
                    wallet_type,
                    async |_db_tx| {
                        TrezorSignerProvider::new(
                            device_id.map(|device_id| SelectedDevice { device_id }),
                        )
                        .map_err(SignerError::TrezorError)
                        .map_err(Into::into)
                    },
                )
                .await
                .map_err(ControllerError::WalletError)?;
                Ok(wallet.map_wallet(RuntimeWallet::Trezor))
            }
            #[cfg(feature = "ledger")]
            WalletTypeArgsComputed::Ledger => {
                let wallet = wallet::Wallet::recover_wallet(
                    Arc::clone(&chain_config),
                    mempool_config,
                    db,
                    wallet_type,
                    async |_db_tx| LedgerSignerProvider::new().await.map_err(Into::into),
                )
                .await
                .map_err(ControllerError::WalletError)?;
                Ok(wallet.map_wallet(RuntimeWallet::Ledger))
            }
        };

        Self::delete_wallet_file_on_wallet_creation_failure(&res, file_path);
        res
    }

    /// If wallet creation/recovery didn't succeed (e.g. due to a hard error, or because
    /// user intervention is required), we must delete the wallet file.
    fn delete_wallet_file_on_wallet_creation_failure(
        result: &Result<WalletCreation<RuntimeWallet<DefaultBackend>>, ControllerError<N>>,
        file_path: impl AsRef<Path>,
    ) {
        let must_remove_wallet_file = match result {
            Err(_) => true,
            Ok(wallet_creation) => match wallet_creation {
                // Wallet was created successfully.
                WalletCreation::Wallet(_) => false,
                // Wallet was not created successfully. The caller will need to handle this result
                // and either fail or try again.
                #[cfg(feature = "trezor")]
                WalletCreation::MultipleAvailableTrezorDevices(_) => true,
            },
        };

        if must_remove_wallet_file {
            let _ = fs::remove_file(file_path);
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

    #[allow(clippy::too_many_arguments)]
    pub async fn open_wallet(
        chain_config: Arc<ChainConfig>,
        mempool_config: Arc<MempoolConfig>,
        file_path: impl AsRef<Path>,
        password: Option<String>,
        current_controller_mode: WalletControllerMode,
        force_change_wallet_type: bool,
        open_as_wallet_type: WalletType,
        #[cfg_attr(not(feature = "trezor"), allow(unused_variables))] device_id: Option<String>,
    ) -> Result<WalletCreation<RuntimeWallet<DefaultBackend>>, ControllerError<N>> {
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
                    mempool_config,
                    db,
                    password,
                    |version| Self::make_backup_wallet_file(file_path.as_ref(), version),
                    current_controller_mode,
                    force_change_wallet_type,
                    async |db_tx| {
                        SoftwareSignerProvider::load_from_database(chain_config.clone(), &db_tx)
                    },
                )
                .await
                .map_err(ControllerError::WalletError)?;
                Ok(wallet.map_wallet(RuntimeWallet::Software))
            }
            #[cfg(feature = "trezor")]
            WalletType::Trezor => {
                let wallet = wallet::Wallet::load_wallet(
                    Arc::clone(&chain_config),
                    mempool_config,
                    db,
                    password,
                    |version| Self::make_backup_wallet_file(file_path.as_ref(), version),
                    current_controller_mode,
                    force_change_wallet_type,
                    async |db_tx| {
                        TrezorSignerProvider::load_from_database(
                            chain_config.clone(),
                            &db_tx,
                            device_id,
                        )
                    },
                )
                .await
                .map_err(ControllerError::WalletError)?;
                Ok(wallet.map_wallet(RuntimeWallet::Trezor))
            }
            #[cfg(feature = "ledger")]
            WalletType::Ledger => {
                let wallet = wallet::Wallet::load_wallet(
                    Arc::clone(&chain_config),
                    mempool_config,
                    db,
                    password,
                    |version| Self::make_backup_wallet_file(file_path.as_ref(), version),
                    current_controller_mode,
                    force_change_wallet_type,
                    async |mut db_tx| {
                        LedgerSignerProvider::load_from_database(chain_config.clone(), &mut db_tx)
                            .await
                    },
                )
                .await
                .map_err(ControllerError::WalletError)?;
                Ok(wallet.map_wallet(RuntimeWallet::Ledger))
            }
        }
    }

    pub fn seed_phrase(&self) -> Result<Option<SeedWithPassPhrase>, ControllerError<N>> {
        self.wallet
            .seed_phrase()
            .map(|opt| opt.map(SeedWithPassPhrase::from_serializable_seed_phrase))
            .map_err(ControllerError::WalletError)
    }

    /// Delete the seed phrase if stored in the database
    pub fn delete_seed_phrase(&mut self) -> Result<Option<SeedWithPassPhrase>, ControllerError<N>> {
        self.wallet
            .delete_seed_phrase()
            .map(|opt| opt.map(SeedWithPassPhrase::from_serializable_seed_phrase))
            .map_err(ControllerError::WalletError)
    }

    /// Rescan the blockchain
    /// Resets the wallet to the genesis block
    pub fn reset_wallet_to_genesis(&mut self) -> Result<(), ControllerError<N>> {
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
    pub fn encrypt_wallet(&mut self, password: &Option<String>) -> Result<(), ControllerError<N>> {
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
    pub fn unlock_wallet(&mut self, password: &String) -> Result<(), ControllerError<N>> {
        self.wallet.unlock_wallet(password).map_err(ControllerError::WalletError)
    }

    /// Locks the wallet by making the encrypted private keys inaccessible.
    ///
    /// # Returns
    ///
    /// This method returns an error if the wallet is not encrypted.
    pub fn lock_wallet(&mut self) -> Result<(), ControllerError<N>> {
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
    ) -> Result<(), ControllerError<N>> {
        utils::ensure!(lookahead_size > 0, ControllerError::InvalidLookaheadSize);

        self.wallet
            .set_lookahead_size(lookahead_size, force_reduce)
            .map_err(ControllerError::WalletError)
    }

    pub fn wallet_info(&self) -> WalletInfo {
        let (wallet_id, account_names) = self.wallet.wallet_info();
        let hw_wallet_info = self.wallet.hardware_wallet_info();
        let extra_info = match hw_wallet_info {
            Some(hw_wallet_info) => match hw_wallet_info {
                #[cfg(feature = "trezor")]
                HardwareWalletFullInfo::Trezor(trezor_info) => WalletExtraInfo::TrezorWallet {
                    device_name: trezor_info.device_name,
                    device_id: trezor_info.device_id,
                    firmware_version: trezor_info.firmware_version.to_string(),
                },
                #[cfg(feature = "ledger")]
                HardwareWalletFullInfo::Ledger(ledger_data) => WalletExtraInfo::LedgerWallet {
                    app_version: ledger_data.app_version.clone(),
                    model: ledger_data.model.to_string(),
                },
            },
            None => WalletExtraInfo::SoftwareWallet,
        };

        WalletInfo {
            wallet_id,
            account_names,
            extra_info,
        }
    }

    pub async fn get_token_info(
        &self,
        token_id: TokenId,
    ) -> Result<RPCTokenInfo, ControllerError<N>> {
        fetch_rpc_token_info(&self.rpc_client, token_id).await
    }

    pub async fn generate_block_by_pool(
        &self,
        account_index: U31,
        pool_id: PoolId,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, ControllerError<N>> {
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
    ) -> Result<Block, ControllerError<N>> {
        let pools = self
            .wallet
            .get_pools(account_index, WalletPoolsFilter::Stake)
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
    ///
    /// Note that this function is intended to be used on regtest/signet to populate the chainstate
    /// and it won't work reliably if a large number of blocks enters the chainstate via other means
    /// at the same time (e.g. via p2p during initial block download).
    pub async fn generate_blocks(
        &mut self,
        account_index: U31,
        block_count: u32,
    ) -> Result<(), ControllerError<N>> {
        let mut recoverable_errors_seen_count = 0;

        for block_idx in 0..block_count {
            // Perform a few attempts to produce a block, retrying on a "recoverable mempool error",
            // which indicates that the block production was aborted because the tip has changed
            // when collecting transactions from the mempool.
            // This may happen either because the mempool is lagging behind chainstate (so the
            // new tip is one of the previously produced blocks) or if blocks enter the chainstate
            // via other means (e.g. p2p).
            // Note:
            // 1) Potentially we may see a "recoverable mempool error" for each of the blocks
            //    we produce here, so the retry count should be at least "the number of blocks we
            //    produced so far" minus "the number of recoverable errors seen so far". We add
            //    a small number to that to have some leeway in case blocks are also entering
            //    the chainstate via other means.
            // 2) The alternative to retrying is to wait for a NewTip event from the mempool after
            //    each block; this would make the function more reliable in the case of the mempool
            //    lagging, but less reliable in the case when blocks enter chainstate via p2p
            //    (in which case a newly produced block may not become a tip at all).
            //    I.e. there seems to be no way to make this function 100% reliable.
            let recoverable_error_retry_count =
                (block_idx + 1).saturating_sub(recoverable_errors_seen_count) + 5;
            let mut recoverable_error_retry_idx = 0;
            loop {
                self.sync_once().await?;
                let block_gen_result = self
                    .generate_block(
                        account_index,
                        vec![],
                        vec![],
                        PackingStrategy::FillSpaceFromMempool,
                    )
                    .await;

                match block_gen_result {
                    Ok(block) => {
                        self.rpc_client
                            .submit_block(block)
                            .await
                            .map_err(ControllerError::NodeCallError)?;
                        break;
                    }
                    Err(err) => {
                        let is_recoverable_err = match &err {
                            ControllerError::NodeCallError(err) => {
                                err.is_recoverable_mempool_error_during_block_production()
                            }
                            ControllerError::SyncError(_)
                            | ControllerError::NotEnoughBlockHeight(_, _)
                            | ControllerError::WalletFileError(_, _)
                            | ControllerError::WalletError(_)
                            | ControllerError::AddressEncodingError(_)
                            | ControllerError::NoStakingPool
                            | ControllerError::FrozenToken(_)
                            | ControllerError::WalletIsLocked
                            | ControllerError::StakingRunning
                            | ControllerError::EndToEndEncryptionError(_)
                            | ControllerError::NodeNotInSyncYet
                            | ControllerError::InvalidLookaheadSize
                            | ControllerError::WalletFileAlreadyOpen
                            | ControllerError::NoWallet
                            | ControllerError::SearchForTimestampsFailed(_)
                            | ControllerError::ExpectingNonEmptyInputs
                            | ControllerError::ExpectingNonEmptyOutputs
                            | ControllerError::NoCoinUtxosToPayFeeFrom
                            | ControllerError::InvalidTxOutput(_)
                            | ControllerError::NotFungibleToken(_)
                            | ControllerError::InvalidCoinAmount
                            | ControllerError::PartiallySignedTransactionError(_)
                            | ControllerError::InvalidTokenId
                            | ControllerError::SighashInputCommitmentCreationError(_)
                            | ControllerError::InvalidHtlcSecretsCount => false,
                        };

                        if !is_recoverable_err {
                            return Err(err);
                        }

                        recoverable_errors_seen_count += 1;
                        recoverable_error_retry_idx += 1;

                        if recoverable_error_retry_idx >= recoverable_error_retry_count {
                            log::warn!(
                                "Too many recoverable mempool errors happened during block production, aborting"
                            );

                            return Err(err);
                        }

                        log::info!(
                            "A recoverable mempool error happened during block production, retrying"
                        );

                        // Sleep for some amount of time, increasing it as the number of retries grows,
                        // with the cap of 1 sec.
                        let delay = Duration::from_millis(100 * recoverable_error_retry_idx as u64);
                        let delay = std::cmp::min(delay, Duration::from_secs(1));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
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
    ) -> Result<BTreeMap<BlockHeight, Vec<BlockTimestamp>>, ControllerError<N>> {
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

    pub async fn create_account(
        &mut self,
        name: Option<String>,
    ) -> Result<(U31, Option<String>), ControllerError<N>> {
        self.wallet
            .create_next_account(name)
            .await
            .map_err(ControllerError::WalletError)
    }

    pub fn update_account_name(
        &mut self,
        account_index: U31,
        name: Option<String>,
    ) -> Result<(U31, Option<String>), ControllerError<N>> {
        self.wallet
            .set_account_name(account_index, name)
            .map_err(ControllerError::WalletError)
    }

    pub fn stop_staking(&mut self, account_index: U31) -> Result<(), ControllerError<N>> {
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
    ) -> Result<BTreeMap<PoolId, Amount>, ControllerError<N>> {
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
    pub async fn sync_once(&mut self) -> Result<(), ControllerError<N>> {
        let res = match &mut self.wallet {
            RuntimeWallet::Software(w) => {
                sync::sync_once(&self.chain_config, &self.rpc_client, w, &self.wallet_events).await
            }
            #[cfg(feature = "trezor")]
            RuntimeWallet::Trezor(w) => {
                sync::sync_once(&self.chain_config, &self.rpc_client, w, &self.wallet_events).await
            }
            #[cfg(feature = "ledger")]
            RuntimeWallet::Ledger(w) => {
                sync::sync_once(&self.chain_config, &self.rpc_client, w, &self.wallet_events).await
            }
        }?;

        match res {
            InSync::Synced => Ok(()),
            InSync::NodeOutOfSync => Err(ControllerError::NodeNotInSyncYet),
        }
    }

    pub async fn try_sync_once(&mut self) -> Result<(), ControllerError<N>> {
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
            #[cfg(feature = "ledger")]
            RuntimeWallet::Ledger(w) => {
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
    ) -> Result<SyncedController<'_, N, W, B>, ControllerError<N>> {
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

    pub fn readonly_controller(&self, account_index: U31) -> ReadOnlyController<'_, N, B> {
        ReadOnlyController::new(
            &self.wallet,
            self.rpc_client.clone(),
            self.chain_config.as_ref(),
            account_index,
        )
    }

    // TODO: this function is currently very limited:
    // 1) HTLC inputs are not supported in the `TransactionToInspect::Signed` case.
    // 2) ProduceBlockFromStake and account-based inputs are not supported.
    // 3) It only works for transactions whose inputs have not yet been spent. Note that this part
    // may be hard to fix, because we don't have a tx index, so there is no easy way of obtaining
    // a txo for an already spent input.
    // https://github.com/mintlayer/mintlayer-core/issues/1939
    pub async fn inspect_transaction(
        &self,
        tx: TransactionToInspect,
    ) -> Result<InspectTransaction, ControllerError<N>> {
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
    ) -> Result<InspectTransaction, ControllerError<N>> {
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
    ) -> Result<(Balances, Vec<SignatureStatus>), ControllerError<N>> {
        let (input_utxos, additional_infos, destinations) = fetch_input_infos(
            &self.rpc_client,
            &self.wallet,
            stx.inputs().iter().map(|inp| (inp, HtlcSpendingCondition::Skip)),
        )
        .await?;

        let only_input_utxos = input_utxos.iter().flatten().cloned().collect_vec();
        let fees = self
            .get_fees(
                stx.inputs(),
                &only_input_utxos,
                stx.outputs(),
                Some(&additional_infos),
            )
            .await?;

        let input_commitments_v0 = make_sighash_input_commitments(
            stx.inputs(),
            &input_utxos,
            &additional_infos,
            SighashInputCommitmentVersion::V0,
        )?;
        let input_commitments_v1 = make_sighash_input_commitments(
            stx.inputs(),
            &input_utxos,
            &additional_infos,
            SighashInputCommitmentVersion::V1,
        )?;

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
                    // Try v0 commitments first; if the verification fails, try v1 commitments.
                    // Note: currently this logic is useless, because inputs for which the commitments
                    // are different in v0 and v1 (i.e. ProduceBlockFromStake, FillOrder, ConcludeOrder)
                    // are currently not supported by inspect_transaction.
                    // TODO: if the v1 commitments fork lands before we get to revamping inspect_transaction
                    // (which is likely), this logic can just be removed.
                    let v0_commitments_status = self.verify_tx_signature(
                        stx,
                        &input_commitments_v0,
                        input_num,
                        input_utxos[input_num].clone(),
                        &dest,
                    );

                    match v0_commitments_status {
                        SignatureStatus::NotSigned
                        | SignatureStatus::UnknownSignature
                        | SignatureStatus::FullySigned
                        | SignatureStatus::PartialMultisig { .. } => v0_commitments_status,

                        SignatureStatus::InvalidSignature => self.verify_tx_signature(
                            stx,
                            &input_commitments_v1,
                            input_num,
                            input_utxos[input_num].clone(),
                            &dest,
                        ),
                    }
                }
            })
            .collect();
        Ok((fees, signature_statuses))
    }

    async fn inspect_partial_tx(
        &self,
        ptx: PartiallySignedTransaction,
    ) -> Result<InspectTransaction, ControllerError<N>> {
        let input_utxos: Vec<_> = ptx.input_utxos().iter().flatten().cloned().collect();
        let fees = self
            .get_fees(
                ptx.tx().inputs(),
                &input_utxos,
                ptx.tx().outputs(),
                Some(ptx.additional_info()),
            )
            .await?;

        let input_commitments_v0 =
            ptx.make_sighash_input_commitments(SighashInputCommitmentVersion::V0)?;
        let input_commitments_v1 =
            ptx.make_sighash_input_commitments(SighashInputCommitmentVersion::V1)?;

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
                    // Try v0 commitments first; if the verification fails, try v1 commitments.
                    // Note: currently this logic is useless, because inputs for which the commitments
                    // are different in v0 and v1 (i.e. ProduceBlockFromStake, FillOrder, ConcludeOrder)
                    // are currently not supported by inspect_transaction.
                    // TODO: if the v1 commitments fork lands before we get to revamping inspect_transaction
                    // (which is likely), this logic can just be removed.
                    let v0_commitments_status = self.verify_tx_signature(
                        &ptx,
                        &input_commitments_v0,
                        input_num,
                        ptx.input_utxos()[input_num].clone(),
                        dest,
                    );

                    match v0_commitments_status {
                        SignatureStatus::NotSigned
                        | SignatureStatus::UnknownSignature
                        | SignatureStatus::FullySigned
                        | SignatureStatus::PartialMultisig { .. } => v0_commitments_status,

                        SignatureStatus::InvalidSignature => self.verify_tx_signature(
                            &ptx,
                            &input_commitments_v1,
                            input_num,
                            ptx.input_utxos()[input_num].clone(),
                            dest,
                        ),
                    }
                }
                (None, _) => SignatureStatus::NotSigned,
            })
            .collect();
        let num_inputs = ptx.inputs_count();
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

    async fn inspect_tx(&self, tx: Transaction) -> Result<InspectTransaction, ControllerError<N>> {
        let inputs: Vec<_> = tx
            .inputs()
            .iter()
            .filter_map(|inp| match inp {
                TxInput::Utxo(utxo) => Some(utxo.clone()),
                TxInput::Account(_) => None,
                TxInput::AccountCommand(_, _) | TxInput::OrderAccountCommand(_) => None,
            })
            .collect();
        let fees = match self.fetch_utxos(&inputs).await {
            Ok(input_utxos) => {
                Some(self.get_fees(tx.inputs(), &input_utxos, tx.outputs(), None).await?)
            }
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
        input_commitments: &[SighashInputCommitment],
        input_num: usize,
        input_utxo: Option<TxOutput>,
        dest: &Destination,
    ) -> SignatureStatus {
        let valid = tx_verifier::input_check::signature_only_check::verify_tx_signature(
            &self.chain_config,
            dest,
            tx,
            input_commitments,
            input_num,
            input_utxo,
        );

        match valid {
            Ok(_) => SignatureStatus::FullySigned,
            Err(e) => match e.error() {
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

                tx_verifier::error::InputCheckErrorPayload::MissingUtxo(_)
                | tx_verifier::error::InputCheckErrorPayload::PoolNotFound(_)
                | tx_verifier::error::InputCheckErrorPayload::OrderNotFound(_)
                | tx_verifier::error::InputCheckErrorPayload::NonUtxoKernelInput(_)
                | tx_verifier::error::InputCheckErrorPayload::UtxoView(_)
                | tx_verifier::error::InputCheckErrorPayload::UtxoInfoProvider(_)
                | tx_verifier::error::InputCheckErrorPayload::PoolInfoProvider(_)
                | tx_verifier::error::InputCheckErrorPayload::OrderInfoProvider(_)
                | tx_verifier::error::InputCheckErrorPayload::Translation(_)
                | tx_verifier::error::InputCheckErrorPayload::Verification(_) => {
                    SignatureStatus::InvalidSignature
                }
            },
        }
    }

    pub async fn compose_transaction(
        &self,
        inputs: Vec<UtxoOutPoint>,
        outputs: Vec<TxOutput>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        only_transaction: bool,
    ) -> Result<(TransactionToSign, Balances), ControllerError<N>> {
        let input_utxos = self.fetch_utxos(&inputs).await?;
        let fees = self.get_fees(&[], &input_utxos, &outputs, None).await?;

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
                    let htlc_spending = HtlcSpendingCondition::from_opt_secrets_array_item(
                        htlc_secrets.as_deref(),
                        i,
                    );

                    get_tx_output_destination(txo, &|_| None, htlc_spending).ok_or_else(|| {
                        WalletError::UnsupportedTransactionOutput(Box::new(txo.clone()))
                    })
                })
                .collect::<Result<Vec<_>, WalletError>>()
                .map_err(ControllerError::WalletError)?;

            let (input_utxos, ptx_additional_info) =
                self.fetch_utxos_extra_info(input_utxos).await?.into_iter().fold(
                    (Vec::new(), PtxAdditionalInfo::new()),
                    |(mut input_utxos, additional_info), (x, y)| {
                        input_utxos.push(x);
                        (input_utxos, additional_info.join(y))
                    },
                );

            let ptx_additional_info = self
                .fetch_utxos_extra_info(tx.outputs().to_vec())
                .await?
                .into_iter()
                .fold(ptx_additional_info, |acc, (_, info)| acc.join(info));
            let tx = PartiallySignedTransaction::new_for_wallet(
                tx,
                vec![None; num_inputs],
                input_utxos.into_iter().map(Option::Some).collect(),
                destinations.into_iter().map(Option::Some).collect(),
                htlc_secrets,
                ptx_additional_info,
            )?;

            TransactionToSign::Partial(tx)
        };

        Ok((tx, fees))
    }

    async fn get_fees(
        &self,
        tx_inputs: &[TxInput],
        input_utxos: &[TxOutput],
        outputs: &[TxOutput],
        additional_order_info: Option<&PtxAdditionalInfo>,
    ) -> Result<Balances, ControllerError<N>> {
        let mut inputs = self.group_inputs(input_utxos)?;
        let mut outputs = self.group_outputs(outputs)?;

        self.add_order_command_amounts(tx_inputs, additional_order_info, &mut inputs, &mut outputs)
            .await?;

        let mut fees = BTreeMap::new();

        for (currency, output) in outputs {
            let input_amount =
                inputs.remove(&currency).ok_or(ControllerError::<N>::WalletError(
                    WalletError::InsufficientUtxoAmount(Amount::ZERO, output),
                ))?;

            let fee = (input_amount - output).ok_or(ControllerError::<N>::WalletError(
                WalletError::InsufficientUtxoAmount(input_amount, output),
            ))?;
            if fee != Amount::ZERO {
                fees.insert(currency, fee);
            }
        }
        // add any leftover inputs
        fees.extend(inputs);

        into_balances(&self.rpc_client, &self.chain_config, fees).await
    }

    // Credits the values that order account command inputs take from (for FillOrder) or free
    // from (for ConcludeOrder) the orders' escrow, mirroring the orders accounting semantics.
    // For FillOrder the ask currency amount paid by the filler is added to `output_amounts`
    // because it is consumed by the transaction.
    async fn add_order_command_amounts(
        &self,
        tx_inputs: &[TxInput],
        additional_order_info: Option<&PtxAdditionalInfo>,
        input_amounts: &mut BTreeMap<Currency, Amount>,
        output_amounts: &mut BTreeMap<Currency, Amount>,
    ) -> Result<(), ControllerError<N>> {
        for input in tx_inputs {
            match input {
                TxInput::AccountCommand(_, command) => match command {
                    AccountCommand::FillOrder(order_id, fill_amount_in_ask_currency, _) => {
                        let order_info =
                            self.resolve_order_info(*order_id, additional_order_info).await?;
                        let filled_amount = orders_accounting::calculate_filled_amount(
                            order_info.ask_balance,
                            order_info.give_balance,
                            *fill_amount_in_ask_currency,
                        )
                        .ok_or(ControllerError::<N>::WalletError(
                            WalletError::CalculateOrderFilledAmountFailed(*order_id),
                        ))?;

                        add_amount(
                            input_amounts,
                            order_currency(&order_info.initially_given)?,
                            filled_amount,
                        )
                        .map_err(ControllerError::WalletError)?;
                        add_amount(
                            output_amounts,
                            order_currency(&order_info.initially_asked)?,
                            *fill_amount_in_ask_currency,
                        )
                        .map_err(ControllerError::WalletError)?;
                    }
                    AccountCommand::ConcludeOrder(order_id) => {
                        let order_info =
                            self.resolve_order_info(*order_id, additional_order_info).await?;
                        add_concluded_order_amounts(&order_info, input_amounts)
                            .map_err(ControllerError::WalletError)?;
                    }
                    AccountCommand::MintTokens(..)
                    | AccountCommand::LockTokenSupply(_)
                    | AccountCommand::UnmintTokens(_)
                    | AccountCommand::FreezeToken(..)
                    | AccountCommand::UnfreezeToken(_)
                    | AccountCommand::ChangeTokenAuthority(..)
                    | AccountCommand::ChangeTokenMetadataUri(..) => {}
                },
                TxInput::OrderAccountCommand(command) => match command {
                    OrderAccountCommand::FillOrder(order_id, fill_amount_in_ask_currency) => {
                        let order_info =
                            self.resolve_order_info(*order_id, additional_order_info).await?;
                        let filled_amount = orders_accounting::calculate_filled_amount(
                            order_info.initially_asked.amount(),
                            order_info.initially_given.amount(),
                            *fill_amount_in_ask_currency,
                        )
                        .ok_or(ControllerError::<N>::WalletError(
                            WalletError::CalculateOrderFilledAmountFailed(*order_id),
                        ))?;

                        add_amount(
                            input_amounts,
                            order_currency(&order_info.initially_given)?,
                            filled_amount,
                        )
                        .map_err(ControllerError::WalletError)?;
                        add_amount(
                            output_amounts,
                            order_currency(&order_info.initially_asked)?,
                            *fill_amount_in_ask_currency,
                        )
                        .map_err(ControllerError::WalletError)?;
                    }
                    OrderAccountCommand::ConcludeOrder(order_id) => {
                        let order_info =
                            self.resolve_order_info(*order_id, additional_order_info).await?;
                        add_concluded_order_amounts(&order_info, input_amounts)
                            .map_err(ControllerError::WalletError)?;
                    }
                    OrderAccountCommand::FreezeOrder(_) => {}
                },
                TxInput::Utxo(_) | TxInput::Account(_) => {}
            }
        }

        Ok(())
    }

    // Order balances are committed to by the transaction's signatures, so the additional info
    // embedded in a PartiallySignedTransaction is used when present and the node is only asked
    // otherwise (e.g. when a signed transaction is inspected).
    async fn resolve_order_info(
        &self,
        order_id: OrderId,
        additional_order_info: Option<&PtxAdditionalInfo>,
    ) -> Result<OrderAdditionalInfo, ControllerError<N>> {
        if let Some(order_info) = additional_order_info
            .and_then(|additional_info| additional_info.get_order_info(&order_id))
        {
            return Ok(order_info.clone());
        }

        let order_info = self
            .rpc_client
            .get_order_info(order_id)
            .await
            .map_err(ControllerError::NodeCallError)?
            .ok_or(ControllerError::<N>::WalletError(
                WalletError::OrderInfoMissing(order_id),
            ))?;

        Ok(OrderAdditionalInfo {
            initially_asked: order_info.initially_asked.into(),
            initially_given: order_info.initially_given.into(),
            ask_balance: order_info.ask_balance,
            give_balance: order_info.give_balance,
        })
    }

    fn group_outputs(
        &self,
        outputs: &[TxOutput],
    ) -> Result<BTreeMap<Currency, Amount>, ControllerError<N>> {
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
    ) -> Result<BTreeMap<Currency, Amount>, ControllerError<N>> {
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
    ) -> Result<Vec<TxOutput>, ControllerError<N>> {
        let tasks: FuturesOrdered<_> = inputs
            .iter()
            .map(|input| fetch_utxo(&self.rpc_client, &self.wallet, input))
            .collect();
        let input_utxos: Vec<TxOutput> = tasks.try_collect().await?;
        Ok(input_utxos)
    }

    async fn fetch_utxos_extra_info(
        &self,
        inputs: Vec<TxOutput>,
    ) -> Result<Vec<(TxOutput, PtxAdditionalInfo)>, ControllerError<N>> {
        let tasks: FuturesOrdered<_> = inputs
            .into_iter()
            .map(|input| fetch_utxo_extra_info(&self.rpc_client, input))
            .collect();
        tasks.try_collect().await
    }

    /// Synchronize the wallet in the background from the node's blockchain.
    /// Try staking new blocks if staking was started.
    pub async fn run(&mut self) -> Result<Never, ControllerError<N>> {
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

            match self.wallet_mode {
                WalletControllerMode::Hot => {
                    // fetch all mempool transactions after a broken connection or after the initial sync
                    if self.should_rescan_mempool_txs {
                        let txs = self.rpc_client.mempool_get_transactions().await;

                        match txs {
                            Ok(txs) => {
                                if let Err(err) =
                                    self.wallet.add_mempool_transactions(&txs, &self.wallet_events)
                                {
                                    log::error!("Error adding mempool transactions: {err}");
                                } else {
                                    self.should_rescan_mempool_txs = false
                                }
                            }
                            Err(err) => {
                                log::error!(
                                    "Failed to fetch all transactions from the mempool: {err}"
                                );
                                tokio::time::sleep(ERROR_DELAY).await;
                                continue;
                            }
                        }
                    }
                }
                WalletControllerMode::Cold => {}
            }

            let mut delay = Box::pin(tokio::time::sleep(NORMAL_DELAY));

            loop {
                tokio::select! {
                    _ = &mut delay => {
                        break;
                    }

                    maybe_event = self.mempool_events.next() => {
                        let event = match maybe_event {
                            Some(e) => e,
                            None => {
                                // Note: currently the wallet is unable to automatically reconnect to the node when
                                // the connection is dropped, so for now this branch mostly handles a hypothetical
                                // situation when the connection is still up, but the stream itself somehow got closed.

                                log::error!("Mempool notifications channel is closed");

                                // Reset in-mempool transactions to inactive so we can rescan them when we connect again.
                                self.wallet.reset_inmempool_txs_to_inactive(Some(&self.wallet_events))?;
                                self.should_rescan_mempool_txs = true;

                                tokio::time::sleep(ERROR_DELAY).await;
                                match self.rpc_client
                                    .mempool_subscribe_to_events()
                                    .await {
                                    Ok(events) => {
                                        self.mempool_events = events;
                                    }
                                    Err(err) => {
                                        log::error!("Re-subscribing to mempool notifications failed: {err}");
                                    }
                                }
                                break
                            }
                        };

                        match event {
                            // TODO: mempool can evict transactions - there is a size limit for the entire mempool
                            // (MAX_MEMPOOL_SIZE_BYTES by default, which is 300Mb) and an expiration time for each tx
                            // (DEFAULT_MEMPOOL_EXPIRY, which is currently 2 weeks). The wallet must be aware of this
                            // and mark all its in-mempool txs that have been evicted as inactive.
                            // At this moment eviction happens when a new tx is being added to the mempool, but note
                            // that a `NewTransaction` event is not guaranteed in this case (e.g. if the newly added
                            // tx gets evicted too). Additionally, txs may be evicted after the mempool has been explicitly
                            // trimmed via `set_max_size`.
                            // So, the simpler (but not 100% reliable) solution would be to check all of the wallet's
                            // in-mempool txs for whether they're still in mempool (preferably via a dedicated rpc method,
                            // to avoid overhead) whenever a `NewTransaction` event arrives.
                            // A better solution is to introduce a separate mempool event, `TransactionsRemoved`,
                            // that would contain ids of all txs that have been evicted or removed due to other reasons
                            // (plus maybe the reason for the eviction/removal).

                            MempoolEvent::NewTransaction { tx_id } => {
                                let transaction = self.rpc_client
                                    .mempool_get_transaction(tx_id)
                                    .await;

                                match transaction {
                                    Ok(Some(transaction)) => {
                                        let txs = [transaction];
                                        if let Err(err) = self.wallet.add_mempool_transactions(&txs, &self.wallet_events) {
                                            log::error!("Error adding mempool transaction {tx_id:x} to the wallet: {err}");
                                        }
                                    }
                                    Ok(None) => {
                                        log::warn!("Transaction {tx_id:x} announced by mempool, but not found when fetched");
                                    }
                                    Err(err) => {
                                        log::error!("Error fetching transaction {tx_id:x} from mempool: {err}");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Note: normally a wallet in the cold mode will not have any transactions to broadcast. However, if it was
            // force-converted from a hot wallet, it may have such transactions, in which case `rebroadcast_txs` will
            // repeatedly print the warning "Rebroadcasting ... failed: Method is not available in cold wallet mode".
            // So we avoid calling `reconcile_and_rebroadcast` in the cold mode.
            match self.wallet_mode {
                WalletControllerMode::Cold => {}
                WalletControllerMode::Hot => {
                    self.reconcile_and_rebroadcast(&mut rebroadcast_txs_timer).await;
                }
            }
        }
    }

    /// Periodically reconcile the wallet's pending transactions against the
    /// node's mempool and (re)submit them in chain order (parents before
    /// children), with per-transaction backoff and a retry budget.
    /// Concurrency bound for the per-pass mempool probes.
    const PROBE_CONCURRENCY: usize = 8;
    /// Minimum gap between reconcile passes when re-timed to an earlier due
    /// time, so a due transaction can never trigger a hot loop.
    const MIN_PASS_GAP_SEC: u64 = 5;

    async fn reconcile_and_rebroadcast(&mut self, rebroadcast_timer: &mut Time) {
        if get_time() < *rebroadcast_timer {
            return;
        }

        if let Err(error) = self.reconcile_and_repush().await {
            log::error!("Reconcile-and-rebroadcast pass failed: {error}");
        }

        // Base pass interval: randomized between 2 and 5 minutes. If some
        // tracked transaction becomes due for its next attempt earlier than
        // that (the first backoff tiers are 30s-2min), time the next pass to
        // the earliest due time so the documented backoff schedule is
        // honored instead of being clamped to the pass cadence.
        let now = get_time();
        let sleep_interval_sec = make_pseudo_rng().random_range(120..=300);
        let regular_wake = (now + Duration::from_secs(sleep_interval_sec))
            .expect("Sleep intervals cannot be this large");
        let min_gap = (now + Duration::from_secs(Self::MIN_PASS_GAP_SEC))
            .expect("Sleep intervals cannot be this large");
        // Only honor wake times actually in the future: an elapsed
        // next_attempt belongs to a transaction that was deferred, blocked or
        // stuck this pass rather than backoff-scheduled, so it has no
        // meaningful due time and must not shrink the pass interval to the
        // minimum gap indefinitely.
        *rebroadcast_timer = match self.repush_tracker.next_wake() {
            Some(due) if due > now && due < regular_wake => due.max(min_gap),
            _ => regular_wake,
        };
    }

    /// One reconciliation pass:
    /// 1. fetch all pending (unconfirmed) transactions per account;
    /// 2. probe the node's mempool for each of them;
    /// 3. prune deterministically-rejected chains (present parent + missing
    ///    child) together with their descendants;
    /// 4. submit the remaining missing transactions parents-first, with
    ///    per-transaction backoff and a retry budget.
    async fn reconcile_and_repush(&mut self) -> Result<(), ControllerError<N>> {
        let per_account = self
            .wallet
            .get_unconfirmed_transactions_per_account()
            .map_err(ControllerError::WalletError)?;

        if per_account.values().all(Vec::is_empty) {
            // Nothing pending at all; drop leftover tracker entries except
            // stuck markers, which the Stuck log line promises persist until
            // they are abandoned or the wallet restarts.
            self.repush_tracker.clear_except_stuck();
            return Ok(());
        }

        let mut pending = Vec::<rebroadcast::PendingTx>::new();
        let mut account_of: BTreeMap<Id<Transaction>, U31> = BTreeMap::new();
        let mut txs_by_id: BTreeMap<Id<Transaction>, &SignedTransaction> = BTreeMap::new();
        // Account-nonce transactions by (account, nonce): consecutive nonces
        // must reach the mempool in order, so a transaction with nonce n
        // depends on the pending transaction with nonce n-1 of the same
        // account even though there is no UTXO parent edge.
        let mut nonce_of: BTreeMap<(U31, u64), Id<Transaction>> = BTreeMap::new();

        for (account_index, txs) in &per_account {
            for tx in txs {
                let id = tx.transaction().get_id();

                // A transaction cannot legitimately belong to two accounts; if the
                // data says otherwise, keep the first occurrence and skip the rest.
                if account_of.contains_key(&id) {
                    log::warn!("Duplicate pending transaction {id:x} across accounts; skipping");
                    continue;
                }

                let mut pending_parents = Vec::new();
                let mut nonce = None;

                for input in tx.transaction().inputs() {
                    match input {
                        TxInput::Utxo(outpoint) => {
                            if let OutPointSourceId::Transaction(source) = outpoint.source_id() {
                                pending_parents.push(source);
                            }
                        }
                        TxInput::Account(outpoint) => {
                            nonce.get_or_insert_with(|| outpoint.nonce().value());
                        }
                        TxInput::AccountCommand(nonce_, _) => {
                            nonce.get_or_insert_with(|| nonce_.value());
                        }
                        TxInput::OrderAccountCommand(_) => {}
                    }
                }

                account_of.insert(id, *account_index);
                txs_by_id.insert(id, tx);
                if let Some(account_nonce) = nonce {
                    nonce_of.insert((*account_index, account_nonce), id);
                }
                pending.push(rebroadcast::PendingTx {
                    id,
                    pending_parents,
                    nonce,
                });
            }
        }

        // Drop tracker state for transactions that are no longer pending, so
        // that the tracker does not accumulate entries forever.
        let pending_ids: BTreeSet<Id<Transaction>> = pending.iter().map(|tx| tx.id).collect();
        self.repush_tracker.retain_where(|id| pending_ids.contains(id));

        // Probe the mempool for each pending transaction. A probe that fails
        // with a transport error only excludes that transaction from this
        // pass (its evidence streak is left untouched); the pass itself
        // continues so one blip cannot stall the others. Probes run with
        // bounded concurrency: a long pending chain must not turn the pass
        // into one serial round-trip per transaction.
        let rpc_client = &self.rpc_client;
        let probe_results: Vec<(Id<Transaction>, Result<Option<_>, _>)> = futures::stream::iter(
            pending
                .iter()
                .map(|tx| async move { (tx.id, rpc_client.mempool_get_transaction(tx.id).await) }),
        )
        .buffer_unordered(Self::PROBE_CONCURRENCY)
        .collect()
        .await;
        let mut presence = BTreeMap::new();
        let mut probed = std::collections::BTreeSet::new();
        for (tx_id, result) in probe_results {
            match result {
                Ok(found) => {
                    presence.insert(tx_id, found.is_some());
                    probed.insert(tx_id);
                }
                Err(error) => {
                    log::warn!(
                        "Mempool probe for transaction {:x} failed: {error}; skipping it this pass",
                        tx_id
                    );
                }
            }
        }
        // A transaction whose parent was not probed cannot be classified this
        // pass: reconcile would treat the unknown parent as absent, reset the
        // child's evidence streak, and resubmit the child against an unknown
        // parent state. Skip unprobed transactions and their descendants.
        let children: BTreeMap<Id<Transaction>, Vec<Id<Transaction>>> = {
            let mut children: BTreeMap<Id<Transaction>, Vec<Id<Transaction>>> = BTreeMap::new();
            for tx in &pending {
                for parent in &tx.pending_parents {
                    children.entry(*parent).or_default().push(tx.id);
                }
            }
            children
        };
        let mut skipped: BTreeSet<Id<Transaction>> =
            pending_ids.iter().filter(|id| !probed.contains(*id)).copied().collect();
        let mut queue: Vec<Id<Transaction>> = skipped.iter().copied().collect();
        while let Some(id) = queue.pop() {
            if let Some(tx_children) = children.get(&id) {
                for child in tx_children {
                    if skipped.insert(*child) {
                        queue.push(*child);
                    }
                }
            }
        }
        if !skipped.is_empty() {
            let skipped_len = skipped.len();
            if probed.is_empty() {
                log::error!(
                    "{skipped_len} pending transaction(s) skipped: all mempool probes failed \
                     (node may be down)"
                );
            } else {
                log::warn!("{skipped_len} pending transaction(s) skipped: mempool probe failed");
            }
        }
        let pending: Vec<rebroadcast::PendingTx> =
            pending.into_iter().filter(|tx| !skipped.contains(&tx.id)).collect();
        // Keep `presence` in lockstep with `pending`: reconcile requires the
        // map to cover exactly the transactions it is given.
        presence.retain(|id, _| !skipped.contains(id));

        let pass_now = get_time();
        let outcome =
            rebroadcast::reconcile(&pending, &presence, &mut self.repush_tracker, pass_now);

        for tx_id in &outcome.to_prune {
            let Some(account_index) = account_of.get(tx_id) else {
                continue;
            };
            match self.wallet.prune_dead_transaction(*account_index, *tx_id) {
                Ok(()) => {
                    self.repush_tracker.forget(tx_id);
                    log::warn!(
                        "Pruned dead transaction {tx_id:x} (and its pending descendants, if any)"
                    );
                }
                Err(error) => {
                    // Keep the tracker entry: the evidence streak (already at
                    // the threshold) triggers a prune retry on the next pass.
                    log::warn!(
                        "Pruning dead transaction {tx_id:x} failed: {error}; it will be retried \
                         (absence streak: {})",
                        self.repush_tracker.absence_streak(tx_id),
                    );
                }
            }
        }

        let now = get_time();
        // Transactions known not to be in the mempool by the end of this pass:
        // their submission failed, they are not due yet (backoff or stuck), or
        // one of their pending parents is in this set. Their pending
        // descendants are deferred as well: submitting a child while its
        // parent is missing is a guaranteed rejection that burns the child's
        // retry budget and can feed the prune-evidence streak. Topological
        // order guarantees every parent is classified before its children.
        let pending_by_id: BTreeMap<Id<Transaction>, &rebroadcast::PendingTx> =
            pending.iter().map(|tx| (tx.id, tx)).collect();
        // Transactions that will not be submitted this pass — in backoff, or
        // stuck (reconcile excludes stuck ones from `to_submit` entirely) —
        // are seeded up front, so the parent checks below see them as not
        // ready even though they never enter the submit loop. A transaction
        // that the probe showed to be present in the mempool never blocks a
        // child, so it is excluded: seeding it would needlessly defer the
        // child while its deterministic-rejection evidence (missing while the
        // present parent is there) keeps accumulating toward a prune without
        // the child ever actually being attempted.
        let mut unsubmitted: BTreeSet<Id<Transaction>> = pending_by_id
            .keys()
            .filter(|id| {
                !presence.get(id).copied().unwrap_or(false) && !self.repush_tracker.is_due(id, now)
            })
            .copied()
            .collect();
        for tx_id in &outcome.to_submit {
            if !self.repush_tracker.is_due(tx_id, now) {
                // Already seeded above; kept as a guard so a not-due
                // transaction is never submitted.
                log::debug!("Skipping transaction {tx_id:x}: not due yet");
                continue;
            }

            let Some(pending_tx) = pending_by_id.get(tx_id) else {
                // Defensive: `to_submit` is derived from the same `pending`
                // vec, so this cannot happen — but if it did, the transaction
                // must still be recorded as unsubmitted to keep the
                // child-deferral invariant intact.
                unsubmitted.insert(*tx_id);
                continue;
            };
            // Not ready = a pending UTXO parent was not submitted this pass
            // (or was skipped entirely), or the account-nonce predecessor is
            // missing. Submitting in either case is a guaranteed rejection
            // that burns this transaction's retry budget and can feed the
            // prune-evidence streak. For nonce chains, the predecessor is the
            // same-account pending transaction with nonce n-1; nonces must
            // reach the mempool consecutively.
            let parent_not_ready =
                pending_tx.pending_parents.iter().any(|parent| unsubmitted.contains(parent))
                    || match (account_of.get(tx_id), pending_tx.nonce) {
                        (Some(account_index), Some(nonce)) if nonce > 0 => {
                            nonce_of.get(&(*account_index, nonce - 1)).is_some_and(|predecessor| {
                                // A predecessor missing from `pending_by_id` was
                                // skipped this pass (e.g. its probe failed).
                                !pending_by_id.contains_key(predecessor)
                                    || unsubmitted.contains(predecessor)
                            })
                        }
                        _ => false,
                    };
            if parent_not_ready {
                unsubmitted.insert(*tx_id);
                log::debug!("Skipping transaction {tx_id:x}: a parent is not ready this pass");
                continue;
            }

            let Some(tx) = txs_by_id.get(tx_id) else {
                // Defensive: same invariant as above.
                unsubmitted.insert(*tx_id);
                continue;
            };

            log::info!("Rebroadcasting transaction {tx_id:x}");
            match self.rpc_client.submit_transaction((*tx).clone(), Default::default()).await {
                Ok(()) => {
                    self.repush_tracker.on_success(tx_id, get_time());
                }
                Err(error) => {
                    unsubmitted.insert(*tx_id);
                    let verdict = if error.is_node_rejection() {
                        self.repush_tracker.on_rejected(tx_id, get_time())
                    } else {
                        self.repush_tracker.on_delivery_failure(tx_id, get_time())
                    };
                    match verdict {
                        rebroadcast::FailureVerdict::Retry(next_attempt) => {
                            log::debug!(
                                "Rebroadcasting transaction {tx_id:x} failed: {error}; will retry after {next_attempt:?}"
                            );
                        }
                        rebroadcast::FailureVerdict::Stuck => {
                            log::warn!(
                                "Rebroadcasting transaction {tx_id:x} failed: {error}; giving up on it \
                                 until it is abandoned (transaction_abandon) or the wallet restarts"
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn add_amount(
    amounts: &mut BTreeMap<Currency, Amount>,
    currency: Currency,
    amount: Amount,
) -> Result<(), WalletError> {
    let entry = amounts.entry(currency).or_insert(Amount::ZERO);
    *entry = (*entry + amount).ok_or(WalletError::OutputAmountOverflow)?;
    Ok(())
}

fn order_currency(output_value: &OutputValue) -> Result<Currency, WalletError> {
    Currency::from_output_value(output_value).ok_or(WalletError::UnsupportedTransactionOutput(
        Box::new(TxOutput::Transfer(
            output_value.clone(),
            Destination::AnyoneCanSpend,
        )),
    ))
}

fn add_concluded_order_amounts(
    order_info: &OrderAdditionalInfo,
    input_amounts: &mut BTreeMap<Currency, Amount>,
) -> Result<(), WalletError> {
    add_amount(
        input_amounts,
        order_currency(&order_info.initially_given)?,
        order_info.give_balance,
    )?;

    let filled_ask_amount = (order_info.initially_asked.amount() - order_info.ask_balance)
        .ok_or(WalletError::OutputAmountOverflow)?;
    add_amount(
        input_amounts,
        order_currency(&order_info.initially_asked)?,
        filled_ask_amount,
    )?;

    Ok(())
}
