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

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use crate::account::transaction_list::TransactionList;
use crate::account::{Currency, DelegationData, UtxoSelectorError};
use crate::key_chain::{KeyChainError, MasterKeyChain};
use crate::send_request::{
    make_issue_nft_outputs, make_issue_token_outputs, StakePoolDataArguments,
};
use crate::wallet_events::{WalletEvents, WalletEventsNoOp};
use crate::{Account, SendRequest};
pub use bip39::{Language, Mnemonic};
use common::address::{Address, AddressError};
use common::chain::block::timestamp::BlockTimestamp;
use common::chain::signature::TransactionSigError;
use common::chain::tokens::{token_id, Metadata, TokenId, TokenIssuanceV0};
use common::chain::{
    AccountNonce, Block, ChainConfig, DelegationId, Destination, GenBlock, PoolId,
    SignedTransaction, Transaction, TransactionCreationError, TxOutput, UtxoOutPoint,
};
use common::primitives::id::WithId;
use common::primitives::{Amount, BlockHeight, Id};
use consensus::PoSGenerateBlockInputData;
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::u31::U31;
use crypto::key::PublicKey;
use crypto::vrf::VRFPublicKey;
use mempool::FeeRate;
use pos_accounting::make_delegation_id;
use tx_verifier::error::TokenIssuanceError;
use utils::ensure;
use wallet_storage::{
    DefaultBackend, Store, StoreTxRw, StoreTxRwUnlocked, TransactionRoLocked, TransactionRwLocked,
    TransactionRwUnlocked, Transactional, WalletStorageReadLocked, WalletStorageReadUnlocked,
    WalletStorageWriteLocked, WalletStorageWriteUnlocked,
};
use wallet_types::chain_info::ChainInfo;
use wallet_types::seed_phrase::{SerializableSeedPhrase, StoreSeedPhrase};
use wallet_types::utxo_types::{UtxoStates, UtxoTypes};
use wallet_types::wallet_tx::TxState;
use wallet_types::with_locked::WithLocked;
use wallet_types::{AccountId, BlockInfo, KeyPurpose, KeychainUsageState};

pub const WALLET_VERSION_UNINITIALIZED: u32 = 0;
pub const WALLET_VERSION_V1: u32 = 1;
pub const WALLET_VERSION_V2: u32 = 2;
pub const CURRENT_WALLET_VERSION: u32 = WALLET_VERSION_V2;

/// Wallet errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum WalletError {
    #[error("Wallet is not initialized")]
    WalletNotInitialized,
    #[error("The wallet belongs to a different chain then the one specified")]
    DifferentChainType,
    #[error("Unsupported wallet version: {0}, max supported version of this software is {CURRENT_WALLET_VERSION}")]
    UnsupportedWalletVersion(u32),
    #[error("Wallet database error: {0}")]
    DatabaseError(#[from] wallet_storage::Error),
    #[error("Transaction already present: {0}")]
    DuplicateTransaction(Id<Transaction>),
    #[error("No transaction found: {0}")]
    NoTransactionFound(Id<Transaction>),
    #[error("Key chain error: {0}")]
    KeyChainError(#[from] KeyChainError),
    #[error("No account found")] // TODO implement display for AccountId
    NoAccountFound(AccountId),
    #[error("No account found with index {0}")]
    NoAccountFoundWithIndex(U31),
    #[error("Account with index {0} already exists")]
    AccountAlreadyExists(U31),
    #[error("Cannot create a new account when last account is still empty")]
    EmptyLastAccount,
    #[error("Cannot create a new account with an empty string name")]
    EmptyAccountName,
    #[error("The maximum number of accounts has been exceeded: {0}")]
    AbsoluteMaxNumAccountsExceeded(U31),
    #[error("Not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("Unsupported transaction output type")] // TODO implement display for TxOutput
    UnsupportedTransactionOutput(Box<TxOutput>),
    #[error("Unsupported input destination")] // TODO implement display for Destination
    UnsupportedInputDestination(Destination),
    #[error("Output amounts overflow")]
    OutputAmountOverflow,
    #[error("Delegation with id: {0} with duplicate AccountNonce: {1}")]
    InconsistentDelegationDuplicateNonce(DelegationId, AccountNonce),
    #[error("Inconsistent produce block from stake for pool id: {0}, missing CreateStakePool")]
    InconsistentProduceBlockFromStake(PoolId),
    #[error("Delegation nonce overflow for id: {0}")]
    DelegationNonceOverflow(DelegationId),
    #[error("Empty inputs in token issuance transaction")]
    MissingTokenId,
    #[error("Unknown token with Id {0}")]
    UnknownTokenId(TokenId),
    #[error("Transaction creation error: {0}")]
    TransactionCreation(#[from] TransactionCreationError),
    #[error("Transaction signing error: {0}")]
    TransactionSig(#[from] TransactionSigError),
    #[error("Delegation not found with id {0}")]
    DelegationNotFound(DelegationId),
    #[error("Not enough UTXOs amount: {0:?}, required: {1:?}")]
    NotEnoughUtxo(Amount, Amount),
    #[error("Token issuance error: {0}")]
    TokenIssuance(#[from] TokenIssuanceError),
    #[error("No UTXOs")]
    NoUtxos,
    #[error("Coin selection error: {0}")]
    CoinSelectionError(#[from] UtxoSelectorError),
    #[error("Cannot abandon a transaction in {0} state")]
    CannotAbandonTransaction(TxState),
    #[error("Transaction with Id {0} not found")]
    CannotFindTransactionWithId(Id<Transaction>),
    #[error("Address error: {0}")]
    AddressError(#[from] AddressError),
    #[error("Unknown pool id {0}")]
    UnknownPoolId(PoolId),
    #[error("Cannot find UTXO")]
    CannotFindUtxo(UtxoOutPoint),
    #[error("Selected UTXO is already consumed")]
    ConsumedUtxo(UtxoOutPoint),
    #[error("Selected UTXO is still locked")]
    LockedUtxo(UtxoOutPoint),
}

/// Result type used for the wallet
pub type WalletResult<T> = Result<T, WalletError>;

pub struct Wallet<B: storage::Backend> {
    chain_config: Arc<ChainConfig>,
    db: Store<B>,
    key_chain: MasterKeyChain,
    accounts: BTreeMap<U31, Account>,
    latest_median_time: BlockTimestamp,
    next_unused_account: (U31, Account),
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct WalletSyncingState {
    pub account_best_blocks: BTreeMap<U31, (Id<GenBlock>, BlockHeight)>,
    pub unused_account_best_block: (Id<GenBlock>, BlockHeight),
}

pub fn open_or_create_wallet_file<P: AsRef<Path>>(path: P) -> WalletResult<Store<DefaultBackend>> {
    Ok(Store::new(DefaultBackend::new(path))?)
}

pub fn create_wallet_in_memory() -> WalletResult<Store<DefaultBackend>> {
    Ok(Store::new(DefaultBackend::new_in_memory())?)
}

impl<B: storage::Backend> Wallet<B> {
    pub fn create_new_wallet(
        chain_config: Arc<ChainConfig>,
        db: Store<B>,
        mnemonic: &str,
        passphrase: Option<&str>,
        save_seed_phrase: StoreSeedPhrase,
        best_block_height: BlockHeight,
        best_block_id: Id<GenBlock>,
    ) -> WalletResult<Self> {
        let mut wallet =
            Self::new_wallet(chain_config, db, mnemonic, passphrase, save_seed_phrase)?;

        wallet.set_best_block(best_block_height, best_block_id)?;

        Ok(wallet)
    }

    pub fn recover_wallet(
        chain_config: Arc<ChainConfig>,
        db: Store<B>,
        mnemonic: &str,
        passphrase: Option<&str>,
        save_seed_phrase: StoreSeedPhrase,
    ) -> WalletResult<Self> {
        Self::new_wallet(chain_config, db, mnemonic, passphrase, save_seed_phrase)
    }

    fn new_wallet(
        chain_config: Arc<ChainConfig>,
        db: Store<B>,
        mnemonic: &str,
        passphrase: Option<&str>,
        save_seed_phrase: StoreSeedPhrase,
    ) -> WalletResult<Self> {
        let mut db_tx = db.transaction_rw_unlocked(None)?;

        let key_chain = MasterKeyChain::new_from_mnemonic(
            chain_config.clone(),
            &mut db_tx,
            mnemonic,
            passphrase,
            save_seed_phrase,
        )?;

        db_tx.set_storage_version(CURRENT_WALLET_VERSION)?;
        db_tx.set_chain_info(&ChainInfo::new(chain_config.as_ref()))?;

        let default_account = Wallet::<B>::create_next_unused_account(
            U31::ZERO,
            chain_config.clone(),
            &key_chain,
            &mut db_tx,
            None,
        )?;

        let next_unused_account = Wallet::<B>::create_next_unused_account(
            U31::ONE,
            chain_config.clone(),
            &key_chain,
            &mut db_tx,
            None,
        )?;

        db_tx.commit()?;

        let latest_median_time = chain_config.genesis_block().timestamp();
        let wallet = Wallet {
            chain_config,
            db,
            key_chain,
            accounts: [default_account].into(),
            latest_median_time,
            next_unused_account,
        };

        Ok(wallet)
    }

    /// Migrate the wallet DB from version 1 to version 2
    /// * save the chain info in the DB based on the chain type specified by the user
    /// * reset transactions
    fn migration_v2(db: &Store<B>, chain_config: Arc<ChainConfig>) -> WalletResult<()> {
        let mut db_tx = db.transaction_rw_unlocked(None)?;
        // set new chain info to the one provided by the user assuming it is the correct one
        db_tx.set_chain_info(&ChainInfo::new(chain_config.as_ref()))?;

        // reset wallet transaction as now we will need to rescan the blockchain to store the
        // correct order of the transactions to avoid bugs in loading them in the wrong order
        Self::reset_wallet_transactions(chain_config.clone(), &mut db_tx)?;

        // Create the next unused account
        Self::migrate_next_unused_account(chain_config, &mut db_tx)?;

        db_tx.set_storage_version(CURRENT_WALLET_VERSION)?;
        db_tx.commit()?;
        logging::log::info!(
            "Successfully migrated wallet database to latest version {}",
            CURRENT_WALLET_VERSION
        );

        Ok(())
    }

    /// Check if the DB is in a supported version and if it needs a migration to be ran
    /// Returns true if a migration needs to be ran, false if it is already on the latest version
    /// and an error if it is an unsupported version
    pub fn check_db_needs_migration(db: &Store<B>) -> WalletResult<bool> {
        match db.get_storage_version()? {
            WALLET_VERSION_UNINITIALIZED => Err(WalletError::WalletNotInitialized),
            WALLET_VERSION_V1 => Ok(true),
            CURRENT_WALLET_VERSION => Ok(false),
            unsupported_version => Err(WalletError::UnsupportedWalletVersion(unsupported_version)),
        }
    }

    /// Check the wallet DB version and perform any migrations needed
    fn check_and_migrate_db(db: &Store<B>, chain_config: Arc<ChainConfig>) -> WalletResult<()> {
        match db.get_storage_version()? {
            WALLET_VERSION_UNINITIALIZED => return Err(WalletError::WalletNotInitialized),
            WALLET_VERSION_V1 => Self::migration_v2(db, chain_config)?,
            CURRENT_WALLET_VERSION => return Ok(()),
            unsupported_version => {
                return Err(WalletError::UnsupportedWalletVersion(unsupported_version))
            }
        }

        Ok(())
    }

    fn validate_chain_info(
        chain_config: &ChainConfig,
        db_tx: &impl WalletStorageReadLocked,
    ) -> WalletResult<()> {
        let chain_info = db_tx.get_chain_info()?;
        ensure!(
            chain_info.is_same(chain_config),
            WalletError::DifferentChainType
        );

        Ok(())
    }

    /// Reset all scanned transactions and revert all accounts to the genesis block
    /// this will cause the wallet to rescan the blockchain
    pub fn reset_wallet_to_genesis(&mut self) -> WalletResult<()> {
        let mut db_tx = self.db.transaction_rw(None)?;
        Self::reset_wallet_transactions(self.chain_config.clone(), &mut db_tx)
    }

    fn reset_wallet_transactions(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> WalletResult<()> {
        db_tx.clear_transactions()?;

        // set all accounts best block to genesis
        let accounts = db_tx.get_accounts_info()?;
        for (id, mut info) in accounts {
            info.update_best_block(BlockHeight::new(0), chain_config.genesis_block_id());
            db_tx.set_account(&id, &info)?;
            db_tx.set_account_unconfirmed_tx_counter(&id, 0)?;
            let mut account = Account::load_from_database(chain_config.clone(), db_tx, &id)?;
            account.scan_genesis(db_tx, &WalletEventsNoOp)?;
        }

        Ok(())
    }

    fn migrate_next_unused_account(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut impl WalletStorageWriteUnlocked,
    ) -> Result<(), WalletError> {
        let key_chain = MasterKeyChain::new_from_existing_database(chain_config.clone(), db_tx)?;
        let accounts_info = db_tx.get_accounts_info()?;
        let mut accounts: BTreeMap<U31, Account> = accounts_info
            .keys()
            .map(|account_id| Account::load_from_database(chain_config.clone(), db_tx, account_id))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|account| (account.account_index(), account))
            .collect();
        let last_account = accounts.pop_last().ok_or(WalletError::WalletNotInitialized)?;
        let next_account_index = last_account
            .0
            .plus_one()
            .map_err(|_| WalletError::AbsoluteMaxNumAccountsExceeded(last_account.0))?;
        Wallet::<B>::create_next_unused_account(
            next_account_index,
            chain_config.clone(),
            &key_chain,
            db_tx,
            None,
        )?;
        Ok(())
    }

    /// Resets the wallet's accounts to the genesis block so it can start to do a rescan of the
    /// blockchain
    pub fn reset_wallet(&mut self, wallet_events: &impl WalletEvents) -> WalletResult<()> {
        let mut db_tx = self.db.transaction_rw(None)?;

        for account in self.accounts.values_mut() {
            account.reset_to_height(&mut db_tx, wallet_events, BlockHeight::new(0))?;
        }

        Ok(())
    }

    pub fn load_wallet(
        chain_config: Arc<ChainConfig>,
        mut db: Store<B>,
        password: Option<String>,
    ) -> WalletResult<Self> {
        if let Some(password) = password {
            db.unlock_private_keys(&password)?;
        }
        Self::check_and_migrate_db(&db, chain_config.clone())?;

        // Please continue to use read-only transaction here.
        // Some unit tests expect that loading the wallet does not change the DB.
        let db_tx = db.transaction_ro()?;

        Self::validate_chain_info(chain_config.as_ref(), &db_tx)?;

        let key_chain = MasterKeyChain::new_from_existing_database(chain_config.clone(), &db_tx)?;

        let accounts_info = db_tx.get_accounts_info()?;

        let mut accounts: BTreeMap<U31, Account> = accounts_info
            .keys()
            .map(|account_id| {
                Account::load_from_database(Arc::clone(&chain_config), &db_tx, account_id)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|account| (account.account_index(), account))
            .collect();

        let latest_median_time =
            db_tx.get_median_time()?.unwrap_or(chain_config.genesis_block().timestamp());

        db_tx.close();

        let next_unused_account = accounts.pop_last().ok_or(WalletError::WalletNotInitialized)?;

        Ok(Wallet {
            chain_config,
            db,
            key_chain,
            accounts,
            latest_median_time,
            next_unused_account,
        })
    }

    pub fn seed_phrase(&self) -> WalletResult<Option<SerializableSeedPhrase>> {
        self.db.transaction_ro_unlocked()?.get_seed_phrase().map_err(WalletError::from)
    }

    pub fn delete_seed_phrase(&self) -> WalletResult<Option<SerializableSeedPhrase>> {
        let mut tx = self.db.transaction_rw_unlocked(None)?;
        let seed_phrase = tx.del_seed_phrase().map_err(WalletError::from)?;
        tx.commit()?;

        Ok(seed_phrase)
    }

    pub fn is_encrypted(&self) -> bool {
        self.db.is_encrypted()
    }

    pub fn is_locked(&self) -> bool {
        self.db.is_locked()
    }

    pub fn encrypt_wallet(&mut self, password: &Option<String>) -> WalletResult<()> {
        self.db.encrypt_private_keys(password).map_err(WalletError::from)
    }

    pub fn lock_wallet(&mut self) -> WalletResult<()> {
        self.db.lock_private_keys().map_err(WalletError::from)
    }

    pub fn unlock_wallet(&mut self, password: &String) -> WalletResult<()> {
        self.db.unlock_private_keys(password).map_err(WalletError::from)
    }

    pub fn account_indexes(&self) -> impl Iterator<Item = &U31> {
        self.accounts.keys()
    }

    pub fn number_of_accounts(&self) -> usize {
        self.accounts.len()
    }

    pub fn account_names(&self) -> impl Iterator<Item = &Option<String>> {
        self.accounts.values().map(|acc| acc.name())
    }

    fn create_next_unused_account(
        next_account_index: U31,
        chain_config: Arc<ChainConfig>,
        master_key_chain: &MasterKeyChain,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        name: Option<String>,
    ) -> WalletResult<(U31, Account)> {
        ensure!(
            name.as_ref().map_or(true, |name| !name.is_empty()),
            WalletError::EmptyAccountName
        );

        let account_key_chain =
            master_key_chain.create_account_key_chain(db_tx, next_account_index)?;

        let account = Account::new(chain_config, db_tx, account_key_chain, name)?;

        Ok((next_account_index, account))
    }

    /// Promotes the unused account into the used accounts and creates a new unused account
    /// Returns the new index and optional name if provided
    pub fn create_next_account(
        &mut self,
        name: Option<String>,
    ) -> WalletResult<(U31, Option<String>)> {
        ensure!(
            self.accounts
                .values()
                .last()
                .expect("must have a default account")
                .has_transactions(),
            WalletError::EmptyLastAccount
        );
        ensure!(
            name.as_ref().map_or(true, |name| !name.is_empty()),
            WalletError::EmptyAccountName
        );

        let next_account_index =
            self.next_unused_account.0.plus_one().map_err(|_| {
                WalletError::AbsoluteMaxNumAccountsExceeded(self.next_unused_account.0)
            })?;

        let mut db_tx = self.db.transaction_rw_unlocked(None)?;

        let mut next_unused_account = Self::create_next_unused_account(
            next_account_index,
            self.chain_config.clone(),
            &self.key_chain,
            &mut db_tx,
            None,
        )?;

        self.next_unused_account.1.set_name(name.clone(), &mut db_tx)?;
        std::mem::swap(&mut self.next_unused_account, &mut next_unused_account);
        let (next_account_index, next_account) = next_unused_account;

        // no need to rescan the blockchain from the start for the next unused account as we have been
        // scanning for addresses of the previous next unused account and it is not allowed to create a gap in
        // the account indexes
        let (best_block_id, best_block_height) = next_account.best_block();
        self.next_unused_account.1.update_best_block(
            &mut db_tx,
            best_block_height,
            best_block_id,
        )?;

        db_tx.commit()?;

        self.accounts.insert(next_account_index, next_account);

        Ok((next_account_index, name))
    }

    pub fn database(&self) -> &Store<B> {
        &self.db
    }

    fn for_account_rw<T>(
        &mut self,
        account_index: U31,
        f: impl FnOnce(&mut Account, &mut StoreTxRw<B>) -> WalletResult<T>,
    ) -> WalletResult<T> {
        let mut db_tx = self.db.transaction_rw(None)?;
        let account = Self::get_account_mut(&mut self.accounts, account_index)?;
        let value = f(account, &mut db_tx)?;
        // The in-memory wallet state has already changed, so rolling back
        // the DB transaction will make the wallet state inconsistent.
        // This should not happen with the sqlite backend in normal situations,
        // so let's abort the process instead.
        db_tx.commit().expect("RW transaction commit failed unexpectedly");
        Ok(value)
    }

    fn for_account_rw_unlocked<T>(
        &mut self,
        account_index: U31,
        f: impl FnOnce(&mut Account, &mut StoreTxRwUnlocked<B>) -> WalletResult<T>,
    ) -> WalletResult<T> {
        let mut db_tx = self.db.transaction_rw_unlocked(None)?;
        let account = Self::get_account_mut(&mut self.accounts, account_index)?;
        match f(account, &mut db_tx) {
            Ok(value) => {
                // Abort the process if the DB transaction fails. See `for_account_rw` for more information.
                db_tx.commit().expect("RW transaction commit failed unexpectedly");
                Ok(value)
            }
            Err(err) => {
                db_tx.abort();
                // In case of an error reload the keys in case the operation issued new ones and
                // are saved in the cache but not in the DB
                let db_tx = self.db.transaction_ro()?;
                account.reload_keys(&db_tx)?;
                Err(err)
            }
        }
    }

    fn get_account(&self, account_index: U31) -> WalletResult<&Account> {
        self.accounts
            .get(&account_index)
            .ok_or(WalletError::NoAccountFoundWithIndex(account_index))
    }

    fn get_account_mut(
        accounts: &mut BTreeMap<U31, Account>,
        account_index: U31,
    ) -> WalletResult<&mut Account> {
        accounts
            .get_mut(&account_index)
            .ok_or(WalletError::NoAccountFoundWithIndex(account_index))
    }

    pub fn get_balance(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> WalletResult<BTreeMap<Currency, Amount>> {
        self.get_account(account_index)?.get_balance(
            utxo_types,
            utxo_states,
            self.latest_median_time,
            with_locked,
        )
    }

    pub fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> WalletResult<BTreeMap<UtxoOutPoint, TxOutput>> {
        let account = self.get_account(account_index)?;
        let utxos = account.get_utxos(
            utxo_types,
            self.latest_median_time,
            utxo_states,
            with_locked,
        );
        let utxos = utxos
            .into_iter()
            .map(|(outpoint, (txo, _token_id))| (outpoint, txo.clone()))
            .collect();
        Ok(utxos)
    }

    pub fn pending_transactions(
        &self,
        account_index: U31,
    ) -> WalletResult<Vec<&WithId<Transaction>>> {
        let account = self.get_account(account_index)?;
        let transactions = account.pending_transactions();
        Ok(transactions)
    }

    pub fn abandon_transaction(
        &mut self,
        account_index: U31,
        tx_id: Id<Transaction>,
    ) -> WalletResult<()> {
        self.for_account_rw(account_index, |account, db_tx| {
            account.abandon_transaction(tx_id, db_tx)
        })
    }

    pub fn get_pool_ids(&self, account_index: U31) -> WalletResult<Vec<(PoolId, BlockInfo)>> {
        let pool_ids = self.get_account(account_index)?.get_pool_ids();
        Ok(pool_ids)
    }

    pub fn get_delegations(
        &self,
        account_index: U31,
    ) -> WalletResult<impl Iterator<Item = (&DelegationId, &DelegationData)>> {
        let delegations = self.get_account(account_index)?.get_delegations();
        Ok(delegations)
    }

    pub fn get_delegation(
        &self,
        account_index: U31,
        delegation_id: DelegationId,
    ) -> WalletResult<&DelegationData> {
        self.get_account(account_index)?.find_delegation(&delegation_id)
    }

    pub fn get_new_address(
        &mut self,
        account_index: U31,
    ) -> WalletResult<(ChildNumber, Address<Destination>)> {
        self.for_account_rw(account_index, |account, db_tx| {
            account.get_new_address(db_tx, KeyPurpose::ReceiveFunds)
        })
    }

    pub fn get_new_public_key(&mut self, account_index: U31) -> WalletResult<PublicKey> {
        self.for_account_rw(account_index, |account, db_tx| {
            account.get_new_public_key(db_tx, KeyPurpose::ReceiveFunds)
        })
    }

    pub fn get_transaction_list(
        &self,
        account_index: U31,
        skip: usize,
        count: usize,
    ) -> WalletResult<TransactionList> {
        let account = self.get_account(account_index)?;
        account.get_transaction_list(skip, count)
    }

    pub fn get_transactions_to_be_broadcast(&self) -> WalletResult<Vec<SignedTransaction>> {
        self.db
            .transaction_ro()?
            .get_user_transactions()
            .map_err(WalletError::DatabaseError)
    }

    pub fn get_all_issued_addresses(
        &self,
        account_index: U31,
    ) -> WalletResult<BTreeMap<ChildNumber, Address<Destination>>> {
        let account = self.get_account(account_index)?;
        Ok(account.get_all_issued_addresses())
    }

    pub fn get_addresses_usage(&self, account_index: U31) -> WalletResult<&KeychainUsageState> {
        let account = self.get_account(account_index)?;
        Ok(account.get_addresses_usage())
    }

    pub fn get_vrf_public_key(&mut self, account_index: U31) -> WalletResult<VRFPublicKey> {
        let db_tx = self.db.transaction_ro_unlocked()?;
        self.get_account(account_index)?.get_vrf_public_key(&db_tx)
    }

    /// Creates a transaction to send funds to specified addresses.
    ///
    /// # Arguments
    ///
    /// * `&mut self` - A mutable reference to the wallet instance.
    /// * `account_index: U31` - The index of the account from which funds will be sent.
    /// * `outputs: impl IntoIterator<Item = TxOutput>` - An iterator over `TxOutput` items representing the addresses and amounts to which funds will be sent.
    /// * `current_fee_rate: FeeRate` - The current fee rate based on the mempool to be used for the transaction.
    /// * `consolidate_fee_rate: FeeRate` - The fee rate in case of a consolidation event, if the
    /// current_fee_rate is lower than the consolidate_fee_rate then the wallet will tend to
    /// use and consolidate multiple smaller inputs, else if the current_fee_rate is higher it will
    /// tend to use inputs with lowest fee.
    ///
    /// # Returns
    ///
    /// A `WalletResult` containing the signed transaction if successful, or an error indicating the reason for failure.
    pub fn create_transaction_to_addresses(
        &mut self,
        account_index: U31,
        outputs: impl IntoIterator<Item = TxOutput>,
        inputs: impl IntoIterator<Item = UtxoOutPoint>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        let request = SendRequest::new().with_outputs(outputs);
        let latest_median_time = self.latest_median_time;
        self.for_account_rw_unlocked(account_index, |account, db_tx| {
            let inputs = inputs.into_iter().collect();
            account.process_send_request(
                db_tx,
                request,
                inputs,
                latest_median_time,
                current_fee_rate,
                consolidate_fee_rate,
            )
        })
    }

    pub fn create_transaction_to_addresses_from_delegation(
        &mut self,
        account_index: U31,
        address: Address<Destination>,
        amount: Amount,
        delegation_id: DelegationId,
        delegation_share: Amount,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        self.for_account_rw_unlocked(account_index, |account, db_tx| {
            account.spend_from_delegation(
                db_tx,
                address,
                amount,
                delegation_id,
                delegation_share,
                current_fee_rate,
            )
        })
    }

    pub fn create_delegation(
        &mut self,
        account_index: U31,
        outputs: Vec<TxOutput>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<(DelegationId, SignedTransaction)> {
        let tx = self.create_transaction_to_addresses(
            account_index,
            outputs,
            [],
            current_fee_rate,
            consolidate_fee_rate,
        )?;
        let input0_outpoint = tx
            .transaction()
            .inputs()
            .get(0)
            .ok_or(WalletError::NoUtxos)?
            .utxo_outpoint()
            .ok_or(WalletError::NoUtxos)?;
        let delegation_id = make_delegation_id(input0_outpoint);
        Ok((delegation_id, tx))
    }

    pub fn issue_new_token(
        &mut self,
        account_index: U31,
        address: Address<Destination>,
        token_issuance: TokenIssuanceV0,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<(TokenId, SignedTransaction)> {
        let outputs =
            make_issue_token_outputs(address, token_issuance, self.chain_config.as_ref())?;

        let tx = self.create_transaction_to_addresses(
            account_index,
            outputs,
            [],
            current_fee_rate,
            consolidate_fee_rate,
        )?;
        let token_id = token_id(tx.transaction()).ok_or(WalletError::MissingTokenId)?;
        Ok((token_id, tx))
    }

    pub fn issue_new_nft(
        &mut self,
        account_index: U31,
        address: Address<Destination>,
        metadata: Metadata,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<(TokenId, SignedTransaction)> {
        let outputs = make_issue_nft_outputs(address, metadata, self.chain_config.as_ref())?;

        let tx = self.create_transaction_to_addresses(
            account_index,
            outputs,
            [],
            current_fee_rate,
            consolidate_fee_rate,
        )?;
        let token_id = token_id(tx.transaction()).ok_or(WalletError::MissingTokenId)?;
        Ok((token_id, tx))
    }

    pub fn create_stake_pool_tx(
        &mut self,
        account_index: U31,
        decommission_key: Option<PublicKey>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        stake_pool_arguments: StakePoolDataArguments,
    ) -> WalletResult<SignedTransaction> {
        let latest_median_time = self.latest_median_time;
        self.for_account_rw_unlocked(account_index, |account, db_tx| {
            account.create_stake_pool_tx(
                db_tx,
                stake_pool_arguments,
                decommission_key,
                latest_median_time,
                current_fee_rate,
                consolidate_fee_rate,
            )
        })
    }

    pub fn decommission_stake_pool(
        &mut self,
        account_index: U31,
        pool_id: PoolId,
        pool_balance: Amount,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        self.for_account_rw_unlocked(account_index, |account, db_tx| {
            account.decommission_stake_pool(db_tx, pool_id, pool_balance, current_fee_rate)
        })
    }

    pub fn get_pos_gen_block_data(
        &self,
        account_index: U31,
        pool_id: PoolId,
    ) -> WalletResult<PoSGenerateBlockInputData> {
        let db_tx = self.db.transaction_ro_unlocked()?;
        self.get_account(account_index)?.get_pos_gen_block_data(
            &db_tx,
            self.latest_median_time,
            pool_id,
        )
    }

    /// Returns the last scanned block hash and height for all accounts.
    /// Returns genesis block when the wallet is just created.
    pub fn get_best_block(&self) -> BTreeMap<U31, (Id<GenBlock>, BlockHeight)> {
        self.accounts
            .iter()
            .map(|(index, account)| (*index, account.best_block()))
            .collect()
    }

    /// Returns the last scanned block hash and height for the account.
    /// Returns genesis block when the account is just created.
    pub fn get_best_block_for_account(
        &self,
        account_index: U31,
    ) -> WalletResult<(Id<GenBlock>, BlockHeight)> {
        Ok(self.get_account(account_index)?.best_block())
    }

    /// Returns the syncing state of the wallet
    /// includes the last scanned block hash and height for each account and the next unused one
    /// if in syncing state else NewlyCreated if this is the first sync after creating a new wallet
    pub fn get_syncing_state(&self) -> WalletSyncingState {
        WalletSyncingState {
            account_best_blocks: self.get_best_block(),
            unused_account_best_block: self.next_unused_account.1.best_block(),
        }
    }

    /// Scan new blocks and update best block hash/height.
    /// New block may reset the chain of previously scanned blocks.
    ///
    /// `common_block_height` is the height of the shared blocks that are still in sync after reorgs.
    /// If `common_block_height` is zero, only the genesis block is considered common.
    pub fn scan_new_blocks(
        &mut self,
        account_index: U31,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        self.for_account_rw(account_index, |acc, db_tx| {
            acc.scan_new_blocks(db_tx, wallet_events, common_block_height, &blocks)
        })?;

        wallet_events.new_block();
        Ok(())
    }

    /// Scan new blocks and update best block hash/height.
    /// New block may reset the chain of previously scanned blocks.
    ///
    /// `common_block_height` is the height of the shared blocks that are still in sync after reorgs.
    /// If `common_block_height` is zero, only the genesis block is considered common.
    /// If a new transaction is recognized for the unused account, it is transferred to the used
    /// accounts and a new unused account is created.
    pub fn scan_new_blocks_unused_account(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        loop {
            let mut db_tx = self.db.transaction_rw(None)?;
            let added_new_tx_in_unused_acc = self.next_unused_account.1.scan_new_blocks(
                &mut db_tx,
                wallet_events,
                common_block_height,
                &blocks,
            )?;

            db_tx.commit()?;

            if added_new_tx_in_unused_acc {
                self.create_next_account(None)?;
            } else {
                break;
            }
        }

        wallet_events.new_block();
        Ok(())
    }

    /// Sets the best block for all accounts
    /// Should be called after creating a new wallet
    fn set_best_block(
        &mut self,
        best_block_height: BlockHeight,
        best_block_id: Id<GenBlock>,
    ) -> WalletResult<()> {
        let mut db_tx = self.db.transaction_rw(None)?;

        for account in self.accounts.values_mut() {
            account.update_best_block(&mut db_tx, best_block_height, best_block_id)?;
        }

        self.next_unused_account.1.update_best_block(
            &mut db_tx,
            best_block_height,
            best_block_id,
        )?;

        db_tx.commit()?;

        Ok(())
    }

    /// Rescan mempool for unconfirmed transactions and UTXOs
    /// TODO: Currently we don't sync with the mempool
    #[cfg(test)]
    pub fn scan_mempool(
        &mut self,
        transactions: &[SignedTransaction],
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        let mut db_tx = self.db.transaction_rw(None)?;

        for account in self.accounts.values_mut() {
            account.scan_new_inmempool_transactions(transactions, &mut db_tx, wallet_events)?;
        }

        Ok(())
    }

    /// Save an unconfirmed transaction in case we need to rebroadcast it later
    /// and mark it as Inactive for now
    pub fn add_unconfirmed_tx(
        &mut self,
        transaction: SignedTransaction,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        let mut db_tx = self.db.transaction_rw(None)?;

        let txs = [transaction];
        for account in self.accounts.values_mut() {
            account.scan_new_inactive_transactions(&txs, &mut db_tx, wallet_events)?;
        }

        Ok(())
    }

    pub fn set_median_time(&mut self, median_time: BlockTimestamp) -> WalletResult<()> {
        self.latest_median_time = median_time;
        self.db.transaction_rw(None)?.set_median_time(median_time)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
