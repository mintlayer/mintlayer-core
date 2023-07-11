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

use crate::account::{Currency, UtxoSelectorError};
use crate::key_chain::{KeyChainError, MasterKeyChain};
use crate::{Account, SendRequest};
pub use bip39::{Language, Mnemonic};
use common::address::pubkeyhash::PublicKeyHashError;
use common::address::Address;
use common::chain::block::timestamp::BlockTimestamp;
use common::chain::signature::TransactionSigError;
use common::chain::{
    Block, ChainConfig, GenBlock, SignedTransaction, Transaction, TransactionCreationError,
    TxOutput, UtxoOutPoint,
};
use common::primitives::{Amount, BlockHeight, Id};
use consensus::PoSGenerateBlockInputData;
use crypto::key::hdkd::u31::U31;
use crypto::key::PublicKey;
use crypto::vrf::VRFPublicKey;
use itertools::Itertools;
use utils::ensure;
use wallet_storage::{
    DefaultBackend, Store, StoreTxRw, TransactionRoLocked, TransactionRwLocked, Transactional,
    WalletStorageReadLocked, WalletStorageWriteLocked,
};
use wallet_storage::{StoreTxRwUnlocked, TransactionRwUnlocked};
use wallet_types::utxo_types::UtxoTypes;
use wallet_types::{AccountId, KeyPurpose};

pub const WALLET_VERSION_UNINITIALIZED: u32 = 0;
pub const WALLET_VERSION_V1: u32 = 1;
pub const CURRENT_WALLET_VERSION: u32 = WALLET_VERSION_V1;

/// Wallet errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum WalletError {
    #[error("Wallet is not initialized")]
    WalletNotInitialized,
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
    #[error("Account with index {0} is not synced yet")]
    AccountNotSyncedWithIndex(U31),
    #[error("Account with index {0} already exists")]
    AccountAlreadyExists(U31),
    #[error("Cannot create a new account when last account is still empty")]
    EmptyLastAccount,
    #[error("Cannot create a new account with an empty string name")]
    EmptyAccountName,
    #[error("Cannot create a new account when last account is still not in sync")]
    LastAccountNotInSync,
    #[error("The maximum number of accounts has been exceeded: {0}")]
    AbsoluteMaxNumAccountsExceeded(U31),
    #[error("No unsynced account")]
    NoUnsyncedAccount,
    #[error("Not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("The send request is complete")]
    SendRequestComplete,
    #[error("Unsupported transaction output type")] // TODO implement display for TxOutput
    UnsupportedTransactionOutput(Box<TxOutput>),
    #[error("Output amounts overflow")]
    OutputAmountOverflow,
    #[error("Empty inputs in token issuance transaction")]
    MissingTokenId,
    #[error("Transaction creation error: {0}")]
    TransactionCreation(#[from] TransactionCreationError),
    #[error("Transaction signing error: {0}")]
    TransactionSig(#[from] TransactionSigError),
    #[error("Not enough UTXOs amount: {0:?}, required: {1:?}")]
    NotEnoughUtxo(Amount, Amount),
    #[error("Invalid address {0}: {1}")]
    InvalidAddress(String, PublicKeyHashError),
    #[error("No UTXOs")]
    NoUtxos,
    #[error("Coin selection error: {0}")]
    CoinSelectionError(#[from] UtxoSelectorError),
}

/// Result type used for the wallet
pub type WalletResult<T> = Result<T, WalletError>;

pub struct Wallet<B: storage::Backend> {
    chain_config: Arc<ChainConfig>,
    db: Store<B>,
    key_chain: MasterKeyChain,
    accounts: BTreeMap<U31, Account>,
    latest_median_time: BlockTimestamp,
    unsynced_accounts: BTreeMap<U31, Account>,
}

pub fn open_or_create_wallet_file<P: AsRef<Path>>(path: P) -> WalletResult<Store<DefaultBackend>> {
    Ok(Store::new(DefaultBackend::new(path))?)
}

pub fn create_wallet_in_memory() -> WalletResult<Store<DefaultBackend>> {
    Ok(Store::new(DefaultBackend::new_in_memory())?)
}

impl<B: storage::Backend> Wallet<B> {
    pub fn new_wallet(
        chain_config: Arc<ChainConfig>,
        db: Store<B>,
        mnemonic: &str,
        passphrase: Option<&str>,
    ) -> WalletResult<Self> {
        let mut db_tx = db.transaction_rw_unlocked(None)?;

        // TODO wallet should save the chain config

        let key_chain = MasterKeyChain::new_from_mnemonic(
            chain_config.clone(),
            &mut db_tx,
            mnemonic,
            passphrase,
        )?;

        db_tx.set_storage_version(CURRENT_WALLET_VERSION)?;

        db_tx.commit()?;

        let latest_median_time = chain_config.genesis_block().timestamp();
        let mut wallet = Wallet {
            chain_config,
            db,
            key_chain,
            accounts: BTreeMap::new(),
            latest_median_time,
            unsynced_accounts: BTreeMap::new(),
        };

        wallet.create_account(None)?;

        Ok(wallet)
    }

    pub fn load_wallet(chain_config: Arc<ChainConfig>, db: Store<B>) -> WalletResult<Self> {
        // Please continue to use read-only transaction here.
        // Some unit tests expect that loading the wallet does not change the DB.
        let db_tx = db.transaction_ro()?;

        let version = db_tx.get_storage_version()?;
        if version == WALLET_VERSION_UNINITIALIZED {
            return Err(WalletError::WalletNotInitialized);
        }

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

        let unsynced_accounts = accounts
            .values()
            .tuple_windows()
            .find_map(|(acc1, acc2)| {
                (acc1.best_block() != acc2.best_block()).then(|| acc2.account_index())
            })
            .map(|first_unsynced| accounts.split_off(&first_unsynced))
            .unwrap_or_default();

        Ok(Wallet { chain_config, db, key_chain, accounts, latest_median_time, unsynced_accounts })
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
        self.accounts.len() + self.unsynced_accounts.len()
    }

    pub fn account_names(&self) -> Vec<&Option<String>> {
        self.accounts
            .values()
            .chain(self.unsynced_accounts.values())
            .map(|acc| acc.name())
            .collect_vec()
    }

    pub fn create_account(&mut self, name: Option<String>) -> WalletResult<(U31, Option<String>)> {
        ensure!(self.unsynced_accounts.is_empty(), WalletError::LastAccountNotInSync);

        let next_account_index = self.accounts.last_key_value().map_or(
            Ok(U31::ZERO),
            |(last_account_index, last_account)| {
                if last_account.has_transactions() {
                    last_account_index.plus_one().map_err(|_| {
                        WalletError::AbsoluteMaxNumAccountsExceeded(*last_account_index)
                    })
                } else {
                    // Cannot create a new account if the latest created one has no transactions
                    // associated with it
                    Err(WalletError::EmptyLastAccount)
                }
            },
        )?;

        ensure!(name.as_ref().map_or(true, |name| !name.is_empty()), WalletError::EmptyAccountName);

        let mut db_tx = self.db.transaction_rw_unlocked(None)?;

        let account_key_chain =
            self.key_chain.create_account_key_chain(&mut db_tx, next_account_index)?;

        let account = Account::new(
            Arc::clone(&self.chain_config),
            &mut db_tx,
            account_key_chain,
            name.clone(),
        )?;

        db_tx.commit()?;

        // if it is the only one insert it directly to accounts
        if self.accounts.is_empty() {
            self.accounts.insert(account.account_index(), account);
        } else {
            // else it is unsynced as the other accounts have already processed blocks
            self.unsynced_accounts.insert(account.account_index(), account);
        }

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
        let account =
            Self::get_account_mut(&mut self.accounts, &self.unsynced_accounts, account_index)?;
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
        let account =
            Self::get_account_mut(&mut self.accounts, &self.unsynced_accounts, account_index)?;
        let value = f(account, &mut db_tx)?;
        // Abort the process if the DB transaction fails. See `for_account_rw` for more information.
        db_tx.commit().expect("RW transaction commit failed unexpectedly");
        Ok(value)
    }

    fn get_account(&self, account_index: U31) -> WalletResult<&Account> {
        self.accounts
            .get(&account_index)
            .ok_or(WalletError::NoAccountFoundWithIndex(account_index))
            .map_err(|err| match self.unsynced_accounts.get(&account_index) {
                Some(_) => WalletError::AccountNotSyncedWithIndex(account_index),
                _ => err,
            })
    }

    fn get_account_mut<'a>(
        accounts: &'a mut BTreeMap<U31, Account>,
        unsynced_accounts: &BTreeMap<U31, Account>,
        account_index: U31,
    ) -> WalletResult<&'a mut Account> {
        accounts
            .get_mut(&account_index)
            .ok_or(WalletError::NoAccountFoundWithIndex(account_index))
            .map_err(|err| match unsynced_accounts.get(&account_index) {
                Some(_) => WalletError::AccountNotSyncedWithIndex(account_index),
                _ => err,
            })
    }

    pub fn get_balance(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
    ) -> WalletResult<BTreeMap<Currency, Amount>> {
        self.get_account(account_index)?
            .get_balance(utxo_types, self.latest_median_time)
    }

    pub fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
    ) -> WalletResult<BTreeMap<UtxoOutPoint, TxOutput>> {
        let account = self.get_account(account_index)?;
        let utxos = account.get_utxos(utxo_types, self.latest_median_time);
        let utxos = utxos
            .into_iter()
            .map(|(outpoint, (txo, _token_id))| (outpoint, txo.clone()))
            .collect();
        Ok(utxos)
    }

    pub fn get_new_address(&mut self, account_index: U31) -> WalletResult<Address> {
        self.for_account_rw(account_index, |account, db_tx| {
            account.get_new_address(db_tx, KeyPurpose::ReceiveFunds)
        })
    }

    pub fn get_new_public_key(&mut self, account_index: U31) -> WalletResult<PublicKey> {
        self.for_account_rw(account_index, |account, db_tx| {
            account.get_new_public_key(db_tx, KeyPurpose::ReceiveFunds)
        })
    }

    pub fn get_vrf_public_key(&mut self, account_index: U31) -> WalletResult<VRFPublicKey> {
        let db_tx = self.db.transaction_ro_unlocked()?;
        self.get_account(account_index)?.get_vrf_public_key(&db_tx)
    }

    pub fn create_transaction_to_addresses(
        &mut self,
        account_index: U31,
        outputs: impl IntoIterator<Item = TxOutput>,
    ) -> WalletResult<SignedTransaction> {
        let request = SendRequest::new().with_outputs(outputs);
        let latest_median_time = self.latest_median_time;
        self.for_account_rw_unlocked(account_index, |account, db_tx| {
            account.process_send_request(db_tx, request, latest_median_time)
        })
    }

    pub fn create_stake_pool_tx(
        &mut self,
        account_index: U31,
        amount: Amount,
        decomission_key: Option<PublicKey>,
    ) -> WalletResult<SignedTransaction> {
        let latest_median_time = self.latest_median_time;
        self.for_account_rw_unlocked(account_index, |account, db_tx| {
            account.create_stake_pool_tx(db_tx, amount, decomission_key, latest_median_time)
        })
    }

    pub fn get_pos_gen_block_data(
        &mut self,
        account_index: U31,
    ) -> WalletResult<PoSGenerateBlockInputData> {
        let db_tx = self.db.transaction_ro_unlocked()?;
        self.get_account(account_index)?
            .get_pos_gen_block_data(&db_tx, self.latest_median_time)
    }

    /// Returns the last scanned block hash and height.
    /// Returns genesis block when the wallet is just created.
    pub fn get_best_block(&self) -> WalletResult<(Id<GenBlock>, BlockHeight)> {
        // all synced accounts should have the same best block
        let account = self.accounts.values().next().ok_or(WalletError::WalletNotInitialized)?;
        Ok(account.best_block())
    }

    /// Returns the last scanned block hash and height for the unsynced_account.
    /// Returns genesis block when the account is just created.
    pub fn get_best_block_for_unsynced_account(&self) -> Option<(Id<GenBlock>, BlockHeight)> {
        self.unsynced_accounts.values().next().map(|acc| acc.best_block())
    }

    /// Scan new blocks and update best block hash/height.
    /// New block may reset the chain of previously scanned blocks.
    ///
    /// `common_block_height` is the height of the shared blocks that are still in sync after reorgs.
    /// If `common_block_height` is zero, only the genesis block is considered common.
    pub fn scan_new_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> WalletResult<()> {
        let mut db_tx = self.db.transaction_rw(None)?;

        for account in self.accounts.values_mut() {
            account.scan_new_blocks(&mut db_tx, common_block_height, &blocks)?;
        }

        db_tx.commit()?;

        Ok(())
    }

    /// Scan new blocks and update best block hash/height for the unsynced_account.
    /// New block may reset the chain of previously scanned blocks.
    ///
    /// `common_block_height` is the height of the shared blocks that are still in sync after reorgs.
    /// If `common_block_height` is zero, only the genesis block is considered common.
    pub fn scan_new_blocks_for_unsynced_account(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> WalletResult<()> {
        let mut db_tx = self.db.transaction_rw(None)?;

        let account = self
            .unsynced_accounts
            .values_mut()
            .next()
            .ok_or(WalletError::NoUnsyncedAccount)?;

        account.scan_new_blocks(&mut db_tx, common_block_height, &blocks)?;

        db_tx.commit()?;

        let synced_best_block_height = self
            .accounts
            .values()
            .next()
            .ok_or(WalletError::WalletNotInitialized)?
            .best_block()
            .1;

        if account.best_block().1 == synced_best_block_height {
            self.unsynced_accounts
                .pop_first()
                .map(|(index, acc)| self.accounts.insert(index, acc));
        }

        Ok(())
    }

    /// Rescan mempool for unconfirmed transactions and UTXOs
    pub fn scan_mempool(&mut self, _transactions: Vec<SignedTransaction>) -> WalletResult<()> {
        Err(WalletError::NotImplemented("scan_mempool"))
    }

    pub fn set_median_time(&mut self, median_time: BlockTimestamp) -> WalletResult<()> {
        self.latest_median_time = median_time;
        self.db.transaction_rw(None)?.set_median_time(median_time)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
