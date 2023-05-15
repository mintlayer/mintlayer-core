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

use crate::key_chain::{KeyChainError, MasterKeyChain};
use crate::{Account, SendRequest};
pub use bip39::{Language, Mnemonic};
use common::address::pubkeyhash::{PublicKeyHash, PublicKeyHashError};
use common::address::Address;
use common::chain::signature::TransactionSigError;
use common::chain::tokens::{OutputValue, TokenId};
use common::chain::{
    Block, ChainConfig, Destination, GenBlock, SignedTransaction, Transaction,
    TransactionCreationError, TxOutput,
};
use common::primitives::{Amount, BlockHeight, Id};
use crypto::key::hdkd::u31::U31;
use utils::ensure;
use wallet_storage::{
    DefaultBackend, Store, StoreTxRo, StoreTxRw, TransactionRo, TransactionRw, Transactional,
    WalletStorageRead, WalletStorageWrite,
};
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
    #[error("Account with index {0} already exists")]
    AccountAlreadyExists(U31),
    #[error("Not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("The send request is complete")]
    SendRequestComplete,
    #[error("Unsupported transaction output type")] // TODO implement display for TxOutput
    UnsupportedTransactionOutput(Box<TxOutput>),
    #[error("Output amounts overflow")]
    OutputAmountOverflow,
    #[error("Transaction creation error: {0}")]
    TransactionCreation(#[from] TransactionCreationError),
    #[error("Transaction signing error: {0}")]
    TransactionSig(#[from] TransactionSigError),
    #[error("Not enough UTXOs amount: {0:?}, required: {1:?}")]
    NotEnoughUtxo(Amount, Amount),
    #[error("Invalid address {0}: {1}")]
    InvalidAddress(String, PublicKeyHashError),
}

/// Result type used for the wallet
pub type WalletResult<T> = Result<T, WalletError>;

#[allow(dead_code)] // TODO remove
pub struct Wallet<B: storage::Backend> {
    chain_config: Arc<ChainConfig>,
    db: Arc<Store<B>>,
    // key_chain: MasterKeyChain<B>,
    key_chain: MasterKeyChain,
    accounts: BTreeMap<U31, Account>,
    best_block_height: BlockHeight,
    best_block_id: Id<GenBlock>,
}

pub fn open_or_create_wallet_file<P: AsRef<Path>>(
    path: P,
) -> WalletResult<Arc<Store<DefaultBackend>>> {
    Ok(Arc::new(Store::new(DefaultBackend::new(path))?))
}

pub fn open_or_create_wallet_in_memory() -> WalletResult<Arc<Store<DefaultBackend>>> {
    Ok(Arc::new(Store::new(DefaultBackend::new_in_memory())?))
}

impl<B: storage::Backend> Wallet<B> {
    pub fn new_wallet(
        chain_config: Arc<ChainConfig>,
        db: Arc<Store<B>>,
        mnemonic: &str,
        passphrase: Option<&str>,
    ) -> WalletResult<Self> {
        let mut db_tx = db.transaction_rw(None)?;

        // TODO wallet should save the chain config

        let key_chain = MasterKeyChain::new_from_mnemonic(
            chain_config.clone(),
            &mut db_tx,
            mnemonic,
            passphrase,
        )?;

        db_tx.set_storage_version(CURRENT_WALLET_VERSION)?;

        db_tx.commit()?;

        let best_block_id = chain_config.genesis_block_id();
        let best_block_height = BlockHeight::zero();

        Ok(Wallet {
            chain_config,
            db,
            key_chain,
            accounts: BTreeMap::new(),
            best_block_id,
            best_block_height,
        })
    }

    pub fn load_wallet(chain_config: Arc<ChainConfig>, db: Arc<Store<B>>) -> WalletResult<Self> {
        let db_tx = db.transaction_ro()?;

        let version = db_tx.get_storage_version()?;
        if version == WALLET_VERSION_UNINITIALIZED {
            return Err(WalletError::WalletNotInitialized);
        }

        let key_chain = MasterKeyChain::load_from_database(Arc::clone(&chain_config), &db_tx)?;

        let account_infos = db_tx.get_account_infos()?;

        let accounts = account_infos
            .keys()
            .map(|account_id| {
                Account::load_from_database(
                    Arc::clone(&chain_config),
                    &db_tx,
                    account_id,
                    key_chain.root_private_key(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|account| (account.account_index(), account))
            .collect();

        db_tx.close();

        // TODO: Load best_block_id and best_block_height from DB
        let best_block_id = chain_config.genesis_block_id();
        let best_block_height = BlockHeight::zero();

        Ok(Wallet {
            chain_config,
            db,
            key_chain,
            accounts,
            best_block_id,
            best_block_height,
        })
    }

    pub fn create_account(&mut self, account_index: U31) -> WalletResult<()> {
        ensure!(
            !self.accounts.contains_key(&account_index),
            WalletError::AccountAlreadyExists(account_index)
        );

        let mut db_tx = self.db.transaction_rw(None)?;

        let account_key_chain =
            self.key_chain.create_account_key_chain(&mut db_tx, account_index)?;

        let account = Account::new(
            Arc::clone(&self.chain_config),
            &mut db_tx,
            account_key_chain,
        )?;

        db_tx.commit()?;

        // TODO: Rescan blockchain

        self.accounts.insert(account.account_index(), account);

        Ok(())
    }

    pub fn database(&self) -> &Store<B> {
        &self.db
    }

    fn for_account_ro<T>(
        &self,
        account_index: U31,
        f: impl FnOnce(&Account, &StoreTxRo<B>) -> WalletResult<T>,
    ) -> WalletResult<T> {
        let mut db_tx = self.db.transaction_ro()?;
        let account = self
            .accounts
            .get(&account_index)
            .ok_or(WalletError::NoAccountFoundWithIndex(account_index))?;
        let value = f(account, &mut db_tx)?;
        db_tx.close();
        Ok(value)
    }

    fn for_account_rw<T>(
        &mut self,
        account_index: U31,
        f: impl FnOnce(&mut Account, &mut StoreTxRw<B>) -> WalletResult<T>,
    ) -> WalletResult<T> {
        let mut db_tx = self.db.transaction_rw(None)?;
        let account = self
            .accounts
            .get_mut(&account_index)
            .ok_or(WalletError::NoAccountFoundWithIndex(account_index))?;
        let value = f(account, &mut db_tx)?;
        db_tx.commit()?;
        Ok(value)
    }

    pub fn get_balance(
        &self,
        account_index: U31,
    ) -> WalletResult<(Amount, BTreeMap<TokenId, Amount>)> {
        self.for_account_ro(account_index, |account, db_tx| account.get_balance(db_tx))
    }

    pub fn get_new_address(&mut self, account_index: U31) -> WalletResult<Address> {
        self.for_account_rw(account_index, |account, db_tx| {
            account.get_new_address(db_tx, KeyPurpose::ReceiveFunds)
        })
    }

    pub fn send_to_address(
        &mut self,
        account_index: U31,
        address: Address,
        amount: Amount,
    ) -> WalletResult<SignedTransaction> {
        let pub_key_hash = PublicKeyHash::try_from(&address)
            .map_err(|e| WalletError::InvalidAddress(address.get().to_owned(), e))?;
        let request = SendRequest::transfer_to_destination(
            OutputValue::Coin(amount),
            Destination::Address(pub_key_hash),
        );
        let tx = self.for_account_rw(account_index, |account, db_tx| {
            account.complete_and_add_send_request(db_tx, request)
        })?;
        Ok(tx)
    }

    /// Returns the last scanned block hash and height.
    /// Returns genesis block when the wallet is just created.
    pub fn get_best_block(&self) -> WalletResult<(Id<GenBlock>, BlockHeight)> {
        Ok((self.best_block_id, self.best_block_height))
    }

    /// Scan new blocks and update best block hash/height.
    /// New block may reset the chain of previously scanned blocks.
    pub fn scan_new_blocks(
        &mut self,
        block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> WalletResult<()> {
        if blocks.is_empty() {
            return Ok(());
        }

        let mut db_tx = self.db.transaction_rw(None)?;

        for account in self.accounts.values_mut() {
            if self.best_block_height >= block_height {
                account.reset_to_height(&mut db_tx, block_height)?;
            }
            account.scan_new_blocks(&mut db_tx, block_height, &blocks)?;
        }

        db_tx.commit()?;

        // Update best_block_height and best_block_id only after successful commit call!
        self.best_block_height = (self.best_block_height.into_int() + blocks.len() as u64).into();
        self.best_block_id = blocks.last().expect("blocks not empty").header().block_id().into();

        Ok(())
    }

    /// Rescan mempool for unconfirmed transactions and UTXOs
    pub fn scan_mempool(&mut self, _transactions: Vec<SignedTransaction>) -> WalletResult<()> {
        Err(WalletError::NotImplemented("scan_mempool"))
    }
}

#[cfg(test)]
mod tests;
