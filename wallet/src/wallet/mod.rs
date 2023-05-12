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
use crate::Account;
pub use bip39::{Language, Mnemonic};
use common::chain::signature::TransactionSigError;
use common::chain::{
    Block, ChainConfig, GenBlock, SignedTransaction, Transaction, TransactionCreationError,
    TxOutput,
};
use common::primitives::{Amount, BlockHeight, Id};
use crypto::key::hdkd::u31::U31;
use wallet_storage::{
    DefaultBackend, Store, TransactionRo, TransactionRw, Transactional, WalletStorageRead,
    WalletStorageWrite,
};
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;
use wallet_types::AccountId;

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

        let account_key_chain =
            key_chain.create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX)?;

        let account = Account::new(Arc::clone(&chain_config), &mut db_tx, account_key_chain)?;

        let accounts = std::iter::once((account.account_index(), account)).collect();

        db_tx.set_storage_version(CURRENT_WALLET_VERSION)?;

        db_tx.commit()?;

        Ok(Wallet {
            chain_config,
            db,
            key_chain,
            accounts,
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
                Account::load_from_database(Arc::clone(&chain_config), &db_tx, account_id)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|account| (account.account_index(), account))
            .collect();

        db_tx.close();

        Ok(Wallet {
            chain_config,
            db,
            key_chain,
            accounts,
        })
    }

    pub fn database(&self) -> &Store<B> {
        &self.db
    }

    /// Returns the last scanned block hash and height.
    /// Returns genesis block when the wallet is just created.
    pub fn get_best_block(&self) -> WalletResult<(Id<GenBlock>, BlockHeight)> {
        Err(WalletError::NotImplemented("get_best_block"))
    }

    /// Scan new blocks and update best block hash/height.
    /// New block may reset the chain of previously scanned blocks.
    pub fn scan_new_blocks(
        &mut self,
        _block_height: BlockHeight,
        _blocks: Vec<Block>,
    ) -> WalletResult<()> {
        Err(WalletError::NotImplemented("scan_new_blocks"))
    }

    /// Rescan mempool for unconfirmed transactions and UTXOs
    pub fn scan_mempool(&mut self, _transactions: Vec<SignedTransaction>) -> WalletResult<()> {
        Err(WalletError::NotImplemented("scan_mempool"))
    }
}

#[cfg(test)]
mod tests;
