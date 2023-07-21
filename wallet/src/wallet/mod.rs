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
use crate::account::{Currency, UtxoSelectorError};
use crate::key_chain::{KeyChainError, MasterKeyChain};
use crate::send_request::{make_issue_nft_outputs, make_issue_token_outputs};
use crate::wallet_events::WalletEvents;
use crate::{Account, SendRequest};
pub use bip39::{Language, Mnemonic};
use common::address::pubkeyhash::PublicKeyHashError;
use common::address::{Address, AddressError};
use common::chain::block::timestamp::BlockTimestamp;
use common::chain::signature::TransactionSigError;
use common::chain::tokens::{token_id, Metadata, TokenId, TokenIssuance};
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
use tx_verifier::error::TokenIssuanceError;
use utils::ensure;
use wallet_storage::{
    DefaultBackend, Store, StoreTxRw, TransactionRoLocked, TransactionRwLocked, Transactional,
    WalletStorageReadLocked, WalletStorageWriteLocked,
};
use wallet_storage::{StoreTxRwUnlocked, TransactionRwUnlocked};
use wallet_types::utxo_types::{UtxoStates, UtxoTypes};
use wallet_types::wallet_tx::TxState;
use wallet_types::{AccountId, BlockInfo, KeyPurpose};

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
    #[error("Cannot create a new account when last account is still empty")]
    EmptyLastAccount,
    #[error("Cannot create a new account with an empty string name")]
    EmptyAccountName,
    #[error("The maximum number of accounts has been exceeded: {0}")]
    AbsoluteMaxNumAccountsExceeded(U31),
    #[error("Not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("The send request is complete")]
    SendRequestComplete,
    #[error("Unsupported transaction output type")] // TODO implement display for TxOutput
    UnsupportedTransactionOutput(Box<TxOutput>),
    #[error("Unsupported input destination")] // TODO implement display for Destination
    UnsupportedInputDestination(Destination),
    #[error("Output amounts overflow")]
    OutputAmountOverflow,
    #[error("Negative delegation amount for id: {0}")]
    NegativeDelegationAmount(DelegationId),
    #[error(
        "Inconsistent delegation state for id: {0}, missing Delegation creation before staking"
    )]
    InconsistentDelegationAddition(DelegationId),
    #[error("Inconsistent delegation state for id: {0}, amount less than 0 while trying to remove transaction")]
    InconsistentDelegationRemoval(DelegationId),
    #[error("Inconsistent delegation state for id: {0}, nonce less than 0 while trying to remove transaction")]
    InconsistentDelegationRemovalNegativeNonce(DelegationId),
    #[error("Delegation with id: {0} with duplicate AccountNonce: {1}")]
    InconsistentDelegationDuplicateNonce(DelegationId, AccountNonce),
    #[error("Delfation amount overflow for id: {0}")]
    DelegationAmountOverflow(DelegationId),
    #[error("Delfation nonce overflow for id: {0}")]
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
    #[error("Invalid address {0}: {1}")]
    InvalidAddress(String, PublicKeyHashError),
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
}

/// Result type used for the wallet
pub type WalletResult<T> = Result<T, WalletError>;

pub struct Wallet<B: storage::Backend> {
    chain_config: Arc<ChainConfig>,
    db: Store<B>,
    key_chain: MasterKeyChain,
    accounts: BTreeMap<U31, Account>,
    latest_median_time: BlockTimestamp,
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

        let accounts: BTreeMap<U31, Account> = accounts_info
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

        Ok(Wallet {
            chain_config,
            db,
            key_chain,
            accounts,
            latest_median_time,
        })
    }

    pub fn is_encrypted(&self) -> bool {
        self.db.is_encrypted()
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

    pub fn create_account(&mut self, name: Option<String>) -> WalletResult<(U31, Option<String>)> {
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

        ensure!(
            name.as_ref().map_or(true, |name| !name.is_empty()),
            WalletError::EmptyAccountName
        );

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

        self.accounts.insert(account.account_index(), account);

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
        let value = f(account, &mut db_tx)?;
        // Abort the process if the DB transaction fails. See `for_account_rw` for more information.
        db_tx.commit().expect("RW transaction commit failed unexpectedly");
        Ok(value)
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
    ) -> WalletResult<BTreeMap<Currency, Amount>> {
        self.get_account(account_index)?.get_balance(
            utxo_types,
            utxo_states,
            self.latest_median_time,
        )
    }

    pub fn get_utxos(
        &self,
        account_index: U31,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
    ) -> WalletResult<BTreeMap<UtxoOutPoint, TxOutput>> {
        let account = self.get_account(account_index)?;
        let utxos = account.get_utxos(utxo_types, self.latest_median_time, utxo_states);
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
    ) -> WalletResult<impl Iterator<Item = (&DelegationId, Amount)>> {
        let delegations = self.get_account(account_index)?.get_delegations();
        Ok(delegations)
    }

    pub fn get_new_address(&mut self, account_index: U31) -> WalletResult<(ChildNumber, Address)> {
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
    ) -> WalletResult<BTreeMap<ChildNumber, Address>> {
        let account = self.get_account(account_index)?;
        Ok(account.get_all_issued_addresses())
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
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        let request = SendRequest::new().with_outputs(outputs);
        let latest_median_time = self.latest_median_time;
        self.for_account_rw_unlocked(account_index, |account, db_tx| {
            account.process_send_request(
                db_tx,
                request,
                latest_median_time,
                current_fee_rate,
                consolidate_fee_rate,
            )
        })
    }

    pub fn create_transaction_to_addresses_from_delegation(
        &mut self,
        wallet_events: &mut impl WalletEvents,
        account_index: U31,
        outputs: Vec<TxOutput>,
        delegation_id: DelegationId,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        self.for_account_rw_unlocked(account_index, |account, db_tx| {
            let tx =
                account.spend_from_delegation(db_tx, outputs, delegation_id, current_fee_rate)?;
            let txs = [tx];
            account.scan_new_unconfirmed_transactions(
                &txs,
                TxState::Inactive,
                db_tx,
                wallet_events,
            )?;

            let [tx] = txs;
            Ok(tx)
        })
    }

    pub fn issue_new_token(
        &mut self,
        account_index: U31,
        address: Address,
        token_issuance: TokenIssuance,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<(TokenId, SignedTransaction)> {
        let outputs =
            make_issue_token_outputs(address, token_issuance, self.chain_config.as_ref())?;

        let tx = self.create_transaction_to_addresses(
            account_index,
            outputs,
            current_fee_rate,
            consolidate_fee_rate,
        )?;
        let token_id = token_id(tx.transaction()).ok_or(WalletError::MissingTokenId)?;
        Ok((token_id, tx))
    }

    pub fn issue_new_nft(
        &mut self,
        account_index: U31,
        address: Address,
        metadata: Metadata,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<(TokenId, SignedTransaction)> {
        let outputs = make_issue_nft_outputs(address, metadata, self.chain_config.as_ref())?;

        let tx = self.create_transaction_to_addresses(
            account_index,
            outputs,
            current_fee_rate,
            consolidate_fee_rate,
        )?;
        let token_id = token_id(tx.transaction()).ok_or(WalletError::MissingTokenId)?;
        Ok((token_id, tx))
    }

    pub fn create_stake_pool_tx(
        &mut self,
        account_index: U31,
        amount: Amount,
        decomission_key: Option<PublicKey>,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        let latest_median_time = self.latest_median_time;
        self.for_account_rw_unlocked(account_index, |account, db_tx| {
            account.create_stake_pool_tx(
                db_tx,
                amount,
                decomission_key,
                latest_median_time,
                current_fee_rate,
                consolidate_fee_rate,
            )
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
    pub fn get_best_block(&self) -> BTreeMap<U31, (Id<GenBlock>, BlockHeight)> {
        self.accounts
            .iter()
            .map(|(index, account)| (*index, account.best_block()))
            .collect()
    }

    pub fn get_best_block_for_account(
        &self,
        account_index: U31,
    ) -> WalletResult<(Id<GenBlock>, BlockHeight)> {
        Ok(self.get_account(account_index)?.best_block())
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
        wallet_events: &mut impl WalletEvents,
    ) -> WalletResult<()> {
        self.for_account_rw(account_index, |account, db_tx| {
            account.scan_new_blocks(db_tx, wallet_events, common_block_height, &blocks)
        })?;
        wallet_events.new_block();
        Ok(())
    }

    /// Rescan mempool for unconfirmed transactions and UTXOs
    pub fn scan_mempool(
        &mut self,
        transactions: &[SignedTransaction],
        wallet_events: &mut impl WalletEvents,
    ) -> WalletResult<()> {
        let mut db_tx = self.db.transaction_rw(None)?;

        for account in self.accounts.values_mut() {
            account.scan_new_unconfirmed_transactions(
                transactions,
                TxState::InMempool,
                &mut db_tx,
                wallet_events,
            )?;
        }

        Ok(())
    }

    /// Save an unconfirmed transaction in case we need to rebroadcast it later
    /// and mark it as Inactive for now
    pub fn add_unconfirmed_tx(
        &mut self,
        transaction: SignedTransaction,
        wallet_events: &mut impl WalletEvents,
    ) -> WalletResult<()> {
        let mut db_tx = self.db.transaction_rw(None)?;

        let txs = [transaction];
        for account in self.accounts.values_mut() {
            account.scan_new_unconfirmed_transactions(
                &txs,
                TxState::Inactive,
                &mut db_tx,
                wallet_events,
            )?;
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
