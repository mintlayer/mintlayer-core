// Copyright (c) 2022 RBB S.r.l
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

mod input_output_policy;
mod pos_accounting_delta_adapter;
mod reward_distribution;
mod token_issuance_cache;

pub mod check_transaction;
pub mod error;
pub mod flush;
pub mod hierarchy;
pub mod input_check;
pub mod storage;
pub mod timelock_check;
pub mod tokens_check;

mod tx_source;
use accounting::BlockRewardUndo;
use constraints_value_accumulator::AccumulatedFee;
use orders_accounting::{
    OrdersAccountingCache, OrdersAccountingDB, OrdersAccountingDeltaData,
    OrdersAccountingOperations, OrdersAccountingStorageRead, OrdersAccountingUndo,
    OrdersAccountingView,
};
use tokens_accounting::{
    TokenAccountingUndo, TokensAccountingCache, TokensAccountingDB, TokensAccountingDeltaData,
    TokensAccountingOperations, TokensAccountingStorageRead, TokensAccountingView,
};
pub use tx_source::{TransactionSource, TransactionSourceForConnect};

mod cached_operation;
pub use cached_operation::CachedOperation;

mod accounting_undo_cache;
pub use accounting_undo_cache::CachedBlockUndo;

mod utxos_undo_cache;
pub use utxos_undo_cache::CachedUtxosBlockUndo;

pub use input_output_policy::{calculate_tokens_burned_in_outputs, IOPolicyError};

use std::collections::{BTreeMap, BTreeSet};

use self::{
    accounting_undo_cache::{AccountingBlockUndoCache, CachedBlockUndoOp},
    error::ConnectTransactionError,
    pos_accounting_delta_adapter::PoSAccountingDeltaAdapter,
    storage::TransactionVerifierStorageRef,
    token_issuance_cache::{ConsumedTokenIssuanceCache, TokenIssuanceCache},
    utxos_undo_cache::{CachedUtxoBlockUndoOp, UtxosBlockUndoCache},
};
use ::utils::{ensure, shallow_clone::ShallowClone};
pub use reward_distribution::{distribute_pos_reward, RewardDistributionError};

use chainstate_types::{BlockIndex, TipStorageTag};
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockRewardTransactable, ConsensusData},
        make_delegation_id, make_order_id, make_pool_id, make_token_id,
        output_value::OutputValue,
        signature::Signable,
        signed_transaction::SignedTransaction,
        AccountCommand, AccountNonce, AccountSpending, AccountType, Block, ChainConfig,
        DelegationId, FrozenTokensValidationVersion, GenBlock, OrderAccountCommand, OrdersVersion,
        Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, BlockHeight, Fee, Id, Idable},
};
use pos_accounting::{
    PoSAccountingDB, PoSAccountingDelta, PoSAccountingDeltaData, PoSAccountingOperations,
    PoSAccountingUndo, PoSAccountingView,
};
use utxo::{ConsumedUtxoCache, UtxosCache, UtxosDB, UtxosStorageRead, UtxosView};

/// The change that a block has caused to the blockchain state
#[derive(Debug, Eq, PartialEq)]
pub struct TransactionVerifierDelta {
    utxo_cache: ConsumedUtxoCache,
    utxo_block_undo: BTreeMap<TransactionSource, CachedUtxoBlockUndoOp>,
    token_issuance_cache: ConsumedTokenIssuanceCache,
    accounting_delta: PoSAccountingDeltaData,
    pos_accounting_delta_undo: BTreeMap<TransactionSource, CachedBlockUndoOp<PoSAccountingUndo>>,
    pos_accounting_block_deltas: BTreeMap<TransactionSource, PoSAccountingDeltaData>,
    account_nonce: BTreeMap<AccountType, CachedOperation<AccountNonce>>,
    tokens_accounting_delta: TokensAccountingDeltaData,
    tokens_accounting_delta_undo:
        BTreeMap<TransactionSource, CachedBlockUndoOp<TokenAccountingUndo>>,
    orders_accounting_delta: OrdersAccountingDeltaData,
    orders_accounting_delta_undo:
        BTreeMap<TransactionSource, CachedBlockUndoOp<OrdersAccountingUndo>>,
}

impl TransactionVerifierDelta {
    pub fn consume(self) -> (ConsumedUtxoCache, PoSAccountingDeltaData) {
        (self.utxo_cache, self.accounting_delta)
    }
}

/// The tool used to verify transactions and cache their updated states in memory
pub struct TransactionVerifier<C, S, U, A, T, O> {
    chain_config: C,
    storage: S,
    best_block: Id<GenBlock>,

    token_issuance_cache: TokenIssuanceCache,

    utxo_cache: UtxosCache<U>,
    utxo_block_undo: UtxosBlockUndoCache,

    pos_accounting_adapter: PoSAccountingDeltaAdapter<A>,
    pos_accounting_block_undo: AccountingBlockUndoCache<PoSAccountingUndo>,

    tokens_accounting_cache: TokensAccountingCache<T>,
    tokens_accounting_block_undo: AccountingBlockUndoCache<TokenAccountingUndo>,

    orders_accounting_cache: OrdersAccountingCache<O>,
    orders_accounting_block_undo: AccountingBlockUndoCache<OrdersAccountingUndo>,

    account_nonce: BTreeMap<AccountType, CachedOperation<AccountNonce>>,
}

impl<C, S: TransactionVerifierStorageRef + ShallowClone>
    TransactionVerifier<
        C,
        S,
        UtxosDB<S>,
        PoSAccountingDB<S, TipStorageTag>,
        TokensAccountingDB<S>,
        OrdersAccountingDB<S>,
    >
{
    pub fn new(storage: S, chain_config: C) -> Self {
        let accounting_delta_adapter =
            PoSAccountingDeltaAdapter::new(PoSAccountingDB::new(storage.shallow_clone()));
        let utxo_cache = UtxosCache::new(UtxosDB::new(storage.shallow_clone()))
            .expect("Utxo cache setup failed");
        let best_block = storage
            .get_best_block_for_utxos()
            .expect("Database error while reading utxos best block");
        let tokens_accounting_cache =
            TokensAccountingCache::new(TokensAccountingDB::new(storage.shallow_clone()));
        let orders_accounting_cache =
            OrdersAccountingCache::new(OrdersAccountingDB::new(storage.shallow_clone()));
        Self {
            storage,
            chain_config,
            best_block,
            token_issuance_cache: TokenIssuanceCache::new(),
            utxo_cache,
            utxo_block_undo: UtxosBlockUndoCache::new(),
            pos_accounting_adapter: accounting_delta_adapter,
            pos_accounting_block_undo: AccountingBlockUndoCache::<PoSAccountingUndo>::new(),
            tokens_accounting_cache,
            tokens_accounting_block_undo: AccountingBlockUndoCache::<TokenAccountingUndo>::new(),
            orders_accounting_cache,
            orders_accounting_block_undo: AccountingBlockUndoCache::<OrdersAccountingUndo>::new(),
            account_nonce: BTreeMap::new(),
        }
    }
}

impl<C, S, U, A, T, O> TransactionVerifier<C, S, U, A, T, O>
where
    S: TransactionVerifierStorageRef,
    U: UtxosView + Send + Sync,
    A: PoSAccountingView + Send + Sync,
    T: TokensAccountingView + Send + Sync,
    O: OrdersAccountingView + Send + Sync,
{
    pub fn new_generic(
        storage: S,
        chain_config: C,
        utxos: U,
        accounting: A,
        tokens_accounting: T,
        orders_accounting: O,
    ) -> Self {
        // TODO: both "expect"s in this function may fire when exiting the node-gui app;
        // get rid of them and return a proper Result.
        // See https://github.com/mintlayer/mintlayer-core/issues/1221
        let best_block = storage
            .get_best_block_for_utxos()
            .expect("Database error while reading utxos best block");
        Self {
            storage,
            chain_config,
            best_block,
            token_issuance_cache: TokenIssuanceCache::new(),
            utxo_cache: UtxosCache::new(utxos).expect("Utxo cache setup failed"),
            utxo_block_undo: UtxosBlockUndoCache::new(),
            pos_accounting_adapter: PoSAccountingDeltaAdapter::new(accounting),
            pos_accounting_block_undo: AccountingBlockUndoCache::<PoSAccountingUndo>::new(),
            tokens_accounting_cache: TokensAccountingCache::new(tokens_accounting),
            tokens_accounting_block_undo: AccountingBlockUndoCache::<TokenAccountingUndo>::new(),
            orders_accounting_cache: OrdersAccountingCache::new(orders_accounting),
            orders_accounting_block_undo: AccountingBlockUndoCache::<OrdersAccountingUndo>::new(),
            account_nonce: BTreeMap::new(),
        }
    }
}

type DerivedTxVerifier<'a, C, S, U, A, T, O> = TransactionVerifier<
    &'a ChainConfig,
    &'a TransactionVerifier<C, S, U, A, T, O>,
    &'a UtxosCache<U>,
    &'a PoSAccountingDelta<A>,
    &'a TokensAccountingCache<T>,
    &'a OrdersAccountingCache<O>,
>;

impl<C, S, U, A, T, O> TransactionVerifier<C, S, U, A, T, O>
where
    C: AsRef<ChainConfig>,
    S: TransactionVerifierStorageRef,
    U: UtxosView,
    A: PoSAccountingView,
    T: TokensAccountingView,
    O: OrdersAccountingView,
    <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
{
    pub fn derive_child(&self) -> DerivedTxVerifier<'_, C, S, U, A, T, O> {
        TransactionVerifier {
            storage: self,
            chain_config: self.chain_config.as_ref(),
            utxo_cache: UtxosCache::new(&self.utxo_cache).expect("construct"),
            utxo_block_undo: UtxosBlockUndoCache::new(),
            token_issuance_cache: TokenIssuanceCache::new(),
            pos_accounting_adapter: PoSAccountingDeltaAdapter::new(
                self.pos_accounting_adapter.accounting_delta(),
            ),
            pos_accounting_block_undo: AccountingBlockUndoCache::<PoSAccountingUndo>::new(),
            tokens_accounting_cache: TokensAccountingCache::new(&self.tokens_accounting_cache),
            tokens_accounting_block_undo: AccountingBlockUndoCache::<TokenAccountingUndo>::new(),
            orders_accounting_cache: OrdersAccountingCache::new(&self.orders_accounting_cache),
            orders_accounting_block_undo: AccountingBlockUndoCache::<OrdersAccountingUndo>::new(),
            best_block: self.best_block,
            account_nonce: BTreeMap::new(),
        }
    }

    pub fn check_block_reward(
        &self,
        block: &WithId<Block>,
        total_fees: Fee,
        block_height: BlockHeight,
    ) -> Result<(), ConnectTransactionError> {
        input_output_policy::check_reward_inputs_outputs_policy(
            self.chain_config.as_ref(),
            &self.utxo_cache,
            block.block_reward_transactable(),
            block.get_id(),
            block_height,
            block.consensus_data(),
            total_fees,
        )
    }

    fn spend_input_from_account(
        &mut self,
        nonce: AccountNonce,
        account: AccountType,
    ) -> Result<(), ConnectTransactionError> {
        // Check that account nonce increments previous value
        let expected_nonce = match self
            .get_account_nonce_count(account)
            .map_err(|_| ConnectTransactionError::TxVerifierStorage)?
        {
            Some(nonce) => nonce
                .increment()
                .ok_or(ConnectTransactionError::FailedToIncrementAccountNonce)?,
            None => AccountNonce::new(0),
        };
        ensure!(
            expected_nonce == nonce,
            ConnectTransactionError::NonceIsNotIncremental(account, expected_nonce, nonce)
        );
        // store new nonce
        self.account_nonce.insert(account, CachedOperation::Write(nonce));

        Ok(())
    }

    fn unspend_input_from_account(
        &mut self,
        account: AccountType,
    ) -> Result<(), ConnectTransactionError> {
        let new_nonce = self
            .get_account_nonce_count(account)
            .map_err(|_| ConnectTransactionError::TxVerifierStorage)?
            .ok_or(ConnectTransactionError::MissingTransactionNonce(account))?
            .decrement()
            .map_or(CachedOperation::Erase, CachedOperation::Write);
        self.account_nonce.insert(account, new_nonce);
        Ok(())
    }

    fn spend_input_from_utxo(
        &mut self,
        tx_source: TransactionSource,
        input_outpoint: &UtxoOutPoint,
    ) -> Result<Option<PoSAccountingUndo>, ConnectTransactionError> {
        let input_utxo =
            self.utxo_cache.utxo(input_outpoint).map_err(|_| utxo::Error::ViewRead)?.ok_or(
                ConnectTransactionError::MissingOutputOrSpent(input_outpoint.clone()),
            )?;
        match input_utxo.output() {
            TxOutput::CreateStakePool(pool_id, _) | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                // If the input spends `CreateStakePool` or `ProduceBlockFromStake` utxo,
                // this means the user is decommissioning the pool.
                let undo = self
                    .pos_accounting_adapter
                    .operations(tx_source)
                    .decommission_pool(*pool_id)
                    .map_err(ConnectTransactionError::PoSAccountingError)?;
                Ok(Some(undo))
            }
            TxOutput::DelegateStaking(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => Ok(None),
        }
    }

    fn connect_pos_accounting_outputs(
        &mut self,
        tx_source: &TransactionSourceForConnect,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        let mut check_delegation: Option<DelegationId> = None;
        let mut delegations_with_spendings = BTreeSet::<DelegationId>::new();

        // Process tx inputs in terms of pos accounting.
        // Spending `CreateStakePool`, `ProduceBlockFromStake` utxos or an account input
        // should result in either decommissioning a pool or spending share in accounting
        let inputs_undos = tx
            .inputs()
            .iter()
            .filter_map(|input| match input {
                TxInput::Utxo(ref outpoint) => {
                    self.spend_input_from_utxo(tx_source.into(), outpoint).transpose()
                }
                TxInput::Account(outpoint) => {
                    match outpoint.account() {
                        AccountSpending::DelegationBalance(delegation_id, withdraw_amount) => {
                            check_delegation = Some(*delegation_id);
                            delegations_with_spendings.insert(*delegation_id);
                            let res = self
                                .spend_input_from_account(
                                    outpoint.nonce(),
                                    outpoint.account().into(),
                                )
                                .and_then(|_| {
                                    // If the input spends from delegation account, this means the user is
                                    // spending part of their share in the pool.
                                    self.pos_accounting_adapter
                                        .operations(tx_source.into())
                                        .spend_share_from_delegation_id(
                                            *delegation_id,
                                            *withdraw_amount,
                                        )
                                        .map_err(ConnectTransactionError::PoSAccountingError)
                                });
                            Some(res)
                        }
                    }
                }
                TxInput::AccountCommand(..) | TxInput::OrderAccountCommand(..) => None,
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Process tx outputs in terms of pos accounting.
        let outputs_undos = tx
            .outputs()
            .iter()
            .filter_map(|output| match output {
                TxOutput::CreateStakePool(pool_id, data) => match make_pool_id(tx.inputs()) {
                    Ok(expected_pool_id) => {
                        let res = if expected_pool_id == *pool_id {
                            if data.pledge() >= self.chain_config.as_ref().min_stake_pool_pledge() {
                                self.pos_accounting_adapter
                                    .operations(tx_source.into())
                                    .create_pool(*pool_id, data.as_ref().clone().into())
                                    .map_err(ConnectTransactionError::PoSAccountingError)
                            } else {
                                Err(ConnectTransactionError::NotEnoughPledgeToCreateStakePool(
                                    tx.get_id(),
                                    data.pledge(),
                                    self.chain_config.as_ref().min_stake_pool_pledge(),
                                ))
                            }
                        } else {
                            Err(ConnectTransactionError::UnexpectedPoolId(
                                *pool_id,
                                expected_pool_id,
                            ))
                        };
                        Some(res)
                    }
                    Err(err) => Some(Err(err.into())),
                },
                TxOutput::CreateDelegationId(spend_destination, target_pool) => {
                    match make_delegation_id(tx.inputs()) {
                        Ok(delegation_id) => {
                            let res = self
                                .pos_accounting_adapter
                                .operations(tx_source.into())
                                .create_delegation_id(
                                    *target_pool,
                                    delegation_id,
                                    spend_destination.clone(),
                                )
                                .map_err(ConnectTransactionError::PoSAccountingError);
                            Some(res)
                        }
                        Err(err) => Some(Err(err.into())),
                    }
                }
                TxOutput::DelegateStaking(amount, delegation_id) => {
                    let res = self
                        .pos_accounting_adapter
                        .operations(tx_source.into())
                        .delegate_staking(*delegation_id, *amount)
                        .map_err(ConnectTransactionError::PoSAccountingError);
                    Some(res)
                }
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Burn(_)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::Htlc(_, _)
                | TxOutput::CreateOrder(_) => None,
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Iterate over all delegations that have spending and get the balance.
        // By retrieving the balance we apply all the deltas from the accounting and can verify
        // that final balance is not negative.
        // This check is not mandatory but a safe-net to ensure no overspends happen.
        for delegation_id in delegations_with_spendings {
            let _ = self
                .pos_accounting_adapter
                .accounting_delta()
                .get_delegation_balance(delegation_id)?;
        }

        // Store pos accounting operations undos
        if !inputs_undos.is_empty() || !outputs_undos.is_empty() {
            let tx_undos = inputs_undos.into_iter().chain(outputs_undos).collect();
            self.pos_accounting_block_undo.add_tx_undo(
                tx_source.into(),
                tx.get_id(),
                accounting::TxUndo::new(tx_undos),
            )?;
        }

        Ok(())
    }

    fn disconnect_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // decrement nonce if disconnected input spent from an account
        for input in tx.inputs() {
            match input {
                TxInput::Utxo(_) | TxInput::OrderAccountCommand(_) => { /* do nothing */ }
                TxInput::Account(outpoint) => {
                    self.unspend_input_from_account(outpoint.account().into())?;
                }
                TxInput::AccountCommand(_, cmd) => {
                    self.unspend_input_from_account(cmd.into())?;
                }
            };
        }

        self.disconnect_pos_accounting_outputs(tx_source, tx)?;

        self.disconnect_tokens_accounting_outputs(tx_source, tx)?;

        self.disconnect_orders_accounting_outputs(tx_source, tx)?;

        Ok(())
    }

    fn disconnect_pos_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // apply undos to accounting
        let block_undo_fetcher = |tx_source: TransactionSource| {
            self.storage
                .get_pos_accounting_undo(tx_source)
                .map_err(|_| ConnectTransactionError::TxVerifierStorage)
        };
        let undos = self.pos_accounting_block_undo.take_tx_undo(
            &tx_source,
            &tx.get_id(),
            block_undo_fetcher,
        )?;
        if let Some(undos) = undos {
            undos.into_inner().into_iter().rev().try_for_each(|undo| {
                self.pos_accounting_adapter.operations(tx_source).undo(undo)
            })?;
        }

        Ok(())
    }

    fn connect_tokens_outputs(
        &mut self,
        tx_source: &TransactionSourceForConnect,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        self.check_operations_with_frozen_tokens(tx, tx_source.expected_block_height())?;

        let input_undos = tx
            .inputs()
            .iter()
            .filter_map(|input| match input {
                TxInput::Utxo(_) | TxInput::Account(_) | TxInput::OrderAccountCommand(_) => None,
                TxInput::AccountCommand(nonce, account_op) => match account_op {
                    AccountCommand::MintTokens(token_id, amount) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .mint_tokens(*token_id, *amount)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::UnmintTokens(ref token_id) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.into())
                            .and_then(|_| {
                                // actual amount to unmint is determined by the number of burned tokens in the outputs
                                let total_burned =
                                    input_output_policy::calculate_tokens_burned_in_outputs(
                                        tx, token_id,
                                    )?;
                                Ok((total_burned > Amount::ZERO).then_some(total_burned))
                            })
                            .transpose()? // return if no tokens were burned
                            .and_then(|total_burned| {
                                self.tokens_accounting_cache
                                    .unmint_tokens(*token_id, total_burned)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::LockTokenSupply(token_id) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .lock_circulating_supply(*token_id)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::FreezeToken(token_id, is_unfreezable) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .freeze_token(*token_id, *is_unfreezable)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::UnfreezeToken(token_id) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .unfreeze_token(*token_id)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::ChangeTokenAuthority(token_id, new_authority) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .change_authority(*token_id, new_authority.clone())
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::ChangeTokenMetadataUri(token_id, new_metadata_uri) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .change_metadata_uri(*token_id, new_metadata_uri.clone())
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => None,
                },
            })
            .collect::<Result<Vec<_>, _>>()?;

        let output_undos = tx
            .outputs()
            .iter()
            .filter_map(|output| match output {
                TxOutput::Transfer(_, _)
                | TxOutput::Burn(_)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::Htlc(_, _)
                | TxOutput::CreateOrder(_) => None,
                TxOutput::IssueFungibleToken(issuance_data) => {
                    let result = make_token_id(
                        self.chain_config.as_ref(),
                        tx_source.expected_block_height(),
                        tx.inputs(),
                    )
                    .map_err(ConnectTransactionError::IdCreationError)
                    .and_then(
                        |token_id| -> Result<tokens_accounting::TokenAccountingUndo, _> {
                            let data = tokens_accounting::TokenData::FungibleToken(
                                issuance_data.as_ref().clone().into(),
                            );
                            self.tokens_accounting_cache
                                .issue_token(token_id, data)
                                .map_err(ConnectTransactionError::TokensAccountingError)
                        },
                    );
                    Some(result)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Store accounting operations undos
        if !input_undos.is_empty() || !output_undos.is_empty() {
            let tx_undos = input_undos.into_iter().chain(output_undos).collect();
            self.tokens_accounting_block_undo.add_tx_undo(
                TransactionSource::from(tx_source),
                tx.get_id(),
                accounting::TxUndo::new(tx_undos),
            )?;
        }

        Ok(())
    }

    fn check_operations_with_frozen_tokens(
        &self,
        tx: &Transaction,
        block_height: BlockHeight,
    ) -> Result<(), ConnectTransactionError> {
        let check_not_frozen = |token_id| {
            // Note: this "if" is needed because NFT ids are also possible here (for which
            // `get_token_data` would return `None`).
            if let Some(token_data) = self.get_token_data(&token_id)? {
                match token_data {
                    tokens_accounting::TokenData::FungibleToken(data) => {
                        ensure!(
                            !data.is_frozen(),
                            ConnectTransactionError::AttemptToSpendFrozenToken(token_id)
                        );
                    }
                };
            }
            Ok(())
        };

        let check_tx_output = |output: &TxOutput| match output {
            TxOutput::Transfer(output_value, _)
            | TxOutput::Burn(output_value)
            | TxOutput::LockThenTransfer(output_value, _, _)
            | TxOutput::Htlc(output_value, _) => match output_value {
                OutputValue::Coin(_) | OutputValue::TokenV0(_) => Ok(()),
                OutputValue::TokenV1(ref token_id, _) => check_not_frozen(*token_id),
            },
            TxOutput::CreateOrder(data) => {
                [data.ask(), data.give()].iter().try_for_each(|v| match v {
                    OutputValue::TokenV0(_) | OutputValue::Coin(_) => Ok(()),
                    OutputValue::TokenV1(token_id, _) => check_not_frozen(*token_id),
                })
            }
            TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_) => Ok(()),
        };

        let check_order_doesnt_use_frozen_token = |order_id| {
            let order_data = self.get_order_data(order_id)?.ok_or(
                ConnectTransactionError::OrdersAccountingError(
                    orders_accounting::Error::OrderDataNotFound(*order_id),
                ),
            )?;
            [order_data.ask(), order_data.give()].iter().try_for_each(|v| match v {
                OutputValue::TokenV0(_) | OutputValue::Coin(_) => Ok(()),
                OutputValue::TokenV1(token_id, _) => check_not_frozen(*token_id),
            })
        };

        tx.inputs()
            .iter()
            .try_for_each(|input| -> Result<(), ConnectTransactionError> {
                match input {
                    TxInput::Utxo(utxo_outpoint) => {
                        let utxo = self
                            .get_utxo(utxo_outpoint)
                            .map_err(|_| ConnectTransactionError::TxVerifierStorage)?
                            .ok_or(ConnectTransactionError::MissingOutputOrSpent(
                                utxo_outpoint.clone(),
                            ))?;

                        match self
                            .chain_config
                            .as_ref()
                            .chainstate_upgrades()
                            .version_at_height(block_height)
                            .1
                            .frozen_tokens_validation_version()
                        {
                            FrozenTokensValidationVersion::V0 => Ok(()),
                            FrozenTokensValidationVersion::V1 => check_tx_output(utxo.output()),
                        }
                    }
                    TxInput::Account(account_outpoint) => match account_outpoint.account() {
                        AccountSpending::DelegationBalance(_, _) => Ok(()),
                    },
                    TxInput::AccountCommand(_, account_command) => match account_command {
                        AccountCommand::MintTokens(id, _)
                        | AccountCommand::UnmintTokens(id)
                        | AccountCommand::LockTokenSupply(id)
                        | AccountCommand::FreezeToken(id, _)
                        | AccountCommand::ChangeTokenAuthority(id, _)
                        | AccountCommand::ChangeTokenMetadataUri(id, _) => check_not_frozen(*id),
                        | AccountCommand::UnfreezeToken(_) => Ok(()),
                        AccountCommand::ConcludeOrder(order_id)
                        | AccountCommand::FillOrder(order_id, _, _) => {
                            check_order_doesnt_use_frozen_token(order_id)
                        }
                    },
                    TxInput::OrderAccountCommand(cmd) => match cmd {
                        OrderAccountCommand::FillOrder(order_id, _)
                        | OrderAccountCommand::ConcludeOrder(order_id) => {
                            check_order_doesnt_use_frozen_token(order_id)
                        }
                        OrderAccountCommand::FreezeOrder(_) => Ok(()),
                    },
                }
            })?;

        tx.outputs()
            .iter()
            .try_for_each(|output| -> Result<(), ConnectTransactionError> {
                check_tx_output(output)
            })
    }

    fn disconnect_tokens_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // apply undos to accounting
        let block_undo_fetcher = |tx_source: TransactionSource| {
            self.storage
                .get_tokens_accounting_undo(tx_source)
                .map_err(|_| ConnectTransactionError::TxVerifierStorage)
        };
        let undos = self.tokens_accounting_block_undo.take_tx_undo(
            &tx_source,
            &tx.get_id(),
            block_undo_fetcher,
        )?;
        if let Some(undos) = undos {
            undos
                .into_inner()
                .into_iter()
                .rev()
                .try_for_each(|undo| self.tokens_accounting_cache.undo(undo))?;
        }

        Ok(())
    }

    fn connect_orders_outputs(
        &mut self,
        tx_source: &TransactionSourceForConnect,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        let input_undos = tx
            .inputs()
            .iter()
            .filter_map(|input| match input {
                TxInput::Utxo(_) | TxInput::Account(_) => None,
                TxInput::AccountCommand(nonce, account_op) => match account_op {
                    AccountCommand::MintTokens(..)
                    | AccountCommand::UnmintTokens(..)
                    | AccountCommand::LockTokenSupply(..)
                    | AccountCommand::FreezeToken(..)
                    | AccountCommand::UnfreezeToken(..)
                    | AccountCommand::ChangeTokenAuthority(..)
                    | AccountCommand::ChangeTokenMetadataUri(..) => None,
                    AccountCommand::ConcludeOrder(order_id) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.into())
                            .and_then(|_| {
                                self.orders_accounting_cache
                                    .conclude_order(*order_id)
                                    .map_err(ConnectTransactionError::OrdersAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::FillOrder(order_id, fill, _) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.into())
                            .and_then(|_| {
                                self.orders_accounting_cache
                                    .fill_order(*order_id, *fill, OrdersVersion::V0)
                                    .map_err(ConnectTransactionError::OrdersAccountingError)
                            });
                        Some(res)
                    }
                },
                TxInput::OrderAccountCommand(cmd) => match cmd {
                    OrderAccountCommand::FillOrder(order_id, fill) => {
                        let res = self
                            .orders_accounting_cache
                            .fill_order(*order_id, *fill, OrdersVersion::V1)
                            .map_err(ConnectTransactionError::OrdersAccountingError);
                        Some(res)
                    }
                    OrderAccountCommand::ConcludeOrder(order_id) => {
                        let res = self
                            .orders_accounting_cache
                            .conclude_order(*order_id)
                            .map_err(ConnectTransactionError::OrdersAccountingError);
                        Some(res)
                    }
                    OrderAccountCommand::FreezeOrder(order_id) => {
                        let res = self
                            .orders_accounting_cache
                            .freeze_order(*order_id)
                            .map_err(ConnectTransactionError::OrdersAccountingError);
                        Some(res)
                    }
                },
            })
            .collect::<Result<Vec<_>, _>>()?;

        let output_undos = tx
            .outputs()
            .iter()
            .filter_map(|output| match output {
                TxOutput::Transfer(..)
                | TxOutput::Burn(..)
                | TxOutput::CreateStakePool(..)
                | TxOutput::ProduceBlockFromStake(..)
                | TxOutput::CreateDelegationId(..)
                | TxOutput::DelegateStaking(..)
                | TxOutput::LockThenTransfer(..)
                | TxOutput::IssueNft(..)
                | TxOutput::DataDeposit(..)
                | TxOutput::IssueFungibleToken(..)
                | TxOutput::Htlc(_, _) => None,
                TxOutput::CreateOrder(order_data) => match make_order_id(tx.inputs()) {
                    Ok(order_id) => {
                        let result = self
                            .orders_accounting_cache
                            .create_order(order_id, order_data.as_ref().clone().into())
                            .map_err(ConnectTransactionError::OrdersAccountingError);
                        Some(result)
                    }
                    Err(err) => Some(Err(err.into())),
                },
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Store accounting operations undos
        if !input_undos.is_empty() || !output_undos.is_empty() {
            let tx_undos = input_undos.into_iter().chain(output_undos).collect();
            self.orders_accounting_block_undo.add_tx_undo(
                TransactionSource::from(tx_source),
                tx.get_id(),
                accounting::TxUndo::new(tx_undos),
            )?;
        }

        Ok(())
    }

    fn disconnect_orders_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // apply undos to accounting
        let block_undo_fetcher = |tx_source: TransactionSource| {
            self.storage
                .get_orders_accounting_undo(tx_source)
                .map_err(|_| ConnectTransactionError::TxVerifierStorage)
        };
        let undos = self.orders_accounting_block_undo.take_tx_undo(
            &tx_source,
            &tx.get_id(),
            block_undo_fetcher,
        )?;
        if let Some(undos) = undos {
            undos
                .into_inner()
                .into_iter()
                .rev()
                .try_for_each(|undo| self.orders_accounting_cache.undo(undo))?;
        }

        Ok(())
    }

    pub fn connect_transaction(
        &mut self,
        tx_source: &TransactionSourceForConnect,
        tx: &SignedTransaction,
        median_time_past: &BlockTimestamp,
    ) -> Result<AccumulatedFee, ConnectTransactionError> {
        check_transaction::check_transaction(
            self.chain_config.as_ref(),
            tx_source.expected_block_height(),
            tx,
        )?;

        let block_id = tx_source.chain_block_index().map(|c| *c.block_id());

        // Register tokens if tx has issuance data
        self.token_issuance_cache.register(
            self.chain_config.as_ref(),
            tx_source.expected_block_height(),
            block_id,
            tx.transaction(),
            |id| {
                self.storage
                    .get_token_aux_data(id)
                    .map_err(|_| ConnectTransactionError::TxVerifierStorage)
            },
        )?;

        // check for attempted money printing and invalid inputs/outputs combinations
        let fee = input_output_policy::check_tx_inputs_outputs_policy(
            tx.transaction(),
            self.chain_config.as_ref(),
            tx_source.expected_block_height(),
            &self.orders_accounting_cache,
            &self.pos_accounting_adapter.accounting_delta(),
            &self.tokens_accounting_cache,
            &self.utxo_cache,
        )?;

        self.verify_inputs(
            tx,
            tx_source,
            *median_time_past,
            tx_source.expected_block_height(),
        )?;

        self.connect_pos_accounting_outputs(tx_source, tx.transaction())?;

        self.connect_tokens_outputs(tx_source, tx.transaction())?;

        self.connect_orders_outputs(tx_source, tx.transaction())?;

        // spend utxos
        let tx_undo = self
            .utxo_cache
            .connect_transaction(tx.transaction(), tx_source.to_utxo_source())
            .map_err(ConnectTransactionError::from)?;

        // save spent utxos for undo
        self.utxo_block_undo.add_tx_undo(
            TransactionSource::from(tx_source),
            tx.transaction().get_id(),
            tx_undo,
        )?;

        Ok(fee)
    }

    pub fn connect_block_reward(
        &mut self,
        block_index: &BlockIndex,
        reward_transactable: BlockRewardTransactable,
        total_fees: Fee,
        median_time_past: BlockTimestamp,
    ) -> Result<(), ConnectTransactionError> {
        let block_height = block_index.block_height();
        let block_id = *block_index.block_id();

        // TODO: test spending block rewards from chains outside the mainchain
        if reward_transactable.inputs().is_some() {
            let tx_source = TransactionSourceForConnect::for_chain(block_index);
            self.verify_inputs(
                &reward_transactable,
                &tx_source,
                median_time_past,
                block_height,
            )?;
        }

        // spend inputs of the block reward
        // if block reward has no inputs then only outputs will be added to the utxo set
        let reward_undo = self
            .utxo_cache
            .connect_block_transactable(&reward_transactable, &block_id.into(), block_height)
            .map_err(ConnectTransactionError::from)?;

        if let Some(reward_undo) = reward_undo {
            // save spent utxos for undo
            self.utxo_block_undo
                .add_reward_undo(TransactionSource::Chain(block_id), reward_undo)?;
        }

        match block_index.block_header().consensus_data() {
            ConsensusData::None | ConsensusData::PoW(_) => { /* do nothing */ }
            ConsensusData::PoS(pos_data) => {
                // distribute reward among staker and delegators
                let block_subsidy =
                    self.chain_config.as_ref().block_subsidy_at_height(&block_height);
                let total_reward = (block_subsidy + total_fees.0)
                    .ok_or(ConnectTransactionError::RewardAdditionError(block_id))?;

                let undos = {
                    let mut accounting_adapter =
                        self.pos_accounting_adapter.operations(TransactionSource::Chain(block_id));

                    let reward_distribution_version = self
                        .chain_config
                        .as_ref()
                        .chainstate_upgrades()
                        .version_at_height(block_height)
                        .1
                        .reward_distribution_version();

                    let undos = reward_distribution::distribute_pos_reward(
                        &mut accounting_adapter,
                        block_id,
                        *pos_data.stake_pool_id(),
                        total_reward,
                        reward_distribution_version,
                    )?;

                    BlockRewardUndo::new(undos)
                };

                self.pos_accounting_block_undo
                    .add_reward_undo(TransactionSource::Chain(block_id), undos)?;
            }
        };

        Ok(())
    }

    pub fn can_disconnect_transaction(
        &self,
        tx_source: &TransactionSource,
        tx_id: &Id<Transaction>,
    ) -> Result<bool, ConnectTransactionError> {
        let block_undo_fetcher = |tx_source: TransactionSource| {
            self.storage
                .get_undo_data(tx_source)
                .map_err(|_| ConnectTransactionError::UndoFetchFailure)
        };
        match tx_source {
            TransactionSource::Chain(block_id) => {
                let current_block_height = self
                    .storage
                    .get_gen_block_index(&(*block_id).into())?
                    .ok_or_else(|| {
                        ConnectTransactionError::BlockIndexCouldNotBeLoaded((*block_id).into())
                    })?
                    .block_height();
                let best_block_height = self
                    .storage
                    .get_gen_block_index(&self.best_block)?
                    .ok_or(ConnectTransactionError::BlockIndexCouldNotBeLoaded(
                        self.best_block,
                    ))?
                    .block_height();

                if current_block_height < best_block_height {
                    Ok(false)
                } else {
                    self.utxo_block_undo.can_disconnect_transaction(
                        tx_source,
                        tx_id,
                        block_undo_fetcher,
                    )
                }
            }
            TransactionSource::Mempool => self.utxo_block_undo.can_disconnect_transaction(
                tx_source,
                tx_id,
                block_undo_fetcher,
            ),
        }
    }

    pub fn disconnect_transaction(
        &mut self,
        tx_source: &TransactionSource,
        tx: &SignedTransaction,
    ) -> Result<(), ConnectTransactionError> {
        let block_undo_fetcher = |tx_source: TransactionSource| {
            self.storage
                .get_undo_data(tx_source)
                .map_err(|_| ConnectTransactionError::UndoFetchFailure)
        };
        let tx_undo = self.utxo_block_undo.take_tx_undo(
            tx_source,
            &tx.transaction().get_id(),
            block_undo_fetcher,
        )?;

        self.disconnect_accounting_outputs(*tx_source, tx.transaction())?;

        self.utxo_cache.disconnect_transaction(tx.transaction(), tx_undo)?;

        // Remove issued tokens v0
        self.token_issuance_cache.unregister(tx.transaction(), |id| {
            self.storage
                .get_token_aux_data(id)
                .map_err(|_| ConnectTransactionError::TxVerifierStorage)
        })?;

        Ok(())
    }

    pub fn disconnect_block_reward(
        &mut self,
        block: &WithId<Block>,
    ) -> Result<(), ConnectTransactionError> {
        let reward_transactable = block.block_reward_transactable();
        let tx_source = TransactionSource::Chain(block.get_id());

        let block_undo_fetcher = |tx_source: TransactionSource| {
            self.storage
                .get_undo_data(tx_source)
                .map_err(|_| ConnectTransactionError::UndoFetchFailure)
        };
        let reward_undo =
            self.utxo_block_undo.take_block_reward_undo(&tx_source, block_undo_fetcher)?;
        self.utxo_cache.disconnect_block_transactable(
            &reward_transactable,
            &block.get_id().into(),
            reward_undo,
        )?;

        match block.header().consensus_data() {
            ConsensusData::None | ConsensusData::PoW(_) => { /*do nothing*/ }
            ConsensusData::PoS(_) => {
                let block_undo_fetcher = |tx_source: TransactionSource| {
                    self.storage
                        .get_pos_accounting_undo(tx_source)
                        .map_err(|_| ConnectTransactionError::TxVerifierStorage)
                };
                let reward_undo = self.pos_accounting_block_undo.take_block_reward_undo(
                    &TransactionSource::Chain(block.get_id()),
                    block_undo_fetcher,
                )?;
                if let Some(reward_undo) = reward_undo {
                    reward_undo.into_inner().into_iter().try_for_each(|undo| {
                        self.pos_accounting_adapter.operations(tx_source).undo(undo)
                    })?;
                }
            }
        }

        Ok(())
    }

    pub fn set_best_block(&mut self, id: Id<GenBlock>) {
        self.utxo_cache.set_best_block(id);
    }

    pub fn verify_inputs<Tx>(
        &self,
        tx: &Tx,
        tx_source: &TransactionSourceForConnect,
        median_time_past: BlockTimestamp,
        height: BlockHeight,
    ) -> Result<(), input_check::InputCheckError>
    where
        Tx: input_check::FullyVerifiable<
            PoSAccountingDelta<A>,
            TokensAccountingCache<T>,
            OrdersAccountingCache<O>,
        >,
    {
        input_check::verify_full(
            tx,
            self.chain_config.as_ref(),
            &self.utxo_cache,
            self.pos_accounting_adapter.accounting_delta(),
            &self.tokens_accounting_cache,
            &self.orders_accounting_cache,
            &self.storage,
            tx_source,
            median_time_past,
            height,
        )
    }

    pub fn consume(self) -> Result<TransactionVerifierDelta, ConnectTransactionError> {
        let (accounting_delta, accounting_block_deltas) = self.pos_accounting_adapter.consume();
        Ok(TransactionVerifierDelta {
            utxo_cache: self.utxo_cache.consume(),
            utxo_block_undo: self.utxo_block_undo.consume(),
            token_issuance_cache: self.token_issuance_cache.consume(),
            accounting_delta,
            pos_accounting_delta_undo: self.pos_accounting_block_undo.consume(),
            pos_accounting_block_deltas: accounting_block_deltas,
            account_nonce: self.account_nonce,
            tokens_accounting_delta: self.tokens_accounting_cache.consume(),
            tokens_accounting_delta_undo: self.tokens_accounting_block_undo.consume(),
            orders_accounting_delta: self.orders_accounting_cache.consume(),
            orders_accounting_delta_undo: self.orders_accounting_block_undo.consume(),
        })
    }
}

#[cfg(test)]
mod tests;

// TODO: write tests for block rewards
// TODO: test that total_block_reward = total_tx_fees + consensus_block_reward
