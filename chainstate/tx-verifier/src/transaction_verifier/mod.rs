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

mod accounting_delta_adapter;
mod accounting_undo_cache;
mod amounts_map;
mod cached_inputs_operation;
mod input_output_policy;
mod optional_tx_index_cache;
mod reward_distribution;
mod signature_check;
mod token_issuance_cache;
mod transferred_amount_check;
mod tx_index_cache;
mod utxos_undo_cache;

pub mod config;
pub mod error;
pub mod flush;
pub mod hierarchy;
pub mod signature_destination_getter;
pub mod storage;
pub mod timelock_check;

mod tx_source;
pub use tx_source::{TransactionSource, TransactionSourceForConnect};

mod cached_operation;
pub use cached_operation::CachedOperation;

use std::collections::BTreeMap;

use self::{
    accounting_delta_adapter::PoSAccountingDeltaAdapter,
    accounting_undo_cache::{AccountingBlockUndoCache, AccountingBlockUndoEntry},
    cached_inputs_operation::CachedInputsOperation,
    config::TransactionVerifierConfig,
    error::{ConnectTransactionError, SpendStakeError, TokensError},
    optional_tx_index_cache::OptionalTxIndexCache,
    signature_destination_getter::SignatureDestinationGetter,
    storage::TransactionVerifierStorageRef,
    token_issuance_cache::{ConsumedTokenIssuanceCache, TokenIssuanceCache},
    transferred_amount_check::{
        check_transferred_amount_in_reward, check_transferred_amounts_and_get_fee,
    },
    utxos_undo_cache::{UtxosBlockUndoCache, UtxosBlockUndoEntry},
};
use ::utils::{ensure, shallow_clone::ShallowClone};

use chainstate_types::BlockIndex;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockRewardTransactable, ConsensusData},
        signature::Signable,
        signed_transaction::SignedTransaction,
        tokens::{get_tokens_issuance_count, TokenId},
        AccountNonce, AccountOutPoint, AccountSpending, AccountType, Block, ChainConfig,
        DelegationId, GenBlock, OutPointSourceId, PoolId, Transaction, TxInput, TxMainChainIndex,
        TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, Id, Idable, H256},
};
use consensus::ConsensusPoSError;
use pos_accounting::{
    PoSAccountingDelta, PoSAccountingDeltaData, PoSAccountingOperations, PoSAccountingUndo,
    PoSAccountingView, PoolData,
};
use utxo::{ConsumedUtxoCache, UtxosCache, UtxosDB, UtxosView};

// TODO: We can move it to mod common, because in chain config we have `token_min_issuance_fee`
//       that essentially belongs to this type, but return Amount
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fee(pub Amount);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subsidy(pub Amount);

/// The change that a block has caused to the blockchain state
#[derive(Debug, Eq, PartialEq)]
pub struct TransactionVerifierDelta {
    tx_index_cache: BTreeMap<OutPointSourceId, CachedInputsOperation>,
    utxo_cache: ConsumedUtxoCache,
    utxo_block_undo: BTreeMap<TransactionSource, UtxosBlockUndoEntry>,
    token_issuance_cache: ConsumedTokenIssuanceCache,
    accounting_delta: PoSAccountingDeltaData,
    accounting_delta_undo: BTreeMap<TransactionSource, AccountingBlockUndoEntry>,
    accounting_block_deltas: BTreeMap<TransactionSource, PoSAccountingDeltaData>,
    account_nonce: BTreeMap<AccountType, CachedOperation<AccountNonce>>,
}

impl TransactionVerifierDelta {
    pub fn consume(self) -> (ConsumedUtxoCache, PoSAccountingDeltaData) {
        (self.utxo_cache, self.accounting_delta)
    }
}

/// The tool used to verify transactions and cache their updated states in memory
pub struct TransactionVerifier<C, S, U, A> {
    chain_config: C,
    storage: S,
    best_block: Id<GenBlock>,

    tx_index_cache: OptionalTxIndexCache,
    token_issuance_cache: TokenIssuanceCache,

    utxo_cache: UtxosCache<U>,
    utxo_block_undo: UtxosBlockUndoCache,

    accounting_delta_adapter: PoSAccountingDeltaAdapter<A>,
    accounting_block_undo: AccountingBlockUndoCache,

    account_nonce: BTreeMap<AccountType, CachedOperation<AccountNonce>>,
}

impl<C, S: TransactionVerifierStorageRef + ShallowClone> TransactionVerifier<C, S, UtxosDB<S>, S> {
    pub fn new(storage: S, chain_config: C, verifier_config: TransactionVerifierConfig) -> Self {
        let accounting_delta_adapter = PoSAccountingDeltaAdapter::new(S::clone(&storage));
        let utxo_cache = UtxosCache::new(UtxosDB::new(storage.shallow_clone()))
            .expect("Utxo cache setup failed");
        let best_block = storage
            .get_best_block_for_utxos()
            .expect("Database error while reading utxos best block");
        let tx_index_cache = OptionalTxIndexCache::from_config(&verifier_config);
        Self {
            storage,
            chain_config,
            best_block,
            tx_index_cache,
            token_issuance_cache: TokenIssuanceCache::new(),
            utxo_cache,
            utxo_block_undo: UtxosBlockUndoCache::new(),
            accounting_delta_adapter,
            accounting_block_undo: AccountingBlockUndoCache::new(),
            account_nonce: BTreeMap::new(),
        }
    }
}

impl<C, S, U, A> TransactionVerifier<C, S, U, A>
where
    S: TransactionVerifierStorageRef,
    U: UtxosView + Send + Sync,
    A: PoSAccountingView + Send + Sync,
{
    pub fn new_generic(
        storage: S,
        chain_config: C,
        utxos: U,
        accounting: A,
        verifier_config: TransactionVerifierConfig,
    ) -> Self {
        let best_block = storage
            .get_best_block_for_utxos()
            .expect("Database error while reading utxos best block");
        let tx_index_cache = OptionalTxIndexCache::from_config(&verifier_config);
        Self {
            storage,
            chain_config,
            best_block,
            tx_index_cache,
            token_issuance_cache: TokenIssuanceCache::new(),
            utxo_cache: UtxosCache::new(utxos).expect("Utxo cache setup failed"),
            utxo_block_undo: UtxosBlockUndoCache::new(),
            accounting_delta_adapter: PoSAccountingDeltaAdapter::new(accounting),
            accounting_block_undo: AccountingBlockUndoCache::new(),
            account_nonce: BTreeMap::new(),
        }
    }
}

impl<C, S, U, A> TransactionVerifier<C, S, U, A>
where
    C: AsRef<ChainConfig>,
    S: TransactionVerifierStorageRef,
    U: UtxosView,
    A: PoSAccountingView,
    <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
{
    pub fn derive_child(
        &self,
    ) -> TransactionVerifier<&ChainConfig, &Self, &UtxosCache<U>, &PoSAccountingDelta<A>> {
        TransactionVerifier {
            storage: self,
            chain_config: self.chain_config.as_ref(),
            tx_index_cache: OptionalTxIndexCache::new(self.tx_index_cache.enabled()),
            utxo_cache: UtxosCache::new(&self.utxo_cache).expect("construct"),
            utxo_block_undo: UtxosBlockUndoCache::new(),
            token_issuance_cache: TokenIssuanceCache::new(),
            accounting_delta_adapter: PoSAccountingDeltaAdapter::new(
                self.accounting_delta_adapter.accounting_delta(),
            ),
            accounting_block_undo: AccountingBlockUndoCache::new(),
            best_block: self.best_block,
            account_nonce: BTreeMap::new(),
        }
    }

    fn check_issuance_fee_burn(
        &self,
        tx: &Transaction,
        block_id: &Option<Id<Block>>,
    ) -> Result<(), ConnectTransactionError> {
        // Check if the fee is enough for issuance
        let issuance_count = get_tokens_issuance_count(tx.outputs());
        if issuance_count == 0 {
            return Ok(());
        }

        let total_burned = tx
            .outputs()
            .iter()
            .filter_map(|output| match output {
                TxOutput::Burn(v) => v.coin_amount(),
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _) => None,
            })
            .sum::<Option<Amount>>()
            .ok_or_else(|| ConnectTransactionError::BurnAmountSumError(tx.get_id()))?;

        if total_burned < self.chain_config.as_ref().token_min_issuance_fee() {
            return Err(ConnectTransactionError::TokensError(
                TokensError::InsufficientTokenFees(
                    tx.get_id(),
                    block_id.unwrap_or_else(|| H256::zero().into()),
                ),
            ));
        }

        Ok(())
    }

    fn get_pool_data_from_output(
        &self,
        output: &TxOutput,
    ) -> Result<PoolData, ConnectTransactionError> {
        match output {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => {
                Err(ConnectTransactionError::InvalidOutputTypeInReward)
            }
            TxOutput::CreateStakePool(_, d) => Ok(d.as_ref().clone().into()),
            TxOutput::ProduceBlockFromStake(_, pool_id) => self
                .accounting_delta_adapter
                .accounting_delta()
                .get_pool_data(*pool_id)?
                .ok_or(ConnectTransactionError::PoolDataNotFound(*pool_id)),
        }
    }

    fn get_pool_id_from_output(
        &self,
        output: &TxOutput,
    ) -> Result<PoolId, ConnectTransactionError> {
        match output {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => {
                Err(ConnectTransactionError::InvalidOutputTypeInReward)
            }
            TxOutput::CreateStakePool(pool_id, _) => Ok(*pool_id),
            TxOutput::ProduceBlockFromStake(_, pool_id) => Ok(*pool_id),
        }
    }

    fn check_stake_outputs_in_reward(
        &self,
        block: &WithId<Block>,
    ) -> Result<(), ConnectTransactionError> {
        match block.consensus_data() {
            ConsensusData::None | ConsensusData::PoW(_) => Ok(()),
            ConsensusData::PoS(_) => {
                let block_reward_transactable = block.block_reward_transactable();

                let kernel_output = consensus::get_kernel_output(
                    block_reward_transactable.inputs().ok_or(
                        SpendStakeError::ConsensusPoSError(ConsensusPoSError::NoKernel),
                    )?,
                    &self.utxo_cache,
                )
                .map_err(SpendStakeError::ConsensusPoSError)?;

                let reward_output = match block_reward_transactable
                    .outputs()
                    .ok_or(SpendStakeError::NoBlockRewardOutputs)?
                {
                    [] => Err(SpendStakeError::NoBlockRewardOutputs),
                    [output] => Ok(output),
                    _ => Err(SpendStakeError::MultipleBlockRewardOutputs),
                }?;

                let kernel_pool_id = self.get_pool_id_from_output(&kernel_output)?;
                let reward_pool_id = self.get_pool_id_from_output(reward_output)?;

                ensure!(
                    kernel_pool_id == reward_pool_id,
                    SpendStakeError::StakePoolIdMismatch(kernel_pool_id, reward_pool_id)
                );

                let kernel_pool_data = self.get_pool_data_from_output(&kernel_output)?;
                let reward_pool_data = self.get_pool_data_from_output(reward_output)?;

                ensure!(
                    kernel_pool_data == reward_pool_data,
                    SpendStakeError::StakePoolDataMismatch
                );

                Ok(())
            }
        }
    }

    pub fn check_block_reward(
        &self,
        block: &WithId<Block>,
        total_fees: Fee,
        block_subsidy_at_height: Subsidy,
    ) -> Result<(), ConnectTransactionError> {
        input_output_policy::check_reward_inputs_outputs_purposes(
            &block.block_reward_transactable(),
            &self.utxo_cache,
        )?;

        self.check_stake_outputs_in_reward(block)?;

        check_transferred_amount_in_reward(
            &self.utxo_cache,
            &self.accounting_delta_adapter.accounting_delta(),
            &block.block_reward_transactable(),
            block.get_id(),
            block.consensus_data(),
            total_fees,
            block_subsidy_at_height,
        )
    }

    fn spend_input_from_account(
        &mut self,
        tx_source: TransactionSource,
        account_input: &AccountOutPoint,
    ) -> Result<PoSAccountingUndo, ConnectTransactionError> {
        let account = *account_input.account();
        // Check that account nonce increments previous value
        let expected_nonce = match self
            .get_account_nonce_count(account.into())
            .map_err(|_| ConnectTransactionError::TxVerifierStorage)?
        {
            Some(nonce) => nonce
                .increment()
                .ok_or(ConnectTransactionError::FailedToIncrementAccountNonce)?,
            None => AccountNonce::new(0),
        };
        ensure!(
            expected_nonce == account_input.nonce(),
            ConnectTransactionError::NonceIsNotIncremental(
                account.into(),
                expected_nonce,
                account_input.nonce(),
            )
        );
        // store new nonce
        self.account_nonce.insert(
            account.into(),
            CachedOperation::Write(account_input.nonce()),
        );

        match account {
            AccountSpending::Delegation(delegation_id, withdraw_amount) => {
                // If the input spends from delegation account, this means the user is
                // spending part of their share in the pool.
                self.accounting_delta_adapter
                    .operations(tx_source)
                    .spend_share_from_delegation_id(delegation_id, withdraw_amount)
                    .map_err(ConnectTransactionError::PoSAccountingError)
            }
        }
    }

    fn spend_input_from_utxo(
        &mut self,
        tx_source: TransactionSource,
        input_outpoint: &UtxoOutPoint,
    ) -> Result<Option<PoSAccountingUndo>, ConnectTransactionError> {
        let input_utxo = self
            .utxo_cache
            .utxo(input_outpoint)
            .map_err(|_| utxo::Error::ViewRead)?
            .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
        match input_utxo.output() {
            TxOutput::CreateStakePool(pool_id, _) | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                // If the input spends `CreateStakePool` or `ProduceBlockFromStake` utxo,
                // this means the user is decommissioning the pool.
                let undo = self
                    .accounting_delta_adapter
                    .operations(tx_source)
                    .decommission_pool(*pool_id)
                    .map_err(ConnectTransactionError::PoSAccountingError)?;
                Ok(Some(undo))
            }
            TxOutput::DelegateStaking(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_) => Ok(None),
        }
    }

    fn connect_pos_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // TODO: this should also collect all the delegations after the pool decommissioning;
        // see mintlayer/mintlayer-core/issues/909
        let mut check_for_delegation_cleanup: Option<DelegationId> = None;

        // Process tx inputs in terms of pos accounting.
        // Spending `CreateStakePool`, `ProduceBlockFromStake` utxos or an account input
        // should result in either decommissioning a pool or spending share in accounting
        let inputs_undos = tx
            .inputs()
            .iter()
            .filter_map(|input| match input {
                TxInput::Utxo(outpoint) => {
                    self.spend_input_from_utxo(tx_source, outpoint).transpose()
                }
                TxInput::Account(account_input) => {
                    check_for_delegation_cleanup = match account_input.account() {
                        AccountSpending::Delegation(delegation_id, _) => Some(*delegation_id),
                    };
                    Some(self.spend_input_from_account(tx_source, account_input))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Process tx outputs in terms of pos accounting.
        let input_utxo_outpoint = tx.inputs().iter().find_map(|input| input.utxo_outpoint());
        let outputs_undos = tx
            .outputs()
            .iter()
            .filter_map(|output| match output {
                TxOutput::CreateStakePool(pool_id, data) => match input_utxo_outpoint {
                    Some(input_utxo_outpoint) => {
                        let expected_pool_id = pos_accounting::make_pool_id(input_utxo_outpoint);
                        let res = if expected_pool_id == *pool_id {
                            if data.value() >= self.chain_config.as_ref().min_stake_pool_pledge() {
                                self.accounting_delta_adapter
                                    .operations(tx_source)
                                    .create_pool(*pool_id, data.as_ref().clone().into())
                                    .map_err(ConnectTransactionError::PoSAccountingError)
                            } else {
                                Err(ConnectTransactionError::NotEnoughPledgeToCreateStakePool(
                                    tx.get_id(),
                                    data.value(),
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
                    None => Some(Err(
                        ConnectTransactionError::AttemptToCreateStakePoolFromAccounts,
                    )),
                },
                TxOutput::CreateDelegationId(spend_destination, target_pool) => {
                    match input_utxo_outpoint {
                        Some(input_utxo_outpoint) => {
                            let res = self
                                .accounting_delta_adapter
                                .operations(tx_source)
                                .create_delegation_id(
                                    *target_pool,
                                    spend_destination.clone(),
                                    input_utxo_outpoint,
                                )
                                .map(|(_, undo)| undo)
                                .map_err(ConnectTransactionError::PoSAccountingError);
                            Some(res)
                        }
                        None => Some(Err(
                            ConnectTransactionError::AttemptToCreateStakePoolFromAccounts,
                        )),
                    }
                }
                TxOutput::DelegateStaking(amount, delegation_id) => {
                    let res = self
                        .accounting_delta_adapter
                        .operations(tx_source)
                        .delegate_staking(*delegation_id, *amount)
                        .map_err(ConnectTransactionError::PoSAccountingError);
                    Some(res)
                }
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Burn(_)
                | TxOutput::ProduceBlockFromStake(_, _) => None,
            })
            .collect::<Result<Vec<_>, _>>()?;

        // delete delegation if the balance is 0 and the pool has been decommissioned
        let delete_delegation_undo = match check_for_delegation_cleanup {
            Some(delegation_id) => {
                let accounting_view = self.accounting_delta_adapter.accounting_delta();
                let delegation_balance =
                    accounting_view.get_delegation_balance(delegation_id)?.ok_or(
                        ConnectTransactionError::DelegationDataNotFound(delegation_id),
                    )?;
                if delegation_balance == Amount::ZERO {
                    let delegation_data =
                        accounting_view.get_delegation_data(delegation_id)?.ok_or(
                            ConnectTransactionError::DelegationDataNotFound(delegation_id),
                        )?;
                    if !accounting_view.pool_exists(*delegation_data.source_pool())? {
                        // clear the nonce
                        self.account_nonce.insert(
                            AccountType::Delegation(delegation_id),
                            CachedOperation::Erase,
                        );

                        Some(
                            self.accounting_delta_adapter
                                .operations(tx_source)
                                .delete_delegation_id(delegation_id)?,
                        )
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            None => None,
        };

        // Store pos accounting operations undos
        if !inputs_undos.is_empty() || !outputs_undos.is_empty() || delete_delegation_undo.is_some()
        {
            let tx_undos = inputs_undos
                .into_iter()
                .chain(outputs_undos.into_iter())
                .chain(delete_delegation_undo.into_iter())
                .collect();
            self.accounting_block_undo
                .get_or_create_block_undo(&tx_source)
                .insert_tx_undo(tx.get_id(), pos_accounting::AccountingTxUndo::new(tx_undos))
                .map_err(ConnectTransactionError::AccountingBlockUndoError)
        } else {
            Ok(())
        }
    }

    fn disconnect_pos_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // decrement nonce if disconnected input spent from account
        for input in tx.inputs() {
            match input {
                TxInput::Utxo(_) => { /* do nothing */ }
                TxInput::Account(account_input) => {
                    let account: AccountType = (*account_input.account()).into();
                    let new_nonce = self
                        .get_account_nonce_count(account)
                        .map_err(|_| ConnectTransactionError::TxVerifierStorage)?
                        .ok_or(ConnectTransactionError::MissingTransactionNonce(account))?
                        .decrement()
                        .map_or(CachedOperation::Erase, CachedOperation::Write);
                    self.account_nonce.insert(account, new_nonce);
                }
            };
        }

        // apply undos to accounting
        tx.outputs().iter().try_for_each(|output| match output {
            TxOutput::CreateStakePool(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => {
                let block_undo_fetcher = |id: Id<Block>| {
                    self.storage
                        .get_accounting_undo(id)
                        .map_err(|_| ConnectTransactionError::TxVerifierStorage)
                };
                self.accounting_block_undo
                    .take_tx_undo(&tx_source, &tx.get_id(), block_undo_fetcher)?
                    .into_inner()
                    .into_iter()
                    .try_for_each(|undo| {
                        self.accounting_delta_adapter.operations(tx_source).undo(undo)?;
                        Ok(())
                    })
            }
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::ProduceBlockFromStake(_, _) => Ok(()),
        })
    }

    pub fn connect_transaction(
        &mut self,
        tx_source: &TransactionSourceForConnect,
        tx: &SignedTransaction,
        median_time_past: &BlockTimestamp,
        tx_index: Option<TxMainChainIndex>,
    ) -> Result<Fee, ConnectTransactionError> {
        let block_id = tx_source.chain_block_index().map(|c| *c.block_id());

        input_output_policy::check_tx_inputs_outputs_purposes(tx.transaction(), &self.utxo_cache)?;

        // pre-cache token ids to check ensure it's not in the db when issuing
        self.token_issuance_cache.precache_token_issuance(
            |id| {
                self.storage
                    .get_token_aux_data(id)
                    .map_err(|_| ConnectTransactionError::TxVerifierStorage)
            },
            tx.transaction(),
        )?;

        let issuance_token_id_getter =
            |tx_id: &Id<Transaction>| -> Result<Option<TokenId>, ConnectTransactionError> {
                // issuance transactions are unique, so we use them to get the token id
                self.get_token_id_from_issuance_tx(*tx_id)
                    .map_err(|_| ConnectTransactionError::TxVerifierStorage)
            };

        // check for attempted money printing
        let fee = check_transferred_amounts_and_get_fee(
            &self.utxo_cache,
            &self.accounting_delta_adapter.accounting_delta(),
            tx.transaction(),
            issuance_token_id_getter,
        )?;

        // check token issuance fee
        self.check_issuance_fee_burn(tx.transaction(), &block_id)?;

        // Register tokens if tx has issuance data
        self.token_issuance_cache.register(block_id, tx.transaction())?;

        // check timelocks of the outputs and make sure there's no premature spending
        timelock_check::check_timelocks(
            &self.storage,
            &self.chain_config,
            &self.utxo_cache,
            tx,
            tx_source,
            tx.transaction().get_id().into(),
            median_time_past,
        )?;

        // verify input signatures
        signature_check::verify_signatures(
            self.chain_config.as_ref(),
            &self.utxo_cache,
            tx,
            SignatureDestinationGetter::new_for_transaction(
                &self.accounting_delta_adapter.accounting_delta(),
                &self.utxo_cache,
            ),
        )?;

        self.connect_pos_accounting_outputs(tx_source.into(), tx.transaction())?;

        // spend utxos
        let tx_undo = self
            .utxo_cache
            .connect_transaction(tx.transaction(), tx_source.expected_block_height())
            .map_err(ConnectTransactionError::from)?;

        // save spent utxos for undo
        self.utxo_block_undo
            .get_or_create_block_undo(&TransactionSource::from(tx_source))
            .insert_tx_undo(tx.transaction().get_id(), tx_undo)?;

        match tx_source {
            TransactionSourceForConnect::Chain { new_block_index: _ } => {
                // update tx index only for txs from main chain
                if let Some(tx_index_cache) = self.tx_index_cache.as_mut() {
                    // pre-cache all inputs
                    tx_index_cache.precache_inputs(tx.inputs(), |tx_id: &OutPointSourceId| {
                        self.storage
                            .get_mainchain_tx_index(tx_id)
                            .map_err(|_| ConnectTransactionError::TxVerifierStorage)
                    })?;

                    // mark tx index as spent
                    tx_index_cache
                        .spend_tx_index_inputs(tx.inputs(), tx.transaction().get_id().into())?;

                    tx_index_cache.add_tx_index(
                        OutPointSourceId::Transaction(tx.transaction().get_id()),
                        tx_index.expect("Guaranteed by verifier_config"),
                    )?;
                }
            }
            TransactionSourceForConnect::Mempool { current_best: _ } => { /* do nothing */ }
        };

        Ok(fee)
    }

    pub fn connect_block_reward(
        &mut self,
        block_index: &BlockIndex,
        reward_transactable: BlockRewardTransactable,
        total_fees: Fee,
        tx_index: Option<TxMainChainIndex>,
    ) -> Result<(), ConnectTransactionError> {
        // TODO: test spending block rewards from chains outside the mainchain
        if let Some(inputs) = reward_transactable.inputs() {
            // pre-cache all inputs
            if let Some(tx_index_cache) = self.tx_index_cache.as_mut() {
                tx_index_cache.precache_inputs(inputs, |tx_id: &OutPointSourceId| {
                    self.storage
                        .get_mainchain_tx_index(tx_id)
                        .map_err(|_| ConnectTransactionError::TxVerifierStorage)
                })?;
            }

            // verify input signatures
            signature_check::verify_signatures(
                self.chain_config.as_ref(),
                &self.utxo_cache,
                &reward_transactable,
                SignatureDestinationGetter::new_for_block_reward(&self.utxo_cache),
            )?;
        }

        let block_id = *block_index.block_id();

        // spend inputs of the block reward
        // if block reward has no inputs then only outputs will be added to the utxo set
        let reward_undo = self
            .utxo_cache
            .connect_block_transactable(
                &reward_transactable,
                &block_id.into(),
                block_index.block_height(),
            )
            .map_err(ConnectTransactionError::from)?;

        if let Some(reward_undo) = reward_undo {
            // save spent utxos for undo
            self.utxo_block_undo
                .get_or_create_block_undo(&TransactionSource::Chain(block_id))
                .set_block_reward_undo(reward_undo);
        }

        if let Some(tx_index_cache) = self.tx_index_cache.as_mut() {
            if let Some(inputs) = reward_transactable.inputs() {
                // mark tx index as spend
                tx_index_cache.spend_tx_index_inputs(inputs, block_id.into())?;
            }

            tx_index_cache.add_tx_index(
                OutPointSourceId::BlockReward(block_id.into()),
                tx_index.expect("Guaranteed by verifier_config"),
            )?;
        }

        match block_index.block_header().consensus_data() {
            ConsensusData::None | ConsensusData::PoW(_) => { /* do nothing */ }
            ConsensusData::PoS(pos_data) => {
                // distribute reward among staker and delegators
                let block_subsidy =
                    self.chain_config.as_ref().block_subsidy_at_height(&block_index.block_height());
                let total_reward = (block_subsidy + total_fees.0)
                    .ok_or(ConnectTransactionError::RewardAdditionError(block_id))?;

                let undos = reward_distribution::distribute_pos_reward(
                    &mut self.accounting_delta_adapter,
                    block_id,
                    *pos_data.stake_pool_id(),
                    total_reward,
                )?;

                self.accounting_block_undo
                    .get_or_create_block_undo(&TransactionSource::Chain(block_id))
                    .set_reward_undo(undos);
            }
        };

        Ok(())
    }

    pub fn can_disconnect_transaction(
        &self,
        tx_source: &TransactionSource,
        tx_id: &Id<Transaction>,
    ) -> Result<bool, ConnectTransactionError> {
        let block_undo_fetcher = |id: Id<Block>| {
            self.storage
                .get_undo_data(id)
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
                    Ok(!self
                        .utxo_block_undo
                        .read_block_undo(tx_source, block_undo_fetcher)?
                        .has_children_of(tx_id))
                }
            }
            TransactionSource::Mempool => Ok(!self
                .utxo_block_undo
                .read_block_undo(tx_source, block_undo_fetcher)?
                .has_children_of(tx_id)),
        }
    }

    pub fn disconnect_transaction(
        &mut self,
        tx_source: &TransactionSource,
        tx: &SignedTransaction,
    ) -> Result<(), ConnectTransactionError> {
        let block_undo_fetcher = |id: Id<Block>| {
            self.storage
                .get_undo_data(id)
                .map_err(|_| ConnectTransactionError::UndoFetchFailure)
        };
        let tx_undo = self.utxo_block_undo.take_tx_undo(
            tx_source,
            &tx.transaction().get_id(),
            block_undo_fetcher,
        )?;

        if let Some(tx_index_cache) = self.tx_index_cache.as_mut() {
            tx_index_cache
                .remove_tx_index(OutPointSourceId::Transaction(tx.transaction().get_id()))?;
        }

        match tx_source {
            TransactionSource::Chain(_) => {
                let tx_index_fetcher = |tx_id: &OutPointSourceId| {
                    self.storage
                        .get_mainchain_tx_index(tx_id)
                        .map_err(|_| ConnectTransactionError::TxVerifierStorage)
                };
                // update tx index only for txs from main chain
                if let Some(tx_index_cache) = self.tx_index_cache.as_mut() {
                    // pre-cache all inputs
                    tx_index_cache.precache_inputs(tx.inputs(), tx_index_fetcher)?;

                    // unspend inputs
                    tx_index_cache.unspend_tx_index_inputs(tx.inputs())?;
                }
            }
            TransactionSource::Mempool => { /* do nothing */ }
        };

        self.disconnect_pos_accounting_outputs(*tx_source, tx.transaction())?;

        self.utxo_cache.disconnect_transaction(tx.transaction(), tx_undo)?;

        // pre-cache token ids before removing them
        self.token_issuance_cache.precache_token_issuance(
            |id| {
                self.storage
                    .get_token_aux_data(id)
                    .map_err(|_| ConnectTransactionError::TxVerifierStorage)
            },
            tx.transaction(),
        )?;

        // Remove issued tokens
        self.token_issuance_cache.unregister(tx.transaction())?;

        Ok(())
    }

    pub fn disconnect_block_reward(
        &mut self,
        block: &WithId<Block>,
    ) -> Result<(), ConnectTransactionError> {
        if let Some(tx_index_cache) = self.tx_index_cache.as_mut() {
            tx_index_cache.remove_tx_index(OutPointSourceId::BlockReward(block.get_id().into()))?;
        }

        let reward_transactable = block.block_reward_transactable();
        let tx_source = TransactionSource::Chain(block.get_id());

        let block_undo_fetcher = |id: Id<Block>| {
            self.storage
                .get_undo_data(id)
                .map_err(|_| ConnectTransactionError::UndoFetchFailure)
        };
        let reward_undo =
            self.utxo_block_undo.take_block_reward_undo(&tx_source, block_undo_fetcher)?;
        self.utxo_cache.disconnect_block_transactable(
            &reward_transactable,
            &block.get_id().into(),
            reward_undo,
        )?;

        if let (Some(inputs), Some(tx_index_cache)) =
            (reward_transactable.inputs(), self.tx_index_cache.as_mut())
        {
            // pre-cache all inputs
            let tx_index_fetcher = |tx_id: &OutPointSourceId| {
                self.storage
                    .get_mainchain_tx_index(tx_id)
                    .map_err(|_| ConnectTransactionError::TxVerifierStorage)
            };
            tx_index_cache.precache_inputs(inputs, tx_index_fetcher)?;

            // unspend inputs
            tx_index_cache.unspend_tx_index_inputs(inputs)?;
        }

        match block.header().consensus_data() {
            ConsensusData::None | ConsensusData::PoW(_) => { /*do nothing*/ }
            ConsensusData::PoS(_) => {
                let block_undo_fetcher = |id: Id<Block>| {
                    self.storage
                        .get_accounting_undo(id)
                        .map_err(|_| ConnectTransactionError::TxVerifierStorage)
                };
                let reward_undo = self.accounting_block_undo.take_block_reward_undo(
                    &TransactionSource::Chain(block.get_id()),
                    block_undo_fetcher,
                )?;
                if let Some(reward_undo) = reward_undo {
                    reward_undo.into_inner().into_iter().try_for_each(|undo| {
                        self.accounting_delta_adapter.operations(tx_source).undo(undo)
                    })?;
                }
            }
        }

        Ok(())
    }

    pub fn set_best_block(&mut self, id: Id<GenBlock>) {
        self.utxo_cache.set_best_block(id);
    }

    pub fn consume(self) -> Result<TransactionVerifierDelta, ConnectTransactionError> {
        let (accounting_delta, accounting_block_deltas) = self.accounting_delta_adapter.consume();
        Ok(TransactionVerifierDelta {
            tx_index_cache: self.tx_index_cache.take_always().consume(),
            utxo_cache: self.utxo_cache.consume(),
            utxo_block_undo: self.utxo_block_undo.consume(),
            token_issuance_cache: self.token_issuance_cache.consume(),
            accounting_delta,
            accounting_delta_undo: self.accounting_block_undo.consume(),
            accounting_block_deltas,
            account_nonce: self.account_nonce,
        })
    }
}

#[cfg(test)]
mod tests;

// TODO: write tests for block rewards
// TODO: test that total_block_reward = total_tx_fees + consensus_block_reward
