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

mod accounting_undo_cache;
mod amounts_map;
mod cached_inputs_operation;
mod token_issuance_cache;
mod tx_index_cache;
mod utils;
mod utxos_undo_cache;

pub mod config;
pub mod error;
pub mod flush;
pub mod hierarchy;
mod optional_tx_index_cache;
pub mod storage;

mod cached_operation;
pub use cached_operation::CachedOperation;

use std::collections::BTreeMap;

use self::{
    accounting_undo_cache::{AccountingBlockUndoCache, AccountingBlockUndoEntry},
    amounts_map::AmountsMap,
    cached_inputs_operation::CachedInputsOperation,
    config::TransactionVerifierConfig,
    error::{ConnectTransactionError, TokensError},
    optional_tx_index_cache::OptionalTxIndexCache,
    storage::TransactionVerifierStorageRef,
    token_issuance_cache::{CoinOrTokenId, ConsumedTokenIssuanceCache, TokenIssuanceCache},
    utils::{
        calculate_total_outputs, check_transferred_amount, get_input_token_id_and_amount,
        get_total_fee,
    },
    utxos_undo_cache::{UtxosBlockUndoCache, UtxosBlockUndoEntry},
};
use ::utils::{ensure, shallow_clone::ShallowClone};

use chainstate_types::{block_index_ancestor_getter, BlockIndex, GenBlockIndex};
use common::{
    amount_sum,
    chain::{
        block::{timestamp::BlockTimestamp, BlockRewardTransactable},
        signature::{verify_signature, Signable, Transactable},
        signed_transaction::SignedTransaction,
        tokens::{get_tokens_issuance_count, OutputValue, TokenId},
        Block, ChainConfig, GenBlock, OutPointSourceId, OutputPurpose, Transaction, TxInput,
        TxMainChainIndex, TxOutput,
    },
    primitives::{id::WithId, Amount, BlockDistance, BlockHeight, Id, Idable, H256},
};
use pos_accounting::{
    PoSAccountingDelta, PoSAccountingDeltaData, PoSAccountingOperations, PoSAccountingUndo,
    PoSAccountingView,
};
use utxo::{ConsumedUtxoCache, Utxo, UtxosCache, UtxosDB, UtxosView};

// TODO: We can move it to mod common, because in chain config we have `token_min_issuance_fee`
//       that essentially belongs to this type, but return Amount
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fee(pub Amount);

pub struct Subsidy(pub Amount);

/// A BlockTransactableRef is a reference to an operation in a block that causes inputs to be spent, outputs to be created, or both
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BlockTransactableRef<'a> {
    Transaction(&'a WithId<Block>, usize),
    BlockReward(&'a WithId<Block>),
}

/// A BlockTransactableRef is a reference to an operation in a block that causes inputs to be spent, outputs to be created, or both
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BlockTransactableWithIndexRef<'a> {
    Transaction(&'a WithId<Block>, usize, Option<TxMainChainIndex>),
    BlockReward(&'a WithId<Block>, Option<TxMainChainIndex>),
}

impl<'a> BlockTransactableWithIndexRef<'a> {
    pub fn without_tx_index(&self) -> BlockTransactableRef<'a> {
        match self {
            BlockTransactableWithIndexRef::Transaction(block, index, _) => {
                BlockTransactableRef::Transaction(block, *index)
            }
            BlockTransactableWithIndexRef::BlockReward(block, _) => {
                BlockTransactableRef::BlockReward(block)
            }
        }
    }

    pub fn take_tx_index(self) -> Option<TxMainChainIndex> {
        match self {
            BlockTransactableWithIndexRef::Transaction(_, _, idx) => idx,
            BlockTransactableWithIndexRef::BlockReward(_, idx) => idx,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TransactionSource {
    Chain(Id<Block>),
    Mempool,
}

impl<'a> From<&TransactionSourceForConnect<'a>> for TransactionSource {
    fn from(t: &TransactionSourceForConnect) -> Self {
        match t {
            TransactionSourceForConnect::Chain { new_block_index } => {
                TransactionSource::Chain(*new_block_index.block_id())
            }
            TransactionSourceForConnect::Mempool { current_best: _ } => TransactionSource::Mempool,
        }
    }
}

pub enum TransactionSourceForConnect<'a> {
    Chain { new_block_index: &'a BlockIndex },
    Mempool { current_best: &'a BlockIndex },
}

impl<'a> TransactionSourceForConnect<'a> {
    /// The block height of the transaction to be connected
    /// For the mempool, it's the height of the next-to-be block
    /// For the chain, it's for the block being connected
    pub fn expected_block_height(&self) -> BlockHeight {
        match self {
            TransactionSourceForConnect::Chain { new_block_index } => {
                new_block_index.block_height()
            }
            TransactionSourceForConnect::Mempool {
                current_best: best_block_index,
            } => best_block_index.block_height().next_height(),
        }
    }

    pub fn chain_block_index(&self) -> Option<&BlockIndex> {
        match self {
            TransactionSourceForConnect::Chain { new_block_index } => Some(new_block_index),
            TransactionSourceForConnect::Mempool { current_best: _ } => None,
        }
    }
}

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

    // represents accumulated delta with all changes done via current verifier object
    accounting_delta: PoSAccountingDelta<A>,
    accounting_block_undo: AccountingBlockUndoCache,

    // stores deltas per block
    accounting_block_deltas: BTreeMap<TransactionSource, PoSAccountingDeltaData>,
}

impl<C, S: TransactionVerifierStorageRef + ShallowClone> TransactionVerifier<C, S, UtxosDB<S>, S> {
    pub fn new(storage: S, chain_config: C, verifier_config: TransactionVerifierConfig) -> Self {
        let accounting_delta = PoSAccountingDelta::new(S::clone(&storage));
        let utxo_cache = UtxosCache::new(UtxosDB::new(S::clone(&storage)));
        let best_block = storage
            .get_best_block_for_utxos()
            .expect("Database error while reading utxos best block")
            .expect("best block should be some");
        let tx_index_cache = OptionalTxIndexCache::from_config(&verifier_config);
        Self {
            storage,
            chain_config,
            best_block,
            tx_index_cache,
            token_issuance_cache: TokenIssuanceCache::new(),
            utxo_cache,
            utxo_block_undo: UtxosBlockUndoCache::new(),
            accounting_delta,
            accounting_block_undo: AccountingBlockUndoCache::new(),
            accounting_block_deltas: BTreeMap::new(),
        }
    }
}

impl<C, S, U, A> TransactionVerifier<C, S, U, A>
where
    S: TransactionVerifierStorageRef,
    U: UtxosView + Send + Sync,
    A: PoSAccountingView + Send + Sync,
{
    pub fn new_from_handle(
        storage: S,
        chain_config: C,
        utxos: U,      // TODO: Replace this parameter with handle
        accounting: A, // TODO: Replace this parameter with handle
        verifier_config: TransactionVerifierConfig,
    ) -> Self {
        let best_block = storage
            .get_best_block_for_utxos()
            .expect("Database error while reading utxos best block")
            .expect("best block should be some");
        let tx_index_cache = OptionalTxIndexCache::from_config(&verifier_config);
        Self {
            storage,
            chain_config,
            best_block,
            tx_index_cache,
            token_issuance_cache: TokenIssuanceCache::new(),
            utxo_cache: UtxosCache::new(utxos), // TODO: take utxos from handle
            utxo_block_undo: UtxosBlockUndoCache::new(),
            accounting_delta: PoSAccountingDelta::new(accounting),
            accounting_block_undo: AccountingBlockUndoCache::new(),
            accounting_block_deltas: BTreeMap::new(),
        }
    }
}

impl<C, S, U, A> TransactionVerifier<C, S, U, A>
where
    C: AsRef<ChainConfig>,
    S: TransactionVerifierStorageRef,
    U: UtxosView,
    A: PoSAccountingView,
{
    pub fn derive_child(
        &self,
    ) -> TransactionVerifier<&ChainConfig, &Self, &UtxosCache<U>, &PoSAccountingDelta<A>> {
        TransactionVerifier {
            storage: self,
            chain_config: self.chain_config.as_ref(),
            tx_index_cache: OptionalTxIndexCache::new(self.tx_index_cache.enabled()),
            utxo_cache: UtxosCache::new(&self.utxo_cache),
            utxo_block_undo: UtxosBlockUndoCache::new(),
            token_issuance_cache: TokenIssuanceCache::new(),
            accounting_delta: PoSAccountingDelta::new(&self.accounting_delta),
            accounting_block_undo: AccountingBlockUndoCache::new(),
            accounting_block_deltas: BTreeMap::new(),
            best_block: self.best_block,
        }
    }

    fn amount_from_outpoint(
        &self,
        tx_id: OutPointSourceId,
        utxo: Utxo,
    ) -> Result<(CoinOrTokenId, Amount), ConnectTransactionError> {
        match tx_id {
            OutPointSourceId::Transaction(tx_id) => {
                let issuance_token_id_getter =
                    || -> Result<Option<TokenId>, ConnectTransactionError> {
                        // issuance transactions are unique, so we use them to get the token id
                        self.get_token_id_from_issuance_tx(tx_id)
                            .map_err(ConnectTransactionError::TransactionVerifierError)
                    };
                let (key, amount) =
                    get_input_token_id_and_amount(utxo.output().value(), issuance_token_id_getter)?;
                Ok((key, amount))
            }
            OutPointSourceId::BlockReward(_) => {
                let (key, amount) =
                    get_input_token_id_and_amount(utxo.output().value(), || Ok(None))?;
                match key {
                    CoinOrTokenId::Coin => Ok((CoinOrTokenId::Coin, amount)),
                    CoinOrTokenId::TokenId(tid) => Ok((CoinOrTokenId::TokenId(tid), amount)),
                }
            }
        }
    }

    fn calculate_total_inputs(
        &self,
        inputs: &[TxInput],
    ) -> Result<BTreeMap<CoinOrTokenId, Amount>, ConnectTransactionError> {
        let iter = inputs.iter().map(|input| {
            let utxo = self
                .utxo_cache
                .utxo(input.outpoint())
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
            self.amount_from_outpoint(input.outpoint().tx_id(), utxo)
        });

        let iter = fallible_iterator::convert(iter);

        let amounts_map = AmountsMap::from_fallible_iter(iter)?;

        Ok(amounts_map.take())
    }

    fn check_transferred_amounts_and_get_fee(
        &self,
        tx: &Transaction,
    ) -> Result<Fee, ConnectTransactionError> {
        let inputs_total_map = self.calculate_total_inputs(tx.inputs())?;
        let outputs_total_map = calculate_total_outputs(tx.outputs(), None)?;

        check_transferred_amount(&inputs_total_map, &outputs_total_map)?;
        let total_fee = get_total_fee(&inputs_total_map, &outputs_total_map)?;

        Ok(total_fee)
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
            .filter(|o| *o.purpose() == OutputPurpose::Burn)
            .filter_map(|o| o.value().coin_amount())
            .try_fold(Amount::ZERO, |so_far, v| {
                (so_far + v).ok_or_else(|| ConnectTransactionError::BurnAmountSumError(tx.get_id()))
            })?;

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

    pub fn check_block_reward(
        &self,
        block: &WithId<Block>,
        total_fees: Fee,
        block_subsidy_at_height: Subsidy,
    ) -> Result<(), ConnectTransactionError> {
        let block_reward_transactable = block.block_reward_transactable();

        let inputs = block_reward_transactable.inputs();
        let outputs = block_reward_transactable.outputs();

        let inputs_total = inputs.map_or_else(
            || Ok::<Amount, ConnectTransactionError>(Amount::from_atoms(0)),
            |ins| {
                Ok(self
                    .calculate_total_inputs(ins)?
                    .get(&CoinOrTokenId::Coin)
                    .cloned()
                    .unwrap_or(Amount::from_atoms(0)))
            },
        )?;
        let outputs_total = outputs.map_or_else(
            || Ok::<Amount, ConnectTransactionError>(Amount::from_atoms(0)),
            |outputs| {
                if outputs.iter().any(|output| match output.value() {
                    OutputValue::Coin(_) => false,
                    OutputValue::Token(_) => true,
                }) {
                    return Err(ConnectTransactionError::TokensError(
                        TokensError::TokensInBlockReward,
                    ));
                }
                Ok(calculate_total_outputs(outputs, None)?
                    .get(&CoinOrTokenId::Coin)
                    .cloned()
                    .unwrap_or(Amount::from_atoms(0)))
            },
        )?;

        let max_allowed_outputs_total =
            amount_sum!(inputs_total, block_subsidy_at_height.0, total_fees.0)
                .ok_or_else(|| ConnectTransactionError::RewardAdditionError(block.get_id()))?;

        if outputs_total > max_allowed_outputs_total {
            return Err(ConnectTransactionError::AttemptToPrintMoney(
                inputs_total,
                outputs_total,
            ));
        }
        Ok(())
    }

    fn check_timelock(
        &self,
        source_block_index: &GenBlockIndex,
        output: &TxOutput,
        spend_height: &BlockHeight,
        spending_time: &BlockTimestamp,
    ) -> Result<(), ConnectTransactionError> {
        use common::chain::timelock::OutputTimeLock;

        let timelock = match output.purpose() {
            OutputPurpose::Transfer(_) => return Ok(()),
            OutputPurpose::LockThenTransfer(_, tl) => tl,
            OutputPurpose::Burn => return Ok(()),
            OutputPurpose::StakePool(_) => return Ok(()),
            OutputPurpose::SpendStakePool(_, tl) => tl,
        };

        let source_block_height = source_block_index.block_height();
        let source_block_time = source_block_index.block_timestamp();

        let past_lock = match timelock {
            OutputTimeLock::UntilHeight(h) => spend_height >= h,
            OutputTimeLock::UntilTime(t) => spending_time >= t,
            OutputTimeLock::ForBlockCount(d) => {
                let d: i64 = (*d)
                    .try_into()
                    .map_err(|_| ConnectTransactionError::BlockHeightArithmeticError)?;
                let d = BlockDistance::from(d);
                *spend_height
                    >= (source_block_height + d)
                        .ok_or(ConnectTransactionError::BlockHeightArithmeticError)?
            }
            OutputTimeLock::ForSeconds(dt) => {
                *spending_time
                    >= source_block_time
                        .add_int_seconds(*dt)
                        .ok_or(ConnectTransactionError::BlockTimestampArithmeticError)?
            }
        };

        ensure!(past_lock, ConnectTransactionError::TimeLockViolation);

        Ok(())
    }

    fn verify_signatures<T: Transactable>(&self, tx: &T) -> Result<(), ConnectTransactionError> {
        let inputs = match tx.inputs() {
            Some(ins) => ins,
            None => return Ok(()),
        };

        for (input_idx, input) in inputs.iter().enumerate() {
            let outpoint = input.outpoint();
            let utxo = self
                .utxo_cache
                .utxo(outpoint)
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;

            // TODO: see if a different treatment should be done for different output purposes
            // TODO: ensure that signature verification is tested in the test-suite, they seem to be tested only internally
            match utxo.output().purpose().destination() {
                Some(d) => verify_signature(self.chain_config.as_ref(), d, tx, input_idx)
                    .map_err(ConnectTransactionError::SignatureVerificationFailed)?,
                None => return Err(ConnectTransactionError::AttemptToSpendBurnedAmount),
            }
        }

        Ok(())
    }

    fn check_timelocks<T: Transactable>(
        &self,
        tx_source: &TransactionSourceForConnect,
        tx: &T,
        spending_time: &BlockTimestamp,
    ) -> Result<(), ConnectTransactionError> {
        let inputs = match tx.inputs() {
            Some(ins) => ins,
            None => return Ok(()),
        };

        for input in inputs {
            let outpoint = input.outpoint();
            let utxo = self
                .utxo_cache
                .utxo(outpoint)
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;

            if utxo.output().has_timelock() {
                let height = match utxo.source() {
                    utxo::UtxoSource::Blockchain(h) => *h,
                    utxo::UtxoSource::Mempool => match tx_source {
                        TransactionSourceForConnect::Chain { new_block_index: _ } => {
                            unreachable!("Mempool utxos can never be reached from storage while connecting local transactions")
                        }
                        TransactionSourceForConnect::Mempool { current_best } => {
                            current_best.block_height().next_height()
                        }
                    },
                };

                let block_index_getter =
                    |db_tx: &S, _chain_config: &ChainConfig, id: &Id<GenBlock>| {
                        db_tx.get_gen_block_index(id)
                    };

                let starting_point: &BlockIndex = match tx_source {
                    TransactionSourceForConnect::Chain { new_block_index } => new_block_index,
                    TransactionSourceForConnect::Mempool { current_best } => current_best,
                };

                let source_block_index = block_index_ancestor_getter(
                    block_index_getter,
                    &self.storage,
                    self.chain_config.as_ref(),
                    (&starting_point.clone().into_gen_block_index()).into(),
                    height,
                )
                .map_err(|e| {
                    ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(
                        e, height,
                    )
                })?;

                self.check_timelock(
                    &source_block_index,
                    utxo.output(),
                    &tx_source.expected_block_height(),
                    spending_time,
                )?;
            }
        }

        Ok(())
    }

    fn connect_pos_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        let input0_getter =
            || tx.inputs().get(0).ok_or(ConnectTransactionError::MissingOutputOrSpent);

        let tx_undo = tx
            .outputs()
            .iter()
            .filter_map(|output| match output.purpose() {
                OutputPurpose::StakePool(data) => Some((data, output.value())),
                OutputPurpose::Transfer(_)
                | OutputPurpose::LockThenTransfer(_, _)
                | OutputPurpose::Burn
                | OutputPurpose::SpendStakePool(_, _) => None,
            })
            .map(
                |(pool_data, output_value)| -> Result<PoSAccountingUndo, ConnectTransactionError> {
                    let input0 = input0_getter()?;

                    // TODO: check StakePoolData fields
                    let delegation_amount = output_value.coin_amount().ok_or_else(|| {
                        ConnectTransactionError::TokenOutputInPoSAccountingOperation(tx.get_id())
                    })?;

                    let mut temp_delta = PoSAccountingDelta::new(&self.accounting_delta);
                    let (_, undo) = temp_delta
                        .create_pool(
                            input0.outpoint(),
                            delegation_amount,
                            pool_data.decommission_key().clone(),
                        )
                        .map_err(ConnectTransactionError::PoSAccountingError)?;
                    let new_delta_data = temp_delta.consume();

                    self.accounting_delta.merge_with_delta(new_delta_data.clone())?;

                    self.accounting_block_deltas
                        .entry(tx_source)
                        .or_default()
                        .merge_with_delta(new_delta_data)?;

                    Ok(undo)
                },
            )
            .collect::<Result<Vec<_>, _>>()?;

        if !tx_undo.is_empty() {
            self.accounting_block_undo
                .get_or_create_block_undo(&tx_source)
                .insert_tx_undo(tx.get_id(), pos_accounting::AccountingTxUndo::new(tx_undo))
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
        tx.outputs().iter().try_for_each(|output| match output.purpose() {
            OutputPurpose::StakePool(_) => {
                let block_undo_fetcher = |id: Id<Block>| self.storage.get_accounting_undo(id);
                self.accounting_block_undo
                    .take_tx_undo(&tx_source, &tx.get_id(), block_undo_fetcher)?
                    .into_inner()
                    .into_iter()
                    .try_for_each(|undo| {
                        let mut temp_delta = PoSAccountingDelta::new(&self.accounting_delta);
                        temp_delta.undo(undo)?;
                        let new_delta_data = temp_delta.consume();

                        self.accounting_delta.merge_with_delta(new_delta_data.clone())?;
                        self.accounting_block_deltas
                            .entry(tx_source)
                            .or_default()
                            .merge_with_delta(new_delta_data)?;
                        Ok(())
                    })
                    .map_err(ConnectTransactionError::PoSAccountingError)
            }
            OutputPurpose::Transfer(_)
            | OutputPurpose::LockThenTransfer(_, _)
            | OutputPurpose::Burn
            | OutputPurpose::SpendStakePool(_, _) => Ok(()),
        })
    }

    pub fn connect_transaction(
        &mut self,
        tx_source: &TransactionSourceForConnect,
        tx: &SignedTransaction,
        median_time_past: &BlockTimestamp,
    ) -> Result<Option<Fee>, ConnectTransactionError> {
        let block_id = tx_source.chain_block_index().map(|c| *c.block_id());

        // pre-cache token ids to check ensure it's not in the db when issuing
        self.token_issuance_cache
            .precache_token_issuance(|id| self.storage.get_token_aux_data(id), tx.transaction())?;

        // check output purposes
        {
            // StakePool/SpendStakePool inputs not allowed to Transfer
            //
        }

        // check for attempted money printing
        let fee = Some(self.check_transferred_amounts_and_get_fee(tx.transaction())?);

        // check token issuance fee
        self.check_issuance_fee_burn(tx.transaction(), &block_id)?;

        // Register tokens if tx has issuance data
        self.token_issuance_cache.register(block_id, tx.transaction())?;

        // check timelocks of the outputs and make sure there's no premature spending
        self.check_timelocks(tx_source, tx, median_time_past)?;

        // verify input signatures
        self.verify_signatures(tx)?;

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
                        self.storage.get_mainchain_tx_index(tx_id)
                    })?;

                    // mark tx index as spent
                    tx_index_cache
                        .spend_tx_index_inputs(tx.inputs(), tx.transaction().get_id().into())?;
                }
            }
            TransactionSourceForConnect::Mempool { current_best: _ } => { /* do nothing */ }
        };

        Ok(fee)
    }

    fn connect_block_reward(
        &mut self,
        block_index: &BlockIndex,
        reward_transactable: BlockRewardTransactable,
    ) -> Result<(), ConnectTransactionError> {
        // TODO: test spending block rewards from chains outside the mainchain
        if let Some(inputs) = reward_transactable.inputs() {
            // pre-cache all inputs
            if let Some(tx_index_cache) = self.tx_index_cache.as_mut() {
                tx_index_cache.precache_inputs(inputs, |tx_id: &OutPointSourceId| {
                    self.storage.get_mainchain_tx_index(tx_id)
                })?;
            }

            // verify input signatures
            self.verify_signatures(&reward_transactable)?;
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

        if let (Some(inputs), Some(tx_index_cache)) =
            (reward_transactable.inputs(), self.tx_index_cache.as_mut())
        {
            // mark tx index as spend
            tx_index_cache.spend_tx_index_inputs(inputs, block_id.into())?;
        }

        Ok(())
    }

    pub fn connect_transactable(
        &mut self,
        block_index: &BlockIndex,
        spend_ref: BlockTransactableWithIndexRef,
        median_time_past: &BlockTimestamp,
    ) -> Result<Option<Fee>, ConnectTransactionError> {
        let fee = match spend_ref {
            BlockTransactableWithIndexRef::Transaction(block, tx_num, ref _tx_index) => {
                let block_id = block.get_id();
                let tx = block.transactions().get(tx_num).ok_or(
                    ConnectTransactionError::TxNumWrongInBlockOnConnect(tx_num, block_id),
                )?;

                self.connect_transaction(
                    &TransactionSourceForConnect::Chain {
                        new_block_index: block_index,
                    },
                    tx,
                    median_time_past,
                )?
            }
            BlockTransactableWithIndexRef::BlockReward(block, _) => {
                self.connect_block_reward(block_index, block.block_reward_transactable())?;
                None
            }
        };
        // add tx index to the cache
        if let Some(tx_index_cache) = self.tx_index_cache.as_mut() {
            tx_index_cache.add_tx_index(
                spend_ref.without_tx_index(),
                spend_ref.take_tx_index().expect("Guaranteed by verifier_config"),
            )?;
        }

        Ok(fee)
    }

    pub fn can_disconnect_transaction(
        &self,
        tx_source: &TransactionSource,
        tx_id: &Id<Transaction>,
    ) -> Result<bool, ConnectTransactionError> {
        let block_undo_fetcher = |id: Id<Block>| self.storage.get_undo_data(id);
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
        let block_undo_fetcher = |id: Id<Block>| self.storage.get_undo_data(id);
        let tx_undo = self.utxo_block_undo.take_tx_undo(
            tx_source,
            &tx.transaction().get_id(),
            block_undo_fetcher,
        )?;

        match tx_source {
            TransactionSource::Chain(_) => {
                let tx_index_fetcher =
                    |tx_id: &OutPointSourceId| self.storage.get_mainchain_tx_index(tx_id);
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
        self.token_issuance_cache
            .precache_token_issuance(|id| self.storage.get_token_aux_data(id), tx.transaction())?;

        // Remove issued tokens
        self.token_issuance_cache.unregister(tx.transaction())?;

        Ok(())
    }

    pub fn disconnect_transactable(
        &mut self,
        spend_ref: BlockTransactableRef,
    ) -> Result<(), ConnectTransactionError> {
        if let Some(tx_index_cache) = self.tx_index_cache.as_mut() {
            // Delete TxMainChainIndex for the current tx
            tx_index_cache.remove_tx_index(spend_ref)?;
        }

        match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let block_id = block.get_id();
                let tx = block.transactions().get(tx_num).ok_or(
                    ConnectTransactionError::TxNumWrongInBlockOnDisconnect(tx_num, block_id),
                )?;
                self.disconnect_transaction(&TransactionSource::Chain(block_id), tx)?;
            }
            BlockTransactableRef::BlockReward(block) => {
                let reward_transactable = block.block_reward_transactable();

                let block_undo_fetcher = |id: Id<Block>| self.storage.get_undo_data(id);
                let reward_undo = self.utxo_block_undo.take_block_reward_undo(
                    &TransactionSource::Chain(block.get_id()),
                    block_undo_fetcher,
                )?;
                self.utxo_cache.disconnect_block_transactable(
                    &reward_transactable,
                    &block.get_id().into(),
                    reward_undo,
                )?;

                let tx_index_fetcher =
                    |tx_id: &OutPointSourceId| self.storage.get_mainchain_tx_index(tx_id);

                if let (Some(inputs), Some(tx_index_cache)) =
                    (reward_transactable.inputs(), self.tx_index_cache.as_mut())
                {
                    // pre-cache all inputs
                    tx_index_cache.precache_inputs(inputs, tx_index_fetcher)?;

                    // unspend inputs
                    tx_index_cache.unspend_tx_index_inputs(inputs)?;
                }
            }
        }

        Ok(())
    }

    pub fn set_best_block(&mut self, id: Id<GenBlock>) {
        self.utxo_cache.set_best_block(id);
    }

    pub fn consume(self) -> Result<TransactionVerifierDelta, ConnectTransactionError> {
        Ok(TransactionVerifierDelta {
            tx_index_cache: self.tx_index_cache.take_always().consume(),
            utxo_cache: self.utxo_cache.consume(),
            utxo_block_undo: self.utxo_block_undo.consume(),
            token_issuance_cache: self.token_issuance_cache.consume(),
            accounting_delta: self.accounting_delta.consume(),
            accounting_delta_undo: self.accounting_block_undo.consume(),
            accounting_block_deltas: self.accounting_block_deltas,
        })
    }
}

#[cfg(test)]
mod tests;

// TODO: write tests for block rewards
// TODO: test that total_block_reward = total_tx_fees + consensus_block_reward
