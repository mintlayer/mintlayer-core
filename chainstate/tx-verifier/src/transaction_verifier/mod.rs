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

mod amounts_map;
mod cached_operation;
pub mod error;
pub mod flush;
pub mod hierarchy;
pub mod storage;
mod tx_index_cache;
use self::{
    amounts_map::AmountsMap,
    error::{ConnectTransactionError, TokensError},
    storage::TransactionVerifierStorageRef,
    token_issuance_cache::{CoinOrTokenId, ConsumedTokenIssuanceCache},
    tx_index_cache::TxIndexCache,
    utils::get_output_token_id_and_amount,
};
use ::utils::ensure;
use cached_operation::CachedInputsOperation;
use fallible_iterator::FallibleIterator;

use std::collections::{btree_map::Entry, BTreeMap};

use chainstate_types::{block_index_ancestor_getter, BlockIndex, GenBlockIndex};
use common::{
    amount_sum,
    chain::{
        block::{timestamp::BlockTimestamp, BlockRewardTransactable},
        signature::{verify_signature, Signable, Transactable},
        signed_transaction::SignedTransaction,
        tokens::{get_tokens_issuance_count, OutputValue, TokenId},
        Block, ChainConfig, GenBlock, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{id::WithId, Amount, BlockDistance, BlockHeight, Id, Idable, H256},
};
use utxo::{
    BlockRewardUndo, BlockUndo, ConsumedUtxoCache, TxUndo, Utxo, UtxosCache, UtxosDB, UtxosView,
};

mod token_issuance_cache;
use self::token_issuance_cache::TokenIssuanceCache;

mod utils;
use self::utils::{check_transferred_amount, get_input_token_id_and_amount};

// TODO: We can move it to mod common, because in chain config we have `token_min_issuance_fee`
//       that essentially belongs to this type, but return Amount
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Fee(pub Amount);

pub struct Subsidy(pub Amount);

#[derive(Debug, Eq, PartialEq)]
pub struct BlockUndoEntry {
    undo: BlockUndo,
    // indicates whether this BlockUndo was fetched from the db or it's new
    is_fresh: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CachedOperation<T> {
    Write(T),
    Read(T),
    Erase,
}

/// A BlockTransactableRef is a reference to an operation in a block that causes inputs to be spent, outputs to be created, or both
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BlockTransactableRef<'a> {
    Transaction(&'a WithId<Block>, usize),
    BlockReward(&'a WithId<Block>),
}

pub enum TransactionSource {
    Chain { new_block_index: BlockIndex },
    Mempool { current_best: BlockIndex },
}

impl TransactionSource {
    /// The block height of the transaction to be connected
    /// For the mempool, it's the height of the next-to-be block
    /// For the chain, it's for the block being connected
    pub fn expected_block_height(&self) -> BlockHeight {
        match self {
            TransactionSource::Chain { new_block_index } => new_block_index.block_height(),
            TransactionSource::Mempool {
                current_best: best_block_index,
            } => best_block_index.block_height().next_height(),
        }
    }

    pub fn chain_block_index(&self) -> Option<&BlockIndex> {
        match self {
            TransactionSource::Chain { new_block_index } => Some(new_block_index),
            TransactionSource::Mempool { current_best: _ } => None,
        }
    }
}

/// The change that a block has caused to the blockchain state
#[derive(Debug, Eq, PartialEq)]
pub struct TransactionVerifierDelta {
    tx_index_cache: BTreeMap<OutPointSourceId, CachedInputsOperation>,
    utxo_cache: ConsumedUtxoCache,
    utxo_block_undo: BTreeMap<Id<Block>, BlockUndoEntry>,
    token_issuance_cache: ConsumedTokenIssuanceCache,
}

/// The tool used to verify transaction and cache their updated states in memory
pub struct TransactionVerifier<'a, S> {
    chain_config: &'a ChainConfig,
    storage_ref: &'a S,
    tx_index_cache: TxIndexCache,
    utxo_cache: UtxosCache<'a>,
    utxo_block_undo: BTreeMap<Id<Block>, BlockUndoEntry>,
    token_issuance_cache: TokenIssuanceCache,
    best_block: Id<GenBlock>,
}

impl<'a, S: TransactionVerifierStorageRef> TransactionVerifier<'a, S> {
    pub fn new(storage_ref: &'a S, chain_config: &'a ChainConfig) -> Self {
        Self {
            storage_ref,
            chain_config,
            tx_index_cache: TxIndexCache::new(),
            utxo_cache: UtxosCache::from_owned_parent(Box::new(UtxosDB::new(storage_ref))),
            utxo_block_undo: BTreeMap::new(),
            token_issuance_cache: TokenIssuanceCache::new(),
            best_block: storage_ref
                .get_best_block_for_utxos()
                .expect("Database error while reading utxos best block")
                .expect("best block should be some"),
        }
    }

    pub fn derive_child(&'a self) -> TransactionVerifier<'a, Self> {
        TransactionVerifier {
            storage_ref: self,
            chain_config: self.chain_config,
            tx_index_cache: TxIndexCache::new(),
            utxo_cache: self.utxo_cache.derive_cache(),
            utxo_block_undo: BTreeMap::new(),
            token_issuance_cache: TokenIssuanceCache::new(),
            best_block: self.best_block,
        }
    }

    fn calculate_total_outputs(
        outputs: &[TxOutput],
        include_issuance: Option<&Transaction>,
    ) -> Result<BTreeMap<CoinOrTokenId, Amount>, ConnectTransactionError> {
        let iter = outputs
            .iter()
            .map(|output| get_output_token_id_and_amount(output.value(), include_issuance));
        let iter = fallible_iterator::convert(iter).filter_map(Ok).map_err(Into::into);

        let result = AmountsMap::from_fallible_iter(iter)?;
        Ok(result.take())
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

    fn get_total_fee(
        inputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
        outputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
    ) -> Result<Fee, ConnectTransactionError> {
        // TODO: fees should support tokens as well in the future
        let outputs_total =
            *outputs_total_map.get(&CoinOrTokenId::Coin).unwrap_or(&Amount::from_atoms(0));
        let inputs_total =
            *inputs_total_map.get(&CoinOrTokenId::Coin).unwrap_or(&Amount::from_atoms(0));
        (inputs_total - outputs_total).map(Fee).ok_or(
            ConnectTransactionError::TxFeeTotalCalcFailed(inputs_total, outputs_total),
        )
    }

    fn check_transferred_amounts_and_get_fee(
        &self,
        block_id: Option<Id<Block>>,
        tx: &Transaction,
    ) -> Result<Fee, ConnectTransactionError> {
        let inputs_total_map = self.calculate_total_inputs(tx.inputs())?;
        let outputs_total_map = Self::calculate_total_outputs(tx.outputs(), None)?;

        check_transferred_amount(&inputs_total_map, &outputs_total_map)?;
        let total_fee = Self::get_total_fee(&inputs_total_map, &outputs_total_map)?;

        // TODO: the fee has the issue that it doesn't deduct the issuance fee from the total fee,
        // which means that anyone issuing tokens will have a free-of-charge priority and a possibly
        // huge transaction compared to what they would get for without the issuance.
        // This has to be studied

        // Check if the fee is enough for issuance
        let issuance_count = get_tokens_issuance_count(tx.outputs());
        if issuance_count > 0 && total_fee < Fee(self.chain_config.token_min_issuance_fee()) {
            return Err(ConnectTransactionError::TokensError(
                TokensError::InsufficientTokenFees(
                    tx.get_id(),
                    block_id.unwrap_or_else(|| H256::zero().into()),
                ),
            ));
        }
        Ok(total_fee)
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
                Ok(Self::calculate_total_outputs(outputs, None)?
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
        use common::chain::OutputPurpose;

        let timelock = match output.purpose() {
            OutputPurpose::Transfer(_) => return Ok(()),
            OutputPurpose::LockThenTransfer(_, tl) => tl,
            OutputPurpose::StakeLock(_) => return Ok(()),
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
            verify_signature(utxo.output().purpose().destination(), tx, input_idx)
                .map_err(ConnectTransactionError::SignatureVerificationFailed)?;
        }

        Ok(())
    }

    fn check_timelocks<T: Transactable>(
        &self,
        tx_source: &TransactionSource,
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

            // TODO: See if we can check timelocks for the current block without needing the block index.
            //       The problem is that it won't be possible to use tx_verifier without the block index history
            //       if this is not restricted with the 'if' condition. But the side effect is that all
            //       timelock txs be rejected if they spend outputs from the same block.
            if utxo.output().has_timelock() {
                let height = match utxo.source() {
                    utxo::UtxoSource::Blockchain(h) => h,
                    utxo::UtxoSource::Mempool => {
                        unreachable!("Mempool utxos can never be reached from storage")
                    }
                };

                let block_index_getter =
                    |db_tx: &S, _chain_config: &ChainConfig, id: &Id<GenBlock>| {
                        db_tx.get_gen_block_index(id)
                    };

                let starting_point = match tx_source {
                    TransactionSource::Chain { new_block_index } => new_block_index,
                    TransactionSource::Mempool { current_best } => current_best,
                };

                let source_block_index = block_index_ancestor_getter(
                    block_index_getter,
                    self.storage_ref,
                    self.chain_config,
                    (&starting_point.clone().into_gen_block_index()).into(),
                    *height,
                )
                .map_err(|e| {
                    ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(
                        e, *height,
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

    fn fetch_block_undo(
        &mut self,
        block_id: &Id<Block>,
    ) -> Result<&mut BlockUndo, ConnectTransactionError> {
        match self.utxo_block_undo.entry(*block_id) {
            Entry::Occupied(entry) => Ok(&mut entry.into_mut().undo),
            Entry::Vacant(entry) => {
                let block_undo = self
                    .storage_ref
                    .get_undo_data(*block_id)?
                    .ok_or(ConnectTransactionError::MissingBlockUndo(*block_id))?;
                Ok(&mut entry
                    .insert(BlockUndoEntry {
                        undo: block_undo,
                        is_fresh: false,
                    })
                    .undo)
            }
        }
    }

    fn take_tx_undo(
        &mut self,
        block_id: &Id<Block>,
        tx_num: usize,
    ) -> Result<TxUndo, ConnectTransactionError> {
        let block_undo = self.fetch_block_undo(block_id)?;
        debug_assert_eq!(
            block_undo.tx_undos().len(),
            tx_num + 1,
            "only the last tx undo can be taken"
        );
        block_undo
            .pop_tx_undo()
            .ok_or(ConnectTransactionError::MissingTxUndo(tx_num, *block_id))
    }

    fn take_block_reward_undo(
        &mut self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockRewardUndo>, ConnectTransactionError> {
        Ok(self.fetch_block_undo(block_id)?.take_block_reward_undo())
    }

    fn get_or_create_block_undo(&mut self, block_id: &Id<Block>) -> &mut BlockUndo {
        &mut self
            .utxo_block_undo
            .entry(*block_id)
            .or_insert(BlockUndoEntry {
                is_fresh: true,
                undo: Default::default(),
            })
            .undo
    }

    pub fn connect_transaction(
        &mut self,
        tx_source: &TransactionSource,
        tx: &SignedTransaction,
        median_time_past: &BlockTimestamp,
    ) -> Result<Option<Fee>, ConnectTransactionError> {
        let tx_index_fetcher =
            |tx_id: &OutPointSourceId| self.storage_ref.get_mainchain_tx_index(tx_id);

        let block_id = tx_source.chain_block_index().map(|c| *c.block_id());

        // pre-cache all inputs
        self.tx_index_cache.precache_inputs(tx.inputs(), tx_index_fetcher)?;

        // pre-cache token ids to check ensure it's not in the db when issuing
        self.token_issuance_cache.precache_token_issuance(
            |id| self.storage_ref.get_token_aux_data(id),
            tx.transaction(),
        )?;

        // check for attempted money printing
        let fee = Some(self.check_transferred_amounts_and_get_fee(block_id, tx.transaction())?);

        // Register tokens if tx has issuance data
        self.token_issuance_cache.register(block_id, tx.transaction())?;

        // check timelocks of the outputs and make sure there's no premature spending
        self.check_timelocks(tx_source, tx, median_time_past)?;

        // verify input signatures
        self.verify_signatures(tx)?;

        // spend utxos
        let tx_undo = self
            .utxo_cache
            .connect_transaction(tx.transaction(), tx_source.expected_block_height())
            .map_err(ConnectTransactionError::from)?;

        // save spent utxos for undo
        if let Some(id) = block_id {
            self.get_or_create_block_undo(&id).push_tx_undo(tx_undo);
        }

        // mark tx index as spent
        let spender = tx.transaction().get_id().into();
        self.tx_index_cache.spend_tx_index_inputs(tx.inputs(), spender)?;

        Ok(fee)
    }

    pub fn connect_block_reward(
        &mut self,
        block_index: &BlockIndex,
        reward_transactable: BlockRewardTransactable,
    ) -> Result<(), ConnectTransactionError> {
        let tx_index_fetcher =
            |tx_id: &OutPointSourceId| self.storage_ref.get_mainchain_tx_index(tx_id);

        // TODO: test spending block rewards from chains outside the mainchain
        if let Some(inputs) = reward_transactable.inputs() {
            // pre-cache all inputs
            self.tx_index_cache.precache_inputs(inputs, tx_index_fetcher)?;

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
            self.get_or_create_block_undo(&block_id).set_block_reward_undo(reward_undo);
        }

        if let Some(inputs) = reward_transactable.inputs() {
            // mark tx index as spend
            self.tx_index_cache.spend_tx_index_inputs(inputs, block_id.into())?;
        }

        Ok(())
    }

    pub fn connect_transactable(
        &mut self,
        block_index: &BlockIndex,
        spend_ref: BlockTransactableRef,
        median_time_past: &BlockTimestamp,
    ) -> Result<Option<Fee>, ConnectTransactionError> {
        let fee = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let block_id = block.get_id();
                let tx = block.transactions().get(tx_num).ok_or(
                    ConnectTransactionError::TxNumWrongInBlockOnConnect(tx_num, block_id),
                )?;

                self.connect_transaction(
                    &TransactionSource::Chain {
                        // TODO: get rid of this clone
                        new_block_index: block_index.clone(),
                    },
                    tx,
                    median_time_past,
                )?
            }
            BlockTransactableRef::BlockReward(block) => {
                self.connect_block_reward(block_index, block.block_reward_transactable())?;
                None
            }
        };
        // add tx index to the cache
        self.tx_index_cache.add_tx_index(spend_ref)?;

        Ok(fee)
    }

    pub fn disconnect_transactable(
        &mut self,
        spend_ref: BlockTransactableRef,
    ) -> Result<(), ConnectTransactionError> {
        // Delete TxMainChainIndex for the current tx
        self.tx_index_cache.remove_tx_index(spend_ref)?;

        let tx_index_fetcher =
            |tx_id: &OutPointSourceId| self.storage_ref.get_mainchain_tx_index(tx_id);

        match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let block_id = block.get_id();
                let tx = block.transactions().get(tx_num).ok_or(
                    ConnectTransactionError::TxNumWrongInBlockOnDisconnect(tx_num, block_id),
                )?;

                let tx_undo = self.take_tx_undo(&block_id, tx_num)?;
                self.utxo_cache.disconnect_transaction(tx.transaction(), tx_undo)?;

                // pre-cache all inputs
                self.tx_index_cache.precache_inputs(tx.inputs(), tx_index_fetcher)?;

                // pre-cache token ids before removing them
                self.token_issuance_cache.precache_token_issuance(
                    |id| self.storage_ref.get_token_aux_data(id),
                    tx.transaction(),
                )?;

                // unspend inputs
                self.tx_index_cache.unspend_tx_index_inputs(tx.inputs())?;

                // Remove issued tokens
                self.token_issuance_cache.unregister(tx.transaction())?;
            }
            BlockTransactableRef::BlockReward(block) => {
                let reward_transactable = block.block_reward_transactable();

                let reward_undo = self.take_block_reward_undo(&block.get_id())?;
                self.utxo_cache.disconnect_block_transactable(
                    &reward_transactable,
                    &block.get_id().into(),
                    reward_undo,
                )?;

                if let Some(inputs) = reward_transactable.inputs() {
                    // pre-cache all inputs
                    self.tx_index_cache.precache_inputs(inputs, tx_index_fetcher)?;

                    // unspend inputs
                    self.tx_index_cache.unspend_tx_index_inputs(inputs)?;
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
            tx_index_cache: self.tx_index_cache.consume(),
            utxo_cache: self.utxo_cache.consume(),
            utxo_block_undo: self.utxo_block_undo,
            token_issuance_cache: self.token_issuance_cache.consume(),
        })
    }
}

#[cfg(test)]
mod tests;

// TODO: write tests for CachedInputs that covers all possible mutations
// TODO: write tests for block rewards
// TODO: test attempting to spend the block reward at the same block
// TODO: test that total_block_reward = total_tx_fees + consensus_block_reward
