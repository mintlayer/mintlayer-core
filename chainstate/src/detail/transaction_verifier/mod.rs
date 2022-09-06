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

pub mod error;

mod cached_operation;
use cached_operation::CachedInputsOperation;

use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
};

use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use chainstate_types::GenBlockIndex;
use common::{
    amount_sum,
    chain::{
        block::timestamp::BlockTimestamp,
        calculate_tx_index_from_block,
        signature::{verify_signature, Transactable},
        tokens::OutputValue,
        Block, ChainConfig, GenBlock, GenBlockId, OutPoint, OutPointSourceId, SpendablePosition,
        Spender, Transaction, TxInput, TxMainChainIndex, TxOutput,
    },
    primitives::{id::WithId, Amount, BlockDistance, BlockHeight, Id, Idable},
};
use utils::ensure;
use utxo::{
    BlockRewardUndo, BlockUndo, ConsumedUtxoCache, FlushableUtxoView, TxUndo, UtxosCache,
    UtxosDBMut, UtxosView,
};

use self::error::ConnectTransactionError;

pub struct Fee(pub Amount);
pub struct Subsidy(pub Amount);

struct BlockUndoEntry {
    undo: BlockUndo,
    // indicates whether this BlockUndo was fetched from the db or it's new
    is_fresh: bool,
}

/// A BlockTransactableRef is a reference to an operation in a block that causes inputs to be spent, outputs to be created, or both
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BlockTransactableRef<'a> {
    Transaction(&'a WithId<Block>, usize),
    BlockReward(&'a WithId<Block>),
}

/// The change that a block has caused to the blockchain state
pub struct TransactionVerifierDelta {
    tx_index: BTreeMap<OutPointSourceId, CachedInputsOperation>,
    utxo_cache: ConsumedUtxoCache,
    utxo_block_undo: BTreeMap<Id<Block>, BlockUndoEntry>,
}

/// The tool used to verify transaction and cache their updated states in memory
pub struct TransactionVerifier<'a, S> {
    db_tx: &'a S,
    tx_index_cache: BTreeMap<OutPointSourceId, CachedInputsOperation>,
    utxo_cache: UtxosCache<'a>,
    utxo_block_undo: BTreeMap<Id<Block>, BlockUndoEntry>,
    chain_config: &'a ChainConfig,
}

// TODO: UtxoDB should be a member of TransactionVerifier and UtxoCache should be constructed from it.
// Investigate how to solve borrows checker lifetime issues with that approach.
impl<'a, S> TransactionVerifier<'a, S> {
    pub fn new(db_tx: &'a S, utxo_cache: UtxosCache<'a>, chain_config: &'a ChainConfig) -> Self {
        Self {
            db_tx,
            chain_config,
            tx_index_cache: BTreeMap::new(),
            utxo_cache,
            utxo_block_undo: BTreeMap::new(),
        }
    }
}

impl<'a, S: BlockchainStorageRead> TransactionVerifier<'a, S> {
    fn outpoint_source_id_from_spend_ref(
        spend_ref: BlockTransactableRef,
    ) -> Result<OutPointSourceId, ConnectTransactionError> {
        let outpoint_source_id = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let tx = block.transactions().get(tx_num).ok_or_else(|| {
                    ConnectTransactionError::InvariantErrorTxNumWrongInBlock(tx_num, block.get_id())
                })?;
                let tx_id = tx.get_id();
                OutPointSourceId::from(tx_id)
            }
            BlockTransactableRef::BlockReward(block) => OutPointSourceId::from(block.get_id()),
        };
        Ok(outpoint_source_id)
    }

    fn add_tx_index(
        &mut self,
        spend_ref: BlockTransactableRef,
    ) -> Result<(), ConnectTransactionError> {
        let tx_index = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                CachedInputsOperation::Write(calculate_tx_index_from_block(block, tx_num)?)
            }
            BlockTransactableRef::BlockReward(block) => {
                match block.block_reward_transactable().outputs() {
                    Some(outputs) => CachedInputsOperation::Write(TxMainChainIndex::new(
                        block.get_id().into(),
                        outputs
                            .len()
                            .try_into()
                            .map_err(|_| ConnectTransactionError::InvalidOutputCount)?,
                    )?),
                    None => return Ok(()), // no outputs to add
                }
            }
        };

        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(spend_ref)?;

        match self.tx_index_cache.entry(outpoint_source_id) {
            Entry::Occupied(_) => {
                return Err(ConnectTransactionError::OutputAlreadyPresentInInputsCache)
            }
            Entry::Vacant(entry) => entry.insert(tx_index),
        };
        Ok(())
    }

    pub fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ConnectTransactionError> {
        match block_id.classify(self.chain_config) {
            GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
                self.chain_config.genesis_block(),
            )))),
            GenBlockId::Block(id) => self
                .db_tx
                .get_block_index(&id)
                .map(|b| b.map(GenBlockIndex::Block))
                .map_err(ConnectTransactionError::from),
        }
    }

    fn remove_tx_index(
        &mut self,
        spend_ref: BlockTransactableRef,
    ) -> Result<(), ConnectTransactionError> {
        let tx_index = CachedInputsOperation::Erase;
        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(spend_ref)?;

        self.tx_index_cache.insert(outpoint_source_id, tx_index);
        Ok(())
    }

    fn get_from_cached_mut(
        &mut self,
        outpoint: &OutPoint,
    ) -> Result<&mut CachedInputsOperation, ConnectTransactionError> {
        let result = match self.tx_index_cache.get_mut(&outpoint.tx_id()) {
            Some(tx_index) => tx_index,
            None => return Err(ConnectTransactionError::PreviouslyCachedInputNotFound),
        };
        Ok(result)
    }

    fn get_tx_index(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<&TxMainChainIndex>, ConnectTransactionError> {
        let result = match self.tx_index_cache.get(&outpoint.tx_id()) {
            Some(tx_index) => tx_index.get_tx_index(),
            None => return Err(ConnectTransactionError::PreviouslyCachedInputNotFound),
        };
        Ok(result)
    }

    fn fetch_and_cache(&mut self, outpoint: &OutPoint) -> Result<(), ConnectTransactionError> {
        match self.tx_index_cache.entry(outpoint.tx_id()) {
            Entry::Occupied(_) => (),
            Entry::Vacant(entry) => {
                // Maybe the utxo is in a previous block?
                let tx_index = self
                    .db_tx
                    .get_mainchain_tx_index(&outpoint.tx_id())?
                    .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
                entry.insert(CachedInputsOperation::Read(tx_index));
            }
        }
        Ok(())
    }

    fn check_transferred_amounts_and_get_fee(
        &self,
        tx: &Transaction,
    ) -> Result<Fee, ConnectTransactionError> {
        let inputs = tx.inputs();
        let outputs = tx.outputs();

        let inputs_total = self.calculate_coins_total_inputs(inputs)?;
        let outputs_total = Self::calculate_coins_total_outputs(outputs)?;

        if outputs_total > inputs_total {
            return Err(ConnectTransactionError::AttemptToPrintMoney(
                inputs_total,
                outputs_total,
            ));
        }

        let paid_fee = inputs_total - outputs_total;
        paid_fee.map(Fee).ok_or(ConnectTransactionError::TxFeeTotalCalcFailed(
            inputs_total,
            outputs_total,
        ))
    }

    fn calculate_coins_total_inputs(
        &self,
        inputs: &[TxInput],
    ) -> Result<Amount, ConnectTransactionError> {
        inputs.iter().try_fold(Amount::from_atoms(0), |total, input| {
            let amount = self
                .utxo_cache
                .utxo(input.outpoint())
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)
                .map(|utxo| match utxo.output().value() {
                    OutputValue::Coin(amount) => *amount,
                })?;
            (total + amount).ok_or(ConnectTransactionError::OutputAdditionError)
        })
    }

    fn calculate_coins_total_outputs(
        outputs: &[TxOutput],
    ) -> Result<Amount, ConnectTransactionError> {
        outputs
            .iter()
            .map(|output| match output.value() {
                OutputValue::Coin(coin) => *coin,
            })
            .try_fold(Amount::from_atoms(0), |accum, out| accum + out)
            .ok_or(ConnectTransactionError::OutputAdditionError)
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
            || Ok(Amount::from_atoms(0)),
            |ins| self.calculate_coins_total_inputs(ins),
        )?;
        let outputs_total = outputs.map_or_else(
            || Ok(Amount::from_atoms(0)),
            Self::calculate_coins_total_outputs,
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
            OutputTimeLock::UntilHeight(h) => (spend_height >= h),
            OutputTimeLock::UntilTime(t) => (spending_time >= t),
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

    fn verify_signatures<T: Transactable>(
        &self,
        tx: &T,
        spend_height: &BlockHeight,
        spending_time: &BlockTimestamp,
    ) -> Result<(), ConnectTransactionError> {
        let inputs = match tx.inputs() {
            Some(ins) => ins,
            None => return Ok(()),
        };

        for (input_idx, input) in inputs.iter().enumerate() {
            let outpoint = input.outpoint();
            let tx_index = self
                .get_tx_index(outpoint)?
                .ok_or(ConnectTransactionError::PreviouslyCachedInputNotFound)?;

            match tx_index.position() {
                SpendablePosition::Transaction(tx_pos) => {
                    let prev_tx = self
                        .db_tx
                        .get_mainchain_tx_by_position(tx_pos)
                        .map_err(ConnectTransactionError::from)?
                        .ok_or_else(|| {
                            ConnectTransactionError::InvariantErrorTransactionCouldNotBeLoaded(
                                tx_pos.clone(),
                            )
                        })?;

                    let output = prev_tx
                        .outputs()
                        .get(input.outpoint().output_index() as usize)
                        .ok_or(ConnectTransactionError::OutputIndexOutOfRange {
                            tx_id: None,
                            source_output_index: outpoint.output_index() as usize,
                        })?;

                    // TODO: see if a different treatment should be done for different output purposes

                    {
                        let block_index = self
                            .db_tx
                            .get_block_index(tx_pos.block_id())
                            .map_err(ConnectTransactionError::from)?
                            .ok_or_else(|| {
                                ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoaded(
                                    *tx_pos.block_id(),
                                )
                            })?;
                        self.check_timelock(
                            &GenBlockIndex::Block(block_index),
                            output,
                            spend_height,
                            spending_time,
                        )?;
                    }

                    verify_signature(output.purpose().destination(), tx, input_idx)
                        .map_err(|_| ConnectTransactionError::SignatureVerificationFailed)?;
                }
                SpendablePosition::BlockReward(block_id) => {
                    let block_index = self.get_gen_block_index(block_id)?.ok_or_else(|| {
                        // TODO get rid of the coercion
                        let block_id = Id::new(block_id.get());
                        ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoaded(block_id)
                    })?;

                    let outputs = self.block_reward_outputs(block_id)?;
                    let output = outputs.get(input.outpoint().output_index() as usize).ok_or(
                        ConnectTransactionError::OutputIndexOutOfRange {
                            tx_id: None,
                            source_output_index: outpoint.output_index() as usize,
                        },
                    )?;

                    // TODO: see if a different treatment should be done for different output purposes

                    self.check_timelock(&block_index, output, spend_height, spending_time)?;

                    verify_signature(output.purpose().destination(), tx, input_idx)
                        .map_err(|_| ConnectTransactionError::SignatureVerificationFailed)?;
                }
            };
        }

        Ok(())
    }

    fn spend_tx_index(
        &mut self,
        inputs: &[TxInput],
        spender: Spender,
    ) -> Result<(), ConnectTransactionError> {
        for input in inputs {
            let outpoint = input.outpoint();
            let prev_tx_index_op = self.get_from_cached_mut(outpoint)?;
            prev_tx_index_op
                .spend(outpoint.output_index(), spender.clone())
                .map_err(ConnectTransactionError::from)?;
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
                    .db_tx
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

    pub fn connect_transactable(
        &mut self,
        spend_ref: BlockTransactableRef,
        spend_height: &BlockHeight,
        median_time_past: &BlockTimestamp,
    ) -> Result<Option<Fee>, ConnectTransactionError> {
        let fee = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let block_id = block.get_id();
                let tx = block.transactions().get(tx_num).ok_or(
                    ConnectTransactionError::TxNumWrongInBlockOnConnect(tx_num, block_id),
                )?;

                // pre-cache all inputs
                self.precache_inputs(tx.inputs())?;

                // check for attempted money printing
                let fee = Some(self.check_transferred_amounts_and_get_fee(tx)?);

                // verify input signatures
                self.verify_signatures(tx, spend_height, median_time_past)?;

                //spend utxos
                let tx_undo = self
                    .utxo_cache
                    .connect_transaction(tx, *spend_height)
                    .map_err(ConnectTransactionError::from)?;

                // save spent utxos for undo
                self.get_or_create_block_undo(&block_id).push_tx_undo(tx_undo);

                // mark tx index as spent
                let spender = tx.get_id().into();
                self.spend_tx_index(tx.inputs(), spender)?;

                fee
            }
            BlockTransactableRef::BlockReward(block) => {
                let reward_transactable = block.block_reward_transactable();
                // TODO: test spending block rewards from chains outside the mainchain
                if let Some(inputs) = reward_transactable.inputs() {
                    // pre-cache all inputs
                    self.precache_inputs(inputs)?;

                    // verify input signatures
                    self.verify_signatures(&reward_transactable, spend_height, median_time_past)?;
                }

                let fee = None;

                // spend inputs of the block reward
                // if block reward has no inputs then only outputs will be added to the utxo set
                let reward_undo = self
                    .utxo_cache
                    .connect_block_transactable(
                        &reward_transactable,
                        &block.get_id().into(),
                        *spend_height,
                    )
                    .map_err(ConnectTransactionError::from)?;

                if let Some(reward_undo) = reward_undo {
                    // save spent utxos for undo
                    self.get_or_create_block_undo(&block.get_id())
                        .set_block_reward_undo(reward_undo);
                }

                if let Some(inputs) = reward_transactable.inputs() {
                    // mark tx index as spend
                    self.spend_tx_index(inputs, block.get_id().into())?;
                }

                fee
            }
        };
        // add tx index to the cache
        self.add_tx_index(spend_ref)?;

        Ok(fee)
    }

    pub fn disconnect_transactable(
        &mut self,
        spend_ref: BlockTransactableRef,
    ) -> Result<(), ConnectTransactionError> {
        // Delete TxMainChainIndex for the current tx
        self.remove_tx_index(spend_ref)?;

        match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let block_id = block.get_id();
                let tx = block.transactions().get(tx_num).ok_or(
                    ConnectTransactionError::TxNumWrongInBlockOnDisconnect(tx_num, block_id),
                )?;

                let tx_undo = self.take_tx_undo(&block_id, tx_num)?;
                self.utxo_cache.disconnect_transaction(tx, tx_undo)?;

                // pre-cache all inputs
                self.precache_inputs(tx.inputs())?;

                // unspend inputs
                for input in tx.inputs() {
                    let outpoint = input.outpoint();

                    // mark tx index as unspend
                    let input_tx_id_op = self.get_from_cached_mut(outpoint)?;
                    input_tx_id_op
                        .unspend(outpoint.output_index())
                        .map_err(ConnectTransactionError::from)?;
                }
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
                    self.precache_inputs(inputs)?;

                    // unspend inputs
                    for input in inputs {
                        let outpoint = input.outpoint();

                        // mark tx index as unspend
                        let input_tx_id_op = self.get_from_cached_mut(outpoint)?;
                        input_tx_id_op
                            .unspend(outpoint.output_index())
                            .map_err(ConnectTransactionError::from)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn precache_inputs(&mut self, inputs: &[TxInput]) -> Result<(), ConnectTransactionError> {
        inputs.iter().try_for_each(|input| self.fetch_and_cache(input.outpoint()))
    }

    fn block_reward_outputs(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Vec<TxOutput>, ConnectTransactionError> {
        match block_id.classify(self.chain_config) {
            GenBlockId::Genesis(_) => Ok(self
                .chain_config
                .genesis_block()
                .block_reward_transactable()
                .outputs()
                .unwrap_or(&[])
                .to_vec()),
            // TODO: Getting the whole block just for reward outputs isn't optimal. See the
            // https://github.com/mintlayer/mintlayer-core/issues/344 issue for details.
            GenBlockId::Block(id) => {
                let block_index = self
                    .db_tx
                    .get_block_index(&id)?
                    .ok_or(ConnectTransactionError::InvariantErrorBlockIndexCouldNotBeLoaded(id))?;
                let reward = self
                    .db_tx
                    .get_block_reward(&block_index)?
                    .ok_or(ConnectTransactionError::InvariantErrorBlockCouldNotBeLoaded(id))?
                    .outputs()
                    .to_vec();
                Ok(reward)
            }
        }
    }

    pub fn consume(self) -> Result<TransactionVerifierDelta, ConnectTransactionError> {
        Ok(TransactionVerifierDelta {
            tx_index: self.tx_index_cache,
            utxo_cache: self.utxo_cache.consume(),
            utxo_block_undo: self.utxo_block_undo,
        })
    }
}

impl<'a, S: BlockchainStorageWrite> TransactionVerifier<'a, S> {
    pub fn flush_to_storage(
        db_tx: &mut S,
        consumed: TransactionVerifierDelta,
    ) -> Result<(), ConnectTransactionError> {
        // flush tx index
        for (tx_id, tx_index_op) in consumed.tx_index {
            match tx_index_op {
                CachedInputsOperation::Write(ref tx_index) => {
                    db_tx.set_mainchain_tx_index(&tx_id, tx_index)?
                }
                CachedInputsOperation::Read(_) => (),
                CachedInputsOperation::Erase => db_tx.del_mainchain_tx_index(&tx_id)?,
            }
        }

        // flush utxo set
        let mut utxo_db = UtxosDBMut::new(db_tx);
        utxo_db.batch_write(consumed.utxo_cache)?;

        //flush block undo
        for (block_id, entry) in consumed.utxo_block_undo {
            if entry.is_fresh {
                db_tx.set_undo_data(block_id, &entry.undo)?;
            } else {
                db_tx.del_undo_data(block_id)?;
            }
        }

        Ok(())
    }
}

// TODO: write tests for CachedInputs that covers all possible mutations
// TODO: write tests for block rewards
// TODO: test attempting to spend the block reward at the same block
// TODO: test that total_block_reward = total_tx_fees + consensus_block_reward
