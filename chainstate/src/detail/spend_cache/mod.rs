// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach

use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use chainstate_types::block_index::BlockIndex;
use common::amount_sum;
use common::chain::block::timestamp::BlockTimestamp;
use common::chain::signature::{verify_signature, Transactable};
use common::chain::Transaction;
use common::{
    chain::{
        block::Block, calculate_tx_index_from_block, OutPoint, OutPointSourceId, SpendablePosition,
        Spender, TxInput, TxMainChainIndex, TxOutput,
    },
    primitives::{Amount, BlockDistance, BlockHeight, Id, Idable},
};
use std::collections::{btree_map::Entry, BTreeMap};
use std::time::Duration;
use utils::ensure;

mod cached_operation;
use cached_operation::CachedInputsOperation;

use self::error::StateUpdateError;

pub mod error;

/// A BlockTransactableRef is a reference to an operation in a block that causes inputs to be spent, outputs to be created, or both
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BlockTransactableRef<'a> {
    Transaction(&'a Block, usize),
    BlockReward(&'a Block),
}

pub struct ConsumedCachedInputs {
    data: BTreeMap<OutPointSourceId, CachedInputsOperation>,
}

pub struct CachedInputs<'a, S> {
    db_tx: &'a S,
    inputs: BTreeMap<OutPointSourceId, CachedInputsOperation>,
}

impl<'a, S> CachedInputs<'a, S> {
    pub fn new(db_tx: &'a S) -> Self {
        Self {
            db_tx,
            inputs: BTreeMap::new(),
        }
    }
}

impl<'a, S: BlockchainStorageRead> CachedInputs<'a, S> {
    fn outpoint_source_id_from_spend_ref(
        spend_ref: BlockTransactableRef,
    ) -> Result<OutPointSourceId, StateUpdateError> {
        let outpoint_source_id = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let tx = block.transactions().get(tx_num).ok_or_else(|| {
                    StateUpdateError::InvariantErrorTxNumWrongInBlock(tx_num, block.get_id())
                })?;
                let tx_id = tx.get_id();
                OutPointSourceId::from(tx_id)
            }
            BlockTransactableRef::BlockReward(block) => OutPointSourceId::from(block.get_id()),
        };
        Ok(outpoint_source_id)
    }

    fn add_outputs(&mut self, spend_ref: BlockTransactableRef) -> Result<(), StateUpdateError> {
        let tx_index = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                CachedInputsOperation::Write(calculate_tx_index_from_block(block, tx_num)?)
            }
            BlockTransactableRef::BlockReward(block) => {
                match block.header().block_reward_transactable().outputs() {
                    Some(outputs) => CachedInputsOperation::Write(TxMainChainIndex::new(
                        block.get_id().into(),
                        outputs
                            .len()
                            .try_into()
                            .map_err(|_| StateUpdateError::InvalidOutputCount)?,
                    )?),
                    None => return Ok(()), // no outputs to add
                }
            }
        };

        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(spend_ref)?;

        match self.inputs.entry(outpoint_source_id) {
            Entry::Occupied(_) => return Err(StateUpdateError::OutputAlreadyPresentInInputsCache),
            Entry::Vacant(entry) => entry.insert(tx_index),
        };
        Ok(())
    }

    fn remove_outputs(&mut self, spend_ref: BlockTransactableRef) -> Result<(), StateUpdateError> {
        let tx_index = CachedInputsOperation::Erase;
        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(spend_ref)?;

        self.inputs.insert(outpoint_source_id, tx_index);
        Ok(())
    }

    fn check_blockreward_maturity(
        &self,
        spending_block_id: &Id<Block>,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), StateUpdateError> {
        let source_block_index = self.db_tx.get_block_index(spending_block_id)?;
        let source_block_index =
            source_block_index.ok_or(StateUpdateError::InvariantBrokenSourceBlockIndexNotFound)?;
        let source_height = source_block_index.block_height();
        let actual_distance =
            (*spend_height - source_height).ok_or(StateUpdateError::BlockHeightArithmeticError)?;
        if actual_distance < *blockreward_maturity {
            return Err(StateUpdateError::ImmatureBlockRewardSpend);
        }
        Ok(())
    }

    fn get_from_cached_mut(
        &mut self,
        outpoint: &OutPoint,
    ) -> Result<&mut CachedInputsOperation, StateUpdateError> {
        let result = match self.inputs.get_mut(&outpoint.tx_id()) {
            Some(tx_index) => tx_index,
            None => return Err(StateUpdateError::PreviouslyCachedInputNotFound),
        };
        Ok(result)
    }

    fn get_from_cached(
        &self,
        outpoint: &OutPoint,
    ) -> Result<&CachedInputsOperation, StateUpdateError> {
        let result = match self.inputs.get(&outpoint.tx_id()) {
            Some(tx_index) => tx_index,
            None => return Err(StateUpdateError::PreviouslyCachedInputNotFound),
        };
        Ok(result)
    }

    fn fetch_and_cache(&mut self, outpoint: &OutPoint) -> Result<(), StateUpdateError> {
        let _tx_index_op = match self.inputs.entry(outpoint.tx_id()) {
            Entry::Occupied(entry) => {
                // If tx index was loaded
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                // Maybe the utxo is in a previous block?
                let tx_index = self
                    .db_tx
                    .get_mainchain_tx_index(&outpoint.tx_id())?
                    .ok_or(StateUpdateError::MissingOutputOrSpent)?;
                entry.insert(CachedInputsOperation::Read(tx_index))
            }
        };
        Ok(())
    }

    fn get_output_amount(
        outputs: &[TxOutput],
        output_index: usize,
        spender_id: Spender,
    ) -> Result<Amount, StateUpdateError> {
        let output = outputs.get(output_index).ok_or(StateUpdateError::OutputIndexOutOfRange {
            tx_id: Some(spender_id),
            source_output_index: output_index,
        })?;
        Ok(output.value())
    }

    fn calculate_total_inputs(&self, inputs: &[TxInput]) -> Result<Amount, StateUpdateError> {
        let mut total = Amount::from_atoms(0);
        for (_input_idx, input) in inputs.iter().enumerate() {
            let outpoint = input.outpoint();
            let tx_index = match self.inputs.get(&outpoint.tx_id()) {
                Some(tx_index_op) => match tx_index_op {
                    CachedInputsOperation::Write(tx_index) => tx_index,
                    CachedInputsOperation::Read(tx_index) => tx_index,
                    CachedInputsOperation::Erase => {
                        return Err(StateUpdateError::PreviouslyCachedInputWasErased)
                    }
                },
                None => return Err(StateUpdateError::PreviouslyCachedInputNotFound),
            };
            let output_index = outpoint.output_index() as usize;

            let output_amount = match tx_index.position() {
                common::chain::SpendablePosition::Transaction(tx_pos) => {
                    let tx = self
                        .db_tx
                        .get_mainchain_tx_by_position(tx_pos)
                        .map_err(StateUpdateError::from)?
                        .ok_or_else(|| {
                            StateUpdateError::InvariantErrorTransactionCouldNotBeLoaded(
                                tx_pos.clone(),
                            )
                        })?;

                    Self::get_output_amount(tx.outputs(), output_index, tx.get_id().into())?
                }
                common::chain::SpendablePosition::BlockReward(block_id) => {
                    let block_index = self
                        .db_tx
                        .get_block_index(block_id)
                        .map_err(StateUpdateError::from)?
                        .ok_or_else(|| {
                            StateUpdateError::InvariantErrorHeaderCouldNotBeLoaded(block_id.clone())
                        })?;

                    let rewards_tx = block_index.block_header().block_reward_transactable();

                    let outputs = rewards_tx.outputs().unwrap_or(&[]);

                    Self::get_output_amount(outputs, output_index, block_id.clone().into())?
                }
            };
            total = (total + output_amount).ok_or(StateUpdateError::InputAdditionError)?;
        }
        Ok(total)
    }

    fn check_transferred_amounts_and_get_fee(
        &self,
        tx: &Transaction,
    ) -> Result<Amount, StateUpdateError> {
        let inputs = tx.inputs();
        let outputs = tx.outputs();

        let inputs_total = self.calculate_total_inputs(inputs)?;
        let outputs_total = Self::calculate_total_outputs(outputs)?;

        if outputs_total > inputs_total {
            return Err(StateUpdateError::AttemptToPrintMoney(
                inputs_total,
                outputs_total,
            ));
        }

        let paid_fee = inputs_total - outputs_total;
        paid_fee.ok_or(StateUpdateError::TxFeeTotalCalcFailed(
            inputs_total,
            outputs_total,
        ))
    }

    fn calculate_total_outputs(outputs: &[TxOutput]) -> Result<Amount, StateUpdateError> {
        outputs
            .iter()
            .try_fold(Amount::from_atoms(0), |accum, out| accum + out.value())
            .ok_or(StateUpdateError::OutputAdditionError)
    }

    fn calculate_block_total_fees(&self, block: &Block) -> Result<Amount, StateUpdateError> {
        let total_fees = block
            .transactions()
            .iter()
            .try_fold(Amount::from_atoms(0), |init, tx| {
                init + self.check_transferred_amounts_and_get_fee(tx).ok()?
            })
            .ok_or_else(|| StateUpdateError::FailedToAddAllFeesOfBlock(block.get_id()))?;
        Ok(total_fees)
    }

    pub fn check_block_reward(
        &self,
        block: &Block,
        block_subsidy_at_height: Amount,
    ) -> Result<(), StateUpdateError> {
        let total_fees = self.calculate_block_total_fees(block)?;

        let block_reward_transactable = block.header().block_reward_transactable();

        let inputs = block_reward_transactable.inputs();
        let outputs = block_reward_transactable.outputs();

        let inputs_total = inputs.map_or_else(
            || Ok(Amount::from_atoms(0)),
            |ins| self.calculate_total_inputs(ins),
        )?;
        let outputs_total =
            outputs.map_or_else(|| Ok(Amount::from_atoms(0)), Self::calculate_total_outputs)?;

        let max_allowed_outputs_total =
            amount_sum!(inputs_total, block_subsidy_at_height, total_fees)
                .ok_or_else(|| StateUpdateError::RewardAdditionError(block.get_id()))?;

        if outputs_total > max_allowed_outputs_total {
            return Err(StateUpdateError::AttemptToPrintMoney(
                inputs_total,
                outputs_total,
            ));
        }
        Ok(())
    }

    fn check_timelock(
        &self,
        source_block_index: &BlockIndex,
        output: &TxOutput,
        spend_height: &BlockHeight,
        spending_time: &BlockTimestamp,
    ) -> Result<(), StateUpdateError> {
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
                let d: i64 =
                    (*d).try_into().map_err(|_| StateUpdateError::BlockHeightArithmeticError)?;
                let d = BlockDistance::from(d);
                *spend_height
                    >= (source_block_height + d)
                        .ok_or(StateUpdateError::BlockHeightArithmeticError)?
            }
            OutputTimeLock::ForSeconds(dt) => {
                spending_time.as_duration_since_epoch()
                    >= source_block_time
                        .as_duration_since_epoch()
                        .checked_add(Duration::from_secs(*dt))
                        .ok_or(StateUpdateError::BlockTimestampArithmeticError)?
            }
        };

        ensure!(past_lock, StateUpdateError::TimeLockViolation);

        Ok(())
    }

    fn verify_signatures<T: Transactable>(
        &self,
        tx: &T,
        spend_height: &BlockHeight,
        spending_time: &BlockTimestamp,
    ) -> Result<(), StateUpdateError> {
        let inputs = match tx.inputs() {
            Some(ins) => ins,
            None => return Ok(()),
        };

        for (input_idx, input) in inputs.iter().enumerate() {
            let outpoint = input.outpoint();
            let prev_tx_index_op = self.get_from_cached(outpoint)?;

            let tx_index = prev_tx_index_op
                .get_tx_index()
                .ok_or(StateUpdateError::PreviouslyCachedInputNotFound)?;

            match tx_index.position() {
                SpendablePosition::Transaction(tx_pos) => {
                    let prev_tx = self
                        .db_tx
                        .get_mainchain_tx_by_position(tx_pos)
                        .map_err(StateUpdateError::from)?
                        .ok_or_else(|| {
                            StateUpdateError::InvariantErrorTransactionCouldNotBeLoaded(
                                tx_pos.clone(),
                            )
                        })?;

                    let output = prev_tx
                        .outputs()
                        .get(input.outpoint().output_index() as usize)
                        .ok_or(StateUpdateError::OutputIndexOutOfRange {
                            tx_id: None,
                            source_output_index: outpoint.output_index() as usize,
                        })?;

                    // TODO: see if a different treatment should be done for different output purposes

                    {
                        let block_index = self
                            .db_tx
                            .get_block_index(tx_pos.block_id())
                            .map_err(StateUpdateError::from)?
                            .ok_or_else(|| {
                                StateUpdateError::InvariantErrorHeaderCouldNotBeLoaded(
                                    tx_pos.block_id().clone(),
                                )
                            })?;
                        self.check_timelock(&block_index, output, spend_height, spending_time)?;
                    }

                    verify_signature(output.purpose().destination(), tx, input_idx)
                        .map_err(|_| StateUpdateError::SignatureVerificationFailed)?;
                }
                SpendablePosition::BlockReward(block_id) => {
                    let block_index = self
                        .db_tx
                        .get_block_index(block_id)
                        .map_err(StateUpdateError::from)?
                        .ok_or_else(|| {
                            StateUpdateError::InvariantErrorHeaderCouldNotBeLoaded(block_id.clone())
                        })?;

                    let reward_tx = block_index.block_header().block_reward_transactable();

                    let output = reward_tx
                        .outputs()
                        .unwrap_or(&[])
                        .get(input.outpoint().output_index() as usize)
                        .ok_or(StateUpdateError::OutputIndexOutOfRange {
                            tx_id: None,
                            source_output_index: outpoint.output_index() as usize,
                        })?;

                    // TODO: see if a different treatment should be done for different output purposes

                    self.check_timelock(&block_index, output, spend_height, spending_time)?;

                    verify_signature(output.purpose().destination(), tx, input_idx)
                        .map_err(|_| StateUpdateError::SignatureVerificationFailed)?;
                }
            };
        }

        Ok(())
    }

    fn apply_spend(
        &mut self,
        inputs: &[TxInput],
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
        spender: Spender,
    ) -> Result<(), StateUpdateError> {
        for input in inputs {
            let outpoint = input.outpoint();

            match outpoint.tx_id() {
                OutPointSourceId::Transaction(_) => {}
                OutPointSourceId::BlockReward(block_id) => {
                    self.check_blockreward_maturity(&block_id, spend_height, blockreward_maturity)?;
                }
            }

            let prev_tx_index_op = self.get_from_cached_mut(outpoint)?;

            prev_tx_index_op
                .spend(outpoint.output_index(), spender.clone())
                .map_err(StateUpdateError::from)?;
        }

        Ok(())
    }

    pub fn spend(
        &mut self,
        spend_ref: BlockTransactableRef,
        spend_height: &BlockHeight,
        median_time_past: &BlockTimestamp,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), StateUpdateError> {
        match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let tx = block.transactions().get(tx_num).ok_or_else(|| {
                    StateUpdateError::TxNumWrongInBlockOnConnect(tx_num, block.get_id())
                })?;

                // pre-cache all inputs
                self.precache_inputs(tx.inputs())?;

                // check for attempted money printing
                self.check_transferred_amounts_and_get_fee(tx)?;

                // verify input signatures
                self.verify_signatures(tx, spend_height, median_time_past)?;

                // spend inputs of this transaction
                let spender = tx.get_id().into();
                self.apply_spend(tx.inputs(), spend_height, blockreward_maturity, spender)?;
            }
            BlockTransactableRef::BlockReward(block) => {
                let reward_transactable = block.header().block_reward_transactable();
                let inputs = reward_transactable.inputs();
                // TODO: test spending block rewards from chains outside the mainchain
                match inputs {
                    Some(ins) => {
                        // pre-cache all inputs
                        self.precache_inputs(ins)?;

                        // verify input signatures
                        self.verify_signatures(
                            &reward_transactable,
                            spend_height,
                            median_time_past,
                        )?;

                        let spender = block.get_id().into();
                        self.apply_spend(ins, spend_height, blockreward_maturity, spender)?;
                    }
                    None => (),
                }
            }
        }
        // add the outputs to the cache
        self.add_outputs(spend_ref)?;

        Ok(())
    }

    pub fn unspend(&mut self, spend_ref: BlockTransactableRef) -> Result<(), StateUpdateError> {
        // Delete TxMainChainIndex for the current tx
        self.remove_outputs(spend_ref)?;

        match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let tx = block.transactions().get(tx_num).ok_or_else(|| {
                    StateUpdateError::TxNumWrongInBlockOnDisconnect(tx_num, block.get_id())
                })?;

                // pre-cache all inputs
                self.precache_inputs(tx.inputs())?;

                // unspend inputs
                for input in tx.inputs() {
                    let outpoint = input.outpoint();

                    let input_tx_id_op = self.get_from_cached_mut(outpoint)?;

                    // Mark input as unspend
                    input_tx_id_op
                        .unspend(outpoint.output_index())
                        .map_err(StateUpdateError::from)?;
                }
            }
            BlockTransactableRef::BlockReward(block) => {
                let reward_transactable = block.header().block_reward_transactable();
                match reward_transactable.inputs() {
                    Some(inputs) => {
                        // pre-cache all inputs
                        self.precache_inputs(inputs)?;

                        // unspend inputs
                        for input in inputs {
                            let outpoint = input.outpoint();

                            let input_tx_id_op = self.get_from_cached_mut(outpoint)?;

                            // Mark input as unspend
                            input_tx_id_op
                                .unspend(outpoint.output_index())
                                .map_err(StateUpdateError::from)?;
                        }
                    }
                    None => (),
                }
            }
        }

        Ok(())
    }

    fn precache_inputs(&mut self, inputs: &[TxInput]) -> Result<(), StateUpdateError> {
        inputs.iter().try_for_each(|input| self.fetch_and_cache(input.outpoint()))
    }

    pub fn consume(self) -> Result<ConsumedCachedInputs, StateUpdateError> {
        Ok(ConsumedCachedInputs { data: self.inputs })
    }
}

impl<'a, S: BlockchainStorageWrite> CachedInputs<'a, S> {
    pub fn flush_to_storage(
        db_tx: &mut S,
        input_data: ConsumedCachedInputs,
    ) -> Result<(), StateUpdateError> {
        for (tx_id, tx_index_op) in input_data.data {
            match tx_index_op {
                CachedInputsOperation::Write(ref tx_index) => {
                    db_tx.set_mainchain_tx_index(&tx_id, tx_index)?
                }
                CachedInputsOperation::Read(_) => (),
                CachedInputsOperation::Erase => db_tx.del_mainchain_tx_index(&tx_id)?,
            }
        }
        Ok(())
    }
}

// TODO: write tests for CachedInputs that covers all possible mutations
// TODO: write tests for block rewards
// TODO: test attempting to spend the block reward at the same block
// TODO: test that total_block_reward = total_tx_fees + consensus_block_reward
