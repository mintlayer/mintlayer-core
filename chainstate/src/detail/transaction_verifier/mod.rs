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
    primitives::{Amount, BlockDistance, BlockHeight, Id, Idable},
};
use utils::ensure;

use self::error::ConnectTransactionError;

/// A BlockTransactableRef is a reference to an operation in a block that causes inputs to be spent, outputs to be created, or both
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BlockTransactableRef<'a> {
    Transaction(&'a Block, usize),
    BlockReward(&'a Block),
}

/// The change that a block has caused to the blockchain state
pub struct TransactionVerifierDelta {
    data: BTreeMap<OutPointSourceId, CachedInputsOperation>,
}

/// The tool used to verify transaction and cache their updated states in memory
pub struct TransactionVerifier<'a, S> {
    db_tx: &'a S,
    tx_index_cache: BTreeMap<OutPointSourceId, CachedInputsOperation>,
    chain_config: &'a ChainConfig,
}

impl<'a, S> TransactionVerifier<'a, S> {
    pub fn new(db_tx: &'a S, chain_config: &'a ChainConfig) -> Self {
        Self {
            db_tx,
            chain_config,
            tx_index_cache: BTreeMap::new(),
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

    fn add_outputs(
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

    fn remove_outputs(
        &mut self,
        spend_ref: BlockTransactableRef,
    ) -> Result<(), ConnectTransactionError> {
        let tx_index = CachedInputsOperation::Erase;
        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(spend_ref)?;

        self.tx_index_cache.insert(outpoint_source_id, tx_index);
        Ok(())
    }

    fn check_blockreward_maturity(
        &self,
        spending_block_id: &Id<GenBlock>,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), ConnectTransactionError> {
        let spending_block_id = match spending_block_id.classify(self.chain_config) {
            GenBlockId::Block(id) => id,
            // TODO Handle premine maturity here or using some other mechanism (output time lock)
            GenBlockId::Genesis(_) => return Ok(()),
        };
        let source_block_index = self.db_tx.get_block_index(&spending_block_id)?;
        let source_block_index = source_block_index
            .ok_or(ConnectTransactionError::InvariantBrokenSourceBlockIndexNotFound)?;
        let source_height = source_block_index.block_height();
        let actual_distance = (*spend_height - source_height)
            .ok_or(ConnectTransactionError::BlockHeightArithmeticError)?;
        if actual_distance < *blockreward_maturity {
            return Err(ConnectTransactionError::ImmatureBlockRewardSpend);
        }
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

    fn get_from_cached(
        &self,
        outpoint: &OutPoint,
    ) -> Result<&CachedInputsOperation, ConnectTransactionError> {
        let result = match self.tx_index_cache.get(&outpoint.tx_id()) {
            Some(tx_index) => tx_index,
            None => return Err(ConnectTransactionError::PreviouslyCachedInputNotFound),
        };
        Ok(result)
    }

    fn fetch_and_cache(&mut self, outpoint: &OutPoint) -> Result<(), ConnectTransactionError> {
        let _tx_index_op = match self.tx_index_cache.entry(outpoint.tx_id()) {
            Entry::Occupied(entry) => {
                // If tx index was loaded
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                // Maybe the utxo is in a previous block?
                let tx_index = self
                    .db_tx
                    .get_mainchain_tx_index(&outpoint.tx_id())?
                    .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
                entry.insert(CachedInputsOperation::Read(tx_index))
            }
        };
        Ok(())
    }

    fn get_output_value(
        outputs: &[TxOutput],
        output_index: usize,
        spender_id: Spender,
    ) -> Result<&OutputValue, ConnectTransactionError> {
        let output =
            outputs
                .get(output_index)
                .ok_or(ConnectTransactionError::OutputIndexOutOfRange {
                    tx_id: Some(spender_id),
                    source_output_index: output_index,
                })?;
        Ok(output.value())
    }

    fn calculate_coins_total_inputs(
        &self,
        inputs: &[TxInput],
    ) -> Result<Amount, ConnectTransactionError> {
        let mut total = Amount::from_atoms(0);
        for (_input_idx, input) in inputs.iter().enumerate() {
            let outpoint = input.outpoint();
            let tx_index = match self.tx_index_cache.get(&outpoint.tx_id()) {
                Some(tx_index_op) => match tx_index_op {
                    CachedInputsOperation::Write(tx_index) => tx_index,
                    CachedInputsOperation::Read(tx_index) => tx_index,
                    CachedInputsOperation::Erase => {
                        return Err(ConnectTransactionError::PreviouslyCachedInputWasErased)
                    }
                },
                None => return Err(ConnectTransactionError::PreviouslyCachedInputNotFound),
            };
            let output_index = outpoint.output_index() as usize;

            let output_amount = match tx_index.position() {
                common::chain::SpendablePosition::Transaction(tx_pos) => {
                    let tx = self
                        .db_tx
                        .get_mainchain_tx_by_position(tx_pos)
                        .map_err(ConnectTransactionError::from)?
                        .ok_or_else(|| {
                            ConnectTransactionError::InvariantErrorTransactionCouldNotBeLoaded(
                                tx_pos.clone(),
                            )
                        })?;

                    Self::get_output_value(tx.outputs(), output_index, tx.get_id().into())
                        .cloned()?
                }
                common::chain::SpendablePosition::BlockReward(block_id) => {
                    let outputs = self.block_reward_outputs(block_id)?;
                    Self::get_output_value(&outputs, output_index, (*block_id).into()).cloned()?
                }
            };
            match output_amount {
                OutputValue::Coin(output_amount) => {
                    total = (total + output_amount)
                        .ok_or(ConnectTransactionError::InputAdditionError)?
                }
            }
        }
        Ok(total)
    }

    fn check_transferred_amounts_and_get_fee(
        &self,
        tx: &Transaction,
    ) -> Result<Amount, ConnectTransactionError> {
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
        paid_fee.ok_or(ConnectTransactionError::TxFeeTotalCalcFailed(
            inputs_total,
            outputs_total,
        ))
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

    fn calculate_block_total_fees(&self, block: &Block) -> Result<Amount, ConnectTransactionError> {
        let total_fees = block
            .transactions()
            .iter()
            .try_fold(Amount::from_atoms(0), |init, tx| {
                init + self.check_transferred_amounts_and_get_fee(tx).ok()?
            })
            .ok_or_else(|| ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id()))?;
        Ok(total_fees)
    }

    pub fn check_block_reward(
        &self,
        block: &Block,
        block_subsidy_at_height: Amount,
    ) -> Result<(), ConnectTransactionError> {
        let total_fees = self.calculate_block_total_fees(block)?;

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
            amount_sum!(inputs_total, block_subsidy_at_height, total_fees)
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
            let prev_tx_index_op = self.get_from_cached(outpoint)?;

            let tx_index = prev_tx_index_op
                .get_tx_index()
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

    fn spend(
        &mut self,
        inputs: &[TxInput],
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
        spender: Spender,
    ) -> Result<(), ConnectTransactionError> {
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
                .map_err(ConnectTransactionError::from)?;
        }

        Ok(())
    }

    pub fn connect_transaction(
        &mut self,
        spend_ref: BlockTransactableRef,
        spend_height: &BlockHeight,
        median_time_past: &BlockTimestamp,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), ConnectTransactionError> {
        match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let tx = block.transactions().get(tx_num).ok_or_else(|| {
                    ConnectTransactionError::TxNumWrongInBlockOnConnect(tx_num, block.get_id())
                })?;

                // pre-cache all inputs
                self.precache_inputs(tx.inputs())?;

                // check for attempted money printing
                self.check_transferred_amounts_and_get_fee(tx)?;

                // verify input signatures
                self.verify_signatures(tx, spend_height, median_time_past)?;

                // spend inputs of this transaction
                let spender = tx.get_id().into();
                self.spend(tx.inputs(), spend_height, blockreward_maturity, spender)?;
            }
            BlockTransactableRef::BlockReward(block) => {
                let reward_transactable = block.block_reward_transactable();
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
                        self.spend(ins, spend_height, blockreward_maturity, spender)?;
                    }
                    None => (),
                }
            }
        }
        // add the outputs to the cache
        self.add_outputs(spend_ref)?;

        Ok(())
    }

    pub fn disconnect_transaction(
        &mut self,
        spend_ref: BlockTransactableRef,
    ) -> Result<(), ConnectTransactionError> {
        // Delete TxMainChainIndex for the current tx
        self.remove_outputs(spend_ref)?;

        match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let tx = block.transactions().get(tx_num).ok_or_else(|| {
                    ConnectTransactionError::TxNumWrongInBlockOnDisconnect(tx_num, block.get_id())
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
                        .map_err(ConnectTransactionError::from)?;
                }
            }
            BlockTransactableRef::BlockReward(block) => {
                let reward_transactable = block.block_reward_transactable();
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
                                .map_err(ConnectTransactionError::from)?;
                        }
                    }
                    None => (),
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
            GenBlockId::Block(id) => Ok(self
                .db_tx
                .get_block(id)?
                .ok_or(ConnectTransactionError::InvariantErrorBlockCouldNotBeLoaded(id))?
                .block_reward_transactable()
                .outputs()
                .unwrap_or(&[])
                .to_vec()),
        }
    }

    pub fn consume(self) -> Result<TransactionVerifierDelta, ConnectTransactionError> {
        Ok(TransactionVerifierDelta {
            data: self.tx_index_cache,
        })
    }
}

impl<'a, S: BlockchainStorageWrite> TransactionVerifier<'a, S> {
    pub fn flush_to_storage(
        db_tx: &mut S,
        input_data: TransactionVerifierDelta,
    ) -> Result<(), ConnectTransactionError> {
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
