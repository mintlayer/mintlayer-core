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

use common::chain::transaction::signature::verify_signature;
use common::chain::SpendablePosition;
use std::collections::{btree_map::Entry, BTreeMap};

use blockchain_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use common::{
    chain::{
        block::Block, calculate_tx_index_from_block, OutPoint, OutPointSourceId, Spender,
        Transaction,
    },
    primitives::{Amount, BlockDistance, BlockHeight, Id, Idable},
};

use crate::detail::{BlockError, TxRw};

mod cached_operation;
use cached_operation::CachedInputsOperation;

pub struct ConsumedCachedInputs {
    data: BTreeMap<OutPointSourceId, CachedInputsOperation>,
}

pub struct CachedInputs<'a> {
    db_tx: &'a TxRw<'a>,
    inputs: BTreeMap<OutPointSourceId, CachedInputsOperation>,
}

impl<'a> CachedInputs<'a> {
    pub fn new(db_tx: &'a TxRw<'a>) -> Self {
        Self {
            db_tx,
            inputs: BTreeMap::new(),
        }
    }

    // TODO: add block reward outputs

    fn add_outputs(&mut self, block: &Block, tx_num: usize) -> Result<(), BlockError> {
        let tx_index = CachedInputsOperation::Write(calculate_tx_index_from_block(block, tx_num)?);
        let tx = block
            .transactions()
            .get(tx_num)
            .ok_or_else(|| BlockError::TxNumWrongInBlock(tx_num, block.get_id()))?;
        let tx_id = tx.get_id();
        match self.inputs.entry(OutPointSourceId::from(tx_id)) {
            Entry::Occupied(_) => return Err(BlockError::OutputAlreadyPresentInInputsCache),
            Entry::Vacant(entry) => entry.insert(tx_index),
        };
        Ok(())
    }

    fn remove_outputs(&mut self, tx: &Transaction) -> Result<(), BlockError> {
        self.inputs.insert(
            OutPointSourceId::from(tx.get_id()),
            CachedInputsOperation::Erase,
        );
        Ok(())
    }

    fn check_blockreward_maturity(
        &self,
        spending_block_id: &Id<Block>,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        let source_block_index = self.db_tx.get_block_index(spending_block_id)?;
        let source_block_index =
            source_block_index.ok_or(BlockError::InvariantBrokenSourceBlockIndexNotFound)?;
        let source_height = source_block_index.get_block_height();
        let actual_distance =
            (*spend_height - source_height).ok_or(BlockError::BlockHeightArithmeticError)?;
        if actual_distance < *blockreward_maturity {
            return Err(BlockError::ImmatureBlockRewardSpend);
        }
        Ok(())
    }

    fn get_from_cached_mut(
        &mut self,
        outpoint: &OutPoint,
    ) -> Result<&mut CachedInputsOperation, BlockError> {
        let result = match self.inputs.get_mut(&outpoint.get_tx_id()) {
            Some(tx_index) => tx_index,
            None => return Err(BlockError::PreviouslyCachedInputNotFound),
        };
        Ok(result)
    }

    fn get_from_cached(&self, outpoint: &OutPoint) -> Result<&CachedInputsOperation, BlockError> {
        let result = match self.inputs.get(&outpoint.get_tx_id()) {
            Some(tx_index) => tx_index,
            None => return Err(BlockError::PreviouslyCachedInputNotFound),
        };
        Ok(result)
    }

    fn fetch_and_cache(&mut self, outpoint: &OutPoint) -> Result<(), BlockError> {
        let _tx_index_op = match self.inputs.entry(outpoint.get_tx_id()) {
            Entry::Occupied(entry) => {
                // If tx index was loaded
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                // Maybe the utxo is in a previous block?
                let tx_index = self
                    .db_tx
                    .get_mainchain_tx_index(&outpoint.get_tx_id())?
                    .ok_or(BlockError::MissingOutputOrSpent)?;
                entry.insert(CachedInputsOperation::Read(tx_index))
            }
        };
        Ok(())
    }

    fn calculate_total_inputs(&self, tx: &Transaction) -> Result<Amount, BlockError> {
        let mut total = Amount::from_atoms(0);
        for (_input_idx, input) in tx.get_inputs().iter().enumerate() {
            let outpoint = input.get_outpoint();
            let tx_index = match self.inputs.get(&outpoint.get_tx_id()) {
                Some(tx_index_op) => match tx_index_op {
                    CachedInputsOperation::Write(tx_index) => tx_index,
                    CachedInputsOperation::Read(tx_index) => tx_index,
                    CachedInputsOperation::Erase => {
                        return Err(BlockError::PreviouslyCachedInputWasErased)
                    }
                },
                None => return Err(BlockError::PreviouslyCachedInputNotFound),
            };
            let output_amount = match tx_index.get_position() {
                common::chain::SpendablePosition::Transaction(tx_pos) => {
                    match self.db_tx.get_mainchain_tx_by_position(tx_pos)? {
                        Some(tx) => tx
                            .get_outputs()
                            .get(outpoint.get_output_index() as usize)
                            .ok_or(BlockError::OutputIndexOutOfRange {
                                tx_id: Some(tx.get_id().into()),
                                source_output_index: outpoint.get_output_index() as usize,
                            })?
                            .get_value(),
                        None => return Err(BlockError::InvariantErrorTransactionCouldNotBeLoaded),
                    }
                }
                common::chain::SpendablePosition::BlockReward(_) => unimplemented!(),
            };
            total = (total + output_amount).ok_or(BlockError::InputAdditionError)?;
        }
        Ok(total)
    }

    fn check_inputs_amounts(&self, tx: &Transaction) -> Result<(), BlockError> {
        let inputs_total = self.calculate_total_inputs(tx)?;
        let outputs_total = tx
            .get_outputs()
            .iter()
            .try_fold(Amount::from_atoms(0), |accum, out| accum + out.get_value())
            .ok_or(BlockError::OutputAdditionError)?;

        if outputs_total > inputs_total {
            return Err(BlockError::AttemptToPrintMoney(inputs_total, outputs_total));
        }
        Ok(())
    }

    fn verify_signatures(&self, tx: &Transaction) -> Result<(), BlockError> {
        for (input_idx, input) in tx.get_inputs().iter().enumerate() {
            let outpoint = input.get_outpoint();
            let prev_tx_index_op = self.get_from_cached(outpoint)?;

            let tx_index = prev_tx_index_op
                .get_tx_index()
                .ok_or(BlockError::PreviouslyCachedInputNotFound)?;

            let input_outpoint_script = match tx_index.get_position() {
                SpendablePosition::Transaction(tx_pos) => {
                    let prev_tx = self
                        .db_tx
                        .get_mainchain_tx_by_position(tx_pos)
                        .map_err(BlockError::from)?
                        .ok_or(BlockError::InvariantErrorTransactionCouldNotBeLoaded)?;
                    let output = prev_tx
                        .get_outputs()
                        .get(input.get_outpoint().get_output_index() as usize)
                        .ok_or(BlockError::OutputIndexOutOfRange {
                            tx_id: Some(tx.get_id().into()),
                            source_output_index: outpoint.get_output_index() as usize,
                        })?;
                    output.get_destination().clone()
                }
                SpendablePosition::BlockReward(_reward_pos) => {
                    // TODO(Roy): fill this with the block reward that the user now is spending
                    todo!()
                }
            };

            verify_signature(&input_outpoint_script, tx, input_idx)
                .map_err(|_| BlockError::SignatureVerificationFailed(tx.get_id()))?;
        }

        Ok(())
    }

    fn apply_spend(
        &mut self,
        tx: &Transaction,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        for input in tx.get_inputs() {
            let outpoint = input.get_outpoint();

            if let OutPointSourceId::BlockReward(block_id) = outpoint.get_tx_id() {
                self.check_blockreward_maturity(&block_id, spend_height, blockreward_maturity)?;
            }

            let prev_tx_index_op = self.get_from_cached_mut(outpoint)?;
            prev_tx_index_op
                .spend(outpoint.get_output_index(), Spender::from(tx.get_id()))
                .map_err(BlockError::from)?;
        }

        Ok(())
    }

    pub fn spend(
        &mut self,
        block: &Block,
        tx_num: usize,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        /*
        TODO(Roy): Add consensus data's output(s) here to spendable in the database
        Whether we want to create a separate function for that is up to you, however,
        it seems it's a bad idea because it's the same stuff for transactions and
        block rewards, and repeating code is bad. Maybe change tx_num to Option<usize>,
        and then None would mean we're going for the block reward. OR... better, an enum.

        Don't forget that users are not allowed to spend the block reward before blockreward_maturity
        passes; the check is down there. Feel free to move stuff around.
        */

        let tx = block
            .transactions()
            .get(tx_num)
            .ok_or_else(|| BlockError::TxNumWrongInBlock(tx_num, block.get_id()))?;

        // pre-cache all inputs
        tx.get_inputs()
            .iter()
            .try_for_each(|input| self.fetch_and_cache(input.get_outpoint()))?;

        // check for attempted money printing
        self.check_inputs_amounts(tx)?;

        // verify input signatures
        self.verify_signatures(tx)?;

        // spend inputs of this transaction
        self.apply_spend(tx, spend_height, blockreward_maturity)?;

        // add the outputs of this transaction to the cache
        self.add_outputs(block, tx_num)?;

        Ok(())
    }

    pub fn unspend(&mut self, tx: &Transaction) -> Result<(), BlockError> {
        // Delete TxMainChainIndex for the current tx
        self.remove_outputs(tx)?;

        // pre-cache all inputs
        tx.get_inputs()
            .iter()
            .try_for_each(|input| self.fetch_and_cache(input.get_outpoint()))?;

        // unspend inputs
        for input in tx.get_inputs() {
            let outpoint = input.get_outpoint();

            let input_tx_id_op = self.get_from_cached_mut(outpoint)?;

            // Mark input as unspend
            input_tx_id_op.unspend(outpoint.get_output_index()).map_err(BlockError::from)?;
        }
        Ok(())
    }

    pub fn consume(self) -> Result<ConsumedCachedInputs, BlockError> {
        Ok(ConsumedCachedInputs { data: self.inputs })
    }

    pub fn flush_to_storage(
        db_tx: &mut TxRw<'a>,
        input_data: ConsumedCachedInputs,
    ) -> Result<(), BlockError> {
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
