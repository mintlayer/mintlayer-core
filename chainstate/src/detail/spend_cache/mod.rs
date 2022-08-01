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

use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
};

use crate::detail::TokensError;

use super::gen_block_index::GenBlockIndex;
use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use common::{
    amount_sum,
    chain::{
        block::timestamp::BlockTimestamp,
        calculate_tx_index_from_block,
        config::{TOKEN_MAX_ISSUANCE_ALLOWED, TOKEN_MIN_ISSUANCE_FEE},
        signature::{verify_signature, Transactable},
        tokens::{get_tokens_issuance_count, token_id, OutputValue, TokenData, TokenId},
        Block, ChainConfig, GenBlock, GenBlockId, OutPoint, OutPointSourceId, SpendablePosition,
        Spender, Transaction, TxInput, TxMainChainIndex, TxOutput,
    },
    primitives::{Amount, BlockDistance, BlockHeight, Id, Idable},
};
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
    chain_config: &'a ChainConfig,
}

impl<'a, S> CachedInputs<'a, S> {
    pub fn new(db_tx: &'a S, chain_config: &'a ChainConfig) -> Self {
        Self {
            db_tx,
            chain_config,
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

    pub fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, StateUpdateError> {
        match block_id.classify(self.chain_config) {
            GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
                self.chain_config.genesis_block(),
            )))),
            GenBlockId::Block(id) => self
                .db_tx
                .get_block_index(&id)
                .map(|b| b.map(GenBlockIndex::Block))
                .map_err(StateUpdateError::from),
        }
    }

    fn remove_outputs(&mut self, spend_ref: BlockTransactableRef) -> Result<(), StateUpdateError> {
        let tx_index = CachedInputsOperation::Erase;
        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(spend_ref)?;

        self.inputs.insert(outpoint_source_id, tx_index);
        Ok(())
    }

    fn check_blockreward_maturity(
        &self,
        spending_block_id: &Id<GenBlock>,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), StateUpdateError> {
        let spending_block_id = match spending_block_id.classify(self.chain_config) {
            GenBlockId::Block(id) => id,
            // TODO Handle premine maturity here or using some other mechanism (output time lock)
            GenBlockId::Genesis(_) => return Ok(()),
        };
        let source_block_index = self.db_tx.get_block_index(&spending_block_id)?;
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
    ) -> Result<&OutputValue, StateUpdateError> {
        let output = outputs.get(output_index).ok_or(StateUpdateError::OutputIndexOutOfRange {
            tx_id: Some(spender_id),
            source_output_index: output_index,
        })?;
        Ok(output.value())
    }

    // Get TokenId and Amount in input
    fn filter_tokens_amount(
        &self,
        prev_tx: &Transaction,
        output: &common::chain::TxOutput,
    ) -> Option<(TokenId, Amount)> {
        match output.value() {
            OutputValue::Coin(_) => None,
            OutputValue::Token(token) => Some(match token {
                TokenData::TokenTransferV1 { token_id, amount } => (*token_id, *amount),
                TokenData::TokenIssuanceV1 {
                    token_ticker: _,
                    amount_to_issue,
                    number_of_decimals: _,
                    metadata_uri: _,
                } => {
                    let token_id = token_id(prev_tx)?;
                    (token_id, *amount_to_issue)
                }
                TokenData::TokenBurnV1 {
                    token_id: _,
                    amount_to_burn: _,
                } => {
                    /* Token have burned and can't be transfered */
                    return None;
                }
            }),
        }
    }

    pub fn calculate_assets_total_inputs(
        &self,
        inputs: &[TxInput],
    ) -> Result<BTreeMap<TokenId, Amount>, StateUpdateError> {
        let mut total_tokens: BTreeMap<TokenId, Amount> = BTreeMap::new();
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
            match tx_index.position() {
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

                    let output = tx.outputs().get(output_index).ok_or(
                        StateUpdateError::OutputIndexOutOfRange {
                            tx_id: Some(tx.get_id().into()),
                            source_output_index: output_index,
                        },
                    )?;

                    match self.filter_tokens_amount(&tx, output) {
                        Some((token_id, amount)) => {
                            total_tokens.insert(
                                token_id,
                                (total_tokens
                                    .get(&token_id)
                                    .cloned()
                                    .unwrap_or(Amount::from_atoms(0))
                                    + amount)
                                    .ok_or(StateUpdateError::InputAdditionError)?,
                            );
                        }
                        None => continue,
                    }
                }
                common::chain::SpendablePosition::BlockReward(_block_id) => {
                    continue;
                }
            }
        }
        Ok(total_tokens)
    }

    fn calculate_coins_total_inputs(&self, inputs: &[TxInput]) -> Result<Amount, StateUpdateError> {
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

                    Self::get_output_amount(tx.outputs(), output_index, tx.get_id().into())
                        .cloned()?
                }
                common::chain::SpendablePosition::BlockReward(block_id) => {
                    let block_index = self.get_gen_block_index(block_id)?.ok_or_else(|| {
                        // TODO get rid of this coercion
                        let block_id = Id::new(block_id.get());
                        StateUpdateError::InvariantErrorHeaderCouldNotBeLoaded(block_id)
                    })?;

                    let rewards_tx = block_index.block_reward_transactable();

                    let outputs = rewards_tx.outputs().unwrap_or(&[]);
                    Self::get_output_amount(outputs, output_index, (*block_id).into()).cloned()?
                }
            };
            match output_amount {
                OutputValue::Coin(output_amount) => {
                    total = (total + output_amount).ok_or(StateUpdateError::InputAdditionError)?
                }
                OutputValue::Token(_) => { /*For now we don't calculate here tokens, use calculate_assets_total_inputs */
                }
            }
        }
        Ok(total)
    }

    fn check_transferred_amounts_and_get_fee(
        &self,
        tx: &Transaction,
    ) -> Result<Amount, StateUpdateError> {
        let inputs = tx.inputs();
        let outputs = tx.outputs();

        let inputs_total = self.calculate_coins_total_inputs(inputs)?;
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
            .try_fold(Amount::from_atoms(0), |accum, out| match out.value() {
                OutputValue::Coin(value) => accum + *value,
                OutputValue::Token(_) => Some(accum),
            })
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
            |ins| self.calculate_coins_total_inputs(ins),
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
        source_block_index: &GenBlockIndex,
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
                *spending_time
                    >= source_block_time
                        .add_int_seconds(*dt)
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
                        .map_err(|_| StateUpdateError::SignatureVerificationFailed)?;
                }
                SpendablePosition::BlockReward(block_id) => {
                    let block_index = self.get_gen_block_index(block_id)?.ok_or_else(|| {
                        // TODO get rid of the coercion
                        let block_id = Id::new(block_id.get());
                        StateUpdateError::InvariantErrorHeaderCouldNotBeLoaded(block_id)
                    })?;

                    let reward_tx = block_index.block_reward_transactable();

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

    fn check_connected_transfer_data(
        &self,
        block_id: Id<Block>,
        tx: &Transaction,
        token_id: &TokenId,
        amount: &Amount,
    ) -> Result<(), TokensError> {
        // Collect token inputs
        let total_value_tokens = self
            .calculate_assets_total_inputs(tx.inputs())
            .map_err(|_err| TokensError::NoTokenInInputs(tx.get_id(), block_id))?;

        // Is token exist in inputs?
        let (_, origin_amount) = total_value_tokens
            .iter()
            .find(|&(origin_token_id, _)| origin_token_id == token_id)
            .ok_or_else(|| TokensError::NoTokenInInputs(tx.get_id(), block_id))?;

        // Check amount
        ensure!(
            origin_amount >= amount,
            TokensError::InsuffienceTokenValueInInputs(tx.get_id(), block_id,)
        );

        Ok(())
    }

    fn check_connected_issue_data(
        &self,
        _token_ticker: &[u8],
        _amount_to_issue: &Amount,
        _number_of_decimals: &u8,
        _metadata_uri: &[u8],
        _tx_id: Id<Transaction>,
        _block_id: Id<Block>,
    ) -> Result<(), TokensError> {
        //TODO: For now, there are no checks, but it might be added for NFT
        Ok(())
    }

    // Calc not burned tokens that were placed in OutputValue::TokenTransfer after partial burn
    fn get_change_amount(
        tx: &Transaction,
        burn_token_id: &TokenId,
        block_id: &Id<Block>,
    ) -> Result<Amount, TokensError> {
        let change_amount = tx
            .outputs()
            .iter()
            .filter_map(|x| match x.value() {
                OutputValue::Coin(_) => None,
                OutputValue::Token(asset) => match asset {
                    TokenData::TokenTransferV1 { token_id, amount } => {
                        if token_id == burn_token_id {
                            Some(amount)
                        } else {
                            None
                        }
                    }
                    TokenData::TokenIssuanceV1 {
                        token_ticker: _,
                        amount_to_issue: _,
                        number_of_decimals: _,
                        metadata_uri: _,
                    }
                    | TokenData::TokenBurnV1 {
                        token_id: _,
                        amount_to_burn: _,
                    } => None,
                },
            })
            .try_fold(Amount::from_atoms(0), |accum, output| accum + *output)
            .ok_or_else(|| TokensError::CoinOrTokenOverflow(tx.get_id(), *block_id))?;
        Ok(change_amount)
    }

    fn check_connected_burn_data(
        &self,
        tx: &Transaction,
        block_id: &Id<Block>,
        burn_token_id: &TokenId,
        amount_to_burn: &Amount,
    ) -> Result<(), TokensError> {
        // Collect token inputs
        let total_value_tokens = self
            .calculate_assets_total_inputs(tx.inputs())
            .map_err(|_err| TokensError::NoTokenInInputs(tx.get_id(), *block_id))?;

        // Is token exist in inputs?
        let (_, origin_amount) = total_value_tokens
            .iter()
            .find(|&(origin_token_id, _)| origin_token_id == burn_token_id)
            .ok_or_else(|| TokensError::NoTokenInInputs(tx.get_id(), *block_id))?;

        // Check amount
        ensure!(
            origin_amount >= amount_to_burn,
            TokensError::InsuffienceTokenValueInInputs(tx.get_id(), *block_id)
        );

        // If we burn a piece of the token, we have to check output with the rest tokens
        if origin_amount > amount_to_burn {
            // Check whether all tokens burn and transfer
            ensure!(
                (*amount_to_burn + Self::get_change_amount(tx, burn_token_id, block_id)?)
                    == Some(*origin_amount),
                TokensError::SomeTokensLost(tx.get_id(), *block_id)
            );
        }
        Ok(())
    }

    fn check_connected_assets(
        &self,
        asset: &TokenData,
        tx: &Transaction,
        block: &Block,
    ) -> Result<(), TokensError> {
        match asset {
            TokenData::TokenTransferV1 { token_id, amount } => {
                self.check_connected_transfer_data(block.get_id(), tx, token_id, amount)?;
            }
            TokenData::TokenIssuanceV1 {
                token_ticker,
                amount_to_issue,
                number_of_decimals,
                metadata_uri,
            } => {
                self.check_connected_issue_data(
                    token_ticker,
                    amount_to_issue,
                    number_of_decimals,
                    metadata_uri,
                    tx.get_id(),
                    block.get_id(),
                )?;
            }
            TokenData::TokenBurnV1 {
                token_id,
                amount_to_burn,
            } => {
                self.check_connected_burn_data(tx, &block.get_id(), token_id, amount_to_burn)?;
            }
        }
        Ok(())
    }

    fn check_tokens_values(&self, block: &Block) -> Result<(), StateUpdateError> {
        for tx in block.transactions() {
            // Check assets before connect tx
            tx.outputs()
                .iter()
                .filter_map(|output| match output.value() {
                    OutputValue::Coin(_) => None,
                    OutputValue::Token(asset) => Some(asset),
                })
                .try_for_each(|asset| self.check_connected_assets(asset, tx, block))
                .map_err(StateUpdateError::TokensError)?;

            // If it is not a genesis and in tx issuance
            if self
                .db_tx
                .get_best_block_id()
                .map_err(StateUpdateError::StorageError)?
                .is_some()
                && get_tokens_issuance_count(tx) == TOKEN_MAX_ISSUANCE_ALLOWED
            {
                // check is fee enough for issuance
                ensure!(
                    self.check_transferred_amounts_and_get_fee(tx).map_err(|_| {
                        StateUpdateError::TokensError(TokensError::InsuffienceTokenFees(
                            tx.get_id(),
                            block.get_id(),
                        ))
                    })? >= TOKEN_MIN_ISSUANCE_FEE,
                    StateUpdateError::TokensError(TokensError::InsuffienceTokenFees(
                        tx.get_id(),
                        block.get_id()
                    ),)
                );
            }
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

                // Check tokens values
                self.check_tokens_values(block)?;

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
