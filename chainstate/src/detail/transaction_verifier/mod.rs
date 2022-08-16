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
use self::{cached_operation::CachedTokensOperation, error::ConnectTransactionError};
use cached_operation::CachedInputsOperation;
use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use chainstate_types::GenBlockIndex;
use chainstate_types::TokensError;
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
use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
};
use utils::ensure;

use super::tokens::filter_transferred_and_burn_amounts;
use super::tokens::filter_transferred_and_issued_amounts;

type TokensMap = BTreeMap<TokenId, Amount>;

/// A BlockTransactableRef is a reference to an operation in a block that causes inputs to be spent, outputs to be created, or both
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BlockTransactableRef<'a> {
    Transaction(&'a Block, usize),
    BlockReward(&'a Block),
}

/// The change that a block has caused to the blockchain state
pub struct TransactionVerifierDelta {
    tx_index_data: BTreeMap<OutPointSourceId, CachedInputsOperation>,
    tokens_data: BTreeMap<TokenId, CachedTokensOperation>,
}

/// The tool used to verify transaction and cache their updated states in memory
pub struct TransactionVerifier<'a, S> {
    db_tx: &'a S,
    tx_index_cache: BTreeMap<OutPointSourceId, CachedInputsOperation>,
    tokens_cache: BTreeMap<TokenId, CachedTokensOperation>,
    chain_config: &'a ChainConfig,
}

impl<'a, S> TransactionVerifier<'a, S> {
    pub fn new(db_tx: &'a S, chain_config: &'a ChainConfig) -> Self {
        Self {
            db_tx,
            chain_config,
            tx_index_cache: BTreeMap::new(),
            tokens_cache: BTreeMap::new(),
        }
    }
}

impl<'a, S: BlockchainStorageRead + 'a> TransactionVerifier<'a, S> {
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

    pub fn calculate_transfered_and_burned_tokens(
        outputs: &[TxOutput],
    ) -> Result<TokensMap, TokensError> {
        let mut total_tokens: TokensMap = BTreeMap::new();

        outputs
            .iter()
            .filter_map(|x| match x.value() {
                OutputValue::Coin(_) => None,
                OutputValue::Token(token_data) => filter_transferred_and_burn_amounts(token_data),
            })
            .try_for_each(|(token_id, amount)| {
                total_tokens.insert(
                    token_id,
                    (total_tokens.get(&token_id).cloned().unwrap_or(Amount::from_atoms(0))
                        + amount)
                        .ok_or(TokensError::CoinOrTokenOverflow)?,
                );
                Ok(())
            })?;

        Ok(total_tokens)
    }

    pub fn calculate_tokens_total_inputs(
        &self,
        inputs: &[TxInput],
        token_id: &TokenId,
    ) -> Result<Amount, ConnectTransactionError> {
        let mut total_tokens = Amount::from_atoms(0);
        for input in inputs.iter() {
            let outpoint = input.outpoint();
            let tx_index = self.get_tx_index_from_cache(outpoint)?;
            let output_index = outpoint.output_index() as usize;
            match tx_index.position() {
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

                    let output = tx.outputs().get(output_index).ok_or(
                        ConnectTransactionError::OutputIndexOutOfRange {
                            tx_id: Some(tx.get_id().into()),
                            source_output_index: output_index,
                        },
                    )?;

                    match filter_transferred_and_issued_amounts(&tx, output) {
                        Some((ref input_token_id, amount)) => {
                            if token_id == input_token_id {
                                total_tokens = (total_tokens + amount)
                                    .ok_or(ConnectTransactionError::InputAdditionError)?
                            }
                        }
                        None => { /* In this case, there are no calculations */ }
                    }
                }
                common::chain::SpendablePosition::BlockReward(_block_id) => { /* In this case, there are no calculations */
                }
            }
        }
        Ok(total_tokens)
    }

    fn get_tx_index_from_cache(
        &self,
        outpoint: &OutPoint,
    ) -> Result<&TxMainChainIndex, ConnectTransactionError> {
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
        Ok(tx_index)
    }

    fn calculate_coins_total_inputs(
        &self,
        inputs: &[TxInput],
    ) -> Result<Amount, ConnectTransactionError> {
        let mut total = Amount::from_atoms(0);
        for input in inputs.iter() {
            let outpoint = input.outpoint();
            let tx_index = self.get_tx_index_from_cache(outpoint)?;
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
                OutputValue::Token(_) => { /*For now we don't calculate here tokens, use calculate_tokens_total_inputs */
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
            .try_fold(Amount::from_atoms(0), |accum, out| match out.value() {
                OutputValue::Coin(value) => accum + *value,
                OutputValue::Token(_) => Some(accum),
            })
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

    fn check_connected_burn_data(
        &self,
        tx: &Transaction,
        block_id: &Id<Block>,
        burn_token_id: &TokenId,
        amount_to_burn: &Amount,
    ) -> Result<(), TokensError> {
        // Calculate token inputs
        let origin_amount = self
            .calculate_tokens_total_inputs(tx.inputs(), burn_token_id)
            .map_err(|_err| TokensError::NoTokenInInputs(tx.get_id(), *block_id))?;

        // Check amount
        ensure!(
            origin_amount >= *amount_to_burn,
            TokensError::InsuffienceTokenValueInInputs(tx.get_id(), *block_id)
        );

        // If we burn a piece of the token, we have to check output with the rest tokens
        if origin_amount > *amount_to_burn {
            // Check whether all tokens burn and transfer
            ensure!(
                (*amount_to_burn + Self::get_change_amount(tx, burn_token_id)?)
                    == Some(origin_amount),
                TokensError::SomeTokensLost(tx.get_id(), *block_id)
            );
        }
        Ok(())
    }

    fn check_connected_transfer_data(
        &self,
        block_id: Id<Block>,
        tx: &Transaction,
        token_id: &TokenId,
        token_amount: &Amount,
    ) -> Result<(), TokensError> {
        // Calculate token inputs
        let input_amount = self
            .calculate_tokens_total_inputs(tx.inputs(), token_id)
            .map_err(|_err| TokensError::NoTokenInInputs(tx.get_id(), block_id))?;

        // Is token exist in outputs?
        let total_output_tokens = Self::calculate_transfered_and_burned_tokens(tx.outputs())?;
        let output_amount = total_output_tokens
            .get(token_id)
            .ok_or_else(|| TokensError::SomeTokensLost(tx.get_id(), block_id))?;

        // Check amounts
        ensure!(
            input_amount >= *token_amount,
            TokensError::InsuffienceTokenValueInInputs(tx.get_id(), block_id,)
        );

        ensure!(
            input_amount >= *output_amount,
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
    fn get_change_amount(tx: &Transaction, burn_token_id: &TokenId) -> Result<Amount, TokensError> {
        let change_amount = tx
            .outputs()
            .iter()
            .filter_map(|x| match x.value() {
                OutputValue::Coin(_) => None,
                OutputValue::Token(asset) => match asset {
                    TokenData::TokenTransferV1 { token_id, amount } => {
                        (token_id == burn_token_id).then_some(amount)
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
            .ok_or(TokensError::CoinOrTokenOverflow)?;
        Ok(change_amount)
    }

    fn register_issuance(&mut self, tx: &Transaction) -> Result<(), TokensError> {
        let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;

        let _tokens_op = match self.tokens_cache.entry(token_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(CachedTokensOperation::Write(tx.get_id())),
        };
        Ok(())
    }

    fn undo_issuance(&mut self, token_id: TokenId) -> Result<(), TokensError> {
        match self.tokens_cache.entry(token_id) {
            Entry::Occupied(entry) => {
                let tokens_op = entry.into_mut();
                *tokens_op = CachedTokensOperation::Erase;
            }
            Entry::Vacant(entry) => {
                entry.insert(CachedTokensOperation::Erase);
            }
        }
        Ok(())
    }

    fn check_connected_tokens(
        &mut self,
        token_data: &TokenData,
        tx: &Transaction,
        block: &Block,
    ) -> Result<(), TokensError> {
        match token_data {
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
                self.register_issuance(tx)?;
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

    fn check_tokens_values(&mut self, block: &Block) -> Result<(), ConnectTransactionError> {
        for tx in block.transactions() {
            // Check tokens before connect tx
            tx.outputs()
                .iter()
                .filter_map(|output| match output.value() {
                    OutputValue::Coin(_) => None,
                    OutputValue::Token(token_data) => Some(token_data),
                })
                .try_for_each(|token_data| self.check_connected_tokens(token_data, tx, block))
                .map_err(ConnectTransactionError::TokensError)?;

            if self.is_issuance_in_custom_block(tx)? {
                // check is fee enough for issuance
                ensure!(
                    self.check_transferred_amounts_and_get_fee(tx).map_err(|_| {
                        ConnectTransactionError::TokensError(TokensError::InsuffienceTokenFees(
                            tx.get_id(),
                            block.get_id(),
                        ))
                    })? >= TOKEN_MIN_ISSUANCE_FEE,
                    ConnectTransactionError::TokensError(TokensError::InsuffienceTokenFees(
                        tx.get_id(),
                        block.get_id()
                    ),)
                );
            }
        }
        Ok(())
    }

    fn is_issuance_in_custom_block(
        &mut self,
        tx: &Transaction,
    ) -> Result<bool, ConnectTransactionError> {
        // If it is not a genesis and in tx issuance
        Ok(self
            .db_tx
            .get_best_block_id()
            .map_err(ConnectTransactionError::StorageError)?
            .is_some()
            && get_tokens_issuance_count(tx) == TOKEN_MAX_ISSUANCE_ALLOWED)
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

                // Check tokens values
                self.check_tokens_values(block)?;

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

    fn remove_tokens(&mut self, tx: &Transaction) -> Result<(), ConnectTransactionError> {
        let was_tokens_issued = tx
            .outputs()
            .iter()
            .find_map(|output| match output.value() {
                OutputValue::Coin(_) => None,
                OutputValue::Token(token_data) => match token_data {
                    TokenData::TokenTransferV1 {
                        token_id: _,
                        amount: _,
                    } => None,
                    TokenData::TokenIssuanceV1 {
                        token_ticker: _,
                        amount_to_issue: _,
                        number_of_decimals: _,
                        metadata_uri: _,
                    } => Some(()),
                    TokenData::TokenBurnV1 {
                        token_id: _,
                        amount_to_burn: _,
                    } => None,
                },
            })
            .is_some();
        if was_tokens_issued {
            let token_id = token_id(tx).ok_or(ConnectTransactionError::TokensError(
                TokensError::TokenIdCantBeCalculated,
            ))?;
            self.undo_issuance(token_id)?;
        }
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

                // Remove issued tokens
                self.remove_tokens(tx)?;
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
            tx_index_data: self.tx_index_cache,
            tokens_data: self.tokens_cache,
        })
    }
}

impl<'a, S: BlockchainStorageWrite + 'a> TransactionVerifier<'a, S> {
    fn flush_tx_index_data(
        db_tx: &mut S,
        tx_id: OutPointSourceId,
        tx_index_op: CachedInputsOperation,
    ) -> Result<(), ConnectTransactionError> {
        match tx_index_op {
            CachedInputsOperation::Write(ref tx_index) => {
                db_tx.set_mainchain_tx_index(&tx_id, tx_index)?
            }
            CachedInputsOperation::Read(_) => (),
            CachedInputsOperation::Erase => db_tx.del_mainchain_tx_index(&tx_id)?,
        }
        Ok(())
    }

    fn flush_tokens(
        db_tx: &mut S,
        token_id: TokenId,
        token_op: CachedTokensOperation,
    ) -> Result<(), ConnectTransactionError> {
        match token_op {
            CachedTokensOperation::Write(ref tx_id) => db_tx.set_token_tx(token_id, *tx_id)?,
            CachedTokensOperation::Read(_) => (),
            CachedTokensOperation::Erase => db_tx.del_token_tx(token_id)?,
        }
        Ok(())
    }

    pub fn flush_to_storage(
        db_tx: &mut S,
        input_data: TransactionVerifierDelta,
    ) -> Result<(), ConnectTransactionError> {
        for (tx_id, tx_index_op) in input_data.tx_index_data {
            Self::flush_tx_index_data(db_tx, tx_id, tx_index_op)?;
        }
        for (token_id, token_op) in input_data.tokens_data {
            Self::flush_tokens(db_tx, token_id, token_op)?;
        }
        Ok(())
    }
}

// TODO: write tests for CachedInputs that covers all possible mutations
// TODO: write tests for block rewards
// TODO: test attempting to spend the block reward at the same block
// TODO: test that total_block_reward = total_tx_fees + consensus_block_reward
