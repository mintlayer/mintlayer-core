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
mod tx_index_cache;
use self::{
    amounts_map::AmountsMap,
    error::{ConnectTransactionError, TokensError},
    token_issuance_cache::{CachedTokensOperation, CoinOrTokenId},
    tx_index_cache::TxIndexCache,
    utils::get_output_token_id_and_amount,
};
use ::utils::ensure;
use cached_operation::CachedInputsOperation;
use fallible_iterator::FallibleIterator;

use std::collections::{btree_map::Entry, BTreeMap};

use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use chainstate_types::{BlockIndex, GenBlockIndex, PropertyQueryError};
use common::{
    amount_sum,
    chain::{
        block::timestamp::BlockTimestamp,
        signature::{verify_signature, Transactable},
        tokens::{get_tokens_issuance_count, OutputValue, TokenId},
        Block, ChainConfig, GenBlock, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{id::WithId, Amount, BlockDistance, BlockHeight, Id, Idable},
};
use utxo::{
    BlockRewardUndo, BlockUndo, ConsumedUtxoCache, FlushableUtxoView, TxUndo, Utxo, UtxosCache,
    UtxosDBMut, UtxosView,
};

mod token_issuance_cache;
use self::token_issuance_cache::TokenIssuanceCache;

mod utils;
use self::utils::{check_transferred_amount, get_input_token_id_and_amount};

use super::chainstateref::{block_index_ancestor_getter, gen_block_index_getter};

// TODO: We can move it to mod common, because in chain config we have `token_min_issuance_fee`
//       that essentially belongs to this type, but return Amount
#[derive(PartialEq, Eq, PartialOrd, Ord)]
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
    tokens_data: TokenIssuanceCache,
}

/// The tool used to verify transaction and cache their updated states in memory
pub struct TransactionVerifier<'a, S> {
    chain_config: &'a ChainConfig,
    db_tx: &'a S,
    tx_index_cache: TxIndexCache,
    utxo_cache: UtxosCache<'a>,
    utxo_block_undo: BTreeMap<Id<Block>, BlockUndoEntry>,
    token_issuance_cache: TokenIssuanceCache,
}

// TODO: UtxoDB should be a member of TransactionVerifier and UtxoCache should be constructed from it.
// Investigate how to solve borrows checker lifetime issues with that approach.
impl<'a, S> TransactionVerifier<'a, S> {
    pub fn new(db_tx: &'a S, utxo_cache: UtxosCache<'a>, chain_config: &'a ChainConfig) -> Self {
        Self {
            db_tx,
            chain_config,
            tx_index_cache: TxIndexCache::new(),
            utxo_cache,
            utxo_block_undo: BTreeMap::new(),
            token_issuance_cache: TokenIssuanceCache::new(),
        }
    }
}

impl<'a, S: BlockchainStorageRead> TransactionVerifier<'a, S> {
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
                        Ok(self.db_tx.get_token_id(&tx_id)?)
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
        block_id: Id<Block>,
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
                TokensError::InsufficientTokenFees(tx.get_id(), block_id),
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

    fn verify_signatures<T: Transactable>(
        &self,
        block_index: &BlockIndex,
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
            let utxo = self
                .utxo_cache
                .utxo(outpoint)
                .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;

            // TODO: see if a different treatment should be done for different output purposes
            verify_signature(utxo.output().purpose().destination(), tx, input_idx)
                .map_err(|_| ConnectTransactionError::SignatureVerificationFailed)?;

            {
                let height = match utxo.source() {
                    utxo::UtxoSource::Blockchain(h) => h,
                    utxo::UtxoSource::Mempool => {
                        unreachable!("Mempool utxos can never be reached from storage")
                    }
                };

                let block_index_getter = |_db_tx, _chain_config, id: Id<GenBlock>| {
                    gen_block_index_getter(self.db_tx, self.chain_config, id)
                        .map_err(|_| PropertyQueryError::BlockIndexAtHeightNotFound(*height))
                };

                let block_index = block_index_ancestor_getter(
                    block_index_getter,
                    self.db_tx,
                    self.chain_config,
                    &block_index.clone().into(),
                    *height,
                )
                .map_err(|e| {
                    ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(
                        e, *height,
                    )
                })?;

                self.check_timelock(&block_index, utxo.output(), spend_height, spending_time)?;
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
        block_index: &BlockIndex,
        spend_ref: BlockTransactableRef,
        spend_height: &BlockHeight,
        median_time_past: &BlockTimestamp,
    ) -> Result<Option<Fee>, ConnectTransactionError> {
        let tx_index_fetcher = |tx_id: &OutPointSourceId| {
            self.db_tx.get_mainchain_tx_index(tx_id).map_err(ConnectTransactionError::from)
        };

        let fee = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let block_id = block.get_id();
                let tx = block.transactions().get(tx_num).ok_or(
                    ConnectTransactionError::TxNumWrongInBlockOnConnect(tx_num, block_id),
                )?;

                // pre-cache all inputs
                self.tx_index_cache.precache_inputs(tx.inputs(), tx_index_fetcher)?;

                // pre-cache token ids to check ensure it's not in the db when issuing
                self.token_issuance_cache.precache_token_issuance(
                    |id| self.db_tx.get_token_aux_data(id).map_err(TokensError::from),
                    tx,
                )?;

                // check for attempted money printing
                let fee = Some(self.check_transferred_amounts_and_get_fee(block.get_id(), tx)?);

                // Register tokens if tx has issuance data
                self.token_issuance_cache.register(block.get_id(), tx)?;

                // verify input signatures
                self.verify_signatures(block_index, tx, spend_height, median_time_past)?;

                // spend utxos
                let tx_undo = self
                    .utxo_cache
                    .connect_transaction(tx, *spend_height)
                    .map_err(ConnectTransactionError::from)?;

                // save spent utxos for undo
                self.get_or_create_block_undo(&block_id).push_tx_undo(tx_undo);

                // mark tx index as spent
                let spender = tx.get_id().into();
                self.tx_index_cache.spend_tx_index_inputs(tx.inputs(), spender)?;

                fee
            }
            BlockTransactableRef::BlockReward(block) => {
                let reward_transactable = block.block_reward_transactable();
                // TODO: test spending block rewards from chains outside the mainchain
                if let Some(inputs) = reward_transactable.inputs() {
                    // pre-cache all inputs
                    self.tx_index_cache.precache_inputs(inputs, tx_index_fetcher)?;

                    // verify input signatures
                    self.verify_signatures(
                        block_index,
                        &reward_transactable,
                        spend_height,
                        median_time_past,
                    )?;
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
                    self.tx_index_cache.spend_tx_index_inputs(inputs, block.get_id().into())?;
                }

                fee
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

        let tx_index_fetcher = |tx_id: &OutPointSourceId| {
            self.db_tx.get_mainchain_tx_index(tx_id).map_err(ConnectTransactionError::from)
        };

        match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let block_id = block.get_id();
                let tx = block.transactions().get(tx_num).ok_or(
                    ConnectTransactionError::TxNumWrongInBlockOnDisconnect(tx_num, block_id),
                )?;

                let tx_undo = self.take_tx_undo(&block_id, tx_num)?;
                self.utxo_cache.disconnect_transaction(tx, tx_undo)?;

                // pre-cache all inputs
                self.tx_index_cache.precache_inputs(tx.inputs(), tx_index_fetcher)?;

                // pre-cache token ids before removing them
                self.token_issuance_cache.precache_token_issuance(
                    |id| self.db_tx.get_token_aux_data(id).map_err(TokensError::from),
                    tx,
                )?;

                // unspend inputs
                self.tx_index_cache.unspend_tx_index_inputs(tx.inputs())?;

                // Remove issued tokens
                self.token_issuance_cache.unregister(tx)?;
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

    pub fn consume(self) -> Result<TransactionVerifierDelta, ConnectTransactionError> {
        Ok(TransactionVerifierDelta {
            tx_index: self.tx_index_cache.take(),
            utxo_cache: self.utxo_cache.consume(),
            utxo_block_undo: self.utxo_block_undo,
            tokens_data: self.token_issuance_cache,
        })
    }
}

impl<'a, S: BlockchainStorageWrite + 'a> TransactionVerifier<'a, S> {
    fn flush_tx_indexes(
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
            CachedTokensOperation::Write(ref issuance_tx) => {
                db_tx.set_token_aux_data(&token_id, issuance_tx)?;
                db_tx.set_token_id(&issuance_tx.issuance_tx().get_id(), &token_id)?;
            }
            CachedTokensOperation::Read(_) => (),
            CachedTokensOperation::Erase(issuance_tx) => {
                db_tx.del_token_aux_data(&token_id)?;
                db_tx.del_token_id(&issuance_tx)?;
            }
        }
        Ok(())
    }

    pub fn flush_to_storage(
        db_tx: &mut S,
        consumed: TransactionVerifierDelta,
    ) -> Result<(), ConnectTransactionError> {
        for (tx_id, tx_index_op) in consumed.tx_index {
            Self::flush_tx_indexes(db_tx, tx_id, tx_index_op)?;
        }
        for (token_id, token_op) in consumed.tokens_data.take() {
            Self::flush_tokens(db_tx, token_id, token_op)?;
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
