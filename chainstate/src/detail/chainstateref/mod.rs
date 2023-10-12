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

mod epoch_seal;
mod in_memory_reorg;
mod tx_verifier_storage;

use std::{cmp::max, collections::BTreeSet};
use thiserror::Error;

use chainstate_storage::{
    BlockchainStorageRead, BlockchainStorageWrite, TipStorageTag, TransactionRw,
};
use chainstate_types::{
    block_index_ancestor_getter, get_skip_height, BlockIndex, BlockIndexHandle, BlockStatus,
    BlockValidationStage, EpochData, EpochDataCache, GenBlockIndex, GetAncestorError,
    PropertyQueryError,
};
use common::{
    chain::{
        block::{
            signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp, BlockReward,
            ConsensusData,
        },
        config::EpochIndex,
        tokens::TokenAuxiliaryData,
        tokens::{get_tokens_issuance_count, TokenId},
        AccountNonce, AccountType, Block, ChainConfig, GenBlock, GenBlockId, OutPointSourceId,
        SignedTransaction, TokenOutput, Transaction, TxMainChainIndex, TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, time::Time, BlockDistance, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
    Uint256,
};
use logging::log;
use pos_accounting::{PoSAccountingDB, PoSAccountingDelta, PoSAccountingView};
use tx_verifier::transaction_verifier::{config::TransactionVerifierConfig, TransactionVerifier};
use utils::{ensure, tap_error_log::LogError};
use utxo::{UtxosCache, UtxosDB, UtxosStorageRead, UtxosView};

use crate::{detail::tokens::check_tokens_issuance_versioned, BlockError, ChainstateConfig};

use self::tx_verifier_storage::gen_block_index_getter;

use super::{
    median_time::calculate_median_time_past,
    tokens::check_tokens_data,
    transaction_verifier::{error::TokensError, flush::flush_to_storage},
    tx_verification_strategy::TransactionVerificationStrategy,
    BlockSizeError, CheckBlockError, CheckBlockTransactionsError,
};

pub use epoch_seal::EpochSealError;

pub struct ChainstateRef<'a, S, V> {
    chain_config: &'a ChainConfig,
    chainstate_config: &'a ChainstateConfig,
    tx_verification_strategy: &'a V,
    db_tx: S,
    time_getter: &'a TimeGetter,
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> BlockIndexHandle
    for ChainstateRef<'a, S, V>
{
    fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.get_block_index(block_id)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.get_gen_block_index(block_id)
    }

    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        self.get_ancestor(&GenBlockIndex::Block(block_index.clone()), ancestor_height)
            .map_err(PropertyQueryError::from)
    }

    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        self.get_block_reward(block_index)
    }
}

impl<'a, S: TransactionRw, V> ChainstateRef<'a, S, V> {
    pub fn commit_db_tx(self) -> chainstate_storage::Result<()> {
        self.db_tx.commit()
    }
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> ChainstateRef<'a, S, V> {
    pub fn new_rw(
        chain_config: &'a ChainConfig,
        chainstate_config: &'a ChainstateConfig,
        tx_verification_strategy: &'a V,
        db_tx: S,
        time_getter: &'a TimeGetter,
    ) -> ChainstateRef<'a, S, V> {
        ChainstateRef {
            chain_config,
            chainstate_config,
            db_tx,
            tx_verification_strategy,
            time_getter,
        }
    }

    pub fn new_ro(
        chain_config: &'a ChainConfig,
        chainstate_config: &'a ChainstateConfig,
        tx_verification_strategy: &'a V,
        db_tx: S,
        time_getter: &'a TimeGetter,
    ) -> ChainstateRef<'a, S, V> {
        ChainstateRef {
            chain_config,
            chainstate_config,
            db_tx,
            tx_verification_strategy,
            time_getter,
        }
    }

    pub fn make_utxo_view(&self) -> impl UtxosView<Error = <S as UtxosStorageRead>::Error> + '_ {
        UtxosDB::new(&self.db_tx)
    }

    pub fn make_pos_accounting_view(
        &self,
    ) -> impl PoSAccountingView<Error = pos_accounting::Error> + '_ {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx)
    }

    pub fn chain_config(&self) -> &ChainConfig {
        self.chain_config
    }

    pub fn current_time(&self) -> Time {
        self.time_getter.get_time()
    }

    pub fn get_is_transaction_index_enabled(&self) -> Result<bool, PropertyQueryError> {
        Ok(self
            .db_tx
            .get_is_mainchain_tx_index_enabled()
            .map_err(PropertyQueryError::from)?
            .expect("Must be set on node initialization"))
    }

    pub fn get_best_block_id(&self) -> Result<Id<GenBlock>, PropertyQueryError> {
        self.db_tx
            .get_best_block_id()
            .map_err(PropertyQueryError::from)
            .map(|bid| bid.expect("Best block ID not initialized"))
    }

    pub fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        log::trace!("Loading block index of id: {}", block_id);
        self.db_tx.get_block_index(block_id).map_err(PropertyQueryError::from)
    }

    pub fn get_existing_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<BlockIndex, PropertyQueryError> {
        self.get_block_index(block_id)?
            .ok_or_else(|| PropertyQueryError::BlockIndexNotFound((*block_id).into()))
    }

    pub fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        gen_block_index_getter(&self.db_tx, self.chain_config, block_id)
            .map_err(PropertyQueryError::from)
    }

    pub fn get_best_block_index(&self) -> Result<GenBlockIndex, PropertyQueryError> {
        self.get_gen_block_index(&self.get_best_block_id().log_err()?)
            .log_err()?
            .ok_or(PropertyQueryError::BestBlockIndexNotFound)
    }

    /// Return BlockIndex of the previous block.
    fn get_previous_block_index(
        &self,
        block_index: &BlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let prev_block_id = block_index.prev_block_id();
        self.get_gen_block_index(prev_block_id)
            .log_err()?
            .ok_or(PropertyQueryError::PrevBlockIndexNotFound(*prev_block_id))
    }

    pub fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, PropertyQueryError> {
        log::trace!("Loading transaction index of id: {:?}", tx_id);
        self.db_tx.get_mainchain_tx_index(tx_id).map_err(PropertyQueryError::from)
    }

    pub fn get_transaction_in_block(
        &self,
        id: Id<Transaction>,
    ) -> Result<Option<SignedTransaction>, PropertyQueryError> {
        log::trace!("Loading whether tx index is enabled: {}", id);
        let is_tx_index_enabled = self.get_is_transaction_index_enabled()?;
        if !is_tx_index_enabled {
            return Err(PropertyQueryError::TransactionIndexDisabled);
        }
        log::trace!("Loading transaction index with id: {}", id);
        let tx_index = self.db_tx.get_mainchain_tx_index(&OutPointSourceId::Transaction(id))?;
        let tx_index = match tx_index {
            Some(tx_index) => tx_index,
            None => return Ok(None),
        };
        log::trace!("Loading transaction with id: {}", id);
        let position = match tx_index.position() {
            common::chain::SpendablePosition::Transaction(pos) => pos,
            common::chain::SpendablePosition::BlockReward(_) => {
                panic!("In get_transaction(), a tx id led to a block reward")
            }
        };
        Ok(self.db_tx.get_mainchain_tx_by_position(position)?)
    }

    pub fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, PropertyQueryError> {
        self.db_tx
            .get_block_id_by_height(height)
            .map_err(PropertyQueryError::from)
            .log_err()
    }

    pub fn get_existing_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Id<GenBlock>, PropertyQueryError> {
        self.get_block_id_by_height(height)?
            .ok_or(PropertyQueryError::BlockForHeightNotFound(*height))
            .log_err()
    }

    pub fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.db_tx.get_block(block_id).map_err(PropertyQueryError::from)
    }

    pub fn get_block_header(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<SignedBlockHeader>, PropertyQueryError> {
        Ok(self.db_tx.get_block_header(block_id).log_err()?)
    }

    pub fn is_block_in_main_chain(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<bool, PropertyQueryError> {
        self.get_block_height_in_main_chain(block_id).log_err().map(|ht| ht.is_some())
    }

    pub fn get_min_height_with_allowed_reorg(&self) -> Result<BlockHeight, PropertyQueryError> {
        Ok(self.db_tx.get_min_height_with_allowed_reorg().log_err()?.unwrap_or(0.into()))
    }

    pub fn get_ancestor(
        &self,
        block_index: &GenBlockIndex,
        target_height: BlockHeight,
    ) -> Result<GenBlockIndex, GetAncestorError> {
        block_index_ancestor_getter(
            gen_block_index_getter,
            &self.db_tx,
            self.chain_config,
            block_index.into(),
            target_height,
        )
    }

    /// Obtain the last common ancestor between the specified blocks.
    pub fn last_common_ancestor(
        &self,
        first_block_index: &GenBlockIndex,
        second_block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let mut first_block_index = first_block_index.clone();
        let mut second_block_index = second_block_index.clone();
        match first_block_index.block_height().cmp(&second_block_index.block_height()) {
            std::cmp::Ordering::Greater => {
                first_block_index = self
                    .get_ancestor(&first_block_index, second_block_index.block_height())
                    .log_err()?;
            }
            std::cmp::Ordering::Less => {
                second_block_index = self
                    .get_ancestor(&second_block_index, first_block_index.block_height())
                    .log_err()?;
            }
            std::cmp::Ordering::Equal => {}
        }

        loop {
            match (&first_block_index, &second_block_index) {
                _ if first_block_index.block_id() == second_block_index.block_id() => {
                    break Ok(first_block_index)
                }
                (GenBlockIndex::Block(first_blkidx), GenBlockIndex::Block(second_blkidx)) => {
                    first_block_index = self.get_previous_block_index(first_blkidx).log_err()?;
                    second_block_index = self.get_previous_block_index(second_blkidx).log_err()?;
                }
                _ => panic!("Chain iteration not in lockstep"),
            }
        }
    }

    /// Obtain the last common ancestor between the specified block and the tip of the main chain.
    ///
    /// Note: if the block is itself on the main chain, its own index will be returned, not parent's.
    // TODO: unlike its generic counterpart above, this function may be optimized by taking jumps
    // via get_ancestor instead of the block-by-block iteration (because here the other chain is
    // the main chain and we can always check whether we've reached it).
    pub fn last_common_ancestor_in_main_chain(
        &self,
        block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let best_block_index = self.get_best_block_index().log_err()?;
        self.last_common_ancestor(block_index, &best_block_index)
    }

    pub fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, PropertyQueryError> {
        self.db_tx.get_token_aux_data(token_id).map_err(PropertyQueryError::from)
    }

    pub fn get_token_id(
        &self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<TokenId>, PropertyQueryError> {
        self.db_tx.get_token_id(tx_id).map_err(PropertyQueryError::from)
    }

    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<SignedBlockHeader>, PropertyQueryError> {
        let id = self.get_existing_block_id_by_height(height).log_err()?;
        let id = id
            .classify(self.chain_config)
            .chain_block_id()
            .ok_or(PropertyQueryError::GenesisHeaderRequested)
            .log_err()?;
        Ok(self
            .get_block_index(&id)
            .log_err()?
            .map(|block_index| block_index.into_block_header()))
    }

    pub fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        Ok(self.db_tx.get_block_reward(block_index).log_err()?)
    }

    pub fn get_epoch_data(
        &self,
        epoch_index: EpochIndex,
    ) -> Result<Option<EpochData>, PropertyQueryError> {
        self.db_tx.get_epoch_data(epoch_index).map_err(PropertyQueryError::from)
    }

    pub fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, PropertyQueryError> {
        self.db_tx.get_account_nonce_count(account).map_err(PropertyQueryError::from)
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        let gen_id = id;
        let id = match gen_id.classify(self.chain_config) {
            GenBlockId::Block(id) => id,
            GenBlockId::Genesis(_) => return Ok(Some(BlockHeight::zero())),
        };

        let block_index = self.get_block_index(&id).log_err()?;
        let block_index = block_index.ok_or(PropertyQueryError::BlockNotFound(id)).log_err()?;
        let mainchain_block_id = self.get_block_id_by_height(&block_index.block_height())?;

        // Note: this function may be called when the chain is still empty, so we don't unwrap
        // mainchain_block_id and wrap gen_id instead.
        if mainchain_block_id.as_ref() == Some(gen_id) {
            Ok(Some(block_index.block_height()))
        } else {
            Ok(None)
        }
    }

    // Get indexes for a new longest chain
    fn get_new_chain(
        &self,
        new_tip_block_index: &BlockIndex,
    ) -> Result<Vec<BlockIndex>, PropertyQueryError> {
        let mut result = Vec::new();
        let mut block_index = new_tip_block_index.clone();
        while !self.is_block_in_main_chain(&(*block_index.block_id()).into()).log_err()? {
            result.push(block_index.clone());
            block_index = match self.get_previous_block_index(&block_index).log_err()? {
                GenBlockIndex::Genesis(_) => break,
                GenBlockIndex::Block(blkidx) => blkidx,
            }
        }
        result.reverse();
        Ok(result)
    }

    fn enforce_checkpoints(&self, header: &SignedBlockHeader) -> Result<(), CheckBlockError> {
        let prev_block_index = self.get_previous_block_index_for_check_block(header)?;
        let current_height = prev_block_index.block_height().next_height();

        // If the block height is at the exact checkpoint height, we need to check that the block id matches the checkpoint id
        if let Some(e) =
            self.chain_config.height_checkpoints().checkpoint_at_height(&current_height)
        {
            let expected_id = Id::<Block>::new(e.to_hash());
            if expected_id != header.get_id() {
                return Err(CheckBlockError::CheckpointMismatch(
                    expected_id,
                    header.get_id(),
                ));
            }
        }

        // If the block height does not match a checkpoint height, we need to check that an ancestor block id matches the checkpoint id
        let (expected_checkpoint_height, expected_checkpoint_id) = self
            .chain_config
            .height_checkpoints()
            .parent_checkpoint_to_height(current_height);

        let parent_checkpoint_block_index =
            self.get_ancestor(&prev_block_index, expected_checkpoint_height)?;

        let parent_checkpoint_id = parent_checkpoint_block_index.block_id();

        if parent_checkpoint_id != expected_checkpoint_id {
            return Err(CheckBlockError::ParentCheckpointMismatch(
                expected_checkpoint_height,
                expected_checkpoint_id,
                parent_checkpoint_id,
            ));
        }

        Ok(())
    }

    fn check_block_height_vs_max_reorg_depth(
        &self,
        header: &SignedBlockHeader,
    ) -> Result<(), CheckBlockError> {
        let prev_block_index = self.get_previous_block_index_for_check_block(header)?;
        let common_ancestor_height =
            self.last_common_ancestor_in_main_chain(&prev_block_index)?.block_height();
        let min_allowed_height = self.get_min_height_with_allowed_reorg()?;

        if common_ancestor_height < min_allowed_height {
            let tip_block_height = self.get_best_block_index()?.block_height();

            return Err(CheckBlockError::AttemptedToAddBlockBeforeReorgLimit(
                common_ancestor_height,
                tip_block_height,
                min_allowed_height,
            ));
        }

        Ok(())
    }

    /// Return BlockIndex of the previous block.
    fn get_previous_block_index_for_check_block(
        &self,
        block_header: &SignedBlockHeader,
    ) -> Result<GenBlockIndex, CheckBlockError> {
        let prev_block_id = block_header.prev_block_id();
        self.get_gen_block_index(prev_block_id)?
            .ok_or(CheckBlockError::PrevBlockNotFound(
                *prev_block_id,
                block_header.get_id(),
            ))
    }

    /// Return Ok(()) if the specified block has a valid parent and an error otherwise.
    pub fn check_block_parent(
        &self,
        block_header: &SignedBlockHeader,
    ) -> Result<(), CheckBlockError> {
        let parent_block_index = self.get_previous_block_index_for_check_block(block_header)?;

        ensure!(
            parent_block_index.status().is_ok(),
            CheckBlockError::InvalidParent(block_header.block_id())
        );

        Ok(())
    }

    pub fn check_block_header(&self, header: &SignedBlockHeader) -> Result<(), CheckBlockError> {
        self.check_block_parent(header).log_err()?;
        self.check_header_size(header).log_err()?;
        self.enforce_checkpoints(header).log_err()?;
        self.check_block_height_vs_max_reorg_depth(header)?;

        let utxos_db = UtxosDB::new(&self.db_tx);
        let pos_db = PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx);

        let is_pos = match header.consensus_data() {
            ConsensusData::None | ConsensusData::PoW(_) => false,
            ConsensusData::PoS(_) => true,
        };
        let (utxos_cache, pos_delta, epoch_data_cache) = if is_pos {
            // Validating PoS blocks in branches requires utxo set, accounting info and epoch data
            // that should be updated by doing a reorg beforehand.
            // It will be a no-op for attaching a block to the tip.
            let best_block_id = self.get_best_block_id()?;
            let (verifier_delta, consumed_epoch_data) =
                self.reorganize_in_memory(header.header(), best_block_id)?;
            let (consumed_utxos, consumed_deltas) = verifier_delta.consume();

            let utxos_cache =
                UtxosCache::from_data(&utxos_db, consumed_utxos).expect("should not fail");
            let pos_delta = PoSAccountingDelta::from_data(&pos_db, consumed_deltas);
            let epoch_data_cache = EpochDataCache::from_data(&self.db_tx, consumed_epoch_data);
            (utxos_cache, pos_delta, epoch_data_cache)
        } else {
            let utxos_cache = UtxosCache::new(&utxos_db).expect("should not fail");
            let pos_delta = PoSAccountingDelta::new(&pos_db);
            let epoch_data_cache = EpochDataCache::new(&self.db_tx);
            (utxos_cache, pos_delta, epoch_data_cache)
        };

        consensus::validate_consensus(
            self.chain_config,
            header,
            self,
            &epoch_data_cache,
            &utxos_cache,
            &pos_delta,
        )
        .map_err(CheckBlockError::ConsensusVerificationFailed)
        .log_err()?;

        // This enforces the minimum accepted timestamp for the block. Depending on the consensus algorithm,
        // there might be extra checks. For example, PoS requires the timestamp to be greater the previous
        // block's timestamp.
        let median_time_past = calculate_median_time_past(self, header.prev_block_id());
        ensure!(
            header.timestamp() >= median_time_past,
            CheckBlockError::BlockTimeOrderInvalid(header.timestamp(), median_time_past),
        );

        let max_future_offset = self.chain_config.max_future_block_time_offset();
        let current_time = self.current_time().as_duration_since_epoch();
        let block_timestamp = header.timestamp();
        ensure!(
            block_timestamp.as_duration_since_epoch() <= current_time + *max_future_offset,
            CheckBlockError::BlockFromTheFuture,
        );
        Ok(())
    }

    fn check_block_reward_maturity_settings(&self, block: &Block) -> Result<(), CheckBlockError> {
        block
            .block_reward()
            .outputs()
            .iter()
            .enumerate()
            .try_for_each(|(index, output)| {
                let required = match block.consensus_data() {
                    ConsensusData::None => {
                        self.chain_config.empty_consensus_reward_maturity_distance()
                    }
                    ConsensusData::PoW(_) => {
                        self.chain_config.get_proof_of_work_config().reward_maturity_distance()
                    }
                    ConsensusData::PoS(_) => BlockDistance::new(0),
                };

                match block.consensus_data() {
                    ConsensusData::None | ConsensusData::PoW(_) => match output {
                        TxOutput::LockThenTransfer(_, _, tl) => {
                            let outpoint = UtxoOutPoint::new(block.get_id().into(), index as u32);
                            tx_verifier::timelock_check::check_output_maturity_setting(
                                tl, required, outpoint,
                            )
                            .map_err(CheckBlockError::BlockRewardMaturityError)
                        }
                        TxOutput::Transfer(_, _)
                        | TxOutput::CreateStakePool(_, _)
                        | TxOutput::ProduceBlockFromStake(_, _)
                        | TxOutput::Burn(_)
                        | TxOutput::CreateDelegationId(_, _)
                        | TxOutput::DelegateStaking(_, _)
                        | TxOutput::Tokens(_) => Err(
                            CheckBlockError::InvalidBlockRewardOutputType(block.get_id()),
                        ),
                    },
                    ConsensusData::PoS(_) => {
                        match output {
                            // The output can be reused in block reward right away
                            TxOutput::ProduceBlockFromStake(_, _) => Ok(()),
                            TxOutput::Transfer(_, _)
                            | TxOutput::LockThenTransfer(_, _, _)
                            | TxOutput::CreateStakePool(_, _)
                            | TxOutput::Burn(_)
                            | TxOutput::CreateDelegationId(_, _)
                            | TxOutput::DelegateStaking(_, _)
                            | TxOutput::Tokens(_) => Err(
                                CheckBlockError::InvalidBlockRewardOutputType(block.get_id()),
                            ),
                        }
                    }
                }
            })
    }

    fn check_header_size(&self, header: &SignedBlockHeader) -> Result<(), BlockSizeError> {
        let size = header.header_size();
        ensure!(
            size <= self.chain_config.max_block_header_size(),
            BlockSizeError::Header(size, self.chain_config.max_block_header_size())
        );

        Ok(())
    }

    fn check_block_size(&self, block: &Block) -> Result<(), BlockSizeError> {
        let block_size = block.block_size();

        ensure!(
            block_size.size_from_header() <= self.chain_config.max_block_header_size(),
            BlockSizeError::Header(
                block_size.size_from_header(),
                self.chain_config.max_block_header_size()
            )
        );

        ensure!(
            block_size.size_from_txs() <= self.chain_config.max_block_size_from_std_scripts(),
            BlockSizeError::SizeOfTxs(
                block_size.size_from_txs(),
                self.chain_config.max_block_size_from_std_scripts()
            )
        );

        ensure!(
            block_size.size_from_smart_contracts()
                <= self.chain_config.max_block_size_from_smart_contracts(),
            BlockSizeError::SizeOfSmartContracts(
                block_size.size_from_smart_contracts(),
                self.chain_config.max_block_size_from_smart_contracts()
            )
        );

        Ok(())
    }

    fn check_witness_count(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        for tx in block.transactions() {
            ensure!(
                tx.inputs().len() == tx.signatures().len(),
                CheckBlockTransactionsError::InvalidWitnessCount
            )
        }
        Ok(())
    }

    fn check_duplicate_inputs(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // check for duplicate inputs (see CVE-2018-17144)
        let mut block_inputs = BTreeSet::new();
        for tx in block.transactions() {
            if tx.inputs().is_empty() || tx.outputs().is_empty() {
                return Err(
                    CheckBlockTransactionsError::EmptyInputsOutputsInTransactionInBlock(
                        tx.transaction().get_id(),
                        block.get_id(),
                    ),
                );
            }
            let mut tx_inputs = BTreeSet::new();
            for input in tx.inputs() {
                ensure!(
                    tx_inputs.insert(input),
                    CheckBlockTransactionsError::DuplicateInputInTransaction(
                        tx.transaction().get_id(),
                        block.get_id()
                    )
                );
                ensure!(
                    block_inputs.insert(input),
                    CheckBlockTransactionsError::DuplicateInputInBlock(block.get_id())
                );
            }
        }
        Ok(())
    }

    fn check_tokens_txs(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // FIXME: check tokens versions
        for tx in block.transactions() {
            // We can't issue multiple tokens in a single tx
            let issuance_count = get_tokens_issuance_count(tx.outputs());
            ensure!(
                issuance_count <= 1,
                CheckBlockTransactionsError::TokensError(
                    TokensError::MultipleTokenIssuanceInTransaction(
                        tx.transaction().get_id(),
                        block.get_id()
                    ),
                )
            );

            // Check tokens
            tx.outputs()
                .iter()
                .try_for_each(|output| match output {
                    TxOutput::Transfer(v, _)
                    | TxOutput::LockThenTransfer(v, _, _)
                    | TxOutput::Burn(v) => {
                        if let Some(token_data) = v.token_data() {
                            check_tokens_data(
                                self.chain_config,
                                token_data,
                                tx.transaction(),
                                block.get_id(),
                            )?;
                        }
                        Ok(())
                    }
                    TxOutput::Tokens(token_output) => match token_output {
                        TokenOutput::TokenIssuance(issuance) => {
                            check_tokens_issuance_versioned(self.chain_config, issuance.as_ref())
                                .map_err(|e| {
                                    TokensError::IssueError(
                                        e,
                                        tx.transaction().get_id(),
                                        block.get_id(),
                                    )
                                })
                        }
                        TokenOutput::IncreaseSupply(_, _)
                        | TokenOutput::DecreaseSupply(_, _)
                        | TokenOutput::LockSupply(_) => Ok(()),
                    },
                    TxOutput::CreateStakePool(_, _)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::DelegateStaking(_, _) => Ok(()),
                })
                .map_err(CheckBlockTransactionsError::TokensError)
                .log_err()?;
        }
        Ok(())
    }

    fn check_no_signature_size(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        for tx in block.transactions() {
            for signature in tx.signatures() {
                match signature {
                    common::chain::signature::inputsig::InputWitness::NoSignature(data) => {
                        if let Some(inner_data) = data {
                            ensure!(
                                inner_data.len() <= self.chain_config.max_no_signature_data_size(),
                                CheckBlockTransactionsError::NoSignatureDataSizeTooLarge(
                                    inner_data.len(),
                                    self.chain_config.max_no_signature_data_size(),
                                )
                            )
                        }
                    }
                    common::chain::signature::inputsig::InputWitness::Standard(_) => (),
                }
            }
        }
        Ok(())
    }

    fn check_transactions(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // Note: duplicate txs are detected through duplicate inputs
        self.check_witness_count(block).log_err()?;
        self.check_duplicate_inputs(block).log_err()?;
        self.check_tokens_txs(block).log_err()?;
        self.check_no_signature_size(block).log_err()?;
        Ok(())
    }

    fn get_block_from_index(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<Block>, chainstate_storage::Error> {
        self.db_tx.get_block(*block_index.block_id()).log_err()
    }

    pub fn check_block(&self, block: &WithId<Block>) -> Result<(), CheckBlockError> {
        self.check_block_header(block.header()).log_err()?;

        self.check_block_size(block)
            .map_err(CheckBlockError::BlockSizeError)
            .log_err()?;

        self.check_block_reward_maturity_settings(block).log_err()?;

        let merkle_proxy = block
            .body()
            .merkle_tree_proxy()
            .map_err(|e| CheckBlockError::MerkleRootCalculationFailed(block.get_id(), e))
            .log_err()?;

        {
            // Merkle root
            let merkle_tree_root = block.merkle_root();
            ensure!(
                merkle_tree_root == merkle_proxy.merkle_tree().root(),
                CheckBlockError::MerkleRootMismatch
            );
        }
        {
            // Witness merkle root
            let witness_merkle_root = block.witness_merkle_root();
            ensure!(
                witness_merkle_root == merkle_proxy.witness_merkle_tree().root(),
                CheckBlockError::MerkleRootMismatch
            );
        }

        self.check_transactions(block)
            .map_err(CheckBlockError::CheckTransactionFailed)
            .log_err()?;

        Ok(())
    }

    fn get_block_proof(
        &self,
        prev_block_timestamp: BlockTimestamp,
        block: &Block,
    ) -> Result<Uint256, BlockError> {
        block
            .header()
            .consensus_data()
            .get_block_proof(prev_block_timestamp, block.timestamp())
            .ok_or_else(|| BlockError::BlockProofCalculationError(block.get_id()))
    }

    pub fn get_mainchain_blocks_list(&self) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        let id_from_height = |block_height: u64| -> Result<Id<Block>, PropertyQueryError> {
            let block_height: BlockHeight = block_height.into();
            let block_id = self
                .get_block_id_by_height(&block_height)
                .log_err()?
                .expect("Since block_height is >= best_height, this must exist");
            let block_id = block_id
                .classify(self.chain_config)
                .chain_block_id()
                .expect("Since the height is never zero, this cannot be genesis");
            Ok(block_id)
        };

        let best_block_index = self.get_best_block_index().log_err()?;
        let best_height = best_block_index.block_height();
        let best_height_int: u64 = best_height.into();
        let mut result = Vec::with_capacity(best_height_int as usize);
        for block_height in 1..=best_height_int {
            result.push(id_from_height(block_height).log_err()?);
        }
        Ok(result)
    }

    pub fn get_block_id_tree_as_list(&self) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        self.get_higher_block_ids_sorted_by_height(0.into())
    }

    /// Return ids of all blocks with height bigger than the specified one,
    /// sorted by height (lower first).
    // TODO: this function iterates over all block indices in the DB, which is too expensive
    // for places where it's currently used (such as block invalidation or best chain selection).
    // We need either to optimize it or replace it with some other solution.
    // See https://github.com/mintlayer/mintlayer-core/issues/1033, item #5.
    pub fn get_higher_block_ids_sorted_by_height(
        &self,
        start_from: BlockHeight,
    ) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        let block_tree_map = self.db_tx.get_block_tree_by_height(start_from).log_err()?;
        let result = block_tree_map
            .into_iter()
            .flat_map(|(_height, ids_per_height)| ids_per_height)
            .collect();
        Ok(result)
    }

    /// Collect block indices corresponding to the branch starting at root_block_id.
    /// The first block index in the result will correspond to root_block_id.
    pub fn collect_block_indices_in_branch(
        &self,
        root_block_id: &Id<Block>,
    ) -> Result<Vec<BlockIndex>, PropertyQueryError> {
        let root_block_index = self.get_existing_block_index(root_block_id).log_err()?;

        let next_block_height = root_block_index.block_height().next_height();
        let maybe_descendant_block_ids =
            self.get_higher_block_ids_sorted_by_height(next_block_height)?;

        let mut result = Vec::new();
        let mut seen_block_ids = BTreeSet::new();
        seen_block_ids.insert(*root_block_index.block_id());
        result.push(root_block_index);

        for cur_block_id in maybe_descendant_block_ids {
            let cur_block_index = self.get_existing_block_index(&cur_block_id).log_err()?;

            let prev_block_id = cur_block_index
                .prev_block_id()
                .classify(self.chain_config)
                .chain_block_id()
                .expect("Genesis at non-zero height");

            if seen_block_ids.contains(&prev_block_id) {
                result.push(cur_block_index);
                seen_block_ids.insert(cur_block_id);
            }
        }

        Ok(result)
    }

    pub fn create_block_index_for_new_block(
        &self,
        block: &WithId<Block>,
        block_status: BlockStatus,
    ) -> Result<BlockIndex, BlockError> {
        let prev_block_id = block.header().prev_block_id();
        let prev_block_index = self
            .get_gen_block_index(prev_block_id)
            .map_err(|err| BlockError::BlockIndexQueryError(*prev_block_id, err))?
            .ok_or(BlockError::PrevBlockNotFoundForNewBlock(block.get_id()))?;

        // Set the block height
        let height = prev_block_index.block_height().next_height();

        let some_ancestor = {
            let skip_ht = get_skip_height(height);
            let err = |_| panic!("Ancestor retrieval failed for block: {}", block.get_id());
            self.get_ancestor(&prev_block_index, skip_ht).unwrap_or_else(err).block_id()
        };

        // Set Time Max
        let time_max = std::cmp::max(prev_block_index.chain_timestamps_max(), block.timestamp());

        let current_block_proof =
            self.get_block_proof(prev_block_index.block_timestamp(), block).log_err()?;

        // Set Chain Trust
        let prev_block_chaintrust: Uint256 = prev_block_index.chain_trust();
        let chain_trust = (prev_block_chaintrust + current_block_proof)
            .expect("Chain trust growth is locally controlled. This can't happen.");
        let block_index = BlockIndex::new(
            block,
            chain_trust,
            some_ancestor,
            height,
            time_max,
            block_status,
        );
        Ok(block_index)
    }
}

impl<'a, S: BlockchainStorageWrite, V: TransactionVerificationStrategy> ChainstateRef<'a, S, V> {
    pub fn disconnect_until(
        &mut self,
        cur_tip_block_id: &Id<Block>,
        last_to_remain_connected: &Id<GenBlock>,
    ) -> Result<(), BlockError> {
        let mut block_id_to_disconnect: Id<GenBlock> = (*cur_tip_block_id).into();

        while block_id_to_disconnect != *last_to_remain_connected {
            let cur_block_id = match block_id_to_disconnect.classify(self.chain_config) {
                GenBlockId::Genesis(_) => panic!("Attempt to disconnect genesis"),
                GenBlockId::Block(id) => id,
            };

            let previous_block_index = self.disconnect_tip(Some(&cur_block_id)).log_err()?;
            block_id_to_disconnect = previous_block_index.block_id();
        }
        Ok(())
    }

    fn reorganize(
        &mut self,
        best_block_id: &Id<GenBlock>,
        new_block_index: &BlockIndex,
    ) -> Result<(), ReorgError> {
        let new_chain = self
            .get_new_chain(new_block_index)
            .map_err(|e| {
                BlockError::InvariantErrorFailedToFindNewChainPath(
                    (*new_block_index.block_id()).into(),
                    *best_block_id,
                    e,
                )
            })
            .log_err()?;
        debug_assert!(!new_chain.is_empty()); // there has to always be at least one new block

        let common_ancestor_id = {
            let err = "This vector cannot be empty since there is at least one block to connect";
            let first_block = new_chain.first().expect(err);
            first_block.prev_block_id()
        };

        // Disconnect the current chain if it is not a genesis
        if let GenBlockId::Block(best_block_id) = best_block_id.classify(self.chain_config) {
            // Disconnect blocks
            self.disconnect_until(&best_block_id, common_ancestor_id).log_err()?;
        }

        // Connect the new chain
        for block_index in new_chain {
            let block: WithId<Block> = self
                .get_block_from_index(&block_index)
                .map_err(BlockError::StorageError)
                .log_err()?
                .ok_or_else(|| {
                    // Note: missing block data is an expected situation; it can happen if
                    // the block was initially considered invalid, so its block data was never
                    // saved, but later its bad status flags were reset.
                    // TODO:
                    // 1) Block data existence check should be moved into connect_tip,
                    // so that it happens after check_block (or we should move the call
                    // of check_block out of connect_tip). The caller code will then be able
                    // to determine that block data is missing for a potentially valid block,
                    // and trigger its re-download.
                    // 2) Right now, all callers handle BlockDataMissing by invalidating the
                    // corresponding block subtree, because currently there is no way of getting
                    // the missing block data again. But once we have a mechanism for triggering
                    // block re-downloading, this behavior must be changed: instead, we should
                    // trigger the re-downloading and completely ignore the subtree during
                    // the current operation.
                    // Alternatively, we can just remove the previously invalid block indices
                    // instead of resetting their statuses.
                    // See https://github.com/mintlayer/mintlayer-core/issues/1033, item #4.
                    ReorgError::BlockDataMissing(*block_index.block_id())
                })
                .log_err()?
                .into();

            self.connect_tip(&block_index, &block)
                .map_err(|err| ReorgError::ConnectTipFailed(*block_index.block_id(), err))
                .log_err()?;
        }

        Ok(())
    }

    fn connect_transactions(
        &mut self,
        block_index: &BlockIndex,
        block: &WithId<Block>,
    ) -> Result<(), BlockError> {
        // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
        let median_time_past = calculate_median_time_past(self, &block.prev_block_id());

        let verifier_config = TransactionVerifierConfig {
            tx_index_enabled: *self.chainstate_config.tx_index_enabled,
        };
        let connected_txs = self
            .tx_verification_strategy
            .connect_block(
                TransactionVerifier::new,
                &*self,
                self.chain_config,
                verifier_config,
                block_index,
                block,
                median_time_past,
            )
            .log_err()?;

        let consumed = connected_txs.consume()?;
        flush_to_storage(self, consumed)?;

        Ok(())
    }

    fn disconnect_transactions(&mut self, block: &WithId<Block>) -> Result<(), BlockError> {
        let verifier_config = TransactionVerifierConfig {
            tx_index_enabled: *self.chainstate_config.tx_index_enabled,
        };
        let cached_inputs = self.tx_verification_strategy.disconnect_block(
            TransactionVerifier::new,
            &*self,
            self.chain_config,
            verifier_config,
            block,
        )?;
        let cached_inputs = cached_inputs.consume()?;
        flush_to_storage(self, cached_inputs)?;

        Ok(())
    }

    // Connect new block
    fn connect_tip(
        &mut self,
        new_tip_block_index: &BlockIndex,
        new_tip: &WithId<Block>,
    ) -> Result<(), BlockError> {
        let new_tip_status = {
            let mut new_tip_status = new_tip_block_index.status();
            ensure!(
                new_tip_status.is_ok(),
                BlockError::InvariantErrorAttemptToConnectInvalidBlock(new_tip.get_id().into())
            );

            if new_tip_status.last_valid_stage() < BlockValidationStage::CheckBlockOk {
                self.check_block(new_tip)?;
                new_tip_status.advance_validation_stage_to(BlockValidationStage::CheckBlockOk);
            }

            new_tip_status
        };

        let best_block_id =
            self.get_best_block_id().map_err(BlockError::BestBlockIdQueryError).log_err()?;
        utils::ensure!(
            &best_block_id == new_tip_block_index.prev_block_id(),
            BlockError::InvariantErrorInvalidTip(new_tip.get_id().into()),
        );

        self.connect_transactions(new_tip_block_index, new_tip).log_err()?;

        self.db_tx
            .set_block_id_at_height(
                &new_tip_block_index.block_height(),
                &(*new_tip_block_index.block_id()).into(),
            )
            .log_err()?;
        self.db_tx
            .set_best_block_id(&(*new_tip_block_index.block_id()).into())
            .log_err()?;

        if new_tip_block_index.status().last_valid_stage() != BlockValidationStage::FullyChecked {
            let mut new_tip_status = new_tip_status;
            new_tip_status.advance_validation_stage_to(BlockValidationStage::FullyChecked);
            let new_block_index = new_tip_block_index.clone().with_status(new_tip_status);
            self.set_block_index(&new_block_index)?;
        }

        self.post_connect_tip(new_tip_block_index, new_tip.as_ref()).log_err()
    }

    /// Does a read-modify-write operation on the database and disconnects a block
    /// by unsetting the `next` pointer.
    /// Returns the previous block (the last block in the main-chain)
    fn disconnect_tip(
        &mut self,
        expected_tip_block_id: Option<&Id<Block>>,
    ) -> Result<GenBlockIndex, BlockError> {
        let best_block_id = self
            .get_best_block_id()
            .expect("Best block not initialized")
            .classify(self.chain_config)
            .chain_block_id()
            .expect("Cannot disconnect genesis");

        // Optionally, we can double-check that the tip is what we're disconnecting
        if let Some(expected_tip_block_id) = expected_tip_block_id {
            debug_assert_eq!(expected_tip_block_id, &best_block_id);
        }

        let block_index = self
            .get_block_index(&best_block_id)
            .expect("Database error on retrieving current best block index")
            .expect("Best block index not present in the database");
        let block = self.get_block_from_index(&block_index).log_err()?.expect("Inconsistent DB");
        // Disconnect transactions
        self.disconnect_transactions(&block.into()).log_err()?;
        self.db_tx.set_best_block_id(block_index.prev_block_id()).log_err()?;
        // Disconnect block
        self.db_tx.del_block_id_at_height(&block_index.block_height()).log_err()?;

        let prev_block_index = self
            .get_previous_block_index(&block_index)
            .expect("Previous block index retrieval failed");

        self.post_disconnect_tip(prev_block_index.block_height()).log_err()?;
        Ok(prev_block_index)
    }

    /// Perform a reorg to the specified block if needed.
    /// Return true if the reorg has been performed, and false otherwise.
    pub fn activate_best_chain(
        &mut self,
        new_block_index: &BlockIndex,
    ) -> Result<bool, ReorgError> {
        let current_best_block_index = self
            .get_best_block_index()
            .map_err(BlockError::BestBlockIndexQueryError)
            .log_err()?;

        if new_block_index.chain_trust() > current_best_block_index.chain_trust() {
            // Chain trust is higher than the best block
            self.reorganize(&current_best_block_index.block_id(), new_block_index)
                .log_err()?;
            return Ok(true);
        }

        Ok(false)
    }

    pub fn persist_block(&mut self, block: &WithId<Block>) -> Result<(), BlockError> {
        if (self.db_tx.get_block(block.get_id()).map_err(BlockError::from).log_err()?).is_some() {
            return Err(BlockError::BlockAlreadyExists(block.get_id()));
        }

        self.db_tx.add_block(block).map_err(BlockError::from).log_err()
    }

    pub fn set_block_index(&mut self, block_index: &BlockIndex) -> Result<(), BlockError> {
        self.db_tx.set_block_index(block_index).map_err(BlockError::from).log_err()
    }

    pub fn set_new_block_index(&mut self, block_index: &BlockIndex) -> Result<(), BlockError> {
        if self.db_tx.get_block_index(block_index.block_id()).log_err()?.is_some() {
            return Err(BlockError::BlockAlreadyExists(*block_index.block_id()));
        }
        self.set_block_index(block_index).log_err()
    }

    /// Update the status of the passed `block_index`.
    /// If a BlockIndex already exists for this block, it must be equal to `block_index`.
    pub fn update_block_status(
        &mut self,
        block_index: BlockIndex,
        block_status: BlockStatus,
    ) -> Result<(), BlockError> {
        #[cfg(debug_assertions)]
        if let Some(existing_block_index) =
            self.db_tx.get_block_index(block_index.block_id()).log_err()?
        {
            assert!(existing_block_index == block_index);
        }

        self.set_block_index(&block_index.with_status(block_status)).log_err()
    }

    fn calc_min_height_with_allowed_reorg(&self, current_tip_height: BlockHeight) -> BlockHeight {
        let result = current_tip_height - self.chain_config.max_depth_for_reorg();
        result.unwrap_or(0.into())
    }

    pub fn update_min_height_with_allowed_reorg(&mut self) -> Result<(), BlockError> {
        let stored_min_height = self
            .get_min_height_with_allowed_reorg()
            .map_err(BlockError::MinHeightForReorgQueryError)?;
        let current_tip_height = self
            .get_best_block_index()
            .map_err(BlockError::BestBlockIndexQueryError)?
            .block_height();
        let calculated_min_height = self.calc_min_height_with_allowed_reorg(current_tip_height);
        self.db_tx
            .set_min_height_with_allowed_reorg(max(stored_min_height, calculated_min_height))?;
        Ok(())
    }

    fn post_connect_tip(&mut self, tip_index: &BlockIndex, tip: &Block) -> Result<(), BlockError> {
        let tip_height = tip_index.block_height();
        epoch_seal::update_epoch_seal(
            &mut self.db_tx,
            self.chain_config,
            epoch_seal::BlockStateEvent::Connect(tip_height),
        )?;
        let mut epoch_data_cache = EpochDataCache::new(&self.db_tx);
        let pos_db = PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx);
        epoch_seal::update_epoch_data(
            &mut epoch_data_cache,
            &pos_db,
            self.chain_config,
            epoch_seal::BlockStateEventWithIndex::Connect(tip_height, tip),
        )?;

        let consumed_epoch_data = epoch_data_cache.consume();
        consumed_epoch_data.flush(&mut self.db_tx)?;
        Ok(())
    }

    fn post_disconnect_tip(&mut self, tip_height: BlockHeight) -> Result<(), BlockError> {
        epoch_seal::update_epoch_seal(
            &mut self.db_tx,
            self.chain_config,
            epoch_seal::BlockStateEvent::Disconnect(tip_height),
        )?;

        let mut epoch_data_cache = EpochDataCache::new(&self.db_tx);
        let pos_db = PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx);
        epoch_seal::update_epoch_data(
            &mut epoch_data_cache,
            &pos_db,
            self.chain_config,
            epoch_seal::BlockStateEventWithIndex::Disconnect(tip_height),
        )?;

        let consumed_epoch_data = epoch_data_cache.consume();
        consumed_epoch_data.flush(&mut self.db_tx)?;
        Ok(())
    }
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ReorgError {
    #[error("Error connecting block {0}: {1}")]
    ConnectTipFailed(Id<Block>, BlockError),
    #[error("Block data missing for block {0}")]
    BlockDataMissing(Id<Block>),
    #[error("Generic error during reorg: {0}")]
    OtherError(#[from] BlockError),
}
