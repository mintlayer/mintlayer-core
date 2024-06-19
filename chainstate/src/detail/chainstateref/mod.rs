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

mod block_info;
mod consistency_checker;
mod epoch_seal;
mod in_memory_reorg;
mod tx_verifier_storage;

use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
};

use itertools::Itertools;
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
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, ChainConfig, GenBlock, GenBlockId, PoolId, Transaction,
        TxOutput, UtxoOutPoint,
    },
    primitives::{
        id::WithId, time::Time, Amount, BlockCount, BlockDistance, BlockHeight, Id, Idable,
    },
    time_getter::TimeGetter,
    Uint256,
};
use logging::log;
use pos_accounting::{PoSAccountingDB, PoSAccountingDelta, PoSAccountingView};
use serialization::{Decode, Encode};
use tx_verifier::transaction_verifier::TransactionVerifier;
use utils::{debug_assert_or_log, ensure, log_error, tap_log::TapLog};
use utxo::{UtxosCache, UtxosDB, UtxosStorageRead, UtxosView};

use crate::{BlockError, ChainstateConfig};

use self::{
    block_info::BlockInfo, consistency_checker::ConsistencyChecker,
    tx_verifier_storage::gen_block_index_getter,
};

use super::{
    in_memory_block_tree::{self, InMemoryBlockTreeRef, InMemoryBlockTrees},
    median_time::calculate_median_time_past,
    transaction_verifier::flush::flush_to_storage,
    tx_verification_strategy::TransactionVerificationStrategy,
    BlockSizeError, CheckBlockError, CheckBlockTransactionsError,
};

pub use epoch_seal::EpochSealError;
pub use in_memory_reorg::InMemoryReorgError;

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
    #[log_error]
    fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.get_block_index(block_id)
    }

    #[log_error]
    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.get_gen_block_index(block_id)
    }

    #[log_error]
    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        self.get_ancestor(&GenBlockIndex::Block(block_index.clone()), ancestor_height)
            .map_err(PropertyQueryError::from)
    }

    #[log_error]
    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        self.get_block_reward(block_index)
    }
}

impl<'a, S: TransactionRw, V> ChainstateRef<'a, S, V> {
    #[log_error]
    pub fn commit_db_tx(self) -> chainstate_storage::Result<()> {
        self.db_tx.commit()
    }

    pub fn check_storage_error(&self) -> chainstate_storage::Result<()> {
        self.db_tx.check_error()
    }
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> ChainstateRef<'a, S, V> {
    pub fn new_rw(
        chain_config: &'a ChainConfig,
        chainstate_config: &'a ChainstateConfig,
        tx_verification_strategy: &'a V,
        db_tx: S,
        time_getter: &'a TimeGetter,
    ) -> Self {
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
    ) -> Self {
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

    #[log_error]
    pub fn get_leaf_block_ids(
        &self,
        min_height: BlockHeight,
    ) -> Result<BTreeSet<Id<Block>>, PropertyQueryError> {
        Ok(self.db_tx.get_leaf_block_ids(min_height)?)
    }

    #[log_error]
    pub fn get_best_block_id(&self) -> Result<Id<GenBlock>, PropertyQueryError> {
        self.db_tx
            .get_best_block_id()
            .map_err(PropertyQueryError::from)
            .map(|bid| bid.expect("Best block ID not initialized"))
    }

    #[log_error]
    pub fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        log::trace!("Loading block index of id: {}", block_id);
        self.db_tx.get_block_index(block_id).map_err(PropertyQueryError::from)
    }

    #[log_error]
    pub fn get_existing_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<BlockIndex, PropertyQueryError> {
        self.get_block_index(block_id)?
            .ok_or_else(|| PropertyQueryError::BlockIndexNotFound((*block_id).into()))
    }

    #[log_error]
    pub fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        gen_block_index_getter(&self.db_tx, self.chain_config, block_id)
            .map_err(PropertyQueryError::from)
    }

    #[log_error]
    pub fn get_existing_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        self.get_gen_block_index(block_id)?
            .ok_or(PropertyQueryError::BlockIndexNotFound(*block_id))
    }

    #[log_error]
    pub fn get_best_block_index(&self) -> Result<GenBlockIndex, PropertyQueryError> {
        self.get_gen_block_index(&self.get_best_block_id()?)?
            .ok_or(PropertyQueryError::BestBlockIndexNotFound)
    }

    /// Return BlockIndex of the previous block.
    #[log_error]
    fn get_previous_block_index(
        &self,
        block_info: &impl BlockInfo,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let prev_block_id = block_info.get_header().prev_block_id();

        self.get_gen_block_index(prev_block_id)?
            .ok_or(PropertyQueryError::PrevBlockIndexNotFound {
                block_id: block_info.get_or_calc_id(),
                prev_block_id: *prev_block_id,
            })
    }

    #[log_error]
    pub fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, PropertyQueryError> {
        self.db_tx.get_block_id_by_height(height).map_err(PropertyQueryError::from)
    }

    #[log_error]
    pub fn get_existing_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Id<GenBlock>, PropertyQueryError> {
        self.get_block_id_by_height(height)?
            .ok_or(PropertyQueryError::BlockForHeightNotFound(*height))
    }

    #[log_error]
    pub fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.db_tx.get_block(block_id).map_err(PropertyQueryError::from)
    }

    #[log_error]
    pub fn block_exists(&self, block_id: Id<Block>) -> Result<bool, PropertyQueryError> {
        self.db_tx.block_exists(block_id).map_err(PropertyQueryError::from)
    }

    #[log_error]
    pub fn get_block_header(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<SignedBlockHeader>, PropertyQueryError> {
        Ok(self.db_tx.get_block_header(block_id)?)
    }

    #[log_error]
    pub fn is_block_in_main_chain(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<bool, PropertyQueryError> {
        self.get_block_height_in_main_chain(block_id).map(|ht| ht.is_some())
    }

    #[log_error]
    pub fn get_min_height_with_allowed_reorg(&self) -> Result<BlockHeight, PropertyQueryError> {
        Ok(self.db_tx.get_min_height_with_allowed_reorg()?.unwrap_or(0.into()))
    }

    #[log_error]
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
    #[log_error]
    pub fn last_common_ancestor(
        &self,
        first_block_index: &GenBlockIndex,
        second_block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let mut first_block_index = first_block_index.clone();
        let mut second_block_index = second_block_index.clone();
        match first_block_index.block_height().cmp(&second_block_index.block_height()) {
            std::cmp::Ordering::Greater => {
                first_block_index =
                    self.get_ancestor(&first_block_index, second_block_index.block_height())?;
            }
            std::cmp::Ordering::Less => {
                second_block_index =
                    self.get_ancestor(&second_block_index, first_block_index.block_height())?;
            }
            std::cmp::Ordering::Equal => {}
        }

        loop {
            match (&first_block_index, &second_block_index) {
                _ if first_block_index.block_id() == second_block_index.block_id() => {
                    break Ok(first_block_index)
                }
                (GenBlockIndex::Block(first_blkidx), GenBlockIndex::Block(second_blkidx)) => {
                    first_block_index = self.get_previous_block_index(first_blkidx)?;
                    second_block_index = self.get_previous_block_index(second_blkidx)?;
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
    #[log_error]
    pub fn last_common_ancestor_in_main_chain(
        &self,
        block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let best_block_index = self.get_best_block_index()?;
        self.last_common_ancestor(block_index, &best_block_index)
    }

    #[log_error]
    pub fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, PropertyQueryError> {
        self.db_tx.get_token_aux_data(token_id).map_err(PropertyQueryError::from)
    }

    #[log_error]
    pub fn get_token_id(
        &self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<TokenId>, PropertyQueryError> {
        self.db_tx.get_token_id(tx_id).map_err(PropertyQueryError::from)
    }

    #[log_error]
    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<SignedBlockHeader>, PropertyQueryError> {
        let id = self.get_existing_block_id_by_height(height)?;
        let id = id
            .classify(self.chain_config)
            .chain_block_id()
            .ok_or(PropertyQueryError::GenesisHeaderRequested)
            .log_err()?;
        Ok(self.get_block_index(&id)?.map(|block_index| block_index.into_block_header()))
    }

    #[log_error]
    pub fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        Ok(self.db_tx.get_block_reward(block_index)?)
    }

    #[log_error]
    pub fn get_epoch_data(
        &self,
        epoch_index: EpochIndex,
    ) -> Result<Option<EpochData>, PropertyQueryError> {
        self.db_tx.get_epoch_data(epoch_index).map_err(PropertyQueryError::from)
    }

    #[log_error]
    pub fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, PropertyQueryError> {
        self.db_tx.get_account_nonce_count(account).map_err(PropertyQueryError::from)
    }

    #[log_error]
    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        let gen_id = id;
        let id = match gen_id.classify(self.chain_config) {
            GenBlockId::Block(id) => id,
            GenBlockId::Genesis(_) => return Ok(Some(BlockHeight::zero())),
        };

        if let Some(block_index) = self.get_block_index(&id)? {
            let mainchain_block_id = self.get_block_id_by_height(&block_index.block_height())?;

            // Note: this function may be called when the chain is still empty, so we don't unwrap
            // mainchain_block_id and wrap gen_id instead.
            if mainchain_block_id.as_ref() == Some(gen_id) {
                return Ok(Some(block_index.block_height()));
            }
        }
        Ok(None)
    }

    // Get indexes for a new longest chain
    #[log_error]
    fn get_new_chain(
        &self,
        new_tip_block_index: &BlockIndex,
    ) -> Result<Vec<BlockIndex>, PropertyQueryError> {
        let mut result = Vec::new();
        let mut block_index = new_tip_block_index.clone();
        while !self.is_block_in_main_chain(&(*block_index.block_id()).into())? {
            result.push(block_index.clone());
            block_index = match self.get_previous_block_index(&block_index)? {
                GenBlockIndex::Genesis(_) => break,
                GenBlockIndex::Block(blkidx) => blkidx,
            }
        }
        result.reverse();
        Ok(result)
    }

    // If the header height is at an exact checkpoint height, check that the block id matches the checkpoint id.
    // Return true if the header height is at an exact checkpoint height.
    fn enforce_exact_checkpoint_assuming_height(
        &self,
        header: &SignedBlockHeader,
        header_height: BlockHeight,
    ) -> Result<bool, CheckBlockError> {
        if let Some(e) = self.chain_config.height_checkpoints().checkpoint_at_height(&header_height)
        {
            let expected_id = Id::<Block>::new(e.to_hash());
            if expected_id != header.get_id() {
                return Err(CheckBlockError::CheckpointMismatch(
                    expected_id,
                    header.get_id(),
                ));
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Enforce checkpoints for the passed header.
    /// The header's parent block must be known.
    #[log_error]
    fn enforce_checkpoints(&self, header: &SignedBlockHeader) -> Result<(), CheckBlockError> {
        let prev_block_index = self.get_previous_block_index(header)?;
        let current_height = prev_block_index.block_height().next_height();

        if self.enforce_exact_checkpoint_assuming_height(header, current_height)? {
            return Ok(());
        }

        // The block height does not match a checkpoint height; we need to check that
        // an ancestor block id matches the checkpoint id.
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

    /// Enforce checkpoints for `headers_to_check`.
    /// The parent block of `checked_header` must be known.
    /// Headers in `headers_to_check` must be connected to each other and to `checked_header`.
    #[log_error]
    pub fn enforce_checkpoints_for_header_chain(
        &self,
        checked_header: &SignedBlockHeader,
        headers_to_check: &[SignedBlockHeader],
    ) -> Result<(), BlockError> {
        let checked_header_height = {
            let prev_block_index = self
                .get_previous_block_index(checked_header)
                .map_err(BlockError::PropertyQueryError)?;
            prev_block_index.block_height().next_height()
        };

        for (cur_header_idx, (prev_header, cur_header)) in std::iter::once(checked_header)
            .chain(headers_to_check.iter())
            .tuple_windows()
            .enumerate()
        {
            let prev_header_id: Id<GenBlock> = prev_header.get_id().into();
            if cur_header.prev_block_id() != &prev_header_id {
                // The caller should enforce this.
                debug_assert!(false);
                return Err(BlockError::InvariantErrorDisconnectedHeaders);
            }

            let cur_header_height = (checked_header_height
                + BlockDistance::new(cur_header_idx as i64 + 1))
            .expect("BlockHeight limit reached");

            self.enforce_exact_checkpoint_assuming_height(cur_header, cur_header_height)?;
        }

        Ok(())
    }

    #[log_error]
    fn check_block_height_vs_max_reorg_depth(
        &self,
        header: &SignedBlockHeader,
    ) -> Result<(), CheckBlockError> {
        let prev_block_index = self.get_previous_block_index(header)?;
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

    /// Return Ok(()) if the specified block has a valid parent and an error otherwise.
    #[log_error]
    pub fn check_block_parent(
        &self,
        block_header: &SignedBlockHeader,
    ) -> Result<(), CheckBlockError> {
        let parent_block_id = block_header.prev_block_id();
        let parent_block_index = self.get_gen_block_index(parent_block_id)?.ok_or_else(|| {
            CheckBlockError::ParentBlockMissing {
                block_id: block_header.block_id(),
                parent_block_id: *parent_block_id,
            }
        })?;

        ensure!(
            parent_block_index.status().is_ok(),
            CheckBlockError::InvalidParent {
                block_id: block_header.block_id(),
                parent_block_id: *parent_block_id,
            }
        );

        Ok(())
    }

    #[log_error]
    pub fn check_block_header(&self, header: &SignedBlockHeader) -> Result<(), CheckBlockError> {
        self.check_block_parent(header)?;
        self.check_header_size(header)?;
        self.enforce_checkpoints(header)?;
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
            let (verifier_delta, consumed_epoch_data) =
                self.reorganize_in_memory(header.header().prev_block_id())?;
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
            CheckBlockError::BlockFromTheFuture(header.block_id()),
        );
        Ok(())
    }

    #[log_error]
    fn check_block_reward_maturity_settings(&self, block: &Block) -> Result<(), CheckBlockError> {
        block
            .block_reward()
            .outputs()
            .iter()
            .enumerate()
            .try_for_each(|(index, output)| {
                let required = match block.consensus_data() {
                    ConsensusData::None => {
                        self.chain_config.empty_consensus_reward_maturity_block_count()
                    }
                    ConsensusData::PoW(_) => {
                        self.chain_config.get_proof_of_work_config().reward_maturity_distance()
                    }
                    ConsensusData::PoS(_) => BlockCount::new(0),
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
                        | TxOutput::IssueFungibleToken(_)
                        | TxOutput::IssueNft(_, _, _)
                        | TxOutput::DataDeposit(_) => Err(
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
                            | TxOutput::IssueFungibleToken(_)
                            | TxOutput::IssueNft(_, _, _)
                            | TxOutput::DataDeposit(_) => Err(
                                CheckBlockError::InvalidBlockRewardOutputType(block.get_id()),
                            ),
                        }
                    }
                }
            })
    }

    #[log_error]
    fn check_header_size(&self, header: &SignedBlockHeader) -> Result<(), BlockSizeError> {
        let size = header.header_size();
        ensure!(
            size <= self.chain_config.max_block_header_size(),
            BlockSizeError::Header(size, self.chain_config.max_block_header_size())
        );

        Ok(())
    }

    #[log_error]
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

    #[log_error]
    fn check_duplicate_inputs(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // check for duplicate inputs (see CVE-2018-17144)
        let mut block_inputs = BTreeSet::new();
        for tx in block.transactions() {
            for input in tx.inputs() {
                ensure!(
                    block_inputs.insert(input),
                    CheckBlockTransactionsError::DuplicateInputInBlock(block.get_id())
                );
            }
        }
        Ok(())
    }

    #[log_error]
    fn check_transactions(
        &self,
        block: &Block,
        block_height: BlockHeight,
    ) -> Result<(), CheckBlockTransactionsError> {
        for tx in block.transactions() {
            tx_verifier::check_transaction(self.chain_config, block_height, tx)?;
        }

        // Note: duplicate txs are detected through duplicate inputs
        self.check_duplicate_inputs(block)?;

        Ok(())
    }

    #[log_error]
    fn get_block_from_index(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<Block>, chainstate_storage::Error> {
        self.db_tx.get_block(*block_index.block_id())
    }

    #[log_error]
    pub fn check_block(&self, block: &WithId<Block>) -> Result<(), CheckBlockError> {
        self.check_block_header(block.header())?;

        self.check_block_size(block).map_err(CheckBlockError::BlockSizeError)?;

        self.check_block_reward_maturity_settings(block)?;

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

        let prev_block_height = self
            .get_gen_block_index(&block.prev_block_id())?
            .ok_or_else(|| PropertyQueryError::PrevBlockIndexNotFound {
                block_id: block.get_id(),
                prev_block_id: block.prev_block_id(),
            })?
            .block_height();

        self.check_transactions(block, prev_block_height.next_height())
            .map_err(CheckBlockError::CheckTransactionFailed)?;

        Ok(())
    }

    #[log_error]
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

    #[log_error]
    pub fn get_mainchain_blocks_list(&self) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        let id_from_height = |block_height: u64| -> Result<Id<Block>, PropertyQueryError> {
            let block_height: BlockHeight = block_height.into();
            let block_id = self
                .get_block_id_by_height(&block_height)?
                .expect("Since block_height is >= best_height, this must exist");
            let block_id = block_id
                .classify(self.chain_config)
                .chain_block_id()
                .expect("Since the height is never zero, this cannot be genesis");
            Ok(block_id)
        };

        let best_block_index = self.get_best_block_index()?;
        let best_height = best_block_index.block_height();
        let best_height_int: u64 = best_height.into();
        let mut result = Vec::with_capacity(best_height_int as usize);
        for block_height in 1..=best_height_int {
            result.push(id_from_height(block_height).log_err()?);
        }
        Ok(result)
    }

    /// Note: the result will be sorted by height; this behavior is expected by some of the callers.
    /// Only ids of persisted blocks will be returned.
    #[log_error]
    pub fn get_block_id_tree_as_list(&self) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        let result = self
            .get_block_tree_top_by_height_traversing_entire_index(
                0.into(),
                BlockValidity::Persisted,
            )?
            .into_iter()
            .flat_map(|(_height, ids_per_height)| ids_per_height)
            .collect();
        Ok(result)
    }

    /// Return ids of all blocks with height bigger than or equal to the specified one,
    /// sorted by height (lower first).
    #[log_error]
    pub fn get_higher_block_ids_sorted_by_height(
        &self,
        start_from: BlockHeight,
        block_validity: BlockValidity,
    ) -> Result<impl DoubleEndedIterator<Item = Id<Block>>, PropertyQueryError> {
        let block_trees =
            self.get_block_tree_top_starting_from_height(start_from, block_validity)?;
        let block_id_map = block_trees.as_by_height_block_id_map()?;

        Ok(block_id_map.into_iter().flat_map(|(_height, ids_per_height)| ids_per_height))
    }

    #[log_error]
    fn get_block_tree_top_by_height_traversing_entire_index(
        &self,
        start_from: BlockHeight,
        block_validity: BlockValidity,
    ) -> Result<BTreeMap<BlockHeight, BTreeSet<Id<Block>>>, PropertyQueryError> {
        let mut result = BTreeMap::<BlockHeight, BTreeSet<Id<Block>>>::new();
        let iter = self.db_tx.iterate_block_index()?;

        for block_index in iter {
            if block_index.block_height() >= start_from
                && block_validity_matches(&block_index, block_validity)
            {
                result
                    .entry(block_index.block_height())
                    .or_default()
                    .insert(*block_index.block_id());
            }
        }

        Ok(result)
    }

    #[log_error]
    fn get_block_tree_top_by_timestamp_traversing_entire_index(
        &self,
        start_from: BlockTimestamp,
        block_validity: BlockValidity,
    ) -> Result<BTreeMap<BlockTimestamp, BTreeSet<Id<Block>>>, PropertyQueryError> {
        let mut result = BTreeMap::<BlockTimestamp, BTreeSet<Id<Block>>>::new();
        let iter = self.db_tx.iterate_block_index()?;

        for block_index in iter {
            if block_index.block_timestamp() >= start_from
                && block_validity_matches(&block_index, block_validity)
            {
                result
                    .entry(block_index.block_timestamp())
                    .or_default()
                    .insert(*block_index.block_id());
            }
        }

        Ok(result)
    }

    /// Return the block index of the first parent of the specified block that has the specified validity
    /// (or the block itself).
    /// At each step call `is_depth_ok`; return None if `is_depth_ok` has returned false.
    #[log_error]
    pub fn find_first_parent_with_validity(
        &self,
        block_index: BlockIndex,
        block_validity: BlockValidity,
        is_depth_ok: impl Fn(&BlockIndex) -> bool,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        let mut cur_block_index = block_index;

        loop {
            if !is_depth_ok(&cur_block_index) {
                return Ok(None);
            }

            if block_validity_matches(&cur_block_index, block_validity) {
                return Ok(Some(cur_block_index));
            }

            if let Some(non_genesis_parent_id) =
                cur_block_index.prev_block_id().classify(self.chain_config).chain_block_id()
            {
                cur_block_index = self.get_existing_block_index(&non_genesis_parent_id)?;
            } else {
                return Ok(None);
            }
        }
    }

    /// Iterate starting from each leaf block downwards and collect the block indices into
    /// an in-memory tree structure.
    /// Only blocks with heights bigger than or equal to the specified one are collected.
    #[log_error]
    pub fn get_block_tree_top_starting_from_height(
        &self,
        min_height: BlockHeight,
        block_validity: BlockValidity,
    ) -> Result<InMemoryBlockTrees, PropertyQueryError> {
        let leaf_block_ids = self.get_leaf_block_ids(min_height)?;
        let result = in_memory_block_tree::get_block_tree_top(
            self,
            leaf_block_ids.iter(),
            |block_index| block_index.block_height() >= min_height,
            block_validity,
        )?;

        if self.chainstate_config.heavy_checks_enabled(self.chain_config) {
            result.assert_all_blocks_match_validity(block_validity);

            // Check that traversing the entire index produces the same result.
            let result_as_map = result.as_by_height_block_id_map()?;
            let alternative_result = self
                .get_block_tree_top_by_height_traversing_entire_index(min_height, block_validity)?;
            assert_eq!(result_as_map, alternative_result);
        }

        Ok(result)
    }

    /// Iterate starting from each leaf block downwards and collect the block indices into
    /// an in-memory tree structure.
    /// Only blocks with timestamps bigger than or equal to the specified one are collected.
    #[log_error]
    pub fn get_block_tree_top_starting_from_timestamp(
        &self,
        min_timestamp: BlockTimestamp,
        block_validity: BlockValidity,
    ) -> Result<InMemoryBlockTrees, PropertyQueryError> {
        let min_height_with_allowed_reorg = self.get_min_height_with_allowed_reorg()?;
        let leaf_block_ids = self.get_leaf_block_ids(min_height_with_allowed_reorg)?;
        let result = in_memory_block_tree::get_block_tree_top(
            self,
            leaf_block_ids.iter(),
            |block_index| block_index.block_timestamp() >= min_timestamp,
            block_validity,
        )?;

        if self.chainstate_config.heavy_checks_enabled(self.chain_config) {
            result.assert_all_blocks_match_validity(block_validity);

            // Check that traversing the entire index produces the same result.
            let result_as_map = result.as_by_timestamp_block_id_map()?;
            let alternative_result = self.get_block_tree_top_by_timestamp_traversing_entire_index(
                min_timestamp,
                block_validity,
            )?;
            assert_eq!(result_as_map, alternative_result);
        }

        Ok(result)
    }

    #[log_error]
    pub fn try_connect_block_trees(
        &self,
        trees: InMemoryBlockTrees,
        min_height: BlockHeight,
    ) -> Result<InMemoryBlockTrees, PropertyQueryError> {
        let result = in_memory_block_tree::try_connect_block_trees(self, trees, min_height)?;

        Ok(result)
    }

    #[log_error]
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

        let chain_transaction_count =
            prev_block_index.chain_transaction_count() + block.transactions().len() as u128;

        // Set Time Max
        let chain_time_max =
            std::cmp::max(prev_block_index.chain_timestamps_max(), block.timestamp());

        let current_block_proof =
            self.get_block_proof(prev_block_index.block_timestamp(), block)?;

        // Set Chain Trust
        let prev_block_chaintrust: Uint256 = prev_block_index.chain_trust();
        let chain_trust = (prev_block_chaintrust + current_block_proof)
            .expect("Chain trust growth is locally controlled. This can't happen.");
        let block_index = BlockIndex::new(
            block,
            chain_trust,
            some_ancestor,
            height,
            chain_time_max,
            chain_transaction_count,
            block_status,
        );
        Ok(block_index)
    }

    #[log_error]
    pub fn get_stake_pool_balances_for_tree(
        &self,
        pool_ids: &[PoolId],
        tree: InMemoryBlockTreeRef<'_>,
        include_tree_root_parent: bool,
    ) -> Result<BTreeMap<Id<GenBlock>, BTreeMap<PoolId, NonZeroPoolBalances>>, BlockError> {
        let best_block_index =
            self.get_best_block_index().map_err(BlockError::PropertyQueryError)?;

        let mut pool_balances_map = BTreeMap::new();

        let balances_at_tip =
            Self::collect_pool_balances(pool_ids.iter(), self, &best_block_index.block_id())?;
        if !balances_at_tip.is_empty() {
            pool_balances_map.insert(best_block_index.block_id(), balances_at_tip);
        }

        self.iterate_block_tree_and_reorganize_in_memory(
            tree,
            include_tree_root_parent,
            |base_block_index, tx_verifier, _| -> Result<_, BlockError> {
                let base_block_id = if let Some(base_block_index) = base_block_index {
                    base_block_index.block_id().into()
                } else {
                    // Sanity check - we can only get here if include_tree_root_parent is true.
                    debug_assert!(include_tree_root_parent);

                    tree.root_block_index()?.prev_block_id()
                };

                let balances =
                    Self::collect_pool_balances(pool_ids.iter(), &tx_verifier, base_block_id)?;

                if !balances.is_empty() {
                    pool_balances_map.insert(*base_block_id, balances);
                }

                Ok(())
            },
        )?;

        Ok(pool_balances_map)
    }

    #[log_error]
    pub fn get_stake_pool_balances_at_heights(
        &self,
        pool_ids: &[PoolId],
        min_height: BlockHeight,
        max_height: BlockHeight,
    ) -> Result<BTreeMap<BlockHeight, BTreeMap<PoolId, NonZeroPoolBalances>>, BlockError> {
        let best_block_index =
            self.get_best_block_index().map_err(BlockError::PropertyQueryError)?;
        let best_block_height = best_block_index.block_height();

        ensure!(
            min_height <= max_height && max_height <= best_block_height,
            BlockError::UnexpectedHeightRange(min_height, max_height)
        );

        // This will track ids of pools that have non-zero balance above the current height.
        let mut pool_ids_that_had_balance = BTreeSet::new();
        // If a pool has no balance at a certain height but it's known to have one
        // at a bigger height, it means that it is created above that height,
        // so there is no point in checking its balance below it.
        // Such pool ids will be removed from the set; if the set becomes empty, we'll stop
        // iterating, to avoid performing useless reorgs.
        let mut pool_ids = pool_ids.iter().copied().collect::<BTreeSet<_>>();

        let mut height_map = BTreeMap::new();

        let max_height = if max_height == best_block_height {
            let balances_at_tip =
                Self::collect_pool_balances(pool_ids.iter(), self, &best_block_index.block_id())?;
            if !balances_at_tip.is_empty() {
                height_map.insert(best_block_height, balances_at_tip);
            }

            if max_height == min_height {
                return Ok(height_map);
            }

            max_height.prev_height().expect("max_height can't be zero at this point")
        } else {
            max_height
        };

        let lowest_block_id = self
            .get_existing_block_id_by_height(&min_height)
            .map_err(BlockError::PropertyQueryError)?;

        self.disconnect_tip_in_memory_until(
            &lowest_block_id,
            |disconnected_block_index, tx_verifier, _| -> Result<_, BlockError> {
                let base_block_id = disconnected_block_index.prev_block_id();
                let base_height = disconnected_block_index
                    .block_height()
                    .prev_height()
                    .expect("Genesis can't be disconnected");
                assert!(base_height >= min_height);

                let balances =
                    Self::collect_pool_balances(pool_ids.iter(), &tx_verifier, base_block_id)?;

                pool_ids.retain(|pool_id| {
                    // We didn't see this pool having balance yet.
                    !pool_ids_that_had_balance.contains(pool_id) ||
                    // We did see this pool having balance and it still does.
                    balances.contains_key(pool_id)
                });

                pool_ids_that_had_balance.extend(balances.keys().copied());

                if base_height <= max_height && !balances.is_empty() {
                    height_map.insert(base_height, balances);
                }

                if pool_ids.is_empty() {
                    log::debug!("Stopping iteration early at height {base_height}");
                    Ok(false)
                } else {
                    Ok(true)
                }
            },
        )?;

        Ok(height_map)
    }

    #[log_error]
    fn collect_pool_balances<'b>(
        pool_ids: impl Iterator<Item = &'b PoolId>,
        pos_accounting_view: &impl PoSAccountingView<Error = pos_accounting::Error>,
        assumed_base_block: &Id<GenBlock>,
    ) -> Result<BTreeMap<PoolId, NonZeroPoolBalances>, BlockError> {
        let mut balances = BTreeMap::new();

        for pool_id in pool_ids {
            if let Some(pool_balance) =
                NonZeroPoolBalances::obtain(pool_id, pos_accounting_view, assumed_base_block)?
            {
                balances.insert(*pool_id, pool_balance);
            }
        }

        Ok(balances)
    }

    /// Panic if block index consistency is violated.
    /// An error is only returned if the checks couldn't be performed for some reason.
    #[log_error]
    pub fn check_consistency(&self) -> Result<(), chainstate_storage::Error> {
        ConsistencyChecker::new(&self.db_tx, self.chain_config)?.check()
    }
}

impl<'a, S: BlockchainStorageWrite, V: TransactionVerificationStrategy> ChainstateRef<'a, S, V> {
    #[log_error]
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

            let previous_block_index = self.disconnect_tip(Some(&cur_block_id))?;
            block_id_to_disconnect = previous_block_index.block_id();
        }
        Ok(())
    }

    #[log_error]
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
            self.disconnect_until(&best_block_id, common_ancestor_id)?;
        }

        // Connect the new chain
        for block_index in new_chain {
            self.connect_tip(&block_index)
                .map_err(|err| ReorgError::ConnectTipFailed(*block_index.block_id(), err))
                .log_err()?;
        }

        Ok(())
    }

    #[log_error]
    fn connect_transactions(
        &mut self,
        block_index: &BlockIndex,
        block: &WithId<Block>,
    ) -> Result<(), BlockError> {
        // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
        let median_time_past = calculate_median_time_past(self, &block.prev_block_id());

        let connected_txs = self
            .tx_verification_strategy
            .connect_block(
                TransactionVerifier::new,
                &*self,
                self.chain_config,
                block_index,
                block,
                median_time_past,
            )
            .log_err()?;

        let consumed = connected_txs.consume()?;
        flush_to_storage(self, consumed)?;

        Ok(())
    }

    #[log_error]
    fn disconnect_transactions(&mut self, block: &WithId<Block>) -> Result<(), BlockError> {
        let cached_inputs = self.tx_verification_strategy.disconnect_block(
            TransactionVerifier::new,
            &*self,
            self.chain_config,
            block,
        )?;
        let cached_inputs = cached_inputs.consume()?;
        flush_to_storage(self, cached_inputs)?;

        Ok(())
    }

    // Connect new block
    #[log_error]
    fn connect_tip(&mut self, block_index: &BlockIndex) -> Result<(), BlockError> {
        let (block, block_status) = {
            let mut block_status = block_index.status();
            ensure!(
                block_status.is_ok(),
                BlockError::InvariantErrorAttemptToConnectInvalidBlock(
                    (*block_index.block_id()).into()
                )
            );

            let block: WithId<Block> = self
                .get_block_from_index(block_index)
                .map_err(BlockError::StorageError)?
                .ok_or_else(|| {
                    let id = *block_index.block_id();
                    log::warn!(
                        "Missing block data for block {id} with a valid status {block_status}"
                    );
                    BlockError::BlockDataMissingForValidBlockIndex(id)
                })
                .log_err()?
                .into();

            if block_status.last_valid_stage() < BlockValidationStage::CheckBlockOk {
                self.check_block(&block)?;
                block_status.advance_validation_stage_to(BlockValidationStage::CheckBlockOk);
            }

            (block, block_status)
        };

        let best_block_id = self.get_best_block_id().map_err(BlockError::BestBlockIdQueryError)?;
        utils::ensure!(
            &best_block_id == block_index.prev_block_id(),
            BlockError::InvariantErrorInvalidTip(block.get_id().into()),
        );

        self.connect_transactions(block_index, &block)?;

        self.db_tx.set_block_id_at_height(
            &block_index.block_height(),
            &(*block_index.block_id()).into(),
        )?;
        self.db_tx.set_best_block_id(&(*block_index.block_id()).into())?;

        if block_index.status().last_valid_stage() != BlockValidationStage::FullyChecked {
            let mut block_status = block_status;
            block_status.advance_validation_stage_to(BlockValidationStage::FullyChecked);
            let new_block_index = block_index.clone().with_status(block_status);
            self.db_tx.set_block_index(&new_block_index)?;
        }

        self.post_connect_tip(block_index, block.as_ref())
    }

    /// Does a read-modify-write operation on the database and disconnects a block
    /// by unsetting the `next` pointer.
    /// Returns the previous block (the last block in the main-chain)
    #[log_error]
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
        let block = self.get_block_from_index(&block_index)?.expect("Inconsistent DB");
        // Disconnect transactions
        self.disconnect_transactions(&block.into())?;
        self.db_tx.set_best_block_id(block_index.prev_block_id())?;
        // Disconnect block
        self.db_tx.del_block_id_at_height(&block_index.block_height())?;

        let prev_block_index = self
            .get_previous_block_index(&block_index)
            .expect("Previous block index retrieval failed");

        self.post_disconnect_tip(prev_block_index.block_height())?;
        Ok(prev_block_index)
    }

    /// Perform a reorg to the specified block if needed.
    /// Return true if the reorg has been performed, and false otherwise.
    #[log_error]
    pub fn activate_best_chain(
        &mut self,
        new_block_index: &BlockIndex,
    ) -> Result<bool, ReorgError> {
        let current_best_block_index =
            self.get_best_block_index().map_err(BlockError::BestBlockIndexQueryError)?;

        if new_block_index.chain_trust() > current_best_block_index.chain_trust() {
            // Chain trust is higher than the best block
            self.reorganize(&current_best_block_index.block_id(), new_block_index)?;
            return Ok(true);
        }

        Ok(false)
    }

    #[log_error]
    pub fn persist_block(&mut self, block: &WithId<Block>) -> Result<(), BlockError> {
        if self.db_tx.block_exists(block.get_id()).map_err(BlockError::from)? {
            return Err(BlockError::BlockAlreadyExists(block.get_id()));
        }

        self.db_tx.add_block(block).map_err(BlockError::from)
    }

    #[log_error]
    pub fn set_new_block_index(&mut self, block_index: &BlockIndex) -> Result<(), BlockError> {
        if self.db_tx.get_block_index(block_index.block_id())?.is_some() {
            return Err(BlockError::BlockIndexAlreadyExists(*block_index.block_id()));
        }
        self.db_tx.set_block_index(block_index)?;

        self.db_tx.mark_as_leaf(block_index, true)?;

        if let Some(non_genesis_parent) =
            block_index.prev_block_id().classify(self.chain_config).chain_block_id()
        {
            let parent_index = self
                .get_existing_block_index(&non_genesis_parent)
                .map_err(BlockError::PropertyQueryError)?;
            self.db_tx.mark_as_leaf(&parent_index, false)?;
        }

        Ok(())
    }

    /// Reset fail flags in block indices for all blocks in the subtree that start at the specified block.
    ///
    /// Note: this is a lower-level function that doesn't attempt to look for a better chain after the blocks have
    /// become valid again. This is supposed to be done by the caller.
    #[log_error]
    pub fn reset_block_failure_flags(&mut self, block_id: &Id<Block>) -> Result<(), BlockError> {
        let block_index = self
            .get_existing_block_index(block_id)
            .map_err(BlockError::PropertyQueryError)?;
        let block_height = block_index.block_height();

        let block_index_trees = self
            .get_block_tree_top_starting_from_height(block_height, BlockValidity::Any)
            .map_err(BlockError::PropertyQueryError)?;
        let block_index_tree_to_clear = block_index_trees.single_tree(block_id)?;

        let old_leaf_block_ids = self.db_tx.get_leaf_block_ids(
            block_height.prev_height().expect("Non-genesis can't have zero height"),
        )?;
        let mut remaining_leaf_block_ids = old_leaf_block_ids.clone();

        // Below we'll be removing block indices of non-persisted blocks; parents of those
        // blocks may need to be marked as leaves. Two cases exist:
        // 1) If `block_index` is itself non-persisted, then we have only one leaf candidate.
        // To check if it's an actual leaf, we need to iterate over all blocks at the same height
        // as `block_index` (which are all root nodes in block_index_trees) and check their parents -
        // if the candidate if not among them, it's an actual leaf.
        // 2) If `block_index` is persisted, all leaf candidates will belong to block_index_tree_to_clear.
        // So, when iterating over the tree, we can collect all parents of all persisted blocks in it
        // and then compare leaf candidates against them - a candidate will be a leaf only if
        // it's not among those parents.

        let mark_as_leaf =
            |this: &mut ChainstateRef<'a, S, V>, leaf_block_id| -> Result<_, BlockError> {
                let new_leaf_index = this
                    .get_existing_block_index(&leaf_block_id)
                    .map_err(BlockError::PropertyQueryError)?;
                this.db_tx.mark_as_leaf(&new_leaf_index, true)?;
                Ok(())
            };

        if !block_index.is_persisted() {
            self.del_block_indices_of_non_persisted_block_tree(
                block_index_tree_to_clear,
                &mut remaining_leaf_block_ids,
            )?;

            // The parent of the removed tree root may be a new leaf.
            let maybe_new_leaf_id = block_index.prev_block_id();
            if let Some(maybe_new_leaf_chain_block_id) =
                maybe_new_leaf_id.classify(self.chain_config).chain_block_id()
            {
                // Check parents of all other roots in block_index_trees. If maybe_new_leaf is not
                // among them, it is a leaf.
                let mut is_parent = false;
                for some_tree in block_index_trees.trees_iter() {
                    let some_root_block_index = some_tree.root_block_index()?;
                    if some_root_block_index.block_id() != block_id
                        && some_root_block_index.prev_block_id() == maybe_new_leaf_id
                    {
                        is_parent = true;
                    }
                }

                if !is_parent {
                    mark_as_leaf(self, maybe_new_leaf_chain_block_id)?;
                }
            }
        } else {
            let mut maybe_new_leaves = BTreeSet::new();
            let mut parents_of_persisted_blocks = BTreeSet::new();

            block_index_tree_to_clear.for_all(|child_node_id| -> Result<_, BlockError> {
                let block_index = block_index_tree_to_clear.get_block_index(child_node_id)?;

                if block_index.is_persisted() {
                    self.update_block_status(
                        block_index.clone(),
                        block_index.status().with_cleared_fail_bits(),
                    )?;
                    parents_of_persisted_blocks.insert(block_index.prev_block_id());
                    Ok(true)
                } else {
                    let subtree = block_index_tree_to_clear.subtree(child_node_id)?;
                    self.del_block_indices_of_non_persisted_block_tree(
                        subtree,
                        &mut remaining_leaf_block_ids,
                    )?;
                    maybe_new_leaves.insert(block_index.prev_block_id());
                    Ok(false)
                }
            })?;

            for new_leaf_id in maybe_new_leaves.difference(&parents_of_persisted_blocks) {
                if let Some(new_leaf_chain_block_id) =
                    new_leaf_id.classify(self.chain_config).chain_block_id()
                {
                    mark_as_leaf(self, new_leaf_chain_block_id)?;
                }
            }
        }

        Ok(())
    }

    #[log_error]
    fn del_block_indices_of_non_persisted_block_tree<'b>(
        &mut self,
        tree: InMemoryBlockTreeRef<'b>,
        leaf_block_ids: &mut BTreeSet<Id<Block>>,
    ) -> Result<(), BlockError> {
        for block_index in tree.all_block_indices_iter() {
            let block_id = *block_index.block_id();

            // Note: here we're being extra-cautious about someone mis-using this function,
            // so we only panic in debug mode.
            debug_assert_or_log!(
                !block_index.is_persisted(),
                "Trying to delete a block index for a persisted block {block_id}",
            );

            self.db_tx.del_block_index(block_id)?;

            if leaf_block_ids.remove(&block_id) {
                self.db_tx.mark_as_leaf(block_index, false)?;
            }
        }

        Ok(())
    }

    /// Update the status of the passed `block_index`.
    /// If a BlockIndex already exists for this block, it must be equal to `block_index`.
    #[log_error]
    pub fn update_block_status(
        &mut self,
        block_index: BlockIndex,
        block_status: BlockStatus,
    ) -> Result<(), BlockError> {
        #[cfg(debug_assertions)]
        if let Some(existing_block_index) = self.db_tx.get_block_index(block_index.block_id())? {
            assert!(existing_block_index.is_identical_to(&block_index));
        }

        self.db_tx.set_block_index(&block_index.with_status(block_status))?;

        Ok(())
    }

    #[log_error]
    pub fn update_min_height_with_allowed_reorg(&mut self) -> Result<(), BlockError> {
        let stored_min_height = self
            .get_min_height_with_allowed_reorg()
            .map_err(BlockError::MinHeightForReorgQueryError)?;
        let current_tip_height = self
            .get_best_block_index()
            .map_err(BlockError::BestBlockIndexQueryError)?
            .block_height();
        let calculated_min_height =
            calc_min_height_with_allowed_reorg(self.chain_config, current_tip_height);
        self.db_tx
            .set_min_height_with_allowed_reorg(max(stored_min_height, calculated_min_height))?;
        Ok(())
    }

    #[log_error]
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

    #[log_error]
    fn post_disconnect_tip(&mut self, tip_height: BlockHeight) -> Result<(), BlockError> {
        epoch_seal::update_epoch_seal(
            &mut self.db_tx,
            self.chain_config,
            epoch_seal::BlockStateEvent::Disconnect(tip_height),
        )?;

        if self.chain_config.is_last_block_in_epoch(&tip_height) {
            // If current tip is the last block of the epoch
            // it means that the first block of next epoch was just disconnected
            // and the epoch delta for the next epoch should be deleted.
            // Otherwise its traces can mess up with connection of future blocks.
            let epoch_index = self.chain_config.epoch_index_from_height(&tip_height.next_height());
            self.db_tx.del_accounting_epoch_delta(epoch_index).log_err()?;
        }

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

fn calc_min_height_with_allowed_reorg(
    chain_config: &ChainConfig,
    current_tip_height: BlockHeight,
) -> BlockHeight {
    let result = current_tip_height - chain_config.max_depth_for_reorg();
    result.unwrap_or(0.into())
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ReorgError {
    #[error("Error connecting block {0}: {1}")]
    ConnectTipFailed(Id<Block>, BlockError),
    #[error("Generic error during reorg: {0}")]
    OtherError(#[from] BlockError),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct NonZeroPoolBalances {
    total_balance: Amount,
    staker_balance: Amount,
}

impl NonZeroPoolBalances {
    pub fn new(total_balance: Amount, staker_balance: Amount) -> Option<Self> {
        assert!(total_balance >= staker_balance);

        if staker_balance != Amount::ZERO {
            Some(Self {
                total_balance,
                staker_balance,
            })
        } else {
            None
        }
    }

    #[log_error]
    pub fn obtain(
        pool_id: &PoolId,
        pos_accounting_view: &impl PoSAccountingView<Error = pos_accounting::Error>,
        assumed_base_block: &Id<GenBlock>,
    ) -> Result<Option<Self>, BlockError> {
        let total_balance = pos_accounting_view
            .get_pool_balance(*pool_id)?
            .and_then(|balance| (balance != Amount::ZERO).then_some(balance));
        let pool_data = pos_accounting_view.get_pool_data(*pool_id)?;

        match (total_balance, pool_data) {
            (Some(total_balance), Some(pool_data)) => {
                let staker_balance = pool_data.staker_balance()?;

                ensure!(
                    total_balance >= staker_balance,
                    BlockError::InvariantErrorTotalPoolBalanceLessThanStakers {
                        total_balance,
                        staker_balance,
                        pool_id: *pool_id,
                        base_block: *assumed_base_block,
                    }
                );

                Ok(NonZeroPoolBalances::new(total_balance, staker_balance))
            }
            (None, None) => Ok(None),
            (Some(_), None) => Err(BlockError::InvariantErrorPoolBalancePresentDataMissing {
                pool_id: *pool_id,
                base_block: *assumed_base_block,
            }),
            (None, Some(_)) => Err(BlockError::InvariantErrorPoolDataPresentBalanceMissing {
                pool_id: *pool_id,
                base_block: *assumed_base_block,
            }),
        }
    }

    pub fn total_balance(&self) -> Amount {
        self.total_balance
    }

    pub fn staker_balance(&self) -> Amount {
        self.staker_balance
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlockValidity {
    Ok,
    Persisted,
    Any,
}

pub fn block_validity_matches(block_index: &BlockIndex, block_validity: BlockValidity) -> bool {
    match block_validity {
        BlockValidity::Ok => block_index.status().is_ok(),
        BlockValidity::Persisted => block_index.is_persisted(),
        BlockValidity::Any => true,
    }
}
