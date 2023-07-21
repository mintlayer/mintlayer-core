// Copyright (c) 2023 RBB S.r.l
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

use std::collections::VecDeque;

use itertools::Itertools;
use thiserror::Error;

use super::{utils::*, Chainstate, TxRw};
use crate::{
    detail::{
        chainstateref::{ChainstateRef, ReorgError},
        orphan_blocks::OrphanBlocksMut,
        DbCommittingContext,
    },
    BlockError, ChainstateEvent, OrphanCheckError, TransactionVerificationStrategy,
};
use chainstate_storage::BlockchainStorage;
use chainstate_types::{BlockIndex, BlockStatus, BlockValidationStage};
use common::{
    chain::Block,
    primitives::{id::WithId, Id, Idable},
};
use logging::log;
use utils::tap_error_log::LogError;

#[derive(Copy, Clone, Eq, Debug, PartialEq)]
pub enum BlockSource {
    Peer,
    Local,
}

impl<S: BlockchainStorage, V: TransactionVerificationStrategy> Chainstate<S, V> {
    /// Integrate the block into the blocktree, performing all the necessary checks.
    /// The returned bool indicates whether a reorg has occurred.
    fn integrate_block(
        chainstate_ref: &mut ChainstateRef<TxRw<'_, S>, V>,
        block: &WithId<Block>,
        block_index: BlockIndex,
    ) -> Result<bool, BlockIntegrationError> {
        let mut block_status = BlockStatus::new();

        let result = chainstate_ref.check_block(block);
        if result.is_err() {
            // TODO: "technical" errors (e.g. a DB error) should not lead to permanent
            // block invalidation. The same applies to the other unconditional
            // call of "set_validation_failed" below.
            // See https://github.com/mintlayer/mintlayer-core/issues/1033 (item #3).
            block_status.set_validation_failed();
        }

        result
            .map_err(BlockError::CheckBlockFailed)
            .map_err(|err| BlockIntegrationError::OtherValidationError(err, block_status))?;

        block_status.advance_validation_stage_to(BlockValidationStage::CheckBlockOk);
        let block_status = block_status;

        let block_index = block_index.with_status(block_status);
        chainstate_ref
            .set_new_block_index(&block_index)
            .and_then(|_| chainstate_ref.persist_block(block))
            .map_err(|err| BlockIntegrationError::OtherValidationError(err, block_status))?;

        // Note: we don't advance the stage to FullyChecked if activate_best_chain succeeds even
        // if we know that a reorg has occurred, because during a reorg multiple blocks get
        // checked. It's activate_best_chain's responsibility to update their statuses.
        // Likewise, we don't set the failure flag here, because the activation could also fail
        // due to a bad parent. This will be done by the caller code.
        let result = chainstate_ref.activate_best_chain(&block_index);

        chainstate_ref
            .update_min_height_with_allowed_reorg()
            .map_err(BlockIntegrationError::OtherNonValidationError)?;

        result.map_err(|err| match err {
            ReorgError::ConnectTipFailed(block_id, block_err) => {
                BlockIntegrationError::ConnectBlockErrorDuringReorg(
                    block_err,
                    block_status,
                    block_id,
                )
            }
            ReorgError::BlockDataMissing(block_id) => {
                BlockIntegrationError::ConnectBlockErrorDuringReorg(
                    BlockError::BlockNotFound(block_id),
                    block_status,
                    block_id,
                )
            }
            ReorgError::OtherError(block_err) => {
                BlockIntegrationError::OtherValidationError(block_err, block_status)
            }
        })
    }

    /// Attempt to process the block. On success, return Some(block_index_of_the_passed_block)
    /// if a reorg has occurred and the passed block is now the best block, otherwise return None.
    fn attempt_to_process_block(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let block = self.check_legitimate_orphan(block_source, block).log_err()?;
        let block_id = block.get_id();

        // Ensure that the block being submitted is new to us. If not, bail out immediately,
        // otherwise create a new block index and continue.
        let block_index = {
            let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from).log_err()?;
            let existing_block_index = get_block_index(&chainstate_ref, &block_id).log_err()?;

            if let Some(block_index) = existing_block_index {
                return if block_index.status().is_ok() {
                    Err(BlockError::BlockAlreadyProcessed(block_id))
                } else {
                    Err(BlockError::InvalidBlockAlreadyProcessed(block_id))
                };
            }

            chainstate_ref
                .create_block_index_for_new_block(&block, BlockStatus::new())
                .log_err()?
        };

        // Perform block checks; `integrate_block_result` is `Result<bool>`, where the bool
        // indicates whether a reorg has occurred.
        let integrate_block_result = self.with_rw_tx(
            |chainstate_ref| Self::integrate_block(chainstate_ref, &block, block_index.clone()),
            |attempt_number| {
                log::info!("Processing block {block_id}, attempt #{attempt_number}");
            },
            |attempts_count, db_err| {
                BlockIntegrationError::BlockCommitError(block_id, attempts_count, db_err)
            },
        );

        // Check the result and bail out on success or on a db error.
        // On a validation error, retrieve its data for the next step.
        let (err, status, first_invalid_block_id) = match integrate_block_result {
            Ok(reorg_occurred) => {
                // If the above code has succeeded, then the block_index must be present in the DB.
                // Note that we can't return the initially obtained block_index, because its
                // block status is outdated.
                let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from).log_err()?;
                let saved_block_index =
                    get_existing_block_index(&chainstate_ref, &block_id).log_err()?;

                assert!(saved_block_index.status().is_ok());
                return Ok(reorg_occurred.then_some(saved_block_index));
            }
            Err(BlockIntegrationError::BlockCommitError(block_id, attempts_count, db_err)) => {
                return Err(BlockError::DbCommitError(
                    attempts_count,
                    db_err,
                    DbCommittingContext::Block(block_id),
                ))
            }
            Err(BlockIntegrationError::OtherNonValidationError(err)) => {
                return Err(err);
            }
            Err(BlockIntegrationError::ConnectBlockErrorDuringReorg(
                err,
                status,
                first_invalid_block_id,
            )) => (err, status, Some(first_invalid_block_id)),
            Err(BlockIntegrationError::OtherValidationError(err, status)) => (err, status, None),
        };

        // Update the block status; note that this is needed even if we're going to call
        // invalidate_stale_block below, because it expects that all block indices
        // already exist (also, it will update this block's status, setting the appropriate
        // failure bit).
        {
            // Note: we already have an error to return, so we ignore the result of
            // the following call.
            let _result = self
                .with_rw_tx(
                    |chainstate_ref| {
                        chainstate_ref.update_block_status(block_index.clone(), status)
                    },
                    |attempt_number| {
                        log::info!(
                            "Updating status for block {block_id}, attempt #{attempt_number}"
                        );
                    },
                    |attempts_count, db_err| {
                        BlockError::DbCommitError(
                            attempts_count,
                            db_err,
                            DbCommittingContext::BlockStatus(block_id),
                        )
                    },
                )
                .log_err();
        }

        if let Some(first_invalid_block_id) = first_invalid_block_id {
            // Again, we ignore the result here.
            let _result = self.invalidate_stale_block(&first_invalid_block_id, false).log_err();
        }

        Err(err)
    }

    fn broadcast_new_tip_event(&self, new_block_index: &Option<BlockIndex>) {
        match new_block_index {
            Some(ref new_block_index) => {
                let new_height = new_block_index.block_height();
                let new_id = *new_block_index.block_id();
                self.events_controller().broadcast(ChainstateEvent::NewTip(new_id, new_height))
            }
            None => (),
        }
    }

    /// process orphan blocks that depend on the given block, recursively
    fn process_orphans_of(
        &mut self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let mut block_indexes = Vec::new();

        let mut orphan_process_queue: VecDeque<_> = vec![*block_id].into();
        while let Some(block_id) = orphan_process_queue.pop_front() {
            let orphans = self.orphan_blocks_pool_mut().take_all_children_of(&block_id.into());
            // whatever was pulled from orphans should be processed next in the queue
            orphan_process_queue.extend(orphans.iter().map(|b| b.get_id()));
            let (orphan_block_indexes, block_errors): (Vec<Option<BlockIndex>>, Vec<BlockError>) =
                orphans
                    .into_iter()
                    .map(|blk| self.attempt_to_process_block(blk, BlockSource::Local))
                    .partition_result();

            block_indexes.extend(orphan_block_indexes.into_iter());

            block_errors.into_iter().for_each(|e| match &self.custom_orphan_error_hook() {
                Some(handler) => handler(&e),
                None => logging::log::error!("Failed to process a chain of orphan blocks: {}", e),
            });
        }

        // since we processed blocks in order, the last one is the tip
        let new_block_index_after_orphans = block_indexes.into_iter().flatten().next_back();

        Ok(new_block_index_after_orphans)
    }

    /// remove orphan blocks that depend on the given block, recursively
    pub(super) fn remove_orphans_of(&mut self, block_id: &Id<Block>) {
        let mut orphan_process_queue: VecDeque<_> = vec![*block_id].into();
        while let Some(block_id) = orphan_process_queue.pop_front() {
            let orphans = self.orphan_blocks_pool_mut().take_all_children_of(&block_id.into());
            orphan_process_queue.extend(orphans.iter().map(|b| b.get_id()));
        }
    }

    fn process_block_and_related_orphans(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let block_id = block.get_id();

        let result = self.attempt_to_process_block(block, block_source)?;

        let new_block_index_after_orphans = self.process_orphans_of(&block_id)?;

        let result = match new_block_index_after_orphans {
            Some(result_from_orphan) => Some(result_from_orphan),
            None => result,
        };

        self.broadcast_new_tip_event(&result);

        if let Some(ref bi) = result {
            log::info!(
                "New tip in chainstate {} with height {}, timestamp: {}",
                bi.block_id(),
                bi.block_height(),
                bi.block_timestamp(),
            );

            self.set_is_initial_block_download_finished(self.is_fresh_block(&bi.block_timestamp()));
        }

        Ok(result)
    }

    /// returns the block index of the new tip
    pub fn process_block(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        self.process_block_and_related_orphans(block, block_source)
    }

    fn check_legitimate_orphan(
        &mut self,
        block_source: BlockSource,
        block: WithId<Block>,
    ) -> Result<WithId<Block>, OrphanCheckError> {
        let chainstate_ref = self.make_db_tx_ro().map_err(OrphanCheckError::from)?;

        let prev_block_id = block.prev_block_id();

        let block_index_found = chainstate_ref
            .get_gen_block_index(&prev_block_id)
            .map_err(OrphanCheckError::PrevBlockIndexNotFound)
            .log_err()?
            .is_some();

        drop(chainstate_ref);

        if block_source == BlockSource::Local && !block_index_found {
            self.new_orphan_block(block).log_err()?;
            return Err(OrphanCheckError::LocalOrphan);
        }
        Ok(block)
    }

    /// Mark new block as an orphan
    fn new_orphan_block(&mut self, block: WithId<Block>) -> Result<(), OrphanCheckError> {
        match self.orphan_blocks_pool_mut().add_block(block) {
            Ok(_) => Ok(()),
            Err(err) => (*err).into(),
        }
    }
}

/// The error type for integrate_block.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
enum BlockIntegrationError {
    #[error("Reorg error during block integration: {0}; resulting block status is {1}; first bad block id is {2}")]
    ConnectBlockErrorDuringReorg(BlockError, BlockStatus, Id<Block>),
    #[error("Generic error during block integration: {0}; resulting block status is {1}")]
    OtherValidationError(BlockError, BlockStatus),
    #[error("Failed to commit block data for block {0} after {1} attempts: {2}")]
    BlockCommitError(Id<Block>, usize, chainstate_storage::Error),
    #[error("Generic error: {0}")]
    OtherNonValidationError(#[from] BlockError),
}

// This is needed by with_rw_tx
impl From<chainstate_storage::Error> for BlockIntegrationError {
    fn from(error: chainstate_storage::Error) -> Self {
        Self::OtherNonValidationError(BlockError::StorageError(error))
    }
}
