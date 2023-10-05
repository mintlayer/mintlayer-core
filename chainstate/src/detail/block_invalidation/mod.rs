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

mod best_chain_candidates;
#[cfg(test)]
mod best_chain_candidates_tests;

use derive_more::Display;
use thiserror::Error;

use self::best_chain_candidates::BestChainCandidates;
use super::{chainstateref::ChainstateRef, Chainstate};
use crate::{detail::chainstateref::ReorgError, BlockError, TransactionVerificationStrategy};
use chainstate_storage::{BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite};
use chainstate_types::{BlockIndex, BlockStatus, GenBlockIndex, PropertyQueryError};
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
    Uint256,
};
use logging::log;
use utils::{ensure, tap_error_log::LogError};

pub use best_chain_candidates::BestChainCandidatesError;

pub struct BlockInvalidator<'a, S, V> {
    chainstate: &'a mut Chainstate<S, V>,
}

pub enum IsExplicit {
    No,
    Yes,
}

impl<'a, S: BlockchainStorage, V: TransactionVerificationStrategy> BlockInvalidator<'a, S, V> {
    pub fn new(chainstate: &'a mut Chainstate<S, V>) -> BlockInvalidator<'a, S, V> {
        BlockInvalidator { chainstate }
    }

    /// Invalidate the specified stale block and its descendants; `is_explicit_invalidation`
    /// specifies whether the invalidation is being triggered implicitly during block processing
    /// or explicitly via ChainstateInterface.
    fn invalidate_stale_block(
        &mut self,
        block_id: &Id<Block>,
        is_explicit_invalidation: IsExplicit,
    ) -> Result<Vec<BlockIndex>, BlockInvalidatorError> {
        let block_indices_to_invalidate = {
            let chainstate_ref =
                self.chainstate.make_db_tx_ro().map_err(BlockInvalidatorError::from).log_err()?;
            assert!(!is_block_in_main_chain(&chainstate_ref, block_id.into()).log_err()?);
            chainstate_ref
                .collect_block_indices_in_branch(block_id)
                .map_err(BlockInvalidatorError::BlockIndicesForBranchQueryError)
                .log_err()?
        };

        self.chainstate
            .with_rw_tx(
                |chainstate_ref| {
                    for (i, block_index) in block_indices_to_invalidate.iter().enumerate() {
                        let mut status = block_index.status();
                        if i == 0 {
                            match is_explicit_invalidation {
                                IsExplicit::Yes => status.set_explicitly_invalidated(),
                                IsExplicit::No => status.set_validation_failed(),
                            }
                        } else {
                            status.set_has_invalid_parent();
                        }

                        update_block_status(chainstate_ref, block_index.clone(), status)?;
                    }

                    Ok(())
                },
                |attempt_number| {
                    log::info!("Invalidating block {block_id}, attempt #{attempt_number}");
                },
                |attempts_count, db_err| {
                    BlockInvalidatorError::DbCommitError(
                        attempts_count,
                        db_err,
                        DbCommittingContext::InvalidatedBlockTreeStatuses(*block_id),
                    )
                },
            )
            .log_err()?;

        self.chainstate.remove_orphans_of(block_id);

        Ok(block_indices_to_invalidate)
    }

    /// Invalidate the specified block and its descendants; `is_explicit_invalidation`
    /// specifies whether the invalidation is being triggered implicitly during block processing
    /// or explicitly via ChainstateInterface.
    pub fn invalidate_block(
        &mut self,
        block_id: &Id<Block>,
        is_explicit_invalidation: IsExplicit,
    ) -> Result<(), BlockInvalidatorError> {
        let (block_index, best_block_index, min_height_with_allowed_reorg) = {
            let chainstate_ref = self.chainstate.make_db_tx_ro().log_err()?;
            let is_block_in_main_chain =
                is_block_in_main_chain(&chainstate_ref, block_id.into()).log_err()?;

            if !is_block_in_main_chain {
                drop(chainstate_ref);
                self.invalidate_stale_block(block_id, is_explicit_invalidation)?;
                return Ok(());
            }

            let block_index = get_existing_block_index(&chainstate_ref, block_id).log_err()?;
            let best_block_index = get_best_block_index(&chainstate_ref).log_err()?;
            let min_height_with_allowed_reorg = get_min_height_with_allowed_reorg(&chainstate_ref)?;

            (block_index, best_block_index, min_height_with_allowed_reorg)
        };

        let best_block_id = best_block_index
            .block_id()
            .classify(&self.chainstate.chain_config)
            .chain_block_id()
            .expect("Attempt to invalidate genesis");

        ensure!(
            block_index.block_height() > min_height_with_allowed_reorg,
            BlockInvalidatorError::BlockTooDeepToInvalidate(*block_id)
        );

        self.chainstate.with_rw_tx(
            |chainstate_ref| {
                let disconnect_until_id = block_index.prev_block_id();
                chainstate_ref.disconnect_until(&best_block_id, disconnect_until_id).map_err(
                    |err| BlockInvalidatorError::BlocksDisconnectionError { disconnect_until: *disconnect_until_id, error: Box::new(err) })
            },
            |attempt_number| {
                log::info!("Disconnecting main chain blocks until block {block_id}, attempt #{attempt_number}");
            },
            |attempts_count, db_err| {
                BlockInvalidatorError::DbCommitError(attempts_count, db_err, DbCommittingContext::BlockTreeDisconnection(*block_id))
            },
        )?;

        self.invalidate_stale_block(block_id, is_explicit_invalidation)?;

        let reorg_succeeded = self.find_and_activate_best_chain()?;

        if !reorg_succeeded {
            log::warn!("No better chain was found after invalidating block {block_id}");
        }

        Ok(())
    }

    /// Search among stale chains for ones with more trust than the current mainchain;
    /// activate the best valid chain among them.
    /// Return true if a reorg has occurred.
    fn find_and_activate_best_chain(&mut self) -> Result<bool, BlockInvalidatorError> {
        let (cur_best_chain_trust, best_chain_candidates) = {
            let chainstate_ref = self.chainstate.make_db_tx_ro().log_err()?;
            let cur_best_block_index = get_best_block_index(&chainstate_ref)?;
            let cur_best_chain_trust = cur_best_block_index.chain_trust();

            let best_chain_candidates = BestChainCandidates::new(
                &chainstate_ref,
                (cur_best_chain_trust + Uint256::ONE)
                    .expect("Chain trust won't be saturated in a very long time"),
            )?;

            (cur_best_chain_trust, best_chain_candidates)
        };

        let mut best_chain_candidates = best_chain_candidates;

        while !best_chain_candidates.is_empty() {
            let candidate =
                *best_chain_candidates.best_item().expect("Item missing after !is_empty check");
            assert!(*candidate.chain_trust() > cur_best_chain_trust);

            let result = self.chainstate.with_rw_tx(
                |chainstate_ref| {
                    let block_index =
                        get_existing_block_index(chainstate_ref, candidate.block_id())?;
                    let reorg_occured = chainstate_ref
                        .activate_best_chain(&block_index)
                        .map_err(ReorgDuringInvalidationError::ReorgError)?;
                    assert!(reorg_occured);
                    Ok(())
                },
                |attempt_number| {
                    log::info!(
                        "Processing block {}, attempt #{}",
                        candidate.block_id(),
                        attempt_number
                    );
                },
                |attempts_count, db_err| {
                    ReorgDuringInvalidationError::OtherError(BlockInvalidatorError::DbCommitError(
                        attempts_count,
                        db_err,
                        DbCommittingContext::Block(*candidate.block_id()),
                    ))
                },
            );

            match result {
                Ok(()) => return Ok(true),
                Err(ReorgDuringInvalidationError::OtherDbError(err)) => {
                    return Err(BlockInvalidatorError::StorageError(err));
                }
                Err(ReorgDuringInvalidationError::OtherError(err)) => {
                    return Err(err);
                }
                Err(ReorgDuringInvalidationError::ReorgError(err)) => match err {
                    ReorgError::OtherError(err) => {
                        return Err(BlockInvalidatorError::GenericReorgError(Box::new(err)));
                    }
                    ReorgError::ConnectTipFailed(first_bad_block, _)
                    | ReorgError::BlockDataMissing(first_bad_block) => {
                        let invalidated_block_indices =
                            self.invalidate_stale_block(&first_bad_block, IsExplicit::No)?;
                        assert!(!invalidated_block_indices.is_empty());
                        best_chain_candidates
                            .on_block_invalidated(
                                &self
                                    .chainstate
                                    .make_db_tx_ro()
                                    .map_err(BlockInvalidatorError::from)
                                    .log_err()?,
                                &invalidated_block_indices[0],
                                &invalidated_block_indices[1..],
                            )
                            .log_err()?;
                    }
                },
            }
        }

        Ok(false)
    }

    /// Reset fail flags in all blocks in the subtree that starts at the specified block.
    pub fn reset_block_failure_flags(
        &mut self,
        block_id: &Id<Block>,
    ) -> Result<(), BlockInvalidatorError> {
        let block_indices_to_clear = {
            let chainstate_ref =
                self.chainstate.make_db_tx_ro().map_err(BlockInvalidatorError::from).log_err()?;

            chainstate_ref
                .collect_block_indices_in_branch(block_id)
                .map_err(BlockInvalidatorError::BlockIndicesForBranchQueryError)
                .log_err()?
        };

        self.chainstate.with_rw_tx(
            |chainstate_ref| {
                for cur_index in &block_indices_to_clear {
                    update_block_status(
                        chainstate_ref,
                        cur_index.clone(),
                        cur_index.status().with_cleared_fail_bits(),
                    )?;
                }

                Ok(())
            },
            |attempt_number| {
                log::info!("Clearing block failure flags, attempt #{}", attempt_number);
            },
            |attempts_count, db_err| {
                BlockInvalidatorError::DbCommitError(
                    attempts_count,
                    db_err,
                    DbCommittingContext::ClearedBlockTreeStatuses(*block_id),
                )
            },
        )?;

        self.find_and_activate_best_chain()?;

        Ok(())
    }
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockInvalidatorError {
    #[error("Block storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("The block {0} is too deep to invalidate")]
    BlockTooDeepToInvalidate(Id<Block>),
    #[error("Error manipulating best chain candidates: {0}")]
    BestChainCandidatesError(#[from] BestChainCandidatesError),
    #[error("Error disconnecting blocks until block {disconnect_until}: {error}")]
    BlocksDisconnectionError {
        disconnect_until: Id<GenBlock>,
        error: Box<BlockError>,
    },
    #[error("Error updating block status for block {0}: {1}")]
    BlockStatusUpdateError(Id<Block>, Box<BlockError>),
    #[error("Generic error during reorg: {0}")]
    GenericReorgError(Box<BlockError>),
    #[error("Failed to commit to the DB after {0} attempts: {1}, context: {2}")]
    DbCommitError(usize, chainstate_storage::Error, DbCommittingContext),

    #[error("Failed to obtain best block index: {0}")]
    BlockIndicesForBranchQueryError(PropertyQueryError),
    #[error("Failed to determine if the block {0} is in mainchain: {1}")]
    IsBlockInMainChainQueryError(Id<GenBlock>, PropertyQueryError),
    #[error("Failed to obtain the minimum height with allowed reorgs: {0}")]
    MinHeightForReorgQueryError(PropertyQueryError),
    #[error("Failed to obtain best block index: {0}")]
    BestBlockIndexQueryError(PropertyQueryError),
    #[error("Failed to obtain block index for block {0}: {1}")]
    BlockIndexQueryError(Id<GenBlock>, PropertyQueryError),
}

#[derive(Debug, Display, PartialEq, Eq, Clone)]
pub enum DbCommittingContext {
    #[display(fmt = "committing block {}", _0)]
    Block(Id<Block>),
    #[display(fmt = "committing block status for block {}", _0)]
    InvalidatedBlockTreeStatuses(Id<Block>),
    #[display(fmt = "committing cleared blocks statuses (root block: {})", _0)]
    ClearedBlockTreeStatuses(Id<Block>),
    #[display(fmt = "committing block tree disconnection (root block: {})", _0)]
    BlockTreeDisconnection(Id<Block>),
}

/// The error type for reorgs that happen inside invalidate_block.
#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, PartialEq, Eq, Clone)]
enum ReorgDuringInvalidationError {
    #[error("Reorg error: {0}")]
    ReorgError(ReorgError),
    #[error("Other error: {0}")]
    OtherError(#[from] BlockInvalidatorError),
    #[error("Database error: {0}")]
    OtherDbError(#[from] chainstate_storage::Error),
}

fn is_block_in_main_chain<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    block_id: &Id<GenBlock>,
) -> Result<bool, BlockInvalidatorError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .is_block_in_main_chain(block_id)
        .map_err(|err| BlockInvalidatorError::IsBlockInMainChainQueryError(*block_id, err))
}

fn get_min_height_with_allowed_reorg<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
) -> Result<BlockHeight, BlockInvalidatorError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_min_height_with_allowed_reorg()
        .map_err(BlockInvalidatorError::MinHeightForReorgQueryError)
}

fn get_best_block_index<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
) -> Result<GenBlockIndex, BlockInvalidatorError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_best_block_index()
        .map_err(BlockInvalidatorError::BestBlockIndexQueryError)
}

fn get_existing_block_index<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    block_id: &Id<Block>,
) -> Result<BlockIndex, BlockInvalidatorError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_existing_block_index(block_id)
        .map_err(|err| BlockInvalidatorError::BlockIndexQueryError((*block_id).into(), err))
}

fn update_block_status<S, V>(
    chainstate_ref: &mut ChainstateRef<S, V>,
    block_index: BlockIndex,
    block_status: BlockStatus,
) -> Result<(), BlockInvalidatorError>
where
    S: BlockchainStorageWrite,
    V: TransactionVerificationStrategy,
{
    let block_id = *block_index.block_id();
    chainstate_ref
        .update_block_status(block_index, block_status)
        .map_err(|err| BlockInvalidatorError::BlockStatusUpdateError(block_id, Box::new(err)))
}
