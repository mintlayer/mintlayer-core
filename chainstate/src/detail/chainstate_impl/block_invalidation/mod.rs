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

use thiserror::Error;

use super::{utils::*, Chainstate};
use crate::{
    detail::{chainstateref::ReorgError, DbCommittingContext},
    BlockError, TransactionVerificationStrategy,
};
use best_chain_candidates::BestChainCandidates;
use chainstate_storage::BlockchainStorage;
use chainstate_types::BlockIndex;
use common::{chain::Block, primitives::Id, Uint256};
use logging::log;
use utils::{ensure, tap_error_log::LogError};

pub mod best_chain_candidates;

impl<S: BlockchainStorage, V: TransactionVerificationStrategy> Chainstate<S, V> {
    /// Invalidate the specified stale block and its descendants; `is_explicit_invalidation`
    /// specifies whether the invalidation is being triggered implicitly during block processing
    /// or explicitly via `invalidate_block`.
    pub(super) fn invalidate_stale_block(
        &mut self,
        block_id: &Id<Block>,
        is_explicit_invalidation: bool,
    ) -> Result<Vec<BlockIndex>, BlockError> {
        let block_indices_to_invalidate = {
            let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from).log_err()?;
            assert!(!is_block_in_main_chain(&chainstate_ref, block_id.into()).log_err()?);
            chainstate_ref
                .collect_block_indices_in_branch(block_id)
                .map_err(BlockError::BlockIndicesForBranchQueryError)
                .log_err()?
        };

        self.with_rw_tx(
            |chainstate_ref| {
                for (i, block_index) in block_indices_to_invalidate.iter().enumerate() {
                    let mut status = block_index.status();
                    if i == 0 {
                        if is_explicit_invalidation {
                            status.set_explicitly_invalidated()
                        } else {
                            status.set_validation_failed()
                        }
                    } else {
                        status.set_has_invalid_parent();
                    }

                    chainstate_ref.update_block_status(block_index.clone(), status)?;
                }

                Ok(())
            },
            |attempt_number| {
                log::info!("Invalidating block {block_id}, attempt #{attempt_number}");
            },
            |attempts_count, db_err| {
                BlockError::DbCommitError(
                    attempts_count,
                    db_err,
                    DbCommittingContext::InvalidatedBlockTreeStatuses(*block_id),
                )
            },
        )
        .log_err()?;

        self.remove_orphans_of(block_id);

        Ok(block_indices_to_invalidate)
    }

    /// Invalidate the specified block and its descendants.
    pub fn invalidate_block(&mut self, block_id: &Id<Block>) -> Result<(), BlockError> {
        let (is_block_on_main_chain, block_index, best_block_index, min_height_with_allowed_reorg) = {
            let chainstate_ref = self.make_db_tx_ro().log_err()?;
            let is_block_in_main_chain =
                is_block_in_main_chain(&chainstate_ref, block_id.into()).log_err()?;
            let block_index = get_existing_block_index(&chainstate_ref, block_id).log_err()?;
            let best_block_index = get_best_block_index(&chainstate_ref).log_err()?;
            let min_height_with_allowed_reorg = get_min_height_with_allowed_reorg(&chainstate_ref)?;

            (
                is_block_in_main_chain,
                block_index,
                best_block_index,
                min_height_with_allowed_reorg,
            )
        };

        if !is_block_on_main_chain {
            self.invalidate_stale_block(block_id, true)?;
            return Ok(());
        }

        let best_block_id = best_block_index
            .block_id()
            .classify(self.chain_config())
            .chain_block_id()
            .expect("Attempt to invalidate genesis");

        ensure!(
            block_index.block_height() > min_height_with_allowed_reorg,
            BlockError::BlockTooDeepToInvalidate(*block_id)
        );

        self.with_rw_tx(
            |chainstate_ref| {
                chainstate_ref.disconnect_until(&best_block_id, block_index.prev_block_id())
            },
            |attempt_number| {
                log::info!("Disconnecting main chain blocks until block {block_id}, attempt #{attempt_number}");
            },
            |attempts_count, db_err| {
                BlockError::DbCommitError(attempts_count, db_err, DbCommittingContext::BlockTreeDisconnection(*block_id))
            },
        )?;

        self.invalidate_stale_block(block_id, true)?;

        let reorg_succeeded = self.find_and_activate_best_chain()?;

        if !reorg_succeeded {
            log::warn!("No better chain was found after invalidating block {block_id}");
        }

        Ok(())
    }

    /// Search among stale chains for ones with more trust than the current mainchain;
    /// activate the best valid chain among them.
    /// Return true if a reorg has occurred.
    fn find_and_activate_best_chain(&mut self) -> Result<bool, BlockError> {
        let (cur_best_chain_trust, best_chain_candidates) = {
            let chainstate_ref = self.make_db_tx_ro().log_err()?;
            let cur_best_block_index = get_best_block_index(&chainstate_ref)?;
            let cur_best_chain_trust = cur_best_block_index.chain_trust();

            let best_chain_candidates =
                BestChainCandidates::new(&chainstate_ref, cur_best_chain_trust + Uint256::ONE)?;

            (cur_best_chain_trust, best_chain_candidates)
        };

        let mut best_chain_candidates = best_chain_candidates;

        while !best_chain_candidates.is_empty() {
            let candidate =
                *best_chain_candidates.best_item().expect("Item missing after !is_empty check");
            assert!(candidate.chain_trust > cur_best_chain_trust);

            let result = self.with_rw_tx(
                |chainstate_ref| {
                    let block_index =
                        get_existing_block_index(chainstate_ref, &candidate.block_id)?;
                    let reorg_occured = chainstate_ref
                        .activate_best_chain(&block_index)
                        .map_err(ReorgDuringInvalidationError::ReorgError)?;
                    assert!(reorg_occured);
                    Ok(())
                },
                |attempt_number| {
                    log::info!(
                        "Processing block {}, attempt #{}",
                        candidate.block_id,
                        attempt_number
                    );
                },
                |attempts_count, db_err| {
                    ReorgDuringInvalidationError::OtherError(BlockError::DbCommitError(
                        attempts_count,
                        db_err,
                        DbCommittingContext::Block(candidate.block_id),
                    ))
                },
            );

            match result {
                Ok(()) => return Ok(true),
                Err(ReorgDuringInvalidationError::OtherDbError(err)) => {
                    return Err(BlockError::StorageError(err));
                }
                Err(ReorgDuringInvalidationError::OtherError(err)) => {
                    return Err(err);
                }
                Err(ReorgDuringInvalidationError::ReorgError(err)) => match err {
                    ReorgError::OtherError(err) => {
                        return Err(err);
                    }
                    ReorgError::ConnectTipFailed(first_bad_block, _)
                    | ReorgError::BlockDataMissing(first_bad_block) => {
                        let invalidated_block_indices =
                            self.invalidate_stale_block(&first_bad_block, false)?;
                        assert!(!invalidated_block_indices.is_empty());
                        best_chain_candidates
                            .on_block_invalidated(
                                &self.make_db_tx_ro().map_err(BlockError::from).log_err()?,
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
    pub fn reset_block_failure_flags(&mut self, block_id: &Id<Block>) -> Result<(), BlockError> {
        let block_indices_to_clear = {
            let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from).log_err()?;

            chainstate_ref
                .collect_block_indices_in_branch(block_id)
                .map_err(BlockError::BlockIndicesForBranchQueryError)
                .log_err()?
        };

        self.with_rw_tx(
            |chainstate_ref| {
                for cur_index in &block_indices_to_clear {
                    chainstate_ref.update_block_status(
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
                BlockError::DbCommitError(
                    attempts_count,
                    db_err,
                    DbCommittingContext::ClearedBlockTreeStatuses(*block_id),
                )
            },
        )?;

        self.find_and_activate_best_chain()?;

        Ok(())
    }

    pub(crate) fn get_best_chain_candidates(
        &self,
        min_chain_trust: Uint256,
    ) -> Result<BestChainCandidates, BlockError> {
        let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from).log_err()?;
        Ok(BestChainCandidates::new(&chainstate_ref, min_chain_trust)?)
    }
}

/// The error type for reorgs that happen inside invalidate_block.
#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, PartialEq, Eq, Clone)]
enum ReorgDuringInvalidationError {
    #[error("Reorg error: {0}")]
    ReorgError(ReorgError),
    #[error("Other error: {0}")]
    OtherError(#[from] BlockError),
    #[error("Database error: {0}")]
    OtherDbError(#[from] chainstate_storage::Error),
}
