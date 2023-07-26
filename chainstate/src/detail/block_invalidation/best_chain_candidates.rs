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

use std::collections::BTreeSet;

use thiserror::Error;

use crate::{detail::chainstateref::ChainstateRef, TransactionVerificationStrategy};
use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{BlockIndex, GenBlockIndex, PropertyQueryError};
use common::{chain::Block, primitives::Id, Uint256};
use utils::tap_error_log::LogError;

#[derive(Eq, Copy, Clone, Debug)]
pub struct BestChainCandidatesItem {
    chain_trust: Uint256,
    block_id: Id<Block>,
}

impl BestChainCandidatesItem {
    pub fn chain_trust(&self) -> &Uint256 {
        &self.chain_trust
    }

    pub fn block_id(&self) -> &Id<Block> {
        &self.block_id
    }

    fn from_block_index(block_index: &BlockIndex) -> Self {
        BestChainCandidatesItem {
            block_id: *block_index.block_id(),
            chain_trust: block_index.chain_trust(),
        }
    }
}

impl Ord for BestChainCandidatesItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Note: the order of fields is important - we first compare items by chain_trust
        // and use block_id only as a tiebreaker.
        (&self.chain_trust, &self.block_id).cmp(&(&other.chain_trust, &other.block_id))
    }
}

impl PartialOrd for BestChainCandidatesItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for BestChainCandidatesItem {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

/// A collection of candidates for the best chain.
#[derive(Debug)]
pub struct BestChainCandidates(BTreeSet<BestChainCandidatesItem>);

impl BestChainCandidates {
    /// Collect candidates for the best chain that have chain trust bigger than or equal to
    /// the specified one.
    /// Only consider branches that start above the minimum height where reorgs are allowed.
    // FIXME: abstract ChainstateRef away here (e.g. hide it behind a trait) so that
    // BestChainCandidates can be unit-tested more easily. Then write the tests.
    pub fn new<S, V>(
        chainstate_ref: &ChainstateRef<S, V>,
        min_chain_trust: Uint256,
    ) -> Result<BestChainCandidates, BestChainCandidatesError>
    where
        S: BlockchainStorageRead,
        V: TransactionVerificationStrategy,
    {
        let min_height_with_allowed_reorg = chainstate_ref.get_min_height_with_allowed_reorg()?;

        // Note: currently, this call has linear complexity with respect to the total number of
        // blocks, see the TODO near the function itself.
        let block_ids_by_height = chainstate_ref
            .get_higher_block_ids_sorted_by_height(min_height_with_allowed_reorg)
            .log_err()?;

        let mut candidates = BTreeSet::new();
        let mut seen_parents = BTreeSet::new();

        // Iterate over the block ids from bigger block height to lower, so that we see children
        // before parents.
        // Note: currently, this loop has the complexity of (the number of tips higher than
        // min_height_with_allowed_reorg) x (the average height of the common ancestor of each
        // tip and the current best block). The latter part can be improved a little by
        // optimizing last_common_ancestor_in_main_chain, see the comment below.
        // TODO: is there a way to make the complexity "more linear" in general?
        for block_id in block_ids_by_height.iter().rev() {
            let block_index = chainstate_ref.get_existing_block_index(block_id).log_err()?;

            // Only consider valid blocks with enough chain trust.
            if block_index.status().is_ok() && block_index.chain_trust() >= min_chain_trust {
                // Only add the tips of branches to the list of candidates.
                if !seen_parents.contains(block_id.into()) {
                    let gen_block_index: GenBlockIndex = block_index.clone().into();
                    // Note: this function can be optimized, see the TODO near it.
                    let last_common_ancestor = chainstate_ref
                        .last_common_ancestor_in_main_chain(&gen_block_index)
                        .log_err()?;

                    // Only consider chains that start above the minimum height that allows reorgs.
                    if last_common_ancestor.block_height() >= min_height_with_allowed_reorg {
                        let candidate = BestChainCandidatesItem::from_block_index(&block_index);
                        candidates.insert(candidate);
                    }
                }
                seen_parents.insert(*block_index.prev_block_id());
            }
        }

        Ok(BestChainCandidates(candidates))
    }

    // Remove the block and its descendants, which must be specified in descendants_indices,
    // from the set and add the block's parent block to the set.
    pub fn on_block_invalidated<S, V>(
        &mut self,
        chainstate_ref: &ChainstateRef<S, V>,
        invalidated_block_index: &BlockIndex,
        descendants_indices: &[BlockIndex],
    ) -> Result<(), BestChainCandidatesError>
    where
        S: BlockchainStorageRead,
        V: TransactionVerificationStrategy,
    {
        self.remove(chainstate_ref, invalidated_block_index);

        for descendant_index in descendants_indices {
            self.remove(chainstate_ref, descendant_index);
        }

        // Add the parent to the list
        if let Some(prev_block_id) = invalidated_block_index
            .prev_block_id()
            .classify(chainstate_ref.chain_config())
            .chain_block_id()
        {
            let prev_block_index = chainstate_ref.get_existing_block_index(&prev_block_id)?;
            self.add(chainstate_ref, &prev_block_index);
        }

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn best_item(&self) -> Option<&BestChainCandidatesItem> {
        self.0.last()
    }

    fn add<S, V>(&mut self, _chainstate_ref: &ChainstateRef<S, V>, block_index: &BlockIndex)
    where
        S: BlockchainStorageRead,
        V: TransactionVerificationStrategy,
    {
        self.0.insert(BestChainCandidatesItem::from_block_index(block_index));
    }

    fn remove<S, V>(&mut self, _chainstate_ref: &ChainstateRef<S, V>, block_index: &BlockIndex)
    where
        S: BlockchainStorageRead,
        V: TransactionVerificationStrategy,
    {
        self.0.remove(&BestChainCandidatesItem::from_block_index(block_index));
    }
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BestChainCandidatesError {
    #[error("Error querying property: `{0}`")]
    PropertyQueryError(#[from] PropertyQueryError),
}
