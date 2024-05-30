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
use chainstate_types::{BlockIndex, BlockStatus, GenBlockIndex, PropertyQueryError};
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
    Uint256,
};
use utils::{log_error, tap_log::TapLog};

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

    fn from_block_info<BI: BlockInfo>(block_info: &BI) -> Self {
        BestChainCandidatesItem {
            block_id: block_info.id(),
            chain_trust: block_info.chain_trust(),
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
    #[log_error]
    pub fn new<Chs: ChainstateAccessor>(
        chs: &Chs,
        min_chain_trust: Uint256,
    ) -> Result<BestChainCandidates, BestChainCandidatesError> {
        let min_height_with_allowed_reorg = chs.min_height_with_allowed_reorg()?;

        let block_ids_by_height = chs
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
            let block_info = chs.get_block_info(block_id).log_err()?;

            // Only consider valid blocks with enough chain trust.
            if block_info.status().is_ok() && block_info.chain_trust() >= min_chain_trust {
                // Only add the tips of branches to the list of candidates.
                if !seen_parents.contains(block_id.into()) {
                    let gen_block_info = Chs::block_info_to_gen(block_info.clone());
                    // Note: this function can be optimized, see the TODO near it.
                    let last_common_ancestor =
                        chs.last_common_ancestor_in_main_chain(&gen_block_info).log_err()?;

                    // Only consider chains that start above the minimum height that allows reorgs.
                    if last_common_ancestor.height() >= min_height_with_allowed_reorg {
                        let candidate = BestChainCandidatesItem::from_block_info(&block_info);
                        candidates.insert(candidate);
                    }
                }
                seen_parents.insert(block_info.parent_id());
            }
        }

        Ok(BestChainCandidates(candidates))
    }

    // Remove the block and its descendants, which must be specified in descendants_indices,
    // from the set and add the block's parent block to the set if its chain trust is not less than
    // the specified minimum.
    #[log_error]
    pub fn remove_tree_add_parent<Chs: ChainstateAccessor>(
        &mut self,
        chs: &Chs,
        root_block_info: &Chs::BlockInfo,
        descendant_block_infos: &[Chs::BlockInfo],
        min_chain_trust: Uint256,
    ) -> Result<(), BestChainCandidatesError> {
        self.remove(root_block_info);

        for descendant_info in descendant_block_infos {
            self.remove(descendant_info);
        }

        // Add the parent to the list
        if let Some(parent_block_id) = chs.gen_block_id_to_normal(&root_block_info.parent_id()) {
            let parent_block_info = chs.get_block_info(&parent_block_id)?;
            if parent_block_info.chain_trust() >= min_chain_trust {
                self.add(&parent_block_info);
            }
        }

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn best_item(&self) -> Option<&BestChainCandidatesItem> {
        self.0.last()
    }

    #[allow(unused)]
    pub fn elements(&self) -> impl Iterator<Item = &BestChainCandidatesItem> {
        self.0.iter()
    }

    fn add<BI: BlockInfo>(&mut self, block_info: &BI) {
        self.0.insert(BestChainCandidatesItem::from_block_info(block_info));
    }

    fn remove<BI: BlockInfo>(&mut self, block_info: &BI) {
        self.0.remove(&BestChainCandidatesItem::from_block_info(block_info));
    }
}

// The purpose of this trait is to abstract away ChainstateRef in order to make
// unit-testing BestChainCandidates easier.
pub trait ChainstateAccessor {
    type BlockInfo: BlockInfo;
    type GenBlockInfo: GenBlockInfo;

    fn min_height_with_allowed_reorg(&self) -> Result<BlockHeight, PropertyQueryError>;

    fn get_higher_block_ids_sorted_by_height(
        &self,
        start_from: BlockHeight,
    ) -> Result<Vec<Id<Block>>, PropertyQueryError>;

    fn get_block_info(&self, block_id: &Id<Block>) -> Result<Self::BlockInfo, PropertyQueryError>;

    fn last_common_ancestor_in_main_chain(
        &self,
        block_info: &Self::GenBlockInfo,
    ) -> Result<Self::GenBlockInfo, PropertyQueryError>;

    fn block_info_to_gen(bi: Self::BlockInfo) -> Self::GenBlockInfo;

    fn gen_block_id_to_normal(&self, id: &Id<GenBlock>) -> Option<Id<Block>>;
}

pub trait BlockInfo: Clone {
    fn id(&self) -> Id<Block>;
    fn parent_id(&self) -> Id<GenBlock>;
    #[allow(dead_code)]
    fn height(&self) -> BlockHeight;
    fn chain_trust(&self) -> Uint256;
    fn status(&self) -> BlockStatus;
}

pub trait GenBlockInfo: Clone {
    fn height(&self) -> BlockHeight;
}

impl<'a, S, V> ChainstateAccessor for ChainstateRef<'a, S, V>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    type BlockInfo = BlockIndex;
    type GenBlockInfo = GenBlockIndex;

    #[log_error]
    fn min_height_with_allowed_reorg(&self) -> Result<BlockHeight, PropertyQueryError> {
        self.get_min_height_with_allowed_reorg()
    }

    #[log_error]
    fn get_higher_block_ids_sorted_by_height(
        &self,
        start_from: BlockHeight,
    ) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        self.get_higher_block_ids_sorted_by_height(start_from)
    }

    #[log_error]
    fn get_block_info(&self, block_id: &Id<Block>) -> Result<BlockIndex, PropertyQueryError> {
        self.get_existing_block_index(block_id)
    }

    #[log_error]
    fn last_common_ancestor_in_main_chain(
        &self,
        block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        self.last_common_ancestor_in_main_chain(block_index)
    }

    fn block_info_to_gen(bi: Self::BlockInfo) -> Self::GenBlockInfo {
        bi.into()
    }

    fn gen_block_id_to_normal(&self, id: &Id<GenBlock>) -> Option<Id<Block>> {
        id.classify(self.chain_config()).chain_block_id()
    }
}

impl BlockInfo for BlockIndex {
    fn id(&self) -> Id<Block> {
        *self.block_id()
    }

    fn parent_id(&self) -> Id<GenBlock> {
        *self.prev_block_id()
    }

    fn height(&self) -> BlockHeight {
        self.block_height()
    }

    fn chain_trust(&self) -> Uint256 {
        self.chain_trust()
    }

    fn status(&self) -> BlockStatus {
        self.status()
    }
}

impl GenBlockInfo for GenBlockIndex {
    fn height(&self) -> BlockHeight {
        self.block_height()
    }
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BestChainCandidatesError {
    #[error("Error querying property: `{0}`")]
    PropertyQueryError(#[from] PropertyQueryError),
}
