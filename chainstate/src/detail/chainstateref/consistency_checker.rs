// Copyright (c) 2021-2024 RBB S.r.l
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

use std::collections::{BTreeMap, BTreeSet};

use chainstate_storage::BlockchainStorageRead;
use chainstate_types::BlockIndex;
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id, Idable},
};
use itertools::{EitherOrBoth, Itertools};
use logging::log;

use super::calc_min_height_with_allowed_reorg;

// Certain tests check for this panic message.
const PANIC_MSG: &str = "Inconsistent chainstate";

pub struct ConsistencyChecker<'a, DbTx> {
    db_tx: &'a DbTx,
    chain_config: &'a ChainConfig,
    /// Keys (block ids) of the block map.
    block_map_keys: BTreeSet<Id<Block>>,
    /// The entire block index map.
    block_index_map: BTreeMap<Id<Block>, BlockIndex>,
    /// The entire block-by-height map.
    block_by_height_map: BTreeMap<BlockHeight, Id<GenBlock>>,
    /// Best block id from the db.
    best_block_id: Id<GenBlock>,
    /// The min_height_with_allowed_reorg from the db.
    min_height_with_allowed_reorg: BlockHeight,
}

impl<'a, DbTx: BlockchainStorageRead> ConsistencyChecker<'a, DbTx> {
    pub fn new(
        db_tx: &'a DbTx,
        chain_config: &'a ChainConfig,
    ) -> Result<Self, chainstate_storage::Error> {
        let block_map_keys = db_tx.get_block_map_keys()?;
        let block_index_map = db_tx.get_block_index_map()?;
        let block_by_height_map = db_tx.get_block_by_height_map()?;
        let best_block_id = db_tx.get_best_block_id()?.unwrap_or_else(|| {
            panic!("{PANIC_MSG}: best block id not stored");
        });
        let min_height_with_allowed_reorg =
            db_tx.get_min_height_with_allowed_reorg()?.unwrap_or(0.into());

        Ok(Self {
            db_tx,
            chain_config,
            block_map_keys,
            block_index_map,
            block_by_height_map,
            best_block_id,
            min_height_with_allowed_reorg,
        })
    }

    pub fn check(&self) -> Result<(), chainstate_storage::Error> {
        log::debug!("Running chainstate consistency checks");

        self.check_block_index_consistency()?;
        self.check_block_height_map_consistency();

        // TODO: add consistency checks for other maps in the chainstate db.
        // https://github.com/mintlayer/mintlayer-core/issues/1710

        Ok(())
    }

    /// Check the block map vs block index map consistency.
    fn check_block_index_consistency(&self) -> Result<(), chainstate_storage::Error> {
        // Loop over block_map_keys and block_index_map simultaneously via merge_join_by, looking
        // for ids that are present in one of them and missing in the other.
        for merged in self
            .block_map_keys
            .iter()
            .merge_join_by(self.block_index_map.iter(), |id1, (id2, _)| {
                Ord::cmp(id1, id2)
            })
        {
            let (block_id, block_index) = match merged {
                EitherOrBoth::Left(block_id) => {
                    // The block object is present, the index object is not.
                    panic!("{PANIC_MSG}: block index data missing for block {block_id}");
                }
                EitherOrBoth::Right((block_id, block_index)) => {
                    // The block index object is present, the block object is not;
                    // The persistence flag must be unset and the status must not be "ok".
                    assert!(
                        !block_index.is_persisted(),
                        "{PANIC_MSG}: block {block_id} must not be persisted"
                    );
                    assert!(
                        !block_index.status().is_ok(),
                        "{PANIC_MSG}: block {block_id} must not be ok"
                    );

                    (block_id, block_index)
                }
                EitherOrBoth::Both(_, (block_id, block_index)) => {
                    // Both the block and block index objects are present.

                    // The persistence flag must be set.
                    assert!(
                        block_index.is_persisted(),
                        "{PANIC_MSG}: block {block_id} must be persisted"
                    );

                    (block_id, block_index)
                }
            };

            // Check that the id stored in the block index matches the supposed id of the block.
            let block_id_in_block_index = block_index.block_id();
            assert_eq!(
                block_id,
                block_id_in_block_index,
                "{PANIC_MSG}: block id from BlockIndex {block_id_in_block_index} doesn't match {block_id}"
            );

            // If the block is persisted, calculate its id and check that it matches the id
            // that was used as the key. Also compare the block header stored in the index vs the one
            // in the block itself.
            if block_index.is_persisted() {
                let block =
                    self.db_tx.get_block(*block_id)?.expect("The block is known to be present");
                let calculated_block_id = block.get_id();
                assert_eq!(
                    calculated_block_id, *block_id,
                    "{PANIC_MSG}: calculated block id {calculated_block_id} doesn't match {block_id}"
                );

                assert_eq!(
                    block.header(),
                    block_index.block_header(),
                    "{PANIC_MSG}: block headers are different in the index and the block itself for block {block_id}"
                );
            }

            // Check the parent, if it's not genesis.
            if let Some(parent_id) =
                block_index.prev_block_id().classify(self.chain_config).chain_block_id()
            {
                let parent_block_index =
                    self.block_index_map.get(&parent_id).unwrap_or_else(|| {
                        panic!("{PANIC_MSG}: block {block_id} parent index not found");
                    });
                if block_index.is_persisted() {
                    // If this block is persisted, the parent must be too.
                    assert!(
                        parent_block_index.is_persisted(),
                        "{PANIC_MSG}: parent block {parent_id} of persisted block {block_id} is not persisted"
                    );
                }

                if block_index.status().is_ok() {
                    // If a block has ok status, its parent must also be ok.
                    assert!(
                        parent_block_index.status().is_ok(),
                        "{PANIC_MSG}: parent block {parent_id} of ok block {block_id} is not ok"
                    );
                }

                // In any case, the parent block must be at least as valid as the child.
                assert!(
                    parent_block_index.status().last_valid_stage()
                        >= block_index.status().last_valid_stage(),
                    "{PANIC_MSG}: parent block {parent_id} is less valid than its child {block_id}"
                );
            }
        }

        Ok(())
    }

    /// Check consistency of the block-by-height map.
    fn check_block_height_map_consistency(&self) {
        // The block at zero height must be the genesis.
        let block_at_zero_height = *self.block_by_height_map.get(&0.into()).unwrap_or_else(|| {
            panic!("{PANIC_MSG}: no block at zero height");
        });
        assert_eq!(
            block_at_zero_height,
            self.chain_config.genesis_block_id(),
            "{PANIC_MSG}: block at zero height is not genesis"
        );

        // The block at the max height must be the same as best_block_id.
        let (max_height, block_at_max_height_id) = self
            .block_by_height_map
            .iter()
            .next_back()
            .expect("The map is known to be non-empty");
        assert_eq!(
            *block_at_max_height_id,
            self.best_block_id,
            "{PANIC_MSG}: block at max height {block_at_max_height_id} is not the same as the best block {bb}",
            bb = self.best_block_id
        );

        // The min_height_with_allowed_reorg value must be consistent with the one calculated
        // from the current max height,
        // Note: the stored min_height_with_allowed_reorg never goes down; so it's possible
        // for the stored value to become bigger than the one calculated from the current tip
        // if some mainchain blocks were invalidated in the past.
        let calculated_min_height_with_allowed_reorg =
            calc_min_height_with_allowed_reorg(self.chain_config, *max_height);
        assert!(
            self.min_height_with_allowed_reorg >= calculated_min_height_with_allowed_reorg,
            "The stored min_height_with_allowed_reorg {} is less then the calculated value {}",
            self.min_height_with_allowed_reorg,
            calculated_min_height_with_allowed_reorg
        );

        // Check the consistency of the map itself.
        for ((prev_height, prev_id), (cur_height, cur_id)) in
            self.block_by_height_map.iter().tuple_windows()
        {
            assert_eq!(
                cur_height,
                &prev_height.next_height(),
                "{PANIC_MSG}: gap in the block-by-height map found - {cur_height} follows {prev_height}"
            );

            let cur_id = cur_id.classify(self.chain_config).chain_block_id().unwrap_or_else(|| {
                panic!("{PANIC_MSG}: genesis at non-zero-height {cur_height}");
            });
            let cur_block_index = self.block_index_map.get(&cur_id).unwrap_or_else(|| {
                panic!("{PANIC_MSG}: block {cur_id} index not found");
            });
            assert_eq!(
                cur_block_index.prev_block_id(),
                prev_id,
                "{PANIC_MSG}: block {prev_id} at height {prev_height} is not a parent of the next block {cur_id}"
            );

            // Since the map contains mainchain blocks, they must be persisted and have the fully checked status.
            assert!(
                cur_block_index.is_persisted(),
                "{PANIC_MSG}: mainchain block {cur_id} must be persisted"
            );
            assert!(
                cur_block_index.status().is_fully_valid(),
                "{PANIC_MSG}: mainchain block {cur_id} must be fully valid"
            );
        }
    }
}
