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
    primitives::{BlockHeight, Id},
};
use itertools::{EitherOrBoth, Itertools};

// Certain tests check for this panic message.
const PANIC_MSG: &str = "Inconsistent chainstate";

pub struct ConsistencyChecker<'a, 'b, DbTx> {
    _db_tx: &'a DbTx,
    chain_config: &'b ChainConfig,
    /// Keys (block ids) of the block map.
    block_map_keys: BTreeSet<Id<Block>>,
    /// The entire block index map.
    block_index_map: BTreeMap<Id<Block>, BlockIndex>,
    /// The entire block-by-height map.
    block_by_height_map: BTreeMap<BlockHeight, Id<GenBlock>>,
}

impl<'a, 'b, DbTx: BlockchainStorageRead> ConsistencyChecker<'a, 'b, DbTx> {
    pub fn new(
        db_tx: &'a DbTx,
        chain_config: &'b ChainConfig,
    ) -> Result<Self, chainstate_storage::Error> {
        let block_map_keys = db_tx.get_block_map_keys()?;
        let block_index_map = db_tx.get_block_index_map()?;
        let block_by_height_map = db_tx.get_block_by_height_map()?;

        Ok(Self {
            _db_tx: db_tx,
            chain_config,
            block_map_keys,
            block_index_map,
            block_by_height_map,
        })
    }

    /// Check the block map vs block index map consistency.
    fn check_block_index_consistency(&self) {
        for merged in self
            .block_map_keys
            .iter()
            .merge_join_by(self.block_index_map.iter(), |id1, (id2, _)| {
                Ord::cmp(id1, id2)
            })
        {
            match merged {
                EitherOrBoth::Left(block_id) => {
                    // The block object is present, the index object is not.
                    panic!("{PANIC_MSG}: block index data missing for block {block_id}");
                }
                EitherOrBoth::Right((block_id, block_index)) => {
                    // The block index object is present, the block object is not.
                    // The index object must not be marked as persistent and must not have an "ok" status.
                    assert!(
                        !block_index.is_persistent(),
                        "{PANIC_MSG}: block {block_id} can't be persistent"
                    );
                    assert!(
                        !block_index.status().is_ok(),
                        "{PANIC_MSG}: block {block_id} can't be ok"
                    );
                }
                EitherOrBoth::Both(_, (block_id, block_index)) => {
                    // Both the block and block index objects are present.

                    // The index object must be marked as persistent.
                    assert!(
                        block_index.is_persistent(),
                        "{PANIC_MSG}: block {block_id} must be persistent"
                    );

                    // Check the parent, if it's not genesis.
                    if let Some(parent_id) =
                        block_index.prev_block_id().classify(self.chain_config).chain_block_id()
                    {
                        let parent_block_index =
                            self.block_index_map.get(&parent_id).unwrap_or_else(|| {
                                panic!("{PANIC_MSG}: block {block_id} parent index not found");
                            });
                        // Since this index object is persistent, the parent must be persistent too.
                        assert!(
                            parent_block_index.is_persistent(),
                            "{PANIC_MSG}: parent block {parent_id} of persistent block {block_id} is not persistent"
                        );

                        if block_index.status().is_ok() {
                            // If a block has ok status, its parent must also be ok.
                            assert!(
                                parent_block_index.status().is_ok(),
                                "{PANIC_MSG}: parent block {parent_id} of ok block {block_id} is not ok"
                            );
                        }

                        // In any case, the parent block must be at least as valid as the child.
                        assert!(
                            parent_block_index.status().last_valid_stage() >= block_index.status().last_valid_stage(),
                            "{PANIC_MSG}: parent block {parent_id} is less valid than its child {block_id}"
                        );
                    }
                }
            }
        }
    }

    fn check_block_height_map_consistency(&self) {
        let block_at_zero_height = *self.block_by_height_map.get(&0.into()).unwrap_or_else(|| {
            panic!("{PANIC_MSG}: no block at zero height");
        });
        assert_eq!(
            block_at_zero_height,
            self.chain_config.genesis_block_id(),
            "{PANIC_MSG}: block at zero height is not genesis"
        );

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

            assert!(
                cur_block_index.is_persistent(),
                "{PANIC_MSG}: mainchain block {cur_id} must be persistent"
            );
            assert!(
                cur_block_index.status().is_fully_valid(),
                "{PANIC_MSG}: mainchain block {cur_id} must be fully valid"
            );
        }
    }

    pub fn check(&self) {
        self.check_block_index_consistency();
        self.check_block_height_map_consistency();
        // FIXME add todo for other checks (e.g. other db maps)
    }
}
