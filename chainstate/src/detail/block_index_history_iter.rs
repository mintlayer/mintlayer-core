// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chainstate_types::block_index::BlockIndex;
use common::{chain::block::Block, primitives::Id};
use logging::log;

use super::consensus_validator::BlockIndexHandle;

/// An iterator that starts at some block starting from a given it, and at every `next()` member call will provide the previous block index,
/// The last viable block index is of the genesis block
pub struct BlockIndexHistoryIterator<'a, H> {
    next_id: Option<Id<Block>>,
    block_index_handle: &'a H,
}

impl<'a, H: BlockIndexHandle> BlockIndexHistoryIterator<'a, H> {
    #[must_use]
    pub fn new(starting_id: Id<Block>, block_index_handle: &'a H) -> Self {
        Self {
            next_id: Some(starting_id),
            block_index_handle,
        }
    }
}

impl<'a, H: BlockIndexHandle> Iterator for BlockIndexHistoryIterator<'a, H> {
    type Item = BlockIndex;

    fn next(&mut self) -> Option<Self::Item> {
        let result = match &self.next_id {
            Some(next_id) => {
                self.block_index_handle.get_block_index(next_id).expect("Database error")
            }
            None => return None,
        };

        let bi = match result {
            Some(bi) => bi,
            None => {
                log::error!("CRITICAL: Invariant error; attempted to read id of a non-existent block index in iterator with id {:?}", self.next_id);
                self.next_id = None;
                return None;
            }
        };

        self.next_id = bi.prev_block_id().clone();

        Some(bi)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chainstate_storage::Store;
    use common::{
        chain::{
            block::{timestamp::BlockTimestamp, ConsensusData},
            config::create_unit_test_config,
        },
        primitives::{time, Idable, H256},
    };

    use crate::{BlockSource, Chainstate, ChainstateConfig};

    use super::*;

    #[test]
    fn history_iteration() {
        common::concurrency::model(|| {
            let chain_config = Arc::new(create_unit_test_config());
            let chainstte_config = ChainstateConfig::new();
            let storage = Store::new_empty().unwrap();
            let mut chainstate = Chainstate::new(
                chain_config.clone(),
                chainstte_config,
                storage,
                None,
                Default::default(),
            )
            .unwrap();

            // put three blocks in a chain after genesis
            let block1 = Block::new(
                vec![],
                Some(Id::new(chainstate.chain_config.genesis_block_id().get())),
                BlockTimestamp::from_duration_since_epoch(time::get()).unwrap(),
                ConsensusData::None,
            )
            .expect("Block creation failed");
            chainstate.process_block(block1.clone(), BlockSource::Local).unwrap();

            let block2 = Block::new(
                vec![],
                Some(block1.get_id()),
                BlockTimestamp::from_duration_since_epoch(time::get()).unwrap(),
                ConsensusData::None,
            )
            .expect("Block creation failed");
            chainstate.process_block(block2.clone(), BlockSource::Local).unwrap();

            let block3 = Block::new(
                vec![],
                Some(block2.get_id()),
                BlockTimestamp::from_duration_since_epoch(time::get()).unwrap(),
                ConsensusData::None,
            )
            .expect("Block creation failed");
            chainstate.process_block(block3.clone(), BlockSource::Local).unwrap();

            ///// test history iterator - start from tip
            {
                let chainstate_ref = chainstate.make_db_tx_ro();
                let mut iter = BlockIndexHistoryIterator::new(block3.get_id(), &chainstate_ref);
                assert_eq!(iter.next().unwrap().block_id(), &block3.get_id());
                assert_eq!(iter.next().unwrap().block_id(), &block2.get_id());
                assert_eq!(iter.next().unwrap().block_id(), &block1.get_id());
                assert_eq!(
                    iter.next().unwrap().block_id(),
                    &chain_config.genesis_block_id()
                );
                assert!(iter.next().is_none());
            }

            ///// test history iterator - start from genesis
            {
                let chainstate_ref = chainstate.make_db_tx_ro();
                let mut iter = BlockIndexHistoryIterator::new(
                    chain_config.genesis_block_id(),
                    &chainstate_ref,
                );
                assert_eq!(
                    iter.next().unwrap().block_id(),
                    &chain_config.genesis_block_id()
                );
                assert!(iter.next().is_none());
            }

            ///// test history iterator - start from an invalid non-existing block id
            {
                let chainstate_ref = chainstate.make_db_tx_ro();
                let mut iter =
                    BlockIndexHistoryIterator::new(Id::new(H256::zero()), &chainstate_ref);

                assert_ne!(iter.next_id, None); // ensure that we start with some id
                assert!(iter.next().is_none());
                assert_eq!(iter.next_id, None); // ensure that we won't be trying to read the db again
                assert!(iter.next().is_none());
            }
        });
    }
}
