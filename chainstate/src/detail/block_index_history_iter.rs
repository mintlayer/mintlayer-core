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

use common::{chain::GenBlock, primitives::Id};
use consensus::BlockIndexHandle;
use logging::log;

use super::GenBlockIndex;

/// An iterator that starts at some block starting from a given it, and at every `next()` member call will provide the previous block index,
/// The last viable block index is of the genesis block
pub struct BlockIndexHistoryIterator<'a, H> {
    next_id: Option<Id<GenBlock>>,
    block_index_handle: &'a H,
}

impl<'a, H: BlockIndexHandle> BlockIndexHistoryIterator<'a, H> {
    #[must_use]
    pub fn new(starting_id: Id<GenBlock>, block_index_handle: &'a H) -> Self {
        Self {
            next_id: Some(starting_id),
            block_index_handle,
        }
    }
}

impl<'a, H: BlockIndexHandle> Iterator for BlockIndexHistoryIterator<'a, H> {
    type Item = GenBlockIndex;

    fn next(&mut self) -> Option<Self::Item> {
        let next_id = self.next_id.as_ref()?;
        let block_index =
            self.block_index_handle.get_gen_block_index(next_id).expect("Database error");
        let block_index = match block_index {
            Some(bi) => bi,
            None => {
                log::error!("CRITICAL: Invariant error; attempted to read id of a non-existent block index in iterator with id {:?}", self.next_id);
                self.next_id = None;
                return None;
            }
        };

        self.next_id = match &block_index {
            GenBlockIndex::Genesis(_) => None,
            GenBlockIndex::Block(blkidx) => Some(*blkidx.prev_block_id()),
        };

        Some(block_index)
    }
}

#[cfg(test)]
mod tests {
    use common::primitives::{Idable, H256};

    use crate::{detail::tests::TestFramework, BlockSource};

    use super::*;

    #[test]
    fn history_iteration() {
        utils::concurrency::model(|| {
            let mut tf = TestFramework::default();

            // put three blocks in a chain after genesis
            let block1 = tf.make_block_builder().build();
            tf.process_block(block1.clone(), BlockSource::Local).unwrap();

            let block2 = tf.make_block_builder().build();
            tf.process_block(block2.clone(), BlockSource::Local).unwrap();

            let block3 = tf.make_block_builder().build();
            tf.process_block(block3.clone(), BlockSource::Local).unwrap();

            ///// test history iterator - start from tip
            {
                let chainstate_ref = tf.chainstate.make_db_tx_ro();
                let mut iter =
                    BlockIndexHistoryIterator::new(block3.get_id().into(), &chainstate_ref);
                assert_eq!(iter.next().unwrap().block_id(), block3.get_id());
                assert_eq!(iter.next().unwrap().block_id(), block2.get_id());
                assert_eq!(iter.next().unwrap().block_id(), block1.get_id());
                assert_eq!(iter.next().unwrap().block_id(), tf.genesis().get_id());
                assert!(iter.next().is_none());
            }

            ///// test history iterator - start from genesis
            {
                let chainstate_ref = tf.chainstate.make_db_tx_ro();
                let mut iter =
                    BlockIndexHistoryIterator::new(tf.genesis().get_id().into(), &chainstate_ref);
                assert_eq!(iter.next().unwrap().block_id(), tf.genesis().get_id(),);
                assert!(iter.next().is_none());
            }

            ///// test history iterator - start from an invalid non-existing block id
            {
                let chainstate_ref = tf.chainstate.make_db_tx_ro();
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
