// Copyright (c) 2021-2022 RBB S.r.l
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

use chainstate::BlockSource;

use crate::TestFramework;

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
            let mut iter = BlockIndexHistoryIterator::new(block3.get_id().into(), &chainstate_ref);
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
            let mut iter = BlockIndexHistoryIterator::new(Id::new(H256::zero()), &chainstate_ref);

            assert_ne!(iter.next_id, None); // ensure that we start with some id
            assert!(iter.next().is_none());
            assert_eq!(iter.next_id, None); // ensure that we won't be trying to read the db again
            assert!(iter.next().is_none());
        }
    });
}
